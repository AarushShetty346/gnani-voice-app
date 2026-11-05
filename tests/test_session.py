"""ListenSession without a socket: fake send/receive, fake stream, fake clock, fake LLM."""
import asyncio
import base64
import json

import pytest

from app import session as sess
from app.detector import Assessment, CallMonitor
from app.gnani import GnaniError
from app.gnani_stream import StreamBase

FRAME = b"\x00\x00" * 512


class FakeStream(StreamBase):
    """Events are whatever the test pushes; close() ends events()."""

    def __init__(self, fail_open: Exception | None = None, reports_speech: bool = False):
        self.reports_speech = reports_speech
        self.q: asyncio.Queue = asyncio.Queue()
        self.frames, self.commits, self.closed, self.cfg = [], 0, False, None
        self.fail_open = fail_open

    async def open(self):
        if self.fail_open:
            raise self.fail_open

    async def send_frame(self, frame):
        self.frames.append(frame)

    async def commit(self):
        self.commits += 1

    async def events(self):
        yield {"type": "connected"}
        while True:
            ev = await self.q.get()
            if ev is None:
                return
            yield ev

    async def close(self):
        self.closed = True
        self.q.put_nowait(None)

    def say(self, text, lang="en-IN"):
        self.q.put_nowait({"type": "transcript", "text": text, "language": lang, "index": 0})


class Harness:
    def __init__(self, clock=None, settle_s=0.0, **kw):
        self.sent: list[dict] = []
        self.inbox: asyncio.Queue = asyncio.Queue()
        self.stream = FakeStream(kw.pop("fail_open", None), kw.pop("reports_speech", False))

        def factory(cfg, lines):
            self.stream.cfg, self.lines = cfg, lines
            return self.stream
        self.t = [0.0]
        self.s = sess.ListenSession(self._send, stream_factory=factory,
                                    clock=(lambda: self.t[0]) if clock else None, **kw)
        self.s.settle_s = settle_s
        self.task: asyncio.Task | None = None

    async def _send(self, msg):
        self.sent.append(msg)

    async def _receive(self):
        return await self.inbox.get()

    def start(self, **over):
        msg = {"type": "start", "source": "mic", "demo_id": None, "language": "indic-auto", "warn_language": "en-IN"}
        msg.update(over)
        self.inbox.put_nowait(json.dumps(msg))
        self.task = asyncio.create_task(self.s.run(self._receive))

    def of(self, kind):
        return [m for m in self.sent if m["type"] == kind]

    async def until(self, pred, timeout=2.0):
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while not pred():
            if loop.time() > end:
                raise AssertionError(f"timed out; sent={[m['type'] for m in self.sent]}")
            await asyncio.sleep(0.005)

    async def say(self, text, at=None, lang="en-IN"):
        if at is not None:
            self.t[0] = at
        n = len(self.of("transcript"))
        self.stream.say(text, lang)
        await self.until(lambda: len(self.of("transcript")) > n)
        await asyncio.sleep(0.01)          # let background alert tasks run

    async def stop(self):
        self.inbox.put_nowait(json.dumps({"type": "stop"}))
        await asyncio.wait_for(self.task, 3)


# ---------------------------------------------------------------- AlertPolicy (pure)

def test_policy_dedupe_gap_and_one_preempt():
    p = sess.AlertPolicy(gap_s=6, followup_gap_s=12, max_alerts=3)
    assert p.decide("safe", ["impersonation"], ["impersonation"], 0) is None
    assert p.decide("caution", ["impersonation"], ["impersonation"], 0) == ("impersonation", "caution")
    assert p.decide("caution", ["account_threat"], [], 12) is None                          # one caution warning
    assert p.decide("danger", ["urgency_secrecy"], [], 13) == ("urgency_secrecy", "danger")  # rise speaks again
    assert p.decide("danger", ["digital_arrest"], [], 30) is None                           # not a direct ask
    assert p.decide("danger", ["otp_request"], [], 20) is None                              # inside the 12 s gap
    assert p.pending == ["otp_request"]
    assert p.blocked(20) and p.next_allowed() == 25
    assert p.decide("danger", [], [], 25) == ("otp_request", "danger")                      # held-back ask
    assert p.decide("danger", ["payment_request"], [], 60) is None                          # max 3 per call
    assert p.sent == ["impersonation", "urgency_secrecy", "otp_request"]


def test_policy_danger_preempts_once_and_followups_wait():
    """Rising to danger may cut the caution gap once; follow-ups never cut the main warning off."""
    p = sess.AlertPolicy(gap_s=6, followup_gap_s=12, max_alerts=3)
    assert p.decide("caution", ["account_threat"], [], 10.0) == ("account_threat", "caution")
    assert p.decide("danger", ["otp_request"], [], 11.0) == ("otp_request", "danger")       # pre-empts the 6 s gap
    assert p.decide("danger", ["remote_access"], [], 14.0) is None                         # 12 s follow-up gap
    assert p.decide("danger", [], [], 23.0) == ("remote_access", "danger")


def test_policy_one_danger_warning_for_a_whole_scam_call():
    """The live Hindi demo used to speak 5 times; now: one danger warning plus one for the money ask."""
    p = sess.AlertPolicy()
    out = [p.decide("danger", ["impersonation", "digital_arrest"], [], 18.7),
           p.decide("danger", ["digital_arrest"], [], 23.2),
           p.decide("danger", ["account_threat"], [], 27.9),
           p.decide("danger", ["urgency_secrecy"], [], 28.2),
           p.decide("danger", ["payment_request"], [], 40.6)]
    assert [o for o in out if o] == [("impersonation", "danger"), ("payment_request", "danger")]


def test_policy_level_rise_falls_back_to_generic():
    p = sess.AlertPolicy(gap_s=6)
    assert p.decide("caution", [], ["impersonation"], 0) == ("impersonation", "caution")
    assert p.decide("danger", [], ["impersonation"], 10) == ("generic", "danger")
    assert p.decide("danger", [], ["impersonation"], 20) is None


def test_parse_languages():
    assert sess.parse_stt_language(None) == "indic-auto"
    assert sess.parse_stt_language(" hi-IN, en-IN ") == "hi-IN,en-IN"
    assert sess.parse_stt_language("hi-IN,hi-IN") is None
    assert sess.parse_stt_language("xx-IN") is None
    assert sess.parse_stt_language("hi-IN,en-IN,ta-IN,te-IN,kn-IN") is None
    assert sess.parse_stream_language("kn-IN") == "kn-IN"
    assert sess.parse_stream_language(None) == "indic-auto"
    assert sess.parse_stream_language("kn-IN,en-IN") == "kn-IN"       # realtime: one code only -> the first
    assert sess.parse_stream_language("xx-IN,en-IN") is None
    assert sess.parse_warn_language("ta-IN") == "ta-IN"
    assert sess.parse_warn_language("../x") == "auto"


# ---------------------------------------------------------------- session flow

async def test_transcripts_risk_alert_dedupe_and_gap():
    h = Harness(clock=True)
    h.start()
    await h.until(lambda: h.of("ready"))
    assert h.of("ready")[0]["mock"] is True
    assert h.stream.cfg.keyterms and h.stream.cfg.telephony is False
    await h.say("I am calling from the cyber crime branch.", at=0)
    assert h.of("risk")[-1]["level"] == "safe" and not h.of("alert")
    await h.say("Tell me the OTP you just received.", at=1)
    await h.say("Tell me the OTP you just received.", at=2)     # same category: no second alert
    await h.say("Install AnyDesk app now.", at=3)               # inside the gap, already danger: held back
    await h.say("Send the money by UPI.", at=4)                 # inside the gap: held back
    assert [a["category"] for a in h.of("alert")] == ["otp_request"]
    await h.say("Okay.", at=20)                                 # gap over: the newest held-back alert goes out
    await h.say("Fine.", at=33)                                 # ...then the next, 12 s later
    await h.until(lambda: len(h.of("alert")) == 3)
    alerts = h.of("alert")
    assert [a["category"] for a in alerts] == ["otp_request", "payment_request", "remote_access"]
    assert [a["id"] for a in alerts] == [1, 2, 3]
    assert all(a["level"] == "danger" and a["language"] == "en-IN" and a["text"] for a in alerts)
    assert all(a["text_en"] is None for a in alerts)   # already English: no second line
    assert all(a["audio_b64"] is None and a["audio_pending"] is False for a in alerts)   # mock mode: no TTS
    assert not h.of("alert_audio")
    t = h.of("transcript")[1]
    assert t["index"] == 1 and t["language"] == "en-IN"
    assert t["flags"] and set(t["flags"][0]) == {"category", "phrase", "start", "end"}
    await h.stop()
    assert h.sent[-1]["type"] == "summary" and h.sent[-1]["verdict"] == "scam"
    assert h.stream.commits == 1 and h.stream.closed and h.s.end_reason == "stop"


async def test_alert_never_waits_for_tts():
    """The alert goes out at once with no audio; the clip follows as alert_audio with the same id."""
    gate = asyncio.Event()

    async def slow_audio(text, lang):
        await gate.wait()
        return b"RIFFfake"
    h = Harness(alert_audio=slow_audio)
    h.start(warn_language="auto")
    await h.until(lambda: h.of("ready"))
    await h.say("आपका OTP बताइए नहीं तो आपका account block हो जायेगा।", lang="hi-IN")
    await h.until(lambda: h.of("alert"))
    a = h.of("alert")[0]
    assert a["language"] == "hi-IN" and a["audio_b64"] is None and a["id"] == 1 and a["text"]
    assert a["audio_pending"] is True
    await h.say("जल्दी कीजिए।", lang="hi-IN")
    await h.say("ठीक है।", lang="hi-IN")
    assert len(h.of("transcript")) == 3 and not h.of("alert_audio")   # TTS pending, transcripts still flow
    gate.set()
    await h.until(lambda: h.of("alert_audio"))
    assert h.of("alert_audio") == [{"type": "alert_audio", "id": 1,
                                    "audio_b64": base64.b64encode(b"RIFFfake").decode()}]
    await h.stop()


async def test_cached_alert_audio_rides_inside_the_alert():
    async def cached(text, lang):
        return b"RIFFcached"
    h = Harness(alert_audio=cached)
    h.start()
    await h.until(lambda: h.of("ready"))
    await h.say("Tell me the OTP you just received.")
    await h.until(lambda: h.of("alert"))
    assert base64.b64decode(h.of("alert")[0]["audio_b64"]) == b"RIFFcached" and not h.of("alert_audio")
    assert h.of("alert")[0]["audio_pending"] is False
    await h.stop()


async def test_alerts_keep_their_order_when_only_the_later_one_is_cached():
    async def audio(text, lang):
        if "OTP" in text:                    # the first alert's clip is not cached: slow TTS
            await asyncio.sleep(0.3)
        return b"RIFF" + text[:4].encode()
    h = Harness(clock=True, alert_audio=audio)
    h.start()
    await h.until(lambda: h.of("ready"))
    h.s._maybe_alert(Assessment(50, "caution", ["otp_request"], "", "rules"), ["otp_request"])
    h.t[0] = 1.0
    h.s._maybe_alert(Assessment(80, "danger", ["remote_access"], "", "rules"), ["remote_access"])
    await h.until(lambda: len(h.of("alert")) == 2 and h.of("alert_audio"))
    assert [(a["id"], a["level"]) for a in h.of("alert")] == [(1, "caution"), (2, "danger")]
    assert h.of("alert")[1]["audio_b64"] and h.of("alert_audio")[0]["id"] == 1
    await h.stop()


async def test_failing_or_slow_tts_still_alerts(monkeypatch):
    monkeypatch.setattr(sess, "ALERT_TTS_TIMEOUT_S", 0.05)

    async def boom(text, lang):
        raise RuntimeError("Timbre down")

    release = asyncio.Event()

    async def never(text, lang):
        await release.wait()
        return b"RIFFlate"
    for fn in (boom, never):
        h = Harness(alert_audio=fn)
        h.start()
        await h.until(lambda: h.of("ready"))
        await h.say("Tell me the OTP you just received.")
        await h.until(lambda: h.of("alert"))
        await asyncio.sleep(0.15)
        assert h.of("alert")[0]["audio_b64"] is None and not h.of("alert_audio")
        await h.stop()

    async def late_boom(text, lang):
        await asyncio.sleep(0.1)
        raise RuntimeError("Timbre 503")
    monkeypatch.setattr(sess, "ALERT_TTS_TIMEOUT_S", 5.0)
    h = Harness(alert_audio=late_boom)
    h.start()
    await h.until(lambda: h.of("ready"))
    await h.say("Tell me the OTP you just received.")
    await h.until(lambda: h.of("alert_audio"))
    assert h.of("alert")[0]["audio_pending"] is True
    assert h.of("alert_audio") == [{"type": "alert_audio", "id": 1, "audio_b64": None}]   # speak now, browser
    await h.stop()
    release.set()                    # the shielded TTS still finishes (and would fill the cache)
    await asyncio.sleep(0.01)


async def test_mic_echo_of_our_own_alert_is_dropped():
    from app import alerts
    h = Harness(clock=True)
    h.start(warn_language="hi-IN")
    await h.until(lambda: h.of("ready"))
    await h.say("आपका OTP बताइए नहीं तो आपका account block हो जायेगा।", at=0, lang="hi-IN")
    await h.until(lambda: h.of("alert"))
    spoken = h.of("alert")[0]["text"]
    assert spoken == alerts.alert_text(h.of("alert")[0]["category"], h.of("alert")[0]["level"], "hi-IN")
    assert h.of("alert")[0]["text_en"] == alerts.alert_text(h.of("alert")[0]["category"], h.of("alert")[0]["level"], "en-IN")
    n = len(h.of("transcript"))
    words = spoken.split()
    h.stream.say(" ".join(words[len(words) // 3:]), "hi-IN")           # the tail of our warning, via the mic
    await asyncio.sleep(0.1)
    assert len(h.of("transcript")) == n
    await h.say("अपना OTP बताइए।", at=2, lang="hi-IN")                  # short real speech is never dropped
    await h.say("सर मैं आपको OTP नहीं बताऊँगी, मैं बैंक को फ़ोन करती हूँ।", at=3, lang="hi-IN")
    assert len(h.of("transcript")) == n + 2
    h.t[0] = 3 + sess.ECHO_WINDOW_S
    await h.say(spoken, lang="hi-IN")                                  # long after: not an echo any more
    assert len(h.of("transcript")) == n + 3
    await h.stop()


def test_echo_score():
    alert = "रुकिए! यह कॉल धोखा लग रहा है। अपना OTP किसी को मत बताइए। अभी फ़ोन काट दीजिए।"
    assert sess.is_echo("यह call धोखा लग रहा है। अपना OTP किसी को मत बताइए", alert)   # code-mixed echo
    assert not sess.is_echo("अपना OTP बताइए", alert)                                   # too short to judge
    assert not sess.is_echo("आपका account block हो जायेगा, OTP बताइए", alert)


async def test_demo_source_never_filters_echo():
    h = Harness()
    h.start(source="demo", demo_id="digital-arrest", warn_language="hi-IN")
    await h.until(lambda: h.of("ready"))
    h.s._spoken.append((h.s.now(), "रुकिए! यह कॉल धोखा लग रहा है। अपना OTP किसी को मत बताइए।"))
    await h.say("रुकिए! यह कॉल धोखा लग रहा है। अपना OTP किसी को मत बताइए।", lang="hi-IN")
    await h.stop()


class FakeLLMMonitor(CallMonitor):
    def __init__(self):
        super().__init__()
        self.gate = asyncio.Event()
        self.calls = self.active = self.max_active = 0

    async def llm_review(self):
        self.calls += 1
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            await self.gate.wait()
        finally:
            self.active -= 1
        self.gate.clear()
        return Assessment(88, "danger", ["impersonation", "payment_request"], "LLM: fake officer wants money", "llm")


async def test_llm_review_single_flight_and_debounce():
    mon = FakeLLMMonitor()
    h = Harness(monitor=mon)
    h.start()
    await h.until(lambda: h.of("ready"))
    await h.say("Hello.")
    assert mon.calls == 0                                       # needs >= 2 utterances
    for text in ("Who is this?", "Please listen.", "This is important.", "Are you there?"):
        await h.say(text)
    assert mon.calls == 1 and mon.max_active == 1               # one in flight; the rest coalesce
    mon.gate.set()
    await h.until(lambda: mon.calls == 2)                       # exactly one re-run for the queued ones
    mon.gate.set()
    await h.until(lambda: mon.active == 0 and h.s._llm_task.done())
    assert mon.calls == 2 and mon.max_active == 1
    llm_risk = [r for r in h.of("risk") if r["source"] == "llm"]
    assert len(llm_risk) == 1 and llm_risk[0]["score"] == 88 and llm_risk[0]["level"] == "danger"
    await h.until(lambda: h.of("alert"))
    assert h.of("alert")[0]["category"] == "impersonation" and h.of("alert")[0]["level"] == "danger"
    await h.stop()


async def test_trailing_transcript_after_stop_is_included():
    h = Harness(settle_s=2.0)
    h.start()
    await h.until(lambda: h.of("ready"))
    await h.say("Hello.")
    h.inbox.put_nowait(json.dumps({"type": "stop"}))
    await h.until(lambda: h.stream.commits == 1)
    h.stream.say("Tell me the OTP you just received.")         # arrives after commit
    await asyncio.wait_for(h.task, 3)
    kinds = [m["type"] for m in h.sent]
    assert kinds.index("summary") > max(i for i, k in enumerate(kinds) if k == "transcript")
    assert len(h.of("transcript")) == 2 and h.sent[-1]["verdict"] != "safe"


async def test_frames_forwarded_and_bad_frames_rejected_once():
    h = Harness()
    h.start()
    await h.until(lambda: h.of("ready"))
    for f in (FRAME, b"\x00" * 10, b"\x00" * 7, FRAME):
        h.inbox.put_nowait(f)
    await h.until(lambda: len(h.stream.frames) == 2)
    errs = h.of("error")
    assert len(errs) == 1 and errs[0]["fatal"] is False
    await h.stop()


async def test_recoverable_stream_error_is_not_shown_but_explains_a_fatal_one():
    h = Harness()
    h.start()
    await h.until(lambda: h.of("ready"))
    h.stream.q.put_nowait({"type": "error", "message": "Concurrent session limit (2) reached", "fatal": False})
    await h.say("Hello.")
    assert not h.of("error")
    h.stream.q.put_nowait({"type": "error", "message": "Gnani stream closed (1008 limit)", "fatal": True})
    await asyncio.wait_for(h.task, 3)
    assert [e["message"] for e in h.of("error")] == [
        "Gnani stream closed (1008 limit): Concurrent session limit (2) reached"]
    assert h.sent[-1]["type"] == "summary"


async def test_settle_ends_early_when_nothing_is_pending():
    """Real Gnani reports speech_start/processing: with every utterance already transcribed, stop
    doesn't sit out the whole settle time."""
    h = Harness(settle_s=5.0, reports_speech=True)
    h.start()
    await h.until(lambda: h.of("ready"))
    await h.say("Hello.")
    loop = asyncio.get_running_loop()
    t = loop.time()
    await h.stop()
    assert loop.time() - t < 1.0 and h.sent[-1]["type"] == "summary"


async def test_settle_waits_for_speech_in_progress():
    h = Harness(settle_s=3.0, reports_speech=True)
    h.start()
    await h.until(lambda: h.of("ready"))
    h.stream.q.put_nowait({"type": "speech_start"})
    await asyncio.sleep(0.02)
    h.inbox.put_nowait(json.dumps({"type": "stop"}))
    await h.until(lambda: h.stream.commits == 1)
    await asyncio.sleep(0.5)                                      # past the grace: still waiting for it
    assert not h.of("summary")
    h.stream.q.put_nowait({"type": "processing"})
    h.stream.say("Tell me the OTP you just received.")
    await asyncio.wait_for(h.task, 3)
    assert len(h.of("transcript")) == 1 and h.sent[-1]["type"] == "summary"


async def test_client_leaving_during_settle_ends_the_session_at_once():
    h = Harness(settle_s=10.0)
    h.start()
    await h.until(lambda: h.of("ready"))
    h.inbox.put_nowait(json.dumps({"type": "stop"}))
    await h.until(lambda: h.stream.commits == 1)
    loop = asyncio.get_running_loop()
    t = loop.time()
    h.inbox.put_nowait(None)                                      # the browser closed the socket
    await asyncio.wait_for(h.task, 3)
    assert loop.time() - t < 0.5 and h.stream.closed and not h.of("summary")


async def test_stop_path_fits_the_browser_wait():
    """The browser's summary wait (app.js) must outlast the server's worst-case stop path."""
    import re

    from app import config, gnani_stream
    js = (config.ROOT / "static" / "app.js").read_text(encoding="utf-8")
    wait_s = int(re.search(r"SUMMARY_WAIT_MS = (\d+)", js).group(1)) / 1000
    worst = (sess.SETTLE_S + gnani_stream.CLOSE_TIMEOUT_S + 1.0
             + max(sess.ALERT_WAIT_S, sess.SUMMARY_TIMEOUT_S))
    assert wait_s > worst + 3
    assert sess.MAX_SESSION_S < 15 * 60


async def test_fatal_stream_error_ends_with_summary():
    h = Harness()
    h.start()
    await h.until(lambda: h.of("ready"))
    await h.say("Hello.")
    h.stream.q.put_nowait({"type": "error", "message": "Gnani stream closed (1008 bad header)", "fatal": True})
    await asyncio.wait_for(h.task, 3)
    assert h.of("error")[0] == {"type": "error", "message": "Gnani stream closed (1008 bad header)", "fatal": True}
    assert h.sent[-1]["type"] == "summary" and h.s.end_reason == "stream" and h.stream.commits == 0


async def test_disconnect_sends_nothing_more():
    h = Harness()
    h.start()
    await h.until(lambda: h.of("ready"))
    await h.say("Tell me the OTP you just received.")
    n = len(h.sent)
    h.inbox.put_nowait(None)
    await asyncio.wait_for(h.task, 3)
    assert h.s.end_reason == "disconnect" and h.stream.closed
    assert not [m for m in h.sent[n:] if m["type"] == "summary"]


async def test_session_cap():
    h = Harness()
    h.s.max_session_s = 0.1
    h.start()
    await asyncio.wait_for(h.task, 3)
    assert h.s.end_reason == "cap"
    assert any(e["fatal"] is False and "15-minute" in e["message"] for e in h.of("error"))
    assert h.sent[-1]["type"] == "summary" and h.sent[-1]["verdict"] == "safe"


@pytest.mark.parametrize("start, needle", [
    ({"source": "demo", "demo_id": "nope"}, "Unknown demo"),
    ({"source": "radio"}, "Unknown source"),
    ({"language": "xx-YY"}, "language"),
    ({"language": "hi-IN,xx-YY"}, "one language code"),
])
async def test_bad_start_messages(start, needle):
    h = Harness()
    h.start(**start)
    await asyncio.wait_for(h.task, 3)
    assert len(h.sent) == 1 and h.sent[0]["type"] == "error" and h.sent[0]["fatal"] and needle in h.sent[0]["message"]


async def test_first_message_must_be_start():
    h = Harness()
    h.inbox.put_nowait(FRAME)
    await asyncio.wait_for(h.s.run(h._receive), 3)
    assert h.sent[0]["type"] == "error" and h.sent[0]["fatal"]


async def test_gnani_open_error_is_reported():
    h = Harness(fail_open=GnaniError(401, "INVALID_API_KEY", "Invalid API key"))
    h.start()
    await asyncio.wait_for(h.task, 3)
    assert h.sent == [{"type": "error", "message": "Could not start Gnani speech-to-text: Invalid API key",
                       "fatal": True}]


async def test_mic_language_list_is_narrowed_to_one_code():
    h = Harness()
    h.start(language="kn-IN,en-IN")
    await h.until(lambda: h.of("ready"))
    assert h.stream.cfg.language == "kn-IN"
    await h.stop()


async def test_demo_source_uses_demo_lines_and_telephony():
    h = Harness()
    h.start(source="demo", demo_id="electricity-anydesk", language="indic-auto")
    await h.until(lambda: h.of("ready"))
    assert h.stream.cfg.telephony is True and h.stream.cfg.language == "kn-IN"   # the demo's own language
    assert h.lines[0][1].startswith("ನಮಸ್ಕಾರ") and h.lines[0][2] == "kn-IN"
    await h.stop()


async def test_mic_source_mocks_digital_arrest():
    h = Harness()
    h.start()
    await h.until(lambda: h.of("ready"))
    assert "साइबर क्राइम" in h.lines[0][1]
    assert h.stream.cfg.language == "indic-auto" and h.stream.cfg.telephony is False
    await h.stop()


async def test_slow_summary_falls_back_to_template(monkeypatch):
    monkeypatch.setattr(sess, "SUMMARY_TIMEOUT_S", 0.05)

    async def slow(monitor, language):
        await asyncio.sleep(5)
    h = Harness(summarize=slow)
    h.start()
    await h.until(lambda: h.of("ready"))
    await h.say("I am calling from the cyber crime branch.")
    await h.say("Tell me the OTP you just received.")
    await h.stop()
    s = h.sent[-1]
    assert s["type"] == "summary" and s["verdict"] == "scam" and "Checked with ScamLingo" in s["share_text"]
