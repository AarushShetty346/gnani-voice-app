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

    def __init__(self, fail_open: Exception | None = None):
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
        self.stream = FakeStream(kw.pop("fail_open", None))

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
    p = sess.AlertPolicy(gap_s=6)
    assert p.decide("safe", ["impersonation"], ["impersonation"], 0) is None
    assert p.decide("caution", ["impersonation"], ["impersonation"], 0) == ("impersonation", "caution")
    assert p.decide("caution", ["impersonation"], ["impersonation"], 10) is None          # once per category
    assert p.decide("caution", ["account_threat"], [], 12) == ("account_threat", "caution")
    assert p.decide("caution", ["urgency_secrecy"], [], 14) is None                         # inside the 6 s gap
    assert p.pending == ["urgency_secrecy"]
    assert p.decide("danger", ["otp_request"], [], 15) == ("otp_request", "danger")         # danger pre-empts once
    assert p.decide("danger", ["remote_access"], [], 16) is None                            # ...only once
    assert p.blocked(16) and p.next_allowed() == 21
    assert p.decide("danger", [], [], 21) == ("remote_access", "danger")                    # newest first
    assert p.decide("danger", [], [], 27) == ("urgency_secrecy", "danger")
    assert p.decide("danger", ["otp_request"], [], 40) is None
    assert p.sent == ["impersonation", "account_threat", "otp_request", "remote_access", "urgency_secrecy"]


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
    assert sess.parse_stream_language("hi-IN,en-IN") is None          # realtime: one code only
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
    await h.say("Install AnyDesk app now.", at=3)               # inside the gap: danger pre-empt (once)
    await h.say("Send the money by UPI right now.", at=4)       # inside the gap: held back
    assert [a["category"] for a in h.of("alert")] == ["otp_request", "remote_access"]
    await h.say("Okay.", at=20)                                 # gap over: the held-back alert goes out
    await h.until(lambda: len(h.of("alert")) == 3)
    alerts = h.of("alert")
    assert alerts[2]["category"] == "payment_request"
    assert all(a["level"] == "danger" and a["language"] == "en-IN" and a["text"] for a in alerts)
    assert all(a["audio_b64"] is None for a in alerts)          # mock mode: no TTS
    t = h.of("transcript")[1]
    assert t["index"] == 1 and t["language"] == "en-IN"
    assert t["flags"] and set(t["flags"][0]) == {"category", "phrase", "start", "end"}
    await h.stop()
    assert h.sent[-1]["type"] == "summary" and h.sent[-1]["verdict"] == "scam"
    assert h.stream.commits == 1 and h.stream.closed and h.s.end_reason == "stop"


async def test_alert_tts_runs_in_background():
    gate = asyncio.Event()

    async def slow_audio(text, lang):
        await gate.wait()
        return b"RIFFfake"
    h = Harness(alert_audio=slow_audio)
    h.start(warn_language="auto")
    await h.until(lambda: h.of("ready"))
    await h.say("आपका OTP बताइए नहीं तो आपका account block हो जायेगा।", lang="hi-IN")
    await h.say("जल्दी कीजिए।", lang="hi-IN")
    await h.say("ठीक है।", lang="hi-IN")
    assert len(h.of("transcript")) == 3 and not h.of("alert")   # TTS pending, transcripts still flow
    gate.set()
    await h.until(lambda: h.of("alert"))
    a = h.of("alert")[0]
    assert a["language"] == "hi-IN" and base64.b64decode(a["audio_b64"]) == b"RIFFfake"
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
    ({"language": "hi-IN,en-IN"}, "one language code"),
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
    assert s["type"] == "summary" and s["verdict"] == "scam" and "Checked with Scam Kavach" in s["share_text"]
