"""One live call check over WS /ws/listen: start message -> STT stream -> detector -> alerts -> summary.

ListenSession owns the whole orchestration and never touches a socket itself: it gets a `send(dict)`
coroutine and a `receive()` coroutine (bytes = audio frame, str = JSON control message, None = the
client went away), plus an injectable stream factory, monitor, alert-audio and summarize functions.
That keeps it testable without a server.

Protocol and rules: docs/SPEC.md, "app/session.py + app/main.py".
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
from dataclasses import asdict
from typing import Awaitable, Callable

from app import alerts, config, summary
from app.detector import Assessment, CallMonitor
from app.gnani import GnaniError
from app.gnani_stream import FRAME_BYTES, StreamBase, StreamConfig, mock_lines_for, open_stream

log = logging.getLogger(__name__)

# Module-level knobs (tests monkeypatch these; read when a session is created).
ALERT_GAP_S = 6.0          # minimum time between two alerts
SETTLE_S = 3.0             # after stop: max wait for trailing transcripts
QUIET_S = 0.5              # ...or stop waiting once a trailing transcript arrived and things went quiet
MAX_SESSION_S = 15 * 60    # one check lasts at most 15 minutes (Gnani's stream cap)
START_TIMEOUT_S = 15.0     # the client must send "start" within this
ALERT_WAIT_S = 5.0         # at the end, wait this long for alert TTS still in flight
SUMMARY_TIMEOUT_S = 15.0   # LLM summary budget before falling back to the template
IDLE_TIMEOUT_S = 300       # Gnani closes a stream after this long without speech
MIC_MOCK_DEMO = "digital-arrest"   # what the mock "hears" from the mic when there is no Gnani key

LEVEL_RANK = {"safe": 0, "caution": 1, "danger": 2}
GENERIC = "generic"        # alert category when the level rose but no specific category is left

Send = Callable[[dict], Awaitable[None]]
Receive = Callable[[], Awaitable["bytes | str | None"]]
StreamFactory = Callable[[StreamConfig, "list[tuple[float, str, str]] | None"], StreamBase]


# ---------------------------------------------------------------- helpers shared with main.py

def parse_stt_language(value: str | None) -> str | None:
    """'indic-auto' or 1-4 distinct supported codes ('hi-IN,en-IN'); None when invalid."""
    v = (value or "indic-auto").strip()
    if v == "indic-auto":
        return v
    codes = [c.strip() for c in v.split(",") if c.strip()]
    if 1 <= len(codes) <= 4 and len(set(codes)) == len(codes) and all(c in config.LANGUAGES for c in codes):
        return ",".join(codes)
    return None


def parse_stream_language(value: str | None) -> str | None:
    """Realtime streaming takes exactly one code or 'indic-auto' (a list closes the socket with 1008)."""
    v = parse_stt_language(value)
    return v if v and "," not in v else None


def parse_warn_language(value: str | None) -> str:
    """A supported code, else 'auto' (= the call's dominant language)."""
    return value if value in config.LANGUAGES else "auto"


def find_demo(demo_id: str | None) -> dict | None:
    for d in config.load_demos():
        if d["id"] == demo_id:
            return d
    return None


def resolve_warn_language(warn: str, monitor: CallMonitor) -> str:
    return warn if warn in config.LANGUAGES else alerts.resolve_language(monitor.dominant_language())


def template_summary(monitor: CallMonitor, warn: str) -> dict:
    """summarize()'s shape from the handwritten templates only (used when the LLM summary is too slow)."""
    lang = resolve_warn_language(warn, monitor)
    a = monitor.assessment
    verdict = {"danger": "scam", "caution": "suspicious"}.get(a.level, "safe")
    text, advice = summary.template(verdict, list(a.categories), lang)
    return {"verdict": verdict, "score": a.score, "categories": list(a.categories), "summary": text,
            "advice": advice, "language": lang, "share_text": summary.share_text(verdict, a.score, text, advice, lang)}


async def safe_summary(monitor: CallMonitor, warn: str, summarize=None, timeout: float | None = None) -> dict:
    """summarize() with a time budget; template fallback on timeout or error."""
    summarize = summarize or summary.summarize
    try:
        return await asyncio.wait_for(summarize(monitor, warn), SUMMARY_TIMEOUT_S if timeout is None else timeout)
    except Exception as e:  # noqa: BLE001 - the summary must always arrive
        log.warning("summary failed (%s); using template", type(e).__name__)
        return template_summary(monitor, warn)


def risk_message(a: Assessment) -> dict:
    return {"type": "risk", **asdict(a)}


# ---------------------------------------------------------------- alert policy

class AlertPolicy:
    """Decides when to interrupt: at most one alert per category per call, at least `gap_s` between
    alerts, and one danger alert may pre-empt the gap (once per call)."""

    def __init__(self, gap_s: float = ALERT_GAP_S):
        self.gap_s = gap_s
        self.sent: list[str] = []        # categories already alerted, in order
        self.pending: list[str] = []     # wanted an alert but were held back by the gap
        self.last_at: float | None = None
        self.last_level = "safe"         # highest level alerted so far
        self.preempt_used = False

    def blocked(self, now: float) -> bool:
        return self.last_at is not None and now - self.last_at < self.gap_s

    def next_allowed(self) -> float:
        return (self.last_at or 0.0) + self.gap_s

    def decide(self, level: str, new: list[str], fallback: list[str], now: float) -> tuple[str, str] | None:
        """level: current call level. new: categories just flagged, best first. fallback: the
        assessment's categories (used when the level rose with nothing new). -> (category, level) or None."""
        if LEVEL_RANK.get(level, 0) < 1:
            return None
        fresh = [c for c in dict.fromkeys(new) if c not in self.sent and c not in self.pending]
        self.pending = fresh + self.pending      # what was just said goes first, held-back ones after
        rose = LEVEL_RANK[level] > LEVEL_RANK[self.last_level]
        if not self.pending:
            if not rose:
                return None
            cand = next((c for c in fallback if c not in self.sent), GENERIC)
            if cand in self.sent:
                return None
            self.pending.append(cand)
        if self.blocked(now):
            if level == "danger" and not self.preempt_used:
                self.preempt_used = True
            else:
                return None
        cand = self.pending.pop(0)
        self.sent.append(cand)
        self.last_at = now
        if LEVEL_RANK[level] > LEVEL_RANK[self.last_level]:
            self.last_level = level
        return cand, level


# ---------------------------------------------------------------- the session

class ListenSession:
    def __init__(self, send: Send, *, stream_factory: StreamFactory | None = None,
                 monitor: CallMonitor | None = None, alert_audio=None, summarize=None,
                 clock: Callable[[], float] | None = None):
        self._send_raw = send
        self._stream_factory = stream_factory or open_stream
        self.monitor = monitor or CallMonitor()
        self._alert_audio = alert_audio or alerts.alert_audio
        self._summarize = summarize or summary.summarize
        self._clock = clock
        self.policy = AlertPolicy(ALERT_GAP_S)
        self.settle_s, self.max_session_s = SETTLE_S, MAX_SESSION_S

        self.stream: StreamBase | None = None
        self.mock = False
        self.source = "mic"
        self.warn_language = "auto"
        self.closed = False              # the client socket is gone: stop sending
        self.end_reason: str | None = None   # stop | disconnect | stream | cap | None (never started)

        self._send_lock = asyncio.Lock()
        self._reader: asyncio.Task | None = None
        self._llm_task: asyncio.Task | None = None
        self._llm_again = False
        self._recheck: asyncio.Task | None = None
        self._alert_tasks: set[asyncio.Task] = set()
        self._stream_done = asyncio.Event()
        self._stream_dead = False
        self._finishing = False
        self._frame_warned = False
        self._n_transcripts = 0
        self._last_transcript_at = 0.0
        self._risk_score = -1
        self._t0 = 0.0

    def now(self) -> float:
        return self._clock() if self._clock else asyncio.get_running_loop().time()

    async def send(self, msg: dict) -> bool:
        if self.closed:
            return False
        try:
            async with self._send_lock:
                await self._send_raw(msg)
            return True
        except Exception:  # noqa: BLE001 - socket closed under us
            self.closed = True
            return False

    async def _fail(self, message: str) -> None:
        await self.send({"type": "error", "message": message, "fatal": True})

    # -- lifecycle

    async def run(self, receive: Receive) -> None:
        try:
            start = await self._read_start(receive)
            if start is None or not await self._open(start):
                return
            self.end_reason = await self._pump(receive)
            await self._finish()
        finally:
            await self._cleanup()

    async def _read_start(self, receive: Receive) -> dict | None:
        try:
            msg = await asyncio.wait_for(receive(), START_TIMEOUT_S)
        except asyncio.TimeoutError:
            await self._fail("No start message received.")
            return None
        except Exception:  # noqa: BLE001
            msg = None
        if msg is None:
            self.closed = True
            return None
        data = None
        if isinstance(msg, str):
            try:
                data = json.loads(msg)
            except ValueError:
                pass
        if not isinstance(data, dict) or data.get("type") != "start":
            await self._fail('The first message must be {"type": "start", ...}.')
            return None
        source = data.get("source") or "mic"
        if source not in ("mic", "demo"):
            await self._fail(f"Unknown source {source!r}; use 'mic' or 'demo'.")
            return None
        demo = None
        if source == "demo":
            demo = find_demo(data.get("demo_id"))
            if demo is None:
                await self._fail(f"Unknown demo id {data.get('demo_id')!r}.")
                return None
        language = parse_stream_language(data.get("language"))
        if language is None:
            await self._fail("language must be 'indic-auto' or one language code like 'hi-IN'.")
            return None
        if demo is not None:
            language = demo["language"]      # demos stream in their own language (indic-auto mishears phone audio)
        return {"source": source, "demo": demo, "language": language,
                "warn_language": parse_warn_language(data.get("warn_language"))}

    async def _open(self, start: dict) -> bool:
        self.source, self.warn_language = start["source"], start["warn_language"]
        cfg = StreamConfig(language=start["language"], fmt="codemix", keyterms=list(config.SCAM_KEYTERMS),
                           telephony=start["source"] == "demo", idle_timeout=IDLE_TIMEOUT_S)
        self.mock = config.gnani_mock()
        lines = None
        if self.mock:
            mock_demo = start["demo"] or find_demo(MIC_MOCK_DEMO)
            lines = mock_lines_for(mock_demo) if mock_demo else []
        self.stream = self._stream_factory(cfg, lines)
        try:
            await self.stream.open()
        except GnaniError as e:
            await self._fail(f"Could not start Gnani speech-to-text: {e.message}")
            return False
        except Exception as e:  # noqa: BLE001
            log.warning("stream open failed: %s", e)
            await self._fail("Could not start speech-to-text.")
            return False
        self._t0 = self.now()
        await self.send({"type": "ready", "mock": self.mock})
        self._reader = asyncio.create_task(self._read_events())
        return True

    async def _pump(self, receive: Receive) -> str:
        """Forward audio until stop / disconnect / the stream dies / the 15-minute cap."""
        deadline = self._t0 + self.max_session_s
        stream_wait = asyncio.create_task(self._stream_done.wait())
        recv: asyncio.Task | None = None
        try:
            while True:
                left = deadline - self.now()
                if left <= 0:
                    await self.send({"type": "error", "fatal": False,
                                     "message": "Reached the 15-minute limit for one check."})
                    return "cap"
                if recv is None:
                    recv = asyncio.create_task(receive())
                done, _ = await asyncio.wait({recv, stream_wait}, timeout=left,
                                             return_when=asyncio.FIRST_COMPLETED)
                if recv in done:
                    task, recv = recv, None
                    try:
                        msg = task.result()
                    except Exception:  # noqa: BLE001
                        msg = None
                    if msg is None:
                        self.closed = True
                        return "disconnect"
                    if isinstance(msg, (bytes, bytearray)):
                        await self._feed(bytes(msg))
                    elif _is_stop(msg):
                        return "stop"
                elif stream_wait in done:
                    return "stream"
        finally:
            stream_wait.cancel()
            if recv is not None:
                recv.cancel()

    async def _feed(self, frame: bytes) -> None:
        if len(frame) != FRAME_BYTES:
            if not self._frame_warned:
                self._frame_warned = True
                await self.send({"type": "error", "fatal": False,
                                 "message": f"Audio frames must be exactly {FRAME_BYTES} bytes (16 kHz s16le mono)."})
            return
        try:
            await self.stream.send_frame(frame)
        except Exception as e:  # noqa: BLE001 - a dead stream reports itself through events()
            log.debug("send_frame failed: %s", e)

    async def _finish(self) -> None:
        self._finishing = True
        if not self._stream_dead:
            try:
                await self.stream.commit()
            except Exception:  # noqa: BLE001
                pass
            if not self.closed:
                await self._settle()
        await self._stop_stream()
        for t in (self._recheck, self._llm_task):
            if t and not t.done():
                t.cancel()
        if self._alert_tasks and not self.closed:
            await asyncio.wait(set(self._alert_tasks), timeout=ALERT_WAIT_S)
        if self.closed:
            return
        result = await safe_summary(self.monitor, self.warn_language, self._summarize)
        await self.send({"type": "summary", **result})

    async def _settle(self) -> None:
        """Wait <= settle_s for transcripts still on the way after commit."""
        lines = getattr(self.stream, "lines", None)          # MockStream: nothing more is coming
        if isinstance(lines, list) and self._n_transcripts >= len(lines):
            return
        mark, deadline = self._n_transcripts, self.now() + self.settle_s
        while self.now() < deadline and not self._stream_done.is_set():
            if self._n_transcripts > mark and self.now() - self._last_transcript_at >= QUIET_S:
                return
            await asyncio.sleep(0.05)

    async def _stop_stream(self) -> None:
        if self.stream is not None:
            try:
                await self.stream.close()
            except Exception:  # noqa: BLE001
                pass
        if self._reader and not self._reader.done():
            try:
                await asyncio.wait_for(asyncio.shield(self._reader), 1.0)
            except (asyncio.TimeoutError, Exception):  # noqa: BLE001
                self._reader.cancel()

    async def _cleanup(self) -> None:
        tasks = [t for t in (self._reader, self._recheck, self._llm_task, *self._alert_tasks) if t and not t.done()]
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if self.stream is not None:
            try:
                await self.stream.close()
            except Exception:  # noqa: BLE001
                pass

    # -- transcripts

    async def _read_events(self) -> None:
        try:
            async for ev in self.stream.events():
                kind = ev.get("type")
                if kind == "transcript":
                    await self._on_transcript(ev)
                elif kind == "error":
                    fatal = bool(ev.get("fatal"))
                    if fatal:
                        self._stream_dead = True
                    if not self._finishing:
                        await self.send({"type": "error", "message": str(ev.get("message") or "Speech stream error"),
                                         "fatal": fatal})
                    if fatal:
                        break
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            log.warning("stream reader failed: %s", e)
            self._stream_dead = True
            if not self._finishing:
                await self._fail("The speech-to-text stream failed.")
        finally:
            self._stream_done.set()

    async def _on_transcript(self, ev: dict) -> None:
        text = str(ev.get("text") or "").strip()
        if not text:
            return
        flags, a = self.monitor.add(text, ev.get("language"))
        u = self.monitor.transcript[-1]
        self._n_transcripts += 1
        self._last_transcript_at = self.now()
        await self.send({"type": "transcript", "index": u["index"], "text": u["text"], "language": u["language"],
                         "flags": [{k: f[k] for k in ("category", "phrase", "start", "end")} for f in u["flags"]]})
        self._risk_score = a.score
        await self.send(risk_message(a))
        new = []
        for f in sorted(flags, key=lambda f: -f.weight):
            if f.category not in new:
                new.append(f.category)
        self._maybe_alert(a, new)
        if len(self.monitor.transcript) >= 2:
            self._kick_llm()

    # -- alerts

    def _maybe_alert(self, a: Assessment, new: list[str]) -> None:
        if self._finishing:
            return
        decision = self.policy.decide(a.level, new, list(a.categories), self.now())
        if decision:
            task = asyncio.create_task(self._deliver_alert(*decision))
            self._alert_tasks.add(task)
            task.add_done_callback(self._alert_tasks.discard)
        elif self.policy.pending and self.policy.blocked(self.now()) and self._recheck is None:
            self._recheck = asyncio.create_task(self._recheck_later(self.policy.next_allowed() - self.now()))

    async def _recheck_later(self, delay: float) -> None:
        await asyncio.sleep(max(0.0, delay) + 0.01)
        self._recheck = None
        self._maybe_alert(self.monitor.assessment, [])

    async def _deliver_alert(self, category: str, level: str) -> None:
        """Background: TTS the warning (never blocks the transcript loop), then send it."""
        lang = resolve_warn_language(self.warn_language, self.monitor)
        text = alerts.alert_text(category, level, lang)
        audio = None
        try:
            audio = await self._alert_audio(text, lang)
        except Exception as e:  # noqa: BLE001
            log.warning("alert audio failed: %s", e)
        await self.send({"type": "alert", "level": level, "category": category, "text": text, "language": lang,
                         "audio_b64": base64.b64encode(audio).decode("ascii") if audio else None})

    # -- LLM review (debounced, single flight)

    def _kick_llm(self) -> None:
        if self._finishing:
            return
        if self._llm_task and not self._llm_task.done():
            self._llm_again = True       # run once more when the current review returns
            return
        self._llm_task = asyncio.create_task(self._llm_loop())

    async def _llm_loop(self) -> None:
        while True:
            self._llm_again = False
            try:
                a = await self.monitor.llm_review()
            except Exception as e:  # noqa: BLE001
                log.warning("LLM review failed: %s", e)
                a = None
            if self._finishing:
                return
            if a is not None and a.score > self._risk_score:
                self._risk_score = a.score
                await self.send(risk_message(a))
                self._maybe_alert(a, [c for c in a.categories if c not in self.policy.sent])
            if not self._llm_again:
                return


def _is_stop(msg: str) -> bool:
    try:
        data = json.loads(msg)
    except ValueError:
        return False
    return isinstance(data, dict) and data.get("type") == "stop"
