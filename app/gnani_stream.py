"""Realtime STT: Gnani Prisma v3.0 WebSocket stream, plus a timed mock for demos.

Both streams share one interface (StreamBase) and are async context managers:

    async with open_stream(StreamConfig(telephony=True), mock_lines) as s:
        await s.send_frame(frame)          # exactly 1024 bytes of s16le mono
        async for ev in s.events(): ...    # normalised dicts, see _normalise()

Besides the SPEC's events, GnaniStream also yields {"type": "speech_start"} and {"type": "empty"} (an
utterance that held no words), so a session can tell when no transcript is still on its way.
Realtime STT takes exactly ONE language code or "indic-auto": a list closes the socket with 1008.
"""
import asyncio
import json
from dataclasses import dataclass
from typing import AsyncIterator

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from app import config
from app.gnani import BACKOFF, GnaniError, parse_error

STREAM_URL = "wss://api.vachana.ai/stt/v3/stream"   # tests point this at a local fake server
FRAME_BYTES = 1024                                   # 512 samples s16le mono
OPEN_TIMEOUT_S = 8.0       # per handshake attempt; the browser waits longer (static/app.js CONNECT_TIMEOUT_MS)
CLOSE_TIMEOUT_S = 2.0      # don't hang on a slow close handshake when a call ends


@dataclass
class StreamConfig:
    language: str = "indic-auto"
    fmt: str = "codemix"
    sample_rate: int = 16000
    keyterms: list[str] | None = None
    telephony: bool = False       # VAD preset for noisy phone audio
    idle_timeout: int = 120       # seconds without speech before Gnani closes (5-900)


def build_headers(cfg: StreamConfig, key: str) -> dict[str, str]:
    """Upgrade headers carrying the whole session config."""
    h = {
        "x-api-key-id": key,
        "model": "prisma-v3.0",
        "language_code": cfg.language,
        "format": cfg.fmt,
        "x-sample-rate": str(cfg.sample_rate),
        "x-idle-timeout-sec": str(max(5, min(900, int(cfg.idle_timeout)))),
    }
    if cfg.keyterms:
        h["keyterms"] = json.dumps(cfg.keyterms, ensure_ascii=True)   # headers must be ASCII
    if cfg.telephony:
        h.update({"x-vad-threshold": "0.7", "x-min-speech-ms": "200", "x-min-silence-ms": "500"})
    return h


def _check_frame(frame: bytes) -> None:
    if len(frame) != FRAME_BYTES:
        raise ValueError(f"frame must be exactly {FRAME_BYTES} bytes, got {len(frame)}")


class StreamBase:
    # True when events() reports "speech_start"/"processing" for an utterance before its transcript,
    # so the session can tell "nothing more is coming" apart from "a transcript is still on its way".
    reports_speech = False

    async def __aenter__(self):
        await self.open()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def open(self) -> None: ...
    async def send_frame(self, frame: bytes) -> None: ...
    async def commit(self) -> None: ...
    async def close(self) -> None: ...

    def events(self) -> AsyncIterator[dict]:
        raise NotImplementedError


def _normalise(msg: dict) -> dict | None:
    """Map a Gnani server message to our event shape; None for messages we ignore."""
    kind = msg.get("type")
    if kind == "transcript":
        text = (msg.get("text") or "").strip()
        if not text:                 # VAD fired on noise: nothing to show, but the utterance is done
            return {"type": "empty"}
        return {"type": "transcript", "text": text, "language": msg.get("detected_language_code"),
                "index": int(msg.get("segment_index") or 0)}
    if kind == "error":
        # A server error alone may be recoverable; if the socket then dies, events() adds a fatal one.
        return {"type": "error", "message": str(msg.get("message") or "Gnani stream error"), "fatal": False}
    if kind in ("connected", "processing", "speech_start"):
        return {"type": kind}
    return None                      # settings_updated, ...


class GnaniStream(StreamBase):
    reports_speech = True

    def __init__(self, cfg: StreamConfig, url: str | None = None):
        self.cfg = cfg
        self.url = url or STREAM_URL
        self._ws = None
        self._closing = False

    async def open(self) -> None:
        """Connect. A handshake refused with 429 (rate limited) is retried with the REST backoff."""
        headers = build_headers(self.cfg, config.gnani_key())
        for attempt in range(len(BACKOFF) + 1):
            try:
                self._ws = await connect(self.url, additional_headers=headers,
                                         open_timeout=OPEN_TIMEOUT_S, close_timeout=CLOSE_TIMEOUT_S)
                return
            except InvalidStatus as e:   # handshake refused, e.g. 401 bad key / 429
                if e.response.status_code == 429 and attempt < len(BACKOFF):
                    await asyncio.sleep(BACKOFF[attempt])
                    continue
                raise parse_error(e.response.status_code, e.response.body or b"") from e
            except (OSError, asyncio.TimeoutError) as e:
                raise GnaniError(0, "NETWORK_ERROR", f"could not connect: {e}") from e

    async def send_frame(self, frame: bytes) -> None:
        _check_frame(frame)
        try:
            await self._ws.send(frame)
        except ConnectionClosed:
            pass                     # dropped; events() reports why the stream died

    async def commit(self) -> None:
        try:
            await self._ws.send(json.dumps({"type": "commit"}))
        except ConnectionClosed:
            pass

    async def events(self) -> AsyncIterator[dict]:
        seq = 0
        try:
            async for raw in self._ws:
                if isinstance(raw, bytes):
                    continue
                try:
                    ev = _normalise(json.loads(raw))
                except (ValueError, AttributeError):
                    continue
                if ev and ev["type"] == "transcript":
                    seq += 1
                    ev["index"] = ev["index"] or seq
                if ev:
                    yield ev
        except ConnectionClosed:
            pass
        if not self._closing:        # the server hung up on us (bad header, idle, 15 min cap, ...)
            code, reason = self._ws.close_code, self._ws.close_reason
            why = f"{code} {reason}".strip() if code is not None else "connection lost"
            yield {"type": "error", "message": f"Gnani stream closed ({why})", "fatal": True}

    async def close(self) -> None:
        self._closing = True
        if self._ws is not None:
            await self._ws.close()


class MockStream(StreamBase):
    """Emits scripted transcript lines on a wall-clock schedule; ignores audio."""

    def __init__(self, lines: list[tuple[float, str, str]]):
        self.lines = sorted(lines, key=lambda line: line[0])
        self._t0: float | None = None
        self._closed = asyncio.Event()

    async def open(self) -> None:
        self._t0 = asyncio.get_running_loop().time()

    async def send_frame(self, frame: bytes) -> None:
        _check_frame(frame)

    async def commit(self) -> None:
        pass

    async def events(self) -> AsyncIterator[dict]:
        loop = asyncio.get_running_loop()
        if self._t0 is None:
            self._t0 = loop.time()
        yield {"type": "connected"}
        for i, (offset, text, lang) in enumerate(self.lines, 1):
            delay = self._t0 + offset - loop.time()
            if delay > 0:
                try:
                    await asyncio.wait_for(self._closed.wait(), delay)
                except asyncio.TimeoutError:
                    pass
            if self._closed.is_set():
                return
            yield {"type": "transcript", "text": text, "language": lang, "index": i}
        await self._closed.wait()

    async def close(self) -> None:
        self._closed.set()


def open_stream(cfg: StreamConfig, mock_lines: list[tuple[float, str, str]] | None = None) -> StreamBase:
    """Real Gnani stream when a key is set, else a MockStream over mock_lines. Not yet opened."""
    return GnaniStream(cfg) if config.gnani_key() else MockStream(mock_lines or [])


def _load_manifest() -> dict:
    path = config.DEMO_DIR / "audio" / "manifest.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def line_timings(demo: dict, manifest: dict | None = None) -> list[tuple[float, float]]:
    """(start_s, end_s) per demo line: from the audio manifest when it matches, else estimated."""
    if manifest is None:
        manifest = _load_manifest()
    entry = manifest.get(demo["id"]) or {}
    lines = entry.get("lines") or []
    if len(lines) == len(demo["lines"]):
        return [(float(x["offset_s"]), float(x["end_s"])) for x in lines]
    out, t = [], 1.0                 # estimate: 1.0 s lead-in, 1.2 s + 65 ms/char per line, 0.6 s gaps
    for line in demo["lines"]:
        end = t + 1.2 + 0.065 * len(line["text"])
        out.append((round(t, 3), round(end, 3)))
        t = end + 0.6
    return out


def mock_lines_for(demo: dict, manifest: dict | None = None) -> list[tuple[float, str, str]]:
    """Mock transcript schedule for a demo. Each line arrives when its speaker finishes (end_s),
    like a real VAD-closed segment. manifest=None reads demo/audio/manifest.json if it exists."""
    timings = line_timings(demo, manifest)
    return [(end, line["text"], demo["language"]) for (_, end), line in zip(timings, demo["lines"])]
