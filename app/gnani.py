"""Async client for Gnani REST speech APIs: Prisma v3.0 STT and Timbre v3.0 TTS.

Gnani allows only 1 active REST request per account, so every call goes through one
process-wide asyncio.Lock, and 429 / 5xx / network errors are retried with backoff.
With no GNANI_API_KEY (mock mode) nothing is sent and canned results come back.
"""
import asyncio
import io
import json
import wave

import httpx

from app import config

BASE_URL = "https://api.vachana.ai"
TIMEOUT = 60.0
BACKOFF = (0.5, 1.0, 2.0)              # sleep before retry 1, 2, 3
RETRY_STATUS = {429, 500, 502, 503, 504}

# Tests inject an httpx.MockTransport here; None means the real network.
_transport: httpx.AsyncBaseTransport | None = None

_lock: asyncio.Lock | None = None
_lock_loop: asyncio.AbstractEventLoop | None = None


class GnaniError(Exception):
    def __init__(self, status: int, code: str | None, message: str):
        super().__init__(f"Gnani {status} {code}: {message}" if code else f"Gnani {status}: {message}")
        self.status = status       # HTTP status, 0 for network errors
        self.code = code           # e.g. RATE_LIMITED, INVALID_API_KEY, INVALID_FORMAT
        self.message = message


def mock_mode() -> bool:
    return config.gnani_mock()


def _get_lock() -> asyncio.Lock:
    """One lock per event loop (pytest and uvicorn reloads create new loops)."""
    global _lock, _lock_loop
    loop = asyncio.get_running_loop()
    if _lock is None or _lock_loop is not loop:
        _lock, _lock_loop = asyncio.Lock(), loop
    return _lock


def parse_error(status: int, body: bytes | str) -> GnaniError:
    """Build a GnaniError from any of Gnani's error body shapes."""
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    code, message = None, text.strip()[:300] or f"HTTP {status}"
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, dict):
        detail, err = data.get("detail"), data.get("error")
        if isinstance(detail, dict):                  # auth / rate limit
            code, message = detail.get("error_code"), detail.get("message") or message
        elif isinstance(detail, list):                # 422 validation
            code = "VALIDATION_ERROR"
            message = "; ".join(str(d.get("msg", d)) if isinstance(d, dict) else str(d) for d in detail)
        elif isinstance(err, dict):                   # STT envelope
            code, message = err.get("type"), err.get("message") or message
        else:                                         # TTS flat body, 504 body
            code = data.get("code") or (err if isinstance(err, str) else None)
            message = data.get("message") or message
    return GnaniError(status, code, message)


async def _request(method: str, path: str, **kwargs) -> httpx.Response:
    headers = {"X-API-Key-ID": config.gnani_key()}
    async with _get_lock():
        async with httpx.AsyncClient(base_url=BASE_URL, timeout=TIMEOUT, transport=_transport) as client:
            for attempt in range(len(BACKOFF) + 1):
                last = attempt == len(BACKOFF)
                try:
                    r = await client.request(method, path, headers=headers, **kwargs)
                except httpx.TransportError as e:
                    if last:
                        raise GnaniError(0, "NETWORK_ERROR", f"{type(e).__name__}: {e}") from e
                else:
                    if r.status_code < 400:
                        return r
                    if last or r.status_code not in RETRY_STATUS:
                        raise parse_error(r.status_code, r.content)
                await asyncio.sleep(BACKOFF[attempt])
    raise AssertionError("unreachable")


async def stt(audio: bytes, filename: str = "clip.wav", language: str = "indic-auto", fmt: str = "codemix",
              keyterms: list[str] | None = None) -> dict:
    """Transcribe one clip (max 30 s). Returns the API JSON (transcript, detected_language_code, ...)."""
    if mock_mode():
        return {"transcript": "", "detected_language_code": None, "mock": True}
    data = {"model": "prisma-v3.0", "language_code": language, "format": fmt}
    if keyterms:
        data["keyterms"] = json.dumps(keyterms, ensure_ascii=False)
    r = await _request("POST", "/stt/v3", data=data, files={"audio_file": (filename, audio)})
    try:
        return r.json()
    except ValueError as e:
        raise GnaniError(r.status_code, "BAD_RESPONSE", "STT response was not JSON") from e


async def tts(text: str, voice: str = "Shivani", language: str = "auto", model: str = "timbre-v3.0",
              speed: float = 1.0, sample_rate: int = 24000) -> bytes:
    """Synthesize speech. Returns mono 16-bit WAV bytes (silence in mock mode)."""
    if mock_mode():
        return silent_wav(0.3, sample_rate)
    body = {
        "text": text, "voice": voice, "model": model, "language": language, "speed": speed,
        "audio_config": {"sample_rate": sample_rate, "num_channels": 1, "sample_width": 2,
                         "encoding": "linear_pcm", "container": "wav"},
    }
    r = await _request("POST", "/api/v1/tts/inference", json=body)
    return r.content


def silent_wav(seconds: float, rate: int = 16000) -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(b"\x00\x00" * int(rate * seconds))
    return buf.getvalue()
