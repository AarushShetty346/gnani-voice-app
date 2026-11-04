"""Thin client for Gnani's speech APIs (Prisma STT, Timbre TTS).

Docs: https://docs.gnani.ai/api/introduction/quick-start
With no GNANI_API_KEY set, every call returns canned data so the app still runs.
"""
import json
import os

import httpx

BASE = "https://api.vachana.ai"
TIMEOUT = 60


def api_key() -> str:
    return os.getenv("GNANI_API_KEY", "").strip()


def mock_mode() -> bool:
    return not api_key()


def stt(audio: bytes, filename: str = "audio.wav", language: str = "indic-auto",
        fmt: str = "codemix", keyterms: list[str] | None = None) -> dict:
    """Transcribe a clip (max 30 s) with Prisma v3.0.

    fmt: verbatim | transcribe | codemix | transliterate
    Returns the API JSON: transcript, detected_language_code, ...
    """
    if mock_mode():
        return {"success": True, "transcript": "[mock] namaste, mera order kab aayega?",
                "detected_language_code": "hi-IN", "model": "mock"}
    data = {"model": "prisma-v3.0", "language_code": language, "format": fmt}
    if keyterms:
        data["keyterms"] = json.dumps(keyterms, ensure_ascii=False)
    r = httpx.post(f"{BASE}/stt/v3", headers={"X-API-Key-ID": api_key()},
                   files={"audio_file": (filename, audio)}, data=data, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


def tts(text: str, voice: str = "Shivani", language: str = "auto",
        model: str = "timbre-v3.0", speed: float = 1.0) -> bytes:
    """Synthesize speech. Returns WAV bytes.

    Timbre v3.0 voices speak all 10 languages and accept audio tags like <laugh>.
    """
    if mock_mode():
        return _silent_wav(0.5)
    body = {
        "text": text, "voice": voice, "model": model, "language": language, "speed": speed,
        "audio_config": {"sample_rate": 24000, "num_channels": 1, "sample_width": 2,
                         "encoding": "linear_pcm", "container": "wav"},
    }
    r = httpx.post(f"{BASE}/api/v1/tts/inference",
                   headers={"X-API-Key-ID": api_key(), "Content-Type": "application/json"},
                   json=body, timeout=TIMEOUT)
    r.raise_for_status()
    return r.content


def _silent_wav(seconds: float, rate: int = 16000) -> bytes:
    import io
    import wave
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(b"\x00\x00" * int(rate * seconds))
    return buf.getvalue()
