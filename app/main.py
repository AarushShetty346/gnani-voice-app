"""ScamLingo web app: live call shield (WS /ws/listen), demo calls, and "check a recording".

Run:  .venv\\Scripts\\python -m uvicorn app.main:app --port 8000
Open: http://localhost:8000
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import asdict
from typing import Awaitable, Callable

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app import audio, config, gnani, llm
from app.detector import CallMonitor
from app.gnani_stream import line_timings
from app.session import (MIC_MOCK_DEMO, ListenSession, find_demo, parse_stt_language, parse_warn_language,
                         safe_summary)

log = logging.getLogger(__name__)

MAX_UPLOAD_BYTES = 25 * 1024 * 1024   # /api/analyze upload limit
MAX_DURATION_S = 10 * 60              # longer recordings would burn too many STT credits
CHUNK_S = 25.0                        # Prisma REST takes <= 30 s per request (split_wav may reach 26 s)
MULTIPART_SLACK = 64 * 1024           # form fields + multipart framing on top of the file itself
LLM_REVIEW_TIMEOUT_S = 25.0

STATIC_DIR = config.ROOT / "static"

app = FastAPI(title="ScamLingo", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def reject_huge_uploads(request: Request, call_next):
    """Refuse an oversized /api/analyze upload from its Content-Length, before the body is spooled."""
    if request.url.path == "/api/analyze":
        try:
            size = int(request.headers.get("content-length") or 0)
        except ValueError:
            size = 0
        if size > MAX_UPLOAD_BYTES + MULTIPART_SLACK:
            return JSONResponse({"detail": f"The file is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."},
                                status_code=413)
    return await call_next(request)


def _demo_audio_path(demo_id: str):
    return config.DEMO_DIR / "audio" / f"{demo_id}.wav"


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})


@app.api_route("/demo-audio/{name}", methods=["GET", "HEAD"], include_in_schema=False)
def demo_audio(name: str):
    """Only <id>.wav for ids in demo/scripts.json; the path is built from the id, never from user input."""
    demo = find_demo(name[:-4]) if name.endswith(".wav") else None
    path = _demo_audio_path(demo["id"]) if demo else None
    if path is None or not path.is_file():
        raise HTTPException(404, "No such demo audio.")
    return FileResponse(path, media_type="audio/wav")


@app.get("/api/status")
def status():
    demos = config.load_demos()
    return {"gnani_mock": config.gnani_mock(), "llm_mock": not llm.configured(),
            "demo_audio": bool(demos) and all(_demo_audio_path(d["id"]).is_file() for d in demos),
            "languages": config.LANGUAGES}


@app.get("/api/demos")
def demos():
    out = []
    for d in config.load_demos():
        timings = line_timings(d)
        out.append({
            "id": d["id"], "title": d["title"], "title_native": d.get("title_native") or d["title"],
            "language": d["language"], "label": d["label"], "categories": d.get("categories", []),
            "has_audio": _demo_audio_path(d["id"]).is_file(),
            "lines": [{"speaker": line["speaker"], "text": line["text"], "offset_s": start, "end_s": end}
                      for line, (start, end) in zip(d["lines"], timings)],
        })
    return out


_SENTENCE_END = re.compile(r"(?<=[.!?।॥])\s+")


def _sentences(text: str) -> list[tuple[int, str]]:
    """(char_offset, sentence) pieces of one chunk transcript, so the UI shows readable bubbles."""
    out, pos = [], 0
    for piece in _SENTENCE_END.split(text):
        idx = text.find(piece, pos)
        if piece.strip():
            out.append((max(idx, 0), piece.strip()))
        pos = max(idx, 0) + len(piece)
    return out


async def _read_upload(upload: UploadFile) -> bytes:
    raw = await upload.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"The file is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
    if not raw:
        raise HTTPException(400, "The file is empty.")
    return raw


class ClientGone(Exception):
    """The browser aborted /api/analyze; stop spending STT credits on it."""


async def _transcribe(wav: bytes, language: str,
                      gone: Callable[[], Awaitable[bool]] | None = None) -> list[tuple[float, str, str | None]]:
    """Live mode: ~25 s chunks, one REST STT call each, strictly one after another. Before each call,
    `gone()` is asked whether the client disconnected (Starlette doesn't cancel the handler for us)."""
    chunks = await asyncio.to_thread(audio.split_wav, wav, CHUNK_S)
    rows = []
    for i, (start, chunk) in enumerate(chunks):
        if gone is not None and await gone():
            log.info("analyze: client went away after %d of %d chunks; stopping", i, len(chunks))
            raise ClientGone()
        try:
            res = await gnani.stt(chunk, f"chunk-{i}.wav", language=language, fmt="codemix",
                                  keyterms=list(config.SCAM_KEYTERMS))
        except gnani.GnaniError as e:
            raise HTTPException(502, f"Gnani speech-to-text failed: {e.message}") from e
        text = str(res.get("transcript") or "").strip()
        if not text:
            continue
        span = await asyncio.to_thread(audio.duration_s, chunk)
        lang = res.get("detected_language_code")
        for off, sentence in _sentences(text):
            rows.append((start + span * off / len(text), sentence, lang))
    return rows


def _mock_rows() -> list[tuple[float, str, str | None]]:
    demo = find_demo(MIC_MOCK_DEMO)
    return [(start, line["text"], demo["language"]) for line, (start, _) in zip(demo["lines"], line_timings(demo))]


@app.post("/api/analyze")
async def analyze(request: Request, audio_file: UploadFile = File(..., alias="audio"),
                  language: str = Form("indic-auto"), warn_language: str = Form("auto")):
    stt_lang = parse_stt_language(language)
    if stt_lang is None:
        raise HTTPException(400, "language must be 'indic-auto' or 1-4 codes like 'hi-IN,en-IN'.")
    warn = parse_warn_language(warn_language)
    raw = await _read_upload(audio_file)
    try:
        # Decode at most a little past the limit: a small low-bitrate file can hold hours of audio.
        wav = await asyncio.to_thread(audio.to_wav, raw, 16000, MAX_DURATION_S + 1)
        duration = await asyncio.to_thread(audio.duration_s, wav)
    except audio.AudioError as e:
        raise HTTPException(400, "Could not read this audio file. Try MP3, M4A, WAV, OGG or WebM.") from e
    if duration < 0.1:
        raise HTTPException(400, "The recording has no audio.")
    if duration > MAX_DURATION_S:
        raise HTTPException(400, f"The recording is longer than the {MAX_DURATION_S / 60:g}-minute limit "
                                 f"(it would use too many speech credits). Trim it and try again.")

    if config.gnani_mock():
        rows = _mock_rows()
    else:
        try:
            rows = await _transcribe(wav, stt_lang, request.is_disconnected)
        except ClientGone:
            return JSONResponse({"detail": "Cancelled."}, status_code=499)
    monitor = CallMonitor()
    transcript = []
    for start_s, text, lang in rows:
        monitor.add(text, lang)
        transcript.append({**monitor.transcript[-1], "start_s": round(start_s, 2)})
    if transcript and llm.configured():
        try:
            await asyncio.wait_for(monitor.llm_review(), LLM_REVIEW_TIMEOUT_S)
        except Exception as e:  # noqa: BLE001 - rules result stands
            log.warning("LLM review failed: %s", type(e).__name__)
    result = await safe_summary(monitor, warn)
    return {"transcript": transcript, "risk": asdict(monitor.assessment), "summary": result,
            "duration_s": round(duration, 2), "mock": config.gnani_mock()}


@app.websocket("/ws/listen")
async def ws_listen(ws: WebSocket):
    await ws.accept()

    async def receive():
        try:
            msg = await ws.receive()
        except (WebSocketDisconnect, RuntimeError):
            return None
        if msg.get("type") == "websocket.disconnect":
            return None
        if msg.get("bytes") is not None:
            return msg["bytes"]
        return msg.get("text") or ""

    session = ListenSession(ws.send_json)
    await session.run(receive)
    if not session.closed:
        try:
            await ws.close()
        except Exception:  # noqa: BLE001
            pass
