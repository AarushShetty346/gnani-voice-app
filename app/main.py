"""FastAPI app: mic audio in -> Prisma STT -> LLM -> Timbre TTS -> audio out.

Run:  .venv\\Scripts\\python -m uvicorn app.main:app --reload
Open: http://localhost:8000
"""
import base64
import subprocess
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, File, Form, HTTPException, UploadFile  # noqa: E402
from fastapi.responses import FileResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402

from app import gnani, llm  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(title="Gnani voice app")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


def to_wav16k(raw: bytes) -> bytes:
    """Browsers record webm/opus, which Prisma's REST API doesn't take. Convert with ffmpeg."""
    p = subprocess.run(
        ["ffmpeg", "-hide_banner", "-loglevel", "error", "-i", "pipe:0",
         "-ac", "1", "-ar", "16000", "-f", "wav", "pipe:1"],
        input=raw, capture_output=True)
    if p.returncode != 0:
        raise HTTPException(400, f"ffmpeg could not read the audio: {p.stderr.decode()[:200]}")
    return p.stdout


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/status")
def status():
    return {"gnani_mock": gnani.mock_mode(), "llm_mock": llm.mock_mode()}


@app.post("/api/talk")
async def talk(audio: UploadFile = File(...), language: str = Form("indic-auto"),
               voice: str = Form("Shivani")):
    wav = to_wav16k(await audio.read())
    heard = gnani.stt(wav, "clip.wav", language=language)
    text = heard.get("transcript", "")
    answer = llm.reply(text) if text else "Maaf kijiye, kuch sunai nahi diya."
    speech = gnani.tts(answer, voice=voice)
    return {
        "transcript": text,
        "detected_language": heard.get("detected_language_code"),
        "reply": answer,
        "audio_b64": base64.b64encode(speech).decode(),
        "mock": {"gnani": gnani.mock_mode(), "llm": llm.mock_mode()},
    }
