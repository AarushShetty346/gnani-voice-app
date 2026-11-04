"""Make the demo call audio with Gnani Timbre v3.0 (needs GNANI_API_KEY; spends TTS credits).

For each demo in demo/scripts.json: TTS every line with its speaker's voice in the demo language
(16 kHz), join the lines with short pauses, make it sound like a phone line (8 kHz band-limited +
light hiss, unless --clean), and write demo/audio/<id>.wav plus demo/audio/manifest.json
({id: {"duration_s", "lines": [{"offset_s", "end_s"}]}}), which the app uses for line timing.

Run:  .venv\\Scripts\\python scripts\\make_demo_audio.py [--only ID ...] [--force] [--clean] [--dry-run]

Line clips are cached in .cache/demo_tts/, so re-running (e.g. with --force or --clean) only pays
for lines whose text or voice changed.
"""
import argparse
import asyncio
import hashlib
import io
import json
import sys
import wave
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import audio, config, gnani  # noqa: E402

RATE = 16000
LEAD_S = 1.6      # silence before the first line
GAP_S = 0.8       # pause between lines
TAIL_S = 2.3      # silence after the last line, so the realtime VAD closes the final segment


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(config.ROOT))
    except ValueError:
        return str(path)


def clip_cache(text: str, voice: str, language: str) -> Path:
    key = hashlib.sha256(f"timbre-v3.0|{voice}|{language}|{RATE}|{text}".encode("utf-8")).hexdigest()
    return config.CACHE_DIR / "demo_tts" / f"{key}.wav"


async def tts_line(text: str, voice: str, language: str) -> tuple[bytes, bool]:
    """(wav, spent_credits)"""
    path = clip_cache(text, voice, language)
    if path.exists():
        return path.read_bytes(), False
    wav = await gnani.tts(text, voice=voice, language=language, sample_rate=RATE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(wav)
    return wav, True


def pad(wav: bytes, lead_s: float, tail_s: float) -> bytes:
    """Add silence before and after (16 kHz mono s16 WAV out)."""
    pcm = audio.to_pcm16(wav, RATE)
    silence = lambda s: b"\x00\x00" * int(s * RATE)  # noqa: E731
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes(silence(lead_s) + pcm + silence(tail_s))
    return buf.getvalue()


async def build(demo: dict, clean: bool) -> dict:
    wavs = []
    for i, line in enumerate(demo["lines"], 1):
        voice = demo["voices"][line["speaker"]]
        wav, paid = await tts_line(line["text"], voice, demo["language"])
        print(f"  {i}/{len(demo['lines'])} {voice:8s} {'TTS' if paid else 'cache'}  {line['text'][:60]}")
        wavs.append(wav)
    joined, spans = audio.concat_wavs(wavs, gap_s=GAP_S, rate=RATE)
    out = pad(joined, LEAD_S, TAIL_S)
    if not clean:
        out = audio.phone_line(out)
    duration = audio.duration_s(out)
    path = config.DEMO_DIR / "audio" / f"{demo['id']}.wav"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(out)
    print(f"  -> {_rel(path)} ({duration:.1f} s)")
    return {"duration_s": round(duration, 3),
            "lines": [{"offset_s": round(s + LEAD_S, 3), "end_s": round(e + LEAD_S, 3)} for s, e in spans]}


async def main() -> int:
    ap = argparse.ArgumentParser(description="Make demo call audio with Gnani Timbre v3.0.")
    ap.add_argument("--only", nargs="+", metavar="ID", help="only these demo ids")
    ap.add_argument("--force", action="store_true", help="rebuild even if demo/audio/<id>.wav exists")
    ap.add_argument("--clean", action="store_true", help="skip the phone-line effect")
    ap.add_argument("--dry-run", action="store_true", help="only print what would be generated")
    args = ap.parse_args()

    demos = config.load_demos()
    if args.only:
        unknown = set(args.only) - {d["id"] for d in demos}
        if unknown:
            print("Unknown demo ids:", ", ".join(sorted(unknown)))
            return 2
        demos = [d for d in demos if d["id"] in args.only]
    audio_dir = config.DEMO_DIR / "audio"
    todo = [d for d in demos if args.force or not (audio_dir / f"{d['id']}.wav").exists()]
    calls = sum(1 for d in todo for line in d["lines"]
                if not clip_cache(line["text"], d["voices"][line["speaker"]], d["language"]).exists())
    print(f"{len(todo)} demo(s) to build, {calls} TTS call(s) to Gnani Timbre v3.0 "
          f"({sum(len(d['lines']) for d in todo) - calls} line(s) cached).")
    if not todo or args.dry_run:
        return 0
    if calls and config.gnani_mock():
        print("No GNANI_API_KEY in .env: cannot call Timbre. Copy .env.example to .env and add your key.")
        return 2

    manifest_path = audio_dir / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        manifest = {}
    for demo in todo:
        print(f"{demo['id']} ({demo['language']})")
        try:
            manifest[demo["id"]] = await build(demo, args.clean)
        except (gnani.GnaniError, audio.AudioError) as e:
            print(f"  failed: {e}")
            return 1
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {_rel(manifest_path)}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
