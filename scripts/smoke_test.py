"""Check that your Gnani key works: Timbre v3.0 TTS of one Hindi line, then Prisma v3.0 STT back.

Run:  .venv\\Scripts\\python scripts\\smoke_test.py            # 2 REST calls (a few credits)
      .venv\\Scripts\\python scripts\\smoke_test.py --stream   # + streams the clip through the realtime
                                                              #   WebSocket at real-time speed
Writes smoke_test.wav in the current folder.
"""
import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import audio, config, gnani  # noqa: E402  (app.config loads .env)
from app.gnani_stream import FRAME_BYTES, GnaniStream, StreamConfig  # noqa: E402

TEXT = "नमस्ते! मैं बैंक से नहीं, ScamLingo से बोल रही हूँ। अपना OTP किसी को मत बताइए।"
FRAME_S = FRAME_BYTES / 2 / 16000          # 32 ms of 16 kHz s16le mono


async def rest_check(out: Path) -> bytes:
    print("TTS  ->", TEXT)
    t = time.perf_counter()
    wav = await gnani.tts(TEXT, voice="Shivani", language="hi-IN", sample_rate=16000)
    out.write_bytes(wav)
    print(f"     saved {out} ({len(wav):,} bytes, {audio.duration_s(wav):.1f} s) in {time.perf_counter() - t:.1f} s")

    print("STT  <-", out.name, "(REST, codemix)")
    t = time.perf_counter()
    res = await gnani.stt(wav, out.name, language="hi-IN,en-IN", fmt="codemix", keyterms=config.SCAM_KEYTERMS)
    print(f"     transcript: {res.get('transcript')!r}")
    print(f"     language:   {res.get('detected_language_code')}  ({time.perf_counter() - t:.1f} s)")
    return wav


async def stream_check(wav: bytes) -> int:
    """Send the clip through the realtime stream at real-time cadence; print transcripts as they arrive."""
    pcm = audio.to_pcm16(wav, 16000) + b"\x00" * 32000          # + 1 s of silence so VAD closes the segment
    frames = audio.pcm_frames(pcm, FRAME_BYTES)
    print(f"WS   -> {len(frames)} frames ({len(frames) * FRAME_S:.1f} s) to the realtime stream")
    got = 0
    t0 = time.perf_counter()
    # Realtime takes one language code (a list like "hi-IN,en-IN" closes the socket with 1008).
    async with GnaniStream(StreamConfig(language="hi-IN", keyterms=config.SCAM_KEYTERMS)) as stream:

        async def reader():
            nonlocal got
            async for ev in stream.events():
                if ev["type"] == "transcript":
                    got += 1
                    print(f"     [{time.perf_counter() - t0:5.1f} s] {ev['text']!r} ({ev['language']})")
                elif ev["type"] == "error":
                    print(f"     error: {ev['message']}" + (" (fatal)" if ev["fatal"] else ""))
                    if ev["fatal"]:
                        return
        task = asyncio.create_task(reader())
        for i, frame in enumerate(frames):
            await stream.send_frame(frame)
            await asyncio.sleep(max(0.0, t0 + (i + 1) * FRAME_S - time.perf_counter()))
        await stream.commit()
        try:
            await asyncio.wait_for(asyncio.shield(task), 5)
        except asyncio.TimeoutError:
            pass                                                 # the stream stays open; we're done
        task.cancel()
    return got


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--stream", action="store_true", help="also test the realtime WebSocket stream")
    ap.add_argument("--out", default="smoke_test.wav")
    args = ap.parse_args()
    if config.gnani_mock():
        print("No GNANI_API_KEY in .env yet. Copy .env.example to .env and paste your key.")
        return 2
    try:
        wav = await rest_check(Path(args.out))
        ok = True
        if args.stream:
            ok = await stream_check(wav) > 0
            print("     OK, realtime streaming works." if ok else "     No transcript from the stream.")
    except gnani.GnaniError as e:
        print(f"Gnani error: {e}")
        return 1
    print("Done.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
