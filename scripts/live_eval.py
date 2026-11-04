"""Live end-to-end check: stream each demo call through Gnani realtime STT and the detector.

Costs credits (about 2.5 min of streaming for all 5 demos). Needs GNANI_API_KEY and demo/audio/.
Run:  .venv\\Scripts\\python -X utf8 scripts\\live_eval.py [demo_id ...] [--lang kn-IN]

Note: realtime streaming takes exactly one language_code (or indic-auto); a list like
"kn-IN,en-IN" closes the socket with 1008. indic-auto misheard Kannada phone audio as
Hindi/Marathi in our tests, so demos stream with their own language.
"""
import argparse
import asyncio
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import audio, config  # noqa: E402
from app.detector import CallMonitor  # noqa: E402
from app.gnani_stream import GnaniStream, StreamConfig  # noqa: E402

FRAME_S = 512 / 16000


async def run(demo: dict, lang: str | None) -> bool:
    wav = (config.DEMO_DIR / "audio" / f"{demo['id']}.wav").read_bytes()
    frames = audio.pcm_frames(audio.to_pcm16(wav))
    cfg = StreamConfig(language=lang or demo["language"], fmt="codemix", telephony=True,
                       keyterms=config.SCAM_KEYTERMS)
    monitor, first_danger, lines = CallMonitor(), None, []
    async with GnaniStream(cfg) as stream:
        t0 = time.monotonic()

        async def send():
            for i, frame in enumerate(frames):          # real-time cadence, no drift
                await stream.send_frame(frame)
                delay = t0 + (i + 1) * FRAME_S - time.monotonic()
                if delay > 0:
                    await asyncio.sleep(delay)
            await stream.commit()

        async def receive():
            nonlocal first_danger
            async for ev in stream.events():
                if ev["type"] == "transcript":
                    _, a = monitor.add(ev["text"], ev.get("language"))
                    t = time.monotonic() - t0
                    lines.append(f"   {t:5.1f}s [{ev.get('language')}] {a.level:7} {a.score:3}  {ev['text']}")
                    if a.level == "danger" and first_danger is None:
                        first_danger = t
                elif ev["type"] == "error":
                    lines.append(f"   ERROR {ev['message']}")
                    if ev.get("fatal"):
                        return

        receiver = asyncio.create_task(receive())
        await send()
        await asyncio.sleep(3.0)                          # trailing transcripts
        receiver.cancel()
    a = monitor.assessment
    ok = (a.level == "danger") == (demo["label"] == "scam")
    when = f"{first_danger:.1f}s" if first_danger else "never"
    print(f"{'PASS' if ok else 'FAIL'} {demo['id']} ({cfg.language}, {len(frames) * FRAME_S:.0f}s): "
          f"{a.level} {a.score} {a.categories} | first danger {when}")
    print("\n".join(lines), flush=True)
    return ok


async def main():
    p = argparse.ArgumentParser()
    p.add_argument("ids", nargs="*")
    p.add_argument("--lang", help="override language_code for every demo")
    args = p.parse_args()
    if config.gnani_mock():
        sys.exit("No GNANI_API_KEY in .env")
    demos = [d for d in config.load_demos() if not args.ids or d["id"] in args.ids]
    results = [await run(d, args.lang) for d in demos]
    print(f"\n{sum(results)}/{len(results)} demos correct on live Prisma realtime")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    asyncio.run(main())
