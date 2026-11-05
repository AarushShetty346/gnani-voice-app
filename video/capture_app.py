"""Record one demo call in the real app: screen frames, the page's own audio, and every event.

    .venv\\Scripts\\python video\\capture_app.py digital-arrest --out video\\out\\cap\\digital-arrest
        [--url http://localhost:8000] [--warn en-IN|auto] [--hangup 1.0] [--light]

Runs headless Chrome at 540x675 CSS px x2 (1080x1350, the video's 4:5 frame). With a live server this
streams the call through Gnani Prisma and plays real Timbre warnings, so it spends credits.
--hangup N: N seconds after the first red alert finishes speaking, tap "Got it, I'll hang up", then Stop.
"""
import argparse
import asyncio
import base64
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cdp import Browser, Screencast  # noqa: E402

HERE = Path(__file__).resolve().parent
W, H, SCALE = 540, 675, 2


async def capture(a):
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    clicks = []
    async with Browser(HERE / "out" / "chrome-profile", port=a.port) as b:
        p = b.page
        await b.setup(W, H, SCALE, dark=not a.light)
        await p.send("Page.addScriptToEvaluateOnNewDocument", source=(HERE / "hook.js").read_text("utf-8"))
        await p.send("Page.navigate", url=a.url.rstrip("/") + "/?v=capture")
        await p.wait_for("document.querySelectorAll('.demo-card[data-id]').length >= 5", 20)
        await p.eval(f"(() => {{ const s = document.getElementById('warnLang'); s.value = {json.dumps(a.warn)};"
                     " s.dispatchEvent(new Event('change')); return s.value; })()")
        await p.click("#tab-demo")
        await p.eval("window.scrollTo(0, 0)")
        await asyncio.sleep(0.6)

        cast = Screencast(p, out / "frames", W * SCALE, H * SCALE)
        await cast.start()
        await asyncio.sleep(a.lead)
        sel = f".demo-card[data-id='{a.demo}'] .demo-play"
        clicks.append({"what": "play", **dict(zip(("x", "y", "t"), await p.click(sel)))})

        t_start = time.time()
        hung_up = False
        while time.time() - t_start < a.max_s:
            evs = await p.eval("window.__kv.events.filter(e => e.type === 'ws').map(e => [e.t, e.m.type, e.m.level || null])")
            if any(e[1] == "summary" for e in evs):
                break
            if a.hangup is not None and not hung_up:
                danger = [e for e in evs if e[1] == "alert" and e[2] == "danger"]
                if danger:
                    until = await p.eval("window.__kv.voiceUntil")
                    if until and time.time() * 1000 > until + a.hangup * 1000:
                        clicks.append({"what": "got-it", **dict(zip(("x", "y", "t"), await p.click("#alarmOk")))})
                        await asyncio.sleep(a.stop_gap)
                        clicks.append({"what": "stop", **dict(zip(("x", "y", "t"), await p.click("#stopBtn")))})
                        hung_up = True
            await asyncio.sleep(0.1)
        else:
            print("WARNING: no summary before --max-s")

        await asyncio.sleep(a.tail)                     # summary slides in; hold on it
        if a.scroll_share:
            # Bring the whole Share button into the frame, with a little room under it.
            await p.eval("(() => { const r = document.getElementById('shareWa').getBoundingClientRect();"
                         " window.scrollBy({top: r.bottom - document.documentElement.clientHeight + 20,"
                         " behavior: 'smooth'}); })()")
            await asyncio.sleep(2.5)
            print("share button:", await p.eval(
                "(() => { const r = document.getElementById('shareWa').getBoundingClientRect(); return"
                " {top: Math.round(r.top), bottom: Math.round(r.bottom), vh: document.documentElement.clientHeight,"
                " ih: innerHeight, y: Math.round(scrollY), max: document.documentElement.scrollHeight}; })()"))
        await cast.stop()

        audio_b64 = await p.eval("window.__kv.stopRec()")
        kv = await p.eval("({events: window.__kv.events, recStart: window.__kv.rec && window.__kv.rec.started})")
        summary = await p.eval("({verdict: document.getElementById('verdict').textContent,"
                               " score: document.getElementById('summaryScore').textContent,"
                               " text: document.getElementById('summaryText').textContent,"
                               " transcript: [...document.querySelectorAll('#transcript li')].map(l => l.innerText)})")

    if audio_b64:
        (out / "audio.webm").write_bytes(base64.b64decode(audio_b64))
    meta = {"demo": a.demo, "warn": a.warn, "size": [W * SCALE, H * SCALE], "clicks": clicks,
            "rec_start_ms": kv["recStart"], "events": kv["events"], "summary": summary}
    (out / "capture.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), "utf-8")
    frames = json.loads((out / "frames" / "frames.json").read_text())
    print(f"{a.demo}: {len(frames)} frames over {frames[-1]['t'] - frames[0]['t']:.1f}s, "
          f"audio {'yes' if audio_b64 else 'NO'}, verdict {summary['verdict']!r}")
    t0 = clicks[0]["t"] * 1000
    for e in kv["events"]:
        if e["type"] == "ws" and e["m"]["type"] in ("alert", "summary", "risk"):
            m = e["m"]
            extra = m.get("level") or m.get("verdict") or ""
            if m["type"] == "risk":
                extra = f"{m.get('level')} {m.get('score')}"
            print(f"  {(e['t'] - t0) / 1000:6.2f}s {m['type']:8} {extra} {m.get('category', '')}")
        elif e["type"] == "source":
            print(f"  {(e['at'] - t0) / 1000:6.2f}s audio    {e['dur']:.2f}s clip")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("demo")
    ap.add_argument("--out", required=True)
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--warn", default="en-IN")
    ap.add_argument("--hangup", type=float, default=None)
    ap.add_argument("--stop-gap", type=float, default=0.9)
    ap.add_argument("--lead", type=float, default=1.5)
    ap.add_argument("--tail", type=float, default=5.0)
    ap.add_argument("--max-s", type=float, default=90)
    ap.add_argument("--scroll-share", action="store_true")
    ap.add_argument("--light", action="store_true")
    ap.add_argument("--port", type=int, default=9333)
    asyncio.run(capture(ap.parse_args()))


if __name__ == "__main__":
    main()
