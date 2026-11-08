"""Record the laptop walkthrough shots in the real app, driven by a slow, human-paced mouse.

    .venv\\Scripts\\python video\\walk_capture.py scam|safe|rec [--out DIR] [--url http://localhost:8000]

Headless Chrome at 1280x720 CSS px x1.2 (1536x864 frames, the browser window of the 16:9 video).
- scam / safe: the Live call tab, with the demo call fed into Chrome's fake microphone. That stands in for a
  phone on speaker, so the app does exactly what it does for a real call (Gnani Prisma realtime STT, live
  scoring, Timbre warnings). The mic file is the demo WAV with silence added before and after.
- rec: the Recording tab, uploading the English KYC demo call through the real file chooser.
The cursor is drawn inside the page (walk_hook.js) from the real mouse events, so it is always in sync.
Writes frames/, frames.json and capture.json (page events, mouse actions, when the mic opened).
Spends Gnani credits.
"""
import argparse
import asyncio
import json
import math
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cdp import Browser, Screencast  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
W, H, SCALE = 1280, 720, 1.2
MIC_PRE, MIC_POST = 1.5, 20.0          # seconds of silence around the call in the fake-mic file
DEMO = {"scam": "digital-arrest", "safe": "legit-bank-reminder", "rec": "bank-kyc-otp"}


def mic_file(demo: str) -> Path:
    out = HERE / "out" / "mic" / f"{demo}.wav"
    if not out.exists():
        out.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(ROOT / "demo" / "audio" / f"{demo}.wav"),
                        "-af", f"adelay={int(MIC_PRE * 1000)}:all=1,apad=pad_dur={MIC_POST}",
                        "-ar", "48000", "-ac", "1", "-c:a", "pcm_s16le", str(out)], check=True)
    return out


def ease(t: float) -> float:
    return 4 * t ** 3 if t < 0.5 else 1 - (-2 * t + 2) ** 3 / 2


class Mouse:
    """Moves like a person: eased, slightly curved paths, about a second per move. Logs every action."""

    def __init__(self, page, log: list):
        self.p, self.log = page, log
        self.x, self.y = 1040.0, 600.0

    async def _move_event(self, x, y):
        await self.p.send("Input.dispatchMouseEvent", type="mouseMoved", x=x, y=y)

    async def place(self, x, y):
        self.x, self.y = x, y
        await self._move_event(x, y)

    async def rect(self, sel: str):
        return await self.p.eval(
            f"(() => {{ const e = document.querySelector({json.dumps(sel)}); if (!e) return null;"
            f" const b = e.getBoundingClientRect(); return [b.x, b.y, b.width, b.height]; }})()")

    async def show(self, sel: str, margin: int = 70, ms: int = 1300):
        """Scroll slowly (only if needed) so the element is fully on screen."""
        x, y, w, h = await self.rect(sel)
        if y < margin or y + h > H - margin:
            sy = await self.p.eval("scrollY")
            target = sy + (y - margin if y < margin else y + h - (H - margin))
            self.log.append({"t": time.time(), "type": "scroll", "ms": ms})
            await self.p.eval(f"window.__kv.scrollTo({target}, {ms})")
            await asyncio.sleep(0.15)

    async def to(self, target, dur: float = 1.0, fx: float = 0.5, fy: float = 0.5):
        """Glide to a selector (fx/fy: where inside its box) or to an (x, y) point."""
        if isinstance(target, str):
            await self.show(target)
            x, y, w, h = await self.rect(target)
            tx, ty = x + w * fx, y + h * fy
        else:
            tx, ty = target
        x0, y0 = self.x, self.y
        dist = math.hypot(tx - x0, ty - y0)
        bow = min(60.0, dist * 0.12)                       # a gentle arc, not a ruler-straight line
        nx, ny = (-(ty - y0) / dist, (tx - x0) / dist) if dist else (0, 0)
        self.log.append({"t": time.time(), "type": "move", "to": [tx, ty], "dur": dur})
        t0 = time.perf_counter()
        while True:
            t = min(1.0, (time.perf_counter() - t0) / dur)
            e = ease(t)
            arc = math.sin(math.pi * e) * bow
            await self._move_event(x0 + (tx - x0) * e + nx * arc, y0 + (ty - y0) * e + ny * arc)
            if t >= 1:
                break
            await asyncio.sleep(1 / 90)
        self.x, self.y = tx, ty

    async def click(self):
        self.log.append({"t": time.time(), "type": "click", "at": [self.x, self.y]})
        await self.p.send("Input.dispatchMouseEvent", type="mousePressed", x=self.x, y=self.y, button="left",
                          clickCount=1)
        await asyncio.sleep(0.09)
        await self.p.send("Input.dispatchMouseEvent", type="mouseReleased", x=self.x, y=self.y, button="left",
                          clickCount=1)

    async def pick(self, sel: str, value: str):
        """Choose an option in a native <select>. Its popup can't be captured headless, so: ripple + set."""
        self.log.append({"t": time.time(), "type": "pick", "value": value})
        await self.p.eval(f"window.__kv.ripple({self.x}, {self.y})")
        await asyncio.sleep(0.25)
        await self.p.eval(f"(() => {{ const s = document.querySelector({json.dumps(sel)}); s.value = {json.dumps(value)};"
                          f" s.dispatchEvent(new Event('change', {{bubbles: true}})); }})()")


async def ws_events(p):
    return await p.eval("window.__kv.events.filter(e => e.type === 'ws').map(e => e.m)")


async def wait_ws(p, pred, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        if any(pred(m) for m in await ws_events(p)):
            return True
        await asyncio.sleep(0.1)
    raise TimeoutError("event never came")


async def shot_scam(p, m: Mouse):
    await asyncio.sleep(2.5)
    await m.to("#warnLang", 1.4, fx=0.3)                  # "first, the language for warnings: I'll keep English"
    await asyncio.sleep(2.0)
    await m.to("#callLang", 1.0, fx=0.3)                  # "then the language of the call"
    await asyncio.sleep(0.8)
    await m.pick("#callLang", "hi-IN")
    await asyncio.sleep(1.8)
    await m.to("#listenBtn", 1.2)                          # scrolls the button into view on the way
    await asyncio.sleep(1.0)
    await m.click()
    await asyncio.sleep(1.5)
    await m.to((150, 640), 1.4)                            # park out of the way while the call plays

    await wait_ws(p, lambda e: e.get("type") == "alert" and e.get("level") == "danger")
    while True:                                            # let the spoken warning finish
        until = await p.eval("window.__kv.voiceUntil")
        if until and time.time() * 1000 > until + 600:
            break
        await asyncio.sleep(0.1)
    await m.to("#alarmOk", 1.0)
    await asyncio.sleep(0.4)
    await m.click()
    await asyncio.sleep(0.6)
    await m.to("#stopBtn", 1.0)
    await asyncio.sleep(0.35)
    await m.click()

    await wait_ws(p, lambda e: e.get("type") == "summary", 60)
    await asyncio.sleep(2.0)                                # the app scrolls its summary into view
    await m.to((1240, 420), 1.0)
    sy = await m.rect("#summary")
    await p.eval(f"window.__kv.scrollTo(scrollY + {sy[1] - 24}, 2400)")
    await asyncio.sleep(4.0)
    await m.to("#advice", 1.2, fx=0.35)
    await asyncio.sleep(3.0)
    await m.to("#shareWa", 1.2)
    await asyncio.sleep(3.5)


async def shot_safe(p, m: Mouse):
    await asyncio.sleep(1.5)
    await m.to("#listenBtn", 1.2)
    await asyncio.sleep(0.8)
    await m.click()
    await asyncio.sleep(1.5)
    await m.to((150, 640), 1.4)
    mic0 = None
    while mic0 is None:
        mic0 = await p.eval("(window.__kv.events.find(e => e.type === 'mic') || {}).t || null")
        await asyncio.sleep(0.1)
    # wait for the call to end (24.9 s of speech after the pre-roll), plus time for the last transcript
    while time.time() * 1000 < mic0 + (MIC_PRE + 24.94 + 2.5) * 1000:
        await asyncio.sleep(0.1)
    await m.to("#stopBtn", 1.1)
    await asyncio.sleep(0.4)
    await m.click()
    await wait_ws(p, lambda e: e.get("type") == "summary", 60)
    await asyncio.sleep(1.5)
    await m.to((1240, 420), 1.0)
    sy = await m.rect("#summary")
    await p.eval(f"window.__kv.scrollTo(scrollY + {sy[1] - 24}, 2400)")
    await asyncio.sleep(4.0)


async def shot_rec(p, m: Mouse):
    upload = ROOT / "demo" / "audio" / f"{DEMO['rec']}.wav"

    async def chooser(params):
        await p.send("DOM.setFileInputFiles", files=[str(upload)], backendNodeId=params["backendNodeId"])
    p.on("Page.fileChooserOpened", chooser)
    await p.send("Page.setInterceptFileChooserDialog", enabled=True)

    await asyncio.sleep(1.5)
    await m.to("#tab-file", 1.3)
    await asyncio.sleep(0.6)
    await m.click()
    await asyncio.sleep(1.2)
    await m.to("#dropZone", 1.0)
    await asyncio.sleep(0.6)
    await m.click()
    await asyncio.sleep(1.8)
    await m.to("#analyzeBtn", 1.0)
    await asyncio.sleep(0.6)
    await m.click()
    await asyncio.sleep(1.0)
    await m.to((1240, 420), 1.2)
    await p.wait_for("!document.getElementById('summary').hidden", 120)
    await asyncio.sleep(2.0)
    await m.to("#transcript mark.flag", 1.2)
    await asyncio.sleep(3.0)
    await m.to((1240, 420), 1.0)
    sy = await m.rect("#summary")
    await p.eval(f"window.__kv.scrollTo(scrollY + {sy[1] - 24}, 2400)")
    await asyncio.sleep(4.0)


SHOTS = {"scam": shot_scam, "safe": shot_safe, "rec": shot_rec}


async def capture(a):
    out = Path(a.out or HERE / "out" / "walk" / a.shot)
    out.mkdir(parents=True, exist_ok=True)
    for f in (out / "frames").glob("*.jpg"):
        f.unlink()
    demo = DEMO[a.shot]
    mic = mic_file(demo if a.shot != "rec" else "legit-bank-reminder")
    args = ["--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream",
            f"--use-file-for-fake-audio-capture={mic}"]
    actions = []
    async with Browser(HERE / "out" / "chrome-profile-walk", port=a.port, extra_args=args, scale=SCALE) as b:
        p = b.page
        await b.setup(W, H, SCALE, dark=True)
        await p.send("Page.addScriptToEvaluateOnNewDocument",
                     source=(HERE / "hook.js").read_text("utf-8") + "\n" + (HERE / "walk_hook.js").read_text("utf-8"))
        url = a.url.rstrip("/") + "/?v=walk"
        await p.send("Page.navigate", url=url)
        await p.wait_for("document.readyState === 'complete'", 20)
        await p.eval("localStorage.clear()")                # start from the defaults (English / Auto-detect)
        await p.send("Page.navigate", url=url)
        await p.wait_for("document.querySelectorAll('.demo-card[data-id]').length >= 5 && !!window.__kv.cursorAt", 20)
        await p.eval("document.fonts.ready.then(() => true)")
        m = Mouse(p, actions)
        if a.shot == "safe":                                # same set-up as the end of the scam shot's setup
            await p.eval("(() => { const s = document.getElementById('callLang'); s.value = 'hi-IN';"
                         " s.dispatchEvent(new Event('change', {bubbles: true})); })()")
            await m.show("#listenBtn", ms=10)
            await m.place(560, 330)
        else:
            await p.eval("window.scrollTo(0, 0)")
            await m.place(1040, 600)
        await asyncio.sleep(0.8)

        cast = Screencast(p, out / "frames", round(W * SCALE), round(H * SCALE))
        await cast.start()
        actions.append({"t": time.time(), "type": "cast-start"})
        try:
            await SHOTS[a.shot](p, m)
        finally:
            await cast.stop()
        kv = await p.eval("({events: window.__kv.events})")
        summary = await p.eval("({verdict: document.getElementById('verdict').textContent,"
                               " score: document.getElementById('summaryScore').textContent,"
                               " text: document.getElementById('summaryText').textContent,"
                               " share: decodeURIComponent((document.getElementById('shareWa').href.split('text=')[1] || '')),"
                               " transcript: [...document.querySelectorAll('#transcript li')].map(l => l.innerText)})")

    meta = {"shot": a.shot, "demo": demo, "size": [round(W * SCALE), round(H * SCALE)], "mic_pre": MIC_PRE,
            "actions": actions, "events": kv["events"], "summary": summary}
    (out / "capture.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), "utf-8")
    frames = json.loads((out / "frames" / "frames.json").read_text())
    print(f"{a.shot}: {len(frames)} frames over {frames[-1]['t'] - frames[0]['t']:.1f}s, verdict {summary['verdict']!r} "
          f"{summary['score']!r}")
    mic = next((e for e in kv["events"] if e["type"] == "mic"), None)
    t0 = mic["t"] + MIC_PRE * 1000 if mic else frames[0]["t"] * 1000
    print(f"  (times below are call time: seconds since the call audio started{'' if mic else ', NO MIC EVENT'})")
    for e in kv["events"]:
        if e["type"] == "ws" and e["m"]["type"] in ("alert", "summary", "risk", "transcript"):
            mm = e["m"]
            extra = {"risk": f"{mm.get('level')} {mm.get('score')}", "alert": f"{mm.get('level')} {mm.get('category')}",
                     "transcript": (mm.get("text") or "")[:60], "summary": mm.get("verdict")}[mm["type"]]
            print(f"  {(e['t'] - t0) / 1000:6.2f}s {mm['type']:10} {extra}")
    for x in actions:
        if x["type"] == "click":
            print(f"  {(x['t'] * 1000 - t0) / 1000:6.2f}s click")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("shot", choices=SHOTS)
    ap.add_argument("--out")
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--port", type=int, default=9335)
    asyncio.run(capture(ap.parse_args()))


if __name__ == "__main__":
    main()
