"""Render an overlay timeline (motion.js + a list of elements) to PNG frames with transparency.

Frames whose state key matches the previous frame are not re-rendered; the ffconcat file just holds the
previous image longer. Output: <out>/frames/*.png and <out>/overlay.ffconcat (30 fps timing).
"""
import asyncio
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cdp import Browser  # noqa: E402

HERE = Path(__file__).resolve().parent
W, H, SCALE, FPS = 540, 675, 2, 30

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Anek+Latin:wght@500..800&family=Noto+Sans:wght@400..800&family=Noto+Sans+Devanagari:wght@400..700&family=Noto+Sans+Kannada:wght@400..700&family=Noto+Sans+Tamil:wght@400..700&display=block">
<style>
html,body{margin:0;width:540px;height:675px;overflow:hidden;background:transparent}
#stage{position:relative;width:540px;height:675px;overflow:hidden}
.el{position:absolute;transform:translate(var(--tx,0),var(--ty,0)) scale(var(--sc,1));will-change:transform,opacity}
__CSS__
</style></head><body><div id="stage"></div>
<script>window.TL = __TL__;</script>
<script>__MOTION__</script>
</body></html>"""


def write_page(out: Path, elements: list[dict], css: str) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    html = (PAGE.replace("__CSS__", css)
            .replace("__TL__", json.dumps(elements, ensure_ascii=False))
            .replace("__MOTION__", (HERE / "motion.js").read_text("utf-8")))
    p = out / "overlay.html"
    p.write_text(html, "utf-8")
    return p


async def render(out: Path, elements: list[dict], css: str, duration: float, port: int = 9351,
                 stills: tuple = ()) -> Path:
    """stills: times (s) to also save as preview PNGs."""
    page_path = write_page(out, elements, css)
    frames_dir = out / "frames"
    frames_dir.mkdir(exist_ok=True)
    for f in frames_dir.glob("*.png"):
        f.unlink()
    async with Browser(HERE / "out" / "chrome-profile-overlay", port=port) as b:
        p = b.page
        await b.setup(W, H, SCALE)
        await p.send("Emulation.setDefaultBackgroundColorOverride", color={"r": 0, "g": 0, "b": 0, "a": 0})
        await p.send("Page.navigate", url=page_path.as_uri())
        await p.wait_for("window.ready && document.readyState === 'complete'", 30)
        await p.eval("window.ready")
        n = int(round(duration * FPS))
        entries, last_key, last_file, held = [], None, None, 0
        uniq = 0
        for i in range(n):
            t = i / FPS
            key = await p.eval(f"seek({t:.5f})")
            if key == last_key and last_file:
                held += 1
                entries[-1][1] += 1
                continue
            r = await p.send("Page.captureScreenshot", format="png")
            name = f"o{i:05d}.png"
            (frames_dir / name).write_bytes(base64.b64decode(r["data"]))
            entries.append([name, 1])
            last_key, last_file = key, name
            uniq += 1
        for s in stills:
            await p.eval(f"seek({s:.5f})")
            r = await p.send("Page.captureScreenshot", format="png")
            (out / f"still_{s:05.2f}.png").write_bytes(base64.b64decode(r["data"]))
    lines = ["ffconcat version 1.0"]
    for name, count in entries:
        lines += [f"file 'frames/{name}'", f"duration {count / FPS:.6f}"]
    lines.append(f"file 'frames/{entries[-1][0]}'")
    (out / "overlay.ffconcat").write_text("\n".join(lines))
    print(f"overlay: {n} frames, {uniq} rendered, {held} reused")
    return out / "overlay.ffconcat"
