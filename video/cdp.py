"""A small Chrome DevTools Protocol client: launch headless Chrome, drive one page, record it.

Only what the launch-video tools need: commands, event handlers, screencast frames, trusted clicks.
No dependencies beyond httpx and websockets (both already in requirements.txt).
"""
import asyncio
import base64
import itertools
import json
import os
import subprocess
import time
from collections import defaultdict
from pathlib import Path

import httpx
import websockets

CHROME_PATHS = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
)


def find_chrome() -> str:
    for p in CHROME_PATHS:
        if os.path.exists(p):
            return p
    raise SystemExit("Chrome or Edge not found")


class Page:
    def __init__(self, ws):
        self.ws = ws
        self.ids = itertools.count(1)
        self.pending: dict[int, asyncio.Future] = {}
        self.handlers: dict[str, list] = defaultdict(list)
        self.reader = asyncio.create_task(self._read())

    async def _read(self):
        async for raw in self.ws:
            msg = json.loads(raw)
            if "id" in msg:
                fut = self.pending.pop(msg["id"], None)
                if fut and not fut.done():
                    if "error" in msg:
                        fut.set_exception(RuntimeError(f"{msg['error']}"))
                    else:
                        fut.set_result(msg.get("result", {}))
            else:
                for h in list(self.handlers.get(msg.get("method"), ())):
                    r = h(msg.get("params", {}))
                    if asyncio.iscoroutine(r):
                        asyncio.create_task(r)

    async def send(self, method: str, **params):
        i = next(self.ids)
        fut = asyncio.get_running_loop().create_future()
        self.pending[i] = fut
        await self.ws.send(json.dumps({"id": i, "method": method, "params": params}))
        return await asyncio.wait_for(fut, 60)

    def on(self, method: str, handler):
        self.handlers[method].append(handler)

    async def eval(self, expr: str, await_promise: bool = True):
        r = await self.send("Runtime.evaluate", expression=expr, awaitPromise=await_promise,
                            returnByValue=True)
        if "exceptionDetails" in r:
            raise RuntimeError(f"JS error: {r['exceptionDetails']}")
        return r.get("result", {}).get("value")

    async def wait_for(self, expr: str, timeout: float = 30, poll: float = 0.1):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if await self.eval(expr):
                return True
            await asyncio.sleep(poll)
        raise TimeoutError(f"timed out waiting for: {expr}")

    async def center_of(self, selector: str):
        r = await self.eval(
            f"(() => {{ const e = document.querySelector({json.dumps(selector)}); if (!e) return null;"
            f" e.scrollIntoView({{block: 'nearest'}}); const b = e.getBoundingClientRect();"
            f" return [b.x + b.width / 2, b.y + b.height / 2]; }})()")
        if not r:
            raise RuntimeError(f"no element {selector}")
        return r

    async def click(self, selector: str):
        """A trusted click (counts as a user gesture), at the element's centre. Returns (x, y, epoch_s)."""
        x, y = await self.center_of(selector)
        t = time.time()
        for typ in ("mousePressed", "mouseReleased"):
            await self.send("Input.dispatchMouseEvent", type=typ, x=x, y=y, button="left", clickCount=1)
        return x, y, t

    async def screenshot(self, path: Path):
        r = await self.send("Page.captureScreenshot", format="png")
        Path(path).write_bytes(base64.b64decode(r["data"]))


class Browser:
    def __init__(self, profile: Path, port: int = 9333, extra_args=(), scale: float = 2):
        # Screencast frames come at the window's real pixel density, so force it (the viewport override
        # alone gives frames at CSS size).
        self.profile, self.port = Path(profile), port
        self.extra_args = [f"--force-device-scale-factor={scale}", *extra_args]
        self.proc = None

    async def __aenter__(self):
        self.profile.mkdir(parents=True, exist_ok=True)
        args = [find_chrome(), f"--remote-debugging-port={self.port}", f"--user-data-dir={self.profile}",
                "--headless=new", "--autoplay-policy=no-user-gesture-required", "--hide-scrollbars",
                "--no-first-run", "--no-default-browser-check", "--disable-background-timer-throttling",
                "--disable-renderer-backgrounding", "--disable-backgrounding-occluded-windows",
                "--force-color-profile=srgb", "--font-render-hinting=none", "--window-size=1400,1700",
                *self.extra_args, "about:blank"]
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        async with httpx.AsyncClient() as c:
            for _ in range(100):
                try:
                    targets = (await c.get(f"http://127.0.0.1:{self.port}/json/list")).json()
                    pages = [t for t in targets if t.get("type") == "page"]
                    if pages:
                        self.ws_url = pages[0]["webSocketDebuggerUrl"]
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.1)
            else:
                raise RuntimeError("Chrome did not start")
        self.ws = await websockets.connect(self.ws_url, max_size=None, ping_interval=None)
        self.page = Page(self.ws)
        for d in ("Page", "Runtime", "Network"):
            await self.page.send(f"{d}.enable")
        await self.page.send("Network.setCacheDisabled", cacheDisabled=True)   # always the latest CSS/JS
        return self

    async def __aexit__(self, *exc):
        try:
            await self.ws.close()
        finally:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    async def setup(self, width: int, height: int, scale: float, dark: bool = True, reduced_motion=False):
        p = self.page
        await p.send("Emulation.setDeviceMetricsOverride", width=width, height=height,
                     deviceScaleFactor=scale, mobile=False)
        await p.send("Emulation.setEmulatedMedia", features=[
            {"name": "prefers-color-scheme", "value": "dark" if dark else "light"},
            {"name": "prefers-reduced-motion", "value": "reduce" if reduced_motion else "no-preference"},
        ])


class Screencast:
    """Saves every compositor frame as JPEG with its wall-clock timestamp (seconds since epoch)."""

    def __init__(self, page: Page, out_dir: Path, max_w: int, max_h: int, quality: int = 92):
        self.page, self.out, self.max_w, self.max_h, self.q = page, Path(out_dir), max_w, max_h, quality
        self.frames: list[dict] = []
        self.out.mkdir(parents=True, exist_ok=True)
        page.on("Page.screencastFrame", self._frame)

    async def _frame(self, params):
        n = len(self.frames)
        name = f"f{n:06d}.jpg"
        (self.out / name).write_bytes(base64.b64decode(params["data"]))
        self.frames.append({"file": name, "t": params["metadata"]["timestamp"]})
        await self.page.send("Page.screencastFrameAck", sessionId=params["sessionId"])

    async def start(self):
        await self.page.send("Page.startScreencast", format="jpeg", quality=self.q,
                             maxWidth=self.max_w, maxHeight=self.max_h, everyNthFrame=1)

    async def stop(self):
        await self.page.send("Page.stopScreencast")
        (self.out / "frames.json").write_text(json.dumps(self.frames))
