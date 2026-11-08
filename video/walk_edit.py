"""Build the 2-3 minute laptop walkthrough (1920x1080, 30 fps) from the walk_capture.py shots.

    .venv\\Scripts\\python video\\walk_edit.py            -> video/out/scamlingo-walkthrough.mp4

Layers, bottom to top:
  1. a static background with a plain browser window (bg.png)
  2. the app footage in that window (1536x864 at x 192, y 64): pieces of the real captures, played or held
  3. a transparent overlay: subtitles in the strip under the window, rings, the "Paused" tag, the intro and
     closing cards (rendered by overlay.py at 960x540 CSS px x2)
Audio: each capture's own sound (the call as heard from the phone on speaker, plus the app's real Timbre
warnings at the times they played, plus soft click ticks), with the narrator (Timbre, male voice) on top.

Every app shot is real footage of the app on live Gnani. A "hold" freezes a frame while the narrator explains
(the call audio pauses with it); a "dip" is a short fade through the app's background colour.
"""
import asyncio
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))
import edit                     # noqa: E402  (loudnorm)
import overlay                  # noqa: E402
import sfx                      # noqa: E402
import walk_narration as wn     # noqa: E402

WALK = HERE / "out" / "walk"
NARR = WALK / "narration"
BUILD = WALK / "build"
FINAL = HERE / "out" / "scamlingo-walkthrough.mp4"
OUTW, OUTH, FPS = 1920, 1080, 30
APPW, APPH, APPX, APPY = 1536, 864, 192, 64
BG = "0x0b0b0c"
APPBG = "0x0a0a0b"          # the app's own page colour, used for dips
DISCLOSURE = "Synthetic demo call · AI voices, made-up names"
LANGS = ["Hindi", "English", "Bengali", "Gujarati", "Kannada", "Malayalam", "Marathi", "Punjabi", "Tamil", "Telugu"]

# English subtitles for the two calls, in call time (seconds since the call audio started).
CALL_SUBS = {
    "scam": [
        (1.6, 6.24, "Caller", "Hello, I'm Inspector Rajesh Sharma from the Mumbai cyber crime branch."),
        (7.04, 8.48, "You", "Yes, go on?"),
        (9.28, 13.76, "Caller", "A parcel was booked with your Aadhaar card, and customs found drugs in it."),
        (22.1, 24.96, "Caller", "Don't disconnect the call, and don't tell anyone."),
    ],
    "safe": [
        (1.6, 5.2, "Caller", "Hello, I'm calling from your bank with a reminder."),
        (6.0, 7.28, "You", "Yes, go ahead."),
        (8.08, 13.68, "Caller", "Your credit card bill is due on the 5th. You can pay in the app or at a branch."),
        (14.48, 15.76, "You", "Okay, thank you."),
        (16.56, 20.7, "Caller", "Remember, the bank never asks for an OTP or PIN over the phone."),
        (20.7, 22.64, "Caller", "Have a nice day."),
    ],
}


LEVEL = {"narr": -16.0, "warn": -16.0, "call": -19.5}     # LUFS each source is set to before the mix
_gains: dict[str, float] = {}


def gain_to(path: Path, target: float) -> float:
    """Linear gain that brings a file's integrated loudness to target (measured once per file)."""
    k = str(path)
    if k not in _gains:
        _gains[k] = 10 ** ((target - edit.measure(path)["I"]) / 20)
    return _gains[k]


# ------------------------------------------------------------------------------------------------ captures
class Cap:
    def __init__(self, shot: str):
        self.shot, self.dir = shot, WALK / shot
        self.meta = json.loads((self.dir / "capture.json").read_text("utf-8"))
        self.frames = json.loads((self.dir / "frames" / "frames.json").read_text())
        self.f0 = self.frames[0]["t"]
        self.length = self.frames[-1]["t"] - self.f0 + 0.5
        mic = next((e for e in self.meta["events"] if e["type"] == "mic"), None)
        self.call0 = mic["t"] / 1000 + self.meta["mic_pre"] - self.f0 if mic else None
        alerts = [e["m"] for e in self.meta["events"] if e["type"] == "ws" and e["m"].get("type") == "alert"]
        srcs = [e for e in self.meta["events"] if e["type"] == "source" and e["dur"] < 20]
        self.warnings = [(e["at"] / 1000 - self.f0, e["dur"], a) for e, a in zip(srcs, alerts)]
        self.clicks = [a["t"] - self.f0 for a in self.meta["actions"] if a["type"] in ("click", "pick")]
        stops = [a["t"] - self.f0 for a in self.meta["actions"] if a["type"] == "click"]
        self.stop = stops[-1] if shot in ("scam", "safe") else None     # the last click is Stop

    def s(self, c: float) -> float:
        """Capture time (s since the first frame) of call time c."""
        return self.call0 + c

    def video(self) -> Path:
        out = self.dir / "clip.mp4"
        if out.exists() and out.stat().st_mtime > (self.dir / "capture.json").stat().st_mtime:
            return out
        lines = ["ffconcat version 1.0"]
        end = self.frames[-1]["t"] + 0.5
        for i, f in enumerate(self.frames):
            nxt = self.frames[i + 1]["t"] if i + 1 < len(self.frames) else end
            lines += [f"file 'frames/{f['file']}'", f"duration {max(0.001, nxt - f['t']):.6f}"]
        lines.append(f"file 'frames/{self.frames[-1]['file']}'")
        (self.dir / "frames.ffconcat").write_text("\n".join(lines))
        subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "concat", "-safe", "0", "-i", "frames.ffconcat",
                        "-vf", f"fps={FPS},scale={APPW}:{APPH}:flags=lanczos", "-c:v", "libx264", "-preset",
                        "medium", "-crf", "12", "-pix_fmt", "yuv420p", str(out)], check=True, cwd=self.dir)
        return out

    def audio(self, ticks: Path) -> Path:
        """The capture's sound on its own timeline: the call (as heard from the phone), ducked under the app's
        spoken warnings, cut when you hang up; the warnings themselves; a soft tick on each click."""
        from scripts.prewarm_alerts import cache_path
        out = self.dir / "track.wav"
        ins, flt, mix = [], [], []
        dur = self.length
        if self.call0 is not None:
            wav = ROOT / "demo" / "audio" / f"{self.meta['demo']}.wav"
            g = gain_to(wav, LEVEL["call"])
            ins += ["-i", str(wav)]
            duck = "+".join(f"between(t,{s - 0.1:.3f},{s + d + 0.2:.3f})" for s, d, _ in self.warnings) or "0"
            cut = f",afade=t=out:st={self.stop:.3f}:d=0.25" if self.shot == "scam" else ""
            flt.append(f"[0:a]aformat=sample_rates=48000:channel_layouts=stereo,adelay={int(self.call0 * 1000)}:all=1,"
                       f"volume='if({duck},{0.3 * g:.4f},{g:.4f})':eval=frame{cut}[call]")
            mix.append("[call]")
        for s, d, a in self.warnings:
            p = cache_path(a["text"], a.get("language") or "en-IN")
            if not p.exists():
                raise SystemExit(f"warning audio not cached: {a['text']!r}")
            i = len(ins) // 2
            ins += ["-i", str(p)]
            flt.append(f"[{i}:a]aformat=sample_rates=48000:channel_layouts=stereo,"
                       f"volume={gain_to(p, LEVEL['warn']):.4f},adelay={int(s * 1000)}:all=1[w{i}]")
            mix.append(f"[w{i}]")
        for s in self.clicks:
            i = len(ins) // 2
            ins += ["-i", str(ticks)]
            flt.append(f"[{i}:a]volume=0.22,adelay={int(s * 1000)}:all=1[k{i}]")
            mix.append(f"[k{i}]")
        flt.append(f"{''.join(mix)}amix=inputs={len(mix)}:normalize=0,apad,atrim=0:{dur:.3f}[out]")
        subprocess.run(["ffmpeg", "-v", "error", "-y", *ins, "-filter_complex", ";".join(flt), "-map", "[out]",
                        "-ar", "48000", "-ac", "2", str(out)], check=True)
        return out


# ------------------------------------------------------------------------------------------------ timeline
class Timeline:
    def __init__(self, caps: dict):
        self.caps = caps
        self.t = 0.0
        self.pieces: list[dict] = []       # app layer, end to end
        self.narr: list[dict] = []         # {"id", "at", "dur"}
        self.ov: list[dict] = []           # overlay elements
        self.subs: list[tuple] = []        # (t0, t1, who, text)
        self.lines = json.loads((NARR / "lines.json").read_text("utf-8"))
        self.marks: dict[str, float] = {}

    def dur(self, k: str) -> float:
        return self.lines[k]["dur"]

    def seg(self, cap: str | None, s0: float, s1: float, narr=(), lead=0.35, gap=0.35, tail=0.45,
            dip_in=0.0, dip_out=0.0, rings=(), paused=False, min_dur=0.0, mark=None):
        """Play cap from s0 to s1 (s0 == s1: a held frame). The narrator starts `lead` in; if he needs longer
        than the play, the last frame is held until he's done. cap None: an empty piece under a card."""
        t0 = self.t
        at = t0 + lead
        spoken = {}
        for k in narr:
            self.narr.append({"id": k, "at": at, "dur": self.dur(k)})
            self.subs.append((at, at + self.dur(k), None, wn.subtitle(wn.LINES[k])))
            spoken[k] = at
            at += self.dur(k) + gap
        need = (at - gap + tail - t0) if narr else 0.0
        play = s1 - s0
        hold = max(0.0, need - play, min_dur - play)
        d = play + hold
        self.pieces.append({"cap": cap, "s0": s0, "s1": s1, "hold": hold, "t": t0, "dur": d,
                            "dip_in": dip_in, "dip_out": dip_out})
        for k, box, kind in rings:
            self.ring(spoken[k] - 0.1, t0 + d, box, kind)
        if paused and hold > 0:
            self.el(t0 + play, t0 + d, '<span class="ic-pause"></span>Paused', cls="paused",
                    fin=("fade", 0.2), fout=("fade", 0.2))
        if mark:
            self.marks[mark] = t0
        self.t += d
        return t0

    def hold(self, cap, s, narr, **kw):
        return self.seg(cap, s, s, narr, **kw)

    # overlay helpers (stage CSS px: 960x540; the app window's content box is x 96-864, y 32-464)
    def el(self, t0, t1, html, cls="", style="", z=5, fin=("fade", 0.3), fout=("fade", 0.3), fx=None):
        d = {"id": f"e{len(self.ov)}", "start": round(t0, 3), "end": round(t1, 3), "html": html, "cls": cls,
             "style": style, "z": z, "in": {"type": fin[0], "dur": fin[1]}, "out": {"type": fout[0], "dur": fout[1]}}
        if fx:
            d["fx"] = fx
        self.ov.append(d)

    def ring(self, t0, t1, box, kind="ring"):
        """box in app frame px (1536x864)."""
        x, y, w, h = box
        st = f"left:{96 + x / 2:.1f}px;top:{32 + y / 2:.1f}px;width:{w / 2:.1f}px;height:{h / 2:.1f}px"
        self.el(t0, t1, "", cls=kind, style=st, z=6, fin=("pop", 0.35), fout=("fade", 0.3))

    def call_subs(self, cap: str):
        """Place the call's English subtitles wherever its pieces actually play (not during holds, not while the
        app's warning voice is speaking)."""
        c = self.caps[cap]
        mute = [(s, s + d) for s, d, _ in c.warnings]
        for p in self.pieces:
            if p["cap"] != cap or p["s1"] <= p["s0"]:
                continue
            for c0, c1, who, text in CALL_SUBS[cap]:
                a, b = max(c.s(c0), p["s0"]), min(c.s(c1), p["s1"], c.stop or 1e9)
                for m0, m1 in mute:
                    if a < m1 and b > m0:
                        a = max(a, m1) if a >= m0 else a
                        b = min(b, m0) if b <= m1 else b
                if b - a > 0.6:
                    self.subs.append((p["t"] + a - p["s0"], p["t"] + b - p["s0"], f"{who} · Hindi", text))

    def chapter(self, t0, t1, text):
        self.el(t0, t1, text, cls="chap", z=4, fin=("fade", 0.5), fout=("fade", 0.4))

    def disclose(self, t0, t1):
        self.el(t0, t1, DISCLOSURE, cls="disc", z=4, fin=("fade", 0.5), fout=("fade", 0.4))


def build_timeline(caps) -> Timeline:
    T = Timeline(caps)
    sc, sf, rc = caps["scam"], caps["safe"], caps["rec"]

    # ---- intro card (the app's home screen is already under it)
    T.seg("scam", 0.0, 0.0, ["i1", "i2", "i3"], lead=0.5, gap=0.35, tail=0.5)
    home = (sc.dir / "frames" / sc.frames[2]["file"]).as_uri()
    T.el(0.0, T.t, INTRO.replace("__HOME__", home), cls="card intro", z=20, fin=("none", 0), fout=("fade", 0.8),
         fx=None)

    # ---- set up (the narrator talks over the slow cursor; nothing else is making sound yet)
    ch0 = T.t
    T.seg("scam", 0.0, 2.4, ["s2"], lead=0.4, tail=0.3)
    T.seg("scam", 2.4, 5.0, ["s3"], lead=1.1, tail=0.3)         # cursor glides to "Warn me in"
    T.seg("scam", 5.0, 8.3, ["s4"], lead=0.7, tail=0.3)         # ... to "Call language", picks Hindi
    T.seg("scam", 8.3, 13.2, ["s5"], lead=2.6, tail=0.3)        # scrolls a little, then to Start listening
    T.chapter(ch0, T.t + 1.0, "Set up")

    # ---- the suspicious call, live
    ch1 = T.t
    call_start = T.t + (sc.s(0) - 13.2)
    T.seg("scam", 13.2, 14.6, dip_out=0.25)                     # click; skip the second of "Connecting"
    T.seg("scam", 16.6, sc.s(8.6), dip_in=0.25)
    T.hold("scam", sc.s(8.6), ["p1", "p2"], paused=True, lead=0.35, rings=[
        ("p1", (726, 412, 700, 100), "ring"),                   # Prisma's first line
        ("p2", (744, 280, 140, 52), "ring"),                    # "Fake official" chip
    ])
    T.seg("scam", sc.s(8.6), sc.s(13.85))
    T.hold("scam", sc.s(13.85), ["q1"], paused=True, lead=0.35, rings=[
        ("q1", (744, 122, 412, 120), "ring red"),               # 85, Scam likely
        ("q1", (740, 300, 284, 60), "ring red"),                # Fake official + Digital arrest
    ])
    T.seg("scam", sc.s(13.85), 37.75)                          # the red alert, spoken in full
    T.hold("scam", 37.75, ["h1", "h2"], paused=True, lead=0.35)
    T.seg("scam", 37.75, 42.3)                                  # Got it, then Stop
    T.seg("scam", 42.3, 46.9, ["h3"], lead=0.6)
    T.seg("scam", 46.9, 48.1, dip_out=0.35)
    T.chapter(ch1, T.t, "A suspicious call")
    T.disclose(call_start - 1.0, T.t)
    T.call_subs("scam")

    # ---- after the call
    ch2 = T.t
    T.seg("scam", 60.9, 65.2, ["a1"], lead=0.6, dip_in=0.35)    # cursor drifts to "What to do"
    a3 = T.seg("scam", 65.2, 70.2, ["a3"], lead=3.4, tail=1.6)  # cursor to Share on WhatsApp
    share = sc.meta["summary"]["share"].replace("🚨 ", "").replace("🛡️ ", "")
    share_html = "<div class='k'>Message ready to share</div><p>" + share.replace("\n", "<br>") + "</p>"
    T.el(a3 + 3.0, T.t, share_html, cls="share", z=7, fin=("rise", 0.45), fout=("fade", 0.3))
    T.seg("scam", 70.2, 70.8, dip_out=0.4)
    T.chapter(ch2, T.t, "After the call")
    T.disclose(ch2, T.t)

    # ---- a genuine call
    ch3 = T.t
    g_start = T.t
    T.seg("safe", 0.0, sf.s(1.5), ["g1", "g2"], lead=0.5, gap=0.3, dip_in=0.4)   # call audio starts at c 1.6
    T.seg("safe", sf.s(1.5), sf.s(5.6), dip_out=0.3)
    T.seg("safe", sf.s(16.2), sf.s(23.3), dip_in=0.3)
    T.hold("safe", sf.s(23.3), ["g3", "g5"], paused=True, lead=0.35, rings=[
        ("g3", (1040, 712, 44, 0), "uline"), ("g3", (1092, 712, 38, 0), "uline"),
        ("g5", (944, 40, 176, 124), "ring green"),
    ])
    T.seg("safe", sf.s(23.3), sf.s(24.3), dip_out=0.5)
    T.chapter(ch3, T.t, "A genuine call")
    T.disclose(ch3, T.t)
    T.call_subs("safe")
    _ = g_start

    # ---- check a recording
    ch4 = T.t
    T.seg("rec", 0.0, 3.1, ["r1"], lead=0.5, dip_in=0.4)
    T.seg("rec", 3.1, 7.6, ["r2"], lead=1.2)
    T.seg("rec", 7.6, 13.9, ["r3"], lead=4.4, dip_out=0.35)
    rs = rec_result_time(rc)
    T.seg("rec", rs, 31.2, dip_in=0.35)
    T.hold("rec", 31.2, ["r4"], lead=0.3, rings=[("r4", REC_MARK, "ring red")])
    T.seg("rec", 31.2, 32.0, dip_out=0.5)
    T.chapter(ch4, T.t, "Check a recording")
    T.disclose(ch4, T.t)

    # ---- close: how to use it, and the languages
    c0 = T.t
    T.seg(None, 0, 0, ["c1", "c3"], lead=0.6, gap=0.45, tail=1.2)
    c3 = next(n["at"] for n in T.narr if n["id"] == "c3")
    c2 = c3
    T.el(c0, T.t + 1.0, CLOSE, cls="card close", z=20, fin=("fade", 0.7), fout=("none", 0))
    per = (T.dur("c3") - 2.6) / len(LANGS)          # the names start after "...ten Indian languages."
    for i, name in enumerate(LANGS):
        col, row = i % 5, i // 5
        T.el(c3 + 2.6 + i * per - 0.05, T.t + 1.0, name, cls="lang",
             style=f"left:{270 + col * 86}px;top:{300 + row * 44}px", z=21, fin=("rise", 0.4), fout=("none", 0))
    T.el(c2, T.t + 1.0, "Works in 10 Indian languages", cls="langs-k", z=21, fin=("fade", 0.5), fout=("none", 0))
    T.el(T.t - 0.9, T.t + 1.0, "", cls="black", z=30, fin=("fade", 0.9), fout=("none", 0))   # fade out
    return T


REC_MARK = (0, 0, 0, 0)        # set from the capture in main()


def rec_result_time(rc: Cap) -> float:
    """When the recording's result has landed (the hover on the risky phrase starts right after)."""
    scrolls = [a["t"] - rc.f0 for a in rc.meta["actions"] if a["type"] == "scroll"]
    return scrolls[-1] - 2.2          # walk_capture waits 2 s on the result before scrolling to the phrase


# ------------------------------------------------------------------------------------------------ look
CSS = """
:root { --body: 'Noto Sans', 'Noto Sans Devanagari', sans-serif; --display: 'Anek Latin', 'Noto Sans', sans-serif;
  --ink: #f4f4f5; --ink2: #a1a1aa; --ink3: #71717a; --red: #ff5a6e; --green: #3ccf8e; }
.el { font-family: var(--body); color: var(--ink); }
.bgwin { left: 96px; top: 12px; width: 768px; height: 452px; border-radius: 10px; background: #0a0a0b;
  box-shadow: 0 0 0 1px #2a2a2e, 0 18px 50px rgb(0 0 0 / .55); }
.bgbar { left: 96px; top: 12px; width: 768px; height: 20px; border-radius: 10px 10px 0 0; background: #18181b;
  border-bottom: 1px solid #26262a; display: flex; align-items: center; }
.bgbar i { width: 7px; height: 7px; border-radius: 50%; background: #3f3f46; margin-left: 7px; }
.bgbar i:first-child { margin-left: 10px; }
.bgbar .url { position: absolute; left: 50%; transform: translateX(-50%); font: 500 8.5px/1 var(--body); color: #a1a1aa;
  background: #0f0f11; border: 1px solid #27272a; border-radius: 6px; padding: 3px 34px 3px; letter-spacing: .01em; }
.corner { width: 9px; height: 9px; top: 455px; background: radial-gradient(circle at var(--cx) 0, transparent 8px, #0b0b0c 8.6px); }
.chap { left: 152px; top: 16px; height: 12px; display: flex; align-items: center; font: 650 8.5px/1 var(--body);
  color: #d4d4d8; letter-spacing: .02em; }
.paused { left: 50%; top: 15px; margin-left: 74px; display: flex; align-items: center; gap: 4px; font: 700 8px/1 var(--body);
  color: #0a0a0b; background: #f4f4f5; border-radius: 99px; padding: 2.5px 7px 2.5px 6px; letter-spacing: .04em;
  text-transform: uppercase; }
.ic-pause { width: 5px; height: 6px; border-left: 1.6px solid #0a0a0b; border-right: 1.6px solid #0a0a0b; box-sizing: border-box; }
.disc { right: 104px; top: 16px; height: 12px; display: flex; align-items: center; font: 600 7.5px/1 var(--body);
  color: #a1a1aa; letter-spacing: .02em; }
.sub { left: 0; right: 0; top: 476px; display: flex; justify-content: center; }
.sub .box { max-width: 760px; display: flex; align-items: baseline; gap: 8px; padding: 6px 13px 7px; border-radius: 9px;
  background: rgb(255 255 255 / .055); font: 500 15px/1.35 var(--body); color: #f4f4f5; text-align: center; }
.sub .who { flex: none; font: 650 10px/1 var(--body); color: #8b8b94; letter-spacing: .03em; text-transform: uppercase; }
.ring { border-radius: 9px; border: 2px solid #fff; box-shadow: 0 0 0 2px rgb(0 0 0 / .35), 0 0 14px rgb(255 255 255 / .35); }
.ring.red { border-color: #ff8a98; box-shadow: 0 0 0 2px rgb(0 0 0 / .35), 0 0 16px rgb(255 90 110 / .55); }
.ring.green { border-color: var(--green); box-shadow: 0 0 0 2px rgb(0 0 0 / .35), 0 0 16px rgb(60 207 142 / .55); }
.uline { height: 2.5px !important; border-radius: 2px; background: var(--green); box-shadow: 0 0 8px rgb(60 207 142 / .8); }
.share { left: 118px; top: 96px; width: 300px; padding: 12px 14px 13px; border-radius: 12px; background: #141416;
  border: 1px solid #2f2f35; box-shadow: 0 14px 40px rgb(0 0 0 / .6); }
.share .k { font: 700 8px/1 var(--body); letter-spacing: .1em; text-transform: uppercase; color: #3ccf8e; margin-bottom: 8px; }
.share p { margin: 0; font: 400 8.6px/1.5 var(--body); color: #e4e4e7; }
.card { left: 0; top: 0; width: 960px; height: 540px; background: #0b0b0c; }
.black { left: 0; top: 0; width: 960px; height: 540px; background: #000; }
.lang { font: 650 13px/1 var(--body); color: var(--ink); padding: 7px 0; width: 78px; text-align: center; border-radius: 99px;
  background: rgb(255 255 255 / .06); border: 1px solid rgb(255 255 255 / .1); }
.langs-k { left: 270px; top: 270px; font: 700 9px/1 var(--body); letter-spacing: .12em; text-transform: uppercase; color: var(--ink3); }
"""

LOGO = ('<svg viewBox="0 0 24 24" width="26" height="26"><path fill="#f4f4f5" d="M12 1.8 20.4 5v6.6c0 5.2-3.5 9.3-8.4 '
        '10.7-4.9-1.4-8.4-5.5-8.4-10.7V5z"/><path stroke="#0a0a0b" stroke-width="2" fill="none" stroke-linecap="round" '
        'd="M9 10v3.5M12 8.5v6.5M15 10v3.5"/></svg>')
SPK = ('<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="#3ccf8e" stroke-width="2" stroke-linecap="round" '
       'stroke-linejoin="round"><path d="M11 5 6 9H2v6h4l5 4z"/><path d="M15.5 8.5a5 5 0 0 1 0 7M19 5a10 10 0 0 1 0 14"/></svg>')

INTRO = f"""
<div style="position:absolute;left:92px;top:150px;width:330px">
  <div style="display:flex;align-items:center;gap:9px;margin-bottom:16px">{LOGO}
    <span style="font:800 25px/1 var(--display);letter-spacing:-.02em">ScamLingo</span></div>
  <div style="font:800 36px/1.06 var(--display);letter-spacing:-.025em;color:#f4f4f5">A live scam-call shield<br>
    <span style="color:#a1a1aa">for the calls that feel off.</span></div>
  <div style="margin-top:18px;font:500 12px/1.5 var(--body);color:#a1a1aa;max-width:290px">Your phone on speaker.
    ScamLingo open on your laptop. It listens, and warns you out loud.</div>
</div>
<div style="position:absolute;left:470px;top:118px;width:330px;height:206px;border-radius:12px;background:#18181b;
  border:6px solid #27272a;box-shadow:0 20px 50px rgb(0 0 0 / .6);overflow:hidden">
  <img src="__HOME__" style="width:100%;height:100%;object-fit:cover;object-position:top left;display:block"></div>
<div style="position:absolute;left:446px;top:330px;width:378px;height:11px;border-radius:0 0 12px 12px;
  background:linear-gradient(#3f3f46,#27272a)"></div>
<div style="position:absolute;left:818px;top:236px;width:82px;height:160px;border-radius:15px;background:#111113;
  border:3px solid #3f3f46;box-shadow:0 16px 40px rgb(0 0 0 / .65);display:flex;flex-direction:column;align-items:center;
  padding-top:22px;box-sizing:border-box">
  <div style="width:30px;height:30px;border-radius:50%;background:#27272a;margin-bottom:8px"></div>
  <div style="font:600 7.5px/1.25 var(--body);color:#e4e4e7;text-align:center">Unknown<br>number</div>
  <div style="font:500 6.5px/1 var(--body);color:#71717a;margin-top:4px">0:12</div>
  <div style="margin-top:22px;display:flex;align-items:center;gap:3px;font:700 6.5px/1 var(--body);color:#3ccf8e;
    background:rgb(60 207 142 / .12);border-radius:99px;padding:4px 7px">{SPK}<span>Speaker</span></div>
</div>
"""

CLOSE = f"""
<div style="position:absolute;left:270px;top:86px;display:flex;align-items:center;gap:9px">{LOGO}
  <span style="font:800 23px/1 var(--display);letter-spacing:-.02em">ScamLingo</span></div>
<div style="position:absolute;left:270px;top:132px;width:440px;display:grid;grid-template-columns:1fr 1fr;gap:12px">
  <div style="padding:13px 14px;border-radius:12px;background:#141416;border:1px solid #27272a">
    <div style="font:700 8px/1 var(--body);letter-spacing:.1em;text-transform:uppercase;color:#3ccf8e">Live</div>
    <div style="font:700 14px/1.3 var(--display);margin-top:7px">Phone on speaker.<br>Click Start listening.</div></div>
  <div style="padding:13px 14px;border-radius:12px;background:#141416;border:1px solid #27272a">
    <div style="font:700 8px/1 var(--body);letter-spacing:.1em;text-transform:uppercase;color:#3ccf8e">Recording</div>
    <div style="font:700 14px/1.3 var(--display);margin-top:7px">Upload a call<br>you already had.</div></div>
</div>
<div style="position:absolute;left:270px;top:226px;font:500 9.5px/1 var(--body);color:#71717a">
  Or try the built-in demo calls first.</div>
<div style="position:absolute;left:270px;top:410px;width:440px;font:500 8.5px/1.6 var(--body);color:#71717a">
  Built by <b style="color:#d4d4d8">Aarush Shetty</b> with Gnani Prisma v3.0 and Timbre v3.0.<br>
  Not 100% accurate. Doesn't block calls. Demo calls are synthetic: AI voices, made-up names.</div>
"""


def background(out: Path) -> Path:
    """The still under everything: page colour, the browser window and its bar."""
    els = [{"id": "w", "start": 0, "end": 1, "cls": "bgwin", "html": "", "in": {"type": "none"}, "out": {"type": "none"}},
           {"id": "b", "start": 0, "end": 1, "cls": "bgbar", "in": {"type": "none"}, "out": {"type": "none"},
            "html": "<i></i><i></i><i></i><span class='url'>localhost:8000</span>"}]
    d = BUILD / "bg"
    asyncio.run(overlay.render(d, els, CSS + "html,body{background:#0b0b0c !important}", 1 / FPS, port=9356,
                               stills=(0.0,), size=(960, 540)))
    src = d / "still_00.00.png"
    out.write_bytes(src.read_bytes())
    return out


# ------------------------------------------------------------------------------------------------ render
def render(T: Timeline, caps: dict, ticks: Path) -> float:
    BUILD.mkdir(parents=True, exist_ok=True)
    total = T.t
    # subtitles -> overlay elements (one line at a time; a new one replaces the last)
    subs = sorted(T.subs)
    for i, (a, b, who, text) in enumerate(subs):
        nxt = subs[i + 1][0] if i + 1 < len(subs) else 1e9
        b = min(b + 0.25, nxt - 0.05)
        tag = f"<span class='who'>{who}</span>" if who else ""
        T.el(a, b, f"<div class='box'>{tag}<span>{text}</span></div>", cls="sub", z=8, fin=("fade", 0.18),
             fout=("fade", 0.15))
    # rounded bottom corners of the window, over the footage
    for x, cx in ((96, "100%"), (855, "0")):     # the arc's centre sits inside the window
        T.el(0, total, "", cls="corner", style=f"left:{x}px;--cx:{cx}", z=3,
             fin=("none", 0), fout=("none", 0))

    bg = background(BUILD / "bg.png")
    ov_dir = BUILD / "overlay"
    concat = asyncio.run(overlay.render(ov_dir, T.ov, CSS, total, port=9357, size=(960, 540)))
    ov_mov = ov_dir / "overlay.mov"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "concat", "-safe", "0", "-i", str(concat),
                    "-vf", f"fps={FPS},format=argb", "-c:v", "qtrle", str(ov_mov)], check=True)

    vids = {k: c.video() for k, c in caps.items()}
    auds = {k: c.audio(ticks) for k, c in caps.items()}
    inputs, flt, pads = [], [], []
    idx = {}
    for k in caps:
        idx[k] = len(inputs)
        inputs += [["-i", str(vids[k])], ["-i", str(auds[k])]]
    uses = {k: sum(1 for p in T.pieces if p["cap"] == k) for k in caps}
    for k, n in uses.items():
        if n:
            flt.append(f"[{idx[k]}:v]split={n}" + "".join(f"[{k}v{j}]" for j in range(n)))
            flt.append(f"[{idx[k] + 1}:a]asplit={n}" + "".join(f"[{k}a{j}]" for j in range(n)))
    used = {k: 0 for k in caps}
    for i, p in enumerate(T.pieces):
        d = p["dur"]
        if p["cap"] is None:
            flt.append(f"color=c={APPBG}:s={APPW}x{APPH}:r={FPS}:d={d:.4f},format=yuv420p,setsar=1[pv{i}]")
            flt.append(f"anullsrc=r=48000:cl=stereo,atrim=0:{d:.4f}[pa{i}]")
        else:
            k, j = p["cap"], used[p["cap"]]
            used[k] += 1
            s0, s1, hold = p["s0"], p["s1"], p["hold"]
            fades = ""
            if p["dip_in"]:
                fades += f",fade=t=in:st=0:d={p['dip_in']}:color={APPBG}"
            if p["dip_out"]:
                fades += f",fade=t=out:st={d - p['dip_out']:.4f}:d={p['dip_out']}:color={APPBG}"
            if s1 > s0:
                flt.append(f"[{k}v{j}]trim=start={s0:.4f}:end={s1:.4f},setpts=PTS-STARTPTS,"
                           f"tpad=stop_mode=clone:stop_duration={hold + 0.1:.4f},trim=0:{d:.4f},setpts=PTS-STARTPTS"
                           f"{fades},setsar=1[pv{i}]")
                afades = f"afade=t=in:d=0.02,afade=t=out:st={max(0, s1 - s0 - 0.03):.4f}:d=0.03"
                if p["dip_in"]:
                    afades = f"afade=t=in:d={p['dip_in']},afade=t=out:st={max(0, s1 - s0 - 0.03):.4f}:d=0.03"
                if p["dip_out"] and not hold:
                    afades += f",afade=t=out:st={max(0, d - p['dip_out']):.4f}:d={p['dip_out']}"
                flt.append(f"[{k}a{j}]atrim=start={s0:.4f}:end={s1:.4f},asetpts=PTS-STARTPTS,{afades},"
                           f"apad=whole_dur={d:.4f},atrim=0:{d:.4f}[pa{i}]")
            else:
                flt.append(f"[{k}v{j}]trim=start={s0:.4f}:end={s0 + 0.1:.4f},setpts=PTS-STARTPTS,"
                           f"tpad=stop_mode=clone:stop_duration={d + 0.1:.4f},trim=0:{d:.4f},setpts=PTS-STARTPTS"
                           f"{fades},setsar=1[pv{i}]")
                flt.append(f"[{k}a{j}]atrim=0:0.01,volume=0,apad=whole_dur={d:.4f},atrim=0:{d:.4f}[pa{i}]")
        pads.append(f"[pv{i}][pa{i}]")
    flt.append(f"{''.join(pads)}concat=n={len(T.pieces)}:v=1:a=1[app][appa]")

    bgi = len(inputs)
    inputs.append(["-loop", "1", "-framerate", str(FPS), "-t", f"{total:.4f}", "-i", str(bg)])
    ovi = len(inputs)
    inputs.append(["-i", str(ov_mov)])
    flt.append(f"[{bgi}:v]format=yuv420p,setsar=1[bgv]")
    flt.append(f"[bgv][app]overlay={APPX}:{APPY}:shortest=0:eof_action=pass[v1]")
    flt.append(f"[{ovi}:v]fps={FPS},format=rgba[ov]")
    flt.append("[v1][ov]overlay=0:0:eof_action=pass:format=auto,format=yuv420p[vout]")

    mix = ["[appa]"]
    for j, n in enumerate(T.narr):
        ni = len(inputs)
        inputs.append(["-i", str(NARR / f"{n['id']}.wav")])
        g = gain_to(NARR / f"{n['id']}.wav", LEVEL["narr"])
        flt.append(f"[{ni}:a]aformat=sample_rates=48000:channel_layouts=stereo,volume={g:.4f},"
                   f"adelay={int(round(n['at'] * 1000))}:all=1[n{j}]")
        mix.append(f"[n{j}]")
    flt.append(f"{''.join(mix)}amix=inputs={len(mix)}:normalize=0:duration=first,atrim=0:{total:.4f},"
               f"alimiter=limit=0.97:level=false:latency=1[aout]")

    graph = BUILD / "graph.txt"
    graph.write_text(";\n".join(flt))
    rough = BUILD / "rough.mov"
    cmd = ["ffmpeg", "-v", "error", "-y"]
    for a in inputs:
        cmd += a
    cmd += ["-/filter_complex", str(graph), "-map", "[vout]", "-map", "[aout]", "-t", f"{total:.4f}",
            "-c:v", "libx264", "-preset", "slow", "-crf", "16", "-profile:v", "high", "-pix_fmt", "yuv420p",
            "-r", str(FPS), "-c:a", "pcm_s16le", str(rough)]
    subprocess.run(cmd, check=True)
    edit.loudnorm(rough, FINAL)
    return total


def main():
    global REC_MARK
    caps = {k: Cap(k) for k in ("scam", "safe", "rec")}
    REC_MARK = tuple(json.loads((WALK / "rec" / "mark.json").read_text())) if (WALK / "rec" / "mark.json").exists() \
        else (728, 466, 696, 114)       # "Please read it out to me..." bubble
    T = build_timeline(caps)
    (BUILD).mkdir(parents=True, exist_ok=True)
    (BUILD / "timeline.json").write_text(json.dumps({"pieces": T.pieces, "narr": T.narr, "subs": T.subs},
                                                    ensure_ascii=False, indent=1), "utf-8")
    print(f"timeline {T.t:.1f}s ({int(T.t // 60)}:{T.t % 60:04.1f}), {len(T.pieces)} pieces, {len(T.narr)} lines")
    if "--plan" in sys.argv:
        for p in T.pieces:
            print(f"  {p['t']:6.1f} +{p['dur']:5.2f}  {p['cap']} {p['s0']:.2f}-{p['s1']:.2f} hold {p['hold']:.2f}")
        return
    ticks = sfx.make(BUILD / "sfx")["tick"]
    total = render(T, caps, ticks)
    print(f"wrote {FINAL} ({total:.1f}s)")


if __name__ == "__main__":
    main()
