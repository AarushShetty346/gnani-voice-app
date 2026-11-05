"""Build the launch video (1080x1920 9:16, 30 fps, under 60 s) from the live captures.

    .venv\\Scripts\\python video\\launch.py            -> video/out/scamlingo-launch.mp4

Every app shot is real footage of the app on live Gnani (Prisma speech-to-text, Timbre warnings), captured by
capture_app.py and synced by footage.py. Cut points are call-time seconds read from each capture's own event
log (clip.json), so the edit follows what that run actually did. The app footage (1080x1350) sits in a band in
the middle of the frame (y 280-1630); headlines live in the band above it and captions below.

Narration (Timbre, voice Shivani, en-IN) lives in video/out/narration/:
  nh1-nh4  "Meet Scam Lingo. It listens to your phone call, live." / "Gnani Prisma writes down every word." /
           "Then it spots the lingo scammers use." / "And Gnani Timbre warns you out loud."
  (The name never opens a line: Timbre's first "S" comes out soft, and Prisma heard "Cam Lingo".)
  n0.wav   "Earlier, on the same call. She picks up. It's the police."   (pauses tightened -> n0s.wav)
  nl.wav   "It works in ten Indian languages."
  n2.wav   "Has your family got a call like this?"
"""
import asyncio
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import edit      # noqa: E402
import overlay   # noqa: E402
import sfx       # noqa: E402

CAP = HERE / "out" / "cap"
CAPS = {"da": CAP / "da-en-hangup", "legit": CAP / "legit-en"}
NARR = HERE / "out" / "narration"
OUT = HERE / "out" / "launch"
FINAL = HERE / "out" / "scamlingo-launch.mp4"

AY = edit.APP_Y / 2          # top of the app footage on the 540x960 overlay stage (CSS px)
DISCLOSURE = "Synthetic demo call: AI voices, made-up names"
LANGS = ["Hindi", "English", "Bengali", "Gujarati", "Kannada", "Malayalam", "Marathi", "Punjabi", "Tamil", "Telugu"]
LOGO = ('<svg viewBox="0 0 24 24"><path fill="#f4f4f5" d="M12 1.8 20.4 5v6.6c0 5.2-3.5 9.3-8.4 10.7-4.9-1.4-8.4-5.5'
        '-8.4-10.7V5z"/><path stroke="#0a0a0b" stroke-width="2" fill="none" stroke-linecap="round" '
        'd="M9 10v3.5M12 8.5v6.5M15 10v3.5"/></svg>')
REWIND = ('<svg width="66" height="40" viewBox="0 0 66 40"><path d="M31 2 3 20l28 18zM63 2 35 20l28 18z" '
          'fill="rgb(255 255 255 / .62)"/></svg>')

# Boxes measured on the captured frames (CSS px of the 540x675 app footage)
TRANSCRIPT_BOX = (11, 495, 466, 108)   # Prisma's first transcript bubble, da call 6.8-8.4
SHARE_BOX = (31, 600, 359, 58)         # "Share on WhatsApp" once the summary has scrolled up (da 44.6+)
SAFE_BOX = (384, 410, 124, 41)         # "Looks safe" pill, legit 39.6+
OTP_PIN = ((265, 297), (318, 345))     # "OTP" and "PIN" in the bank caller's bubble, legit 39.6+
OTP_Y = 282

EXTRA_CSS = """
.topband { left: 0; right: 0; top: 0; height: 140px; display: flex; flex-direction: column; justify-content: center;
  padding: 0 28px; }
.topband .k { font: 750 13px/1 var(--body); letter-spacing: .14em; text-transform: uppercase; color: var(--ink3);
  margin-bottom: 10px; }
.topband .k b { color: var(--ink); font-weight: 800; }
.topband .t { font: 800 31px/1.08 var(--display); letter-spacing: -.02em; color: var(--ink); text-wrap: balance; }
.t .dim, .tt .dim { color: var(--ink2); }
.t .red { color: #ff5a6e; }
.t .grn { color: var(--green); }
.t .amb { color: var(--amber); }
/* captions overlap the bottom of the app footage, so it shows through them */
.cap.bottom { top: auto; bottom: 160px; }
.cap .box { background: rgb(10 10 11 / .22); border-color: rgb(255 255 255 / .22); }
/* soft top/bottom edges on the app footage instead of a hard cut through its text */
.fadeT { left: 0; right: 0; height: 30px; background: linear-gradient(to bottom, #0a0a0b, rgb(10 10 11 / 0)); }
.fadeB { left: 0; right: 0; height: 26px; background: linear-gradient(to top, #0a0a0b, rgb(10 10 11 / 0)); }
.disc { left: 0; right: 0; display: flex; justify-content: center; }
.disc span { font: 650 13px/1 var(--body); color: rgb(255 255 255 / .8); background: rgb(255 255 255 / .06);
  padding: 6px 12px 7px; border-radius: 999px; letter-spacing: .01em; }
.box { border-radius: 12px; border: 3px solid #fff;
  box-shadow: 0 0 0 3px rgb(0 0 0 / .35), 0 0 22px rgb(255 255 255 / .35); }
.box.round { border-radius: 999px; }
.box.green { border-color: var(--green); box-shadow: 0 0 0 3px rgb(0 0 0 / .35), 0 0 24px rgb(60 207 142 / .6); }
.uline { height: 4px; border-radius: 2px; background: var(--green); box-shadow: 0 0 10px rgb(60 207 142 / .8); }
.edge { left: 0; width: 540px; height: 675px;
  box-shadow: inset 0 0 0 9px rgb(255 70 90 / .9), inset 0 0 90px rgb(255 40 60 / .65); }
.rew { left: 0; right: 0; display: flex; justify-content: center; }
.srow { left: 34px; right: 30px; display: flex; gap: 18px; align-items: flex-start; }
.srow .num { flex: none; width: 46px; height: 46px; border-radius: 50%; background: #0a0a0b; border: 2px solid #52525b;
  display: grid; place-items: center; font: 800 22px/1 var(--display); color: var(--ink); }
.srow .tt { font: 800 29px/1.08 var(--display); letter-spacing: -.02em; color: var(--ink); margin-top: 6px; }
.srow .sd { font: 600 18.5px/1.38 var(--body); color: var(--ink2); margin-top: 6px; }
.vline { left: 56px; width: 2px; background: #3f3f46; }
.langs { left: 34px; right: 34px; display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.langs .w { font: 700 19px/1 var(--body); color: var(--ink); background: #141416; border: 1px solid #2a2a2e;
  border-radius: 12px; padding: 13px 16px; }
.cta-box { left: 34px; right: 34px; padding: 16px 18px; border-radius: 16px; background: #141416;
  border: 1px solid #2a2a2e; font: 600 18px/1.4 var(--body); color: var(--ink2); }
.cta-box b { color: var(--ink); font-weight: 800; }
.foot { left: 34px; right: 34px; font: 600 16.5px/1.5 var(--body); color: var(--ink3); }
.foot b { color: var(--ink2); }
"""

base: list[dict] = []
els: list[dict] = []
audio: list[dict] = []
T = [0.0]


def seg(s: dict) -> float:
    t = T[0]
    base.append(s)
    T[0] += edit.seg_dur(s)
    return t


def el(start, end, html, cls="", style="", z=5, i=("fade", .3), o=("fade", .25), fx=None):
    d = {"id": f"e{len(els)}", "start": round(start, 4), "end": round(end, 4), "html": html, "cls": cls,
         "style": style, "z": z, "in": {"type": i[0], "dur": i[1]}, "out": {"type": o[0], "dur": o[1]}}
    if fx:
        d["fx"] = fx
    els.append(d)


def snd(at, src, gain=1.0, **kw):
    audio.append({"at": round(at, 4), "src": src, "gain": gain, **kw})


def head(t0, t1, text, kicker="", i=("rise", .45), o=("fade", .25)):
    """Headline in the band above the app footage, with an optional small kicker line."""
    k = f'<div class="k">{kicker}</div>' if kicker else ""
    el(t0, t1, f'{k}<div class="t">{text}</div>', cls="topband", z=20, i=i, o=o)


def caption(t0, t1, who, text, who_cls="caller", i=("fade", .35), o=("fade", .25)):
    """Caption on frosted glass: edit.py blurs the footage behind the box (it fades, so the blur can match)."""
    el(t0, t1, f'<div class="box"><span class="who {who_cls}">{who}</span>{text}</div>', cls="cap bottom", z=18,
       i=i, o=o)
    els[-1]["frost"] = True


def disc(t0, t1):
    el(t0, t1, f"<span>{DISCLOSURE}</span>", cls="disc", style="bottom:10px", z=30, i=("fade", .3), o=("fade", .3))


def ring(t0, t1, x, y, w, h, kind="", i=("pop", .4)):
    """Highlight box around something in the app footage (x, y in app px)."""
    el(t0, t1, "", cls=f"box {kind}", style=f"left:{x}px;top:{y + AY}px;width:{w}px;height:{h}px", z=15, i=i,
       o=("fade", .25))


def tap(t, x, y, end=None):
    el(t, min(t + 0.6, end or 1e9), '<div class="ring"></div><div class="dot"></div>', cls="ripple",
       style=f"left:{x}px;top:{y + AY}px", z=25, i=("none", 0), o=("none", 0), fx={"ripple": {}})
    snd(t, "sfx:tick", 0.55)


def flash(t, dur=0.45):
    el(t, t + dur, "", cls="edge", style=f"top:{AY}px", z=12, i=("none", 0), o=("fade", dur * .9))


def make_extra_sfx(d: Path) -> dict:
    recipes = {
        # warm C-major pad with some upper partials so it still reads on phone speakers
        "pad": "aevalsrc='0.04*(sin(2*PI*130.81*t)+0.8*sin(2*PI*196*t)+0.7*sin(2*PI*261.63*t)"
               "+0.5*sin(2*PI*329.63*t)+0.45*sin(2*PI*392*t)+0.35*sin(2*PI*523.25*t)+0.22*sin(2*PI*659.25*t)"
               "+0.12*sin(2*PI*1046.5*t)+0.1*sin(2*PI*1568*t)+0.07*sin(2*PI*2093*t)*(0.6+0.4*sin(2*PI*0.7*t)))*(0.85+0.15*sin(2*PI*0.3*t))':s=48000:d=20,"
               "lowpass=f=4500,aecho=0.8:0.6:70|140:0.25|0.15",
        # soft two-note chime for "Looks safe"
        "chime": "aevalsrc='0.35*sin(2*PI*1046.5*t)*exp(-t*4.5)+0.28*sin(2*PI*1568*t)*exp(-t*5.5)"
                 "*gte(t,0.09)':s=48000:d=1.5",
    }
    out = {}
    for name, src in recipes.items():
        p = d / f"{name}.wav"
        subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", src, "-ac", "2", "-ar", "48000", str(p)],
                       check=True)
        out[name] = p
    return out


def prep_narration():
    """Tighten the pauses in n0 (to fit the rewind card) and in nh1 (speech kept intact)."""
    for src, dst, keep, end in (
            ("n0", "n0s", "between(t,0,0.50)+between(t,0.70,1.62)+between(t,1.92,2.72)+between(t,3.02,3.92)", 3.0),
            ("nh1", "nh1s", "between(t,0,1.15)+between(t,1.40,2.85)+between(t,3.03,3.70)", 3.24)):
        subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(NARR / f"{src}.wav"), "-af",
                        f"aselect='{keep}',asetpts=N/SR/TB,afade=t=out:st={end}:d=0.03", str(NARR / f"{dst}.wav")],
                       check=True)


def edge_fades():
    """Fade the top and bottom edges of every app-footage segment laid so far."""
    t = 0.0
    for s in base:
        d = edit.seg_dur(s)
        if s["type"] == "clip":
            for cls, top in (("fadeT", AY), ("fadeB", AY + 675 - 26)):
                if cls == "fadeT" and not s.get("top_fade", True):   # page not scrolled: nothing cut at the top
                    continue
                el(t, t + d, "", cls=cls, style=f"top:{top}px", z=11, i=("none", 0), o=("none", 0))
        t += d


def timeline():
    # ---- S1 cold open: the real red alert, mid-call. Timbre's voice ("Stop! ...") starts 0.57 s before the
    # first frame, which is the first settled red frame.
    s1 = seg({"type": "clip", "cap": "da", "t0": 18.4, "t1": 20.4, "zoom": [1.0, 1.04], "focus": [540, 560],
              "audio": False, "top_fade": False})
    snd(s1, "cap:da", 1.0, t0=17.76, t1=19.86, fade_out=0.05)
    snd(s1 + 0.12, "sfx:alert", 0.2)
    head(s1, T[0], 'My app caught this scam <span class="red">mid-call.</span>', "ScamLingo", i=("none", 0),
         o=("fade", .3))
    flash(s1, 0.4)

    # ---- S2 how it works, narrated by Timbre
    s2 = seg({"type": "black", "dur": 11.0})
    snd(s2 - 0.05, "sfx:whoosh", 0.5)
    snd(s2 + 0.2, "sfx:pad", 0.38, t0=0, t1=15.2, fade_in=0.6, fade_out=0.6)    # bed under S2-S3
    snd(s2 + 0.25, str(NARR / "nh1s.wav"), 1.0)
    el(s2, T[0], "", cls="card grain", z=2, i=("fade", .4), o=("none", 0))
    el(s2 + 0.15, T[0], "How it works", cls="kicker", style="top:150px", i=("fade", .4), o=("fade", .3))
    el(s2 + 0.25, T[0], f'{LOGO}<span>ScamLingo</span>', cls="logo", style="left:34px;top:184px",
       i=("rise", .45), o=("fade", .3))
    el(s2 + 1.4, T[0], '<span class="w">listens</span> <span class="w">to</span> <span class="w">your</span> '
       '<span class="w">phone</span> <span class="w">call,</span> <span class="w">live.</span>',
       cls="h2", style="top:252px;color:var(--ink2)", i=("none", 0), o=("fade", .3), fx={"words": {"per": .17}})
    steps = [  # (narration, at, title, subtitle)
        ("nh2", 3.6, "Gnani Prisma", "writes down every word, live. Even Hinglish."),
        ("nh3", 6.1, "ScamLingo", "spots the lingo scammers use, and scores the risk."),
        ("nh4", 8.45, "Gnani Timbre", "warns you out loud, in your language."),
    ]
    for j, (n, at, title, sub) in enumerate(steps):
        snd(s2 + at, str(NARR / f"{n}.wav"), 1.0)
        el(s2 + at, T[0], f'<div class="num">{j + 1}</div><div><div class="tt">{title}</div>'
           f'<div class="sd">{sub}</div></div>', cls="srow", style=f"top:{378 + 150 * j}px", z=4,
           i=("rise", .45), o=("fade", .3))
        if j:
            el(s2 + at, T[0], "", cls="vline", style=f"top:{378 + 150 * j - 102}px;height:100px", z=3,
               i=("fade", .4), o=("fade", .3))

    # ---- S3 rewind card, narrated ("Earlier, on the same call. She picks up. It's the police.")
    s3 = seg({"type": "black", "dur": 3.6})
    snd(s3 - 0.05, "sfx:whoosh", 0.6)
    snd(s3 + 0.40, str(NARR / "n0s.wav"), 1.0)
    el(s3, T[0], "", cls="card grain", z=2, i=("none", 0), o=("none", 0))
    el(s3 + 0.05, T[0], REWIND, cls="rew", style="top:330px", i=("pop", .4), o=("fade", .3))
    el(s3 + 0.15, T[0], "Earlier on the same call", cls="kicker center", style="top:406px", i=("fade", .35),
       o=("fade", .3))
    el(s3 + 1.90, T[0], '<span class="w">She</span> <span class="w">picks</span> <span class="w">up.</span>',
       cls="h1 center", style="top:448px;font-size:48px", i=("none", 0), o=("fade", .3), fx={"words": {"per": .12}})
    el(s3 + 2.76, T[0], 'It\'s <span class="red">"the police"</span>.', cls="h1 center",
       style="top:508px;font-size:48px", i=("slam", .3), o=("fade", .3))
    snd(s3 + 2.76, "sfx:hit", 0.15)

    # ---- S4 the call starts (in the pause after "Hello"); Prisma's first transcript line lands at call 6.78
    s4 = seg({"type": "clip", "cap": "da", "t0": 2.4, "t1": 8.4, "vfade_in": 0.35, "top_fade": False})
    head(s4 + 0.2, s4 + 4.3, 'A <span class="red">"police inspector"</span> calls', "Real app · live on Gnani")
    head(s4 + 4.3, T[0], 'Gnani Prisma <span class="dim">writes it down, live</span>', "<b>Step 1</b> · hears")
    caption(s4 + 0.1, s4 + 3.84, "Caller · Hindi", "I'm Inspector Rajesh Sharma from the Mumbai Cyber Crime Branch.")
    # Off before her reply lands (call 8.07) and the transcript list scrolls up under the box (8.1).
    ring(s4 + 4.45, s4 + 8.05 - 2.4, *TRANSCRIPT_BOX)

    # ---- S5 he builds a fake case
    s5 = seg({"type": "clip", "cap": "da", "t0": 9.4, "t1": 13.8, "fade_out": 0.08})
    head(s5, T[0], 'He builds a <span class="red">fake case</span>')
    caption(s5 + 0.05, T[0], "Caller · Hindi", "A parcel was booked on your Aadhaar card. Customs found drugs in it.")

    # ---- S6 one continuous take: the risk jumps, the amber warning, then the red alert and Timbre's voice
    s6 = seg({"type": "clip", "cap": "da", "t0": 14.3, "t1": 24.2})
    c6 = s6 - 14.3                     # call time -> video time in this shot
    head(s6, c6 + 17.7, 'ScamLingo <span class="dim">spots the lingo.</span> <span class="amb">Risk 61.</span>',
         "<b>Step 2</b> · checks")
    snd(c6 + 17.7, "sfx:hit", 0.15)
    flash(c6 + 17.7)
    head(c6 + 17.7, c6 + 20.4, 'Gnani Timbre <span class="dim">warns her out loud</span>', "<b>Step 3</b> · warns",
         i=("rise", .35))
    head(c6 + 20.4, T[0], 'Before he even said <span class="red">"digital arrest"</span>', "<b>Step 3</b> · warns")
    caption(c6 + 18.0, T[0], "Caller · Hindi", "There's an arrest warrant in your name. You're under digital arrest.")

    # ---- S7 she taps "Got it", then Stop: the call audio dies
    s7 = seg({"type": "clip", "cap": "da", "t0": 24.2, "t1": 25.2, "fade_out": 0.04})
    s7b = seg({"type": "clip", "cap": "da", "t0": 25.72, "t1": 26.12, "freeze": 1.2, "audio": False})
    tap(s7 + 0.56, 270, 447)
    tap(s7b + 0.02, 464.6, 24)
    head(s7 + 0.1, T[0], 'She hangs up <span class="dim">before the money ask.</span>')

    # ---- S8 the WhatsApp-ready summary (on screen from 39.1; scrolls to the Share button at 44.2-44.6)
    s8 = seg({"type": "clip", "cap": "da", "t0": 41.8, "t1": 44.8, "freeze": 1.0, "audio": False,
              "vfade_in": 0.3})
    snd(s7b + 0.9, "sfx:pad", 0.8, t0=0, t1=T[0] - s7b - 0.9, fade_in=0.5, fade_out=0.5)
    head(s8 + 0.15, T[0], 'A summary <span class="grn">to send family</span>', "After the call")
    ring(s8 + 2.8, T[0], *SHARE_BOX, "green")

    # ---- S9 a normal bank call in Hindi: it says OTP and PIN, and stays safe
    s9 = seg({"type": "clip", "cap": "legit", "t0": 16.5, "t1": 22.4, "vfade_in": 0.3, "fade_out": 0.1})
    c9 = s9 - 16.5
    head(s9 + 0.15, T[0], 'A normal bank call <span class="dim">in Hindi</span>', "The other side")
    caption(c9 + 16.6, c9 + 20.8, "Bank caller · Hindi",
            "Remember, the bank never asks for an OTP or PIN over the phone.")
    s10 = seg({"type": "clip", "cap": "legit", "t0": 39.8, "t1": 42.0, "freeze": 0.4, "audio": False})
    snd(s10 + 0.3, "sfx:chime", 0.45)
    head(s10, T[0], 'Says <span class="grn">"OTP"</span> and <span class="grn">"PIN"</span>. '
         '<span class="grn">Stays safe.</span>', "After the call", i=("rise", .35))
    for x0, x1 in OTP_PIN:
        el(s10 + 0.4, T[0], "", cls="uline", style=f"left:{x0}px;top:{OTP_Y + AY}px;width:{x1 - x0}px", z=16,
           i=("wipe", .35))
    ring(s10 + 0.9, T[0], *SAFE_BOX, "green round")

    disc(s1, s2)
    edge_fades()
    disc(s4, T[0])

    # ---- S11 languages + what it's built on
    s11 = seg({"type": "black", "dur": 3.6})
    snd(s11 - 0.4, "sfx:whoosh", 0.45)
    snd(s11 + 0.25, str(NARR / "nl.wav"), 1.0)
    snd(s11, "sfx:pad", 0.6, t0=0, t1=7.7, fade_in=0.8, fade_out=1.4)
    el(s11, T[0], "", cls="card", z=2, i=("fade", .3), o=("none", 0))
    el(s11 + 0.15, T[0], 'Works in <span style="color:var(--green)">10</span> Indian languages', cls="h2",
       style="top:190px;font-size:40px", i=("rise", .4), o=("fade", .3))
    el(s11 + 0.5, T[0], "".join(f'<span class="w">{x}</span>' for x in LANGS), cls="langs", style="top:300px",
       z=4, i=("none", 0), o=("fade", .3), fx={"words": {"per": .07}})
    el(s11 + 1.5, T[0], "Hears the call and warns you in every one of them, including code-mixed calls like Hinglish.",
       cls="foot", style="top:612px;font-size:18px;color:var(--ink2)", i=("fade", .4), o=("fade", .3))
    el(s11 + 1.9, T[0], "Built on <b>Gnani Prisma</b> (speech-to-text) and <b>Gnani Timbre</b> (voice).",
       cls="foot", style="top:688px", i=("fade", .4), o=("fade", .3))

    # ---- S12 call to action (the last second holds still)
    s12 = seg({"type": "black", "dur": 4.2})
    snd(s12 + 0.25, str(NARR / "n2.wav"), 1.0, t0=0, t1=2.0, fade_out=0.05)
    el(s12, T[0], "", cls="card", z=1, i=("none", 0), o=("none", 0))
    el(s12, T[0], "Has your family got a call like this?", cls="h1", style="top:190px;font-size:48px",
       i=("rise", .45), o=("none", 0))
    el(s12 + 0.8, T[0], "Tell me in the comments.", cls="h2", style="top:356px;font-size:28px;color:var(--ink2)",
       i=("rise", .4), o=("none", 0))
    el(s12 + 1.3, T[0], "Lost money to a scam? Call <b>1930</b> or report at <b>cybercrime.gov.in</b>",
       cls="cta-box", style="top:430px", i=("rise", .4), o=("none", 0))
    el(s12 + 1.8, T[0], f'{LOGO}<span>ScamLingo</span>', cls="logo", style="left:34px;top:574px;font-size:24px",
       i=("fade", .4), o=("none", 0))
    el(s12 + 2.0, T[0], "Built by <b>Aarush Shetty</b><br>Not 100% accurate. Doesn't block calls.<br>"
       "Demo calls are synthetic: AI voices, made-up names.",
       cls="foot", style="top:630px", i=("fade", .4), o=("none", 0))
    el(s12 + 2.2, T[0], "#GnaniAI<br>#GreatIndianAIInternshipChallenge", cls="foot",
       style="top:742px;font:800 21px/1.4 var(--body);color:var(--ink)", i=("fade", .4), o=("none", 0))
    return T[0]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    prep_narration()
    total = timeline()
    print(f"timeline: {total:.2f} s, {len(base)} segments, {len(els)} overlay elements, {len(audio)} sounds")
    sounds = sfx.make(HERE / "out" / "sfx")
    sounds.update(make_extra_sfx(HERE / "out" / "sfx"))
    css = (HERE / "style.css").read_text("utf-8") + EXTRA_CSS
    frosts: list[dict] = []
    concat = asyncio.run(overlay.render(OUT / "overlay", els, css, total, frosts=frosts))
    spec = {"captures": {k: str(v) for k, v in CAPS.items()}, "base": base, "audio": audio, "frost": frosts}
    edit.build(spec, OUT, concat, sounds, FINAL)
    print(f"wrote {FINAL}")


if __name__ == "__main__":
    main()
