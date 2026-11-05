"""Build the launch video (1080x1350, 30 fps, under 60 s) from the live captures.

    .venv\\Scripts\\python video\\launch.py            -> video/out/scam-kavach-launch.mp4

Every app shot is real footage of the app on live Gnani (Prisma v3.0 speech-to-text, Timbre v3.0 warnings),
captured by capture_app.py and synced by footage.py. Cut points are call-time seconds read from each
capture's own event log (clip.json), so the edit follows what that run actually did.

Narration (Timbre v3.0, voice Shivani, en-IN) lives in video/out/narration/:
  n0.wav  "Earlier, on the same call. She picks up. It's the police."   (pauses tightened -> n0s.wav)
  n1.wav  "Gnani Prisma hears the call. Gnani Timbre speaks the warning."
  n2.wav  "Has your family got a call like this?"
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
CAPS = {"da": CAP / "da-en-hangup", "kyc": CAP / "kyc-en", "kn": CAP / "kn-auto", "legit": CAP / "legit-en"}
NARR = HERE / "out" / "narration"
OUT = HERE / "out" / "launch"
FINAL = HERE / "out" / "scam-kavach-launch.mp4"

DISCLOSURE = "Synthetic demo call: AI voices, made-up names"
LOGO = ('<svg viewBox="0 0 24 24"><path fill="#f4f4f5" d="M12 1.8 20.4 5v6.6c0 5.2-3.5 9.3-8.4 10.7-4.9-1.4-8.4-5.5'
        '-8.4-10.7V5z"/><path stroke="#0a0a0b" stroke-width="2" fill="none" stroke-linecap="round" '
        'd="M9 10v3.5M12 8.5v6.5M15 10v3.5"/></svg>')
REWIND = ('<svg width="66" height="40" viewBox="0 0 66 40"><path d="M31 2 3 20l28 18zM63 2 35 20l28 18z" '
          'fill="rgb(255 255 255 / .62)"/></svg>')

# Boxes measured on the captured frames (CSS px of the 540x675 stage)
TRANSCRIPT_BOX = (11, 495, 466, 108)   # Prisma's first transcript bubble, da call 6.9-8.1
SHARE_BOX = (29, 620, 357, 64)         # "Share on WhatsApp" once the summary stops scrolling (da 44.6+)
SAFE_BOX = (383, 247, 122, 40)         # "Looks safe" pill, legit 31.7-33.7

EXTRA_CSS = """
.scrimT { left: 0; right: 0; top: 0; height: 178px;
  background: linear-gradient(to bottom, rgb(10 10 11 / .95) 0%, rgb(10 10 11 / .86) 50%, rgb(10 10 11 / 0) 100%); }
.scrimT.solid { height: 205px; background: linear-gradient(to bottom, #0a0a0b 0%, #0a0a0b 52%, rgb(10 10 11 / 0) 100%); }
.scrimB.solid { background: linear-gradient(to top, #0a0a0b 0%, #0a0a0b 58%, rgb(10 10 11 / 0) 100%); }
.cap.opaque .box { background: #141416; }
.scrimB { left: 0; right: 0; bottom: 0; height: 170px;
  background: linear-gradient(to top, rgb(10 10 11 / .96) 0%, rgb(10 10 11 / .9) 55%, rgb(10 10 11 / 0) 100%); }
.hl { left: 28px; right: 28px; font: 800 33px/1.06 var(--display); letter-spacing: -.02em; color: var(--ink);
  text-wrap: balance; }
.hl.top { top: 22px; }
.hl.bot { bottom: 46px; }
.hl .dim { color: var(--ink2); }
.hl .red { color: #ff5a6e; }
.hl .grn { color: var(--green); }
.hl .amb { color: var(--amber); }
.band { left: 0; right: 0; padding: 14px 28px 15px; background: rgb(10 10 11 / .93);
  border-top: 1px solid rgb(255 255 255 / .08); border-bottom: 1px solid rgb(255 255 255 / .08); }
.disc { left: 0; right: 0; display: flex; justify-content: center; }
.disc span { font: 650 14px/1 var(--body); color: rgb(255 255 255 / .86); background: rgb(10 10 11 / .8);
  padding: 6px 12px 7px; border-radius: 999px; letter-spacing: .01em; }
.box { border-radius: 12px; border: 3px solid #fff;
  box-shadow: 0 0 0 3px rgb(0 0 0 / .35), 0 0 22px rgb(255 255 255 / .35); }
.box.round { border-radius: 999px; }
.box.green { border-color: var(--green); box-shadow: 0 0 0 3px rgb(0 0 0 / .35), 0 0 24px rgb(60 207 142 / .6); }
.box.red { border-color: #ff4d5e; box-shadow: 0 0 0 3px rgb(0 0 0 / .35), 0 0 24px rgb(255 77 94 / .6); }
.uline { height: 4px; border-radius: 2px; background: var(--green); box-shadow: 0 0 10px rgb(60 207 142 / .8); }
.edge { left: 0; top: 0; width: 540px; height: 675px;
  box-shadow: inset 0 0 0 9px rgb(255 70 90 / .9), inset 0 0 90px rgb(255 40 60 / .65); }
.cap.bottom { bottom: 46px; }
.rew { left: 0; right: 0; display: flex; justify-content: center; }
.celltag { font: 700 13px/1 var(--body); letter-spacing: .08em; text-transform: uppercase; color: var(--ink);
  background: rgb(10 10 11 / .86); padding: 6px 9px; border-radius: 8px; border: 1px solid rgb(255 255 255 / .12); }
.cta-box { left: 34px; right: 34px; padding: 16px 18px; border-radius: 16px; background: #141416;
  border: 1px solid #2a2a2e; font: 600 18px/1.4 var(--body); color: var(--ink2); }
.cta-box b { color: var(--ink); font-weight: 800; }
.foot { left: 34px; right: 34px; font: 600 17px/1.5 var(--body); color: var(--ink3); }
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


def el(start, end, html, cls="", style="", z=5, i=("fade", .25), o=("fade", .2), fx=None):
    d = {"id": f"e{len(els)}", "start": round(start, 4), "end": round(end, 4), "html": html, "cls": cls,
         "style": style, "z": z, "in": {"type": i[0], "dur": i[1]}, "out": {"type": o[0], "dur": o[1]}}
    if fx:
        d["fx"] = fx
    els.append(d)


def snd(at, src, gain=1.0, **kw):
    audio.append({"at": round(at, 4), "src": src, "gain": gain, **kw})


def head(t0, t1, text, where="top", i=("rise", .35), o=("fade", .18), style=""):
    el(t0, t1, text, cls=f"hl {where}".strip(), style=style, z=20, i=i, o=o)


def scrim(t0, t1, where="T", i=("fade", .2), o=("fade", .2), kind="", style=""):
    el(t0, t1, "", cls=f"scrim{where} {kind}".strip(), style=style, z=10, i=i, o=o)


def caption(t0, t1, who, text, where="bottom", style="", who_cls="caller", i=("rise", .3), o=("fade", .2)):
    el(t0, t1, f'<div class="box"><span class="who {who_cls}">{who}</span>{text}</div>', cls=f"cap {where}",
       style=style, z=18, i=i, o=o)


def disc(t0, t1, style="bottom: 9px"):
    el(t0, t1, f"<span>{DISCLOSURE}</span>", cls="disc", style=style, z=30, i=("none", 0), o=("none", 0))


def ring(t0, t1, x, y, w, h, kind="", i=("pop", .35)):
    el(t0, t1, "", cls=f"box {kind}", style=f"left:{x}px;top:{y}px;width:{w}px;height:{h}px", z=15, i=i,
       o=("fade", .2))


def tap(t, x, y, end=None):
    el(t, min(t + 0.6, end or 1e9), '<div class="ring"></div><div class="dot"></div>', cls="ripple",
       style=f"left:{x}px;top:{y}px", z=25, i=("none", 0), o=("none", 0), fx={"ripple": {}})
    snd(t, "sfx:tick", 0.55)


def flash(t, dur=0.35):
    el(t, t + dur, "", cls="edge", z=12, i=("none", 0), o=("fade", dur * .9))


def make_extra_sfx(d: Path) -> dict:
    recipes = {
        # warm C-major pad with some upper partials so it still reads on phone speakers
        "pad": "aevalsrc='0.04*(sin(2*PI*130.81*t)+0.8*sin(2*PI*196*t)+0.7*sin(2*PI*261.63*t)"
               "+0.5*sin(2*PI*329.63*t)+0.45*sin(2*PI*392*t)+0.35*sin(2*PI*523.25*t)+0.22*sin(2*PI*659.25*t)"
               "+0.12*sin(2*PI*1046.5*t)+0.1*sin(2*PI*1568*t)+0.07*sin(2*PI*2093*t)*(0.6+0.4*sin(2*PI*0.7*t)))*(0.85+0.15*sin(2*PI*0.3*t))':s=48000:d=14,"
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
    """n0 with its pauses tightened so it fits the rewind card (speech kept intact)."""
    keep = "between(t,0,0.50)+between(t,0.70,1.62)+between(t,1.92,2.72)+between(t,3.02,3.92)"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(NARR / "n0.wav"), "-af",
                    f"aselect='{keep}',asetpts=N/SR/TB,afade=t=out:st=3.0:d=0.03", str(NARR / "n0s.wav")],
                   check=True)


def timeline():
    # ---- S1 cold open: the real red alert, mid-call. The voice ("Stop! ...") starts 0.57 s before the
    # first frame, which is the first settled red frame.
    s1 = seg({"type": "clip", "cap": "da", "t0": 18.38, "t1": 19.95, "zoom": [1.0, 1.05], "focus": [540, 560],
              "audio": False})
    snd(s1, "cap:da", 1.0, t0=17.81, t1=19.88, fade_out=0.05)
    snd(s1 + 0.12, "sfx:alert", 0.2)
    scrim(s1, T[0], i=("none", 0), kind="solid")
    head(s1, T[0], 'My app caught this <span class="red">mid-call.</span>', i=("none", 0), o=("none", 0))
    flash(s1, 0.3)

    # ---- S2 rewind card, narrated by Timbre ("Earlier, on the same call. She picks up. It's the police.")
    s2 = seg({"type": "black", "dur": 3.6})
    snd(s2 - 0.05, "sfx:whoosh", 0.6)
    snd(s2 + 0.40, str(NARR / "n0s.wav"), 1.0)
    snd(s2 + 0.2, "sfx:pad", 0.45, t0=0, t1=5.0, fade_in=0.4, fade_out=0.5)   # bed under S2-S3
    el(s2, T[0], "", cls="card grain", z=2, i=("none", 0), o=("none", 0))
    el(s2 + 0.05, T[0], REWIND, cls="rew", style="top:150px", i=("pop", .35), o=("none", 0))
    el(s2 + 0.15, T[0], "Earlier on the same call", cls="kicker center", style="top:226px", i=("fade", .3),
       o=("none", 0))
    el(s2 + 1.90, T[0], '<span class="w">She</span> <span class="w">picks</span> <span class="w">up.</span>',
       cls="h1 center", style="top:268px;font-size:48px", i=("none", 0), o=("none", 0), fx={"words": {"per": .12}})
    el(s2 + 2.76, T[0], 'It\'s <span class="red">"the police"</span>.', cls="h1 center",
       style="top:328px;font-size:48px", i=("slam", .3), o=("none", 0))
    snd(s2 + 2.76, "sfx:hit", 0.15)

    # ---- S3 pre-roll: the real app on live Gnani, tap Play
    s3 = seg({"type": "clip", "cap": "da", "t0": -2.55, "t1": -0.95})
    ring(s3 + 0.1, T[0], 335, 22, 108, 36, "round")
    tap(s3 + 1.35, 464.8, 494.6, end=T[0])
    scrim(s3, T[0], "B", kind="solid", style="height:230px")
    head(s3, T[0], 'Real app. <span class="grn">Live Gnani.</span>', "bot", i=("rise", .3))

    # ---- S4 the call starts (in the pause after "Hello"); Prisma's first transcript line lands at call 6.8
    s4 = seg({"type": "clip", "cap": "da", "t0": 2.38, "t1": 8.1})
    scrim(s4, T[0])
    head(s4, s4 + 3.9, 'A <span class="red">"police inspector"</span> calls')
    head(s4 + 3.9, T[0], 'Gnani Prisma v3.0 <span class="dim">hears it live</span>', i=("rise", .3))
    caption(s4 + 0.05, s4 + 3.88, "Caller · Hindi",
            "I'm Inspector Rajesh Sharma from the Mumbai Cyber Crime Branch.")
    ring(s4 + 4.52, T[0], *TRANSCRIPT_BOX)

    # ---- S5 risk climbs, first (amber) warning
    s5a = seg({"type": "clip", "cap": "da", "t0": 9.25, "t1": 13.8, "fade_out": 0.08})
    s5b = seg({"type": "clip", "cap": "da", "t0": 14.2, "t1": 17.44})
    scrim(s5a, s5b)
    head(s5a, s5b, 'He builds a <span class="red">fake case</span>', o=("fade", .15))
    caption(s5a + 0.05, s5a + 4.5, "Caller · Hindi", "A parcel was booked on your Aadhaar card. Customs found drugs in it.")
    # S5b: the gauge (jumping to 61) is at the very top and the amber banner arrives at the bottom, so the
    # headline and the disclosure sit on a band across the transcript in between, as the banner lands.
    band_at = s5b + 0.5
    el(band_at, T[0], f'<div class="disc" style="position:absolute;bottom:9px"><span>{DISCLOSURE}</span></div>',
       cls="band", style="top:290px;height:96px;padding:0", z=19, i=("fade", .2))
    head(band_at, T[0], 'Risk jumps. <span class="amb">First warning.</span>', "", i=("rise", .3),
         style="top:302px")

    # ---- S6 back to the red alert: Timbre says it out loud
    s6 = seg({"type": "clip", "cap": "da", "t0": 19.95, "t1": 24.19, "zoom": [1.0, 1.06], "focus": [540, 560],
              "fade_in": 0.02})
    snd(s6, "sfx:hit", 0.15)
    flash(s6, 0.35)
    scrim(s6, T[0], i=("none", 0), kind="solid")
    head(s6, s6 + 2.1, 'Gnani Timbre v3.0 <span class="dim">says it out loud</span>', i=("rise", .3))
    head(s6 + 2.1, T[0], 'Before he even said <span class="red">"digital arrest"</span>', i=("rise", .3))

    # ---- S7 she taps "Got it", then Stop: the call audio dies
    s7 = seg({"type": "clip", "cap": "da", "t0": 24.63, "t1": 25.13, "fade_out": 0.04})
    s7b = seg({"type": "clip", "cap": "da", "t0": 25.95, "t1": 26.35, "freeze": 0.8, "audio": False})
    tap(s7 + 0.30, 270, 447)
    snd(s7b, "sfx:tick", 0.45)
    scrim(s7, T[0], "B", style="height:230px")
    head(s7 + 0.05, T[0], 'Hung up <span class="dim">before the money ask.</span>', "bot", i=("rise", .3))

    # ---- S8 the WhatsApp-ready summary (the capture's slow scroll ends at 44.6; hold that frame)
    s8 = seg({"type": "clip", "cap": "da", "t0": 40.3, "t1": 44.7, "freeze": 0.6, "audio": False})
    snd(s7b + 0.75, "sfx:pad", 0.9, t0=0, t1=T[0] - s7b - 0.75, fade_in=0.5, fade_out=0.5)
    scrim(s8, T[0])
    head(s8 + 0.1, T[0], 'A summary to <span class="grn">send family</span>')
    ring(s8 + 4.0, T[0], *SHARE_BOX, "green")

    # ---- S9 Kannada call, Kannada warning
    s9a = seg({"type": "clip", "cap": "kn", "t0": 11.95, "t1": 15.1, "fade_in": 0.06, "fade_out": 0.06})
    s9b = seg({"type": "clip", "cap": "kn", "t0": 16.2, "t1": 19.3, "zoom": [1.0, 1.04], "focus": [540, 300]})
    snd(s9b + 0.1, "sfx:hit", 0.15)
    scrim(s9a, s9b, "B", o=("none", 0))
    head(s9a, s9b + 0.35, 'Kannada call. <span class="dim">Kannada warning.</span>', "bot", o=("fade", .15))
    el(s9b, T[0], "", cls="band", style="top:auto;bottom:0;height:165px;padding:0;background:#0a0a0b", z=19,
       i=("none", 0), o=("none", 0))
    head(s9b + 0.35, T[0], 'Red <span class="red">about 1 second</span> after the threat', "bot", i=("rise", .3),
         o=("none", 0))
    caption(s9a + 0.05, s9a + 2.81, "Caller · Kannada", "Your home's power will be cut tonight at 9 o'clock.",
            "top", "top:400px")
    caption(s9b + 0.3, T[0], "Kavach · in Kannada", "Stop! This looks like a scam call.", "top", "top:18px",
            "kavach")

    # ---- S10 grid: three scams go red, the real-style bank call stays safe
    cells = [("da", 17.44, [72, 210], "Hindi"), ("kyc", 18.27, [576, 210], "English"),
             ("kn", 14.74, [72, 762], "Kannada"), ("legit", 12.9, [576, 762], "Hindi · bank")]
    s10 = seg({"type": "grid", "dur": 3.6, "cells": [
        {"cap": c, "t0": t0, "rect": [x, y, 432, 540], "audio": c == "kyc"} for c, t0, (x, y), _ in cells]})
    head(s10, T[0], '3 scams flagged.<br><span class="grn">1 safe call: no warning.</span>', i=("rise", .3))
    for j, (c, _, (x, y), label) in enumerate(cells):
        cx, cy = x / 2, y / 2
        el(s10 + 0.1, T[0], label, cls="celltag", style=f"left:{cx + 8}px;top:{cy + 270 - 34}px", z=16,
           i=("fade", .2))
        if c != "legit":
            red_at = s10 + 0.4 + 0.5 * j
            ring(red_at, T[0], cx - 2, cy - 2, 220, 274, "red")
            snd(red_at, "sfx:hit", 0.15)
    ring(s10 + 1.7, T[0], 286, 379, 220, 274, "green")
    el(s10 + 1.75, T[0], '<span class="pill green" style="background:#0f2a1d"><span class="dot"></span>'
       'Stays safe</span>', style="left:300px;top:412px", z=17, i=("pop", .35))
    snd(s10 + 1.75, "sfx:chime", 0.35)

    # ---- S11 zoom into the safe call: it says OTP and PIN, and stays safe
    s11 = seg({"type": "clip", "cap": "legit", "t0": 18.0, "t1": 23.6, "fade_out": 0.1})
    el(s11, s11 + 3.7, '<div class="hl" style="position:static">A normal bank call <span class="dim">in Hindi</span></div>',
       cls="band", style="top:236px", z=20, i=("fade", .25), o=("fade", .15))
    el(s11 + 3.7, T[0], '<div class="hl" style="position:static">Says <span class="grn">"OTP"</span> and '
       '<span class="grn">"PIN"</span>. Stays safe.</div>', cls="band", style="top:236px", z=20, i=("fade", .2))
    # Captions sit just above the OTP/PIN sentence (bottom edge at y 608) so they never cover the words.
    cap_pos = "top:auto;bottom:67px"
    caption(s11 + 0.05, s11 + 3.3, "Bank caller · Hindi",
            "Remember, the bank never asks for an OTP or PIN over the phone.", "", cap_pos, o=("none", 0))
    caption(s11 + 3.3, T[0], "Bank caller · Hindi", "Have a good day.", "opaque",
            cap_pos + ";left:20px;justify-content:flex-start", i=("none", 0))
    for x0, x1 in ((352, 384), (406, 434)):
        el(s11 + 4.05, T[0] - 0.1, "", cls="uline", style=f"left:{x0}px;top:633px;width:{x1 - x0}px", z=16,
           i=("wipe", .3))

    # ---- S12 after the call: Looks safe
    s12 = seg({"type": "clip", "cap": "legit", "t0": 31.7, "t1": 33.7, "fade_in": 0.06})
    snd(s12 + 0.25, "sfx:chime", 0.45)
    scrim(s12, T[0])
    head(s12, T[0], 'After the call: <span class="grn">Looks safe</span>')
    ring(s12 + 0.35, T[0], *SAFE_BOX, "green round")

    disc(0.0, band_at)
    disc(s6, s8)
    disc(s8, s9a, "top:66px")
    disc(s9a, s12)
    disc(s12, T[0], "top:66px")       # keep off the Share button

    # ---- S13 credits
    s13 = seg({"type": "black", "dur": 5.0})
    snd(s13 - 0.45, "sfx:whoosh", 0.45)
    snd(s13 + 0.25, str(NARR / "n1.wav"), 1.0)
    end_all = s13 + 5.0 + 5.2
    snd(s13, "sfx:pad", 0.6, t0=0, t1=end_all - s13, fade_in=0.8, fade_out=1.4)
    end13 = T[0]               # credits fade out by the cut; the CTA headline rises at once (no blink)
    el(s13, end13, "", cls="card", z=2, i=("fade", .25), o=("none", 0))
    el(s13 + 0.15, end13, f'{LOGO}<span>Scam Kavach</span>', cls="logo", style="left:34px;top:120px",
       i=("rise", .35), o=("fade", .25))
    el(s13 + 0.35, end13, "Built on Gnani AI", cls="kicker", style="top:218px", i=("fade", .3), o=("fade", .25))
    el(s13 + 0.5, end13, 'Prisma v3.0<br><span class="dim">hears the call live</span>', cls="h2",
       style="top:252px", i=("rise", .35), o=("fade", .25))
    el(s13 + 2.4, end13, 'Timbre v3.0<br><span class="dim">speaks the warning</span>', cls="h2",
       style="top:352px", i=("rise", .35), o=("fade", .25))
    el(s13 + 3.0, end13, "<b>Measured live: 5/5 demo calls judged right.</b><br>Not 100% accurate. "
       "Doesn't block calls.<br>Optional LLM second opinion on top.", cls="foot", style="top:490px", i=("fade", .35), o=("fade", .25))

    # ---- S14 call to action (the last second holds still)
    s14 = seg({"type": "black", "dur": 5.2})
    snd(s14 + 0.3, str(NARR / "n2.wav"), 1.0, t0=0, t1=2.6, fade_out=0.05)
    el(s14, T[0], "", cls="card", z=1, i=("none", 0), o=("none", 0))
    el(s14 + 0.0, T[0], "Has your family got a call like this?", cls="h1", style="top:96px;font-size:48px",
       i=("rise", .4), o=("none", 0))
    el(s14 + 0.9, T[0], "Tell me in the comments.", cls="h2", style="top:262px;font-size:28px;color:var(--ink2)",
       i=("rise", .35), o=("none", 0))
    el(s14 + 1.6, T[0], "Lost money to a scam? Call <b>1930</b> or report at <b>cybercrime.gov.in</b>",
       cls="cta-box", style="top:338px", i=("rise", .35), o=("none", 0))
    el(s14 + 2.3, T[0], f'{LOGO}<span>Scam Kavach</span>', cls="logo", style="left:34px;top:470px;font-size:24px",
       i=("fade", .35), o=("none", 0))
    el(s14 + 2.5, T[0], "Built on Gnani Prisma v3.0 + Timbre v3.0<br>Built by <b>Aarush Shetty</b>, VIT Vellore<br>"
       "Demo calls are synthetic: AI voices, made-up names.",
       cls="foot", style="top:524px;font-size:16.5px", i=("fade", .35), o=("none", 0))
    return T[0]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    prep_narration()
    total = timeline()
    print(f"timeline: {total:.2f} s, {len(base)} segments, {len(els)} overlay elements, {len(audio)} sounds")
    sounds = sfx.make(HERE / "out" / "sfx")
    sounds.update(make_extra_sfx(HERE / "out" / "sfx"))
    css = (HERE / "style.css").read_text("utf-8") + EXTRA_CSS
    concat = asyncio.run(overlay.render(OUT / "overlay", els, css, total))
    spec = {"captures": {k: str(v) for k, v in CAPS.items()}, "base": base, "audio": audio}
    edit.build(spec, OUT, concat, sounds, FINAL)
    print(f"wrote {FINAL}")


if __name__ == "__main__":
    main()
