"""Assemble the launch video from a timeline spec: base footage segments + overlay layer + extra audio.

Base segments (laid end to end):
  {"type": "black", "dur": 3.0}
  {"type": "clip", "cap": "hero", "t0": 12.0, "t1": 20.5, "ref": "call",   # seconds into the call audio
   "zoom": [1.0, 1.25], "focus": [540, 700], "freeze": 0.0, "gain": 1.0, "audio": True}
  {"type": "grid", "dur": 4.0, "cells": [{"cap": "kn", "t0": 15.0, "ref": "call", "rect": [0, 0, 540, 675],
   "audio": True}, ...]}
Extra audio (absolute times): {"at": 0.0, "src": "sfx:buzz" | "path.wav" | "cap:hero", "t0":.., "t1":..,
  "ref": "call", "gain": 0.8}
"""
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUTW, OUTH, FPS = 1080, 1920, 30          # 9:16, like a reel
APPW, APPH, APP_Y = 1080, 1350, 280      # app footage sits in a band in the middle
BG = "0x0a0a0b"


def load_caps(caps: dict) -> dict:
    out = {}
    for k, d in caps.items():
        d = Path(d)
        info = json.loads((d / "clip.json").read_text("utf-8"))
        info["path"] = d / "clip.mov"
        out[k] = info
    return out


def clip_time(info: dict, t: float, ref: str) -> float:
    return t + info["call0"] if ref == "call" else t


def seg_dur(s: dict) -> float:
    if s["type"] == "clip":
        return (s["t1"] - s["t0"]) + s.get("freeze", 0.0)
    return s["dur"]


def zoom_chain(s: dict, dur: float) -> str:
    z = s.get("zoom")
    if not z:
        return ""
    z0, z1 = z
    cx, cy = s.get("focus", [APPW / 2, APPH / 2])
    d = max(0.01, s.get("zoom_dur", dur))
    p = f"clip(t/{d:.3f},0,1)"
    zz = f"({z0}+({z1}-{z0})*pow({p},2)*(3-2*{p}))"
    return (f",scale=w='2*trunc({APPW / 2}*{zz})':h='2*trunc({APPH / 2}*{zz})':eval=frame:flags=lanczos"
            f",crop={APPW}:{APPH}:x='clip({cx}*iw/{APPW}-{APPW / 2},0,iw-{APPW})'"
            f":y='clip({cy}*ih/{APPH}-{APPH / 2},0,ih-{APPH})'")


def vfades(s: dict, dur: float) -> str:
    """Optional dips to the background colour at a segment's start/end (soft section changes)."""
    out = ""
    if s.get("vfade_in"):
        out += f",fade=t=in:st=0:d={s['vfade_in']}:color={BG}"
    if s.get("vfade_out"):
        out += f",fade=t=out:st={max(0, dur - s['vfade_out']):.4f}:d={s['vfade_out']}:color={BG}"
    return out


def build(spec: dict, out_dir: Path, overlay_concat: Path | None, sfx: dict, final: Path):
    caps = load_caps(spec["captures"])
    inputs: list[list[str]] = []
    filters: list[str] = []
    concat_pads = []

    def add_input(args: list[str]) -> int:
        inputs.append(args)
        return len(inputs) - 1

    t_cursor = 0.0
    for k, s in enumerate(spec["base"]):
        dur = seg_dur(s)
        if s["type"] == "black":
            col = s.get("color", BG)
            filters.append(f"color=c={col}:s={OUTW}x{OUTH}:r={FPS}:d={dur:.4f},format=yuv420p,setsar=1[v{k}]")
            filters.append(f"anullsrc=r=48000:cl=stereo,atrim=0:{dur:.4f}[a{k}]")
        elif s["type"] == "clip":
            info = caps[s["cap"]]
            a = clip_time(info, s["t0"], s.get("ref", "call"))
            clip_len = s["t1"] - s["t0"]
            i = add_input(["-ss", f"{a:.4f}", "-t", f"{clip_len:.4f}", "-i", str(info["path"])])
            fr = s.get("freeze", 0.0)
            tp = f",tpad=stop_mode=clone:stop_duration={fr:.4f}" if fr else ""
            filters.append(f"[{i}:v]setpts=PTS-STARTPTS,fps={FPS}{zoom_chain(s, dur)}{tp},"
                           f"pad={OUTW}:{OUTH}:0:{APP_Y}:color={BG},format=yuv420p,setsar=1,"
                           f"trim=0:{dur:.4f},setpts=PTS-STARTPTS{vfades(s, dur)}[v{k}]")
            if s.get("audio", True):
                g = s.get("gain", 1.0)
                fi, fo = s.get("fade_in", 0.03), s.get("fade_out", 0.05)
                filters.append(f"[{i}:a]asetpts=PTS-STARTPTS,atrim=0:{clip_len:.4f},volume={g},"
                               f"afade=t=in:d={fi},afade=t=out:st={max(0, clip_len - fo):.4f}:d={fo},"
                               f"apad=whole_dur={dur:.4f}[a{k}]")
            else:
                filters.append(f"anullsrc=r=48000:cl=stereo,atrim=0:{dur:.4f}[a{k}]")
        elif s["type"] == "grid":
            col = s.get("bg", "0x0a0a0b")
            filters.append(f"color=c={col}:s={OUTW}x{OUTH}:r={FPS}:d={dur:.4f},format=yuv420p[g{k}b0]")
            alabels = []
            for j, c in enumerate(s["cells"]):
                info = caps[c["cap"]]
                a = clip_time(info, c["t0"], c.get("ref", "call"))
                i = add_input(["-ss", f"{a:.4f}", "-t", f"{dur:.4f}", "-i", str(info["path"])])
                x, y, w, h = c["rect"]
                cz = c.get("crop")       # [x, y, w, h] region of the 1080x1350 source to show
                crop = f",crop={cz[2]}:{cz[3]}:{cz[0]}:{cz[1]}" if cz else ""
                filters.append(f"[{i}:v]setpts=PTS-STARTPTS,fps={FPS}{crop},scale={w}:{h}:flags=lanczos,"
                               f"tpad=stop_mode=clone:stop_duration={dur:.4f},trim=0:{dur:.4f}[g{k}c{j}]")
                filters.append(f"[g{k}b{j}][g{k}c{j}]overlay={x}:{y}:shortest=0[g{k}b{j + 1}]")
                if c.get("audio"):
                    filters.append(f"[{i}:a]asetpts=PTS-STARTPTS,volume={c.get('gain', 1.0)},"
                                   f"afade=t=in:d=0.03,afade=t=out:st={max(0, dur - 0.05):.4f}:d=0.05,"
                                   f"apad=whole_dur={dur:.4f},atrim=0:{dur:.4f}[g{k}a{j}]")
                    alabels.append(f"[g{k}a{j}]")
            filters.append(f"[g{k}b{len(s['cells'])}]trim=0:{dur:.4f},setpts=PTS-STARTPTS,setsar=1[v{k}]")
            if alabels:
                mix = "".join(alabels)
                filters.append(f"{mix}amix=inputs={len(alabels)}:normalize=0,atrim=0:{dur:.4f}[a{k}]")
            else:
                filters.append(f"anullsrc=r=48000:cl=stereo,atrim=0:{dur:.4f}[a{k}]")
        concat_pads.append(f"[v{k}][a{k}]")
        t_cursor += dur
    total = t_cursor
    filters.append(f"{''.join(concat_pads)}concat=n={len(spec['base'])}:v=1:a=1[bv][ba]")

    vout = "[bv]"
    if overlay_concat:
        # Pre-encode the PNG sequence to one alpha video: feeding the concat demuxer straight into the big
        # graph stalls ffmpeg's scheduler (it waits forever at the first cut).
        ov_mov = Path(overlay_concat).with_suffix(".mov")
        subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "concat", "-safe", "0", "-i", str(overlay_concat),
                        "-vf", f"fps={FPS},format=argb", "-c:v", "qtrle", str(ov_mov)], check=True)
        i = add_input(["-i", str(ov_mov)])
        filters.append(f"[{i}:v]fps={FPS},format=rgba[ov]")
        filters.append(f"[bv][ov]overlay=0:0:eof_action=pass:format=auto,format=yuv420p[vout]")
        vout = "[vout]"

    mix = ["[ba]"]
    for j, x in enumerate(spec.get("audio", [])):
        src = x["src"]
        if src.startswith("cap:"):
            info = caps[src[4:]]
            a = clip_time(info, x["t0"], x.get("ref", "call"))
            i = add_input(["-ss", f"{a:.4f}", "-t", f"{x['t1'] - x['t0']:.4f}", "-i", str(info["path"])])
        else:
            path = sfx[src[4:]] if src.startswith("sfx:") else src
            pre = []
            if "t0" in x:
                pre = ["-ss", f"{x['t0']:.4f}", "-t", f"{x['t1'] - x['t0']:.4f}"]
            i = add_input([*pre, "-i", str(path)])
        ms = int(round(x["at"] * 1000))
        fades = ""
        if x.get("fade_in"):
            fades += f",afade=t=in:d={x['fade_in']}"
        if x.get("fade_out") and "t1" in x:
            fades += f",afade=t=out:st={max(0, x['t1'] - x['t0'] - x['fade_out']):.3f}:d={x['fade_out']}"
        filters.append(f"[{i}:a]aformat=sample_rates=48000:channel_layouts=stereo,asetpts=PTS-STARTPTS"
                       f"{fades},volume={x.get('gain', 1.0)},adelay={ms}:all=1[x{j}]")
        mix.append(f"[x{j}]")
    filters.append(f"{''.join(mix)}amix=inputs={len(mix)}:normalize=0:duration=first,"
                   f"atrim=0:{total:.4f},alimiter=limit=0.97:level=false:latency=1[aout]")

    graph = out_dir / "graph.txt"
    graph.write_text(";\n".join(filters))
    rough = out_dir / "rough.mp4"
    cmd = ["ffmpeg", "-v", "error", "-y"]
    for a in inputs:
        cmd += a
    cmd += ["-/filter_complex", str(graph), "-map", vout, "-map", "[aout]", "-t", f"{total:.4f}",
            "-c:v", "libx264", "-preset", "slow", "-crf", "17", "-profile:v", "high", "-pix_fmt", "yuv420p",
            "-r", str(FPS), "-c:a", "pcm_s16le", str(rough.with_suffix(".mov"))]
    subprocess.run(cmd, check=True)
    loudnorm(rough.with_suffix(".mov"), final)
    return total


def measure(path: Path) -> dict:
    """Integrated loudness (LUFS) and true peak (dBTP) of a file's audio, via loudnorm's analysis pass."""
    r = subprocess.run(["ffmpeg", "-hide_banner", "-i", str(path), "-af",
                        "loudnorm=I=-14:TP=-1:LRA=20:print_format=json", "-f", "null", "-"],
                       capture_output=True, text=True)
    m = json.loads(r.stderr[r.stderr.rfind("{"):r.stderr.rfind("}") + 1])
    return {"I": float(m["input_i"]), "TP": float(m["input_tp"]), "LRA": float(m["input_lra"])}


def loudnorm(src: Path, dst: Path, target=-14.0, tp=-1.5):
    """Bring the mix to the feed level (~-14 LUFS) with one static gain and a true-peak limiter.

    loudnorm's own linear mode needs a lot of peak headroom and otherwise silently switches to dynamic
    (gain riding), which changes the balance between speech, beds and effects. A static gain keeps the mix
    exactly as built; the limiter only catches the few peaks that would pass the ceiling.
    """
    gain = target - measure(src)["I"]
    for _ in range(3):
        af = (f"volume={gain:.2f}dB,alimiter=limit={10 ** (tp / 20):.4f}:level=false:attack=1.5:release=60:"
              f"latency=1,aresample=48000")
        subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(src), "-af", af, "-c:v", "copy", "-c:a", "aac",
                        "-b:a", "192k", "-movflags", "+faststart", str(dst)], check=True)
        m = measure(dst)
        if abs(m["I"] - target) <= 0.3:
            break
        gain += target - m["I"]
    print(f"loudness: {m['I']:.1f} LUFS, true peak {m['TP']:.1f} dBTP, gain {gain:+.1f} dB")
    return m
