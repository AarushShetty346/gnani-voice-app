"""Turn a capture (frames + page audio + event log) into a 30 fps clip with the audio in sync.

    .venv\\Scripts\\python video\\footage.py video\\out\\cap\\digital-arrest

Writes clip.mp4 and clip.json into the capture folder. clip.json maps the capture to clip time:
  call0      seconds into the clip where the demo call audio starts (call time 0)
  events     server messages / audio starts / taps, each with "clip_t" (seconds into the clip)
Sync is checked by cross-correlating the recorded page audio with the demo WAV it played.
"""
import array
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FPS = 30
ENV_RATE = 8000
HOP = 80            # 10 ms envelope frames at 8 kHz


def pcm(path: Path, start: float = 0.0, dur: float | None = None) -> array.array:
    cmd = ["ffmpeg", "-v", "error", "-ss", f"{start:.3f}", "-i", str(path)]
    if dur:
        cmd += ["-t", f"{dur:.3f}"]
    cmd += ["-ac", "1", "-ar", str(ENV_RATE), "-f", "s16le", "-"]
    a = array.array("h")
    a.frombytes(subprocess.run(cmd, capture_output=True, check=True).stdout)
    return a


def envelope(a: array.array) -> list[float]:
    out = []
    for i in range(0, len(a) - HOP, HOP):
        s = 0
        for v in a[i:i + HOP:4]:
            s += v * v
        out.append((s / (HOP / 4)) ** 0.5)
    m = sum(out) / max(1, len(out))
    return [x - m for x in out]


def best_lag(ref: list[float], sig: list[float], center: int, radius: int) -> tuple[int, float]:
    """Lag (in envelope frames) at which ref best matches sig, searched around center."""
    best, best_c = center, -1e30
    n = len(ref)
    for lag in range(center - radius, center + radius + 1):
        if lag < 0:
            continue
        c = 0.0
        seg = sig[lag:lag + n]
        for x, y in zip(ref, seg):
            c += x * y
        if c > best_c:
            best, best_c = lag, c
    return best, best_c


def best_lag_norm(ref: list[float], sig: list[float], lo: int, hi: int) -> int:
    """Lag in [lo, hi] with the highest normalised correlation of ref against sig."""
    rr = sum(x * x for x in ref) or 1.0
    best, best_c = lo, -2.0
    for lag in range(max(0, lo), hi + 1):
        seg = sig[lag:lag + len(ref)]
        if len(seg) < len(ref):
            break
        ss = sum(y * y for y in seg) or 1.0
        c = sum(x * y for x, y in zip(ref, seg)) / (rr * ss) ** 0.5
        if c > best_c:
            best, best_c = lag, c
    return best


def check_alert_sync(clip_audio: Path, info: dict) -> list[float]:
    """Offsets (ms) between where each Timbre warning is heard and where the log says it started."""
    sys.path.insert(0, str(ROOT))
    from scripts.prewarm_alerts import cache_path            # same file the server played
    out = []
    src_times = [e["clip_t"] for e in info["events"] if e["type"] == "audio" and e["dur"] < 20]
    alerts = [e for e in info["events"] if e["type"] == "alert"]
    for e, t in zip(alerts, src_times):
        p = cache_path(e["text"], e.get("language") or "en-IN")
        if not p.exists():
            continue
        ref = envelope(pcm(p, 0, 2.5))
        sig = envelope(pcm(clip_audio, max(0, t - 1.5), 5.5))
        lag = best_lag_norm(ref, sig, 0, 300)
        out.append(round((max(0, t - 1.5) + lag / 100 - t) * 1000))
    return out


def build(cap_dir: Path) -> dict:
    cap_dir = Path(cap_dir).resolve()
    cap = json.loads((cap_dir / "capture.json").read_text("utf-8"))
    frames = json.loads((cap_dir / "frames" / "frames.json").read_text())
    t_first = frames[0]["t"]
    end_t = frames[-1]["t"] + 0.5

    # 1) video: hold each frame until the next one, resampled to constant 30 fps
    lines = ["ffconcat version 1.0"]
    for i, f in enumerate(frames):
        nxt = frames[i + 1]["t"] if i + 1 < len(frames) else end_t
        lines += [f"file 'frames/{f['file']}'", f"duration {max(0.001, nxt - f['t']):.6f}"]
    lines.append(f"file 'frames/{frames[-1]['file']}'")
    (cap_dir / "frames.ffconcat").write_text("\n".join(lines))
    video_tmp = cap_dir / "video_only.mp4"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "concat", "-safe", "0", "-i", str(cap_dir / "frames.ffconcat"),
                    "-fps_mode", "cfr", "-r", str(FPS), "-c:v", "libx264", "-preset", "medium", "-crf", "14",
                    "-pix_fmt", "yuv420p", str(video_tmp)], check=True, cwd=cap_dir)

    # 2) audio: the recorder started at rec_start; place it on the clip timeline, then verify with the WAV
    rec_off = cap["rec_start_ms"] / 1000 - t_first             # seconds into the clip where audio.webm starts
    demo_src = next(e for e in cap["events"] if e["type"] == "source" and e["dur"] > 20)
    # Map AudioContext time to wall time using moments when the clock was surely running (clock samples,
    # later audio starts). The call itself is scheduled right after the context is created, before its
    # clock starts moving, so its own logged wall time can be ~0.5 s early.
    pairs = [e["t"] - e["ctxTime"] * 1000 for e in cap["events"]
             if e["type"] in ("ctx", "source") and e.get("ctxTime", 0) > 1.0]
    if pairs:
        pairs.sort()
        wall0 = pairs[len(pairs) // 2]
        call_wall = wall0 + demo_src["when"] * 1000
        cap["_ctx_wall0"] = wall0
    else:
        call_wall = demo_src["at"]
        print("WARNING: no running-clock samples; call start may be off by ~0.5 s")
    call0_logged = call_wall / 1000 - t_first
    rec = pcm(cap_dir / "audio.webm")
    wav = pcm(ROOT / "demo" / "audio" / f"{cap['demo']}.wav", 0, 14)   # first 14 s: before any alert ducking
    env_rec, env_wav = envelope(rec), envelope(wav)
    # Where the call starts inside audio.webm (normalised correlation over 0..3 s). MediaRecorder's own
    # start time is unreliable (it can begin ~0.5 s after start()), so the audio is placed so the call
    # starts exactly when the AudioContext scheduled it: the same clock the on-screen events follow.
    lag = best_lag_norm(env_wav, env_rec, 0, 300)
    call_in_rec = lag / 100
    call0 = call0_logged
    drift_ms = (rec_off + call_in_rec - call0_logged) * 1000         # recorder start error (diagnostic)
    audio_off = call0_logged - call_in_rec                            # where audio.webm starts in the clip

    audio_tmp = cap_dir / "audio_aligned.wav"
    if audio_off >= 0:
        af = f"adelay={int(round(audio_off * 1000))}:all=1,apad"
        pre = []
    else:
        af, pre = "apad", ["-ss", f"{-audio_off:.3f}"]
    dur = end_t - t_first
    subprocess.run(["ffmpeg", "-v", "error", "-y", *pre, "-i", str(cap_dir / "audio.webm"), "-af", af,
                    "-t", f"{dur:.3f}", "-ar", "48000", "-ac", "2", str(audio_tmp)], check=True)
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(video_tmp), "-i", str(audio_tmp), "-map", "0:v",
                    "-map", "1:a", "-c:v", "copy", "-c:a", "pcm_s16le", "-shortest", str(cap_dir / "clip.mov")], check=True)

    # 3) events on the clip timeline (all on the page's wall clock, which the aligned audio now follows)
    evs = []
    for e in cap["events"]:
        if e["type"] == "source":
            t_a = call0 if e is demo_src else e["at"] / 1000 - t_first
            evs.append({"type": "audio", "dur": e["dur"], "clip_t": t_a})
        elif e["type"] == "ws":
            m = e["m"]
            keep = {k: m.get(k) for k in ("type", "level", "score", "category", "text", "text_en", "verdict",
                                          "speaker", "language", "final", "summary") if k in m}
            evs.append({**keep, "clip_t": e["t"] / 1000 - t_first})
    for c in cap["clicks"]:
        evs.append({"type": "tap", "what": c["what"], "x": c["x"], "y": c["y"], "clip_t": c["t"] - t_first})
    evs.sort(key=lambda e: e["clip_t"])
    info = {"demo": cap["demo"], "warn": cap["warn"], "duration": dur, "call0": call0,
            "call0_logged": call0_logged, "sync_drift_ms": round(drift_ms, 1), "events": evs,
            "summary": cap["summary"]}
    (cap_dir / "clip.json").write_text(json.dumps(info, ensure_ascii=False, indent=1), "utf-8")
    video_tmp.unlink(missing_ok=True)
    return info


if __name__ == "__main__":
    for d in sys.argv[1:]:
        i = build(Path(d))
        i["alert_sync_ms"] = check_alert_sync(Path(d).resolve() / "clip.mov", i)
        alerts = [f"{e['clip_t'] - i['call0']:.2f}s {e.get('level')}" for e in i["events"] if e["type"] == "alert"]
        print(f"{i['demo']}: {i['duration']:.1f}s clip, call starts at {i['call0']:.2f}s, "
              f"recorder start error {i['sync_drift_ms']} ms, warning-voice sync {i['alert_sync_ms']} ms, alerts at call {alerts}")
