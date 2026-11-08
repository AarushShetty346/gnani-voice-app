"""Contact sheet of a walkthrough capture at given times (left to right, top to bottom).

    .venv\\Scripts\\python video\\walk_peek.py video\\out\\walk\\scam out.png c:12.5 s:3 ...

c:T = T seconds of call time (since the call audio started), s:T = T seconds since the screencast started.
"""
import json
import subprocess
import sys
from pathlib import Path


def frame_at(cap: Path, spec: str) -> Path:
    meta = json.loads((cap / "capture.json").read_text("utf-8"))
    frames = json.loads((cap / "frames" / "frames.json").read_text())
    kind, t = spec.split(":")
    if kind == "c":
        mic = next(e for e in meta["events"] if e["type"] == "mic")
        wall = mic["t"] / 1000 + meta["mic_pre"] + float(t)
    else:
        wall = frames[0]["t"] + float(t)
    best = frames[0]
    for f in frames:
        if f["t"] <= wall:
            best = f
    return cap / "frames" / best["file"]


def main():
    cap, out, specs = Path(sys.argv[1]), sys.argv[2], sys.argv[3:]
    files = [frame_at(cap, s) for s in specs]
    cols = 2 if len(files) > 1 else 1
    rows = (len(files) + cols - 1) // cols
    inputs = sum((["-i", str(f)] for f in files), [])
    scaled = "".join(f"[{i}:v]scale=768:-1,pad=iw:ih+4:0:0:yellow[v{i}];" for i in range(len(files)))
    layout = "|".join(f"{(i % cols) * 768}_{(i // cols) * 436}" for i in range(len(files)))
    pads = "".join(f"[v{i}]" for i in range(len(files)))
    flt = scaled + (f"{pads}xstack=inputs={len(files)}:layout={layout}:fill=black" if len(files) > 1 else "[v0]null")
    subprocess.run(["ffmpeg", "-v", "error", "-y", *inputs, "-filter_complex", flt, "-frames:v", "1", out], check=True)
    _ = rows


if __name__ == "__main__":
    main()
