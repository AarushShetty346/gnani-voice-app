"""Contact sheet of capture frames at call times:  grab.py out.png cap:t cap:t ...  (t = seconds into the call)"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def frame(cap: str, t: float, out: Path, w: int = 432):
    c = json.loads((HERE / "out" / "cap" / cap / "clip.json").read_text("utf-8"))
    ss = max(0.0, c["call0"] + t)
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-ss", f"{ss:.3f}", "-i", str(HERE / "out" / "cap" / cap / "clip.mov"),
                    "-frames:v", "1", "-vf", f"scale={w}:-2", str(out)], check=True)


if __name__ == "__main__":
    out = Path(sys.argv[1])
    tmp = []
    for i, a in enumerate(sys.argv[2:]):
        cap, t = a.rsplit(":", 1)
        p = out.with_name(f"_{out.stem}_{i}.png")
        frame(cap, float(t), p)
        tmp.append(p)
    args = []
    for p in tmp:
        args += ["-i", str(p)]
    subprocess.run(["ffmpeg", "-v", "error", "-y", *args, "-filter_complex", f"hstack=inputs={len(tmp)}", str(out)],
                   check=True)
    for p in tmp:
        p.unlink()
