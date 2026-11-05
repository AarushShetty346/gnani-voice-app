"""Synthesized sound effects (no sample libraries): phone buzz, alert hit, whoosh, soft tick."""
import subprocess
from pathlib import Path

RECIPES = {
    # a phone vibrating on a table: two 0.45 s rattly bursts
    "buzz": "aevalsrc='0.32*(sgn(sin(2*PI*155*t))*0.7+sin(2*PI*310*t)*0.3)*(0.65+0.35*sin(2*PI*31*t))"
            "*between(mod(t,0.95),0,0.45)':s=48000:d=1.9,lowpass=f=1400,highpass=f=90",
    # deep hit + short bright crack for the red alert
    "hit": "aevalsrc='0.95*sin(2*PI*(46+70*exp(-t*14))*t)*exp(-t*3.2)+0.18*sin(2*PI*92*t)*exp(-t*6)':"
           "s=48000:d=1.6,lowpass=f=900",
    "crack": "anoisesrc=d=0.22:c=pink:a=0.5:r=48000,afade=t=out:d=0.22,highpass=f=1800",
    # airy whoosh for transitions
    "whoosh": "anoisesrc=d=0.7:c=pink:a=0.6:r=48000,bandpass=f=1400:width_type=o:w=2,"
              "afade=t=in:d=0.35:curve=qsin,afade=t=out:st=0.35:d=0.35:curve=qsin",
    # soft UI tick for taps
    "tick": "aevalsrc='0.5*sin(2*PI*1900*t)*exp(-t*90)+0.3*sin(2*PI*950*t)*exp(-t*60)':s=48000:d=0.12",
}


def make(out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {}
    for name, src in RECIPES.items():
        p = out_dir / f"{name}.wav"
        subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", src, "-ac", "2", "-ar", "48000", str(p)],
                       check=True)
        paths[name] = p
    # the alert hit = boom + crack together
    hit = out_dir / "alert.wav"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(paths["hit"]), "-i", str(paths["crack"]),
                    "-filter_complex", "amix=inputs=2:normalize=0", str(hit)], check=True)
    paths["alert"] = hit
    return paths


if __name__ == "__main__":
    print(make(Path(__file__).resolve().parent / "out" / "sfx"))
