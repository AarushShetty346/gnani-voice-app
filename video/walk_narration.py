"""Narrator lines for the walkthrough, voiced by Gnani Timbre (male voice Shubham, so he never sounds like the
app's own warning voice, Shivani) and checked by a Gnani Prisma round-trip.

    .venv\\Scripts\\python video\\walk_narration.py        -> video/out/walk/narration/<id>.wav (+ check report)

"Scam Lingo" is written as two words so Timbre says it clearly. Lines are only re-made when their text changes.
"""
import asyncio
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
OUT = HERE / "out" / "walk" / "narration"
VOICE, SPEED = "Shubham", 0.92

LINES = {
    # intro
    "i1": "This is Scam Lingo.",
    "i2": "It listens to a phone call with you, and warns you out loud if it sounds like a scam.",
    "i3": "In the next two minutes, watch it catch a scam call live, and stay quiet on a genuine one.",
    # set up
    "s2": "Say a call feels off. Put your phone on speaker, and open Scam Lingo on your laptop.",
    "s3": "First, choose the language you want your warnings in. I'll keep English.",
    "s4": "Then, the language of the call. This caller speaks Hindi.",
    "s5": "Now, click Start listening.",
    # the scam call
    "p1": "Gnani Prisma is writing down every word.",
    "p2": "It already spotted a fake police officer. But one sign isn't enough, so it stays calm.",
    "q1": "Now it says scam likely. Before he has even said digital arrest, or asked for a single rupee.",
    "h1": "That's Gnani Timbre, warning you out loud.",
    "h2": "So you hang up.",
    "h3": "He would have asked for your money just a few seconds later.",
    # after the call
    "a1": "When the call ends, you get a plain summary, and what to do next.",
    "a3": "And one click shares all of this with your family, on WhatsApp.",
    # the genuine call
    "g1": "But does it panic on every call that mentions an OTP?",
    "g2": "Here's a genuine bank reminder, also in Hindi.",
    "g3": "She said OTP and PIN, but only to warn you never to share them.",
    "g5": "It can tell advice from a request. So, it stays safe.",
    # check a recording
    "r1": "Already took the call, and recorded it?",
    "r2": "Open Recording, and choose the file.",
    "r3": "Gnani Prisma transcribes the whole call.",
    "r4": "And Scam Lingo points out exactly where they asked for your OTP.",
    # close
    "c1": "Use it live, with your phone on speaker. Or check a recording.",
    "c3": "And it works in ten Indian languages. Hindi, English, Bengali, Gujarati, Kannada, Malayalam, Marathi, Punjabi, Tamil and Telugu.",
}

# What the on-screen subtitle says for each line (the spoken text, with the name spelled properly).
def subtitle(text: str) -> str:
    return text.replace("Scam Lingo", "ScamLingo")


def duration(path: Path) -> float:
    r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(path)],
                       capture_output=True, text=True, check=True)
    return float(r.stdout.strip())


def words(s: str) -> list[str]:
    s = s.lower().replace("scamlingo", "scam lingo").replace("1930", "nineteen thirty")
    return re.findall(r"[a-z0-9']+", s)


def must_hear(text: str, heard: str) -> list[str]:
    """Words Prisma has to hear for a take to pass: the product name and the word "scam"."""
    h = words(heard)
    return [w for w in ("scam", "lingo") if w in words(text) and w not in h]


async def main():
    from app import gnani
    OUT.mkdir(parents=True, exist_ok=True)
    made = json.loads((OUT / "lines.json").read_text("utf-8")) if (OUT / "lines.json").exists() else {}
    report = {}
    for k, text in LINES.items():
        raw, wav = OUT / f"{k}.raw.wav", OUT / f"{k}.wav"
        tries = 0
        while (made.get(k, {}).get("text") != text or not wav.exists()
               or (tries < 4 and must_hear(text, made[k].get("heard", "")))):
            tries += 1
            raw.write_bytes(await gnani.tts(text, voice=VOICE, language="en-IN", speed=SPEED))
            # trim the silence Timbre leaves around the speech, keep a short natural tail
            subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(raw), "-af",
                            "silenceremove=start_periods=1:start_threshold=-50dB,areverse,"
                            "silenceremove=start_periods=1:start_threshold=-50dB,areverse,apad=pad_dur=0.12",
                            "-ar", "48000", "-ac", "1", str(wav)], check=True)
            raw.unlink()
            r = await gnani.stt(wav.read_bytes(), "line.wav", "en-IN")
            heard = r.get("transcript") or r.get("text") or ""
            made[k] = {"text": text, "heard": heard, "tries": tries}
        made[k]["dur"] = round(duration(wav), 3)
        a, b = words(text), words(made[k]["heard"])
        miss = [w for w in a if w not in b]
        report[k] = miss
        print(f"{k:3} {made[k]['dur']:5.2f}s {'OK ' if not miss else 'CHK'} {made[k]['heard']}"
              + (f"   (missing: {miss})" if miss else ""))
    made = {k: made[k] for k in LINES}
    (OUT / "lines.json").write_text(json.dumps(made, ensure_ascii=False, indent=1), "utf-8")
    total = sum(v["dur"] for v in made.values() if v.get("dur"))
    print(f"total narration {total:.1f}s; {sum(1 for v in report.values() if v)} lines to check by ear")


if __name__ == "__main__":
    asyncio.run(main())
