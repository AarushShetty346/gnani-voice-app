"""Check that your Gnani key works: TTS a Hinglish sentence, then STT it back.

Run: .venv\\Scripts\\python scripts\\smoke_test.py
Uses 2 API calls (a few credits).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

from app import gnani  # noqa: E402

if gnani.mock_mode():
    sys.exit("No GNANI_API_KEY in .env yet. Copy .env.example to .env and paste your key.")

text = "Namaste! Mera naam Shivani hai, aur main aapki madad karne ke liye yahan hoon."
print("TTS ->", text)
audio = gnani.tts(text, voice="Shivani", language="hi-IN")
out = Path("smoke_test.wav")
out.write_bytes(audio)
print(f"  saved {out} ({len(audio):,} bytes)")

print("STT <- smoke_test.wav")
res = gnani.stt(audio, "smoke_test.wav", language="hi-IN,en-IN", fmt="codemix")
print("  transcript:", res.get("transcript"))
print("  language:  ", res.get("detected_language_code"))
print("OK, the key works." if res.get("transcript") else "Got an empty transcript. Check the output above.")
