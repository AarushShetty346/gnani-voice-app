"""static/speaker.js labels live transcripts Caller/You by matching them to the demo script.

The transcripts below are what live Gnani Prisma returned for the demo audio (code-mix spellings, split
lines). The test runs the real JS file under Node, so it is skipped where Node isn't installed.
"""
import json
import shutil
import subprocess

import pytest

from app import config

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(not NODE, reason="node not installed")

RUNNER = """
const ks = require(process.argv[1]);
const cases = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = cases.map(([lines, text, t]) => {
  const i = ks.matchLine(lines, text, t);
  return i < 0 ? null : lines[i].speaker;
});
process.stdout.write(JSON.stringify(out));
"""


def speakers(cases):
    js = str(config.ROOT / "static" / "speaker.js")
    r = subprocess.run([NODE, "-e", RUNNER, js], input=json.dumps(cases, ensure_ascii=False),
                       capture_output=True, text=True, encoding="utf-8", check=True)
    return json.loads(r.stdout)


def timeline(demo_id):
    d = next(d for d in config.load_demos() if d["id"] == demo_id)
    # rough script timing: only "has this line started yet" matters to the matcher
    out, t = [], 1.0
    for line in d["lines"]:
        out.append({"speaker": line["speaker"], "text": line["text"], "start": t})
        t += 1.5 + 0.065 * len(line["text"])
    return out


def test_live_digital_arrest_transcripts_get_the_right_speaker():
    tl = timeline("digital-arrest")
    live = [
        ("Hello, मैं मुंबई cyber crime branch से inspector राजेश शर्मा बोल रहा हूँ।", "caller"),
        ("जी।", "victim"),
        ("बोलिए।", "victim"),
        ("आपके Aadhaar card से एक parcel book हुआ है, जिसमें customs को drugs मिले हैं।", "caller"),
        ("क्या मैंने तो कोई parcel नहीं भेजा?", "victim"),
        ("आपके नाम पर arrest warrant निकला है। अभी से आप digital arrest में हैं।", "caller"),
        ("call disconnect मत कीजिए और किसी को मत बताइए।", "caller"),
    ]
    assert speakers([[tl, text, 99.0] for text, _ in live]) == [who for _, who in live]


def test_live_bank_reminder_transcripts_get_the_right_speaker():
    tl = timeline("legit-bank-reminder")
    live = [
        ("नमस्ते, मैं आपके bank से एक reminder call कर रही हूँ।", "caller"),
        ("जी बताइए।", "victim"),
        ("आपके credit card का bill पाँच तारीख को due है। आप app या branch से payment कर सकते हैं।", "caller"),
        ("ठीक है, धन्यवाद।", "victim"),
        ("ध्यान रखें, bank कभी भी phone पर OTP या PIN नहीं मांगता।", "caller"),
        ("आपका दिन शुभ हो।", "caller"),
    ]
    assert speakers([[tl, text, 99.0] for text, _ in live]) == [who for _, who in live]


def test_lines_that_have_not_started_cannot_match_and_nonsense_gives_up():
    tl = [{"speaker": "caller", "text": "pay the fine now", "start": 0.0},
          {"speaker": "victim", "text": "okay I will pay", "start": 10.0}]
    assert speakers([[tl, "okay I will pay", 2.0],      # line 2 hasn't started: no match
                     [tl, "okay I will pay", 12.0],
                     [tl, "completely different words", 12.0],
                     [tl, "", 12.0],
                     [tl, "okay I will pay", None]]) == [None, "victim", None, None, "victim"]  # audio stopped
