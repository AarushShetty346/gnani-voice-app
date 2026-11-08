# ScamLingo 🛡️

**Demo video (3 min):** [youtu.be/DQaPu_4Ylbc](https://youtu.be/DQaPu_4Ylbc) ·
**One-page pitch:** [PITCH.md](PITCH.md) ([PDF](PITCH.pdf))

**A live scam-call shield for Indian phone users.** If a call feels off, put it on speaker. ScamLingo
listens for the lingo scammers use ("digital arrest", "share the OTP", "don't tell anyone") as the call happens, and **warns you out loud in your own language** before you share an OTP
or send money. When the call ends you get a plain-language summary you can forward to family on WhatsApp.

> संदिग्ध कॉल? स्पीकर पर डालिए। ScamLingo सुनेगा और आपको समय रहते सावधान करेगा।

It handles "digital arrest" threats from fake police, fake bank KYC and OTP calls, power-cut threats that push
AnyDesk, and work-from-home job scams. Calls can be in any of 10 Indian languages, in code-mixed Hinglish, and
over noisy phone audio.

## How it works

```
 phone on speaker
        │  mic, 16 kHz PCM, 32 ms frames
        ▼
 browser ──WS /ws/listen──► FastAPI session ──► Gnani Prisma v3.0 realtime STT
                                 │                   (VAD-segmented transcripts)
                                 ▼
                          scam detector: multilingual rules (fast, every utterance)
                                 │      + optional LLM review (rolling transcript)
                                 ▼
               risk 0-100 ──► alert? ──► Gnani Timbre v3.0 TTS in your language
                                 │
                 stop ──► summary + WhatsApp share text
```

- **Rules first.** Every utterance is scanned (about 0.4 ms) for 8 scam signals: OTP/PIN request,
  impersonation, digital-arrest threats, account/service threats, payment requests, remote-access apps,
  urgency/secrecy, prize/job bait. Signals combine: authority plus an OTP, money or app request means danger.
  Safety advice ("the bank never asks for your OTP") is recognised as advice, so genuine calls stay safe.
- **LLM second opinion (optional).** Any OpenAI-compatible model rereads the last ~12 utterances. It can raise the
  risk but can't push a call to "scam" on its own without a rule hit.
- **Interrupts, not just flags.** When the risk rises, ScamLingo speaks a short warning ("Stop! Never share your
  OTP… Hang up now.") in the listener's language. Alerts are limited to one per category and spaced at least 6 s
  apart. The warning appears on screen the moment it fires; its Timbre voice follows a second or two later (or
  instantly when pre-generated with `scripts/prewarm_alerts.py`), and the browser's own voice steps in if the clip
  takes longer than 2.5 s. Warnings queue instead of cutting each other off.
- **Doesn't hear itself.** In live-call mode the app sends silence while its own warning plays (plus a short echo
  tail), and the server drops any transcript that matches a warning it just spoke.

## Gnani models used

| Model | Where | How |
|---|---|---|
| **Prisma v3.0 realtime** (`wss://api.vachana.ai/stt/v3/stream`) | live calls, demo calls | `codemix` output (English words stay in Latin script), scam keyterms (OTP, KYC, AnyDesk, CBI, digital arrest…), telephony VAD preset for phone audio |
| **Prisma v3.0 REST** (`/stt/v3`) | "Check a recording" | ≤ 25 s chunks transcribed one at a time, auto language detection |
| **Timbre v3.0** (`/api/v1/tts/inference`) | spoken alerts, demo calls | calm Shivani voice for alerts in all 10 languages (cached on disk); separate caller and victim voices for each demo call |

## Features

- **Live call:** pick the caller's language ("Call language"; Auto-detect works, but one fixed language is far
  more accurate on phone audio), tap "Start listening" and put the phone on speaker.
- **Demo calls:** 5 scripted calls (Hindi, English, Kannada, Tamil, plus one genuine bank reminder that must stay
  safe), played through a simulated phone line.
- **Check a recording:** upload a call recording (up to 10 min / 25 MB) for a transcript, risk score and summary.
- A risk meter, a live transcript with the suspicious phrases highlighted, a full-screen danger alert with voice
  and vibration, and a post-call summary with advice and the 1930 cybercrime helpline. The summary has "Share on
  WhatsApp" and "Copy" buttons.
- "Warn me in": English by default, "Same as the call", or any of the 10 languages. When the warning is in
  another language, the alert also shows the English wording underneath.
- Demo cards don't say which calls are scams. ScamLingo's verdict appears on the card after the call plays.

**Languages:** Hindi, English, Bengali, Gujarati, Kannada, Malayalam, Marathi, Punjabi, Tamil, Telugu, plus
code-mixed Hinglish.

## Run it

Needs Python 3.12 and [ffmpeg](https://ffmpeg.org/) on PATH.

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt     # macOS/Linux: .venv/bin/python
cp .env.example .env                                         # add GNANI_API_KEY (and optionally an LLM)
.venv/Scripts/python -m uvicorn app.main:app --port 8000
```

Open http://localhost:8000. The microphone needs `localhost` or HTTPS.

Optional scripts (these spend Gnani credits):

```bash
.venv/Scripts/python scripts/smoke_test.py [--stream]     # check your key: TTS one line, STT it back (REST; --stream adds realtime)
.venv/Scripts/python scripts/make_demo_audio.py           # voice the demo calls with Timbre v3.0 into demo/audio/
                                                          #   (--dry-run shows the TTS call count; --force, --clean, --only ID)
.venv/Scripts/python -X utf8 scripts/live_eval.py         # stream every demo through live Prisma + the detector
.venv/Scripts/python scripts/prewarm_alerts.py            # voice every alert once into .cache/tts (up to 180 TTS
                                                          #   calls; --dry-run counts them, --lang hi-IN,kn-IN)
```

Before filming a demo, run `prewarm_alerts.py` (at least for the demo languages) so every warning plays instantly.

**Mock mode.** Without `GNANI_API_KEY`, nothing calls Gnani. The live stream replays the scripted demo lines on
schedule, alerts are shown as text and spoken by the browser's built-in voice, and "Check a recording" returns
the digital-arrest demo transcript. Without an LLM key, detection is rules-only and summaries come from
handwritten templates in all 10 languages. Everything still runs end to end.

**Tests** (offline, never call the network):

```bash
.venv/Scripts/python -m pytest -q
.venv/Scripts/python scripts/eval_detector.py      # detector accuracy on scam / genuine phrases
```

## API

| | |
|---|---|
| `GET /` | the app |
| `GET /api/status` | `{gnani_mock, llm_mock, demo_audio, languages}` |
| `GET /api/demos` | demo calls with per-line timing |
| `GET /demo-audio/<id>.wav` | demo call audio |
| `POST /api/analyze` | multipart `audio` (+ `language`, `warn_language`) → transcript, risk, summary |
| `WS /ws/listen` | `start` → 1024-byte PCM frames → `stop`; server sends `ready`, `transcript`, `risk`, `alert`, `alert_audio`, `summary`, `error` |

`start` is `{"type":"start","source":"mic"|"demo","demo_id":…,"language":…,"warn_language":…}`. Realtime STT takes
exactly one `language` code or `indic-auto` (a list is cut to its first code); demo calls always use their own
language. Each `alert` carries an `id` and `audio_b64: null` unless the clip was cached; the clip then follows as
`{"type":"alert_audio","id":…,"audio_b64":…}`.

## Synthetic data only

Every demo call is scripted and voiced by Timbre v3.0. All names, numbers and organisations in them are made up.
No real call recordings were used to build or test ScamLingo. The share text never includes phone or account
numbers.

---

Built by **Aarush Shetty** for the Gnani AI **Great Indian AI Internship Challenge**.
