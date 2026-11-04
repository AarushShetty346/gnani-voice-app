# Gnani AI Internship Challenge: app doc

**Deadline: Tue 10 Nov 2026, 11:59 PM IST.** (6 days from 4 Nov.) No extensions.

Selection is mostly **verified engagement on your LinkedIn/X post**, then interviews. So the demo video and
post matter as much as the code. Build something people want to share.

---

## Your to-do list (things only you can do)

Do these, then open Claude in this folder and say "keys are in, let's build".

- [ ] **1. Gnani API key** (5 min). Sign in at [app.gnani.ai/voice](https://app.gnani.ai/voice) with your VIT
      email, open API keys, create one (you get 3 free). Copy `.env.example` to `.env` and paste it after
      `GNANI_API_KEY=`.
- [ ] **2. LLM key** (5 min). Gnani has no hosted LLM yet, and Evon (30B) won't fit in your 16 GB RAM, so we need
      a hosted one for the "thinking" part. Easiest is free **Gemini**: get a key at
      [aistudio.google.com/apikey](https://aistudio.google.com/apikey), then in `.env`:
      `LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai`, `LLM_API_KEY=<key>`,
      `LLM_MODEL=<current flash model name from their docs>`. Groq's free tier also works.
- [ ] **3. Pick the idea** (see below). My pick is **A**.
- [ ] **4. Solo or duo?** Tell me if you registered with a teammate. It decides which award you target
      (Solo Ninja vs Two-Person Army) and whose account holds the 5,000 credits.
- [ ] **5. Check credits pricing** in the dashboard: how many credits one STT / TTS call costs. Tells us how much
      testing we can afford.
- [ ] *(optional)* Join the [Gnani Discord](https://discord.gg/aECcvtABpq) for build help.
- [ ] *(later)* Record the demo, post on LinkedIn **and** X with **#GnaniAI #GreatIndianAIInternshipChallenge**,
      tag @GnaniAi, then nominate the posts in the submission form when it opens.

Leave everything else to Claude.

---

## Ideas (pick one)

Award categories: regional language, code-mixed (Hinglish), noisy telephony audio, real-world impact, solo/duo,
creativity, Tier 2/3 town, best 60-sec demo, crowd favourite.

### A. Scam Kavach: a live scam-call shield ⭐ recommended
Put a call on speaker (or play a recording). Prisma transcribes it live in any Indian language or Hinglish, the
LLM watches for scam patterns ("digital arrest", fake KYC, OTP asks, courier/customs, "your account will be
blocked"), and the app **interrupts out loud** in the listener's language with a Timbre voice:
*"Ruko! Yeh call scam lag raha hai. OTP mat dena."* Ends with a plain-language summary to share with family.
- **Awards it hits:** Noise Canceller (phone audio), Mixed Vibes, Real Deal, Main Character, 60-sec demo.
- **Why it spreads:** everyone's parents get these calls. Very shareable post.
- **60-sec demo:** staged scam call (you and a friend, scripted) → app cuts in with a warning → summary card.
- Uses Prisma **realtime streaming** + Timbre v3.0 (with `<whispers>`/`<pauses>` audio tags for drama).

### B. Bol Khata: voice ledger for kirana shops
Shopkeeper says *"Ramesh ko do kilo cheeni udhaar, nabbe rupaye"* → entry added to the khata. *"Ramesh ka total
kitna hai?"* → answers aloud. Daily summary read out in Kannada/Hindi.
- **Awards:** Jugaad Genius, Small Town Big Build, Mixed Vibes, Real Deal.
- Simpler to build, a bit less viral.

### C. Sarkari Saathi: government scheme helper
Ask by voice in your language ("PM Kisan ka paisa kab aayega?", "ration card kaise banaye?"), get a short spoken
answer plus the steps on screen.
- **Awards:** Main Character, Real Deal. Risk: answers need to be accurate, so more content work.

**Rule to remember:** synthetic data only. Use scripted calls and made-up names and numbers, no real recordings
or real personal/financial info.

---

## What's already set up

- Python 3.12 venv in `.venv` with FastAPI, httpx, websockets.
- `app/gnani.py`: Prisma v3.0 STT (REST, auto language detect, `codemix` output, keyterms) and Timbre v3.0 TTS.
- `app/llm.py`: plug-in LLM (any OpenAI-compatible API).
- `app/main.py` + `static/index.html`: working push-to-talk page. Mic → Prisma → LLM → Timbre → plays the reply.
- `scripts/smoke_test.py`: checks your Gnani key with 2 calls.
- **Mock mode:** with no keys, everything runs with canned replies, so it's testable now. Tested end to end in
  mock mode; **not yet tested against the real API** (needs your key).

### Run it
```bash
.venv\Scripts\python scripts\smoke_test.py
```
```bash
.venv\Scripts\python -m uvicorn app.main:app --reload
```
Then open http://localhost:8000.

### Gnani API cheat sheet
- Base URL `https://api.vachana.ai`, header `X-API-Key-ID: <key>`.
- STT REST: `POST /stt/v3` (max 30 s per clip). Realtime: `wss://api.vachana.ai/stt/v3/stream` (16-bit mono PCM,
  8/16 kHz, 1024-byte frames, up to 15 min).
- TTS REST: `POST /api/v1/tts/inference`. Streaming: `/api/v1/tts/sse`. Realtime: `wss://api.vachana.ai/api/v1/tts`.
- 10 languages: hi, en, bn, gu, kn, ml, mr, pa, ta, te (`-IN`). `indic-auto` detects the language.
- Timbre v3.0: 13 voices, each speaks all 10 languages, supports audio tags like `<laugh>`, `<whispers>`.
- Docs index: https://docs.gnani.ai/llms.txt

---

## Rough plan once keys are in

| Day | Work |
|---|---|
| Wed 4 – Thu 5 | Keys in, smoke test, pick idea, build the core flow |
| Fri 6 – Sat 7 | Polish UI, test noisy phone audio, handle Hinglish edge cases |
| Sun 8 | Deploy a public link, script and record the 60-sec demo |
| Mon 9 | Post on LinkedIn + X, push engagement |
| Tue 10 | Buffer, submit before 11:59 PM |

Honest estimate: the core of idea A is 4–8 hours of build with Claude, polish and demo another 4–6.
