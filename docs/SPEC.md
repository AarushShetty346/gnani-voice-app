# ScamLingo: build spec (shared contract for all builders)

**Product:** ScamLingo. A live scam-call shield for Indian phone users. Put a suspicious call on
speaker; the app transcribes it live with Gnani **Prisma v3.0** (any of 10 Indian languages, code-mixed
Hinglish, noisy phone audio), detects scam patterns, and **interrupts out loud** in the listener's language with a
Gnani **Timbre v3.0** voice. After the call it shows a plain-language summary to share with family on WhatsApp.

Built for the Gnani AI "Great Indian AI Internship Challenge" (deadline 10 Nov 2026). Judged on public engagement
with a 60-second demo video, plus awards for regional languages, code-mixed speech, noisy telephony, real-world
impact. **Synthetic data only** (contest rule): demo calls are scripted, see `demo/scripts.json`.

Stack: Python 3.12, FastAPI, httpx, websockets; vanilla HTML/CSS/JS frontend (no build step); ffmpeg on PATH.
Venv: `.venv` (run things with `.venv/Scripts/python`). Tests: pytest + pytest-asyncio (`asyncio_mode = auto`
in `pytest.ini`). **Tests must never hit the network.**

Gnani API doc pages (already downloaded, markdown):
`C:/Users/aarus/AppData/Local/Temp/claude/3a0546643dc31d6b/f58192ea-cd93-4bfb-bd5a-39f9267ea5df/scratchpad/docs/`
(`introduction_quick-start.md`, `STT_speech-to-text.md`, `STT_stt-websocket.md`, `STT_models_prisma-v3.md`,
`TTS_tts-inference.md`, `TTS_available-voices.md`, `TTS_tts-audio-tags.md`, `introduction_errors.md`, ...).
Read the relevant ones before coding against the API.

## Critical Gnani API facts

- Base `https://api.vachana.ai`, auth header `X-API-Key-ID: <key>` (WS: `x-api-key-id`). Key from env `GNANI_API_KEY`.
- **Only 1 active REST request at a time per account.** A second concurrent request gets `429` with
  `detail.error_code = RATE_LIMITED`. So all REST calls (STT and TTS) go through one process-wide `asyncio.Lock`,
  and 429/5xx are retried with backoff (0.5 s, 1 s, 2 s; max 3 retries).
- STT REST: `POST /stt/v3`, multipart `audio_file` + form `model=prisma-v3.0`, `language_code` (`indic-auto`, or
  1–4 comma-separated like `hi-IN,en-IN`), `format` (`verbatim|transcribe|codemix|transliterate`), optional
  `keyterms` (JSON array string). **Max 30 s audio per request.** Response: `transcript`, `detected_language_code`.
- STT realtime: `wss://api.vachana.ai/stt/v3/stream`. Config via **upgrade headers**: `x-api-key-id`,
  `model: prisma-v3.0`, `language_code`, `format`, `x-sample-rate` (8000/16000/44100/48000), `keyterms`
  (JSON array, non-ASCII JSON-escaped), VAD headers (`x-vad-threshold`, `x-min-silence-ms`, `x-min-speech-ms`,
  `x-min-segment-ms`, `x-max-speech-s`), `x-idle-timeout-sec` (5–900). Send binary frames of **exactly 1024 bytes**
  (512 samples s16le mono) at real-time cadence (32 ms each at 16 kHz). Text frame `{"type":"commit"}` closes the
  open utterance. Server JSON messages: `connected`, `processing`, `transcript` (`text`, `detected_language_code`,
  `segment_index`, `latency`, ...), `error` (`message`). Session max 15 min. Invalid header → `error` then close 1008.
- TTS REST: `POST /api/v1/tts/inference`, JSON `{text, voice, model:"timbre-v3.0", language, speed,
  audio_config:{sample_rate, num_channels:1, sample_width:2, encoding:"linear_pcm", container:"wav"}}` →
  binary WAV. `language` can be `auto` or one of the 10 codes. Timbre v3.0 voices (each speaks all 10 languages):
  female Shivani, Lakshmi, Kalpana, Chetana, Vasudha, Riyaa, Tarika; male Avinash, Shubham, Prakash, Devansh,
  Yashraj, Harshad. Audio tags inline in text: `<pauses>`, `<whispers>`, `<shouting>`, `<excited>`, `<sigh>`, ...
- 10 languages: `hi-IN en-IN bn-IN gu-IN kn-IN ml-IN mr-IN pa-IN ta-IN te-IN`.
- LLM (optional "brain"): any OpenAI-compatible chat endpoint, env `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`.

**Mock mode:** with no `GNANI_API_KEY`, nothing calls Gnani; with no `LLM_API_KEY`, nothing calls the LLM. The
whole app must still run and demo end to end in mock mode (see "Mock behaviour").

## File ownership (one builder per file; don't edit files you don't own)

| Owner | Files |
|---|---|
| core | `app/config.py`, `app/gnani.py`, `app/gnani_stream.py`, `app/audio.py`, `tests/test_gnani.py`, `tests/test_gnani_stream.py`, `tests/test_audio.py`, `pytest.ini` |
| detector | `app/detector.py`, `app/alerts.py`, `app/summary.py`, `app/llm.py`, `tests/test_detector.py`, `tests/test_alerts.py`, `scripts/eval_detector.py` |
| frontend | `static/index.html`, `static/app.js`, `static/style.css`, `static/pcm-worklet.js` |
| api (runs after core + detector) | `app/main.py`, `app/session.py`, `scripts/make_demo_audio.py`, `scripts/smoke_test.py`, `tests/test_api.py`, `tests/test_session.py`, `README.md`, `requirements.txt` |

Shared, already written (read-only): `demo/scripts.json`, this spec. **Nobody commits to git.**

## Module contracts

### `app/config.py`
```python
LANGUAGES: dict[str, dict]   # code -> {"name": "Hindi", "native": "हिन्दी"} for the 10 codes
DEFAULT_VOICE: dict[str, str] # language -> Timbre v3.0 voice used for alerts (calm, clear female voice, e.g. Shivani)
SCAM_KEYTERMS: list[str]      # ~25 terms to bias STT: "OTP","KYC","AnyDesk","TeamViewer","CBI","ED","customs",
                              # "digital arrest","UPI","Aadhaar","PAN","RBI","arrest warrant","parcel", ...
ROOT: Path; CACHE_DIR: Path   # ROOT/.cache (git-ignored), created on demand
DEMO_DIR: Path                # ROOT/demo
def gnani_key() -> str; def llm_configured() -> bool; def gnani_mock() -> bool
def load_demos() -> list[dict]  # demo/scripts.json "demos"
```
Load `.env` with python-dotenv once at import (`load_dotenv(ROOT/".env")`). Read env lazily in functions (tests
monkeypatch env).

### `app/gnani.py` (async REST)
```python
class GnaniError(Exception): status: int; code: str | None; message: str
async def stt(audio: bytes, filename: str = "clip.wav", language: str = "indic-auto", fmt: str = "codemix",
              keyterms: list[str] | None = None) -> dict   # mock: {"transcript": "", "detected_language_code": None, "mock": True}
async def tts(text: str, voice: str = "Shivani", language: str = "auto", model: str = "timbre-v3.0",
              speed: float = 1.0, sample_rate: int = 24000) -> bytes   # WAV bytes; mock: short silent WAV
```
One module-level `asyncio.Lock` (create lazily per event loop) serializes both. Retry 429/502/503/504 + network
errors with backoff; raise `GnaniError` otherwise (parse `detail.error_code` / `detail.message` when present).
Reuse one `httpx.AsyncClient` per loop or create per call (simple is fine). Never log the API key.

### `app/gnani_stream.py` (realtime STT)
```python
@dataclass class StreamConfig:
    language: str = "indic-auto"; fmt: str = "codemix"; sample_rate: int = 16000
    keyterms: list[str] | None = None; telephony: bool = False   # telephony → VAD preset threshold 0.7,
    idle_timeout: int = 120                                     # min_speech 200, min_silence 500
class StreamBase:  # async context manager
    async def send_frame(self, frame: bytes) -> None   # exactly 1024 bytes; raise ValueError otherwise
    async def commit(self) -> None
    def events(self) -> AsyncIterator[dict]            # server messages as dicts, normalised:
        # {"type":"transcript","text":str,"language":str|None,"index":int}  |  {"type":"error","message":str,"fatal":bool}
        # | {"type":"connected"} | {"type":"processing"}. Ends when the connection closes.
    async def close(self) -> None
class GnaniStream(StreamBase): ...           # real WS, headers built from StreamConfig (+ keyterms JSON, ensure_ascii=True)
class MockStream(StreamBase):
    def __init__(self, lines: list[tuple[float, str, str]])   # (offset_s, text, language) relative to start
    # emits "connected" immediately, then each line as a transcript when wall-clock time since start >= offset_s.
    # Ignores audio content. commit() flushes nothing extra. After the last line, events() keeps waiting until close().
def open_stream(config: StreamConfig, mock_lines: list[tuple[float, str, str]] | None = None) -> StreamBase
    # GnaniStream if a key is set, else MockStream(mock_lines or [])
def mock_lines_for(demo: dict, manifest: dict | None = None) -> list[tuple[float, str, str]]
    # line timing from demo/audio/manifest.json when present, else estimate: start at 1.0 s; each line lasts
    # 1.2 s + 0.065 s per character; 0.6 s gap between lines.
```
Use `websockets` (v17: `websockets.asyncio.client.connect(url, additional_headers=...)`).

### `app/audio.py` (ffmpeg helpers, sync; callers wrap in `asyncio.to_thread`)
```python
class AudioError(Exception)
def to_wav(raw: bytes, rate: int = 16000) -> bytes          # any input → mono s16 WAV
def to_pcm16(raw: bytes, rate: int = 16000) -> bytes        # any input → raw s16le mono
def duration_s(raw: bytes) -> float
def split_wav(raw: bytes, max_s: float = 25.0) -> list[tuple[float, bytes]]  # (start_s, wav) chunks ≤ max_s
def phone_line(wav: bytes, noise: float = 0.015) -> bytes   # simulate a phone call: 8 kHz, 300–3400 Hz band,
                                                           # light hiss; returns 16 kHz mono WAV
def pcm_frames(pcm: bytes, size: int = 1024) -> list[bytes] # pad last frame with zeros
def concat_wavs(wavs: list[bytes], gap_s: float = 0.45, rate: int = 16000) -> tuple[bytes, list[tuple[float, float]]]
    # joins clips with silence; returns (wav, [(start_s, end_s) per clip])
```

### `app/detector.py`
Categories (keys are fixed, used everywhere):
`otp_request, impersonation, digital_arrest, account_threat, payment_request, remote_access, urgency_secrecy,
prize_job_offer`.
```python
@dataclass class Flag: category: str; phrase: str; start: int; end: int; weight: int   # start/end = char offsets in text
@dataclass class Assessment: score: int; level: str; categories: list[str]; reason: str; source: str  # "rules"|"llm"
LEVELS: safe < 35 <= caution < 70 <= danger
def scan(text: str) -> list[Flag]
class CallMonitor:
    def __init__(self): ...
    transcript: list[dict]                       # {"index","text","language","flags":[Flag as dict]}
    assessment: Assessment
    def add(self, text: str, language: str | None) -> tuple[list[Flag], Assessment]   # fast, sync, rules only
    async def llm_review(self) -> Assessment | None   # None when no LLM configured or on LLM error
    def dominant_language(self) -> str          # most common detected language, default "hi-IN"
```
Rules must cover English, romanised Hinglish ("otp batao", "account band ho jayega"), Devanagari Hindi, and
key terms in Kannada, Tamil, Telugu, Marathi, Bengali, Gujarati, Malayalam, Punjabi (incl. transliterated English
words like ಓಟಿಪಿ, ஓடிபி, ఓటీపీ, एनीडेस्क, ಎನಿಡೆಸ್ಕ್). Case-insensitive; Unicode-aware. Must handle **negation /
safety advice** ("bank kabhi OTP nahi maangta", "never share your OTP", "OTP किसी को न बताएं") so that the
`legit-bank-reminder` demo stays `safe`. Scoring: per-call accumulated score from distinct categories (repeats
add little), with **combination boosts** (authority + payment/OTP/remote-access ⇒ danger). Every scam demo in
`demo/scripts.json` must reach `danger` by its last line; the legit demo must stay `safe`.
LLM review: send the rolling transcript (last ~12 utterances) and ask for JSON
`{"score":0-100,"categories":[...],"reason":"..."}`; merged result = higher of rules and LLM, but never let the
LLM alone push a call to danger without at least one rule flag... (keep it simple: final = max(rules, llm) with
llm capped at 85 if no rule flags).

### `app/alerts.py`
```python
def alert_text(category: str, level: str, language: str) -> str
    # short (≤ 22 words), urgent, spoken warning in that language, handwritten for all 10 languages × 8 categories
    # (plus a generic one per language). Example hi-IN otp_request danger:
    # "रुकिए! यह कॉल धोखा लग रहा है। अपना OTP किसी को मत बताइए। अभी फ़ोन काट दीजिए।"
    # Starts with an audio tag for Timbre v3.0 where it helps (e.g. "<shouting>" is too much; prefer none or <pauses>).
async def alert_audio(text: str, language: str) -> bytes | None
    # Gnani TTS with config.DEFAULT_VOICE; cache by sha256(text+lang) in CACHE_DIR/tts/*.wav; None in mock mode
```
Native speakers will see these in a public demo. Write natural, simple phrasing, not literal translations.

### `app/summary.py`
```python
async def summarize(monitor: CallMonitor, language: str) -> dict
    # {"verdict":"scam"|"suspicious"|"safe","score":int,"categories":[...],"summary":str,"advice":[str,...],
    #  "language":str,"share_text":str}
    # LLM writes summary/advice in `language` when configured; otherwise template text per language (all 10;
    # at minimum hi-IN and en-IN templates, others may fall back to en-IN + hi-IN). share_text is WhatsApp-ready
    # (≤ 600 chars, includes "Checked with ScamLingo" and no personal data).
```

### `app/llm.py`
```python
def configured() -> bool
async def chat(messages: list[dict], temperature: float = 0.3, json_mode: bool = False, timeout: float = 20) -> str
async def chat_json(messages: list[dict]) -> dict | None   # try response_format json_object, fall back to parsing
                                                           # the first {...} block; None on any failure
```

### `app/session.py` + `app/main.py` (api builder)
`GET /` → `static/index.html`; `/static/*` static files; `/demo-audio/<id>.wav` serves `demo/audio/<id>.wav`.
`GET /api/status` → `{"gnani_mock":bool,"llm_mock":bool,"demo_audio":bool,"languages":LANGUAGES}`.
`GET /api/demos` → `[{"id","title","title_native","language","label","has_audio":bool,"lines":[{"speaker","text","offset_s","end_s"}]}]`.
`POST /api/analyze` (multipart `audio`, form `language`=`indic-auto`, `warn_language`=`auto`) → splits ≤ 25 s
chunks, REST STT each (sequential), runs `CallMonitor` + LLM review + summary →
`{"transcript":[{"index","text","language","flags","start_s"}],"risk":Assessment,"summary":{...}}`.
Reject files > 10 min (credits). Mock mode: use the `digital-arrest` demo lines as the transcript.

`WS /ws/listen` protocol (browser ⇄ backend):
- client → `{"type":"start","source":"mic"|"demo","demo_id":str|null,"language":"indic-auto","warn_language":"auto"|code}`
- client → binary frames: s16le mono **16 kHz**, exactly 1024 bytes, real-time cadence
- client → `{"type":"stop"}`
- server → `{"type":"ready","mock":bool}`
- server → `{"type":"transcript","index":int,"text":str,"language":str|null,"flags":[{"category","phrase","start","end"}]}`
- server → `{"type":"risk","score":int,"level":"safe"|"caution"|"danger","categories":[str],"reason":str,"source":"rules"|"llm"}`
- server → `{"type":"alert","level":"caution"|"danger","category":str,"text":str,"text_en":str|null,"language":str,"audio_b64":str|null}` (WAV; `text_en` is the English wording for the screen, null when the alert is already English)
- server → `{"type":"summary", ...summarize() fields}` then the server closes the socket
- server → `{"type":"error","message":str,"fatal":bool}`

Session rules: open stream (`telephony=True` when source is demo); mock lines = the demo's lines (source demo)
or the `digital-arrest` lines (source mic) when there is no Gnani key. Forward frames; for each transcript:
`monitor.add` → send `transcript` then `risk`. Alerts: when level rises to caution or danger, send an alert for the
highest-weight new category; at most one alert per category per call, at least 6 s between alerts, a danger alert
may pre-empt the gap once. Alert TTS runs in a background task (never blocks the transcript loop). LLM review
debounced: at most one in flight; run after each new transcript once ≥ 2 utterances; if it raises the level, send
`risk` (source llm) and maybe an alert. On `stop` or client disconnect: `commit`, wait ≤ 3 s for trailing
transcripts, send `summary` (if the socket is still open), close everything. 15-minute cap. Errors from Gnani →
`error` message (fatal if the stream died). `warn_language: "auto"` → `monitor.dominant_language()`.

### Mock behaviour (summary)
No Gnani key: STT stream = `MockStream` over demo lines; TTS returns None/silence (frontend shows alert text and
uses the browser's `speechSynthesis` as a fallback voice only when `audio_b64` is null); `/api/analyze` returns the
digital-arrest transcript. No LLM key: rules only; template summaries.

### `scripts/make_demo_audio.py` (needs a Gnani key)
For each demo: TTS every line with its speaker's voice and the demo language (sample_rate 16000), `concat_wavs`,
`phone_line` (unless `--clean`), write `demo/audio/<id>.wav` and `demo/audio/manifest.json`
`{id: {"duration_s": float, "lines": [{"offset_s","end_s"}]}}`. Skips demos whose audio exists unless `--force`.
Prints the number of TTS calls before starting.

## Frontend (frontend builder)
Mobile-first single page (people will film it on a phone for the 60-second demo). Name "ScamLingo" with a
shield mark; tagline e.g. "Suspicious call? Put it on speaker. ScamLingo listens and warns you." and a Hindi line.
Three tabs/modes:
1. **Live call**: big "Start listening" button → mic via `getUserMedia` (echoCancellation off, noiseSuppression on)
   → `AudioWorklet` (`pcm-worklet.js`) downsamples to 16 kHz Int16 and posts 512-sample (1024-byte) frames →
   `WS /ws/listen` with source `mic`. "Stop" sends `{"type":"stop"}`.
2. **Demo calls**: list from `/api/demos` (title, native title, language badge, SCAM/LEGIT badge). Play → if
   `has_audio`, play `/demo-audio/<id>.wav` through an `AudioContext` (`MediaElementSource` → speakers **and** the
   same worklet → WS, source `demo`); if no audio, still open the WS with source `demo` and send silent frames at
   real-time cadence while showing "mock audio" (the backend mock emits the lines on schedule).
3. **Check a recording**: file input → `POST /api/analyze` → render the same transcript/risk/summary UI.
Shared UI: risk meter (0–100, green/amber/red, label Safe / Be careful / Scam likely), live transcript bubbles
with flagged phrases highlighted using `flags[].start/end` (tooltip = category label), category chips, a
**full-screen red alert overlay** on `alert` (big text in the warn language, play `audio_b64` WAV, `navigator.vibrate`,
dismiss button; caution alerts use an amber banner instead), and a **summary card** at the end with verdict,
advice list and "Share on WhatsApp" (`https://wa.me/?text=` + encoded `share_text`) + "Copy" buttons.
"Warn me in" language picker (Auto + the 10 languages with native names). Status line from `/api/status`
showing mock vs live. Works in light and dark (`prefers-color-scheme`), no horizontal scroll at 360 px, large
touch targets, accessible (aria-live for transcript and alerts). No external JS libraries; Google Fonts allowed
(e.g. Noto Sans + Noto Sans Devanagari/Kannada/Tamil for Indic scripts). Category labels in English + Hindi.
