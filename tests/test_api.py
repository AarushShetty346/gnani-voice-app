"""HTTP + WebSocket API in mock mode (no Gnani key, no LLM key): nothing touches the network."""
import io
import json
import shutil
import wave

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app import config, gnani, main
from app import session as sess

FRAME = b"\x00\x00" * 512


def wav_bytes(seconds: float, rate: int = 16000) -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(b"\x00\x00" * int(rate * seconds))
    return buf.getvalue()


@pytest.fixture
def client():
    with TestClient(main.app) as c:
        yield c


@pytest.fixture
def fast_demos(monkeypatch):
    """Mock stream emits each demo line 40 ms apart instead of at real speaking pace."""
    def fast(demo, manifest=None):
        return [(0.05 + 0.04 * i, line["text"], demo["language"]) for i, line in enumerate(demo["lines"])]
    monkeypatch.setattr(sess, "mock_lines_for", fast)


def demo(demo_id):
    return next(d for d in config.load_demos() if d["id"] == demo_id)


# ---------------------------------------------------------------- pages and status

def test_index_and_static(client):
    r = client.get("/")
    assert r.status_code == 200 and "Scam Kavach" in r.text
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/style.css").status_code == 200


def test_status_mock(client):
    s = client.get("/api/status").json()
    assert s["gnani_mock"] is True and s["llm_mock"] is True
    assert isinstance(s["demo_audio"], bool)
    assert len(s["languages"]) == 10 and s["languages"]["kn-IN"]["native"] == "ಕನ್ನಡ"


def test_demos_list(client):
    demos = client.get("/api/demos").json()
    assert [d["id"] for d in demos] == [d["id"] for d in config.load_demos()]
    for d in demos:
        assert {"id", "title", "title_native", "language", "label", "has_audio", "lines"} <= set(d)
        assert d["label"] in ("scam", "legit")
        last = 0.0
        for line in d["lines"]:
            assert {"speaker", "text", "offset_s", "end_s"} <= set(line)
            assert last <= line["offset_s"] < line["end_s"]
            last = line["end_s"]


@pytest.fixture
def tmp_demo_dir(tmp_path, monkeypatch):
    shutil.copy(config.DEMO_DIR / "scripts.json", tmp_path / "scripts.json")
    (tmp_path / "audio").mkdir()
    (tmp_path / "audio" / "digital-arrest.wav").write_bytes(wav_bytes(0.5))
    (tmp_path / "secret.txt").write_text("nope")
    n = len(demo("digital-arrest")["lines"])
    manifest = {"digital-arrest": {"duration_s": 30.0,
                                   "lines": [{"offset_s": 1.0 + 4 * i, "end_s": 4.0 + 4 * i} for i in range(n)]}}
    (tmp_path / "audio" / "manifest.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(config, "DEMO_DIR", tmp_path)
    return tmp_path


def test_demo_audio_serving(client, tmp_demo_dir):
    r = client.get("/demo-audio/digital-arrest.wav")
    assert r.status_code == 200 and r.headers["content-type"] == "audio/wav" and r.content[:4] == b"RIFF"
    assert client.head("/demo-audio/digital-arrest.wav").status_code == 200
    part = client.get("/demo-audio/digital-arrest.wav", headers={"Range": "bytes=0-3"})
    assert part.status_code == 206 and part.content == b"RIFF"                # seeking works for <audio>
    for bad in ("/demo-audio/bank-kyc-otp.wav",          # known id, no file yet
                "/demo-audio/nope.wav", "/demo-audio/digital-arrest.mp3", "/demo-audio/digital-arrest",
                "/demo-audio/..%2Fsecret.txt", "/demo-audio/..%2Faudio%2Fdigital-arrest.wav",
                "/demo-audio/%2E%2E%2Fscripts.json"):
        assert client.get(bad).status_code == 404, bad
    demos = {d["id"]: d for d in client.get("/api/demos").json()}
    assert demos["digital-arrest"]["has_audio"] is True and demos["bank-kyc-otp"]["has_audio"] is False
    assert demos["digital-arrest"]["lines"][1]["offset_s"] == 5.0          # timing from the manifest
    assert client.get("/api/status").json()["demo_audio"] is False         # not every demo has audio


# ---------------------------------------------------------------- /api/analyze

def test_analyze_mock_returns_digital_arrest(client):
    r = client.post("/api/analyze", files={"audio": ("call.wav", wav_bytes(1.0), "audio/wav")},
                    data={"language": "indic-auto", "warn_language": "auto"})
    assert r.status_code == 200, r.text
    data = r.json()
    lines = demo("digital-arrest")["lines"]
    assert [t["text"] for t in data["transcript"]] == [line["text"] for line in lines]
    starts = [t["start_s"] for t in data["transcript"]]
    assert starts == sorted(starts)
    assert {"index", "text", "language", "flags", "start_s"} <= set(data["transcript"][0])
    assert any(t["flags"] for t in data["transcript"])
    assert data["risk"]["level"] == "danger" and data["risk"]["source"] in ("rules", "llm")
    assert data["summary"]["verdict"] == "scam" and data["summary"]["language"] == "hi-IN"
    assert data["mock"] is True


@pytest.mark.parametrize("payload, status", [
    (b"this is not audio at all", 400),
    (b"", 400),
])
def test_analyze_bad_audio(client, payload, status):
    r = client.post("/api/analyze", files={"audio": ("x.mp3", payload, "audio/mpeg")})
    assert r.status_code == status
    assert isinstance(r.json()["detail"], str)


def test_analyze_limits(client, monkeypatch):
    monkeypatch.setattr(main, "MAX_DURATION_S", 1)
    r = client.post("/api/analyze", files={"audio": ("long.wav", wav_bytes(1.5), "audio/wav")})
    assert r.status_code == 400 and "minutes" in r.json()["detail"]
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 1000)
    r = client.post("/api/analyze", files={"audio": ("big.wav", wav_bytes(1.0), "audio/wav")})
    assert r.status_code == 413
    r = client.post("/api/analyze", files={"audio": ("a.wav", wav_bytes(0.01), "audio/wav")},
                    data={"language": "klingon"})
    assert r.status_code == 400


def test_analyze_live_chunks_sequentially(client, monkeypatch):
    """With a key: <= CHUNK_S chunks, one STT call at a time, keyterms sent, sentences split."""
    monkeypatch.setenv("GNANI_API_KEY", "test-key")
    monkeypatch.setattr(main, "CHUNK_S", 1.0)
    calls, active = [], [0]
    replies = ["Hello, main Mumbai cyber crime branch se bol raha hoon. Aapka OTP bataiye.",
               "", "Nahi toh aapka account block ho jayega."]

    async def fake_stt(audio, filename="clip.wav", language="indic-auto", fmt="codemix", keyterms=None):
        active[0] += 1
        assert active[0] == 1
        calls.append({"filename": filename, "language": language, "fmt": fmt, "keyterms": keyterms,
                      "seconds": (len(audio) - 44) / 32000})
        active[0] -= 1
        return {"transcript": replies[len(calls) - 1], "detected_language_code": "hi-IN"}
    monkeypatch.setattr(gnani, "stt", fake_stt)
    r = client.post("/api/analyze", files={"audio": ("call.wav", wav_bytes(2.5), "audio/wav")},
                    data={"language": "hi-IN,en-IN", "warn_language": "en-IN"})
    assert r.status_code == 200, r.text
    assert len(calls) == 3 and all(c["seconds"] <= 1.0 for c in calls)
    assert all(c["language"] == "hi-IN,en-IN" and c["fmt"] == "codemix" and c["keyterms"] == config.SCAM_KEYTERMS
               for c in calls)
    data = r.json()
    assert [t["text"] for t in data["transcript"]] == [
        "Hello, main Mumbai cyber crime branch se bol raha hoon.", "Aapka OTP bataiye.",
        "Nahi toh aapka account block ho jayega."]
    assert [t["start_s"] for t in data["transcript"]][0] == 0 and data["transcript"][2]["start_s"] == 2.0
    assert data["risk"]["level"] != "safe" and data["summary"]["language"] == "en-IN" and data["mock"] is False


def test_analyze_gnani_error_is_502(client, monkeypatch):
    monkeypatch.setenv("GNANI_API_KEY", "test-key")

    async def broken(*a, **k):
        raise gnani.GnaniError(429, "RATE_LIMITED", "Too many requests")
    monkeypatch.setattr(gnani, "stt", broken)
    r = client.post("/api/analyze", files={"audio": ("call.wav", wav_bytes(0.5), "audio/wav")})
    assert r.status_code == 502 and "Too many requests" in r.json()["detail"]


# ---------------------------------------------------------------- WS /ws/listen

def run_call(client, start: dict, n_lines: int | None) -> list[dict]:
    """Start a call, wait for n_lines transcripts (None: don't wait), stop, collect until the server closes."""
    msgs = []
    with client.websocket_connect("/ws/listen") as ws:
        ws.send_json({"type": "start", "language": "indic-auto", "warn_language": "auto", **start})
        msgs.append(ws.receive_json())
        if msgs[0]["type"] != "ready":
            with pytest.raises(WebSocketDisconnect):
                ws.receive_json()
            return msgs
        while n_lines and sum(m["type"] == "transcript" for m in msgs) < n_lines:
            ws.send_bytes(FRAME)
            msgs.append(ws.receive_json())
        ws.send_json({"type": "stop"})
        while msgs[-1]["type"] != "summary":
            msgs.append(ws.receive_json())
        with pytest.raises(WebSocketDisconnect):
            ws.receive_json()
    return msgs


def test_ws_digital_arrest_demo(client, fast_demos):
    n = len(demo("digital-arrest")["lines"])
    msgs = run_call(client, {"source": "demo", "demo_id": "digital-arrest"}, n)
    assert msgs[0] == {"type": "ready", "mock": True}
    transcripts = [m for m in msgs if m["type"] == "transcript"]
    assert [t["text"] for t in transcripts] == [line["text"] for line in demo("digital-arrest")["lines"]]
    assert all(t["language"] == "hi-IN" for t in transcripts)
    risks = [m for m in msgs if m["type"] == "risk"]
    assert len(risks) >= n
    scores = [r["score"] for r in risks]
    assert scores == sorted(scores) and scores[0] < scores[-1] and risks[-1]["level"] == "danger"
    alerts = [m for m in msgs if m["type"] == "alert"]
    assert any(a["level"] == "danger" for a in alerts)
    assert len({a["category"] for a in alerts}) == len(alerts)              # one alert per category
    assert all(a["language"] == "hi-IN" and a["text"] and a["audio_b64"] is None for a in alerts)
    summary = msgs[-1]
    assert summary["type"] == "summary" and summary["verdict"] == "scam"
    assert "Checked with Scam Kavach" in summary["share_text"]
    # order: every transcript is followed by its risk
    kinds = [m["type"] for m in msgs]
    for i, k in enumerate(kinds):
        if k == "transcript":
            assert kinds[i + 1] == "risk"


def test_ws_legit_call_stays_safe(client, fast_demos):
    n = len(demo("legit-bank-reminder")["lines"])
    msgs = run_call(client, {"source": "demo", "demo_id": "legit-bank-reminder", "warn_language": "en-IN"}, n)
    assert sum(m["type"] == "transcript" for m in msgs) == n
    assert not [m for m in msgs if m["type"] == "alert" and m["level"] == "danger"]
    assert all(m["level"] == "safe" for m in msgs if m["type"] == "risk")
    assert msgs[-1]["verdict"] == "safe" and msgs[-1]["language"] == "en-IN"


def test_ws_mic_in_mock_mode_hears_digital_arrest(client, fast_demos):
    msgs = run_call(client, {"source": "mic"}, 2)
    first = next(m for m in msgs if m["type"] == "transcript")
    assert first["text"] == demo("digital-arrest")["lines"][0]["text"]
    assert msgs[-1]["type"] == "summary"


def test_ws_stop_right_away_still_summarises(client):
    msgs = run_call(client, {"source": "demo", "demo_id": "bank-kyc-otp"}, None)
    assert msgs[0]["type"] == "ready" and msgs[-1]["type"] == "summary" and msgs[-1]["verdict"] == "safe"


def test_ws_unknown_demo(client):
    msgs = run_call(client, {"source": "demo", "demo_id": "../../etc/passwd"}, None)
    assert msgs == [{"type": "error", "message": "Unknown demo id '../../etc/passwd'.", "fatal": True}]


def test_ws_garbage_first_message(client):
    with client.websocket_connect("/ws/listen") as ws:
        ws.send_text("hello")
        m = ws.receive_json()
        assert m["type"] == "error" and m["fatal"] is True
        with pytest.raises(WebSocketDisconnect):
            ws.receive_json()


# ---------------------------------------------------------------- scripts/make_demo_audio.py (offline)

async def test_make_demo_audio_build_offline(tmp_path, monkeypatch):
    """build() with a fake Timbre: writes <id>.wav + manifest timing the app then uses. No network, tmp dirs."""
    import importlib.util

    from app.gnani_stream import line_timings
    spec = importlib.util.spec_from_file_location("make_demo_audio", config.ROOT / "scripts" / "make_demo_audio.py")
    mda = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mda)
    d = demo("legit-bank-reminder")
    monkeypatch.setattr(config, "DEMO_DIR", tmp_path / "demo")
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    calls = []

    async def fake_tts(text, voice="Shivani", language="auto", model="timbre-v3.0", speed=1.0, sample_rate=24000):
        calls.append((voice, language, sample_rate))
        return wav_bytes(0.5 + 0.01 * len(calls), sample_rate)
    monkeypatch.setattr(gnani, "tts", fake_tts)
    entry = await mda.build(d, clean=False)
    assert calls == [(d["voices"][line["speaker"]], "hi-IN", 16000) for line in d["lines"]]
    out = (tmp_path / "demo" / "audio" / "legit-bank-reminder.wav").read_bytes()
    assert out[:4] == b"RIFF" and abs(entry["duration_s"] - (len(out) - 44) / 32000) < 0.05
    spans = [(x["offset_s"], x["end_s"]) for x in entry["lines"]]
    assert spans[0][0] == mda.LEAD_S and all(a < b for a, b in spans)
    assert entry["duration_s"] >= spans[-1][1] + mda.TAIL_S - 0.05
    await mda.build(d, clean=True)                       # second run: every line comes from the cache
    assert len(calls) == len(d["lines"])
    assert line_timings(d, {"legit-bank-reminder": entry}) == spans
