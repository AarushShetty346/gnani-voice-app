"""app.gnani against httpx.MockTransport: no network."""
import asyncio
import io
import json
import wave

import httpx
import pytest

from app import gnani


@pytest.fixture
def live(monkeypatch):
    """Pretend a key is set, skip backoff sleeps, and route requests to a handler."""
    monkeypatch.setenv("GNANI_API_KEY", "test-key")
    monkeypatch.setattr(gnani, "BACKOFF", (0.0, 0.0, 0.0))

    def use(handler):
        monkeypatch.setattr(gnani, "_transport", httpx.MockTransport(handler))
    return use


async def test_stt_success_sends_expected_request(live):
    seen = {}

    def handler(req: httpx.Request):
        seen["url"] = str(req.url)
        seen["key"] = req.headers["x-api-key-id"]
        seen["body"] = req.content.decode("utf-8", "replace")
        return httpx.Response(200, json={"success": True, "transcript": "OTP batao",
                                         "detected_language_code": "hi-IN"})
    live(handler)
    out = await gnani.stt(b"RIFFfake", language="hi-IN,en-IN", keyterms=["OTP", "ओटीपी"])
    assert out["transcript"] == "OTP batao"
    assert seen["url"] == "https://api.vachana.ai/stt/v3"
    assert seen["key"] == "test-key"
    for part in ('name="model"', "prisma-v3.0", "hi-IN,en-IN", "codemix", 'name="audio_file"', "ओटीपी"):
        assert part in seen["body"]


async def test_tts_success_body(live):
    seen = {}

    def handler(req):
        seen.update(json.loads(req.content))
        return httpx.Response(200, content=b"RIFF....WAVE")
    live(handler)
    out = await gnani.tts("रुकिए!", voice="Kalpana", language="hi-IN", sample_rate=16000)
    assert out == b"RIFF....WAVE"
    assert seen["model"] == "timbre-v3.0" and seen["voice"] == "Kalpana" and seen["language"] == "hi-IN"
    assert seen["audio_config"] == {"sample_rate": 16000, "num_channels": 1, "sample_width": 2,
                                    "encoding": "linear_pcm", "container": "wav"}


async def test_429_then_success_retries(live):
    calls = []

    def handler(req):
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(429, json={"detail": {"error_code": "RATE_LIMITED", "message": "busy",
                                                        "status_code": 429}})
        return httpx.Response(200, json={"transcript": "ok"})
    live(handler)
    assert (await gnani.stt(b"x"))["transcript"] == "ok"
    assert len(calls) == 2


async def test_network_error_then_success(live):
    calls = []

    def handler(req):
        calls.append(1)
        if len(calls) < 3:
            raise httpx.ConnectError("boom", request=req)
        return httpx.Response(200, content=b"wav")
    live(handler)
    assert await gnani.tts("hi") == b"wav"
    assert len(calls) == 3


async def test_retries_give_up_after_three(live):
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(503, json={"success": False, "message": "down", "status_code": 503})
    live(handler)
    with pytest.raises(gnani.GnaniError) as ei:
        await gnani.tts("hi")
    assert len(calls) == 4                       # first try + 3 retries
    assert ei.value.status == 503 and ei.value.message == "down"


async def test_400_error_is_not_retried_and_parsed(live):
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(400, json={"success": False,
                                         "error": {"type": "INVALID_FORMAT", "message": "Invalid format."}})
    live(handler)
    with pytest.raises(gnani.GnaniError) as ei:
        await gnani.stt(b"x", fmt="nope")
    assert len(calls) == 1
    assert (ei.value.status, ei.value.code, ei.value.message) == (400, "INVALID_FORMAT", "Invalid format.")


async def test_401_detail_error_code(live):
    live(lambda req: httpx.Response(401, json={"detail": {"error_code": "INVALID_API_KEY",
                                                          "message": "Unauthorized", "status_code": 401}}))
    with pytest.raises(gnani.GnaniError) as ei:
        await gnani.tts("hi")
    assert ei.value.code == "INVALID_API_KEY" and ei.value.message == "Unauthorized"
    assert "test-key" not in str(ei.value)


def test_parse_error_shapes():
    e = gnani.parse_error(422, json.dumps({"detail": [{"msg": "Field required"}]}))
    assert (e.code, e.message) == ("VALIDATION_ERROR", "Field required")
    e = gnani.parse_error(504, json.dumps({"error": "Gateway Timeout", "code": "UPSTREAM_TIMEOUT", "message": "slow"}))
    assert (e.code, e.message) == ("UPSTREAM_TIMEOUT", "slow")
    e = gnani.parse_error(502, b"<html>bad gateway</html>")
    assert e.code is None and "bad gateway" in e.message


async def test_lock_serializes_concurrent_calls(live):
    active, peak, order = 0, 0, []

    async def handler(req):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        order.append("start")
        await asyncio.sleep(0.05)
        order.append("end")
        active -= 1
        if req.url.path == "/stt/v3":
            return httpx.Response(200, json={"transcript": "a"})
        return httpx.Response(200, content=b"wav")
    live(handler)
    await asyncio.gather(gnani.stt(b"x"), gnani.tts("y"), gnani.tts("z"))
    assert peak == 1
    assert order == ["start", "end"] * 3


async def test_mock_mode_never_calls_network(monkeypatch):
    monkeypatch.delenv("GNANI_API_KEY", raising=False)

    def handler(req):
        raise AssertionError("network used in mock mode")
    monkeypatch.setattr(gnani, "_transport", httpx.MockTransport(handler))
    assert gnani.mock_mode()
    assert await gnani.stt(b"x") == {"transcript": "", "detected_language_code": None, "mock": True}
    wav = await gnani.tts("hello", sample_rate=24000)
    with wave.open(io.BytesIO(wav)) as w:
        assert (w.getnchannels(), w.getsampwidth(), w.getframerate()) == (1, 2, 24000)
        assert w.getnframes() > 0
