"""app.gnani_stream against a local fake Gnani WebSocket server, plus MockStream timing."""
import asyncio
import json
from http import HTTPStatus

import pytest
from websockets.asyncio.server import serve

from app import gnani_stream as gs
from app.gnani import GnaniError

FRAME = b"\x01\x00" * 512


@pytest.fixture
async def fake_server(monkeypatch):
    """Start a fake Gnani server on 127.0.0.1:<random>. `behaviour(ws, state)` drives each session."""
    monkeypatch.setenv("GNANI_API_KEY", "test-key")
    servers = []

    async def start(behaviour, process_request=None):
        state = {"headers": None, "frames": [], "texts": []}

        async def handler(ws):
            state["headers"] = ws.request.headers
            await behaviour(ws, state)
        server = await serve(handler, "127.0.0.1", 0, process_request=process_request)
        servers.append(server)
        port = server.sockets[0].getsockname()[1]
        monkeypatch.setattr(gs, "STREAM_URL", f"ws://127.0.0.1:{port}")
        return state
    yield start
    for s in servers:
        s.close()
        await s.wait_closed()


async def gnani_like(ws, state):
    """Echo Gnani's protocol: connected, then on commit a processing + transcripts + an error."""
    await ws.send(json.dumps({"type": "connected", "config": {"sample_rate": 16000, "chunk_size": 512}}))
    async for msg in ws:
        if isinstance(msg, bytes):
            state["frames"].append(msg)
            continue
        state["texts"].append(json.loads(msg))
        if json.loads(msg).get("type") == "commit":
            await ws.send(json.dumps({"type": "speech_start", "utterance_id": "u1"}))
            await ws.send(json.dumps({"type": "processing"}))
            await ws.send(json.dumps({"type": "transcript", "text": "  OTP batao  ", "segment_index": 1,
                                      "detected_language_code": "hi-IN", "latency": 300}))
            await ws.send(json.dumps({"type": "transcript", "text": "", "segment_index": 2}))
            await ws.send(json.dumps({"type": "error", "message": "utterance failed"}))


async def test_headers_frames_commit_and_events(fake_server):
    state = await fake_server(gnani_like)
    cfg = gs.StreamConfig(language="hi-IN,en-IN", keyterms=["OTP", "ओटीपी"], telephony=True, idle_timeout=2000)
    events = []
    async with gs.open_stream(cfg) as stream:
        assert isinstance(stream, gs.GnaniStream)
        for _ in range(3):
            await stream.send_frame(FRAME)
        await stream.commit()
        async for ev in stream.events():
            events.append(ev)
            if ev["type"] == "error":
                break

    h = state["headers"]
    assert h["x-api-key-id"] == "test-key"
    assert h["model"] == "prisma-v3.0"
    assert h["language_code"] == "hi-IN,en-IN"
    assert h["format"] == "codemix"
    assert h["x-sample-rate"] == "16000"
    assert h["x-idle-timeout-sec"] == "900"                      # clamped to Gnani's 5-900 range
    assert (h["x-vad-threshold"], h["x-min-speech-ms"], h["x-min-silence-ms"]) == ("0.7", "200", "500")
    assert h["keyterms"].isascii() and json.loads(h["keyterms"]) == ["OTP", "ओटीपी"]

    assert state["frames"] == [FRAME] * 3
    assert state["texts"] == [{"type": "commit"}]
    assert events == [
        {"type": "connected"},
        {"type": "processing"},
        {"type": "transcript", "text": "OTP batao", "language": "hi-IN", "index": 1},
        {"type": "error", "message": "utterance failed", "fatal": False},
    ]


async def test_no_vad_headers_without_telephony():
    h = gs.build_headers(gs.StreamConfig(), "k")
    assert "x-vad-threshold" not in h and "keyterms" not in h
    assert h["language_code"] == "indic-auto" and h["x-idle-timeout-sec"] == "120"


async def test_frame_size_validation(fake_server):
    await fake_server(gnani_like)
    async with gs.GnaniStream(gs.StreamConfig()) as stream:
        with pytest.raises(ValueError):
            await stream.send_frame(b"\x00" * 1000)
    with pytest.raises(ValueError):
        await gs.MockStream([]).send_frame(b"\x00" * 1025)


async def test_server_close_gives_fatal_error(fake_server):
    async def bad_header(ws, state):
        await ws.send(json.dumps({"type": "error", "message": "Invalid language_code"}))
        await ws.close(1008, "invalid header")
    await fake_server(bad_header)
    async with gs.GnaniStream(gs.StreamConfig(language="xx-XX")) as stream:
        events = [ev async for ev in stream.events()]
    assert events[0] == {"type": "error", "message": "Invalid language_code", "fatal": False}
    assert events[-1]["type"] == "error" and events[-1]["fatal"] is True
    assert "1008" in events[-1]["message"]
    await stream.send_frame(FRAME)                               # sending after death is a no-op


async def test_client_close_ends_events_quietly(fake_server):
    await fake_server(gnani_like)
    stream = gs.GnaniStream(gs.StreamConfig())
    await stream.open()
    got = []

    async def read():
        async for ev in stream.events():
            got.append(ev)
    reader = asyncio.create_task(read())
    await asyncio.sleep(0.1)
    await stream.close()
    await asyncio.wait_for(reader, 2)
    assert got == [{"type": "connected"}]


async def test_handshake_401_raises_gnani_error(fake_server):
    def refuse(connection, request):
        body = json.dumps({"detail": {"error_code": "INVALID_API_KEY", "message": "Unauthorized"}})
        return connection.respond(HTTPStatus.UNAUTHORIZED, body)
    await fake_server(gnani_like, process_request=refuse)
    with pytest.raises(GnaniError) as ei:
        async with gs.GnaniStream(gs.StreamConfig()):
            pass
    assert (ei.value.status, ei.value.code) == (401, "INVALID_API_KEY")


async def test_open_stream_mock_without_key(monkeypatch):
    monkeypatch.delenv("GNANI_API_KEY", raising=False)
    assert isinstance(gs.open_stream(gs.StreamConfig()), gs.MockStream)


async def test_mock_stream_timing():
    lines = [(0.15, "second", "en-IN"), (0.05, "first", "hi-IN")]
    loop = asyncio.get_running_loop()
    async with gs.MockStream(lines) as stream:
        t0 = loop.time()
        got = []
        events = stream.events()
        for _ in range(3):
            ev = await events.__anext__()
            got.append((round(loop.time() - t0, 2), ev))
        # after the last line it keeps waiting until close()
        nxt = asyncio.ensure_future(events.__anext__())
        await asyncio.sleep(0.05)
        assert not nxt.done()
        nxt.cancel()
    assert got[0] == (0.0, {"type": "connected"})
    assert got[1][1] == {"type": "transcript", "text": "first", "language": "hi-IN", "index": 1}
    assert got[2][1] == {"type": "transcript", "text": "second", "language": "en-IN", "index": 2}
    assert 0.04 <= got[1][0] < 0.12 and 0.14 <= got[2][0] < 0.25


async def test_mock_stream_close_stops_events():
    stream = gs.MockStream([(5.0, "never", "hi-IN")])
    await stream.open()
    events = stream.events()
    assert await events.__anext__() == {"type": "connected"}
    later = asyncio.ensure_future(events.__anext__())
    await asyncio.sleep(0.02)
    await stream.close()
    with pytest.raises(StopAsyncIteration):
        await asyncio.wait_for(later, 1)


DEMO = {"id": "t", "language": "kn-IN", "lines": [{"speaker": "caller", "text": "a" * 10},
                                                  {"speaker": "victim", "text": "b" * 20}]}


def test_mock_lines_for_estimate():
    lines = gs.mock_lines_for(DEMO, manifest={})
    # line 1: 1.0 -> 1.0+1.2+0.65 = 2.85; line 2: 3.45 -> 3.45+1.2+1.3 = 5.95
    assert lines == [(2.85, "a" * 10, "kn-IN"), (5.95, "b" * 20, "kn-IN")]
    assert gs.line_timings(DEMO, {}) == [(1.0, 2.85), (3.45, 5.95)]


def test_mock_lines_for_manifest():
    manifest = {"t": {"duration_s": 9.0, "lines": [{"offset_s": 0.5, "end_s": 2.0}, {"offset_s": 2.4, "end_s": 7.5}]}}
    assert gs.mock_lines_for(DEMO, manifest) == [(2.0, "a" * 10, "kn-IN"), (7.5, "b" * 20, "kn-IN")]
    # a manifest entry that doesn't match the script falls back to the estimate
    stale = {"t": {"lines": [{"offset_s": 0.5, "end_s": 2.0}]}}
    assert gs.mock_lines_for(DEMO, stale) == gs.mock_lines_for(DEMO, {})
