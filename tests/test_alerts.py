"""Alerts (text + cached TTS), post-call summary, and the LLM client. No network: fakes + MockTransport."""
import json
import sys
import types

import httpx
import pytest

from app import alerts, llm, summary
from app.detector import CATEGORIES, CallMonitor

SCRIPT_RANGES = {"hi-IN": (0x0900, 0x097F), "mr-IN": (0x0900, 0x097F), "bn-IN": (0x0980, 0x09FF),
                 "pa-IN": (0x0A00, 0x0A7F), "gu-IN": (0x0A80, 0x0AFF), "ta-IN": (0x0B80, 0x0BFF),
                 "te-IN": (0x0C00, 0x0C7F), "kn-IN": (0x0C80, 0x0CFF), "ml-IN": (0x0D00, 0x0D7F)}


# ---------------------------------------------------------------- alert text

@pytest.mark.parametrize("lang", alerts.LANGS)
def test_alert_texts_complete_short_and_in_script(lang):
    for cat in (*CATEGORIES, "generic"):
        assert cat in alerts.TEXTS[lang]
        for level in ("danger", "caution"):
            text = alerts.alert_text(cat, level, lang)
            assert text and len(text.split()) <= 22, (lang, cat, level, text)
            if lang in SCRIPT_RANGES:
                lo, hi = SCRIPT_RANGES[lang]
                assert sum(lo <= ord(ch) <= hi for ch in text) > len(text) / 3, text
    for cat in CATEGORIES:
        assert alerts.LABELS[lang][cat]


def test_alert_text_shape():
    t = alerts.alert_text("otp_request", "danger", "hi-IN")
    assert t == "रुकिए! यह कॉल धोखा लग रहा है। अपना OTP किसी को मत बताइए। अभी फ़ोन काट दीजिए।"
    assert alerts.alert_text("otp_request", "caution", "en-IN").startswith("Be careful.")
    # every danger alert ends with "hang up" in its language
    for lang in alerts.LANGS:
        for cat in CATEGORIES:
            assert alerts.alert_text(cat, "danger", lang).endswith(alerts.TEXTS[lang]["hangup"])


def test_alert_text_fallbacks():
    assert alerts.alert_text("nonsense", "danger", "en-IN") == alerts.alert_text("generic", "danger", "en-IN")
    assert alerts.alert_text("otp_request", "danger", "auto") == alerts.alert_text("otp_request", "danger", "hi-IN")
    assert alerts.alert_text("otp_request", "safe", "en-IN") == alerts.alert_text("otp_request", "caution", "en-IN")


# ---------------------------------------------------------------- alert audio

@pytest.fixture
def fake_env(monkeypatch, tmp_path):
    """Fake app.config + app.gnani in sys.modules (alerts imports them lazily)."""
    calls = []
    cfg = types.ModuleType("app.config")
    cfg.CACHE_DIR = tmp_path
    cfg.DEFAULT_VOICE = {"ta-IN": "Vasudha"}
    cfg.gnani_mock = lambda: False
    gn = types.ModuleType("app.gnani")

    async def tts(text, voice="Shivani", language="auto", **kw):
        calls.append((text, voice, language))
        return b"RIFF-fake-wav"

    gn.tts = tts
    monkeypatch.setitem(sys.modules, "app.config", cfg)
    monkeypatch.setitem(sys.modules, "app.gnani", gn)
    return cfg, gn, calls


async def test_alert_audio_none_in_mock_mode(fake_env):
    cfg, _, calls = fake_env
    cfg.gnani_mock = lambda: True
    assert await alerts.alert_audio("hello", "en-IN") is None
    assert calls == []


async def test_alert_audio_caches(fake_env, tmp_path):
    _, _, calls = fake_env
    text = alerts.alert_text("payment_request", "danger", "ta-IN")
    assert await alerts.alert_audio(text, "ta-IN") == b"RIFF-fake-wav"
    assert await alerts.alert_audio(text, "ta-IN") == b"RIFF-fake-wav"
    assert calls == [(text, "Vasudha", "ta-IN")]                       # second call served from cache
    assert len(list((tmp_path / "tts").glob("*.wav"))) == 1


async def test_alert_audio_error_returns_none(fake_env):
    _, gn, _ = fake_env

    async def boom(*a, **k):
        raise RuntimeError("rate limited")

    gn.tts = boom
    assert await alerts.alert_audio("x", "hi-IN") is None


# ---------------------------------------------------------------- summary

def _monitor(lines, lang):
    m = CallMonitor()
    for t in lines:
        m.add(t, lang)
    return m


SCAM = ["Main CBI se bol raha hoon", "Aap digital arrest mein hain, kisi ko mat batana",
        "50000 rupaye safe account mein transfer kijiye, call me on 9876543210"]


@pytest.fixture
def no_llm(monkeypatch):
    monkeypatch.setattr(llm, "configured", lambda: False)


async def test_summary_template_scam_hindi(no_llm):
    s = await summary.summarize(_monitor(SCAM, None), "hi-IN")
    assert s["verdict"] == "scam" and s["score"] >= 70 and s["language"] == "hi-IN"
    assert "digital_arrest" in s["categories"]
    assert s["summary"].startswith("यह कॉल धोखाधड़ी लगती है")
    assert any("1930" in a for a in s["advice"])
    assert set(s) == {"verdict", "score", "categories", "summary", "advice", "language", "share_text"}


@pytest.mark.parametrize("lang", alerts.LANGS)
async def test_summary_templates_every_language(no_llm, lang):
    s = await summary.summarize(_monitor(SCAM, None), lang)
    assert s["language"] == lang and s["summary"] and len(s["advice"]) >= 3
    share = s["share_text"]
    assert len(share) <= 600 and "Checked with Scam Kavach" in share


async def test_summary_safe_call_english(no_llm):
    s = await summary.summarize(_monitor(["Your appointment is confirmed for tomorrow"], "en-IN"), "en-IN")
    assert s["verdict"] == "safe" and s["categories"] == []
    assert s["summary"] == "No clear scam signs were heard in this call."


async def test_summary_auto_language_uses_dominant(no_llm):
    m = _monitor(["ನಿಮ್ಮ ಖಾತೆ ಬ್ಲಾಕ್ ಆಗುತ್ತದೆ", "ಓಟಿಪಿ ಹೇಳಿ"], None)
    s = await summary.summarize(m, "auto")
    assert s["language"] == "kn-IN" and s["verdict"] == "scam"


def test_share_text_limits_and_redaction():
    advice = ["Do not pay. " * 20] * 6
    text = summary.share_text("scam", 95, "Caller 98765 43210 asked for money, mail a@b.com " * 10, advice, "en-IN")
    assert len(text) <= 600 and text.endswith("Checked with Scam Kavach")
    assert "98765" not in text and "a@b.com" not in text
    assert "1930" in summary.share_text("scam", 90, "Call 1930.", [], "en-IN")


async def test_summary_uses_llm_when_configured(monkeypatch):
    seen = {}

    async def fake(messages):
        seen["system"] = messages[0]["content"]
        return {"summary": "कॉल करने वाला नकली पुलिस था।", "advice": ["पैसे मत भेजिए", "1930 पर शिकायत करें", 5]}

    monkeypatch.setattr(llm, "configured", lambda: True)
    monkeypatch.setattr(llm, "chat_json", fake)
    s = await summary.summarize(_monitor(SCAM, None), "hi-IN")
    assert s["summary"] == "कॉल करने वाला नकली पुलिस था।"
    assert s["advice"] == ["पैसे मत भेजिए", "1930 पर शिकायत करें"]
    assert "Hindi" in seen["system"] and s["verdict"] == "scam"


@pytest.mark.parametrize("reply", [None, {"summary": ""}, {"summary": "ok", "advice": "not a list"}])
async def test_summary_falls_back_when_llm_fails(monkeypatch, reply):
    async def fake(messages):
        return reply

    monkeypatch.setattr(llm, "configured", lambda: True)
    monkeypatch.setattr(llm, "chat_json", fake)
    s = await summary.summarize(_monitor(SCAM, None), "en-IN")
    assert s["summary"].startswith("This call looks like a scam")


# ---------------------------------------------------------------- llm client (httpx.MockTransport)

@pytest.fixture
def llm_env(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_BASE_URL", "https://llm.test/v1/")
    monkeypatch.setenv("LLM_MODEL", "test-model")
    requests = []

    def use(handler):
        def wrapped(request):
            requests.append(request)
            return handler(request)
        monkeypatch.setattr(llm, "_transport", httpx.MockTransport(wrapped))
    return requests, use


def _ok(content):
    return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": content}}]})


def test_configured_needs_all_three(monkeypatch):
    for k in ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL"):
        monkeypatch.setenv(k, "x")
    assert llm.configured()
    monkeypatch.setenv("LLM_MODEL", "")
    assert not llm.configured()


async def test_chat_sends_openai_request(llm_env):
    requests, use = llm_env
    use(lambda r: _ok("  namaste  "))
    out = await llm.chat([{"role": "user", "content": "hi"}], temperature=0.1, json_mode=True)
    assert out == "namaste"
    (req,) = requests
    assert str(req.url) == "https://llm.test/v1/chat/completions"
    assert req.headers["authorization"] == "Bearer test-key"
    body = json.loads(req.content)
    assert body["model"] == "test-model" and body["temperature"] == 0.1
    assert body["response_format"] == {"type": "json_object"}


async def test_chat_errors(llm_env, monkeypatch):
    _, use = llm_env
    use(lambda r: httpx.Response(500, text="boom"))
    with pytest.raises(llm.LLMError) as e:
        await llm.chat([{"role": "user", "content": "hi"}])
    assert e.value.status == 500
    use(lambda r: httpx.Response(200, json={"oops": 1}))
    with pytest.raises(llm.LLMError):
        await llm.chat([{"role": "user", "content": "hi"}])

    def down(r):
        raise httpx.ConnectError("no route")
    use(down)
    with pytest.raises(llm.LLMError):
        await llm.chat([{"role": "user", "content": "hi"}])
    monkeypatch.setenv("LLM_API_KEY", "")
    with pytest.raises(llm.LLMError):
        await llm.chat([{"role": "user", "content": "hi"}])


async def test_chat_json_direct(llm_env):
    _, use = llm_env
    use(lambda r: _ok('{"score": 80, "categories": ["otp_request"]}'))
    assert await llm.chat_json([{"role": "user", "content": "x"}]) == {"score": 80, "categories": ["otp_request"]}


async def test_chat_json_falls_back_without_json_mode(llm_env):
    requests, use = llm_env

    def handler(r):
        if "response_format" in json.loads(r.content):
            return httpx.Response(400, json={"error": "response_format not supported"})
        return _ok('Sure! Here it is:\n```json\n{"score": 12, "reason": "a {curly} \\"quote\\""}\n``` hope it helps')
    use(handler)
    out = await llm.chat_json([{"role": "user", "content": "x"}])
    assert out == {"score": 12, "reason": 'a {curly} "quote"'}
    assert len(requests) == 2


async def test_chat_json_none_on_failure(llm_env):
    _, use = llm_env
    use(lambda r: httpx.Response(503, text="down"))
    assert await llm.chat_json([{"role": "user", "content": "x"}]) is None
    use(lambda r: _ok("no json here"))
    assert await llm.chat_json([{"role": "user", "content": "x"}]) is None


def test_parse_json():
    assert llm.parse_json('{"a": 1}') == {"a": 1}
    assert llm.parse_json('text {bad} then {"b": [1, {"c": 2}]} tail') == {"b": [1, {"c": 2}]}
    assert llm.parse_json("[1, 2]") is None
