"""llm.chat() retries once with LLM_FALLBACK_MODEL when the primary model is overloaded or times out."""
import json

import httpx
import pytest

from app import llm


@pytest.fixture
def llm_env(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_BASE_URL", "https://llm.test/v1")
    monkeypatch.setenv("LLM_MODEL", "primary")
    models = []

    def use(handler):
        def wrapped(request):
            models.append(json.loads(request.content)["model"])
            return handler(request, models[-1])
        monkeypatch.setattr(llm, "_transport", httpx.MockTransport(wrapped))
    return models, use


def ok(text):
    return httpx.Response(200, json={"choices": [{"message": {"content": text}}]})


@pytest.mark.parametrize("status", [429, 500, 503])
async def test_falls_back_on_overload(llm_env, monkeypatch, status):
    monkeypatch.setenv("LLM_FALLBACK_MODEL", "backup")
    models, use = llm_env
    use(lambda r, m: httpx.Response(status, json={"error": "high demand"}) if m == "primary" else ok("from backup"))
    assert await llm.chat([{"role": "user", "content": "hi"}]) == "from backup"
    assert models == ["primary", "backup"]


async def test_falls_back_on_timeout(llm_env, monkeypatch):
    monkeypatch.setenv("LLM_FALLBACK_MODEL", "backup")
    models, use = llm_env

    def handler(r, m):
        if m == "primary":
            raise httpx.ReadTimeout("slow", request=r)
        return ok("{\"score\": 5}")
    use(handler)
    assert await llm.chat_json([{"role": "user", "content": "hi"}]) == {"score": 5}
    assert models == ["primary", "backup"]


async def test_no_fallback_for_other_errors_or_when_unset(llm_env, monkeypatch):
    models, use = llm_env
    monkeypatch.setenv("LLM_FALLBACK_MODEL", "backup")
    use(lambda r, m: httpx.Response(401, text="bad key"))
    with pytest.raises(llm.LLMError) as e:
        await llm.chat([{"role": "user", "content": "hi"}])
    assert e.value.status == 401 and models == ["primary"]

    models.clear()
    monkeypatch.delenv("LLM_FALLBACK_MODEL")
    use(lambda r, m: httpx.Response(503, text="busy"))
    with pytest.raises(llm.LLMError):
        await llm.chat([{"role": "user", "content": "hi"}])
    assert models == ["primary"]


async def test_fallback_failure_raises_once(llm_env, monkeypatch):
    monkeypatch.setenv("LLM_FALLBACK_MODEL", "backup")
    models, use = llm_env
    use(lambda r, m: httpx.Response(503, text="busy"))
    with pytest.raises(llm.LLMError) as e:
        await llm.chat([{"role": "user", "content": "hi"}])
    assert e.value.status == 503 and models == ["primary", "backup"]
