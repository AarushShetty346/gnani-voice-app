"""Optional LLM 'brain': any OpenAI-compatible chat endpoint (OpenAI, Gemini, Groq, OpenRouter,
a local llama.cpp server, ...).

Env (read on every call, so tests can monkeypatch): LLM_API_KEY, LLM_BASE_URL, LLM_MODEL.
All three must be set (same rule as config.llm_configured); otherwise the app runs rules-only.
"""
from __future__ import annotations

import json
import logging
import os
import re

import httpx

try:                       # app.config loads .env at import; fine if it isn't there yet
    import app.config  # noqa: F401
except Exception:          # pragma: no cover
    pass

log = logging.getLogger(__name__)

# Tests inject an httpx.MockTransport here; None means the real network.
_transport: httpx.AsyncBaseTransport | None = None


class LLMError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def configured() -> bool:
    return all(_env(k) for k in ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL"))


def mock_mode() -> bool:   # older name, kept for callers that still use it
    return not configured()


async def chat(messages: list[dict], temperature: float = 0.3, json_mode: bool = False, timeout: float = 20) -> str:
    """One chat completion; returns the assistant text. Raises LLMError on any failure."""
    if not configured():
        raise LLMError("LLM not configured (set LLM_API_KEY, LLM_BASE_URL, LLM_MODEL)")
    key, base = _env("LLM_API_KEY"), _env("LLM_BASE_URL").rstrip("/")
    body: dict = {"model": _env("LLM_MODEL"), "messages": messages, "temperature": temperature}
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    try:
        async with httpx.AsyncClient(timeout=timeout, transport=_transport) as client:
            r = await client.post(f"{base}/chat/completions", json=body,
                                  headers={"Authorization": f"Bearer {key}"})
    except httpx.HTTPError as e:
        raise LLMError(f"LLM network error: {type(e).__name__}") from e
    if r.status_code >= 400:
        raise LLMError(f"LLM HTTP {r.status_code}: {r.text[:200]}", r.status_code)
    try:
        content = r.json()["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as e:
        raise LLMError("LLM response has no choices[0].message.content") from e
    if not isinstance(content, str):
        raise LLMError("LLM returned empty content")
    return content.strip()


def parse_json(text: str) -> dict | None:
    """The JSON object in `text`: the whole text, else the first balanced {...} block."""
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except ValueError:
        pass
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        data = json.loads(text[start:i + 1])
                        if isinstance(data, dict):
                            return data
                    except ValueError:
                        pass
                    break
        start = text.find("{", start + 1)
    return None


async def chat_json(messages: list[dict]) -> dict | None:
    """Chat expecting a JSON object. Tries response_format=json_object first; if the endpoint rejects
    it, retries without. None on any failure (never raises)."""
    try:
        content = await chat(messages, temperature=0.2, json_mode=True)
    except LLMError as e:
        if e.status not in (400, 404, 415, 422):
            log.warning("LLM call failed: %s", e)
            return None
        try:                                   # endpoint doesn't support json_object: plain call
            content = await chat(messages, temperature=0.2)
        except LLMError as e2:
            log.warning("LLM call failed: %s", e2)
            return None
    return parse_json(content)
