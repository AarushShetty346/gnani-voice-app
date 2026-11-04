"""The 'brain' between STT and TTS. Any OpenAI-compatible chat endpoint works
(Gemini, Groq, OpenRouter, a local llama.cpp server running Evon, ...).

Set LLM_BASE_URL, LLM_API_KEY, LLM_MODEL in .env. With no key it echoes back.
"""
import os

import httpx

SYSTEM_PROMPT = (
    "You are a helpful Indian voice assistant. Reply in the same language and style the user "
    "spoke (Hindi, Hinglish, Kannada, Tamil...). Keep replies under 40 words: they are read aloud."
)


def mock_mode() -> bool:
    return not os.getenv("LLM_API_KEY", "").strip()


def reply(user_text: str, history: list[dict] | None = None, system: str = SYSTEM_PROMPT) -> str:
    key = os.getenv("LLM_API_KEY", "").strip()
    if not key:
        return f"Aapne kaha: {user_text}"
    messages = [{"role": "system", "content": system}, *(history or []),
                {"role": "user", "content": user_text}]
    base = os.getenv("LLM_BASE_URL", "").rstrip("/")
    r = httpx.post(f"{base}/chat/completions",
                   headers={"Authorization": f"Bearer {key}"},
                   json={"model": os.getenv("LLM_MODEL"), "messages": messages,
                         "temperature": 0.4},
                   timeout=60)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()
