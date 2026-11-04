"""Tests never touch the real APIs or spend credits.

Blank the keys before any app module loads .env (python-dotenv won't override a variable that
already exists). Tests that need a key set it themselves with monkeypatch + a mock transport.
"""
import os

os.environ["GNANI_API_KEY"] = ""
os.environ["LLM_API_KEY"] = ""
