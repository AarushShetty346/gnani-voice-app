"""Shared settings: languages, voices, scam keyterms, paths, env helpers.

Env is read lazily inside functions so tests can monkeypatch it.
"""
import json
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = ROOT / ".cache"   # git-ignored; callers mkdir(parents=True, exist_ok=True) on demand
DEMO_DIR = ROOT / "demo"

load_dotenv(ROOT / ".env")    # never overrides variables already set in the environment

LANGUAGES: dict[str, dict] = {
    "hi-IN": {"name": "Hindi", "native": "हिन्दी"},
    "en-IN": {"name": "English", "native": "English"},
    "bn-IN": {"name": "Bengali", "native": "বাংলা"},
    "gu-IN": {"name": "Gujarati", "native": "ગુજરાતી"},
    "kn-IN": {"name": "Kannada", "native": "ಕನ್ನಡ"},
    "ml-IN": {"name": "Malayalam", "native": "മലയാളം"},
    "mr-IN": {"name": "Marathi", "native": "मराठी"},
    "pa-IN": {"name": "Punjabi", "native": "ਪੰਜਾਬੀ"},
    "ta-IN": {"name": "Tamil", "native": "தமிழ்"},
    "te-IN": {"name": "Telugu", "native": "తెలుగు"},
}

# Alert voice per language. Every Timbre v3.0 voice speaks all 10 languages;
# Shivani is calm and clear, so we use her everywhere.
DEFAULT_VOICE: dict[str, str] = {code: "Shivani" for code in LANGUAGES}

# Terms that bias Prisma STT toward scam vocabulary (ASCII + a few Devanagari spellings).
SCAM_KEYTERMS: list[str] = [
    "OTP", "KYC", "AnyDesk", "TeamViewer", "QuickSupport", "CBI", "ED", "customs", "digital arrest",
    "UPI", "UPI PIN", "Aadhaar", "PAN", "RBI", "arrest warrant", "parcel", "FedEx", "cyber crime",
    "narcotics", "money laundering", "debit card", "CVV", "safe account", "TRAI", "SIM block",
    "ओटीपी", "डिजिटल अरेस्ट",
]


def gnani_key() -> str:
    return os.getenv("GNANI_API_KEY", "").strip()


def gnani_mock() -> bool:
    """True when no Gnani key is set: nothing calls Gnani."""
    return not gnani_key()


def llm_configured() -> bool:
    """An LLM is usable only when key, base URL and model are all set."""
    return all(os.getenv(k, "").strip() for k in ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL"))


def load_demos() -> list[dict]:
    with open(DEMO_DIR / "scripts.json", encoding="utf-8") as f:
        return json.load(f)["demos"]
