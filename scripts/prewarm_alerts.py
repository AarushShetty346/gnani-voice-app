"""Voice every spoken alert ahead of time, so a live call never waits for Timbre TTS.

Generates alert_text(category, level, language) for every category (plus "generic") at both alert
levels, for each language, and stores the WAVs in .cache/tts/ -- exactly where app.alerts.alert_audio()
looks. Already-cached clips are skipped. Calls run one at a time (Gnani allows 1 REST request per
account), so run it while nothing else is using the key.

    .venv/Scripts/python scripts/prewarm_alerts.py --dry-run            # count missing clips, no calls
    .venv/Scripts/python scripts/prewarm_alerts.py --lang hi-IN,kn-IN   # only these languages
    .venv/Scripts/python scripts/prewarm_alerts.py                      # all 10 languages
"""
import argparse
import asyncio
import hashlib
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import alerts, config  # noqa: E402  (app.config loads .env)
from app.detector import CATEGORIES  # noqa: E402

LEVELS = ("caution", "danger")
MAX_FAILS_IN_A_ROW = 3        # the key is busy or broken: stop instead of burning retries


def cache_path(text: str, language: str) -> Path:
    """Must match app.alerts.alert_audio() (tests/test_api.py checks that it does)."""
    digest = hashlib.sha256((text + language).encode("utf-8")).hexdigest()
    return Path(config.CACHE_DIR) / "tts" / f"{digest}.wav"


def alert_texts(languages: list[str]) -> list[tuple[str, str]]:
    """(language, text) for every alert the app can speak in these languages, without duplicates."""
    out = []
    for lang in languages:
        for category in (*CATEGORIES, "generic"):
            for level in LEVELS:
                item = (lang, alerts.alert_text(category, level, lang))
                if item not in out:
                    out.append(item)
    return out


def parse_languages(value: str | None) -> list[str]:
    if not value:
        return list(config.LANGUAGES)
    codes = [c.strip() for c in value.split(",") if c.strip()]
    bad = [c for c in codes if c not in config.LANGUAGES]
    if bad:
        raise SystemExit(f"Unknown language code(s): {', '.join(bad)}. Use: {', '.join(config.LANGUAGES)}")
    return codes


async def prewarm(languages: list[str], dry_run: bool = False) -> int:
    items = alert_texts(languages)
    missing = [(lang, text) for lang, text in items if not cache_path(text, lang).exists()]
    print(f"{len(items)} alert clips for {', '.join(languages)}: {len(items) - len(missing)} cached, "
          f"{len(missing)} to generate ({len(missing)} TTS calls).")
    if dry_run or not missing:
        return 0
    if config.gnani_mock():
        print("GNANI_API_KEY is not set: nothing to do (mock mode has no voice).")
        return 1
    done = fails = in_a_row = 0
    for i, (lang, text) in enumerate(missing, 1):
        t = time.perf_counter()
        wav = await alerts.alert_audio(text, lang)
        ok = bool(wav) and cache_path(text, lang).exists()
        print(f"[{i}/{len(missing)}] {lang} {'ok ' if ok else 'FAILED'} {time.perf_counter() - t:4.1f} s  {text}")
        if ok:
            done, in_a_row = done + 1, 0
        else:
            fails, in_a_row = fails + 1, in_a_row + 1
            if in_a_row >= MAX_FAILS_IN_A_ROW:
                print("Stopping: several failures in a row (key busy or out of credits?). Run it again later;"
                      " clips already made are kept.")
                break
    print(f"Done: {done} generated, {fails} failed.")
    return 0 if fails == 0 else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lang", help="comma-separated language codes (default: all 10)")
    ap.add_argument("--dry-run", action="store_true", help="only count the clips that are missing")
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):          # Indic text through a Windows pipe
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    return asyncio.run(prewarm(parse_languages(args.lang), args.dry_run))


if __name__ == "__main__":
    sys.exit(main())
