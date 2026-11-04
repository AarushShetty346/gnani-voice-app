"""Post-call summary for the user and a WhatsApp-ready share text.

LLM writes the summary/advice in the listener's language when configured; otherwise (or if the LLM
fails) handwritten templates are used, available for all 10 languages.
"""
from __future__ import annotations

import logging
import re

from app import alerts, llm
from app.detector import CallMonitor

log = logging.getLogger(__name__)

SHARE_MAX = 600
SHARE_FOOTER = "Checked with Scam Kavach"

VERDICT_WORDS = {
    "en-IN": {"scam": "Scam likely", "suspicious": "Be careful", "safe": "Looks safe"},
    "hi-IN": {"scam": "धोखे की आशंका", "suspicious": "सावधान रहें", "safe": "सुरक्षित लगती है"},
    "kn-IN": {"scam": "ಮೋಸದ ಸಾಧ್ಯತೆ", "suspicious": "ಎಚ್ಚರಿಕೆ", "safe": "ಸುರಕ್ಷಿತ ಅನಿಸುತ್ತದೆ"},
    "ta-IN": {"scam": "மோசடி வாய்ப்பு அதிகம்", "suspicious": "கவனம் தேவை", "safe": "பாதுகாப்பாகத் தெரிகிறது"},
    "te-IN": {"scam": "మోసం అయ్యే అవకాశం", "suspicious": "జాగ్రత్త", "safe": "సురక్షితంగా ఉంది"},
    "mr-IN": {"scam": "फसवणुकीची शक्यता", "suspicious": "सावध राहा", "safe": "सुरक्षित वाटतो"},
    "bn-IN": {"scam": "প্রতারণার সম্ভাবনা", "suspicious": "সাবধান", "safe": "নিরাপদ মনে হচ্ছে"},
    "gu-IN": {"scam": "છેતરપિંડીની શક્યતા", "suspicious": "સાવધાન", "safe": "સુરક્ષિત લાગે છે"},
    "ml-IN": {"scam": "തട്ടിപ്പിന് സാധ്യത", "suspicious": "ശ്രദ്ധിക്കുക", "safe": "സുരക്ഷിതമെന്ന് തോന്നുന്നു"},
    "pa-IN": {"scam": "ਠੱਗੀ ਦੀ ਸੰਭਾਵਨਾ", "suspicious": "ਸਾਵਧਾਨ", "safe": "ਸੁਰੱਖਿਅਤ ਲੱਗਦੀ ਹੈ"},
}

# {signs} = comma-separated category labels.
VERDICT_LINES = {
    "en-IN": {"scam": "This call looks like a scam. Warning signs: {signs}.",
              "suspicious": "This call seems suspicious. Warning signs: {signs}.",
              "safe": "No clear scam signs were heard in this call."},
    "hi-IN": {"scam": "यह कॉल धोखाधड़ी लगती है। खतरे के संकेत: {signs}।",
              "suspicious": "यह कॉल संदिग्ध लगती है। संकेत: {signs}।",
              "safe": "इस कॉल में धोखे के कोई साफ़ संकेत नहीं मिले।"},
    "kn-IN": {"scam": "ಈ ಕರೆ ಮೋಸದ ಕರೆ ಅನಿಸುತ್ತದೆ. ಎಚ್ಚರಿಕೆಯ ಸೂಚನೆಗಳು: {signs}.",
              "suspicious": "ಈ ಕರೆ ಅನುಮಾನಾಸ್ಪದವಾಗಿದೆ. ಸೂಚನೆಗಳು: {signs}.",
              "safe": "ಈ ಕರೆಯಲ್ಲಿ ಮೋಸದ ಸ್ಪಷ್ಟ ಸೂಚನೆಗಳು ಕಾಣಲಿಲ್ಲ."},
    "ta-IN": {"scam": "இந்த அழைப்பு மோசடி போல் தெரிகிறது. எச்சரிக்கை அறிகுறிகள்: {signs}.",
              "suspicious": "இந்த அழைப்பு சந்தேகமாக உள்ளது. அறிகுறிகள்: {signs}.",
              "safe": "இந்த அழைப்பில் மோசடிக்கான தெளிவான அறிகுறிகள் இல்லை."},
    "te-IN": {"scam": "ఈ కాల్ మోసంలా ఉంది. హెచ్చరిక సంకేతాలు: {signs}.",
              "suspicious": "ఈ కాల్ అనుమానాస్పదంగా ఉంది. సంకేతాలు: {signs}.",
              "safe": "ఈ కాల్‌లో మోసానికి స్పష్టమైన సంకేతాలు కనిపించలేదు."},
    "mr-IN": {"scam": "हा कॉल फसवणुकीचा वाटतो. धोक्याची चिन्हे: {signs}.",
              "suspicious": "हा कॉल संशयास्पद वाटतो. चिन्हे: {signs}.",
              "safe": "या कॉलमध्ये फसवणुकीची स्पष्ट चिन्हे आढळली नाहीत."},
    "bn-IN": {"scam": "এই কলটা প্রতারণা বলে মনে হচ্ছে। সতর্ক সংকেত: {signs}।",
              "suspicious": "এই কলটা সন্দেহজনক। সংকেত: {signs}।",
              "safe": "এই কলে প্রতারণার কোনো স্পষ্ট লক্ষণ পাওয়া যায়নি।"},
    "gu-IN": {"scam": "આ કૉલ છેતરપિંડી લાગે છે. ચેતવણીના સંકેતો: {signs}.",
              "suspicious": "આ કૉલ શંકાસ્પદ લાગે છે. સંકેતો: {signs}.",
              "safe": "આ કૉલમાં છેતરપિંડીના કોઈ સ્પષ્ટ સંકેત મળ્યા નથી."},
    "ml-IN": {"scam": "ഈ കോൾ തട്ടിപ്പാണെന്ന് തോന്നുന്നു. മുന്നറിയിപ്പ് സൂചനകൾ: {signs}.",
              "suspicious": "ഈ കോൾ സംശയകരമാണ്. സൂചനകൾ: {signs}.",
              "safe": "ഈ കോളിൽ തട്ടിപ്പിന്റെ വ്യക്തമായ സൂചനകളൊന്നുമില്ല."},
    "pa-IN": {"scam": "ਇਹ ਕਾਲ ਠੱਗੀ ਲੱਗਦੀ ਹੈ। ਖ਼ਤਰੇ ਦੇ ਸੰਕੇਤ: {signs}।",
              "suspicious": "ਇਹ ਕਾਲ ਸ਼ੱਕੀ ਲੱਗਦੀ ਹੈ। ਸੰਕੇਤ: {signs}।",
              "safe": "ਇਸ ਕਾਲ ਵਿੱਚ ਠੱਗੀ ਦੇ ਕੋਈ ਸਾਫ਼ ਸੰਕੇਤ ਨਹੀਂ ਮਿਲੇ।"},
}

# National cybercrime helpline 1930 / cybercrime.gov.in.
REPORT_LINES = {
    "en-IN": "Report it: call 1930 or visit cybercrime.gov.in.",
    "hi-IN": "शिकायत करें: 1930 पर कॉल करें या cybercrime.gov.in पर जाएँ।",
    "kn-IN": "ದೂರು ನೀಡಿ: 1930ಗೆ ಕರೆ ಮಾಡಿ ಅಥವಾ cybercrime.gov.in ನೋಡಿ.",
    "ta-IN": "புகார் செய்யுங்கள்: 1930-ஐ அழையுங்கள் அல்லது cybercrime.gov.in-ல் பதிவு செய்யுங்கள்.",
    "te-IN": "ఫిర్యాదు చేయండి: 1930కి కాల్ చేయండి లేదా cybercrime.gov.in లో నమోదు చేయండి.",
    "mr-IN": "तक्रार करा: 1930 वर कॉल करा किंवा cybercrime.gov.in वर जा.",
    "bn-IN": "অভিযোগ জানান: 1930-এ ফোন করুন বা cybercrime.gov.in-এ যান।",
    "gu-IN": "ફરિયાદ કરો: 1930 પર કૉલ કરો અથવા cybercrime.gov.in પર જાઓ.",
    "ml-IN": "പരാതി നൽകൂ: 1930-ൽ വിളിക്കൂ അല്ലെങ്കിൽ cybercrime.gov.in സന്ദർശിക്കൂ.",
    "pa-IN": "ਸ਼ਿਕਾਇਤ ਕਰੋ: 1930 'ਤੇ ਕਾਲ ਕਰੋ ਜਾਂ cybercrime.gov.in 'ਤੇ ਜਾਓ।",
}

_VERDICT = {"danger": "scam", "caution": "suspicious"}


def _language(language: str | None, monitor: CallMonitor) -> str:
    if language in alerts.TEXTS:
        return language
    return alerts.resolve_language(monitor.dominant_language())


def template(verdict: str, categories: list[str], language: str) -> tuple[str, list[str]]:
    """(summary, advice) from the handwritten texts."""
    lang = alerts.resolve_language(language)
    signs = ", ".join(alerts.category_label(c, lang) for c in categories[:4])
    if verdict == "safe" or not categories:
        line = VERDICT_LINES[lang]["safe"]
        return line, [alerts.category_text("otp_request", lang)]
    summary = VERDICT_LINES[lang][verdict].format(signs=signs)
    advice = [alerts.category_text(c, lang) for c in categories[:3]]
    if "otp_request" not in categories[:3]:
        advice.append(alerts.category_text("otp_request", lang))
    advice.append(REPORT_LINES[lang])
    return summary, advice


async def _llm_text(monitor: CallMonitor, verdict: str, categories: list[str], language: str) -> tuple[str, list[str]] | None:
    lines = "\n".join(f"[{u['index']}] {u['text']}" for u in monitor.transcript[-30:])
    lang_name = alerts.LANG_NAMES.get(language, language)
    messages = [
        {"role": "system", "content": (
            "You write short post-call summaries for Scam Kavach, a scam-call shield for Indian families. "
            f"Write in {lang_name} (simple everyday words, the way people really speak; English words like OTP, "
            "UPI, bank are fine). No names, phone numbers or account numbers. Reply with JSON only: "
            '{"summary": "2 sentences: what the caller wanted and why it is or is not a scam", '
            '"advice": ["3 to 4 short, concrete safety steps"]}')},
        {"role": "user", "content": f"Verdict: {verdict}. Warning signs: {', '.join(categories) or 'none'}.\n"
                                    f"Call transcript:\n{lines}"},
    ]
    data = await llm.chat_json(messages)
    if not isinstance(data, dict):
        return None
    summary = data.get("summary")
    advice = data.get("advice")
    if not isinstance(summary, str) or not summary.strip() or not isinstance(advice, list):
        return None
    advice = [a.strip() for a in advice if isinstance(a, str) and a.strip()][:5]
    if not advice:
        return None
    return summary.strip()[:500], advice


_REDACT = [(re.compile(r"\S+@\S+\.\S+"), "[email]"), (re.compile(r"(?<!\d)\d[\d\s-]{4,}\d(?!\d)"), "[number]")]


def _redact(text: str) -> str:
    """Strip phone/account numbers and emails (keeps short numbers like 1930)."""
    for rx, sub in _REDACT:
        text = rx.sub(sub, text)
    return text


def share_text(verdict: str, score: int, summary: str, advice: list[str], language: str) -> str:
    """WhatsApp-ready text (<= 600 chars), no personal data, ends with 'Checked with Scam Kavach'."""
    lang = alerts.resolve_language(language)
    icon = {"scam": "🚨", "suspicious": "⚠️"}.get(verdict, "✅")
    head = f"{icon} {VERDICT_WORDS[lang][verdict]} ({score}/100)"
    summary = _redact(summary)
    tips = [f"• {_redact(a)}" for a in advice]
    footer = f"🛡️ {SHARE_FOOTER}"
    while True:
        text = "\n".join([head, summary, *tips, footer])
        if len(text) <= SHARE_MAX:
            return text
        if tips:
            tips.pop()
        else:
            room = SHARE_MAX - len(head) - len(footer) - 3
            summary = summary[:max(0, room - 1)].rstrip() + "…"


async def summarize(monitor: CallMonitor, language: str) -> dict:
    """{"verdict","score","categories","summary","advice","language","share_text"} for the finished call."""
    lang = _language(language, monitor)
    a = monitor.assessment
    verdict = _VERDICT.get(a.level, "safe")
    cats = list(a.categories)
    text = None
    if llm.configured():
        try:
            text = await _llm_text(monitor, verdict, cats, lang)
        except Exception as e:  # never let the summary fail the call
            log.warning("LLM summary failed: %s", e)
    summary, advice = text or template(verdict, cats, lang)
    return {"verdict": verdict, "score": a.score, "categories": cats, "summary": summary, "advice": advice,
            "language": lang, "share_text": share_text(verdict, a.score, summary, advice, lang)}
