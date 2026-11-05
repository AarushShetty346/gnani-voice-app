"""Evaluate the rule detector on the demo calls and on extra hand-written utterances.

    .venv/Scripts/python scripts/eval_detector.py [-v]

Prints per-demo level/score/categories and an overall PASS/FAIL. Exit code 1 on any failure.
All text here is synthetic (contest rule).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.detector import CallMonitor  # noqa: E402

LEVELS = ("safe", "caution", "danger")

# (text, language, expected, categories that must be flagged). expected: "safe" = must stay safe,
# "caution"/"danger" = must reach at least that level as a single utterance.
EXTRA_CASES: list[tuple[str, str | None, str, set[str]]] = [
    # --- scams, one utterance each
    ("Sir, aapka account band ho jayega, jaldi se OTP bata dijiye", None, "danger", {"account_threat", "otp_request"}),
    ("Main CBI se bol raha hoon, aapke naam pe money laundering ka case hai", None, "danger",
     {"impersonation", "digital_arrest"}),
    ("आपका बिजली कनेक्शन आज रात काट दिया जाएगा, तुरंत इस नंबर पर कॉल करें", "hi-IN", "caution",
     {"account_threat", "urgency_secrecy"}),
    ("Please download AnyDesk so I can fix your refund", "en-IN", "caution", {"remote_access"}),
    ("Congratulations! You have won a lottery of 25 lakh rupees, just pay the processing fee", "en-IN", "danger",
     {"prize_job_offer", "payment_request"}),
    ("ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಖಾತೆ ಬ್ಲಾಕ್ ಆಗುತ್ತದೆ, ಓಟಿಪಿ ಹೇಳಿ", "kn-IN", "danger", {"account_threat", "otp_request"}),
    ("உங்கள் வங்கிக் கணக்கு முடக்கப்படும், ஓடிபி சொல்லுங்கள்", "ta-IN", "danger", {"account_threat", "otp_request"}),
    ("మీ ఖాతా బ్లాక్ అవుతుంది, వెంటనే ఓటీపీ చెప్పండి", "te-IN", "danger", {"account_threat", "otp_request"}),
    ("तुमचं खाते बंद होईल, ओटीपी सांगा", "mr-IN", "danger", {"account_threat", "otp_request"}),
    ("আপনার অ্যাকাউন্ট ব্লক হয়ে যাবে, ওটিপি বলুন", "bn-IN", "danger", {"account_threat", "otp_request"}),
    ("તમારું એકાઉન્ટ બ્લોક થઈ જશે, ઓટીપી જણાવો", "gu-IN", "danger", {"account_threat", "otp_request"}),
    ("നിങ്ങളുടെ അക്കൗണ്ട് ബ്ലോക്ക് ആകും, ഒടിപി പറയൂ", "ml-IN", "danger", {"account_threat", "otp_request"}),
    ("ਤੁਹਾਡਾ ਖਾਤਾ ਬੰਦ ਹੋ ਜਾਵੇਗਾ, ਓਟੀਪੀ ਦੱਸੋ", "pa-IN", "danger", {"account_threat", "otp_request"}),
    ("Aap digital arrest mein hain, video call se mat hatna aur kisi ko mat batana", None, "danger",
     {"digital_arrest", "urgency_secrecy"}),
    ("ghar baithe roz 3000 kamaiye, bas YouTube videos like karne hain", None, "caution", {"prize_job_offer"}),
    ("Customs mein aapka parcel pakda gaya hai, usme drugs mile hain", None, "caution", {"digital_arrest"}),
    ("Your SIM card will be deactivated in 2 hours, press 9 to speak to an officer", "en-IN", "caution",
     {"account_threat", "urgency_secrecy"}),
    ("Sir please share the code you received on your phone, it is for verification", "en-IN", "caution",
     {"otp_request"}),
    ("RBI ke safe account mein paisa transfer kar dijiye, verification ke baad wapas mil jayega", None, "danger",
     {"payment_request", "impersonation"}),
    ("UPI se 10 rupaye bhejo, refund turant aa jayega", None, "caution", {"payment_request"}),
    ("ಮನೆಯಿಂದಲೇ ಕೆಲಸ ಮಾಡಿ ದಿನಕ್ಕೆ ಐದು ಸಾವಿರ ಸಂಪಾದಿಸಿ, ನೋಂದಣಿ ಶುಲ್ಕ ಕಟ್ಟಿ", "kn-IN", "danger",
     {"prize_job_offer", "payment_request"}),
    ("मुझे अपना ATM PIN और CVV बताइए", "hi-IN", "caution", {"otp_request"}),
    ("आपके नाम पर एक केस दर्ज हुआ है, वीडियो कॉल पर रहिए और किसी को मत बताइए", "hi-IN", "caution",
     {"digital_arrest", "urgency_secrecy"}),
    ("ये OTP किसी को मत बताना, सिर्फ मुझे बताओ", "hi-IN", "caution", {"otp_request"}),
    ("Main Delhi Police se Inspector Verma bol raha hoon, aapko arrest kar liya jayega", None, "caution",
     {"impersonation", "digital_arrest"}),
    ("ఇంటి నుంచే పని చేసి రోజుకు మూడు వేల రూపాయలు సంపాదించవచ్చు, రిజిస్ట్రేషన్ ఫీజు కట్టండి", "te-IN", "danger",
     {"prize_job_offer", "payment_request"}),
    ("આ એપ ડાઉનલોડ કરો, હું તમારી સ્ક્રીન શેર કરીને મદદ કરીશ", "gu-IN", "caution", {"remote_access"}),
    ("ਤੁਹਾਡੀ ਲਾਟਰੀ ਨਿਕਲੀ ਹੈ, ਫੀਸ ਭਰੋ ਤੇ ਇਨਾਮ ਲਓ", "pa-IN", "danger", {"prize_job_offer", "payment_request"}),
    # "if you don't tell the OTP, your account is blocked": conditional threats are not negation
    ("OTP नहीं बताया तो आपका account बंद हो जाएगा", "hi-IN", "danger", {"otp_request", "account_threat"}),
    ("OTP nahi bataya to aapka account block ho jayega", None, "danger", {"otp_request", "account_threat"}),
    ("OTP না দিলে আপনার অ্যাকাউন্ট বন্ধ হয়ে যাবে", "bn-IN", "danger", {"otp_request", "account_threat"}),
    ("OTP ಹೇಳಿ ಇಲ್ಲಾಂದ್ರೆ ನಿಮ್ಮ ಅಕೌಂಟ್ ಬ್ಲಾಕ್ ಆಗುತ್ತೆ", "kn-IN", "danger", {"otp_request", "account_threat"}),
    ("OTP नाही सांगितला तर तुमचं खाते बंद होईल", "mr-IN", "danger", {"otp_request", "account_threat"}),
    # -ये spellings (Prisma writes बताइये / जायेगा)
    ("आपका OTP बोलिये", "hi-IN", "caution", {"otp_request"}),
    ("OTP बता दीजिये", "hi-IN", "caution", {"otp_request"}),
    ("OTP बताईये", "hi-IN", "caution", {"otp_request"}),
    ("किसी को भी मत बताइयेगा, पैसे ट्रांसफर कीजिये", "hi-IN", "caution", {"urgency_secrecy", "payment_request"}),
    ("आपका KYC pending है, आपका SBI account आज suspend हो जायेगा", "hi-IN", "caution", {"account_threat"}),
    # brand + refund is a customer-care scam, not a delivery
    ("Main Amazon customer care se bol raha hoon, aapka refund atak gaya hai, OTP bata dijiye", None, "danger",
     {"otp_request", "impersonation"}),
    # Latin nouns with Hindi verbs, arrests, fines, Skype
    ("मैं TRAI से बोल रहा हूँ, दो घंटे में आपका mobile number बंद हो जाएगा", "hi-IN", "danger",
     {"impersonation", "account_threat"}),
    ("आपको गिरफ्तार किया जाएगा", "hi-IN", "caution", {"digital_arrest"}),
    ("aapka parcel seize hua hai, isme ganja mila hai, fine bharna padega", None, "danger",
     {"digital_arrest", "payment_request"}),
    ("आप Skype download कीजिए, CBI officer आपसे बात करेंगे", "hi-IN", "caution", {"remote_access", "digital_arrest"}),
    ("a case has been registered against you", "en-IN", "caution", {"digital_arrest"}),
    ("ನಿಮ್ಮ ಹೆಸರಲ್ಲಿ ಕೇಸ್ ಇದೆ", "kn-IN", "caution", {"digital_arrest"}),
    ("உங்க பேர்ல கேஸ் இருக்கு", "ta-IN", "caution", {"digital_arrest"}),
    ("మీ పేరు మీద కేసు ఉంది", "te-IN", "caution", {"digital_arrest"}),
    # OTP / CVV / UPI-collect without the word OTP, polite question forms
    ("आपके फोन पे एक code आया होगा, वो बताइए", "hi-IN", "caution", {"otp_request"}),
    ("aapke phone pe ek message aaya hoga, usme jo chhe digit ka number hai wo bata dijiye", None, "caution",
     {"otp_request"}),
    ("card ke peeche teen digit ka number bataiye", None, "caution", {"otp_request"}),
    ("पैसे receive करने के लिए आपको UPI PIN डालना होगा", "hi-IN", "caution", {"otp_request"}),
    ("ನಿಮ್ಮ ಅಕೌಂಟ್ ಬ್ಲಾಕ್ ಆಗುತ್ತೆ, OTP ಹೇಳ್ತೀರಾ", "kn-IN", "danger", {"account_threat", "otp_request"}),
    ("మీ అకౌంట్ బ్లాక్ అయిపోతుంది, ఓటీపీ చెప్తారా", "te-IN", "danger", {"account_threat", "otp_request"}),
    # sextortion, mistaken-transfer refund, investment / task scams, phishing link
    ("Sir aapka video call recording hai mere paas, paise nahi bheje to aapke sabhi contacts ko bhej dunga", None,
     "danger", {"urgency_secrecy", "payment_request"}),
    ("आपका video viral कर देंगे, पचास हज़ार भेजो वरना YouTube पर डाल देंगे", "hi-IN", "danger",
     {"urgency_secrecy", "payment_request"}),
    ("Bhaiya galti se aapke account mein 5000 rupaye chale gaye, please wapas kar dijiye", None, "caution",
     {"payment_request"}),
    ("भैया गलती से आपके account में 5000 रुपये चले गए, please वापस कर दीजिए", "hi-IN", "caution", {"payment_request"}),
    ("is WhatsApp group mein join kijiye, IPO allotment mein 300 percent return milega", None, "caution",
     {"prize_job_offer"}),
    ("आप hotel review का task करके रोज़ तीन हज़ार कमा सकते हैं", "hi-IN", "caution", {"prize_job_offer"}),
    ("Telegram पर task मिलेगा, पहले थोड़ा invest करना होगा", "hi-IN", "danger", {"prize_job_offer", "payment_request"}),
    ("link पर click करके details भरिए", "hi-IN", "caution", {"otp_request"}),
    # a "nahi" elsewhere in the sentence is not safety advice
    ("Main aapko pareshan nahi karunga bas OTP bata dijiye", None, "caution", {"otp_request"}),
    ("Aapka paisa kahin nahi jayega bas OTP bata dijiye", None, "caution", {"otp_request"}),
    ("आप digital arrest में हैं आप कुछ नहीं कर सकते", "hi-IN", "caution", {"digital_arrest"}),
    ("उनके पास कोई रास्ता नहीं, आपके खिलाफ arrest warrant है अब कुछ नहीं हो सकता", "hi-IN", "caution", {"digital_arrest"}),
    ("உங்களுக்கு வேற வழி இல்லை டிஜிட்டல் அரெஸ்ட்ல இருக்கீங்க", "ta-IN", "caution", {"digital_arrest"}),
    ("ನಿಮಗೆ ಬೇರೆ ದಾರಿ ಇಲ್ಲ ನೀವು ಡಿಜಿಟಲ್ ಅರೆಸ್ಟ್ ಆಗಿದ್ದೀರಿ", "kn-IN", "caution", {"digital_arrest"}),
    ("మీకు వేరే దారి లేదు మీరు డిజిటల్ అరెస్ట్ లో ఉన్నారు", "te-IN", "caution", {"digital_arrest"}),
    ("উপায় নেই আপনি ডিজিটাল অ্যারেস্টে আছেন", "bn-IN", "caution", {"digital_arrest"}),
    # --- benign / safety advice: must stay safe
    ("My OTP for Swiggy delivery came, I gave it to the delivery guy", "en-IN", "safe", set()),
    ("police ne mere bhai ko help ki", None, "safe", set()),
    ("Bank kabhi OTP nahi maangta, kisi ko mat batana", None, "safe", set()),
    ("Never share your OTP or PIN with anyone, not even bank staff", "en-IN", "safe", set()),
    ("OTP किसी को न बताएं, बैंक कभी फ़ोन पर OTP नहीं माँगता", "hi-IN", "safe", set()),
    ("Mummy, I reached office, will call you in the evening", "en-IN", "safe", set()),
    ("Aaj bijli chali gayi thi, ab aa gayi", None, "safe", set()),
    ("Please pay the electricity bill online before the due date using the official app", "en-IN", "safe", set()),
    ("I won the cricket match today!", "en-IN", "safe", set()),
    ("Kal mera Amazon parcel aa gaya", None, "safe", set()),
    ("मैंने अपने भाई को UPI से पैसे भेजे", "hi-IN", "safe", set()),
    ("ಓಟಿಪಿ ಯಾರಿಗೂ ಹೇಳಬೇಡಿ, ಬ್ಯಾಂಕ್ ಎಂದಿಗೂ ಕೇಳುವುದಿಲ್ಲ", "kn-IN", "safe", set()),
    ("ஓடிபி யாரிடமும் சொல்லாதீர்கள், வங்கி ஒருபோதும் கேட்காது", "ta-IN", "safe", set()),
    ("The police helped us find our lost dog", "en-IN", "safe", set()),
    ("Inspector sahab ne FIR likh li, ab ghar ja rahe hain", None, "safe", set()),
    ("मेरा बेटा वर्क फ्रॉम होम करता है", "hi-IN", "safe", set()),
    ("Sir, delivery ke liye OTP bata dijiye", None, "safe", set()),
    ("नमस्ते, मैं आपके बैंक से बोल रही हूँ, आपका नया डेबिट कार्ड ब्रांच में आ गया है", "hi-IN", "safe", set()),
    ("Main SBI se bol raha hoon, aapka home loan approve ho gaya hai, documents leke branch aaiye", None, "safe", set()),
    ("আজ আমার ভাইয়ের জন্মদিন, স্কুলে ও পুরস্কার পেয়েছে", "bn-IN", "safe", set()),
    ("Turant doctor ke paas jao, bukhar bahut tez hai", None, "safe", set()),
    ("Paise wapas mil gaye, thank you", None, "safe", set()),
    ("Kisi ko mat batana, mummy ke liye surprise party hai", None, "safe", set()),
    ("Don't worry, the bank will never block your account without notice", "en-IN", "safe", set()),
    ("डिजिटल अरेस्ट जैसा कुछ नहीं होता, पुलिस फ़ोन पर गिरफ़्तार नहीं करती", "hi-IN", "safe", set()),
    ("ఓటీపీ ఎవరికీ చెప్పకండి, బ్యాంక్ ఎప్పుడూ అడగదు", "te-IN", "safe", set()),
    ("ਆਪਣਾ ਓਟੀਪੀ ਕਿਸੇ ਨੂੰ ਨਾ ਦੱਸੋ", "pa-IN", "safe", set()),
    # scam-awareness talk (PSAs, a relative warning about scams)
    ("There is nothing called digital arrest, police will never call you on video", "en-IN", "safe", set()),
    ("Beware of digital arrest scams. Police never ask for money on a video call", "en-IN", "safe", set()),
    ("digital arrest naam ki koi cheez nahi hoti", None, "safe", set()),
    ("डिजिटल अरेस्ट जैसी कोई चीज़ नहीं होती", "hi-IN", "safe", set()),
    ("Agar koi digital arrest bole to samajh lo scam hai", None, "safe", set()),
    ("ಡಿಜಿಟಲ್ ಅರೆಸ್ಟ್ ಅನ್ನೋದು ಇಲ್ಲ, ಪೊಲೀಸರು ಫೋನ್‌ನಲ್ಲಿ ಬಂಧಿಸುವುದಿಲ್ಲ", "kn-IN", "safe", set()),
    ("ডিজিটাল অ্যারেস্ট বলে কিছু হয় না", "bn-IN", "safe", set()),
    # family and daily life
    ("Mera account block ho jayega bank wale ne bola, beta paise bhej do", None, "safe", set()),
    ("Beta wifi ka password bata do", None, "safe", set()),
    ("Netflix ka password bhej do na", None, "safe", set()),
    ("Gas cylinder wala aaya hai, OTP bata do", None, "safe", set()),
    ("मेरा फ़ोन नंबर बंद हो गया था, नया सिम लिया", "hi-IN", "safe", set()),
    ("Main galti se aapke ghar aa gaya, wapas ja raha hoon", None, "safe", set()),
    ("Bank kabhi OTP nahi maangta to kisi ko OTP mat batana", None, "safe", set()),
    ("Download the IRCTC app to book tickets", "en-IN", "safe", set()),
]

# Short multi-line calls: (name, language, lines, expected final level)
MINI_CALLS: list[tuple[str, str | None, list[str], str]] = [
    ("hinglish-digital-arrest", None, [
        "Hello, main Delhi Police cyber cell se Inspector Verma bol raha hoon",
        "Aapke Aadhaar se ek parcel book hua hai jisme drugs mile hain",
        "Aapke naam par arrest warrant hai, aap digital arrest mein hain, call mat kaatiye",
        "Case band karne ke liye 50000 rupaye RBI safe account mein transfer kijiye"], "danger"),
    ("telugu-kyc-otp", "te-IN", [
        "నమస్కారం, నేను బ్యాంక్ నుండి మాట్లాడుతున్నాను",
        "మీ KYC అప్‌డేట్ కాలేదు, మీ అకౌంట్ బ్లాక్ అవుతుంది",
        "మీ ఫోన్‌కి వచ్చిన OTP వెంటనే చెప్పండి"], "danger"),
    ("bengali-lottery", "bn-IN", [
        "অভিনন্দন! আপনি লটারিতে পঁচিশ লাখ টাকা জিতেছেন",
        "টাকা পেতে প্রথমে রেজিস্ট্রেশন ফি পাঁচ হাজার টাকা পাঠান",
        "এই অফার শুধু আজকের জন্য, কাউকে বলবেন না"], "danger"),
    ("gujarati-anydesk", "gu-IN", [
        "હું તમારી બેંકમાંથી બોલું છું",
        "તમારું એકાઉન્ટ બ્લોક થઈ જશે",
        "તરત AnyDesk એપ ડાઉનલોડ કરો અને મને કોડ જણાવો"], "danger"),
    ("malayalam-kseb", "ml-IN", [
        "ഞാൻ കെഎസ്ഇബിയിൽ നിന്നാണ് വിളിക്കുന്നത്",
        "ഇന്ന് രാത്രി നിങ്ങളുടെ കറന്റ് കട്ട് ചെയ്യും",
        "ഉടനെ പത്ത് രൂപ അടയ്ക്കണം, ഒടിപി പറയൂ"], "danger"),
    ("benign-clinic", "en-IN", [
        "Hi, this is Riya from Dr. Mehta's clinic",
        "Your appointment is confirmed for tomorrow at 10",
        "Please carry your old reports. Thank you!"], "safe"),
    ("benign-delivery", "hi-IN", [
        "नमस्ते, मैं Amazon से delivery boy बोल रहा हूँ",
        "आपका parcel गेट पर है, OTP बता दीजिए",
        "ठीक है, धन्यवाद"], "safe"),
    # VAD splits sentences at short pauses: phrases must still match across two utterances
    ("vad-split-hinglish", None, [
        "Hello main CBI", "se bol raha hoon", "aapka account", "block ho jayega", "aapke phone par jo OTP aaya hai",
        "woh bata dijiye"], "danger"),
    ("vad-split-hindi-otp", "hi-IN", ["आपके फ़ोन पर एक ओटीपी आया होगा", "वो बताइये"], "caution"),
    # one delivery word does not excuse every later OTP request
    ("delivery-then-bank", "en-IN", [
        "Your parcel delivery failed", "I am calling from the bank, your account will be blocked",
        "tell me the OTP"], "danger"),
    ("courier-otp-later", None, [
        "aapka parcel deliver nahi ho paya", "aapka address galat hai", "OTP bataiye"], "caution"),
    ("benign-gas-cylinder", None, [
        "Namaste, Indane gas cylinder delivery ke liye aaya hoon", "OTP bata dijiye", "theek hai, thank you"], "safe"),
    ("benign-family-warning", None, [
        "Maine news mein dekha digital arrest ke baare mein", "CBI wale bolke call karte hain",
        "paise transfer karwa lete hain", "kabhi mat dena"], "safe"),
    ("benign-family-money", None, ["Beta 2000 rupaye bhej do", "jaldi bhejna aaj hi chahiye"], "safe"),
]


def _at_least(level: str, expected: str) -> bool:
    return LEVELS.index(level) >= LEVELS.index(expected)


def run_case(text: str, language: str | None, expected: str, must: set[str]) -> tuple[bool, CallMonitor]:
    m = CallMonitor()
    m.add(text, language)
    a = m.assessment
    ok = a.level == "safe" if expected == "safe" else _at_least(a.level, expected) and must <= set(a.categories)
    return ok, m


def run_lines(lines: list[str], language: str | None) -> tuple[CallMonitor, list[str]]:
    m = CallMonitor()
    levels = [m.add(t, language)[1].level for t in lines]
    return m, levels


def load_demos() -> list[dict]:
    return json.loads((ROOT / "demo" / "scripts.json").read_text(encoding="utf-8"))["demos"]


def check_demo(demo: dict) -> tuple[bool, CallMonitor, list[str]]:
    m, levels = run_lines([ln["text"] for ln in demo["lines"]], demo["language"])
    if demo["label"] == "scam":
        ok = levels[-1] == "danger" and set(demo["categories"]) <= set(m.assessment.categories)
    else:
        ok = all(lv == "safe" for lv in levels)
    return ok, m, levels


def main(verbose: bool = False) -> int:
    failures = 0
    print("Demo calls")
    for demo in load_demos():
        ok, m, levels = check_demo(demo)
        failures += not ok
        a = m.assessment
        print(f"  {'PASS' if ok else 'FAIL'}  {demo['id']:<22} {a.level:<7} {a.score:>3}  {', '.join(a.categories)}")
        if verbose or not ok:
            for u, lv in zip(m.transcript, levels):
                print(f"        {lv:<7} {u['text'][:70]}  {[f['category'] for f in u['flags']]}")
    print("\nMini calls")
    for name, lang, lines, expected in MINI_CALLS:
        m, levels = run_lines(lines, lang)
        ok = levels[-1] == expected if expected != "safe" else all(lv == "safe" for lv in levels)
        failures += not ok
        a = m.assessment
        print(f"  {'PASS' if ok else 'FAIL'}  {name:<24} {a.level:<7} {a.score:>3}  {', '.join(a.categories)}")
    print("\nExtra utterances")
    n_scam = n_safe = 0
    for text, lang, expected, must in EXTRA_CASES:
        ok, m = run_case(text, lang, expected, must)
        failures += not ok
        n_scam += expected != "safe"
        n_safe += expected == "safe"
        a = m.assessment
        if verbose or not ok:
            print(f"  {'PASS' if ok else 'FAIL'}  want {expected:<7} got {a.level:<7} {a.score:>3} "
                  f"{','.join(a.categories):<40} {text[:60]}")
    total = len(load_demos()) + len(MINI_CALLS) + len(EXTRA_CASES)
    print(f"  {len(EXTRA_CASES)} utterances ({n_scam} scam, {n_safe} benign)")
    print(f"\n{'PASS' if not failures else 'FAIL'}: {total - failures}/{total} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main(verbose="-v" in sys.argv))
