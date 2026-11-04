"""Scam pattern detector: multilingual rules + optional LLM review.

`scan(text)` finds scam phrases (with char offsets into the ORIGINAL text, for highlighting).
`CallMonitor` accumulates flags over a call and turns them into a 0-100 risk score.

Rules cover English, romanised Hinglish (Prisma `transliterate`), Devanagari Hindi/Marathi and
Kannada, Tamil, Telugu, Bengali, Gujarati, Malayalam, Punjabi, including English words written in
native script (ಓಟಿಪಿ, ஓடிபி, एनीडेस्क) and code-mixed output (native script + Latin English words).

Matching runs on a normalised copy of the text (NFD, no nukta / zero-width joiners, chandrabindu ->
anusvara, Malayalam chillu -> base+virama), with an index map back to the original characters.
Patterns are normalised the same way, so they can be written naturally.
"""
from __future__ import annotations

import re
import unicodedata
from collections import Counter
from dataclasses import asdict, dataclass, replace

CATEGORIES = ("otp_request", "impersonation", "digital_arrest", "account_threat", "payment_request",
              "remote_access", "urgency_secrecy", "prize_job_offer")
LANG_CODES = ("hi-IN", "en-IN", "bn-IN", "gu-IN", "kn-IN", "ml-IN", "mr-IN", "pa-IN", "ta-IN", "te-IN")
CAUTION_AT, DANGER_AT = 35, 70
LLM_CAP_NO_FLAGS = 85          # the LLM alone (no rule flag) can't push a call past this

# Short English reasons, used in Assessment.reason.
REASONS = {
    "otp_request": "asks for OTP/PIN/card details",
    "impersonation": "claims to be police, bank or officials",
    "digital_arrest": "arrest / legal threat (\"digital arrest\")",
    "account_threat": "threatens to block your account or cut a service",
    "payment_request": "asks you to send money",
    "remote_access": "asks you to install a screen-sharing app",
    "urgency_secrecy": "rushes you or asks for secrecy",
    "prize_job_offer": "promises a prize, job or easy money",
}


@dataclass
class Flag:
    category: str
    phrase: str
    start: int        # char offsets into the original text
    end: int
    weight: int


@dataclass
class Assessment:
    score: int
    level: str        # safe | caution | danger
    categories: list[str]
    reason: str
    source: str       # rules | llm


def level_for(score: int) -> str:
    return "danger" if score >= DANGER_AT else "caution" if score >= CAUTION_AT else "safe"


# ---------------------------------------------------------------- normalisation

_DROP = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD,                 # zero-width, soft hyphen
         0x093C, 0x09BC, 0x0A3C, 0x0ABC, 0x0B3C, 0x0CBC}                  # nukta signs
_PRE = {"ൌ": "ൗ", "’": "'", "‘": "'"}                 # Malayalam au, curly quotes
_POST = {
    "ँ": "ं", "ঁ": "ং", "ઁ": "ં", "ੰ": "ਂ",  # chandrabindu/tippi
    "ॉ": "ो", "ऑ": "ओ", "ॅ": "े", "ऍ": "ए",  # ॉ->ो, ऑ->ओ, ॅ->े
    "ൺ": "ണ്", "ൻ": "ന്", "ർ": "ര്",    # Malayalam chillu
    "ൽ": "ല്", "ൾ": "ള്", "ൿ": "ക്",
}


def _normalize(text: str) -> tuple[str, list[int]]:
    """Normalised text plus, for every normalised char, the index of its source char."""
    out: list[str] = []
    idx: list[int] = []
    for i, ch in enumerate(text):
        for d in unicodedata.normalize("NFD", _PRE.get(ch, ch)):
            o = ord(d)
            if o in _DROP or 0x300 <= o <= 0x36F:
                continue
            d = _POST.get(d, d)
            out.append(d)
            idx.extend([i] * len(d))
    return "".join(out), idx


def _norm(s: str) -> str:
    return _normalize(s)[0]


# ---------------------------------------------------------------- pattern helpers

def L(*alts: str) -> str:
    """Latin alternatives with ASCII word boundaries (\\b is unreliable next to Indic marks)."""
    return r"(?<![a-z0-9])(?:" + "|".join(alts) + r")(?![a-z0-9])"


def A(*alts: str) -> str:
    return "(?:" + "|".join(alts) + ")"


IS = r"(?<![ऀ-෿])"      # start of an Indic word
IE = r"(?![ऀ-෿])"       # end of an Indic word


def G(n: int) -> str:
    """A short gap that stays inside one sentence/clause."""
    return r"[^.!?।॥,\n]{0,%d}?" % n


@dataclass(frozen=True)
class _Rule:
    category: str
    weight: int
    rx: re.Pattern
    neg: str | None = None     # None | "neg" (dropped in a negated clause) | "strict" (explicit denial only)
    advice: bool = False       # secrecy phrase: dropped when the sentence is about OTP/PIN (safety advice)
    soft: bool = False         # context only (see scan): "calling from your bank", "parcel", "police"


@dataclass(frozen=True)
class _Pair:
    """Term A and term B within `window` chars (either order), e.g. OTP ... tell me."""
    category: str
    weight: int
    a: re.Pattern
    b: re.Pattern
    window: int = 100


def _c(p: str) -> re.Pattern:
    return re.compile(_norm(p), re.IGNORECASE)


_RULES: list[_Rule] = []


def _r(cat: str, weight: int, *alts: str, neg: str | None = None, advice: bool = False, soft: bool = False) -> None:
    _RULES.append(_Rule(cat, weight, _c(A(*alts)), neg, advice, soft or weight < 15))


# ---------------------------------------------------------------- shared vocab

OTP_T = A(
    L(r"otp", r"o\.\s?t\.\s?p\.?", r"one[- ]time (?:password|pin|code)", r"verification code",
      r"security code", r"(?:\d|four|six|4|6)[- ]digit (?:code|number|otp|pin)",
      r"(?:the|that|this) code(?: you)? (?:received|got|just got)", r"code (?:aaya|aya|aayega)"),
    r"ओटीपी", r"ओ\.?टी\.?पी", "ಓಟಿಪಿ", "ಒಟಿಪಿ", "ஓடிபி", r"ஓ\.டி\.பி", "ఓటీపీ", "ఓటిపి", "ওটিপি",
    "ઓટીપી", "ഒടിപി", "ഓടിപി", "ਓਟੀਪੀ")

SECRET_T = A(
    L(r"pin(?!\s?code)", "upi pin", "atm pin", "m-?pin", "cvv", "password", "passcode",
      r"card (?:number|details|no)", r"expiry(?: date)?", r"net ?banking (?:password|id|login)",
      "login id", "user ?id"),
    IS + r"पिन(?!\s*कोड)", "सीवीवी", "पासवर्ड", r"कार्ड\s*(?:नंबर|नम्बर|डिटेल)", "एक्सपायरी",
    IS + r"ಪಿನ್(?!\s*ಕೋಡ್)", "ಸಿವಿವಿ", "ಪಾಸ್ವರ್ಡ್", r"ಕಾರ್ಡ್\s*ನಂಬರ್",
    r"பின்\s*(?:நம்பர்|எண்)", "சிவிவி", "பாஸ்வேர்ட்", r"கார்டு\s*(?:நம்பர்|எண்)",
    IS + r"పిన్(?!\s*కోడ్)", "సీవీవీ", "పాస్వర్డ్", r"కార్డ్\s*నంబర్",
    IS + r"পিন(?!\s*কোড)", "সিভিভি", "পাসওয়ার্ড", r"কার্ড\s*নম্বর",
    IS + r"પિન(?!\s*કોડ)", "સીવીવી", "પાસવર્ડ", r"કાર્ડ\s*નંબર",
    IS + r"പിൻ(?!\s*കോഡ്)", "സിവിവി", "പാസ്വേഡ്", r"കാർഡ്\s*നമ്പർ",
    IS + r"ਪਿੰਨ(?!\s*ਕੋਡ)", "ਸੀਵੀਵੀ", "ਪਾਸਵਰਡ", r"ਕਾਰਡ\s*ਨੰਬਰ")

# "tell me / give / share" addressed to the listener, in every language (romanised too).
REQ_V = A(
    L(r"tell(?: me)?", "share", "give", r"read(?: it)?(?: out)?", "send", "forward", "say", "confirm",
      "provide", "enter", "type", "note down", "batao", "bataiye", "bataye", "bataen", "bataein",
      "batayen", "batayiye", r"bata (?:do|dijiye|dena|de)", "bolo", "boliye", r"bol (?:do|dijiye)",
      r"de (?:do|dijiye)", "dedo", "dijiye", "bhejo", "bhejiye", r"bhej (?:do|dijiye)",
      r"share (?:karo|kijiye|kariye|kar do)", "sunao", "sunaiye", r"padh ?(?:ke|kar)", "likhwao",
      "heli", "helu", "kodi", "kalisi", "sollunga", "sollungal", "sollu", "kodunga", "anuppunga",
      "cheppandi", "cheppu", "ivvandi", "pampandi", "sanga", "saanga", "pathva", "bolun", "pathan",
      "kaho", "janavo", "moklo", "parayu", "parayoo", "tharu", "dasso"),
    "बताओ", "बताइए", "बताइये", "बताएं", "बताये", "बतायें", r"बता\s*(?:दो|दीजिए|दें|देना)", "बोलो", "बोलिए",
    r"बोल\s*(?:दीजिए|दो)", r"दे\s*(?:दो|दीजिए)", "दीजिए", "भेजो", "भेजिए", r"भेज\s*(?:दो|दीजिए)",
    r"शेयर\s*कर", r"पढ़\s*(?:कर|के)", "सुनाइए", "सुनाओ", "लिखवाइए",
    IS + "सांगा", IS + "द्या", "पाठवा", r"शेअर\s*करा", "वाचून",
    r"ಹೇಳಿ(?:ರಿ)?" + IE, r"ಹೇಳು" + IE, r"ಕೊಡಿ" + IE, r"ಕೊಡು" + IE, r"ಕಳುಹಿಸಿ" + IE, r"ಕಳಿಸಿ" + IE,
    r"ಶೇರ್\s*ಮಾಡಿ", r"ಓದಿ" + IE, r"ತಿಳಿಸಿ" + IE,
    "சொல்லுங்க", "சொல்லவும்", r"சொல்லு" + IE, "கொடுங்க", "கொடுக்கவும்", "அனுப்புங்க", "அனுப்பவும்",
    r"ஷேர்\s*(?:செய்|பண்ணு)", "பகிருங்க", "படிங்க", r"படித்துச்\s*சொல்ல", "தெரிவியுங்க",
    "చెప్పండి", r"చెప్పు" + IE, "ఇవ్వండి", "పంపండి", "పంపించండి", r"షేర్\s*చేయండి", "చదవండి", "తెలపండి",
    "বলুন", r"বলো" + IE, r"বলে\s*দিন", r"দিয়ে\s*দিন", "পাঠান", r"শেয়ার\s*করুন", r"পড়ে\s*শোনান", "জানান",
    "કહો", "જણાવો", IS + "આપો", "મોકલો", r"શેર\s*કરો", r"વાંચી\s*સંભળાવો",
    "പറയൂ", "പറയണം", "പറയുക", "തരൂ", "തരണം", "അയക്കൂ", "അയക്കണം", r"ഷെയർ\s*ചെയ്യ", r"വായിച്ചു\s*തര",
    "ਦੱਸੋ", r"ਦੱਸ\s*ਦਿਓ", IS + "ਦਿਓ", "ਭੇਜੋ", r"ਸ਼ੇਅਰ\s*ਕਰੋ", r"ਪੜ੍ਹ\s*ਕੇ\s*ਸੁਣਾਓ")

UPDATE_T = A(L("update", "updated", "expire", "expired", "expiring", "pending", "incomplete", "not linked",
               "verify", "verification", "suspend", "suspended", "band"),
             "अपडेट", "एक्सपायर", "ಅಪ್ಡೇಟ್", "அப்டேட்", "అప్డేట్", "আপডেট", "અપડેટ", "അപ്ഡേറ്റ്", "ਅਪਡੇਟ")
KYC_T = A(L("kyc", "e-kyc", "ekyc"), "केवाईसी", "केवायसी", "ಕೆವೈಸಿ", "கேஒய்சி", r"கே\.ஒய்\.சி", "కేవైసీ",
          "কেওয়াইসি", "કેવાયસી", "കെവൈസി", "ਕੇਵਾਈਸੀ")

# Negation / safety-advice cues, checked inside the clause of a match.
_NEG = _c(A(
    L("never", "not", "no one", "nobody", "don'?t", "dont", "do not", "doesn'?t", "does not", "won'?t",
      "will not", "nahi", "nahin", "nhi", "mat", "kabhi bhi", "kabhi",
      r"na\s+(?:batao|bataye|bataiye|bataen|batana|dein|de|dijiye|karein|karo|kare|share|bhejo|bhejna)"),
    "नहीं", "नही", IS + "मत" + IE, IS + r"न\s+(?:बता|दें|दे|दीजिए|करें|कीजिए|शेयर|भेज|बोल)", "कभी", IS + "नका",
    "नाही", "कधीही", "कधीच",
    "ಬೇಡ", "ಇಲ್ಲ", "ಎಂದಿಗೂ", "ಯಾವತ್ತೂ",
    "வேண்டாம்", "ஒருபோதும்", "மாட்டா", "இல்லை", "தில்லை", "ாதீர்", "ாதீங்க", "கேட்காது",
    "వద్దు", "ఎప్పుడూ", "కండి", "లేదు", "అడగరు", "అడగదు", "ొద్దు",
    IS + "না" + IE, "নয়", "কখনও", "কখনো", "নেই",
    "નહીં", "નહિ", IS + "ના" + IE, "ક્યારેય", "નથી",
    "അരുത്", "ഒരിക്കലും", "ില്ല", "ഇല്ല", "വേണ്ട", "േണ്ട",
    IS + "ਨਾ" + IE, "ਨਹੀਂ", "ਕਦੇ"))
# Conditionals ("if you don't pay...") turn a negation into a threat, so they cancel it.
_COND = _c(A(
    L("if", "unless", "otherwise", "or else", "agar", "warna", "varna", r"nahi\s*(?:to|toh)", r"nahin\s*(?:to|toh)"),
    "अगर", "वरना", r"नहीं\s*तो", "नाहीतर", r"नाही\s*तर", IS + "जर" + IE,
    "ದಿದ್ದರೆ", "ಇಲ್ಲವಾದರೆ", "என்றால்", "இல்லையென்றால்", "இல்லைனா", "ாவிட்டால்", "లేకపోతే", "లేకుంటే",
    "নাহলে", r"না\s*হলে", "নইলে", "যদি", "નહીંતર", r"નહિ\s*તો", r"નહીં\s*તો", IS + "જો" + IE,
    "െങ്കിൽ", r"ਨਹੀਂ\s*ਤਾਂ", IS + "ਜੇ" + IE, "ਜੇਕਰ"))
# Reassurance that is not negation ("don't worry", "घबराइए मत").
_NEG_EXCEPT = _c(A(
    L(r"don'?t worry", "do not worry", "no problem", "no tension", "not to worry", r"no need to (?:worry|panic)",
      r"(?:chinta|tension|fikar|fikr)\s*(?:mat|na|nahi)", r"ghabra(?:o|iye|ye|na)?\s*(?:mat|nahi)"),
    r"(?:चिंता|टेंशन|फिक्र)\s*(?:मत|न|ना|नहीं)", r"घबरा\S*\s*(?:मत|नहीं)", r"ಚಿಂತೆ\s*ಮಾಡಬೇಡಿ", "ಹೆದರಬೇಡಿ",
    r"கவலைப்படா\S*", r"கவலை\s*வேண்டாம்", r"பயப்பட\S*", "భయపడకండి", "చింతించకండి", "భయపడొద్దు",
    r"काळजी\s*करू\s*नका", r"घाबरू\s*नका", r"চিন্তা\s*করবেন\s*না", r"ভয়\s*পাবেন\s*না", r"ચિંતા\s*ન\s*કરો",
    r"ગભરાશો\s*નહીં", "പേടിക്കേണ്ട", "വിഷമിക്കേണ്ട", r"ਚਿੰਤਾ\s*ਨਾ\s*ਕਰੋ", r"ਘਬਰਾਓ\s*ਨਾ"))
# Explicit denial of an arrest threat ("there is no such thing as digital arrest").
_STRICT_NEG = _c(A(
    L("no such thing", r"does(?: not|n't) exist", r"is (?:a )?fake", "is not real", "never arrest",
      r"(?:can ?not|can't) arrest", r"(?:nahi|nahin) hota", "kuch nahi hota"),
    r"नहीं\s*होता", r"नहीं\s*करती", r"नहीं\s*करते", r"कुछ\s*नहीं", "ಇಲ್ಲ", "இல்லை", "மாட்டா", "లేదు", "చేయరు",
    "नसतं", "नसते", r"करत\s*नाहीत", "নেই", r"হয়\s*না", r"করে\s*না", "નથી", "ില്ല", r"ਨਹੀਂ\s*ਹੁੰਦੀ", r"ਨਹੀਂ\s*ਕਰਦੀ"))
_SENSITIVE = _c(A(OTP_T, SECRET_T))
_DELIVERY = _c(A(L("delivery", "deliver", "delivered", "swiggy", "zomato", "zepto", "blinkit", "instamart",
                   "amazon", "flipkart", "myntra", "meesho", "dunzo", "uber", "ola", "rapido"),
                 "डिलीवरी", "डिलिवरी", "ಡೆಲಿವರಿ", "டெலிவரி", "డెలివరీ", "ডেলিভারি", "ડિલિવરી", "ഡെലിവറി", "ਡਿਲੀਵਰੀ"))

_CLAUSE = re.compile(_norm(r"[.!?।॥,;:\n]|\s(?:but|lekin|magar|लेकिन|मगर|ಆದರೆ|ஆனால்|కానీ|কিন্তু|പക്ഷേ)\s"),
                     re.IGNORECASE)
_SENTENCE = re.compile(r"[.!?।॥\n]")

# ---------------------------------------------------------------- rules: otp_request

_PAIRS = [
    _Pair("otp_request", 45, _c(OTP_T), _c(REQ_V)),
    _Pair("otp_request", 40, _c(SECRET_T), _c(REQ_V), window=60),
]
_r("otp_request", 40, L(r"(?:upi|atm) pin" + G(20) + r"(?:daalo|dalo|daaliye|enter|type|daal do)"),
   r"(?:upi|यूपीआई)\s*(?:pin|पिन)" + G(20) + r"(?:डालिए|डालो|डालें|डाल\s*दीजिए|enter|एंटर)", neg="neg")
_r("otp_request", 35, L(r"(?:only|just) (?:tell|give|share)(?: it)? (?:to )?me", r"sirf (?:mujhe|mujhko) (?:batao|bataiye|bolo)"),
   r"(?:सिर्फ|केवल)\s*(?:मुझे|मुझको)\s*(?:बताइए|बताओ|बताएं|बोलिए)")

# ---------------------------------------------------------------- rules: impersonation

AUTH_EN = (r"police|cyber ?(?:crime|cell|police)|crime branch|cbi|ncb|narcotics(?: control bureau| department)?|"
           r"enforcement directorate|ed office|income ?tax(?: department)?|trai|telecom regulatory|rbi|"
           r"reserve bank(?: of india)?|customs(?: department| office)?|interpol|police station")
SERV_EN = (r"bank|sbi|hdfc|icici|axis|kotak|pnb|bank of baroda|canara|paytm|phonepe|google pay|gpay|"
           r"electricity (?:board|department|office)|power (?:company|department)|bescom|msedcl|tata power|"
           r"kseb|tneb|telecom|jio|airtel|vodafone|bsnl|courier|fedex|dhl|blue ?dart|amazon|flipkart|"
           r"kyc (?:department|team|cell)|customer care|head office|lic|insurance")
_FROM_EN = r"(?:calling|speaking|call(?:ing)? you|i am|i'm|we are|this is \w+)(?: \w+){0,2}? from(?: the| your)?(?: \w+){0,2}? "
_SE_HL = r"(?: \w+){0,2}? (?:se|ki taraf se|ki or se)(?: \w+){0,3}? (?:bol|baat|call|phone)"

_r("impersonation", 30, L(_FROM_EN + "(?:" + AUTH_EN + ")"),
   L("(?:" + AUTH_EN + r"|thane|thana|delhi police|mumbai police)" + _SE_HL))
_r("impersonation", 15, L(_FROM_EN + "(?:" + SERV_EN + ")"),
   L(r"(?:" + SERV_EN + r"|bijli vibhag|bijli vibhaag|bijli office)" + _SE_HL), soft=True)
_r("impersonation", 25, L(r"(?:i am|i'm|this is|myself|main|mai|mera naam)(?: \w+){0,3}? "
                          r"(?:inspector|sub[- ]inspector|constable|officer|dsp|acp|sho|commissioner|investigating officer)"))
_r("impersonation", 18, L(r"cyber ?(?:crime|cell|police)", "crime branch", "cbi", "ncb", "narcotics", "interpol",
                          "enforcement directorate", r"ed (?:officer|department|office)", r"income ?tax department",
                          "trai", "rbi", "reserve bank", "customs"))
_r("impersonation", 10, L("police", "inspector", "officer", "thana", "thane", "court"))

# Devanagari (Hindi + Marathi): "<org> से ... बोल रहा हूँ" / "<org>तून बोलतोय"
AUTH_HI = (r"पुलिस|पोलीस|साइबर\s*(?:क्राइम|सेल|पुलिस)|सायबर|क्राइम\s*ब्रांच|सीबीआई|सीबीआय|एनसीबी|नारकोटिक्स|ईडी|"
           r"प्रवर्तन\s*निदेशालय|इनकम\s*टैक्स|आयकर|ट्राई|आरबीआई|आरबीआय|रिजर्व\s*बैंक|कस्टम्स?|थाने|थाना|कोर्ट|"
           r"(?<![a-z])(?:cbi|rbi|customs|police|cyber cell|cyber crime|crime branch|trai|ncb)(?![a-z])")
SERV_HI = (r"बैंक|बँक|बिजली\s*(?:विभाग|दफ्तर|ऑफिस|कंपनी)|विद्युत\s*विभाग|कूरियर|कुरियर|टेलीकॉम|कस्टमर\s*केयर|"
           r"केवाईसी\s*विभाग|महावितरण|वीज\s*(?:मंडळ|वितरण|कंपनी)|(?<![a-z])(?:" + SERV_EN + r")(?![a-z])")
_FROM_HI = r"(?:\sसे|\sकी\s*तरफ\s*से|\sकी\s*ओर\s*से|तून|मधून|कडून|हून)" + IE + r"[^.!?।\n]{0,40}?(?:बोल|बात\s*कर|कॉल|call|फोन\s*कर)"
_r("impersonation", 30, "(?:" + AUTH_HI + ")" + G(25) + _FROM_HI)
_r("impersonation", 15, "(?:" + SERV_HI + ")" + G(25) + _FROM_HI, soft=True)
_r("impersonation", 25, IS + r"(?:मैं|मै)\s" + G(30) + r"(?:इंस्पेक्टर|ऑफिसर|अधिकारी|हवलदार|कांस्टेबल|दरोगा|inspector|officer)")
_r("impersonation", 18, r"साइबर\s*(?:क्राइम|सेल|पुलिस)", "सायबर", r"क्राइम\s*ब्रांच", "सीबीआई", "सीबीआय", "एनसीबी",
   "नारकोटिक्स", r"प्रवर्तन\s*निदेशालय", r"इनकम\s*टैक्स\s*विभाग", "आयकर विभाग", "आरबीआई", "आरबीआय",
   r"रिजर्व\s*बैंक", "कस्टम्स", IS + "कस्टम" + IE, IS + "ईडी" + IE)
_r("impersonation", 10, "पुलिस", "पोलीस", "इंस्पेक्टर", "थाने", "थाना", "कोर्ट")

# Other scripts: (from-suffix, authority words, police words, service words)
_IMP_LANGS = [
    ("(?:ಿಂದ|ನಿಂದ|ಇಂದ)", r"ಸೈಬರ್\s*ಕ್ರೈ|ಸಿಬಿಐ|ಕಸ್ಟಮ್ಸ|ಆರ್ಬಿಐ|ಆದಾಯ\s*ತೆರಿಗೆ|ನಾರ್ಕೋಟಿಕ್ಸ", r"ಪೊಲೀಸ|ಠಾಣೆ",
     r"ಬ್ಯಾಂಕ|ವಿದ್ಯುತ್\s*ಇಲಾಖೆ|ಇಲಾಖೆ|ಬೆಸ್ಕಾಂ|ಹೆಸ್ಕಾಂ|ಕೊರಿಯರ|ಕಸ್ಟಮರ್\s*ಕೇರ"),
    ("(?:இருந்து|ிருந்து)", r"சைபர்\s*(?:க்ரைம|கிரைம)|சிபிஐ|கஸ்டம்ஸ|சுங்க|ஆர்பிஐ|வருமான\s*வரி",
     r"போலீஸ|காவல்\s*துறை|காவல்துறை|காவல்\s*நிலைய", r"வங்கி|பேங்க|மின்சார\s*வாரிய|மின்\s*வாரிய|மின்வாரிய|கூரியர|கொரியர|டெலிகாம"),
    ("(?:నుండి|నుంచి)", r"సైబర్\s*క్రైమ|సీబీఐ|కస్టమ్స|ఆర్బీఐ|ఆదాయపు\s*పన్ను", r"పోలీస|పోలీసు",
     r"బ్యాంక|విద్యుత్\s*శాఖ|కరెంట్\s*ఆఫీస|విద్యుత్|కొరియర"),
    (r"\s*থেকে", r"সাইবার\s*ক্রাইম|সিবিআই|কাস্টমস|আরবিআই|আয়কর", r"পুলিশ|থানা",
     r"ব্যাংক|ব্যাঙ্ক|বিদ্যুৎ|ইলেকট্রিক|কুরিয়ার"),
    ("(?:માંથી|તરફથી|થી)", r"સાયબર\s*ક્રાઇમ|સીબીઆઈ|કસ્ટમ્સ|આરબીઆઈ|ઇન્કમ\s*ટેક્સ", r"પોલીસ",
     r"બેંક|વીજ|ઇલેક્ટ્રિસિટી|કુરિયર"),
    (r"\s*(?:നിന്ന്|നിന്നും|നിന്നാണ്)", r"സൈബർ\s*(?:ക്രൈം|സെൽ)|സിബിഐ|കസ്റ്റംസ|ആർബിഐ|ആദായ\s*നികുതി", r"പോലീസ",
     r"ബാങ്ക|കെഎസ്ഇബി|വൈദ്യുതി|ഇലക്ട്രിസിറ്റി|കൊറിയർ"),
    (r"\s*(?:ਤੋਂ|ਵੱਲੋਂ)", r"ਸਾਈਬਰ\s*ਕ੍ਰਾਈਮ|ਸੀਬੀਆਈ|ਕਸਟਮ|ਆਰਬੀਆਈ", r"ਪੁਲਿਸ|ਪੁਲੀਸ|ਥਾਣ", r"ਬੈਂਕ|ਬਿਜਲੀ|ਪਾਵਰਕਾਮ|ਕੋਰੀਅਰ"),
]
for _from, _auth, _pol, _serv in _IMP_LANGS:
    _r("impersonation", 28, f"(?:{_auth}|{_pol})" + r"[^.!?।,\n]{0,25}?" + _from)
    _r("impersonation", 15, f"(?:{_serv})" + r"[^.!?।,\n]{0,25}?" + _from, soft=True)
    _r("impersonation", 18, _auth)
    _r("impersonation", 10, _pol)

# ---------------------------------------------------------------- rules: digital_arrest

_r("digital_arrest", 45, L("digital arrest", "digitally arrested", "online arrest", "virtual arrest"),
   r"डिजिटल\s*(?:अरेस्ट|गिरफ्तारी)", r"ಡಿಜಿಟಲ್\s*ಅರೆಸ್ಟ್", r"டிஜிட்டல்\s*அரெஸ்ட்", r"డిజిటల్\s*అరెస్ట్",
   r"ডিজিটাল\s*(?:অ্যারেস্ট|গ্রেফতার)", r"ડિજિટલ\s*અરેસ્ટ", r"ഡിജിറ്റൽ\s*അറസ്റ്റ്", r"ਡਿਜੀਟਲ\s*ਅਰੈਸਟ", neg="strict")
_r("digital_arrest", 35, L("arrest warrant", "warrant", "non[- ]bailable"), "वारंट", "ವಾರಂಟ್", "வாரண்ட்", "வாரன்ட்",
   "వారెంట్", "ওয়ারেন্ট", "વોરંટ", "വാറണ്ട്", "വാറന്റ്", "ਵਾਰੰਟ", neg="strict")
_r("digital_arrest", 30, L(r"(?:your name|aapke naam|apke naam|aapke nam|against you|aapke khilaf|aap par|aap pe)"
                           r"(?: \w+){0,4}? (?:case|fir|complaint|warrant|parcel|sim|account|money laundering)"),
   r"(?:आपके\s*(?:नाम|खिलाफ)|आप\s*पर)" + G(30) + r"(?:केस|एफआईआर|मामला|शिकायत|वारंट|पार्सल|सिम|case|fir|warrant|parcel)",
   L("money laundering", "hawala"), "मनी लॉन्ड्रिंग", "मनी लांड्रिंग", "हवाला", "ಮನಿ ಲಾಂಡರಿಂಗ್", "மணி லாண்டரிங்",
   "మనీ లాండరింగ్", "মানি লন্ডারিং", "મની લોન્ડરિંગ", "മണി ലോണ്ടറിങ്", "ਮਨੀ ਲਾਂਡਰਿੰਗ",
   L(r"(?:video call|camera)(?: \w+){0,4}? (?:rahiye|rahna|on rakh\w*|band mat|mat kaat\w*|mat hat\w*|stay|keep)",
     r"stay on (?:the )?video"),
   r"(?:वीडियो\s*कॉल|कैमरा|video call|camera)" + G(25) + r"(?:रहिए|रहना|ऑन\s*रख|मत\s*हट|मत\s*काट|बंद\s*मत)", neg="strict")
_r("digital_arrest", 25, L(r"(?:you will|you'll|will) be arrested", r"arrest (?:kar|ho) (?:liya|lenge|jaoge|jayenge|jaenge|sakte)"),
   r"गिरफ्तार\s*(?:कर|हो)\s*(?:लिया|लेंगे|जाएंगे|जाओगे|सकते)", "गिरफ्तारी", r"अटक\s*(?:होईल|करू|करण्यात)",
   "ಬಂಧಿಸ", "ಬಂಧನ", "ಅರೆಸ್ಟ", "கைது", "அரெஸ்ட", "అరెస్ట", "অ্যারেস্ট", "গ্রেফতার", "গ্রেপ্তার", "ધરપકડ", "અરેસ્ટ",
   "അറസ്റ്റ", "ਗ੍ਰਿਫ਼ਤਾਰ", "ਅਰੈਸਟ",
   L("drugs", "narcotics", "mdma", "contraband"), "ड्रग्स", "ड्रग", "नशीले", "ಡ್ರಗ್ಸ", "டிரக்ஸ", "போதைப்பொருள",
   "డ్రగ్స", "మాదకద్రవ్య", "ড্রাগস", "মাদক", "ડ્રગ્સ", "ഡ്രഗ്സ", "മയക്കുമരുന്ന", "ਡਰੱਗ", "ਨਸ਼ੀਲ",
   r"(?:aadhaa?r|adhaar|आधार|ಆಧಾರ|ஆதார|ఆధార|আধার|આધાર|ആധാർ|ਆਧਾਰ)" + G(30)
   + r"(?:misuse|parcel|sim|case|illegal|book|गलत|इस्तेमाल|बुक|पार्सल|सिम|ಪಾರ್ಸೆಲ|பார்சல|పార్సిల|పార్సెల|পার্সেল|પાર્સલ|പാർസൽ|ਪਾਰਸਲ)",
   neg="strict")
_r("digital_arrest", 20, L(r"(?:fir|case) (?:darj|registered|filed|lodged)", "legal notice", "court notice"),
   r"(?:एफआईआर|केस|मामला)\s*दर्ज", neg="neg")
_r("digital_arrest", 15, L("arrest", "arrested"), neg="strict")
_r("digital_arrest", 10, L("fir", "illegal"), "एफआईआर", "गैरकानूनी")
_r("digital_arrest", 8, L("parcel", "courier"), "पार्सल", "कूरियर", "ಪಾರ್ಸೆಲ", "பார்சல", "పార్సిల", "పార్సెల",
   "পার্সেল", "પાર્સલ", "പാർസൽ", "ਪਾਰਸਲ")

# ---------------------------------------------------------------- rules: account_threat

_THREAT_EN = r"(?:blocked|suspended|frozen|closed|deactivated|disabled|terminated|cancelled|seized|disconnected|cut)"
_r("account_threat", 30,
   L(r"(?:account|card|upi|net ?banking|sim|number|connection|electricity|power|gas connection)(?: \w+){0,4}? "
     r"(?:will|would|is going to|has been|have been|gets|get|will get|shall)(?: be| get)? (?:permanently |temporarily )?" + _THREAT_EN,
     r"(?:block|suspend|freeze|close|deactivate|seize|disconnect|cut) your (?:account|card|sim|number|connection|electricity|power)",
     r"(?:account|khata|card|sim|number)(?: \w+){0,3}? (?:band|block|freeze|suspend|seal|deactivate)"
     r"(?: \w+)? (?:ho jayega|ho jaega|ho jayegi|ho jaegi|kar diya jayega|kar diya jaega|kar denge|hoga|hogi|ho sakta)",
     r"(?:electricity|bijli|light|power|current)(?: connection| supply| line)?(?: \w+){0,4}? "
     r"(?:will be (?:cut|disconnected|stopped)|(?:kat|kaat|cut|disconnect|band)(?: kar)?(?: di| diya| de)? ?"
     r"(?:jayegi|jaayegi|jayega|jaega|jaegi|denge|hoga|hogi))"),
   r"(?:खाता|खाते|खातं|अकाउंट|एकाउंट|अकॉउंट|account|सिम|कार्ड)" + G(25)
   + r"(?:बंद|ब्लॉक|block|फ्रीज|freeze|सस्पेंड|suspend|सील)\s*(?:हो|कर|किया)",
   r"(?:बिजली|लाइट|कनेक्शन|connection|वीज)" + G(30) + r"(?:कट|काट|बंद|डिस्कनेक्ट|disconnect)\s*(?:कर\s*)?(?:दी|दिया|दे)?\s*"
   r"(?:जाएगी|जायेगी|जाएगा|जायेगा|देंगे|होगा|होगी|जाईल|होईल)",
   r"(?:ಖಾತೆ|ಅಕೌಂಟ್|account)" + G(25) + r"(?:ಬ್ಲಾಕ್|ಬಂದ್|ಸ್ಥಗಿತ|ಫ್ರೀಜ್|block)",
   r"ಸಂಪರ್ಕ\s*ಕಡಿತ", r"ಕರೆಂಟ್\s*ಕಟ್", r"ವಿದ್ಯುತ್\s*ಕಡಿತ", r"ಪವರ್\s*ಕಟ್",
   r"(?:கணக்கு|அக்கவுண்ட்|account)" + G(25) + r"(?:முடக்க|ப்ளாக்|பிளாக்|block|நிறுத்த|மூட)",
   r"மின்\s*இணைப்பு" + G(15) + "துண்டி", r"கரண்ட்\s*கட்", r"மின்சாரம்\s*துண்டி", r"பவர்\s*கட்",
   r"(?:ఖాతా|అకౌంట్|account)" + G(25) + r"(?:బ్లాక్|నిలిపి|ఫ్రీజ్|మూసి|block|క్లోజ్)",
   r"కరెంట్\s*(?:కనెక్షన్\s*)?కట్", r"విద్యుత్\s*(?:కనెక్షన్\s*)?(?:కట్|నిలిపి)", r"పవర్\s*కట్",
   r"(?:অ্যাকাউন্ট|একাউন্ট|account)" + G(25) + r"(?:ব্লক|বন্ধ|ফ্রিজ|block)",
   "বিদ্যুৎ" + G(20) + r"(?:বিচ্ছিন্ন|কেটে|বন্ধ)", r"লাইন\s*কেটে\s*দেওয়া",
   r"(?:ખાતું|ખાતા|એકાઉન્ટ|account)" + G(25) + r"(?:બ્લોક|બંધ|block)",
   r"(?:વીજળી|લાઇટ|વીજ)" + G(20) + r"(?:કપાઈ|કાપી|બંધ)",
   r"(?:അക്ക\S{0,2}ണ്ട്|account)" + G(25) + r"(?:ബ്ലോക്ക്|മരവിപ്പി|block|ക്ലോസ്)",
   r"(?:കറന്റ്|വൈദ്യുതി)" + G(25) + r"(?:കട്ട്|വിച്ഛേദി)",
   r"(?:ਖਾਤਾ|ਖਾਤੇ|ਅਕਾਊਂਟ|account)" + G(25) + r"(?:ਬੰਦ|ਬਲੌਕ|ਬਲਾਕ|block)", "ਬਿਜਲੀ" + G(20) + r"(?:ਕੱਟ|ਬੰਦ)", neg="neg")
_r("account_threat", 25, KYC_T + G(25) + UPDATE_T, UPDATE_T + G(15) + KYC_T,
   L(r"(?:pan|aadhaa?r)(?: card)? (?:is )?(?:not linked|blocked|expired|suspended)"),
   L("legal action", r"penalty (?:will|of)", "heavy fine"))
_r("account_threat", 15, r"ಬಿಲ್\s*ಬಾಕಿ", L(r"(?:bill|dues?) (?:is )?(?:pending|overdue|unpaid)", r"bill (?:baaki|bakaya)"),
   r"बिल\s*(?:बाकी|बकाया)", r"பில்\s*(?:பாக்கி|நிலுவை)", r"బిల్లు\s*బాకీ", r"বিল\s*বাকি", r"બિલ\s*બાકી")
_r("account_threat", 10, KYC_T)

# ---------------------------------------------------------------- rules: payment_request

_r("payment_request", 40, L("safe account", "secure account", "safety account", "rbi account", "government account",
                            r"verification account", "escrow account"),
   r"सेफ\s*अकाउंट", r"सुरक्षित\s*खात", r"सरकारी\s*खात", r"ಸುರಕ್ಷಿತ\s*ಖಾತೆ", r"பாதுகாப்பான\s*கணக்கு",
   r"సురక్షిత\s*ఖాతా", r"(?:সুরক্ষিত|সেফ)\s*অ্যাকাউন্ট", r"સુરક્ષિત\s*ખાતા", r"സുരക്ഷിത\s*അക്ക", r"ਸੁਰੱਖਿਅਤ\s*ਖਾਤ",
   neg="neg")
_r("payment_request", 35,
   L(r"(?:processing|registration|clearance|verification|activation|joining|release) (?:fee|fees|charge|charges)",
     r"security deposit", r"refundable deposit", r"advance (?:fee|payment)", r"token amount",
     r"tax (?:on|for) (?:the |your )?(?:prize|lottery|reward)", r"customs (?:duty|charges?|fee)", r"gst charges?"),
   r"(?:रजिस्ट्रेशन|प्रोसेसिंग|रजिस्ट्रेशन)\s*(?:फीस|चार्ज)", r"पंजीकरण\s*शुल्क", r"ನೋಂದಣಿ\s*ಶುಲ್ಕ",
   r"பதிவுக்?\s*கட்டண", "முன்பணம்", r"రిజిస్ట్రేషన్\s*ఫీజు", r"রেজিস্ট্রেশন\s*ফি", r"(?:રજીસ્ટ્રેશન|નોંધણી)\s*ફી",
   r"രജിസ്ട്രേഷൻ\s*ഫീസ്", r"ਰਜਿਸਟ੍ਰੇਸ਼ਨ\s*ਫੀਸ", neg="neg")
_r("payment_request", 30,
   L(r"(?:transfer|send|pay|deposit|wire)(?: me)?(?: the| a| your| this| an| all| some| only| just)?(?: \w+){0,2}? "
     r"(?:money|amount|funds|payment|fee|fees|fine|charges?|penalty|deposit|rs\.?|rupees|inr|\d[\d,]*)",
     r"make (?:a|the) payment", r"pay (?:now|immediately|it now|right now)", r"scan (?:this|the) qr", r"qr code (?:scan|bhej\w*)",
     r"scan (?:karo|kijiye|kariye)", r"gift cards?", r"google play (?:card|voucher)",
     r"upi(?: id)? (?:se|par|pe|via|through|on)(?: \w+){0,3}? (?:bhejo|bhejiye|pay|send|transfer|kar do|kijiye)",
     r"(?:paise|paisa|paisey|rupaye|rupees|rupay|amount|fees?|payment|rakam)(?: \w+){0,3}? "
     r"(?:bhejo|bhejiye|bhej do|bhej dijiye|bhejna hoga|bhejne honge|bhejne padenge|transfer karo|transfer kijiye|"
     r"transfer kariye|transfer kar do|transfer kar dijiye|transfer karna hoga|transfer karna padega|jama karo|"
     r"jama kijiye|jama karna hoga|daalo|dalo|bharo|bhariye|bharna hoga|dena hoga|deni hogi|dene honge|pay karo|pay kijiye)",
     r"(?:transfer|payment) (?:karo|kijiye|kariye|kar do|kar dijiye|karna hoga|karna padega|karein|karen)"),
   r"(?:ट्रांसफर|transfer|पेमेंट|payment|भुगतान|जमा)\s*(?:करो|करें|कीजिए|करिए|कर\s*दो|कर\s*दें|कर\s*दीजिए|"
   r"करना\s*होगा|करना\s*पड़ेगा|करना\s*है|कराना\s*होगा)",
   r"(?:पैसे|पैसा|रुपये|रुपए|रकम|अमाउंट|amount|फीस|शुल्क)\S*\s*(?:\S+\s*){0,3}?(?:भेजो|भेजें|भेजिए|भेज\s*दो|"
   r"भेज\s*दीजिए|भेजने\s*होंगे|भेजना\s*होगा|जमा\s*कर|भरो|भरें|भरिए|भरना\s*होगा|देने\s*होंगे|देनी\s*होगी|देना\s*होगा)",
   r"(?:पैसे|रक्कम|फी|शुल्क)\s*(?:\S+\s*){0,2}?(?:पाठवा|भरा|जमा\s*करा)" + IE,
   r"(?:ट्रान्सफर|पेमेंट)\s*करा" + IE,
   r"(?:ಹಣ|ರೂಪಾಯಿ|ದುಡ್ಡು|ಶುಲ್ಕ|ಮೊತ್ತ)\S*\s*(?:\S+\s*){0,2}?(?:ಕಳುಹಿಸಿ|ಕಳಿಸಿ|ವರ್ಗಾಯಿಸಿ|ಕಟ್ಟಿ|ಪಾವತಿಸಿ|ಹಾಕಿ)" + IE,
   r"(?:ಪಾವತಿ|ಪೇಮೆಂಟ್|ಟ್ರಾನ್ಸ್ಫರ್)\s*ಮಾಡಿ" + IE, "ಪಾವತಿಸಿ" + IE,
   r"(?:பணம்|பணத்தை|ரூபாய்|கட்டணம்|தொகை|யுபிஐ|ஜிபே|போன்பே)\S*\s*(?:\S+\s*){0,3}?"
   r"(?:அனுப்பு(?:ங்க|வும்)|செலுத்து(?:ங்க|வும்)|கட்டு(?:ங்க|வும்)|டிரான்ஸ்ஃபர்\s*(?:செய்|பண்ணு))",
   r"(?:డబ్బు|డబ్బులు|రూపాయలు|ఫీజు|మొత్తం|యూపీఐ)\S*\s*(?:\S+\s*){0,3}?(?:పంపండి|పంపించండి|కట్టండి|చెల్లించండి|వేయండి)",
   "చెల్లించండి", r"(?:ట్రాన్స్ఫర్|పేమెంట్)\s*చేయండి",
   r"(?:টাকা|রুপি|ফি|ইউপিআই)\S*\s*(?:\S+\s*){0,3}?(?:পাঠান|পাঠিয়ে\s*দিন|দিন|জমা\s*দিন|ট্রান্সফার\s*করুন)",
   r"(?:ট্রান্সফার|পেমেন্ট)\s*করুন",
   r"(?:પૈસા|રૂપિયા|ફી|રકમ|યુપીઆઈ)\S*\s*(?:\S+\s*){0,3}?(?:મોકલો|ભરો|આપો|જમા\s*કરો|ટ્રાન્સફર\s*કરો)",
   r"(?:ટ્રાન્સફર|પેમેન્ટ|ચૂકવણી)\s*કરો",
   r"(?:പണം|രൂപ|ഫീസ്|തുക|യുപിഐ)\S*\s*(?:\S+\s*){0,3}?(?:അയക്കൂ|അയയ്ക്കൂ|അയക്കണം|അടയ്ക്കൂ|അടയ്ക്കണം|അടക്കണം|ട്രാൻസ്ഫർ\s*ചെയ്യ)",
   r"(?:ട്രാൻസ്ഫർ|പേയ്മെന്റ്)\s*ചെയ്യ(?:ൂ|ണം)",
   r"(?:ਪੈਸੇ|ਪੈਸਾ|ਰੁਪਏ|ਫੀਸ|ਰਕਮ|ਯੂਪੀਆਈ)\S*\s*(?:\S+\s*){0,3}?(?:ਭੇਜੋ|ਭਰੋ|ਜਮ੍ਹਾਂ\s*ਕਰੋ|ਟ੍ਰਾਂਸਫਰ\s*ਕਰੋ)",
   r"(?:ਟ੍ਰਾਂਸਫਰ|ਪੇਮੈਂਟ)\s*ਕਰੋ", neg="neg")
_r("payment_request", 15, L(r"(?:will be|get) refunded", r"(?:wapas|vapas) mil (?:jayega|jaega|jayenge)",
                            r"refund (?:ho jayega|mil jayega|aa jayega)"),
   r"वापस\s*मिल\s*जाएग", r"रिफंड\s*(?:हो|मिल|आ)\s*जाएग", neg="neg")

# ---------------------------------------------------------------- rules: remote_access

_r("remote_access", 40, L("anydesk", "any desk", "teamviewer", "team viewer", "quicksupport", "quick support",
                          "rustdesk", "airdroid", "ammyy", "ultraviewer", "alpemix"),
   "एनीडेस्क", r"एनी\s*डेस्क", r"टीम\s*व्यूअर", r"ಎನಿ\s*ಡೆಸ್ಕ", r"ಟೀಮ್\s*ವ್ಯೂವರ", "ஏனிடெஸ்க", "எனிடெஸ்க",
   r"டீம்\s*வியூவர", "ఎనీడెస్క", "ఎనిడెస్క", r"టీమ్\s*వ్యూయర", "অ্যানিডেস্ক", "এনিডেস্ক", "টিমভিউয়ার",
   "એનીડેસ્ક", "એનિડેસ્ક", "ટીમવ્યૂઅર", "എനിഡെസ്ക", "ടീംവ്യൂവർ", "ਐਨੀਡੈਸਕ", "ਟੀਮਵਿਊਅਰ", neg="neg")
_r("remote_access", 35, L(r"screen ?shar(?:e|ing)", r"remote (?:access|control|app|support|desktop)"),
   r"स्क्रीन\s*शेयर", r"ಸ್ಕ್ರೀನ್\s*ಶೇರ", r"ஸ்கிரீன்\s*ஷேர", r"స్క్రీన్\s*షేర", r"স্ক্রিন\s*শেয়ার", r"સ્ક્રીન\s*શેર",
   r"സ്ക്രീൻ\s*ഷെയർ", r"ਸਕ੍ਰੀਨ\s*ਸ਼ੇਅਰ", neg="neg")
_APP = r"(?:app|apk|application|ऐप|एप|ಆಪ|ಆ್ಯಪ|ஆப|ஆப்ப|యాప|অ্যাপ|এপ|એપ|ആപ്പ|ਐਪ)"
_DL = (r"(?:download|install|डाउनलोड|इंस्टॉल|ಡೌನ್ಲೋಡ|ಇನ್ಸ್ಟಾಲ|டவுன்லோட|இன்ஸ்டால|డౌన్లోడ|ఇన్స్టాల|ডাউনলোড|"
       r"ইনস্টল|ડાઉનલોડ|ઇન્સ્ટોલ|ഡൗൺലോഡ|ഇൻസ്റ്റാൾ|ਡਾਊਨਲੋਡ|ਇੰਸਟਾਲ)")
_r("remote_access", 25, L(r"(?:download|install)(?: this| the| an| ek| yeh| ye| our)? ?(?:app|application|apk)",
                          r"apk file", r"\.apk"),
   _APP + G(25) + _DL, _DL + G(15) + _APP, neg="neg")

# ---------------------------------------------------------------- rules: urgency_secrecy

_r("urgency_secrecy", 25,
   L(r"(?:don'?t|do not) (?:cut|disconnect|hang up|end)(?: the)?(?: call| phone| line)?", r"stay on the (?:line|call)",
     r"keep the (?:call|line) (?:on|open)", r"(?:call|phone) (?:mat|na) (?:kaat|kat|kaato|katna|kaatna|kaatiye|kaatein|rakhna|rakhiye|disconnect)\w*",
     r"(?:call|phone) disconnect (?:mat|na)", "disconnect mat"),
   r"(?:कॉल|फोन|call|phone)\s*(?:को\s*)?(?:मत|न)\s*(?:काट|रख|डिस्कनेक्ट|disconnect)",
   r"(?:डिस्कनेक्ट|disconnect)\s*(?:मत|न)\s*(?:कीजिए|करें|करना|करो|करिए)",
   r"(?:ಕಾಲ್|ಕರೆ|ಫೋನ್)\s*(?:ಕಟ್|ಕಡಿತ)\s*ಮಾಡಬೇಡಿ", r"(?:கால்|அழைப்ப|போன)\S*\s*(?:கட்\s*(?:பண்ணா|செய்யா)|துண்டிக்கா|வைக்கா)",
   r"(?:కాల్|ఫోన్)\s*(?:కట్\s*చేయకండి|కట్\s*చేయొద్దు|పెట్టేయకండి)", r"(?:फोन|कॉल)\s*(?:कट|बंद)\s*करू\s*नका",
   r"(?:ফোন|কল)\s*(?:কাটবেন\s*না|কেটে\s*দেবেন\s*না)", r"(?:ફોન|કૉલ)\s*(?:કાપશો\s*નહીં|કટ\s*ન\s*કરો|ન\s*કાપો)",
   r"(?:ഫോൺ|കോൾ)\s*(?:കട്ട്\s*ചെയ്യരുത്|വെക്കരുത്)", r"(?:ਫ਼ੋਨ|ਕਾਲ)\s*ਨਾ\s*ਕੱਟ")
_r("urgency_secrecy", 25,
   L(r"(?:don'?t|do not|never) (?:tell|inform|talk to|discuss (?:this|it) with|share (?:this|it) with) "
     r"(?:anyone|anybody|your family|family|police|bank|relatives|friends|others|any one)",
     r"keep (?:this|it) (?:a )?(?:secret|confidential|between us)", r"tell no one",
     r"(?:kisi|kisiko)(?: ko)?(?: bhi)? (?:mat|na|nahi) (?:batana|bataiye|batao|bataye|batayein|bolna|kehna)",
     r"ghar (?:walon|waalon|wale|par)(?: ko)? (?:mat|na|nahi) (?:batana|bataiye|batao)", "confidential"),
   r"किसी\s*(?:को|से)\s*(?:भी\s*)?(?:मत|न|नहीं)\s*(?:बताइए|बताएं|बताना|बताओ|बोलना|बोलिए|कहना|कहिए)",
   r"(?:घरवालों|परिवार|घर\s*वालों)\s*(?:को|से)\s*(?:भी\s*)?(?:मत|न|नहीं)\s*(?:बता|बोल|कह)", r"गुप्त\s*रख", r"राज\s*रख",
   r"ಯಾರಿಗೂ\s*(?:ಹೇಳಬೇಡಿ|ಹೇಳಬೇಡ|ತಿಳಿಸಬೇಡಿ)", "ಗುಟ್ಟಾಗಿ", "ರಹಸ್ಯವಾಗಿ",
   r"யாரிடமும்\s*(?:சொல்லா|சொல்ல\s*வேண்டாம்|கூறா|பகிரா)", "ரகசியமாக",
   r"ఎవరికీ\s*(?:చెప్పకండి|చెప్పొద్దు|చెప్పవద్దు)", "రహస్యంగా", r"कोणालाही\s*(?:सांगू|कळवू)\s*नका",
   r"কাউকে\s*(?:বলবেন\s*না|বলো\s*না|জানাবেন\s*না)", r"গোপন\s*রাখ", r"કોઈને\s*(?:કહેશો\s*નહીં|કહેતા\s*નહીં|ન\s*કહો|જણાવશો\s*નહીં)",
   r"ગુપ્ત\s*રાખ", r"ആരോടും\s*(?:പറയരുത്|പറയണ്ട|പറയേണ്ട)", "രഹസ്യമായി",
   r"ਕਿਸੇ\s*ਨੂੰ\s*(?:ਵੀ\s*)?ਨਾ\s*ਦੱਸ", r"ਗੁਪਤ\s*ਰੱਖ", advice=True)
_r("urgency_secrecy", 15,
   L(r"right now", "immediately", r"urgent(?:ly)?", r"hurry(?: up)?", "as soon as possible", "asap",
     r"(?:within|in)(?: the next)? (?:\d+|one|two|three|few|24|48) (?:hours?|minutes?|mins?)", "today itself",
     "last chance", r"before (?:tonight|midnight)", "tonight", "turant", "fauran", r"jaldi(?: se| karo| kijiye| kariye)?",
     "abhi ke abhi", "abhi turant", "aaj hi", "sirf aaj", r"aaj raat(?: tak)?", r"(?:\d+|do|teen|ek) ghante (?:mein|me|ke andar)",
     r"\d+ minute (?:mein|me)"),
   "तुरंत", "फौरन", r"जल्दी\s*(?:कीजिए|करें|करो|करिए)", r"अभी\s*के\s*अभी", r"आज\s*ही", r"सिर्फ\s*आज", r"आज\s*रात",
   r"(?:\d+|दो|तीन|एक)\s*घंटे\s*(?:में|के\s*अंदर)", "लगेच", "ताबडतोब", "आजच", r"आज\s*रात्री",
   "ತಕ್ಷಣ", "ಈಗಲೇ", "ಇಂದೇ", r"ಇಂದು\s*ರಾತ್ರಿ", r"ಬೇಗ\s*ಮಾಡಿ", "ಗಂಟೆಯೊಳಗೆ",
   "உடனே", "உடனடியாக", r"இன்று\s*மட்டும்", "இன்றைக்குள்", "சீக்கிரம்", r"இன்று\s*இரவு",
   "వెంటనే", "ఇప్పుడే", r"ఈ\s*రోజే", r"ఈ\s*రోజు\s*మాత్రమే", "త్వరగా", r"ఈ\s*రాత్రి",
   "এখনই", "এক্ষুনি", "তাড়াতাড়ি", "আজই", r"শুধু\s*আজ", r"আজ\s*রাতে",
   "તાત્કાલિક", r"હમણાં\s*જ", IS + "તરત", r"આજે\s*જ", r"આજે\s*રાત્રે", r"જલ્દી\s*કરો",
   "ഉടനെ", IS + "ഉടൻ", r"ഇപ്പോൾ\s*തന്നെ", r"ഇന്ന്\s*മാത്രം", r"ഇന്ന്\s*രാത്രി", "വേഗം",
   "ਤੁਰੰਤ", "ਹੁਣੇ", "ਫ਼ੌਰਨ", r"ਅੱਜ\s*ਹੀ", r"ਸਿਰਫ਼\s*ਅੱਜ", r"ਜਲਦੀ\s*ਕਰੋ")

# ---------------------------------------------------------------- rules: prize_job_offer

_r("prize_job_offer", 35, L(r"(?:like|rate|review)(?: youtube| insta(?:gram)?)? (?:videos?|hotels?|products?|reviews?)",
                            r"youtube videos? like", r"videos? like (?:karo|karke|karne|kijiye)", r"telegram (?:task|group)",
                            r"task[- ]based", "prepaid task"),
   r"(?:वीडियो|यूट्यूब|video|youtube)" + G(15) + r"(?:लाइक|like)", r"लाइक\s*कर(?:के|ने|ो)", r"ಲೈಕ್\s*ಮಾಡಿ",
   r"லைக்\s*(?:செய்|பண்ண)", r"లైక్\s*(?:చేస్తే|చేయండి)", r"লাইক\s*(?:করুন|করলে)", r"લાઇક\s*(?:કરો|કરવા)",
   r"ലൈക്ക്\s*ചെയ്യ", r"ਲਾਈਕ\s*ਕਰੋ", neg="neg")
_r("prize_job_offer", 30, L(r"you(?: have|'ve)? won", "winner of", "lottery", "lucky draw", "jackpot", "prize money",
                            "cash prize", "kbc", "kaun banega crorepati", "bumper prize", "inaam", "inam",
                            r"(?:aap|aapne|tumne|aapko)(?: \w+){0,4}? (?:jeet|jeeta|jeete|jeeti)\w*"),
   "लॉटरी", r"लकी\s*ड्रॉ", "इनाम", "ईनाम", "जैकपॉट", "केबीसी", r"कौन\s*बनेगा\s*करोड़पति",
   r"(?:आप|आपने|आपको)" + G(25) + r"(?:जीत|जीता|जीते)", r"जिंकल(?:ात|ा\s*आहात)",
   "ಲಾಟರಿ", "ಜಾಕ್ಪಾಟ್", "ಗೆದ್ದಿದ್ದೀರ", "லாட்டரி", r"பரிசு\s*விழுந்", r"பரிசுத்\s*தொகை", "ஜாக்பாட்", "வென்றுள்ளீர்கள்",
   "வென்றிருக்கிறீர்கள்", "ஜெயிச்சிருக்கீங்க", "లాటరీ", "జాక్పాట్", "గెలుచుకున్నారు", "గెలిచారు", "লটারি", "জ্যাকপট",
   "জিতেছেন", "લોટરી", "જેકપોટ", r"જીત્યા\s*છો", r"જીતી\s*ગયા", "ലോട്ടറി", "ജാക്ക്പോട്ട്", r"സമ്മാനം\s*നേടി",
   "നേടിയിരിക്കുന്നു", "ਲਾਟਰੀ", "ਜੈਕਪਾਟ", r"ਜਿੱਤ\s*ਗਏ\s*ਹੋ", r"ਜਿੱਤਿਆ\s*ਹੈ", neg="neg")
_r("prize_job_offer", 25,
   L("work from home", r"part[- ]time (?:job|work)", "ghar baithe", "ghar se kaam", r"daily (?:earning|income|payment)",
     r"earn (?:rs\.? ?|₹ ?)?\d[\d,]*(?: rupees)?(?: per day| daily| a day| every day| roz)", r"roz \d[\d,]* kama\w*",
     r"double (?:your|the) money", "paisa double", r"guaranteed (?:returns?|profit)", r"high returns?",
     r"investment (?:plan|scheme|opportunity)", "crypto trading"),
   r"घर\s*बैठे", r"वर्क\s*फ्रॉम\s*होम", r"पार्ट\s*टाइम\s*(?:जॉब|नौकरी)", r"रोज\s*\S+\s*(?:रुपये|रुपए)?\s*कमा", r"पैसा\s*डबल",
   r"डबल\s*(?:मुनाफा|पैसा)", "घरबसल्या", r"घरून\s*काम", r"नोकरीची\s*संधी", r"कमवू\s*शकता", IS + "कमवा" + IE,
   "ಮನೆಯಿಂದಲೇ", r"ಮನೆಯಿಂದ\s*ಕೆಲಸ", r"ವರ್ಕ್\s*ಫ್ರಮ್\s*ಹೋಮ್", r"ಪಾರ್ಟ್\s*ಟೈಮ್", r"(?:ಉದ್ಯೋಗ|ಕೆಲಸದ)\s*ಅವಕಾಶ", "ಸಂಪಾದಿಸಿ",
   "ಸಂಪಾದಿಸಬಹುದು", "ಗಳಿಸಬಹುದು", "ದಿನಕ್ಕೆ" + G(20) + r"(?:ಸಾವಿರ|ರೂಪಾಯಿ)",
   r"வேலை\s*வாய்ப்பு", r"பார்ட்\s*டைம்", r"வொர்க்\s*ஃப்ரம்\s*ஹோம்", "சம்பாதிக்க", "தினமும்" + G(25) + "ரூபாய்",
   r"ఇంటి\s*(?:నుండి|నుంచే)\s*పని", r"వర్క్\s*ఫ్రమ్\s*హోమ్", r"పార్ట్\s*టైమ్", r"ఉద్యోగ\s*అవకాశం", "సంపాదించ",
   "రోజుకు" + G(20) + "రూపాయలు", r"বাড়ি\s*থেকে\s*কাজ", r"ঘরে\s*বসে", r"পার্ট\s*টাইম", r"চাকরির\s*সুযোগ",
   r"(?:আয়|রোজগার)\s*করুন", "রোজ" + G(20) + "টাকা", r"ઘરે\s*બેઠા", r"ઘરેથી\s*કામ", r"પાર્ટ\s*ટાઇમ", r"નોકરીની\s*તક",
   "કમાઓ", r"કમાણી\s*કરો", "રોજ" + G(20) + "રૂપિયા", "വീട്ടിലിരുന്ന്", r"വർക്ക്\s*ഫ്രം\s*ഹോം", r"പാർട്ട്\s*ടൈം",
   r"ജോലി\s*(?:അവസരം|ഓഫർ)", "സമ്പാദിക്കാം", "ദിവസവും" + G(20) + "രൂപ", r"ਘਰ\s*ਬੈਠੇ", r"ਪਾਰਟ\s*ਟਾਈਮ",
   r"ਨੌਕਰੀ\s*ਦਾ\s*ਮੌਕਾ", "ਕਮਾਓ", "ਰੋਜ਼" + G(20) + "ਰੁਪਏ", neg="neg")
_r("prize_job_offer", 12, "வீட்டிலிருந்து", "பரிசு", "బహుమతి", "পুরস্কার", "ಬಹುಮಾನ", "बक्षीस", "ઇનામ", "സമ്മാനം",
   "ਇਨਾਮ", neg="neg")


# ---------------------------------------------------------------- scanning

def _spans(rx: re.Pattern, s: str) -> list[tuple[int, int]]:
    out, pos = [], 0
    for m in rx.finditer(s):
        out.append((pos, m.start()))
        pos = m.end()
    out.append((pos, len(s)))
    return out


def _seg(spans: list[tuple[int, int]], pos: int) -> tuple[int, int]:
    for a, b in spans:
        if a <= pos <= b:
            return a, b
    return spans[-1]


def _negated(clause: str) -> bool:
    clause = _NEG_EXCEPT.sub(" ", clause)
    return bool(_NEG.search(clause)) and not _COND.search(clause)


_INDIC = re.compile(r"[ऀ-ॣ०-෿]")   # Indic letters/marks (not the danda)


def _candidates(norm: str, delivery: bool = False) -> list[tuple[str, int, int, int, bool]]:
    """(category, weight, start, end, soft) in normalised coordinates, after negation/advice filtering."""
    clauses = _spans(_CLAUSE, norm)
    sentences = _spans(_SENTENCE, norm)
    clause_neg = {c: _negated(norm[c[0]:c[1]]) for c in clauses}
    out = []
    for rule in _RULES:
        for m in rule.rx.finditer(norm):
            if m.end() == m.start():
                continue
            clause = _seg(clauses, m.start())
            if rule.neg == "neg" and clause_neg[clause]:
                continue
            if rule.neg == "strict":
                text = norm[clause[0]:clause[1]]
                if _STRICT_NEG.search(text) and not _COND.search(text):
                    continue
            if rule.advice:
                sent = _seg(sentences, m.start())
                if _SENSITIVE.search(norm[sent[0]:sent[1]]):
                    continue
            out.append((rule.category, rule.weight, m.start(), m.end(), rule.soft))
    delivery = delivery or bool(_DELIVERY.search(norm))
    for pair in _PAIRS:
        bs = [(m.start(), m.end()) for m in pair.b.finditer(norm)]
        for m in pair.a.finditer(norm):
            near = [(max(b0 - m.end(), m.start() - b1, 0), b0, b1) for b0, b1 in bs]
            near = [n for n in near if n[0] <= pair.window]
            if not near:
                continue
            _, b0, b1 = min(near)
            ca, cb = _seg(clauses, m.start()), _seg(clauses, b0)
            # Safety advice ("never share your OTP"): negated where the term is, and where the verb is.
            if clause_neg[ca] and (ca == cb or clause_neg[cb]):
                continue
            start, end = min(m.start(), b0), max(m.end(), b1)
            if end - start > 50 or _seg(sentences, m.start()) != _seg(sentences, b0):
                start, end = m.start(), m.end()
            # A delivery agent asking for the order OTP is normal: keep it as weak context only.
            out.append((pair.category, 10 if delivery else pair.weight, start, end, delivery))
    return out


def _scan_all(text: str, delivery: bool = False) -> tuple[list[Flag], list[Flag]]:
    """(flags, soft): soft flags are context ("calling from your bank", "parcel") that only count
    toward the score once the call has a real scam flag, and are not highlighted.
    `delivery`: the call already mentioned a delivery/order, so an OTP request is weak context."""
    if not text or not text.strip():
        return [], []
    norm, idx = _normalize(text)
    cands = sorted(_candidates(norm, delivery), key=lambda c: (-c[1], c[2] - c[3]))
    kept: list[tuple[str, int, int, int, bool]] = []
    for c in cands:
        cat, _, a, b, _ = c
        overlap = [k for k in kept if a < k[3] and k[2] < b]
        # Drop overlapping duplicates, unless this is the only evidence for its category.
        if overlap and any(k[0] == cat for k in kept):
            continue
        kept.append(c)
    flags, soft = [], []
    for cat, w, a, b, is_soft in sorted(kept, key=lambda k: k[2]):
        # Highlight whole Indic words: stems like "ಎನಿಡೆಸ್ಕ" grow to "ಎನಿಡೆಸ್ಕ್".
        while b < len(norm) and _INDIC.match(norm[b]) and _INDIC.match(norm[b - 1]):
            b += 1
        start, end = idx[a], idx[b - 1] + 1
        (soft if is_soft else flags).append(Flag(cat, text[start:end], start, end, w))
    return flags, soft


def scan(text: str) -> list[Flag]:
    """Scam phrases in `text`, ordered by position. Offsets index into `text` itself."""
    return _scan_all(text)[0]


# ---------------------------------------------------------------- scoring

def _category_scores(flags: list[Flag]) -> dict[str, int]:
    by_cat: dict[str, list[Flag]] = {}
    for f in flags:
        by_cat.setdefault(f.category, []).append(f)
    scores = {}
    for cat, fs in by_cat.items():
        distinct = {f.phrase.casefold() for f in fs}
        scores[cat] = max(f.weight for f in fs) + min(6, 3 * (len(distinct) - 1))   # repeats add little
    return scores


def _rules_assessment(flags: list[Flag]) -> Assessment:
    cs = _category_scores(flags)
    get = lambda c: cs.get(c, 0)  # noqa: E731
    strong = {c for c, s in cs.items() if s >= 15}
    asks = strong & {"otp_request", "payment_request", "remote_access"}
    boost = 0
    if asks:
        if get("impersonation") >= 25 or get("digital_arrest") >= 25:
            boost += 25                        # authority + OTP/money/remote access
        elif get("impersonation") >= 15:
            boost += 12
        if "account_threat" in strong:
            boost += 20
        if "urgency_secrecy" in strong:
            boost += 10
    if "prize_job_offer" in strong and "payment_request" in strong:
        boost += 25                            # "pay a fee to get the prize/job"
    if get("digital_arrest") >= 30:
        boost += 15                            # warrant / digital arrest / laundering is serious on its own
    if len(strong) >= 3:
        boost += 10
    score = min(100, sum(cs.values()) + boost) if cs else 0
    cats = sorted(cs, key=lambda c: -cs[c])
    if cats:
        reason = "; ".join(REASONS[c] for c in cats[:4])
        reason = reason[0].upper() + reason[1:] + "."
    else:
        reason = "No scam patterns heard so far."
    return Assessment(score, level_for(score), cats, reason, "rules")


_SCRIPTS = [((0x0900, 0x097F), "hi-IN"), ((0x0980, 0x09FF), "bn-IN"), ((0x0A00, 0x0A7F), "pa-IN"),
            ((0x0A80, 0x0AFF), "gu-IN"), ((0x0B80, 0x0BFF), "ta-IN"), ((0x0C00, 0x0C7F), "te-IN"),
            ((0x0C80, 0x0CFF), "kn-IN"), ((0x0D00, 0x0D7F), "ml-IN")]


def guess_language(text: str) -> str | None:
    """Language from the dominant Indic script (Devanagari -> hi-IN). None for Latin-only text."""
    counts: Counter[str] = Counter()
    for ch in text:
        o = ord(ch)
        for (lo, hi), code in _SCRIPTS:
            if lo <= o <= hi:
                counts[code] += 1
                break
    return counts.most_common(1)[0][0] if counts else None


class CallMonitor:
    """Per-call state: transcript, accumulated flags and the running assessment."""

    def __init__(self):
        self.transcript: list[dict] = []
        self.assessment = Assessment(0, "safe", [], "No scam patterns heard so far.", "rules")
        self._flags: list[Flag] = []
        self._soft: list[Flag] = []
        self._delivery = False
        self._llm: Assessment | None = None

    def add(self, text: str, language: str | None) -> tuple[list[Flag], Assessment]:
        """Scan one utterance (fast, sync, rules only) and update the running assessment."""
        flags, soft = _scan_all(text, self._delivery)
        self._delivery = self._delivery or bool(_DELIVERY.search(_norm(text)))
        self._soft.extend(soft)
        self.transcript.append({"index": len(self.transcript), "text": text,
                                "language": language or guess_language(text),
                                "flags": [asdict(f) for f in flags]})
        self._flags.extend(flags)
        self._update()
        return flags, self.assessment

    def _scored_flags(self) -> list[Flag]:
        return self._flags + self._soft if self._flags else []

    def _update(self) -> None:
        best = _rules_assessment(self._scored_flags())
        if self._llm and self._llm.score > best.score:
            cats = best.categories + [c for c in self._llm.categories if c not in best.categories]
            best = replace(self._llm, categories=cats)
        prev = self.assessment
        if best.score < prev.score:            # the meter never goes down during a call
            best = replace(best, score=prev.score, level=prev.level)
        self.assessment = best

    async def llm_review(self) -> Assessment | None:
        """Ask the LLM about the last ~12 utterances; returns the merged assessment.
        None when no LLM is configured, nothing was said yet, or the LLM failed."""
        from app import llm
        if not llm.configured() or not self.transcript:
            return None
        lines = "\n".join(f"[{u['index']}] ({u['language'] or '?'}) {u['text']}" for u in self.transcript[-12:])
        rules = _rules_assessment(self._scored_flags())
        messages = [
            {"role": "system", "content": (
                "You are Scam Kavach, a scam-call detector for Indian phone users. You read a live phone-call "
                "transcript (any Indian language, code-mixed, with speech-recognition errors) and rate how likely "
                "the caller is a scammer. Categories: " + ", ".join(CATEGORIES) + ". Genuine reminders and "
                "safety advice (e.g. 'the bank never asks for your OTP') are NOT scams. Reply with JSON only: "
                '{"score": 0-100, "categories": [..], "reason": "one short English sentence"}')},
            {"role": "user", "content": f"Transcript so far (oldest first):\n{lines}\n\n"
                                        f"Rule-based score: {rules.score} ({', '.join(rules.categories) or 'none'})."},
        ]
        data = await llm.chat_json(messages)
        if not isinstance(data, dict):
            return None
        try:
            score = max(0, min(100, int(float(data.get("score", 0)))))
        except (TypeError, ValueError):
            return None
        cats = [c for c in data.get("categories") or [] if c in CATEGORIES]
        if not self._flags:
            score = min(score, LLM_CAP_NO_FLAGS)
        reason = str(data.get("reason") or "").strip()[:240] or rules.reason
        self._llm = Assessment(score, level_for(score), cats, reason, "llm")
        self._update()
        return self.assessment

    def dominant_language(self) -> str:
        """Most common detected language in the call (default hi-IN)."""
        langs = [u["language"] for u in self.transcript if u["language"] in LANG_CODES]
        return Counter(langs).most_common(1)[0][0] if langs else "hi-IN"
