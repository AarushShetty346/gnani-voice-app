"""Spoken scam warnings: handwritten text for 10 languages x 8 categories (+ generic), and Timbre TTS.

A warning is built from three short parts so every combination stays natural and <= 22 words:
    danger:  "<stop opener> <category advice> <hang up now>"
    caution: "<be careful> <category advice>"
No audio tags: the same text is shown on screen in the alert overlay.
"""
from __future__ import annotations

import hashlib
import importlib
import logging
from pathlib import Path

log = logging.getLogger(__name__)

LANGS = ("hi-IN", "en-IN", "bn-IN", "gu-IN", "kn-IN", "ml-IN", "mr-IN", "pa-IN", "ta-IN", "te-IN")
MAX_WORDS = 22
LANG_NAMES = {"hi-IN": "Hindi", "en-IN": "Indian English", "bn-IN": "Bengali", "gu-IN": "Gujarati",
              "kn-IN": "Kannada", "ml-IN": "Malayalam", "mr-IN": "Marathi", "pa-IN": "Punjabi",
              "ta-IN": "Tamil", "te-IN": "Telugu"}

TEXTS: dict[str, dict[str, str]] = {
    "en-IN": {
        "danger": "Stop! This looks like a scam call.",
        "caution": "Be careful.",
        "hangup": "Hang up now.",
        "otp_request": "Never share your OTP, PIN or card number with anyone.",
        "impersonation": "This caller may be pretending to be police or bank staff.",
        "digital_arrest": "There's no 'digital arrest'. Police never arrest anyone over a call.",
        "account_threat": "No real office threatens like this. Call the official number yourself.",
        "payment_request": "Do not send money or make any payment.",
        "remote_access": "Do not install AnyDesk or any app they ask for.",
        "urgency_secrecy": "Don't let them rush you. Talk to your family first.",
        "prize_job_offer": "Real jobs and prizes never ask you to pay first.",
        "generic": "This call seems suspicious. Do not share any details.",
    },
    "hi-IN": {
        "danger": "रुकिए! यह कॉल धोखाधड़ी लग रही है।",
        "caution": "सावधान रहिए।",
        "hangup": "अभी फ़ोन काट दीजिए।",
        "otp_request": "अपना OTP किसी को मत बताइए।",
        "impersonation": "हो सकता है यह नकली पुलिस या बैंक वाला हो।",
        "digital_arrest": "डिजिटल अरेस्ट कुछ नहीं होता। पुलिस फ़ोन पर गिरफ़्तार नहीं करती।",
        "account_threat": "कोई बैंक या कंपनी ऐसी धमकी नहीं देती। खुद पता कीजिए।",
        "payment_request": "कोई पैसा मत भेजिए, कोई पेमेंट मत कीजिए।",
        "remote_access": "AnyDesk या उनका बताया कोई भी ऐप डाउनलोड मत कीजिए।",
        "urgency_secrecy": "जल्दबाज़ी मत कीजिए। पहले घरवालों से बात कीजिए।",
        "prize_job_offer": "असली नौकरी या इनाम के लिए पहले पैसे नहीं देने पड़ते।",
        "generic": "यह कॉल संदिग्ध है। अपनी कोई भी जानकारी मत दीजिए।",
    },
    "kn-IN": {
        "danger": "ಎಚ್ಚರ! ಇದು ಮೋಸದ ಕರೆ ಅನಿಸುತ್ತಿದೆ.",
        "caution": "ಎಚ್ಚರಿಕೆ!",
        "hangup": "ಈಗಲೇ ಕರೆ ಕಟ್ ಮಾಡಿ.",
        "otp_request": "ನಿಮ್ಮ OTP, PIN ಅಥವಾ ಕಾರ್ಡ್ ನಂಬರ್ ಯಾರಿಗೂ ಹೇಳಬೇಡಿ.",
        "impersonation": "ಇವರು ನಕಲಿ ಪೊಲೀಸ್ ಅಥವಾ ಬ್ಯಾಂಕ್ ಸಿಬ್ಬಂದಿ ಆಗಿರಬಹುದು.",
        "digital_arrest": "ಡಿಜಿಟಲ್ ಅರೆಸ್ಟ್ ಅನ್ನೋದು ಇಲ್ಲ. ಪೊಲೀಸರು ಫೋನ್‌ನಲ್ಲಿ ಬಂಧಿಸುವುದಿಲ್ಲ.",
        "account_threat": "ಬ್ಯಾಂಕ್ ಆಗಲಿ ವಿದ್ಯುತ್ ಇಲಾಖೆ ಆಗಲಿ ಫೋನ್‌ನಲ್ಲಿ ಹೀಗೆ ಬೆದರಿಸುವುದಿಲ್ಲ. ಅಧಿಕೃತ ನಂಬರ್‌ಗೆ ನೀವೇ ಕರೆ ಮಾಡಿ.",
        "payment_request": "ಯಾವುದೇ ಹಣ ಕಳುಹಿಸಬೇಡಿ, ಪಾವತಿ ಮಾಡಬೇಡಿ.",
        "remote_access": "ಎನಿಡೆಸ್ಕ್ ಅಥವಾ ಅವರು ಹೇಳುವ ಯಾವುದೇ ಆಪ್ ಡೌನ್‌ಲೋಡ್ ಮಾಡಬೇಡಿ.",
        "urgency_secrecy": "ಆತುರ ಪಡಬೇಡಿ. ಮೊದಲು ಮನೆಯವರ ಜೊತೆ ಮಾತಾಡಿ.",
        "prize_job_offer": "ನಿಜವಾದ ಕೆಲಸ ಅಥವಾ ಬಹುಮಾನಕ್ಕೆ ಮೊದಲು ಹಣ ಕಟ್ಟುವ ಅಗತ್ಯವಿಲ್ಲ.",
        "generic": "ಈ ಕರೆ ಅನುಮಾನಾಸ್ಪದವಾಗಿದೆ. ನಿಮ್ಮ ಯಾವುದೇ ವಿವರ ಕೊಡಬೇಡಿ.",
    },
    "ta-IN": {
        "danger": "ஜாக்கிரதை! இது மோசடி அழைப்பு போல் தெரிகிறது.",
        "caution": "கவனமாக இருங்கள்!",
        "hangup": "உடனே போனை கட் பண்ணுங்க.",
        "otp_request": "உங்கள் OTP, PIN, கார்டு நம்பரை யாரிடமும் சொல்லாதீர்கள்.",
        "impersonation": "இவர் போலி போலீஸ் அல்லது வங்கி அதிகாரியாக இருக்கலாம்.",
        "digital_arrest": "டிஜிட்டல் அரெஸ்ட் என்று எதுவும் இல்லை. போலீஸ் போனில் கைது செய்ய மாட்டார்கள்.",
        "account_threat": "வங்கியோ மின்வாரியமோ போனில் இப்படி மிரட்டாது. அதிகாரப்பூர்வ எண்ணில் நீங்களே கேளுங்கள்.",
        "payment_request": "எந்தப் பணமும் அனுப்பாதீர்கள், எந்தக் கட்டணமும் செலுத்தாதீர்கள்.",
        "remote_access": "AnyDesk அல்லது அவர்கள் சொல்லும் எந்த ஆப்பையும் டவுன்லோட் செய்யாதீர்கள்.",
        "urgency_secrecy": "அவசரப்பட வேண்டாம். முதலில் வீட்டில் உள்ளவர்களிடம் பேசுங்கள்.",
        "prize_job_offer": "உண்மையான வேலைக்கோ பரிசுக்கோ முதலில் பணம் கட்ட வேண்டியதில்லை.",
        "generic": "இந்த அழைப்பு சந்தேகமாக உள்ளது. உங்கள் விவரங்கள் எதையும் கொடுக்காதீர்கள்.",
    },
    "te-IN": {
        "danger": "ఆగండి! ఇది మోసపు కాల్‌లా ఉంది.",
        "caution": "జాగ్రత్తగా ఉండండి!",
        "hangup": "వెంటనే కాల్ కట్ చేయండి.",
        "otp_request": "మీ OTP, PIN లేదా కార్డ్ నంబర్ ఎవరికీ చెప్పకండి.",
        "impersonation": "వీళ్ళు నకిలీ పోలీసులు లేదా బ్యాంక్ సిబ్బంది కావచ్చు.",
        "digital_arrest": "డిజిటల్ అరెస్ట్ అనేది లేదు. పోలీసులు ఫోన్‌లో అరెస్ట్ చేయరు.",
        "account_threat": "బ్యాంక్ గానీ కరెంట్ ఆఫీస్ గానీ ఫోన్‌లో ఇలా బెదిరించవు. అధికారిక నంబర్‌కి మీరే ఫోన్ చేయండి.",
        "payment_request": "ఎలాంటి డబ్బు పంపకండి, ఏ పేమెంట్ చేయకండి.",
        "remote_access": "AnyDesk లాంటి ఏ యాప్‌నూ డౌన్‌లోడ్ చేయకండి.",
        "urgency_secrecy": "తొందరపడకండి. ముందు ఇంట్లోవాళ్ళతో మాట్లాడండి.",
        "prize_job_offer": "నిజమైన ఉద్యోగానికి గానీ బహుమతికి గానీ ముందు డబ్బు కట్టాల్సిన అవసరం లేదు.",
        "generic": "ఈ కాల్ అనుమానాస్పదంగా ఉంది. మీ వివరాలు ఏవీ ఇవ్వకండి.",
    },
    "mr-IN": {
        "danger": "थांबा! हा फसवणुकीचा कॉल वाटतोय.",
        "caution": "सावध राहा!",
        "hangup": "लगेच फोन कट करा.",
        "otp_request": "तुमचा OTP, PIN किंवा कार्ड नंबर कोणालाही सांगू नका.",
        "impersonation": "हा माणूस खोटा पोलीस किंवा बँक कर्मचारी असू शकतो.",
        "digital_arrest": "डिजिटल अरेस्ट असं काहीही नसतं. पोलीस फोनवर अटक करत नाहीत.",
        "account_threat": "बँक किंवा वीज कंपनी फोनवर अशी धमकी देत नाही. अधिकृत नंबरवर स्वतः विचारा.",
        "payment_request": "कोणतेही पैसे पाठवू नका, कोणतेही पेमेंट करू नका.",
        "remote_access": "AnyDesk किंवा ते सांगतील ते कोणतेही अ‍ॅप डाउनलोड करू नका.",
        "urgency_secrecy": "घाई करू नका. आधी घरच्यांशी बोला.",
        "prize_job_offer": "खऱ्या नोकरीसाठी किंवा बक्षिसासाठी आधी पैसे भरावे लागत नाहीत.",
        "generic": "हा कॉल संशयास्पद आहे. तुमची कोणतीही माहिती देऊ नका.",
    },
    "bn-IN": {
        "danger": "থামুন! এটা প্রতারণার কল মনে হচ্ছে।",
        "caution": "সাবধান!",
        "hangup": "এখনই ফোন কেটে দিন।",
        "otp_request": "আপনার OTP, PIN বা কার্ড নম্বর কাউকে বলবেন না।",
        "impersonation": "এরা ভুয়ো পুলিশ বা ব্যাংকের লোক হতে পারে।",
        "digital_arrest": "ডিজিটাল অ্যারেস্ট বলে কিছু হয় না। পুলিশ ফোনে গ্রেফতার করে না।",
        "account_threat": "ব্যাংক বা বিদ্যুৎ অফিস এভাবে হুমকি দেয় না। নিজে খোঁজ নিন।",
        "payment_request": "কোনো টাকা পাঠাবেন না, কোনো পেমেন্ট করবেন না।",
        "remote_access": "AnyDesk বা ওদের বলা কোনো অ্যাপ ডাউনলোড করবেন না।",
        "urgency_secrecy": "তাড়াহুড়ো করবেন না। আগে বাড়ির লোকের সঙ্গে কথা বলুন।",
        "prize_job_offer": "আসল চাকরি বা পুরস্কারের জন্য আগে টাকা দিতে হয় না।",
        "generic": "এই কলটা সন্দেহজনক। আপনার কোনো তথ্য দেবেন না।",
    },
    "gu-IN": {
        "danger": "રોકાઈ જાઓ! આ છેતરપિંડીનો કૉલ લાગે છે.",
        "caution": "સાવધાન!",
        "hangup": "ફોન કાપી નાખો.",
        "otp_request": "તમારો OTP, PIN કે કાર્ડ નંબર કોઈને કહેશો નહીં.",
        "impersonation": "આ વ્યક્તિ નકલી પોલીસ કે બેંક કર્મચારી હોઈ શકે છે.",
        "digital_arrest": "ડિજિટલ અરેસ્ટ જેવું કંઈ હોતું નથી. પોલીસ ફોન પર ધરપકડ કરતી નથી.",
        "account_threat": "બેંક કે વીજ કંપની આવી ધમકી આપતી નથી. જાતે તપાસ કરો.",
        "payment_request": "કોઈ પૈસા મોકલશો નહીં, કોઈ પેમેન્ટ કરશો નહીં.",
        "remote_access": "AnyDesk કે તેઓ કહે તે કોઈ પણ એપ ડાઉનલોડ કરશો નહીં.",
        "urgency_secrecy": "ઉતાવળ ન કરો. પહેલાં ઘરના લોકો સાથે વાત કરો.",
        "prize_job_offer": "સાચી નોકરી કે ઇનામ માટે પહેલાં પૈસા ભરવા પડતા નથી.",
        "generic": "આ કૉલ શંકાસ્પદ છે. તમારી કોઈ માહિતી આપશો નહીં.",
    },
    "ml-IN": {
        "danger": "സൂക്ഷിക്കുക! ഇതൊരു തട്ടിപ്പ് കോൾ ആണെന്ന് തോന്നുന്നു.",
        "caution": "ശ്രദ്ധിക്കൂ!",
        "hangup": "ഉടനെ ഫോൺ കട്ട് ചെയ്യൂ.",
        "otp_request": "നിങ്ങളുടെ OTP, PIN, കാർഡ് നമ്പർ ആരോടും പറയരുത്.",
        "impersonation": "ഇത് വ്യാജ പോലീസോ ബാങ്ക് ജീവനക്കാരനോ ആകാം.",
        "digital_arrest": "ഡിജിറ്റൽ അറസ്റ്റ് എന്നൊന്നില്ല. പോലീസ് ഫോണിലൂടെ അറസ്റ്റ് ചെയ്യില്ല.",
        "account_threat": "ബാങ്കോ കെഎസ്ഇബിയോ ഫോണിൽ ഇങ്ങനെ ഭീഷണിപ്പെടുത്തില്ല. ഔദ്യോഗിക നമ്പറിൽ സ്വയം വിളിച്ച് ചോദിക്കൂ.",
        "payment_request": "പണം അയക്കരുത്, ഒരു പേയ്മെന്റും ചെയ്യരുത്.",
        "remote_access": "AnyDesk പോലുള്ള ഒരു ആപ്പും ഡൗൺലോഡ് ചെയ്യരുത്.",
        "urgency_secrecy": "തിരക്ക് കൂട്ടരുത്. ആദ്യം വീട്ടുകാരോട് സംസാരിക്കൂ.",
        "prize_job_offer": "യഥാർത്ഥ ജോലിക്കോ സമ്മാനത്തിനോ ആദ്യം പണം അടയ്ക്കേണ്ടതില്ല.",
        "generic": "ഈ കോൾ സംശയകരമാണ്. നിങ്ങളുടെ വിവരങ്ങൾ ഒന്നും നൽകരുത്.",
    },
    "pa-IN": {
        "danger": "ਰੁਕੋ! ਇਹ ਠੱਗੀ ਵਾਲੀ ਕਾਲ ਲੱਗਦੀ ਹੈ।",
        "caution": "ਸਾਵਧਾਨ!",
        "hangup": "ਹੁਣੇ ਫ਼ੋਨ ਕੱਟ ਦਿਓ।",
        "otp_request": "ਆਪਣਾ OTP, PIN ਜਾਂ ਕਾਰਡ ਨੰਬਰ ਕਿਸੇ ਨੂੰ ਨਾ ਦੱਸੋ।",
        "impersonation": "ਇਹ ਨਕਲੀ ਪੁਲਿਸ ਜਾਂ ਬੈਂਕ ਵਾਲਾ ਹੋ ਸਕਦਾ ਹੈ।",
        "digital_arrest": "ਡਿਜੀਟਲ ਅਰੈਸਟ ਕੁਝ ਨਹੀਂ ਹੁੰਦਾ। ਪੁਲਿਸ ਫ਼ੋਨ 'ਤੇ ਗ੍ਰਿਫ਼ਤਾਰ ਨਹੀਂ ਕਰਦੀ।",
        "account_threat": "ਬੈਂਕ ਜਾਂ ਬਿਜਲੀ ਵਿਭਾਗ ਇੰਝ ਧਮਕੀ ਨਹੀਂ ਦਿੰਦੇ। ਖ਼ੁਦ ਪਤਾ ਕਰੋ।",
        "payment_request": "ਕੋਈ ਪੈਸਾ ਨਾ ਭੇਜੋ, ਕੋਈ ਪੇਮੈਂਟ ਨਾ ਕਰੋ।",
        "remote_access": "AnyDesk ਜਾਂ ਉਨ੍ਹਾਂ ਦੀ ਦੱਸੀ ਕੋਈ ਵੀ ਐਪ ਡਾਊਨਲੋਡ ਨਾ ਕਰੋ।",
        "urgency_secrecy": "ਕਾਹਲੀ ਨਾ ਕਰੋ। ਪਹਿਲਾਂ ਘਰਦਿਆਂ ਨਾਲ ਗੱਲ ਕਰੋ।",
        "prize_job_offer": "ਅਸਲੀ ਨੌਕਰੀ ਜਾਂ ਇਨਾਮ ਲਈ ਪਹਿਲਾਂ ਪੈਸੇ ਨਹੀਂ ਭਰਨੇ ਪੈਂਦੇ।",
        "generic": "ਇਹ ਕਾਲ ਸ਼ੱਕੀ ਹੈ। ਆਪਣੀ ਕੋਈ ਜਾਣਕਾਰੀ ਨਾ ਦਿਓ।",
    },
}

# Short category labels (summary card / share text).
LABELS: dict[str, dict[str, str]] = {
    "en-IN": {"otp_request": "asking for OTP/PIN", "impersonation": "posing as police/bank/officials",
              "digital_arrest": "fake arrest or legal threat", "account_threat": "threat to block account or cut service",
              "payment_request": "asking for money", "remote_access": "asking to install a remote-access app",
              "urgency_secrecy": "pressure and secrecy", "prize_job_offer": "fake prize or job offer"},
    "hi-IN": {"otp_request": "OTP/PIN माँगना", "impersonation": "पुलिस/बैंक/अफ़सर बनकर बात",
              "digital_arrest": "नकली गिरफ़्तारी की धमकी", "account_threat": "खाता या सेवा बंद करने की धमकी",
              "payment_request": "पैसे माँगना", "remote_access": "रिमोट ऐप (AnyDesk) डलवाना",
              "urgency_secrecy": "जल्दबाज़ी और राज़ रखने का दबाव", "prize_job_offer": "नकली इनाम या नौकरी का लालच"},
    "kn-IN": {"otp_request": "OTP/PIN ಕೇಳುವುದು", "impersonation": "ಪೊಲೀಸ್/ಬ್ಯಾಂಕ್ ಅಧಿಕಾರಿ ಎಂದು ನಟನೆ",
              "digital_arrest": "ನಕಲಿ ಬಂಧನದ ಬೆದರಿಕೆ", "account_threat": "ಖಾತೆ ಅಥವಾ ಸೇವೆ ನಿಲ್ಲಿಸುವ ಬೆದರಿಕೆ",
              "payment_request": "ಹಣ ಕೇಳುವುದು", "remote_access": "ರಿಮೋಟ್ ಆಪ್ (AnyDesk) ಹಾಕಿಸುವುದು",
              "urgency_secrecy": "ಆತುರ ಮತ್ತು ಗುಟ್ಟಿನ ಒತ್ತಡ", "prize_job_offer": "ನಕಲಿ ಬಹುಮಾನ ಅಥವಾ ಕೆಲಸದ ಆಮಿಷ"},
    "ta-IN": {"otp_request": "OTP/PIN கேட்பது", "impersonation": "போலீஸ்/வங்கி அதிகாரி போல் நடிப்பது",
              "digital_arrest": "போலி கைது மிரட்டல்", "account_threat": "கணக்கு அல்லது சேவையை நிறுத்தும் மிரட்டல்",
              "payment_request": "பணம் கேட்பது", "remote_access": "ரிமோட் ஆப் (AnyDesk) நிறுவச் சொல்வது",
              "urgency_secrecy": "அவசரம், ரகசியம் என்ற அழுத்தம்", "prize_job_offer": "போலி பரிசு அல்லது வேலை ஆசை"},
    "te-IN": {"otp_request": "OTP/PIN అడగడం", "impersonation": "పోలీస్/బ్యాంక్ అధికారిలా నటించడం",
              "digital_arrest": "నకిలీ అరెస్ట్ బెదిరింపు", "account_threat": "ఖాతా లేదా సేవ ఆపేస్తామనే బెదిరింపు",
              "payment_request": "డబ్బు అడగడం", "remote_access": "రిమోట్ యాప్ (AnyDesk) వేయించడం",
              "urgency_secrecy": "తొందర, రహస్యం అనే ఒత్తిడి", "prize_job_offer": "నకిలీ బహుమతి లేదా ఉద్యోగ ఆశ"},
    "mr-IN": {"otp_request": "OTP/PIN मागणे", "impersonation": "पोलीस/बँक अधिकारी असल्याचे भासवणे",
              "digital_arrest": "खोट्या अटकेची धमकी", "account_threat": "खाते किंवा सेवा बंद करण्याची धमकी",
              "payment_request": "पैसे मागणे", "remote_access": "रिमोट अ‍ॅप (AnyDesk) टाकायला लावणे",
              "urgency_secrecy": "घाई आणि गुप्ततेचा दबाव", "prize_job_offer": "खोट्या बक्षिसाचे किंवा नोकरीचे आमिष"},
    "bn-IN": {"otp_request": "OTP/PIN চাওয়া", "impersonation": "পুলিশ/ব্যাংকের লোক সেজে কথা",
              "digital_arrest": "ভুয়ো গ্রেফতারের হুমকি", "account_threat": "অ্যাকাউন্ট বা পরিষেবা বন্ধের হুমকি",
              "payment_request": "টাকা চাওয়া", "remote_access": "রিমোট অ্যাপ (AnyDesk) বসাতে বলা",
              "urgency_secrecy": "তাড়াহুড়ো আর গোপন রাখার চাপ", "prize_job_offer": "ভুয়ো পুরস্কার বা চাকরির লোভ"},
    "gu-IN": {"otp_request": "OTP/PIN માંગવો", "impersonation": "પોલીસ/બેંક અધિકારી બનીને વાત",
              "digital_arrest": "નકલી ધરપકડની ધમકી", "account_threat": "ખાતું કે સેવા બંધ કરવાની ધમકી",
              "payment_request": "પૈસા માંગવા", "remote_access": "રિમોટ એપ (AnyDesk) નખાવવી",
              "urgency_secrecy": "ઉતાવળ અને ગુપ્તતાનું દબાણ", "prize_job_offer": "નકલી ઇનામ કે નોકરીની લાલચ"},
    "ml-IN": {"otp_request": "OTP/PIN ചോദിക്കൽ", "impersonation": "പോലീസ്/ബാങ്ക് ഉദ്യോഗസ്ഥനായി അഭിനയിക്കൽ",
              "digital_arrest": "വ്യാജ അറസ്റ്റ് ഭീഷണി", "account_threat": "അക്കൗണ്ടോ സേവനമോ നിർത്തുമെന്ന ഭീഷണി",
              "payment_request": "പണം ചോദിക്കൽ", "remote_access": "റിമോട്ട് ആപ്പ് (AnyDesk) ഇടാൻ പറയൽ",
              "urgency_secrecy": "തിടുക്കവും രഹസ്യവും ആവശ്യപ്പെടൽ", "prize_job_offer": "വ്യാജ സമ്മാനമോ ജോലിയോ വാഗ്ദാനം"},
    "pa-IN": {"otp_request": "OTP/PIN ਮੰਗਣਾ", "impersonation": "ਪੁਲਿਸ/ਬੈਂਕ ਅਫ਼ਸਰ ਬਣ ਕੇ ਗੱਲ",
              "digital_arrest": "ਨਕਲੀ ਗ੍ਰਿਫ਼ਤਾਰੀ ਦੀ ਧਮਕੀ", "account_threat": "ਖਾਤਾ ਜਾਂ ਸੇਵਾ ਬੰਦ ਕਰਨ ਦੀ ਧਮਕੀ",
              "payment_request": "ਪੈਸੇ ਮੰਗਣਾ", "remote_access": "ਰਿਮੋਟ ਐਪ (AnyDesk) ਪੁਆਉਣਾ",
              "urgency_secrecy": "ਕਾਹਲੀ ਤੇ ਗੁਪਤਤਾ ਦਾ ਦਬਾਅ", "prize_job_offer": "ਨਕਲੀ ਇਨਾਮ ਜਾਂ ਨੌਕਰੀ ਦਾ ਲਾਲਚ"},
}


def resolve_language(language: str | None) -> str:
    """A supported language code; unknown/auto falls back to hi-IN."""
    return language if language in TEXTS else "hi-IN"


def category_text(category: str, language: str) -> str:
    """The advice sentence for a category (generic when unknown)."""
    t = TEXTS[resolve_language(language)]
    return t.get(category, t["generic"])


def category_label(category: str, language: str) -> str:
    return LABELS[resolve_language(language)].get(category, category)


def alert_text(category: str, level: str, language: str) -> str:
    """Short spoken warning in `language`. danger: stop + advice + hang up; anything else: careful + advice."""
    t = TEXTS[resolve_language(language)]
    body = t.get(category, t["generic"])
    if level == "danger":
        text = f"{t['danger']} {body} {t['hangup']}"
        return text if len(text.split()) <= MAX_WORDS else f"{t['danger']} {body}"
    return f"{t['caution']} {body}"


def _mod(name: str):
    # import_module consults sys.modules first, so tests can swap in fakes for config/gnani.
    return importlib.import_module(name)


async def alert_audio(text: str, language: str) -> bytes | None:
    """Timbre v3.0 WAV for `text`, cached on disk by sha256(text+language). None in mock mode or on error."""
    config = _mod("app.config")
    if config.gnani_mock():
        return None
    lang = language if language in LANGS else "auto"
    path = Path(config.CACHE_DIR) / "tts" / (hashlib.sha256((text + language).encode("utf-8")).hexdigest() + ".wav")
    if path.exists():
        return path.read_bytes()
    voice = config.DEFAULT_VOICE.get(language, "Shivani")
    try:
        wav = await _mod("app.gnani").tts(text, voice=voice, language=lang)
    except Exception as e:  # alerts must never break the call loop
        log.warning("alert TTS failed: %s", e)
        return None
    if not wav:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(wav)
    tmp.replace(path)
    return wav
