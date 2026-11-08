# ScamLingo: a live scam-call shield

**Put a suspicious call on speaker. ScamLingo listens, spots the lingo scammers use, and warns you out loud before
you share an OTP or send money.**

**The problem.** Indians reported losing about ₹22,800 crore to cyber fraud in 2024 (I4C data, via PIB). Scam
calls such as fake-police "digital arrest", bank KYC and OTP, power-cut threats that push AnyDesk, and job scams
work because the person is alone, scared and rushed, often in Hindi or a regional language. Most help arrives
after the money is gone.

**Who it's for.** Parents and grandparents who pick up every call, and anyone whose call "feels off".

**What it does**
- **Listens live** through the phone's speaker, writes the call down and scores the risk (0–100) after every
  sentence, highlighting the risky phrases.
- **Interrupts out loud.** At high risk the screen turns red and a calm voice says "Stop! This looks like a scam
  call… Hang up now." in English or in the caller's language.
- **After the call:** a plain-language summary, what to do, the 1930 helpline, and one tap to share on WhatsApp.
- Also checks an uploaded call recording, and has 5 demo calls to try.

**How it uses Gnani AI**

| Gnani model | What it does in ScamLingo |
|---|---|
| **Prisma v3.0 realtime STT** | Streams the call live. Code-mix output keeps Hinglish readable, scam keyterms (OTP, KYC, AnyDesk, digital arrest…) and the telephony VAD preset handle phone audio. |
| **Prisma v3.0 REST STT** | "Check a recording": transcribes uploaded calls. |
| **Timbre v3.0 TTS** | Speaks every warning in 10 Indian languages, and voices the demo calls. |

Detection runs on every sentence in about 0.4 ms: multilingual rules for 8 scam signals (OTP/PIN asks, fake
officials, digital arrest, account threats, payment asks, remote-access apps, pressure and secrecy, job or prize
bait). Signals combine (an "official" plus an OTP, money or app request means danger), and safety advice like "the
bank never asks for your OTP" is recognised, so genuine calls stay safe. An optional LLM gives a second opinion; it
can raise the risk but can't call a scam on its own.

**Results on live Gnani.** 5 of 5 demo calls judged right. In the Hindi "digital arrest" call the red alert fires
at 17.7 s, before the caller says "digital arrest" (about 20 s) and long before he asks for money (29 s). A
genuine bank reminder that says "OTP" and "PIN" stays Safe the whole call. 343 offline tests.

**Languages.** Hindi, English, Bengali, Gujarati, Kannada, Malayalam, Marathi, Punjabi, Tamil, Telugu, plus
code-mixed Hinglish.

**Limits.** Uses Gnani's cloud APIs, not on-device. It doesn't sit inside the dialer or block calls; you put the
call on speaker. It won't catch every scam, and 5 calls is a small test. All demo calls are synthetic (AI voices,
made-up names).

**Next.** An Android app that hears the call directly (with consent), an alert to a family member, and more scam
scripts per language.

Built by **Aarush Shetty** (app, scam detection, UI and demo video) ·
Code: [github.com/AarushShetty346/gnani-voice-app](https://github.com/AarushShetty346/gnani-voice-app)
