# Scam Kavach launch kit

Video: `video/out/scam-kavach-launch.mp4` (1080×1350, 30 fps, under 60 s, captions burned in, −14 LUFS).
Rebuild it with `.venv\Scripts\python video\launch.py` (needs the captures in `video/out/cap/`).

**Before posting**

- LinkedIn: type `@Gnani.ai` and pick the company page from the dropdown (it should link to
  linkedin.com/company/gnani-ai). Upload the mp4 natively, not as a YouTube link. Pick the first frame as the
  cover ("My app caught this mid-call.").
- X: the handle is `@GnaniAi`. Post the video natively. Re-count characters after any edit (limit 280).
- Both posts must end with **#GnaniAI #GreatIndianAIInternshipChallenge**.
- First hour matters most: reply to every comment, and repost from your own account later in the day.
- The calls in the video are synthetic (AI voices, made-up names). Never describe them as a real incident.

## LinkedIn post

```text
A fake "cyber crime inspector" calls. Before he says "digital arrest" or asks for a rupee, my app cuts in out loud: "Stop! This looks like a scam call."

I built Scam Kavach for the Great Indian AI Internship Challenge by @Gnani.ai.

How it works:
→ Put a suspicious call on speaker next to Kavach, a web app in the browser.
→ Gnani Prisma v3.0 (real-time speech-to-text) transcribes it live, Hinglish and code-mixed speech included.
→ Every sentence is checked for 8 scam signals (OTP or PIN asks, fake police or bank staff, "digital arrest", account threats, payment asks, remote-access apps like AnyDesk, pressure and secrecy, job or prize bait), plus an optional LLM second opinion.
→ At high risk the screen goes red and Gnani Timbre v3.0 speaks the warning, in English or in the caller's language.
→ After the call you get a plain-language summary (LLM-written when the LLM is on) to forward to family on WhatsApp, with the 1930 helpline.

What I measured on live Gnani: 5 demo calls, 5/5 judged right. In the Kannada call the screen went red about 1 second after the threat. A bank reminder that says "the bank never asks for an OTP or PIN" stayed Safe the whole call.

Honest limits: it uses Gnani's cloud APIs, not on-device. It isn't part of your dialer and doesn't block calls; you put the call on speaker. It won't catch every scam, and 5 calls is a small test. The calls in the video are synthetic: AI voices, made-up names.

Why I built it: Indians reported losing about ₹22,800 crore to cyber fraud in 2024 (I4C data, shared by MHA via PIB). Lost money? Call 1930 or report at cybercrime.gov.in.

Has your family got a call like this? Tell me in the comments, and send this to whoever at home picks up every call.

#VoiceAI #BuildInPublic #GnaniAI #GreatIndianAIInternshipChallenge
```

## X post

```text
A fake "police officer" calls. Before he asks for a rupee, my app says out loud: "Stop! This looks like a scam call."

Scam Kavach: built on @GnaniAi Prisma v3.0 + Timbre v3.0. Warns in the caller's language too. Demo calls: synthetic.

#GnaniAI #GreatIndianAIInternshipChallenge
```

## X thread (optional replies under the post)

1. ```text
   How it works: put a suspicious call on speaker next to Kavach, a web app. Gnani Prisma v3.0 transcribes it live, every sentence is checked for 8 scam signals (plus an optional LLM check), and at high risk the screen goes red while Gnani Timbre v3.0 speaks the warning.
   ```
2. ```text
   Tested on live Gnani: 5/5 demo calls judged right. A bank reminder saying "the bank never asks for an OTP or PIN" stayed Safe. Small test, not a guarantee. It doesn't block calls or run offline.
   ```
3. ```text
   Lost money to a scam? Call 1930 or report at cybercrime.gov.in. Has your family got a call like this? Reply and tell me. #GnaniAI #GreatIndianAIInternshipChallenge
   ```

## Facts behind the claims

Call times are seconds into each demo call, from the capture logs in `video/out/cap/*/clip.json` and the
line timings in `demo/audio/manifest.json`.

| Claim | Evidence |
|---|---|
| Red before the caller says "digital arrest" | Hindi call: risk turns red at 17.6 s and the red alert fires at 17.7 s; he says "digital arrest" at about 20.3–21.7 s. |
| Hung up before the money ask | "Got it" tapped at 24.9 s, Stop at 25.9 s; the money-ask line starts at 29.1 s. |
| Kannada: red about 1 second after the threat | The threat ("power will be cut tonight") ends at 14.8 s; risk turns red at 15.9 s, alert at 16.0 s (1.1–1.3 s). |
| Bank reminder stays Safe | Score never above 5/100, no warning fired, verdict "Looks safe". (It shows a "Fake official" chip at 5/100: the bank introduces itself.) |
| 5/5 demo calls judged right | The five live captures on real Gnani (Hindi digital arrest, English KYC, Kannada electricity, Tamil job scam, Hindi bank reminder) all got the right verdict; the live eval (`scripts/live_eval.py`) passed 5/5 on 5 Nov. |
| ₹22,800 crore reported lost in 2024 | I4C (NCRP complaints) data, MHA reply in Parliament, PIB release 2226441. |
