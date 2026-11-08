# ScamLingo: 2–3 minute walkthrough (as built)

**Video:** `video/out/scamlingo-walkthrough.mp4`. It runs just under 3:00 at 1920×1080 (16:9 laptop view) and
30 fps. This is the one for the form's video field and for YouTube. The 60 s reel (`scamlingo-launch.mp4`) stays
the LinkedIn video.

**To rebuild:**
```
.venv\Scripts\python video\walk_capture.py scam|safe|rec    # live takes (spends Gnani credits)
.venv\Scripts\python video\walk_narration.py                 # narrator lines (Timbre) + Prisma check
.venv\Scripts\python video\walk_edit.py                      # the edit
```

## How it's made

- **Real app on live Gnani.**
  - The two calls run through the **Live call** tab. The demo call audio is fed into Chrome's fake microphone,
    which stands in for a phone on speaker. Gnani Prisma transcribes it live, the app scores it, and Timbre speaks
    the real warnings.
  - The recording is uploaded through the real file chooser.
  - Live mode labels each line "On the call", because the app can't know who is speaking. The subtitles say who
    is talking.
- **Cursor.** It's drawn inside the page from the real mouse events (`walk_hook.js`). It moves at about 1 s per
  move, on a gentle arc, with a click ripple.
  - Native dropdowns can't be captured headless, so picking Hindi shows the ripple and then the new value.
- **Two voices.**
  - The narrator is Timbre **Shubham** (male, speed 0.92).
  - The app's warnings are its real voice, **Shivani** (female).
  - Every narrator line is checked with a Prisma round-trip (`walk_narration.py`).
- **Pauses.** A "Paused" tag shows in the browser bar while the frame is frozen for the narrator. The call audio
  pauses too.
  - A few silent stretches are skipped with a short fade: "Connecting…", the middle of the genuine call, and the
    wait for transcription.
- **Subtitles.** They sit in the strip under the browser window, one line at a time. Call lines carry a
  "Caller · Hindi" or "You · Hindi" tag. They're hidden while the app's warning voice speaks.
- **Labels.** A disclosure pill reading "Synthetic demo call · AI voices, made-up names" sits in the browser bar
  during calls.

## What this take did (scam call, live mode)

Live mode differs from the Demo calls tab. This time it went straight to red, with no amber step, and it
missed the victim's "I never sent a parcel" line.

All times are call time:
- 0:06: the first line is transcribed. The "Fake official" chip shows, but the call stays Safe at 30.
- 12.0 s: the score goes to 85, "Scam likely", while he's still on the parcel / drugs line. An AI review agreed.
- 14.1 s: the red alert, spoken.
- About 20 s: he first says "digital arrest".
- 22.4 s: Got it.
- 26.1 s: Stop.
- 29.1 s: where his money demand would have started.

The genuine bank call stayed Safe the whole time (at most 15/100), and the verdict was "Looks safe". The uploaded
English KYC call came back as Scam, with "read it out" highlighted.

## Narration

| | Line |
|---|---|
| Intro | This is Scam Lingo. It listens to a phone call with you, and warns you out loud if it sounds like a scam. In the next two minutes, watch it catch a scam call live, and stay quiet on a genuine one. |
| Set up | Say a call feels off. Put your phone on speaker, and open Scam Lingo on your laptop. · First, choose the language you want your warnings in. I'll keep English. · Then, the language of the call. This caller speaks Hindi. · Now, click Start listening. |
| Pause 1 | Gnani Prisma is writing down every word. It already spotted a fake police officer. But one sign isn't enough, so it stays calm. |
| Pause 2 | Now it says scam likely. Before he has even said digital arrest, or asked for a single rupee. |
| (Spoken alert plays in full) | |
| Pause 3 | That's Gnani Timbre, warning you out loud. So you hang up. |
| After Stop | He would have asked for your money just a few seconds later. |
| After the call | When the call ends, you get a plain summary, and what to do next. · And one click shares all of this with your family, on WhatsApp. |
| Genuine call | But does it panic on every call that mentions an OTP? Here's a genuine bank reminder, also in Hindi. · (pause) She said OTP and PIN, but only to warn you never to share them. It can tell advice from a request. So, it stays safe. |
| Recording | Already took the call, and recorded it? · Open Recording, and choose the file. · Gnani Prisma transcribes the whole call. · And Scam Lingo points out exactly where they asked for your OTP. |
| Close | Use it live, with your phone on speaker. Or check a recording. And it works in ten Indian languages. Hindi, English, Bengali, Gujarati, Kannada, Malayalam, Marathi, Punjabi, Tamil and Telugu. |
