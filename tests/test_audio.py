"""app.audio with real ffmpeg on generated sine tones."""
import io
import subprocess
import wave

import pytest

from app import audio


def sine(seconds: float, rate: int = 44100, channels: int = 2, fmt: str = "wav", freq: int = 440) -> bytes:
    """Generate a tone with ffmpeg's lavfi sine source."""
    codec = ["-c:a", "libmp3lame"] if fmt == "mp3" else []
    out = subprocess.run(
        ["ffmpeg", "-hide_banner", "-loglevel", "error", "-f", "lavfi",
         "-i", f"sine=frequency={freq}:duration={seconds}:sample_rate={rate}",
         "-ac", str(channels), *codec, "-f", fmt, "pipe:1"],
        capture_output=True, check=True)
    return out.stdout


def wav_info(data: bytes) -> tuple[int, int, int, float]:
    with wave.open(io.BytesIO(data)) as w:
        return w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes() / w.getframerate()


def test_to_wav_converts_any_input():
    ch, width, rate, dur = wav_info(audio.to_wav(sine(1.5, fmt="mp3")))
    assert (ch, width, rate) == (1, 2, 16000)
    assert dur == pytest.approx(1.5, abs=0.1)              # mp3 adds a little padding


def test_to_pcm16_length():
    pcm = audio.to_pcm16(sine(2.0), rate=8000)
    assert len(pcm) == 2 * 8000 * 2


def test_duration_s():
    assert audio.duration_s(sine(1.25)) == pytest.approx(1.25, abs=0.01)
    assert audio.duration_s(sine(2.0, fmt="mp3")) == pytest.approx(2.0, abs=0.1)


def pcm_of(wav: bytes) -> bytes:
    with wave.open(io.BytesIO(wav)) as w:
        return w.readframes(w.getnframes())


def test_split_wav_chunks():
    """Silence everywhere: cuts land exactly on the limit; chunks rejoin to the original audio."""
    silent = audio._pcm_to_wav(bytes(2 * (16000 * 5 + 8000)), 16000)
    chunks = audio.split_wav(silent, max_s=2.0)
    assert [start for start, _ in chunks] == [0.0, 2.0, 4.0]
    assert [wav_info(w)[3] for _, w in chunks] == pytest.approx([2.0, 2.0, 1.5], abs=0.01)
    assert all(wav_info(w)[:3] == (1, 2, 16000) for _, w in chunks)
    tone = sine(5.5)
    parts = audio.split_wav(tone, max_s=2.0)
    assert all(wav_info(w)[3] <= 2.0 for _, w in parts)
    assert b"".join(pcm_of(w) for _, w in parts) == audio.to_pcm16(tone)


def test_split_wav_cuts_in_a_pause_not_a_word():
    """A pause just before the limit is where the cut goes, so no word is split across requests."""
    joined, spans = audio.concat_wavs([sine(1.8, freq=300), sine(1.5, freq=500)], gap_s=0.1)
    (start, _), (second, rest) = audio.split_wav(joined, max_s=2.0)
    assert spans[0][1] <= second <= spans[1][0]                # inside the 1.8-1.9 s gap
    assert wav_info(rest)[3] == pytest.approx(3.4 - second, abs=0.01)


def test_split_wav_merges_a_tiny_tail():
    """2.05 s at max 2 s: no 50 ms third request; the last chunk is at most 4% longer."""
    chunks = audio.split_wav(audio._pcm_to_wav(bytes(2 * int(16000 * 4.05)), 16000), max_s=2.0)
    assert [s for s, _ in chunks] == [0.0, 2.0]
    assert wav_info(chunks[-1][1])[3] == pytest.approx(2.05, abs=0.01)


def test_to_wav_max_s_caps_decoding():
    assert wav_info(audio.to_wav(sine(3.0, fmt="mp3"), max_s=1.0))[3] == pytest.approx(1.0, abs=0.05)
    assert wav_info(audio.to_wav(sine(3.0), max_s=1.0))[3] == pytest.approx(1.0, abs=0.01)   # WAV fast path


def test_pcm_frames_pads_last():
    frames = audio.pcm_frames(b"\x01" * 2500)
    assert [len(f) for f in frames] == [1024, 1024, 1024]
    assert frames[-1] == b"\x01" * 452 + b"\x00" * 572
    assert audio.pcm_frames(b"") == []


def test_phone_line_output():
    out = audio.phone_line(audio.to_wav(sine(1.0, freq=1000)))
    ch, width, rate, dur = wav_info(out)
    assert (ch, width, rate) == (1, 2, 16000)
    assert dur == pytest.approx(1.0, abs=0.05)
    assert wav_info(audio.phone_line(sine(0.5), noise=0))[2] == 16000


def test_concat_offsets():
    joined, spans = audio.concat_wavs([sine(1.0), sine(0.5, fmt="mp3"), audio.to_wav(sine(2.0))], gap_s=0.5)
    (s1, e1), (s2, e2), (s3, e3) = spans
    assert (s1, e1) == (0.0, pytest.approx(1.0))
    assert s2 == pytest.approx(1.5) and e2 == pytest.approx(2.0, abs=0.1)
    assert s3 == pytest.approx(e2 + 0.5) and e3 == pytest.approx(s3 + 2.0)
    assert wav_info(joined)[3] == pytest.approx(e3)


def test_bad_input_raises_audio_error():
    with pytest.raises(audio.AudioError):
        audio.to_wav(b"definitely not audio")
    with pytest.raises(audio.AudioError):
        audio.to_wav(b"")
