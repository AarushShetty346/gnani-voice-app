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


def test_split_wav_chunks():
    chunks = audio.split_wav(sine(5.5), max_s=2.0)
    assert [start for start, _ in chunks] == [0.0, 2.0, 4.0]
    lengths = [wav_info(w)[3] for _, w in chunks]
    assert lengths == pytest.approx([2.0, 2.0, 1.5], abs=0.01)
    assert all(wav_info(w)[:3] == (1, 2, 16000) for _, w in chunks)


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
