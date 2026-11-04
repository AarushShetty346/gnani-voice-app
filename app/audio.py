"""Audio helpers built on the ffmpeg CLI (sync; async callers wrap them in asyncio.to_thread).

Everything is normalised to mono signed 16-bit PCM. WAV headers are written by Python's
wave module (ffmpeg can't fix up WAV sizes when writing to a pipe).
"""
import io
import os
import subprocess
import tempfile
import wave


class AudioError(Exception):
    pass


def _ffmpeg(args: list[str], raw: bytes | None = None) -> bytes:
    """Run ffmpeg with the input written to a temp file (some containers, e.g. m4a, need seeking).
    The literal "{in}" in args is replaced by that file's path. Returns stdout."""
    path = None
    try:
        if raw is not None:
            if not raw:
                raise AudioError("empty audio")
            fd, path = tempfile.mkstemp(suffix=".bin", prefix="kavach-")
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
            args = [path if a == "{in}" else a for a in args]
        proc = subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin", *args],
                              capture_output=True, timeout=300)
    except FileNotFoundError as e:
        raise AudioError("ffmpeg not found on PATH") from e
    except subprocess.TimeoutExpired as e:
        raise AudioError("ffmpeg timed out") from e
    finally:
        if path:
            os.unlink(path)
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise AudioError(f"ffmpeg failed: {msg[-1] if msg else proc.returncode}")
    return proc.stdout


def _read_wav(raw: bytes) -> tuple[int, int, int, bytes] | None:
    """(channels, sample_width, rate, frames) of a plain PCM WAV, else None.
    Reads to the end of the data rather than trusting the header size: WAVs streamed
    through a pipe (e.g. by ffmpeg) carry a placeholder size."""
    try:
        with wave.open(io.BytesIO(raw)) as w:
            frames = w.readframes(2**31 - 1)
            if frames:
                return w.getnchannels(), w.getsampwidth(), w.getframerate(), frames
    except (wave.Error, EOFError):
        pass
    return None


def _wav_pcm(raw: bytes, rate: int) -> bytes | None:
    """Fast path: PCM from a WAV that is already mono s16 at `rate`, else None."""
    info = _read_wav(raw)
    if info and info[:3] == (1, 2, rate):
        return info[3]
    return None


def _pcm_to_wav(pcm: bytes, rate: int) -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm)
    return buf.getvalue()


def to_pcm16(raw: bytes, rate: int = 16000) -> bytes:
    """Any input → raw s16le mono at `rate`."""
    pcm = _wav_pcm(raw, rate)
    if pcm is not None:
        return pcm
    return _ffmpeg(["-i", "{in}", "-vn", "-ac", "1", "-ar", str(rate), "-f", "s16le", "-acodec", "pcm_s16le",
                    "pipe:1"], raw)


def to_wav(raw: bytes, rate: int = 16000) -> bytes:
    """Any input → mono s16 WAV at `rate`."""
    return _pcm_to_wav(to_pcm16(raw, rate), rate)


def duration_s(raw: bytes) -> float:
    info = _read_wav(raw)
    if info:
        ch, width, rate, frames = info
        return len(frames) // (ch * width) / rate
    return len(to_pcm16(raw, 16000)) / 32000


def split_wav(raw: bytes, max_s: float = 25.0, rate: int = 16000) -> list[tuple[float, bytes]]:
    """Cut audio into consecutive WAV chunks of at most max_s seconds: [(start_s, wav), ...]."""
    pcm = to_pcm16(raw, rate)
    step = int(max_s * rate) * 2                     # bytes per chunk (2 bytes per sample)
    return [(i / (2 * rate), _pcm_to_wav(pcm[i:i + step], rate)) for i in range(0, len(pcm), step)]


def phone_line(wav: bytes, noise: float = 0.015) -> bytes:
    """Make clean speech sound like a phone call: 8 kHz, 300-3400 Hz band, light hiss.
    Returns 16 kHz mono WAV (what the browser and Gnani stream use)."""
    voice = "[0:a]aformat=channel_layouts=mono,aresample=8000,highpass=f=300,lowpass=f=3400"
    if noise > 0:
        graph = (f"{voice}[v];anoisesrc=color=white:amplitude={noise}:sample_rate=8000[n];"
                 "[v][n]amix=inputs=2:duration=first:normalize=0,aresample=16000")
    else:
        graph = f"{voice},aresample=16000"
    pcm = _ffmpeg(["-i", "{in}", "-filter_complex", graph, "-ac", "1", "-ar", "16000",
                   "-f", "s16le", "-acodec", "pcm_s16le", "pipe:1"], wav)
    return _pcm_to_wav(pcm, 16000)


def pcm_frames(pcm: bytes, size: int = 1024) -> list[bytes]:
    """Split PCM into fixed-size frames, zero-padding the last one."""
    frames = [pcm[i:i + size] for i in range(0, len(pcm), size)]
    if frames and len(frames[-1]) < size:
        frames[-1] = frames[-1].ljust(size, b"\x00")
    return frames


def concat_wavs(wavs: list[bytes], gap_s: float = 0.45, rate: int = 16000) -> tuple[bytes, list[tuple[float, float]]]:
    """Join clips with `gap_s` of silence between them. Returns (wav, [(start_s, end_s) per clip])."""
    gap = b"\x00\x00" * int(gap_s * rate)
    parts, spans, pos = [], [], 0                    # pos counts bytes
    for i, clip in enumerate(wavs):
        if i:
            parts.append(gap)
            pos += len(gap)
        pcm = to_pcm16(clip, rate)
        parts.append(pcm)
        spans.append((pos / (2 * rate), (pos + len(pcm)) / (2 * rate)))
        pos += len(pcm)
    return _pcm_to_wav(b"".join(parts), rate), spans
