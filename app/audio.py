"""Audio helpers built on the ffmpeg CLI (sync; async callers wrap them in asyncio.to_thread).

Everything is normalised to mono signed 16-bit PCM. WAV headers are written by Python's
wave module (ffmpeg can't fix up WAV sizes when writing to a pipe).
"""
import io
import os
import subprocess
import sys
import tempfile
import wave
from array import array


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


def to_pcm16(raw: bytes, rate: int = 16000, max_s: float | None = None) -> bytes:
    """Any input → raw s16le mono at `rate`. max_s: decode at most this many seconds (a small file in a
    low-bitrate codec can hold hours of audio; this keeps memory and ffmpeg time bounded)."""
    pcm = _wav_pcm(raw, rate)
    if pcm is not None:
        return pcm if max_s is None else pcm[:int(max_s * rate) * 2]
    limit = ["-t", f"{max_s:.3f}"] if max_s is not None else []
    return _ffmpeg(["-i", "{in}", *limit, "-vn", "-ac", "1", "-ar", str(rate), "-f", "s16le",
                    "-acodec", "pcm_s16le", "pipe:1"], raw)


def to_wav(raw: bytes, rate: int = 16000, max_s: float | None = None) -> bytes:
    """Any input → mono s16 WAV at `rate` (at most max_s seconds when given)."""
    return _pcm_to_wav(to_pcm16(raw, rate, max_s), rate)


def duration_s(raw: bytes) -> float:
    info = _read_wav(raw)
    if info:
        ch, width, rate, frames = info
        return len(frames) // (ch * width) / rate
    return len(to_pcm16(raw, 16000)) / 32000


SEARCH_FRAC = 0.12     # look for a quiet cut point in the last 12% of each chunk (3 s of 25 s)
TAIL_FRAC = 0.04       # a final piece shorter than 4% of max_s (1 s of 25 s) joins the previous chunk
CUT_WIN_S = 0.02       # 20 ms energy windows


def _samples(pcm: bytes) -> array:
    a = array("h")
    a.frombytes(pcm[:len(pcm) // 2 * 2])
    if sys.byteorder == "big":
        a.byteswap()
    return a


def _quiet_cut(a: array, lo: int, hi: int, win: int) -> int:
    """Sample index in [lo, hi] with the least energy around it; ties go to the latest (longest chunk)."""
    best, best_e = hi, None
    c = hi
    while c >= lo:
        seg = a[max(0, c - win // 2):c + win // 2]
        e = sum(x * x for x in seg)
        if best_e is None or e < best_e:
            best, best_e = c, e
            if e == 0:
                break
        c -= win
    return best


def split_wav(raw: bytes, max_s: float = 25.0, rate: int = 16000) -> list[tuple[float, bytes]]:
    """Cut audio into consecutive WAV chunks of about max_s seconds: [(start_s, wav), ...].

    Each cut goes at the quietest 20 ms in the last ~12% before max_s, so a word is rarely split across
    two STT requests. A tiny last piece is merged into the previous chunk instead of costing an extra
    request, so a chunk can reach 1.04 * max_s (26 s for 25 s; Prisma REST takes 30 s)."""
    a = _samples(to_pcm16(raw, rate))
    n, limit = len(a), int(max_s * rate)
    win = max(1, int(CUT_WIN_S * rate))
    cuts, start = [0], 0
    while n - start > limit:
        hi = start + limit
        start = _quiet_cut(a, hi - int(limit * SEARCH_FRAC), hi, win)
        cuts.append(start)
    if len(cuts) > 1 and n - cuts[-1] < limit * TAIL_FRAC:
        cuts.pop()
    cuts.append(n)
    return [(s / rate, _pcm_to_wav(_le_bytes(a[s:e]), rate)) for s, e in zip(cuts, cuts[1:]) if e > s]


def _le_bytes(a: array) -> bytes:
    if sys.byteorder == "big":
        a = array("h", a)
        a.byteswap()
    return a.tobytes()


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
