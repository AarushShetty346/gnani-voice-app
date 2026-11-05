/* ScamLingo: AudioWorklet that turns whatever the AudioContext runs at (usually 48000 or 44100 Hz)
 * into 16 kHz mono signed 16-bit little-endian PCM, and posts it to the main thread as ArrayBuffers of
 * exactly 512 samples (1024 bytes). That is the frame size Gnani's realtime STT expects (32 ms each).
 *
 * Downsampling: channels are averaged to mono, run through two cascaded one-pole low-pass filters
 * (cutoff about 7.2 kHz, below the 8 kHz Nyquist of the 16 kHz output), then box-averaged over each
 * output sample's span of input samples (handles non-integer ratios such as 44100 / 16000).
 * If the context happens to run below 16 kHz, it upsamples with linear interpolation instead.
 *
 * When the input has no channels (e.g. a paused media element), it treats the block as silence so
 * frames keep flowing at real-time cadence.
 *
 * Main thread: node.port.postMessage({type: "stop"}) ends processing.
 */
const FRAME_SAMPLES = 512;
const FRAME_BYTES = FRAME_SAMPLES * 2;

class PcmDownsampler extends AudioWorkletProcessor {
  constructor(options) {
    super();
    const opts = (options && options.processorOptions) || {};
    this.target = opts.targetRate || 16000;
    this.ratio = sampleRate / this.target;           // input samples per output sample
    const fc = Math.min(this.target * 0.45, sampleRate * 0.45);
    this.alpha = 1 - Math.exp((-2 * Math.PI * fc) / sampleRate);
    this.lp1 = 0;
    this.lp2 = 0;
    this.acc = 0;     // box-average accumulator
    this.n = 0;
    this.phase = 0;   // fractional position inside the current output sample's span
    this.prev = 0;    // previous input sample (upsampling path)
    this.active = true;
    this.newFrame();
    this.port.onmessage = (e) => {
      if (e.data && e.data.type === 'stop') this.active = false;
    };
  }

  newFrame() {
    this.buf = new ArrayBuffer(FRAME_BYTES);
    this.view = new DataView(this.buf);
    this.fill = 0;
  }

  push(sample) {
    let s = sample;
    if (s > 1) s = 1;
    else if (s < -1) s = -1;
    const v = s < 0 ? Math.round(s * 0x8000) : Math.round(s * 0x7fff);
    this.view.setInt16(this.fill * 2, v, true); // little-endian
    this.fill += 1;
    if (this.fill === FRAME_SAMPLES) {
      const out = this.buf;
      this.newFrame();
      this.port.postMessage(out, [out]);
    }
  }

  consume(x) {
    if (this.ratio >= 1) {
      // low-pass, then average every `ratio` input samples into one output sample
      this.lp1 += this.alpha * (x - this.lp1);
      this.lp2 += this.alpha * (this.lp1 - this.lp2);
      this.acc += this.lp2;
      this.n += 1;
      this.phase += 1;
      if (this.phase >= this.ratio) {
        this.phase -= this.ratio;
        this.push(this.acc / this.n);
        this.acc = 0;
        this.n = 0;
      }
    } else {
      // upsample (context slower than 16 kHz): linear interpolation between prev and x
      while (this.phase < 1) {
        this.push(this.prev + (x - this.prev) * this.phase);
        this.phase += this.ratio;
      }
      this.phase -= 1;
      this.prev = x;
    }
  }

  process(inputs) {
    if (!this.active) return false;
    const input = inputs[0];
    if (!input || input.length === 0) {
      for (let i = 0; i < 128; i++) this.consume(0); // keep real-time cadence with silence
      return true;
    }
    const channels = input.length;
    const len = input[0].length;
    if (channels === 1) {
      const ch = input[0];
      for (let i = 0; i < len; i++) this.consume(ch[i]);
    } else {
      for (let i = 0; i < len; i++) {
        let sum = 0;
        for (let c = 0; c < channels; c++) sum += input[c][i];
        this.consume(sum / channels);
      }
    }
    return true;
  }
}

registerProcessor('pcm-downsampler', PcmDownsampler);
