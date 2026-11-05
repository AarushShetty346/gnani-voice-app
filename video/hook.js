// Injected before the app loads (capture only). Logs server messages and audio starts with wall-clock
// times, and records exactly what the page plays (call audio + Timbre warnings, with the app's ducking).
(() => {
  const now = () => performance.timeOrigin + performance.now();      // ms since epoch
  const kv = (window.__kv = { events: [], rec: null, voiceUntil: 0 });
  const ev = (type, data) => kv.events.push(Object.assign({ t: now(), type }, data));

  const WS = window.WebSocket;
  window.WebSocket = class extends WS {
    constructor(...a) {
      super(...a);
      this.addEventListener('message', (e) => {
        if (typeof e.data !== 'string') return;
        try {
          const m = JSON.parse(e.data);
          const c = Object.assign({}, m);
          if (c.audio_b64) c.audio_b64 = c.audio_b64.length;
          ev('ws', { m: c });
        } catch (_) { /* not JSON */ }
      });
    }
  };

  const connect = AudioNode.prototype.connect;
  function tap(ctx) {
    if (kv.rec && kv.rec.ctx === ctx) return kv.rec;
    const dest = ctx.createMediaStreamDestination();
    const mr = new MediaRecorder(dest.stream, { mimeType: 'audio/webm;codecs=opus', audioBitsPerSecond: 256000 });
    const chunks = [];
    mr.ondataavailable = (e) => { if (e.data && e.data.size) chunks.push(e.data); };
    kv.rec = { ctx, dest, mr, chunks, started: null };
    mr.start(500);
    kv.rec.started = now();
    kv.rec.ctxStart = ctx.currentTime;
    ev('rec-start', { ctxTime: ctx.currentTime });
    // sample the audio clock against wall time (it may start running a moment after creation)
    setInterval(() => { if (ctx.state === 'running') ev('ctx', { ctxTime: ctx.currentTime }); }, 500);
    return kv.rec;
  }
  AudioNode.prototype.connect = function (target, ...rest) {
    const r = connect.call(this, target, ...rest);
    if (typeof AudioDestinationNode !== 'undefined' && target instanceof AudioDestinationNode) {
      connect.call(this, tap(this.context).dest);
    }
    return r;
  };

  const start = AudioBufferSourceNode.prototype.start;
  AudioBufferSourceNode.prototype.start = function (when, ...rest) {
    const ctx = this.context;
    const dur = this.buffer ? this.buffer.duration : 0;
    const at = now() + Math.max(0, ((when || 0) - ctx.currentTime)) * 1000;
    ev('source', { at, dur, when: when || 0, ctxTime: ctx.currentTime });
    if (dur < 20) kv.voiceUntil = Math.max(kv.voiceUntil, at + dur * 1000);   // a warning clip, not the call
    return start.call(this, when, ...rest);
  };

  kv.stopRec = () => new Promise((resolve) => {
    const r = kv.rec;
    if (!r) { resolve(null); return; }
    r.mr.onstop = async () => {
      const blob = new Blob(r.chunks, { type: 'audio/webm' });
      const bytes = new Uint8Array(await blob.arrayBuffer());
      let s = '';
      for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
      resolve(btoa(s));
    };
    r.mr.stop();
  });
})();
