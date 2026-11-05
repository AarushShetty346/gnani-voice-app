// Deterministic overlay timeline for the launch video. The renderer calls seek(t) for every frame and
// screenshots the page (transparent background), so nothing here may depend on real time.
// window.TL = [{id, start, end, html, cls, style, z, in:{type,dur}, out:{type,dur}, fx:{...}}]
(() => {
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const ease = (p) => 1 - Math.pow(1 - p, 3);                 // easeOutCubic
  const easeIO = (p) => (p < 0.5 ? 4 * p * p * p : 1 - Math.pow(-2 * p + 2, 3) / 2);
  const back = (p) => { const c = 1.6; return 1 + (c + 1) * Math.pow(p - 1, 3) + c * Math.pow(p - 1, 2); };

  const IN = {
    none: () => ({}),
    fade: (p) => ({ opacity: ease(p) }),
    rise: (p) => ({ opacity: ease(p), ty: (1 - ease(p)) * 28 }),
    drop: (p) => ({ opacity: ease(p), ty: -(1 - ease(p)) * 28 }),
    pop: (p) => ({ opacity: clamp(p * 2.2, 0, 1), scale: 0.82 + 0.18 * back(p) }),
    slam: (p) => ({ opacity: clamp(p * 3, 0, 1), scale: 1.35 - 0.35 * ease(p) }),
    wipe: (p) => ({ clip: `inset(0 ${(1 - easeIO(p)) * 100}% 0 0)` }),
    left: (p) => ({ opacity: ease(p), tx: -(1 - ease(p)) * 60 }),
  };
  const OUT = {
    none: () => ({}),
    fade: (p) => ({ opacity: ease(p) }),
    sink: (p) => ({ opacity: ease(p), ty: (1 - ease(p)) * 18 }),
    shrink: (p) => ({ opacity: ease(p), scale: 0.9 + 0.1 * ease(p) }),
  };

  // per-element effects driven by local time u (seconds since the element started)
  const FX = {
    // reveal words one by one: html must contain <span class="w">word</span> pieces
    words(el, u, fx) {
      const ws = el.querySelectorAll('.w');
      const per = fx.per || 0.12;
      ws.forEach((w, i) => {
        const p = clamp((u - i * per) / 0.18, 0, 1);
        w.style.opacity = String(ease(p));
        w.style.transform = `translateY(${(1 - ease(p)) * 14}px)`;
      });
      return [...ws].map((w) => w.style.opacity).join(',');
    },
    // count a number from a to b
    count(el, u, fx) {
      const p = easeIO(clamp((u - (fx.delay || 0)) / (fx.dur || 1), 0, 1));
      const v = Math.round(fx.from + (fx.to - fx.from) * p);
      const t = el.querySelector('.n');
      if (t) t.textContent = (fx.prefix || '') + v.toLocaleString('en-IN') + (fx.suffix || '');
      return String(v);
    },
    // a tap ripple: expanding ring + dot
    ripple(el, u) {
      const p = clamp(u / 0.55, 0, 1);
      const ring = el.querySelector('.ring');
      const dot = el.querySelector('.dot');
      if (ring) { ring.style.transform = `translate(-50%,-50%) scale(${0.4 + ease(p) * 1.4})`; ring.style.opacity = String(1 - p); }
      if (dot) { dot.style.opacity = String(clamp(1 - (u - 0.15) / 0.3, 0, 1)); }
      return p.toFixed(3);
    },
    // gentle breathing scale for emphasis
    pulse(el, u, fx) {
      const s = 1 + (fx.amp || 0.03) * Math.sin(u * Math.PI * 2 * (fx.hz || 1.4));
      el.style.setProperty('--pulse', String(s));
      return s.toFixed(3);
    },
    // phone buzz: small horizontal shake in bursts
    buzz(el, u, fx) {
      const period = fx.period || 1.0, on = fx.on || 0.45;
      const ph = u % period;
      const x = ph < on ? Math.sin(u * 90) * (fx.amp || 7) : 0;
      el.style.setProperty('--buzz', x.toFixed(1) + 'px');
      return x.toFixed(1);
    },
    // progress bar width 0 -> 100% over the element's life
    progress(el, u, fx) {
      const b = el.querySelector('.bar');
      const p = clamp(u / (fx.dur || 1), 0, 1);
      if (b) b.style.transform = `scaleX(${p})`;
      return p.toFixed(3);
    },
  };

  const items = [];
  function build() {
    const root = document.getElementById('stage');
    for (const d of window.TL) {
      const el = document.createElement('div');
      el.className = 'el ' + (d.cls || '');
      if (d.style) el.setAttribute('style', d.style);
      el.style.zIndex = String(d.z || 1);
      el.innerHTML = d.html || '';
      el.style.display = 'none';
      root.appendChild(el);
      items.push({ d, el });
    }
  }

  window.seek = (t) => {
    const key = [];
    for (const { d, el } of items) {
      if (t < d.start || t >= d.end) { if (el.style.display !== 'none') el.style.display = 'none'; continue; }
      el.style.display = '';
      const u = t - d.start;
      const i = d.in || { type: 'fade', dur: 0.25 };
      const o = d.out || { type: 'fade', dur: 0.2 };
      const a = (IN[i.type] || IN.fade)(clamp(u / (i.dur || 0.001), 0, 1));
      const b = (OUT[o.type] || OUT.fade)(clamp((d.end - t) / (o.dur || 0.001), 0, 1));
      const opacity = (a.opacity ?? 1) * (b.opacity ?? 1);
      const scale = (a.scale ?? 1) * (b.scale ?? 1);
      const tx = (a.tx || 0) + (b.tx || 0), ty = (a.ty || 0) + (b.ty || 0);
      el.style.opacity = opacity.toFixed(4);
      el.style.setProperty('--tx', tx.toFixed(2) + 'px');
      el.style.setProperty('--ty', ty.toFixed(2) + 'px');
      el.style.setProperty('--sc', scale.toFixed(4));
      el.style.clipPath = a.clip || '';
      let fxk = '';
      if (d.fx) for (const [name, cfg] of Object.entries(d.fx)) fxk += FX[name](el, u, cfg || {}) + ';';
      key.push(d.id + ':' + el.style.opacity + ':' + tx.toFixed(1) + ':' + ty.toFixed(1) + ':' + scale.toFixed(3) + ':' + (a.clip || '') + ':' + fxk);
    }
    return key.join('|');
  };

  window.ready = (async () => {
    build();
    // Show everything once so every font (and unicode subset) is requested before frame 0 is captured.
    for (const { el } of items) el.style.display = '';
    if (document.fonts) await document.fonts.ready;
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    for (const { el } of items) el.style.display = 'none';
    return true;
  })();
})();
