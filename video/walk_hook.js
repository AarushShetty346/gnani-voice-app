// Injected (capture only, after hook.js) for the laptop walkthrough: draws a mouse cursor that follows the
// real (CDP-dispatched) mouse events, shows a ripple on each click, and logs when the microphone opens.
(() => {
  const kv = window.__kv;
  const now = () => performance.timeOrigin + performance.now();

  const gum = navigator.mediaDevices && navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
  if (gum) {
    navigator.mediaDevices.getUserMedia = async (c) => {
      const asked = now();
      const s = await gum(c);
      kv.events.push({ t: now(), type: 'mic', asked });
      return s;
    };
  }

  const css = `
    #__cur { position: fixed; left: 0; top: 0; width: 22px; height: 30px; z-index: 2147483647; pointer-events: none;
      transform: translate(-100px, -100px); filter: drop-shadow(0 1px 2px rgb(0 0 0 / .55)); transition: none; }
    #__cur svg { display: block; width: 22px; height: 30px; transform-origin: 3px 2px; transition: transform .12s ease; }
    #__cur.down svg { transform: scale(.86); }
    .__rip { position: fixed; z-index: 2147483646; pointer-events: none; width: 44px; height: 44px; margin: -22px 0 0 -22px;
      border-radius: 50%; border: 2.5px solid rgb(255 255 255 / .9); animation: __rip .55s ease-out forwards; }
    @keyframes __rip { from { transform: scale(.2); opacity: .95; } to { transform: scale(1.25); opacity: 0; } }`;
  // A standard arrow pointer: white fill, dark outline.
  const svg = '<svg viewBox="0 0 22 30" xmlns="http://www.w3.org/2000/svg"><path d="M2 2v22.5l5.6-5.3 3.7 8.6 3.9-1.7' +
    '-3.7-8.4h7.8z" fill="#fff" stroke="#111" stroke-width="1.6" stroke-linejoin="round"/></svg>';

  const mount = () => {
    const st = document.createElement('style');
    st.textContent = css;
    document.head.appendChild(st);
    const cur = document.createElement('div');
    cur.id = '__cur';
    cur.innerHTML = svg;
    document.body.appendChild(cur);
    const place = (x, y) => { cur.style.transform = `translate(${x - 2}px, ${y - 2}px)`; };
    addEventListener('mousemove', (e) => place(e.clientX, e.clientY), true);
    addEventListener('mousedown', (e) => {
      place(e.clientX, e.clientY);
      cur.classList.add('down');
      const r = document.createElement('div');
      r.className = '__rip';
      r.style.left = e.clientX + 'px';
      r.style.top = e.clientY + 'px';
      document.body.appendChild(r);
      setTimeout(() => r.remove(), 700);
    }, true);
    addEventListener('mouseup', () => cur.classList.remove('down'), true);
    kv.cursorAt = place;
    // A click ripple without a real press (for native <select>s, whose popup a headless capture can't show).
    kv.ripple = (x, y) => {
      cur.classList.add('down');
      setTimeout(() => cur.classList.remove('down'), 140);
      const r = document.createElement('div');
      r.className = '__rip';
      r.style.left = x + 'px';
      r.style.top = y + 'px';
      document.body.appendChild(r);
      setTimeout(() => r.remove(), 700);
    };
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount);
  else mount();

  // Smooth, eased page scroll (a person scrolling slowly), resolves when done.
  kv.scrollTo = (y, ms) => new Promise((resolve) => {
    const y0 = scrollY;
    const max = document.documentElement.scrollHeight - innerHeight;
    const y1 = Math.max(0, Math.min(max, y));
    const t0 = performance.now();
    const ease = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
    const step = () => {
      const t = Math.min(1, (performance.now() - t0) / ms);
      window.scrollTo({ top: y0 + (y1 - y0) * ease(t), behavior: 'instant' });
      if (t < 1) requestAnimationFrame(step); else resolve(y1);
    };
    requestAnimationFrame(step);
  });
})();
