/* Scam Kavach frontend. Vanilla JS, no libraries.
 *
 * Server text is never put into innerHTML: every transcript, alert, summary and status string is
 * inserted with textContent / text nodes. Flag highlights are built from start/end offsets as DOM nodes.
 */
'use strict';

(() => {
  // ---------------------------------------------------------------- constants
  const FRAME_BYTES = 1024;          // 512 samples s16le @ 16 kHz = 32 ms
  const FRAME_MS = 32;
  const MAX_SESSION_MS = 15 * 60 * 1000;
  const SUMMARY_WAIT_MS = 25000;     // after "stop": server waits <= 3 s + LLM summary (<= 20 s)
  const CONNECT_TIMEOUT_MS = 10000;

  const LEVELS = {
    idle: { en: 'Not listening', hi: 'अभी सुन नहीं रहा' },
    safe: { en: 'Safe', hi: 'सुरक्षित' },
    caution: { en: 'Be careful', hi: 'सावधान रहें' },
    danger: { en: 'Scam likely', hi: 'धोखे की आशंका' },
  };
  const LEVEL_RANK = { idle: 0, safe: 1, caution: 2, danger: 3 };

  const CATS = {
    otp_request: { en: 'Asks for OTP', hi: 'OTP माँगना' },
    impersonation: { en: 'Fake official', hi: 'नकली अधिकारी' },
    digital_arrest: { en: 'Digital arrest', hi: 'डिजिटल अरेस्ट' },
    account_threat: { en: 'Account threat', hi: 'खाता बंद करने की धमकी' },
    payment_request: { en: 'Asks for money', hi: 'पैसे की माँग' },
    remote_access: { en: 'Remote-access app', hi: 'रिमोट ऐप' },
    urgency_secrecy: { en: 'Pressure and secrecy', hi: 'जल्दबाज़ी और राज़' },
    prize_job_offer: { en: 'Prize or job lure', hi: 'इनाम या नौकरी का लालच' },
  };

  const VERDICTS = {
    scam: { en: 'Scam', hi: 'धोखा', level: 'danger' },
    suspicious: { en: 'Suspicious', hi: 'संदिग्ध', level: 'caution' },
    safe: { en: 'Looks safe', hi: 'सुरक्षित लगती है', level: 'safe' },
  };

  const FALLBACK_LANGS = {
    'hi-IN': { name: 'Hindi', native: 'हिन्दी' },
    'en-IN': { name: 'English', native: 'English' },
    'bn-IN': { name: 'Bengali', native: 'বাংলা' },
    'gu-IN': { name: 'Gujarati', native: 'ગુજરાતી' },
    'kn-IN': { name: 'Kannada', native: 'ಕನ್ನಡ' },
    'ml-IN': { name: 'Malayalam', native: 'മലയാളം' },
    'mr-IN': { name: 'Marathi', native: 'मराठी' },
    'pa-IN': { name: 'Punjabi', native: 'ਪੰਜਾਬੀ' },
    'ta-IN': { name: 'Tamil', native: 'தமிழ்' },
    'te-IN': { name: 'Telugu', native: 'తెలుగు' },
  };

  const reducedMotion = () => window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ---------------------------------------------------------------- tiny DOM helpers
  const $ = (id) => document.getElementById(id);

  function el(tag, props, ...children) {
    const n = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v == null || v === false) continue;
        if (k === 'class') n.className = v;
        else if (k === 'text') n.textContent = String(v);
        else if (k === 'dataset') Object.assign(n.dataset, v);
        else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2), v);
        else n.setAttribute(k, v === true ? '' : String(v));
      }
    }
    for (const c of children.flat()) {
      if (c == null || c === false) continue;
      n.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return n;
  }

  function icon(name) {
    const NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('class', 'ic');
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS(NS, 'use');
    use.setAttribute('href', '#i-' + name);
    svg.append(use);
    return svg;
  }

  const validLang = (code) => (typeof code === 'string' && /^[a-z]{2,3}(-[A-Za-z]{2})?$/.test(code) ? code : null);
  const langs = () => (S.status && S.status.languages && typeof S.status.languages === 'object' ? S.status.languages : FALLBACK_LANGS);
  const langNative = (code) => {
    const L = code && langs()[code];
    return L ? (L.native || L.name || code) : (code || '');
  };
  const catLabel = (key) => {
    const c = CATS[key];
    if (c) return c;
    const pretty = String(key || 'warning').replace(/_/g, ' ');
    return { en: pretty.charAt(0).toUpperCase() + pretty.slice(1), hi: '' };
  };
  const stripTags = (t) => String(t || '').replace(/<\/?[a-z_ -]{1,24}>/gi, ' ').replace(/\s{2,}/g, ' ').trim();
  const fmtTime = (sec) => {
    const s = Math.max(0, Math.floor(sec || 0));
    return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
  };
  const clamp = (v, a, b) => Math.min(b, Math.max(a, v));

  // ---------------------------------------------------------------- state
  const S = {
    status: null,
    demos: [],
    tab: 'live',
    session: null,       // current live/demo session (see startSession)
    seq: 0,
    items: new Map(),    // transcript index -> <li>
    risk: { score: 0, level: 'idle' },
    shownScore: 0,
    analyzing: null,     // AbortController for /api/analyze
    file: null,
    alertAudio: null,
    lastAlert: null,
  };

  // ---------------------------------------------------------------- status line
  async function loadStatus() {
    const box = $('status');
    try {
      const r = await fetch('/api/status', { cache: 'no-store' });
      if (!r.ok) throw new Error(String(r.status));
      S.status = await r.json();
      box.replaceChildren(
        el('span', {
          class: 'pill ' + (S.status.gnani_mock ? 'pill-mock' : 'pill-live'),
          title: S.status.gnani_mock ? 'No Gnani API key: speech is simulated' : 'Gnani Prisma v3.0 speech-to-text is live',
        }, S.status.gnani_mock ? 'Gnani: mock' : 'Gnani: live'),
        el('span', {
          class: 'pill ' + (S.status.llm_mock ? 'pill-mock' : 'pill-live'),
          title: S.status.llm_mock ? 'No LLM key: rule-based detection only' : 'Rules plus LLM review',
        }, S.status.llm_mock ? 'LLM: off (rules)' : 'LLM: on'),
      );
      if (S.status.gnani_mock) {
        $('liveHint').textContent = 'Mock mode: no Gnani key, so Kavach plays a scripted sample call instead of transcribing your mic.';
      }
    } catch (e) {
      box.replaceChildren(el('span', { class: 'pill pill-off' }, 'Server not reachable'));
    }
    fillLanguages();
  }

  function fillLanguages() {
    const sel = $('warnLang');
    let saved = null;
    try { saved = localStorage.getItem('kavach.warn'); } catch (e) { /* storage blocked */ }
    sel.replaceChildren(el('option', { value: 'auto' }, "Auto (call language)"));
    for (const [code, L] of Object.entries(langs())) {
      const name = L && L.name ? L.name : code;
      const native = L && L.native ? L.native : name;
      sel.append(el('option', { value: code }, native === name ? name : native + ' (' + name + ')'));
    }
    if (saved && [...sel.options].some((o) => o.value === saved)) sel.value = saved;
  }

  const warnLang = () => $('warnLang').value || 'auto';

  // ---------------------------------------------------------------- tabs
  function selectTab(name, focus) {
    S.tab = name;
    for (const btn of document.querySelectorAll('.tab')) {
      const on = btn.dataset.tab === name;
      btn.setAttribute('aria-selected', String(on));
      btn.tabIndex = on ? 0 : -1;
      if (on && focus) btn.focus();
    }
    for (const id of ['live', 'demo', 'file']) $('panel-' + id).hidden = id !== name;
  }

  function initTabs() {
    const tabs = [...document.querySelectorAll('.tab')];
    tabs.forEach((btn, i) => {
      btn.addEventListener('click', () => selectTab(btn.dataset.tab));
      btn.addEventListener('keydown', (e) => {
        let j = null;
        if (e.key === 'ArrowRight') j = (i + 1) % tabs.length;
        else if (e.key === 'ArrowLeft') j = (i - 1 + tabs.length) % tabs.length;
        else if (e.key === 'Home') j = 0;
        else if (e.key === 'End') j = tabs.length - 1;
        if (j != null) { e.preventDefault(); selectTab(tabs[j].dataset.tab, true); }
      });
    });
  }

  // ---------------------------------------------------------------- demos
  function demoTimeline(demo) {
    // Use server offsets when present; otherwise the same estimate the backend mock uses.
    const out = [];
    let t = 1.0;
    for (const line of Array.isArray(demo.lines) ? demo.lines : []) {
      const text = String(line.text || '');
      const est = 1.2 + 0.065 * Array.from(text).length;
      const start = typeof line.offset_s === 'number' ? line.offset_s : t;
      const end = typeof line.end_s === 'number' ? line.end_s : start + est;
      out.push({ speaker: line.speaker === 'victim' ? 'victim' : 'caller', text, start, end });
      t = end + 0.6;
    }
    return out;
  }

  async function loadDemos() {
    const list = $('demoList');
    list.setAttribute('aria-busy', 'true');
    try {
      const r = await fetch('/api/demos', { cache: 'no-store' });
      if (!r.ok) throw new Error(String(r.status));
      const data = await r.json();
      S.demos = Array.isArray(data) ? data : [];
      renderDemos();
    } catch (e) {
      list.replaceChildren(el('li', { class: 'demo-error' },
        el('p', null, 'Could not load the demo calls.'),
        el('button', { class: 'btn btn-ghost', type: 'button', onclick: loadDemos }, 'Try again')));
    } finally {
      list.setAttribute('aria-busy', 'false');
    }
  }

  function renderDemos() {
    const list = $('demoList');
    if (!S.demos.length) {
      list.replaceChildren(el('li', { class: 'demo-error' }, el('p', null, 'No demo calls found in demo/scripts.json.')));
      return;
    }
    const live = S.status && !S.status.gnani_mock;
    list.replaceChildren(...S.demos.map((d) => {
      const isScam = d.label !== 'legit';
      const title = String(d.title || d.id || 'Demo call');
      const native = d.title_native && d.title_native !== d.title ? String(d.title_native) : null;
      const audioTag = d.has_audio ? 'Phone audio' : 'Mock audio';
      const btn = el('button', {
        class: 'demo-play', type: 'button', 'aria-label': 'Play demo: ' + title, dataset: { id: String(d.id) },
        onclick: () => {
          const s = S.session;
          if (s && s.demo && s.demo.id === d.id && s.state !== 'ended') stopSession();
          else startSession('demo', d);
        },
      }, icon('play'), el('span', { class: 'demo-play-label' }, 'Play'));
      return el('li', { class: 'demo-card', dataset: { id: String(d.id), label: isScam ? 'scam' : 'legit' } },
        el('div', { class: 'demo-body' },
          el('div', { class: 'badges' },
            el('span', { class: 'badge badge-' + (isScam ? 'scam' : 'legit') }, isScam ? 'SCAM' : 'LEGIT'),
            el('span', { class: 'badge badge-lang', lang: validLang(d.language) }, langNative(d.language) || 'Auto'),
            el('span', { class: 'badge badge-audio' }, audioTag)),
          el('h3', { class: 'demo-title' }, title),
          native ? el('p', { class: 'demo-native', lang: validLang(d.language) }, native) : null,
          (!d.has_audio && live) ? el('p', { class: 'demo-note' }, 'No demo audio yet: run scripts/make_demo_audio.py, or the live STT will hear silence.') : null),
        btn);
    }));
    syncDemoButtons();
  }

  function syncDemoButtons() {
    const s = S.session;
    const activeId = s && s.demo && s.state !== 'ended' ? String(s.demo.id) : null;
    for (const card of document.querySelectorAll('.demo-card[data-id]')) {
      const on = card.dataset.id === activeId;
      card.classList.toggle('playing', on);
      const b = card.querySelector('.demo-play');
      if (!b) continue;
      b.replaceChildren(icon(on ? 'stop' : 'play'), el('span', { class: 'demo-play-label' }, on ? 'Stop' : 'Play'));
      const t = card.querySelector('.demo-title');
      b.setAttribute('aria-label', (on ? 'Stop demo: ' : 'Play demo: ') + (t ? t.textContent : ''));
    }
  }

  // ---------------------------------------------------------------- notices
  let noticeTimer = null;
  function showNotice(msg, persist) {
    $('noticeText').textContent = String(msg || 'Something went wrong.');
    $('notice').hidden = false;
    clearTimeout(noticeTimer);
    if (!persist) noticeTimer = setTimeout(hideNotice, 7000);
  }
  function hideNotice() { $('notice').hidden = true; clearTimeout(noticeTimer); }

  function friendlyError(err) {
    const name = err && err.name;
    const msg = err && err.message;
    if (name === 'NotAllowedError' || name === 'SecurityError') return 'Microphone permission was blocked. Allow mic access for this site in your browser settings, then try again.';
    if (name === 'NotFoundError' || name === 'OverconstrainedError') return 'No microphone found on this device.';
    if (name === 'NotReadableError') return 'The microphone is busy in another app. Close it and try again.';
    if (msg === 'mic-unsupported') return 'This browser cannot use the microphone here. Open the app on localhost or over HTTPS.';
    if (msg === 'audio-unsupported' || msg === 'worklet-unsupported') return 'This browser does not support live audio processing (AudioWorklet). Try a recent Chrome, Edge, Firefox or Safari.';
    return msg ? String(msg) : 'Something went wrong.';
  }

  // ---------------------------------------------------------------- monitor: reset, risk meter
  function resetMonitor() {
    S.items.clear();
    $('transcript').replaceChildren(emptyStateNode());
    $('summary').hidden = true;
    setRisk({ score: 0, level: 'idle', categories: [] }, true);
    hideBanner();
    closeAlarm(true);
  }

  let emptyNode = null;
  function emptyStateNode() {
    if (!emptyNode) emptyNode = $('emptyState');
    return emptyNode;
  }

  function setRisk(m, silent) {
    let score = Math.round(Number(m && m.score));
    if (!Number.isFinite(score)) score = 0;
    score = clamp(score, 0, 100);
    let level = m && LEVELS[m.level] ? m.level : (score >= 70 ? 'danger' : score >= 35 ? 'caution' : 'safe');
    if (m && m.level === 'idle') level = 'idle';
    const prev = S.risk.level;
    S.risk = { score, level };

    const meter = $('meter');
    meter.dataset.level = level;
    $('gaugeFill').style.strokeDashoffset = String(100 - score);
    $('needle').style.transform = 'rotate(' + (-90 + score * 1.8) + 'deg)';
    $('levelLabel').textContent = LEVELS[level].en;
    $('levelLabelHi').textContent = LEVELS[level].hi;
    const rm = $('riskMeter');
    rm.setAttribute('aria-valuenow', String(score));
    rm.setAttribute('aria-valuetext', score + ' out of 100, ' + LEVELS[level].en);
    animateScore(score);

    const reason = $('reason');
    const why = m && typeof m.reason === 'string' ? m.reason.trim() : '';
    if (why && level !== 'idle') {
      reason.replaceChildren(
        el('span', { class: 'reason-src' }, m.source === 'llm' ? 'AI review' : 'Pattern check'),
        document.createTextNode(why));
      reason.hidden = false;
    } else {
      reason.hidden = true;
      reason.replaceChildren();
    }
    renderChips($('chips'), m && Array.isArray(m.categories) ? m.categories : []);

    if (!silent && LEVEL_RANK[level] > LEVEL_RANK[prev] && LEVEL_RANK[level] >= 2) {
      meter.classList.remove('bump');
      void meter.offsetWidth; // restart the animation
      meter.classList.add('bump');
    }
  }

  let scoreRaf = 0;
  function animateScore(target) {
    cancelAnimationFrame(scoreRaf);
    const node = $('score');
    const from = S.shownScore;
    if (reducedMotion() || document.hidden || from === target) { S.shownScore = target; node.textContent = String(target); return; }
    const t0 = performance.now();
    const dur = 700;
    const step = (now) => {
      const p = Math.min(1, (now - t0) / dur);
      const e = 1 - Math.pow(1 - p, 3);
      const v = Math.round(from + (target - from) * e);
      S.shownScore = v;
      node.textContent = String(v);
      if (p < 1) scoreRaf = requestAnimationFrame(step);
    };
    scoreRaf = requestAnimationFrame(step);
  }

  function renderChips(ul, cats) {
    const seen = new Set();
    const items = [];
    for (const c of cats) {
      if (typeof c !== 'string' || seen.has(c)) continue;
      seen.add(c);
      const L = catLabel(c);
      items.push(el('li', { class: 'chip', dataset: { cat: c } },
        el('span', { class: 'chip-en' }, L.en),
        L.hi ? el('span', { class: 'chip-hi', lang: 'hi' }, L.hi) : null));
    }
    ul.replaceChildren(...items);
  }

  // ---------------------------------------------------------------- transcript
  function renderFlagged(p, text, flags) {
    const chars = Array.from(text); // offsets are code points (Python str indices)
    const L = chars.length;
    const ranges = [];
    for (const f of Array.isArray(flags) ? flags : []) {
      if (!f || typeof f !== 'object') continue;
      let a = Number(f.start);
      let b = Number(f.end);
      let ok = Number.isInteger(a) && Number.isInteger(b) && a >= 0 && b > a && b <= L;
      if (!ok && typeof f.phrase === 'string' && f.phrase) {
        const i = text.toLowerCase().indexOf(f.phrase.toLowerCase());
        if (i >= 0) {
          a = Array.from(text.slice(0, i)).length;
          b = Math.min(L, a + Array.from(f.phrase).length);
          ok = b > a;
        }
      }
      if (ok) ranges.push({ a, b, cat: typeof f.category === 'string' ? f.category : '' });
    }
    ranges.sort((x, y) => x.a - y.a || (y.b - y.a) - (x.b - x.a));
    let pos = 0;
    for (const r of ranges) {
      if (r.a < pos) continue; // skip overlaps
      if (r.a > pos) p.append(document.createTextNode(chars.slice(pos, r.a).join('')));
      const lab = catLabel(r.cat);
      const tip = lab.hi ? lab.en + ' / ' + lab.hi : lab.en;
      const mark = el('mark', { class: 'flag', tabindex: '0', title: tip, dataset: { tip, cat: r.cat } });
      mark.textContent = chars.slice(r.a, r.b).join('');
      p.append(mark);
      pos = r.b;
    }
    if (pos < L) p.append(document.createTextNode(chars.slice(pos).join('')));
    return ranges.length;
  }

  const norm = (t) => String(t || '').replace(/\s+/g, ' ').trim().toLowerCase();

  function guessSpeaker(s, text) {
    if (!s || !s.timeline) return null;
    const n = norm(text);
    for (let i = 0; i < s.timeline.length; i++) {
      if (!s.usedLines.has(i) && norm(s.timeline[i].text) === n) {
        s.usedLines.add(i);
        s.lineCursor = i + 1;
        return s.timeline[i].speaker;
      }
    }
    if (s.mock && s.lineCursor < s.timeline.length) {
      const i = s.lineCursor++;
      s.usedLines.add(i);
      return s.timeline[i].speaker;
    }
    return null;
  }

  function addTranscript(m, s, tSec) {
    const text = typeof m.text === 'string' ? m.text : '';
    if (!text.trim()) return;
    const idx = Number.isInteger(m.index) ? m.index : S.items.size + 1000;
    const prev = S.items.get(idx);
    const speaker = prev ? prev.dataset.speaker || null : guessSpeaker(s, text);
    const lang = validLang(m.language);

    const p = el('p', { class: 'bubble-text', lang });
    const nFlags = renderFlagged(p, text, m.flags);
    const who = speaker === 'caller' ? 'Caller' : speaker === 'victim' ? 'You' : 'On the call';
    const meta = el('div', { class: 'bubble-meta' },
      el('span', { class: 'who' }, who),
      tSec != null ? el('span', { class: 'time' }, fmtTime(tSec)) : null,
      lang ? el('span', { class: 'blang' }, langNative(lang)) : null,
      nFlags ? el('span', { class: 'bflag' }, icon('alert'), nFlags === 1 ? '1 warning sign' : nFlags + ' warning signs') : null);
    const li = el('li', {
      class: 'bubble' + (speaker ? ' from-' + speaker : '') + (nFlags ? ' flagged' : ''),
      dataset: { index: String(idx), speaker: speaker || '' },
    }, meta, p);

    const list = $('transcript');
    if (emptyStateNode().isConnected) emptyStateNode().remove();
    if (prev) prev.replaceWith(li);
    else {
      // keep order by index
      let before = null;
      for (const [k, node] of S.items) if (k > idx && (!before || Number(before.dataset.index) > k)) before = node;
      list.insertBefore(li, before);
    }
    S.items.set(idx, li);
    if (s) requestAnimationFrame(() => li.scrollIntoView({ block: 'nearest', behavior: reducedMotion() ? 'auto' : 'smooth' }));
  }

  // ---------------------------------------------------------------- alerts
  function showAlert(m, s) {
    const level = m.level === 'danger' ? 'danger' : 'caution';
    const text = stripTags(m.text);
    const lang = validLang(m.language);
    const L = catLabel(m.category);
    const catText = L.hi ? L.en + ' / ' + L.hi : L.en;
    S.lastAlert = { m, s };

    $('srAlert').textContent = (level === 'danger' ? 'Scam alert. ' : 'Be careful. ') + text;

    if (level === 'danger') {
      hideBanner();
      $('alarmCat').textContent = catText;
      const t = $('alarmText');
      t.textContent = text;
      if (lang) t.setAttribute('lang', lang); else t.removeAttribute('lang');
      openAlarm();
      vibrate([380, 140, 380, 140, 700]);
    } else {
      $('bannerCat').textContent = catText;
      const bt = $('bannerText');
      bt.textContent = text;
      if (lang) bt.setAttribute('lang', lang); else bt.removeAttribute('lang');
      openBanner();
      vibrate([220, 120, 220]);
    }
    speakAlert(m, s);
  }

  function vibrate(pattern) {
    try { if (navigator.vibrate) navigator.vibrate(pattern); } catch (e) { /* not supported */ }
  }

  function duck(s, on) {
    if (!s) return;
    if (s.speakerGain && s.ctx && s.ctx.state !== 'closed') {
      try { s.speakerGain.gain.setTargetAtTime(on ? 0.18 : 1, s.ctx.currentTime, 0.08); } catch (e) { /* closed */ }
    }
    // In mic mode, don't let Kavach transcribe its own spoken warning: send silence while it speaks.
    if (s.source === 'mic') {
      s.suppress = on;
      clearTimeout(s.suppressTimer);
      if (on) s.suppressTimer = setTimeout(() => { s.suppress = false; }, 15000);
    }
  }

  function stopAlertVoice() {
    if (S.alertAudio) {
      try { S.alertAudio.pause(); } catch (e) { /* ignore */ }
      S.alertAudio = null;
    }
    try { if (window.speechSynthesis) window.speechSynthesis.cancel(); } catch (e) { /* ignore */ }
  }

  function speakAlert(m, s) {
    stopAlertVoice();
    const b64 = typeof m.audio_b64 === 'string' ? m.audio_b64.replace(/\s+/g, '') : '';
    if (b64 && /^[A-Za-z0-9+/=]+$/.test(b64)) {
      const a = new Audio('data:audio/wav;base64,' + b64);
      S.alertAudio = a;
      const done = () => { duck(s, false); if (S.alertAudio === a) S.alertAudio = null; };
      a.addEventListener('ended', done);
      a.addEventListener('error', () => { done(); speakFallback(m, s); });
      duck(s, true);
      a.play().catch(() => { done(); speakFallback(m, s); });
    } else {
      speakFallback(m, s);
    }
  }

  let voices = [];
  function loadVoices() {
    try { voices = window.speechSynthesis ? window.speechSynthesis.getVoices() : []; } catch (e) { voices = []; }
  }

  function speakFallback(m, s) {
    const synth = window.speechSynthesis;
    if (!synth || typeof window.SpeechSynthesisUtterance !== 'function') return;
    const text = stripTags(m.text);
    if (!text) return;
    const lang = validLang(m.language) || 'hi-IN';
    if (!voices.length) loadVoices();
    const want = lang.toLowerCase();
    const base = want.slice(0, 2);
    const v = voices.find((x) => x.lang && x.lang.replace('_', '-').toLowerCase() === want)
      || voices.find((x) => x.lang && x.lang.toLowerCase().startsWith(base));
    const u = new SpeechSynthesisUtterance(text);
    u.lang = lang;
    if (v) u.voice = v;
    u.rate = 0.95;
    u.onstart = () => duck(s, true);
    u.onend = () => duck(s, false);
    u.onerror = () => duck(s, false);
    try { synth.cancel(); synth.speak(u); } catch (e) { duck(s, false); }
  }

  // danger overlay
  let alarmReturnFocus = null;
  function openAlarm() {
    const o = $('dangerOverlay');
    if (o.hidden) {
      alarmReturnFocus = document.activeElement;
      o.hidden = false;
      document.body.classList.add('alarm-open');
      o.classList.remove('show');
      void o.offsetWidth;
      o.classList.add('show');
    }
    setTimeout(() => $('alarmOk').focus({ preventScroll: true }), 60);
  }
  function closeAlarm(silent) {
    const o = $('dangerOverlay');
    if (o.hidden) return;
    o.hidden = true;
    o.classList.remove('show');
    document.body.classList.remove('alarm-open');
    if (!silent) {
      stopAlertVoice();
      if (S.lastAlert) duck(S.lastAlert.s, false);
    }
    if (alarmReturnFocus && alarmReturnFocus.isConnected && !silent) {
      try { alarmReturnFocus.focus({ preventScroll: true }); } catch (e) { /* ignore */ }
    }
  }

  // caution banner
  let bannerTimer = null;
  function openBanner() {
    const b = $('cautionBanner');
    b.hidden = false;
    b.classList.remove('show');
    void b.offsetWidth;
    b.classList.add('show');
    clearTimeout(bannerTimer);
    bannerTimer = setTimeout(hideBanner, 14000);
  }
  function hideBanner() {
    clearTimeout(bannerTimer);
    const b = $('cautionBanner');
    b.classList.remove('show');
    b.hidden = true;
  }

  // ---------------------------------------------------------------- summary
  function renderSummary(m) {
    if (!m || typeof m !== 'object') return;
    const v = VERDICTS[m.verdict] || VERDICTS.suspicious;
    const box = $('summary');
    box.dataset.level = v.level;
    $('verdict').replaceChildren(el('span', null, v.en), el('span', { class: 'hi', lang: 'hi' }, v.hi));
    let score = Math.round(Number(m.score));
    $('summaryScore').textContent = Number.isFinite(score) ? 'Risk score ' + clamp(score, 0, 100) + ' / 100' : '';
    renderChips($('summaryChips'), Array.isArray(m.categories) ? m.categories : []);
    const lang = validLang(m.language);
    const st = $('summaryText');
    st.textContent = typeof m.summary === 'string' ? m.summary : '';
    if (lang) st.setAttribute('lang', lang); else st.removeAttribute('lang');
    const adv = $('advice');
    const items = Array.isArray(m.advice) ? m.advice.filter((x) => typeof x === 'string' && x.trim()) : [];
    adv.replaceChildren(...items.map((a) => el('li', { lang }, a)));
    adv.previousElementSibling.hidden = !items.length;

    let share = typeof m.share_text === 'string' && m.share_text.trim() ? m.share_text.trim() : '';
    if (!share) share = (v.en + ': ' + (m.summary || '')).slice(0, 560) + '\nChecked with Scam Kavach';
    $('shareWa').href = 'https://wa.me/?text=' + encodeURIComponent(share);
    $('shareWa').dataset.share = share;
    $('copyLabel').textContent = 'Copy';
    box.hidden = false;
    requestAnimationFrame(() => {
      box.scrollIntoView({ block: 'start', behavior: reducedMotion() ? 'auto' : 'smooth' });
      box.focus({ preventScroll: true });
    });
  }

  async function copyShare() {
    const text = $('shareWa').dataset.share || '';
    if (!text) return;
    let ok = false;
    try {
      if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); ok = true; }
    } catch (e) { ok = false; }
    if (!ok) {
      const ta = el('textarea', { class: 'sr-only', readonly: true });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      ta.remove();
    }
    $('copyLabel').textContent = ok ? 'Copied' : 'Copy failed';
    setTimeout(() => { $('copyLabel').textContent = 'Copy'; }, 2200);
  }

  // ---------------------------------------------------------------- session (live mic + demo calls)
  function later(s, ms, fn) {
    const id = setTimeout(() => { s.timers.delete(id); fn(); }, ms);
    s.timers.add(id);
    return id;
  }
  function every(s, ms, fn) {
    const id = setInterval(fn, ms);
    s.intervals.add(id);
    return id;
  }

  function wsUrl() {
    return (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws/listen';
  }

  async function startSession(source, demo) {
    if (S.analyzing) { S.analyzing.abort(); S.analyzing = null; }
    if (S.session && S.session.state !== 'ended') finish(S.session, true);
    hideNotice();
    resetMonitor();
    stopAlertVoice();
    if (!voices.length) loadVoices();

    const s = {
      id: ++S.seq, source, demo: demo || null, state: 'connecting', mock: null,
      ws: null, ctx: null, node: null, srcNode: null, micStream: null, media: null, speakerGain: null,
      timers: new Set(), intervals: new Set(), t0: 0, gotSummary: false, errorShown: false,
      suppress: false, suppressTimer: null, level: 0,
      timeline: demo ? demoTimeline(demo) : null, usedLines: new Set(), lineCursor: 0,
    };
    S.session = s;
    renderSessionUI();

    try {
      if (source === 'mic') await setupMic(s);
      else if (demo && demo.has_audio) await setupDemoAudio(s);
      if (S.session !== s || s.state === 'ended') return;
      openSocket(s);
    } catch (err) {
      if (S.session !== s) return;
      showNotice(friendlyError(err), true);
      s.errorShown = true;
      finish(s);
    }
  }

  async function makeAudioGraph(s) {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (!AC) throw new Error('audio-unsupported');
    const ctx = new AC({ latencyHint: 'interactive' });
    s.ctx = ctx;
    if (!ctx.audioWorklet || typeof window.AudioWorkletNode !== 'function') throw new Error('worklet-unsupported');
    if (ctx.state === 'suspended') ctx.resume().catch(() => {});
    await ctx.audioWorklet.addModule('/static/pcm-worklet.js');
    if (ctx.state === 'closed') throw new Error('Audio stopped.');
    const node = new AudioWorkletNode(ctx, 'pcm-downsampler', {
      numberOfInputs: 1, numberOfOutputs: 1, outputChannelCount: [1],
      processorOptions: { targetRate: 16000 },
    });
    // Keep the worklet pulled by the graph without making it audible.
    const mute = ctx.createGain();
    mute.gain.value = 0;
    node.connect(mute).connect(ctx.destination);
    node.port.onmessage = (e) => onFrame(s, e.data);
    s.node = node;
    return ctx;
  }

  async function setupMic(s) {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) throw new Error('mic-unsupported');
    s.micStream = await navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: false, noiseSuppression: true, autoGainControl: true, channelCount: 1 },
    });
    if (S.session !== s || s.state === 'ended') { stopTracks(s.micStream); s.micStream = null; return; }
    const ctx = await makeAudioGraph(s);
    s.srcNode = ctx.createMediaStreamSource(s.micStream);
    s.srcNode.connect(s.node);
    for (const t of s.micStream.getAudioTracks()) {
      t.addEventListener('ended', () => {
        if (S.session === s && s.state === 'live') { showNotice('The microphone was disconnected.'); stopSession(); }
      });
    }
  }

  async function setupDemoAudio(s) {
    const ctx = await makeAudioGraph(s);
    const media = new Audio();
    media.preload = 'auto';
    media.src = '/demo-audio/' + encodeURIComponent(s.demo.id) + '.wav';
    s.media = media;
    s.srcNode = ctx.createMediaElementSource(media);
    s.speakerGain = ctx.createGain();
    s.srcNode.connect(s.speakerGain).connect(ctx.destination);   // speakers
    s.srcNode.connect(s.node);                                    // and the worklet -> WS
    media.addEventListener('ended', () => {
      if (S.session === s && s.state === 'live') later(s, 1500, () => stopSession());
    });
    media.addEventListener('error', () => {
      if (S.session === s && s.state !== 'ended' && s.state !== 'stopping') {
        showNotice('Could not load the demo audio file.', true);
        s.errorShown = true;
        stopSession();
      }
    });
  }

  function stopTracks(stream) {
    if (!stream) return;
    for (const t of stream.getTracks()) { try { t.stop(); } catch (e) { /* ignore */ } }
  }

  function onFrame(s, buf) {
    if (!(buf instanceof ArrayBuffer) || buf.byteLength !== FRAME_BYTES) return;
    if (S.session !== s) return;
    // level for the VU bars
    const v = new Int16Array(buf);
    let peak = 0;
    for (let i = 0; i < v.length; i += 4) { const a = v[i] < 0 ? -v[i] : v[i]; if (a > peak) peak = a; }
    const lvl = Math.min(1, Math.sqrt(peak / 32768) * 1.25);
    s.level = s.level * 0.6 + lvl * 0.4;
    if (s.suppress) sendFrame(s, ZERO_FRAME);
    else sendFrame(s, buf);
  }

  const ZERO_FRAME = new ArrayBuffer(FRAME_BYTES);
  function sendFrame(s, buf) {
    const ws = s.ws;
    if (!ws || ws.readyState !== WebSocket.OPEN || s.state !== 'live') return;
    if (ws.bufferedAmount > 512 * 1024) return; // network stalled: drop rather than queue forever
    try { ws.send(buf); } catch (e) { /* closing */ }
  }

  function openSocket(s) {
    let ws;
    try { ws = new WebSocket(wsUrl()); } catch (e) { throw new Error('Could not open a connection to the Kavach server.'); }
    ws.binaryType = 'arraybuffer';
    s.ws = ws;
    ws.onopen = () => {
      if (S.session !== s || s.state === 'ended') { try { ws.close(1000); } catch (e) { /* ignore */ } return; }
      ws.send(JSON.stringify({
        type: 'start', source: s.source, demo_id: s.demo ? String(s.demo.id) : null,
        language: 'indic-auto', warn_language: warnLang(),
      }));
    };
    ws.onmessage = (e) => {
      if (typeof e.data !== 'string') return;
      let m;
      try { m = JSON.parse(e.data); } catch (err) { return; }
      if (m && typeof m === 'object') handleMessage(s, m);
    };
    ws.onerror = () => { s.sockError = true; };
    ws.onclose = (e) => onSocketClose(s, e);
    later(s, CONNECT_TIMEOUT_MS, () => {
      if (s.state === 'connecting') {
        showNotice('Could not reach the Kavach server. Is it running?', true);
        s.errorShown = true;
        finish(s);
      }
    });
  }

  function handleMessage(s, m) {
    if (S.session !== s || s.state === 'ended') return;
    switch (m.type) {
      case 'ready': onReady(s, m); break;
      case 'transcript': addTranscript(m, s, s.t0 ? (performance.now() - s.t0) / 1000 : null); break;
      case 'risk': setRisk(m); break;
      case 'alert': showAlert(m, s); break;
      case 'summary':
        s.gotSummary = true;
        renderSummary(m);
        if (s.state === 'live') { s.state = 'stopping'; stopCapture(s); renderSessionUI(); }
        later(s, 3000, () => finish(s)); // server closes right after; this is a fallback
        break;
      case 'error': {
        const msg = typeof m.message === 'string' && m.message ? m.message : 'Something went wrong.';
        showNotice(msg, !!m.fatal);
        if (m.fatal) {
          s.errorShown = true;
          if (s.state === 'connecting') { finish(s); break; }
          if (s.state === 'live') { s.state = 'stopping'; stopCapture(s); renderSessionUI(); }
          later(s, 5000, () => finish(s));
        }
        break;
      }
      default: break; // ignore unknown message types
    }
  }

  function onReady(s, m) {
    if (s.state !== 'connecting') return;
    s.state = 'live';
    s.mock = !!m.mock;
    s.t0 = performance.now();
    if (s.ctx && s.ctx.state === 'suspended') s.ctx.resume().catch(() => {});

    if (s.source === 'demo') {
      if (s.media) {
        s.media.play().catch(() => {
          showNotice('The browser blocked audio playback. Tap Play again.', true);
          s.errorShown = true;
          stopSession();
        });
      } else {
        startSilentFrames(s);
        const tl = s.timeline || [];
        const total = tl.length ? tl[tl.length - 1].end : 5;
        later(s, Math.round((total + 2.5) * 1000), () => stopSession());
      }
      if (s.timeline && s.timeline.length) every(s, 120, () => updateSubtitle(s));
    }
    every(s, 250, () => {
      $('clock').textContent = fmtTime((performance.now() - s.t0) / 1000);
      paintVu(s);
    });
    later(s, MAX_SESSION_MS, () => { showNotice('Reached the 15-minute limit for one check.'); stopSession(); });
    renderSessionUI();
  }

  function startSilentFrames(s) {
    const start = performance.now();
    let sent = 0;
    every(s, FRAME_MS, () => {
      const due = Math.floor((performance.now() - start) / FRAME_MS);
      let n = Math.min(due - sent, 8);
      while (n-- > 0) { sendFrame(s, ZERO_FRAME); sent++; }
      if (due - sent > 8) sent = due; // tab was throttled: skip ahead instead of bursting
    });
  }

  function updateSubtitle(s) {
    const tl = s.timeline;
    if (!tl || !tl.length) return;
    const t = s.media ? s.media.currentTime : (performance.now() - s.t0) / 1000;
    let cur = null;
    for (const line of tl) if (t >= line.start - 0.05 && t <= line.end + 0.35) cur = line;
    const total = tl[tl.length - 1].end || 1;
    $('subtitleBar').style.transform = 'scaleX(' + clamp(t / total, 0, 1).toFixed(3) + ')';
    const box = $('subtitle');
    if (cur === s.subLine) return;
    s.subLine = cur;
    box.classList.toggle('dim', !cur);
    if (cur) {
      $('subtitleWho').textContent = cur.speaker === 'victim' ? 'You' : 'Caller';
      const p = $('subtitleText');
      p.textContent = cur.text;
      const lang = validLang(s.demo && s.demo.language);
      if (lang) p.setAttribute('lang', lang); else p.removeAttribute('lang');
      box.classList.remove('swap');
      void box.offsetWidth;
      box.classList.add('swap');
    }
  }

  function paintVu(s) {
    const bars = $('vu').children;
    const base = s.source === 'mic' || s.media ? s.level : 0;
    for (let i = 0; i < bars.length; i++) {
      const shape = [0.55, 0.85, 1, 0.8, 0.6][i] || 1;
      bars[i].style.transform = 'scaleY(' + (0.18 + base * shape * 0.82).toFixed(3) + ')';
    }
    $('listenBtn').style.setProperty('--lvl', base.toFixed(3));
  }

  function onSocketClose(s, e) {
    if (S.session !== s || s.state === 'ended') return;
    if (!s.gotSummary && !s.errorShown) {
      if (s.state === 'connecting') showNotice('Could not connect to the Kavach server. Is it running?', true);
      else if (s.state === 'live') showNotice('Connection to the server was lost' + (e && e.code && e.code !== 1000 ? ' (code ' + e.code + ').' : '.'), true);
      else if (s.state === 'stopping') showNotice('Call ended. The server closed before sending a summary.');
    }
    finish(s);
  }

  function stopSession() {
    const s = S.session;
    if (!s || s.state === 'ended' || s.state === 'stopping') return;
    if (s.state === 'connecting') { finish(s); return; }
    s.state = 'stopping';
    stopCapture(s);
    try {
      if (s.ws && s.ws.readyState === WebSocket.OPEN) s.ws.send(JSON.stringify({ type: 'stop' }));
      else { finish(s); return; }
    } catch (e) { finish(s); return; }
    later(s, SUMMARY_WAIT_MS, () => {
      if (!s.gotSummary && !s.errorShown) showNotice('No summary arrived from the server.');
      finish(s);
    });
    renderSessionUI();
  }

  // Stops audio capture/playback and per-call loops. Leaves the socket open (to receive the summary).
  function stopCapture(s) {
    for (const id of s.intervals) clearInterval(id);
    s.intervals.clear();
    clearTimeout(s.suppressTimer);
    s.suppress = false;
    if (s.node) {
      try { s.node.port.postMessage({ type: 'stop' }); } catch (e) { /* ignore */ }
      s.node.port.onmessage = null;
      try { s.node.disconnect(); } catch (e) { /* ignore */ }
      s.node = null;
    }
    if (s.srcNode) { try { s.srcNode.disconnect(); } catch (e) { /* ignore */ } s.srcNode = null; }
    if (s.speakerGain) { try { s.speakerGain.disconnect(); } catch (e) { /* ignore */ } s.speakerGain = null; }
    stopTracks(s.micStream);
    s.micStream = null;
    if (s.media) {
      try { s.media.pause(); s.media.removeAttribute('src'); s.media.load(); } catch (e) { /* ignore */ }
      s.media = null;
    }
    if (s.ctx) {
      const ctx = s.ctx;
      s.ctx = null;
      if (ctx.state !== 'closed') ctx.close().catch(() => {});
    }
    s.level = 0;
    paintVu(s);
  }

  // Final teardown: audio, timers, socket. Idempotent.
  function finish(s, quiet) {
    if (s.state === 'ended') return;
    stopCapture(s);
    for (const id of s.timers) clearTimeout(id);
    s.timers.clear();
    const ws = s.ws;
    s.ws = null;
    if (ws) {
      ws.onopen = ws.onmessage = ws.onerror = ws.onclose = null;
      if (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN) {
        try { ws.close(1000, quiet ? 'restart' : 'done'); } catch (e) { /* ignore */ }
      }
    }
    s.state = 'ended';
    if (S.session === s) {
      renderSessionUI();
      // The panels come back above the monitor when a call ends; bring the summary back into view.
      if (!quiet && s.gotSummary && !$('summary').hidden) {
        requestAnimationFrame(() => $('summary').scrollIntoView({ block: 'start', behavior: reducedMotion() ? 'auto' : 'smooth' }));
      }
    }
  }

  function renderSessionUI() {
    const s = S.session;
    const active = !!s && s.state !== 'ended';
    document.body.classList.toggle('in-session', active);
    $('sessionBar').hidden = !active;
    for (const id of ['live', 'demo', 'file']) $('panel-' + id).hidden = active || id !== S.tab;
    for (const t of document.querySelectorAll('.tab')) t.disabled = active;
    $('warnLang').disabled = active;
    syncDemoButtons();
    if (!active) { $('clock').textContent = '0:00'; return; }

    const title = $('sessionTitle');
    const meta = $('sessionMeta');
    const stop = $('stopBtn');
    const bar = $('sessionBar');
    bar.dataset.state = s.state;
    bar.dataset.audio = s.source === 'mic' || s.media ? 'yes' : 'no';
    stop.disabled = s.state === 'stopping';
    stop.querySelector('span').textContent = s.state === 'stopping' ? 'Wait' : 'Stop';

    if (s.state === 'connecting') {
      title.textContent = s.source === 'mic' ? 'Starting the mic…' : 'Connecting…';
      meta.textContent = '';
    } else if (s.state === 'stopping') {
      title.textContent = 'Preparing the summary…';
      meta.textContent = s.gotSummary ? 'Done' : 'Finishing the last words';
    } else if (s.source === 'mic') {
      title.textContent = 'Listening to the call';
      meta.textContent = s.mock ? 'Mock mode: scripted sample call' : 'Live: Gnani Prisma v3.0';
    } else {
      title.textContent = s.demo ? String(s.demo.title || s.demo.id) : 'Demo call';
      meta.textContent = s.media ? 'Playing phone audio' + (s.mock ? ' (mock STT)' : '') : 'Mock audio: lines play as subtitles';
    }
    const sub = $('subtitle');
    sub.hidden = !(s.source === 'demo' && s.timeline && s.timeline.length && s.state !== 'connecting');
    if (s.state === 'connecting') { s.subLine = undefined; $('subtitleText').textContent = ''; $('subtitleWho').textContent = ''; $('subtitleBar').style.transform = 'scaleX(0)'; }
  }

  // ---------------------------------------------------------------- check a recording
  function setFile(file) {
    S.file = file || null;
    const title = $('dropTitle');
    const sub = $('dropSub');
    if (S.file) {
      title.textContent = S.file.name;
      const mb = S.file.size / (1024 * 1024);
      sub.textContent = (mb >= 1 ? mb.toFixed(1) + ' MB' : Math.max(1, Math.round(S.file.size / 1024)) + ' KB') + '. Tap to choose another.';
      $('dropZone').classList.add('has-file');
    } else {
      title.textContent = 'Choose a call recording';
      sub.textContent = 'WAV, MP3, M4A, OGG or WebM, up to 10 minutes';
      $('dropZone').classList.remove('has-file');
    }
    $('analyzeBtn').disabled = !S.file || !!S.analyzing;
  }

  function errDetail(data) {
    if (!data) return null;
    const d = data.detail !== undefined ? data.detail : data;
    if (typeof d === 'string') return d;
    if (Array.isArray(d)) return d.map((x) => (x && x.msg) || '').filter(Boolean).join('; ') || null;
    if (d && typeof d === 'object') return d.message || d.error || null;
    return null;
  }

  async function analyzeFile() {
    const file = S.file;
    if (!file || S.analyzing) return;
    if (S.session && S.session.state !== 'ended') finish(S.session, true);
    hideNotice();
    resetMonitor();
    const ctrl = new AbortController();
    S.analyzing = ctrl;
    const btn = $('analyzeBtn');
    const label = $('analyzeLabel');
    btn.disabled = true;
    btn.classList.add('busy');
    const t0 = performance.now();
    const tick = setInterval(() => { label.textContent = 'Transcribing and checking… ' + fmtTime((performance.now() - t0) / 1000); }, 500);
    label.textContent = 'Transcribing and checking…';
    const list = $('transcript');
    emptyStateNode().remove();
    list.append(...[0, 1, 2].map(() => el('li', { class: 'bubble skeleton', 'aria-hidden': 'true' })));
    list.setAttribute('aria-busy', 'true');

    try {
      const fd = new FormData();
      fd.append('audio', file, file.name || 'recording');
      fd.append('language', 'indic-auto');
      fd.append('warn_language', warnLang());
      const r = await fetch('/api/analyze', { method: 'POST', body: fd, signal: ctrl.signal });
      let data = null;
      try { data = await r.json(); } catch (e) { data = null; }
      if (!r.ok) throw new Error(errDetail(data) || 'The server could not check this file (error ' + r.status + ').');
      if (S.analyzing !== ctrl) return;
      list.replaceChildren();
      const rows = data && Array.isArray(data.transcript) ? data.transcript : [];
      rows.forEach((row, i) => {
        if (!row || typeof row !== 'object') return;
        addTranscript({ ...row, index: Number.isInteger(row.index) ? row.index : i }, null,
          typeof row.start_s === 'number' ? row.start_s : null);
      });
      if (!S.items.size) list.replaceChildren(el('li', { class: 'empty' }, el('p', null, 'No speech was found in this recording.')));
      if (data && data.risk) setRisk(data.risk);
      if (data && data.summary) renderSummary(data.summary);
    } catch (e) {
      if (e && e.name === 'AbortError') return;
      list.replaceChildren(emptyStateNode());
      showNotice(e && e.message ? e.message : 'Could not check this recording.', true);
    } finally {
      clearInterval(tick);
      list.removeAttribute('aria-busy');
      for (const sk of list.querySelectorAll('.skeleton')) sk.remove();
      if (S.analyzing === ctrl) S.analyzing = null;
      btn.classList.remove('busy');
      label.textContent = 'Check this recording';
      btn.disabled = !S.file;
    }
  }

  function initFile() {
    const input = $('fileInput');
    input.addEventListener('change', () => setFile(input.files && input.files[0]));
    const zone = $('dropZone');
    zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('drag'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('drag'));
    zone.addEventListener('drop', (e) => {
      e.preventDefault();
      zone.classList.remove('drag');
      const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) setFile(f);
    });
    $('analyzeBtn').addEventListener('click', analyzeFile);
  }

  // ---------------------------------------------------------------- wiring
  function init() {
    initTabs();
    initFile();
    $('listenBtn').addEventListener('click', () => startSession('mic', null));
    $('stopBtn').addEventListener('click', stopSession);
    $('noticeClose').addEventListener('click', hideNotice);
    $('bannerClose').addEventListener('click', () => { hideBanner(); stopAlertVoice(); if (S.lastAlert) duck(S.lastAlert.s, false); });
    $('alarmOk').addEventListener('click', () => closeAlarm(false));
    $('alarmReplay').addEventListener('click', () => { if (S.lastAlert) speakAlert(S.lastAlert.m, S.lastAlert.s); });
    $('copyBtn').addEventListener('click', copyShare);
    $('warnLang').addEventListener('change', () => {
      try { localStorage.setItem('kavach.warn', warnLang()); } catch (e) { /* storage blocked */ }
    });
    document.addEventListener('keydown', (e) => {
      const o = $('dangerOverlay');
      if (o.hidden) return;
      if (e.key === 'Escape') { e.preventDefault(); closeAlarm(false); return; }
      if (e.key === 'Tab') { // keep focus inside the alert
        const f = [$('alarmOk'), $('alarmReplay')];
        const i = f.indexOf(document.activeElement);
        e.preventDefault();
        f[(i + (e.shiftKey ? f.length - 1 : 1)) % f.length].focus();
      }
    });
    window.addEventListener('pagehide', () => { if (S.session) finish(S.session, true); stopAlertVoice(); });
    if (window.speechSynthesis) {
      loadVoices();
      try { window.speechSynthesis.addEventListener('voiceschanged', loadVoices); } catch (e) { /* old API */ }
    }
    setRisk({ score: 0, level: 'idle' }, true);
    selectTab('live');
    loadStatus().then(loadDemos);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
