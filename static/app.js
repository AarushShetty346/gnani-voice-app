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
  const MAX_SESSION_MS = 15 * 60 * 1000;   // backstop; the server ends a check at 14.5 min on its own
  // After "stop" the server needs at most ~18 s: settle 3 + stream close 2 + 1 + summary 12 (app/session.py).
  const SUMMARY_WAIT_MS = 25000;
  // The server's Gnani handshake takes at most ~12 s: 8 s timeout + 3.5 s of 429 backoff (app/gnani_stream.py).
  const CONNECT_TIMEOUT_MS = 20000;
  const ALERT_AUDIO_WAIT_MS = 2500;  // wait this long for the Timbre clip, then use the browser's voice
  const ALERT_PAUSE_MS = 300;        // gap between two queued alert voices
  const ECHO_TAIL_MS = 800;          // mic mode: keep sending silence this long after our voice ends
  const DEMO_STOP_DELAY_MS = 300;    // demo audio ended: send "stop" this soon after

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
  const langName = (code) => {
    const L = code && langs()[code];
    return L ? (L.name || L.native || code) : (code || '');
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
    demoResults: {},   // demo id -> verdict, shown on the card after that demo has played
    tab: 'live',
    session: null,       // current live/demo session (see startSession)
    seq: 0,
    items: new Map(),    // transcript index -> <li>
    risk: { score: 0, level: 'idle' },
    shownScore: 0,
    analyzing: null,     // AbortController for /api/analyze
    file: null,
    lastAlert: null,     // the alert entry shown last (for "Hear it again")
    ctx: null,           // one AudioContext for the whole app: unlocked by the first tap, never closed
    worklet: null,       // promise: pcm-worklet.js loaded into S.ctx
  };

  // Alert voices play one at a time, in arrival order (see the alerts section).
  const V = { byId: new Map(), queue: [], current: null, closeWhenIdle: false, pauseTimer: null };

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

  function fillLanguageSelect(sel, autoValue, autoLabel, storageKey, defaultValue) {
    let saved = null;
    try { saved = localStorage.getItem(storageKey); } catch (e) { /* storage blocked */ }
    sel.replaceChildren(el('option', { value: autoValue }, autoLabel));
    for (const [code, L] of Object.entries(langs())) {
      const name = L && L.name ? L.name : code;
      const native = L && L.native ? L.native : name;
      sel.append(el('option', { value: code }, native === name ? name : native + ' (' + name + ')'));
    }
    const has = (v) => v && [...sel.options].some((o) => o.value === v);
    if (has(saved)) sel.value = saved;
    else if (has(defaultValue)) sel.value = defaultValue;
  }

  function fillLanguages() {
    // English by default; "Same as the call" (warn in the caller's language) is one tap away.
    fillLanguageSelect($('warnLang'), 'auto', 'Same as the call', 'kavach.warn2', 'en-IN');
    fillLanguageSelect($('callLang'), 'indic-auto', 'Auto-detect', 'kavach.callLang');
  }

  const warnLang = () => $('warnLang').value || 'auto';
  // Realtime STT takes exactly one language (or indic-auto). Demo calls use their own language server-side.
  const callLang = () => $('callLang').value || 'indic-auto';

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
      const title = String(d.title || d.id || 'Demo call');
      const audioTag = d.has_audio ? 'Phone audio' : 'Mock audio';
      const btn = el('button', {
        class: 'demo-play', type: 'button', 'aria-label': 'Play demo: ' + title, dataset: { id: String(d.id) },
        onclick: () => {
          const s = S.session;
          if (s && s.demo && s.demo.id === d.id && s.state !== 'ended') stopSession();
          else startSession('demo', d);
        },
      }, icon('play'), el('span', { class: 'demo-play-label' }, 'Play'));
      // No scam/legit label up front: the verdict appears on the card only after Kavach has heard the call.
      const card = el('li', { class: 'demo-card', dataset: { id: String(d.id) } },
        el('div', { class: 'demo-body' },
          el('div', { class: 'badges' },
            el('span', { class: 'badge badge-lang' }, langName(d.language) || 'Auto'),
            el('span', { class: 'badge badge-audio' }, audioTag),
            el('span', { class: 'badge badge-result', hidden: true })),
          el('h3', { class: 'demo-title' }, title),
          (!d.has_audio && live) ? el('p', { class: 'demo-note' }, 'No demo audio yet: run scripts/make_demo_audio.py, or the live STT will hear silence.') : null),
        btn);
      paintDemoResult(card, S.demoResults[String(d.id)]);
      return card;
    }));
    syncDemoButtons();
  }

  // After a demo call: show what Kavach decided, on that card.
  function paintDemoResult(card, verdict) {
    const v = VERDICTS[verdict];
    const b = card.querySelector('.badge-result');
    if (!v || !b) return;
    card.dataset.result = v.level;
    b.textContent = v.level === 'safe' ? 'Kavach: looks safe' : v.level === 'danger' ? 'Kavach: scam' : 'Kavach: suspicious';
    b.className = 'badge badge-result badge-' + v.level;
    b.hidden = false;
  }

  function revealDemoResult(s, m) {
    if (!s || !s.demo || !m || !VERDICTS[m.verdict]) return;
    const id = String(s.demo.id);
    S.demoResults[id] = m.verdict;
    const card = [...document.querySelectorAll('.demo-card[data-id]')].find((c) => c.dataset.id === id);
    if (card) paintDemoResult(card, m.verdict);
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
      items.push(el('li', { class: 'chip', dataset: { cat: c } }, el('span', { class: 'chip-en' }, L.en)));
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
      const tip = lab.en;
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
    // Live Gnani never returns the script text verbatim (code-mix, VAD splits/merges lines): go by timing.
    // A transcript arrives after its line ends, so take the latest unused line that has already ended.
    if (s.media && !s.mock) {
      const t = s.media.currentTime - 0.3;
      let pick = -1;
      for (let i = 0; i < s.timeline.length; i++) {
        if (!s.usedLines.has(i) && s.timeline[i].end <= t && (pick < 0 || s.timeline[i].end > s.timeline[pick].end)) pick = i;
      }
      if (pick >= 0) { s.usedLines.add(pick); return s.timeline[pick].speaker; }
      // Every ended line is taken: VAD split one, so this is the rest of the latest ended line.
      for (let i = s.timeline.length - 1; i >= 0; i--) if (s.timeline[i].end <= t) return s.timeline[i].speaker;
      pick = s.timeline.findIndex((_, i) => !s.usedLines.has(i));   // nothing ended yet: the line being spoken
      if (pick >= 0) { s.usedLines.add(pick); return s.timeline[pick].speaker; }
      return null;
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
      lang ? el('span', { class: 'blang' }, langName(lang)) : null,
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
  // The overlay/banner shows the moment an "alert" arrives. Its voice is the Timbre clip: inside the alert
  // when the server had it cached, else an "alert_audio" message with the same id. If that clip hasn't
  // come within ALERT_AUDIO_WAIT_MS the browser's own voice speaks instead (never both). Voices never cut
  // each other off: they queue, except that a danger alert interrupts a caution voice.
  function showAlert(m, s) {
    const level = m.level === 'danger' ? 'danger' : 'caution';
    const text = stripTags(m.text);
    const lang = validLang(m.language);
    const L = catLabel(m.category);
    const catText = L.en;
    // English wording for viewers who don't read the call's language (null when the alert is already English).
    const textEn = typeof m.text_en === 'string' && m.text_en.trim() && m.text_en.trim() !== text ? stripTags(m.text_en) : '';

    $('srAlert').textContent = (level === 'danger' ? 'Scam alert. ' : 'Be careful. ') + text;

    if (level === 'danger') {
      hideBanner();
      $('alarmCat').textContent = catText;
      const t = $('alarmText');
      t.textContent = text;
      if (lang) t.setAttribute('lang', lang); else t.removeAttribute('lang');
      $('alarmEn').textContent = textEn;
      $('alarmEn').hidden = !textEn;
      openAlarm();
      vibrate([380, 140, 380, 140, 700]);
    } else {
      $('bannerCat').textContent = catText;
      const bt = $('bannerText');
      bt.textContent = text;
      if (lang) bt.setAttribute('lang', lang); else bt.removeAttribute('lang');
      $('bannerEn').textContent = textEn;
      $('bannerEn').hidden = !textEn;
      openBanner();
      vibrate([220, 120, 220]);
    }
    queueVoice(m, s, level);
  }

  function vibrate(pattern) {
    try { if (navigator.vibrate) navigator.vibrate(pattern); } catch (e) { /* not supported */ }
  }

  const cleanB64 = (v) => {
    const b64 = typeof v === 'string' ? v.replace(/\s+/g, '') : '';
    return b64 && /^[A-Za-z0-9+/=]+$/.test(b64) ? b64 : null;
  };

  function queueVoice(m, s, level) {
    const id = Number.isInteger(m.id) ? m.id : null;
    const entry = { id, m, s, level, audio: cleanB64(m.audio_b64), ready: false, started: false, timer: null };
    S.lastAlert = entry;
    if (entry.audio) entry.ready = true;
    else if (id == null || m.audio_pending === false) entry.ready = true;   // no clip is coming: speak now
    else {
      entry.timer = setTimeout(() => { entry.ready = true; pumpVoices(); }, ALERT_AUDIO_WAIT_MS);
      V.byId.set(id, entry);
    }
    if (level === 'danger') V.queue = V.queue.filter((e) => e.level === 'danger');   // drop waiting cautions
    V.queue.push(entry);
    V.closeWhenIdle = false;
    pumpVoices();
  }

  // The Timbre clip for an alert shown earlier (audio_b64 null: TTS failed, use the browser voice now).
  function onAlertAudio(m) {
    const entry = Number.isInteger(m.id) ? V.byId.get(m.id) : null;
    if (!entry) return;
    V.byId.delete(m.id);
    if (entry.started) return;                           // the browser voice already spoke it
    clearTimeout(entry.timer);
    entry.audio = cleanB64(m.audio_b64);
    entry.ready = true;
    pumpVoices();
  }

  function pumpVoices() {
    const cur = V.current;
    const next = V.queue[0];
    if (cur && next && cur.level !== 'danger' && next.level === 'danger' && next.ready) {
      stopCurrentVoice();                                // a scam warning beats a "be careful"
    } else if (cur || V.pauseTimer) {
      return;
    }
    if (!next) {
      if (V.closeWhenIdle) { V.closeWhenIdle = false; closeAlarmForSummary(); }
      return;
    }
    if (!next.ready) return;                             // keep the order: wait for its clip (<= 2.5 s)
    V.queue.shift();
    playVoice(next);
  }

  function voiceDone(entry) {
    if (V.current !== entry) return;
    V.current = null;
    duck(entry.s, false);
    clearTimeout(V.pauseTimer);
    V.pauseTimer = setTimeout(() => { V.pauseTimer = null; pumpVoices(); }, ALERT_PAUSE_MS);
  }

  function playVoice(entry) {
    entry.started = true;
    clearTimeout(entry.timer);
    if (entry.id != null) V.byId.delete(entry.id);
    V.current = entry;
    duck(entry.s, true);
    if (entry.audio) playClip(entry);
    else speakFallback(entry);
  }

  function b64ToBuffer(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }

  // Through the app's AudioContext, which the first tap unlocked: on iOS a later new Audio().play() is blocked.
  function playClip(entry) {
    const ctx = S.ctx;
    const fail = () => { if (V.current === entry && !entry.node) speakFallback(entry); };
    if (!ctx || ctx.state === 'closed') { playClipElement(entry); return; }
    if (ctx.state === 'suspended') ctx.resume().catch(() => {});
    let buf;
    try { buf = b64ToBuffer(entry.audio); } catch (e) { fail(); return; }
    decodeAudio(ctx, buf).then((audioBuf) => {
      if (V.current !== entry) return;                   // stopped meanwhile
      const src = ctx.createBufferSource();
      src.buffer = audioBuf;
      src.connect(ctx.destination);
      src.onended = () => voiceDone(entry);
      entry.node = src;
      src.start();
    }).catch(fail);
  }

  function playClipElement(entry) {                      // no AudioContext (e.g. very old browser)
    const a = new Audio('data:audio/wav;base64,' + entry.audio);
    entry.node = a;
    a.addEventListener('ended', () => voiceDone(entry));
    a.play().catch(() => { entry.node = null; if (V.current === entry) speakFallback(entry); });
  }

  function stopCurrentVoice() {
    const cur = V.current;
    if (!cur) return;
    V.current = null;
    const n = cur.node;
    cur.node = null;
    if (n) {
      try { if (typeof n.stop === 'function') { n.onended = null; n.stop(); } else n.pause(); } catch (e) { /* ignore */ }
    }
    if (cur.utter) { cur.utter.onend = cur.utter.onerror = null; }
    try { if (window.speechSynthesis) window.speechSynthesis.cancel(); } catch (e) { /* ignore */ }
    duck(cur.s, false);
  }

  // Stop everything: the voice playing, queued voices, pending clips.
  function stopAlertVoice() {
    for (const e of V.queue) clearTimeout(e.timer);
    for (const e of V.byId.values()) clearTimeout(e.timer);
    V.queue = [];
    V.byId.clear();
    clearTimeout(V.pauseTimer);
    V.pauseTimer = null;
    V.closeWhenIdle = false;
    stopCurrentVoice();
  }

  function replayAlert() {
    const last = S.lastAlert;
    if (!last) return;
    stopAlertVoice();
    unlockAudio();                                       // this is a tap: make sure audio may play
    playVoice({ ...last, ready: true, started: false, timer: null, node: null, utter: null, id: null });
  }

  function duck(s, on) {
    if (!s) return;
    if (s.speakerGain && S.ctx && S.ctx.state !== 'closed') {
      try { s.speakerGain.gain.setTargetAtTime(on ? 0.18 : 1, S.ctx.currentTime, 0.08); } catch (e) { /* closed */ }
    }
    // In mic mode, don't let Kavach transcribe its own spoken warning: send silence while it speaks, and a
    // little longer for the speaker's latency and the room's echo (the server also drops echoed transcripts).
    if (s.source === 'mic') {
      clearTimeout(s.suppressTimer);
      if (on) {
        s.suppress = true;
        s.suppressTimer = setTimeout(() => { s.suppress = false; }, 20000);
      } else if (s.suppress) {
        s.suppressTimer = setTimeout(() => { s.suppress = false; }, ECHO_TAIL_MS);
      }
    }
  }

  let voices = [];
  function loadVoices() {
    try { voices = window.speechSynthesis ? window.speechSynthesis.getVoices() : []; } catch (e) { voices = []; }
  }

  function speakFallback(entry) {
    const synth = window.speechSynthesis;
    const text = stripTags(entry.m.text);
    if (!synth || typeof window.SpeechSynthesisUtterance !== 'function' || !text) { voiceDone(entry); return; }
    const lang = validLang(entry.m.language) || 'hi-IN';
    if (!voices.length) loadVoices();
    const want = lang.toLowerCase();
    const base = want.slice(0, 2);
    const v = voices.find((x) => x.lang && x.lang.replace('_', '-').toLowerCase() === want)
      || voices.find((x) => x.lang && x.lang.toLowerCase().startsWith(base));
    const u = new SpeechSynthesisUtterance(text);
    u.lang = lang;
    if (v) u.voice = v;
    u.rate = 0.95;
    u.onend = () => voiceDone(entry);
    u.onerror = () => voiceDone(entry);
    entry.utter = u;
    try { synth.cancel(); synth.speak(u); } catch (e) { voiceDone(entry); }
  }

  // ---------------------------------------------------------------- audio unlock (iOS)
  // iOS only lets audio start inside a tap. So the first Play/Start tap creates and resumes one AudioContext
  // that lives as long as the page (demo audio and alert clips play through it later, outside any tap),
  // and primes speechSynthesis with a silent utterance so the fallback voice may speak later too.
  function audioCtx() {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (!AC) throw new Error('audio-unsupported');
    if (!S.ctx || S.ctx.state === 'closed') {
      S.ctx = new AC({ latencyHint: 'interactive' });
      S.worklet = null;
    }
    if (S.ctx.state === 'suspended') S.ctx.resume().catch(() => {});
    return S.ctx;
  }

  let speechPrimed = false;
  function unlockAudio() {
    try { audioCtx(); } catch (e) { /* reported when the session needs it */ }
    const synth = window.speechSynthesis;
    if (speechPrimed || !synth || typeof window.SpeechSynthesisUtterance !== 'function') return;
    speechPrimed = true;
    try {
      const u = new SpeechSynthesisUtterance(' ');
      u.volume = 0;
      synth.speak(u);
    } catch (e) { /* ignore */ }
  }

  function decodeAudio(ctx, data) {
    return new Promise((resolve, reject) => {
      const p = ctx.decodeAudioData(data, resolve, reject);   // old Safari: callbacks only
      if (p && typeof p.then === 'function') p.then(resolve, reject);
    });
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
    fitAlarm();
    setTimeout(() => $('alarmOk').focus({ preventScroll: true }), 60);
  }
  // Pin the buttons to the bottom (on a solid backing) only when the alert is taller than the screen.
  // Otherwise that backing shows as a dark box on the red gradient.
  function fitAlarm() {
    const o = $('dangerOverlay');
    if (o.hidden) return;
    o.classList.remove('overflowing');
    o.classList.toggle('overflowing', o.scrollHeight > o.clientHeight + 1);
  }
  // The call is over and the summary is in: take the red overlay down (after its voice finished).
  function closeAlarmForSummary() {
    if ($('dangerOverlay').hidden) return;
    closeAlarm(true);
    const box = $('summary');
    if (!box.hidden) {
      box.scrollIntoView({ block: 'start', behavior: reducedMotion() ? 'auto' : 'smooth' });
      box.focus({ preventScroll: true });
    }
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
    $('verdict').replaceChildren(el('span', null, v.en));
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

  // Called straight from a tap: everything before the first await runs inside the user gesture.
  async function startSession(source, demo) {
    if (S.analyzing) { S.analyzing.abort(); S.analyzing = null; }
    if (S.session && S.session.state !== 'ended') finish(S.session, true);
    hideNotice();
    resetMonitor();
    stopAlertVoice();
    unlockAudio();
    if (!voices.length) loadVoices();

    const s = {
      id: ++S.seq, source, demo: demo || null, state: 'connecting', mock: null,
      ws: null, wsOpen: false, ctx: null, node: null, srcNode: null, micStream: null, media: null, speakerGain: null,
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
    const ctx = audioCtx();                          // the app-wide context (unlocked by this tap)
    s.ctx = ctx;
    if (!ctx.audioWorklet || typeof window.AudioWorkletNode !== 'function') throw new Error('worklet-unsupported');
    if (!S.worklet) {
      S.worklet = ctx.audioWorklet.addModule('/static/pcm-worklet.js');
      S.worklet.catch(() => { if (S.ctx === ctx) S.worklet = null; });
    }
    await S.worklet;
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

  // Demo audio is decoded up front and played as an AudioBuffer on the app's (already unlocked) context,
  // so it can start when the server says "ready", seconds after the tap. An <audio> element can't on iOS.
  async function setupDemoAudio(s) {
    const ctx = await makeAudioGraph(s);
    let buffer;
    try {
      const r = await fetch('/demo-audio/' + encodeURIComponent(s.demo.id) + '.wav');
      if (!r.ok) throw new Error(String(r.status));
      buffer = await decodeAudio(ctx, await r.arrayBuffer());
    } catch (e) {
      throw new Error('Could not load the demo audio file.');
    }
    if (S.session !== s || s.state === 'ended') return;
    s.speakerGain = ctx.createGain();
    s.speakerGain.connect(ctx.destination);
    s.media = makePlayer(s, ctx, buffer);
  }

  // A tiny stand-in for <audio>: play() / stop() / currentTime / an end callback.
  function makePlayer(s, ctx, buffer) {
    const p = {
      src: null, startAt: 0, duration: buffer.duration,
      get currentTime() { return p.src ? clamp(ctx.currentTime - p.startAt, 0, p.duration) : 0; },
      play() {
        const src = ctx.createBufferSource();
        src.buffer = buffer;
        src.connect(s.speakerGain);                  // speakers (ducked while an alert speaks)
        if (s.node) src.connect(s.node);             // and the worklet -> WS
        src.onended = () => {
          if (p.src !== src) return;
          if (S.session === s && s.state === 'live') later(s, DEMO_STOP_DELAY_MS, () => stopSession());
        };
        p.startAt = ctx.currentTime + 0.05;
        src.start(p.startAt);
        p.src = src;
        return ctx.state === 'running' ? Promise.resolve() : ctx.resume();
      },
      stop() {
        const src = p.src;
        p.src = null;
        if (!src) return;
        src.onended = null;
        try { src.stop(); } catch (e) { /* not started */ }
        try { src.disconnect(); } catch (e) { /* ignore */ }
      },
    };
    return p;
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
      s.wsOpen = true;
      ws.send(JSON.stringify({
        type: 'start', source: s.source, demo_id: s.demo ? String(s.demo.id) : null,
        language: s.source === 'mic' ? callLang() : 'indic-auto', warn_language: warnLang(),
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
        // The socket opened, so our server is fine: it's still waiting on Gnani's speech service.
        showNotice(s.wsOpen ? 'The speech service is slow to respond. Please try again in a moment.'
          : 'Could not reach the Kavach server. Is it running?', true);
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
      case 'alert_audio': onAlertAudio(m); break;
      case 'summary':
        s.gotSummary = true;
        renderSummary(m);
        revealDemoResult(s, m);
        // The red overlay would hide the summary: close it once its voice is done.
        if (!V.current && !V.queue.length) closeAlarmForSummary(); else V.closeWhenIdle = true;
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
          later(s, SUMMARY_WAIT_MS, () => finish(s));   // the server still sends a summary, then closes
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
      s.media.stop();
      s.media = null;
    }
    s.ctx = null;                    // the AudioContext is app-wide and stays open (alerts play through it)
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
    $('callLang').disabled = active;
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
    $('alarmReplay').addEventListener('click', replayAlert);
    $('copyBtn').addEventListener('click', copyShare);
    $('warnLang').addEventListener('change', () => {
      try { localStorage.setItem('kavach.warn2', warnLang()); } catch (e) { /* storage blocked */ }
    });
    $('callLang').addEventListener('change', () => {
      try { localStorage.setItem('kavach.callLang', callLang()); } catch (e) { /* storage blocked */ }
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
    window.addEventListener('resize', fitAlarm);
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
