/* Who said this line? Matches a live transcript to the demo script line it came from.
 *
 * Live Gnani text is close to the script but never verbatim: code-mix spellings differ ("हेलो" / "Hello"),
 * and VAD splits or merges lines. So score each script line by how much of the transcript's wording it
 * contains, with words that appear in many lines counting less. Lines that haven't started yet can't match.
 * Loaded as a plain script (window.ScamLingoSpeaker) and by the Node test (module.exports).
 */
(function (root) {
  'use strict';

  function tokens(text) {
    return String(text || '')
      .normalize('NFC')
      .replace(/\u093C/g, '')            // nukta (dot below), e.g. phone written two ways
      .replace(/\u0901/g, '\u0902')      // chandrabindu vs anusvara, e.g. maangta written two ways
      .toLowerCase()
      .split(/[^\p{L}\p{M}\p{N}]+/u)
      .filter(Boolean);
  }

  // Index of the script line that best explains `text`, or -1 when nothing matches well enough.
  // `t` is the call time in seconds when the transcript arrived (optional).
  function matchLine(timeline, text, t, minScore) {
    if (!Array.isArray(timeline) || !timeline.length) return -1;
    const want = [...new Set(tokens(text))];
    if (!want.length) return -1;
    const sets = timeline.map((l) => new Set(tokens(l.text)));
    const df = new Map();
    for (const set of sets) for (const w of set) df.set(w, (df.get(w) || 0) + 1);
    const weight = (w) => 1 / (df.get(w) || 1);
    const total = want.reduce((sum, w) => sum + weight(w), 0);

    let best = -1, bestScore = 0;
    for (let i = 0; i < timeline.length; i++) {
      if (typeof t === 'number' && typeof timeline[i].start === 'number' && timeline[i].start > t + 0.5) continue;
      let hit = 0;
      for (const w of want) if (sets[i].has(w)) hit += weight(w);
      const score = hit / total;
      if (score <= 0) continue;
      // Near-ties go to the later line: the transcript is about what was just said.
      if (best < 0 || score >= bestScore - 0.05) { best = i; bestScore = Math.max(score, bestScore); }
    }
    return bestScore >= (minScore == null ? 0.3 : minScore) ? best : -1;
  }

  const api = { tokens, matchLine };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.ScamLingoSpeaker = api;
})(typeof window !== 'undefined' ? window : globalThis);
