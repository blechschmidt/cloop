// jsstrip_oracle.js — checks the Go comment stripper (pkg/ui/jsstrip.go)
// against acorn, a real JavaScript parser. See jsstrip_test.go.
//
// Usage: node jsstrip_oracle.js <acorn-module-dir> <raw.js> <stripped.js>
// Prints one JSON document: {ok, blanked, comment_lines, mismatches, tokens_equal, error}.
'use strict';
const fs = require('fs');
const acorn = require(process.argv[2]);
const raw = fs.readFileSync(process.argv[3], 'utf8');
const stripped = fs.readFileSync(process.argv[4], 'utf8');
const opts = {ecmaVersion: 'latest', sourceType: 'script', allowHashBang: true};

const out = {ok: false, blanked: 0, comment_lines: 0, mismatches: [], tokens_equal: false};
try {
  // Lines acorn says are whole-line comments: a line comment that is the
  // first thing on its line.
  const lineStarts = [0];
  for (let i = 0; i < raw.length; i++) if (raw[i] === '\n') lineStarts.push(i + 1);
  const lineOf = pos => {
    let lo = 0, hi = lineStarts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (lineStarts[mid] <= pos) lo = mid; else hi = mid - 1; }
    return lo;
  };
  const commentLines = new Set();
  acorn.parse(raw, Object.assign({}, opts, {
    onComment(block, text, start) {
      if (block) return;
      const ln = lineOf(start);
      if (raw.slice(lineStarts[ln], start).trim() === '') commentLines.add(ln);
    },
  }));
  out.comment_lines = commentLines.size;

  const rl = raw.split('\n'), sl = stripped.split('\n');
  if (rl.length !== sl.length) throw new Error('line count differs: ' + rl.length + ' vs ' + sl.length);
  for (let i = 0; i < rl.length; i++) {
    const blanked = rl[i] !== sl[i];
    if (blanked) out.blanked++;
    if (blanked && (sl[i].replace(/\r$/, '') !== '' || !commentLines.has(i))) out.mismatches.push({line: i + 1, why: 'blanked but not a whole-line comment'});
    if (!blanked && commentLines.has(i)) out.mismatches.push({line: i + 1, why: 'whole-line comment kept'});
    if (out.mismatches.length > 20) break;
  }

  // The token streams must be identical once comments are gone.
  const toks = src => {
    const t = [];
    for (const tok of acorn.tokenizer(src, opts)) t.push(tok.type.label + '\u0000' + (tok.value === undefined ? '' : String(tok.value)));
    return t;
  };
  const a = toks(raw), b = toks(stripped);
  out.tokens_equal = a.length === b.length && a.every((x, i) => x === b[i]);
  out.ok = out.mismatches.length === 0 && out.tokens_equal;
} catch (e) {
  out.error = String(e && e.stack || e);
}
process.stdout.write(JSON.stringify(out));
