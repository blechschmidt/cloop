// reviewgate_browser.js — drives the review gate's dashboard surfaces in a real
// browser (Task 20357) and reports what it saw; reviewgate_browser_test.go
// judges it.
//
//   * dialog  — the Overview's Review gate card opens the dialog on a real
//               click, the provider choice refills the model list, block mode
//               hides the fix-rounds field, and Save stores the settings and
//               updates the card without a reload.
//   * reload  — after a reload the card and a reopened dialog show what was
//               saved.
//   * task    — a task the gate blocked shows its verdict and findings in the
//               task details, and a chip in the task list.
//
// Usage: node reviewgate_browser.js <chrome-binary> <base-url>
// Prints one JSON document on stdout.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const SHOT = process.env.REVIEWGATE_SCREENSHOT_DIR || '';
const WAIT_MS = 30000;
const sleep = ms => new Promise(r => setTimeout(r, ms));

// How long Chrome gets to report its DevTools port, in 50 ms polls: 90 s.
// A cold start on a CI runner that is also running three race-instrumented
// test binaries has taken longer than the 30 s this used to allow (Task 20372).
const CHROME_START_POLLS = 1800;

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.exceptions = [];
    ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
      if (msg.method === 'Runtime.exceptionThrown') {
        const d = msg.params.exceptionDetails || {};
        this.exceptions.push(((d.exception || {}).description || d.text || '').split('\n')[0]);
      }
      if (msg.id === undefined) return;
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      // Cleared on reply: an armed 20 s timer keeps node alive after the
      // last command (Task 20356).
      clearTimeout(p.timer);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    });
  }
  send(method, params) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(method + ' timed out'));
      }, 20000);
      this.pending.set(id, {resolve, reject, timer});
      this.ws.send(JSON.stringify({id, method, params: params || {}}));
    });
  }
  async eval(expr) {
    const r = await this.send('Runtime.evaluate', {expression: expr, awaitPromise: true, returnByValue: true});
    if (r.exceptionDetails) {
      throw new Error('eval failed: ' + JSON.stringify(r.exceptionDetails.exception || r.exceptionDetails));
    }
    return r.result.value;
  }
  async clickAt(x, y) {
    const base = {x, y, button: 'left', clickCount: 1};
    await this.send('Input.dispatchMouseEvent', Object.assign({type: 'mousePressed'}, base));
    await this.send('Input.dispatchMouseEvent', Object.assign({type: 'mouseReleased'}, base));
    await sleep(15);
  }
}

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-reviewgate-'));
  const proc = spawn(CHROME, [
    '--headless=new', '--remote-debugging-port=0', '--user-data-dir=' + dir,
    // Runs as root on the dev box and unprivileged in CI; the profile is a
    // throwaway loading only a local httptest server.
    '--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--window-size=1280,900', 'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe']});
  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });
  try {
    const portFile = path.join(dir, 'DevToolsActivePort');
    let port = 0;
    for (let i = 0; i < CHROME_START_POLLS && !port; i++) {
      await sleep(50);
      if (proc.exitCode !== null) throw new Error('chrome exited: ' + stderr);
      try {
        const txt = fs.readFileSync(portFile, 'utf8').split('\n');
        if (txt[0] && txt[0].trim()) port = Number(txt[0].trim());
      } catch (e) { /* not written yet */ }
    }
    if (!port) throw new Error('chrome never reported a debugging port within ' + CHROME_START_POLLS * 50 / 1000 + 's: ' + stderr);
    const res = await fetch('http://127.0.0.1:' + port + '/json/list', {signal: AbortSignal.timeout(15000)});
    const page = (await res.json()).find(t => t.type === 'page');
    if (!page) throw new Error('no page target');
    const ws = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((ok, bad) => {
      setTimeout(() => bad(new Error('cdp connect timed out')), 15000).unref();
      ws.addEventListener('open', ok, {once: true});
      ws.addEventListener('error', () => bad(new Error('CDP socket failed')), {once: true});
    });
    return {cdp: new CDP(ws), proc, dir};
  } catch (e) {
    try { proc.kill('SIGKILL'); } catch (_) { /* already gone */ }
    throw e;
  }
}

async function waitFor(cdp, expr) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    try {
      if (await cdp.eval(expr)) return true;
    } catch (e) { /* navigating or not yet defined */ }
    if (Date.now() > deadline) return false;
    await sleep(50);
  }
}

// click presses the middle of an element with the mouse, as a person would,
// so a card that is covered or not clickable fails here.
async function click(cdp, id) {
  const box = await cdp.eval(`(() => { const e = document.getElementById(${JSON.stringify(id)});
    if (!e) return null; e.scrollIntoView({block: 'center'}); const r = e.getBoundingClientRect();
    return {x: r.left + r.width / 2, y: r.top + r.height / 2}; })()`);
  if (!box) throw new Error('no #' + id + ' to click');
  await cdp.clickAt(box.x, box.y);
}

async function shot(cdp, name) {
  if (!SHOT) return;
  const r = await cdp.send('Page.captureScreenshot', {format: 'png', captureBeyondViewport: false});
  fs.writeFileSync(path.join(SHOT, name + '.png'), Buffer.from(r.data, 'base64'));
}

const overlayOpen = `(() => { const o = document.getElementById('review-gate-overlay');
  return !!o && getComputedStyle(o).display !== 'none'; })()`;
// Parenthesised: the result is compared with === by callers, and an unwrapped
// `a || '' === b` is `a || ('' === b)`, which is always true.
const text = id => `((document.getElementById(${JSON.stringify(id)}) || {}).textContent || '')`;
const setValue = (id, v) => `(() => { const e = document.getElementById(${JSON.stringify(id)});
  e.value = ${JSON.stringify(v)}; e.dispatchEvent(new Event('change', {bubbles: true})); return e.value; })()`;

async function boot(cdp) {
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Page.navigate', {url: BASE + '/'});
  // appState lives inside the bundle's closure, out of reach from here; the
  // Provider card is filled in by the same render that fills the gate's card.
  return waitFor(cdp, `${text('statProvider')} !== '' && ${text('statProvider')} !== '—'`);
}

const results = {};

async function scenarioDialog(cdp) {
  const r = {};
  r.booted = await boot(cdp);
  r.card_before = await cdp.eval(text('statReviewGate'));
  await click(cdp, 'reviewGateCard');
  r.opened = await waitFor(cdp, overlayOpen);
  r.enabled_before = await cdp.eval(`document.getElementById('rgEnabled').checked`);
  r.focus = await cdp.eval(`document.activeElement && document.activeElement.id`);
  await cdp.eval(`document.getElementById('rgEnabled').checked = true`);
  await cdp.eval(setValue('rgProvider', 'anthropic'));
  r.models = await cdp.eval(`[...document.getElementById('rgModel').options].map(o => o.value)`);
  await cdp.eval(setValue('rgModel', 'claude-opus-5-5'));
  await cdp.eval(setValue('rgMode', 'block'));
  r.rounds_hidden_in_block = await cdp.eval(`getComputedStyle(document.getElementById('rgRoundsRow')).display === 'none'`);
  await cdp.eval(`document.getElementById('rgInstructions').value = 'Reject changes to migrations.'`);
  await shot(cdp, 'review-gate-dialog');
  const save = await cdp.eval(`(() => { const b = [...document.querySelectorAll('#review-gate-overlay .modal-footer button')]
    .find(b => b.textContent.trim() === 'Save'); b.id = 'rgSaveProbe'; return !!b; })()`);
  if (save) await click(cdp, 'rgSaveProbe');
  r.closed = await waitFor(cdp, `!${overlayOpen}`);
  r.card_updated = await waitFor(cdp, `${text('statReviewGate')} === 'claude-opus-5-5'`);
  r.card_after = await cdp.eval(text('statReviewGate'));
  r.card_sub_after = await cdp.eval(text('statReviewGateSub'));
  r.error_shown = await cdp.eval(`getComputedStyle(document.getElementById('rgError')).display !== 'none'`);
  await shot(cdp, 'review-gate-card');
  results.dialog = r;
}

async function scenarioReload(cdp) {
  const r = {};
  r.booted = await boot(cdp);
  r.card = await waitFor(cdp, `${text('statReviewGate')} === 'claude-opus-5-5'`);
  await click(cdp, 'reviewGateCard');
  r.opened = await waitFor(cdp, overlayOpen);
  r.enabled = await cdp.eval(`document.getElementById('rgEnabled').checked`);
  r.provider = await cdp.eval(`document.getElementById('rgProvider').value`);
  r.model = await cdp.eval(`document.getElementById('rgModel').value`);
  r.mode = await cdp.eval(`document.getElementById('rgMode').value`);
  r.instructions = await cdp.eval(`document.getElementById('rgInstructions').value`);
  await cdp.eval(`closeReviewGateModal()`);
  results.reload = r;
}

async function scenarioTask(cdp) {
  const r = {};
  await cdp.eval(`switchTab('tasks')`);
  // A failed task is hidden until completed tasks are shown.
  await cdp.eval(`(typeof showCompletedTasks !== 'undefined' && showCompletedTasks) || toggleCompletedTasks()`);
  r.chip = await waitFor(cdp, `(() => { const e = document.querySelector('.task-item[data-task-id="1"]');
    return !!e && e.textContent.includes('review: not published'); })()`);
  await cdp.eval(`openTaskDetails(1)`);
  r.details = await waitFor(cdp, `(document.getElementById('td-body') || {}).textContent &&
    document.getElementById('td-body').textContent.includes('Review gate: changes requested')`);
  r.details_text = await cdp.eval(`(() => { const s = [...document.querySelectorAll('#td-body .td-section')]
    .find(e => e.textContent.includes('Review gate')); return s ? s.textContent : ''; })()`);
  await shot(cdp, 'review-gate-task');
  results.task = r;
}

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  try {
    await scenarioDialog(cdp);
    await scenarioReload(cdp);
    await scenarioTask(cdp);
    results.exceptions = cdp.exceptions;
    process.stdout.write(JSON.stringify(results, null, 2));
  } finally {
    try { cdp.ws.close(); } catch (e) { /* already closed */ }
    try { proc.kill('SIGKILL'); } catch (e) { /* already gone */ }
    if (proc.exitCode === null && proc.signalCode === null) {
      await new Promise(r => { proc.once('exit', r); setTimeout(r, 5000).unref(); });
    }
    try {
      fs.rmSync(dir, {recursive: true, force: true, maxRetries: 10, retryDelay: 100});
    } catch (e) { /* best effort */ }
  }
}

main().then(() => process.exit(0), err => {
  process.stdout.write(JSON.stringify({error: {message: String(err && err.message || err)}}, null, 2));
  process.exit(1);
});
