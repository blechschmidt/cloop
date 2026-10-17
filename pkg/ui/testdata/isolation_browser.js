// isolation_browser.js — the isolation evidence on an executor's card, in a
// real browser (Task 20439).
//
// The verdict is drawn by the deferred execadmin script onto cards the bundle
// rendered, after every redraw, and its Re-probe button is wired by that script
// rather than by an attribute. Neither is visible to testdata/domshim.js, which
// builds no DOM from markup: a querySelector there finds nothing, so a chip
// that never appeared and one that did would read the same. This boots the real
// dashboard against a real hub, opens the Executors tab, reads the card a user
// would read, and presses the button.
//
// Usage: node isolation_browser.js <chrome-binary> <base-url> <executor-id>
// Prints one JSON document on stdout.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const EXEC_ID = process.argv[4];

const sleep = ms => new Promise(r => setTimeout(r, ms));

// How long Chrome gets to report its DevTools port, in 50 ms polls: 90 s.
// A cold start on a CI runner that is also running three race-instrumented
// test binaries has taken longer than the 30 s this used to allow (Task 20372).
const CHROME_START_POLLS = 1800;

// Chrome runs in its own process group (spawned detached), so one signal takes
// its helpers with it; killing only the browser leaves them writing into a
// profile that is being deleted.
function killChrome(proc) {
  try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) {
    try { proc.kill('SIGKILL'); } catch (_) { /* already gone */ }
  }
}

// closeChrome kills Chrome, waits for it to be gone (bounded, and unref'd so
// the wait cannot hold node open) and removes the profile, retrying while the
// last helpers let go of it. Best effort: cleanup never fails a run.
async function closeChrome(proc, dir) {
  killChrome(proc);
  if (proc.exitCode === null && proc.signalCode === null) {
    await new Promise(r => { proc.once('exit', r); setTimeout(r, 5000).unref(); });
  }
  try { fs.rmSync(dir, {recursive: true, force: true, maxRetries: 10, retryDelay: 100}); } catch (_) { /* best effort */ }
}

// WAIT_MS bounds each wait for the page to reach a state; it is how long to
// keep looking before giving up, not a pause a healthy run sits out. Every
// round trip this panel makes opens the control-plane database, which under
// -race on a 4-core box with the CPU saturated takes seconds rather than the
// milliseconds a quiet machine needs. 30s leaves ample margin over that, and
// the handful of waits a run makes stay inside the 4-minute bound the Go side
// puts on this driver even if every one of them expires.
const WAIT_MS = 30000;

// waitFor polls a page expression until it is truthy or WAIT_MS passes, and
// reports which. The fixed sleeps it replaces were sized on a quiet machine:
// under load the panel's own requests land after the sleep has expired, and
// the driver then typed into a form that was about to be overwritten.
async function waitFor(cdp, expr) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    if (await cdp.eval(expr)) return true;
    if (Date.now() >= deadline) return false;
    await sleep(50);
  }
}

// ── a minimal CDP client ────────────────────────────────────────────────────
//
// The same shape as ptt_browser.js's. Duplicated rather than shared because
// these drivers are standalone node scripts with no module system between them,
// and a require() across testdata/ would make each one's "run this file" story
// depend on the other's layout.

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id === undefined) return;
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    });
  }
  send(method, params) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      // Cleared on the reply: a timer left armed keeps node alive for its
      // whole span after the last command, which cost every run of this
      // driver up to 20 s (Task 20372).
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(method + ' timed out'));
      }, 20000);
      this.pending.set(id, {
        resolve: v => { clearTimeout(timer); resolve(v); },
        reject: e => { clearTimeout(timer); reject(e); },
      });
      this.ws.send(JSON.stringify({id, method, params: params || {}}));
    });
  }
  async eval(expr) {
    const r = await this.send('Runtime.evaluate', {
      expression: expr, awaitPromise: true, returnByValue: true,
    });
    if (r.exceptionDetails) {
      throw new Error('eval failed: ' + JSON.stringify(r.exceptionDetails.exception || r.exceptionDetails));
    }
    return r.result.value;
  }
}

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-isolation-'));
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    // Root on this project's dev box, unprivileged in CI. See ptt_browser.js.
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe'], detached: true});

  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });

  // A launch that fails after the spawn must take Chrome with it. Left
  // running, it holds this process's stderr pipe open, node never exits,
  // and the Go test waiting on node hangs until the package timeout — the
  // 20-minute CI hang Task 20340 traced to a Chrome slow to report its port.
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

    const list = await (await fetch('http://127.0.0.1:' + port + '/json/list', {signal: AbortSignal.timeout(15000)})).json();
    const page = list.find(t => t.type === 'page');
    if (!page) throw new Error('no page target');

    const ws = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((res, rej) => {
      setTimeout(() => rej(new Error('cdp connect timed out')), 15000).unref();
      ws.addEventListener('open', res, {once: true});
      ws.addEventListener('error', () => rej(new Error('cdp connect failed')), {once: true});
    });
    return {cdp: new CDP(ws), proc, dir};
  } catch (e) {
    killChrome(proc);
    throw e;
  }
}

// ── the scenario ────────────────────────────────────────────────────────────

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  const out = {};
  try {
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Page.navigate', {url: BASE + '/'});
    if (!await waitFor(cdp, `typeof window.panelAct === 'function' && typeof window.switchTab === 'function'`)) {
      throw new Error('the bundle never defined panelAct and switchTab');
    }
    const card = `(() => { for (const c of document.querySelectorAll('#execList .exec-card')) {
        if (c.textContent.indexOf(${JSON.stringify(EXEC_ID)}) >= 0) return c; } return null; })()`;
    // Selected again on every poll: the dashboard's own boot may still pick
    // the tab it restores after this driver picked Executors, and a chip drawn
    // on a hidden tab is drawn but not seen.
    out.chip_drawn = await waitFor(cdp, `(() => { window.switchTab('executors'); const c = ${card};
      const chip = c && c.querySelector('[data-iso]'); return !!(chip && chip.getClientRects().length); })()`);
    Object.assign(out, await cdp.eval(`(() => {
      const c = ${card};
      if (!c) return {card: false};
      const chip = c.querySelector('[data-iso]');
      const kata = Array.from(c.querySelectorAll('.exec-chip')).find(e => e.textContent === 'kata / VM');
      const btn = Array.from(c.querySelectorAll('button')).find(b => b.textContent === 'Re-probe');
      return {
        card: true,
        chip_text: chip ? chip.textContent : '',
        chip_negative: !!(chip && chip.classList.contains('neg')),
        chip_title: chip ? chip.title : '',
        chip_visible: !!(chip && chip.getClientRects().length),
        kata_chip_negative: !!(kata && kata.classList.contains('neg')),
        reprobe_button: !!btn,
      };
    })()`));
    // A redraw — every executor event causes one — must not lose the chip or
    // double it.
    await cdp.eval(`window.loadExecutors()`);
    await waitFor(cdp, `(() => { const c = ${card}; return !!(c && c.querySelector('[data-iso]')); })()`);
    out.chips_after_redraw = await cdp.eval(`(() => { const c = ${card}; return c ? c.querySelectorAll('[data-iso]').length : -1; })()`);
    // Press Re-probe as a user does; the card itself must not open its drill-in.
    await cdp.eval(`(() => { const t = document.getElementById('toast'); if (t) { t.className = ''; t.textContent = ''; } })()`);
    out.clicked = await cdp.eval(`(() => { const c = ${card};
      const btn = c && Array.from(c.querySelectorAll('button')).find(b => b.textContent === 'Re-probe');
      if (!btn) return false; btn.click(); return true; })()`);
    out.toast_ok = await waitFor(cdp, `(() => { const t = document.getElementById('toast');
      return !!t && t.textContent.indexOf('Probing') >= 0; })()`);
    out.detail_opened = await cdp.eval(`(() => { const o = document.getElementById('executor-detail-overlay');
      return !!o && o.style.display !== 'none' && o.getClientRects().length > 0; })()`);
    process.stdout.write(JSON.stringify(out, null, 2));
  } finally {
    await closeChrome(proc, dir);
  }
}

main().then(() => process.exit(0), err => {
  process.stdout.write(JSON.stringify({error: String(err && err.message || err)}, null, 2));
  process.exit(1);
});
