// executor_pools_browser.js — the Executors tab's executor pools, in a real
// browser against a real hub served over TLS (Task 20486).
//
// What only a browser shows:
//
//   * the seeded pool's card: its demand, runners, volumes, controller and
//     last contact, and the problems the hub reports for it;
//   * that "+ Add Kubernetes pool" opens a dialog that keeps keyboard focus
//     inside it — Tab and Shift+Tab cycle its controls, Escape closes it and
//     hands focus back to the button that opened it;
//   * that creating a pool shows, once, the commands that install its
//     controller with the hub's address and the credential filled in, focused
//     on Copy, and that the result fits a 360 px phone;
//   * that Cordon (through the page's prompt) and Revoke (through its confirm)
//     change the card, and that a task run on a pool's runner names the pool
//     and the runner in its details.
//
// Usage: node executor_pools_browser.js <chrome-binary> <base-url> [screenshot-dir]
// Prints one JSON document on stdout.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const SHOTS = process.argv[4] || '';

const sleep = ms => new Promise(r => setTimeout(r, ms));
const CHROME_START_POLLS = 1800;
const WAIT_MS = 30000;

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.handlers = [];
    ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id === undefined) {
        for (const h of this.handlers) h(msg);
        return;
      }
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      clearTimeout(p.timer);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    });
  }
  on(fn) { this.handlers.push(fn); }
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
}

function killChrome(proc) {
  try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) {
    try { proc.kill('SIGKILL'); } catch (_) { /* already gone */ }
  }
}

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-pools-'));
  const proc = spawn(CHROME, [
    '--headless=new', '--remote-debugging-port=0', '--user-data-dir=' + dir, '--no-sandbox',
    '--disable-dev-shm-usage', '--disable-gpu', '--window-size=1400,1000',
    // The hub's certificate is httptest's own.
    '--ignore-certificate-errors', 'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe'], detached: true});
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
    if (!port) throw new Error('chrome never reported a debugging port: ' + stderr);
    const list = await (await fetch('http://127.0.0.1:' + port + '/json/list',
      {signal: AbortSignal.timeout(15000)})).json();
    const page = list.find(t => t.type === 'page');
    if (!page) throw new Error('no page target');
    const ws = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((res, rej) => {
      const timer = setTimeout(() => rej(new Error('cdp connect timed out')), 15000);
      ws.addEventListener('open', () => { clearTimeout(timer); res(); }, {once: true});
      ws.addEventListener('error', () => { clearTimeout(timer); rej(new Error('cdp connect failed')); }, {once: true});
    });
    return {cdp: new CDP(ws), proc, dir};
  } catch (e) {
    killChrome(proc);
    throw e;
  }
}

const q = s => JSON.stringify(s);
const text = sel => `((document.querySelector(${q(sel)}) || {}).textContent || '')`;
const visible = sel => `(() => { const e = document.querySelector(${q(sel)});
  return !!e && e.getClientRects().length > 0; })()`;
const card = name => `[...document.querySelectorAll('#poolList .exec-card')].find(c =>
  (c.querySelector('.exec-name') || {}).textContent === ${q(name)})`;

async function waitFor(cdp, expr, what, diag) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    let v = false;
    try { v = await cdp.eval(expr); } catch (e) { /* navigating */ }
    if (v) return v;
    if (Date.now() >= deadline) {
      let said = '';
      try { said = diag ? ' — the page shows: ' + await cdp.eval(diag) : ''; } catch (e) { /* gone */ }
      throw new Error('timed out waiting for ' + what + said);
    }
    await sleep(25);
  }
}

// click is humangate_browser.js's: aim, arm a guard that swallows a press that
// lands elsewhere, press, and aim again if the element moved.
async function click(cdp, sel) {
  const deadline = Date.now() + WAIT_MS;
  let why = '';
  for (let i = 0; i === 0 || Date.now() < deadline; i++) {
    if (i) await sleep(50);
    const pt = await cdp.eval(`(() => {
      const e = document.querySelector(${q(sel)});
      if (!e) return null;
      e.scrollIntoView({block: 'center'});
      const r = e.getBoundingClientRect();
      if (!r.width || !r.height) return null;
      return {x: r.left + r.width / 2, y: r.top + r.height / 2};
    })()`);
    if (!pt) { why = 'nothing clickable at ' + sel; continue; }
    const armed = await cdp.eval(`(() => {
      const e = document.elementFromPoint(${pt.x}, ${pt.y});
      const want = document.querySelector(${q(sel)});
      if (!e || !want || !(e === want || want.contains(e))) return false;
      const seen = {}, types = ['mousedown', 'mouseup', 'click'];
      const guard = ev => {
        if (!ev.isTrusted) return;
        seen[ev.type] = ev.target === want || want.contains(ev.target);
        if (!seen[ev.type]) { ev.preventDefault(); ev.stopImmediatePropagation(); }
      };
      types.forEach(t => window.addEventListener(t, guard, true));
      window.__pressSeen = () => new Promise(res => setTimeout(() => {
        types.forEach(t => window.removeEventListener(t, guard, true));
        res(seen);
      }, 'click' in seen ? 0 : 100));
      return true;
    })()`);
    if (!armed) { why = sel + ' is covered by another element'; continue; }
    for (const type of ['mousePressed', 'mouseReleased']) {
      await cdp.send('Input.dispatchMouseEvent', {type, x: pt.x, y: pt.y, button: 'left', clickCount: 1});
    }
    const seen = await cdp.eval(`window.__pressSeen()`);
    if (seen.click === true) return;
    why = 'click' in seen ? sel + ' moved between the aim and the press' : 'a press on ' + sel + ' brought no click';
  }
  throw new Error(why);
}

async function key(cdp, k, shift) {
  const codes = {Tab: 9, Escape: 27};
  for (const type of ['keyDown', 'keyUp']) {
    await cdp.send('Input.dispatchKeyEvent', {type, key: k, code: k, windowsVirtualKeyCode: codes[k],
      modifiers: shift ? 8 : 0});
  }
}

// setValue types a value the way the page reads it: the value, then input.
const setValue = (cdp, id, v) => cdp.eval(`(() => { const e = document.getElementById(${q(id)});
  e.focus(); e.value = ${q(v)}; e.dispatchEvent(new Event('input', {bubbles: true})); return true; })()`);

async function shot(cdp, name) {
  if (!SHOTS) return;
  const r = await cdp.send('Page.captureScreenshot', {format: 'png'});
  fs.writeFileSync(path.join(SHOTS, name + '.png'), Buffer.from(r.data, 'base64'));
}

async function viewport(cdp, w, h, mobile) {
  await cdp.send('Emulation.setDeviceMetricsOverride', {width: w, height: h, deviceScaleFactor: mobile ? 3 : 1, mobile: !!mobile});
  await sleep(150);
}

const activeInOverlay = `(() => { const o = document.getElementById('pool-overlay'), a = document.activeElement;
  return !!o && !!a && o.contains(a) && a !== o; })()`;

const results = {};

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  // The page's prompt and confirm, answered as a person would.
  const answers = [];
  cdp.on(msg => {
    if (msg.method !== 'Page.javascriptDialogOpening') return;
    const p = msg.params;
    answers.push(p.type + ': ' + p.message);
    cdp.send('Page.handleJavaScriptDialog', {accept: true,
      promptText: p.type === 'prompt' ? 'maintenance window' : undefined}).catch(() => {});
  });
  try {
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `try { sessionStorage.setItem('cloop_resume', '{"at":0}'); } catch (e) {}`,
    });
    await cdp.send('Page.navigate', {url: BASE + '/?tab=executors'});
    await waitFor(cdp, `sessionStorage.getItem('cloop_resume') === null`, 'the dashboard to boot');
    await cdp.eval(`window.switchTab('executors')`);
    await waitFor(cdp, `!!${card('seeded-pool')}`, 'the seeded pool\'s card', text('#poolSection'));
    await waitFor(cdp, `${card('seeded-pool')}.textContent.includes('stuck Pending')`, 'the seeded pool\'s problems',
      text('#poolList'));
    results.card = await cdp.eval(`${card('seeded-pool')}.innerText`);
    results.runner_cards = await cdp.eval(`[...document.querySelectorAll('#execList .exec-name')].map(e => e.textContent)`);
    await shot(cdp, 'pools-list');

    // The dialog, and focus inside it.
    await click(cdp, '#poolSection [data-act="addPool"]');
    await waitFor(cdp, `window.isOverlayOpen('pool-overlay') && document.activeElement && document.activeElement.id === 'poolName'`,
      'the dialog, focused on its name', `(document.activeElement || {}).id`);
    results.focus_initial = await cdp.eval(`document.activeElement.id`);
    let escaped = 0, stops = new Set();
    for (let i = 0; i < 24; i++) {
      await key(cdp, 'Tab', false);
      if (!(await cdp.eval(activeInOverlay))) escaped++;
      stops.add(await cdp.eval(`document.activeElement.id || document.activeElement.textContent.trim()`));
    }
    for (let i = 0; i < 8; i++) {
      await key(cdp, 'Tab', true);
      if (!(await cdp.eval(activeInOverlay))) escaped++;
    }
    results.tab_escaped = escaped;
    results.tab_stops = [...stops];
    await key(cdp, 'Escape', false);
    await waitFor(cdp, `!window.isOverlayOpen('pool-overlay')`, 'Escape to close the dialog');
    results.focus_after_escape = await cdp.eval(`(document.activeElement || {}).dataset ? document.activeElement.dataset.act || '' : ''`);

    // Create a pool, with volumes.
    await click(cdp, '#poolSection [data-act="addPool"]');
    await waitFor(cdp, visible('#poolName'), 'the dialog again');
    await setValue(cdp, 'poolName', 'browser-pool');
    await setValue(cdp, 'poolMax', '2');
    await setValue(cdp, 'poolLabels', 'zone=eu-1');
    await setValue(cdp, 'poolAudience', 'group:qa');
    await click(cdp, '#poolPersist');
    await waitFor(cdp, visible('#poolSize'), 'the volume fields');
    results.namespace_placeholder = await cdp.eval(`document.getElementById('poolNamespace').placeholder`);
    await setValue(cdp, 'poolSize', '30Gi');
    await click(cdp, '#poolSubmitBtn');
    await waitFor(cdp, visible('#poolResult'), 'the result', text('#poolError'));
    results.command = await cdp.eval(text('#poolCommand'));
    results.notice = await cdp.eval(text('#poolNotice'));
    results.notes = await cdp.eval(text('#poolNotes'));
    results.focus_result = await cdp.eval(`(document.activeElement || {}).id`);
    await shot(cdp, 'pools-result');

    // The result on a 360 px phone: nothing wider than the screen, and the
    // footer reachable inside the dialog.
    await viewport(cdp, 360, 780, true);
    results.phone = await cdp.eval(`(() => {
      const box = document.querySelector('#pool-overlay > div'), pre = document.getElementById('poolCommand');
      const done = document.getElementById('poolDoneBtn');
      done.scrollIntoView({block: 'nearest'});
      const r = box.getBoundingClientRect(), d = done.getBoundingClientRect();
      return {page_overflow: document.documentElement.scrollWidth - window.innerWidth,
        box_left: Math.round(r.left), box_right: Math.round(r.right), width: window.innerWidth,
        pre_overflow: pre.scrollWidth - pre.clientWidth,
        done_visible: d.top >= 0 && d.bottom <= window.innerHeight && d.left >= 0 && d.right <= window.innerWidth};
    })()`);
    await shot(cdp, 'pools-result-phone');
    await viewport(cdp, 1400, 1000, false);
    await click(cdp, '#poolDoneBtn');
    await waitFor(cdp, `!window.isOverlayOpen('pool-overlay') && !!${card('browser-pool')}`, 'the new pool\'s card',
      text('#poolList'));
    // The credential left the page with the dialog.
    results.left_in_page = await cdp.eval(`document.getElementById('pool-overlay').textContent.includes('cloop_pool1_')`);
    results.new_card = await cdp.eval(`${card('browser-pool')}.innerText`);

    // Cordon, through the page's prompt, then revoke, through its confirm.
    await click(cdp, `#poolList .exec-card[data-pool] button[data-act="cordonPool"][data-arg="${await cdp.eval(
      `[...document.querySelectorAll('#poolList .exec-card')].indexOf(${card('browser-pool')})`)}"]`);
    await waitFor(cdp, `${card('browser-pool')}.textContent.includes('maintenance window')`, 'the card to say it is cordoned',
      `${card('browser-pool')}.innerText`);
    results.cordoned_card = await cdp.eval(`${card('browser-pool')}.innerText`);
    const idx = await cdp.eval(`[...document.querySelectorAll('#poolList .exec-card')].indexOf(${card('browser-pool')})`);
    await click(cdp, `#poolList button[data-act="revokePool"][data-arg="${idx}"]`);
    await waitFor(cdp, `!${card('browser-pool')}`, 'the revoked pool to leave the list', text('#poolList'));
    results.answers = answers;

    // A task its run had on a pool's runner names the pool and the runner.
    await cdp.eval(`window.switchTab('tasks')`);
    await waitFor(cdp, `typeof window.openTaskDetails === 'function'`, 'the task details');
    await cdp.eval(`window.openTaskDetails(1)`);
    await waitFor(cdp, `[...document.querySelectorAll('#td-body .td-chip')].some(c => c.textContent.startsWith('Pool'))`,
      'the task\'s pool chip', text('#td-body .td-meta'));
    results.task_chip = await cdp.eval(`[...document.querySelectorAll('#td-body .td-chip')].find(c =>
      c.textContent.startsWith('Pool')).textContent`);
  } finally {
    killChrome(proc);
    try { fs.rmSync(dir, {recursive: true, force: true, maxRetries: 5}); } catch (_) { /* best effort */ }
  }
}

main().then(() => {
  process.stdout.write(JSON.stringify(results));
  process.exit(0);
}, e => {
  results.error = {message: String(e && e.stack || e)};
  process.stdout.write(JSON.stringify(results));
  process.exit(0);
});
