// projectmove_browser.js — the Move dialog in a real browser against a real hub
// (Task 20496).
//
// What only a browser shows:
//
//   * that while a move holds the project its Run buttons are disabled and its
//     card on the Projects tab says it is moving, and that both come back
//     when the move ends — from the hub's projects push, not a reload;
//   * that the dialog opened on a move under way follows it phase by phase
//     from what the hub pushes over the WebSocket: it reads the move once when
//     it opens and once when it ends, and never polls in between;
//   * that a move's review keeps Move disabled until every warning is ticked,
//     that the move then runs to a verified end on screen, and that cleanup
//     waits for its own tick;
//   * that the dialog keeps the keyboard inside it, and hands focus back to
//     the button that opened it when it closes.
//
// The node side asks a control server the Go test runs to make the hub-side
// changes a person cannot: start, advance and end a move the hub is not
// driving.
//
// Usage: node projectmove_browser.js <chrome-binary> <base-url> <control-url> [screenshot-dir]
// Prints one JSON document on stdout.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const CONTROL = process.argv[4];
const SHOTS = process.argv[5] || '';

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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-projectmove-'));
  const proc = spawn(CHROME, [
    '--headless=new', '--remote-debugging-port=0', '--user-data-dir=' + dir, '--no-sandbox',
    '--disable-dev-shm-usage', '--disable-gpu', '--window-size=1400,1000', 'about:blank',
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
    const list = await (await fetch('http://127.0.0.1:' + port + '/json/list', {signal: AbortSignal.timeout(15000)})).json();
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
const text = sel => `((document.querySelector(${q(sel)}) || {}).innerText || '')`;
const face = `((document.getElementById('pm-box') || {dataset: {}}).dataset.face || '')`;
const inDialog = `(() => { const o = document.getElementById('pm-overlay'), a = document.activeElement;
  return !!o && !!a && o.contains(a); })()`;
const currentStep = `((document.querySelector('#pm-body .pm-step[aria-current="step"]') || {}).innerText || '')`;

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

// click presses an element's centre with the mouse once it is on top, and
// presses again when the page moved it between the aim and the press (see
// humangate_browser.js, whose guard this is).
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

async function key(cdp, name, code, keyCode, modifiers) {
  for (const type of ['keyDown', 'keyUp']) {
    await cdp.send('Input.dispatchKeyEvent', {type, key: name, code, windowsVirtualKeyCode: keyCode, modifiers: modifiers || 0});
  }
}

async function shot(cdp, name) {
  if (!SHOTS) return;
  const r = await cdp.send('Page.captureScreenshot', {format: 'png'});
  fs.writeFileSync(path.join(SHOTS, name + '.png'), Buffer.from(r.data, 'base64'));
}

async function control(what) {
  const r = await fetch(CONTROL + '/' + what, {method: 'POST', signal: AbortSignal.timeout(20000)});
  if (!r.ok) throw new Error('control ' + what + ': HTTP ' + r.status + ' ' + await r.text());
  return r.text();
}

const results = {};

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  // project_move frames the page's socket received, in order.
  const frames = [];
  cdp.on(msg => {
    if (msg.method !== 'Network.webSocketFrameReceived') return;
    try {
      const m = JSON.parse(msg.params.response.payloadData);
      if (m.type === 'project_move') frames.push(m.data.move.phase);
    } catch (e) { /* not ours */ }
  });
  try {
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Network.enable');
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `try { sessionStorage.setItem('cloop_resume', '{"at":0}'); } catch (e) {}
        // Every read of one move the page makes, to tell pushes from polling.
        window.__moveReads = 0;
        const f = window.fetch;
        window.fetch = function (u) {
          if (/\\/move\\/[0-9a-f]{16}(\\?|$)/.test(String(u && u.url || u))) window.__moveReads++;
          return f.apply(this, arguments);
        };`,
    });
    await cdp.send('Page.navigate', {url: BASE + '/'});
    await waitFor(cdp, `typeof window.switchTab === 'function' && sessionStorage.getItem('cloop_resume') === null`,
      'the dashboard to boot');
    await cdp.eval(`window.switchTab('overview')`);
    await waitFor(cdp, `(() => { const b = document.getElementById('moveBtn');
      return !!b && b.getClientRects().length > 0 && !b.disabled; })()`, 'the Move to… button');
    results.run_before = await cdp.eval(`document.getElementById('ctrlRun').disabled`);

    // ── A move under way: the hub's pushes, and nothing else ──────────────
    await control('seed');
    await waitFor(cdp, `document.getElementById('ctrlRun').disabled`, 'Run to wait for the move');
    results.run_while_moving = await cdp.eval(`document.getElementById('ctrlRun').disabled`);
    await cdp.eval(`window.switchTab('projects')`);
    await waitFor(cdp, `${text('#projList')}.includes('Moving to')`, 'the project card to say it is moving',
      text('#projList'));
    results.card_while_moving = await cdp.eval(`(() => {
      const c = document.querySelector('#projList .proj-card');
      const run = c && c.querySelector('[data-action="projectRun"]');
      return {text: c ? c.innerText : '', run_disabled: !!run && run.disabled};
    })()`);
    await cdp.eval(`window.switchTab('overview')`);
    await waitFor(cdp, `(() => { const b = document.getElementById('moveBtn'); return !!b && b.getClientRects().length > 0; })()`,
      'the Overview again');

    await click(cdp, '#moveBtn');
    await waitFor(cdp, `${face} === 'progress' && ${currentStep}.includes('Capture')`, 'the move under way at capture',
      `${face} + ' / ' + ${text('#pm-box')}`);
    results.progress_title = await cdp.eval(text('#pm-title'));
    results.focus_on_open = await cdp.eval(`document.activeElement && document.activeElement.id`);
    await shot(cdp, 'move-progress');
    await control('advance');
    await waitFor(cdp, `${currentStep}.includes('Seed')`, 'the pushed step to seed', `${currentStep}`);
    results.steps_done = await cdp.eval(`[...document.querySelectorAll('#pm-body .pm-step.done strong')].map(e => e.textContent)`);
    results.reads_while_moving = await cdp.eval(`window.__moveReads`);
    results.live = await cdp.eval(`document.getElementById('pm-live').textContent`);
    await control('finish');
    await waitFor(cdp, `${face} === 'result'`, 'the ended move\'s result', `${face} + ' / ' + ${text('#pm-box')}`);
    results.ended_text = await cdp.eval(text('#pm-body'));
    results.reads_after_end = await cdp.eval(`window.__moveReads`);
    await waitFor(cdp, `!document.getElementById('ctrlRun').disabled`, 'Run to come back when the move ended');
    results.run_after = await cdp.eval(`document.getElementById('ctrlRun').disabled`);
    await key(cdp, 'Escape', 'Escape', 27);
    await waitFor(cdp, `document.getElementById('pm-overlay').style.display === 'none'`, 'Escape to close the dialog');
    results.focus_after_close = await cdp.eval(`document.activeElement && document.activeElement.id`);
    results.frames_seeded = frames.slice();

    // ── A real move: review, ticks, Move, the result, cleanup ─────────────
    frames.length = 0;
    await click(cdp, '#moveBtn');
    await waitFor(cdp, `${face} === 'choose'`, 'the targets', `${face} + ' / ' + ${text('#pm-box')}`);
    results.choose_text = await cdp.eval(text('#pm-body'));
    await cdp.eval(`(() => { const r = [...document.querySelectorAll('#pm-body input[name="pmTarget"]')]
      .find(i => !i.disabled && i.closest('label').innerText.includes('host')); r.focus(); r.click(); return true; })()`);
    await waitFor(cdp, `!document.getElementById('pmCheck').disabled`, 'Review to be pressable');
    await click(cdp, '#pmCheck');
    await waitFor(cdp, `${face} === 'review'`, 'the review', `${face} + ' / ' + ${text('#pm-box')}`);
    results.review = await cdp.eval(`(() => ({
      groups: [...document.querySelectorAll('#pm-body .pm-group h3')].map(e => e.textContent),
      acks: document.querySelectorAll('#pm-body input[data-change="ack"]').length,
      remedies: document.querySelectorAll('#pm-body .pm-remedy').length,
      move_disabled: document.getElementById('pmGo').disabled,
    }))()`);
    await shot(cdp, 'move-review');

    // The keyboard stays inside: forwards round the whole dialog and back.
    const stops = await cdp.eval(`document.querySelectorAll('#pm-overlay button, #pm-overlay input, #pm-overlay [tabindex="0"]').length`);
    let escaped = 0;
    for (let i = 0; i < stops + 3; i++) {
      await key(cdp, 'Tab', 'Tab', 9);
      if (!await cdp.eval(inDialog)) escaped++;
    }
    for (let i = 0; i < stops + 3; i++) {
      await key(cdp, 'Tab', 'Tab', 9, 8);
      if (!await cdp.eval(inDialog)) escaped++;
    }
    results.tab_escapes = escaped;

    // Every warning ticked, one at a time: Move waits for the last.
    const acks = await cdp.eval(`document.querySelectorAll('#pm-body input[data-change="ack"]').length`);
    results.disabled_until_last = true;
    for (let i = 0; i < acks; i++) {
      if (!await cdp.eval(`document.getElementById('pmGo').disabled`)) results.disabled_until_last = false;
      await click(cdp, `#pm-body .pm-warning .pm-finding:nth-of-type(${i + 1}) input[data-change="ack"]`);
    }
    results.enabled_after_ticks = await cdp.eval(`!document.getElementById('pmGo').disabled`);
    await click(cdp, '#pmGo');
    await waitFor(cdp, `${face} === 'result'`, 'the move\'s result', `${face} + ' / ' + ${text('#pm-box')}`);
    results.result_text = await cdp.eval(text('#pm-body'));
    results.frames_real = frames.slice();
    results.clean_disabled_first = await cdp.eval(`document.getElementById('pmClean').disabled`);
    await shot(cdp, 'move-result');
    await click(cdp, '#pmConfirm');
    await waitFor(cdp, `!document.getElementById('pmClean').disabled`, 'Clean up to be pressable after the tick');
    await click(cdp, '#pmClean');
    await waitFor(cdp, `${text('#pm-body')}.includes('Cleaned up')`, 'the cleanup to be done', text('#pm-box'));
    results.cleaned_text = await cdp.eval(text('#pm-body'));
    await shot(cdp, 'move-cleaned');
    results.errors = await cdp.eval(`((document.getElementById('pm-error') || {}).textContent || '')`);
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
