// harness_credential_browser.js — drives the Claude credential card and dialog
// in a real browser (Task 20379).
//
// The task is a claim about what a person sees and does: a red chip on the
// Overview of a project whose sandbox has no Claude login, a Run button whose
// refusal opens the dialog that fixes it, a pasted token that becomes a grant
// and turns the chip amber or green, and a dialog that hands the token back to
// nobody. The DOM shim can say which endpoint was called; only a browser can
// say whether the card was on screen, whether the dialog opened over the page
// and whether the field was empty afterwards.
//
// Clicks are real mouse events at the element's on-screen position; text is
// typed with Input.insertText. Waits are on DOM state, bounded, never sleeps
// standing in for one.
//
// Usage: node harness_credential_browser.js <chrome-binary> <base-url> <token>
// Prints one JSON document on stdout: {scenario: {...}, ...}.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const TOKEN = process.argv[4];

const sleep = ms => new Promise(r => setTimeout(r, ms));

// How long Chrome gets to report its DevTools port, in 50 ms polls: 90 s.
const CHROME_START_POLLS = 1800;

function killChrome(proc) {
  try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) {
    try { proc.kill('SIGKILL'); } catch (_) { /* already gone */ }
  }
}

async function closeChrome(proc, dir) {
  killChrome(proc);
  if (proc.exitCode === null && proc.signalCode === null) {
    await new Promise(r => { proc.once('exit', r); setTimeout(r, 5000).unref(); });
  }
  try { fs.rmSync(dir, {recursive: true, force: true, maxRetries: 10, retryDelay: 100}); } catch (_) { /* best effort */ }
}

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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-harnesscred-'));
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--window-size=1400,1000',
    'about:blank',
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

// ── helpers ─────────────────────────────────────────────────────────────────

const visibleExpr = sel =>
  `(() => { const e = document.querySelector(${JSON.stringify(sel)});
     return !!e && e.getClientRects().length > 0; })()`;

async function click(cdp, sel) {
  let pt = null, hit = false;
  for (let i = 0; i < 200 && !hit; i++) {
    if (i) await sleep(50);
    pt = await cdp.eval(`(() => {
      const e = document.querySelector(${JSON.stringify(sel)});
      if (!e) return null;
      e.scrollIntoView({block: 'center'});
      const r = e.getBoundingClientRect();
      if (!r.width || !r.height) return null;
      return {x: r.left + r.width / 2, y: r.top + r.height / 2};
    })()`);
    if (!pt) continue;
    hit = await cdp.eval(`(() => {
      const e = document.elementFromPoint(${pt.x}, ${pt.y});
      const want = document.querySelector(${JSON.stringify(sel)});
      return !!e && !!want && (e === want || want.contains(e));
    })()`);
  }
  if (!pt) throw new Error('nothing clickable at ' + sel);
  if (!hit) throw new Error(sel + ' is covered by another element');
  for (const type of ['mousePressed', 'mouseReleased']) {
    await cdp.send('Input.dispatchMouseEvent', {type, x: pt.x, y: pt.y, button: 'left', clickCount: 1});
  }
}

const setSelectExpr = (sel, value) =>
  `(() => { const e = document.querySelector(${JSON.stringify(sel)});
     if (!e) return 'no element';
     e.value = ${JSON.stringify(value)};
     e.dispatchEvent(new Event('change', {bubbles: true}));
     return e.value; })()`;

// Bounded at 30 s: under -race a control-plane round trip takes seconds.
async function waitFor(cdp, expr, what) {
  for (let i = 0; i < 600; i++) {
    if (await cdp.eval(expr)) return;
    await sleep(50);
  }
  throw new Error('timed out waiting for ' + what);
}

async function fetchJSON(cdp, url) {
  return cdp.eval(`(async () => (await fetch(${JSON.stringify(url)})).json())()`);
}

// chip reads the card as a person would: is it on screen, what does it say,
// and what colour is it drawn in, against the theme's own green, yellow, red.
const chipExpr = `(() => {
  const card = document.getElementById('harnessCredCard');
  const chip = document.getElementById('harnessCredChip');
  const root = getComputedStyle(document.documentElement);
  const rgb = v => {
    const probe = document.createElement('span');
    probe.style.color = v;
    document.body.appendChild(probe);
    const c = getComputedStyle(probe).color;
    probe.remove();
    return c;
  };
  if (!card || !chip) return {present: false};
  const color = getComputedStyle(chip).color;
  const tone = color === rgb(root.getPropertyValue('--red').trim()) ? 'red'
    : color === rgb(root.getPropertyValue('--yellow').trim()) ? 'amber'
    : color === rgb(root.getPropertyValue('--green').trim()) ? 'green' : color;
  return {
    present: true,
    visible: card.getClientRects().length > 0,
    text: chip.textContent,
    sub: (document.getElementById('harnessCredSub') || {}).textContent || '',
    tone: tone,
  };
})()`;

// boot opens the project the way a person does, then waits for the card.
async function boot(cdp) {
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Page.navigate', {url: BASE + '/'});
  await waitFor(cdp, `typeof window.openProject === 'function'`, 'the bundle to load');
  const name = await cdp.eval(`(async () => {
    const d = await (await fetch('/api/projects')).json();
    return ((d && d.projects) || [])[0] ? d.projects[0].name : '';
  })()`);
  await cdp.eval(`window.openProject(0, ${JSON.stringify(name)})`);
  await waitFor(cdp, `(() => {
      const c = document.getElementById('harnessCredCard');
      return !!c && c.getClientRects().length > 0 && !!document.getElementById('harnessCredChip').textContent;
    })()`, 'the Claude credential card to be drawn');
}

const overlayOpen = visibleExpr('#harness-cred-overlay');

// ── scenarios ───────────────────────────────────────────────────────────────

const results = {};

async function scenarioRedWhenMissing(cdp) {
  results.red_when_missing = await cdp.eval(chipExpr);
}

async function scenarioRunRefusalOpensTheDialog(cdp) {
  await click(cdp, '#ctrlRun');
  await waitFor(cdp, overlayOpen, 'the dialog to open on the Run refusal');
  await waitFor(cdp, `(document.getElementById('hcRefusal') || {}).textContent.length > 0`, 'the refusal text');
  results.run_refusal_opens_dialog = {
    open: await cdp.eval(overlayOpen),
    refusal: await cdp.eval(`document.getElementById('hcRefusal').textContent`),
    toast: await cdp.eval(`document.getElementById('toast').textContent`),
    focus_inside: await cdp.eval(`document.getElementById('harness-cred-overlay').contains(document.activeElement)`),
    paste_shown: await cdp.eval(visibleExpr('#hcToken')),
    started: (await fetchJSON(cdp, '/api/projects/0/harness-credential')).state,
  };
}

async function scenarioPasteGrantsAmber(cdp) {
  // One day: inside the three-day amber window.
  await cdp.eval(setSelectExpr('#hcTTL', '1440'));
  await click(cdp, '#hcToken');
  await cdp.send('Input.insertText', {text: TOKEN});
  await click(cdp, '#hcGrant');
  await waitFor(cdp, `!(${overlayOpen})`, 'the dialog to close after granting');
  await waitFor(cdp, `(document.getElementById('harnessCredChip') || {}).textContent.indexOf(' left') >= 0`,
    'the chip to show the expiry');
  const view = await fetchJSON(cdp, '/api/projects/0/harness-credential');
  results.paste_grants_amber = Object.assign(await cdp.eval(chipExpr), {
    field_cleared: await cdp.eval(`document.getElementById('hcToken').value === ''`),
    state: view.state,
    secret: view.satisfied_by ? view.satisfied_by.secret_name : '',
    token_on_page: await cdp.eval(`document.documentElement.outerHTML.indexOf(${JSON.stringify(TOKEN)}) >= 0`),
  });
}

async function scenarioPickGrantsGreen(cdp) {
  await click(cdp, '#harnessCredCard');
  await waitFor(cdp, overlayOpen, 'the dialog to open from the card');
  await waitFor(cdp, `document.querySelectorAll('#hcSecret option[value]:not([value=""])').length > 0`,
    'the candidates to load');
  const options = await cdp.eval(`Array.from(document.querySelectorAll('#hcSecret option')).map(o => o.textContent)`);
  const id = await cdp.eval(`document.querySelector('#hcSecret option[value]:not([value=""])').value`);
  await cdp.eval(setSelectExpr('#hcSecret', id));
  await cdp.eval(setSelectExpr('#hcTTL', '43200'));
  await click(cdp, '#hcGrant');
  await waitFor(cdp, `!(${overlayOpen})`, 'the dialog to close after granting');
  await waitFor(cdp, `(document.getElementById('harnessCredChip') || {}).textContent.indexOf(' d left') >= 0`,
    'the chip to show the longer expiry');
  results.pick_grants_green = Object.assign(await cdp.eval(chipExpr), {options: options});
}

async function scenarioEscapeCloses(cdp) {
  await click(cdp, '#harnessCredCard');
  await waitFor(cdp, overlayOpen, 'the dialog to open');
  await cdp.send('Input.dispatchKeyEvent', {type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27});
  await cdp.send('Input.dispatchKeyEvent', {type: 'keyUp', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27});
  await waitFor(cdp, `!(${overlayOpen})`, 'Escape to close the dialog');
  results.escape_closes = {closed: !(await cdp.eval(overlayOpen))};
}

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  try {
    await boot(cdp);
    await scenarioRedWhenMissing(cdp);
    await scenarioRunRefusalOpensTheDialog(cdp);
    await scenarioPasteGrantsAmber(cdp);
    await scenarioPickGrantsGreen(cdp);
    await scenarioEscapeCloses(cdp);
    process.stdout.write(JSON.stringify(results, null, 2));
  } finally {
    await closeChrome(proc, dir);
  }
}

main().then(() => process.exit(0), err => {
  process.stdout.write(JSON.stringify({error: {message: String(err && err.message || err)}, partial: results}, null, 2));
  process.exit(1);
});
