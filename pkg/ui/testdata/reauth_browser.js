// reauth_browser.js — the "Confirm it's you" dialog in a real browser
// (Task 20448).
//
// A refused enrollment from a session whose sign-in is three hours old must
// open the dialog; Cancel must give the click back; "Sign in again" must open
// the identity provider in a window of its own, and the enrollment must then go
// through from the page it was made on, carrying what was typed. Then, at
// 360px and with windows refused, the tab itself goes to the provider, comes
// back to the Executors tab and asks for the button once more — which then
// works.
//
// Usage: node reauth_browser.js <chrome-binary> <hub-url> <control-url>
// Prints one JSON document on stdout.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const CONTROL = process.argv[4];

const sleep = ms => new Promise(r => setTimeout(r, ms));
const CHROME_START_POLLS = 1800;
// How long to keep looking, not a pause a healthy run sits out.
const WAIT_MS = 30000;

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.handlers = new Map();
    ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id === undefined) {
        for (const fn of this.handlers.get(msg.method) || []) fn(msg.params);
        return;
      }
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    });
  }
  on(method, fn) {
    if (!this.handlers.has(method)) this.handlers.set(method, []);
    this.handlers.get(method).push(fn);
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
  async eval(expr, gesture) {
    const r = await this.send('Runtime.evaluate',
      {expression: expr, awaitPromise: true, returnByValue: true, userGesture: !!gesture});
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-reauth-'));
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--window-size=1280,900',
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

async function ctl(method, p) {
  const r = await fetch(CONTROL + p, {method, signal: AbortSignal.timeout(15000)});
  if (!r.ok) throw new Error(method + ' ' + p + ' = ' + r.status);
  return method === 'GET' ? r.json() : null;
}

async function evalSafe(cdp, expr) {
  try { return await cdp.eval(expr); } catch (_) { return undefined; }
}

async function waitFor(cdp, expr, what) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    if (await evalSafe(cdp, expr)) return;
    if (Date.now() >= deadline) {
      const diag = await evalSafe(cdp, `JSON.stringify({loc: location.href,
        ra: (document.getElementById('ra-overlay') || {style: {}}).style.display,
        status: (document.getElementById('ra-status') || {}).textContent,
        err: (document.getElementById('enrollError') || {}).textContent,
        toast: (document.getElementById('toast') || {}).textContent})`);
      throw new Error('timed out waiting for ' + what + ' (' + diag + ')');
    }
    await sleep(50);
  }
}

// A document that has run the bundle, holds a session, has finished booting,
// and is not the one marked before a navigation was asked for. Boot's last step
// (resumeView) removes cloop_resume, and BOOT_MARK seeds a stale one into every
// document that has none — so its absence means boot is over, and the view the
// driver sets is not switched away under it (pkg-ui-test-notes, the boot race).
const READY = `!window.__old && typeof window.switchTab === 'function' &&
  document.getElementById('userChip').style.display === 'flex' &&
  sessionStorage.getItem('cloop_resume') === null`;

// BOOT_MARK runs before any script of every document: it seeds the boot marker
// — never over the real one signInAgain leaves for the way back — and records
// every toast from the first, since the one a returning tab shows is raised
// during boot, before the driver's spies exist.
const BOOT_MARK = `(() => {
  try { if (sessionStorage.getItem('cloop_resume') === null) sessionStorage.setItem('cloop_resume', '{"at":0}'); } catch (_) {}
  window.__bootToasts = [];
  document.addEventListener('DOMContentLoaded', () => {
    const t = document.getElementById('toast');
    if (t) new MutationObserver(() => window.__bootToasts.push(t.textContent))
      .observe(t, {attributes: true, childList: true, characterData: true, subtree: true});
  });
})()`;

// What a person would have seen: error toasts, and the last toast of any kind.
const SPIES = `(() => {
  window.__errToasts = [];
  window.__toasts = [];
  const t = document.getElementById('toast');
  new MutationObserver(() => {
    window.__toasts.push(t.textContent);
    if (/\\berror\\b/.test(t.className)) window.__errToasts.push(t.textContent);
  }).observe(t, {attributes: true, childList: true, characterData: true, subtree: true});
  return true;
})()`;

const DIALOG_OPEN = `(() => { const o = document.getElementById('ra-overlay');
  return !!o && o.style.display === 'flex'; })()`;
const DIALOG_CLOSED = `(() => { const o = document.getElementById('ra-overlay');
  return !o || o.style.display !== 'flex'; })()`;

// openEnroll opens the Executors tab's enrollment dialog and submits name.
async function submitEnrollment(cdp, name) {
  await cdp.eval(`window.switchTab('executors')`);
  await waitFor(cdp, `!!document.querySelector('[data-action="openEnrollModal"]') &&
    document.getElementById('tab-executors').classList.contains('active')`, 'the Executors tab');
  await cdp.eval(`document.querySelector('[data-action="openEnrollModal"]').click()`, true);
  await waitFor(cdp, `(() => { const o = document.getElementById('enroll-overlay');
    return !!o && o.style.display === 'flex' && !!document.getElementById('enrollName'); })()`, 'the enrollment dialog');
  await cdp.eval(`document.getElementById('enrollName').value = ${JSON.stringify(name)}`);
  await cdp.eval(`document.getElementById('enrollSubmitBtn').click()`, true);
}

// shot saves what the page shows when REAUTH_SHOTS names a directory: for a
// person to look at the dialog, not for the test to judge.
async function shot(cdp, name) {
  const dir = process.env.REAUTH_SHOTS;
  if (!dir) return;
  const r = await cdp.send('Page.captureScreenshot', {format: 'png'});
  fs.writeFileSync(path.join(dir, name + '.png'), Buffer.from(r.data, 'base64'));
}

const ENROLLED = `(() => { const r = document.getElementById('enrollResult');
  return !!r && r.style.display === 'block' && !!document.getElementById('enrollCommand').textContent; })()`;

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  const out = {enroll_statuses: []};
  const csp = [];
  const enrollBodies = new Map();
  try {
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Network.enable');
    await cdp.send('Log.enable');
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {source: BOOT_MARK});
    cdp.on('Network.requestWillBeSent', p => {
      if (p.request.url.endsWith('/api/executors/enroll')) enrollBodies.set(p.requestId, p.request.postData || '');
    });
    cdp.on('Network.responseReceived', p => {
      if (p.response.url.endsWith('/api/executors/enroll')) {
        out.enroll_statuses.push(p.response.status);
        if (p.response.status === 200) out.last_enroll_body = enrollBodies.get(p.requestId) || '';
      }
    });
    cdp.on('Log.entryAdded', p => {
      if (/Content Security Policy/i.test(p.entry.text)) csp.push(p.entry.text);
    });

    // ── 1. a window of its own ──
    await cdp.send('Page.navigate', {url: BASE + '/'});
    await waitFor(cdp, READY, 'the dashboard to load with a session');
    await cdp.eval(SPIES);
    const w = {};
    await submitEnrollment(cdp, 'edge-browser');
    await waitFor(cdp, DIALOG_OPEN, 'the dialog after a refused enrollment');
    w.dialog_shown = true;
    w.window_text = await cdp.eval(`document.getElementById('ra-window').textContent`);
    w.focus_on_go = await cdp.eval(`document.activeElement && document.activeElement.id === 'ra-go'`);
    await shot(cdp, 'confirm-its-you-desktop');
    // Cancel gives the click back: the dialog closes and the enrollment says why.
    await cdp.eval(`document.querySelector('#ra-overlay [data-act="cancel"]').click()`, true);
    await waitFor(cdp, DIALOG_CLOSED, 'Cancel to close the dialog');
    await waitFor(cdp, `/confirm/.test(document.getElementById('enrollError').textContent)`, 'the refusal to be said');
    w.cancel_rejected = true;
    // Again, and this time sign in.
    await cdp.eval(`document.getElementById('enrollSubmitBtn').click()`, true);
    await waitFor(cdp, DIALOG_OPEN, 'the dialog a second time');
    await cdp.eval(`document.getElementById('ra-go').click()`, true);
    await waitFor(cdp, ENROLLED, 'the enrollment to go through after signing in in the window');
    await waitFor(cdp, DIALOG_CLOSED, 'the dialog to close');
    w.enrolled = true;
    w.dialog_hidden = true;
    w.prompts = (await ctl('GET', '/stats')).prompts;
    try { w.name_kept = JSON.parse(out.last_enroll_body || '{}').name || ''; } catch (_) { w.name_kept = ''; }
    w.error_toasts = await cdp.eval('window.__errToasts');
    w.csp_violations = csp.splice(0);
    out.window = w;
    await cdp.eval(`document.querySelector('#enroll-overlay [data-act="closeEnrollModal"]') &&
      document.querySelector('#enroll-overlay [data-act="closeEnrollModal"]').click()`, true);

    // ── 2. no window, at 360px ──
    // A stale session again: the provider's sign-in three hours old, a new
    // sign-in from it.
    await ctl('POST', '/stale');
    await cdp.send('Network.clearBrowserCookies');
    await cdp.send('Emulation.setDeviceMetricsOverride',
      {width: 360, height: 780, deviceScaleFactor: 3, mobile: true});
    await evalSafe(cdp, 'window.__old = true');
    await cdp.send('Page.navigate', {url: BASE + '/'});
    await waitFor(cdp, READY, 'the dashboard to load again at 360px');
    await cdp.eval(SPIES);
    const sm = {};
    // A browser that will not open a window.
    await cdp.eval(`window.open = () => null`);
    await submitEnrollment(cdp, 'edge-phone');
    await waitFor(cdp, DIALOG_OPEN, 'the dialog at 360px');
    sm.dialog_shown = true;
    const layout = await cdp.eval(`(() => {
      const card = document.querySelector('#ra-overlay .modal-card');
      const r = card.getBoundingClientRect();
      const hit = id => { const b = document.getElementById(id) || document.querySelector(id);
        const q = b.getBoundingClientRect();
        const at = document.elementFromPoint(q.left + q.width / 2, q.top + q.height / 2);
        return !!at && (at === b || b.contains(at)); };
      return {left: r.left, right: r.right, top: r.top, bottom: r.bottom, vw: innerWidth, vh: innerHeight,
        scroll: document.documentElement.scrollWidth,
        go: hit('ra-go'), cancel: hit('#ra-overlay [data-act="cancel"]')};
    })()`);
    sm.layout = JSON.stringify(layout);
    await shot(cdp, 'confirm-its-you-360px');
    sm.fits = layout.left >= 0 && layout.right <= layout.vw && layout.top >= 0 && layout.bottom <= layout.vh &&
      layout.scroll <= layout.vw && layout.go && layout.cancel;
    await evalSafe(cdp, 'window.__old = true');
    await cdp.eval(`document.getElementById('ra-go').click()`, true);
    await waitFor(cdp, READY, 'the tab to come back from the identity provider');
    await cdp.eval(SPIES);
    await waitFor(cdp, `document.getElementById('tab-executors').classList.contains('active')`, 'the Executors tab to be restored');
    sm.came_back = true;
    await waitFor(cdp, `(window.__bootToasts || []).some(x => /once more/.test(x))`, 'the ask for the button once more');
    sm.toast = await cdp.eval(`(window.__bootToasts || []).find(x => /once more/.test(x))`);
    await submitEnrollment(cdp, 'edge-phone');
    await waitFor(cdp, ENROLLED, 'the second press to enroll');
    sm.enrolled = !(await cdp.eval(DIALOG_OPEN));
    sm.prompts = (await ctl('GET', '/stats')).prompts;
    sm.error_toasts = await cdp.eval('window.__errToasts');
    sm.csp_violations = csp.splice(0);
    out.same_tab = sm;

    process.stdout.write(JSON.stringify(out, null, 2));
  } catch (e) {
    out.error = {message: String(e && e.message || e)};
    process.stdout.write(JSON.stringify(out, null, 2));
  } finally {
    try { cdp.ws.close(); } catch (e) { /* already closed */ }
    killChrome(proc);
    if (proc.exitCode === null && proc.signalCode === null) {
      await new Promise(r => { proc.once('exit', r); setTimeout(r, 5000).unref(); });
    }
    try { fs.rmSync(dir, {recursive: true, force: true, maxRetries: 10, retryDelay: 100}); } catch (e) { /* best effort */ }
  }
}

main().then(() => process.exit(0), err => {
  process.stdout.write(JSON.stringify({error: {message: String(err && err.message || err)}}, null, 2));
  process.exit(0);
});
