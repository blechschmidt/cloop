// oidc_rbac_browser.js — drives Settings → Single sign-on in a real browser
// against a real hub (Task 20395).
//
// testdata/oidc_rbac_scenarios.js runs the panel's logic in domshim, whose
// getElementById conjures an element for any id: a note or button whose id in
// the markup differs from the one the code looks up passes there and shows
// nothing on the page. This drives the assembled page instead, on a hub whose
// saved ui.oidc turns single sign-on on with admin_emails and no policy:
//
//   - the RBAC notice is on screen, the Enforce button is clickable, and the
//     default-role select reads "unset";
//   - Save with nothing changed is accepted without a question (the save no
//     longer switches RBAC as a side effect);
//   - Enforce asks, posts, and the panel re-renders the hub's answer.
//
// Every gesture is a mouse click at the control's centre, and every step waits
// for what the panel shows rather than for a fixed time.
//
// Usage: node oidc_rbac_browser.js <chrome-binary> <base-url>
// Prints one JSON document on stdout.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const sleep = ms => new Promise(r => setTimeout(r, ms));

// How long Chrome gets to report its DevTools port, in 50 ms polls: 90 s.
const CHROME_START_POLLS = 1800;

// WAIT_MS bounds each wait for the page to reach a state.
const WAIT_MS = 30000;

class CDP {
  constructor(ws) {
    this.ws = ws; this.id = 0; this.pending = new Map(); this.handlers = new Map();
    ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id === undefined) {
        const h = this.handlers.get(msg.method);
        if (h) h(msg.params);
        return;
      }
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      clearTimeout(p.timer);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    });
  }
  on(method, fn) { this.handlers.set(method, fn); }
  send(method, params) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      // Cleared on reply, so node does not linger 20 s after the last command.
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(method + ' timed out'));
      }, 20000);
      this.pending.set(id, {resolve, reject, timer});
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

// killChrome takes the browser's whole process group: a helper outliving the
// browser goes on writing into the profile while it is deleted.
function killChrome(proc) {
  try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) {
    try { proc.kill('SIGKILL'); } catch (_) { /* already gone */ }
  }
}

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-oidcrbac-'));
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    // Same reasoning as the other browser gates here: this runs as root on the
    // project's dev box and unprivileged in CI, against a throwaway profile
    // loading only a local httptest server.
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--window-size=1400,1000',
    'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe'], detached: true});

  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });

  // A launch that fails after the spawn must take Chrome with it, or node never
  // exits and the Go test waiting on it hangs to the package timeout.
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

    const list = await (await fetch('http://127.0.0.1:' + port + '/json/list',
      {signal: AbortSignal.timeout(15000)})).json();
    const page = list.find(t => t.type === 'page');
    if (!page) throw new Error('no page target');
    const ws = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((ok, bad) => {
      const timer = setTimeout(() => bad(new Error('cdp connect timed out')), 15000);
      ws.addEventListener('open', () => { clearTimeout(timer); ok(); }, {once: true});
      ws.addEventListener('error', () => { clearTimeout(timer); bad(new Error('cdp connect failed')); }, {once: true});
    });
    return {proc, cdp: new CDP(ws), dir};
  } catch (e) {
    killChrome(proc);
    throw e;
  }
}

async function waitFor(cdp, expr, what) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    try {
      if (await cdp.eval(expr)) return;
    } catch (_) { /* mid-navigation: no context to evaluate in yet */ }
    if (Date.now() >= deadline) throw new Error('timed out waiting for ' + what);
    await sleep(50);
  }
}

// click scrolls an element into view and clicks its centre with the mouse,
// once it is laid out and on top — a control covered by another element fails
// here the way it would fail a user.
async function click(cdp, sel) {
  const deadline = Date.now() + WAIT_MS;
  let pt = null, hit = false;
  for (let i = 0; !hit && (i === 0 || Date.now() < deadline); i++) {
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

// What an operator is looking at in the panel.
const READ = `(() => {
  const el = id => document.getElementById(id);
  const seen = e => !!e && e.getClientRects().length > 0 && getComputedStyle(e).display !== 'none';
  const sel = el('oidcDefaultRole');
  const opt = sel && sel.selectedIndex >= 0 ? sel.options[sel.selectedIndex] : null;
  return {
    panel_visible: seen(el('oidcPanel')),
    note_visible: seen(el('oidcRbacNote')),
    note: (el('oidcRbacNote') || {}).textContent || '',
    enforce_visible: seen(el('oidcEnforceBtn')),
    select_value: sel ? sel.value : null,
    select_text: opt ? opt.textContent : '',
    restart_note: (el('oidcRestartNote') || {}).textContent || '',
  };
})()`;

async function openPanel(cdp) {
  await cdp.send('Page.navigate', {url: BASE + '/'});
  await waitFor(cdp, `typeof window.switchTab === 'function' && typeof window.panelAct === 'function'
    && sessionStorage.getItem('cloop_resume') === null`, 'the dashboard to finish booting');
  await cdp.eval(`window.switchTab('settings')`);
  // The notice is written only once GET /api/config/oidc has answered.
  await waitFor(cdp, `(() => {
    const n = document.getElementById('oidcRbacNote');
    return !!n && n.getClientRects().length > 0 && n.textContent !== '';
  })()`, 'the RBAC notice to render');
  // Count the panel's writes and their answers: a save that changes nothing
  // on screen is otherwise indistinguishable from one still in flight.
  await cdp.eval(`(() => {
    window.__oidcWrites = [];
    const f = window.fetch;
    window.fetch = (u, o) => f(u, o).then(r => {
      if (String(u).startsWith('/api/config/oidc') && o && (o.method === 'PUT' || o.method === 'POST')) {
        window.__oidcWrites.push({method: o.method, url: String(u), status: r.status, body: o.body || ''});
      }
      return r;
    });
  })()`);
}

(async () => {
  const out = {};
  let chrome = null;
  try {
    chrome = await launchChrome();
    const {cdp} = chrome;

    const errors = [];
    const dialogs = [];
    cdp.on('Runtime.exceptionThrown', p => {
      errors.push(JSON.stringify((p.exceptionDetails || {}).exception || p.exceptionDetails));
    });
    cdp.on('Page.javascriptDialogOpening', p => {
      dialogs.push(p.message);
      cdp.send('Page.handleJavaScriptDialog', {accept: true}).catch(() => {});
    });
    await cdp.send('Runtime.enable');
    await cdp.send('Page.enable');
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `try { sessionStorage.setItem('cloop_resume', '{"at":0}'); } catch (e) {}`,
    });

    await openPanel(cdp);
    out.fresh = await cdp.eval(READ);

    // Save with nothing changed: accepted, and nothing asked.
    await click(cdp, '#oidcPanel [data-act="saveOIDCSettings"]');
    await waitFor(cdp, `window.__oidcWrites.length === 1`, 'the save to be answered');
    out.save = await cdp.eval(`window.__oidcWrites[0]`);
    out.dialogs_after_save = dialogs.slice();

    // Enforce deny-by-default: asked, posted, and the hub's answer rendered.
    await click(cdp, '#oidcEnforceBtn');
    await waitFor(cdp, `window.__oidcWrites.length === 2`, 'the enforce action to be answered');
    out.enforce = await cdp.eval(`window.__oidcWrites[1]`);
    await waitFor(cdp, `getComputedStyle(document.getElementById('oidcEnforceBtn')).display === 'none'`,
      'the Enforce button to go once nothing is left to enforce');
    out.after_enforce = await cdp.eval(READ);
    out.dialogs = dialogs;
    out.console_errors = errors;
  } catch (e) {
    out.error = {message: (e && e.stack) || String(e)};
  } finally {
    if (chrome) {
      try { chrome.cdp.ws.close(); } catch (e) { /* already closed */ }
      killChrome(chrome.proc);
      if (chrome.proc.exitCode === null && chrome.proc.signalCode === null) {
        await new Promise(r => { chrome.proc.once('exit', r); setTimeout(r, 5000).unref(); });
      }
      try { fs.rmSync(chrome.dir, {recursive: true, force: true, maxRetries: 10, retryDelay: 100}); } catch (e) { /* best effort */ }
    }
  }
  process.stdout.write(JSON.stringify(out, null, 2));
  process.exit(0);
})();
