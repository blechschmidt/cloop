// hubhealth_browser.js — drives Settings → Hub health and the header's
// indicator in a real browser against a real hub (Task 20434).
//
// The DOM shim (hubhealth_scenarios.js) checks the wiring: who asks for the
// report, when, and that the panel's markup escapes what a check wrote. It
// cannot check what only an assembled page shows: that the indicator is a
// control a person can press, that pressing it lands on the section with the
// section on screen, that the findings are grouped where the eye finds them,
// that markup a check carried stays text once the browser has parsed the
// panel — nothing injected, nothing run, no policy violation — and that no
// credential the hub's configuration holds is anywhere in the document.
//
// Two visits. The administrator's: the open hub grants every permission. The
// viewer's: an API token stamped viewer, which the hub enforces with no role
// policy in force; that page must not even ask for the report.
//
// Every gesture is a mouse click at the control's centre and every step waits
// for what the page shows, never for a fixed time.
//
// Usage: node hubhealth_browser.js <chrome-binary> <config.json>
// The config names the hub's URL, the viewer's token and the strings that must
// not reach the page. Prints one JSON document on stdout.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const CFG = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const BASE = CFG.base;
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
    const r = await this.send('Runtime.evaluate', {expression: expr, awaitPromise: true, returnByValue: true});
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-hubhealth-'));
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    // As in the other browser gates here: root on the project's dev box,
    // unprivileged in CI, a throwaway profile loading only a local hub.
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--window-size=1280,800',
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

// click clicks an element's centre with the mouse once it is laid out and on
// top — a control covered by another element fails here as it fails a user.
// It does not scroll first: the header's indicator has to be pressable where
// the page put it.
async function click(cdp, sel, scroll) {
  const deadline = Date.now() + WAIT_MS;
  let pt = null, hit = false;
  for (let i = 0; !hit && (i === 0 || Date.now() < deadline); i++) {
    if (i) await sleep(50);
    pt = await cdp.eval(`(() => {
      const e = document.querySelector(${JSON.stringify(sel)});
      if (!e) return null;
      ${scroll ? "e.scrollIntoView({block: 'center'});" : ''}
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

// Seeded before every document: a stale resume marker, whose removal says boot
// is done; a record of every fetch, so a request the page never makes can be
// told from one that failed; and a record of every policy violation.
const PRELUDE = `
  try { sessionStorage.setItem('cloop_resume', '{"at":0}'); } catch (e) {}
  window.__fetched = [];
  window.__healthBodies = [];
  window.__csp = [];
  const realFetch = window.fetch.bind(window);
  window.fetch = function (u, o) {
    const url = String(u && u.url || u);
    window.__fetched.push(url);
    const p = realFetch(u, o);
    if (url.indexOf('/api/hub/health') === -1) return p;
    return p.then(r => { r.clone().text().then(t => window.__healthBodies.push(t), () => {}); return r; });
  };
  document.addEventListener('securitypolicyviolation', e => window.__csp.push(e.violatedDirective + ' ' + e.blockedURI));
`;

const booted = `typeof window.switchTab === 'function' && typeof window.panelAct === 'function'
  && sessionStorage.getItem('cloop_resume') === null`;

// What the Hub health section shows, as a person reads it.
const READ = `(() => {
  const sec = document.getElementById('hubHealthSection');
  const body = document.getElementById('hubHealthBody');
  const r = sec ? sec.getBoundingClientRect() : null;
  const badge = document.getElementById('hubHealthBadge');
  return {
    section_shown: !!sec && sec.getClientRects().length > 0,
    in_settings: !!sec && !!sec.closest('#tab-settings'),
    section_top: r ? Math.round(r.top) : null,
    viewport: window.innerHeight,
    groups: Array.from(body ? body.querySelectorAll('h4, details > summary') : []).map(h => h.textContent.trim()),
    findings: Array.from(body ? body.querySelectorAll('.hh-finding') : []).map(f => f.innerText),
    links: Array.from(body ? body.querySelectorAll('a') : []).map(a => a.getAttribute('href')),
    injected: body ? body.querySelectorAll('img, svg, script, iframe, object').length : -1,
    member: body && body.querySelector('p') ? body.querySelector('p').innerText : '',
    status: (document.getElementById('hubHealthStatus') || {}).textContent || '',
    badge_shown: !!badge && badge.getClientRects().length > 0,
    badge_text: badge ? badge.textContent : '',
    fetched: window.__fetched.filter(u => u.indexOf('/api/hub/health') !== -1),
    csp: window.__csp,
    xss: window.__xss === undefined ? null : String(window.__xss),
  };
})()`;

// secretsIn reports which of the strings that must not reach the page are in
// what this feature put there: the reports the hub sent, the section's markup,
// attributes and text, and the indicator. (Settings → Single sign-on shows the
// configured issuer in its own form, to the people who may edit it.)
const secretsIn = `(() => {
  const sec = document.getElementById('hubHealthSection'), badge = document.getElementById('hubHealthBadge');
  const seen = window.__healthBodies.join('\\n') + sec.outerHTML + sec.innerText + badge.outerHTML;
  return ${JSON.stringify(CFG.secrets)}.filter(s => seen.indexOf(s) !== -1)
    .concat(window.__healthBodies.length ? [] : ['(no report was read)']);
})()`;

(async () => {
  const out = {};
  let chrome = null;
  try {
    chrome = await launchChrome();
    const {cdp} = chrome;
    const errors = [];
    cdp.on('Runtime.exceptionThrown', p => {
      errors.push(JSON.stringify((p.exceptionDetails || {}).exception || p.exceptionDetails));
    });
    await cdp.send('Runtime.enable');
    await cdp.send('Page.enable');
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {source: PRELUDE});

    // ── The administrator ────────────────────────────────────────────────
    await cdp.send('Page.navigate', {url: BASE + '/'});
    await waitFor(cdp, booted, 'the dashboard to finish booting');
    await waitFor(cdp, `(() => { const b = document.getElementById('hubHealthBadge');
      return !!b && b.getClientRects().length > 0 && /\\d/.test(b.textContent); })()`, 'the header indicator');
    out.admin_before = await cdp.eval(READ);
    await click(cdp, '#hubHealthBadge', false);
    await waitFor(cdp, `document.querySelectorAll('#hubHealthBody .hh-finding').length > 0`, 'the findings');
    // reveal scrolls the section into view once the report is drawn, and
    // below the sticky header: a heading under the tabs is in the viewport
    // and still off screen, so what is at the heading's place has to be it.
    await waitFor(cdp, `(() => { const t = document.querySelector('#hubHealthSection h3');
      const r = t.getBoundingClientRect(), head = document.querySelector('header').getBoundingClientRect();
      const at = document.elementFromPoint(r.left + 10, r.top + r.height / 2);
      return r.top >= head.bottom - 1 && r.top < window.innerHeight / 2 && !!at && t.contains(at); })()`,
      'the section to come into view below the header');
    out.admin = await cdp.eval(READ);
    out.admin_secrets = await cdp.eval(secretsIn);

    // Run the checks again: one more request, asking for a fresh run.
    const before = out.admin.fetched.length;
    await click(cdp, '#hubHealthRerun', true);
    await waitFor(cdp, `window.__fetched.filter(u => u.indexOf('/api/hub/health?fresh=1') !== -1).length > 0
      && document.querySelectorAll('#hubHealthBody .hh-finding').length > 0
      && !!document.getElementById('hubHealthRerun') && !document.getElementById('hubHealthRerun').disabled`,
      'the rerun to come back');
    out.admin_rerun = await cdp.eval(READ);
    out.admin_rerun.before = before;

    // ── The viewer ───────────────────────────────────────────────────────
    await cdp.send('Page.navigate', {url: 'about:blank'});
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `try { sessionStorage.setItem('cloop_token', ${JSON.stringify(CFG.viewerToken)}); } catch (e) {}`,
    });
    await cdp.send('Page.navigate', {url: BASE + '/'});
    await waitFor(cdp, booted, 'the viewer\'s dashboard to finish booting');
    // /api/me answered for the viewer once the Settings gating hides the
    // section; then the indicator has had every chance to ask.
    await cdp.eval(`window.switchTab('settings')`);
    await waitFor(cdp, `!!document.getElementById('hubHealthSection')
      && document.getElementById('hubHealthSection').getClientRects().length === 0
      && window.__fetched.some(u => u.indexOf('/api/me') !== -1)`, 'Settings to render for the viewer');
    await sleep(1500);
    out.viewer = await cdp.eval(READ);
    out.console_errors = errors;
  } catch (e) {
    out.error = {message: (e && e.stack) || String(e)};
    try { out.at_error = await chrome.cdp.eval(READ); } catch (_) { /* no page */ }
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
