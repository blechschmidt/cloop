// renew_browser.js — silent sign-in renewal and the way back from a lapsed
// session, in a real browser (Task 20359).
//
// Why a browser rather than testdata/domshim.js: what is asserted here is what
// only a user agent decides. The renewal is a frame navigating to the identity
// provider and back; whether that hop is allowed is the framing document's
// frame-src, and whether the frame may load at all is frame-ancestors on the
// documents it lands on; the answer is a postMessage across the frame boundary;
// and a sign-in is a top-level trip that has to come back to the same view.
//
// It drives the real page: the scheduler arms from the real /api/me, the
// reactive retry starts from a real refused request, the banner's real button is
// clicked. The only lever pulled by hand is the hub's clock, through the
// control endpoint the Go test serves — so each phase meets claims exactly as
// stale as it needs, without sleeping through a five-minute window.
//
// Usage: node renew_browser.js <chrome-binary> <hub-url> <control-url>
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

// How long to keep looking, not a pause a healthy run sits out: under -race on
// a loaded box a round trip through the control plane takes seconds.
const WAIT_MS = 30000;

// The client spaces renewals at least this far apart (RENEW.GAP in 32-renew.js).
const RENEW_GAP_MS = 5000;

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
      // Cleared on the reply: an armed timer keeps node running for its whole
      // span after the last command.
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
    const r = await this.send('Runtime.evaluate', {expression: expr, awaitPromise: true, returnByValue: true});
    if (r.exceptionDetails) {
      throw new Error('eval failed: ' + JSON.stringify(r.exceptionDetails.exception || r.exceptionDetails));
    }
    return r.result.value;
  }
}

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-renew-'));
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--window-size=1280,900',
    'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe']});
  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });
  // A launch that fails after the spawn must take Chrome with it, or node never
  // exits and the Go test hangs to the package timeout.
  try {
    const portFile = path.join(dir, 'DevToolsActivePort');
    let port = 0;
    for (let i = 0; i < 600 && !port; i++) {
      await sleep(50);
      if (proc.exitCode !== null) throw new Error('chrome exited: ' + stderr);
      try {
        const txt = fs.readFileSync(portFile, 'utf8').split('\n');
        if (txt[0] && txt[0].trim()) port = Number(txt[0].trim());
      } catch (e) { /* not written yet */ }
    }
    if (!port) throw new Error('chrome never reported a debugging port within 30s: ' + stderr);
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
    try { proc.kill('SIGKILL'); } catch (_) { /* already gone */ }
    throw e;
  }
}

// ── what the page did ───────────────────────────────────────────────────────

const requests = [];   // {url, path, time}
const responses = [];  // {path, status}
const csp = [];        // console lines the browser wrote about a policy violation

function pathOf(u) {
  try { return new URL(u).pathname; } catch (_) { return ''; }
}

function since(list, mark, pred) {
  return list.slice(mark).filter(pred);
}

const isPath = p => r => r.path === p;

async function ctl(method, p) {
  const r = await fetch(CONTROL + p, {method, signal: AbortSignal.timeout(15000)});
  if (!r.ok) throw new Error(method + ' ' + p + ' = ' + r.status);
  return method === 'GET' ? r.json() : null;
}

// evalSafe is eval that reads a page in the middle of navigating as "not yet".
async function evalSafe(cdp, expr) {
  try { return await cdp.eval(expr); } catch (_) { return undefined; }
}

async function waitFor(cdp, expr) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    if (await evalSafe(cdp, expr)) return true;
    if (Date.now() >= deadline) return false;
    await sleep(50);
  }
}

async function waitUntil(fn) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    if (await fn()) return true;
    if (Date.now() >= deadline) return false;
    await sleep(50);
  }
}

// A document that has run the bundle, holds a session (the user chip is drawn
// from /api/me), and is not the one marked before a navigation was asked for.
const READY = `!window.__old && typeof window.renewSession === 'function' &&
  document.getElementById('userChip').style.display === 'flex'`;

// spies records, in the page, what a person would have seen: error toasts, the
// token prompt opening, and each verdict a renewal frame posted. The token
// prompt goes to sessionStorage because it has to outlive a navigation.
const SPIES = `(() => {
  window.__errToasts = [];
  window.__renewOutcomes = [];
  const t = document.getElementById('toast');
  new MutationObserver(() => {
    if (/\\berror\\b/.test(t.className)) window.__errToasts.push(t.textContent);
  }).observe(t, {attributes: true, childList: true, characterData: true, subtree: true});
  const lo = document.getElementById('loginOverlay');
  const seen = () => { if (lo.classList.contains('visible')) sessionStorage.setItem('__tokenPrompt', '1'); };
  new MutationObserver(seen).observe(lo, {attributes: true});
  seen();
  window.addEventListener('message', ev => {
    if (ev.data && ev.data.type === 'cloop.oidc.renew') window.__renewOutcomes.push(ev.data.outcome);
  });
  return true;
})()`;

async function navigated(cdp, action) {
  await evalSafe(cdp, 'window.__old = true');
  await action();
  if (!await waitFor(cdp, READY)) throw new Error('the page never came back signed in after a navigation');
  await cdp.eval(SPIES);
}

const STATE = `(() => {
  const b = document.getElementById('sessionRenewBanner');
  return {
    banner: b.style.display === 'flex',
    banner_text: document.getElementById('sessionRenewText').textContent,
    frames: document.querySelectorAll('iframe').length,
    error_toasts: window.__errToasts || [],
    login_modal: document.getElementById('loginOverlay').classList.contains('visible'),
    audit_tab_active: document.getElementById('tab-audit').classList.contains('active'),
    signed_in: document.getElementById('userChip').style.display === 'flex',
    location: location.href,
    renew_outcome: (window.__renewOutcomes || []).slice(-1)[0] || '',
    token_prompt_ever: sessionStorage.getItem('__tokenPrompt') === '1',
  };
})()`;

const CLAIM_AGE = `fetch('/api/me').then(r => r.json()).then(m => m.claim_age_seconds)`;

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  const out = {};
  let cspMark = 0;
  const violations = () => { const v = csp.slice(cspMark); cspMark = csp.length; return v; };
  try {
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Network.enable');
    await cdp.send('Log.enable');
    cdp.on('Network.requestWillBeSent', p => {
      requests.push({url: p.request.url, path: pathOf(p.request.url), time: Date.now()});
    });
    cdp.on('Network.responseReceived', p => {
      responses.push({path: pathOf(p.response.url), status: p.response.status});
    });
    cdp.on('Log.entryAdded', p => {
      if (/Content Security Policy|Refused to (frame|display)/i.test(p.entry.text)) csp.push(p.entry.text);
    });
    cdp.on('Runtime.consoleAPICalled', p => {
      const text = (p.args || []).map(a => a.value || a.description || '').join(' ');
      if (/Content Security Policy|Refused to (frame|display)/i.test(text)) csp.push(text);
    });

    // ── boot: the gate sends the browser through the provider and back ──
    await cdp.send('Page.navigate', {url: BASE + '/'});
    if (!await waitFor(cdp, READY)) throw new Error('the dashboard never finished loading with a session');
    await cdp.eval(SPIES);
    out.boot = Object.assign(await cdp.eval(STATE), {csp_violations: violations()});

    // ── 1. scheduled: the timer /api/me armed fires and the frame renews ──
    // 5m of claim age less the 90s slack less 3s: the reloaded page is told to
    // renew in about three seconds, and has to do it on its own.
    {
      const mark = requests.length;
      await ctl('POST', '/advance?seconds=207');
      await navigated(cdp, () => cdp.send('Page.reload'));
      const before = (await ctl('GET', '/stats')).prompt_none;
      const done = await waitUntil(async () =>
        (await ctl('GET', '/stats')).prompt_none > before &&
        (await evalSafe(cdp, `document.querySelectorAll('iframe').length === 0 &&
          (window.__renewOutcomes || []).length > 0`)));
      if (!done) throw new Error('no scheduled renewal completed within ' + WAIT_MS + 'ms');
      const renewAt = since(requests, mark, isPath('/auth/renew')).map(r => r.time)[0] || Date.now();
      // Nothing should follow: the answer carries the next schedule. Give a
      // stray /api/me a moment to show itself before counting.
      await sleep(1000);
      const meAfter = since(requests, mark, r => r.path === '/api/me' && r.time > renewAt).length;
      out.scheduled = Object.assign(await cdp.eval(STATE), {
        renew_requests: since(requests, mark, isPath('/auth/renew')).length,
        prompt_none: (await ctl('GET', '/stats')).prompt_none - before,
        me_after_renewal: meAfter,
        claim_age: await cdp.eval(CLAIM_AGE),
        csp_violations: violations(),
      });
      out.scheduled.renew_outcome = (await cdp.eval(`(window.__renewOutcomes || []).join(',')`));
      out.scheduled.last_renew_at = renewAt;
    }

    // ── 2. reactive: a privileged call refused for claim age ──
    // Past the throttle the last renewal opened, then ten minutes on.
    {
      await sleep(Math.max(0, out.scheduled.last_renew_at + RENEW_GAP_MS + 500 - Date.now()));
      const mark = requests.length;
      const rmark = responses.length;
      await ctl('POST', '/advance?seconds=600');
      await cdp.eval(`switchTab('audit'), true`);
      const done = await waitUntil(async () =>
        since(responses, rmark, r => r.path === '/api/audit' && r.status === 200).length > 0 ||
        since(responses, rmark, r => r.path === '/api/audit').length >= 2);
      if (!done) throw new Error('the audit panel never received an answer');
      await waitFor(cdp, `document.querySelectorAll('iframe').length === 0`);
      out.reactive = Object.assign(await cdp.eval(STATE), {
        audit_statuses: since(responses, rmark, r => r.path === '/api/audit').map(r => r.status),
        renew_requests: since(requests, mark, isPath('/auth/renew')).length,
        csp_violations: violations(),
      });
      out.reactive.at = Date.now();
    }

    // ── 3. the provider needs to see the user ──
    // login_required is what a provider says when it cannot see its own
    // session — and what one says when the browser blocks its cookies in a
    // frame. The refused call cannot be cleared silently, so the banner goes up
    // and nothing navigates on its own: the session is alive, and the user
    // picks the moment.
    {
      const lastRenew = since(requests, 0, isPath('/auth/renew')).map(r => r.time).pop() || 0;
      await sleep(Math.max(0, lastRenew + RENEW_GAP_MS + 500 - Date.now()));
      const mark = requests.length;
      await ctl('POST', '/silent?error=login_required');
      await ctl('POST', '/advance?seconds=600');
      await cdp.eval(`window.loadAudit().then(() => true)`);
      await waitFor(cdp, `document.getElementById('sessionRenewBanner').style.display === 'flex'`);
      out.banner = Object.assign(await cdp.eval(STATE), {
        login_requests: since(requests, mark, isPath('/auth/login')).length,
        csp_violations: violations(),
      });
    }

    // ── 4. the banner's sign-in, back to the same tab and view ──
    {
      const mark = requests.length;
      await ctl('POST', '/silent?error=');
      await navigated(cdp, () => cdp.eval(
        `document.querySelector('#sessionRenewBanner .btn.primary').click(), true`));
      await waitFor(cdp, `document.getElementById('tab-audit').classList.contains('active')`);
      const logins = since(requests, mark, isPath('/auth/login'));
      out.back_in = Object.assign(await cdp.eval(STATE), {
        login_requests: logins.length,
        login_url: logins.length ? logins[0].url : '',
        csp_violations: violations(),
      });
    }

    // ── 5. a provider that will not answer inside a frame ──
    // Its page refuses to be framed, so the browser shows its own error page
    // and nothing posts back. The frame comes to rest on a document that is
    // not ours, which has to read as "needs the user" well before the 20s
    // timeout — the same ending as a browser that keeps the provider's
    // cookies out of the frame, for a provider that then shows a login page.
    {
      const lastRenew = since(requests, 0, isPath('/auth/renew')).map(r => r.time).pop() || 0;
      await sleep(Math.max(0, lastRenew + RENEW_GAP_MS + 500 - Date.now()));
      await ctl('POST', '/silent?frame=deny');
      const started = Date.now();
      const outcome = await cdp.eval(`window.renewSession().then(r => r.outcome)`);
      const elapsed = Date.now() - started;
      await ctl('POST', '/silent');
      out.blocked = Object.assign(await cdp.eval(STATE), {
        renew_outcome: outcome,
        elapsed_ms: elapsed,
        csp_violations: violations(),
      });
    }

    // ── 6. the session ends server-side; the next call is a 401 ──
    {
      const mark = requests.length;
      await ctl('POST', '/revoke');
      await navigated(cdp, () => cdp.eval(`window.loadAudit(), true`));
      await waitFor(cdp, `document.getElementById('tab-audit').classList.contains('active')`);
      const logins = since(requests, mark, isPath('/auth/login'));
      out.lapsed = Object.assign(await cdp.eval(STATE), {
        login_requests: logins.length,
        login_url: logins.length ? logins[0].url : '',
        automatic_redirect: logins.length > 0,
        csp_violations: violations(),
      });
    }

    process.stdout.write(JSON.stringify(out, null, 2));
  } catch (e) {
    out.error = {message: String(e && e.message || e), csp_violations: csp};
    process.stdout.write(JSON.stringify(out, null, 2));
  } finally {
    try { cdp.ws.close(); } catch (e) { /* already closed */ }
    try { proc.kill('SIGKILL'); } catch (e) { /* already gone */ }
    // Chrome's helpers go on writing into the profile while it dies; wait for
    // the exit and retry, so removal does not race them. Best effort.
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
