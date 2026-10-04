// members_browser.js — the Members card on a project's Overview, in a real
// browser (Task 20366).
//
// What only a browser can show: that the card's script is fetched on demand
// and not on first paint, that the delegated listeners on a card built from a
// string really add, re-role and remove members, and that a member whose
// access is withdrawn while they watch the project is taken back to the
// projects that remain — the hub closes their socket with 1008 and the page
// has to act on it.
//
// Two people, one browser, one after the other: alice (a maintainer, the
// owner) manages the roster; bob, a member, watches the project while the Go
// test revokes him through its control endpoint, then is re-admitted and
// leaves on his own. Their sessions come from the Go test, which signed both
// in through the fake identity provider before Chrome started; the driver only
// installs the session cookie.
//
// Usage: node members_browser.js <chrome> <hub-url> <control-url> <project-path>
// with MEMBERS_COOKIES='{"alice":"…","bob":"…"}' in the environment.
// Prints one JSON document on stdout.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const CONTROL = process.argv[4];
const PROJECT = process.argv[5];
const COOKIES = JSON.parse(process.env.MEMBERS_COOKIES || '{}');

const sleep = ms => new Promise(r => setTimeout(r, ms));

// How long Chrome gets to report its DevTools port, in 50 ms polls: 90 s.
// A cold start on a CI runner that is also running three race-instrumented
// test binaries has taken longer than the 30 s this used to allow (Task 20372).
const CHROME_START_POLLS = 1800;

// A bound on how long to keep looking, not a pause: under -race on a loaded
// machine a control-plane round trip takes seconds.
const WAIT_MS = 30000;

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
      clearTimeout(p.timer);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    });
  }
  send(method, params) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      // Cleared on the reply: an armed timer would hold node open after the
      // last command.
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-members-'));
  // Its own process group, so killChrome takes every helper with it and the
  // profile can be deleted.
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
    if (!port) throw new Error('chrome never reported a debugging port within ' + CHROME_START_POLLS * 50 / 1000 + 's: ' + stderr);
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

async function evalSafe(cdp, expr) {
  try { return await cdp.eval(expr); } catch (_) { return undefined; }
}

async function waitFor(cdp, expr, what) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    if (await evalSafe(cdp, expr)) return;
    if (Date.now() > deadline) throw new Error('timed out waiting for ' + what);
    await sleep(50);
  }
}

async function ctl(method, p) {
  const r = await fetch(CONTROL + p, {method, signal: AbortSignal.timeout(15000)});
  if (!r.ok) throw new Error(method + ' ' + p + ' = ' + r.status + ' ' + await r.text());
  return r.json();
}

// click waits for the element to be laid out and on top, then clicks its
// centre with the mouse.
async function click(cdp, sel) {
  let pt = null, hit = false;
  const deadline = Date.now() + WAIT_MS;
  while (!hit) {
    if (Date.now() > deadline) throw new Error((pt ? sel + ' is covered' : 'nothing clickable at ' + sel));
    pt = await evalSafe(cdp, `(() => {
      const e = document.querySelector(${JSON.stringify(sel)});
      if (!e) return null;
      e.scrollIntoView({block: 'center'});
      const r = e.getBoundingClientRect();
      if (!r.width || !r.height) return null;
      return {x: r.left + r.width / 2, y: r.top + r.height / 2};
    })()`);
    if (pt) {
      hit = await evalSafe(cdp, `(() => {
        const e = document.elementFromPoint(${pt.x}, ${pt.y});
        const want = document.querySelector(${JSON.stringify(sel)});
        return !!e && !!want && (e === want || want.contains(e));
      })()`);
    }
    if (!hit) await sleep(50);
  }
  for (const type of ['mousePressed', 'mouseReleased']) {
    await cdp.send('Input.dispatchMouseEvent', {type, x: pt.x, y: pt.y, button: 'left', clickCount: 1});
  }
}

async function type(cdp, sel, text) {
  await click(cdp, sel);
  await cdp.eval(`document.querySelector(${JSON.stringify(sel)}).value = ''`);
  await cdp.send('Input.insertText', {text});
}

// signIn installs one person's session and boots the dashboard. The stale
// resume marker is what tells boot is over: resumeView, boot's last step,
// removes it (32-renew.js).
async function signIn(cdp, who) {
  // Off the previous person's page first. Left running, its background
  // requests start failing the moment the cookie is cleared, and a 401 sends
  // it through the identity provider — which signs the browser in as whoever
  // the fake provider last answered for, racing the cookie set below.
  await cdp.send('Page.navigate', {url: 'about:blank'});
  await waitFor(cdp, `location.href === 'about:blank'`, 'the previous page to unload');
  await cdp.send('Network.clearBrowserCookies');
  const ok = await cdp.send('Network.setCookie', {name: 'cloop_session', value: COOKIES[who], url: BASE, httpOnly: true});
  if (!ok || ok.success === false) throw new Error('could not set ' + who + "'s session cookie");
  await evalSafe(cdp, 'window.__old = true');
  await cdp.send('Page.navigate', {url: BASE + '/'});
  await waitFor(cdp, `!window.__old && typeof window.openProject === 'function' &&
    sessionStorage.getItem('cloop_resume') === null`, who + "'s dashboard to finish booting");
  // Error toasts, recorded as they appear; the card answers failures with one.
  await cdp.eval(`(() => {
    window.__toasts = [];
    const t = document.getElementById('toast');
    new MutationObserver(() => {
      if (t.className.indexOf('show') !== -1) window.__toasts.push({text: t.textContent, error: /\\berror\\b/.test(t.className)});
    }).observe(t, {attributes: true, childList: true, characterData: true, subtree: true});
    window.confirm = () => true;
    return true;
  })()`);
}

const PROJECT_IDX = `(window._lastProjectsData && window._lastProjectsData.projects || [])
  .findIndex(p => p.path === ${JSON.stringify(PROJECT)})`;

async function openTheProject(cdp) {
  await waitFor(cdp, `${PROJECT_IDX} >= 0`, 'the project in the list');
  await cdp.eval(`(() => {
    const list = window._lastProjectsData.projects;
    const i = ${PROJECT_IDX};
    window.openProject(i, list[i].name);
    return true;
  })()`);
  await waitFor(cdp, `(() => { const s = document.getElementById('membersSection');
    return !!s && s.getClientRects().length > 0; })()`, 'the Members card');
}

const ROSTER = `(() => {
  const rows = [...document.querySelectorAll('#membersList [data-member]')];
  return rows.map(r => {
    const sel = r.querySelector('select[data-act="role"]');
    const chip = r.querySelector('.feat-opt');
    return {
      identity: r.getAttribute('data-member'),
      role: sel ? sel.value : (chip ? chip.textContent : ''),
      editable: !!sel,
      remove: !!r.querySelector('button[data-act="remove"]'),
      leave: !!r.querySelector('button[data-act="leave"]'),
    };
  });
})()`;

const row = (who) => `(${ROSTER}).find(m => m.identity === ${JSON.stringify(who)})`;

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  const out = {};
  try {
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Network.enable');
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `try { sessionStorage.setItem('cloop_resume', '{"at":0}'); } catch (e) {}`});
    // How each socket ended, for the failure report.
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {source: `(() => {
      const Native = window.WebSocket;
      function Recorded(url, protocols) {
        const ws = protocols === undefined ? new Native(url) : new Native(url, protocols);
        ws.addEventListener('close', e => (window.__wsCloses = window.__wsCloses || [])
          .push({url: String(url).replace(/^.*\\/api/, '/api'), code: e.code, reason: e.reason}));
        return ws;
      }
      Object.setPrototypeOf(Recorded, Native);
      Recorded.prototype = Native.prototype;
      window.WebSocket = Recorded;
    })()`});

    // ── alice: the card arrives on demand and manages the roster ──
    await signIn(cdp, 'alice');
    out.meta_names_script = await cdp.eval(`!!(document.querySelector('meta[name="cloop-members-src"]') || {}).content`);
    out.loaded_before_overview = await cdp.eval(`!!document.querySelector('script[src*="/assets/members."]')`);
    await openTheProject(cdp);
    out.loaded_after_overview = await cdp.eval(`document.querySelectorAll('script[src*="/assets/members."]').length`);
    out.alice_initial = await cdp.eval(ROSTER);
    out.alice_form_visible = await cdp.eval(`document.getElementById('membersAddForm').getClientRects().length > 0`);
    out.alice_roles_offered = await cdp.eval(`[...document.querySelectorAll('#memberRole option')].map(o => o.value)`);

    await type(cdp, '#memberIdentity', 'Bob@Example.com');
    await cdp.eval(`document.getElementById('memberRole').value = 'operator'`);
    await type(cdp, '#memberReason', 'pairing on the ledger');
    await click(cdp, '#memberAddBtn');
    await waitFor(cdp, `(() => { const m = ${row('bob@example.com')}; return !!m && m.role === 'operator'; })()`,
      "bob's row as operator");
    out.after_add = await cdp.eval(ROSTER);
    out.server_after_add = await ctl('GET', '/members');

    // A role change through the row's own select.
    await cdp.eval(`(() => {
      const sel = document.querySelector('#membersList [data-member="bob@example.com"] select[data-act="role"]');
      sel.value = 'viewer';
      sel.dispatchEvent(new Event('change', {bubbles: true}));
      return true;
    })()`);
    // The hub, not the select the driver just set, says whether it landed.
    {
      const deadline = Date.now() + WAIT_MS;
      while ((await ctl('GET', '/members'))['bob@example.com'] !== 'viewer') {
        if (Date.now() > deadline) throw new Error('timed out waiting for the role change to reach the hub');
        await sleep(50);
      }
    }
    await waitFor(cdp, `(() => { const m = ${row('bob@example.com')}; return !!m && m.role === 'viewer' && m.editable &&
      !document.querySelector('#membersList select[data-act="role"]').disabled; })()`, "bob's re-rendered row as viewer");
    out.server_after_change = await ctl('GET', '/members');

    // An identity no signed-in user can carry is refused, and said so.
    const before = await cdp.eval(`window.__toasts.length`);
    await type(cdp, '#memberIdentity', 'carol');
    await click(cdp, '#memberAddBtn');
    await waitFor(cdp, `window.__toasts.slice(${before}).some(t => t.error)`, 'the refusal');
    out.refusal = await cdp.eval(`window.__toasts.slice(${before}).filter(t => t.error).map(t => t.text)`);

    // Removal through the row's button.
    await click(cdp, '#membersList [data-member="bob@example.com"] button[data-act="remove"]');
    await waitFor(cdp, `!${row('bob@example.com')}`, "bob's row to go");
    out.server_after_remove = await ctl('GET', '/members');

    // ── bob: a member watching the project loses it while he watches ──
    await ctl('POST', '/grant?role=viewer');
    await signIn(cdp, 'bob');
    out.bob_me = await cdp.eval(`fetch('/api/me').then(r => r.json()).then(m => m.email || '')`);
    out.bob_projects = await cdp.eval(`(window._lastProjectsData.projects || []).map(p => p.path)`);
    await openTheProject(cdp);
    out.bob_view = await cdp.eval(ROSTER);
    out.bob_form_visible = await cdp.eval(`document.getElementById('membersAddForm').getClientRects().length > 0`);
    // The live socket is attached to the project before it is withdrawn: the
    // hub, not the page, says so.
    {
      const deadline = Date.now() + WAIT_MS;
      while ((await ctl('GET', '/room')).clients < 1) {
        if (Date.now() > deadline) throw new Error("timed out waiting for bob's socket in the project's room");
        await sleep(50);
      }
    }
    const toastsBefore = await cdp.eval(`window.__toasts.length`);
    await ctl('POST', '/revoke');
    await waitFor(cdp, `document.getElementById('tab-projects').classList.contains('active') &&
      (document.getElementById('breadcrumbName') || {}).offsetParent === null`, 'bob to be sent back to his projects');
    out.bob_after_revoke_toasts = await cdp.eval(`window.__toasts.slice(${toastsBefore}).map(t => t.text)`);
    await waitFor(cdp, `${PROJECT_IDX} === -1`, 'the project to leave bob\'s list');

    // Re-admitted, it is back on his next visit — with no project left he
    // holds no live channel to be told on — and he can leave it himself.
    await ctl('POST', '/grant?role=viewer');
    await signIn(cdp, 'bob');
    out.readmitted = await cdp.eval(`${PROJECT_IDX} >= 0`);
    await openTheProject(cdp);
    await click(cdp, '#membersList [data-member="bob@example.com"] button[data-act="leave"]');
    await waitFor(cdp, `document.getElementById('tab-projects').classList.contains('active')`, 'bob back on his projects');
    await waitFor(cdp, `${PROJECT_IDX} === -1`, 'the project gone after leaving');
    out.server_after_leave = await ctl('GET', '/members');

    process.stdout.write(JSON.stringify(out, null, 2));
  } catch (e) {
    out.error = {message: String(e && e.message || e)};
    out.debug = await evalSafe(cdp, `({
      ws_closes: window.__wsCloses || [],
      toasts: window.__toasts || [],
      active: [...document.querySelectorAll('.tab-panel.active')].map(p => p.id),
      location: location.href,
    })`);
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
