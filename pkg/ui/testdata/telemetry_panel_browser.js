// telemetry_panel_browser.js — drives Settings → Telemetry in a real browser
// against a real hub (Task 20311).
//
// Why a browser and not testdata/domshim.js: the panel is a form, and every
// question worth asking about it is about form state — which boxes are ticked
// after the master switch flips, what the Save button therefore submits, and
// whether the answer survives a reload. The shim's elements are auto-vivified
// stubs with no tree, so `querySelectorAll('#host input[data-x]')` finds
// nothing there and a checkbox test would pass against a panel that renders no
// checkboxes at all.
//
// It is not a hypothetical. The first version of this panel ticked the master
// switch, left every source box clear — they had been rendered from a policy
// that collected nothing — and submitted "collect, from nowhere", which the
// hub stores as off. An operator turned collection on, pressed Save, and
// watched the badge stay off. Every handler test passed. Only the assembled
// page shows it.
//
// Every gesture is a mouse click at the control's centre, and every step waits
// for what the panel shows rather than for a fixed time: under a loaded -race
// run a hub round trip takes seconds.
//
// Usage: node telemetry_panel_browser.js <chrome-binary> <base-url>
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
// A cold start on a CI runner that is also running three race-instrumented
// test binaries has taken longer than the 30 s this used to allow (Task 20372).
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-telemetrypanel-'));
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

// What an operator is looking at.
const READ = `(() => {
  const el = id => document.getElementById(id);
  const sec = el('telemetryPolicySection');
  return {
    section_present: !!sec && sec.getClientRects().length > 0,
    in_settings: !!sec && !!sec.closest('#tab-settings'),
    badge: (el('telemetryPolicyBadge') || {}).textContent || '',
    enabled: !!(el('telemetryPolicyEnabled') || {}).checked,
    sources: Array.from(document.querySelectorAll('#telemetryPolicySources input[data-tel-source]'))
      .map(b => ({name: b.getAttribute('data-tel-source'), checked: b.checked, disabled: b.disabled})),
    note: (el('telemetryPolicyNote') || {}).textContent || '',
  };
})()`;

const badgeIs = text => `((document.getElementById('telemetryPolicyBadge') || {}).textContent || '') === ${JSON.stringify(text)}`;

async function openPanel(cdp) {
  await cdp.send('Page.navigate', {url: BASE + '/'});
  // Boot picks a view once /api/projects answers, which under a loaded run is
  // after a switch made here — and then hides Settings. Its last step,
  // resumeView, removes the cloop_resume marker seeded below (stale, so it
  // restores nothing), which makes the marker's absence the signal that boot
  // is done with the tabs.
  await waitFor(cdp, `typeof window.switchTab === 'function' && typeof window.panelAct === 'function'
    && sessionStorage.getItem('cloop_resume') === null`, 'the dashboard to finish booting');
  await cdp.eval(`window.switchTab('settings')`);
  // The badge is written only once GET /api/config/telemetry has answered and
  // rendered, so a non-empty badge is the panel showing the hub's policy.
  await waitFor(cdp, `(() => {
    const sec = document.getElementById('telemetryPolicySection');
    return !!sec && sec.getClientRects().length > 0
      && ((document.getElementById('telemetryPolicyBadge') || {}).textContent || '') !== '';
  })()`, 'the telemetry policy to render');
}

// save presses Save and waits for the hub's answer to repaint the badge. A
// save that never lands reports what the panel showed instead, the note above
// all, which is where a refused save says why.
async function save(cdp, badge) {
  await click(cdp, '#telemetryPolicySave');
  try {
    await waitFor(cdp, badgeIs(badge), 'the badge to read ' + JSON.stringify(badge));
  } catch (e) {
    throw new Error(e.message + '; the panel shows ' + JSON.stringify(await cdp.eval(READ)));
  }
}

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
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `try { sessionStorage.setItem('cloop_resume', '{"at":0}'); } catch (e) {}`,
    });

    await openPanel(cdp);
    out.fresh = await cdp.eval(READ);

    // The gesture an operator actually makes: tick the master switch, press
    // Save. Nothing else. This is the one the first version got wrong.
    await click(cdp, '#telemetryPolicyEnabled');
    await waitFor(cdp, `document.getElementById('telemetryPolicyEnabled').checked`, 'the switch to tick');
    out.after_toggle = await cdp.eval(READ);
    await save(cdp, 'collecting');
    out.after_save = await cdp.eval(READ);

    // Narrow to the glasses alone, the posture the feature exists for.
    await click(cdp, '#telemetryPolicySources input[data-tel-source="dashboard"]');
    await waitFor(cdp, `!document.querySelector('#telemetryPolicySources input[data-tel-source="dashboard"]').checked`,
      'the dashboard box to untick');
    await save(cdp, 'collecting · 1 of 2');
    out.after_narrow = await cdp.eval(READ);

    // A reload proves the answer came from the hub rather than from the DOM
    // the previous step left behind.
    await openPanel(cdp);
    out.after_reload = await cdp.eval(READ);

    // And what each front end is now told about itself — the answer that
    // decides whether the browser transmits anything at all.
    out.client_policy = {
      dashboard: await cdp.eval(`fetch('/api/telemetry/config').then(r => r.json())`),
      glasses: await cdp.eval(`fetch('/api/glasses/telemetry/config').then(r => r.json())`),
    };

    // Off again, which is the direction an operator is likelier to need fast.
    await click(cdp, '#telemetryPolicyEnabled');
    await waitFor(cdp, `!document.getElementById('telemetryPolicyEnabled').checked`, 'the switch to untick');
    await save(cdp, 'off');
    out.after_disable = await cdp.eval(READ);
    out.disabled_client_policy = await cdp.eval(`fetch('/api/telemetry/config').then(r => r.json())`);

    // And on again: the narrowing to the glasses must still be what the form
    // offers, so a Save does not quietly widen collection to every front end.
    await click(cdp, '#telemetryPolicyEnabled');
    await waitFor(cdp, `document.getElementById('telemetryPolicyEnabled').checked`, 'the switch to tick again');
    out.after_reenable = await cdp.eval(READ);
    await save(cdp, 'collecting · 1 of 2');
    out.after_resave = await cdp.eval(READ);

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
