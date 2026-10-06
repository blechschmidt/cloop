// executor_virtual_browser.js — drives the virtual-executor dialog's network
// access choice in a real browser (Task 20356).
//
// The dialog used to show a Network select, an "IP firewall" checkbox, "Allow
// the public Internet" and the allow/deny lists side by side, all editable at
// once; rules typed with the firewall off were dropped on save without a word.
// Now the network is one choice, and the rules exist on screen only under
// Firewalled. That is a claim about what a person can see and what the hub
// stores, so it is checked with both: Chrome clicks the real radios (whose
// inline onchange must reach a handler exported from the bundle's IIFE — the
// bug class of Tasks 20033 and 20065), types into the fields that appear, and
// then the hub is asked what it stored.
//
// Usage: node executor_virtual_browser.js <chrome-binary> <base-url> <device-id>
// Prints one JSON document on stdout: {scenario: {...}, ...}.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const DEVICE = process.argv[4];

const sleep = ms => new Promise(r => setTimeout(r, ms));

// How long Chrome gets to report its DevTools port, in 50 ms polls: 90 s.
// A cold start on a CI runner that is also running three race-instrumented
// test binaries has taken longer than the 30 s this used to allow (Task 20372).
const CHROME_START_POLLS = 1800;

// See sandbox_browser.js: how long to keep looking, not a pause a healthy run
// sits out. Round trips here open the control-plane database, which under -race
// on a loaded box takes seconds.
const WAIT_MS = 30000;

async function waitFor(cdp, expr) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    if (await cdp.eval(expr)) return true;
    if (Date.now() >= deadline) return false;
    await sleep(50);
  }
}

// The same minimal CDP client as sandbox_browser.js; duplicated because these
// drivers are standalone scripts with no module system between them.
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
      // Cleared on the reply: an armed timer keeps node running for its whole
      // span after the last command, which cost every run 20 seconds.
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-evx-'));
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe']});

  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });

  // A launch that fails after the spawn must take Chrome with it, or node
  // never exits and the Go test hangs to the package timeout (Task 20340).
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

// ── helpers ─────────────────────────────────────────────────────────────────

// visible asks the layout engine: offsetParent is null for anything under a
// display:none ancestor, which is how the settings of an unchosen access hide.
const visibleExpr = id =>
  `(() => { const e = document.getElementById(${JSON.stringify(id)});
     if (!e) return false;
     return !!(e.offsetParent || e.getClientRects().length); })()`;

// click runs a radio's or checkbox's activation behaviour — the checked flip
// and the real change event — exactly as a user's click does.
const clickExpr = id =>
  `(() => { const e = document.getElementById(${JSON.stringify(id)});
     if (!e) return 'no element';
     e.click();
     return 'ok'; })()`;

const typeExpr = (id, value) =>
  `(() => { const e = document.getElementById(${JSON.stringify(id)});
     if (!e) return 'no element';
     e.value = ${JSON.stringify(value)};
     e.dispatchEvent(new Event('input', {bubbles: true}));
     return e.value; })()`;

const textExpr = id =>
  `((document.getElementById(${JSON.stringify(id)}) || {}).textContent || '')`;

async function click(cdp, id) {
  const r = await cdp.eval(clickExpr(id));
  if (r !== 'ok') throw new Error('click ' + id + ': ' + r);
}

async function boot(cdp) {
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Page.navigate', {url: BASE + '/'});
  if (!await waitFor(cdp, `typeof window.panelAct === 'function' && typeof window.loadExecutors === 'function'`)) {
    throw new Error('the dashboard bundle never ran');
  }
}

// openDialog opens the device's dialog the way its card's button does — a
// click, which fetches the deferred dialog through panelAct (Task 20386) —
// and waits for the form its GET fills.
async function openDialog(cdp) {
  await cdp.eval(`window.loadExecutors && window.loadExecutors()`);
  // The card index is whatever the page's own list says, once it has one.
  const idx = await (async () => {
    const deadline = Date.now() + WAIT_MS;
    for (;;) {
      const i = await cdp.eval(`(() => {
        const m = /'openExecutorVirtual',(\\d+)\\)/.exec((document.getElementById('execList') || {}).innerHTML || '');
        return m ? Number(m[1]) : -1; })()`);
      if (i >= 0) return i;
      if (Date.now() >= deadline) return -1;
      await sleep(50);
    }
  })();
  if (idx < 0) throw new Error('the device card never offered its Virtual button');
  await cdp.eval(`document.querySelector('#execList button[onclick*="\\'openExecutorVirtual\\',${idx})"]').click()`);
  if (!await waitFor(cdp, `!!document.getElementById('evxNetNone')`)) {
    throw new Error('the dialog never rendered its network choice: ' + await cdp.eval(textExpr('evxBody')));
  }
}

async function stored(cdp) {
  return cdp.eval(`(async () => {
    const r = await fetch('/api/executors/' + ${JSON.stringify(encodeURIComponent(DEVICE))} + '/virtuals');
    const d = await r.json();
    return (d && d.virtual_executors) || [];
  })()`);
}

// save presses the dialog's own button, waits for the hub to hold a virtual
// executor named `name` whose spec satisfies `ok`, and then for the dialog to
// re-render from the save's answer.
//
// The last wait is what the next step depends on. The hub stores a write
// before the dialog hears back, and until the dialog re-renders, the form on
// screen is the one just submitted — in create mode, after a first save. A
// click on it is lost when the re-render replaces it, and Create pressed there
// makes a second executor. No field on that form tells the two apart (the
// submitted one already shows the name and the choice), so it is marked before
// the click and the wait is for a form without the mark. The first CI run of
// this driver acted on the stale form and lost two saves (Task 20356).
async function save(cdp, name, ok) {
  const clicked = await cdp.eval(`(() => {
    const f = document.getElementById('evxName');
    const b = document.querySelector('#evxBody .modal-footer .btn.primary');
    if (!f || !b) return false;
    f.dataset.submitted = '1';
    b.click();
    return true; })()`);
  if (!clicked) throw new Error('the dialog has no form to save');
  let v = null;
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    v = (await stored(cdp)).find(x => x.name === name) || null;
    if (v && ok(v.spec)) break;
    if (Date.now() >= deadline) return v;
    await sleep(100);
  }
  if (!await waitFor(cdp, `(() => { const f = document.getElementById('evxName');
    return !!f && !f.dataset.submitted; })()`)) {
    throw new Error('the dialog never re-rendered after saving ' + name);
  }
  return v;
}

// ── scenarios ───────────────────────────────────────────────────────────────

const results = {};

async function scenarioSettingsFollowTheChoice(cdp) {
  await openDialog(cdp);
  const r = {};
  r.none_checked_at_first = await cdp.eval(`document.getElementById('evxNetNone').checked`);
  r.rules_hidden_at_first = !(await cdp.eval(visibleExpr('evxAllow')))
    && !(await cdp.eval(visibleExpr('evxPublic')));
  r.name_hidden_at_first = !(await cdp.eval(visibleExpr('evxNetName')));

  await click(cdp, 'evxNetFw');
  r.rules_shown_for_firewalled = await cdp.eval(visibleExpr('evxPublic'))
    && await cdp.eval(visibleExpr('evxAllow')) && await cdp.eval(visibleExpr('evxDeny'))
    && await cdp.eval(visibleExpr('evxPorts')) && await cdp.eval(visibleExpr('evxDns'));
  r.summary_shown = await cdp.eval(visibleExpr('evxFwSum'));
  r.summary_default = await cdp.eval(textExpr('evxFwSum'));

  // Typing reaches the summary through the field's own oninput.
  await cdp.eval(typeExpr('evxAllow', '10.8.0.0/24'));
  await cdp.eval(typeExpr('evxDeny', '203.0.113.0/24'));
  r.summary_typed = await cdp.eval(textExpr('evxFwSum'));
  await click(cdp, 'evxPublic');
  await cdp.eval(typeExpr('evxAllow', ''));
  await cdp.eval(typeExpr('evxDns', ''));
  r.summary_nothing = await cdp.eval(textExpr('evxFwSum'));
  r.summary_nothing_warns = await cdp.eval(`document.getElementById('evxFwSum').classList.contains('warn')`);

  await click(cdp, 'evxNetOpen');
  r.rules_hidden_for_unfiltered = !(await cdp.eval(visibleExpr('evxAllow')));
  r.name_shown_for_unfiltered = await cdp.eval(visibleExpr('evxNetName'));
  r.name_default = await cdp.eval(`document.getElementById('evxNetName').value`);

  await click(cdp, 'evxNetNone');
  r.all_hidden_for_none = !(await cdp.eval(visibleExpr('evxAllow')))
    && !(await cdp.eval(visibleExpr('evxNetName')));
  results.settings_follow_the_choice = r;
}

async function scenarioSavedAsChosen(cdp) {
  await openDialog(cdp);
  const name = 'Browser firewalled';
  await cdp.eval(typeExpr('evxName', name));
  await click(cdp, 'evxNetFw');
  await cdp.eval(typeExpr('evxAllow', '10.8.0.0/24'));
  await cdp.eval(typeExpr('evxDeny', '203.0.113.0/24'));
  const fw = await save(cdp, name, s => !!s.firewall);
  const r = {firewalled: fw && fw.spec};

  // The save reopens the dialog on the executor it made, Firewalled and with
  // its rules on screen. Switching to No network and saving must take the
  // firewall away, rules still typed underneath or not.
  await waitFor(cdp, `(() => { const e = document.getElementById('evxNetFw');
    return !!e && e.checked && document.getElementById('evxName').value === ${JSON.stringify(name)}; })()`);
  r.reopened_rules_visible = await cdp.eval(visibleExpr('evxAllow'));
  r.reopened_allow = await cdp.eval(`document.getElementById('evxAllow').value`);
  await click(cdp, 'evxNetNone');
  const none = await save(cdp, name, s => !s.firewall);
  r.after_none = none && none.spec;

  // Unfiltered on a named network, then the name must survive a reopen.
  await waitFor(cdp, `(() => { const e = document.getElementById('evxNetNone'); return !!e && e.checked; })()`);
  await click(cdp, 'evxNetOpen');
  await cdp.eval(typeExpr('evxNetName', 'lab-net'));
  const open = await save(cdp, name, s => (s.sandbox || {}).network === 'lab-net');
  r.after_open = open && open.spec;
  await waitFor(cdp, `(() => { const e = document.getElementById('evxNetOpen'); return !!e && e.checked; })()`);
  r.reopened_open_checked = await cdp.eval(`document.getElementById('evxNetOpen').checked`);
  r.reopened_network_name = await cdp.eval(`document.getElementById('evxNetName').value`);
  r.reopened_name_visible = await cdp.eval(visibleExpr('evxNetName'));
  // Three saves of one executor: one create, two edits.
  r.executors = (await stored(cdp)).length;
  results.saved_as_chosen = r;
}

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  try {
    await boot(cdp);
    await scenarioSettingsFollowTheChoice(cdp);
    await cdp.eval(`window.panelAct('execadmin', 'closeExecutorVirtual')`);
    await scenarioSavedAsChosen(cdp);
    process.stdout.write(JSON.stringify(results, null, 2));
  } finally {
    try { cdp.ws.close(); } catch (e) { /* already closed */ }
    try { proc.kill('SIGKILL'); } catch (e) { /* already gone */ }
    // Chrome's helpers go on writing into the profile while it dies; wait for
    // the exit and retry, so the removal does not race them (see
    // cssstrip_oracle.js). Cleanup stays best effort either way.
    if (proc.exitCode === null && proc.signalCode === null) {
      await new Promise(r => { proc.once('exit', r); setTimeout(r, 5000).unref(); });
    }
    try {
      fs.rmSync(dir, {recursive: true, force: true, maxRetries: 10, retryDelay: 100});
    } catch (e) { /* best effort */ }
  }
}

main().then(() => process.exit(0), err => {
  process.stdout.write(JSON.stringify({error: {message: String(err && err.message || err)}}, null, 2));
  process.exit(1);
});
