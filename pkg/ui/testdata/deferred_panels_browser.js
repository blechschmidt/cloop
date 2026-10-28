// deferred_panels_browser.js — every tab and dialog Task 20386 moved off first
// paint, opened from a cold page in a real browser.
//
// The Settings and admin tabs and the executor dialogs used to arrive with the
// bundle. Each is now a deferred script fetched the first time it is opened,
// carrying its own markup, with its buttons routed by mountPanel. That is a
// claim about loading and about wiring, so every scenario starts from a fresh
// navigation with the cache off, checks the panel's script had not been
// fetched, opens the panel the way a person does — a tab button, a card's
// button, the command palette — waits for it on screen, presses its primary
// action, and asks the hub what it stored.
//
// With a fourth argument, `fail`, it runs the other half: Chrome refuses the
// deferred scripts (CDP Fetch), and the page has to say so with a Retry that
// works once the network does — for a tab, and for a dialog opened from a card.
//
// `tabs:<way>` opens every tab Task 20456 moved off first paint — Activity,
// Kanban, Knowledge Base, Dependencies, Risk Matrix, Analytics, Chat,
// Assistant, Replay, Provider Calls, Executors — one way for the whole run:
// `cold` from its tab button, `link` from /?tab=<name>, `resume` as the tab a
// sign-in round trip restores, `reconnect` after the hub has dropped the
// page's stream (the control server's /sever, the close a hub restart sends),
// and `fast3g` with the network throttled to Fast 3G. Each waits for the tab
// to draw its content, presses a control of the moved markup, and reports
// every error the page logged. `session` is the multi-project hub of the
// other run: a session that keeps to Projects and Tasks must fetch no
// deferred script at all, and a moved tab follows a project switch.
//
// Usage: node deferred_panels_browser.js <chrome> <base-url> <device-id>
//   [fail | tabs:<way> | session] [control-url] [project paths, comma-separated]
// Prints one JSON document on stdout: {scenario: {...}, ...}.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const DEVICE = process.argv[4];
const MODE = process.argv[5] || 'cold';
const CONTROL = process.argv[6] || '';
const PROJECTS = (process.argv[7] || '').split(',').filter(Boolean);

const sleep = ms => new Promise(r => setTimeout(r, ms));

// How long Chrome gets to report its DevTools port, in 50 ms polls: 90 s
// (Task 20372).
const CHROME_START_POLLS = 1800;

// See sandbox_browser.js: how long to keep looking, not a pause a healthy run
// sits out. Under -race a control-plane round trip takes seconds.
const WAIT_MS = 30000;

// The deferred scripts Tasks 20386 and 20456 added, by the stem of their
// asset URL. A single-project page fetches the Overview's own cards (harness,
// devices) at boot; none of these.
const MOVED_TABS = ['queue', 'kanban', 'kb', 'deps', 'risk-matrix', 'analytics', 'chat', 'assistant',
  'replay', 'provider-calls', 'executors', 'requirements'];
const DEFERRED = ['settings', 'budget', 'secrets', 'audit', 'quotas', 'telemetry', 'execadmin', 'execpicker']
  .concat(MOVED_TABS);
const DEFERRED_RE = new RegExp('/assets/(' + DEFERRED.join('|') + ')\\.[0-9a-f]{16}\\.js$');
// Any script the page fetches beyond the four it names in its head — every
// deferred panel, and chart.js: what the Projects-and-Tasks session must not
// fetch.
const SCRIPT_RE = /\/assets\/([a-z-]+)\.[0-9a-f]{16}\.js$/;
const EAGER = new Set(['app', 'errboundary', 'theme']);

// Fast 3G as Chrome's DevTools defines it: 562.5 ms round trip, 180 KB/s down,
// 84 KB/s up.
const FAST3G = {offline: false, latency: 562.5, downloadThroughput: 180000, uploadThroughput: 84375};

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
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    });
  }
  on(fn) { this.handlers.push(fn); }
  send(method, params) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      // Cleared on the reply: an armed timer keeps node running for its whole
      // span after the last command (Task 20372).
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
  async key(key, code, vk, modifiers) {
    const base = {key, code, windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk, modifiers: modifiers || 0};
    await this.send('Input.dispatchKeyEvent', Object.assign({type: 'rawKeyDown'}, base));
    await this.send('Input.dispatchKeyEvent', Object.assign({type: 'keyUp'}, base));
  }
}

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-deferred-'));
  const proc = spawn(CHROME, ['--headless=new', '--remote-debugging-port=0', '--user-data-dir=' + dir,
    '--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--window-size=1400,1000', 'about:blank'],
  {stdio: ['ignore', 'ignore', 'pipe'], detached: true});
  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });
  // A launch that fails after the spawn must take Chrome with it, or node never
  // exits and the Go test hangs to the package timeout (Task 20340).
  try {
    let port = 0;
    for (let i = 0; i < CHROME_START_POLLS && !port; i++) {
      await sleep(50);
      if (proc.exitCode !== null) throw new Error('chrome exited: ' + stderr);
      try {
        const txt = fs.readFileSync(path.join(dir, 'DevToolsActivePort'), 'utf8').split('\n');
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
    try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) { /* already gone */ }
    throw e;
  }
}

// Chrome runs in its own process group (spawned detached), so one signal takes
// its helpers with it; then the profile can go.
async function closeChrome(proc, dir) {
  try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) { /* already gone */ }
  for (let i = 0; i < 100 && proc.exitCode === null && proc.signalCode === null; i++) await sleep(20);
  try { fs.rmSync(dir, {recursive: true, force: true, maxRetries: 5, retryDelay: 100}); } catch (_) { /* best effort */ }
}

// ── page helpers ────────────────────────────────────────────────────────────

const q = s => JSON.stringify(s);

// waitFor polls a page expression until it is truthy. On a timeout it reports
// diag, an expression for what the page was saying instead — a refusal in a
// dialog's warning line, say — which is usually the whole diagnosis.
async function waitFor(cdp, expr, what, diag) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    let v = false;
    try { v = await cdp.eval(expr); } catch (e) { /* navigating */ }
    if (v) return v;
    if (Date.now() >= deadline) {
      let said = '';
      try { said = diag ? ' — the page says: ' + await cdp.eval(diag) : ''; } catch (e) { /* gone */ }
      throw new Error('timed out waiting for ' + what + said);
    }
    await sleep(25);
  }
}

// pageSays is the diag for a dialog: its warning or error line, and the toast.
const pageSays = sel => `[${text(sel)}, ${text('#toast')}].filter(Boolean).join(' / ')`;

// waitUntil is waitFor for a condition on what the driver has heard over CDP
// (a request, a dialog) rather than on the page.
async function waitUntil(fn, what) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() >= deadline) throw new Error('timed out waiting for ' + what);
    await sleep(25);
  }
}

// visible asks the layout engine, so a field inside a hidden tab or dialog is
// not counted as on screen.
const visible = sel => `(() => { const e = document.querySelector(${q(sel)});
  return !!e && e.getClientRects().length > 0; })()`;

const text = sel => `((document.querySelector(${q(sel)}) || {}).textContent || '')`;

async function click(cdp, sel) {
  const r = await cdp.eval(`(() => { const e = document.querySelector(${q(sel)});
    if (!e) return 'no element ' + ${q(sel)};
    e.click(); return 'ok'; })()`);
  if (r !== 'ok') throw new Error(r);
}

// type sets a field the way a person's typing ends up: value, then the input
// and change events that bubble to mountPanel's routers.
async function type(cdp, sel, value) {
  const r = await cdp.eval(`(() => { const e = document.querySelector(${q(sel)});
    if (!e) return 'no element ' + ${q(sel)};
    e.value = ${q(value)};
    e.dispatchEvent(new Event('input', {bubbles: true}));
    e.dispatchEvent(new Event('change', {bubbles: true}));
    return 'ok'; })()`);
  if (r !== 'ok') throw new Error(r);
}

const getJSON = url => `(async () => (await fetch(${q(url)})).json())()`;

// ── the run ─────────────────────────────────────────────────────────────────

const fetched = [];   // deferred scripts requested since the last navigation
const scripts = [];   // every script but the page's four, likewise (SCRIPT_RE)
const apiCalls = [];  // API paths requested since the last navigation
const streams = [];   // event streams opened (WebSocket or EventSource), likewise
const problems = [];  // what the page logged as an error since the last navigation
const dialogs = [];   // JavaScript dialogs seen, with how they were answered
let answers = [];     // the answers queued for the next ones: {accept, text}

function track(cdp) {
  cdp.on(msg => {
    const p = msg.params || {};
    if (msg.method === 'Network.requestWillBeSent') {
      const u = new URL(p.request.url);
      const m = DEFERRED_RE.exec(u.pathname);
      if (m) fetched.push(m[1]);
      const sm = SCRIPT_RE.exec(u.pathname);
      if (sm && !EAGER.has(sm[1])) scripts.push(sm[1]);
      if (u.pathname.startsWith('/api/')) apiCalls.push(u.pathname + u.search);
      if (p.type === 'EventSource') streams.push('sse');
    }
    if (msg.method === 'Network.webSocketCreated') streams.push('ws');
    // An error the page reports: thrown, logged with console.error, or the
    // warning panelIf gives a panel function that threw ("cloop: …"); and
    // the browser's own (a blocked script, a failed load).
    if (msg.method === 'Runtime.exceptionThrown') {
      const d = p.exceptionDetails || {};
      problems.push('uncaught: ' + ((d.exception && d.exception.description) || d.text || '').split('\n')[0]);
    }
    if (msg.method === 'Runtime.consoleAPICalled' && (p.type === 'error' || p.type === 'warning')) {
      const line = (p.args || []).map(a => a.value !== undefined ? String(a.value) : (a.description || '')).join(' ');
      if (p.type === 'error' || /^cloop:/.test(line)) problems.push('console.' + p.type + ': ' + line.split('\n')[0]);
    }
    if (msg.method === 'Log.entryAdded' && p.entry && p.entry.level === 'error') {
      problems.push('browser (' + p.entry.source + '): ' + p.entry.text + (p.entry.url ? ' ' + p.entry.url : ''));
    }
    // alert, confirm and prompt block the page until answered, which a driver
    // waiting on the page would never see; answered here as queued.
    if (msg.method === 'Page.javascriptDialogOpening') {
      const a = answers.shift() || {accept: true};
      dialogs.push({type: msg.params.type, message: msg.params.message, answered: a});
      cdp.send('Page.handleJavaScriptDialog', {accept: a.accept, promptText: a.text || ''}).catch(() => {});
    }
  });
}

// cold navigates afresh, the cache off, and waits for boot to be done with the
// tabs: resumeView, its last step, removes the stale cloop_resume marker seeded
// below (telemetry_panel_browser.js). Reports what had been fetched by then.
async function cold(cdp, url) {
  fetched.length = 0;
  scripts.length = 0;
  apiCalls.length = 0;
  streams.length = 0;
  problems.length = 0;
  await cdp.send('Page.navigate', {url: url || BASE + '/'});
  await waitFor(cdp, `typeof window.panelAct === 'function' && sessionStorage.getItem('cloop_resume') === null`,
    'the dashboard to boot');
  return fetched.slice();
}

// openTab clicks a header tab button and waits for sel inside the tab.
async function openTab(cdp, tab, sel) {
  await click(cdp, '#tbtn-' + tab);
  await waitFor(cdp, visible('#tab-' + tab + ' ' + sel), 'the ' + tab + ' tab to render');
}

// card finds the device's card and returns its index, from its buttons.
async function cardIndex(cdp) {
  return waitFor(cdp, `(() => {
    const b = document.querySelector('#execList button[data-act="sandbox"]');
    return b ? String(b.dataset.arg) : ''; })()`, 'the device card').then(Number);
}

// A card's button, by the action it names in the Executors tab's panel
// (deferred/executors.js, Task 20456), which forwards it to execadmin.
const cardButton = (act, i) => `#execList button[data-act="${act}"][data-arg="${i}"]`;

// scenario runs one check from a cold page and records what it found, or why
// it could not finish — a later scenario still runs.
async function scenario(out, name, cdp, fn) {
  try {
    const before = await cold(cdp);
    const r = await fn();
    out[name] = Object.assign({fetched_before: before, fetched: fetched.slice()}, r);
  } catch (e) {
    out[name] = {error: String(e && e.stack || e), fetched: fetched.slice()};
  }
}

async function runCold(cdp) {
  const out = {};

  // ── the tabs ──

  await scenario(out, 'settings', cdp, async () => {
    await openTab(cdp, 'settings', '#cfgProvider');
    // The resident loaders run after the markup arrives: the build section and
    // the hidden-projects button are drawn by bundled code.
    await waitFor(cdp, `${text('#buildInfoBody')}.indexOf('Loading') === -1`, 'the build section');
    // And the form is filled in from the hub's answer whenever that arrives:
    // a value typed before it is put back to the stored one, and saved as
    // that — the likeliest reading of a CI run (38987521738) that timed out
    // below on a slow runner. The key badges are drawn by the same answer.
    await waitFor(cdp, `!!document.querySelector('#anthropicKeyStatus .badge')`, 'the stored settings');
    await type(cdp, '#cfgProvider', 'anthropic');
    await click(cdp, '#tab-settings [data-act="saveProvider"]');
    const stored = await waitFor(cdp, `(async () => { const d = await (await fetch('/api/config')).json();
      return d.provider === 'anthropic' ? d.provider : ''; })()`, 'the provider to be stored',
      `'the field holds ' + document.getElementById('cfgProvider').value + ' / ' + ${text('#toast')}`);
    return {rendered: true, oidc_section: await cdp.eval(visible('#oidcPanel')), stored};
  });

  await scenario(out, 'budget', cdp, async () => {
    await openTab(cdp, 'budget', '#bgDailyUSD');
    // Disk & Retention loads with the tab now; it used to wait for Settings.
    await waitFor(cdp, `!!document.querySelector('#diskUsageBody .du-headline')`, 'Disk & Retention');
    await type(cdp, '#bgDailyUSD', '5');
    await type(cdp, '#bgDailyTokens', '100000');
    await type(cdp, '#bgAlertPct', '80');
    await click(cdp, '#tab-budget [data-act="saveBudgetGlobal"]');
    // The note shows for two seconds once the hub has answered the save.
    const savedNote = await waitFor(cdp, visible('#budgetGlobalSaveMsg'), 'the saved note', pageSays('#budgetGlobalSaveMsg'));
    const stored = await waitFor(cdp, `(async () => { const d = await (await fetch('/api/budget')).json();
      return (d.global || {}).daily_usd_limit === 5 ? d.global : null; })()`, 'the global limit to be stored');
    return {rendered: true, disk_usage: true, stored, saved_note: savedNote};
  });

  await scenario(out, 'secrets', cdp, async () => {
    await openTab(cdp, 'secrets', '#secSecretsTable');
    await waitFor(cdp, `${text('#secSecretsBody')}.indexOf('dp-seeded') !== -1`, 'the seeded secret');
    const mark = apiCalls.length;
    await click(cdp, '#tab-secrets [data-act="loadSecretsPanel"]');
    await waitUntil(() => apiCalls.slice(mark).some(p => p === '/api/secrets'), 'Refresh to re-read the secrets');
    return {rendered: true, refreshed: true};
  });

  await scenario(out, 'audit', cdp, async () => {
    await openTab(cdp, 'audit', '#auditTable');
    await waitFor(cdp, `${text('#auditIntegrityText')}.indexOf('intact') !== -1`, 'the chain verdict');
    const mark = apiCalls.length;
    await click(cdp, '#tab-audit [data-act="verifyAuditChain"]');
    await waitUntil(() => apiCalls.slice(mark).some(p => p.startsWith('/api/audit/verify')), 'Verify chain to ask the hub');
    await waitFor(cdp, `${text('#auditIntegrityText')}.indexOf('intact') !== -1`, 'the chain verdict again');
    return {rendered: true, rows: await cdp.eval(`document.querySelectorAll('#auditBody .audit-row').length`),
      verified: true, verdict: await cdp.eval(text('#auditIntegrityText'))};
  });

  await scenario(out, 'quotas', cdp, async () => {
    await openTab(cdp, 'quotas', '#quotaTable');
    const idx = await waitFor(cdp, `(() => {
      const rows = [...document.querySelectorAll('#quotaBody tr')];
      const i = rows.findIndex(r => r.textContent.indexOf('bob@example.com') !== -1);
      return i >= 0 ? String(i) : ''; })()`, 'bob\'s row');
    await type(cdp, `.quota-input[data-identity-idx="${idx}"][data-resource="max_projects"]`, '7');
    await click(cdp, `[data-quota-save="${idx}"]`);
    const stored = await waitFor(cdp, `(async () => { const d = await (await fetch('/api/quotas')).json();
      const r = (d.quotas || []).find(x => x.identity === 'bob@example.com');
      return r && r.limits && r.limits.max_projects === 7 ? r.limits : null; })()`, 'the quota to be stored');
    return {rendered: true, stored};
  });

  await scenario(out, 'telemetry', cdp, async () => {
    await openTab(cdp, 'telemetry', '#telemetryTable');
    await waitFor(cdp, `${text('#telemetryBody')}.indexOf('deferred-panels-seed') !== -1`, 'the seeded event');
    await type(cdp, '#telemetryFilterSearch', 'deferred-panels-seed');
    const summary = await waitFor(cdp, `(() => { const s = ${text('#telemetrySummary')};
      return /^Showing 1 of 1 /.test(s) ? s : ''; })()`, 'the filtered trail');
    return {rendered: true, summary};
  });

  // ── the executor dialogs ──

  const executors = async () => {
    await click(cdp, '#tbtn-executors');
    return cardIndex(cdp);
  };

  await scenario(out, 'enroll', cdp, async () => {
    await executors();
    await click(cdp, `#tab-executors button[data-action="openEnrollModal"]`);
    await waitFor(cdp, visible('#enrollName'), 'the enrollment dialog');
    await type(cdp, '#enrollName', 'dp-edge');
    await click(cdp, '#enrollSubmitBtn');
    const command = await waitFor(cdp, text('#enrollCommand'), 'the join command');
    return {rendered: true, command};
  });

  await scenario(out, 'detail', cdp, async () => {
    const i = await executors();
    await click(cdp, cardButton('detail', i));
    const verdict = await waitFor(cdp, `(() => { const v = document.querySelector('#execDetailBody .exec-detail-verdict');
      return v && v.getClientRects().length ? v.textContent : ''; })()`, 'the host verdict');
    return {rendered: true, verdict};
  });

  await scenario(out, 'sandbox', cdp, async () => {
    const i = await executors();
    await click(cdp, cardButton('sandbox', i));
    await waitFor(cdp, `(document.getElementById('execSandboxEngine') || {options: []}).options.length > 1`,
      'the sandbox form to fill');
    await type(cdp, '#execSandboxMode', 'container');
    await waitFor(cdp, visible('#execSandboxImage'), 'the container fields');
    await type(cdp, '#execSandboxImage', 'ghcr.io/acme/sandbox:v1');
    await click(cdp, '#executor-sandbox-overlay [data-act="saveExecutorSandbox"]');
    const stored = await waitFor(cdp, `(async () => {
      const d = await (await fetch('/api/executors/' + encodeURIComponent(${q(DEVICE)}) + '/sandbox')).json();
      return (d.settings || {}).mode === 'container' ? d.settings : null; })()`, 'the sandbox to be stored');
    return {rendered: true, stored};
  });

  await scenario(out, 'virtual', cdp, async () => {
    const i = await executors();
    await click(cdp, cardButton('virtual', i));
    await waitFor(cdp, visible('#evxNetNone'), 'the virtual-executor form');
    await type(cdp, '#evxName', 'dp-virtual');
    await click(cdp, '#evxBody .modal-footer .btn.primary');
    const stored = await waitFor(cdp, `(async () => {
      const d = await (await fetch('/api/executors/' + encodeURIComponent(${q(DEVICE)}) + '/virtuals')).json();
      return (d.virtual_executors || []).some(v => v.name === 'dp-virtual'); })()`, 'the virtual executor');
    return {rendered: true, stored};
  });

  await scenario(out, 'firewall', cdp, async () => {
    const i = await executors();
    await click(cdp, cardButton('firewall', i));
    await waitFor(cdp, visible('#efwAllow'), 'the firewall form');
    await type(cdp, '#efwPorts', '443');
    await click(cdp, '#efwBody .modal-footer .btn.primary');
    const stored = await waitFor(cdp, `(async () => {
      const d = await (await fetch('/api/executors/' + encodeURIComponent(${q(DEVICE)}) + '/firewall')).json();
      return d.configured ? d.rules : null; })()`, 'the firewall to be stored');
    return {rendered: true, stored};
  });

  await scenario(out, 'limits', cdp, async () => {
    const i = await executors();
    await click(cdp, cardButton('limits', i));
    await waitFor(cdp, visible('#execLimitsMemory'), 'the limits form');
    await type(cdp, '#execLimitsMemory', '2g');
    await click(cdp, '#executor-limits-overlay [data-act="saveExecutorLimits"]');
    const stored = await waitFor(cdp, `(async () => {
      const d = await (await fetch('/api/executors/' + encodeURIComponent(${q(DEVICE)}) + '/limits')).json();
      return d.configured ? d.ceiling : null; })()`, 'the ceiling to be stored');
    return {rendered: true, stored};
  });

  await scenario(out, 'audience', cdp, async () => {
    const i = await executors();
    await click(cdp, cardButton('audience', i));
    await waitFor(cdp, visible('#execAudienceValue'), 'the access list');
    // The first principal turns the gate on, and the hub refuses one that
    // would lock out whoever is adding it. This hub has no sign-on, so its
    // admin is in no group and every first entry is refused: what the dialog
    // has to do is ask the hub and show its answer in place.
    await type(cdp, '#execAudienceValue', 'platform-team');
    await click(cdp, '#executor-audience-overlay [data-act="addExecutorAudience"]');
    const answer = await waitFor(cdp, `(() => { const s = ${text('#execAudienceWarn')};
      return s.indexOf('remove your own access') !== -1 ? s : ''; })()`, 'the hub\'s answer', pageSays('#execAudienceWarn'));
    return {rendered: true, message: answer,
      open_after_refusal: await cdp.eval(`window.isOverlayOpen('executor-audience-overlay')`)};
  });

  await scenario(out, 'upgrade', cdp, async () => {
    const i = await executors();
    const seen = dialogs.length;
    answers = [{accept: true}];
    await click(cdp, cardButton('upgrade', i));
    // A device with no release it could move to is told why, in an alert; one
    // with a release is asked which, in a prompt. Either is the dialog.
    const d = await waitUntil(() => dialogs[seen], 'the upgrade dialog');
    return {rendered: true, dialog_type: d.type, message: d.message};
  });

  await scenario(out, 'autoupdate', cdp, async () => {
    await executors();
    await waitFor(cdp, visible('#fleetAutoUpdateBar button'), 'the auto-update bar');
    // Turn it on, track the hub's build, one device at a time.
    answers = [{accept: true}, {accept: true, text: ''}, {accept: true, text: '1'}];
    await click(cdp, '#fleetAutoUpdateBar button');
    const stored = await waitFor(cdp, `(async () => { const d = await (await fetch('/api/fleet/autoupdate')).json();
      return d.enabled ? d : null; })()`, 'the policy to be stored');
    return {rendered: true, enabled: !!stored.enabled, bar: await cdp.eval(text('#fleetAutoUpdateBar'))};
  });

  // ── the secrets dialogs ──

  await scenario(out, 'secret_dialog', cdp, async () => {
    await openTab(cdp, 'secrets', '#secSecretsTable');
    await click(cdp, '#tab-secrets [data-act="openSecretModal"]');
    await waitFor(cdp, visible('#secretName'), 'the store-a-secret dialog');
    // No sign-on on this hub, so nobody could own a personal secret: the
    // choice is not offered and the secret is shared.
    const ownershipShown = await cdp.eval(visible('#secretOwnershipGroup'));
    // A name already taken: the hub refuses, and the dialog has to say so and
    // stay open rather than report it stored.
    await type(cdp, '#secretName', 'dp-seeded');
    await type(cdp, '#secretKind', 'env');
    await type(cdp, '#secretPayload', '{"BAR":"baz"}');
    await click(cdp, '#secretSubmitBtn');
    const refusal = await waitFor(cdp, `(() => { const e = document.getElementById('secretError');
      return e && e.getClientRects().length ? e.textContent : ''; })()`, 'the refusal', pageSays('#secretError'));
    const openAfterRefusal = await cdp.eval(`window.isOverlayOpen('secret-overlay')`);
    await type(cdp, '#secretName', 'dp-stored');
    await click(cdp, '#secretSubmitBtn');
    const stored = await waitFor(cdp, `(async () => { const d = await (await fetch('/api/secrets')).json();
      return (d.secrets || []).some(s => s.name === 'dp-stored'); })()`, 'the secret to be stored',
    pageSays('#secretError'));
    return {rendered: true, stored, refusal, open_after_refusal: openAfterRefusal, ownership_shown: ownershipShown};
  });

  await scenario(out, 'grant_dialog', cdp, async () => {
    await openTab(cdp, 'secrets', '#secSecretsTable');
    await click(cdp, '#tab-secrets [data-act="openGrantModal"]');
    await waitFor(cdp, visible('#grantKind'), 'the grant dialog');
    await type(cdp, '#grantKind', 'env');
    await waitFor(cdp, `[...document.getElementById('grantSecret').options].some(o => o.textContent.indexOf('dp-seeded') !== -1)`,
      'the seeded secret in the picker');
    await cdp.eval(`(() => { const s = document.getElementById('grantSecret');
      s.value = [...s.options].find(o => o.textContent.indexOf('dp-seeded') !== -1).value;
      s.dispatchEvent(new Event('change', {bubbles: true})); })()`);
    await type(cdp, '#grantSubject', 'project:*');
    await type(cdp, '#grantEnvKeys', 'FOO');
    await click(cdp, '#grantSubmitBtn');
    const stored = await waitFor(cdp, `(async () => { const d = await (await fetch('/api/grants')).json();
      return (d.grants || []).some(g => (g.constraints || {}).env_keys && g.constraints.env_keys.indexOf('FOO') !== -1); })()`,
    'the grant to be stored');
    return {rendered: true, stored};
  });

  await scenario(out, 'token_dialog', cdp, async () => {
    await openTab(cdp, 'secrets', '#secSecretsTable');
    await click(cdp, '#tab-secrets [data-act="openTokenModal"]');
    await waitFor(cdp, visible('#tokenName'), 'the token dialog');
    await type(cdp, '#tokenName', 'dp-ci');
    await cdp.eval(`(() => { const s = document.getElementById('tokenRoles');
      if (s.options.length) s.options[0].selected = true;
      s.dispatchEvent(new Event('change', {bubbles: true})); })()`);
    await click(cdp, '#tokenSubmitBtn');
    const plaintext = await waitFor(cdp, `(document.getElementById('tokenPlaintext') || {}).value || ''`,
      'the minted token');
    return {rendered: true, minted: /^cloop_pat_/.test(plaintext)};
  });

  await scenario(out, 'request_dialog', cdp, async () => {
    await openTab(cdp, 'secrets', '#secSecretsTable');
    await click(cdp, '#tab-secrets [data-act="openRequestModal"]');
    await waitFor(cdp, visible('#requestSubject'), 'the access-request dialog');
    await waitFor(cdp, `[...document.getElementById('requestSecret').options].some(o => o.textContent.indexOf('dp-seeded') !== -1)`,
      'the seeded secret in the picker');
    await cdp.eval(`(() => { const s = document.getElementById('requestSecret');
      s.value = [...s.options].find(o => o.textContent.indexOf('dp-seeded') !== -1).value;
      s.dispatchEvent(new Event('change', {bubbles: true})); })()`);
    await type(cdp, '#requestSubject', 'project:*');
    await type(cdp, '#requestJustification', 'deferred panels: filed from the dialog');
    await type(cdp, '#requestEnvKeys', 'FOO');
    await click(cdp, '#requestSubmitBtn');
    const filed = await waitFor(cdp, `(async () => { const d = await (await fetch('/api/grant-requests')).json();
      return JSON.stringify(d).indexOf('filed from the dialog') !== -1; })()`, 'the request to be filed');
    return {rendered: true, filed};
  });

  await scenario(out, 'decide_dialog', cdp, async () => {
    await openTab(cdp, 'secrets', '#secSecretsTable');
    // The seeded request was filed by somebody else, so it can be decided here.
    await waitFor(cdp, `!!document.querySelector('[data-req-approve]')`, 'a request to approve');
    await click(cdp, '[data-req-approve]');
    await waitFor(cdp, visible('#request-decide-overlay [data-act="submitDecision"]'), 'the decision dialog');
    await click(cdp, '#request-decide-overlay [data-act="submitDecision"]');
    const approved = await waitFor(cdp, `(async () => { const d = await (await fetch('/api/grant-requests')).json();
      return (d.requests || []).some(r => r.state === 'approved'); })()`, 'the request to be approved');
    return {rendered: true, approved};
  });

  // ── the command palette, from a cold page ──

  await scenario(out, 'palette', cdp, async () => {
    await cdp.key('k', 'KeyK', 75, 2);
    await waitFor(cdp, `window.isOverlayOpen('cmd-backdrop')`, 'the command palette');
    await cdp.send('Input.insertText', {text: 'Settings'});
    await cdp.key('Enter', 'Enter', 13, 0);
    await waitFor(cdp, visible('#tab-settings #cfgProvider'), 'Settings, from the palette');
    return {rendered: true};
  });

  // ── the moved tabs from the keyboard and the palette (Task 20456) ──

  await scenario(out, 'shortcut', cdp, async () => {
    await cdp.key('3', 'Digit3', 51, 0);
    await waitFor(cdp, `${text('#kb-body-pending')}.includes('dp-task-alpha')`, 'Kanban, from its number key');
    // j focuses the first card and l moves it a column on — the board's
    // status buckets, which 18-shortcuts.js spells out itself now that the
    // board's code is not always there.
    await cdp.key('j', 'KeyJ', 74, 0);
    await waitFor(cdp, `!!document.querySelector('#tab-kanban .kb-card.kb-focus')`, 'a focused card');
    const id = await cdp.eval(`document.querySelector('#tab-kanban .kb-card.kb-focus').dataset.taskId`);
    await cdp.key('l', 'KeyL', 76, 0);
    const stored = await waitFor(cdp, `(async () => { const s = await (await fetch('/api/state')).json();
      const t = ((s.plan || {}).tasks || []).find(t => String(t.id) === ${q(id)});
      return t && t.status === 'in_progress' ? t.status : ''; })()`, 'the card to move a column');
    await hub('PATCH', '/api/tasks/' + id, {status: 'pending'});
    return {rendered: true, stored};
  });

  await scenario(out, 'palette_moved', cdp, async () => {
    await cdp.key('k', 'KeyK', 75, 2);
    await waitFor(cdp, `window.isOverlayOpen('cmd-backdrop')`, 'the command palette');
    await cdp.send('Input.insertText', {text: 'Analytics'});
    await cdp.key('Enter', 'Enter', 13, 0);
    await waitFor(cdp, TAB.analytics.ready, 'Analytics, from the palette');
    return {rendered: true};
  });

  return out;
}

// runFail refuses every deferred script and checks the page offers a retry: in
// the tab that would otherwise stay empty, and in a banner for a dialog.
async function runFail(cdp) {
  const out = {};
  // Refused until the scenario lets the network come back for it.
  const refusing = new Set(['audit', 'execadmin']);
  const refused = [];
  await cdp.send('Fetch.enable', {patterns: [{urlPattern: '*/assets/*', requestStage: 'Request'}]});
  cdp.on(msg => {
    if (msg.method !== 'Fetch.requestPaused') return;
    const {requestId, request} = msg.params;
    const m = DEFERRED_RE.exec(new URL(request.url).pathname);
    if (m && refusing.has(m[1])) {
      refused.push(m[1]);
      cdp.send('Fetch.failRequest', {requestId, errorReason: 'ConnectionRefused'}).catch(() => {});
      return;
    }
    cdp.send('Fetch.continueRequest', {requestId}).catch(() => {});
  });

  try {
    await cold(cdp);
    // A tab: the error and its Retry, where the panel would have been.
    await click(cdp, '#tbtn-audit');
    const tabError = await waitFor(cdp, `(() => { const p = document.querySelector('#tab-audit [role="alert"]');
      return p && p.getClientRects().length ? p.textContent : ''; })()`, 'the tab to say it did not load');
    out.tab = {
      error: tabError,
      retry_offered: await cdp.eval(visible('#tab-audit [role="alert"] button')),
      panel_absent: !(await cdp.eval(`!!document.getElementById('auditTable')`)),
    };
    // The network comes back for the tab: its Retry, pressed where the panel
    // should be, brings the panel.
    refusing.delete('audit');
    await click(cdp, '#tab-audit [role="alert"] button');
    await waitFor(cdp, visible('#tab-audit #auditTable') + ` || ${visible('#tab-audit #auditEmpty')}`,
      'the Audit tab after Retry');
    out.tab.recovered = true;
    // A dialog: the card's button, and the banner with Retry and Dismiss.
    await click(cdp, '#tbtn-executors');
    const i = await cardIndex(cdp);
    await click(cdp, cardButton('limits', i));
    const banner = await waitFor(cdp, `(() => { const b = document.getElementById('deferredFail');
      return b && b.getClientRects().length ? b.textContent : ''; })()`, 'the banner');
    out.dialog = {
      banner,
      buttons: await cdp.eval(`document.querySelectorAll('#deferredFail button').length`),
      dialog_absent: !(await cdp.eval(`!!document.getElementById('executor-limits-overlay')`)),
    };

    // The network comes back for the dialog: its banner's Retry opens it.
    refusing.delete('execadmin');
    await click(cdp, '#deferredFail button');
    await waitFor(cdp, `window.isOverlayOpen('executor-limits-overlay')`, 'the limits dialog after Retry');
    out.dialog.recovered = true;
    out.dialog.banner_gone = !(await cdp.eval(`!!document.getElementById('deferredFail')`));
    out.refused = refused;
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  return out;
}

// ── the tabs Task 20456 moved ───────────────────────────────────────────────

// hub calls the hub from here rather than from the page, the way another
// user's dashboard or the CLI changes a project: the page hears of it only
// through its event stream.
async function hub(method, p, body) {
  const r = await fetch(BASE + p, {method, headers: {'Content-Type': 'application/json'},
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(20000)});
  const t = await r.text();
  if (!r.ok) throw new Error(method + ' ' + p + ' = ' + r.status + ': ' + t);
  return t ? JSON.parse(t) : null;
}

// sever has the test's control server close every WebSocket the hub holds,
// with the close a hub that is going down sends.
async function sever() {
  const r = await fetch(CONTROL + '/sever', {method: 'POST', signal: AbortSignal.timeout(20000)});
  if (!r.ok) throw new Error('sever = ' + r.status);
}

// requested waits for a request whose path starts with prefix, made since mark.
const requested = (mark, prefix, what) =>
  waitUntil(() => apiCalls.slice(mark).some(p => p.startsWith(prefix)), what);

// TAB is, for each moved tab, what it shows once its script has arrived and
// its open() has drawn (ready), and a control of its moved markup pressed
// with what that press does (press). before runs after the page has booted
// and before the tab is opened: what it changes reaches the page as an event
// for a tab whose code is not there yet, and the tab has to show it once it
// is. during runs while the tab's script is in flight, on Fast 3G.
const TAB = {
  queue: {
    ready: `!!document.querySelector('#queueStatsBar .stat-card') && (${visible('#queueTable')} || ${visible('#queueEmpty')})`,
    press: async cdp => {
      const mark = apiCalls.length;
      await type(cdp, '#queueFilterKind', 'task');
      await requested(mark, '/api/queue?kind=task', 'the kind filter to re-read the log');
      return 'filtered';
    },
  },
  kanban: {
    // The task posted by before, which arrived while the board's code had not.
    before: async way => { await hub('POST', '/api/tasks', {title: 'dp-task-late-' + way, priority: 3}); },
    during: async way => { await hub('POST', '/api/tasks', {title: 'dp-task-inflight-' + way, priority: 3}); },
    ready: way => `${text('#kb-body-pending')}.includes('dp-task-alpha') && ${text('#kanbanBoard')}.includes('dp-task-late-' + ${q(way)})`
      + (way === 'fast3g' ? ` && ${text('#kanbanBoard')}.includes('dp-task-inflight-fast3g')` : ''),
    press: async cdp => {
      await click(cdp, '#kanbanCompactBtn');
      await waitFor(cdp, `${text('#kanbanCompactBtn')} === 'Expanded' && !!document.querySelector('#kanbanBoard .kb-card.kb-compact')`,
        'the compact board');
      // A card dragged to another column, by the events a drag fires, which
      // the board hears from its own tab: the task's new status is stored.
      const to = await cdp.eval(`(() => {
        const card = [...document.querySelectorAll('#kanbanBoard .kb-card')].find(c => c.textContent.includes('dp-task-beta'));
        if (!card) return '';
        const to = card.closest('#kb-body-done') ? 'pending' : 'done';
        const dt = new DataTransfer(), body = document.getElementById('kb-body-' + to);
        card.dispatchEvent(new DragEvent('dragstart', {bubbles: true, dataTransfer: dt}));
        body.dispatchEvent(new DragEvent('dragover', {bubbles: true, cancelable: true, dataTransfer: dt}));
        body.dispatchEvent(new DragEvent('drop', {bubbles: true, cancelable: true, dataTransfer: dt}));
        card.dispatchEvent(new DragEvent('dragend', {bubbles: true, dataTransfer: dt}));
        return to; })()`);
      if (!to) throw new Error('no card for dp-task-beta on the board');
      await waitFor(cdp, `(async () => { const s = await (await fetch('/api/state')).json();
        const t = ((s.plan || {}).tasks || []).find(t => t.title === 'dp-task-beta');
        return !!t && t.status === ${q(to)}; })()`, 'the dropped card\'s status to be stored');
      return 'compacted, dropped on ' + to;
    },
    // after a reconnect: a change made elsewhere reaches the open board.
    after: async (cdp, way) => {
      const s = await hub('GET', '/api/state');
      const t = ((s.plan || {}).tasks || []).find(t => t.title.startsWith('dp-task-alpha'));
      await hub('PATCH', '/api/tasks/' + t.id, {title: 'dp-task-alpha-' + way});
      await waitFor(cdp, `${text('#kanbanBoard')}.includes('dp-task-alpha-' + ${q(way)})`, 'the renamed card');
      return true;
    },
  },
  kb: {
    before: async way => { await hub('POST', '/api/kb', {title: 'dp-kb-late-' + way, body: 'added before the tab opened', tags: []}); },
    ready: way => `${text('#kbGrid')}.includes('dp-kb-seeded') && ${text('#kbGrid')}.includes('dp-kb-late-' + ${q(way)})`,
    press: async (cdp, way) => {
      const title = 'dp-kb-added-' + way;
      await click(cdp, '#tab-kb [data-act="toggleAdd"]');
      await waitFor(cdp, visible('#kbNewTitle'), 'the add form');
      await type(cdp, '#kbNewTitle', title);
      await type(cdp, '#kbNewBody', 'added from the deferred panel');
      await click(cdp, '#tab-kb [data-act="add"]');
      await waitFor(cdp, `(async () => { const d = await (await fetch('/api/kb')).json();
        return (d.entries || []).some(e => e.title === ${q(title)}); })()`, 'the entry to be stored');
      await waitFor(cdp, `${text('#kbGrid')}.includes(${q(title)})`, 'the entry on the page');
      return 'added';
    },
  },
  deps: {
    ready: `!!document.querySelector('#depsSvg .deps-node') && !!document.querySelector('#depsSvg line, #depsSvg path')`,
    press: async cdp => {
      const mark = apiCalls.length;
      await click(cdp, '#depsShowAll');
      await requested(mark, '/api/deps', 'Show all to re-read the graph');
      return 'shown all';
    },
  },
  'risk-matrix': {
    ready: `${text('#rmStatus')} === '' && (${visible('#rmEmpty')} || ${visible('#rmNoTasks')} || ${visible('#rmChartWrap')})`,
    press: async cdp => {
      const mark = apiCalls.length;
      await click(cdp, '#tab-risk-matrix [data-act="load"]');
      await requested(mark, '/api/risk-matrix', 'Refresh to re-read the scores');
      return 'refreshed';
    },
  },
  analytics: {
    ready: `!!window.Chart && document.getElementById('analyticsCharts').style.display !== 'none'
      && !!document.querySelector('#chartVelocity') && !!window.Chart.getChart(document.querySelector('#chartVelocity'))`,
    press: async cdp => {
      const mark = apiCalls.length;
      await click(cdp, '#tab-analytics [data-act="resetRange"]');
      await requested(mark, '/api/analytics', 'Last 30d to re-read the figures');
      return 'reset the range';
    },
    // after a reconnect: a change pushed over the new stream refreshes the
    // charts on screen (the debounced schedule()).
    after: async (cdp, way) => {
      const mark = apiCalls.length;
      await hub('POST', '/api/tasks', {title: 'dp-task-analytics-' + way, priority: 4});
      await requested(mark, '/api/analytics', 'a pushed change to refresh the charts');
      return true;
    },
  },
  chat: {
    ready: `${visible('#chatMessages .chat-welcome')} || !!document.querySelector('#chatMessages .chat-bubble-row')`,
    press: async cdp => {
      await click(cdp, '#chatTtsToggle');
      await waitFor(cdp, `localStorage.getItem('cloop_chat_tts') === 'true'`, 'read-aloud to be switched on');
      await click(cdp, '#chatTtsToggle');
      await waitFor(cdp, `localStorage.getItem('cloop_chat_tts') === 'false'`, 'read-aloud to be switched off');
      await click(cdp, '#tab-chat [data-act="clear"]');
      await waitFor(cdp, visible('#chatMessages .chat-welcome'), 'the cleared chat');
      return 'toggled read-aloud, cleared';
    },
  },
  assistant: {
    ready: visible('#assistantMessages .chat-welcome'),
    press: async cdp => {
      await type(cdp, '#assistantInput', 'one\ntwo\nthree\nfour');
      await waitFor(cdp, `document.getElementById('assistantInput').style.height !== ''`, 'the box to grow');
      await click(cdp, '#tab-assistant [data-act="clear"]');
      await waitFor(cdp, visible('#assistantMessages .chat-welcome'), 'the cleared conversation');
      return 'grew, cleared';
    },
  },
  replay: {
    ready: `${text('#replayRuns')}.includes('No replay runs yet') && document.querySelectorAll('#replayTaskSel option').length > 0`,
    press: async cdp => {
      await click(cdp, '#tab-replay [data-act="submit"]');
      await waitFor(cdp, `${text('#replayStatus')} === 'Pick a task to replay.'`, 'the form to ask for a task');
      return 'asked for a task';
    },
  },
  'provider-calls': {
    ready: `${text('#pcEmpty')}.includes('No provider calls')`,
    press: async cdp => {
      const mark = apiCalls.length;
      await click(cdp, '#tab-provider-calls [data-act="load"]');
      await requested(mark, '/api/provider-calls', 'Refresh to re-read the calls');
      return 'refreshed';
    },
  },
  // The Requirements tab (Task 20458): added through its own form, and after a
  // reconnect one added elsewhere arrives by its requirements_update push.
  requirements: {
    before: async way => { await hub('POST', '/api/requirements', {title: 'dp-req-late-' + way}); },
    ready: way => `${text('#reqList')}.includes('dp-req-seeded') && ${text('#reqList')}.includes('dp-req-late-' + ${q(way)})`,
    press: async (cdp, way) => {
      const title = 'dp-req-added-' + way;
      await click(cdp, '#tab-requirements [data-act="add"]');
      await waitFor(cdp, visible('#reqTitle'), 'the requirement form');
      await type(cdp, '#reqTitle', title);
      await type(cdp, '#reqTests', 'true');
      await click(cdp, '#tab-requirements [data-act="save"]');
      await waitFor(cdp, `(async () => { const d = await (await fetch('/api/requirements')).json();
        return (d.requirements || []).some(r => r.title === ${q(title)} && (r.tests || []).length === 1); })()`, 'the requirement to be stored');
      await waitFor(cdp, `${text('#reqList')}.includes(${q(title)})`, 'the requirement on the page');
      return 'added';
    },
    after: async (cdp, way) => {
      await hub('POST', '/api/requirements', {title: 'dp-req-pushed-' + way});
      await waitFor(cdp, `${text('#reqList')}.includes('dp-req-pushed-' + ${q(way)})`, 'the pushed requirement');
      return true;
    },
  },
  executors: {
    ready: `!!document.querySelector('#execList button[data-act="limits"]') && !!document.getElementById('fwdList')`,
    press: async cdp => {
      // A card's button, which the tab's panel forwards to execadmin's dialog.
      await click(cdp, '#execList button[data-act="limits"]');
      await waitFor(cdp, `window.isOverlayOpen('executor-limits-overlay')`, 'the limits dialog');
      await cdp.eval(`window.closeOverlay('executor-limits-overlay')`);
      return 'opened a card\'s dialog';
    },
  },
};

// runTabs opens every moved tab one way, each from a page of its own.
async function runTabs(cdp, way) {
  const out = {};
  let resumeScript = null;
  if (way === 'fast3g') await cdp.send('Network.emulateNetworkConditions', FAST3G);
  try {
    for (const tab of MOVED_TABS) {
      const spec = TAB[tab];
      await scenario(out, tab, cdp, async () => {
        const ready = typeof spec.ready === 'function' ? spec.ready(way) : spec.ready;
        let r = {};
        const t0 = Date.now();
        // A link or a restored tab opens while the page boots, so what before
        // changes has to be there first; the other ways change it once the
        // page is up, with the tab's code not yet fetched.
        const booting = way === 'link' || way === 'resume';
        if (booting && spec.before) await spec.before(way);
        if (way === 'link') {
          // cold() navigated to the plain page; the link is a page of its own.
          await cold(cdp, BASE + '/?tab=' + encodeURIComponent(tab));
          r.link_dropped = await cdp.eval(`location.search === ''`);
        } else if (way === 'resume') {
          // The marker signInAgain leaves for the page it comes back to.
          resumeScript = (await cdp.send('Page.addScriptToEvaluateOnNewDocument', {source: `try {
            sessionStorage.setItem('cloop_resume', JSON.stringify({path: '', tab: ${q(tab)}, at: Date.now()})); } catch (e) {}`})).identifier;
          await cold(cdp);
          await cdp.send('Page.removeScriptToEvaluateOnNewDocument', {identifier: resumeScript});
          resumeScript = null;
        }
        if (way === 'reconnect') {
          const n = streams.length;
          await sever();
          await waitUntil(() => streams.length > n, 'the page to open a new event stream');
          await waitFor(cdp, `document.getElementById('liveDot').classList.contains('connected')`, 'the stream to reconnect');
          r.reconnected = streams.slice(n);
        }
        if (!booting && spec.before) await spec.before(way);
        const before = fetched.slice();
        // What the page logged before the tab was opened — the reconnect's own
        // close, say — is reported apart from what opening it logged. A link
        // or a restored tab opens during boot, so all of it is the tab's.
        const p0 = booting ? 0 : problems.length;
        r.boot_problems = problems.slice(0, p0);
        if (!booting) {
          await click(cdp, '#tbtn-' + tab);
          if (way === 'fast3g' && spec.during) await spec.during(way);
        }
        await waitFor(cdp, ready, 'the ' + tab + ' tab to draw', `JSON.stringify((document.getElementById('tab-' + ${q(tab)}) || {}).innerText || '').slice(0, 300)`);
        r.ms = Date.now() - t0;
        r.active = await cdp.eval(`document.getElementById('tab-' + ${q(tab)}).classList.contains('active')`);
        r.pressed = await spec.press(cdp, way);
        if (way === 'reconnect' && spec.after) r.after_event = await spec.after(cdp, way);
        return Object.assign(r, {rendered: true, opened_before: before, problems: problems.slice(p0)});
      });
      // What the scenario logged, even where it failed.
      if (out[tab] && !out[tab].problems) out[tab].problems = problems.slice();
    }
  } finally {
    if (resumeScript) await cdp.send('Page.removeScriptToEvaluateOnNewDocument', {identifier: resumeScript}).catch(() => {});
    if (way === 'fast3g') await cdp.send('Network.emulateNetworkConditions', {offline: false, latency: 0,
      downloadThroughput: -1, uploadThroughput: -1}).catch(() => {});
  }
  return out;
}

// runSession is the multi-project hub: PROJECTS[0] and [1], each with one task
// and one knowledge-base entry of its own.
async function runSession(cdp) {
  const out = {};
  const [a, b] = PROJECTS;
  const all = [];   // every script fetched by the session, across its pages

  // ── Projects and Tasks only ──
  await scenario(out, 'projects_and_tasks', cdp, async () => {
    await waitFor(cdp, `document.getElementById('tab-projects').classList.contains('active')
      && ${text('#projList')}.includes('dp-session-a')`, 'the Projects grid');
    all.push(...scripts);
    // A project's Tasks, by the link that names them: straight there, so the
    // Overview's own loaders never run.
    await cold(cdp, BASE + '/?project=' + encodeURIComponent(a) + '&tab=tasks');
    await waitFor(cdp, `document.getElementById('tab-tasks').classList.contains('active')
      && ${text('#taskListFull')}.includes('dp-task-a')`, 'project A\'s tasks');
    const overviewSkipped = !apiCalls.some(p => p.startsWith('/api/executors'));
    // What a person does there: show completed tasks, open one, filter, and
    // go to Projects and back.
    await click(cdp, '#toggleCompletedBtn');
    await cdp.eval(`(() => { const r = [...document.querySelectorAll('#taskListFull .task-item')].find(x => x.textContent.includes('dp-task-a'));
      r.querySelector('[data-action="taskRowClick"]') ? r.querySelector('[data-action="taskRowClick"]').click() : r.click(); })()`);
    await waitFor(cdp, `window.isOverlayOpen('td-overlay')`, 'the task\'s details');
    await cdp.eval(`window.dismissTopOverlay()`);
    await type(cdp, '#filterQ', 'dp-task');
    await waitFor(cdp, `${text('#taskListFull')}.includes('dp-task-a')`, 'the filtered list');
    await type(cdp, '#filterQ', '');
    await click(cdp, '#tbtn-projects');
    await waitFor(cdp, `${text('#projList')}.includes('dp-session-b')`, 'the Projects grid again');
    await click(cdp, '#tbtn-tasks');
    await waitFor(cdp, `${text('#taskListFull')}.includes('dp-task-a')`, 'project A\'s tasks again');
    all.push(...scripts);
    return {rendered: true, scripts: all.slice(), overview_skipped: overviewSkipped, problems: problems.slice()};
  });

  // ── A moved tab follows a project switch ──
  await scenario(out, 'project_switch', cdp, async () => {
    await cold(cdp, BASE + '/?project=' + encodeURIComponent(a) + '&tab=kanban');
    await waitFor(cdp, `${text('#kanbanBoard')}.includes('dp-task-a')`, 'project A\'s board');
    await click(cdp, '#tbtn-kb');
    await waitFor(cdp, `${text('#kbGrid')}.includes('dp-kb-a')`, 'project A\'s knowledge base');
    // The header's project selector, as a person switches.
    await click(cdp, '#projSelectorBtn');
    await cdp.eval(`(() => { const e = [...document.querySelectorAll('#projSelectorDropdown [data-action="selectProjectFromDropdown"]')]
      .find(x => x.textContent.includes('dp-session-b')); e.click(); })()`);
    await waitFor(cdp, `${text('#breadcrumbName')}.includes('dp-session-b')`, 'project B to open');
    await click(cdp, '#tbtn-kanban');
    await waitFor(cdp, `${text('#kanbanBoard')}.includes('dp-task-b')`, 'project B\'s board');
    const boardLeak = await cdp.eval(`${text('#kanbanBoard')}.includes('dp-task-a')`);
    await click(cdp, '#tbtn-kb');
    await waitFor(cdp, `${text('#kbGrid')}.includes('dp-kb-b')`, 'project B\'s knowledge base');
    const kbLeak = await cdp.eval(`${text('#kbGrid')}.includes('dp-kb-a')`);
    return {rendered: true, board_leak: boardLeak, kb_leak: kbLeak, problems: problems.slice()};
  });
  return out;
}

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  let out;
  try {
    track(cdp);
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Network.enable');
    await cdp.send('Log.enable');
    // Cold means cold: every navigation fetches every script again.
    await cdp.send('Network.setCacheDisabled', {cacheDisabled: true});
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `try { sessionStorage.setItem('cloop_resume', '{"at":0}'); } catch (e) {}`,
    });
    out = MODE === 'fail' ? await runFail(cdp)
      : MODE.startsWith('tabs:') ? await runTabs(cdp, MODE.slice(5))
        : MODE === 'session' ? await runSession(cdp) : await runCold(cdp);
  } catch (e) {
    out = {error: String(e && e.stack || e)};
  } finally {
    try { cdp.ws.close(); } catch (e) { /* already closed */ }
    await closeChrome(proc, dir);
  }
  process.stdout.write(JSON.stringify(out, null, 2));
}

main().then(() => process.exit(0), e => {
  process.stdout.write(JSON.stringify({error: String(e && e.stack || e)}));
  process.exit(1);
});
