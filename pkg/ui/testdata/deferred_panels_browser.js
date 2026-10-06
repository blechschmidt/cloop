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
// Usage: node deferred_panels_browser.js <chrome> <base-url> <device-id> [fail]
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

const sleep = ms => new Promise(r => setTimeout(r, ms));

// How long Chrome gets to report its DevTools port, in 50 ms polls: 90 s
// (Task 20372).
const CHROME_START_POLLS = 1800;

// See sandbox_browser.js: how long to keep looking, not a pause a healthy run
// sits out. Under -race a control-plane round trip takes seconds.
const WAIT_MS = 30000;

// The deferred scripts this task added, by the stem of their asset URL.
const DEFERRED = ['settings', 'budget', 'secrets', 'audit', 'quotas', 'telemetry', 'execadmin'];
const DEFERRED_RE = new RegExp('/assets/(' + DEFERRED.join('|') + ')\\.[0-9a-f]{16}\\.js$');

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
const apiCalls = [];  // API paths requested since the last navigation
const dialogs = [];   // JavaScript dialogs seen, with how they were answered
let answers = [];     // the answers queued for the next ones: {accept, text}

function track(cdp) {
  cdp.on(msg => {
    if (msg.method === 'Network.requestWillBeSent') {
      const u = new URL(msg.params.request.url);
      const m = DEFERRED_RE.exec(u.pathname);
      if (m) fetched.push(m[1]);
      if (u.pathname.startsWith('/api/')) apiCalls.push(u.pathname + u.search);
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
async function cold(cdp) {
  fetched.length = 0;
  apiCalls.length = 0;
  await cdp.send('Page.navigate', {url: BASE + '/'});
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
    const m = /'openExecutorSandbox',(\\d+)\\)/.exec((document.getElementById('execList') || {}).innerHTML || '');
    return m ? String(m[1]) : ''; })()`, 'the device card').then(Number);
}

const cardButton = (fn, i) => `#execList button[onclick*="'${fn}',${i})"]`;

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
    await type(cdp, '#cfgProvider', 'anthropic');
    await click(cdp, '#tab-settings [data-act="saveProvider"]');
    const stored = await waitFor(cdp, `(async () => { const d = await (await fetch('/api/config')).json();
      return d.provider === 'anthropic' ? d.provider : ''; })()`, 'the provider to be stored');
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
    await click(cdp, `#tab-executors button[onclick*="'openEnrollModal'"]`);
    await waitFor(cdp, visible('#enrollName'), 'the enrollment dialog');
    await type(cdp, '#enrollName', 'dp-edge');
    await click(cdp, '#enrollSubmitBtn');
    const command = await waitFor(cdp, text('#enrollCommand'), 'the join command');
    return {rendered: true, command};
  });

  await scenario(out, 'detail', cdp, async () => {
    const i = await executors();
    await click(cdp, cardButton('openExecutorDetail', i));
    const verdict = await waitFor(cdp, `(() => { const v = document.querySelector('#execDetailBody .exec-detail-verdict');
      return v && v.getClientRects().length ? v.textContent : ''; })()`, 'the host verdict');
    return {rendered: true, verdict};
  });

  await scenario(out, 'sandbox', cdp, async () => {
    const i = await executors();
    await click(cdp, cardButton('openExecutorSandbox', i));
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
    await click(cdp, cardButton('openExecutorVirtual', i));
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
    await click(cdp, cardButton('openExecutorFirewall', i));
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
    await click(cdp, cardButton('openExecutorLimits', i));
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
    await click(cdp, cardButton('openExecutorAudience', i));
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
    await click(cdp, cardButton('upgradeExecutor', i));
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
    await click(cdp, cardButton('openExecutorLimits', i));
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

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  let out;
  try {
    track(cdp);
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Network.enable');
    // Cold means cold: every navigation fetches every script again.
    await cdp.send('Network.setCacheDisabled', {cacheDisabled: true});
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `try { sessionStorage.setItem('cloop_resume', '{"at":0}'); } catch (e) {}`,
    });
    out = MODE === 'fail' ? await runFail(cdp) : await runCold(cdp);
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
