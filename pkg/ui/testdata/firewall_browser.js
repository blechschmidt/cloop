// firewall_browser.js — drives the firewall panels (Task 20363) in a real
// browser against a real hub.
//
// The hub holds a device with a virtual executor (the public Internet and
// 10.20.0.0/16 on any port) and a project bound to it with rules of its own.
// The driver sets the device's rule set from its card — the public Internet on
// 443 — and reads back what that narrowed; then edits the project's card on
// the Overview, where a widening must be refused on the form and a narrowing
// stored, and a refresh mid-edit must keep both the edit and the refusal; then
// opens the virtual-executor dialog, which must show the device's rules and
// offer no unfiltered network under them.
//
// Usage: node firewall_browser.js <chrome-binary> <base-url> <device-id> [screenshot-dir]
// Prints one JSON document on stdout.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const DEVICE = process.argv[4];
const SHOTS = process.argv[5] || '';

const sleep = ms => new Promise(r => setTimeout(r, ms));

// How long Chrome gets to report its DevTools port, in 50 ms polls: 90 s.
// A cold start on a CI runner that is also running three race-instrumented
// test binaries has taken longer than the 30 s this used to allow (Task 20372).
const CHROME_START_POLLS = 1800;
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
    const r = await this.send('Runtime.evaluate', {expression: expr, awaitPromise: true, returnByValue: true});
    if (r.exceptionDetails) {
      throw new Error('eval failed: ' + JSON.stringify(r.exceptionDetails.exception || r.exceptionDetails));
    }
    return r.result.value;
  }
}

async function waitFor(cdp, expr, what) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    if (await cdp.eval(expr)) return;
    if (Date.now() >= deadline) throw new Error('timed out waiting for ' + what);
    await sleep(50);
  }
}

const visible = id => `(() => { const e = document.getElementById(${JSON.stringify(id)});
  return !!e && !!(e.offsetParent || e.getClientRects().length); })()`;
const text = id => `((document.getElementById(${JSON.stringify(id)}) || {}).textContent || '')`;
const type = (id, v) => `(() => { const e = document.getElementById(${JSON.stringify(id)});
  if (!e) return 'no ' + ${JSON.stringify(id)};
  e.value = ${JSON.stringify(v)}; e.dispatchEvent(new Event('input', {bubbles: true})); return 'ok'; })()`;
const click = sel => `(() => { const e = document.querySelector(${JSON.stringify(sel)});
  if (!e) return 'no ' + ${JSON.stringify(sel)}; e.click(); return 'ok'; })()`;
const getJSON = url => `(async () => (await fetch(${JSON.stringify(url)})).json())()`;

async function act(cdp, expr) {
  const r = await cdp.eval(expr);
  if (r !== 'ok') throw new Error(r);
}

async function shot(cdp, name) {
  if (!SHOTS) return;
  const r = await cdp.send('Page.captureScreenshot', {format: 'png', captureBeyondViewport: false});
  fs.writeFileSync(path.join(SHOTS, name + '.png'), Buffer.from(r.data, 'base64'));
}

// cardIndex finds the index the page's own list gives the device's card. The
// card's buttons reach their deferred dialogs through panelAct (Task 20386):
// onclick="panelAct('execadmin','<fn>',<index>)".
async function cardIndex(cdp, fn) {
  await cdp.eval(`window.loadExecutors()`);
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    const i = await cdp.eval(`(() => { const re = new RegExp("'" + ${JSON.stringify(fn)} + "',(\\\\d+)\\\\)");
      const m = re.exec((document.getElementById('execList') || {}).innerHTML || ''); return m ? Number(m[1]) : -1; })()`);
    if (i >= 0) return i;
    if (Date.now() >= deadline) throw new Error('no card offers ' + fn);
    await sleep(50);
  }
}

// openFromCard clicks the card's button, which fetches the dialog first.
async function openFromCard(cdp, fn, idx) {
  await act(cdp, click('#execList button[onclick*="\'' + fn + '\',' + idx + ')"]'));
}

async function main(cdp) {
  const out = {};
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Emulation.setDeviceMetricsOverride', {width: 1600, height: 1000, deviceScaleFactor: 1, mobile: false});
  // resumeView, the last step of booting, removes this stale marker; its
  // absence is how the driver knows the page has stopped choosing its view.
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
    source: `try { sessionStorage.setItem('cloop_resume', '{"at":0}'); } catch (e) {}`});
  await cdp.send('Page.navigate', {url: BASE + '/'});
  await waitFor(cdp, `typeof window.panelAct === 'function'
    && sessionStorage.getItem('cloop_resume') === null`, 'the dashboard to finish booting');

  // ── the device's rule set ──
  await cdp.eval(`window.switchTab('executors')`);
  const idx = await cardIndex(cdp, 'openExecutorFirewall');
  // One card offers the button: the device's, not the hub's host-process
  // executor's nor the virtual executor's.
  out.firewall_buttons = await cdp.eval(
    `(document.getElementById('execList').innerHTML.match(/'openExecutorFirewall',/g) || []).length`);
  await openFromCard(cdp, 'openExecutorFirewall', idx);
  await waitFor(cdp, `!!document.getElementById('efwAllow')`, 'the device dialog');
  out.device_fields_visible = true;
  for (const id of ['efwPub', 'efwAllow', 'efwDeny', 'efwPorts', 'efwDns', 'efwSum']) {
    if (!await cdp.eval(visible(id))) out.device_fields_visible = false;
  }
  out.device_before = await cdp.eval(text('efwBody'));
  await act(cdp, type('efwAllow', ''));
  await act(cdp, type('efwPorts', '443'));
  await act(cdp, type('efwDns', '1.1.1.1'));
  out.device_summary = await cdp.eval(text('efwSum'));
  await shot(cdp, 'device-dialog');
  await act(cdp, click('#efwBody .modal-footer .btn.primary'));
  await waitFor(cdp, `${text('efwBody')}.includes('Narrowed to fit')`, 'the narrowing to be reported');
  out.device_after = await cdp.eval(text('efwBody'));
  out.device_stored = await cdp.eval(getJSON('/api/executors/' + encodeURIComponent(DEVICE) + '/firewall'));
  await shot(cdp, 'device-dialog-saved');
  await cdp.eval(`window.panelAct('execadmin', 'closeExecutorFirewall')`);

  // ── the project's card ──
  await cdp.eval(`window.switchTab('overview')`);
  // The card rendered once at boot; this waits for the render that follows the
  // device's save, the first to name the device's rules among its levels.
  await waitFor(cdp, `${visible('projectFirewallPanel')} && !!document.getElementById('pfwAllow')
    && ${text('projectFirewallBody')}.includes("device " + ${JSON.stringify(DEVICE)} + "'s firewall")`,
  'the project card to show the device level');
  await cdp.eval(`document.getElementById('projectFirewallPanel').scrollIntoView()`);
  out.project_card = await cdp.eval(text('projectFirewallBody'));
  out.project_allow = await cdp.eval(`document.getElementById('pfwAllow').value`);
  await act(cdp, type('pfwAllow', '8.8.8.0/24'));
  await act(cdp, type('pfwPorts', '22'));
  // An executor_update refreshes the card through loadProjectFirewall, at
  // whatever moment the hub's event arrives — the device's save sends one.
  // Refreshing here, and again after the refusal, is that moment made certain:
  // neither the edit nor the refusal may go with it.
  await cdp.eval(`window.loadProjectFirewall()`);
  const typed = await cdp.eval(`document.getElementById('pfwAllow').value + ' '
    + document.getElementById('pfwPorts').value`);
  if (typed !== '8.8.8.0/24 22') throw new Error('a fleet event redrew the card under the edit: the form holds ' + typed);
  await act(cdp, click('#projectFirewallBody .modal-footer .btn.primary'));
  await waitFor(cdp, `${text('pfwWarn')}.length > 0`, 'the refusal on the form');
  await cdp.eval(`window.loadProjectFirewall()`);
  out.project_refusal = await cdp.eval(text('pfwWarn'));
  await shot(cdp, 'project-card-refused');
  await act(cdp, type('pfwAllow', '140.82.112.0/24'));
  await act(cdp, type('pfwPorts', '443'));
  await act(cdp, click('#projectFirewallBody .modal-footer .btn.primary'));
  await waitFor(cdp, `(async () => { const d = await (await fetch('/api/firewall')).json();
    return (d.rules.allow_cidrs || []).join() === '140.82.112.0/24'; })()`, 'the narrowing to be stored');
  out.project_stored = await cdp.eval(getJSON('/api/firewall'));
  await shot(cdp, 'project-card');

  // ── the virtual-executor dialog ──
  await cdp.eval(`window.switchTab('executors')`);
  const vidx = await cardIndex(cdp, 'openExecutorVirtual');
  await openFromCard(cdp, 'openExecutorVirtual', vidx);
  await waitFor(cdp, `${text('evxBody')}.includes('Device firewall')`, 'the device rules in the dialog');
  out.virtual_dialog = await cdp.eval(text('evxBody'));
  out.unfiltered_disabled = await cdp.eval(`document.getElementById('evxNetOpen').disabled`);
  await shot(cdp, 'virtual-dialog');
  return out;
}

async function run() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-fw-'));
  const proc = spawn(CHROME, ['--headless=new', '--remote-debugging-port=0', '--user-data-dir=' + dir,
    '--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', 'about:blank'],
  {stdio: ['ignore', 'ignore', 'pipe'], detached: true});
  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });
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
    const out = await main(new CDP(ws));
    ws.close();
    return out;
  } finally {
    try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) { try { proc.kill('SIGKILL'); } catch (_) {} }
    await new Promise(r => { if (proc.exitCode !== null || proc.signalCode !== null) r(); else { proc.once('exit', r); setTimeout(r, 5000).unref(); } });
    try { fs.rmSync(dir, {recursive: true, force: true, maxRetries: 10, retryDelay: 100}); } catch (_) {}
  }
}

run().then(r => { process.stdout.write(JSON.stringify(r)); process.exit(0); })
  .catch(e => { process.stdout.write(JSON.stringify({error: String((e && e.stack) || e)})); process.exit(0); });
