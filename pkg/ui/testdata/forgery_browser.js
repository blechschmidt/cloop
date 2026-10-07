// forgery_browser.js — a page elsewhere tries to drive a hub with no sign-in,
// in a real browser (Task 20394).
//
// What a forged request looks like is decided by the browser, not by the
// tests that imitate it: which headers it attaches, what a text/plain form
// sends, whether a no-cors fetch goes out at all. So this drives Chromium over
// CDP. The attacker's pages are served by the Go test on another port:
//
//   * <attacker>/page on 127.0.0.1 — another origin of the hub's own site, the
//     case SameSite cookies do not stop;
//   * the same page on localhost — another site.
//
// Each submits a hidden enctype=text/plain form whose single field spells a
// JSON task, fires a no-cors fetch with a JSON body, a no-cors fetch with an
// untyped Blob body, and opens a WebSocket. The browser's own record of each
// response (the Network domain) is the witness; the Go side asks the hub what
// it stored.
//
// Then the hub's own page, in the same browser: it adds a task through its
// form and saves a setting through its own code — the dashboard must still be
// able to do what a page elsewhere may not. And the browser is pointed at the
// hub by a name it was never told to answer to, which is what a page sees once
// DNS rebinding has pointed that name at the hub.
//
// Usage: node forgery_browser.js <chrome-binary> <hub-url> <attacker-port>
// Prints one JSON document on stdout.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const HUB = process.argv[3];
const ATTACKER_PORT = process.argv[4];
const HUB_PORT = new URL(HUB).port;

const sleep = ms => new Promise(r => setTimeout(r, ms));

// See add_task_browser.js for both bounds.
const CHROME_START_POLLS = 1800;
const WAIT_MS = 30000;

// A minimal CDP client, the same shape as add_task_browser.js's, which also
// keeps the events it is sent: the Network domain's record of each response
// is how a cross-origin answer the page cannot read is seen.
class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.events = [];
    ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id === undefined) {
        if (msg.method) this.events.push(msg);
        return;
      }
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

function killChrome(proc) {
  try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) {
    try { proc.kill('SIGKILL'); } catch (_) { /* already gone */ }
  }
}

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-forgery-'));
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--window-size=1400,1000',
    // rebind.test is answered with 127.0.0.1 — what a DNS rebinding attack
    // makes the attacker's own name answer with.
    '--host-resolver-rules=MAP rebind.test 127.0.0.1',
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

async function waitFor(cdp, expr, what) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    if (await cdp.eval(expr)) return;
    if (Date.now() >= deadline) throw new Error('timed out waiting for ' + what);
    await sleep(50);
  }
}

// responses is what the browser recorded of the hub's answers since `since`
// (an index into the event list): {url, status, method} per request.
function responses(cdp, since) {
  const methods = {};
  const out = [];
  for (const ev of cdp.events.slice(since)) {
    if (ev.method === 'Network.requestWillBeSent') {
      methods[ev.params.requestId] = ev.params.request.method;
    }
    if (ev.method === 'Network.responseReceived') {
      const url = ev.params.response.url;
      if (url.indexOf(':' + HUB_PORT + '/') === -1) continue;
      out.push({url: url.replace(/^https?:\/\/[^/]+/, ''), status: ev.params.response.status,
        method: methods[ev.params.requestId] || ''});
    }
  }
  return out;
}

// attack loads the attacker's page at origin and waits until it reports that
// everything it tried has settled.
async function attack(cdp, origin) {
  const since = cdp.events.length;
  await cdp.send('Page.navigate', {url: origin + '/page?hub=' + encodeURIComponent(HUB)});
  await waitFor(cdp, `window.__done === true`, 'the attacker page at ' + origin + ' to finish');
  const page = await cdp.eval(`window.__report`);
  // The form's answer arrives in its frame; give the record a moment to catch
  // up with a navigation the page saw finish.
  const deadline = Date.now() + WAIT_MS;
  let seen = responses(cdp, since);
  while (seen.filter(r => r.method === 'POST').length < 3 && Date.now() < deadline) {
    await sleep(50);
    seen = responses(cdp, since);
  }
  return {page, responses: seen.filter(r => r.method === 'POST' || r.url.indexOf('/api/ws') === 0)};
}

// dashboard boots the hub's own page, adds a task through its form, and saves
// a setting through its own request helper.
async function dashboard(cdp) {
  await cdp.send('Page.navigate', {url: HUB + '/'});
  await waitFor(cdp, `typeof window.openProject === 'function' && typeof window.submitAddTask === 'function'`,
    'the dashboard bundle');
  const name = await cdp.eval(`(async () => {
    const d = await (await fetch('/api/projects')).json();
    return ((d && d.projects) || [])[0] ? d.projects[0].name : '';
  })()`);
  await cdp.eval(`window.openProject(0, ${JSON.stringify(name)})`);
  await cdp.eval(`window.switchTab('tasks')`);
  await waitFor(cdp, `(() => {
      const t = document.getElementById('newTaskTitle');
      return !!t && t.getClientRects().length > 0;
    })()`, 'the Add Task form');
  await cdp.eval(`(() => {
    document.getElementById('newTaskTitle').value = 'Added by the dashboard itself';
    document.getElementById('newTaskDesc').value = 'same-origin';
    window.submitAddTask();
  })()`);
  await waitFor(cdp, `document.getElementById('newTaskTitle').value === ''`, 'the form to clear after adding');

  // A Settings write, through the Settings tab's own Save button: the
  // telemetry policy, a PUT the panel sends with its own request helper.
  await cdp.eval(`window.switchTab('settings')`);
  // The panel renders the stored policy when its own GET answers, source
  // boxes included; ticking the form before then would be overwritten by it.
  await waitFor(cdp, `(() => {
      const b = document.getElementById('telemetryPolicySave');
      return !!b && b.getClientRects().length > 0 && !b.disabled
        && document.querySelectorAll('#telemetryPolicySources input[data-tel-source]').length > 0;
    })()`, 'the Settings tab\'s telemetry policy to load');
  await cdp.eval(`(() => {
    document.getElementById('telemetryPolicyEnabled').checked = true;
    document.querySelectorAll('#telemetryPolicySources input[data-tel-source]').forEach(cb => {
      cb.disabled = false;
      cb.checked = true;
    });
    document.getElementById('telemetryPolicySave').click();
  })()`);
  await waitFor(cdp, `(async () => {
    const d = await (await fetch('/api/config/telemetry')).json();
    return !!(d && d.enabled);
  })()`, 'the saved telemetry policy to read back as on');
  return {added: true, setting_saved: true};
}

// rebound points the browser at the hub by a name it does not answer to.
async function rebound(cdp) {
  await cdp.send('Page.navigate', {url: 'http://rebind.test:' + HUB_PORT + '/api/state'});
  await waitFor(cdp, `document.readyState === 'complete' && !!document.body`, 'the rebound page');
  return {
    text: await cdp.eval(`document.body.innerText.slice(0, 600)`),
    status: (responses(cdp, 0).filter(r => r.url === '/api/state').pop() || {}).status || 0,
  };
}

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  const results = {};
  try {
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Network.enable');
    results.same_site = await attack(cdp, 'http://127.0.0.1:' + ATTACKER_PORT);
    results.cross_site = await attack(cdp, 'http://localhost:' + ATTACKER_PORT);
    results.dashboard = await dashboard(cdp);
    results.rebound = await rebound(cdp);
    process.stdout.write(JSON.stringify(results, null, 2));
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
  process.exit(1);
});
