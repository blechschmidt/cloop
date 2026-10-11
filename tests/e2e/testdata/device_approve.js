// device_approve.js — a person approving (or denying) a terminal's sign-in code
// in a real browser (Task 20412).
//
// It opens the link `cloop login` printed, signs in through the identity
// provider the test runs (which answers every authorization request at once),
// lands on the approval page, reads what the page shows about the request, and
// presses Approve or Deny. For an approval it then follows the identity
// provider's round trip back to the page and waits for the page to say the
// terminal is signed in.
//
// A browser rather than an HTTP client because what is under test is the page:
// a separate document whose only script is the hashed device.js, under the
// hub's script-src 'self' policy, that has to work with no inline script at
// all — and a redirect chain through the provider that only a browser follows
// with its cookies the way a person's does.
//
// Usage: node device_approve.js <chrome-binary> <url> <approve|deny>
// Prints one JSON document on stdout.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const URL_TO_OPEN = process.argv[3];
const ACTION = process.argv[4] || 'approve';

const sleep = ms => new Promise(r => setTimeout(r, ms));
const WAIT_MS = 45000;

function killChrome(proc) {
  try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) {
    try { proc.kill('SIGKILL'); } catch (_) { /* already gone */ }
  }
}

async function closeChrome(proc, dir) {
  killChrome(proc);
  if (proc.exitCode === null && proc.signalCode === null) {
    await new Promise(r => { proc.once('exit', r); setTimeout(r, 5000).unref(); });
  }
  try { fs.rmSync(dir, {recursive: true, force: true, maxRetries: 10, retryDelay: 100}); } catch (_) { /* best effort */ }
}

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.handlers = [];
    ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id !== undefined) {
        const p = this.pending.get(msg.id);
        if (!p) return;
        this.pending.delete(msg.id);
        msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
        return;
      }
      for (const h of this.handlers) h(msg);
    });
  }
  on(fn) { this.handlers.push(fn); }
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
    if (r.exceptionDetails) throw new Error('eval failed: ' + JSON.stringify(r.exceptionDetails));
    return r.result.value;
  }
}

async function waitFor(cdp, expr) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    try {
      if (await cdp.eval(expr)) return true;
    } catch (_) { /* mid-navigation */ }
    if (Date.now() >= deadline) return false;
    await sleep(50);
  }
}

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-device-'));
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    // Root on a dev box, an unprivileged user in CI; a throwaway profile
    // loading only the test's own servers.
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe'], detached: true});
  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });
  try {
    const portFile = path.join(dir, 'DevToolsActivePort');
    let port = 0;
    for (let i = 0; i < 1800 && !port; i++) {
      await sleep(50);
      if (proc.exitCode !== null) throw new Error('chrome exited: ' + stderr);
      try {
        const txt = fs.readFileSync(portFile, 'utf8').split('\n');
        if (txt[0] && txt[0].trim()) port = Number(txt[0].trim());
      } catch (_) { /* not yet */ }
    }
    if (!port) throw new Error('chrome reported no debugging port: ' + stderr);
    const list = await (await fetch('http://127.0.0.1:' + port + '/json/list', {signal: AbortSignal.timeout(15000)})).json();
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
    killChrome(proc);
    throw e;
  }
}

async function main() {
  const out = {action: ACTION, csp_violations: [], console_errors: []};
  const {cdp, proc, dir} = await launchChrome();
  try {
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Log.enable');
    cdp.on(msg => {
      if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
        out.console_errors.push(msg.params.args.map(a => a.value || a.description || '').join(' '));
      }
      if (msg.method === 'Log.entryAdded' && /Content Security Policy/i.test(msg.params.entry.text || '')) {
        out.csp_violations.push(msg.params.entry.text);
      }
    });

    await cdp.send('Page.navigate', {url: URL_TO_OPEN});
    // Through sign-in and back to the page, which looks the code up on its
    // own and shows the request.
    out.request_shown = await waitFor(cdp,
      "location.pathname === '/device' && document.getElementById('request') && !document.getElementById('request').hidden");
    out.landed = await cdp.eval('location.pathname + location.search').catch(() => '');
    if (!out.request_shown) {
      out.status_text = await cdp.eval("(document.getElementById('status')||{}).textContent || document.body.innerText").catch(() => '');
      return out;
    }
    const read = id => cdp.eval("(document.getElementById('" + id + "')||{}).textContent || ''");
    out.shown_code = await read('shown-code');
    out.who = await read('who');
    out.from_host = await read('from-host');
    out.from_ip = await read('from-ip');
    out.from_agent = await read('from-agent');
    out.network_note = await read('network-note');
    out.warning = await cdp.eval("(document.querySelector('.warning')||{}).textContent || ''");

    await cdp.eval("document.getElementById('" + (ACTION === 'deny' ? 'deny' : 'approve') + "').click(), true");
    const want = ACTION === 'deny' ? 'Denied' : 'Approved';
    out.finished = await waitFor(cdp,
      "location.pathname === '/device' && (document.getElementById('status')||{}).textContent.indexOf('" + want + "') >= 0");
    out.status_text = await cdp.eval("(document.getElementById('status')||{}).textContent || ''").catch(() => '');
    out.final = await cdp.eval('location.pathname + location.search').catch(() => '');
    return out;
  } finally {
    await closeChrome(proc, dir);
  }
}

main().then(out => {
  process.stdout.write(JSON.stringify(out) + '\n');
  process.exit(0);
}, err => {
  process.stdout.write(JSON.stringify({error: String(err && err.stack || err)}) + '\n');
  process.exit(1);
});
