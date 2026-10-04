// htmlstrip_oracle.js — checks the page comment stripper (htmlstrip.go)
// against a real HTML parser: Chrome's.
//
// Both pages are parsed with DOMParser, which builds the document without
// running a script. The raw one then has its comment nodes removed and both are
// normalized (adjacent text merged), so they are equal exactly when deleting
// the comments in the source changed nothing but the comments.
//
// A canary proves the comparison has teeth: replacing a comment inside a <pre>
// with the newline it spanned adds text, and an oracle that called that equal
// would pass a stripper that keeps line counts.
//
// Usage: node htmlstrip_oracle.js <chrome-binary> <raw.html> <stripped.html>
// Prints one JSON document on stdout.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const RAW = fs.readFileSync(process.argv[3], 'utf8');
const STRIPPED = fs.readFileSync(process.argv[4], 'utf8');

const sleep = ms => new Promise(r => setTimeout(r, ms));

// How long Chrome gets to report its DevTools port, in 50 ms polls: 90 s.
// A cold start on a CI runner that is also running three race-instrumented
// test binaries has taken longer than the 30 s this used to allow (Task 20372).
const CHROME_START_POLLS = 1800;

// The same minimal CDP client as cssstrip_oracle.js; duplicated because these
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
    const r = await this.send('Runtime.evaluate', {expression: expr, returnByValue: true});
    if (r.exceptionDetails) {
      throw new Error('eval failed: ' + JSON.stringify(r.exceptionDetails.exception || r.exceptionDetails));
    }
    return r.result.value;
  }
}

async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-htmlstrip-'));
  // detached, so every helper shares one process group and dies with it.
  const proc = spawn(CHROME, [
    '--headless=new', '--remote-debugging-port=0', '--user-data-dir=' + dir,
    '--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', 'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe'], detached: true});
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
    const cdp = new CDP(ws);
    const out = await cdp.eval(`(() => {
      const parse = t => new DOMParser().parseFromString(t, 'text/html');
      const drop = doc => {
        const w = doc.createTreeWalker(doc, NodeFilter.SHOW_COMMENT), found = [];
        while (w.nextNode()) found.push(w.currentNode);
        found.forEach(c => c.remove());
        doc.normalize();
        return found.length;
      };
      const render = doc => (doc.doctype ? '<!DOCTYPE ' + doc.doctype.name + '>' : '') + doc.documentElement.outerHTML;
      const firstDiff = (a, b) => {
        let i = 0;
        while (i < a.length && a[i] === b[i]) i++;
        return i >= a.length && a.length === b.length ? null
          : {at: i, raw: a.slice(Math.max(0, i - 80), i + 80), stripped: b.slice(Math.max(0, i - 80), i + 80)};
      };
      const raw = parse(${JSON.stringify(RAW)}), stripped = parse(${JSON.stringify(STRIPPED)});
      const comments = drop(raw), left = drop(stripped);
      const a = render(raw), b = render(stripped);
      const c1 = parse('<pre>a<!--x\\n-->b</pre>'); drop(c1);
      const c2 = parse('<pre>a\\nb</pre>'); drop(c2);
      return {comments, comments_left: left, elements: raw.getElementsByTagName('*').length,
        diff: firstDiff(a, b), canary_caught: render(c1) !== render(c2), user_agent: navigator.userAgent};
    })()`);
    ws.close();
    return out;
  } finally {
    await stopChrome(proc, dir);
  }
}

async function stopChrome(proc, dir) {
  try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) {
    try { proc.kill('SIGKILL'); } catch (_) { /* already gone */ }
  }
  if (proc.exitCode === null && proc.signalCode === null) {
    await new Promise(r => {
      proc.once('exit', r);
      setTimeout(r, 5000).unref();
    });
  }
  try {
    fs.rmSync(dir, {recursive: true, force: true, maxRetries: 10, retryDelay: 100});
  } catch (_) { /* best effort: a leftover profile in the temp dir harms nothing */ }
}

main().then(r => {
  process.stdout.write(JSON.stringify(r));
  process.exit(0);
}).catch(e => {
  process.stdout.write(JSON.stringify({error: String((e && e.stack) || e)}));
  process.exit(0);
});
