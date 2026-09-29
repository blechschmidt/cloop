// cssstrip_oracle.js — checks the stylesheet comment stripper (cssstrip.go)
// against a real CSS parser: Chrome's.
//
// Both sheets are parsed into constructable stylesheets and every rule is
// serialized back with cssText, which is what the browser actually holds after
// parsing — comments gone, invalid declarations dropped, values normalised.
// Stripping changed nothing a user could see exactly when the two lists match.
//
// A canary pair proves the comparison has teeth: `1px/**/2px` is two lengths,
// and with the comment deleted outright `1px2px` is one invalid token, so the
// declaration is dropped. An oracle that reported that pair equal would pass
// any stripper.
//
// Usage: node cssstrip_oracle.js <chrome-binary> <raw.css> <stripped.css>
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
    const r = await this.send('Runtime.evaluate', {expression: expr, returnByValue: true});
    if (r.exceptionDetails) {
      throw new Error('eval failed: ' + JSON.stringify(r.exceptionDetails.exception || r.exceptionDetails));
    }
    return r.result.value;
  }
}

async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-cssstrip-'));
  const proc = spawn(CHROME, [
    '--headless=new', '--remote-debugging-port=0', '--user-data-dir=' + dir,
    '--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', 'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe']});
  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });
  try {
    let port = 0;
    for (let i = 0; i < 600 && !port; i++) {
      await sleep(50);
      if (proc.exitCode !== null) throw new Error('chrome exited: ' + stderr);
      try {
        const txt = fs.readFileSync(path.join(dir, 'DevToolsActivePort'), 'utf8').split('\n');
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
    const cdp = new CDP(ws);
    const out = await cdp.eval(`(() => {
      const rules = t => { const s = new CSSStyleSheet(); s.replaceSync(t); return Array.from(s.cssRules, r => r.cssText); };
      const diff = (a, b) => {
        const m = [];
        for (let i = 0; i < Math.max(a.length, b.length) && m.length < 5; i++) {
          if (a[i] !== b[i]) m.push({index: i, raw: a[i] || null, stripped: b[i] || null});
        }
        return m;
      };
      const raw = rules(${JSON.stringify(RAW)}), stripped = rules(${JSON.stringify(STRIPPED)});
      const canary = diff(rules('.x { margin: 1px/**/2px }'), rules('.x { margin: 1px2px }'));
      return {rules: raw.length, stripped_rules: stripped.length, mismatches: diff(raw, stripped),
        canary_caught: canary.length > 0, user_agent: navigator.userAgent};
    })()`);
    ws.close();
    return out;
  } finally {
    await stopChrome(proc, dir);
  }
}

// stopChrome kills Chrome and removes its profile, as best it can. Chrome's
// helper processes go on writing into the profile while it dies, so removal is
// retried after the process exits, and a failure to clean up never replaces
// the comparison's result: the first CI run of this oracle reported ENOTEMPTY
// from rmSync instead of a verdict (Task 20356).
async function stopChrome(proc, dir) {
  try { proc.kill('SIGKILL'); } catch (_) { /* already gone */ }
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
