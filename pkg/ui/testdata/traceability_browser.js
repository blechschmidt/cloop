// traceability_browser.js — the traceability matrix in a real browser (Task
// 20465).
//
// The Overview's Spec coverage card is bundle markup that opens the deferred
// Requirements tab's Traceability view; the view pages the matrix from the
// hub, filters it, and reads it again when a requirements_coverage push says
// it moved — never on a timer. Whether those connect is a question about a
// browser: the fetches, the deferred script, the clicks and the WebSocket.
// domshim builds no DOM from markup, so this drives Chromium over CDP against
// a real hub; the change that moves the matrix is made by the Go side, which
// the driver asks through its control server.
//
// Usage: node traceability_browser.js <chrome-binary> <base-url> <control-url>
// Prints one JSON document on stdout: {scenario: {...}, ...}.

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

// WAIT_MS bounds every wait for the page to reach a state. Under a loaded -race
// run a hub round trip takes seconds, so this is how long to keep looking, never
// a pause a healthy run sits out.
const WAIT_MS = 30000;

// A minimal CDP client, the same shape as features_browser.js's; duplicated
// for the reason given in sandbox_browser.js.
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
      // Cleared when the answer arrives: left pending, each call's timer held
      // node open for up to 20 s after the driver had finished.
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-traceability-'));
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

  // A launch that fails after the spawn must take Chrome with it. Left
  // running, it holds this process's stderr pipe open, node never exits,
  // and the Go test waiting on node hangs until the package timeout — the
  // 20-minute CI hang Task 20340 traced to a Chrome slow to report its port.
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

    // Both steps are bounded: a Chrome that accepts the connection and never
    // answers would otherwise hang this driver, and the test waiting on it, with
    // nothing to say why.
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

// ── helpers ─────────────────────────────────────────────────────────────────

async function waitFor(cdp, expr, what) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    if (await cdp.eval(expr)) return;
    if (Date.now() >= deadline) throw new Error('timed out waiting for ' + what);
    await sleep(50);
  }
}

// click scrolls an element into view and clicks its centre with the mouse,
// once it is laid out and on top — a control covered by another element fails
// here the way it would fail a user.
//
// The check and the press are separate round trips, and the page can move the
// element in between: the presence bar that ends the socket's connect burst
// pushes the whole tab down 33 px. So the check arms a guard on the window
// that lets through the mousedown, mouseup and click that reach the element
// and swallows any that land elsewhere; a swallowed press is aimed and made
// again.
async function click(cdp, sel) {
  const deadline = Date.now() + WAIT_MS;
  let why = '';
  for (let i = 0; i === 0 || Date.now() < deadline; i++) {
    if (i) await sleep(50);
    const pt = await cdp.eval(`(() => {
      const e = document.querySelector(${JSON.stringify(sel)});
      if (!e) return null;
      e.scrollIntoView({block: 'center'});
      const r = e.getBoundingClientRect();
      if (!r.width || !r.height) return null;
      return {x: r.left + r.width / 2, y: r.top + r.height / 2};
    })()`);
    if (!pt) { why = 'nothing clickable at ' + sel; continue; }
    const armed = await cdp.eval(`(() => {
      const e = document.elementFromPoint(${pt.x}, ${pt.y});
      const want = document.querySelector(${JSON.stringify(sel)});
      if (!e || !want || !(e === want || want.contains(e))) return false;
      const seen = {}, types = ['mousedown', 'mouseup', 'click'];
      const guard = ev => {
        if (!ev.isTrusted) return; // the page's own clicks are not the press
        seen[ev.type] = ev.target === want || want.contains(ev.target);
        if (!seen[ev.type]) { ev.preventDefault(); ev.stopImmediatePropagation(); }
      };
      types.forEach(t => window.addEventListener(t, guard, true));
      // The click is dispatched with the mouseup, before the release returns;
      // the pause covers a press that brought no click at all.
      window.__pressSeen = () => new Promise(res => setTimeout(() => {
        types.forEach(t => window.removeEventListener(t, guard, true));
        res(seen);
      }, 'click' in seen ? 0 : 100));
      return true;
    })()`);
    if (!armed) { why = sel + ' is covered by another element'; continue; }
    for (const type of ['mousePressed', 'mouseReleased']) {
      await cdp.send('Input.dispatchMouseEvent', {type, x: pt.x, y: pt.y, button: 'left', clickCount: 1});
    }
    // The click decides: it is what runs the control's action, and it reaches
    // the element only when the press began and ended inside it.
    const seen = await cdp.eval(`window.__pressSeen()`);
    if (seen.click === true) return;
    why = 'click' in seen ? sel + ' moved between the aim and the press' : 'a press on ' + sel + ' brought no click';
  }
  throw new Error(why);
}

// ── the page ────────────────────────────────────────────────────────────────

const CONTROL = process.argv[4];

const text = sel => `((document.querySelector(${JSON.stringify(sel)}) || {}).textContent || '').replace(/\\s+/g, ' ').trim()`;
const rows = `Array.from(document.querySelectorAll('#rtTable tr[data-trace]')).map(r => +r.dataset.trace)`;
const traceReads = `window.__traceReads.length`;

async function boot(cdp) {
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  // Boot's last step (resumeView) removes this marker, so its absence says
  // boot is over and will not switch the tab out from under the driver.
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
    source: "try { sessionStorage.setItem('cloop_resume', '{\"at\":0}'); } catch (e) {}",
  });
  // Every read of the matrix, as the page asked for it.
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
    source: `window.__traceReads = [];
      const f = window.fetch;
      window.fetch = function (u) {
        if (String(u).indexOf('/api/requirements/trace') >= 0) window.__traceReads.push(String(u));
        return f.apply(this, arguments);
      };`,
  });
  await cdp.send('Page.navigate', {url: BASE + '/'});
  await waitFor(cdp, `typeof window.openProject === 'function' && typeof window.switchTab === 'function'`, 'the bundle to load');
  await waitFor(cdp, `sessionStorage.getItem('cloop_resume') === null`, 'boot to finish');
  await waitFor(cdp, `document.getElementById('liveDot').classList.contains('connected')`, 'the WebSocket');
}

// selectBy sets a filter as a person does, with a change event.
async function selectBy(cdp, id, value) {
  await cdp.eval(`(() => { const s = document.getElementById(${JSON.stringify(id)});
    s.value = ${JSON.stringify(value)}; s.dispatchEvent(new Event('change', {bubbles: true})); return true; })()`);
}

const results = {};

// The Overview's card shows the coverage of the musts, and opens the matrix.
async function scenarioCard(cdp) {
  await cdp.eval(`window.switchTab('overview')`);
  await waitFor(cdp, `document.getElementById('reqCovCard').style.display !== 'none' && ${text('#statReqCov')} !== '—'`,
    'the Spec coverage card');
  results.card = {value: await cdp.eval(text('#statReqCov')), sub: await cdp.eval(text('#statReqCovSub'))};
  await click(cdp, '#reqCovCard');
  await waitFor(cdp, `document.getElementById('tab-requirements').classList.contains('active') &&
    !!document.getElementById('reqTrace') && document.getElementById('reqTrace').style.display !== 'none' &&
    ${rows}.length > 0`, 'the Traceability view');
  results.opened = {
    rows: await cdp.eval(rows), count: await cdp.eval(text('#rtCount')),
    more: await cdp.eval(`document.getElementById('rtMore').style.display !== 'none'`),
    coverage: await cdp.eval(text('#rtCov')), pressed: await cdp.eval(`document.getElementById('reqViewTrace').getAttribute('aria-pressed')`),
  };
}

// A gap filter narrows the matrix, and Load more brings the rest of it.
async function scenarioFilterAndPage(cdp) {
  await selectBy(cdp, 'rtGap', 'unlinked');
  await waitFor(cdp, `${text('#rtCount')}.indexOf('of 53 shown') >= 0`, 'the unlinked requirements');
  const first = await cdp.eval(rows);
  await click(cdp, '#rtMore button');
  await waitFor(cdp, `${rows}.length === 53`, 'the second page');
  results.paged = {first: first.length, all: await cdp.eval(rows),
    more: await cdp.eval(`document.getElementById('rtMore').style.display !== 'none'`),
    reads: await cdp.eval(`window.__traceReads.filter(u => u.indexOf('gap=unlinked') >= 0)`)};
  await selectBy(cdp, 'rtGap', '');
  await selectBy(cdp, 'rtPriority', 'must');
  await waitFor(cdp, `${rows}.join(',') === '1,2'`, 'the musts');
  results.musts = {
    rows: await cdp.eval(rows),
    r1: await cdp.eval(text('#rtTable tr[data-trace="1"]')),
    r2: await cdp.eval(text('#rtTable tr[data-trace="2"]')),
  };
}

// The hub adds a must: the push redraws the coverage and the view reads its
// rows once — nothing reads them before the push says to.
async function scenarioPush(cdp) {
  const before = await cdp.eval(traceReads);
  const resp = await fetch(CONTROL + '/change', {method: 'POST', signal: AbortSignal.timeout(20000)});
  if (!resp.ok) throw new Error('the control server answered ' + resp.status);
  await waitFor(cdp, `${rows}.join(',') === '1,2,56'`, 'the new must, pushed');
  await waitFor(cdp, `${text('#rtCov')}.indexOf('3 must requirements') >= 0`, 'the coverage of three musts');
  results.pushed = {
    rows: await cdp.eval(rows), reads: (await cdp.eval(traceReads)) - before,
    coverage: await cdp.eval(text('#rtCov')), card: await cdp.eval(text('#statReqCov')),
  };
}

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  try {
    await boot(cdp);
    await scenarioCard(cdp);
    await scenarioFilterAndPage(cdp);
    await scenarioPush(cdp);
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
  process.stdout.write(JSON.stringify({error: {message: String(err && err.message || err)}, partial: results}, null, 2));
  process.exit(1);
});
