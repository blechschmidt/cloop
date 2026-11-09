// humangate_browser.js — human review gates on the Tasks tab, in a real
// browser against a real hub (Task 20477).
//
// What only a browser shows:
//
//   * that a gate's row is drawn as a gate — its own icon, the words "review
//     gate", the dashed border — and keeps the drag handle a queued task has;
//   * that the gate a run stopped at reads "waiting for review" and offers
//     Approve & continue, while a gate further down offers plain Approve;
//   * that + Review gate adds a gate to the end of the queue, and that the
//     list catches up from the hub's state_diff, with no refetch;
//   * that Approve opens a gate and its row turns into one that offers Reopen;
//   * that the aborted-outcome Reopen, moved to a deferred script to pay for
//     the gate's row, is fetched on its first press and still works.
//
// Approve & continue is not pressed: it starts a run. The Go side asks the hub
// what it stored. With a third argument the driver saves screenshots there.
//
// Usage: node humangate_browser.js <chrome-binary> <base-url> [screenshot-dir]
// Prints one JSON document on stdout: {scenario: {...}, ...}.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const SHOTS = process.argv[4] || '';

const sleep = ms => new Promise(r => setTimeout(r, ms));

// How long Chrome gets to report its DevTools port, in 50 ms polls: 90 s
// (Task 20372).
const CHROME_START_POLLS = 1800;

// How long to keep looking for a state the page should reach; never a pause a
// healthy run sits out. Under a loaded -race run a hub round trip takes seconds.
const WAIT_MS = 30000;

// A minimal CDP client, as in decompose_browser.js.
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
      clearTimeout(p.timer);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    });
  }
  on(fn) { this.handlers.push(fn); }
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-humangate-'));
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

  // A launch that fails after the spawn must take Chrome with it, or node never
  // exits and the Go test hangs to the package timeout (Task 20340).
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

// ── helpers ─────────────────────────────────────────────────────────────────

const q = s => JSON.stringify(s);
const text = sel => `((document.querySelector(${q(sel)}) || {}).textContent || '')`;
const valueOf = id => `(document.getElementById(${q(id)}) || {}).value`;
const visible = sel => `(() => { const e = document.querySelector(${q(sel)});
  return !!e && e.getClientRects().length > 0; })()`;

// waitFor polls a page expression until it is truthy. On a timeout it reports
// diag, an expression for what the page was showing instead.
async function waitFor(cdp, expr, what, diag) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    let v = false;
    try { v = await cdp.eval(expr); } catch (e) { /* navigating */ }
    if (v) return v;
    if (Date.now() >= deadline) {
      let said = '';
      try { said = diag ? ' — the page shows: ' + await cdp.eval(diag) : ''; } catch (e) { /* gone */ }
      throw new Error('timed out waiting for ' + what + said);
    }
    await sleep(25);
  }
}

// click scrolls an element into view and clicks its centre with the mouse,
// once it is laid out and on top — a control covered by another element (the
// sticky header, a toast) fails here the way it would fail a user.
//
// The page can still move the element between that check and the press, which
// are separate round trips. The socket's connect burst ends with the presence
// bar, which boot does not wait for and which pushes the whole tab down 33 px:
// a press made as it landed fell on the tab's background, nothing was posted,
// and the wait for the new gate timed out with no toast (CI, on 4c022890). So
// the check arms a guard on the window that lets through the mousedown and
// click that reach the element and swallows any that do not, which keeps a
// moved press from setting off whatever slid under the pointer; a swallowed
// press is aimed and made again.
async function click(cdp, sel) {
  const deadline = Date.now() + WAIT_MS;
  let why = '';
  for (let i = 0; i === 0 || Date.now() < deadline; i++) {
    if (i) await sleep(50);
    const pt = await cdp.eval(`(() => {
      const e = document.querySelector(${q(sel)});
      if (!e) return null;
      e.scrollIntoView({block: 'center'});
      const r = e.getBoundingClientRect();
      if (!r.width || !r.height) return null;
      return {x: r.left + r.width / 2, y: r.top + r.height / 2};
    })()`);
    if (!pt) { why = 'nothing clickable at ' + sel; continue; }
    const armed = await cdp.eval(`(() => {
      const e = document.elementFromPoint(${pt.x}, ${pt.y});
      const want = document.querySelector(${q(sel)});
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


async function shot(cdp, name) {
  if (!SHOTS) return;
  const r = await cdp.send('Page.captureScreenshot', {format: 'png'});
  fs.writeFileSync(path.join(SHOTS, name + '.png'), Buffer.from(r.data, 'base64'));
}

// row describes one task row: what it says and what it offers.
const rowExpr = id => `(() => {
  const r = document.querySelector('#taskListFull .task-item[data-task-id="${id}"]');
  if (!r) return null;
  const cs = getComputedStyle(r);
  return {
    gate: r.classList.contains('gate'),
    icon: (r.querySelector('.task-icon') || {}).textContent || '',
    meta: (r.querySelector('.task-meta span') || {}).textContent || '',
    buttons: [...r.querySelectorAll('.task-actions button')].map(b => b.textContent.trim()),
    draggable: r.getAttribute('draggable') === 'true',
    border: cs.borderTopStyle,
  };
})()`;

// The ids of the rows, top to bottom.
const orderExpr = `[...document.querySelectorAll('#taskListFull .task-item')].map(r => +r.dataset.taskId)`;

const results = {};

async function boot(cdp) {
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  // Boot's last step, resumeView, removes this stale marker: its absence says
  // boot is done choosing a tab, so it cannot switch away from the one below.
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
    source: `try { sessionStorage.setItem('cloop_resume', '{"at":0}'); } catch (e) {}`,
  });
  await cdp.send('Page.navigate', {url: BASE + '/'});
  await waitFor(cdp, `typeof window.approveGate === 'function' && sessionStorage.getItem('cloop_resume') === null`,
    'the dashboard to boot');
  await cdp.eval(`window.switchTab('tasks')`);
  await waitFor(cdp, `!!document.querySelector('#taskListFull .task-item[data-task-id="3"]')`, 'the task list',
    `document.getElementById('taskListFull').textContent`);
}

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  try {
    await boot(cdp);

    // The gate the run stopped at (3), and one further down (5).
    results.waiting = await cdp.eval(rowExpr(3));
    results.later = await cdp.eval(rowExpr(5));
    results.order_before = await cdp.eval(orderExpr);
    await shot(cdp, 'humangate-waiting');

    // + Review gate: a new gate at the end of the queue.
    await click(cdp, 'button[data-action="addReviewGate"]');
    await waitFor(cdp, `!!document.querySelector('#taskListFull .task-item[data-task-id="8"]')`,
      'the new gate in the list', `document.getElementById('toast').textContent`);
    results.added = await cdp.eval(rowExpr(8));
    // The row can arrive over the WebSocket before the button's own answer
    // toasts, so the toast is waited for rather than read.
    await waitFor(cdp, `document.getElementById('toast').textContent.indexOf('added') !== -1`,
      'the add toast', `document.getElementById('toast').textContent`);
    results.added_toast = await cdp.eval(`document.getElementById('toast').textContent`);
    results.order_after = await cdp.eval(orderExpr);

    // Approve the new gate: its row turns into an open gate's. Finished rows
    // are hidden by default, so they are shown first.
    await click(cdp, '#toggleCompletedBtn');
    await click(cdp, '#taskListFull .task-item[data-task-id="8"] button[data-action="approveGate"]');
    await waitFor(cdp, `(() => { const r = ${rowExpr(8)}; return !!r && r.buttons.indexOf('Reopen') !== -1; })()`,
      'the approved gate to offer Reopen', `document.getElementById('toast').textContent`);
    results.approved = await cdp.eval(rowExpr(8));
    await waitFor(cdp, `document.getElementById('toast').textContent.indexOf('approved') !== -1`,
      'the approve toast', `document.getElementById('toast').textContent`);
    results.approved_toast = await cdp.eval(`document.getElementById('toast').textContent`);
    await shot(cdp, 'humangate-approved');

    // The verdicts on a task recorded done on a refusal moved to a deferred
    // script to pay for the gate's row: it is fetched on the first press, not
    // before, and Reopen still reaches the hub.
    const ledgerFetched = `performance.getEntriesByType('resource').some(e =>
      new URL(e.name).pathname.startsWith('/assets/ledger.'))`;
    results.ledger_before = await cdp.eval(ledgerFetched);
    await click(cdp, '#taskListFull .task-item[data-task-id="7"] button[data-action="reopenAbortedTask"]');
    await waitFor(cdp, `document.getElementById('toast').textContent.indexOf('reopened') !== -1`,
      'the reopen toast', `document.getElementById('toast').textContent`);
    results.reopen_toast = await cdp.eval(`document.getElementById('toast').textContent`);
    results.ledger_after = await cdp.eval(ledgerFetched);
  } finally {
    killChrome(proc);
    try { fs.rmSync(dir, {recursive: true, force: true}); } catch (_) { /* best effort */ }
  }
}

main().then(() => {
  process.stdout.write(JSON.stringify(results));
  process.exit(0);
}, e => {
  results.error = {message: String(e && e.stack || e)};
  process.stdout.write(JSON.stringify(results));
  process.exit(0);
});
