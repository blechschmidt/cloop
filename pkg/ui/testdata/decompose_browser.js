// decompose_browser.js — plans a task with Decompose, and splits one with the
// Split dialog, in a real browser against a real hub (Task 20441).
//
// Decompose sits beside Add Task: the task typed there is planned by the AI
// into several, reviewed as cards in the suggestions panel and added with
// Add all. What only a browser shows:
//
//   * that the button is on screen and pressable where Add Task is, on a
//     desktop and on a 360px phone;
//   * that one click runs the whole circuit — the hub plans the request
//     (a stand-in for `cloop suggest`), the plan arrives over the WebSocket,
//     and Add all puts its tasks in the list;
//   * that the Split dialog, a deferred script since this task, is fetched by
//     the first Split and not before, and that the list catches up after an
//     apply from the hub's state_diff, with no refetch.
//
// The Go side asks the hub what it stored. With a third argument the driver
// also saves screenshots there.
//
// Usage: node decompose_browser.js <chrome-binary> <base-url> [screenshot-dir]
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

// The plan the stand-in for `cloop suggest` answers with (suggest_plan_test.go).
const PLAN_TITLES = ['Add provider config', 'Callback handler', 'Login button', 'Document login'];

// A minimal CDP client, as in add_task_browser.js, that also hands events to
// listeners.
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-decompose-'));
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
async function click(cdp, sel) {
  let pt = null, hit = false;
  const deadline = Date.now() + WAIT_MS;
  for (let i = 0; !hit && (i === 0 || Date.now() < deadline); i++) {
    if (i) await sleep(50);
    pt = await cdp.eval(`(() => {
      const e = document.querySelector(${q(sel)});
      if (!e) return null;
      e.scrollIntoView({block: 'center'});
      const r = e.getBoundingClientRect();
      if (!r.width || !r.height) return null;
      return {x: r.left + r.width / 2, y: r.top + r.height / 2};
    })()`);
    if (!pt) continue;
    hit = await cdp.eval(`(() => {
      const e = document.elementFromPoint(${pt.x}, ${pt.y});
      const want = document.querySelector(${q(sel)});
      return !!e && !!want && (e === want || want.contains(e));
    })()`);
  }
  if (!pt) throw new Error('nothing clickable at ' + sel);
  if (!hit) throw new Error(sel + ' is covered by another element');
  for (const type of ['mousePressed', 'mouseReleased']) {
    await cdp.send('Input.dispatchMouseEvent', {type, x: pt.x, y: pt.y, button: 'left', clickCount: 1});
  }
}

// typeInto clicks into a field and types, as a person does. A click that
// lands while the page is still shifting goes to the page instead; a person
// clicks again, and so does this.
async function typeInto(cdp, sel, value) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    await click(cdp, sel);
    if (await cdp.eval(`document.activeElement === document.querySelector(${q(sel)})`)) break;
    if (Date.now() >= deadline) throw new Error('clicking ' + sel + ' never gave it the focus');
    await sleep(100);
  }
  await cdp.send('Input.insertText', {text: value});
}

// layout measures the Add Task form's two buttons: where they are, and whether
// the press would land on them.
const layoutExpr = `(() => {
  const box = el => {
    if (!el) return null;
    const b = el.getBoundingClientRect();
    const x = b.left + b.width / 2, y = b.top + b.height / 2;
    const at = b.width && b.height && y >= 0 && y < window.innerHeight ? document.elementFromPoint(x, y) : null;
    return {top: b.top, left: b.left, right: b.right, width: b.width, height: b.height,
            on_top: !!at && (at === el || el.contains(at))};
  };
  const bar = document.querySelector('.add-task-bar');
  const decompose = document.getElementById('decomposeTaskBtn');
  decompose.scrollIntoView({block: 'center'});
  const bcs = getComputedStyle(bar);
  const de = document.documentElement;
  return {
    bar_width: bar.clientWidth - parseFloat(bcs.paddingLeft) - parseFloat(bcs.paddingRight),
    decompose: box(decompose),
    add: box(bar.querySelector('button.primary')),
    title: box(document.getElementById('newTaskTitle')),
    label: decompose.textContent.trim(),
    disabled: decompose.disabled,
    overflow_px: de.scrollWidth - de.clientWidth,
    viewport_w: window.innerWidth,
  };
})()`;

async function shot(cdp, name) {
  if (!SHOTS) return;
  const r = await cdp.send('Page.captureScreenshot', {format: 'png'});
  fs.writeFileSync(path.join(SHOTS, name + '.png'), Buffer.from(r.data, 'base64'));
}

// ── the run ─────────────────────────────────────────────────────────────────

const splitFetches = []; // requests for the Split dialog's deferred script

const results = {};

async function boot(cdp) {
  cdp.on(msg => {
    if (msg.method === 'Network.requestWillBeSent' &&
        /^\/assets\/split\.[0-9a-f]{16}\.js$/.test(new URL(msg.params.request.url).pathname)) {
      splitFetches.push(msg.params.request.url);
    }
  });
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Network.enable');
  // Boot's last step, resumeView, removes this stale marker: its absence says
  // boot is done choosing a tab, so it cannot switch away from the one below.
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
    source: `try { sessionStorage.setItem('cloop_resume', '{"at":0}'); } catch (e) {}`,
  });
  await cdp.send('Page.navigate', {url: BASE + '/'});
  await waitFor(cdp, `typeof window.decomposeNewTask === 'function' && sessionStorage.getItem('cloop_resume') === null`,
    'the dashboard to boot');
  await cdp.eval(`window.switchTab('tasks')`);
  await waitFor(cdp, visible('#decomposeTaskBtn'), 'the Decompose button');
  await waitFor(cdp, `!!document.querySelector('#taskListFull .task-item[data-task-id="2"]')`, 'the task list');
}

// Decompose the task typed into Add Task, and add the whole plan.
async function scenarioDecompose(cdp) {
  await typeInto(cdp, '#newTaskTitle', 'Add OAuth login');
  await typeInto(cdp, '#newTaskDesc', 'Sign in with GitHub, and keep the session.');
  await typeInto(cdp, '#newTaskPriority', '2');
  await typeInto(cdp, '#newTaskDeps', '1');
  const panelBefore = await cdp.eval(visible('#suggestPanel'));
  await click(cdp, '#decomposeTaskBtn');

  // The form empties once the hub has the job, and the request is in the panel.
  await waitFor(cdp, `${valueOf('newTaskTitle')} === '' && ${valueOf('newTaskDeps')} === ''`,
    'the form to clear', `${text('#toast')} + ' / ' + ${text('#suggestStatusText')}`);
  const input = await cdp.eval(valueOf('suggestInput'));

  await waitFor(cdp, `document.querySelectorAll('#suggestList .suggest-card').length === ${PLAN_TITLES.length}`,
    "the plan's cards", `${text('#suggestStatusText')} + ' / ' + ${text('#toast')}`);
  const cards = await cdp.eval(`[...document.querySelectorAll('#suggestList .suggest-card-title')].map(e => e.textContent)`);
  const summary = await cdp.eval(text('#suggestSummary'));
  const toast = await cdp.eval(text('#toast'));
  // The cards a person is to review are where they can see them.
  const cardsOnScreen = await cdp.eval(`(() => {
    const r = document.querySelector('#suggestList .suggest-card').getBoundingClientRect();
    return r.top < window.innerHeight && r.bottom > 0; })()`);
  await shot(cdp, 'decompose-plan');

  await click(cdp, '#suggestAddAllBtn');
  await waitFor(cdp, `document.querySelectorAll('#suggestList .suggest-card').length === 0`, 'the cards to be added',
    text('#toast'));
  await waitFor(cdp, `(() => {
    const list = ${text('#taskListFull')};
    return ${q(PLAN_TITLES)}.every(t => list.indexOf(t) !== -1); })()`, 'the plan in the task list', text('#taskListFull'));
  const addToast = await cdp.eval(text('#toast'));
  await shot(cdp, 'decompose-added');

  results.decompose = {
    panel_before: panelBefore, panel_after: await cdp.eval(visible('#suggestPanel')),
    input, cards, summary, toast, cards_on_screen: cardsOnScreen, add_toast: addToast,
  };
}

// Split task #2 with the deferred dialog, keeping two of its three sub-tasks.
async function scenarioSplit(cdp) {
  const before = splitFetches.length;
  await click(cdp, '#taskListFull .task-item[data-task-id="2"] button[data-action="splitTask"]');
  await waitFor(cdp, `document.querySelectorAll('#dc-body .dc-sub').length === 3`, 'the proposed sub-tasks',
    text('#dc-body'));
  const title = await cdp.eval(text('#dc-title'));
  const focusInside = await cdp.eval(`(() => {
    const m = document.getElementById('dc-modal');
    return !!m && m.contains(document.activeElement); })()`);
  await shot(cdp, 'split-dialog');
  await click(cdp, '#dc-body label.dc-sub:nth-of-type(2) input');
  await waitFor(cdp, `${text('#dc-count')} === '2/3 selected'`, 'the second sub-task to be dropped', text('#dc-count'));
  await click(cdp, '#dc-apply-btn');
  await waitFor(cdp, `!document.getElementById('dc-overlay').classList.contains('open')`, 'the dialog to close',
    text('#toast'));
  const toast = await cdp.eval(text('#toast'));
  // The list follows the hub's state_diff; the dialog no longer refetches.
  await waitFor(cdp, `(() => {
    const list = ${text('#taskListFull')};
    return list.indexOf('Write the migration') !== -1 && list.indexOf('Verify the row counts') !== -1; })()`,
  'the sub-tasks in the task list', text('#taskListFull'));
  results.split = {
    fetched_before_click: before, fetched_after: splitFetches.length, title, focus_inside: focusInside, toast,
    dropped_listed: await cdp.eval(`${text('#taskListFull')}.indexOf('Backfill the old rows') !== -1`),
  };
}

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  try {
    await boot(cdp);
    results.desktop_layout = await cdp.eval(layoutExpr);
    await scenarioDecompose(cdp);
    await scenarioSplit(cdp);

    // The phone the users carry: 360px wide, where the form is a column.
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 360, height: 780, deviceScaleFactor: 3, mobile: true,
    });
    await waitFor(cdp, `window.innerWidth === 360`, 'the phone viewport');
    await waitFor(cdp, `getComputedStyle(document.querySelector('.add-task-bar')).flexDirection === 'column'`,
      'the phone layout');
    results.phone_layout = await cdp.eval(layoutExpr);
    await shot(cdp, 'decompose-phone');

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
  process.stdout.write(JSON.stringify(Object.assign(results, {error: {message: String(err && err.stack || err)}}), null, 2));
  process.exit(1);
});
