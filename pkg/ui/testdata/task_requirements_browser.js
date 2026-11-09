// task_requirements_browser.js — links a task to the requirements it
// implements in a real browser (Task 20460).
//
// The edit dialog's list of requirements is a deferred panel drawn into the
// bundle's dialog, the task card's R-n chips are bundle markup that opens the
// deferred Requirements tab, and a requirement's details list the tasks that
// implement it. Whether those connect is a question about a browser: the
// fetches, the deferred scripts, the clicks and the layout. domshim builds no
// DOM from markup, so this drives Chromium over CDP against a real hub; the Go
// side asks the hub what it stored afterwards.
//
// Usage: node task_requirements_browser.js <chrome-binary> <base-url>
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-taskreqs-'));
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

const rowSel = id => `.task-item[data-task-id="${id}"]`;
const editSel = id => `${rowSel(id)} button[data-action="openEditModal"]`;
const pickerExpr = `Array.from(document.querySelectorAll('#modalReqs input[data-req]'))`;

async function boot(cdp) {
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  // Boot's last step (resumeView) removes this marker, so its absence says
  // boot is over and will not switch the tab out from under the driver.
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
    source: "try { sessionStorage.setItem('cloop_resume', '{\"at\":0}'); } catch (e) {}",
  });
  // Every task edit's body, as the page sent it.
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
    source: `window.__edits = [];
      const f = window.fetch;
      window.fetch = function (u, o) {
        if (String(u).indexOf('/api/task/edit') >= 0 && o && o.body) window.__edits.push(JSON.parse(o.body));
        return f.apply(this, arguments);
      };`,
  });
  await cdp.send('Page.navigate', {url: BASE + '/'});
  await waitFor(cdp, `typeof window.openProject === 'function' && typeof window.openEditModal === 'function'`,
    'the bundle to load');
  await waitFor(cdp, `sessionStorage.getItem('cloop_resume') === null`, 'boot to finish');
  const name = await cdp.eval(`(async () => {
    const d = await (await fetch('/api/projects')).json();
    return ((d && d.projects) || [])[0] ? d.projects[0].name : '';
  })()`);
  await cdp.eval(`window.openProject(0, ${JSON.stringify(name)})`);
  await cdp.eval(`window.switchTab('tasks')`);
  await waitFor(cdp, `!!document.querySelector(${JSON.stringify(rowSel(1))}) && !!document.querySelector(${JSON.stringify(rowSel(2))})`,
    'both task rows');
}

const chipsOf = id => `Array.from(document.querySelectorAll(${JSON.stringify(rowSel(id) + ' [data-action="openRequirement"]')})).map(c => c.textContent)`;

// openEdit opens task id's edit dialog and waits for its requirements.
async function openEdit(cdp, id, n) {
  await click(cdp, editSel(id));
  await waitFor(cdp, `document.getElementById('modal-overlay').classList.contains('open') &&
    document.getElementById('modalTaskId').value === '${id}'`, 'the edit dialog of task ' + id);
  await waitFor(cdp, `document.getElementById('modalReqs').style.display !== 'none' && ${pickerExpr}.length === ${n}`,
    n + ' requirements in the dialog of task ' + id);
}

const offered = `${pickerExpr}.map(i => ({id: +i.dataset.req, checked: i.checked,
  label: i.closest('label').textContent.replace(/\\s+/g, ' ').trim()}))`;

async function save(cdp) {
  const before = await cdp.eval(`window.__edits.length`);
  await click(cdp, '#modal button[data-action="submitEditTask"]');
  await waitFor(cdp, `window.__edits.length === ${before + 1} && !document.getElementById('modal-overlay').classList.contains('open')`,
    'the edit to be sent and the dialog to close');
  return cdp.eval(`window.__edits[window.__edits.length - 1]`);
}

const results = {};

// The chips the plan starts with: task 2 implements R-3.
async function scenarioChips(cdp) {
  results.chips = {task1: await cdp.eval(chipsOf(1)), task2: await cdp.eval(chipsOf(2))};
}

// Task 2's dialog offers the approved requirements and the deprecated one it
// already implements, ticked; saved untouched, it sends no requirements.
async function scenarioUntouched(cdp) {
  await openEdit(cdp, 2, 3);
  const list = await cdp.eval(offered);
  const sent = await save(cdp);
  results.untouched = {offered: list, sent_keys: Object.keys(sent).sort()};
}

// Task 1's dialog offers the approved ones; ticking R-4 and saving links it,
// and the row grows its chip.
async function scenarioLink(cdp) {
  await openEdit(cdp, 1, 2);
  const list = await cdp.eval(offered);
  await click(cdp, '#modalReqs input[data-req="4"]');
  const sent = await save(cdp);
  await waitFor(cdp, `${chipsOf(1)}.join(',') === 'R-4'`, 'the R-4 chip on task 1');
  results.link = {offered: list, sent: sent.requirements, chips: await cdp.eval(chipsOf(1))};
}

// The chip opens the requirement in the Requirements tab, whose details name
// the task; the task's button there opens the task.
async function scenarioChipOpens(cdp) {
  await click(cdp, `${rowSel(1)} [data-action="openRequirement"]`);
  await waitFor(cdp, `document.getElementById('tab-requirements').classList.contains('active')`, 'the Requirements tab');
  await waitFor(cdp, `(() => { const b = document.getElementById('reqDetails4');
    return !!b && b.style.display !== 'none' && b.textContent.indexOf('Implemented by') >= 0 &&
      !!b.querySelector('button[data-act="openTask"]'); })()`, "R-4's details naming its task");
  const details = await cdp.eval(`(() => {
    const b = document.getElementById('reqDetails4');
    return {
      tasks: Array.from(b.querySelectorAll('button[data-act="openTask"]')).map(x => x.textContent),
      text: b.textContent.replace(/\\s+/g, ' '),
    };
  })()`);
  await click(cdp, '#reqDetails4 button[data-act="openTask"]');
  await waitFor(cdp, `document.getElementById('td-overlay').classList.contains('open') &&
    document.getElementById('td-title').textContent === 'Task #1: Ship the parser' &&
    (document.getElementById('td-body').textContent || '').indexOf('Implements') >= 0`, "task 1's details");
  const implementsChip = await cdp.eval(`Array.from(document.querySelectorAll('#td-body .td-chip'))
    .map(c => c.textContent).filter(t => t.indexOf('Implements') === 0).join('')`);
  results.opened = {details_tasks: details.tasks, details_text: details.text, task_details: true, implements: implementsChip};
  await cdp.eval(`window.closeTaskDetails()`);
}

// At a phone's width the dialog and its list fit.
async function scenarioPhone(cdp) {
  await cdp.send('Emulation.setDeviceMetricsOverride', {width: 360, height: 780, deviceScaleFactor: 3, mobile: true});
  await waitFor(cdp, `window.innerWidth === 360`, 'the phone viewport');
  await cdp.eval(`window.switchTab('tasks')`);
  await waitFor(cdp, `!!document.querySelector(${JSON.stringify(rowSel(1))})`, 'the task rows');
  await openEdit(cdp, 1, 2);
  results.phone = await cdp.eval(`(() => {
    const de = document.documentElement;
    const modal = document.getElementById('modal').getBoundingClientRect();
    const box = document.getElementById('modalReqs');
    const r = box.getBoundingClientRect();
    return {
      overflow_px: de.scrollWidth - de.clientWidth,
      fits: r.left >= modal.left && r.right <= modal.right + 1 && box.scrollWidth <= box.clientWidth + 1,
    };
  })()`);
}

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  try {
    await boot(cdp);
    await scenarioChips(cdp);
    await scenarioUntouched(cdp);
    await scenarioLink(cdp);
    await scenarioChipOpens(cdp);
    await scenarioPhone(cdp);
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
