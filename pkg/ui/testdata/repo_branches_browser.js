// repo_branches_browser.js — drives the Repository Access panel's branch
// restriction in a real browser (Task 20340).
//
// The task is "restrict write permissions to particular branches through the
// user interface", which is a claim about a form: that the branch field is
// there when it applies and gone when it does not, that the panel says what a
// restriction amounts to on this hub, and that editing one actually replaces
// the grant. The shim can say which endpoint was called; only a browser can
// say whether a person could see the field and click the button.
//
// Clicks are real mouse events at the element's on-screen position, not
// el.click(): a button hidden behind another element, or rendered with no
// size, fails here the way it would fail a user.
//
// Usage: node repo_branches_browser.js <chrome-binary> <base-url>
// Prints one JSON document on stdout: {scenario: {...}, ...}.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];

const sleep = ms => new Promise(r => setTimeout(r, ms));

// A minimal CDP client, the same shape as sandbox_browser.js's; duplicated for
// the reason given there.
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
      this.pending.set(id, {resolve, reject});
      this.ws.send(JSON.stringify({id, method, params: params || {}}));
      setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(method + ' timed out'));
      }, 20000);
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

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-branches-'));
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--window-size=1400,1000',
    'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe']});

  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });

  // A launch that fails after the spawn must take Chrome with it. Left
  // running, it holds this process's stderr pipe open, node never exits,
  // and the Go test waiting on node hangs until the package timeout — the
  // 20-minute CI hang Task 20340 traced to a Chrome slow to report its port.
  try {
    const portFile = path.join(dir, 'DevToolsActivePort');
    let port = 0;
    for (let i = 0; i < 600 && !port; i++) {
      await sleep(50);
      if (proc.exitCode !== null) throw new Error('chrome exited: ' + stderr);
      try {
        const txt = fs.readFileSync(portFile, 'utf8').split('\n');
        if (txt[0] && txt[0].trim()) port = Number(txt[0].trim());
      } catch (e) { /* not written yet */ }
    }
    if (!port) throw new Error('chrome never reported a debugging port within 30s: ' + stderr);

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
    try { proc.kill('SIGKILL'); } catch (_) { /* already gone */ }
    throw e;
  }
}

// ── helpers ─────────────────────────────────────────────────────────────────

// visible asks the layout engine: display:none on the element or any ancestor
// leaves it with no client rects.
const visibleExpr = sel =>
  `(() => { const e = document.querySelector(${JSON.stringify(sel)});
     return !!e && e.getClientRects().length > 0; })()`;

// click scrolls an element into view and clicks its centre with the mouse.
//
// It waits for the element to be there, laid out and on top first, for up to
// five seconds: the dashboard re-renders panels as its own start-up requests
// land, and on a loaded machine that can still be happening when a scenario
// begins. A button that never becomes clickable is still a failure.
async function click(cdp, sel) {
  let pt = null, hit = false;
  for (let i = 0; i < 100 && !hit; i++) {
    if (i) await sleep(50);
    pt = await cdp.eval(`(() => {
      const e = document.querySelector(${JSON.stringify(sel)});
      if (!e) return null;
      e.scrollIntoView({block: 'center'});
      const r = e.getBoundingClientRect();
      if (!r.width || !r.height) return null;
      return {x: r.left + r.width / 2, y: r.top + r.height / 2};
    })()`);
    if (!pt) continue;
    // What is actually on top at that point is what the click lands on.
    hit = await cdp.eval(`(() => {
      const e = document.elementFromPoint(${pt.x}, ${pt.y});
      const want = document.querySelector(${JSON.stringify(sel)});
      return !!e && !!want && (e === want || want.contains(e));
    })()`);
  }
  if (!pt) throw new Error('nothing clickable at ' + sel);
  if (!hit) throw new Error(sel + ' is covered by another element');
  for (const type of ['mousePressed', 'mouseReleased']) {
    await cdp.send('Input.dispatchMouseEvent', {type, x: pt.x, y: pt.y, button: 'left', clickCount: 1});
  }
}

// setSelect changes a <select> and dispatches the real change event.
const setSelectExpr = (sel, value) =>
  `(() => { const e = document.querySelector(${JSON.stringify(sel)});
     if (!e) return 'no element';
     e.value = ${JSON.stringify(value)};
     e.dispatchEvent(new Event('change', {bubbles: true}));
     return e.value; })()`;

async function waitFor(cdp, expr, what) {
  for (let i = 0; i < 100; i++) {
    if (await cdp.eval(expr)) return;
    await sleep(50);
  }
  throw new Error('timed out waiting for ' + what);
}

async function fetchJSON(cdp, url) {
  return cdp.eval(`(async () => (await fetch(${JSON.stringify(url)})).json())()`);
}

// boot opens the project the way a person does — its card calls openProject,
// which selects it and switches to its Overview — rather than relying on the
// hub having exactly one project, where the Overview happens to show it
// unselected. Then it waits for the panel to be on screen, not merely in the
// DOM.
async function boot(cdp) {
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Page.navigate', {url: BASE + '/'});
  await waitFor(cdp, `typeof window.loadProjectRepositories === 'function'
    && typeof window.openProject === 'function'`, 'the bundle to define the panel');
  const name = await cdp.eval(`(async () => {
    const d = await (await fetch('/api/projects')).json();
    return ((d && d.projects) || [])[0] ? d.projects[0].name : '';
  })()`);
  await cdp.eval(`window.openProject(0, ${JSON.stringify(name)})`);
  await waitFor(cdp, `(() => {
      const b = document.getElementById('projectReposBody');
      return !!b && b.getClientRects().length > 0 && b.textContent.indexOf('acme/api') >= 0;
    })()`, 'the repositories panel to show the seeded assignment');
}

// ── scenarios ───────────────────────────────────────────────────────────────

const results = {};

async function scenarioPanelShowsTheRestriction(cdp) {
  const text = await cdp.eval(`document.getElementById('projectReposBody').textContent`);
  results.panel_shows_restriction = {
    panel_visible: await cdp.eval(visibleExpr('#projectReposPanel')),
    names_branch: text.indexOf('branches: cloop/*') >= 0,
    says_not_enforced: text.indexOf('no git proxy') >= 0,
    edit_visible: await cdp.eval(visibleExpr('[data-gh-edit]')),
  };
}

async function scenarioAssignFormFollowsAccess(cdp) {
  const hiddenForRead = !(await cdp.eval(visibleExpr('#ghAssignBranches')));
  await cdp.eval(setSelectExpr('#ghAssignAccess', 'write'));
  await sleep(50);
  const shownForWrite = await cdp.eval(visibleExpr('#ghAssignBranches'));
  const hint = await cdp.eval(`(document.querySelector('#ghAssignBranchGroup .gh-branch-hint') || {}).textContent || ''`);
  await cdp.eval(setSelectExpr('#ghAssignAccess', 'read'));
  await sleep(50);
  results.assign_form_follows_access = {
    hidden_for_read: hiddenForRead,
    shown_for_write: shownForWrite,
    hint_warns_no_proxy: hint.indexOf('no git proxy') >= 0 && hint.indexOf('read-only') >= 0,
    hidden_again: !(await cdp.eval(visibleExpr('#ghAssignBranches'))),
  };
}

async function scenarioEditReplacesTheGrant(cdp) {
  const before = await fetchJSON(cdp, '/api/projects/0/repositories');
  const oldID = before.assignments[0].grant_id;

  await click(cdp, '[data-gh-edit]');
  await waitFor(cdp, `!!document.querySelector('.gh-edit-row')`, 'the edit row to open');
  const prefilled = await cdp.eval(`document.querySelector('.gh-edit-branches').value`);

  await cdp.eval(setSelectExpr('.gh-edit-access', 'read'));
  await sleep(50);
  const hiddenForRead = !(await cdp.eval(visibleExpr('.gh-edit-branches')));
  await cdp.eval(setSelectExpr('.gh-edit-access', 'write'));
  await sleep(50);
  const shownForWrite = await cdp.eval(visibleExpr('.gh-edit-branches'));

  // Typed the way a person types: focus, select all, insert text.
  await click(cdp, '.gh-edit-branches');
  await cdp.eval(`document.querySelector('.gh-edit-branches').select()`);
  await cdp.send('Input.insertText', {text: 'feature/**, release/*'});

  await click(cdp, '[data-gh-edit-save]');
  await waitFor(cdp, `!document.querySelector('.gh-edit-row')`, 'the edit row to close after saving');

  // The hub, not the screen, is the witness: what we typed is on the screen.
  const after = await fetchJSON(cdp, '/api/projects/0/repositories');
  const rows = (after && after.assignments) || [];
  results.edit_replaces_grant = {
    prefilled: prefilled,
    hidden_for_read: hiddenForRead,
    shown_for_write: shownForWrite,
    assignments: rows.length,
    new_grant: rows.length === 1 && rows[0].grant_id !== oldID,
    branches: rows.length ? (rows[0].branches || []) : [],
    access: rows.length ? rows[0].access : '',
    panel_updated: await cdp.eval(`document.getElementById('projectReposBody').textContent
      .indexOf('feature/**') >= 0`),
  };
}

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  try {
    await boot(cdp);
    await scenarioPanelShowsTheRestriction(cdp);
    await scenarioAssignFormFollowsAccess(cdp);
    await scenarioEditReplacesTheGrant(cdp);
    process.stdout.write(JSON.stringify(results, null, 2));
  } finally {
    try { proc.kill('SIGKILL'); } catch (e) { /* already gone */ }
    try { fs.rmSync(dir, {recursive: true, force: true}); } catch (e) { /* best effort */ }
  }
}

main().catch(err => {
  process.stdout.write(JSON.stringify({error: {message: String(err && err.message || err)}}, null, 2));
  process.exit(1);
});
