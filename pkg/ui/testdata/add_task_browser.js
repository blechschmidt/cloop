// add_task_browser.js — types a multi-line description into the Tasks tab's
// Add Task form in a real browser (Task 20343).
//
// The form's description used to be an <input>, which cannot hold a line
// break: a brief typed or pasted into it reached the plan as one run-on line.
// Whether its replacement works is a question about a browser, not a bundle:
//
//   * Enter starts a new line in a <textarea> only because nothing handles
//     it. The title beside it adds the task on Enter, and that handler copied
//     across would turn every paragraph break into a half-written task.
//   * Ctrl+Enter and Cmd+Enter are real key events with real modifiers.
//   * Whether the box gets a line of its own, or stretches every input that
//     shares its line to its own height, is layout.
//
// testdata/domshim.js has no keyboard, no default actions and no box model,
// so this drives Chromium over CDP against a real hub. Keys are CDP key
// events and clicks are mouse events at the element's centre; the Go side
// asks the hub what it stored.
//
// Usage: node add_task_browser.js <chrome-binary> <base-url>
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-addtask-'));
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
async function click(cdp, sel) {
  let pt = null, hit = false;
  const deadline = Date.now() + WAIT_MS;
  for (let i = 0; !hit && (i === 0 || Date.now() < deadline); i++) {
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

// CDP modifier bits.
const CTRL = 2, META = 4;

// pressEnter sends Enter the way Puppeteer's keyboard does: a keyDown that
// carries the '\r' a real key produces, and — once Ctrl or Cmd is held — a
// rawKeyDown with no text, because a modified Enter types nothing.
async function pressEnter(cdp, modifiers) {
  const key = {key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13, modifiers: modifiers || 0};
  const down = modifiers ? {type: 'rawKeyDown'} : {type: 'keyDown', text: '\r', unmodifiedText: '\r'};
  await cdp.send('Input.dispatchKeyEvent', {...key, ...down});
  await cdp.send('Input.dispatchKeyEvent', {...key, type: 'keyUp'});
}

// type inserts text at the caret of whatever has focus, as an IME commit does.
// Lines are typed one at a time with a real Enter between them: inserting a
// '\n' directly would prove only that a textarea can hold one.
async function type(cdp, lines) {
  for (let i = 0; i < lines.length; i++) {
    if (i) await pressEnter(cdp, 0);
    if (lines[i]) await cdp.send('Input.insertText', {text: lines[i]});
  }
}

const valueOf = id => `(document.getElementById(${JSON.stringify(id)}) || {}).value`;

// focusByClick clicks into a field and makes sure the click gave it the
// keys. A click is aimed at where the field was when it was measured; if the
// page shifted in between — the task list rendering above the form while the
// panel is still loading, which CI's slower runner showed (Task 20376) — the
// press lands on the page instead, and every key after it goes to <body>.
// A person would click again, and so does this.
async function focusByClick(cdp, sel) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    await click(cdp, sel);
    const focused = await cdp.eval(`document.activeElement === document.querySelector(${JSON.stringify(sel)})`);
    if (focused) return;
    if (Date.now() >= deadline) throw new Error('clicking ' + sel + ' never gave it the focus');
    await sleep(100);
  }
}

// fill types a title and a description the way a person does: a click into
// each field, then the keys.
async function fill(cdp, title, lines) {
  await focusByClick(cdp, '#newTaskTitle');
  await cdp.send('Input.insertText', {text: title});
  await focusByClick(cdp, '#newTaskDesc');
  await type(cdp, lines);
}

// added waits for submitAddTask's success path, which empties both fields
// only once the hub has answered ok. A timeout says what the page looked like
// then — which element had the keys, what the fields held, whether the POST
// went out and what the last toast said — because "the form did not clear"
// alone cannot tell a key that never reached the form from a hub that never
// answered (CI saw it once, at eb40abf, and nowhere else).
async function added(cdp, what) {
  try {
    await waitFor(cdp, `${valueOf('newTaskTitle')} === '' && ${valueOf('newTaskDesc')} === ''`,
      'the form to clear after ' + what);
  } catch (e) {
    const seen = await cdp.eval(`JSON.stringify({
      focused: (document.activeElement || {}).id || (document.activeElement || {}).tagName || '',
      title: ${valueOf('newTaskTitle')},
      desc: ${valueOf('newTaskDesc')},
      posts: window.__addTaskPosts,
      toast: ((document.getElementById('toast') || {}).textContent || '').slice(0, 200),
    })`).catch(err => 'unreadable: ' + err.message);
    throw new Error(e.message + ' — page: ' + seen);
  }
}

// layout measures the form. visible_lines is the description box's content
// height in lines of the title field's text — the font is the same, so the
// title's content box is exactly one line.
const layoutExpr = `(() => {
  const box = el => {
    if (!el) return null;
    const b = el.getBoundingClientRect();
    return {top: b.top, bottom: b.bottom, left: b.left, right: b.right, width: b.width, height: b.height};
  };
  const content = el => {
    const cs = getComputedStyle(el);
    return el.clientHeight - parseFloat(cs.paddingTop) - parseFloat(cs.paddingBottom);
  };
  const bar = document.querySelector('.add-task-bar');
  const title = document.getElementById('newTaskTitle');
  const desc = document.getElementById('newTaskDesc');
  const bcs = getComputedStyle(bar);
  const de = document.documentElement;
  return {
    tag: desc.tagName,
    bar_width: bar.clientWidth - parseFloat(bcs.paddingLeft) - parseFloat(bcs.paddingRight),
    title: box(title),
    desc: box(desc),
    priority: box(document.getElementById('newTaskPriority')),
    deps: box(document.getElementById('newTaskDeps')),
    add: box(bar.querySelector('button.primary')),
    visible_lines: content(desc) / content(title),
    overflow_px: de.scrollWidth - de.clientWidth,
    viewport_w: window.innerWidth,
    viewport_h: window.innerHeight,
  };
})()`;

async function boot(cdp) {
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Page.navigate', {url: BASE + '/'});
  await waitFor(cdp, `typeof window.openProject === 'function'
    && typeof window.submitAddTask === 'function'`, 'the bundle to load');
  const name = await cdp.eval(`(async () => {
    const d = await (await fetch('/api/projects')).json();
    return ((d && d.projects) || [])[0] ? d.projects[0].name : '';
  })()`);
  await cdp.eval(`window.openProject(0, ${JSON.stringify(name)})`);
  await cdp.eval(`window.switchTab('tasks')`);
  await waitFor(cdp, `(() => {
      const d = document.getElementById('newTaskDesc');
      return !!d && d.getClientRects().length > 0;
    })()`, 'the Add Task form to be on screen');
}

// ── scenarios ───────────────────────────────────────────────────────────────

const results = {};

async function scenarioEnterStartsANewLine(cdp) {
  // Counted in the page rather than waited for: submitAddTask calls fetch in
  // the keydown that triggers it, so an Enter that submitted has already made
  // its request by the time the key event returns. The hub's task count, read
  // by the Go side, is the second witness.
  await cdp.eval(`(() => {
    window.__addTaskPosts = 0;
    const inner = window.fetch;
    window.fetch = function(url) {
      if (String(url).indexOf('/api/task/add') !== -1) window.__addTaskPosts++;
      return inner.apply(this, arguments);
    };
  })()`);
  await fill(cdp, 'Write the release notes',
    ['Summarise the changes since v0.0.1.', '', '- link each PR']);
  results.enter_starts_a_new_line = {
    value: await cdp.eval(valueOf('newTaskDesc')),
    title: await cdp.eval(valueOf('newTaskTitle')),
    focused: await cdp.eval(`(document.activeElement || {}).id || ''`),
    posts: await cdp.eval('window.__addTaskPosts'),
  };
}

async function scenarioCtrlEnterAdds(cdp) {
  await pressEnter(cdp, CTRL);
  await added(cdp, 'Ctrl+Enter');
  results.ctrl_enter_adds = {ok: true};
}

async function scenarioCmdEnterAdds(cdp) {
  await fill(cdp, 'Rotate the signing key', ['Generate a new key.', 'Publish it.']);
  await pressEnter(cdp, META);
  await added(cdp, 'Cmd+Enter');
  results.cmd_enter_adds = {ok: true};
}

async function scenarioButtonAdds(cdp) {
  // Trailing blank lines, which the form trims like it trims the title.
  await fill(cdp, 'Tidy the flags', ['Drop --legacy.', 'Keep --json.', '', '']);
  await click(cdp, '.add-task-bar button.primary');
  await added(cdp, 'the Add Task button');
  results.button_adds = {ok: true};
}

// The edit modal is where a description is read back and changed. Its box was
// already a textarea; what this pins is that a task added with line breaks
// opens there with them.
async function scenarioEditShowsTheLines(cdp) {
  const id = await cdp.eval(`(async () => {
    const s = await (await fetch('/api/state')).json();
    const t = ((s && s.plan && s.plan.tasks) || []).find(x => x.title === 'Write the release notes');
    return t ? t.id : 0;
  })()`);
  if (!id) throw new Error('the hub has no task titled "Write the release notes"');
  await cdp.eval(`window.openEditModal(${id})`);
  await waitFor(cdp, `document.getElementById('modal-overlay').classList.contains('open')`, 'the edit modal');
  results.edit_shows_the_lines = {
    tag: await cdp.eval(`document.getElementById('modalDesc').tagName`),
    value: await cdp.eval(valueOf('modalDesc')),
  };
  await cdp.eval(`window.closeModal()`);
}

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  try {
    await boot(cdp);
    results.desktop_layout = await cdp.eval(layoutExpr);
    await scenarioEnterStartsANewLine(cdp);
    await scenarioCtrlEnterAdds(cdp);
    await scenarioCmdEnterAdds(cdp);
    await scenarioButtonAdds(cdp);
    await scenarioEditShowsTheLines(cdp);

    // A phone, where the form stacks into a column and a 100% flex basis
    // would have become a height.
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 390, height: 844, deviceScaleFactor: 2, mobile: true,
    });
    await waitFor(cdp, `window.innerWidth === 390`, 'the phone viewport');
    // Measured once the phone media query has turned the form into a column.
    await waitFor(cdp, `getComputedStyle(document.querySelector('.add-task-bar')).flexDirection === 'column'`,
      'the phone layout');
    results.phone_layout = await cdp.eval(layoutExpr);

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
