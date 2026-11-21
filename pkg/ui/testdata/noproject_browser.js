// noproject_browser.js — the dashboard of a hub with several projects and none
// of them opened, in a real browser against a real hub (Task 20508).
//
// "It is unintuitive that tasks are empty if no project has been selected yet.
// As long as no project has been selected yet, menu items whose view only makes
// sense if a project has been selected, such as Tasks and others, should be
// hidden."
//
// What only a browser shows: that the per-project tabs, the phone menu's
// Project section, the back arrow and the task-key hints are really off
// screen until a project is opened and really on it afterwards — the hiding is
// one stylesheet rule keyed on a class of <body>, and testdata/domshim.js has
// no stylesheet. And that they are off from the first paint: the page does not
// know how many projects the hub has until its first request is answered, so
// this holds that answer back and looks at what is on screen meanwhile.
//
// The driver measures and reports; noproject_browser_test.go judges. Every
// step waits on what the page shows. The one fixed wait is for a key that must
// do nothing: 200 ms, twice what the n key takes to move the caret when it
// does something.
//
// Usage: node noproject_browser.js <chrome-binary> <base-url> <config.json>
// config: {mode: "several"|"one", viewports: [{name,width,height,scale,mobile}],
//          tabs: [...every tab...], open: {idx, name, task}, own_task, shots}
// Prints one JSON document on stdout.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const CONFIG = JSON.parse(fs.readFileSync(process.argv[4], 'utf8'));
const SHOTS = CONFIG.shots || '';

const sleep = ms => new Promise(r => setTimeout(r, ms));
const q = v => JSON.stringify(v);

// How long Chrome gets to report its DevTools port, in 50 ms polls: 90 s
// (Task 20372).
const CHROME_START_POLLS = 1800;

// How long to keep looking for a state the page should reach; never a pause a
// healthy run sits out. Under a loaded -race run a hub round trip takes seconds.
const WAIT_MS = 30000;

// A minimal CDP client, as in humangate_browser.js.
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-noproject-'));
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
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

// until polls a node-side condition, for what the page cannot be asked.
async function until(fn, what) {
  const deadline = Date.now() + WAIT_MS;
  while (!fn()) {
    if (Date.now() >= deadline) throw new Error('timed out waiting for ' + what);
    await sleep(25);
  }
}

// click scrolls an element into view and clicks its centre with the mouse,
// once it is laid out and on top — a control that is hidden, or covered by
// another element, fails here the way it would fail a user. The guard is
// humangate_browser.js's: the page can move between the aim and the press (the
// presence bar lands late and shifts everything 33 px), so a press that did not
// reach the element is swallowed, aimed and made again.
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
    const seen = await cdp.eval(`window.__pressSeen()`);
    if (seen.click === true) return;
    why = 'click' in seen ? sel + ' moved between the aim and the press' : 'a press on ' + sel + ' brought no click';
  }
  throw new Error(why);
}

// press types one key at the page, outside any field. mods: 2 is Ctrl.
async function press(cdp, key, opts) {
  opts = opts || {};
  await cdp.eval(`document.activeElement && document.activeElement !== document.body && document.activeElement.blur()`);
  const ev = {key, code: opts.code || '', windowsVirtualKeyCode: opts.vk || 0, modifiers: opts.mods || 0};
  if (key.length === 1 && !opts.mods) ev.text = key;
  await cdp.send('Input.dispatchKeyEvent', Object.assign({type: 'keyDown'}, ev));
  await cdp.send('Input.dispatchKeyEvent', Object.assign({type: 'keyUp'}, ev));
}

async function shot(cdp, name) {
  if (!SHOTS) return;
  const r = await cdp.send('Page.captureScreenshot', {format: 'png'});
  fs.writeFileSync(path.join(SHOTS, name + '.png'), Buffer.from(r.data, 'base64'));
}

async function setViewport(cdp, v) {
  await cdp.send('Emulation.setDeviceMetricsOverride',
    {width: v.width, height: v.height, deviceScaleFactor: v.scale || 1, mobile: !!v.mobile});
  await cdp.send('Emulation.setTouchEmulationEnabled', {enabled: !!v.mobile});
}

// nav reads what the page offers: which tab buttons are laid out — in the
// header strip and in the phone's menu — and can be hit where they are drawn,
// with the rest of what the no-project rule touches.
const NAV = `(() => {
  const shown = e => !!e && e.getClientRects().length > 0 && getComputedStyle(e).visibility !== 'hidden';
  // On top where it is drawn: the element a press at its middle would reach.
  const hittable = e => {
    if (!shown(e)) return false;
    const r = e.getBoundingClientRect();
    const x = r.left + r.width / 2, y = r.top + r.height / 2;
    if (x < 0 || y < 0 || x > innerWidth || y > innerHeight) return true;   // off screen, not covered: the strip scrolls
    const at = document.elementFromPoint(x, y);
    return !!at && (at === e || e.contains(at));
  };
  const tabs = ${q(CONFIG.tabs)};
  const strip = tabs.filter(t => shown(document.getElementById('tbtn-' + t)));
  const header = document.querySelector('header');
  return {
    in_project: document.body.classList.contains('in-project'),
    active: ((document.querySelector('.tab-panel.active') || {}).id || '').replace(/^tab-/, ''),
    strip,
    strip_covered: strip.filter(t => !hittable(document.getElementById('tbtn-' + t))),
    strip_rows: new Set(strip.map(t => Math.round(document.getElementById('tbtn-' + t).getBoundingClientRect().top))).size,
    menu: tabs.filter(t => shown(document.getElementById('mtbtn-' + t))),
    labels: [...document.querySelectorAll('.tab-section-label, .mobile-nav-section-label')].filter(shown).map(e => e.textContent.trim()),
    back: shown(document.getElementById('projBackBtn')),
    hints: [...document.querySelectorAll('#kb-footer span')]
      .filter(e => e.querySelector(':scope > kbd') && shown(e)).map(e => e.textContent.replace(/\\s+/g, ' ').trim()),
    add_task_form: shown(document.getElementById('newTaskTitle')),
    danger_zone: shown(document.querySelector('#tab-settings .danger-zone')),
    provider_cards: shown(document.getElementById('cfgProvider')),
    project_caps: shown(document.getElementById('bpDailyUSD')),
    global_limits: shown(document.getElementById('bgDailyUSD')),
    selector: (document.getElementById('projSelectorLabel') || {}).textContent || '',
    scope: (document.getElementById('scopeHint') || {}).textContent || '',
    focus: (document.activeElement && document.activeElement.id) || '',
    overflow_x: document.documentElement.scrollWidth - innerWidth,
    header_height: header ? Math.round(header.getBoundingClientRect().height) : 0,
    search: location.search,
  };
})()`;

// What the Tasks tab lists.
const TASKS = `[...document.querySelectorAll('#taskListFull .task-item .task-title')].map(e => e.textContent.trim())`;

const results = {};

// The requests the page made, by path and query, since the last take().
let requests = [];
function take() { const r = requests; requests = []; return r; }

// load opens a page of the dashboard and waits for boot to finish choosing a
// view: resumeView, boot's last step, removes the stale marker seeded below.
async function load(cdp, pathAndQuery) {
  await cdp.send('Page.navigate', {url: BASE + (pathAndQuery || '/')});
  await waitFor(cdp, `typeof window.switchTab === 'function' && sessionStorage.getItem('cloop_resume') === null`,
    'the dashboard to boot');
}

// loadHeld opens the dashboard with its first request for the project list
// held back, and reports what is on screen while the page does not know yet
// how many projects the hub has. Then it lets the answer through.
async function loadHeld(cdp) {
  let held = null;
  const onPaused = msg => { if (msg.method === 'Fetch.requestPaused' && !held) held = msg.params.requestId; };
  cdp.on(onPaused);
  await cdp.send('Fetch.enable', {patterns: [{urlPattern: '*/api/projects', requestStage: 'Request'}]});
  await cdp.send('Page.navigate', {url: BASE + '/'});
  await until(() => held, 'the page to ask for the project list');
  // The bundle has run (it is what asked) and the header is laid out.
  await waitFor(cdp, `typeof window.switchTab === 'function' && !!document.getElementById('tbtn-projects') &&
    document.getElementById('tbtn-projects').getClientRects().length > 0`, 'the header to be laid out');
  const before = await cdp.eval(NAV);
  await cdp.send('Fetch.continueRequest', {requestId: held});
  await cdp.send('Fetch.disable');
  await waitFor(cdp, `sessionStorage.getItem('cloop_resume') === null`, 'the dashboard to boot');
  return before;
}

const cardsDrawn = `document.querySelectorAll('#projList .proj-card').length >= 2`;

async function several(cdp) {
  const open = CONFIG.open;
  const card = `#projList .proj-card[data-arg="${open.idx}"] .proj-name`;

  // 1. First paint, the answer to "how many projects" held back.
  await setViewport(cdp, CONFIG.viewports[0]);
  results.held = await loadHeld(cdp);
  await waitFor(cdp, cardsDrawn, 'the project list');

  // 2. The landing page at every size.
  results.landing = {};
  for (const v of CONFIG.viewports) {
    await setViewport(cdp, v);
    await load(cdp, '/');
    await waitFor(cdp, cardsDrawn, 'the project list at ' + v.name);
    const m = await cdp.eval(NAV);
    if (v.mobile && v.width < 480) {
      await click(cdp, '#hamburgerBtn');
      await waitFor(cdp, `document.getElementById('mobileNavOverlay').classList.contains('open') &&
        document.getElementById('mtbtn-projects').getClientRects().length > 0`, 'the phone menu at ' + v.name);
      m.opened_menu = await cdp.eval(NAV);
      await shot(cdp, 'noproject-' + v.name + '-menu');
      await click(cdp, '.mobile-nav-close');
      await waitFor(cdp, `!document.getElementById('mobileNavOverlay').classList.contains('open')`, 'the menu to close');
    }
    results.landing[v.name] = m;
    await shot(cdp, 'noproject-' + v.name + '-landing');
  }

  // 3. The ways into a project's tab that are not a button, none open.
  await setViewport(cdp, CONFIG.viewports[0]);
  await load(cdp, '/');
  await waitFor(cdp, cardsDrawn, 'the project list');
  take();
  await press(cdp, '2');
  await press(cdp, 'n');
  // n would put the caret in the add-task title 100 ms on; give it that.
  await waitFor(cdp, `new Promise(r => setTimeout(() => r(true), 200))`, 'the n key to settle');
  results.keys_none = await cdp.eval(NAV);

  await press(cdp, 'k', {mods: 2, code: 'KeyK', vk: 75});
  await waitFor(cdp, `document.getElementById('cmd-backdrop').classList.contains('open')`, 'the command palette');
  results.palette_none = await cdp.eval(`[...document.querySelectorAll('#cmd-results .cmd-item-label')].map(e => e.textContent)`);
  await shot(cdp, 'noproject-palette');
  await press(cdp, 'Escape', {code: 'Escape', vk: 27});
  await waitFor(cdp, `!document.getElementById('cmd-backdrop').classList.contains('open')`, 'the palette to close');

  await press(cdp, '?');
  await waitFor(cdp, `document.getElementById('help-backdrop').classList.contains('open')`, 'the shortcut help');
  results.help_none = await cdp.eval(`[...document.querySelectorAll('#help-modal-body h4')].map(e => e.textContent)`);
  await press(cdp, 'Escape', {code: 'Escape', vk: 27});
  await waitFor(cdp, `!document.getElementById('help-backdrop').classList.contains('open')`, 'the help to close');

  await load(cdp, '/?tab=tasks');
  await waitFor(cdp, cardsDrawn, 'the project list behind /?tab=tasks');
  results.link_none = await cdp.eval(NAV);

  // Settings with none open: the reset of "the project" is not on offer.
  await click(cdp, '#tbtn-settings');
  await waitFor(cdp, `!!document.querySelector('#tab-settings .danger-zone')`, 'the Settings tab');
  results.settings_none = await cdp.eval(NAV);
  // Budget with none open: the hub's limits, without a project's caps.
  await click(cdp, '#tbtn-budget');
  await waitFor(cdp, `!!document.getElementById('bgDailyUSD') && document.getElementById('bgDailyUSD').getClientRects().length > 0`,
    'the Budget tab');
  results.budget_none = await cdp.eval(NAV);
  results.requests_none = take();

  // 4. Open a project by its card: its tabs arrive.
  await click(cdp, '#tbtn-projects');
  await waitFor(cdp, cardsDrawn, 'the project list');
  await click(cdp, card);
  await waitFor(cdp, `(document.getElementById('breadcrumbName') || {}).textContent === ${q(open.name)} &&
    document.getElementById('projectPanel').style.display !== 'none'`, 'the project to open',
  `document.getElementById('toast').textContent`);
  results.opened = await cdp.eval(NAV);
  await shot(cdp, 'noproject-opened');

  await click(cdp, '#tbtn-tasks');
  await waitFor(cdp, `${TASKS}.length > 0`, 'the project\'s tasks', `document.getElementById('taskListFull').textContent`);
  results.tasks = {nav: await cdp.eval(NAV), titles: await cdp.eval(TASKS)};

  await press(cdp, '1');
  await waitFor(cdp, `document.getElementById('tab-overview').classList.contains('active')`, 'key 1 to open the Overview');
  await press(cdp, '2');
  await waitFor(cdp, `document.getElementById('tab-tasks').classList.contains('active')`, 'key 2 to open Tasks');
  results.keys_open = await cdp.eval(NAV);

  await press(cdp, 'k', {mods: 2, code: 'KeyK', vk: 75});
  await waitFor(cdp, `document.getElementById('cmd-backdrop').classList.contains('open')`, 'the command palette');
  results.palette_open = await cdp.eval(`[...document.querySelectorAll('#cmd-results .cmd-item-label')].map(e => e.textContent)`);
  await press(cdp, 'Escape', {code: 'Escape', vk: 27});
  await waitFor(cdp, `!document.getElementById('cmd-backdrop').classList.contains('open')`, 'the palette to close');

  // A global tab, visited from inside the project, keeps the project's tabs.
  await click(cdp, '#tbtn-settings');
  await waitFor(cdp, `document.getElementById('tab-settings').classList.contains('active') &&
    !!document.querySelector('#tab-settings .danger-zone')`, 'Settings from inside the project');
  results.settings_open = await cdp.eval(NAV);
  await click(cdp, '#tbtn-budget');
  await waitFor(cdp, `document.getElementById('tab-budget').classList.contains('active') &&
    !!document.getElementById('bgDailyUSD') && document.getElementById('bgDailyUSD').getClientRects().length > 0`,
  'Budget from inside the project');
  results.budget_open = await cdp.eval(NAV);

  // 5. Back to the list with the header's arrow: they go again.
  await click(cdp, '#projBackBtn');
  await waitFor(cdp, `document.getElementById('tab-projects').classList.contains('active') &&
    !document.body.classList.contains('in-project')`, 'the list after the back arrow');
  results.closed = await cdp.eval(NAV);

  // 6. A phone: the menu with the project open, and a press in it.
  const phone = CONFIG.viewports.find(v => v.mobile && v.width < 480);
  if (phone) {
    await setViewport(cdp, phone);
    await load(cdp, '/');
    await waitFor(cdp, cardsDrawn, 'the project list on the phone');
    await click(cdp, card);
    await waitFor(cdp, `(document.getElementById('breadcrumbName') || {}).textContent === ${q(open.name)}`, 'the project on the phone');
    await click(cdp, '#hamburgerBtn');
    await waitFor(cdp, `document.getElementById('mobileNavOverlay').classList.contains('open') &&
      document.getElementById('mtbtn-tasks').getClientRects().length > 0`, 'the phone menu with a project open');
    results.phone_menu_open = await cdp.eval(NAV);
    await shot(cdp, 'noproject-phone-menu-opened');
    await click(cdp, '#mtbtn-tasks');
    await waitFor(cdp, `document.getElementById('tab-tasks').classList.contains('active') &&
      !document.getElementById('mobileNavOverlay').classList.contains('open') && ${TASKS}.length > 0`, 'Tasks from the phone menu');
    results.phone_tasks = {nav: await cdp.eval(NAV), titles: await cdp.eval(TASKS)};
  }
}

// A hub with one project: its tabs are there once the page knows, and work.
async function one(cdp) {
  await setViewport(cdp, CONFIG.viewports[0]);
  results.held = await loadHeld(cdp);
  await waitFor(cdp, `document.getElementById('projectPanel').style.display !== 'none'`, 'the project\'s Overview');
  results.landing = await cdp.eval(NAV);
  await shot(cdp, 'noproject-one-landing');
  await click(cdp, '#tbtn-tasks');
  await waitFor(cdp, `${TASKS}.length > 0`, 'the project\'s tasks', `document.getElementById('taskListFull').textContent`);
  results.tasks = {nav: await cdp.eval(NAV), titles: await cdp.eval(TASKS)};
  // Its Projects tab still lists it, and going there takes nothing away.
  await click(cdp, '#tbtn-projects');
  await waitFor(cdp, `document.querySelectorAll('#projList .proj-card').length >= 1`, 'the project list');
  results.projects = await cdp.eval(NAV);
}

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  try {
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Network.enable');
    cdp.on(msg => {
      if (msg.method !== 'Network.requestWillBeSent') return;
      const u = msg.params.request.url;
      if (u.startsWith(BASE + '/api/')) requests.push((msg.params.request.method === 'GET' ? '' : msg.params.request.method + ' ') + u.slice(BASE.length));
    });
    // Boot's last step, resumeView, removes this stale marker: its absence
    // says boot is done choosing a tab.
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `try { sessionStorage.setItem('cloop_resume', '{"at":0}'); } catch (e) {}`,
    });
    if (CONFIG.mode === 'one') await one(cdp);
    else await several(cdp);
  } finally {
    killChrome(proc);
    try { fs.rmSync(dir, {recursive: true, force: true, maxRetries: 10, retryDelay: 100}); } catch (_) { /* best effort */ }
  }
}

main().then(() => {
  process.stdout.write(JSON.stringify(results));
  process.exit(0);
}, e => {
  results.error = String(e && e.stack || e);
  process.stdout.write(JSON.stringify(results));
  process.exit(0);
});
