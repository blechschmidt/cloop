// walk.js — the dashboard, walked tab by tab in headless Chrome, for the
// documentation site's demo (scripts/demo/README.md).
//
//   node walk.js record <chrome> <hub-url> <token> <projects.json> <out.json>
//   node walk.js check  <chrome> <demo-url> <projects.json> <out.json> [<sweep.json>]
//
// record opens the real dashboard on a throwaway hub, opens every project tab
// for each project in projects.json and every hub tab, and each task's details,
// and writes every GET answer the page received from the hub and the frames
// each of its sockets received to out.json. record-fixtures.sh hands that to
// recorder.py, which turns it into fixtures.
//
// check opens the built demo (scripts/build-demo.py) the same way and writes,
// per tab, whether the tab drew content, which requests the demo's shim had no
// fixture for, and anything the page logged as an error or the policy blocked.
// It also opens the main admin dialogs (executors, secrets, a knowledge source,
// the approvals inbox, an audit row's details), presses Add task, Start run and
// Delete to see each refused with the read-only notice and nothing on the page
// changed, and lists every request that went anywhere but the demo's own
// server. tests/demo's browser sweep judges all of it (Task 20507).
//
// sweep.json (check mode, optional) turns on the layout sweep: {"viewports":
// [...], "allow": [...]}, as internal/layoutsweep defines them. Every tab, every
// task's details and every dialog is then laid out at each viewport and
// measured by internal/layoutsweep/probe.js — the probe the dashboard's own
// layout sweep uses — and the measurements are written for the Go side to
// judge. The walk itself happens at the last viewport, which should be a
// desktop. "probe" names another probe file.
//
// projects.json is a list of {"name", "path"}: in record mode the hub's paths,
// in check mode the paths the fixtures show (/home/demo/projects/<name>).
//
// WALK_DAYS_LATER=N (check mode) opens the demo with the page's clock N days
// ahead, as a reader meets it long after the recording: a read keyed by a date
// the dashboard computed from today must still find its fixture.
//
// The page's own token goes into sessionStorage before any script runs, which
// is what the dashboard's sign-in box does with it. Node 22 or later (the
// global WebSocket); no packages.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const MODE = process.argv[2];
const CHROME = process.argv[3];
const BASE = (process.argv[4] || '').replace(/\/+$/, '');
const TOKEN = MODE === 'record' ? process.argv[5] : '';
const PROJECTS = JSON.parse(fs.readFileSync(process.argv[MODE === 'record' ? 6 : 5], 'utf8'));
const OUT = process.argv[MODE === 'record' ? 7 : 6];
const SWEEP = MODE === 'check' && process.argv[7] ? JSON.parse(fs.readFileSync(process.argv[7], 'utf8')) : null;

if ((MODE !== 'record' && MODE !== 'check') || !CHROME || !BASE || !OUT) {
  console.error('usage: node walk.js record <chrome> <hub-url> <token> <projects.json> <out.json>\n' +
    '       node walk.js check  <chrome> <demo-url> <projects.json> <out.json> [<sweep.json>]');
  process.exit(2);
}
if (SWEEP && !(Array.isArray(SWEEP.viewports) && SWEEP.viewports.length)) {
  console.error('walk: sweep.json names no viewports');
  process.exit(2);
}

// The probe the dashboard's layout sweep measures with (Task 20407), shared
// through internal/layoutsweep so that the demo is held to the same
// definition of overflow.
const PROBE = SWEEP
  ? fs.readFileSync(SWEEP.probe || path.join(__dirname, '..', '..', 'internal', 'layoutsweep', 'probe.js'), 'utf8')
  : '';

// The tabs, as index.html's tab strip names them: a project's, then the hub's.
const PROJECT_TABS = ['overview', 'tasks', 'requirements', 'knowledge', 'queue', 'kanban', 'timeline', 'kb',
  'deps', 'risk-matrix', 'analytics', 'chat', 'assistant', 'replay', 'provider-calls'];
const HUB_TABS = ['projects', 'budget', 'executors', 'secrets', 'audit', 'quotas', 'telemetry', 'settings'];

// What a tab shows when it has data: an expression over the page that is true
// once the tab's own list, chart or card holds something recorded. check
// reports a tab whose expression stays false as unpopulated; record waits on
// it (bounded) so that a tab's slower requests are in before it moves on.
const q = s => JSON.stringify(s);
const count = sel => `document.querySelectorAll(${q(sel)}).length`;
const text = sel => `(((document.querySelector(${q(sel)}) || {}).innerText) || '').trim()`;
const placeholder = (sel, re) => `(${text(sel)}.length > 0 && !${re}.test(${text(sel)}))`;
const visible = sel => `(() => { const e = document.querySelector(${q(sel)});
  return !!e && e.checkVisibility({checkVisibilityCSS: true}); })()`;
const POPULATED = {
  'overview': `${text('#goalText')}.length > 0 && ${text('#statProvider')}.length > 0`,
  'tasks': `${count('#taskListFull .task-item')} > 0`,
  'requirements': `${count('#reqList [data-act="details"]')} > 0`,
  'knowledge': `${count('#knBound .kn-card')} > 0`,
  'queue': `${count('#queueTable tr, #queueTable .queue-row')} > 1`,
  'kanban': `${count('#kanbanBoard .kanban-card, #kanbanBoard [data-task-id]')} > 0`,
  'timeline': `${text('#timelineChart')}.length > 20`,
  'kb': placeholder('#tab-kb', '/No entries yet/'),
  'deps': `${count('#depsSvg .deps-node')} > 0`,
  'risk-matrix': `${count('#rmTable tr')} > 1`,
  'analytics': `!!window.Chart && (document.getElementById('analyticsCharts') || {style: {}}).style.display !== 'none'`,
  'chat': placeholder('#chatMessages', '/Type a natural language command/'),
  // The plan assistant keeps its conversation in the page: a recording has
  // none to show, and the demo opens on its suggestions.
  'assistant': `/Try asking/.test(${text('#tab-assistant')})`,
  'replay': placeholder('#replayRuns', '/No replay|Loading/i'),
  'provider-calls': `${count('#pcTbody tr')} > 0`,
  'projects': `${count('#projList .project-card, #projList [data-idx], #projList > *')} > 0`,
  'budget': `${text('#tab-budget')}.length > 200`,
  'executors': `${count('#execList > *')} > 1`,
  'secrets': `${count('#secSecretsBody tr')} > 0`,
  'audit': `${count('#auditBody .audit-row')} > 0`,
  'quotas': `${count('#quotaBody tr')} > 0`,
  // The demo's page itself never collects, so the tab's status line always
  // says collection is off; the recorded trail is in its rows.
  'telemetry': `${count('#telemetryBody tr')} > 0`,
  'settings': `${text('#tab-settings')}.length > 400 && !/Loading…/.test(${text('#buildInfoBody')})`,
};

// ── Check mode: the admin dialogs ───────────────────────────────────────────
//
// Each is reached the way a person reaches it — the tab, then the button — and
// is ready once it shows what the recording put in it. tab is the tab to open
// first, press the control to click, and the dialog's root is #<id>.
const DIALOGS = [
  // Executors: the enrolled edge device's details and firewall, and the form
  // that enrolls the next machine.
  {id: 'executor-detail-overlay', tab: 'executors', press: '#execList button[data-act="detail"]',
    ready: `!!document.querySelector('#execDetailBody .exec-detail-verdict')`},
  {id: 'executor-firewall-overlay', tab: 'executors', press: '#execList button[data-act="firewall"]',
    ready: visible('#efwAllow')},
  {id: 'enroll-overlay', tab: 'executors', press: '#tab-executors button[data-action="openEnrollModal"]',
    ready: visible('#enrollName')},
  // Secrets: a new secret, and a grant of one to a project.
  {id: 'secret-overlay', tab: 'secrets', press: '#tab-secrets [data-act="openSecretModal"]',
    ready: visible('#secretName')},
  {id: 'grant-overlay', tab: 'secrets', press: '#tab-secrets [data-act="openGrantModal"]',
    ready: visible('#grantSubject')},
  // Knowledge: a connected Confluence or Jira source, from Settings.
  {id: 'ks-overlay', tab: 'settings', press: '#ksList [data-ks="edit"]',
    ready: `((document.getElementById('ksName') || {}).value || '').length > 0`},
  // Approvals: the inbox the header's badge opens, with the waiting request.
  {id: 'approvals-overlay', press: '#approvalsBadge', ready: `!!document.querySelector('#approvalsList li')`},
];

// ── Check mode: writes ──────────────────────────────────────────────────────
//
// Each is a button that changes the hub, pressed on the Tasks tab of the last
// project in projects.json. The demo must refuse it in the page (the shim
// answers 405 and never sends it), say so in the dashboard's toast, and leave
// what the page shows as it was.
const WRITES = [
  {name: 'add task', act: async (cdp) => {
    await typeInto(cdp, '#newTaskTitle', 'Write the release notes');
    await press(cdp, '#tab-tasks [data-action="submitAddTask"]');
  }},
  {name: 'start run', act: async (cdp) => { await press(cdp, '#tasksCtrlRun'); }},
  {name: 'delete', act: async (cdp) => {
    await press(cdp, '#taskListFull .task-item[data-task-id] button[data-action="removeTask"]');
    if (!await waitFor(cdp, `window.isOverlayOpen('delete-modal-overlay')`, 5000)) {
      throw new Error('the delete confirmation never opened');
    }
    await press(cdp, '#delete-modal-overlay [data-action="executeDeleteTask"]');
  }},
];

// What the Tasks tab shows of the project: each task row (id, status class,
// title) and the run bar's state. Counters are blanked, so a "resumes in 2h"
// that ticks over between two reads is not a change.
const SNAPSHOT = `JSON.stringify({
  tasks: [...document.querySelectorAll('#taskListFull .task-item[data-task-id]')].map(e =>
    e.getAttribute('data-task-id') + ' ' + e.className + ' ' + ((e.querySelector('.task-title') || {}).textContent || '')),
  count: ((document.getElementById('taskCountBadge') || {}).textContent || '').replace(/\\d+/g, '#'),
  status: ((document.getElementById('tasksRunStatus') || {}).textContent || '').replace(/\\d+/g, '#'),
  start: (document.getElementById('tasksCtrlRun') || {style: {}}).style.display,
  stop: (document.getElementById('tasksCtrlStop') || {style: {}}).style.display,
})`;

const sleep = ms => new Promise(r => setTimeout(r, ms));
const WAIT_MS = 20000;       // the longest any one condition is waited for
const QUIET_MS = 900;        // record: no request in flight for this long, the tab is drawn
const SETTLE_MS = 300;       // check: no request, real or answered by the shim, for this long
const EMPTY_MS = 2000;       // check: settled this long without content, the tab has none
const CHROME_START_POLLS = 1800;

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
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
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
    if (r.exceptionDetails) {
      throw new Error('eval failed: ' + JSON.stringify(r.exceptionDetails.exception || r.exceptionDetails));
    }
    return r.result.value;
  }
}

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-demo-walk-'));
  const proc = spawn(CHROME, ['--headless=new', '--remote-debugging-port=0', '--user-data-dir=' + dir,
    '--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--window-size=1440,1000', 'about:blank'],
  {stdio: ['ignore', 'ignore', 'pipe'], detached: true});
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
    if (!port) throw new Error('chrome never reported a debugging port: ' + stderr);
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
    return {cdp: new CDP(ws), proc, dir};
  } catch (e) {
    try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) { /* already gone */ }
    throw e;
  }
}

// Chrome runs in its own process group, so one signal takes its helpers with
// it; then the profile can go.
async function closeChrome(proc, dir) {
  try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) { /* already gone */ }
  for (let i = 0; i < 100 && proc.exitCode === null && proc.signalCode === null; i++) await sleep(20);
  try { fs.rmSync(dir, {recursive: true, force: true, maxRetries: 5, retryDelay: 100}); } catch (_) { /* best effort */ }
}

async function waitFor(cdp, expr, ms) {
  const until = Date.now() + (ms || WAIT_MS);
  for (;;) {
    let ok = false;
    try { ok = !!(await cdp.eval(expr)); } catch (_) { ok = false; }
    if (ok) return true;
    if (Date.now() > until) return false;
    await sleep(150);
  }
}

// press clicks the first element sel matches, as the page's own handlers see a
// click; typeInto fills a field the way typing does.
async function press(cdp, sel) {
  const r = await cdp.eval(`(() => { const e = document.querySelector(${q(sel)});
    if (!e) return 'nothing matches ' + ${q(sel)};
    if (!e.checkVisibility({checkVisibilityCSS: true})) return ${q(sel)} + ' is not visible';
    e.click(); return 'ok'; })()`);
  if (r !== 'ok') throw new Error(r);
}

async function typeInto(cdp, sel, value) {
  const r = await cdp.eval(`(() => { const e = document.querySelector(${q(sel)});
    if (!e) return 'nothing matches ' + ${q(sel)};
    e.focus(); e.value = ${q(value)};
    e.dispatchEvent(new Event('input', {bubbles: true}));
    e.dispatchEvent(new Event('change', {bubbles: true}));
    return 'ok'; })()`);
  if (r !== 'ok') throw new Error(r);
}

// ── The network, as the page sees it ────────────────────────────────────────

function hubPath(url) {
  try {
    const u = new URL(url);
    return u.origin === new URL(BASE).origin ? u.pathname + u.search : null;
  } catch (_) { return null; }
}

// offSite is whether a request the browser made left the demo's own server:
// another origin. data:, blob: and about: never touch the network.
function offSite(url) {
  let u;
  try { u = new URL(url); } catch (_) { return true; }
  if (u.protocol === 'data:' || u.protocol === 'blob:' || u.protocol === 'about:') return false;
  const origin = u.protocol === 'ws:' ? 'http:' : u.protocol === 'wss:' ? 'https:' : u.protocol;
  return origin + '//' + u.host !== new URL(BASE).origin;
}

function watchNetwork(cdp, scenarioOf) {
  const inflight = new Map();   // requestId -> started at
  const reqs = new Map();       // requestId -> {method, url}
  const answers = [];           // GET answers from the hub, in order
  const sockets = new Map();    // requestId -> {url, opened, frames: [{t, data}]}
  const problems = [];          // console errors, exceptions, policy violations
  const foreign = [];           // check: requests the browser sent to another origin
  const realSockets = [];       // check: WebSockets the browser opened itself
  let seen = 0;                 // every request the browser made, to show this listened
  let last = Date.now();
  cdp.on(msg => {
    const p = msg.params || {};
    switch (msg.method) {
      case 'Network.requestWillBeSent':
        seen++;
        if (MODE === 'check' && offSite(p.request.url)) {
          foreign.push({scenario: scenarioOf(), url: p.request.url, type: p.type || ''});
        }
        if (p.type === 'WebSocket' || p.type === 'EventSource') break;
        reqs.set(p.requestId, {method: p.request.method, url: p.request.url, type: p.type});
        inflight.set(p.requestId, Date.now());
        last = Date.now();
        break;
      case 'Network.responseReceived': {
        const r = reqs.get(p.requestId);
        if (r) { r.status = p.response.status; r.mime = p.response.mimeType; }
        break;
      }
      case 'Network.loadingFinished':
      case 'Network.loadingFailed': {
        inflight.delete(p.requestId);
        last = Date.now();
        const r = reqs.get(p.requestId);
        if (!r || msg.method === 'Network.loadingFailed' || r.method !== 'GET') break;
        const where = hubPath(r.url);
        if (!where || !/^\/(api|auth)\//.test(where) || MODE !== 'record') break;
        const entry = {path: where, status: r.status, mime: r.mime || '', type: r.type};
        answers.push(entry);
        cdp.send('Network.getResponseBody', {requestId: p.requestId}).then(b => {
          entry.body = b.base64Encoded ? null : b.body;
          entry.base64 = !!b.base64Encoded;
        }, e => { entry.error = String(e.message || e); });
        break;
      }
      case 'Network.webSocketCreated': {
        // The demo's shim stands in for WebSocket, so in check mode the
        // browser opens none at all: one here went around the shim.
        if (MODE === 'check') realSockets.push({scenario: scenarioOf(), url: p.url});
        const at = hubPath(p.url.replace(/^ws/, 'http'));
        if (at) sockets.set(p.requestId, {path: at, opened: Date.now(), frames: []});
        break;
      }
      case 'Network.webSocketFrameReceived': {
        const s = sockets.get(p.requestId);
        if (s && p.response && p.response.opcode === 1) {
          s.frames.push({t: Date.now() - s.opened, data: p.response.payloadData});
        }
        break;
      }
      case 'Runtime.exceptionThrown':
        problems.push({scenario: scenarioOf(), kind: 'exception',
          text: (p.exceptionDetails && (p.exceptionDetails.exception || {}).description) ||
          JSON.stringify(p.exceptionDetails || {}).slice(0, 400)});
        break;
      case 'Runtime.consoleAPICalled':
        if (p.type === 'error' || p.type === 'warning') {
          problems.push({scenario: scenarioOf(), kind: 'console.' + p.type,
            text: (p.args || []).map(a => a.value !== undefined ? String(a.value) : (a.description || '')).join(' ').slice(0, 400)});
        }
        break;
      case 'Log.entryAdded':
        if (p.entry && (p.entry.level === 'error' || p.entry.source === 'security')) {
          problems.push({scenario: scenarioOf(), kind: 'log.' + p.entry.source, text: String(p.entry.text || '').slice(0, 400),
            url: p.entry.url || ''});
        }
        break;
      case 'Page.javascriptDialogOpening':
        // An alert or confirm blocks the page; the dashboard has its own dialogs.
        problems.push({scenario: scenarioOf(), kind: 'dialog.' + p.type, text: String(p.message || '').slice(0, 400)});
        cdp.send('Page.handleJavaScriptDialog', {accept: false}).catch(() => {});
        break;
    }
  });
  // busy counts the requests still in flight. One the page never finishes (a
  // stream it opened by fetch) stops counting after five seconds.
  const busy = () => {
    for (const [id, at] of inflight) if (Date.now() - at > 5000) inflight.delete(id);
    return inflight.size;
  };
  return {
    answers, sockets, problems, foreign, realSockets, busy, seen: () => seen,
    // quiet resolves once nothing has been in flight for QUIET_MS, within WAIT_MS.
    async quiet() {
      const until = Date.now() + WAIT_MS;
      while (Date.now() < until) {
        if (busy() === 0 && Date.now() - last >= QUIET_MS) return true;
        await sleep(100);
      }
      return false;
    },
  };
}

// ── Check mode: settling and measuring ──────────────────────────────────────
//
// The demo's reads never reach the network: the shim answers them in the page,
// so the browser's own view of the network sees only the demo's files. A page
// is settled once neither has moved for SETTLE_MS — the shim's request log and
// the browser's requests in flight — and two frames have been drawn.

const frames = cdp => cdp.eval('new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))');
const SHIM_KEY = `(() => { const r = window.cloopDemo ? window.cloopDemo.requests() : [];
  return r.length + ':' + (r.length ? r[r.length - 1].at : 0); })()`;

async function settle(cdp, net, quietMs) {
  const until = Date.now() + WAIT_MS;
  let key = null, since = Date.now();
  while (Date.now() < until) {
    let k = '';
    try { k = await cdp.eval(SHIM_KEY); } catch (_) { k = 'navigating'; }
    if (k !== key) { key = k; since = Date.now(); }
    if (net.busy() === 0 && Date.now() - since >= (quietMs === undefined ? SETTLE_MS : quietMs)) break;
    await sleep(50);
  }
  try { await frames(cdp); } catch (_) { /* navigating */ }
}

// drawn waits until expr holds, or the page has settled for EMPTY_MS without
// it: a tab with nothing recorded to show (todo-api is finished, so it has no
// dependency graph) draws its empty state and asks for nothing more.
async function drawn(cdp, net, expr) {
  const until = Date.now() + WAIT_MS;
  let key = null, since = Date.now();
  for (;;) {
    let ok = false;
    try { ok = !!(await cdp.eval(expr)); } catch (_) { ok = false; }
    if (ok) return true;
    let k = '';
    try { k = await cdp.eval(SHIM_KEY); } catch (_) { k = 'navigating'; }
    if (k !== key || net.busy() > 0) { key = k; since = Date.now(); }
    if (Date.now() - since >= EMPTY_MS || Date.now() > until) return false;
    await sleep(100);
  }
}

// The viewport the walk itself happens at: the sweep's last, which is a
// desktop, or the window the walk has always used.
const HOME_VIEW = SWEEP ? SWEEP.viewports[SWEEP.viewports.length - 1]
  : {name: 'desktop-1440', width: 1440, height: 1000, scale: 1, mobile: false};

async function setViewport(cdp, v) {
  await cdp.send('Emulation.setDeviceMetricsOverride', {width: v.width, height: v.height,
    deviceScaleFactor: v.scale, mobile: v.mobile});
  // A page that overflowed at the last width was zoomed out to fit; that scale
  // must not be carried into a measurement at this one.
  await cdp.send('Emulation.resetPageScaleFactor');
  try { await cdp.eval('window.scrollTo(0, 0)'); } catch (_) { /* navigating */ }
}

// measure lays the page out at every viewport of the sweep and measures scope
// there, then puts the walk's own viewport back. Without a sweep it does
// nothing.
async function measure(cdp, net, report, name, scope) {
  if (!SWEEP) return;
  const rec = {name, measurements: []};
  report.scenarios.push(rec);
  try {
    for (const v of SWEEP.viewports) {
      await setViewport(cdp, v);
      await frames(cdp);
      // A resize can set off a redraw that fetches (a chart, the timeline).
      if (net.busy() > 0) await settle(cdp, net);
      const m = await cdp.eval(`window.__sweep.measure(${q({w: v.width, h: v.height, scope, allow: SWEEP.allow || []})})`);
      m.viewport = v.name;
      m.theme = 'light';
      rec.measurements.push(m);
    }
  } catch (e) {
    rec.error = String(e && e.message || e);
  }
  await setViewport(cdp, HOME_VIEW);
  await frames(cdp);
}

// closeAll dismisses every open dialog through its own close path, frontmost
// first, and says which would not go.
async function closeAll(cdp) {
  for (let i = 0; i < 6; i++) {
    const top = await cdp.eval(`(() => { const t = window.topOverlay && window.topOverlay(); return t ? t.el.id || '?' : ''; })()`);
    if (!top) return '';
    await cdp.eval(`window.dismissTopOverlay()`);
    await frames(cdp);
  }
  return cdp.eval(`(() => { const t = window.topOverlay && window.topOverlay(); return t ? t.el.id || '?' : ''; })()`);
}

// ── The walk ─────────────────────────────────────────────────────────────────

async function openTab(cdp, net, tab) {
  await cdp.eval(`(() => { const b = document.getElementById('tbtn-${tab}'); if (b) b.click(); return !!b; })()`);
  if (MODE === 'record') {
    let shown = await waitFor(cdp, `(${POPULATED[tab]})`, 8000);
    if (!shown && tab === 'tasks') {
      // A finished project hides its done tasks until asked, as a reader would.
      await cdp.eval(`(() => { const b = document.getElementById('toggleCompletedBtn');
        if (b && /Show/.test(b.textContent)) b.click(); })()`);
      shown = await waitFor(cdp, `(${POPULATED[tab]})`, 5000);
    }
    await net.quiet();
    return shown;
  }
  let shown = await drawn(cdp, net, `(${POPULATED[tab]})`);
  if (!shown && tab === 'tasks') {
    await cdp.eval(`(() => { const b = document.getElementById('toggleCompletedBtn');
      if (b && /Show/.test(b.textContent)) b.click(); })()`);
    shown = await drawn(cdp, net, `(${POPULATED[tab]})`);
  }
  await settle(cdp, net);
  return shown;
}

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  let exit = 0;
  let current = 'boot';   // the scenario running, to attribute what the page does
  const report = {mode: MODE, base: BASE, tabs: [], scenarios: [], dialogs: [], writes: [], requests: []};
  try {
    const net = watchNetwork(cdp, () => current);
    report.problems = net.problems;
    await cdp.send('Network.enable', {maxPostDataSize: 0});
    await cdp.send('Runtime.enable');
    await cdp.send('Log.enable');
    await cdp.send('Page.enable');
    await setViewport(cdp, HOME_VIEW);
    // The hub records the browser a session and its telemetry came from; the
    // demo shows a desktop Chrome rather than the headless one it was.
    await cdp.send('Network.setUserAgentOverride', {userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ' +
      '(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36', platform: 'Linux x86_64'});
    const later = Number(process.env.WALK_DAYS_LATER || 0);
    if (MODE === 'check' && later) {
      await cdp.send('Page.addScriptToEvaluateOnNewDocument', {source: `(() => {
        const shift = ${later} * 86400000, RealDate = Date;
        class ShiftedDate extends RealDate {
          constructor(...a) { if (a.length) super(...a); else super(RealDate.now() + shift); }
          static now() { return RealDate.now() + shift; }
        }
        window.Date = ShiftedDate;
      })()`});
    }
    if (TOKEN) {
      await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
        source: `try { sessionStorage.setItem('cloop_token', ${q(TOKEN)}); } catch (e) {}`});
    }
    if (PROBE) await cdp.send('Page.addScriptToEvaluateOnNewDocument', {source: PROBE});

    const t0 = Date.now();
    const shimLog = async () => MODE === 'check'
      ? cdp.eval(`(window.cloopDemo ? window.cloopDemo.requests() : [])`) : [];
    // Each page keeps its own log of what the shim answered; harvest collects
    // it before the walk leaves the page.
    const harvest = async () => {
      if (MODE !== 'check') return;
      try { report.requests.push(...(await shimLog())); } catch (_) { /* no page */ }
    };
    const navigate = async url => {
      await harvest();
      current = 'navigate ' + url.slice(BASE.length);
      await cdp.send('Page.navigate', {url});
      await waitFor(cdp, `document.readyState === 'complete'`);
    };

    const visit = async (label, project, tab) => {
      current = 'tab:' + tab + (project ? '@' + project : '');
      const before = (await shimLog()).length;
      const shown = await openTab(cdp, net, tab);
      const reqs = (await shimLog()).slice(before);
      const entry = {project, tab, drawn: shown};
      if (MODE === 'check') {
        entry.empty = reqs.filter(r => r.answer === 'empty' || (r.method === 'WS' && r.answer === 'quiet'))
          .map(r => r.method + ' ' + r.url);
        entry.text = (await cdp.eval(`${text('#tab-' + tab)}`)).slice(0, 240);
        await measure(cdp, net, report, current, ['body']);
      }
      report.tabs.push(entry);
      console.error(`walk: ${label} ${tab}: ${shown ? 'drawn' : 'NOT DRAWN'}` +
        (entry.empty && entry.empty.length ? ` (no fixture: ${entry.empty.join(', ')})` : ''));
    };

    // The projects page first: the hub's view with no project open.
    await navigate(BASE + '/');
    await waitFor(cdp, `${count('#projList > *')} > 0`);
    if (MODE === 'record') await net.quiet(); else await settle(cdp, net);
    await visit('hub', '', 'projects');

    for (const p of PROJECTS) {
      await navigate(BASE + '/?project=' + encodeURIComponent(p.path) + '&tab=overview');
      if (!await waitFor(cdp, `${text('#goalText')}.length > 0`)) {
        console.error(`walk: ${p.name}: the project did not open`);
        report.unopened = (report.unopened || []).concat(p.name);
        exit = 1;
      }
      if (MODE === 'record') await net.quiet(); else await settle(cdp, net);
      for (const tab of PROJECT_TABS) await visit(p.name, p.name, tab);
      // Each task's details, the way a click on its row opens them.
      const ids = await cdp.eval(`(() => { const s = new Set(); document.querySelectorAll('[data-task-id]')
        .forEach(e => s.add(Number(e.getAttribute('data-task-id')))); return [...s].filter(n => n > 0).sort((a, b) => a - b); })()`);
      await openTab(cdp, net, 'tasks');
      for (const id of ids) {
        current = 'task:' + p.name + '#' + id;
        await cdp.eval(`window.openTaskDetails && window.openTaskDetails(${id})`);
        if (MODE === 'record') {
          await net.quiet();
        } else {
          const ready = await waitFor(cdp, `(() => { const b = document.getElementById('td-body');
            return window.isOverlayOpen('td-overlay') && !!b && !/Loading…/.test(b.innerText) && b.innerText.trim().length > 40; })()`);
          await settle(cdp, net);
          report.details = (report.details || []).concat({project: p.name, id, shown: ready});
          await measure(cdp, net, report, current, ['#td-overlay']);
        }
        await cdp.send('Input.dispatchKeyEvent', {type: 'rawKeyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27});
        await cdp.send('Input.dispatchKeyEvent', {type: 'keyUp', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27});
        await sleep(100);
      }
      for (const tab of HUB_TABS) await visit(p.name, p.name, tab);
    }

    if (MODE === 'check') {
      // The admin dialogs, opened as a person opens them.
      for (const d of DIALOGS) {
        current = 'dialog:' + d.id;
        const rec = {id: d.id, opened: false};
        report.dialogs.push(rec);
        try {
          const left = await closeAll(cdp);
          if (left) throw new Error('could not close the dialog ' + left);
          if (d.tab) await openTab(cdp, net, d.tab);
          if (!await waitFor(cdp, visible(d.press))) throw new Error(d.press + ' never showed');
          await press(cdp, d.press);
          if (!await waitFor(cdp, `window.isOverlayOpen(${q(d.id)})`)) throw new Error('the dialog never opened');
          if (!await waitFor(cdp, d.ready)) throw new Error('the dialog never showed its content');
          await settle(cdp, net);
          rec.opened = true;
          await measure(cdp, net, report, current, ['#' + d.id]);
        } catch (e) {
          rec.error = String(e && e.message || e);
        }
        console.error(`walk: dialog ${d.id}: ${rec.opened ? 'opened' : 'FAILED: ' + rec.error}`);
      }
      {
        // An audit row's details: its hashes and payload, under the row.
        current = 'view:audit-row';
        const rec = {id: 'audit row details', opened: false};
        report.dialogs.push(rec);
        try {
          await closeAll(cdp);
          await openTab(cdp, net, 'audit');
          await press(cdp, '#auditBody tr.audit-row');
          if (!await waitFor(cdp, visible('#auditBody tr.audit-detail .audit-detail-inner'))) {
            throw new Error('the row never opened');
          }
          await settle(cdp, net);
          rec.opened = true;
          await measure(cdp, net, report, current, ['body']);
        } catch (e) {
          rec.error = String(e && e.message || e);
        }
        console.error(`walk: audit row details: ${rec.opened ? 'opened' : 'FAILED: ' + rec.error}`);
      }

      // The writes, on the Tasks tab of the last project.
      await closeAll(cdp);
      await openTab(cdp, net, 'tasks');
      const message = await cdp.eval(`window.cloopDemo ? window.cloopDemo.message : ''`);
      report.message = message;
      for (const w of WRITES) {
        current = 'write:' + w.name;
        const rec = {name: w.name};
        report.writes.push(rec);
        try {
          await closeAll(cdp);
          await settle(cdp, net);
          rec.before = await cdp.eval(SNAPSHOT);
          const from = (await shimLog()).length;
          await cdp.eval(`(() => { const t = document.getElementById('toast');
            if (t) { t.className = ''; t.textContent = ''; } })()`);
          await w.act(cdp);
          rec.toast = await waitFor(cdp, `(() => { const t = document.getElementById('toast');
            return !!t && /\\bshow\\b/.test(t.className) && t.textContent === ${q(message)}; })()`, 5000);
          // What the dashboard does with the refusal comes after it: give it
          // the time a reader would, then look again.
          await settle(cdp, net, 600);
          rec.toast_text = await cdp.eval(`((document.getElementById('toast') || {}).textContent || '')`);
          rec.after = await cdp.eval(SNAPSHOT);
          rec.requests = (await shimLog()).slice(from).filter(r => r.method !== 'GET' && r.method !== 'WS')
            .map(r => ({method: r.method, url: r.url, answer: r.answer}));
        } catch (e) {
          rec.error = String(e && e.message || e);
        }
        console.error(`walk: write ${w.name}: ` + (rec.error ? 'FAILED: ' + rec.error
          : (rec.toast ? 'refused with the notice' : 'NO NOTICE') + (rec.before === rec.after ? '' : ', THE PAGE CHANGED')));
      }
      await closeAll(cdp);

      // The control: an error thrown in the page has to reach the listener
      // the check for uncaught errors reads, or that check proves nothing.
      current = 'control';
      const CONTROL = 'walk.js control: an uncaught error';
      await cdp.eval(`(setTimeout(() => { throw new Error(${q(CONTROL)}); }, 0), true)`);
      const caught = () => net.problems.findIndex(x => x.kind === 'exception' && x.text.includes(CONTROL));
      for (let i = 0; i < 100 && caught() < 0; i++) await sleep(50);
      report.control = caught() >= 0;
      for (let i = caught(); i >= 0; i = caught()) net.problems.splice(i, 1);
    }

    if (MODE === 'record') {
      await sleep(500);  // the last bodies
      report.answers = net.answers;
      report.sockets = [...net.sockets.values()];
      for (const k of ['scenarios', 'dialogs', 'writes', 'requests']) delete report[k];
    } else {
      await harvest();
      // A tab is judged across the projects: todo-api is finished, so its
      // dependency graph and risk matrix are empty, as they would be.
      const shown = {};
      for (const t of report.tabs) shown[t.tab] = (shown[t.tab] || []).concat(t.drawn ? [t.project || 'hub'] : []);
      report.shown = shown;
      report.unpopulated = Object.keys(shown).filter(tab => shown[tab].length === 0);
      report.missing = [...new Set(report.tabs.flatMap(t => t.empty || []))].sort();
      report.requests_seen = net.seen();
      report.foreign = net.foreign;
      report.real_sockets = net.realSockets;
      report.away = report.requests.filter(r => r.to === 'away');
      const failedWrites = report.writes.filter(w => w.error || !w.toast || w.before !== w.after);
      if (report.unpopulated.length || net.problems.length || net.foreign.length || net.realSockets.length ||
          report.away.length || report.dialogs.some(d => !d.opened) || failedWrites.length || !report.control) exit = 1;
    }
    report.elapsed_ms = Date.now() - t0;
    fs.writeFileSync(OUT, JSON.stringify(report, null, 1));
  } finally {
    await closeChrome(proc, dir);
  }
  process.exit(exit);
}

main().catch(e => { console.error('walk: ' + (e && e.stack || e)); process.exit(1); });
