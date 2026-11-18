// walk.js — the dashboard, walked tab by tab in headless Chrome, for the
// documentation site's demo (scripts/demo/README.md).
//
//   node walk.js record <chrome> <hub-url> <token> <projects.json> <out.json>
//   node walk.js check  <chrome> <demo-url> <projects.json> <out.json>
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

if ((MODE !== 'record' && MODE !== 'check') || !CHROME || !BASE || !OUT) {
  console.error('usage: node walk.js record <chrome> <hub-url> <token> <projects.json> <out.json>\n' +
    '       node walk.js check  <chrome> <demo-url> <projects.json> <out.json>');
  process.exit(2);
}

// The tabs, as index.html's tab strip names them: a project's, then the hub's.
const PROJECT_TABS = ['overview', 'tasks', 'requirements', 'knowledge', 'queue', 'kanban', 'timeline', 'kb',
  'deps', 'risk-matrix', 'analytics', 'chat', 'assistant', 'replay', 'provider-calls'];
const HUB_TABS = ['projects', 'budget', 'executors', 'secrets', 'audit', 'quotas', 'telemetry', 'settings'];

// What a tab shows when it has data: an expression over the page that is true
// once the tab's own list, chart or card holds something recorded. check
// reports a tab whose expression stays false as unpopulated; record waits on
// it (bounded) so that a tab's slower requests are in before it moves on.
const count = sel => `document.querySelectorAll(${JSON.stringify(sel)}).length`;
const text = sel => `(((document.querySelector(${JSON.stringify(sel)}) || {}).innerText) || '').trim()`;
const placeholder = (sel, re) => `(${text(sel)}.length > 0 && !${re}.test(${text(sel)}))`;
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

const sleep = ms => new Promise(r => setTimeout(r, ms));
const WAIT_MS = 20000;       // the longest any one condition is waited for
const QUIET_MS = 900;        // no request in flight for this long: the tab is drawn
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

// ── The network, as the page sees it ────────────────────────────────────────

function hubPath(url) {
  try {
    const u = new URL(url);
    return u.origin === new URL(BASE).origin ? u.pathname + u.search : null;
  } catch (_) { return null; }
}

function watchNetwork(cdp) {
  const inflight = new Map();   // requestId -> started at
  const reqs = new Map();       // requestId -> {method, url}
  const answers = [];           // GET answers from the hub, in order
  const sockets = new Map();    // requestId -> {url, opened, frames: [{t, data}]}
  const problems = [];          // console errors, exceptions, policy violations
  let last = Date.now();
  cdp.on(msg => {
    const p = msg.params || {};
    switch (msg.method) {
      case 'Network.requestWillBeSent':
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
        const where = hubPath(p.url.replace(/^ws/, 'http'));
        if (where) sockets.set(p.requestId, {path: where, opened: Date.now(), frames: []});
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
        problems.push({kind: 'exception', text: (p.exceptionDetails && (p.exceptionDetails.exception || {}).description) ||
          JSON.stringify(p.exceptionDetails || {}).slice(0, 400)});
        break;
      case 'Runtime.consoleAPICalled':
        if (p.type === 'error' || p.type === 'warning') {
          problems.push({kind: 'console.' + p.type,
            text: (p.args || []).map(a => a.value !== undefined ? String(a.value) : (a.description || '')).join(' ').slice(0, 400)});
        }
        break;
      case 'Log.entryAdded':
        if (p.entry && (p.entry.level === 'error' || p.entry.source === 'security')) {
          problems.push({kind: 'log.' + p.entry.source, text: String(p.entry.text || '').slice(0, 400), url: p.entry.url || ''});
        }
        break;
    }
  });
  return {
    answers, sockets, problems,
    // quiet resolves once nothing has been in flight for QUIET_MS, within WAIT_MS.
    async quiet() {
      const until = Date.now() + WAIT_MS;
      while (Date.now() < until) {
        // A request the page never finishes (a stream it opened by fetch) does
        // not keep the walk waiting past five seconds.
        for (const [id, at] of inflight) if (Date.now() - at > 5000) inflight.delete(id);
        if (inflight.size === 0 && Date.now() - last >= QUIET_MS) return true;
        await sleep(100);
      }
      return false;
    },
  };
}

// ── The walk ─────────────────────────────────────────────────────────────────

async function openTab(cdp, net, tab) {
  await cdp.eval(`(() => { const b = document.getElementById('tbtn-${tab}'); if (b) b.click(); return !!b; })()`);
  let drawn = await waitFor(cdp, `(${POPULATED[tab]})`, MODE === 'record' ? 8000 : WAIT_MS);
  if (!drawn && tab === 'tasks') {
    // A finished project hides its done tasks until asked, as a reader would.
    await cdp.eval(`(() => { const b = document.getElementById('toggleCompletedBtn');
      if (b && /Show/.test(b.textContent)) b.click(); })()`);
    drawn = await waitFor(cdp, `(${POPULATED[tab]})`, 5000);
  }
  await net.quiet();
  return drawn;
}

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  let exit = 0;
  try {
    const net = watchNetwork(cdp);
    await cdp.send('Network.enable', {maxPostDataSize: 0});
    await cdp.send('Runtime.enable');
    await cdp.send('Log.enable');
    await cdp.send('Page.enable');
    await cdp.send('Emulation.setDeviceMetricsOverride', {width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false});
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
        source: `try { sessionStorage.setItem('cloop_token', ${JSON.stringify(TOKEN)}); } catch (e) {}`});
    }
    const report = {mode: MODE, base: BASE, tabs: [], problems: net.problems};
    const shimLog = async () => MODE === 'check'
      ? cdp.eval(`(window.cloopDemo ? window.cloopDemo.requests() : [])`) : [];

    const visit = async (label, project, tab) => {
      const before = (await shimLog()).length;
      const drawn = await openTab(cdp, net, tab);
      const reqs = (await shimLog()).slice(before);
      const entry = {project, tab, drawn};
      if (MODE === 'check') {
        entry.empty = reqs.filter(r => r.answer === 'empty' || (r.method === 'WS' && r.answer === 'quiet'))
          .map(r => r.method + ' ' + r.url);
        entry.text = (await cdp.eval(`${text('#tab-' + tab)}`)).slice(0, 240);
      }
      report.tabs.push(entry);
      console.error(`walk: ${label} ${tab}: ${drawn ? 'drawn' : 'NOT DRAWN'}` +
        (entry.empty && entry.empty.length ? ` (no fixture: ${entry.empty.join(', ')})` : ''));
    };

    // The projects page first: the hub's view with no project open.
    await cdp.send('Page.navigate', {url: BASE + '/'});
    await waitFor(cdp, `document.readyState === 'complete'`);
    await waitFor(cdp, `${count('#projList > *')} > 0`);
    await net.quiet();
    await visit('hub', '', 'projects');

    for (const p of PROJECTS) {
      const url = BASE + '/?project=' + encodeURIComponent(p.path) + '&tab=overview';
      await cdp.send('Page.navigate', {url});
      await waitFor(cdp, `document.readyState === 'complete'`);
      if (!await waitFor(cdp, `${text('#goalText')}.length > 0`)) {
        console.error(`walk: ${p.name}: the project did not open`);
        exit = 1;
      }
      await net.quiet();
      for (const tab of PROJECT_TABS) await visit(p.name, p.name, tab);
      // Each task's details, the way a click on its row opens them.
      const ids = await cdp.eval(`(() => { const s = new Set(); document.querySelectorAll('[data-task-id]')
        .forEach(e => s.add(Number(e.getAttribute('data-task-id')))); return [...s].filter(n => n > 0).sort((a, b) => a - b); })()`);
      await openTab(cdp, net, 'tasks');
      for (const id of ids) {
        await cdp.eval(`window.openTaskDetails && window.openTaskDetails(${id})`);
        await net.quiet();
        await cdp.send('Input.dispatchKeyEvent', {type: 'rawKeyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27});
        await cdp.send('Input.dispatchKeyEvent', {type: 'keyUp', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27});
        await sleep(100);
      }
      for (const tab of HUB_TABS) await visit(p.name, p.name, tab);
    }

    if (MODE === 'record') {
      await sleep(500);  // the last bodies
      report.answers = net.answers;
      report.sockets = [...net.sockets.values()];
    } else {
      report.requests = await shimLog();
      // A tab is judged across the projects: todo-api is finished, so its
      // dependency graph and risk matrix are empty, as they would be.
      const shown = {};
      for (const t of report.tabs) shown[t.tab] = (shown[t.tab] || []).concat(t.drawn ? [t.project || 'hub'] : []);
      report.shown = shown;
      report.unpopulated = Object.keys(shown).filter(tab => shown[tab].length === 0);
      report.missing = [...new Set(report.tabs.flatMap(t => t.empty || []))].sort();
      if (report.unpopulated.length || net.problems.length) exit = 1;
    }
    fs.writeFileSync(OUT, JSON.stringify(report, null, 1));
  } finally {
    await closeChrome(proc, dir);
  }
  process.exit(exit);
}

main().catch(e => { console.error('walk: ' + (e && e.stack || e)); process.exit(1); });
