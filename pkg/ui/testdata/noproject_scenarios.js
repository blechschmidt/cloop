// noproject_scenarios.js — a hub that lists several projects, with none of
// them opened, driven through the real dashboard bundle (Task 20508).
//
//   "it is unintuitive that tasks are empty if no project has been selected
//    yet. As long as no project has been selected yet, menu items whose view
//    only makes sense if a project has been selected, such as "Tasks" and
//    others, should be hidden"
//
// What was behind the empty Tasks tab: a request without ?project_idx is
// answered for the hub's own project (resolveWorkDir), so every per-project
// tab opened with nothing selected read — and wrote — a project nobody had
// picked. The scenarios here walk every way into such a tab (the tab bar, a
// link, a resumed view, a key, the command palette), every way the page comes
// to believe a project is in view (a project list that is late, unreadable, an
// error, or changes under the page), and what the page asks the hub for
// meanwhile. The markup half — the buttons really being off screen — needs a
// browser and is testdata/noproject_browser.js.
//
// Run by TestDashboard_NoProjectOpen*. Each scenario returns a plain object;
// the Go side asserts on it. Printed as one JSON document on stdout.
//
// Usage: node noproject_scenarios.js <domshim.js> <bundle.js> <config.json>
// config: {project_tabs: [...], global_tabs: [...]} as index.html draws them.

'use strict';

const fs = require('fs');

const shimPath = process.argv[2];
const bundlePath = process.argv[3];
const CONFIG = JSON.parse(fs.readFileSync(process.argv[4], 'utf8'));

// Three projects whose task IDs do not overlap. alpha is the hub's own: what
// a request without an index is answered for.
function state(name, base) {
  return {
    goal: name + ' goal', status: 'idle', workdir: '/srv/' + name,
    plan: {goal: name + ' goal', tasks: [
      {id: base + 1, title: name + ' one', status: 'pending', priority: 1},
      {id: base + 2, title: name + ' two', status: 'pending', priority: 2},
    ]},
  };
}
const STATES = {0: state('alpha', 100), 1: state('beta', 200), 2: state('gamma', 300)};

// A project list as the hub sends it, GET or push. several: the hub's
// multi_project flag, by default what the count says.
function roster(names, several) {
  return {
    multi_project: several === undefined ? names.length > 1 : several,
    stats: {total_projects: names.length},
    projects: names.map(n => ({name: n, path: '/srv/' + n, goal: n + ' goal', total_tasks: 2, done_tasks: 0, health: 'idle'})),
  };
}

function clone(o) { return JSON.parse(JSON.stringify(o)); }

// The tabs the dashboard switched to, in order: switchTab names each one to
// the telemetry reporter the moment it accepts it, and names nothing for a
// switch it refuses. (The shim has no selectors, so the panels' own "active"
// classes cannot say which tab is on screen.)
let views;
// Every address history.replaceState was given.
let replaced;
// Set by boot when opts.hold: lets the held project list through.
let release;

// boot loads a fresh shim and bundle. opts.names: the hub's projects (three
// by default); opts.roster: the whole list instead; opts.search: the page's
// query string; opts.resume: a view saved by a sign-in round trip;
// opts.before(h): last changes before the bundle runs; opts.hold: the first
// answer to GET /api/projects is held until release() is called, and boot
// returns with the page still waiting for it.
async function boot(opts) {
  opts = opts || {};
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.projects = opts.roster || roster(opts.names || ['alpha', 'beta', 'gamma']);
  h.states = clone(STATES);
  views = [];
  replaced = [];
  release = null;
  globalThis.cloopTelemetry = {setView: v => views.push(v), setRelease() {}};
  // As a browser does it: the address loses its query.
  globalThis.history = {replaceState: (s, t, url) => { replaced.push(url); location.search = ''; }};
  location.search = opts.search || '';
  if (opts.resume) sessionStorage.setItem('cloop_resume', JSON.stringify(Object.assign({at: Date.now()}, opts.resume)));
  if (opts.hold) {
    const real = globalThis.fetch;
    let held = false;
    globalThis.fetch = function(url, o) {
      if (!held && String(url).startsWith('/api/projects')) {
        held = true;
        return new Promise(resolve => { release = () => resolve(real(url, o)); });
      }
      return real(url, o);
    };
  }
  if (opts.before) opts.before(h);
  require(bundlePath);
  // The document is parsed by the time its last script has run: what the
  // bundle left for then — who is signed in, whether the hub can transcribe —
  // is part of first paint.
  document.dispatchEvent({type: 'DOMContentLoaded', target: document});
  await globalThis.__settle(8);
  const ws = h.sockets[h.sockets.length - 1];
  if (ws) ws.open();
  await globalThis.__settle(3);
  return h;
}

const tab = () => (views.length ? views[views.length - 1] : 'overview');
const inProject = () => document.body.classList.contains('in-project');
const urls = (h, from) => h.requests.slice(from || 0).map(r => (r.method === 'GET' ? '' : r.method + ' ') + r.url);
const socketURL = h => (h.sockets.length ? h.sockets[h.sockets.length - 1].url : '');
const toastText = () => String(document.getElementById('toast').textContent || '');
// How many project cards the Projects grid holds.
const cards = () => (String(document.getElementById('projList').innerHTML || '').match(/class="proj-card/g) || []).length;
// The scripts of deferred tabs the page fetched: each is a <script> the bundle
// appended to the document head.
const scripts = () => document.head.children.map(c => String(c.src || '')).filter(Boolean);
const where = h => ({tab: tab(), in_project: inProject(), socket: socketURL(h)});
// A wait in real time, for what the page does on a timer.
const pause = ms => new Promise(r => setTimeout(r, ms));

// open selects a project the way a click on its card does, and delivers its
// stream's first frame.
async function open(h, idx, name, st) {
  window.openProject(idx, name);
  await globalThis.__settle(5);
  const ws = h.sockets[h.sockets.length - 1];
  ws.open();
  ws.deliver('task_update', clone(st || STATES[idx]));
  await globalThis.__settle(5);
  return ws;
}

// close goes back to the list the way the header's back button does.
async function close(h) {
  window.clearProjectSelection();
  await globalThis.__settle(5);
  const ws = h.sockets[h.sockets.length - 1];
  ws.open();
  await globalThis.__settle(3);
  return ws;
}

// key presses a key on the page, outside any field.
async function key(k, mods) {
  document.dispatchEvent(Object.assign({type: 'keydown', key: k, target: document.body, preventDefault() {}}, mods || {}));
  await globalThis.__settle(5);
}

// What the command palette lists, in order, with the index each row selects.
function paletteRows() {
  const html = String(document.getElementById('cmd-results').innerHTML || '');
  const rows = [];
  const re = /data-idx="(\d+)"[\s\S]*?cmd-item-match">([^<]*)</g;
  let m;
  while ((m = re.exec(html)) !== null) rows.push({idx: Number(m[1]), label: m[2]});
  return rows;
}

// The shortcut help's groups, as headed.
function helpGroups() {
  const html = String(document.getElementById('help-modal-body').innerHTML || '');
  const out = [];
  const re = /<h4>([^<]*)<\/h4>/g;
  let m;
  while ((m = re.exec(html)) !== null) out.push(m[1]);
  return {groups: out, mentionsNewTask: /New task/.test(html), mentionsTabs: /Go to Tasks tab/.test(html)};
}

const scenarios = {
  // First paint on a hub of several projects: the list, nothing per-project
  // on offer, a stream that asked for no project, and no project's state read.
  async landing() {
    const h = await boot();
    return Object.assign(where(h), {requests: urls(h)});
  },

  // Until the project list answers, the page does not know whether the hub
  // has one project or several: it must show no project on a guess. A key, a
  // call and a global tab pressed in that window, then the answer.
  async before_the_list_answers() {
    const h = await boot({hold: true});
    const out = {held: where(h)};
    await key('2');
    await key('n');
    window.switchTab('tasks');
    await globalThis.__settle(3);
    out.project_tab = Object.assign(where(h), {requests: urls(h)});
    window.switchTab('settings');
    await globalThis.__settle(5);
    out.global_tab = Object.assign(where(h), {requests: urls(h)});
    release();
    await globalThis.__settle(8);
    out.answered = where(h);
    return out;
  },

  // Every per-project tab, asked for with none open: by its tab button's
  // action. None may open, fetch its script or ask the hub for anything.
  async tabs_refused() {
    const h = await boot();
    const before = h.requests.length;
    const fetched = scripts().length;
    const opened = [];
    for (const name of CONFIG.project_tabs) {
      window.switchTab(name);
      await globalThis.__settle(3);
      if (tab() !== 'projects') opened.push(name + ' -> ' + tab());
    }
    return Object.assign(where(h), {opened, requests: urls(h, before), scripts: scripts().slice(fetched)});
  },

  // The global tabs stay reachable with none open, and reaching one leaves
  // the per-project navigation off.
  async global_tabs_open() {
    await boot();
    const reached = [];
    const offered = [];
    for (const name of CONFIG.global_tabs) {
      window.switchTab(name);
      await globalThis.__settle(3);
      reached.push(tab());
      offered.push(inProject());
    }
    return {reached, offered};
  },

  // Opening a project brings its tabs; closing it takes them away again; and
  // a global tab visited from inside a project keeps them.
  async open_then_close() {
    const h = await boot();
    const out = {before: where(h)};

    await open(h, 1, 'beta');
    out.opened = where(h);

    window.switchTab('tasks');
    await globalThis.__settle(3);
    out.tasks = {tab: tab(), rendered: globalThis.__renderedTaskIds()};

    window.switchTab('settings');
    await globalThis.__settle(5);
    out.settings = where(h);

    await close(h);
    out.closed = where(h);

    const mark = h.requests.length;
    window.switchTab('tasks');
    await globalThis.__settle(3);
    out.after = {tab: tab(), requests: urls(h, mark)};
    return out;
  },

  // A hub with one project has it in view once its list has said so: its tabs
  // are on offer and open, as they always did.
  async one_project() {
    const h = await boot({names: ['alpha']});
    const out = where(h);
    h.sockets[h.sockets.length - 1].deliver('task_update', clone(STATES[0]));
    window.switchTab('tasks');
    await globalThis.__settle(3);
    out.tasks = {tab: tab(), rendered: globalThis.__renderedTaskIds()};
    return out;
  },

  // /?tab=tasks names a project's tab and no project: the list stays.
  async link_to_a_project_tab() {
    const h = await boot({search: '?tab=tasks'});
    return Object.assign(where(h), {replaced, requests: urls(h)});
  },

  // /?tab=settings names a global tab: it opens, with nothing per-project.
  async link_to_a_global_tab() {
    const h = await boot({search: '?tab=settings'});
    return Object.assign(where(h), {replaced});
  },

  // /?project=<path>&tab=tasks names both: the project opens on that tab, and
  // the header says so — its badge reads Project and its breadcrumb is shown.
  // (The Projects tab's own load opens the project, and used to put its own
  // "Global" back over it on the way out.)
  async link_to_a_project_and_tab() {
    const h = await boot({search: '?project=' + encodeURIComponent('/srv/beta') + '&tab=tasks'});
    const ws = h.sockets[h.sockets.length - 1];
    ws.open();
    ws.deliver('task_update', clone(STATES[1]));
    await globalThis.__settle(5);
    return Object.assign(where(h), {
      rendered: globalThis.__renderedTaskIds(), replaced,
      badge: String(document.getElementById('scopeHint').textContent || ''),
      breadcrumb: String(document.getElementById('projectBreadcrumb').style.display || ''),
    });
  },

  // The same link without a tab opens the project's Overview.
  async link_to_a_project() {
    const h = await boot({search: '?project=' + encodeURIComponent('/srv/beta')});
    return Object.assign(where(h), {badge: String(document.getElementById('scopeHint').textContent || '')});
  },

  // Back from a sign-in to a project that is gone meanwhile: its Tasks tab is
  // not reopened over nothing.
  async resume_without_the_project() {
    const h = await boot({resume: {path: '/srv/gone', tab: 'tasks'}});
    return where(h);
  },

  // Back from a sign-in to a project that is still there: project and tab.
  async resume_with_the_project() {
    const h = await boot({resume: {path: '/srv/gamma', tab: 'tasks'}});
    return where(h);
  },

  // The keys that go to a project's tabs do nothing with none open; r reads
  // the list again, never a state document; with a project open all three act
  // on it.
  async keys() {
    const h = await boot();
    const out = {};

    let mark = h.requests.length;
    await key('2');
    await key('n');
    await key('5');
    await pause(150);   // n focuses the title field 100 ms on
    out.none = {tab: tab(), requests: urls(h, mark), focus: String((document.activeElement || {}).id || '')};

    mark = h.requests.length;
    await key('r');
    out.refresh_none = {tab: tab(), requests: urls(h, mark), toast: toastText()};

    await open(h, 1, 'beta');
    await key('2');
    out.open = {tab: tab(), rendered: globalThis.__renderedTaskIds()};
    mark = h.requests.length;
    await key('r');
    out.refresh_open = {requests: urls(h, mark), toast: toastText()};
    return out;
  },

  // The project list answers with an error (r held down runs into the hub's
  // rate limit). api() resolves an error body, and read as an empty list it
  // emptied the grid and told the page the hub had one project — the hub's
  // own, in view, tabs and all. An error says nothing about the projects.
  async the_list_answers_with_an_error() {
    const h = await boot();
    const out = {before: Object.assign(where(h), {cards: cards()})};
    h.routes['/api/projects'] = {error: 'rate limit exceeded'};
    h.routeStatus['/api/projects'] = 429;

    await key('r');
    out.refreshed = Object.assign(where(h), {cards: cards(), toast: toastText()});
    await key('2');
    out.key = where(h);

    // The Projects tab's own read meets the same answer.
    window.switchTab('settings');
    await globalThis.__settle(5);
    window.switchTab('projects');
    await globalThis.__settle(5);
    out.revisited = Object.assign(where(h), {cards: cards()});

    delete h.routes['/api/projects'];
    delete h.routeStatus['/api/projects'];
    await key('r');
    out.recovered = Object.assign(where(h), {cards: cards(), toast: toastText()});
    return out;
  },

  // The command palette lists what can be done now: with none open nothing
  // that needs a project, with one open everything.
  async palette() {
    const h = await boot();
    const out = {};
    await key('k', {ctrlKey: true});
    out.none = paletteRows().map(r => r.label);
    await key('k', {ctrlKey: true});   // the same keys close it

    await open(h, 1, 'beta');
    await key('k', {ctrlKey: true});
    out.open = paletteRows().map(r => r.label);
    return out;
  },

  // A project that closes under the open palette takes its commands with it:
  // Stop run, listed while beta was open and chosen after it closed, stops
  // nothing. Chosen with beta open it stops beta.
  async palette_after_the_project_closed() {
    const h = await boot();
    const out = {};
    await open(h, 1, 'beta');

    await key('k', {ctrlKey: true});
    const stop = paletteRows().find(r => r.label === 'Stop run');
    out.listed = !!stop;
    let mark = h.requests.length;
    window.cmdSelect(stop.idx);
    await globalThis.__settle(5);
    out.open = urls(h, mark);

    await key('k', {ctrlKey: true});
    const again = paletteRows().find(r => r.label === 'Stop run');
    await close(h);                      // access withdrawn, the project removed…
    mark = h.requests.length;
    window.cmdSelect(again.idx);
    await globalThis.__settle(5);
    out.closed = urls(h, mark).filter(u => /\/api\/(stop|run)/.test(u));
    return out;
  },

  // The shortcut help leaves the project groups out while none is open.
  async help() {
    const h = await boot();
    const out = {};
    window.openHelpModal();
    out.none = helpGroups();
    window.closeHelpModal();
    await open(h, 1, 'beta');
    window.openHelpModal();
    out.open = helpGroups();
    return out;
  },

  // The hub tells a client it dropped frames (resync). With a project open
  // the page reads that project again. With none open there is nothing to
  // catch up on: before Task 20508 the page then read the hub's own project's
  // whole state, and spliced that project's history rows into the list the
  // last project left behind — which reopening it showed.
  async resync() {
    const step = (n, msg) => ({id: n + 1, kind: 'step', step: n, timestamp: '2026-11-20T10:00:0' + n + 'Z',
      message: msg, output: 'x', exit_code: 0, duration: '1s'});
    const h = await boot({before(hh) {
      // The history endpoint, answered by project as the hub answers it: beta's
      // rows for ?project_idx=1, and for a request that names no project the
      // hub's own — alpha's. The shim's routes match by prefix only, so the
      // body is chosen here, per request.
      const real = globalThis.fetch;
      globalThis.fetch = function(url, o) {
        const u = String(url);
        if (u.startsWith('/api/event-history')) {
          const gap = /[?&]after=/.test(u);
          hh.routes['/api/event-history'] = /[?&]project_idx=1\b/.test(u)
            ? (gap ? {entries: [step(1, 'beta step two')], top: [1, 0]}
              : {entries: [step(0, 'beta step')], top: [0, 0], bottom: ['2026-11-20', 'step', 0], more: false})
            : {entries: [step(6, 'ALPHA-ONLY step')], top: [6, 0], bottom: ['2026-11-20', 'step', 6], more: false};
        }
        return real(url, o);
      };
    }});
    const out = {};

    const wsBeta = await open(h, 1, 'beta');
    out.history_open = /beta step/.test(String(document.getElementById('stepList').innerHTML));
    let mark = h.requests.length;
    wsBeta.deliver('resync', {});
    await globalThis.__settle(5);
    out.open = urls(h, mark).filter(u => /\/api\/(state|event-history)/.test(u));

    const wsLanding = await close(h);
    mark = h.requests.length;
    wsLanding.deliver('resync', {});
    await globalThis.__settle(5);
    out.none = urls(h, mark);

    await open(h, 1, 'beta');
    const list = String(document.getElementById('stepList').innerHTML);
    out.reopened = {beta: /beta step/.test(list), alpha: /ALPHA-ONLY/.test(list)};
    return out;
  },

  // A stream that drops asks the hub one thing before it reconnects, to tell
  // a lapsed sign-in from an outage. With a project open that is the
  // project's state; with none open it was the hub's own project's — its
  // whole task list, read for a status code. Both the WebSocket and the
  // event-stream fallback.
  async a_stream_drops() {
    const h = await boot();
    const out = {};

    let mark = h.requests.length;
    h.sockets[h.sockets.length - 1].finishClose();
    await globalThis.__settle(5);
    out.none = urls(h, mark);

    const ws = await open(h, 1, 'beta');
    mark = h.requests.length;
    ws.finishClose();
    await globalThis.__settle(5);
    out.open = urls(h, mark).filter(u => /\/api\/(state|projects)/.test(u));

    // The fallback: a socket that fails before it ever opens.
    await close(h);
    const dead = h.sockets[h.sockets.length - 1];
    dead.readyState = 3;
    dead.onerror({});
    await globalThis.__settle(3);
    const es = h.eventSources[h.eventSources.length - 1];
    out.fallback = es ? es.url : '';
    mark = h.requests.length;
    if (es) es.onerror({});
    await globalThis.__settle(5);
    out.fallback_none = urls(h, mark);
    return out;
  },

  // A state document asked for with a project open that arrives after it has
  // closed is nobody's: it must not become the page's state. Told by the Stop
  // button, which render shows for a running project. The same answer taken
  // with the project still open is the control.
  async late_state() {
    const h = await boot();
    const stopShown = () => document.getElementById('ctrlStop').style.display !== 'none';
    const out = {};

    await open(h, 1, 'beta');
    out.idle = stopShown();
    h.states[1].status = 'running';
    window.refreshState();
    await globalThis.__settle(5);
    out.taken_while_open = stopShown();

    h.states[1].status = 'idle';
    window.refreshState();
    await globalThis.__settle(5);
    out.idle_again = stopShown();

    h.states[1].status = 'running';
    window.refreshState();            // asked with beta open…
    window.clearProjectSelection();   // …answered after it closed
    await globalThis.__settle(5);
    out.taken_after_close = stopShown();
    return out;
  },

  // The Claude Code caps card re-reads its figures when the tab comes back to
  // the foreground. With the project it belonged to closed since, there is no
  // project to read them for.
  async limits_after_the_project_closed() {
    const h = await boot();
    const out = {};
    const st = Object.assign(clone(STATES[1]), {provider: 'claudecode'});
    await open(h, 1, 'beta', st);

    let mark = h.requests.length;
    window.loadCCLimits({force: true});
    await globalThis.__settle(3);
    out.open = urls(h, mark).filter(u => /claudecode-limits/.test(u));

    await close(h);
    mark = h.requests.length;
    document.hidden = false;
    document.dispatchEvent({type: 'visibilitychange', target: document});
    window.loadCCLimits({force: true});
    await globalThis.__settle(3);
    out.none = urls(h, mark).filter(u => /claudecode-limits/.test(u));
    return out;
  },

  // What two global tabs do for one project: Settings' provider cards and
  // reset, Budget's per-project caps and the breakdown of its .cloop
  // directory. With none open they are not read and a save sends nothing;
  // with a project open they are that project's.
  async settings_and_budget_for_a_project() {
    const h = await boot();
    const out = {};
    const sent = mark => urls(h, mark).filter(u => /\/api\/(config(\?|\/set|$)|reset|budget\/project|disk-usage)/.test(u));
    const disk = () => String(document.getElementById('diskUsageBody').innerHTML || '');
    h.routes['/api/disk-usage'] = {total_bytes: 4096, entries: [{name: 'state.db', bytes: 4096}], policy: {enabled: true}};

    let mark = h.requests.length;
    window.switchTab('settings');
    await globalThis.__settle(5);
    const settings = await window.panelAct('settings');
    settings.saveProvider();
    settings.confirmReset();
    window.switchTab('budget');
    await globalThis.__settle(5);
    const budget = await window.panelAct('budget');
    budget.saveBudgetProject();
    await globalThis.__settle(5);
    out.none = sent(mark);
    out.disk_none = disk();

    await open(h, 1, 'beta');
    mark = h.requests.length;
    window.switchTab('settings');
    await globalThis.__settle(5);
    settings.saveProvider();
    settings.confirmReset();
    window.switchTab('budget');
    await globalThis.__settle(5);
    budget.saveBudgetProject();
    await globalThis.__settle(5);
    out.open = sent(mark).sort();
    out.disk_open = disk();

    // An error is said as one: it used to draw as an empty directory with
    // retention off.
    h.routes['/api/disk-usage'] = {error: 'the requested resource does not exist'};
    h.routeStatus['/api/disk-usage'] = 404;
    await budget.loadDiskUsage();
    await globalThis.__settle(3);
    out.disk_error = disk();
    return out;
  },

  // A hub with one project gains a second while the first one's Tasks tab is
  // on screen: the page read the list again (here, as the grid does after a
  // Hide). The page stays on that tab of that project, which is now picked
  // by name: its stream and its requests name it.
  async second_project_appears() {
    const h = await boot({names: ['alpha']});
    h.sockets[h.sockets.length - 1].deliver('task_update', clone(STATES[0]));
    window.switchTab('tasks');
    await globalThis.__settle(3);
    const out = {before: where(h)};

    h.projects = roster(['alpha', 'beta']);
    h.routes['/api/projects/0/hidden'] = {ok: true};
    window.projectHide(0, 'alpha');
    await globalThis.__settle(8);
    const ws = h.sockets[h.sockets.length - 1];
    ws.open();
    ws.deliver('task_update', clone(STATES[0]));
    await globalThis.__settle(5);
    out.after = Object.assign(where(h), {
      rendered: globalThis.__renderedTaskIds(),
      selector: String(document.getElementById('projSelectorLabel').textContent || ''),
    });
    return out;
  },

  // The same, learned from the hub's push instead of a read — and then the
  // second project opened from its card. Before Task 20508 a push did not tell
  // the page the hub had more than one project: the card opened under the
  // second project's name on the first project's stream, and drew its tasks.
  async second_project_is_pushed() {
    const h = await boot({names: ['alpha']});
    const first = h.sockets[h.sockets.length - 1];
    first.deliver('task_update', clone(STATES[0]));
    window.switchTab('tasks');
    await globalThis.__settle(3);
    const out = {};

    first.deliver('projects', roster(['alpha', 'beta']));
    await globalThis.__settle(8);
    out.pushed = where(h);

    // The first project's old stream is still closing, and delivers a frame.
    await open(h, 1, 'beta');
    first.deliver('task_update', clone(STATES[0]));
    window.switchTab('tasks');
    await globalThis.__settle(3);
    out.opened = Object.assign(where(h), {rendered: globalThis.__renderedTaskIds()});
    return out;
  },

  // A second project appears while a global tab is on screen: nothing of the
  // first project is being looked at, so none is picked. The page is now a
  // hub of several with none open, on a stream that carries no project.
  async second_project_under_a_global_tab() {
    const h = await boot({names: ['alpha']});
    const first = h.sockets[h.sockets.length - 1];
    first.deliver('task_update', clone(STATES[0]));
    window.switchTab('settings');
    await globalThis.__settle(5);
    const out = {before: where(h)};
    first.deliver('projects', roster(['alpha', 'beta']));
    await globalThis.__settle(8);
    out.after = where(h);
    const mark = h.requests.length;
    window.switchTab('tasks');
    await globalThis.__settle(3);
    out.tasks = Object.assign(where(h), {requests: urls(h, mark)});
    return out;
  },

  // A hub of two projects is left with one (the other was deleted) while none
  // is open. The one that is left is in view now: the page asks for its
  // stream and draws it, instead of the deleted project's last Overview over
  // a Start button that runs the hub's own.
  async down_to_one_project() {
    const h = await boot({names: ['alpha', 'beta']});
    await open(h, 1, 'beta');
    window.switchTab('tasks');
    await globalThis.__settle(3);
    await close(h);
    const out = {before: where(h)};

    h.projects = roster(['alpha']);
    await key('r');
    out.turned = where(h);
    out.goal_cleared = globalThis.__renderedTaskIds();
    const ws = h.sockets[h.sockets.length - 1];
    ws.open();
    ws.deliver('task_update', clone(STATES[0]));
    window.switchTab('tasks');
    await globalThis.__settle(3);
    out.after = Object.assign(where(h), {rendered: globalThis.__renderedTaskIds()});
    return out;
  },

  // The hub's only project goes and two others come, under its Tasks tab:
  // there is no project to stay on, so the page goes to the list rather than
  // sit on a project's tab with nothing to show and its navigation gone.
  async the_only_project_is_replaced() {
    const h = await boot({names: ['alpha']});
    h.sockets[h.sockets.length - 1].deliver('task_update', clone(STATES[0]));
    window.switchTab('tasks');
    await globalThis.__settle(3);
    const out = {before: where(h)};
    h.projects = roster(['beta', 'gamma']);   // what a read of the list now says too
    h.sockets[h.sockets.length - 1].deliver('projects', roster(['beta', 'gamma']));
    await globalThis.__settle(8);
    out.after = Object.assign(where(h), {cards: cards()});
    return out;
  },

  // The back arrow goes away with the project it leaves. Pressed from the
  // keyboard, the caret moves to the project selector beside it, where it can
  // pick the next one, instead of falling to the top of the page.
  async back_arrow_keeps_the_caret() {
    const h = await boot();
    await open(h, 1, 'beta');
    const back = document.getElementById('projBackBtn');
    back.dataset.action = 'clearProjectSelection';   // as index.html marks it
    back.focus();
    window.clearProjectSelection();
    await globalThis.__settle(5);
    return {tab: tab(), focus: String((document.activeElement || {}).id || '')};
  },

  // A list of one project is not a hub of one project: a member's single
  // shared project, on a hub whose own project they cannot see, comes with
  // multi_project true. A push says so too; one from a hub member that
  // predates the flag says nothing, and must not be read as "one project".
  async a_list_of_one_on_a_hub_of_several() {
    const h = await boot({roster: roster(['beta'], true)});
    const out = {landing: where(h)};
    const ws = h.sockets[h.sockets.length - 1];

    const old = roster(['beta']);
    delete old.multi_project;
    ws.deliver('projects', old);
    await globalThis.__settle(5);
    out.old_push = where(h);

    ws.deliver('projects', roster(['beta'], true));
    await globalThis.__settle(5);
    out.push = where(h);
    return out;
  },

  // The project list cannot be read at first paint: the hub is restarting.
  // The page shows no project and asks again; it used to connect regardless,
  // be handed the hub's own project by its stream, and show that one — tabs
  // and all — on a hub of several, until somebody reloaded it.
  async the_list_is_unreadable() {
    let down = true;
    const h = await boot({before() {
      const real = globalThis.fetch;
      globalThis.fetch = function(url, o) {
        if (down && String(url).startsWith('/api/projects')) return Promise.reject(new Error('network down'));
        return real(url, o);
      };
    }});
    const out = {down: Object.assign(where(h), {sockets: h.sockets.length, toast: toastText()})};
    await key('2');
    out.key = where(h);

    down = false;
    await pause(1300);   // the first retry comes a second on
    await globalThis.__settle(8);
    out.back = Object.assign(where(h), {sockets: h.sockets.length, cards: cards()});
    return out;
  },

  // The same with an answer that parses and is not a list: a 500's body.
  async the_list_is_an_error_at_first_paint() {
    const h = await boot({before(hh) {
      hh.routes['/api/projects'] = {error: 'internal error'};
      hh.routeStatus['/api/projects'] = 500;
    }});
    const out = {down: Object.assign(where(h), {sockets: h.sockets.length, requests: urls(h), toast: toastText()})};
    delete h.routes['/api/projects'];
    delete h.routeStatus['/api/projects'];
    await pause(1300);
    await globalThis.__settle(8);
    out.back = Object.assign(where(h), {sockets: h.sockets.length, cards: cards()});
    return out;
  },
};

(async () => {
  const out = {};
  const only = process.argv[5];
  for (const [name, fn] of Object.entries(scenarios)) {
    if (only && only !== name) continue;
    try {
      out[name] = await fn();
    } catch (e) {
      out[name] = {error: String((e && e.stack) || e)};
    }
  }
  // Written, then gone: the bundle leaves timers pending (a toast's three
  // seconds, a stream's reconnect) that node would otherwise sit out.
  process.stdout.write(JSON.stringify(out), () => process.exit(0));
})();
