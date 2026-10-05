// history_scenarios.js — the Event History panel through a live run, against
// the real dashboard bundle (Task 20384).
//
// The panel used to refetch GET /api/event-history after every task_update,
// state_diff, task_added, task_deleted, task_mutation and run_state message,
// asking for every row it already held. Each scenario here drives the frames a
// running project produces, with the history_append pushes the hub now sends
// beside them, and reports every event-history request the bundle made and the
// rows the panel ended up showing. The Go side (TestDashboard_EventHistory-
// StaysLiveWithoutRefetching) holds the requests to the ones a scenario can
// justify — the first page, a page the user scrolled to, one read to fill a
// gap — and the rows to the journal's.
//
// The endpoint is played by a small model of the hub's journal (below) rather
// than canned bodies: after= and before= have to answer from where the client
// says it is, or a client that asked for the wrong range would still pass.
//
// Usage: node history_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const PROJECT = {
  goal: 'ship the feed',
  status: 'running',
  current_step: 0,
  steps_count: 0,
  plan: {goal: 'ship the feed', tasks: [
    {id: 1, title: 'first', status: 'in_progress', priority: 1},
    {id: 2, title: 'second', status: 'pending', priority: 2},
  ]},
};

function clone(o) { return JSON.parse(JSON.stringify(o)); }

// ── the hub's journal ───────────────────────────────────────────────────────

// J holds one project's journal newest first, its top (newest step number and
// event id), and the position the hub's pushes have reached.
let J;
let clock;

function resetJournal() {
  J = {rows: [], step: -1, event: 0, pushed: null};
  clock = Date.UTC(2026, 9, 5, 9, 0, 0);
}

function stamp() { clock += 1000; return new Date(clock).toISOString(); }

function addStep(msg) {
  J.step++;
  J.rows.unshift({id: J.step + 1, kind: 'step', step: J.step, timestamp: stamp(),
    message: msg, output: msg + ' — output', exit_code: 0, duration: '1s'});
}

function addEvent(kind, msg) {
  J.event++;
  J.rows.unshift({id: -J.event, kind, step: -1, task_id: 1, timestamp: stamp(), message: msg});
}

const top = () => [J.step, J.event];
const keyOf = r => (r.kind === 'step' ? 's' + r.step : 'e' + r.id);
// A row's place as the hub writes it: [day, kind, key]. The day is not needed
// by a model that keeps its rows in order; the client must send all three back.
const placeOf = r => [2461318.5 + J.rows.length - J.rows.indexOf(r), r.kind === 'step' ? 0 : 1, r.kind === 'step' ? r.step : -r.id];
const newerThan = (c, r) => (r.kind === 'step' ? r.step > c[0] : -r.id > c[1]);

function endpoint(url) {
  const q = new URL(url, 'https://hub.example').searchParams;
  const limit = Number(q.get('limit')) || 50;
  const newest = gap => {
    const entries = J.rows.slice(0, limit);
    return {entries, top: top(), bottom: entries.length ? placeOf(entries[entries.length - 1]) : null,
      more: J.rows.length > limit, gap};
  };
  if (q.get('after')) {
    const c = q.get('after').split(',').map(Number);
    if (c.length !== 2 || c.some(isNaN)) return {status: 400, body: {error: 'after'}};
    const fresh = J.rows.filter(r => newerThan(c, r));
    if (fresh.length > limit) return {body: newest(true)};
    return {body: {entries: fresh, top: top(), bottom: null, more: false}};
  }
  if (q.get('before')) {
    const p = q.get('before').split(',').map(Number);
    const at = J.rows.findIndex(r => String(placeOf(r)) === String(p));
    if (p.length !== 3 || at < 0) return {status: 400, body: {error: 'before'}};
    const entries = J.rows.slice(at + 1, at + 1 + limit);
    return {body: {entries, bottom: entries.length ? placeOf(entries[entries.length - 1]) : p,
      more: at + 1 + limit < J.rows.length}};
  }
  return {body: newest(false)};
}

// push delivers what the hub's watcher would after a write: the rows written
// since its last push, from where that push ended.
function push(sock) {
  const from = J.pushed;
  const entries = J.rows.filter(r => newerThan(from, r));
  J.pushed = top();
  sock.deliver('history_append', {entries, from, to: J.pushed});
}

// syncPoint is what the hub primes a stream with when it opens.
function syncPoint(sock) {
  if (!J.pushed) J.pushed = top();
  sock.deliver('history_append', {entries: [], from: J.pushed, to: J.pushed});
}

// ── the browser ─────────────────────────────────────────────────────────────

async function boot(opts) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.states = {0: clone(PROJECT)};
  h.projects = {multi_project: false, stats: {total_projects: 1}, projects: []};
  // The sentinel below the list scrolling into view, on the scenario's cue.
  h.scrolled = () => {};
  globalThis.IntersectionObserver = class {
    constructor(cb) { h.scrolled = () => cb([{isIntersecting: true}]); }
    observe() {}
    disconnect() {}
  };
  // The endpoint answers from the journal model; everything else from the shim.
  const shimFetch = globalThis.fetch;
  globalThis.fetch = function(url, o) {
    const u = String(url);
    if (!u.startsWith('/api/event-history')) return shimFetch(url, o);
    h.requests.push({url: u, method: 'GET', body: null});
    const {status, body} = endpoint(u);
    const text = JSON.stringify(body);
    return Promise.resolve({ok: !status, status: status || 200,
      headers: {get: () => null}, json: async () => JSON.parse(text), text: async () => text});
  };
  if (opts && opts.withoutWebSocket) delete globalThis.WebSocket;

  require(bundlePath);
  await globalThis.__settle(8);
  return h;
}

const socket = h => h.sockets[h.sockets.length - 1];
const historyRequests = h => h.requests.filter(r => r.url.startsWith('/api/event-history')).map(r => r.url.split('?')[1] || '');

// What the panel shows: entry keys in the order they are drawn.
function rendered() {
  const html = document.getElementById('stepList').innerHTML || '';
  const out = [];
  const re = /data-idx="([^"]+)"/g;
  let m;
  while ((m = re.exec(html)) !== null) if (m[1] !== 'running') out.push(m[1]);
  return out;
}

// A run's messages arrive seconds apart, not in one burst; this is the
// shortest gap that still models that — the old panel debounced its refetch by
// 250 ms, so anything closer would have hidden its reads.
const pace = () => new Promise(r => setTimeout(r, 300));

// runTask writes what one task of a run journals, delivers every message the
// hub sends for it — the ones that each used to trigger a refetch — and then
// the push the watcher makes beside them.
async function runTask(sock, n, s) {
  addEvent('task_started', 'Task #' + n + ' started');
  addStep('Task ' + n + ': work');
  addEvent('task_done', 'Task #' + n + ' done');
  s.steps_count = J.step + 1;
  s.current_step = J.step + 1;
  sock.deliver('run_state', {running: true});
  sock.deliver('task_update', clone(s));
  sock.deliver('state_diff', {state_changed: {steps_count: s.steps_count, current_step: s.current_step}});
  sock.deliver('task_mutation', {task: {id: 1, title: 'first'}});
  sock.deliver('task_added', {task: {id: 100 + n}});
  sock.deliver('task_deleted', {id: 100 + n});
  push(sock);
  await pace();
  await globalThis.__settle(3);
}

const result = (h, extra) => Object.assign({
  requests: historyRequests(h),
  rendered: rendered(),
  want: J.rows.map(keyOf),
}, extra || {});

const scenarios = {
  // A run of eight tasks with the panel open: the first page is the only
  // read, and the panel holds every row the run wrote, newest first.
  async live_run() {
    resetJournal();
    for (let i = 0; i < 3; i++) addEvent('task_added', 'Task #' + (i + 1) + ' added');
    const h = await boot();
    const sock = socket(h);
    sock.open();
    syncPoint(sock);
    await globalThis.__settle(3);
    const s = clone(PROJECT);
    for (let n = 1; n <= 8; n++) await runTask(sock, n, s);
    return result(h);
  },

  // The socket drops mid-run and rows are written while it is down. The new
  // socket's sync point is above the list's top, so the panel reads past its
  // top once — and only that — then carries on from the pushes.
  async reconnect_after_missed_rows() {
    resetJournal();
    const h = await boot();
    let sock = socket(h);
    sock.open();
    syncPoint(sock);
    const s = clone(PROJECT);
    await runTask(sock, 1, s);
    await runTask(sock, 2, s);

    sock.finishClose();
    // Written while nobody was connected: the hub pushed them to an empty
    // room, so its position moved on without this client.
    addEvent('task_started', 'Task #3 started');
    addStep('Task 3: work');
    J.pushed = top();
    await new Promise(r => setTimeout(r, 1300)); // the client's reconnect backoff
    await globalThis.__settle(3);
    sock = socket(h);
    sock.open();
    syncPoint(sock);
    await globalThis.__settle(5);
    const afterReconnect = historyRequests(h).length;
    await runTask(sock, 4, s);
    await runTask(sock, 5, s);
    return result(h, {sockets: h.sockets.length, afterReconnect});
  },

  // A reconnect that missed nothing reads nothing.
  async reconnect_without_missed_rows() {
    resetJournal();
    const h = await boot();
    let sock = socket(h);
    sock.open();
    syncPoint(sock);
    const s = clone(PROJECT);
    await runTask(sock, 1, s);
    sock.finishClose();
    await new Promise(r => setTimeout(r, 1300));
    await globalThis.__settle(3);
    sock = socket(h);
    sock.open();
    syncPoint(sock);
    await globalThis.__settle(5);
    await runTask(sock, 2, s);
    return result(h, {sockets: h.sockets.length});
  },

  // A push that never arrived (the hub dropped it for a slow client): the
  // next one does not continue from the list's top, and one read fills it.
  async dropped_push() {
    resetJournal();
    const h = await boot();
    const sock = socket(h);
    sock.open();
    syncPoint(sock);
    const s = clone(PROJECT);
    await runTask(sock, 1, s);
    addEvent('task_started', 'Task #2 started');
    J.pushed = top(); // pushed, but lost on the way
    await runTask(sock, 3, s);
    await runTask(sock, 4, s);
    return result(h);
  },

  // The user scrolls two pages down mid-run. Those pages are read once each;
  // later pushes and a reconnect read none of them again.
  async scrolled_history() {
    resetJournal();
    for (let i = 0; i < 130; i++) addEvent('task_added', 'Task #' + (i + 1) + ' added');
    const h = await boot();
    let sock = socket(h);
    sock.open();
    syncPoint(sock);
    await globalThis.__settle(3);
    h.scrolled();
    await globalThis.__settle(3);
    h.scrolled();
    await globalThis.__settle(3);
    const s = clone(PROJECT);
    await runTask(sock, 1, s);
    sock.finishClose();
    await new Promise(r => setTimeout(r, 1300));
    await globalThis.__settle(3);
    sock = socket(h);
    sock.open();
    syncPoint(sock);
    await globalThis.__settle(3);
    await runTask(sock, 2, s);
    // The 130 rows the user scrolled through and the six written since.
    return result(h);
  },

  // Behind a proxy that blocks WebSocket upgrades, the same pushes arrive as
  // named SSE events.
  async sse_fallback() {
    resetJournal();
    addEvent('task_added', 'Task #1 added');
    const h = await boot({withoutWebSocket: true});
    const es = h.eventSources[h.eventSources.length - 1];
    if (!es) return {error: 'the bundle opened no EventSource without WebSocket support'};
    es.open();
    if (!J.pushed) J.pushed = top();
    es.deliver('history_append', {entries: [], from: J.pushed, to: J.pushed});
    await globalThis.__settle(3);
    const s = clone(PROJECT);
    for (let n = 1; n <= 3; n++) {
      addEvent('task_started', 'Task #' + n + ' started');
      addStep('Task ' + n + ': work');
      s.steps_count = J.step + 1;
      es.deliver('message', clone(s)); // the SSE stream's full-state frame
      es.deliver('run_state', {running: true});
      const from = J.pushed;
      const entries = J.rows.filter(r => newerThan(from, r));
      J.pushed = top();
      es.deliver('history_append', {entries, from, to: J.pushed});
      await pace();
      await globalThis.__settle(3);
    }
    return result(h);
  },
};

(async () => {
  const out = {};
  for (const [name, fn] of Object.entries(scenarios)) {
    try {
      out[name] = await fn();
    } catch (e) {
      out[name] = {error: String(e && e.stack || e)};
    }
  }
  process.stdout.write(JSON.stringify(out));
  process.exit(0);
})();
