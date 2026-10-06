// run_build_scenarios.js — drives the "running build X, N builds behind this
// hub" note on the Overview and the Tasks run bar, its one-shot adoption, and
// the Follow New Builds badge, against the real dashboard bundle (Task 20389).
//
// Run by TestDashboard_RunBuildNote. Each scenario returns a flat object and
// the Go side asserts on it. Printed as one JSON document on stdout.
//
// Usage: node run_build_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const PROJECT = {
  goal: 'ship it',
  status: 'running',
  plan: {goal: 'ship it', tasks: [{id: 1, title: 'one', status: 'in_progress', priority: 1}]},
};

const PROJECTS = {
  multi_project: true,
  stats: {total_projects: 1},
  projects: [{name: 'alpha', path: '/srv/alpha', goal: 'ship it', total_tasks: 1, done_tasks: 0, health: 'running'}],
};

const LAGGING = {
  build: {version: 'dev+g4e35bf6', sequence: 831},
  reference: {version: 'dev+g89510f3', sequence: 963},
  behind: 132, comparable: true, live: true, live_known: true, pid: 4242,
  executor: 'localprocess', adoptable: true,
};

function clone(o) { return JSON.parse(JSON.stringify(o)); }

async function open(st, me) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  if (me) h.me = me;
  h.states = {0: clone(st)};
  h.projects = clone(PROJECTS);
  require(bundlePath);
  await globalThis.__settle(5);
  window.openProject(0, 'alpha');
  await globalThis.__settle();
  const ws = h.sockets[h.sockets.length - 1];
  ws.open();
  ws.deliver('task_update', clone(st));
  await globalThis.__settle(2);
  return {h, ws};
}

function note(id) {
  const el = document.getElementById(id);
  return {shown: el.style.display !== 'none', html: el.innerHTML || ''};
}

function notes() {
  return {overview: note('runBuildNote'), tasks: note('tasksRunBuild')};
}

function badge(text) {
  const html = document.getElementById('activeOptionsGrid').innerHTML || '';
  const i = html.indexOf('<span>' + text + '</span>');
  if (i < 0) return 'absent';
  const start = html.lastIndexOf('<button', i);
  const tag = html.slice(start, html.indexOf('>', start));
  return /class="option-badge on /.test(tag) ? 'on' : 'off';
}

const scenarios = {
  // A run behind the hub is named on both surfaces; the Overview offers the
  // one-shot adoption. A state_diff that brings it level hides both.
  async lagging_then_level() {
    const st = clone(PROJECT);
    st.run_build = clone(LAGGING);
    const {ws} = await open(st);
    const lagging = notes();
    const level = clone(LAGGING);
    level.behind = 0;
    level.build = {version: 'dev+g89510f3', sequence: 963};
    ws.deliver('state_diff', {state_changed: {run_build: level}});
    await globalThis.__settle(2);
    return {lagging, level: notes()};
  },

  // A request filed for this run says it is waiting, instead of a button.
  async request_pending() {
    const st = clone(PROJECT);
    st.run_build = clone(LAGGING);
    st.adopt_request = {id: 'adopt_1', run: {pid: 4242, start_ticks: 1, boot_id: 'b'}};
    await open(st);
    return notes();
  },

  // A device or container run keeps its own upgrade path: said, not offered.
  async device_run() {
    const st = clone(PROJECT);
    st.run_build = clone(LAGGING);
    st.run_build.adoptable = false;
    st.run_build.executor = 'remote';
    await open(st);
    return notes();
  },

  // Someone who may not start runs is not offered the action.
  async viewer() {
    const st = clone(PROJECT);
    st.run_build = clone(LAGGING);
    await open(st, {oidc_enabled: true, authenticated: true, permissions: ['project.read']});
    return notes();
  },

  // The button files the request through the hub and shows its answer.
  async adopt_posts() {
    const st = clone(PROJECT);
    st.run_build = clone(LAGGING);
    const {h} = await open(st);
    h.routes['/api/run/adopt-build'] = {ok: true, message: 'Requested: the run (pid 4242) adopts dev+g89510f3 at its next task boundary'};
    window.adoptBuild();
    await globalThis.__settle(4);
    const posts = h.requests.filter(r => r.url.startsWith('/api/run/adopt-build')).map(r => r.method);
    return {posts};
  },

  // Whatever a record says is text, not markup.
  async escaped() {
    const st = clone(PROJECT);
    st.run_build = clone(LAGGING);
    st.run_build.build.version = '<img src=x onerror=alert(1)>';
    await open(st);
    return notes();
  },

  // Follow New Builds is an Active Options badge that follows the state and
  // posts its flag.
  async follow_badge() {
    const {h, ws} = await open(clone(PROJECT));
    const off = badge('Follow New Builds');
    ws.deliver('state_diff', {state_changed: {follow_builds: true}});
    await globalThis.__settle(2);
    const on = badge('Follow New Builds');
    h.routes['/api/options/toggle'] = {ok: true, follow_builds: false};
    window.toggleOption('follow_builds', false);
    await globalThis.__settle(4);
    const posts = h.requests.filter(r => r.url.startsWith('/api/options/toggle')).map(r => r.body);
    return {off, on, posts};
  },
};

(async () => {
  const out = {};
  for (const [name, fn] of Object.entries(scenarios)) {
    try {
      out[name] = await fn();
    } catch (e) {
      out[name] = {error: String((e && e.stack) || e)};
    }
  }
  process.stdout.write(JSON.stringify(out));
})();
