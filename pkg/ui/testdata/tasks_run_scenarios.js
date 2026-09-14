// tasks_run_scenarios.js — drives the Tasks tab's Start/Stop bar against the
// real dashboard bundle (Task 20253).
//
// The bar exists so somebody who has just edited a plan can start it without
// navigating away, and that makes it the third view offering to start a run.
// Three views offering one action is exactly how the multi-project scoping bug
// class kept coming back (Tasks 150, 152, 163, 168, 8000, 20013, 20018, 20197),
// so the properties worth holding are behavioural rather than textual:
//
//   * the pair tracks run state live, without a tab switch — a bar that only
//     refreshes on navigation would offer Start on a running project, which is
//     the dispatch handleRun now refuses;
//   * Start acts on the project being *viewed*, not on the hub's default;
//   * with no project selected there is no button at all, because there is no
//     project for it to act on.
//
// Run by TestDashboard_TasksTabStartsRuns. Each scenario returns a flat object
// and the Go side asserts on it. Printed as one JSON document on stdout.
//
// Usage: node tasks_run_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

// Two projects so "acts on the viewed project" is falsifiable: a Start that
// resolved to the hub's default would post beta's index as alpha's, or none.
const ALPHA = {
  goal: 'alpha goal',
  status: 'initialized',
  plan: {goal: 'alpha goal', tasks: [{id: 101, title: 'alpha one', status: 'pending', priority: 1}]},
};
const BETA = {
  goal: 'beta goal',
  status: 'initialized',
  plan: {goal: 'beta goal', tasks: [{id: 201, title: 'beta one', status: 'pending', priority: 1}]},
};

const PROJECTS = {
  multi_project: true,
  stats: {total_projects: 2},
  projects: [
    {name: 'alpha', path: '/srv/alpha', goal: 'alpha goal', total_tasks: 1, done_tasks: 0, health: 'idle'},
    {name: 'beta',  path: '/srv/beta',  goal: 'beta goal',  total_tasks: 1, done_tasks: 0, health: 'idle'},
  ],
};

function clone(o) { return JSON.parse(JSON.stringify(o)); }

async function boot() {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.states = {0: clone(ALPHA), 1: clone(BETA)};
  h.projects = clone(PROJECTS);

  require(bundlePath);
  await globalThis.__settle(5);
  const ws = h.sockets[h.sockets.length - 1];
  if (ws) ws.open();
  await globalThis.__settle(2);
  return h;
}

function currentSocket(h) { return h.sockets[h.sockets.length - 1]; }

// vis reads back what the user can see. The shim models no layout, so
// style.display is the whole truth about whether a button is on the page —
// which is also all updateRunButtonState sets.
function vis(id) {
  const el = document.getElementById(id);
  return !el || el.style.display !== 'none';
}

// pair snapshots every copy of the Run/Stop affordance at once. Asserting on
// all four is the point: the Overview pair and the Tasks pair must never
// disagree about one project.
function pair() {
  return {
    overviewRun:  vis('ctrlRun'),
    overviewStop: vis('ctrlStop'),
    tasksRun:     vis('tasksCtrlRun'),
    tasksStop:    vis('tasksCtrlStop'),
    barVisible:   vis('tasksRunBar'),
    status:       document.getElementById('tasksRunStatus').innerHTML || '',
  };
}

// runPosts returns the POSTs the bundle aimed at /api/run, in order.
function runPosts(h) {
  return h.requests.filter(r => r.url.startsWith('/api/run')).map(r => r.url);
}

// openBeta walks to beta's Tasks tab, which is where every scenario starts.
async function openBeta(h) {
  window.openProject(1, 'beta');
  await globalThis.__settle();
  const ws = currentSocket(h);
  ws.open();
  ws.deliver('task_update', clone(BETA));
  window.switchTab('tasks');
  await globalThis.__settle(2);
  return ws;
}

const scenarios = {
  // An idle project offers Start and nothing else.
  async idle_offers_start() {
    const h = await boot();
    await openBeta(h);
    return pair();
  },

  // The live case, and the one that matters: a run_state frame arrives while
  // the user is parked on the Tasks tab. Nothing re-renders the tab, so if the
  // bar were wired to a render path it would keep offering Start on a project
  // that is now running.
  async run_state_flips_the_pair_without_navigating() {
    const h = await boot();
    const ws = await openBeta(h);

    ws.deliver('run_state', {running: true});
    await globalThis.__settle(2);
    const started = pair();

    ws.deliver('run_state', {running: false});
    await globalThis.__settle(2);
    const stopped = pair();

    return {started, stopped};
  },

  // A project whose state says it is running must not be offered Start on the
  // first paint either — the frame that hydrates the tab carries the status.
  async running_project_offers_stop_on_arrival() {
    const h = await boot();
    const running = clone(BETA);
    running.status = 'running';
    running.plan.tasks[0].status = 'in_progress';
    h.states[1] = running;

    window.openProject(1, 'beta');
    await globalThis.__settle();
    const ws = currentSocket(h);
    ws.open();
    ws.deliver('task_update', clone(running));
    window.switchTab('tasks');
    await globalThis.__settle(2);
    return pair();
  },

  // Start must spend the *viewed* project's budget. ?project_idx=1 is beta;
  // an unscoped /api/run would start whatever the hub's own WorkDir points at.
  async start_posts_the_viewed_project() {
    const h = await boot();
    await openBeta(h);
    window.apiRun();
    await globalThis.__settle(3);
    return {posts: runPosts(h), after: pair()};
  },

  // handleRun refuses a second harness with {error, running:true}. The client
  // keys on that body, so the button it just proved wrong becomes Stop instead
  // of sitting there inviting another click.
  async refusal_corrects_the_button() {
    const h = await boot();
    await openBeta(h);
    h.routes['/api/run'] = {
      error: 'a run is already in progress for this project — stop it before starting another',
      running: true,
    };
    window.apiRun();
    await globalThis.__settle(3);
    return pair();
  },

  // Back on the projects grid nothing is selected, so pUrl drops the index and
  // Start would resolve to the hub's default project. There must be no button.
  async no_selection_hides_the_bar() {
    const h = await boot();
    await openBeta(h);
    const whileSelected = vis('tasksRunBar');

    window.clearProjectSelection();
    await globalThis.__settle(2);
    return {whileSelected, afterClearing: vis('tasksRunBar')};
  },

  // An uninitialised project has no plan to run. The bar hides rather than
  // offering a Start that could only fail.
  async uninitialised_project_hides_the_bar() {
    const h = await boot();
    await openBeta(h);
    const withGoal = vis('tasksRunBar');

    const ws = currentSocket(h);
    ws.deliver('task_update', {goal: '', status: 'initialized', plan: {tasks: []}});
    await globalThis.__settle(2);
    return {withGoal, withoutGoal: vis('tasksRunBar')};
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
