// scoping_scenarios.js — replays the navigation from Task 20197 against the
// real dashboard bundle.
//
//   "switching to the tasks page of a project, switching back to the projects
//    page and switching to the tasks page of another project [shows] the tasks
//    from another project"
//
// Run by TestDashboard_TasksNeverShowAnotherProject. Each scenario returns
// {name, selected, rendered} and the Go side asserts `rendered` holds only the
// selected project's task IDs. Printed as one JSON document on stdout.
//
// Usage: node scoping_scenarios.js <domshim.js> <bundle.js>

'use strict';

const path = process.argv[2];
const bundlePath = process.argv[3];

// Two projects whose task IDs do not overlap, so a leak is unambiguous: any
// 1xx ID rendered while beta is selected came from alpha.
const ALPHA = {
  goal: 'alpha goal',
  status: 'idle',
  plan: {goal: 'alpha goal', tasks: [
    {id: 101, title: 'alpha one',   status: 'pending', priority: 1},
    {id: 102, title: 'alpha two',   status: 'pending', priority: 2},
  ]},
};
const BETA = {
  goal: 'beta goal',
  status: 'idle',
  plan: {goal: 'beta goal', tasks: [
    {id: 201, title: 'beta one',   status: 'pending', priority: 1},
    {id: 202, title: 'beta two',   status: 'pending', priority: 2},
  ]},
};

const PROJECTS = {
  multi_project: true,
  stats: {total_projects: 2},
  projects: [
    {name: 'alpha', path: '/srv/alpha', goal: 'alpha goal', total_tasks: 2, done_tasks: 0, health: 'idle'},
    {name: 'beta',  path: '/srv/beta',  goal: 'beta goal',  total_tasks: 2, done_tasks: 0, health: 'idle'},
  ],
};

function clone(o) { return JSON.parse(JSON.stringify(o)); }

// boot loads a fresh shim + bundle pair and walks it to the Projects landing
// page, the state every scenario starts from. Each scenario gets its own
// module registry so bundle-level state (appState, selectedProjectIdx, the
// socket list) never leaks between them.
async function boot() {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(path);
  const h = globalThis.__harness;
  h.states = {0: clone(ALPHA), 1: clone(BETA)};
  h.projects = clone(PROJECTS);

  require(bundlePath);
  await globalThis.__settle(5);   // checkAuthAndInit's fetch chain

  // The landing socket carries no project_idx — the server resolves it to the
  // primary project, which is alpha.
  const ws0 = h.sockets[h.sockets.length - 1];
  ws0.open();
  return h;
}

function currentSocket(h) { return h.sockets[h.sockets.length - 1]; }

const scenarios = {
  // The report, step for step. The frame that leaks is the one the landing
  // socket was already sending when the user clicked into beta: the server
  // wrote alpha's state the moment that socket opened, and it lands after the
  // click. Nothing in the envelope says "alpha", so the client renders it.
  async reported_sequence() {
    const h = await boot();

    window.openProject(0, 'alpha');
    await globalThis.__settle();
    const wsAlpha = currentSocket(h);
    wsAlpha.open();
    wsAlpha.deliver('task_update', clone(ALPHA));
    window.switchTab('tasks');
    const alphaView = globalThis.__renderedTaskIds();

    window.clearProjectSelection();          // back to the projects page
    await globalThis.__settle();
    const wsLanding = currentSocket(h);      // unscoped again -> primary = alpha
    wsLanding.open();

    window.openProject(1, 'beta');           // straight into beta
    await globalThis.__settle();

    // Beta's own stream delivers first, so the tab legitimately holds beta.
    // Asserting on a populated list rather than an empty one is what keeps
    // this honest: a "fix" that merely blanked the panel would not pass.
    const wsBeta = currentSocket(h);
    wsBeta.open();
    wsBeta.deliver('task_update', clone(BETA));

    // ...and only then does alpha's in-flight frame land, on the socket the
    // bundle closed but the browser has not finished tearing down. Ordering
    // between two sockets is not guaranteed, and this is the order that
    // actually corrupts the view: the stray frame arrives last and wins.
    wsLanding.deliver('task_update', clone(ALPHA));

    window.switchTab('tasks');
    return {alphaView, selected: 'beta', rendered: globalThis.__renderedTaskIds()};
  },

  // Same shape, one hop shorter: alpha's own socket is closed by the switch
  // but still delivers. This is the interleaving that survives even when the
  // landing page is skipped (project selector dropdown instead of Back).
  async stale_socket_task_update() {
    const h = await boot();

    window.openProject(0, 'alpha');
    await globalThis.__settle();
    const wsAlpha = currentSocket(h);
    wsAlpha.open();
    wsAlpha.deliver('task_update', clone(ALPHA));
    window.switchTab('tasks');

    window.selectProjectFromDropdown(1, 'beta');
    await globalThis.__settle();
    const wsBeta = currentSocket(h);
    wsBeta.open();
    wsBeta.deliver('task_update', clone(BETA));

    wsAlpha.deliver('task_update', clone(ALPHA));   // late frame, alpha's room

    window.switchTab('tasks');
    return {selected: 'beta', rendered: globalThis.__renderedTaskIds()};
  },

  // A delta, not a snapshot: alpha's watcher pushes a state_diff adding a task
  // after the switch. applyStateDiff merges into whatever appState holds, so a
  // leak here splices alpha's task into beta's list rather than replacing it —
  // the "sometimes I see one extra task" version of the same report.
  async stale_socket_state_diff() {
    const h = await boot();

    window.openProject(0, 'alpha');
    await globalThis.__settle();
    const wsAlpha = currentSocket(h);
    wsAlpha.open();
    wsAlpha.deliver('task_update', clone(ALPHA));

    window.selectProjectFromDropdown(1, 'beta');
    await globalThis.__settle();
    const wsBeta = currentSocket(h);
    wsBeta.open();
    wsBeta.deliver('task_update', clone(BETA));

    wsAlpha.deliver('state_diff', {
      tasks_added: [{id: 103, title: 'alpha three', status: 'pending', priority: 1}],
    });

    window.switchTab('tasks');
    return {selected: 'beta', rendered: globalThis.__renderedTaskIds()};
  },

  // The reverse direction: opening a project must not leave the previous
  // project's rows on screen while the new state is still in flight. A stale
  // list that is never corrected is the same bug from the user's side.
  async no_stale_rows_before_first_frame() {
    const h = await boot();

    window.openProject(0, 'alpha');
    await globalThis.__settle();
    const wsAlpha = currentSocket(h);
    wsAlpha.open();
    wsAlpha.deliver('task_update', clone(ALPHA));
    window.switchTab('tasks');

    window.selectProjectFromDropdown(1, 'beta');
    await globalThis.__settle();
    window.switchTab('tasks');               // beta's frame has not arrived yet

    return {selected: 'beta (awaiting first frame)', rendered: globalThis.__renderedTaskIds()};
  },

  // The legacy full-state envelopes take the same path as task_update and are
  // just as unlabelled, so they get the same guard.
  async stale_socket_legacy_envelopes() {
    const h = await boot();

    window.openProject(0, 'alpha');
    await globalThis.__settle();
    const wsAlpha = currentSocket(h);
    wsAlpha.open();
    wsAlpha.deliver('task_update', clone(ALPHA));

    window.selectProjectFromDropdown(1, 'beta');
    await globalThis.__settle();
    const wsBeta = currentSocket(h);
    wsBeta.open();
    wsBeta.deliver('task_update', clone(BETA));

    wsAlpha.deliver('task_added',    {state: clone(ALPHA)});
    wsAlpha.deliver('task_deleted',  {state: clone(ALPHA)});
    wsAlpha.deliver('task_mutation', {state: clone(ALPHA)});

    window.switchTab('tasks');
    return {selected: 'beta', rendered: globalThis.__renderedTaskIds()};
  },

  // Single-project mode has no index to compare against; the guard must not
  // turn into a filter that drops every frame and leaves the tab empty.
  async single_project_still_renders() {
    for (const k of Object.keys(require.cache)) delete require.cache[k];
    require(path);
    const h = globalThis.__harness;
    h.states = {0: clone(ALPHA)};
    h.projects = {multi_project: false, stats: {}, projects: [
      {name: 'alpha', path: '/srv/alpha', goal: 'alpha goal', total_tasks: 2, done_tasks: 0, health: 'idle'},
    ]};
    require(bundlePath);
    await globalThis.__settle(5);

    const ws = currentSocket(h);
    ws.open();
    ws.deliver('task_update', clone(ALPHA));
    window.switchTab('tasks');
    return {selected: 'alpha (single-project)', rendered: globalThis.__renderedTaskIds()};
  },

  // The live socket must keep working after the switch, or the fix would trade
  // a leak for a dead panel: beta's own updates still have to land.
  async current_socket_keeps_updating() {
    const h = await boot();

    window.openProject(0, 'alpha');
    await globalThis.__settle();
    currentSocket(h).open();
    currentSocket(h).deliver('task_update', clone(ALPHA));

    window.selectProjectFromDropdown(1, 'beta');
    await globalThis.__settle();
    const wsBeta = currentSocket(h);
    wsBeta.open();
    wsBeta.deliver('task_update', clone(BETA));
    wsBeta.deliver('state_diff', {
      tasks_added: [{id: 203, title: 'beta three', status: 'pending', priority: 1}],
    });

    window.switchTab('tasks');
    return {selected: 'beta', rendered: globalThis.__renderedTaskIds()};
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
  process.stdout.write(JSON.stringify(out, null, 2));
})();
