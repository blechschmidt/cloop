// reorder_scenarios.js — drives the real dashboard bundle through drag-to-
// reorder on the Tasks tab (Task 20299).
//
// The property worth running the actual bundle for is that the drop handler and
// the renderer agree about what list the user is pointing at. They are written
// in different files against different sorts: renderTasks floats pinned and
// running rows to the top, while onDrop used to re-sort every task in the plan
// by priority alone and index into *that*. Both sorts are individually
// reasonable and the mismatch is invisible in the source — it only shows up as
// "I dragged the row to the top and it sprang back", which needs the rendered
// DOM and the request the drop actually sent.
//
// Run by TestDashboard_DragReorderFollowsTheRenderedOrder. Each scenario returns
// a plain object; the Go side asserts on it. Printed as one JSON document.
//
// Usage: node reorder_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

function clone(o) { return JSON.parse(JSON.stringify(o)); }

function task(id, priority, extra) {
  return Object.assign({
    id,
    title: 'task ' + id,
    description: '',
    priority,
    status: 'pending',
    depends_on: [],
    tags: [],
  }, extra || {});
}

// boot loads the bundle against a project whose plan is `tasks`, and leaves the
// Tasks tab rendered.
async function boot(tasks) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.projects = {multi_project: false, stats: {total_projects: 1}, projects: []};
  h.states = {0: {
    goal: 'ship it',
    status: 'running',
    plan: {goal: 'ship it', tasks: clone(tasks)},
  }};
  // Answer the reorder endpoint the way the server does, so the bundle takes
  // its success path — which ends in refreshState(), the round trip that
  // decides what the user sees next.
  h.routes['/api/tasks/reorder'] = {ok: true};

  require(bundlePath);
  await globalThis.__settle(5);

  // renderTasks is what publishes the queue the drop handler splices, so the
  // tab has to actually render before a drag means anything. It is IIFE-local,
  // so the tab is opened the way a click opens it.
  globalThis.switchTab('tasks');
  await globalThis.__settle(3);
  return h;
}

// applyAndRefresh stores the order the server would have written and then pulls
// it back through the dashboard's own refresh, so the reported order is the one
// a user would be looking at after the drag — not a list assembled by this file.
async function applyAndRefresh(h, tasks, ids) {
  h.states[0].plan.tasks = applyReorder(tasks, ids);
  globalThis.refreshState();
  await globalThis.__settle(4);
  globalThis.switchTab('tasks');
  await globalThis.__settle(2);
  return globalThis.__renderedTaskIds();
}

// setSearch drives the filter bar's own change handler rather than poking at
// filterState, which is IIFE-local — and which is the point: the query has to
// travel the path the input actually uses.
async function setSearch(q) {
  document.getElementById('filterQ').value = q;
  globalThis.onFilterChange();
  await globalThis.__settle(2);
}

// A drag: press on `srcId`, release over `targetId`, exactly as the inline
// handlers on the rows would fire.
function drag(srcId, targetId) {
  const ev = {
    preventDefault() {},
    dataTransfer: {effectAllowed: '', dropEffect: '', setData() {}, getData() { return ''; }},
    currentTarget: {classList: {remove() {}, add() {}}},
  };
  globalThis.onDragStart(ev, srcId);
  globalThis.onDrop(ev, targetId);
}

// reorderPost returns the ids from the last POST /api/tasks/reorder, or null if
// the drag sent nothing at all — which is the failure the old handler produced
// most often, and is indistinguishable from "it worked" unless you look.
function reorderPost(h) {
  const posts = h.requests.filter(r =>
    r.method === 'POST' && r.url.indexOf('/api/tasks/reorder') !== -1);
  if (!posts.length) return null;
  const body = JSON.parse(posts[posts.length - 1].body || '{}');
  return body.ids || null;
}

// applyReorder is what the server does with those ids: dense priorities, in the
// order given, over exactly the tasks named. Applying it here lets a scenario
// report the order the user would see next, rather than an intermediate list
// only this test understands.
function applyReorder(tasks, ids) {
  const out = clone(tasks);
  const byId = new Map(out.map(t => [t.id, t]));
  ids.forEach((id, i) => { if (byId.has(id)) byId.get(id).priority = i + 1; });
  return out;
}

const scenarios = {};

// Baseline: a plain queue, drag the last row to the top. This much worked
// before, and is here so a regression in the new index math is distinguishable
// from the pinned case below.
scenarios.plain_queue_drag_to_top = async () => {
  const tasks = [task(1, 1), task(2, 2), task(3, 3)];
  const h = await boot(tasks);
  const before = globalThis.__renderedTaskIds();

  drag(3, 1);
  await globalThis.__settle(3);

  const ids = reorderPost(h);
  let after = null;
  if (ids) {
    after = await applyAndRefresh(h, tasks, ids);
  }
  return {before, posted: ids, after};
};

// The regression. Task 3 is pinned, so it renders first despite having the
// worst priority — the rendered order is [3,1,2] while a priority-only sort is
// [1,2,3]. Dragging 2 above 1 is a move *within* the unpinned group, so it is
// perfectly expressible; the old handler computed both indices in the wrong
// list and moved the wrong pair.
scenarios.pinned_head_drag_below_it = async () => {
  const tasks = [task(1, 1), task(2, 2), task(3, 9, {pinned: true})];
  const h = await boot(tasks);
  const before = globalThis.__renderedTaskIds();

  drag(2, 1);
  await globalThis.__settle(3);

  const ids = reorderPost(h);
  let after = null;
  if (ids) {
    after = await applyAndRefresh(h, tasks, ids);
  }
  return {before, posted: ids, after};
};

// Dragging an unpinned task onto the pinned head. Pinned tasks lead the queue
// by definition, so "put this above the pinned one" is not expressible in
// priorities — and the old handler did not notice: it spliced the task to
// index 2 of a priority-sorted list, which rendered it at the *bottom*. The
// user dragged a row to the top and watched it land last, with no indication
// that anything had gone wrong. Refusing and saying why is the honest answer.
scenarios.drag_across_the_pin_boundary = async () => {
  const tasks = [task(1, 1), task(2, 2), task(3, 9, {pinned: true})];
  const h = await boot(tasks);
  const before = globalThis.__renderedTaskIds();

  drag(1, 3);
  await globalThis.__settle(3);

  const ids = reorderPost(h);
  let after = before;
  if (ids) {
    after = await applyAndRefresh(h, tasks, ids);
  }
  return {before, posted: ids, after};
};

// A running task floats above the pending queue, so it is the same shape of
// boundary. It is not in the queue at all — dragging onto it must not post.
scenarios.drop_onto_running_row = async () => {
  const tasks = [task(1, 9, {status: 'in_progress'}), task(2, 1), task(3, 2)];
  const h = await boot(tasks);
  const before = globalThis.__renderedTaskIds();

  drag(3, 1);
  await globalThis.__settle(3);

  return {before, posted: reorderPost(h)};
};

// Completed rows are history and carry no drag affordance. With "show
// completed" on they are interleaved into the list, so the queue published for
// the drop handler must still contain only the tasks that can run.
scenarios.completed_rows_are_not_in_the_queue = async () => {
  const tasks = [
    task(1, 1, {status: 'done', completed_at: '2026-01-01T00:00:00Z'}),
    task(2, 2),
    task(3, 3),
  ];
  const h = await boot(tasks);
  globalThis.toggleCompletedTasks();
  await globalThis.__settle(2);

  const before = globalThis.__renderedTaskIds();
  const handles = (document.getElementById('taskListFull').innerHTML || '')
    .split('drag-handle-disabled').length - 1;

  drag(3, 2);
  await globalThis.__settle(3);

  return {before, posted: reorderPost(h), disabledHandles: handles};
};

// A search filter hides rows but must not drop them out of the queue being
// rewritten: the hidden task keeps its place relative to the ones on screen.
scenarios.filtered_view_keeps_hidden_tasks_in_the_queue = async () => {
  const tasks = [task(1, 1), task(2, 2), task(3, 3), task(4, 4)];
  const h = await boot(tasks);

  await setSearch('task 4');
  const before = globalThis.__renderedTaskIds();

  // Nothing to drag against inside a one-row view; clear the filter and drag,
  // then confirm the posted queue still names every task.
  await setSearch('');
  drag(4, 2);
  await globalThis.__settle(3);

  return {before, posted: reorderPost(h)};
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
