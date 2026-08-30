// background_scenarios.js — renders tasks carrying background work against the
// real dashboard bundle (Task 20205).
//
// The thing being checked is that an operator can tell, from the task list
// alone, that a task's agent left work running — because when it did, the task
// is not finished no matter what its status says, and the tasks after it are
// probably reading a half-written artifact.
//
// Run by TestDashboard_BackgroundWorkIsVisible. Each scenario returns
// {html, ids, error} and the Go side asserts on the markup. Printed as one
// JSON document on stdout.
//
// Usage: node background_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

// One project, four tasks, one per background state plus a control. The
// control is what proves the badge is driven by the data rather than always
// present.
const PROJECT = {
  goal: 'train and ship a model',
  status: 'running',
  plan: {
    goal: 'train and ship a model',
    tasks: [
      {
        id: 48, title: 'Train the model', status: 'in_progress', priority: 1,
        background: {
          state: 'waiting', detected: 2, commands: ['python3', 'tee'],
          detected_at: '2026-08-30T10:00:00Z',
        },
      },
      {
        id: 49, title: 'Evaluate the model', status: 'failed', priority: 1,
        background: {
          state: 'abandoned', detected: 1, commands: ['train.py'],
          waited_seconds: 1800, terminated: 1, detected_at: '2026-08-30T10:00:00Z',
        },
      },
      {
        id: 50, title: 'Export the model', status: 'done', priority: 2,
        background: {
          state: 'drained', detected: 1, commands: ['make'],
          waited_seconds: 95, detected_at: '2026-08-30T10:00:00Z',
        },
      },
      // Control: an ordinary task with no background work at all.
      {id: 51, title: 'Publish metrics', status: 'pending', priority: 2},
    ],
  },
};

function clone(o) { return JSON.parse(JSON.stringify(o)); }

async function boot() {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.states = {0: clone(PROJECT)};
  h.projects = {multi_project: false, stats: {total_projects: 1}, projects: []};

  require(bundlePath);
  await globalThis.__settle(5);
  const ws = h.sockets[h.sockets.length - 1];
  if (ws) ws.open();
  await globalThis.__settle(3);
  return h;
}

function taskListHTML() {
  return document.getElementById('taskListFull').innerHTML || '';
}

const scenarios = {
  // Every state must be legible in the list the user actually looks at.
  async task_list() {
    await boot();
    // Completed tasks are hidden by default, and one of the fixtures is done.
    if (typeof window.toggleCompletedTasks === 'function') {
      window.toggleCompletedTasks();
      await globalThis.__settle(2);
    }
    window.switchTab('tasks');
    await globalThis.__settle(3);
    return {html: taskListHTML(), ids: globalThis.__renderedTaskIds()};
  },
};

(async () => {
  const out = {};
  for (const [name, fn] of Object.entries(scenarios)) {
    try {
      out[name] = await fn();
    } catch (e) {
      out[name] = {html: '', ids: [], error: String((e && e.stack) || e)};
    }
  }
  process.stdout.write(JSON.stringify(out));
})();
