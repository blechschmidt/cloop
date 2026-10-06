// quarantine_scenarios.js — opens the task details of a task quarantined as a
// suspected node killer against the real dashboard bundle (Task 20391).
//
// Run by TestDashboard_QuarantineIsShownInTaskDetails. Each scenario returns
// {html, error}; the Go side asserts on the markup. Printed as one JSON
// document on stdout.
//
// Usage: node quarantine_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const SUSPECT = {
  id: 7, title: 'Allocate until the kernel gives up', status: 'failed', priority: 1,
  result: 'suspected node killer: 2 distinct executors went unreachable while this task was running',
  quarantine: {
    kind: 'node_killer',
    reason: 'suspected node killer',
    marked_at: '2026-10-06T12:04:00Z',
    marked_by: 'failover',
    nodes: [
      {executor_id: 'sgx', lost_at: '2026-10-06T12:00:00Z', session_id: 's1'},
      {executor_id: 'edge-<b>2</b>', lost_at: '2026-10-06T12:03:00Z', session_id: 's2'},
      {executor_id: 'sgx', lost_at: '2026-10-06T12:06:00Z', session_id: 's3'},
    ],
  },
};
// Control: an ordinary failed task.
const ORDINARY = {id: 8, title: 'Flaky test', status: 'failed', priority: 2, result: 'tests failed'};

const PROJECT = {
  goal: 'g', status: 'idle',
  plan: {goal: 'g', tasks: [SUSPECT, ORDINARY]},
};

function clone(o) { return JSON.parse(JSON.stringify(o)); }

async function boot() {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.states = {0: clone(PROJECT)};
  h.projects = {multi_project: false, stats: {total_projects: 1}, projects: []};
  h.routes['/api/tasks/7/details'] = {ok: true, task: clone(SUSPECT)};
  h.routes['/api/tasks/8/details'] = {ok: true, task: clone(ORDINARY)};
  require(bundlePath);
  await globalThis.__settle(5);
  const ws = h.sockets[h.sockets.length - 1];
  if (ws) ws.open();
  await globalThis.__settle(3);
  return h;
}

async function details(id) {
  await boot();
  window.openTaskDetails(id);
  await globalThis.__settle(6);
  return {html: document.getElementById('td-body').innerHTML || ''};
}

const scenarios = {
  suspect: () => details(7),
  ordinary: () => details(8),
};

(async () => {
  const out = {};
  for (const [name, fn] of Object.entries(scenarios)) {
    try {
      out[name] = await fn();
    } catch (e) {
      out[name] = {html: '', error: String((e && e.stack) || e)};
    }
  }
  process.stdout.write(JSON.stringify(out));
})();
