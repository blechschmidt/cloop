// boot_scenarios.js — what the dashboard requests on first paint (Task 20280).
//
// The landing page used to probe authentication with /api/state and only then
// request /api/projects from inside that promise. /api/state is scoped to the
// hub's own WorkDir when no project is selected, so the probe downloaded that
// project's whole task list — 734 KB for cloop — and in multi-project mode
// threw the body away unread. The projects list could not begin loading until
// that discarded transfer had finished.
//
// Asserted by running the real bundle rather than grepping it, because the
// property is about request order and which branch consumes a body: both are
// behaviour, and a text gate cannot see either.
//
// Usage: node boot_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const TASKS = [];
for (let i = 1; i <= 50; i++) {
  TASKS.push({id: i, title: 'task ' + i, status: 'done', priority: 1, description: 'x'.repeat(200)});
}

async function scenario(multi) {
  delete require.cache[require.resolve(shimPath)];
  require(shimPath);
  const h = globalThis.__harness;

  h.states = {0: {goal: 'g', status: 'running', plan: {goal: 'g', tasks: TASKS}}};
  h.projects = {
    multi_project: multi,
    stats: {},
    projects: multi
      ? [{name: 'cloop', path: '/p/cloop', total_tasks: 50},
         {name: 'sysmon', path: '/p/sysmon', total_tasks: 0}]
      : [{name: 'cloop', path: '/p/cloop', total_tasks: 50}],
  };

  // The bundle calls checkAuthAndInit() at the end of its own IIFE, so simply
  // loading it performs first paint.
  delete require.cache[require.resolve(bundlePath)];
  require(bundlePath);
  await globalThis.__settle(8);

  return {
    requests: h.requests.map(r => r.url),
    sockets: h.sockets.length,
  };
}

(async () => {
  const out = {};
  try {
    out.multi = await scenario(true);
  } catch (e) {
    out.multi = {error: String((e && e.stack) || e)};
  }
  try {
    out.single = await scenario(false);
  } catch (e) {
    out.single = {error: String((e && e.stack) || e)};
  }
  process.stdout.write(JSON.stringify(out));
})();
