// deeplink_scenarios.js — drives the real dashboard bundle through the link
// `cloop remote init` prints, /?project=<path> (Task 20417).
//
// Run by TestDashboard_OpensTheProjectALinkNames. Each scenario returns a
// plain object; the Go side asserts on it. Printed as one JSON document.
//
// Usage: node deeplink_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

function payload() {
  const mk = (name) => ({name, path: '/srv/projects/' + name, goal: 'goal of ' + name, total_tasks: 0,
    done_tasks: 0, failed_tasks: 0, health: 'idle', has_project: true});
  return {multi_project: true, stats: {total_projects: 3}, projects: [mk('alpha'), mk('beta'), mk('gamma')]};
}

async function boot(search) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.projects = payload();
  h.states = {0: {goal: '', status: 'idle', plan: {goal: '', tasks: []}},
    1: {goal: 'goal of beta', status: 'idle', plan: {goal: 'goal of beta', tasks: []}}};
  location.search = search;
  const replaced = [];
  globalThis.history = {replaceState: (state, title, url) => replaced.push(url)};
  require(bundlePath);
  await globalThis.__settle(5);
  const crumb = document.getElementById('breadcrumbName');
  return {opened: crumb ? String(crumb.textContent || '') : '', replaced};
}

const scenarios = {
  // The link names the second project: it is opened, and the query dropped.
  opensTheNamedProject: async () => boot('?project=' + encodeURIComponent('/srv/projects/beta')),
  // A path the list does not hold opens nothing, and the query still goes.
  ignoresAnUnknownProject: async () => boot('?project=' + encodeURIComponent('/srv/projects/nope')),
  // No link: nothing opened, nothing rewritten.
  noLink: async () => boot(''),
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
})();
