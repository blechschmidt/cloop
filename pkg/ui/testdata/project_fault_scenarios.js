// project_fault_scenarios.js — drives the real dashboard bundle through
// projects the hub could not load (Task 20254).
//
// The bug these cover is one of indistinguishability. A project whose state.db
// will not open arrives with total_tasks 0, done_tasks 0, health "unknown" and
// an empty goal — which is byte-for-byte what a freshly initialised project
// with nothing in it looks like. On 2026-09-14 a schema skew refused all 18
// databases at once and the dashboard rendered 18 perfectly ordinary cards, so
// the reported symptom was "project state is broken and tasks are not shown"
// rather than anything naming a database.
//
// Whether the fault is visible is a property of the rendered DOM, so these run
// the bundle in node and read back what a user would see.
//
// Run by TestDashboard_SurfacesProjectsThatWillNotLoad. Each scenario returns a
// plain object; the Go side asserts on it. Printed as one JSON document.
//
// Usage: node project_fault_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const SKEW = 'statedb: database schema is newer than this binary: database is at ' +
             'schema version 34 but this binary carries 33';

function mk(name, extra) {
  return Object.assign({
    name,
    path: '/srv/' + name,
    goal: '',
    total_tasks: 0,
    done_tasks: 0,
    failed_tasks: 0,
    health: 'unknown',
    has_project: false,
  }, extra || {});
}

function payload(projects) {
  return {multi_project: true, stats: {total_projects: projects.length}, projects};
}

function clone(o) { return JSON.parse(JSON.stringify(o)); }

async function boot(p) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.projects = clone(p);
  h.states = {0: {goal: '', status: 'idle', plan: {goal: '', tasks: []}}};

  require(bundlePath);
  await globalThis.__settle(5);
  return h;
}

function banner() {
  const el = document.getElementById('projFaultBanner');
  return {
    shown: el.style.display !== 'none',
    html: el.innerHTML || '',
    text: String(el.innerHTML || '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim(),
  };
}

function gridHTML() {
  return document.getElementById('projList').innerHTML || '';
}

const scenarios = {
  // The outage: every project refused for the same reason. The banner must
  // say so, and must group rather than repeat the message 18 times.
  allFaultedForTheSameReason: async () => {
    await boot(payload([
      mk('alpha', {error: SKEW}),
      mk('beta', {error: SKEW}),
      mk('gamma', {error: SKEW}),
    ]));
    const b = banner();
    return {
      shown: b.shown,
      text: b.text,
      occurrences: (b.html.match(/schema version 34/g) || []).length,
      gridSaysCouldNotLoad: (gridHTML().match(/could not be loaded/g) || []).length,
    };
  },

  // The healthy case. A dashboard that cries wolf on every load is one nobody
  // reads, so an ordinary payload must leave the banner hidden.
  noFaults: async () => {
    await boot(payload([
      mk('alpha', {goal: 'ship it', total_tasks: 3, done_tasks: 1, health: 'idle', has_project: true}),
      mk('beta', {goal: 'also ship it', total_tasks: 2, done_tasks: 2, health: 'complete', has_project: true}),
    ]));
    const b = banner();
    return {shown: b.shown, text: b.text, gridSaysCouldNotLoad: (gridHTML().match(/could not be loaded/g) || []).length};
  },

  // An uninitialised directory is not a fault. It is the normal state of a
  // just-registered path and must not raise an alarm.
  emptyProjectIsNotAFault: async () => {
    await boot(payload([mk('brand-new')]));
    const b = banner();
    return {shown: b.shown, gridSaysNoGoal: gridHTML().includes('no goal set')};
  },

  // Two different causes must stay distinguishable: one is a deployment
  // problem, the other is a single project's problem.
  distinctFaultsAreListedSeparately: async () => {
    await boot(payload([
      mk('alpha', {error: SKEW}),
      mk('beta', {error: 'permission denied'}),
      mk('gamma', {goal: 'fine', total_tasks: 1, has_project: true}),
    ]));
    const b = banner();
    return {
      shown: b.shown,
      text: b.text,
      mentionsSkew: b.text.includes('schema version 34'),
      mentionsDenied: b.text.includes('permission denied'),
      countsTwo: b.text.includes('2 projects'),
    };
  },

  // The message originates server-side and contains a filesystem path, so it
  // reaches innerHTML. It must arrive as text, not as markup.
  faultTextIsEscaped: async () => {
    await boot(payload([
      mk('evil<img src=x onerror=alert(1)>', {error: '<script>alert(1)</script> broke'}),
    ]));
    const b = banner();
    return {
      shown: b.shown,
      rawScriptTag: b.html.includes('<script>'),
      rawImgTag: b.html.includes('<img src=x'),
      escapedSomething: b.html.includes('&lt;'),
    };
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
