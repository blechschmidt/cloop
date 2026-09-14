// executor_detail_scenarios.js — drives the real dashboard bundle through the
// executor detail drill-in (Task 20258).
//
// GET /api/executors/{id} had computed the fleet's audit answer since Task
// 20244 — in-flight work, recent completions with project attribution, sweep
// coverage, and host_total — and no frontend code called it. A grep gate over
// 23-executors.js could only have asserted that some markup exists; it could
// not have caught the defect that mattered (nobody calls the endpoint), and it
// cannot assert the thing this panel has to get right: that "we found no host
// runs" and "we could not look" never render the same way.
//
// So the bundle is executed. Each scenario boots it, opens the drill-in, and
// returns the rendered HTML for the Go test to assert on.
//
// Run by TestDashboard_ExecutorDetailIsAuditable. Output is one JSON document
// on stdout: {scenario: {html, list, error}}.
//
// Usage: node executor_detail_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const EXEC_ID = 'edge-1';

// The card the operator clicks. Kind and status are incidental here; what
// matters is that it is addressable by index.
const EXECUTOR = {
  id: EXEC_ID,
  name: 'edge-1',
  kind: 'remote',
  status: 'online',
  registered: true,
  enrolled: true,
  isolation: 'remote',
  sched_state: 'ready',
  schedulable: true,
  supports_revocation: true,
  capabilities: {supports_stream: true, network_egress: true},
};

// Two projects the browser knows about, so a completion can link back to one
// of them — and one in the sweep that is absent from this list, which is the
// case a naive index-based link would send the operator to the wrong project.
const PROJECTS = [
  {name: 'alpha', path: '/srv/alpha', health: 'idle', status: 'idle'},
  {name: 'beta', path: '/srv/beta', health: 'running', status: 'running'},
];

const HOUR_AGO = new Date(Date.now() - 3600e3).toISOString();
const NOW = new Date().toISOString();

function ref(over) {
  return Object.assign({
    project_name: 'alpha',
    project_path: '/srv/alpha',
    id: 1,
    title: 'a task',
    status: 'done',
    isolation: 'remote',
    on_host: false,
    started_at: HOUR_AGO,
    completed_at: NOW,
  }, over || {});
}

function detail(workload) {
  return Object.assign({}, EXECUTOR, {
    last_heartbeat: NOW,
    last_seen: NOW,
    projects: ['/srv/alpha'],
    workload: Object.assign({
      in_flight: [],
      completed: [],
      completed_total: 0,
      host_total: 0,
      not_running: 0,
      projects_scanned: 2,
      projects_truncated: false,
    }, workload || {}),
  });
}

// boot loads the bundle against a fresh shim and opens the drill-in for card 0.
//
// detailBody may be a response body or, with `status`, a refusal — the two
// differ in how the bundle's parseAPIResponse routes them, and the panel has to
// land in the same honest state either way.
async function boot(detailBody, status) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.states = {0: {goal: 'g', status: 'idle', plan: {goal: 'g', tasks: []}}};
  h.projects = {multi_project: true, stats: {total_projects: 2}, projects: PROJECTS};

  // Longer prefix first: the shim matches in insertion order, so registering
  // '/api/executors' first would swallow the detail request.
  h.routes['/api/executors/' + EXEC_ID] = detailBody;
  h.routes['/api/executors'] = {executors: [EXECUTOR], policy: {}, ready: true};
  if (status) h.routeStatus['/api/executors/' + EXEC_ID] = status;

  require(bundlePath);
  await globalThis.__settle(5);
  const ws = h.sockets[h.sockets.length - 1];
  if (ws) ws.open();
  await globalThis.__settle(3);

  await window.loadExecutors();
  await globalThis.__settle(3);
  window.openExecutorDetail(0);
  await globalThis.__settle(5);
  return h;
}

function out() {
  return {
    html: (document.getElementById('execDetailBody') || {}).innerHTML || '',
    list: (document.getElementById('execList') || {}).innerHTML || '',
    overlay: ((document.getElementById('executor-detail-overlay') || {}).style || {}).display || '',
    requests: globalThis.__harness.requests.map(r => r.url),
  };
}

const scenarios = {
  // The finding. An executor that ran work on the hub's own machine must say
  // so in words, not leave a 3 in a counter for someone to notice.
  async host_runs() {
    await boot(detail({
      host_total: 2,
      completed_total: 2,
      completed: [
        ref({id: 11, title: 'ran on the host', isolation: 'none', on_host: true}),
        ref({id: 12, title: 'also on the host', isolation: 'none', on_host: true,
             project_name: 'beta', project_path: '/srv/beta'}),
      ],
    }));
    return out();
  },

  // The clean case. A complete sweep that found nothing is the only state that
  // earns an affirmative claim.
  async clean() {
    await boot(detail({
      completed_total: 1,
      completed: [ref({id: 5, title: 'ran in a sandbox'})],
    }));
    return out();
  },

  // A capped sweep. host_total is 0 here exactly as in `clean`, and the panel
  // must not make the same claim: the projects past the cap were never read.
  async truncated() {
    await boot(detail({
      projects_scanned: 200,
      projects_truncated: true,
      completed_total: 1,
      completed: [ref({id: 5, title: 'ran in a sandbox'})],
    }));
    return out();
  },

  // A sweep that read nothing. Not a synthetic case: a hub whose projects have
  // no plan yet — a fresh one, or one whose project directories moved — skips
  // every project silently and reports host_total 0 with projects_scanned 0.
  // Observed against a live `cloop ui`, which is how it was found.
  async nothing_scanned() {
    await boot(detail({projects_scanned: 0}));
    return out();
  },

  // In-flight work, plus the completed cap: 25 rows out of 400 must not read
  // as 25 tasks.
  async in_flight_and_cap() {
    const completed = [];
    for (let i = 0; i < 25; i++) {
      completed.push(ref({id: 100 + i, title: 'completed ' + i}));
    }
    await boot(detail({
      in_flight: [ref({id: 9, title: 'running right now', status: 'in_progress',
                       completed_at: null, project_name: 'beta', project_path: '/srv/beta'})],
      completed: completed,
      completed_total: 400,
      not_running: 3,
    }));
    return out();
  },

  // A row whose project the browser does not have. Clicking it must refuse
  // rather than navigate to whatever sits at some index.
  async unknown_project_link() {
    await boot(detail({
      completed_total: 1,
      completed: [ref({id: 77, title: 'in a project you cannot see',
                       project_name: 'gamma', project_path: '/srv/gamma'})],
    }));
    window.openExecutorTaskRef(0);
    await globalThis.__settle(3);
    const r = out();
    r.toast = (document.getElementById('toast') || {}).textContent || '';
    // openProject writes the project name into the breadcrumb, so an empty one
    // is the observable proof that no navigation happened.
    r.breadcrumb = (document.getElementById('breadcrumbName') || {}).textContent || '';
    return r;
  },

  // A row the browser can resolve: it navigates, and the task detail request
  // is scoped to that project's index rather than whichever was selected.
  async known_project_link() {
    const h = await boot(detail({
      completed_total: 1,
      completed: [ref({id: 42, title: 'in beta',
                       project_name: 'beta', project_path: '/srv/beta'})],
    }));
    h.requests.length = 0;
    window.openExecutorTaskRef(0);
    await globalThis.__settle(5);
    const r = out();
    r.requests = h.requests.map(x => x.url);
    r.breadcrumb = (document.getElementById('breadcrumbName') || {}).textContent || '';
    return r;
  },

  // Withheld existence: require() answers 404 rather than confirming an
  // executor the caller may not read. The body carries the error and the
  // status is not one parseAPIResponse diverts, so this lands in .then().
  async not_found() {
    await boot({error: {code: 'NOT_FOUND', message: 'the requested resource does not exist'}}, 404);
    return out();
  },

  // The other refusal shape: 403 rejects the promise inside parseAPIResponse,
  // so the panel never sees a body at all. A renderer that only handled an
  // error body would leave "Loading…" on screen forever.
  async forbidden() {
    await boot({error: {code: 'FORBIDDEN', message: 'your role does not permit this action',
                        details: {required_permission: 'executor.read'}}}, 403);
    return out();
  },
};

(async () => {
  const result = {};
  for (const [name, fn] of Object.entries(scenarios)) {
    try {
      result[name] = await fn();
    } catch (err) {
      result[name] = {html: '', list: '', error: String((err && err.stack) || err)};
    }
  }
  process.stdout.write(JSON.stringify(result));
})();
