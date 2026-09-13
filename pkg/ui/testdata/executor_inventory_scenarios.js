// executor_inventory_scenarios.js — renders the Executors panel against the
// real dashboard bundle to check that an edge device's build version and
// hardware inventory actually reach the page (Task 20230).
//
// Driving the bundle rather than grepping it matters especially here, because
// the defect being fixed was *exactly* a grep-invisible one: the backend had
// been sending the device's full capability advertisement in every
// /api/executors response for as long as remote executors existed, and the panel
// rendered none of it. Every field was present in the payload and absent from
// the page. A source-level gate asserting "the markup exists in 23-executors.js"
// would have passed throughout.
//
// Run by TestDashboard_ExecutorInventoryIsVisible. Each scenario returns
// {html, error} as one JSON document on stdout.
//
// Usage: node executor_inventory_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

// A device trailing the hub by two minor releases, with a full advertisement.
const STALE_DEVICE = {
  id: 'edge-stale',
  name: 'edge-stale',
  kind: 'remote',
  status: 'online',
  registered: true,
  enrolled: true,
  isolation: 'remote',
  sched_state: 'ready',
  schedulable: true,
  supports_revocation: true,
  capabilities: {supports_stream: true, supports_signal: true, network_egress: true},
  inventory: {
    agent_version: 'v0.1.0',
    agent_version_label: 'v0.1.0',
    os: 'linux',
    arch: 'arm64',
    cpus: 4,
    memory_mb: 7861,
    memory_label: '7.7 GB',
    harnesses: ['claude', 'codex'],
    container_runtimes: ['podman'],
    workdir_root: '/var/lib/cloop-executor/work',
    live: true,
  },
  version_skew: {
    skew: 'behind',
    material: true,
    hub_version: 'v0.3.0',
    note: 'This device runs v0.1.0, which materially trails the hub\'s v0.3.0. '
      + 'Copy the new cloop binary to the device and run '
      + '`cloop executor agent install --upgrade` there.',
  },
};

// A device on the hub's own build. Its inventory must still render — the chips
// are inventory, not a warning — but nothing may be flagged.
const CURRENT_DEVICE = {
  id: 'edge-current',
  name: 'edge-current',
  kind: 'remote',
  status: 'online',
  registered: true,
  enrolled: true,
  isolation: 'remote',
  sched_state: 'ready',
  schedulable: true,
  supports_revocation: true,
  capabilities: {supports_stream: true, supports_signal: true, network_egress: true},
  inventory: {
    agent_version: 'v0.3.0',
    agent_version_label: 'v0.3.0',
    os: 'linux',
    arch: 'amd64',
    cpus: 8,
    memory_label: '31.2 GB',
    harnesses: ['claude'],
    live: true,
  },
  version_skew: {skew: 'none', material: false, hub_version: 'v0.3.0'},
};

// An offline device whose numbers came from the stored row. Must be marked as
// last-known rather than presented as current.
const OFFLINE_DEVICE = {
  id: 'edge-offline',
  name: 'edge-offline',
  kind: 'remote',
  status: 'offline',
  registered: true,
  enrolled: true,
  isolation: 'remote',
  sched_state: 'unreachable',
  schedulable: false,
  supports_revocation: false,
  capabilities: {},
  inventory: {
    agent_version_label: 'legacy (pre-1 placeholder)',
    os: 'linux',
    arch: 'armv7',
    cpus: 2,
    memory_label: '1.0 GB',
    harnesses: ['claude'],
    live: false,
  },
  version_skew: {
    skew: 'legacy',
    material: true,
    hub_version: 'v0.3.0',
    note: 'This device reports the placeholder build version. '
      + 'Copy the new cloop binary to the device and run '
      + '`cloop executor agent install --upgrade` there.',
  },
};

// A container backend: it runs the hub's own binary, so it must render no
// device inventory and no skew warning at all.
const CONTAINER_BACKEND = {
  id: 'container',
  name: 'container',
  kind: 'container',
  status: 'online',
  registered: true,
  enrolled: false,
  isolation: 'container',
  sched_state: 'ready',
  schedulable: true,
  supports_revocation: true,
  capabilities: {supports_stream: true, supports_resource_limits: true},
};

function payload(executors) {
  return {executors: executors, policy: {}, ready: true};
}

async function boot(executors) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.states = {0: {goal: 'g', status: 'idle', plan: {goal: 'g', tasks: []}}};
  h.projects = {multi_project: false, stats: {total_projects: 1}, projects: []};
  h.routes['/api/executors'] = payload(executors);

  require(bundlePath);
  await globalThis.__settle(5);
  const ws = h.sockets[h.sockets.length - 1];
  if (ws) ws.open();
  await globalThis.__settle(3);

  // The panel loads lazily when its tab is shown; call it directly so the test
  // does not depend on tab-switching mechanics it is not checking.
  await window.loadExecutors();
  await globalThis.__settle(3);
  return h;
}

function listHTML() {
  const el = document.getElementById('execList');
  return (el && el.innerHTML) || '';
}

const scenarios = {
  // The core assertion: every advertised field is on the page.
  async stale_device() {
    await boot([STALE_DEVICE]);
    return {html: listHTML()};
  },
  // A uniform fleet must render inventory without any warning, so the panel is
  // not permanently alarming.
  async current_device() {
    await boot([CURRENT_DEVICE]);
    return {html: listHTML()};
  },
  // Stored inventory must be marked, not presented as live.
  async offline_device() {
    await boot([OFFLINE_DEVICE]);
    return {html: listHTML()};
  },
  // A local driver has no build of its own to compare.
  async container_backend() {
    await boot([CONTAINER_BACKEND]);
    return {html: listHTML()};
  },
};

(async () => {
  const out = {};
  for (const [name, fn] of Object.entries(scenarios)) {
    try {
      out[name] = await fn();
    } catch (err) {
      out[name] = {html: '', error: String((err && err.stack) || err)};
    }
  }
  process.stdout.write(JSON.stringify(out));
})();
