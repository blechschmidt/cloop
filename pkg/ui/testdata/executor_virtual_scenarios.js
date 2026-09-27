// executor_virtual_scenarios.js — drives the virtual-executor dialog (Task
// 20345) in the real dashboard bundle: the device's USB inventory must reach
// the form, and what an admin ticks and types must reach the API as the spec
// the backend validates.
//
// Run by TestDashboard_VirtualExecutorDialog. Prints one JSON document.
//
// Usage: node executor_virtual_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const DEVICE = {
  id: 'sgx-dev', name: 'sgx', kind: 'remote', status: 'online', registered: true, enrolled: true,
  isolation: 'remote', sched_state: 'ready', schedulable: true, virtual_count: 1,
  capabilities: {supports_stream: true},
};
const VIRTUAL = {
  id: 'vx-abcdefghij', name: 'HSM sandbox', kind: 'virtual', status: 'online', registered: true,
  isolation: 'remote', sched_state: 'ready', schedulable: true,
  capabilities: {supports_stream: true, network_egress: true},
  sandbox: {mode: 'container', engine: 'docker', network: 'firewalled', configured: true},
  virtual: {parent_id: 'sgx-dev', parent_name: 'sgx', firewall: 'public Internet; deny 203.0.113.0/24',
    devices: ['yubihsm-0=usb 1050:0030']},
};
const PARENT_VIEW = {
  executor_id: 'sgx-dev', name: 'sgx', connected: true, protocol_version: 14, supported: true,
  engines: ['docker'], oci_runtimes: ['runc', 'runsc'], networks: ['none', 'bridge'],
  packet_filter: true, usb_live: false,
  usb_devices: [
    {port: 'usb1', bus: 1, dev: 1, vendor_id: '1d6b', product_id: '0002', class: '09', node: '/dev/bus/usb/001/001'},
    {port: '1-1', bus: 1, dev: 2, vendor_id: '1050', product_id: '0030', manufacturer: 'Yubico',
      product: 'YubiHSM', serial: '0031650425', node: '/dev/bus/usb/001/002'},
  ],
  virtual_executors: [],
};

async function boot() {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.states = {0: {goal: 'g', status: 'idle', plan: {goal: 'g', tasks: []}}};
  h.projects = {multi_project: false, stats: {total_projects: 1}, projects: []};
  // Longest prefix first; see domshim's fetch.
  h.routes['/api/executors/sgx-dev/virtuals'] = PARENT_VIEW;
  h.routes['/api/executors/vx-abcdefghij/virtual'] = {id: 'vx-abcdefghij', name: 'HSM sandbox'};
  h.routes['/api/executors'] = {executors: [DEVICE, VIRTUAL], policy: {}, ready: true};
  require(bundlePath);
  await globalThis.__settle(5);
  await window.loadExecutors();
  await globalThis.__settle(3);
  return h;
}

const el = id => document.getElementById(id);

const scenarios = {
  // The cards: the device offers the dialog, the virtual executor shows its
  // parent, firewall and devices and offers Edit rather than Revoke.
  async cards() {
    await boot();
    return {html: el('execList').innerHTML};
  },
  // The dialog lists the USB hardware, hubs excluded.
  async dialog() {
    await boot();
    window.openExecutorVirtual(0);
    await globalThis.__settle(4);
    return {html: el('evxBody').innerHTML};
  },
  // Ticking the YubiHSM and filling the firewall posts the spec the backend
  // expects.
  async create() {
    const h = await boot();
    window.openExecutorVirtual(0);
    await globalThis.__settle(4);
    el('evxName').value = 'HSM sandbox';
    el('evxEngine').value = 'docker';
    el('evxRuntime').value = 'runc';
    el('evxUsb0').checked = true;
    el('evxGroup').value = 'plugdev';
    el('evxFw').checked = true;
    el('evxPublic').checked = true;
    el('evxAllow').value = '10.8.0.0/24';
    el('evxDeny').value = '203.0.113.0/24\n198.51.100.7';
    el('evxPorts').value = '';
    el('evxDns').value = '1.1.1.1, 9.9.9.9';
    window.saveExecutorVirtual();
    await globalThis.__settle(4);
    const post = h.requests.filter(r => r.method === 'POST' && r.url.includes('/virtuals')).pop();
    return {body: post ? post.body : ''};
  },
};

(async () => {
  const out = {};
  for (const [name, fn] of Object.entries(scenarios)) {
    try {
      out[name] = await fn();
    } catch (err) {
      out[name] = {error: String((err && err.stack) || err)};
    }
  }
  process.stdout.write(JSON.stringify(out));
})();
