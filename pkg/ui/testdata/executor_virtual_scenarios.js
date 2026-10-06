// executor_virtual_scenarios.js — drives the virtual-executor dialog (Task
// 20345) in the real dashboard bundle: the device's USB inventory must reach
// the form, and what an admin ticks and types must reach the API as the spec
// the backend validates. Since Task 20356 the network is one choice — none,
// firewalled or unfiltered — and the firewall rules are sent, shown and read
// back as a sentence only under Firewalled.
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
  agent_capabilities: {usb_devices: [
    {port: 'usb1', class: '09', vendor_id: '1d6b', product_id: '0002', node: '/dev/bus/usb/001/001'},
    {port: '1-1', vendor_id: '1050', product_id: '0030', manufacturer: 'Yubico', product: 'YubiHSM',
      serial: '0031650425', node: '/dev/bus/usb/001/002'},
  ]},
};
const VIRTUAL = {
  id: 'vx-abcdefghij', name: 'HSM sandbox', kind: 'virtual', status: 'online', registered: true,
  isolation: 'remote', sched_state: 'ready', schedulable: true,
  capabilities: {supports_stream: true, network_egress: true},
  sandbox: {mode: 'container', engine: 'docker', network: 'firewalled', configured: true},
  virtual: {parent_id: 'sgx-dev', parent_name: 'sgx', firewall: 'public Internet; deny 203.0.113.0/24',
    devices: ['yubihsm-0=usb 1050:0030']},
};
// Two more virtual executors on the same device, one per remaining network
// access, so each card's chip can be read.
const VX_OPEN = {
  id: 'vx-openopenop', name: 'Lab bench', kind: 'virtual', status: 'online', registered: true,
  isolation: 'remote', sched_state: 'ready', schedulable: true, capabilities: {supports_stream: true},
  sandbox: {mode: 'container', engine: 'docker', network: 'lab-net', configured: true},
  virtual: {parent_id: 'sgx-dev', parent_name: 'sgx'},
};
const VX_NONE = {
  id: 'vx-nonenonen', name: 'Offline box', kind: 'virtual', status: 'online', registered: true,
  isolation: 'remote', sched_state: 'ready', schedulable: true, capabilities: {supports_stream: true},
  sandbox: {mode: 'container', engine: 'docker', configured: true},
  virtual: {parent_id: 'sgx-dev', parent_name: 'sgx'},
};
// What the device's dialog lists for them.
const STORED = [
  {id: 'vx-abcdefghij', parent_id: 'sgx-dev', name: 'HSM sandbox', registered: true,
    spec: {sandbox: {mode: 'container', engine: 'docker'},
      firewall: {allow_public_internet: true, deny_cidrs: ['203.0.113.0/24'], resolvers: ['1.1.1.1']}}},
  {id: 'vx-openopenop', parent_id: 'sgx-dev', name: 'Lab bench', registered: true,
    spec: {sandbox: {mode: 'container', engine: 'docker', network: 'lab-net'}}},
];
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

async function boot(opts) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.states = {0: {goal: 'g', status: 'idle', plan: {goal: 'g', tasks: []}}};
  h.projects = {multi_project: false, stats: {total_projects: 1}, projects: []};
  // Longest prefix first; see domshim's fetch.
  h.routes['/api/executors/sgx-dev/virtuals'] = Object.assign({}, PARENT_VIEW,
    opts && opts.stored ? {virtual_executors: STORED} : {}, opts && opts.parent);
  h.routes['/api/executors/vx-abcdefghij/virtual'] = {id: 'vx-abcdefghij', name: 'HSM sandbox'};
  h.routes['/api/executors'] = {executors: [DEVICE, VIRTUAL, VX_OPEN, VX_NONE], policy: {}, ready: true};
  require(bundlePath);
  await globalThis.__settle(5);
  await window.loadExecutors();
  await globalThis.__settle(3);
  // The dialog is deferred (Task 20386): fetched through the loader the
  // card's buttons use, then driven directly.
  globalThis.XA = await window.panelAct('execadmin');
  return h;
}

const el = id => document.getElementById(id);

// choose ticks one network access. The shim has no radio groups, so the other
// two are cleared by hand, the way a browser clears them.
function choose(id) {
  for (const r of ['evxNetNone', 'evxNetFw', 'evxNetOpen']) el(r).checked = r === id;
}

// fillRules types a full set of firewall rules.
function fillRules() {
  el('evxPublic').checked = true;
  el('evxAllow').value = '10.8.0.0/24';
  el('evxDeny').value = '203.0.113.0/24';
  el('evxPorts').value = '';
  el('evxDns').value = '1.1.1.1';
}

async function postedAfterSave(h) {
  XA.saveExecutorVirtual();
  await globalThis.__settle(4);
  const post = h.requests.filter(r => r.method === 'POST' && r.url.includes('/virtuals')).pop();
  return post ? post.body : '';
}

// summary types rules, runs the handler the fields call, and reads back what
// the dialog shows.
function summary(mode, fill) {
  choose(mode);
  fillRules();
  fill();
  XA.evxSync();
  return {sum: el('evxFwSum').innerHTML, warn: el('evxFwSum').classList.contains('warn'),
    rules: el('evxFwRules').style.display, open: el('evxOpenNet').style.display};
}

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
    XA.openExecutorVirtual(0);
    await globalThis.__settle(4);
    return {html: el('evxBody').innerHTML};
  },
  // The Settings tab lists every device's USB hardware, hubs excluded, with a
  // way into that device's dialog.
  async settings() {
    await boot();
    await window.panelAct('settings', 'loadUSBSettings');
    await globalThis.__settle(4);
    return {html: el('usbList').innerHTML};
  },
  // Ticking the YubiHSM and filling the firewall posts the spec the backend
  // expects.
  async create() {
    const h = await boot();
    XA.openExecutorVirtual(0);
    await globalThis.__settle(4);
    el('evxName').value = 'HSM sandbox';
    el('evxEngine').value = 'docker';
    el('evxRuntime').value = 'runc';
    el('evxUsb0').checked = true;
    el('evxGroup').value = 'plugdev';
    choose('evxNetFw');
    el('evxPublic').checked = true;
    el('evxAllow').value = '10.8.0.0/24';
    el('evxDeny').value = '203.0.113.0/24\n198.51.100.7';
    el('evxPorts').value = '';
    el('evxDns').value = '1.1.1.1, 9.9.9.9';
    XA.saveExecutorVirtual();
    await globalThis.__settle(4);
    const post = h.requests.filter(r => r.method === 'POST' && r.url.includes('/virtuals')).pop();
    return {body: post ? post.body : ''};
  },
  // Rules typed and then left for No network are not applied: the POST has
  // no firewall, and the network is none.
  async createNoNetwork() {
    const h = await boot();
    XA.openExecutorVirtual(0);
    await globalThis.__settle(4);
    el('evxName').value = 'Quiet';
    fillRules();
    choose('evxNetNone');
    return {body: await postedAfterSave(h)};
  },
  // Unfiltered sends the network named, and no firewall either.
  async createUnfiltered() {
    const h = await boot();
    XA.openExecutorVirtual(0);
    await globalThis.__settle(4);
    el('evxName').value = 'Lab';
    fillRules();
    choose('evxNetOpen');
    el('evxNetName').value = 'lab-net';
    return {body: await postedAfterSave(h)};
  },
  // Editing opens on the stored access: the firewalled one with its rules on
  // screen, the named network with its name, which the old none/bridge select
  // could not show and so reset to none on save.
  async editFirewalled() {
    await boot({stored: true});
    XA.openExecutorVirtual(1);
    await globalThis.__settle(4);
    return {html: el('evxBody').innerHTML};
  },
  async editNamed() {
    await boot({stored: true});
    XA.openExecutorVirtual(2);
    await globalThis.__settle(4);
    return {html: el('evxBody').innerHTML};
  },
  // An agent too old for a virtual executor's firewall or devices: the dialog
  // shows the hub's sentence (Task 20371), which knows the hub's build, rather
  // than a remedy written into the script.
  async tooOld() {
    await boot({parent: {protocol_version: 13, supported: false,
      unsupported_note: "This device's agent speaks protocol v13, and the hub needs v14 to apply a virtual " +
        "executor's firewall or devices. NOTE FROM THE HUB."}});
    XA.openExecutorVirtual(0);
    await globalThis.__settle(4);
    return {html: el('evxBody').innerHTML};
  },
  // A device that cannot install a firewall says so under Firewalled.
  async noPacketFilter() {
    await boot({parent: {packet_filter: false, packet_filter_issue: 'nft(8) needs CAP_NET_ADMIN'}});
    XA.openExecutorVirtual(0);
    await globalThis.__settle(4);
    return {html: el('evxBody').innerHTML};
  },
  // The sentence under the rules, for each shape of rule set.
  async summaries() {
    await boot();
    XA.openExecutorVirtual(0);
    await globalThis.__settle(4);
    const out = {};
    out.full = summary('evxNetFw', () => {});
    out.ports = summary('evxNetFw', () => { el('evxPorts').value = '443, 8443'; el('evxDeny').value = ''; });
    out.noDNS = summary('evxNetFw', () => { el('evxDns').value = ''; });
    out.nothing = summary('evxNetFw', () => {
      el('evxPublic').checked = false; el('evxAllow').value = ''; el('evxDns').value = '';
    });
    out.dnsOnly = summary('evxNetFw', () => { el('evxPublic').checked = false; el('evxAllow').value = ''; });
    out.hostile = summary('evxNetFw', () => { el('evxAllow').value = '<img src=x onerror=alert(1)>'; });
    out.none = summary('evxNetNone', () => {});
    out.open = summary('evxNetOpen', () => {});
    return {body: JSON.stringify(out)};
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
