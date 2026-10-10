// firewall_scenarios.js — drives the firewall panels (Task 20363) in the real
// dashboard bundle: a device's rule set from its card in the Executors tab,
// the device's rules read back in the virtual-executor dialog, and a project's
// rule set on the Overview page beside the rules that govern it.
//
// Run by TestDashboard_FirewallPanels. Prints one JSON document.
//
// Usage: node firewall_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const DEVICE = {id: 'sgx-dev', name: 'sgx', kind: 'remote', status: 'online', registered: true, enrolled: true,
  isolation: 'remote', sched_state: 'ready', schedulable: true, capabilities: {}};
const LOCAL = {id: 'local', name: 'local', kind: 'localprocess', status: 'online', registered: true,
  isolation: 'none', sched_state: 'ready', schedulable: true, capabilities: {}};
const VIRTUAL = {id: 'vx-abcdefghij', name: 'Lab', kind: 'virtual', status: 'online', registered: true,
  isolation: 'remote', sched_state: 'ready', schedulable: true, capabilities: {},
  virtual: {parent_id: 'sgx-dev', parent_name: 'sgx'}};

const DEVICE_RULES = {allow_public_internet: true, allow_ports: [443], resolvers: ['1.1.1.1:53'],
  deny_cidrs: ['203.0.113.0/24']};
const DEVICE_VIEW = {executor_id: 'sgx-dev', kind: 'remote', configured: true, rules: DEVICE_RULES,
  describe: 'public Internet', config: null, enforced: false,
  warning: 'device sgx-dev runs payloads on its host, where no per-workload firewall can be installed',
  set_by: 'admin@example.com',
  children: [
    {kind: 'virtual', id: 'vx-abcdefghij', name: 'Lab', describe: 'x', fits: true},
    {kind: 'project', id: '/srv/app', describe: 'y', fits: false, reasons: ['port 22 is not allowed']},
  ]};
const PROJECT_VIEW = {project: '/srv/app', visible: true, configured: false, rules: {}, describe: 'no network',
  executor_id: 'vx-abcdefghij', executor_kind: 'virtual',
  levels: [
    {kind: 'device', name: "device sgx-dev's firewall", rules: DEVICE_RULES},
    {kind: 'own', name: "virtual executor vx-abcdefghij's firewall",
      rules: {allow_cidrs: ['1.1.1.0/24'], allow_ports: [443], resolvers: ['1.1.1.1:53']}},
  ],
  governing: {allow_cidrs: ['1.1.1.0/24'], allow_ports: [443], resolvers: ['1.1.1.1:53'],
    deny_cidrs: ['203.0.113.0/24']},
  fits: true, enforced: true};

async function boot(opts) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.states = {0: {goal: 'g', status: 'idle', plan: {goal: 'g', tasks: []}}};
  h.projects = {multi_project: false, stats: {total_projects: 1}, projects: []};
  if (opts && opts.me) h.me = opts.me;
  h.routes['/api/executors/sgx-dev/firewall'] = (opts && opts.deviceView) || DEVICE_VIEW;
  h.routes['/api/executors/sgx-dev/virtuals'] = {executor_id: 'sgx-dev', name: 'sgx', connected: true,
    protocol_version: 15, supported: true, engines: ['docker'], oci_runtimes: ['runc'], networks: ['none', 'bridge'],
    packet_filter: true, usb_devices: [], device_firewall: DEVICE_RULES,
    virtual_executors: [{id: 'vx-abcdefghij', parent_id: 'sgx-dev', name: 'Lab', registered: true,
      spec: {sandbox: {mode: 'container', engine: 'docker'}, firewall: {allow_public_internet: true}},
      exceeds_device: ['it allows every port, but the governing rule set allows only 443']}]};
  h.routes['/api/executors'] = {executors: [DEVICE, LOCAL, VIRTUAL], policy: {}, ready: true};
  h.routes['/api/firewall'] = (opts && opts.projectView) || PROJECT_VIEW;
  require(bundlePath);
  await globalThis.__settle(5);
  await window.loadExecutors();
  await globalThis.__settle(3);
  // A device's dialog is deferred (Task 20386): fetched through the loader its
  // card's button uses, then driven directly. The project card is bundled.
  globalThis.XA = await window.panelAct('execadmin');
  return h;
}

const el = id => document.getElementById(id);
const lastPut = (h, part) => h.requests.filter(r => r.method === 'PUT' && r.url.includes(part)).pop();

const scenarios = {
  // The Firewall button is on devices only, never on the host-process
  // executor or a virtual one, and the dialog reads the device back.
  async device_dialog() {
    const h = await boot();
    const cards = el('execList').innerHTML;
    XA.openExecutorFirewall(0);
    await globalThis.__settle(4);
    return {html: cards + '\n----\n' + el('efwBody').innerHTML};
  },

  // The form reads itself back as one sentence. The shim does not parse the
  // form's markup into inputs, so the fields are filled the way a browser
  // would have filled them from it.
  async summary() {
    await boot();
    XA.openExecutorFirewall(0);
    await globalThis.__settle(4);
    el('efwPub').checked = true;
    el('efwAllow').value = '';
    el('efwPorts').value = '443';
    el('efwDns').value = '1.1.1.1:53';
    el('efwDeny').value = '203.0.113.0/24';
    window.fwSync('efw');
    const one = el('efwSum').textContent;
    el('efwPub').checked = false;
    el('efwDns').value = '';
    window.fwSync('efw');
    return {html: one + '\n' + el('efwSum').textContent};
  },

  // Saving sends the form as lists, the ports as numbers.
  async device_save() {
    const h = await boot();
    XA.openExecutorFirewall(0);
    await globalThis.__settle(4);
    el('efwPub').checked = false;
    el('efwAllow').value = '10.8.0.0/24\n 140.82.112.0/20';
    el('efwDeny').value = '10.8.0.9';
    el('efwPorts').value = '443, 8443';
    el('efwDns').value = '1.1.1.1';
    h.routes['/api/executors/sgx-dev/firewall'] = Object.assign({}, DEVICE_VIEW, {constrained: [
      {kind: 'project', subject: '/srv/app', from: 'a', to: 'b', notes: ['its ports were narrowed from 22, 443 to 443']}]});
    XA.saveExecutorFirewall();
    await globalThis.__settle(4);
    const put = lastPut(h, '/api/executors/sgx-dev/firewall');
    return {body: put ? put.body : '', html: el('efwBody').innerHTML};
  },

  // A refused save shows the hub's reasons on the form.
  async device_refused() {
    const h = await boot();
    XA.openExecutorFirewall(0);
    await globalThis.__settle(4);
    h.routes['/api/executors/sgx-dev/firewall'] = {error: 'refused', code: 'firewall_exceeds_bound',
      reasons: ['10.0.0.0/8 is outside the governing rule set']};
    h.routeStatus['/api/executors/sgx-dev/firewall'] = 409;
    XA.saveExecutorFirewall();
    await globalThis.__settle(4);
    return {html: el('efwWarn').innerHTML};
  },

  // The virtual-executor dialog shows the device's rules read-only, offers no
  // unfiltered network under them, and marks a virtual executor outside them.
  async virtual_dialog() {
    await boot();
    XA.openExecutorVirtual(0);
    await globalThis.__settle(4);
    return {html: el('evxBody').innerHTML};
  },

  // The Overview card: the governing levels beside an editable form, which
  // starts from the governing rules when the project has none of its own.
  async project_card() {
    const h = await boot();
    await window.loadProjectFirewall();
    await globalThis.__settle(3);
    el('pfwAllow').value = '1.1.1.0/25';
    el('pfwPorts').value = '443';
    window.saveProjectFirewall();
    await globalThis.__settle(4);
    const put = lastPut(h, '/api/firewall');
    return {html: el('projectFirewallPanel').style.display + '|' + el('projectFirewallBody').innerHTML,
      body: put ? put.url + ' ' + put.body : ''};
  },

  // A fleet event refreshes the card (loadExecutors → loadProjectFirewall).
  // While someone is editing it — the form differs from its last render, or
  // holds the caret — only the governing rules move: the form, and the refusal
  // of their last save, stay. A form nobody is in is drawn again.
  async project_card_keeps_edits() {
    const h = await boot();
    await window.loadProjectFirewall();
    await globalThis.__settle(3);
    const drawn = el('projectFirewallBody').innerHTML;
    const view = cidr => Object.assign({}, PROJECT_VIEW, {levels: [{kind: 'device', name: "device sgx-dev's firewall",
      rules: {allow_cidrs: [cidr], allow_ports: [443]}}]});
    el('pfwAllow').value = '8.8.8.0/24';
    h.routes['/api/firewall'] = {error: 'refused', code: 'firewall_exceeds_bound',
      reasons: ['8.8.8.0/24 is outside the governing rule set']};
    h.routeStatus['/api/firewall'] = 409;
    window.saveProjectFirewall();
    await globalThis.__settle(4);
    delete h.routeStatus['/api/firewall'];
    const out = [];
    const refresh = async (cidr, label) => {
      h.routes['/api/firewall'] = view(cidr);
      await window.loadExecutors();
      await globalThis.__settle(4);
      out.push(label + ': ' + (el('projectFirewallBody').innerHTML === drawn ? 'kept' : 'drawn') + ' | '
        + el('pfwGov').innerHTML + ' | ' + el('pfwWarn').innerHTML);
    };
    await refresh('10.1.0.0/16', 'typed');
    el('pfwAllow').value = '';
    const dns = el('pfwDns');
    dns.tagName = 'INPUT';
    dns.focus();
    await refresh('10.2.0.0/16', 'caret');
    dns.blur();
    await refresh('10.3.0.0/16', 'idle');
    out.push(el('projectFirewallBody').innerHTML);
    return {html: out.join('\n----\n')};
  },

  // A save the hub refuses with 400 because an allowlist entry contains a
  // cloud metadata service it does not name (Task 20397): the sentence lands
  // on the form, in both cards, and the form keeps what was typed.
  async metadata_refused() {
    const h = await boot();
    const refusal = {error: 'allow_cidrs: 169.254.0.0/16 contains the cloud metadata service at 169.254.169.254 '
      + '(instance metadata on AWS, Azure, Google Cloud, Oracle Cloud and most other clouds) without naming it. Add '
      + '169.254.169.254/32 to the allowlist if a sandbox should reach it, or to the denylist so it stays closed'};
    XA.openExecutorFirewall(0);
    await globalThis.__settle(4);
    el('efwAllow').value = '169.254.0.0/16';
    h.routes['/api/executors/sgx-dev/firewall'] = refusal;
    h.routeStatus['/api/executors/sgx-dev/firewall'] = 400;
    XA.saveExecutorFirewall();
    await globalThis.__settle(4);
    const device = el('efwWarn').innerHTML;
    await window.loadProjectFirewall();
    await globalThis.__settle(3);
    el('pfwAllow').value = '169.254.0.0/16';
    h.routes['/api/firewall'] = refusal;
    h.routeStatus['/api/firewall'] = 400;
    window.saveProjectFirewall();
    await globalThis.__settle(4);
    return {html: device + '\n----\n' + el('pfwWarn').innerHTML + '\n----\n' + el('pfwAllow').value};
  },

  // A rule set stored before the rule: each card lists what the hub says about
  // it, and the device's dialog marks its children that carry one.
  async metadata_stored() {
    const note = '100.64.0.0/10 contains the cloud metadata service at 100.100.100.200 (Alibaba Cloud instance '
      + 'metadata) without naming it. It stays closed: every filter compiled from these rules drops it ahead of the allow.';
    const deviceView = Object.assign({}, DEVICE_VIEW, {metadata: [note], children: [
      {kind: 'virtual', id: 'vx-abcdefghij', name: 'Lab', describe: 'x', fits: true, metadata: ['vx note']}]});
    const h = await boot({deviceView: deviceView, projectView: Object.assign({}, PROJECT_VIEW, {metadata: [note]})});
    XA.openExecutorFirewall(0);
    await globalThis.__settle(4);
    const device = el('efwBody').innerHTML;
    await window.loadProjectFirewall();
    await globalThis.__settle(3);
    const project = el('projectFirewallBody').innerHTML;
    h.routes['/api/executors/sgx-dev/virtuals'].virtual_executors[0].metadata = [note];
    XA.openExecutorVirtual(0);
    await globalThis.__settle(4);
    XA.editExecutorVirtual(0);
    await globalThis.__settle(2);
    return {html: device + '\n----\n' + project + '\n----\n' + el('evxBody').innerHTML};
  },

  // Someone who may not change the project's configuration is not shown it.
  // The hub answers anyone below config.write with visible:false; the card
  // then stays hidden without a word, and no error is raised for it.
  async project_card_viewer() {
    const h = await boot({me: {oidc_enabled: true, authenticated: true, permissions: ['project.read']}});
    h.routes['/api/firewall'] = {project: '/srv/app', visible: false};
    el('projectFirewallPanel').style.display = '';
    await window.loadProjectFirewall();
    await globalThis.__settle(3);
    return {html: el('projectFirewallPanel').style.display};
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
  process.exit(0);
})();
