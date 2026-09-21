// interfacegrant_scenarios.js — drives the real dashboard bundle through the
// Secrets panel's grant dialog (Task 20329).
//
// Run against the bundle rather than grepped, because the property that broke
// here is not expressible as a string. `host_device` had a constraint entry in
// SEC_KIND_CONSTRAINTS, a fieldset in SEC_KIND_FIELDSET, an input in the HTML
// and a validator in the broker — every grep-able piece — and an operator still
// could not issue a device grant from the dashboard, because SEC_GRANT_KINDS
// did not list it and so the kind never appeared in the dropdown. The bug lived
// in the relationship between four tables, which is exactly what a DOM run can
// see and a text search cannot.
//
// Run by the TestDashboard_GrantDialog* tests in
// interfacegrant_frontend_test.go. The kind *list* is not among them: it is
// static markup, and the shim deliberately does not parse HTML, so that one
// assertion reads the served page instead. Each scenario returns a plain
// object; the Go side asserts on it. Printed as one JSON document.
//
// Usage: node interfacegrant_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

async function boot() {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.projects = {multi_project: false, stats: {}, projects: [
    {name: 'firmware', path: '/srv/firmware', goal: 'bring-up', health: 'idle'},
  ]};
  // One secret of each inventory kind, so the kind-filtered secret picker has
  // something to offer and "no secret stored" cannot mask a missing kind.
  h.routes['/api/secrets'] = {secrets: [
    {id: 'sec_if', name: 'bench-net', kind: 'host_interface'},
    {id: 'sec_dev', name: 'bench-hw', kind: 'host_device'},
    {id: 'sec_repo', name: 'trees', kind: 'local_repo'},
  ]};
  require(bundlePath);
  await globalThis.__settle(5);
  return h;
}

// visibleKindSets returns the ids of the grant dialog's fieldsets that are
// currently revealed. `on` is the class _secShowKindSet toggles, so this reads
// what the operator would actually see.
function visibleKindSets() {
  const ids = ['grantSet-github', 'grantSet-kubeconfig', 'grantSet-egress',
    'grantSet-registry', 'grantSet-env', 'grantSet-egressproxy',
    'grantSet-localrepo', 'grantSet-hostdevice', 'grantSet-hostinterface',
    'grantSet-writable'];
  return ids.filter(id => {
    const el = document.getElementById(id);
    return !!(el && el.classList && el.classList.contains('on'));
  });
}

function setVal(id, v) {
  const el = document.getElementById(id);
  if (el) el.value = v;
}

const scenarios = {
  // Selecting the kind must reveal its own allowlist field and nothing else —
  // a dialog showing the wrong fieldset collects a constraint the broker will
  // reject, or worse, none at all.
  async selecting_host_interface_reveals_its_fieldset() {
    await boot();
    setVal('grantKind', 'host_interface');
    window.onGrantKindChange();
    await globalThis.__settle(2);
    return {visible: visibleKindSets()};
  },

  // writable applies to local_repo and host_device and to nothing else. It had
  // no control on this dialog at all before, so a device grant made here was
  // silently read-only however the operator set the inventory up.
  async writable_follows_the_kind() {
    await boot();
    const out = {};
    for (const kind of ['host_device', 'local_repo', 'host_interface', 'kubeconfig']) {
      setVal('grantKind', kind);
      window.onGrantKindChange();
      await globalThis.__settle(2);
      out[kind] = visibleKindSets().includes('grantSet-writable');
    }
    return out;
  },

  // The payload is what the broker sees. An allowlist the dialog collected but
  // did not send produces "a host_interface grant needs an interface
  // allowlist" from a form that plainly had one filled in.
  async submit_sends_the_interface_allowlist() {
    const h = await boot();
    setVal('grantKind', 'host_interface');
    window.onGrantKindChange();
    await globalThis.__settle(2);
    setVal('grantSubject', 'project:/srv/firmware');
    setVal('grantSecret', 'sec_if');
    setVal('grantInterfaces', 'dut, can0');
    setVal('grantTTL', '480');
    window.submitGrant();
    await globalThis.__settle(5);

    const post = h.requests.filter(r => r.method === 'POST' && r.url.startsWith('/api/grants')).pop();
    return {
      sent: !!post,
      body: post ? post.body : '',
    };
  },

  // The same path for a device grant, which is the one that was impossible
  // before. Asserted alongside rather than assumed from the interface case:
  // they read different inputs and different constraint keys.
  async submit_sends_the_device_allowlist_and_writable() {
    const h = await boot();
    setVal('grantKind', 'host_device');
    window.onGrantKindChange();
    await globalThis.__settle(2);
    setVal('grantSubject', 'project:/srv/firmware');
    setVal('grantSecret', 'sec_dev');
    setVal('grantDevices', 'serial0');
    setVal('grantTTL', '480');
    const wr = document.getElementById('grantWritable');
    if (wr) wr.checked = true;
    window.submitGrant();
    await globalThis.__settle(5);

    const post = h.requests.filter(r => r.method === 'POST' && r.url.startsWith('/api/grants')).pop();
    return {sent: !!post, body: post ? post.body : ''};
  },

  // And the negative: writable must not ride along on a kind the broker
  // refuses it for, which would make an otherwise fine grant unfileable.
  async submit_omits_writable_for_other_kinds() {
    const h = await boot();
    setVal('grantKind', 'host_interface');
    window.onGrantKindChange();
    await globalThis.__settle(2);
    setVal('grantSubject', 'project:/srv/firmware');
    setVal('grantSecret', 'sec_if');
    setVal('grantInterfaces', 'dut');
    const wr = document.getElementById('grantWritable');
    if (wr) wr.checked = true;   // stale from a previous kind
    window.submitGrant();
    await globalThis.__settle(5);

    const post = h.requests.filter(r => r.method === 'POST' && r.url.startsWith('/api/grants')).pop();
    return {sent: !!post, body: post ? post.body : ''};
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
  process.stdout.write(JSON.stringify(out, null, 2));
})();
