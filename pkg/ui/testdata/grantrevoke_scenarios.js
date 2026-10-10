// grantrevoke_scenarios.js — drives the real dashboard bundle through the
// Secrets panel's grant revocation (Task 20403).
//
// The confirmation is assembled from the holders preview, and the result from
// the revocation's per-holder outcomes. Both are about what an operator is told
// before and after taking a credential out of running workloads — which of them
// hold it in their environment, which will be terminated — so they are run
// rather than grepped.
//
// Run by TestDashboard_GrantRevoke* in grantrevoke_frontend_test.go. Each
// scenario returns a plain object; the Go side asserts on it. Printed as one
// JSON document.
//
// Usage: node grantrevoke_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const HOLDERS = {
  grant_id: 'grant_pat', in_environment: 2, terminated: 1,
  workloads: [
    {lease_id: 'lease_1', executor_id: 'ctr-1', executor_kind: 'container', grant_id: 'grant_pat',
      env_keys: ['GIT_CONFIG_GLOBAL'], files: 3, in_environment: true, known: true, terminated: true},
    {lease_id: 'lease_2', executor_id: 'edge-1', executor_kind: 'remote', grant_id: 'grant_pat',
      env_keys: ['GITHUB_TOKEN'], files: 0, in_environment: true, known: true, terminated: false},
    {lease_id: 'lease_3', executor_id: '', executor_kind: '', grant_id: 'grant_pat',
      files: 0, in_environment: false, known: false, terminated: false},
  ],
};

const REVOKED = {
  ok: true, id: 'grant_pat', revoked: true, source: 'secret', state: 'revoked',
  note: 'Revoked, and taken back from 3 lease(s).',
  local: [{lease_id: 'lease_1', grant_id: 'grant_pat', executor_id: 'ctr-1', state: 'revoked',
    ack: {known: true, files_removed: 3, killed: ['h-1']}}],
  remote: [{lease_id: 'lease_2', grant_id: 'grant_pat', executor_id: 'edge-1', state: 'revoked',
    ack: {known: true, env_scrubbed: ['GITHUB_TOKEN']},
    widened: 'Agent edge-1 speaks protocol v18, and the hub needs v19.'}],
};

async function boot(routes) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.projects = {multi_project: false, stats: {}, projects: [
    {name: 'app', path: '/srv/app', goal: 'ship', health: 'idle'},
  ]};
  // Longest prefix first: the shim matches in insertion order.
  for (const [prefix, body] of routes) h.routes[prefix] = body;
  require(bundlePath);
  await globalThis.__settle(5);
  globalThis.SEC = await window.panelAct('secrets');
  return h;
}

function requestsTo(h, method, prefix) {
  return h.requests.filter(r => r.method === method && r.url.startsWith(prefix));
}

const scenarios = {
  async confirm_names_the_holders_and_the_result_lists_them() {
    const h = await boot([
      ['/api/grants/grant_pat/holders', HOLDERS],
      ['/api/grants/grant_pat', REVOKED],
    ]);
    const asked = [];
    globalThis.confirm = msg => { asked.push(msg); return true; };
    await SEC.revokeGrant('grant_pat');
    await globalThis.__settle(5);
    const box = document.getElementById('secGrantRevokeResult');
    return {
      prompt: asked[0] || '',
      holdersAsked: requestsTo(h, 'GET', '/api/grants/grant_pat/holders').length,
      deletes: requestsTo(h, 'DELETE', '/api/grants/grant_pat').length,
      result: box.innerHTML || '',
      resultShown: box.style.display !== 'none',
      toast: document.getElementById('toast').textContent || '',
    };
  },

  async declining_sends_no_revocation() {
    const h = await boot([
      ['/api/grants/grant_pat/holders', HOLDERS],
      ['/api/grants/grant_pat', REVOKED],
    ]);
    globalThis.confirm = () => false;
    await SEC.revokeGrant('grant_pat');
    await globalThis.__settle(3);
    return {deletes: requestsTo(h, 'DELETE', '/api/grants/').length};
  },

  async nobody_holding_it_is_said() {
    const h = await boot([
      ['/api/grants/grant_idle/holders', {grant_id: 'grant_idle', workloads: [], in_environment: 0, terminated: 0}],
      ['/api/grants/grant_idle', {ok: true, id: 'grant_idle', revoked: true, state: 'revoked',
        note: 'Revoked. No running workload held this grant.'}],
    ]);
    const asked = [];
    globalThis.confirm = msg => { asked.push(msg); return true; };
    await SEC.revokeGrant('grant_idle');
    await globalThis.__settle(3);
    return {prompt: asked[0] || '', deletes: requestsTo(h, 'DELETE', '/api/grants/grant_idle').length};
  },

  async an_egress_grant_asks_for_no_holders() {
    const h = await boot([['/api/grants/egress_1', {ok: true, id: 'egress_1', revoked: true, source: 'egress'}]]);
    const asked = [];
    globalThis.confirm = msg => { asked.push(msg); return true; };
    await SEC.revokeGrant('egress_1');
    await globalThis.__settle(3);
    return {
      prompt: asked[0] || '',
      holdersAsked: requestsTo(h, 'GET', '/api/grants/egress_1/holders').length,
      deletes: requestsTo(h, 'DELETE', '/api/grants/egress_1').length,
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
