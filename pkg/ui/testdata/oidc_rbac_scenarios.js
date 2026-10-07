// oidc_rbac_scenarios.js — drives Settings → Single sign-on against the real
// dashboard bundle (Task 20395).
//
// Three properties, each about what the panel does on its own:
//
//  - It shows the saved default role as it is. It used to pre-select "none"
//    for an unset role, so saving any field of the form wrote default_role:
//    none — which switches RBAC on for a hub without a policy.
//  - It renders the hub's verdict on RBAC (view.rbac, authz.Enforced), never
//    one it works out from default_role and role_mappings. Fed a view whose
//    fields and verdict disagree, it follows the verdict.
//  - A save the hub refuses as an RBAC switch is asked as a question, and
//    resent with confirm_rbac only on yes; Enforce deny-by-default asks first
//    and posts to its own route.
//
// Run by TestDashboard_OIDCPanelShowsTheHubsRBACVerdict; prints one JSON
// document on stdout.
//
// Usage: node oidc_rbac_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const ISSUER = 'https://idp.example.com/realms/main';
const OFF = 'RBAC is off: everyone who can sign in through ' + ISSUER + ' has full access.';

function clone(o) { return JSON.parse(JSON.stringify(o)); }

// view is the shape GET /api/config/oidc returns, for an SSO hub with
// admin_emails and no policy unless a scenario changes it.
function view(over) {
  return Object.assign({
    enabled: true, issuer: ISSUER, client_id: 'cloop', redirect_url: 'https://cloop.example.com/auth/callback',
    scopes: ['openid', 'profile', 'email'], admin_emails: ['ops@example.com'],
    default_role: '', role_mappings: [],
    session_ttl_hours: 0, idle_timeout_hours: 0, refresh_interval_minutes: 0,
    max_claim_age_minutes: 0, clock_skew_seconds: 0,
    require_idp: false, require_rbac: false, cookie_secure: 'auto',
    client_secret_set: false, client_secret_source: 'unset',
    active: {enabled: true, issuer: ISSUER, idp_ready: true},
    restart_required: false,
    rbac: {enforced: false, saved_enforced: false, warning: OFF, can_enforce: true},
    limits: {}, roles: ['none', 'viewer', 'operator', 'maintainer', 'admin'],
    claims: ['group', 'role', 'email', 'sub'],
  }, over || {});
}

// respond is the slice of a fetch Response the bundle's parseAPIResponse reads.
function respond(body, status) {
  const text = JSON.stringify(body);
  return Promise.resolve({
    ok: status < 400, status,
    headers: {get: () => null},
    json: () => Promise.resolve(JSON.parse(text)),
    text: () => Promise.resolve(text),
  });
}

async function boot(oidcView) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.states = {0: {goal: 'g', status: 'initialized', plan: {goal: 'g', tasks: []}}};
  h.projects = {multi_project: false, stats: {total_projects: 1},
    projects: [{name: 'alpha', path: '/srv/alpha', goal: 'g', total_tasks: 0, done_tasks: 0, health: 'idle'}]};
  // Longest prefix first: the shim matches in insertion order.
  h.routes['/api/config/oidc/enforce'] = view({default_role: 'none', rbac: {
    enforced: false, saved_enforced: true, can_enforce: false,
    warning: OFF + ' Deny-by-default is saved: restart the hub to enforce it.'}});
  h.routes['/api/config/oidc'] = clone(oidcView);
  require(bundlePath);
  await globalThis.__settle(5);
  const ws = h.sockets[h.sockets.length - 1];
  if (ws) ws.open();
  await globalThis.__settle(2);
  window.switchTab('settings');
  await globalThis.__settle(6);
  return h;
}

const $ = id => document.getElementById(id);
const shown = id => { const el = $(id); return !!el && el.style.display !== 'none'; };
const oidcRequests = (h, method) =>
  h.requests.filter(r => r.url.startsWith('/api/config/oidc') && r.method === method);

// interceptPUT answers PUT /api/config/oidc with each of answers in turn,
// recording the request the way the shim's own fetch does.
function interceptPUT(h, answers) {
  const orig = globalThis.fetch;
  let n = 0;
  globalThis.fetch = function(url, opts) {
    if (String(url).startsWith('/api/config/oidc') && opts && opts.method === 'PUT') {
      h.requests.push({url: String(url), method: 'PUT', body: opts.body});
      const [body, status] = answers[Math.min(n++, answers.length - 1)];
      return respond(body, status);
    }
    return orig(url, opts);
  };
}

const TURNS_ON = [{error: {code: 'CONFLICT', message: 'this save turns RBAC on: after the next restart, ' +
  'a signed-in user who matches no role mapping gets "none" — confirm to save it',
  details: {rbac_change: 'rbac_turns_on'}}}, 409];

const scenarios = {
  async unset_role_shows_unset_and_saves_unset() {
    const h = await boot(view());
    const selectValue = $('oidcDefaultRole').value;
    await window.panelAct('settings', 'saveOIDCSettings');
    await globalThis.__settle(4);
    const puts = oidcRequests(h, 'PUT');
    const body = puts.length ? JSON.parse(puts[0].body) : {};
    return {selectValue, puts: puts.length, putDefaultRole: body.default_role, putConfirm: !!body.confirm_rbac};
  },

  async off_warns_and_offers_enforce() {
    await boot(view());
    return {note: $('oidcRbacNote').textContent, noteShown: shown('oidcRbacNote'), enforceShown: shown('oidcEnforceBtn')};
  },

  // Fields and verdict disagree on purpose; the panel follows the verdict.
  async verdict_is_the_hubs() {
    await boot(view({rbac: {enforced: true, saved_enforced: true, default_role: 'none', can_enforce: false}}));
    const quiet = {note: $('oidcRbacNote').textContent, enforceShown: shown('oidcEnforceBtn')};
    await boot(view({default_role: 'viewer', role_mappings: [{claim: 'group', value: 'g', role: 'admin'}]}));
    return {quietNote: quiet.note, quietEnforce: quiet.enforceShown, loudNote: $('oidcRbacNote').textContent};
  },

  async enforce_asks_then_posts() {
    const h = await boot(view());
    const asked = [];
    globalThis.confirm = msg => { asked.push(msg); return false; };
    await window.panelAct('settings', 'oidcEnforce');
    await globalThis.__settle(3);
    const postsWhenDeclined = oidcRequests(h, 'POST').length;
    globalThis.confirm = msg => { asked.push(msg); return true; };
    await window.panelAct('settings', 'oidcEnforce');
    await globalThis.__settle(4);
    const posts = oidcRequests(h, 'POST');
    return {
      asked: asked.length, postsWhenDeclined, posts: posts.length,
      url: posts.length ? posts[0].url : '', body: posts.length ? posts[0].body : '',
      noteAfter: $('oidcRbacNote').textContent, enforceShownAfter: shown('oidcEnforceBtn'),
    };
  },

  async rbac_switch_is_asked_and_resent_on_yes() {
    const h = await boot(view());
    const asked = [];
    globalThis.confirm = msg => { asked.push(msg); return true; };
    interceptPUT(h, [TURNS_ON, [view({default_role: 'none'}), 200]]);
    await window.panelAct('settings', 'saveOIDCSettings');
    await globalThis.__settle(5);
    const puts = oidcRequests(h, 'PUT').map(r => JSON.parse(r.body));
    return {asked, puts: puts.length, firstConfirm: !!puts[0].confirm_rbac, secondConfirm: !!(puts[1] || {}).confirm_rbac};
  },

  async rbac_switch_declined_sends_nothing_more() {
    const h = await boot(view());
    globalThis.confirm = () => false;
    interceptPUT(h, [TURNS_ON]);
    await window.panelAct('settings', 'saveOIDCSettings');
    await globalThis.__settle(4);
    return {puts: oidcRequests(h, 'PUT').length};
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
