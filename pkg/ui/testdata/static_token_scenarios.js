// static_token_scenarios.js — drives Settings → Static admin token against the
// real dashboard bundle (Task 20406).
//
// The card draws the hub's verdicts — accepted, retired, strands — and its
// Retire button: no request without a reason, a question before the POST, and
// a second, forced POST only when the hub refuses to strand a token-only hub
// and the operator says yes.
//
// Run by TestDashboard_StaticTokenCard; prints one JSON document on stdout.
//
// Usage: node static_token_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

function view(over) {
  return Object.assign({
    configured: true, fingerprint: '3f9c1e7a2b5d', status: 'accepted',
    last_used_at: '2026-10-09T08:00:00Z', last_used_ip: '203.0.113.7',
    sso: true, admin_tokens: 0, strands: false, self: false,
  }, over || {});
}

function respond(body, status) {
  const text = JSON.stringify(body);
  return Promise.resolve({
    ok: status < 400, status,
    headers: {get: () => null},
    json: () => Promise.resolve(JSON.parse(text)),
    text: () => Promise.resolve(text),
  });
}

async function boot(tokenView) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.states = {0: {goal: 'g', status: 'initialized', plan: {goal: 'g', tasks: []}}};
  h.projects = {multi_project: false, stats: {total_projects: 1},
    projects: [{name: 'alpha', path: '/srv/alpha', goal: 'g', total_tasks: 0, done_tasks: 0, health: 'idle'}]};
  h.routes['/api/static-token'] = tokenView;
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
// The shim keeps markup as written: the card draws with innerHTML, its
// no-token sentence with textContent.
const text = id => { const el = $(id); return el ? (el.innerHTML || el.textContent || '') : ''; };

// interceptRetire answers POST /api/static-token/retire with each of answers in
// turn, recording each request.
function interceptRetire(h, answers) {
  const orig = globalThis.fetch;
  const posts = [];
  globalThis.fetch = function(url, opts) {
    if (String(url).startsWith('/api/static-token/retire') && opts && opts.method === 'POST') {
      posts.push(JSON.parse(opts.body || '{}'));
      const [body, status] = answers[Math.min(posts.length - 1, answers.length - 1)];
      return respond(body, status);
    }
    return orig(url, opts);
  };
  return posts;
}

const RETIRED = view({status: 'retired', retired: {at: '2026-10-10T12:00:00Z', by: 'ops@example.com',
  reason: 'SSO is live'}, refused: {count: 3, last_at: '2026-10-10T12:03:00Z', last_ip: '198.51.100.9'}});

const scenarios = {
  async accepted_shows_fingerprint_use_and_retire() {
    await boot(view());
    return {badge: text('staticTokenBadge'), body: text('staticTokenBody'),
      actions: shown('staticTokenActions')};
  },

  async retire_needs_a_reason_then_asks_then_posts() {
    const h = await boot(view());
    const posts = interceptRetire(h, [[{retired: true, token: RETIRED}, 200]]);
    const asked = [];
    globalThis.confirm = msg => { asked.push(msg); return true; };
    await window.panelAct('settings', 'retireStaticToken');
    await globalThis.__settle(3);
    const postsWithoutReason = posts.length;
    $('staticTokenReason').value = 'SSO is live, INC-4471';
    await window.panelAct('settings', 'retireStaticToken');
    await globalThis.__settle(4);
    return {postsWithoutReason, posts, asked: asked.length, badge: text('staticTokenBadge'),
      body: text('staticTokenBody'), actions: shown('staticTokenActions'),
      reasonAfter: $('staticTokenReason').value};
  },

  async a_refused_strand_is_asked_and_forced_on_yes() {
    const h = await boot(view({sso: false, strands: true, self: true}));
    const strandsNote = text('staticTokenBody');
    const posts = interceptRetire(h, [
      [{error: 'retiring the static token would leave this hub with no way in: ... --force'}, 409],
      [{retired: true, token: RETIRED}, 200]]);
    const asked = [];
    globalThis.confirm = msg => { asked.push(msg); return true; };
    $('staticTokenReason').value = 'locking the door first';
    await window.panelAct('settings', 'retireStaticToken');
    await globalThis.__settle(6);
    return {strandsNote, posts, asked: asked.length, badge: text('staticTokenBadge')};
  },

  async none_configured_offers_nothing() {
    await boot(view({configured: false, status: 'none', fingerprint: ''}));
    return {badge: text('staticTokenBadge'), body: text('staticTokenBody'),
      actions: shown('staticTokenActions')};
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
