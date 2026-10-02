// signin_scenarios.js — what a 401 does to the user, per deployment
// (Task 20359, re-landing Task 20330).
//
// An SSO hub has no access token to type, yet a lapsed session used to open the
// token prompt: "This dashboard is protected. Enter the access token to
// continue." The fix is a decision spread over three files and two async hops —
// the request that 401s, the hint on the refusal, the branch that picks a
// dialog — so it is asserted by running the real bundle rather than reading it.
//
// Run by TestDashboard_UnauthorizedPicksTheRightSignIn. Prints one JSON
// document, then exits: the bundle arms timers (a renewal schedule can be
// minutes away) that would otherwise keep node alive.
//
// Usage: node signin_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const HINT = {'X-Cloop-Sign-In': '/auth/login'};

// boot loads the bundle against a fresh shim. setup runs before the bundle, so
// it can shape the first requests; storage seeds sessionStorage, which is how
// a page that came back from a sign-in finds what the previous page left.
async function boot(setup, storage) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.states = {0: {goal: 'g', status: 'idle', plan: {goal: 'g', tasks: []}}};
  h.projects = {multi_project: true, stats: {}, projects: [
    {name: 'alpha', path: '/p/alpha', total_tasks: 0},
    {name: 'beta', path: '/p/beta', total_tasks: 0},
  ]};
  for (const [k, v] of Object.entries(storage || {})) sessionStorage.setItem(k, v);
  // The shim has no markup, so state what index.html says about the two
  // things read back below: the token prompt is shown by a class, and the
  // banner starts hidden.
  document.getElementById('loginOverlay').setAttribute('data-overlay', 'class:visible');
  document.getElementById('sessionRenewBanner').style.display = 'none';

  // The shim's location.assign is a no-op; a sign-in navigation is the outcome
  // under test, so record it.
  const assigns = [];
  globalThis.location.assign = u => { assigns.push(String(u)); };
  if (setup) setup(h);

  require(bundlePath);
  await globalThis.__settle(10);
  return {h, assigns};
}

// refuse makes a path answer 401, the way an SSO hub (hinted) or a token-only
// hub (bare) does.
function refuse(h, path, hinted) {
  h.routes[path] = {error: 'authentication required'};
  h.routeStatus[path] = 401;
  if (hinted) h.routeHeaders[path] = HINT;
}

function view(assigns) {
  const banner = document.getElementById('sessionRenewBanner');
  return {
    assigns: assigns.slice(),
    login_modal: !!window.isOverlayOpen('loginOverlay'),
    banner: !!(banner && banner.style && banner.style.display === 'flex'),
    banner_text: document.getElementById('sessionRenewText').textContent || '',
    resume: sessionStorage.getItem('cloop_resume'),
    signin_at: sessionStorage.getItem('cloop_signin_at'),
  };
}

// 1. A lapsed SSO session meets its first request at boot. No /api/me has
//    answered — and on an SSO hub it cannot, needing a session too — so the
//    hint on the refusal is the only thing that can say "go to the provider".
async function ssoLapsedAtBoot() {
  const {assigns} = await boot(h => refuse(h, '/api/projects', true));
  // Nothing was on screen yet but the defaults, so there is no view to keep.
  return view(assigns);
}

// 2. A token-only hub, unchanged: its 401 carries no hint, and the prompt is
//    the way in on a deployment with no identity provider.
async function tokenHub() {
  const {assigns} = await boot(h => refuse(h, '/api/projects', false));
  return view(assigns);
}

// 3. A live session lapses under an open tab, discovered the way it usually
//    is: the socket drops and its reconnect probe is refused. A second refusal
//    must not navigate again — a hub that keeps refusing would otherwise
//    bounce the tab between here and the provider.
async function ssoSocketDrop() {
  const {h, assigns} = await boot(null);
  if (!h.sockets.length) return {error: 'no WebSocket was opened at boot'};
  refuse(h, '/api/state', true);
  h.sockets[h.sockets.length - 1].finishClose();
  await globalThis.__settle(10);
  const first = view(assigns);
  h.sockets[h.sockets.length - 1].finishClose();
  await globalThis.__settle(10);
  return {first, second: view(assigns)};
}

// 4. The Task 20330 bug. The page learned it is on an SSO hub while signed in,
//    then /api/me reports no session (as it does for a token-authenticated
//    caller), and a 401 arrives without the hint — from a proxy, say. "No live
//    session" must not be read as "not an SSO hub".
async function modeOutlivesTheSession() {
  const {h, assigns} = await boot(h2 => {
    h2.me = {oidc_enabled: true, authenticated: true, permissions: [], global_permissions: []};
  });
  // refreshPermissions runs on DOMContentLoaded, which the shim never fires;
  // returning to the project list runs it too.
  window.clearProjectSelection();
  await globalThis.__settle(10);
  h.me = {oidc_enabled: true, authenticated: false, permissions: [], global_permissions: []};
  window.clearProjectSelection();
  await globalThis.__settle(10);
  refuse(h, '/api/state', false);
  h.sockets[h.sockets.length - 1].finishClose();
  await globalThis.__settle(10);
  return view(assigns);
}

// 5. Back from a sign-in that did not produce a working session: the page that
//    sent the user away recorded when, and nothing since has confirmed a
//    session. Navigating again would be a loop; the banner says what happened
//    and leaves the button for a person to try anyway.
async function loopGuard() {
  const {assigns} = await boot(h => refuse(h, '/api/projects', true),
    {cloop_signin_at: String(Date.now() - 5000)});
  const before = view(assigns);
  // The banner's own button is a person choosing to try again: allowed.
  window.signInAgain();
  return {before, after_click: view(assigns)};
}

// 6. A sign-in the dashboard sent the user through comes back to what they
//    were looking at: the project (by path — indices shift) and the tab.
async function resume() {
  const {h, assigns} = await boot(null, {
    cloop_resume: JSON.stringify({path: '/p/beta', tab: 'tasks', at: Date.now()}),
    cloop_signin_at: String(Date.now() - 3000),
  });
  const ws = h.sockets[h.sockets.length - 1];
  return {
    assigns,
    breadcrumb: document.getElementById('breadcrumbName').textContent,
    tasks_active: document.getElementById('tab-tasks').classList.contains('active'),
    socket_scope: ws ? ws.projectIdx : null,
    resume_left: sessionStorage.getItem('cloop_resume'),
  };
}

// 7. What signInAgain leaves behind for that page to find: where to return in
//    the URL, and the view in session storage.
async function savesTheView() {
  const {h, assigns} = await boot(null);
  window.openProject(1, 'beta');
  await globalThis.__settle(5);
  window.switchTab('kanban');
  refuse(h, '/api/state', true);
  h.sockets[h.sockets.length - 1].finishClose();
  await globalThis.__settle(10);
  return view(assigns);
}

(async () => {
  const out = {};
  for (const [name, fn] of Object.entries({
    sso_lapsed_at_boot: ssoLapsedAtBoot,
    token_hub: tokenHub,
    sso_socket_drop: ssoSocketDrop,
    mode_outlives_the_session: modeOutlivesTheSession,
    loop_guard: loopGuard,
    resume: resume,
    saves_the_view: savesTheView,
  })) {
    try {
      out[name] = await fn();
    } catch (e) {
      out[name] = {error: String((e && e.stack) || e)};
    }
  }
  process.stdout.write(JSON.stringify(out, null, 2));
  process.exit(0);
})();
