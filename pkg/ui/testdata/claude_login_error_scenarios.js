// claude_login_error_scenarios.js — drives the real dashboard bundle through
// what the Claude Code panel shows when the hub refuses a login (Task 20320).
//
// The reported bug was not that the hub refused. It was that the refusal
// arrived as the literal string "[object Object]", so the operator had nothing
// to act on — and the message it replaced happens to name the two config
// changes that fix the hub.
//
// Two things produced that. The hub speaks two error dialects (jsonErr's
// {"error": "text"} and pkg/apierror's {"error": {code, message, details}}, the
// latter from middleware, so authz/quota/rate-limit refusals all arrive nested),
// and this panel was the one place that called fetch() directly instead of
// api() — bypassing parseAPIResponse, which is where 401, 403 and the dialect
// difference are all supposed to be handled once.
//
// Driven through the bundle rather than grepped because the assertion is about
// what ends up on screen after a click.
//
// Run by TestDashboard_ClaudeLoginRefusalIsReadable. Prints one JSON document.
//
// Usage: node claude_login_error_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

// The refusal the live :8888 hub produced, copied from the Go reproduction in
// claude_login_authz_test.go rather than paraphrased — the point is that this
// exact body becomes prose.
const CLAIM_FRESHNESS_MESSAGE =
  "oidcauth: this session's group and role claims are 7m0s old (limit 5m0s) and " +
  "cannot be re-checked: no refresh token is retained for it. Set CLOOP_SECRET_KEY " +
  "so the hub can seal refresh tokens, or set ui.oidc.max_claim_age_minutes: -1 to " +
  "accept sign-in-time claims for privileged actions";

const STRUCTURED_403 = {
  error: {
    code: 'FORBIDDEN',
    message: CLAIM_FRESHNESS_MESSAGE,
    details: {
      reason: 'no_refresh_token',
      required_permission: 'secret.own',
      claim_age_seconds: 420,
      max_claim_age_seconds: 300,
    },
  },
};

// A non-403 structured refusal. 409 is what denyHostSideEffect answers on a hub
// that forbids host execution, and it resolves rather than rejecting, so it is
// the case that reaches the panel's own error branch.
const STRUCTURED_409 = {
  error: {code: 'CONFLICT', message: 'host execution is not permitted on this hub'},
};

// The older flat dialect, which already worked. Kept as a control: a fix that
// handles only the nested shape would trade one bug for another.
const FLAT_409 = {error: 'claude CLI is not installed on this hub'};

async function boot(loginResponse, loginStatus) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;

  h.routes['/api/claudecode/auth/status'] = {
    per_user: true,
    status: {loggedIn: false},
    session: null,
  };
  h.routes['/api/claudecode/auth/login'] = loginResponse;
  if (loginStatus) h.routeStatus['/api/claudecode/auth/login'] = loginStatus;

  require(bundlePath);
  await globalThis.__settle(5);
  return h;
}

const panelHTML = () => (document.getElementById('ccAuthPanel').innerHTML || '');
const toastText = () => (document.getElementById('toast').textContent || '');

// clickSignIn renders the panel, then presses "Sign in with Claude.ai".
async function clickSignIn() {
  await window.loadClaudeAuthStatus();
  await globalThis.__settle(5);
  await window.startClaudeAuthLogin({});
  await globalThis.__settle(5);
}

async function main() {
  const out = {};

  // 0. The reported bug, in the shape that caused it. A 403 is surfaced by
  //    parseAPIResponse as a toast — the dashboard's established place for a
  //    refusal — so that is where the sentence has to appear.
  {
    await boot(STRUCTURED_403, 403);
    await clickSignIn();
    const where = toastText() + '\n' + panelHTML();
    out.structured_403 = {
      seen_len: where.length,
      shows_object_object: where.indexOf('[object Object]') !== -1,
      // The remedy is the part an operator acts on.
      names_secret_key: where.indexOf('CLOOP_SECRET_KEY') !== -1,
      names_max_claim_age: where.indexOf('max_claim_age_minutes') !== -1,
      names_required_permission: where.indexOf('secret.own') !== -1,
    };
  }

  // 1. A structured non-403: resolves, so the panel's own branch renders it.
  {
    await boot(STRUCTURED_409, 409);
    await clickSignIn();
    const html = panelHTML();
    out.structured_409 = {
      shows_object_object: html.indexOf('[object Object]') !== -1,
      shows_message: html.indexOf('host execution is not permitted on this hub') !== -1,
    };
  }

  // 2. The flat dialect still renders. Control for the above.
  {
    await boot(FLAT_409, 409);
    await clickSignIn();
    const html = panelHTML();
    out.flat_409 = {
      shows_object_object: html.indexOf('[object Object]') !== -1,
      shows_message: html.indexOf('claude CLI is not installed on this hub') !== -1,
    };
  }

  // 3. A success must not be mistaken for an error: normalizeAPIError leaves a
  //    body with no error alone, and the handler branches on that, so the login
  //    has to advance to the code-entry step. active:true matches
  //    claudecodeauth.Snapshot, which the panel's in-flight branch requires.
  {
    await boot({session: {active: true, url: 'https://claude.ai/oauth/authorize?x=1', done: false}}, 0);
    await clickSignIn();
    const html = panelHTML();
    out.success = {
      shows_object_object: html.indexOf('[object Object]') !== -1,
      offers_code_input: html.indexOf('ccAuthCode') !== -1,
    };
  }

  return out;
}

main().then(
  out => process.stdout.write(JSON.stringify(out)),
  err => process.stdout.write(JSON.stringify({fatal: {error: String(err && err.stack || err)}})),
);
