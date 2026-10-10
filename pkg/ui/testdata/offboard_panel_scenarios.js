// offboard_panel_scenarios.js — drives the real dashboard bundle through the
// offboarding preview's stored-credentials section and its legal hold
// (Task 20400).
//
// The panel is two deferred scripts deep: the Secrets panel's Preview button
// fetches offboard.js and hands it the helpers it calls. What is asserted is
// what reaches the server and what reaches the screen — that the Legal hold box
// is sent as keep_credentials, that every personal secret, the shared project
// that loses one, each Claude login copy and an unreachable hub member are
// listed, that the disposition reads "destroyed" or "kept" accordingly, and that
// a name chosen by a person is escaped.
//
// Run by TestDashboard_OffboardPreviewShowsTheStoredFootprint. Prints one JSON
// document.
//
// Usage: node offboard_panel_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

function report(keep) {
  return {
    dry_run: true,
    target: {input: 'alice@example.com', key: 'alice@example.com', emails: ['alice@example.com'], subjects: ['u-alice']},
    sessions: [], tokens: [], glasses: [], denies: [{id: 'rb_1', claim: 'email', value: 'alice@example.com'}],
    leases: [], tasks: [], projects: [], memberships: [],
    credentials: {
      keep: keep,
      secrets: [{id: 'sec_1', name: 'alice-pat', kind: 'github_pat', created_at: '2026-10-01T09:00:00Z'}],
      grants: [{id: 'grant_1', secret_id: 'sec_1', secret_name: 'alice-pat', subject: 'project:/srv/shared'}],
      requests: [{id: 'req_1', requested_by: 'alice@example.com', secret_name: '<img src=x onerror=alert(1)>', subject: 'project:/srv/alice'}],
      claude: [{member: 'hub_a1', owner_key: 'alice@example.com', dir: '/var/lib/cloop/.config/cloop/claude-identities/ff8d9819fc0e12bf0d24892e45987e24', exists: true, credential: true}],
      claude_unreached: [{member: 'hub_old', detail: 'did not answer within 1m0s'}],
    },
    warnings: [],
  };
}

async function boot(keep) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.routes['/api/users/offboard'] = report(keep);
  require(bundlePath);
  await globalThis.__settle(5);
  return h;
}

async function preview(h, keep) {
  document.getElementById('offboardIdentity').value = 'alice@example.com';
  document.getElementById('offboardKeep').checked = keep;
  await window.panelAct('secrets', 'offboardPreview');
  await globalThis.__settle(10);
  const sent = h.requests.filter(r => r.url === '/api/users/offboard');
  const last = sent.length ? JSON.parse(sent[sent.length - 1].body || '{}') : {};
  return {html: document.getElementById('offboardResult').innerHTML || '', body: last, calls: sent.length};
}

async function main() {
  const out = {};

  {
    const h = await boot(false);
    const {html, body, calls} = await preview(h, false);
    out.destroy = {
      calls,
      dry_run_sent: body.dry_run === true,
      keep_sent: body.keep_credentials === true,
      lists_secret: html.indexOf('alice-pat') !== -1,
      names_shared_project: html.indexOf('project:/srv/shared') !== -1,
      lists_claude_copy: html.indexOf('claude-identities/ff8d9819fc0e12bf0d24892e45987e24') !== -1,
      names_member: html.indexOf('hub_a1') !== -1,
      names_unreached_member: html.indexOf('hub_old') !== -1,
      says_destroyed: html.indexOf('Personal secrets — destroyed') !== -1,
      says_kept: html.indexOf('kept under the legal hold') !== -1,
      raw_markup_injected: html.indexOf('<img src=x') !== -1,
      escaped_name_shown: html.indexOf('&lt;img src=x') !== -1,
    };
  }

  {
    const h = await boot(true);
    const {html, body} = await preview(h, true);
    out.keep = {
      keep_sent: body.keep_credentials === true,
      says_kept: html.indexOf('kept under the legal hold') !== -1,
      says_destroyed: html.indexOf('Personal secrets — destroyed') !== -1,
      button_names_hold: html.indexOf('under a legal hold') !== -1,
    };
  }

  process.stdout.write(JSON.stringify(out));
}

main().catch(err => {
  process.stdout.write(JSON.stringify({fatal: {error: String(err && err.stack || err)}}));
});
