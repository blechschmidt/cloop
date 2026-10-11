// sessions_kind_scenarios.js — the Active Sessions panel with a terminal's
// session beside a browser's (Task 20412), through the real dashboard bundle.
//
// The two kinds idle out on clocks of their own, and the panel colours each
// row's idle time against its own kind's: a terminal fifty minutes quiet on a
// one-hour clock is about to lapse, a browser equally quiet on an eight-hour
// clock is not.
//
// Run by TestDashboard_TerminalSessionsIdleOnTheirOwnClock in
// sessions_kind_frontend_test.go. Printed as one JSON document.
//
// Usage: node sessions_kind_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

async function main() {
  require(shimPath);
  const h = globalThis.__harness;
  h.projects = {multi_project: false, stats: {}, projects: [
    {name: 'api', path: '/srv/api', goal: '', health: 'idle'},
  ]};
  h.routes['/api/sessions'] = {
    sessions: [
      {id: 'cli1', kind: 'cli', client: 'dev-laptop', email: 'alice@example.com',
        idle_seconds: 50 * 60, expires_in_seconds: 3600, user_agent: 'cloop/dev (linux/amd64)'},
      {id: 'web1', kind: 'browser', email: 'alice@example.com',
        idle_seconds: 50 * 60, expires_in_seconds: 3600, user_agent: 'Mozilla/5.0'},
    ],
    total: 2,
    absolute_ttl_seconds: 24 * 3600, idle_timeout_seconds: 8 * 3600,
    cli_absolute_ttl_seconds: 6 * 3600, cli_idle_timeout_seconds: 3600,
  };
  require(bundlePath);
  await globalThis.__settle(5);
  const SEC = await window.panelAct('secrets');
  await SEC.loadSessions();
  await globalThis.__settle(5);

  const rows = document.getElementById('secSessionsBody').innerHTML
    .split('</tr>').filter(r => r.indexOf('<tr') >= 0);
  // The first span-only cell is the idle column; the expiry column follows.
  const idleClass = r => {
    const m = /<td><span class="(sec-ttl[^"]*)">/.exec(r || '');
    return m ? m[1] : '';
  };
  return {
    rows: rows.length,
    cli_idle: idleClass(rows.find(r => r.indexOf('>terminal<') >= 0)),
    browser_idle: idleClass(rows.find(r => r.indexOf('>terminal<') < 0)),
    policy: document.getElementById('secSessionsPolicy').innerHTML,
  };
}

main().then(out => {
  process.stdout.write(JSON.stringify(out) + '\n');
  process.exit(0);
}, err => {
  process.stdout.write(JSON.stringify({error: String(err && err.stack || err)}) + '\n');
  process.exit(0);
});
