// claude_usage_scenarios.js — drives the real dashboard bundle through the two
// views of Claude Code subscription usage: the Overview's caps panel and the
// Budget tab's usage panel (Task 20490).
//
// Fable's weekly window reaches the dashboard as usage.seven_day_models, a
// list of {model, utilization, resets_at}, because the usage API reports it
// only as a model-scoped row of its limits[] list. The model's name is the
// server's, so it is also checked here that a hostile one renders as text.
//
// Run by TestDashboard_LimitViewsShowModelWindows. Prints one JSON document.
//
// Usage: node claude_usage_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const RESET = '2026-11-13T22:00:00.283105Z';
const HOSTILE = '<img src=x onerror=alert(1)>';

// usage is the snapshot as /api/claude-usage serves it and as
// /api/claudecode-limits nests it under "usage".
function usage(models) {
  const u = {
    seven_day: {utilization: 61, resets_at: RESET},
    fetched_at: '2026-11-10T21:27:55Z',
  };
  if (models) u.seven_day_models = models;
  return u;
}

async function boot(routes) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  Object.assign(h.routes, routes);
  require(bundlePath);
  await globalThis.__settle(5);
  return h;
}

// overview renders the Overview's caps panel from a /api/claudecode-limits
// answer carrying u, and returns the panel's markup.
async function overview(u) {
  // No caps, so the first percentage after a label is its utilization and
  // not a "(cap N%)" note.
  await boot({'/api/claudecode-limits': {
    limits: {max_weekly_pct: 0, max_five_hour_pct: 0, max_weekly_opus_pct: 0, max_weekly_sonnet_pct: 0},
    usage: u,
    violations: [],
  }});
  window.loadCCLimits({force: true});
  await globalThis.__settle(5);
  return document.getElementById('ccLimitsUsage').innerHTML || '';
}

// budget renders the Budget tab's usage panel from a /api/claude-usage answer
// of u. The panel is the tab's deferred script, fetched on first use.
async function budget(u) {
  await boot({'/api/claude-usage': u});
  await window.panelAct('budget', 'loadClaudeUsage');
  await globalThis.__settle(5);
  return document.getElementById('claudeUsagePanel').innerHTML || '';
}

// pctAfter is the percentage the view prints after a label, or null.
function pctAfter(html, label) {
  const at = html.indexOf(label);
  if (at === -1) return null;
  const m = /(\d+)%/.exec(html.slice(at + label.length));
  return m ? Number(m[1]) : null;
}

function report(html) {
  return {
    fable_pct: pctAfter(html, 'Weekly Fable'),
    fable_count: html.split('Weekly Fable').length - 1,
    weekly_all_pct: pctAfter(html, 'Weekly (all)') ?? pctAfter(html, 'Weekly (All Models)'),
    shows_undefined: html.indexOf('undefined') !== -1,
    shows_nan: html.indexOf('NaN') !== -1,
    raw_tag: html.indexOf('<img') !== -1,
    escaped_tag: html.indexOf('&lt;img src=x onerror=alert(1)&gt;') !== -1,
  };
}

async function main() {
  const out = {};
  const fable = [{model: 'Fable', utilization: 7, resets_at: RESET}];
  const hostile = [{model: HOSTILE, utilization: 12, resets_at: RESET}];

  out.overview = report(await overview(usage(fable)));
  out.overview_hostile = report(await overview(usage(hostile)));
  // A hub that predates seven_day_models, or a plan with no model window.
  out.overview_none = report(await overview(usage(null)));

  out.budget = report(await budget(usage(fable)));
  out.budget_hostile = report(await budget(usage(hostile)));
  out.budget_none = report(await budget(usage(null)));
  return out;
}

main().then(
  out => process.stdout.write(JSON.stringify(out)),
  err => process.stdout.write(JSON.stringify({fatal: {error: String(err && err.stack || err)}})),
);
