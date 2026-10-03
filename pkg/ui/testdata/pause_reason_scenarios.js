// pause_reason_scenarios.js — renders paused projects against the real
// dashboard bundle (Task 20285).
//
// What is being checked is that an operator scanning the dashboard can tell
// *why* a project stopped. Before the pause reason existed, ~26 different
// conditions all rendered as the single word "paused": an approval waiting on
// a human, a spent budget, a Ctrl-C, a killed process and an exhausted
// subscription window were indistinguishable, so a fleet could sit stalled for
// a week with the screen giving no hint which of those it was.
//
// Driving the bundle rather than grepping it matters for the usual reason: the
// markup existing in a source file proves nothing about whether it survives
// the render path, the escaping and the concatenation. It also pins the one
// thing this formatter invites getting wrong — the clock must be rendered in
// the *reader's* timezone, so the server sends an instant and the browser
// formats it. A test that hard-coded "14:50" would pass only on a UTC box.
//
// Run by TestDashboard_PauseReasonIsVisible. Each scenario returns
// {html, badge, text, error} as one JSON document on stdout.
//
// Usage: node pause_reason_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

// A fixed instant, formatted by the same Date the bundle uses so the
// expectation follows the runner's timezone instead of assuming UTC.
const RESET_MS = Date.now() + 3 * 60 * 60 * 1000;
const RESET_ISO = new Date(RESET_MS).toISOString();

function expectedClock() {
  const d = new Date(RESET_MS);
  return String(d.getHours()).padStart(2, '0') + ':' +
         String(d.getMinutes()).padStart(2, '0');
}

const CAP_REASON = {
  code: 'usage_cap',
  detail: '5-hour cap reached',
  resumes_at: RESET_ISO,
};

const PROJECT = {
  goal: 'evolve cloop',
  status: 'paused',
  pause_reason: CAP_REASON,
  plan: {goal: 'evolve cloop', tasks: []},
};

// A run that stopped because the database refused a write it could not do
// without (Task 20362): what the orchestrator stores as the pause, and the
// session_failed row it journals beside it.
const UNSAVED_DETAIL = "could not save task #3's completion (status done): database or disk is full";
const UNSAVED_EVENT = {
  id: -9, kind: 'session_failed', timestamp: new Date().toISOString(),
  task_id: 3, task_title: 'Add login', step: -1,
  message: 'Run stopped: ' + UNSAVED_DETAIL +
    '. Nothing after that was recorded; the next run recovers the tasks this one left in progress.',
  details: {cause: 'state_not_persisted', status_recorded: true},
};

function clone(o) { return JSON.parse(JSON.stringify(o)); }

async function boot(state, projects, routes) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.states = {0: clone(state)};
  h.projects = projects || {multi_project: false, stats: {total_projects: 1}, projects: []};
  h.routes = routes || {};

  require(bundlePath);
  await globalThis.__settle(5);
  const ws = h.sockets[h.sockets.length - 1];
  if (ws) ws.open();
  await globalThis.__settle(3);
  return h;
}

const scenarios = {
  // The overview badge must name the cause and the clock, not just "Paused".
  async overview_badge() {
    await boot(PROJECT);
    const el = document.getElementById('statusBadge');
    return {badge: el ? (el.innerHTML || '') : '', clock: expectedClock()};
  },

  // The same reason must reach the project grid, which is where an operator
  // scans a fleet rather than one project.
  async project_card() {
    await boot(PROJECT, {
      multi_project: true,
      stats: {total_projects: 1},
      projects: [{
        name: 'cloop', path: '/srv/cloop', status: 'paused',
        pause_reason: CAP_REASON, health: 'idle', goal: 'evolve cloop',
        total_tasks: 3, done_tasks: 1, running: false,
      }],
    });
    window.switchTab('projects');
    await globalThis.__settle(3);
    const el = document.getElementById('projList');
    return {html: el ? (el.innerHTML || '') : '', clock: expectedClock()};
  },

  // A pause with no known reset must not imply one — "resumes" with no time,
  // or a time invented from nothing, is worse than saying only the cause.
  async no_reset() {
    const st = clone(PROJECT);
    st.pause_reason = {code: 'approval', detail: 'approval declined for task #7'};
    await boot(st);
    const el = document.getElementById('statusBadge');
    return {badge: el ? (el.innerHTML || '') : ''};
  },

  // A reason carrying no detail falls back to the code's prose label rather
  // than showing the operator a raw identifier like "token_budget".
  async bare_code() {
    const st = clone(PROJECT);
    st.pause_reason = {code: 'token_budget'};
    await boot(st);
    const el = document.getElementById('statusBadge');
    return {badge: el ? (el.innerHTML || '') : ''};
  },

  // A reset already in the past reads as pending, not as a future time: the
  // hub's sweep runs on an interval, so between the reset and the next sweep
  // "resumes 14:50" at 15:10 would look broken.
  async reset_already_passed() {
    const st = clone(PROJECT);
    st.pause_reason = {
      code: 'usage_cap', detail: '5-hour cap reached',
      resumes_at: new Date(Date.now() - 60 * 1000).toISOString(),
    };
    await boot(st);
    const el = document.getElementById('statusBadge');
    return {badge: el ? (el.innerHTML || '') : ''};
  },

  // A run that stopped because its progress could not be saved says what was
  // lost — in the badge, and in the Event History beside it.
  async unsaved_progress() {
    const st = clone(PROJECT);
    st.pause_reason = {code: 'state_not_persisted', detail: UNSAVED_DETAIL};
    await boot(st, null, {'/api/event-history': {entries: [UNSAVED_EVENT], total: 1}});
    const badge = document.getElementById('statusBadge');
    const history = document.getElementById('stepList');
    return {
      badge: badge ? (badge.innerHTML || '') : '',
      html: history ? (history.innerHTML || '') : '',
    };
  },

  // The same stop recorded by the hub with no detail of its own still reads
  // as prose.
  async unsaved_progress_bare() {
    const st = clone(PROJECT);
    st.pause_reason = {code: 'state_not_persisted'};
    await boot(st);
    const el = document.getElementById('statusBadge');
    return {badge: el ? (el.innerHTML || '') : ''};
  },

  // A running project must carry no pause text at all.
  async running_project() {
    const st = clone(PROJECT);
    st.status = 'running';
    delete st.pause_reason;
    await boot(st);
    const el = document.getElementById('statusBadge');
    return {badge: el ? (el.innerHTML || '') : ''};
  },
};

(async function main() {
  const out = {};
  for (const name of Object.keys(scenarios)) {
    try {
      out[name] = await scenarios[name]();
    } catch (e) {
      out[name] = {error: (e && e.stack) ? e.stack : String(e)};
    }
  }
  process.stdout.write(JSON.stringify(out));
})();
