// ledger_scenarios.js — renders tasks whose recorded summary is a provider
// refusal against the real dashboard bundle (Task 20224).
//
// What is being checked is that an operator can tell, from the page alone, that
// a task the plan calls "done" never actually ran — because for about a hundred
// iterations nobody could. The finding existed only in `cloop task
// audit-ledger`, which nothing ran, so fourteen tasks sat in cloop's own list
// looking finished while three of the features they named were absent from the
// tree entirely.
//
// Driving the bundle rather than grepping it matters here for the usual reason:
// the badge markup existing in a source file proves nothing about whether it
// survives the filter, the sort, the escaping and the concatenation order. It
// also catches the specific mistake this panel invites — treating a *reopened*
// task as an open finding, which would leave the banner permanently accusing
// the plan of work it has already re-queued.
//
// Run by TestDashboard_AbortedOutcomesAreVisible. Each scenario returns
// {html, banner, ids, error} as one JSON document on stdout.
//
// Usage: node ledger_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const USAGE_LIMIT = "You've hit your limit · resets 2:50pm (UTC)";
const ORG_QUOTA = "You've hit your org's monthly usage limit";

// Four tasks covering every state the record can be in, plus a control. The
// control is what proves the badge is driven by the data rather than always
// rendered.
const PROJECT = {
  goal: 'evolve cloop',
  status: 'running',
  plan: {
    goal: 'evolve cloop',
    tasks: [
      // An open finding: still filed as done on a refusal. This one is the
      // reason the banner exists.
      {
        id: 194, title: 'cloop task watch-deps', status: 'done', priority: 1,
        result: USAGE_LIMIT,
        abort: {
          class: 'usage_limit', reason: 'subscription limit reached',
          evidence: USAGE_LIMIT, summary_fingerprint: 'deadbeefdeadbeef',
        },
      },
      // A second open finding in a different class, so the banner has to
      // summarise by cause rather than just count.
      {
        id: 20104, title: 'Add chaos test for SyncFromDisk', status: 'done', priority: 1,
        result: ORG_QUOTA,
        abort: {
          class: 'quota_exceeded', reason: 'organisation monthly usage limit reached',
          evidence: ORG_QUOTA, summary_fingerprint: 'cafebabecafebabe',
        },
      },
      // Already reopened: pending, carries the record as history. Must NOT be
      // counted as open, and must NOT offer the verdict buttons again.
      {
        id: 195, title: 'cloop task ai-pr-review', status: 'pending', priority: 1,
        result: USAGE_LIMIT,
        abort: {
          class: 'usage_limit', reason: 'subscription limit reached',
          evidence: USAGE_LIMIT, summary_fingerprint: 'deadbeefdeadbeef',
        },
      },
      // Triaged: the work exists despite the summary. Stays done, stays
      // visible, must not be counted as open.
      {
        id: 193, title: 'cloop task tdd', status: 'done', priority: 1,
        result: USAGE_LIMIT,
        abort: {
          class: 'usage_limit', reason: 'subscription limit reached',
          evidence: USAGE_LIMIT, summary_fingerprint: 'deadbeefdeadbeef',
          cleared: true, cleared_by: 'triage',
          cleared_note: 're-landed by cmd/task_tdd.go',
        },
      },
      // Control: an ordinary completed task with no record at all.
      {id: 20221, title: 'Prove a commit reproduces', status: 'done', priority: 2,
       result: 'Shipped cloop task reproduce. TASK_DONE'},
    ],
  },
};

function clone(o) { return JSON.parse(JSON.stringify(o)); }

async function boot() {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.states = {0: clone(PROJECT)};
  h.projects = {multi_project: false, stats: {total_projects: 1}, projects: []};

  require(bundlePath);
  await globalThis.__settle(5);
  const ws = h.sockets[h.sockets.length - 1];
  if (ws) ws.open();
  await globalThis.__settle(3);
  return h;
}

function bannerHTML() {
  const el = document.getElementById('abortedLedgerBanner');
  if (!el) return '';
  // A hidden banner is not a rendered banner: an operator sees nothing.
  if (el.style && el.style.display === 'none') return '';
  return el.innerHTML || '';
}

const scenarios = {
  // Every state must be legible in the list the operator actually looks at,
  // and the banner must count only the findings that are still open.
  async task_list() {
    await boot();
    // Completed tasks are hidden by default, and the findings are all done.
    if (typeof window.toggleCompletedTasks === 'function') {
      window.toggleCompletedTasks();
      await globalThis.__settle(2);
    }
    window.switchTab('tasks');
    await globalThis.__settle(3);
    return {
      html: document.getElementById('taskListFull').innerHTML || '',
      banner: bannerHTML(),
      ids: globalThis.__renderedTaskIds(),
    };
  },

  // With every finding resolved the banner must disappear entirely. A banner
  // that cannot reach zero is one an operator learns to ignore.
  async all_resolved() {
    const h = await boot();
    const st = clone(PROJECT);
    st.plan.tasks.forEach(function(t) {
      if (!t.abort) return;
      t.abort.cleared = true;
      t.abort.cleared_note = 'checked';
    });
    h.states = {0: st};
    if (typeof window.refreshState === 'function') window.refreshState();
    await globalThis.__settle(5);
    return {html: '', banner: bannerHTML(), ids: []};
  },
};

(async () => {
  const out = {};
  for (const [name, fn] of Object.entries(scenarios)) {
    try {
      out[name] = await fn();
    } catch (e) {
      out[name] = {html: '', banner: '', ids: [], error: String((e && e.stack) || e)};
    }
  }
  process.stdout.write(JSON.stringify(out));
})();
