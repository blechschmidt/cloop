// ── Verdicts on a task recorded done on a refusal (Task 20224) ───────────────
//
// reopen and clear record the two verdicts available on a task whose stored
// summary is a provider refusal rather than work. Until they existed the only
// way to act on one of these findings was `cloop task audit-ledger --reopen` on
// the CLI — which is why fourteen of them sat unnoticed in this project's own
// plan for about a hundred iterations.
//
// Fetched on the first press of Reopen or Keep rather than bundled (static.go,
// deferredScripts): Task 20477 moved them here to pay for the human review
// gate's row in the task list. It runs outside the dashboard's IIFE, so it is
// handed the helpers it calls, and the only name it puts on window is the
// factory.
(function () {
  'use strict';

  window.cloopLedgerPanel = function (h) {
    const {api, pUrl, toast} = h;

    // Neither verdict refetches the state: the row catches up from the
    // state_diff the hub sends every page on the project once it has saved.
    // Refetching as well toasted "Refreshed" over the verdict's own toast,
    // often before it could be read (the same fix as deferred/split.js).
    function reopen(id) {
      api(pUrl('/api/tasks/' + id + '/reopen-aborted'), {}).then(d => {
        if (d.ok) toast('Task ' + id + ' reopened — it never ran', 'ok');
        else toast(d.error || 'Reopen failed', 'err');
      }).catch(() => toast('Request failed', 'err'));
    }

    // The note is mandatory server-side: a clearance without a reason cannot
    // be told apart from giving up on the audit, and an audit nobody can close
    // is an audit that gets ignored. Prompt rather than a modal because the
    // answer is one line ("re-landed by Task N") and this is a rare,
    // deliberate action.
    function clear(id) {
      const note = window.prompt(
        'This task is recorded as done but its summary is a provider refusal.\n\n' +
        'Where did the work actually land? (e.g. "re-implemented by Task 20016")');
      if (note === null) return;
      if (!note.trim()) { toast('A note is required', 'err'); return; }
      api(pUrl('/api/tasks/' + id + '/clear-aborted'), {note: note.trim()}).then(d => {
        if (d.ok) toast('Task ' + id + ': ledger entry checked', 'ok');
        else toast(d.error || 'Could not clear the finding', 'err');
      }).catch(() => toast('Request failed', 'err'));
    }

    // Mounted with no markup of its own: its buttons are the task list's, and
    // mountPanel hands back the functions panelAct calls.
    return h.mount({reopen, clear});
  };
})();
