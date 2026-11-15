// ── The review gate's verdict on a task (Task 20357) ────────────────────────
//
// What the project's review gate — a reviewer model checking a task's changes
// before they are pushed or merged — said about a task: the verdict, the
// reviewer and its rounds, its findings, and the pushes it held. Drawn into
// #td-review in the task's details; 12-task-crud.js draws the empty section and
// calls show() through panelAct when a task with a verdict is opened.
//
// Deferred by Task 20496 to pay for the Move dialog's button on first paint.
// Everything shown came from a model or a run's record, so all of it goes
// through esc. It runs outside the dashboard's IIFE and puts nothing on window
// but its factory.
(function () {
  'use strict';

  window.cloopTdreviewPanel = function (h) {
    const {esc} = h;
    const labels = {approved: 'approved', changes_requested: 'changes requested', unavailable: 'no verdict', no_changes: 'nothing to review'};

    function show(r) {
      const box = document.getElementById('td-review');
      if (!box || !r) return;
      box.className = 'td-section ' + (r.blocked ? 'fail' : (r.verdict === 'approved' || r.verdict === 'no_changes' ? 'done' : 'warn'));
      const who = r.model || r.provider || '';
      const meta = (who ? 'Reviewer ' + who + ' · ' : '') + r.rounds + ' review(s)' +
        (r.fix_rounds ? ', sent back ' + r.fix_rounds + '×' : '') + ' · mode ' + r.mode +
        (r.blocked ? ' — nothing was pushed or merged.' : '');
      let out = '<h3>Review gate: ' + esc(labels[r.verdict] || r.verdict) + '</h3><div class="td-text">' + esc(meta) + '</div>';
      if (r.error) out += '<div class="td-text">' + esc(r.error) + '</div>';
      if (r.summary) out += '<div class="td-text">' + esc(r.summary) + '</div>';
      if (r.findings && r.findings.length) {
        out += '<ul style="margin:6px 0 0 18px">' + r.findings.map(f => '<li><strong>' + esc(f.severity) + '</strong> ' +
          (f.file ? '<code>' + esc(f.file + (f.line ? ':' + f.line : '')) + '</code> ' : '') + esc(f.title) +
          (f.detail ? ' — ' + esc(f.detail) : '') + '</li>').join('') + '</ul>';
      }
      if (r.published && r.published.length) {
        out += '<div class="td-text">Held pushes: ' + r.published.map(p => esc(p.remote + ' ' + p.ref + ': ' + p.outcome +
          (p.detail ? ' (' + p.detail + ')' : ''))).join('; ') + '</div>';
      }
      box.innerHTML = out;
    }

    return h.mount({show});
  };
})();
