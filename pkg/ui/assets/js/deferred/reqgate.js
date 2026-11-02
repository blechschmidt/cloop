// ── The requirements gate's verdict on a task (Task 20461) ──────────────────
//
// What the project's requirements gate found when it last checked a task's
// work: each requirement's verdict, the ones that kept the task from being
// done, regressions, and the commands that failed with the end of their
// output. Drawn into #td-reqgate in the task's details; 12-task-crud.js draws
// the empty section and calls show() through panelAct the first time a task
// with a verdict is opened (static.go, deferredScripts).
//
// A verdict carries the red-green proof of the tests the task added or changed
// (Task 20464); one whose new test passed without the change is "vacuous".
//
// Everything shown came from a test's output or the record a run wrote, so all
// of it goes through esc, and output only ever as text in a <pre>.
(function () {
  'use strict';

  window.cloopReqgatePanel = function (h) {
    const {esc} = h;
    const short = c => (c || '').slice(0, 12);
    const decisions = {
      met: 'the task was let through',
      requeued: 'back to pending with these checks in its next prompt',
      failed: 'the task failed: requirements_unmet',
    };

    function verdictRow(v) {
      const bad = v.blocking;
      const p = v.proof;
      const vacuous = bad && p && p.outcome === 'vacuous';
      const tags = [];
      if (v.linked) tags.push('implements');
      if (v.must) tags.push('must');
      if (v.regression) tags.push('regression: ' + (v.was || 'fulfilled') + (v.was_commit ? ' at ' + short(v.was_commit) : '') + ' before');
      let row = '<li' + (bad ? ' style="color:var(--red)"' : '') + '><strong>R-' + (+v.requirement_id) + '</strong> ' +
        esc(v.title || '') + ' — <strong>' + esc(vacuous ? 'vacuous' : v.verdict) + '</strong>' +
        (tags.length ? ' <span class="td-empty">(' + esc(tags.join(', ')) + ')</span>' : '') +
        (v.summary ? '<div class="td-text">' + esc(v.summary) + '</div>' : '');
      (v.tests || []).filter(t => t.outcome !== 'pass').forEach(t => {
        row += '<div class="td-text"><code>$ ' + esc(t.command || '') + '</code> — ' + esc(t.outcome) +
          (t.outcome === 'fail' ? ' (exit ' + (+t.exit_code) + ')' : '') + (t.error ? ': ' + esc(t.error) : '') + '</div>';
        if (t.output) {
          row += '<pre class="td-pre" style="max-height:240px;overflow:auto">' +
            (t.truncated ? '…\n' : '') + esc(t.output) + '</pre>';
        }
      });
      (v.evidence || []).forEach(e => { row += '<div class="td-text">· ' + esc(e) + '</div>'; });
      if (p) {
        row += '<div class="td-text">Red-green proof: <strong>' + esc(p.outcome || 'error') + '</strong>' +
          (p.before && p.before.commit ? ' at base ' + esc(short(p.before.commit)) : '') +
          (p.summary ? ' — ' + esc(p.summary) : '') + '</div>';
      }
      return row + '</li>';
    }

    function show(c) {
      const sec = document.getElementById('td-reqgate');
      if (!sec || !c) return;
      const unmet = c.outcome === 'unmet';
      const regressions = (c.requirements || []).filter(v => v.regression).length;
      sec.className = 'td-section ' + (unmet ? 'fail' : 'done');
      const meta = ['mode ' + (c.mode || 'linked')];
      if (c.commit) meta.push('commit ' + short(c.commit) + (c.dirty ? ' (with uncommitted changes)' : ''));
      if (c.checked_at) meta.push(h.relTime ? h.relTime(c.checked_at) : c.checked_at);
      if (c.consecutive > 1) meta.push('unmet ' + (+c.consecutive) + ' times in a row');
      let html = '<h3>Requirements gate: ' + (unmet ? 'not met' : 'met') +
        (regressions ? ' · ' + regressions + ' regression' + (regressions > 1 ? 's' : '') : '') + '</h3>' +
        '<div class="td-text">' + esc(meta.join(' · ')) +
        (c.decision && decisions[c.decision] ? ' — ' + esc(decisions[c.decision]) : '') + '</div>';
      if (c.note) html += '<div class="td-text">' + esc(c.note) + '</div>';
      html += '<ul style="margin:6px 0 0 18px">' + (c.requirements || []).map(verdictRow).join('') + '</ul>';
      const first = +(((c.requirements || [])[0] || {}).requirement_id) || 0;
      if (first) {
        html += '<div class="td-text"><span class="task-tag" role="button" tabindex="0" data-action="openRequirement" data-arg="' +
          first + '">Open the Requirements tab</span></div>';
      }
      sec.innerHTML = html;
    }

    return h.mount({show});
  };
})();
