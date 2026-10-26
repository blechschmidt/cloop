// ── Split a task into sub-tasks (Task 20154) ─────────────────────────────────
//
// The dialog a pending task's Split button opens: the AI proposes sub-tasks
// for that task, the user keeps the ones they want, and applying adds them in
// sequence — each depending on the one before — and marks the task skipped.
//
// Fetched on the first Split rather than bundled (static.go, deferredScripts):
// Task 20441 moved it here to pay for Decompose, the button beside Add Task
// that plans a task before it exists. It runs outside the dashboard's IIFE, so
// it is handed the helpers it calls, and the only name it puts on window is
// the factory.
(function () {
  'use strict';

  window.cloopSplitPanel = function (h) {
    const {api, pUrl, esc, toast} = h;
    const {openOverlay, closeOverlay} = window;
    const el = id => document.getElementById(id);
    let taskId = 0;    // the task being split; 0 while the dialog is closed
    let subtasks = []; // the proposal, each sub-task with a _keep flag
    let busy = false;  // a proposal or an apply is in flight

    function open(id) {
      id = +id;
      const st = h.tl.state();
      const t = ((st && st.plan && st.plan.tasks) || []).find(x => x.id === id);
      taskId = id;
      subtasks = [];
      busy = true;
      el('dc-title').textContent = 'Split Task #' + id + (t && t.title ? ' — ' + t.title : '');
      el('dc-apply-btn').style.display = 'none';
      el('dc-count').textContent = '';
      el('dc-body').innerHTML =
        '<div class="dc-spin"><span class="spinner"></span>' +
        '<span>Asking the AI to break this task into smaller sub-tasks… this can take a minute.</span></div>';
      openOverlay('dc-overlay', {dismiss: close});

      return api(pUrl('/api/tasks/' + id + '/decompose'), {}).then(d => {
        if (taskId !== id) return; // closed, or reopened for another task
        busy = false;
        if (!d.ok) {
          el('dc-body').innerHTML =
            '<div class="empty-state"><h3>Split failed</h3><p>' + esc(d.error || 'unknown error') + '</p></div>';
          // The proposal is made on the project's executor (Task 20442): one
          // with no Claude login also opens, over this, the dialog that grants
          // one — as Revise does.
          h.harnessRefused(d);
          return;
        }
        subtasks = (d.subtasks || []).map(s => Object.assign({_keep: true}, s));
        render();
      }).catch(() => {
        if (taskId !== id) return;
        busy = false;
        el('dc-body').innerHTML =
          '<div class="empty-state"><h3>Request failed</h3><p>Could not reach the server.</p></div>';
      });
    }

    function close() {
      closeOverlay('dc-overlay');
      taskId = 0;
      subtasks = [];
      busy = false;
    }

    function render() {
      const body = el('dc-body');
      if (!subtasks.length) {
        body.innerHTML = '<div class="empty-state"><h3>No sub-tasks proposed</h3>' +
          '<p>The AI did not propose any sub-tasks for this task. Close the dialog and try again.</p></div>';
        footer();
        return;
      }
      body.innerHTML =
        '<div class="dc-hint">Review the proposed sub-tasks. Applying adds the selected ones in sequence ' +
        '(each depending on the previous) and marks the parent task as <strong>skipped</strong>.</div>' +
        subtasks.map((st, i) =>
          '<label class="dc-sub' + (st._keep ? '' : ' off') + '">' +
            '<input type="checkbox" ' + (st._keep ? 'checked' : '') + ' data-change="toggle" data-arg="' + i + '">' +
            '<div style="flex:1;min-width:0">' +
              '<div class="dc-sub-title">' + (i + 1) + '. ' + esc(st.title || '') + '</div>' +
              (st.description ? '<div class="dc-sub-desc">' + esc(st.description) + '</div>' : '') +
              ((st.role || st.estimated_minutes) ?
                '<div class="dc-sub-meta">' +
                  (st.role ? '<span>' + esc(st.role) + '</span>' : '') +
                  (st.estimated_minutes ? '<span>est: ' + esc(st.estimated_minutes) + 'm</span>' : '') +
                '</div>' : '') +
            '</div>' +
          '</label>'
        ).join('');
      footer();
    }

    // toggle keeps or drops sub-task i; its checkbox's change calls it.
    function toggle(i) {
      const st = subtasks[+i];
      if (!st) return;
      st._keep = !st._keep;
      render();
    }

    function footer() {
      const kept = subtasks.filter(st => st._keep).length;
      const btn = el('dc-apply-btn');
      btn.style.display = subtasks.length ? '' : 'none';
      btn.disabled = kept === 0 || busy;
      btn.textContent = kept ? 'Add ' + kept + ' sub-task' + (kept === 1 ? '' : 's') : 'Add sub-tasks';
      el('dc-count').textContent = subtasks.length ? kept + '/' + subtasks.length + ' selected' : '';
    }

    function apply() {
      if (busy || !taskId) return;
      const id = taskId;
      const kept = subtasks.filter(st => st._keep).map(st => ({
        title: st.title || '',
        description: st.description || '',
        role: st.role || '',
        estimated_minutes: st.estimated_minutes || 0,
      }));
      if (!kept.length) return;
      busy = true;
      footer();
      return api(pUrl('/api/tasks/' + id + '/decompose/apply'), {subtasks: kept}).then(d => {
        busy = false;
        if (!d.ok) {
          footer();
          toast(d.error || 'Apply failed', 'err');
          return;
        }
        close();
        // The list catches up from the state_diff the hub sends every page on
        // the project; refetching the state here as well toasted "Refreshed"
        // over this.
        const n = (d.added || []).length;
        toast('Task #' + d.parent_id + ' split into ' + n + ' sub-task' + (n === 1 ? '' : 's'), 'ok');
      }).catch(() => {
        busy = false;
        footer();
        toast('Request failed', 'err');
      });
    }

    return h.mount({open, close, toggle, apply}, null, null, `
<div id="dc-overlay" data-overlay="class:open" data-dismiss="close">
  <div id="dc-modal" role="dialog" aria-modal="true" aria-labelledby="dc-title">
    <div class="dc-header">
      <h2 id="dc-title">Split Task</h2>
      <button class="dc-close" data-act="close" aria-label="Close">&times;</button>
    </div>
    <div id="dc-body" class="dc-body"></div>
    <div class="modal-footer">
      <span id="dc-count" style="margin-right:auto;font-size:12px;color:var(--muted)"></span>
      <button class="btn" data-act="close">Cancel</button>
      <button class="btn primary" id="dc-apply-btn" data-act="apply" style="display:none">Add sub-tasks</button>
    </div>
  </div>
</div>`);
  };
})();
