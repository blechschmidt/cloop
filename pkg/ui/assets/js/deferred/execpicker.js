// ── Execution target picker (Task 20160) ────────────────────────────────────
//
// Where a project's harness runs: the dialog the Overview's executor card
// opens. Fetched on the first press of the card since Task 20456, its markup
// with it; it was part of 23-executors.js.
//
// It runs outside the dashboard's IIFE, so it is handed the helpers it calls —
// pidx is the project the Overview shows, null with none selected — and the
// only name it puts on window is the factory. open() runs on every press.
(function () {
  'use strict';

  window.cloopExecpickerPanel = function (h) {
    const {api, esc, toast, execKind: _execKindLabel} = h;
    const {openOverlay, closeOverlay, loadExecutors} = window;

    function open() {
      const sel = document.getElementById('epExecutor');
      const err = document.getElementById('epError');
      if (err) err.style.display = 'none';
      openOverlay('executor-picker-overlay', {dismiss: close});
      if (sel) sel.innerHTML = '<option value="">Loading…</option>';
      // Always refetch: an executor may have gone offline, or the policy may
      // have changed, since the tab was last painted.
      return loadExecutors().then(d => _populateExecutorPicker(d));
    }

    function _populateExecutorPicker(d) {
      const sel = document.getElementById('epExecutor');
      if (!sel) return;
      d = d || {};
      const proj = d.project || {};
      const execs = d.executors || [];
      let h = '<option value="">Registry default'
        + (d.default_id ? ' (' + esc(d.default_id) + ')' : '') + '</option>';
      execs.forEach(ex => {
        const label = (ex.name || ex.id) + ' · ' + _execKindLabel(ex.kind)
          + (ex.status ? ' · ' + ex.status : '')
          + (ex.blocked ? ' · blocked by policy' : '');
        h += '<option value="' + esc(ex.id) + '"' + (ex.blocked ? ' disabled' : '')
          + (proj.executor_id === ex.id ? ' selected' : '') + '>' + esc(label) + '</option>';
      });
      sel.innerHTML = h;
      const hint = document.getElementById('epHint');
      if (hint) {
        hint.textContent = proj.bound
          ? 'Currently pinned to ' + proj.executor_id + '.'
          : 'Currently inheriting the registry default'
            + (proj.effective_id ? ' (' + proj.effective_id + ')' : '') + '.';
      }
    }

    function close() {
      closeOverlay('executor-picker-overlay');
    }

    function save() {
      const sel = document.getElementById('epExecutor');
      const errEl = document.getElementById('epError');
      const btn = document.getElementById('epSaveBtn');
      if (!sel) return;
      const idx = h.pidx();
      if (idx === null) {
        if (errEl) { errEl.textContent = 'Select a project first.'; errEl.style.display = 'block'; }
        return;
      }
      if (errEl) errEl.style.display = 'none';
      if (btn) btn.disabled = true;

      return api('/api/projects/' + idx + '/executor', {executor_id: sel.value}).then(d => {
        if (btn) btn.disabled = false;
        if (!d || d.error) {
          if (errEl) {
            // A 409 body carries a remediation sentence naming the alternatives;
            // showing it verbatim is the whole point of returning it.
            errEl.textContent = ((d && d.error) || 'Failed to set executor')
              + (d && d.remediation ? ' — ' + d.remediation : '');
            errEl.style.display = 'block';
          }
          return;
        }
        toast('Execution target updated', 'ok');
        close();
        loadExecutors();
      }).catch(err => {
        if (btn) btn.disabled = false;
        if (errEl) {
          errEl.textContent = 'Failed to set executor: ' + (err && err.message || String(err));
          errEl.style.display = 'block';
        }
      });
    }

    return h.mount({open, close, save}, null, null, `
    <div id="executor-picker-overlay" data-overlay="flex" data-dismiss="close" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:50;align-items:center;justify-content:center">
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;width:560px;max-width:95vw;max-height:90vh;overflow:auto">
        <h2 style="font-size:15px;font-weight:600;margin-bottom:6px">Execution target</h2>
        <p style="font-size:12px;color:var(--muted);margin-bottom:16px;line-height:1.5">
          Where this project's harness runs. Changing it takes effect on the next run; work already in flight
          stays on the executor that started it.
        </p>
        <div class="form-group">
          <label class="form-label">Executor</label>
          <select class="form-select" id="epExecutor"></select>
        </div>
        <div id="epHint" style="font-size:11.5px;color:var(--muted);margin-bottom:12px;line-height:1.5"></div>
        <div id="epError" style="font-size:12px;color:var(--red);margin-bottom:8px;display:none"></div>
        <div class="modal-footer">
          <button class="btn" data-act="close">Cancel</button>
          <button class="btn primary" id="epSaveBtn" data-act="save">Save</button>
        </div>
      </div>
    </div>
    `);
  };
})();
