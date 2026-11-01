// ── The requirements a task implements, in its edit dialog (Task 20460) ─────
//
// A list of the project's approved requirements — and of any the task already
// implements, whatever their status — to tick, drawn into #modalReqs when the
// edit dialog opens (12-task-crud.js calls pick() through panelAct). Each one
// ticked is part of the task's acceptance contract: its run's agent is given
// the requirement's details and tests.
//
// Nothing is sent unless a box changes. Then the list is kept in the box's
// data-ids, which the dialog's Save sends as `requirements`; a dialog whose
// list never loaded leaves the task's links as they are. The hub checks every
// id against the task's own project (task_requirements_api.go).
//
// Fetched on the first Edit rather than bundled (static.go, deferredScripts).
// It runs outside the dashboard's IIFE, so it is handed the helpers it calls,
// and the only name it puts on window is the factory.
(function () {
  'use strict';

  window.cloopTaskreqsPanel = function (h) {
    const {api, esc, pUrl} = h;
    let taskID = 0;  // the task the dialog edits
    let chosen = []; // the requirements ticked
    let reqs = [];   // the ones on offer

    const box = () => document.getElementById('modalReqs');
    const editing = () => +((document.getElementById('modalTaskId') || {}).value || 0);

    function wire(b) {
      if (b.dataset.routed) return;
      b.dataset.routed = '1';
      b.addEventListener('change', e => {
        const id = e.target && +e.target.dataset.req;
        if (!id) return;
        chosen = chosen.filter(x => x !== id);
        if (e.target.checked) chosen.push(id);
        b.dataset.ids = JSON.stringify(chosen.sort((x, y) => x - y));
      });
      b.addEventListener('input', e => {
        if (!e.target || !('reqFilter' in e.target.dataset)) return;
        const q = (e.target.value || '').trim().toLowerCase();
        b.querySelectorAll('[data-req-row]').forEach(row => {
          row.style.display = !q || row.dataset.reqRow.includes(q) ? '' : 'none';
        });
      });
    }

    // pick draws the requirements task id may implement, ticked as linked
    // has them, once the project's list arrives — unless the dialog has moved
    // on to another task by then.
    function pick(id, linked) {
      taskID = +id;
      const b = box();
      if (!b) return;
      wire(b);
      return api(pUrl('/api/requirements')).then(d => {
        if (taskID !== +id || editing() !== +id || !d || !d.ok) return;
        const all = d.requirements || [];
        // A link to a requirement that is gone is dropped from what Save
        // sends; one deprecated since it was made stays on offer, ticked.
        chosen = (linked || []).map(Number).filter(x => all.some(r => r.id === x));
        reqs = all.filter(r => (r.status || 'approved') === 'approved' || chosen.includes(r.id));
        render(b);
      }, () => {});
    }

    function render(b) {
      if (!reqs.length) {
        b.style.display = 'none';
        b.innerHTML = '';
        return;
      }
      b.innerHTML = '<label class="form-label">Requirements it implements</label>' +
        (reqs.length > 8 ? '<input class="form-input" data-req-filter placeholder="Filter requirements…" style="margin-bottom:4px">' : '') +
        '<div style="max-height:170px;overflow:auto;border:1px solid var(--border);border-radius:6px;padding:4px 8px">' +
        reqs.map(r => {
          const status = r.status || 'approved';
          return '<label data-req-row="' + esc(('r-' + r.id + ' ' + r.title).toLowerCase()) +
            '" style="display:flex;gap:6px;align-items:baseline;font-size:12px;padding:2px 0;overflow-wrap:anywhere">' +
            '<input type="checkbox" data-req="' + (+r.id) + '"' + (chosen.includes(r.id) ? ' checked' : '') + '>' +
            '<span><strong>R-' + (+r.id) + '</strong> ' + esc(r.title) +
            (status !== 'approved' ? ' <em class="form-hint">' + esc(status) + '</em>' : '') + '</span></label>';
        }).join('') + '</div>' +
        '<div class="form-hint">Its run is given each one\'s details and tests as the task\'s acceptance contract.</div>';
      b.style.display = '';
    }

    return h.mount({pick});
  };
})();
