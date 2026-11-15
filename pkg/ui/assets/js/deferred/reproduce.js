// ── Reproduce a task (Task 20221) ───────────────────────────────────────────
//
// The Reproduce button in a task's details: runs the task again in a fresh
// sandbox and compares the commit. Whether the button can be pressed, and the
// reproductions so far, are read by the bundle when the details open
// (_tdLoadReproductions in 12-task-crud.js); only the press is here.
//
// Deferred by Task 20496 to pay for the Move dialog's button on first paint,
// and fetched on the first press, so opening a task's details still fetches no
// script. It runs outside the dashboard's IIFE and puts nothing on window but
// its factory.
(function () {
  'use strict';

  window.cloopReproducePanel = function (h) {
    const {api, esc, toast, pUrl, harnessRefused} = h;
    const el = id => document.getElementById(id);

    // run reproduces task id; reload reads its reproductions again, and does
    // nothing when the details show another task by then. No timeout on the
    // client: the hub bounds a reproduction at 20 minutes, and an abort here
    // would orphan the sandbox without releasing its quota.
    function run(id, reload) {
      if (!id) return;
      const btn = el('td-reproduce-btn');
      const host = el('td-repro-list');
      if (btn) { btn.disabled = true; btn.textContent = 'Reproducing…'; }
      if (host) {
        host.innerHTML = '<div class="td-empty">Running the task again in a fresh sandbox and comparing the ' +
          'commit. This takes as long as the original run did.</div>';
      }
      return api(pUrl('/api/tasks/' + id + '/reproduce'), {}).then(d => {
        if (btn) { btn.textContent = 'Reproduce'; btn.disabled = false; }
        if (!d || !d.ok) {
          const msg = (d && (d.message || d.error)) || 'The reproduction could not be run';
          if (host) host.innerHTML = '<div class="td-empty">' + esc(msg) + '</div>';
          if (!harnessRefused(d)) toast(msg, false);
          return;
        }
        if (reload) reload(id);
        const v = (d.reproduction && d.reproduction.verdict) || '';
        toast('Verdict: ' + String(v).toUpperCase(), v === 'identical' || v === 'equivalent');
      }).catch(() => {
        if (btn) { btn.textContent = 'Reproduce'; btn.disabled = false; }
        if (host) host.innerHTML = '<div class="td-empty">Request failed</div>';
      });
    }

    return h.mount({run});
  };
})();
