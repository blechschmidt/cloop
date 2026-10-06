// ── Free-space floor: Settings → Disk & Retention (Task 20381) ──────────────
//
// Edits orchestrator.min_free_disk_mb for this hub: the free space a run wants
// on the volumes it writes to before it starts a task or an evolve round, and
// what the hub's doctor and admin banner hold its own state volume to. Admins
// only, like every hub-scope setting the panel writes; the server picks the file
// (this hub's per-instance overlay once it has one, config.yaml otherwise) and
// the panel says which.
//
// Fetched the first time an admin opens the section (static.go,
// deferredScripts): first paint has no room for a form most sessions never
// see. It runs outside the dashboard's IIFE, so loadDiskUsage in
// deferred/budget.js hands over the helpers it calls, and the only name it
// puts on window is the factory.
(function () {
  'use strict';

  window.cloopDiskfloorPanel = function (h) {
    const box = () => document.getElementById('diskFloorBody');

    function render(d) {
      const el = box();
      if (!el) return;
      const hub = d.hub || {};
      let state;
      if (hub.error) {
        state = 'The hub\'s state volume could not be measured: ' + h.esc(hub.error);
      } else if (!d.min_free_disk_mb) {
        state = '<strong class="du-warn">The check is off.</strong> Runs start on any disk, and a ' +
          'task\'s outcome written onto a full one has no reserve to fall back on.';
      } else {
        state = 'This hub\'s state volume, <code>' + h.esc(hub.volume || '?') + '</code>, has ' +
          h.fmt(hub.free_bytes) + ' free' +
          (hub.low ? ' — <strong class="du-warn">below the floor</strong>.'
            : hub.warn ? ' — <strong class="du-warn">less than twice the floor</strong>.' : '.');
      }
      el.innerHTML =
        '<div class="du-policy"><strong>Free-space floor.</strong> A run pauses before its next task or evolve ' +
        'round while a volume it writes to has less than this free, and carries on by itself once there is ' +
        'room again. <code>0</code> turns the check off. ' + state +
        '<div style="display:flex;gap:8px;align-items:center;margin-top:8px;flex-wrap:wrap">' +
        '<input type="number" id="diskFloorInput" class="form-input" style="width:120px" min="0" max="' +
        d.upper_mb + '" step="64" value="' + d.min_free_disk_mb + '" aria-label="Free-space floor in MB">' +
        '<span class="du-note">MB (default ' + d.default_mb + '; ' + d.lower_mb + '–' + d.upper_mb + ')</span>' +
        '<button class="btn" id="diskFloorSave">Save</button></div>' +
        '<span class="du-note">Saved to ' + (d.overlay ? 'this hub\'s overlay config' : '.cloop/config.yaml') +
        '. It applies to runs of the hub\'s own directory; other projects set ' +
        '<code>orchestrator.min_free_disk_mb</code> in their own config.yaml.</span></div>';
      document.getElementById('diskFloorSave').addEventListener('click', save);
    }

    function save() {
      const input = document.getElementById('diskFloorInput');
      const v = Number(input && input.value);
      if (!Number.isInteger(v) || v < 0) { h.toast('Enter a whole number of megabytes, or 0', 'err'); return; }
      h.apiMethod('PUT', '/api/config/disk', {min_free_disk_mb: v}).then(d => {
        if (!d || d.error) { h.toast((d && d.error) || 'Save failed', 'err'); return; }
        h.toast(v ? 'Free-space floor set to ' + v + ' MB' : 'Free-space check turned off', 'ok');
        render(d);
      }).catch(() => h.toast('Save failed', 'err'));
    }

    function load() {
      return h.api('/api/config/disk').then(d => {
        if (d && !d.error) render(d);
      });
    }

    return {load: load};
  };
})();
