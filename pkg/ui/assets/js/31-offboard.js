// ── Offboarding: sever every credential one identity holds (Task 20261) ─────
//
// The panel is fetched the first time someone presses Preview (Task 20379):
// it is an admin-only form, and first paint has no room for code most sessions
// never run. deferred/offboard.js holds it and the reasoning behind it; this
// is the button's wiring and the hand-over of the helpers it calls.
function offboardPreview() {
  deferredPanel('offboard', 'cloopOffboardPanel', {
    apiMethod, esc, toast, gate: () => _secApplyGating(), sessions: () => loadSessions(),
  }).then(p => p.preview()).catch(() => toast('Could not load the offboarding panel', 'err'));
}

document.addEventListener('DOMContentLoaded', function() {
  const btn = document.getElementById('offboardPreviewBtn');
  if (btn) btn.addEventListener('click', offboardPreview);
  const input = document.getElementById('offboardIdentity');
  if (input) input.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); offboardPreview(); }
  });
});
