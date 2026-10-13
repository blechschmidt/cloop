// ── Approvals badge (Task 20427) ─────────────────────────────────────────────
// How many grant requests and API tokens wait on this user, in the header. The
// hub broadcasts a change as a verb and an id, never the row, so each client
// asks for its own count: on connect, on every such broadcast, and once the
// soonest deadline passes, since a lapse changes the count with nobody acting.
// The inbox it opens is deferred/approvals.js, re-read with the count while it
// is on screen. A burst of broadcasts is one question: each one restarts the
// wait.
let _apvMine = [], _apvAsk = 0, _apvDue = 0;
function refreshApprovals() {
  clearTimeout(_apvAsk);
  _apvAsk = setTimeout(() => {
    panelIf('approvals', 'refresh');
    api('/api/approvals/count').then(d => {
      const n = (d && d.count) || 0, b = document.getElementById('approvalsBadge');
      _apvMine = (d && d.mine_pending) || [];
      if (b) {
        b.style.display = n ? '' : 'none';
        b.textContent = '\u{1F514} ' + n;
        b.setAttribute('aria-label', n + ' waiting on you');
      }
      clearTimeout(_apvDue);
      const due = d && d.next_deadline ? Date.parse(d.next_deadline) - Date.now() : 0;
      if (due > 0 && due < 864e5) _apvDue = setTimeout(refreshApprovals, due + 1e3);
    }).catch(() => {});
  }, 250);
}
// approvalsChanged takes secrets_update and approvals_update. A decision on
// one of this user's own requests is said aloud once — the handler that made
// it and the notifier that later records it may both broadcast it — and then
// the count is re-read.
function approvalsChanged(d) {
  const ev = (d && d.event) || '', id = d && d.id;
  if (_apvMine.includes(id) && /^request_(approved|denied)$/.test(ev)) {
    _apvMine = _apvMine.filter(x => x !== id);
    toast('Your access request was ' + ev.slice(8), ev === 'request_denied' ? 'err' : 'ok');
  }
  refreshApprovals();
}
act('openApprovals', () => panelAct('approvals', 'open'));
// A message's link: /?approvals=1 opens the inbox once the page is up. Signing
// in first keeps the query (oidc.go's ?return=).
if (/[?&]approvals=/.test(location.search)) setTimeout(() => panelAct('approvals', 'open'), 0);
