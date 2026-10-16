// ── Hub health indicator (Task 20434) ───────────────────────────────────────
// Lit in the header for an administrator — config.write across the hub — while
// any of the hub doctor's checks fails on the hub member that answered. The
// report is computed in the hub and cached there for about a minute, so this
// asks again only when the hub says the report changed (hub_health), on every
// reconnect, and once the report it last read expires: one timer per answer,
// at the hub's own expiry, never a poll of its own. It asks nothing before
// /api/me has said who this is, so a caller who may not read the report never
// sends the request. A burst of reasons — /api/me answering as the socket
// opens — is one question. The panel the indicator opens is
// deferred/hubhealth.js, in Settings, re-read with the indicator while it is on
// screen.
let _hhDue = 0, _hhAdmin;
function refreshHubHealth() {
  clearTimeout(_hhDue);
  _hhDue = setTimeout(() => {
    const b = document.getElementById('hubHealthBadge');
    if (!myGlobalPerms || !canGlobal('config.write')) { b.style.display = 'none'; return; }
    api('/api/hub/health?summary=1').then(d => {
      if (!d || d.error) throw 0;
      const n = d.failing || 0;
      b.style.display = n ? '' : 'none';
      b.textContent = '⚠ ' + n;
      b.setAttribute('aria-label', n + ' hub health check' + (n > 1 ? 's' : '') + ' failing');
      // By the hub's clock, which the page's may not keep.
      const ttl = Date.parse(d.expires_at) - Date.parse(d.served_at);
      if (ttl > 0) _hhDue = setTimeout(refreshHubHealth, ttl + 1e3);
      if (activeTab === 'settings') panelAct('hubhealth', 'refresh');
    }).catch(e => {
      // A refusal is an answer (and said once); a failure to answer is not.
      if (!(e instanceof Error) || e instanceof TypeError) _hhDue = setTimeout(refreshHubHealth, 6e4);
    });
  }, 250);
}
// hubHealthPerms runs whenever /api/me answers, and asks only when the answer
// moved this user into or out of the audience: a refusal re-reads /api/me,
// which must not ask again for what was just refused.
function hubHealthPerms() {
  if (_hhAdmin !== canGlobal('config.write')) { _hhAdmin = canGlobal('config.write'); refreshHubHealth(); }
}
ACTIONS.openHubHealth = () => { switchTab('settings'); panelAct('hubhealth', 'reveal'); };
