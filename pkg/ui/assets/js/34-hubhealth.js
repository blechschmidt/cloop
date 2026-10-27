// ── Hub health indicator (Tasks 20434, 20446) ───────────────────────────────
// Lit in the header for an administrator — config.write across the hub — while
// any of the hub doctor's checks fails on the hub member this page's socket
// reaches. The member makes its report itself, every few minutes and when
// something changes what it finds, and pushes the summary (hub_health: the
// failing count and its generation) to the sockets of identities that may read
// it, so this asks only when the page cannot have heard: once /api/me has said
// who this is, and whenever the socket opens again. No timer of its own, but a
// retry a minute after a failed read. A push without a count says this socket
// may no longer read the report. A burst of reasons — /api/me answering as the
// socket opens — is one question. The panel the indicator opens is
// deferred/hubhealth.js, in Settings, re-read when a new report arrives while
// it is on screen.
let _hhAsk = 0, _hhAdmin, _hhGen;
function hubHealthShow(d) {
  const b = document.getElementById('hubHealthBadge'), n = d.failing || 0;
  b.style.display = n ? '' : 'none';
  b.textContent = '⚠ ' + n;
  b.setAttribute('aria-label', n + ' hub health check' + (n > 1 ? 's' : '') + ' failing');
  // A generation is its member's, and behind a balancer a read may reach
  // another member than the socket. Kept only once /api/me has answered, so
  // the panel Settings left empty until then is drawn by the next answer.
  const g = (d.member || {}).id + ':' + d.generation;
  if (myGlobalPerms && g !== _hhGen) {
    _hhGen = g;
    if (activeTab === 'settings') panelAct('hubhealth', 'refresh');
  }
}
function refreshHubHealth() {
  clearTimeout(_hhAsk);
  _hhAsk = setTimeout(() => {
    if (!myGlobalPerms || !canGlobal('config.write')) { document.getElementById('hubHealthBadge').style.display = 'none'; return; }
    api('/api/hub/health?summary=1').then(d => {
      if (!d || d.error) throw 0;
      hubHealthShow(d);
    }).catch(e => {
      // A refusal is an answer (and said once); a failure to answer is not.
      if (!(e instanceof Error) || e instanceof TypeError) _hhAsk = setTimeout(refreshHubHealth, 6e4);
    });
  }, 250);
}
// hubHealthPushed takes the hub_health push. A hub on an older build sends {},
// which means ask.
function hubHealthPushed(d) {
  if (d && typeof d.failing === 'number') hubHealthShow(d);
  else if (d && d.withdrawn) { document.getElementById('hubHealthBadge').style.display = 'none'; refreshPermissions(); }
  else refreshHubHealth();
}
// hubHealthPerms runs whenever /api/me answers, and asks only when the answer
// moved this user into or out of the audience: a refusal re-reads /api/me,
// which must not ask again for what was just refused.
function hubHealthPerms() {
  if (_hhAdmin !== canGlobal('config.write')) { _hhAdmin = canGlobal('config.write'); refreshHubHealth(); }
}
ACTIONS.openHubHealth = () => { switchTab('settings'); panelAct('hubhealth', 'reveal'); };
