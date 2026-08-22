// ── Active sessions panel + self-service sign-out (Task 20176) ──────────────
//
// Two audiences in one file. The table is the operator's: who is signed in,
// from where, how long each has left, and a button to end one. The two
// sign-out helpers are every user's, and they are here rather than in the
// header code because "end this session" and "end my other sessions" are the
// same lifecycle the table renders.
//
// Plain paths rather than pUrl(): sessions are a control-plane object, so a
// ?project_idx would imply a per-project scope the backend does not have.
//
// Nothing here ever handles a session cookie. Every id on this wire is a
// digest — see pkg/ui/sessions_api.go — which is why one can safely sit in a
// data- attribute and a URL path.

const sessState = {
  rows: [],
  total: 0,
  truncated: false,
  absoluteTTL: 0,
  idleTimeout: 0,
  durable: true,
  idpRevocation: true,
};

window.loadSessions = function() {
  return api('/api/sessions').then(d => {
    d = d || {};
    sessState.rows          = Array.isArray(d.sessions) ? d.sessions : [];
    sessState.total         = typeof d.total === 'number' ? d.total : sessState.rows.length;
    sessState.truncated     = !!d.truncated;
    sessState.absoluteTTL   = d.absolute_ttl_seconds || 0;
    sessState.idleTimeout   = d.idle_timeout_seconds || 0;
    sessState.durable       = d.durable !== false;
    sessState.idpRevocation = d.idp_revocation !== false;
    _sessRenderPolicy();
    _sessRenderBanner();
    _sessRender();
    return d;
  }).catch(err => _secFail('secSessionsEmpty', 'secSessionsTable', err, 'sessions'));
};

// _sessRenderPolicy states the two clocks in the panel. An operator looking at
// "idle 3h" needs to know what it is measured against without going to find
// the YAML.
function _sessRenderPolicy() {
  const el = document.getElementById('secSessionsPolicy');
  if (!el) return;
  const idle = sessState.idleTimeout > 0
    ? 'go unused for ' + _secFmtDuration(sessState.idleTimeout)
    : 'never time out on inactivity';
  el.innerHTML =
    'Sessions end after ' + esc(_secFmtDuration(sessState.absoluteTTL)) + ' regardless of activity, or sooner if they ' +
    esc(idle) + '. Terminating one takes effect on this hub immediately and on any other replica within 30 seconds; ' +
    'work already running on behalf of that user is not interrupted, only their access to start more.';
}

// _sessRenderBanner surfaces the two degraded modes where the operator will act
// on them. Both are legitimate configurations, and neither is discoverable from
// the table itself — a session list looks identical whether or not a restart
// will empty it.
function _sessRenderBanner() {
  const el = document.getElementById('secSessionsBanner');
  if (!el) return;
  const warn = [];
  if (!sessState.durable) {
    warn.push('<strong>Sessions are process-local.</strong> They are not written to the control-plane ' +
      'database, so a restart or a rolling upgrade signs every user out.');
  }
  if (!sessState.idpRevocation) {
    warn.push('<strong>IdP revocation is not armed.</strong> No refresh token is retained, so disabling a ' +
      'user at the identity provider does not end their cloop session &mdash; only the timeouts above, or a ' +
      'termination here, will. Set <code>CLOOP_SECRET_KEY</code> to enable it.');
  }
  if (!warn.length) { el.style.display = 'none'; el.innerHTML = ''; return; }
  el.style.display = '';
  el.innerHTML = '<span aria-hidden="true">&#9888;</span><span>' + warn.join('<br><br>') + '</span>';
}

function _sessRender() {
  const body  = document.getElementById('secSessionsBody');
  const table = document.getElementById('secSessionsTable');
  const empty = document.getElementById('secSessionsEmpty');
  const count = document.getElementById('secSessionsCount');
  if (!body) return;

  const rows = sessState.rows;
  if (count) {
    // Say so when the response was capped: a count that silently equals the
    // cap reads as "that is all of them".
    count.textContent = !rows.length ? ''
      : sessState.truncated ? '(showing ' + rows.length + ' of ' + sessState.total + ')'
      : '(' + rows.length + ')';
  }
  if (!rows.length) {
    if (table) table.style.display = 'none';
    if (empty) empty.style.display = '';
    body.innerHTML = '';
    _secApplyGating();
    return;
  }
  if (empty) empty.style.display = 'none';
  if (table) table.style.display = '';

  body.innerHTML = rows.map(s => {
    const who = s.display_name || s.email || s.subject || '(unknown)';
    return '<tr' + (s.current ? ' style="background:var(--hover-bg)"' : '') + '>' +
      '<td><strong>' + esc(who) + '</strong>' +
        (s.email && s.email !== who ? '<br><span class="sec-count">' + esc(s.email) + '</span>' : '') +
        (s.current ? ' <span class="sec-chip kind">this session</span>' : '') + '</td>' +
      '<td class="sec-fp">' + esc(s.ip || '—') + '</td>' +
      '<td class="sec-hide-sm" title="' + esc(s.user_agent || '') + '">' + esc(_sessDevice(s.user_agent)) + '</td>' +
      '<td class="audit-time sec-hide-sm">' + esc(_secFmtTime(s.issued_at)) + '</td>' +
      '<td>' + _sessIdleCell(s) + '</td>' +
      '<td><span class="' + _secTTLClass(s.expires_in_seconds) + '">' +
        esc(_secFmtDuration(Math.max(0, s.expires_in_seconds || 0))) + '</span></td>' +
      '<td class="audit-time sec-hide-sm">' +
        esc(s.idp_checked_at ? _secFmtTime(s.idp_checked_at) : 'never') + '</td>' +
      '<td><div class="sec-actions">' +
        '<button class="btn" data-global-perm="session.admin" data-sess-revoke="' + esc(s.id) + '">' +
          (s.current ? 'End mine' : 'Terminate') + '</button>' +
      '</div></td>' +
    '</tr>';
  }).join('');

  body.querySelectorAll('[data-sess-revoke]').forEach(btn => {
    btn.addEventListener('click', () => revokeSession(btn.getAttribute('data-sess-revoke')));
  });
  _secApplyGating();
}

// _sessIdleCell colours the idle column against the configured timeout, so a
// session about to lapse on its own is visually distinct from one that is
// simply quiet. Without the comparison "idle 2h" means nothing on its own.
function _sessIdleCell(s) {
  const idle = Math.max(0, s.idle_seconds || 0);
  let cls = 'sec-ttl';
  if (sessState.idleTimeout > 0) {
    const left = sessState.idleTimeout - idle;
    if (left <= 0)                         cls = 'sec-ttl gone';
    else if (left < sessState.idleTimeout * 0.2) cls = 'sec-ttl warn';
  }
  return '<span class="' + cls + '">' + esc(_secFmtDuration(idle)) + '</span>';
}

// _sessDevice reduces a User-Agent to something a human can scan. Best effort
// and purely cosmetic: the full string is in the cell's title, and nothing
// keys off either — a User-Agent is attacker-supplied, so it is a label to
// recognise a session by, never an input to a decision.
function _sessDevice(ua) {
  if (!ua) return '—';
  const browser =
    /Edg\//.test(ua)                        ? 'Edge'    :
    /OPR\/|Opera/.test(ua)                  ? 'Opera'   :
    /Chrome\//.test(ua)                     ? 'Chrome'  :
    /Firefox\//.test(ua)                    ? 'Firefox' :
    /Safari\//.test(ua)                     ? 'Safari'  :
    /curl\//.test(ua)                       ? 'curl'    : '';
  const os =
    /Windows/.test(ua)                      ? 'Windows' :
    /Android/.test(ua)                      ? 'Android' :
    /iPhone|iPad|iOS/.test(ua)              ? 'iOS'     :
    /Mac OS X|Macintosh/.test(ua)           ? 'macOS'   :
    /Linux/.test(ua)                        ? 'Linux'   : '';
  const label = [browser, os].filter(Boolean).join(' on ');
  return label || ua.slice(0, 40);
}

// ── mutations ──

window.revokeSession = function(id) {
  const s = sessState.rows.filter(x => x.id === id)[0];
  const who = (s && (s.display_name || s.email || s.subject)) || 'this user';
  const mine = s && s.current;
  const msg = mine
    ? 'End your own session?\n\nYou will be signed out of this tab immediately.'
    : 'Terminate the session for ' + who + '?\n\nTheir next request is refused and they must sign in again. ' +
      'This does not disable the account — they can sign straight back in unless you also disable them at the identity provider.';
  if (!confirm(msg)) return;
  apiMethod('DELETE', '/api/sessions/' + encodeURIComponent(id)).then(() => {
    if (mine) { window.location.href = '/auth/login'; return; }
    toast('Session terminated', 'ok');
    loadSessions();
  }).catch(err => toast('Terminate failed: ' + ((err && err.message) || String(err)), 'err'));
};

// ── self-service sign-out ──

// signOut ends this session, then hands the browser to the identity provider's
// logout endpoint when it advertises one.
//
// Without that second hop the provider's own cookie survives, so the next
// sign-in completes with no prompt and the button looks like it did nothing —
// which is worst precisely where it matters most, on a shared machine.
window.signOut = function() {
  fetch('/auth/logout', {method: 'POST'})
    .then(r => r.json().catch(() => ({})))
    .catch(() => ({}))
    .then(d => {
      window.location.href = (d && d.redirect) ? d.redirect : '/auth/login';
    });
};

// signOutEverywhere ends every *other* session for this user and leaves the
// current one alone, so an operator who clicks it from the dashboard is not
// thrown out of the page they clicked it from.
window.signOutEverywhere = function() {
  if (!confirm('Sign out of every other session?\n\nEvery other browser and device signed in as you is ended immediately. This session stays open.')) return;
  api('/api/session/logout-all', {}).then(d => {
    const n = (d && d.ended) || 0;
    toast(n ? 'Ended ' + n + ' other session' + (n === 1 ? '' : 's') : 'No other sessions were open', 'ok');
    if (typeof loadSessions === 'function' && document.getElementById('secSessionsTable')) loadSessions();
  }).catch(err => toast('Sign out everywhere failed: ' + ((err && err.message) || String(err)), 'err'));
};
