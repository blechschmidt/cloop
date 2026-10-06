// ── Self-service sign-out (Task 20176) ──────────────────────────────────────
//
// Every user's, and in the header, so they stay in the bundle. The operator's
// table of everybody's sessions, which these used to sit beside, is part of the
// Secrets tab and is fetched with it (deferred/secrets.js, Task 20386).

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
    panelIf('secrets', 'loadSessions');
  }).catch(err => toast('Sign out everywhere failed: ' + ((err && err.message) || String(err)), 'err'));
};
