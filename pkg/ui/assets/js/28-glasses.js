// ── Display-glasses link (Task 20194) ───────────────────────────────────────
//
// The panel is deliberately small: three buttons and one field, because the
// interesting part of this feature is what the backend refuses to let the link
// do, not what the UI does with it.
//
// One rule shapes every function here — the URL is returned exactly once, by
// the mint call, and is not recoverable afterwards. So `_glassesURL` is the
// only copy that exists, it is never written to localStorage (which would put
// a live credential somewhere a later XSS could read at leisure), and the
// status line after a reload can report that a link *exists* without being
// able to show it.
//
// Plain paths rather than pUrl(): a link is a property of the user, not of the
// selected project, so a ?project_idx here would imply a scope the backend
// does not have.

let _glassesURL = '';

window.loadGlassesLink = function() {
  return api('/api/glasses/link').then(d => {
    _glassesRender((d && d.link) || {});
    return d;
  }).catch(err => {
    const el = document.getElementById('glassesStatus');
    if (el) el.textContent = 'Could not read link status: ' + (err && err.message ? err.message : err);
  });
};

function _glassesRender(link) {
  const status = document.getElementById('glassesStatus');
  const gen    = document.getElementById('glassesGenBtn');
  const revoke = document.getElementById('glassesRevokeBtn');
  const copy   = document.getElementById('glassesCopyBtn');
  if (!status) return;

  // Only offer Copy while this page still holds the plaintext. After a reload
  // the button would have nothing to put on the clipboard, and a button that
  // silently copies an empty string is worse than one that is not there.
  if (copy) copy.style.display = _glassesURL ? '' : 'none';

  if (!link.exists) {
    status.innerHTML = 'No link yet. Generating one issues a read-only credential that expires in 30 days.' +
      (link.per_user ? '' : ' <em>This hub has no sign-on configured, so the link belongs to the deployment rather than to an individual user.</em>');
    if (gen) gen.textContent = 'Generate link';
    if (revoke) revoke.style.display = 'none';
    return;
  }

  const expires = link.expires_at ? new Date(link.expires_at) : null;
  const used    = link.last_used_at ? new Date(link.last_used_at) : null;
  let html = 'Active link <code>' + esc(link.prefix || '') + '</code>';
  if (link.owner) html += ' for ' + esc(link.owner);
  if (expires)    html += ' · expires ' + expires.toLocaleDateString();
  html += used ? ' · last used ' + relTime(used) : ' · never used';
  html += '<br><span style="color:var(--muted)">The URL itself cannot be shown again — cloop stores only a hash. ' +
          'Generating a new link revokes this one.</span>';
  status.innerHTML = html;
  if (gen) gen.textContent = 'Regenerate link';
  if (revoke) revoke.style.display = '';
}

window.generateGlassesLink = function() {
  // Confirm only when replacing: rotation silently breaks a pair of glasses
  // that is already working, and the wearer is usually not the person at the
  // dashboard.
  const existing = document.getElementById('glassesRevokeBtn');
  if (existing && existing.style.display !== 'none' &&
      !confirm('Generate a new link?\n\nThe link currently on your glasses stops working immediately.')) {
    return;
  }
  const btn = document.getElementById('glassesGenBtn');
  if (btn) { btn.disabled = true; btn.textContent = 'Generating…'; }

  apiMethod('POST', '/api/glasses/link', {}).then(d => {
    _glassesURL = (d && d.url) || '';
    const box = document.getElementById('glassesUrlBox');
    const url = document.getElementById('glassesUrl');
    const warn = document.getElementById('glassesWarning');
    if (url) url.value = _glassesURL;
    if (warn) warn.textContent = (d && d.warning) || '';
    if (box) box.style.display = '';
    _glassesRender((d && d.link) || {});
    if (url) { try { url.select(); } catch (e) {} }
    toast('Link generated — copy it now', 'ok');
  }).catch(err => {
    toast('Could not generate link: ' + (err && err.message ? err.message : err), 'err');
  }).finally(() => {
    if (btn) btn.disabled = false;
    loadGlassesLink();
  });
};

window.copyGlassesLink = function() {
  if (!_glassesURL) { toast('The link is only available right after generating it', 'err'); return; }
  const done = () => toast('Link copied', 'ok');
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(_glassesURL).then(done).catch(() => _glassesCopyFallback(done));
    return;
  }
  _glassesCopyFallback(done);
};

// execCommand('copy') is deprecated but is the only path that works without a
// secure context, which a hub reached over plain HTTP on a LAN is not.
function _glassesCopyFallback(done) {
  const url = document.getElementById('glassesUrl');
  if (!url) return;
  url.select();
  try { document.execCommand('copy'); done(); }
  catch (e) { toast('Copy failed — select the field and copy manually', 'err'); }
}

window.revokeGlassesLink = function() {
  if (!confirm('Revoke your display-glasses link?\n\nThe app on your glasses stops working immediately.')) return;
  apiMethod('DELETE', '/api/glasses/link').then(() => {
    _glassesURL = '';
    const box = document.getElementById('glassesUrlBox');
    if (box) box.style.display = 'none';
    toast('Link revoked', 'ok');
    loadGlassesLink();
  }).catch(err => {
    toast('Could not revoke link: ' + (err && err.message ? err.message : err), 'err');
  });
};

// Closes the main IIFE opened in 00-core.js. It lives in the last bundle
// fragment on purpose: a fragment appended *after* the close is at global
// scope, where none of the shared helpers (api, esc, toast, relTime) are
// visible, so every call in it throws ReferenceError the first time a user
// opens that panel. That is exactly how the Sessions and Quotas panels shipped
// broken — the close had drifted to the end of 25-replay.js while two more
// fragments were appended behind it. TestDashboard_MainIIFEClosesInLastFragment
// pins it here.
})();
