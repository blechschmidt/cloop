// ── Secrets & grants panel (Task 20171) ─────────────────────────────────────
//
// Global, maintainer and above. Three tables over the two brokers: what is
// stored, who may use it, and who is holding it right now.
//
// Plain paths rather than pUrl(): every route here is scopeGlobal and reads
// the control plane's own database, so a ?project_idx would be noise that
// implies a per-project scope the backend does not have.
//
// Nothing in this block ever renders a payload, because no response carries
// one. The only credential-shaped string the panel handles is the one an
// operator types into the Store-a-secret form, which travels outbound only.
const secState = {
  secrets: [],
  grants: [],
  leases: [],
  kinds: [],
  broker: null,
  ticker: null,
};

window.loadSecretsPanel = function() {
  return Promise.all([loadSecrets(), loadGrants(), loadLeases()])
    .then(() => { _secStartTicker(); });
};

window.loadSecrets = function() {
  return api('/api/secrets').then(d => {
    d = d || {};
    secState.secrets = Array.isArray(d.secrets) ? d.secrets : [];
    secState.kinds   = Array.isArray(d.kinds) ? d.kinds : [];
    secState.broker  = d.broker || null;
    _secRenderBroker();
    _secRenderSecrets();
    return d;
  }).catch(err => _secFail('secSecretsEmpty', 'secSecretsTable', err, 'secrets'));
};

window.loadGrants = function() {
  const activeOnly = (document.getElementById('secGrantsActiveOnly') || {}).checked;
  return api('/api/grants' + (activeOnly ? '?active=1' : '')).then(d => {
    d = d || {};
    secState.grants = Array.isArray(d.grants) ? d.grants : [];
    if (d.broker) { secState.broker = d.broker; _secRenderBroker(); }
    _secRenderGrants();
    return d;
  }).catch(err => _secFail('secGrantsEmpty', 'secGrantsTable', err, 'grants'));
};

window.loadLeases = function() {
  return api('/api/leases').then(d => {
    d = d || {};
    secState.leases = Array.isArray(d.leases) ? d.leases : [];
    _secRenderLeases();
    return d;
  }).catch(err => _secFail('secLeasesEmpty', 'secLeasesTable', err, 'leases'));
};

// _secFail renders a load failure inside the table's empty slot. A 403 is the
// expected answer for a role below maintainer, not a fault, so it is worded
// as an answer rather than as an error.
function _secFail(emptyID, tableID, err, what) {
  const table = document.getElementById(tableID);
  const empty = document.getElementById(emptyID);
  if (table) table.style.display = 'none';
  if (!empty) return;
  empty.style.display = '';
  const msg = (err && err.message) ? String(err.message) : String(err);
  empty.innerHTML = /forbidden|not permit|403/i.test(msg)
    ? 'Your role does not permit managing ' + esc(what) + '.'
    : 'Failed to load ' + esc(what) + ': ' + esc(msg);
}

function _secRenderBroker() {
  const el = document.getElementById('secBrokerBanner');
  if (!el) return;
  const b = secState.broker;
  if (!b || b.secrets_available) { el.style.display = 'none'; return; }
  el.style.display = '';
  el.innerHTML = '<span aria-hidden="true">&#9888;</span><span><strong>' +
    esc(b.reason || 'the secret store is unavailable') + '</strong><br>' +
    esc(b.remediation || '') + '</span>';
}

// _secFmtDuration renders a countdown compactly: an operator scanning a lease
// table wants "4m 12s", not an ISO duration.
function _secFmtDuration(sec) {
  sec = Math.max(0, Math.floor(Number(sec) || 0));
  if (sec <= 0) return 'expired';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (d > 0) return d + 'd ' + h + 'h';
  if (h > 0) return h + 'h ' + m + 'm';
  if (m > 0) return m + 'm ' + s + 's';
  return s + 's';
}

function _secFmtTime(ts) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleString(); } catch(_) { return String(ts); }
}

function _secFmtBytes(n) {
  n = Number(n) || 0;
  if (n <= 0) return 'unlimited';
  const units = ['B','KB','MB','GB','TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (Math.round(n * 10) / 10) + ' ' + units[i];
}

// _secTTLClass colours a countdown so a lease about to lapse is visible
// without reading the number.
function _secTTLClass(sec) {
  if (sec <= 0) return 'sec-ttl gone';
  if (sec < 120) return 'sec-ttl soon';
  return 'sec-ttl';
}

function _secChips(values, cls) {
  if (!values || !values.length) return '';
  return values.map(v => '<span class="sec-chip' + (cls ? ' ' + cls : '') + '">' + esc(String(v)) + '</span>').join('');
}

function _secRenderSecrets() {
  const body  = document.getElementById('secSecretsBody');
  const table = document.getElementById('secSecretsTable');
  const empty = document.getElementById('secSecretsEmpty');
  const count = document.getElementById('secSecretsCount');
  if (!body) return;

  const rows = secState.secrets;
  if (count) count.textContent = rows.length ? '(' + rows.length + ')' : '';
  if (!rows.length) {
    if (table) table.style.display = 'none';
    if (empty) { empty.style.display = ''; empty.textContent = 'No secrets stored. Add one, then grant it to a project or executor.'; }
    body.innerHTML = '';
    return;
  }
  if (empty) empty.style.display = 'none';
  if (table) table.style.display = '';

  body.innerHTML = rows.map(s =>
    '<tr>' +
      '<td><strong>' + esc(s.name || '') + '</strong></td>' +
      '<td><span class="sec-chip kind">' + esc(s.kind || '') + '</span></td>' +
      '<td class="sec-fp sec-hide-sm" title="A digest of the sealed record, not of the value. Re-storing the same credential yields a different fingerprint.">' +
        esc(s.fingerprint || '—') + '</td>' +
      '<td>' + (s.active_grants || 0) + ' active' +
        (s.grants > s.active_grants ? ' <span class="sec-count">/ ' + s.grants + '</span>' : '') + '</td>' +
      '<td class="audit-time sec-hide-sm">' + esc(_secFmtTime(s.created_at)) + '</td>' +
      '<td><div class="sec-actions">' +
        '<button class="btn" data-global-perm="audit.read" data-perm-hide data-sec-audit="' + esc(s.id) + '">Audit</button>' +
        '<button class="btn" data-global-perm="secret.revoke" data-sec-delete="' + esc(s.id) + '">Delete</button>' +
      '</div></td>' +
    '</tr>'
  ).join('');

  body.querySelectorAll('[data-sec-delete]').forEach(btn => {
    btn.addEventListener('click', () => deleteSecret(btn.getAttribute('data-sec-delete')));
  });
  body.querySelectorAll('[data-sec-audit]').forEach(btn => {
    btn.addEventListener('click', () => secretsAuditFor('secret', btn.getAttribute('data-sec-audit')));
  });
  _secApplyGating();
}

// _secConstraintCell renders a grant's allowlist. Every dimension present is
// shown: a grant whose constraints an operator cannot see at a glance is one
// they cannot audit, which is the whole reason this panel exists.
function _secConstraintCell(g) {
  const c = g.constraints || {};
  const parts = [];
  const add = (label, chips) => {
    if (chips) parts.push('<div><span class="sec-count">' + label + '</span> ' + chips + '</div>');
  };
  add('repos', _secChips(c.repos));
  add('perms', _secChips(c.permissions));
  add('contexts', _secChips(c.contexts));
  add('namespaces', _secChips(c.namespaces));
  add('hosts', _secChips(c.hosts));
  add('cidrs', _secChips(c.cidrs));
  add('ports', _secChips(c.ports));
  add('methods', _secChips(c.methods));
  add('registries', _secChips(c.registries));
  add('env keys', _secChips(c.env_keys));
  if (c.max_bytes_up || c.max_bytes_down) {
    parts.push('<div><span class="sec-count">quota</span> ' +
      '&uarr; ' + esc(_secFmtBytes(c.max_bytes_up)) + ' &nbsp; &darr; ' + esc(_secFmtBytes(c.max_bytes_down)) + '</div>');
  }
  if (c.session_ttl_seconds) {
    parts.push('<div><span class="sec-count">session</span> ' + esc(_secFmtDuration(c.session_ttl_seconds)) + '</div>');
  }
  return parts.length ? parts.join('') : '<span class="sec-count">' + esc(g.summary || 'none') + '</span>';
}

function _secRenderGrants() {
  const body  = document.getElementById('secGrantsBody');
  const table = document.getElementById('secGrantsTable');
  const empty = document.getElementById('secGrantsEmpty');
  const count = document.getElementById('secGrantsCount');
  if (!body) return;

  const rows = secState.grants;
  if (count) count.textContent = rows.length ? '(' + rows.length + ')' : '';
  if (!rows.length) {
    if (table) table.style.display = 'none';
    if (empty) { empty.style.display = ''; empty.textContent = 'No grants.'; }
    body.innerHTML = '';
    return;
  }
  if (empty) empty.style.display = 'none';
  if (table) table.style.display = '';

  const now = Date.now();
  body.innerHTML = rows.map(g => {
    // Recompute the countdown client-side so the ticker can refresh it
    // without a round trip; the server's value is the reference at load.
    let remaining = Number(g.remaining_seconds) || 0;
    if (g.active && g.expires_at) {
      remaining = Math.max(0, Math.floor((new Date(g.expires_at).getTime() - now) / 1000));
    }
    const resource = g.source === 'egress'
      ? 'the hub&rsquo;s Internet connection'
      : (esc(g.secret_name || g.secret_id || '—'));
    return '<tr>' +
      '<td><span class="sec-chip kind">' + esc(g.kind || '') + '</span></td>' +
      '<td>' + resource + '</td>' +
      '<td class="audit-entity">' + esc(g.subject || '') +
        (g.scope ? ' <span class="sec-chip">' + esc(g.scope) + '</span>' : '') + '</td>' +
      '<td class="sec-hide-sm">' + _secConstraintCell(g) + '</td>' +
      '<td><span class="sec-status ' + esc(g.status || '') + '">' + esc(g.status || '') + '</span></td>' +
      '<td class="' + _secTTLClass(g.active ? remaining : 0) + '">' +
        (g.active ? esc(_secFmtDuration(remaining)) : '—') + '</td>' +
      '<td><div class="sec-actions">' +
        '<button class="btn" data-global-perm="audit.read" data-perm-hide data-grant-audit="' + esc(g.id) + '">Audit</button>' +
        (g.status === 'revoked' ? '' :
          '<button class="btn" data-global-perm="secret.revoke" data-grant-revoke="' + esc(g.id) + '">Revoke</button>') +
      '</div></td>' +
    '</tr>';
  }).join('');

  body.querySelectorAll('[data-grant-revoke]').forEach(btn => {
    btn.addEventListener('click', () => revokeGrant(btn.getAttribute('data-grant-revoke')));
  });
  body.querySelectorAll('[data-grant-audit]').forEach(btn => {
    btn.addEventListener('click', () => secretsAuditFor('grant', btn.getAttribute('data-grant-audit')));
  });
  _secApplyGating();
}

function _secRenderLeases() {
  const body  = document.getElementById('secLeasesBody');
  const table = document.getElementById('secLeasesTable');
  const empty = document.getElementById('secLeasesEmpty');
  const count = document.getElementById('secLeasesCount');
  if (!body) return;

  const rows = secState.leases;
  if (count) count.textContent = rows.length ? '(' + rows.length + ')' : '';
  if (!rows.length) {
    if (table) table.style.display = 'none';
    if (empty) empty.style.display = '';
    body.innerHTML = '';
    return;
  }
  if (empty) empty.style.display = 'none';
  if (table) table.style.display = '';

  const now = Date.now();
  body.innerHTML = rows.map(l => {
    const remaining = l.expires_at
      ? Math.max(0, Math.floor((new Date(l.expires_at).getTime() - now) / 1000))
      : (Number(l.remaining_seconds) || 0);
    const mats = (l.materials || []).map(m =>
      '<span class="sec-chip kind" title="' + esc(m.summary || '') + '">' +
        esc(m.secret_name || m.secret_id || '') + ' &middot; ' + esc(m.kind || '') + '</span>'
    ).join('');
    return '<tr>' +
      '<td><strong>' + esc(l.executor_id || '—') + '</strong></td>' +
      '<td class="audit-entity">' + esc(l.project_name || l.project_path || '—') + '</td>' +
      '<td>' + (mats || '<span class="sec-count">none</span>') + '</td>' +
      '<td class="' + _secTTLClass(remaining) + '">' + esc(_secFmtDuration(remaining)) + '</td>' +
      '<td class="audit-time sec-hide-sm">' + esc(_secFmtTime(l.issued_at)) + '</td>' +
      '<td><div class="sec-actions">' +
        '<button class="btn" data-global-perm="secret.revoke" data-lease-revoke="' + esc(l.id) + '">Revoke</button>' +
      '</div></td>' +
    '</tr>';
  }).join('');

  body.querySelectorAll('[data-lease-revoke]').forEach(btn => {
    btn.addEventListener('click', () => revokeLease(btn.getAttribute('data-lease-revoke')));
  });
  _secApplyGating();
}

function _secApplyGating() {
  const panel = document.getElementById('tab-secrets');
  if (panel && typeof applyPermissionGating === 'function') applyPermissionGating(panel);
}

// _secStartTicker keeps the countdowns moving. It stops itself the first time
// it fires while the panel is hidden, so leaving the tab does not leave an
// interval re-rendering three tables forever.
function _secStartTicker() {
  if (secState.ticker) return;
  secState.ticker = setInterval(() => {
    const panel = document.getElementById('tab-secrets');
    if (!panel || !panel.classList.contains('active')) { _secStopTicker(); return; }
    _secRenderGrants();
    _secRenderLeases();
  }, 1000);
}

function _secStopTicker() {
  if (!secState.ticker) return;
  clearInterval(secState.ticker);
  secState.ticker = null;
}

// secretsAuditFor jumps to the Audit panel scoped to one secret or grant.
//
// The two use different filters because the trail indexes them differently:
// the broker's auditor records the *secret* as the row's entity and carries
// the grant id inside the payload, so a grant is found by payload search.
window.secretsAuditFor = function(kind, id) {
  const entity = document.getElementById('auditFilterEntityID');
  const search = document.getElementById('auditFilterSearch');
  if (entity) entity.value = (kind === 'secret') ? (id || '') : '';
  if (search) search.value = (kind === 'secret') ? '' : (id || '');
  switchTab('audit');
};

// ── mutations ──

window.deleteSecret = function(id) {
  const sec = secState.secrets.filter(s => s.id === id)[0];
  const name = (sec && sec.name) || id;
  const live = (sec && sec.active_grants) || 0;
  const warn = live
    ? '\n\n' + live + ' active grant' + (live === 1 ? '' : 's') + ' will be revoked with it. Any project relying on this credential loses it at its next lease.'
    : '';
  if (!confirm('Delete secret "' + name + '"?' + warn)) return;
  apiMethod('DELETE', '/api/secrets/' + encodeURIComponent(id)).then(() => {
    toast('Secret deleted', 'ok');
    loadSecrets(); loadGrants();
  }).catch(err => toast('Delete failed: ' + ((err && err.message) || String(err)), 'err'));
};

window.revokeGrant = function(id) {
  if (!confirm('Revoke grant ' + id + '?\n\nFor a secret grant this lands at the next lease or renewal — revoke the lease too if a workload is holding the credential now. For an egress grant it also closes live sessions immediately.')) return;
  apiMethod('DELETE', '/api/grants/' + encodeURIComponent(id)).then(d => {
    toast((d && d.note) ? 'Grant revoked — takes effect at the next lease' : 'Grant revoked', 'ok');
    loadGrants(); loadSecrets();
  }).catch(err => toast('Revoke failed: ' + ((err && err.message) || String(err)), 'err'));
};

window.revokeLease = function(id) {
  if (!confirm('Revoke lease ' + id + '?\n\nThe credential directory is wiped now. A process that has already read a file keeps what it read, so revoke the grant as well if the credential itself is compromised.')) return;
  api('/api/leases/' + encodeURIComponent(id) + '/revoke', {}).then(() => {
    toast('Lease revoked and credentials wiped', 'ok');
    loadLeases();
  }).catch(err => toast('Revoke failed: ' + ((err && err.message) || String(err)), 'err'));
};

// ── store-a-secret modal ──

const SEC_PAYLOAD_HINTS = {
  github_pat:   'The raw token, e.g. ghp_… or github_pat_…. Mint it with the narrowest scopes GitHub offers; the grant narrows which repositories cloop will use it for.',
  github_app:   'The App installation credential as JSON: {"app_id":…, "installation_id":…, "private_key":"-----BEGIN…"}.',
  kubeconfig:   'A full kubeconfig YAML document. Delivery rewrites it to contain only the granted contexts, with the granted namespace pinned on each.',
  registry:     'A docker config JSON, or "user:password". Delivery filters it to the granted registries.',
  env:          'A JSON object of key/value pairs, or a bare value delivered as one variable named after the secret.',
  egress_proxy: 'The proxy endpoint, e.g. http://user:pass@proxy.internal:3128.'
};

window.openSecretModal = function() {
  const kind = document.getElementById('secretKind');
  if (kind) {
    const kinds = secState.kinds.length ? secState.kinds
      : ['github_pat','github_app','kubeconfig','registry','env','egress_proxy'];
    kind.innerHTML = kinds.map(k => '<option value="' + esc(k) + '">' + esc(k) + '</option>').join('');
  }
  ['secretName','secretPayload'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  const err = document.getElementById('secretError');
  if (err) err.style.display = 'none';
  onSecretKindChange();
  const ov = document.getElementById('secret-overlay');
  if (ov) ov.style.display = 'flex';
  _secApplyGating();
  setTimeout(() => { const n = document.getElementById('secretName'); if (n) n.focus(); }, 50);
};

window.closeSecretModal = function() {
  // Clear the payload on close as well as on open: leaving a typed credential
  // in a hidden DOM node is the browser-side version of leaving it in a
  // buffer, and this modal is the one place in the dashboard that holds one.
  const p = document.getElementById('secretPayload');
  if (p) p.value = '';
  const ov = document.getElementById('secret-overlay');
  if (ov) ov.style.display = 'none';
};

window.onSecretKindChange = function() {
  const kind = ((document.getElementById('secretKind') || {}).value) || '';
  const hint = document.getElementById('secretPayloadHint');
  if (hint) hint.textContent = SEC_PAYLOAD_HINTS[kind] || '';
};

window.submitSecret = function() {
  const errEl = document.getElementById('secretError');
  const btn   = document.getElementById('secretSubmitBtn');
  const body = {
    name:    ((document.getElementById('secretName') || {}).value || '').trim(),
    kind:    (document.getElementById('secretKind') || {}).value || '',
    payload: (document.getElementById('secretPayload') || {}).value || ''
  };
  if (!body.name)    { _secFormError(errEl, 'A name is required.'); return; }
  if (!body.payload) { _secFormError(errEl, 'A payload is required.'); return; }
  if (errEl) errEl.style.display = 'none';
  if (btn) btn.disabled = true;

  api('/api/secrets', body).then(() => {
    if (btn) btn.disabled = false;
    closeSecretModal();
    toast('Secret stored', 'ok');
    loadSecrets();
  }).catch(err => {
    if (btn) btn.disabled = false;
    _secFormError(errEl, (err && err.message) || String(err));
  });
};

function _secFormError(el, msg) {
  if (!el) { toast(msg, 'err'); return; }
  el.textContent = msg;
  el.style.display = 'block';
}

// ── grant wizard ──

// SEC_GRANT_KINDS maps each kind to the fieldset it reveals, whether it needs
// a stored secret, and which broker creates it. Keeping this as data rather
// than as a switch is what lets the same table drive the fieldset toggle, the
// secret picker, and the request body.
const SEC_GRANT_KINDS = {
  github_pat:   {set:'grantSet-github',      secret:true,  source:'secret'},
  github_app:   {set:'grantSet-github',      secret:true,  source:'secret'},
  kubeconfig:   {set:'grantSet-kubeconfig',  secret:true,  source:'secret'},
  registry:     {set:'grantSet-registry',    secret:true,  source:'secret'},
  env:          {set:'grantSet-env',         secret:true,  source:'secret'},
  egress_proxy: {set:'grantSet-egressproxy', secret:true,  source:'secret'},
  egress:       {set:'grantSet-egress',      secret:false, source:'egress'}
};

window.openGrantModal = function() {
  const err = document.getElementById('grantError');
  if (err) err.style.display = 'none';
  ['grantRepos','grantPermissions','grantContexts','grantNamespaces','grantHosts',
   'grantCIDRs','grantPorts','grantMethods','grantMaxUp','grantMaxDown','grantSessionTTL',
   'grantRegistries','grantEnvKeys','grantProxyHosts','grantScope','grantSubject'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  onGrantKindChange();
  const ov = document.getElementById('grant-overlay');
  if (ov) ov.style.display = 'flex';
  _secApplyGating();
  setTimeout(() => { const s = document.getElementById('grantSubject'); if (s) s.focus(); }, 50);
};

window.closeGrantModal = function() {
  const ov = document.getElementById('grant-overlay');
  if (ov) ov.style.display = 'none';
};

window.onGrantKindChange = function() {
  const kind = ((document.getElementById('grantKind') || {}).value) || 'github_pat';
  const spec = SEC_GRANT_KINDS[kind] || SEC_GRANT_KINDS.github_pat;

  document.querySelectorAll('#grant-overlay .sec-kindset').forEach(el => el.classList.remove('on'));
  const set = document.getElementById(spec.set);
  if (set) set.classList.add('on');

  // The secret picker offers only secrets of the chosen kind: a kubeconfig
  // grant against a PAT is rejected by the broker anyway, and offering it
  // would turn a type error into a support question.
  const group = document.getElementById('grantSecretGroup');
  const sel   = document.getElementById('grantSecret');
  const hint  = document.getElementById('grantSecretHint');
  if (group) group.style.display = spec.secret ? '' : 'none';
  if (spec.secret && sel) {
    const matching = secState.secrets.filter(s => s.kind === kind);
    sel.innerHTML = matching.length
      ? matching.map(s => '<option value="' + esc(s.id) + '">' + esc(s.name) + '</option>').join('')
      : '<option value="">— no ' + esc(kind) + ' secret stored —</option>';
    if (hint) {
      hint.textContent = matching.length ? ''
        : 'Store a secret of kind "' + kind + '" first — a grant points at one.';
    }
  } else if (hint) {
    hint.textContent = 'Egress grants lease the hub’s own Internet connection and need no stored secret.';
  }
};

// _secList splits a comma-or-whitespace separated field into a clean list.
function _secList(id) {
  const raw = ((document.getElementById(id) || {}).value) || '';
  return raw.split(',').map(v => v.trim()).filter(v => v !== '');
}

// _secParseBytes accepts the CLI's quota syntax (100m, 2g) as well as a bare
// byte count, so the two interfaces take the same input.
function _secParseBytes(id) {
  const raw = (((document.getElementById(id) || {}).value) || '').trim().toLowerCase();
  if (!raw) return 0;
  const m = /^([0-9]+(?:\.[0-9]+)?)\s*([kmgt]?)b?$/.exec(raw);
  if (!m) return NaN;
  const mult = {'':1, k:1024, m:1048576, g:1073741824, t:1099511627776}[m[2]];
  return Math.round(parseFloat(m[1]) * mult);
}

window.submitGrant = function() {
  const errEl = document.getElementById('grantError');
  const btn   = document.getElementById('grantSubmitBtn');
  const kind  = ((document.getElementById('grantKind') || {}).value) || 'github_pat';
  const spec  = SEC_GRANT_KINDS[kind] || SEC_GRANT_KINDS.github_pat;

  const body = {
    source:      spec.source,
    subject:     (((document.getElementById('grantSubject') || {}).value) || '').trim(),
    scope:       (((document.getElementById('grantScope') || {}).value) || '').trim(),
    ttl_minutes: parseInt(((document.getElementById('grantTTL') || {}).value) || '1440', 10)
  };
  if (!body.subject) { _secFormError(errEl, 'A subject is required — a grant with no subject would match nothing.'); return; }

  if (spec.secret) {
    body.secret_ref = ((document.getElementById('grantSecret') || {}).value) || '';
    if (!body.secret_ref) { _secFormError(errEl, 'Store a secret of this kind first, then grant it.'); return; }
  }

  if (kind === 'github_pat' || kind === 'github_app') {
    body.repos = _secList('grantRepos');
    body.permissions = _secList('grantPermissions');
  } else if (kind === 'kubeconfig') {
    body.contexts = _secList('grantContexts');
    body.namespaces = _secList('grantNamespaces');
  } else if (kind === 'registry') {
    body.registries = _secList('grantRegistries');
  } else if (kind === 'env') {
    body.env_keys = _secList('grantEnvKeys');
  } else if (kind === 'egress_proxy') {
    body.hosts = _secList('grantProxyHosts');
  } else if (kind === 'egress') {
    body.hosts = _secList('grantHosts');
    body.cidrs = _secList('grantCIDRs');
    body.ports = _secList('grantPorts').map(p => parseInt(p, 10)).filter(p => !isNaN(p));
    const up = _secParseBytes('grantMaxUp');
    const down = _secParseBytes('grantMaxDown');
    if (isNaN(up) || isNaN(down)) { _secFormError(errEl, 'Quotas must look like 100m, 2g, or a byte count.'); return; }
    body.max_bytes_up = up;
    body.max_bytes_down = down;
    const sttl = parseInt(((document.getElementById('grantSessionTTL') || {}).value) || '0', 10);
    if (sttl > 0) body.session_ttl_minutes = sttl;
  }

  if (errEl) errEl.style.display = 'none';
  if (btn) btn.disabled = true;
  api('/api/grants', body).then(() => {
    if (btn) btn.disabled = false;
    closeGrantModal();
    toast('Grant created', 'ok');
    loadGrants(); loadSecrets();
  }).catch(err => {
    if (btn) btn.disabled = false;
    _secFormError(errEl, (err && err.message) || String(err));
  });
};

