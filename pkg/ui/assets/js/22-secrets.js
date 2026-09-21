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
  const loads = [];
  // Secrets, grants and leases are all secret.grant, and since Task 20271 the
  // tab itself opens one rung lower — an operator holding only secret.request
  // reaches this panel to file a request. Firing these three for them would
  // produce three 403s and three audit rows recording their own denial, on
  // every visit, for sections they cannot see.
  // Since Task 20275 the secrets and grants tables open one rung lower again:
  // an operator holding secret.own has personal credentials of their own to
  // manage, and the server sends them their own rows and no others. Leases
  // stayed at secret.grant — a lease is live fleet state with no owner to
  // scope it by — so it is fetched separately rather than riding along and
  // producing a 403 plus an audit row on every operator's visit.
  if (typeof canGlobal !== 'function' || canGlobal('secret.own')) {
    loads.push(loadSecrets(), loadGrants());
  }
  if (typeof canGlobal !== 'function' || canGlobal('secret.grant')) {
    loads.push(loadLeases());
  }
  // Tokens are admin-only and the section is hidden below token.admin, so
  // skip the fetch entirely for a maintainer rather than firing a request
  // whose only outcome is a 403 and an audit row for the denial.
  if (typeof canGlobal !== 'function' || canGlobal('token.admin')) {
    loads.push(loadTokens());
  }
  // Same rule for the sessions table (Task 20176): hidden below session.admin,
  // so a maintainer opening this tab should not fire a request whose only
  // outcome is a 403 and an audit row recording their own denial.
  if (typeof canGlobal !== 'function' || canGlobal('session.admin')) {
    loads.push(loadSessions());
  }
  // Access requests (Task 20271) sit one rung lower: secret.request is an
  // operator permission, so this section is the one part of the tab a
  // non-maintainer can use — and the only one they can use it for is their
  // own requests, which is what the server sends them.
  if (typeof canGlobal !== 'function' || canGlobal('secret.request')) {
    loads.push(loadGrantRequests());
  }
  return Promise.all(loads).then(() => { _secStartTicker(); });
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

// _secOwnerBadge marks whose credential a row is.
//
// Three states, because they mean three different things to the person
// reading the table: "Mine" is yours to grant and delete, a named owner is a
// colleague's that an admin can see but not spend, and no badge at all is the
// organisation's shared credential.
function _secOwnerBadge(s) {
  if (!s || !s.personal) return '';
  if (s.mine) return ' <span class="sec-chip sec-own-mine" title="Only you can see, grant or delete this.">Mine</span>';
  return ' <span class="sec-chip sec-own-other" title="Belongs to another user. You can see it because you administer users, but you cannot grant it.">' +
    esc(s.owner || 'another user') + '</span>';
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
      '<td><strong>' + esc(s.name || '') + '</strong>' + _secOwnerBadge(s) + '</td>' +
      '<td><span class="sec-chip kind">' + esc(s.kind || '') + '</span></td>' +
      '<td class="sec-fp sec-hide-sm" title="A digest of the sealed record, not of the value. Re-storing the same credential yields a different fingerprint.">' +
        esc(s.fingerprint || '—') + '</td>' +
      '<td>' + (s.active_grants || 0) + ' active' +
        (s.grants > s.active_grants ? ' <span class="sec-count">/ ' + s.grants + '</span>' : '') + '</td>' +
      '<td class="audit-time sec-hide-sm">' + esc(_secFmtTime(s.created_at)) + '</td>' +
      '<td><div class="sec-actions">' +
        '<button class="btn" data-global-perm="audit.read" data-perm-hide data-sec-audit="' + esc(s.id) + '">Audit</button>' +
        // A secret you own is yours to delete, so your own rows gate on
        // secret.own and the organisation's on secret.revoke. Gating both on
        // secret.revoke would show an operator a Delete button on their own
        // credential that the server then refuses.
        //
        // Written as two whole literal buttons rather than one with a computed
        // data-global-perm, because TestFrontendPermissionAttributesAreValid
        // reads these attributes statically to catch a misspelled permission —
        // and a gate whose value it cannot read is a gate that never denies.
        (s.mine
          ? '<button class="btn" data-global-perm="secret.own" data-sec-delete="' + esc(s.id) + '">Delete</button>'
          : '<button class="btn" data-global-perm="secret.revoke" data-sec-delete="' + esc(s.id) + '">Delete</button>') +
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
  // Verbs are the one dimension whose empty value is not "unset" but a policy
  // of its own, so the row renders the *effective* set rather than a blank an
  // operator would read as "anything goes". Whether that set writes comes from
  // the server (constraints.read_only) rather than from a second copy of the
  // rule here — the two disagreeing would be a badge that lies about a cluster
  // credential, which is the one thing this cell exists to prevent.
  if (g.kind === 'kubeconfig') {
    add('verbs', _secChips((c.verbs && c.verbs.length) ? c.verbs : ['get','list','watch']) +
      (c.read_only
        ? ' <span class="sec-chip ok" title="Read-only: nothing this grant permits can create, change or delete anything in the cluster.">read-only</span>'
        : ' <span class="sec-chip warn" title="This grant carries a write verb, so the holder can change the cluster within the granted contexts and namespaces.">writes</span>'));
  }
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
  // Where the allowlist above is actually checked. Two kinds send this, because
  // they are the two whose grant can say more than the delivered payload
  // enforces: a github_pat's repository list is otherwise checked by a helper
  // inside the sandbox, and a kubeconfig's verbs have no representation in the
  // file at all. The row already shows "repos acme/*" or "verbs create" either
  // way, so without this the two cases are indistinguishable — which is the
  // case worth marking.
  //
  // The wording follows the kind rather than the mode, because the remedy
  // differs: a kubeconfig row telling an operator to enable the git proxy
  // names a setting that would not change anything about this grant.
  const kube = g.kind === 'kubeconfig';
  if (g.enforcement === 'proxy') {
    parts.push('<div><span class="sec-count">enforced</span> ' +
      '<span class="sec-chip ok" title="' + (kube
        ? 'The Kubernetes access monitor stands between the sandbox and the API server. ' +
          'Contexts, namespaces and verbs are checked outside the sandbox, on every request.'
        : 'The git proxy holds the token. The repository allowlist and ref policy are ' +
          'enforced outside the sandbox, which never sees the credential.') +
      '">&#128274; ' + (kube ? 'kube monitor' : 'git proxy') + '</span></div>');
  } else if (g.enforcement === 'unguarded') {
    parts.push('<div><span class="sec-count">enforced</span> ' +
      '<span class="sec-chip warn" title="' + (kube
        ? 'The kubeconfig is delivered into the sandbox and nothing checks the verbs on it — ' +
          'a kubeconfig has no field for them, so the cluster\'s own RBAC is the only limit. ' +
          'Enable executors.kube_guard to enforce this grant outside the sandbox.'
        : 'The token is delivered into the sandbox and the allowlist is enforced by a ' +
          'credential helper the workload could read around. Enable executors.git_proxy to ' +
          'hold the token on the hub instead.') +
      '">&#9888; in sandbox</span></div>');
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
      '<td>' + _secRevocationCell(l) + '</td>' +
      '<td class="audit-time sec-hide-sm">' + esc(_secFmtTime(l.issued_at)) + '</td>' +
      '<td><div class="sec-actions">' +
        '<button class="btn" data-global-perm="secret.revoke" data-lease-revoke="' + esc(l.id) + '">Revoke</button>' +
        '<button class="btn danger" data-global-perm="secret.revoke" data-lease-kill="' + esc(l.id) + '">Revoke &amp; kill</button>' +
      '</div></td>' +
    '</tr>';
  }).join('');

  body.querySelectorAll('[data-lease-revoke]').forEach(btn => {
    btn.addEventListener('click', () => revokeLease(btn.getAttribute('data-lease-revoke'), 'scrub'));
  });
  body.querySelectorAll('[data-lease-kill]').forEach(btn => {
    btn.addEventListener('click', () => revokeLease(btn.getAttribute('data-lease-kill'), 'kill'));
  });
  _secApplyGating();
}

// _secRevocationCell renders how far a lease's revocation has actually got.
//
// The three states are kept distinct rather than collapsed into "revoked"
// because they are three different security postures. Only "revoked" means an
// agent confirmed it scrubbed the material; "revoke pending" means the frame
// is in flight; "unreachable" means the credential is still sitting on a
// machine the hub cannot talk to. A panel that showed the last of those as a
// success would let an operator close an incident on a live credential.
function _secRevocationCell(lease) {
  const revs = lease.revocations || [];
  if (!revs.length) {
    // Never revoked. Say whether it *could* be, because an agent too old to
    // honour the frame is something to find out before the incident, not
    // during it.
    if (lease.revocable === false) {
      return '<span class="sec-chip warn" title="At least one agent holding this lease speaks a protocol ' +
        'older than v2 and cannot scrub material on request. Upgrade it: cloop executor agent install --upgrade">' +
        'not revocable</span>';
    }
    return '<span class="sec-count">—</span>';
  }

  // Worst state wins, for the same reason the server aggregates that way.
  const rank = { revoked: 0, revoke_pending: 1, failed: 2, unreachable: 3 };
  let worst = revs[0];
  revs.forEach(r => { if ((rank[r.state] || 0) > (rank[worst.state] || 0)) worst = r; });

  const label = {
    revoked: 'revoked',
    revoke_pending: 'revoke pending',
    unreachable: 'unreachable',
    failed: 'failed'
  }[worst.state] || worst.state;

  const cls = worst.state === 'revoked' ? 'ok'
    : worst.state === 'revoke_pending' ? 'kind'
    : 'warn';

  const detail = [];
  if (worst.executor_id) detail.push('executor ' + worst.executor_id);
  if (worst.files_removed) detail.push(worst.files_removed + ' file(s) removed');
  if (worst.env_scrubbed && worst.env_scrubbed.length) {
    detail.push('env dropped: ' + worst.env_scrubbed.join(', '));
  }
  if (worst.egress_dropped) detail.push('egress allowlist dropped');
  if (worst.killed && worst.killed.length) detail.push('killed ' + worst.killed.length + ' task(s)');
  if (worst.error) detail.push(worst.error);
  if (revs.length > 1) detail.push(revs.length + ' holders');

  return '<span class="sec-chip ' + cls + '" title="' + esc(detail.join(' · ')) + '">' + esc(label) + '</span>';
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
    // A pending request is racing a decision deadline, so its countdown moves
    // for the same reason a lease's does. Rendered from cached state — the
    // list itself is refreshed by the secrets_update WebSocket event, never by
    // this interval.
    _reqRender();
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

window.revokeLease = function(id, action) {
  const kill = action === 'kill';
  const prompt = kill
    ? 'Revoke lease ' + id + ' and kill the tasks holding it?\n\n' +
      'Credential files are wiped, egress is dropped, and every task still using this lease is ' +
      'terminated (SIGTERM, then SIGKILL after 5s). Use this when the credential itself is ' +
      'compromised — an environment variable already handed to a running process cannot be taken ' +
      'back any other way.'
    : 'Revoke lease ' + id + '?\n\n' +
      'Credential files are wiped and egress allowlist entries are dropped on every executor holding ' +
      'this lease, now rather than at exit. The task keeps running and fails naturally on its next use. ' +
      'A variable already in a running process\'s own environment stays there — use "Revoke & kill" for that.';
  if (!confirm(prompt)) return;

  api('/api/leases/' + encodeURIComponent(id) + '/revoke', { action: kill ? 'kill' : 'scrub' }).then(d => {
    // The server\'s note is the honest description of what landed, including
    // the partial cases. Preferring it over a fixed string is what keeps the
    // toast from claiming a guarantee an unreachable agent did not deliver.
    const state = (d && d.state) || 'revoked';
    toast((d && d.note) || 'Lease revoked and credentials wiped',
      state === 'revoked' ? 'ok' : 'warn');
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
  egress_proxy: 'The proxy endpoint, e.g. http://user:pass@proxy.internal:3128.',
  local_repo:   'One name=/absolute/path per line, naming git repositories on the executor\u2019s host. Grants then select from it by name.',
  host_device:  'The host\u2019s device inventory: one name=/dev/path[:/dev/target][:mode] per line, where mode is r, rw (the default) or rwm. Grants then select from it by name.',
  host_interface: 'The host\u2019s interface inventory: one name=ifname[,target=eth1][,address=172.31.99.200/24][,gateway=\u2026][,mtu=\u2026] per line. Moving one into a sandbox takes it away from the executor for the life of the run, so never name the interface this host is reached on.'
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
  openOverlay('secret-overlay', {dismiss: closeSecretModal, focus: '#secretName'});
  _secApplyGating();
};

window.closeSecretModal = function() {
  // Clear the payload on close as well as on open: leaving a typed credential
  // in a hidden DOM node is the browser-side version of leaving it in a
  // buffer, and this modal is the one place in the dashboard that holds one.
  const p = document.getElementById('secretPayload');
  if (p) p.value = '';
  closeOverlay('secret-overlay');
};

window.onSecretKindChange = function() {
  const kind = ((document.getElementById('secretKind') || {}).value) || '';
  const hint = document.getElementById('secretPayloadHint');
  if (hint) hint.textContent = SEC_PAYLOAD_HINTS[kind] || '';
};

window.submitSecret = function() {
  const errEl = document.getElementById('secretError');
  const btn   = document.getElementById('secretSubmitBtn');
  // Default to personal when the shared radio is absent, which is what an
  // operator without secret.grant sees. Defaulting the other way would turn a
  // hidden control into a silent publication of the user's own credential.
  const sharedEl = document.getElementById('secretOwnShared');
  const body = {
    name:     ((document.getElementById('secretName') || {}).value || '').trim(),
    kind:     (document.getElementById('secretKind') || {}).value || '',
    payload:  (document.getElementById('secretPayload') || {}).value || '',
    personal: !(sharedEl && sharedEl.checked)
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

// SEC_KIND_FIELDSET names the constraint fieldset a kind reveals, without the
// form's own prefix: the grant wizard renders it as `grantSet-github` and the
// access-request form (Task 20271) as `requestSet-github`. One mapping with two
// readers rather than two mappings, because the alternative is two forms that
// quietly come to disagree about which allowlist belongs to which kind — and
// the one that is wrong is the one nobody opened this week.
const SEC_KIND_FIELDSET = {
  github_pat:   'github',
  github_app:   'github',
  kubeconfig:   'kubeconfig',
  registry:     'registry',
  env:          'env',
  egress_proxy: 'egressproxy',
  local_repo:   'localrepo',
  host_device:  'hostdevice',
  host_interface: 'hostinterface',
  egress:       'egress'
};

// SEC_KIND_CONSTRAINTS maps a kind to the allowlist dimensions it takes, as
// [body field, input id suffix] pairs — the same shape both POST /api/grants
// and POST /api/grant-requests accept.
//
// `egress` is absent on purpose: it is the hub's own connection rather than a
// stored secret, its quota/port/CIDR fields have no counterpart in an access
// request, and there is nothing to ask for because nothing was sealed. It stays
// handled inline in submitGrant.
const SEC_KIND_CONSTRAINTS = {
  github_pat:   [['repos','Repos'], ['permissions','Permissions']],
  github_app:   [['repos','Repos'], ['permissions','Permissions']],
  kubeconfig:   [['contexts','Contexts'], ['namespaces','Namespaces']],
  registry:     [['registries','Registries']],
  env:          [['env_keys','EnvKeys']],
  egress_proxy: [['hosts','ProxyHosts']],
  local_repo:   [['repos','LocalRepos']],
  host_device:  [['devices','Devices']],
  host_interface: [['interfaces','Interfaces']]
};

// SEC_KIND_WRITABLE are the kinds whose grant can be widened to read-write.
// The broker rejects `writable` on any other kind, so sending it would turn a
// request that is merely over-specified into one that cannot be filed at all.
const SEC_KIND_WRITABLE = {local_repo: true, host_device: true};

// _secReadConstraints copies one kind's allowlist fields out of a prefixed
// input group ('grant' or 'request') into an outgoing body.
function _secReadConstraints(prefix, kind, body) {
  (SEC_KIND_CONSTRAINTS[kind] || []).forEach(f => { body[f[0]] = _secList(prefix + f[1]); });
  return body;
}

// _secShowKindSet reveals the one fieldset belonging to kind inside a form and
// hides the rest. An unknown kind reveals nothing rather than falling back to
// a neighbour's fieldset, which would invite an allowlist that gates nothing.
function _secShowKindSet(overlayID, prefix, kind) {
  document.querySelectorAll('#' + overlayID + ' .sec-kindset').forEach(el => el.classList.remove('on'));
  const stem = SEC_KIND_FIELDSET[kind] || '';
  const set = stem ? document.getElementById(prefix + 'Set-' + stem) : null;
  if (set) set.classList.add('on');
}

// SEC_GRANT_KINDS says whether a kind needs a stored secret and which broker
// creates it. The fieldset it reveals comes from SEC_KIND_FIELDSET above.
const SEC_GRANT_KINDS = {
  github_pat:   {secret:true,  source:'secret'},
  github_app:   {secret:true,  source:'secret'},
  kubeconfig:   {secret:true,  source:'secret'},
  registry:     {secret:true,  source:'secret'},
  env:          {secret:true,  source:'secret'},
  egress_proxy: {secret:true,  source:'secret'},
  local_repo:   {secret:true,  source:'secret'},
  host_device:  {secret:true,  source:'secret'},
  host_interface: {secret:true, source:'secret'},
  egress:       {secret:false, source:'egress'}
};

window.openGrantModal = function() {
  const err = document.getElementById('grantError');
  if (err) err.style.display = 'none';
  ['grantRepos','grantPermissions','grantContexts','grantNamespaces','grantVerbs','grantHosts',
   'grantCIDRs','grantPorts','grantMethods','grantMaxUp','grantMaxDown','grantSessionTTL',
   'grantRegistries','grantEnvKeys','grantProxyHosts','grantScope','grantSubject',
   'grantLocalRepos','grantDevices','grantInterfaces'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  onGrantKindChange();
  openOverlay('grant-overlay', {dismiss: closeGrantModal, focus: '#grantSubject'});
  _secApplyGating();
};

window.closeGrantModal = function() {
  closeOverlay('grant-overlay');
};

window.onGrantKindChange = function() {
  const kind = ((document.getElementById('grantKind') || {}).value) || 'github_pat';
  const spec = SEC_GRANT_KINDS[kind] || SEC_GRANT_KINDS.github_pat;

  _secShowKindSet('grant-overlay', 'grant', kind);
  // writable has its own fieldset for the reason the request form's does: it
  // applies to two kinds rather than one, so it cannot live inside either
  // kind's own block.
  const wrSet = document.getElementById('grantSet-writable');
  if (wrSet) wrSet.classList.toggle('on', !!SEC_KIND_WRITABLE[kind]);
  const wr = document.getElementById('grantWritable');
  if (wr && !SEC_KIND_WRITABLE[kind]) wr.checked = false;

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

  if (kind !== 'egress') {
    _secReadConstraints('grant', kind, body);
    // Verbs stay out of SEC_KIND_CONSTRAINTS for the same reason egress's
    // dimensions do: that table is shared with the access-request form, whose
    // body has no verbs field. An entry there would let an asker type
    // `create` into a request that files without it, and the approval would
    // read as granting a write it never carried.
    if (kind === 'kubeconfig') body.verbs = _secList('grantVerbs');
    // Only for the kinds that take it: the broker rejects `writable` on any
    // other kind, so sending it unconditionally would make every grant
    // unfileable rather than merely over-specified.
    if (SEC_KIND_WRITABLE[kind]) {
      body.writable = !!((document.getElementById('grantWritable') || {}).checked);
    }
  } else {
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


// ── Access requests (Task 20271) ────────────────────────────────────────────
//
// The other direction through the same broker. Everything above this line is
// somebody handing out authority; this is somebody asking for it, so that the
// ask has a record with a deadline on it instead of living in a chat window.
//
// Four rules this panel deliberately does not re-derive, because the server has
// already decided them and a second copy would be the one that drifts:
//
//	decidable  — false for the caller's own request even when they hold
//	             secret.grant, because the broker refuses self-approval. A
//	             button rendered from a client-side guess would always fail.
//	mine       — who may withdraw.
//	the list   — already scoped: a caller who cannot decide is sent only their
//	             own requests, so there is nothing left to filter out here.
//	the TTL    — an approver may narrow but never widen; the broker clamps.
//
// Free text is the new surface this section adds — a justification and a
// decision note, both typed by one user and read by another — so both go
// through esc() on the way into the table, and neither is ever interpolated
// into an attribute that carries code.
const reqState = {
  requests: [],
  pending: 0,
  canDecide: false,
  actor: '',
  // uses caches GET /api/grant-requests/{id}/uses per request. The countdown
  // ticker re-renders this table every second, and re-fetching on each tick
  // would be a poll wearing an expansion panel's clothes.
  uses: {},
  open: {},     // request id → its "what did this do" row is expanded
  decide: null  // {id, action} while the decision modal is open
};

// _reqURL builds a sub-resource path: withdraw, approve, deny, uses.
//
// The separator is concatenated rather than left on the end of the base
// literal, deliberately. The route-drift gate in frontend_test.go reads URL
// literals out of the bundle and truncates each at its first interpolation; a
// base ending in a slash would therefore be recorded as a two-segment path that
// no route serves, and the gate would fail on a call that is perfectly correct.
// Keeping the base whole records it as the collection route it belongs to.
function _reqURL(id, action) {
  return '/api/grant-requests' + '/' + encodeURIComponent(id) + '/' + action;
}

window.loadGrantRequests = function() {
  const sel = document.getElementById('secRequestsFilter');
  const state = (sel && sel.value) || '';
  return api('/api/grant-requests' + (state ? '?state=' + encodeURIComponent(state) : '')).then(d => {
    d = d || {};
    reqState.requests  = Array.isArray(d.requests) ? d.requests : [];
    reqState.pending   = Number(d.pending_count) || 0;
    reqState.canDecide = !!d.can_decide;
    reqState.actor     = d.actor || '';
    _reqRender();
    return d;
  }).catch(err => _secFail('secRequestsEmpty', 'secRequestsTable', err, 'access requests'));
};

// _reqClamp shortens free text for a table cell. The full string still rides
// along in the title attribute, so clamping hides nothing — it only stops one
// four-kilobyte justification from owning the whole page.
function _reqClamp(s, max) {
  s = String(s ?? '');
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

function _reqRender() {
  const body  = document.getElementById('secRequestsBody');
  const table = document.getElementById('secRequestsTable');
  const empty = document.getElementById('secRequestsEmpty');
  const count = document.getElementById('secRequestsCount');
  if (!body) return;

  const rows = reqState.requests;
  if (count) {
    count.textContent = rows.length
      ? '(' + (reqState.pending ? reqState.pending + ' pending / ' : '') + rows.length + ')'
      : '';
  }
  if (!rows.length) {
    if (table) table.style.display = 'none';
    if (empty) {
      empty.style.display = '';
      // Naming the filter matters: "no access requests" under a state filter
      // reads as "the queue is empty" when the queue may be full of another
      // state, which is how an approver misses a pending row.
      const state = ((document.getElementById('secRequestsFilter') || {}).value) || '';
      empty.textContent = state
        ? 'No ' + state + ' requests.'
        : (reqState.canDecide
            ? 'No access requests. Nothing is waiting on you.'
            : 'You have no access requests. Ask for a credential here and the ask gets a deadline, a reviewer, and an audit row.');
    }
    body.innerHTML = '';
    _secApplyGating();
    return;
  }
  if (empty) empty.style.display = 'none';
  if (table) table.style.display = '';

  const now = Date.now();
  body.innerHTML = rows.map(r => _reqRow(r, now)).join('');

  body.querySelectorAll('[data-req-approve]').forEach(btn => {
    btn.addEventListener('click', () => approveRequest(btn.getAttribute('data-req-approve')));
  });
  body.querySelectorAll('[data-req-deny]').forEach(btn => {
    btn.addEventListener('click', () => denyRequest(btn.getAttribute('data-req-deny')));
  });
  body.querySelectorAll('[data-req-withdraw]').forEach(btn => {
    btn.addEventListener('click', () => withdrawRequest(btn.getAttribute('data-req-withdraw')));
  });
  body.querySelectorAll('[data-req-uses]').forEach(btn => {
    btn.addEventListener('click', () => toggleRequestUses(btn.getAttribute('data-req-uses')));
  });
  body.querySelectorAll('[data-req-audit]').forEach(btn => {
    btn.addEventListener('click', () => secretsAuditFor('grant', btn.getAttribute('data-req-audit')));
  });
  _secApplyGating();
}

// _reqDeadlineCell is the countdown a pending request is racing.
//
// It is rendered from expires_at rather than from the server's
// expires_in_seconds so the ticker can move it without a round trip, and it is
// allowed to reach "deadline passed": expiry is applied by a sweep, so there is
// a real window in which a row is past its deadline and still pending. Showing
// that honestly is the difference between a queue an approver trusts and one
// that appears to hold rows open forever.
function _reqDeadlineCell(r, now) {
  if (r.state !== 'pending') {
    if (!r.decided_at) return '<span class="sec-count">—</span>';
    return '<span class="audit-time">' + esc(_secFmtTime(r.decided_at)) + '</span>' +
      (r.decided_by ? '<br><span class="sec-count">by ' + esc(r.decided_by) + '</span>' : '');
  }
  let remaining = Number(r.expires_in_seconds) || 0;
  if (r.expires_at) {
    remaining = Math.floor((new Date(r.expires_at).getTime() - now) / 1000);
  }
  if (remaining <= 0) {
    return '<span class="sec-ttl gone" title="The decision window has closed. A sweep moves it to expired; until then it is still listed as pending.">deadline passed</span>';
  }
  return '<span class="' + _secTTLClass(remaining) + '">' + esc(_secFmtDuration(remaining)) + '</span>' +
    '<br><span class="sec-count">to decide</span>';
}

// _reqWantsCell shows the lifetime asked for and, once approved, the one
// actually issued. Both, because an approver narrowing a 30-day ask to 4 hours
// is the behaviour this whole feature exists to make ordinary, and a panel that
// printed only the ask would render that indistinguishable from waving it
// through.
function _reqWantsCell(r) {
  const asked = (Number(r.ttl_minutes) || 0) * 60;
  let html = '<span class="sec-ttl">' + esc(_secFmtDuration(asked)) + '</span>';
  if (r.state !== 'approved' || !r.grant_expires_at) return html;
  const from = r.decided_at ? new Date(r.decided_at).getTime() : 0;
  const issued = from ? Math.floor((new Date(r.grant_expires_at).getTime() - from) / 1000) : 0;
  if (issued > 0 && issued < asked - 60) {
    html += '<br><span class="sec-chip warn" title="The approver issued a shorter grant than was asked for.">' +
      esc(_secFmtDuration(issued)) + ' issued</span>';
  }
  html += '<br><span class="sec-count">until ' + esc(_secFmtTime(r.grant_expires_at)) + '</span>';
  return html;
}

function _reqRow(r, now) {
  const id = String(r.id || '');
  const pending = r.state === 'pending';

  const why = '<div title="' + esc(r.justification || '') + '">' +
      esc(_reqClamp(r.justification, 160)) + '</div>' +
    (r.decision_note
      ? '<div class="sec-count" style="margin-top:4px" title="' + esc(r.decision_note) + '">decision: ' +
          esc(_reqClamp(r.decision_note, 160)) + '</div>'
      : '');

  const actions =
    (r.decidable
      ? '<button class="btn" data-global-perm="secret.grant" data-req-approve="' + esc(id) + '">Approve</button>' +
        '<button class="btn danger" data-global-perm="secret.grant" data-req-deny="' + esc(id) + '">Deny</button>'
      : '') +
    (r.mine && pending
      ? '<button class="btn" data-global-perm="secret.request" data-req-withdraw="' + esc(id) + '">Withdraw</button>'
      : '') +
    (r.state === 'approved'
      ? '<button class="btn" data-global-perm="secret.grant" data-perm-hide data-req-uses="' + esc(id) + '">' +
          (reqState.open[id] ? 'Hide uses' : 'What did this do?') + '</button>'
      : '') +
    '<button class="btn" data-global-perm="audit.read" data-perm-hide data-req-audit="' + esc(id) + '">Audit</button>';

  let html = '<tr>' +
    '<td class="audit-entity"><strong>' + esc(r.requested_by || '—') + '</strong>' +
      (r.mine ? ' <span class="sec-chip">you</span>' : '') + '</td>' +
    '<td>' + esc(r.secret_name || r.secret_id || '—') +
      (r.kind ? '<br><span class="sec-chip kind">' + esc(r.kind) + '</span>' : '') + '</td>' +
    '<td class="audit-entity">' + esc(r.subject || '') +
      (r.scope ? ' <span class="sec-chip">' + esc(r.scope) + '</span>' : '') + '</td>' +
    '<td class="sec-hide-sm">' + (r.constraints
      ? '<span class="sec-chip">' + esc(r.constraints) + '</span>'
      : '<span class="sec-count">none</span>') + '</td>' +
    '<td>' + _reqWantsCell(r) + '</td>' +
    '<td class="sec-hide-sm">' + why + '</td>' +
    '<td><span class="sec-status ' + esc(r.state || '') + '">' + esc(r.state || '') + '</span></td>' +
    '<td>' + _reqDeadlineCell(r, now) + '</td>' +
    '<td><div class="sec-actions">' + actions + '</div></td>' +
  '</tr>';

  if (reqState.open[id]) {
    html += '<tr><td colspan="9">' + _reqUsesCell(id, r) + '</td></tr>';
  }
  return html;
}

// _reqUsesCell answers "what did approving this actually do".
//
// An approval mints authority; only the leases say whether anything ever
// redeemed it. Three outcomes are distinguished rather than collapsed, because
// they lead to different next decisions: not yet read, nothing ever used it,
// and here is exactly what did. The middle one is a finding — an ask that was
// wider than the work needed — so it is worded as one.
function _reqUsesCell(id, r) {
  const uses = reqState.uses[id];
  if (uses === undefined) return '<p class="sec-hint">Reading the lease history&hellip;</p>';
  if (typeof uses === 'string') {
    return '<p class="sec-hint">Could not read the lease history: ' + esc(uses) + '</p>';
  }
  if (!uses.length) {
    return '<p class="sec-hint">Grant <code>' + esc(r.grant_id || '') + '</code> has never been leased. ' +
      'Nothing has used this credential — if that is still true when it expires, the ask was wider than the work needed.</p>';
  }
  const rows = uses.map(u => {
    const first = u.first_seen ? new Date(u.first_seen).getTime() : 0;
    const last  = u.last_seen ? new Date(u.last_seen).getTime() : 0;
    const held  = (first && last && last > first) ? Math.floor((last - first) / 1000) : 0;
    return '<tr>' +
      '<td class="sec-fp">' + esc(u.lease_id || '—') + '</td>' +
      '<td>' + esc(u.executor_id || '—') + '</td>' +
      '<td class="audit-entity">' + esc(u.project_id || '—') + '</td>' +
      // task_id is 0 both for "no task" and for "not attributed", so the
      // server sends the discriminator rather than making the panel guess.
      '<td>' + (u.attributed
        ? 'task #' + esc(String(u.task_id))
        : '<span class="sec-count" title="The lease was issued for a whole project run, so no single task can be named.">project run (not task-scoped)</span>') + '</td>' +
      '<td class="audit-time">' + esc(_secFmtTime(u.first_seen)) + '</td>' +
      '<td class="sec-ttl">' + esc(held ? _secFmtDuration(held) : '—') + '</td>' +
    '</tr>';
  }).join('');
  return '<div class="sec-subtitle" style="margin-bottom:4px">What this grant did ' +
      '<span class="sec-count">' + uses.length + ' lease' + (uses.length === 1 ? '' : 's') + '</span></div>' +
    '<table class="audit-table"><thead><tr>' +
      '<th style="width:190px">Lease</th><th style="width:150px">Executor</th>' +
      '<th style="width:170px">Project</th><th style="width:200px">Attributed to</th>' +
      '<th style="width:170px">First seen</th><th style="width:100px">Held for</th>' +
    '</tr></thead><tbody>' + rows + '</tbody></table>';
}

window.toggleRequestUses = function(id) {
  if (reqState.open[id]) { delete reqState.open[id]; _reqRender(); return; }
  reqState.open[id] = true;
  if (reqState.uses[id] !== undefined) { _reqRender(); return; }
  _reqRender(); // paints the "reading…" line before the round trip
  api(_reqURL(id, 'uses')).then(d => {
    reqState.uses[id] = Array.isArray(d && d.uses) ? d.uses : [];
    _reqRender();
  }).catch(err => {
    reqState.uses[id] = (err && err.message) ? String(err.message) : String(err);
    _reqRender();
  });
};

// ── file a request ──

// _secCatalog resolves the name-and-kind list the request form's picker needs.
//
// A maintainer already has it: loadSecrets() populated secState.secrets from
// GET /api/secrets. An operator does not and must not — that route is
// maintainer-only because the full inventory (fingerprints, grant counts,
// metadata) is reconnaissance — so they fetch GET /api/secrets/catalog, which
// publishes an id, a name and a kind and nothing else.
//
// Resolved per open rather than cached, because a secret minted since the page
// loaded is exactly the one somebody is about to ask for.
function _secCatalog() {
  if (secState.secrets && secState.secrets.length) {
    return Promise.resolve(secState.secrets);
  }
  return api('/api/secrets/catalog')
    .then(d => (d && Array.isArray(d.secrets)) ? d.secrets : [])
    .catch(() => []);
}

window.openRequestModal = function() {
  const sel = document.getElementById('requestSecret');
  // Every stored secret, not one kind's worth: the request form's whole job is
  // that the asker does not already know which credential exists, so the chosen
  // secret decides the kind rather than the other way round.
  _secCatalog().then(list => {
    secState.catalog = list;
    if (!sel) return;
    sel.innerHTML = list.length
      ? list.map(s =>
          '<option value="' + esc(s.id) + '">' + esc(s.name || s.id) + ' — ' + esc(s.kind || '') + '</option>').join('')
      : '<option value="">— no secrets stored on this hub —</option>';
    // The kind-specific constraint fields follow the selection, so they can
    // only be drawn once the list has arrived.
    onRequestSecretChange();
  });
  ['requestSubject','requestScope','requestJustification','requestRepos','requestPermissions',
   'requestContexts','requestNamespaces','requestRegistries','requestEnvKeys','requestProxyHosts',
   'requestLocalRepos','requestDevices','requestInterfaces'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  const wr = document.getElementById('requestWritable');
  if (wr) wr.checked = false;
  const err = document.getElementById('requestError');
  if (err) err.style.display = 'none';
  openOverlay('request-overlay', {dismiss: closeRequestModal, focus: '#requestSubject'});
  _secApplyGating();
};

window.closeRequestModal = function() {
  closeOverlay('request-overlay');
};

// _reqKindOf resolves the kind of the secret a request names. The kind decides
// which allowlist the broker will demand, so it comes from the stored secret
// rather than from a second picker the asker could set inconsistently.
function _reqKindOf(secretID) {
  // secState.catalog is whatever the picker was built from: the full secret
  // list for a maintainer, the name-and-kind catalogue for an operator. Reading
  // secState.secrets directly would resolve every kind to '' for an operator —
  // whose GET /api/secrets is refused — so the form would ask for no allowlist
  // and the broker would reject the request at the very last step.
  const list = (secState.catalog && secState.catalog.length)
    ? secState.catalog : (secState.secrets || []);
  const s = list.filter(x => x.id === secretID)[0];
  return (s && s.kind) || '';
}

window.onRequestSecretChange = function() {
  const kind = _reqKindOf(((document.getElementById('requestSecret') || {}).value) || '');
  _secShowKindSet('request-overlay', 'request', kind);
  // writable is its own fieldset because it applies to two kinds rather than
  // one, so it cannot live inside either kind's own block.
  const wrSet = document.getElementById('requestSet-writable');
  if (wrSet) wrSet.classList.toggle('on', !!SEC_KIND_WRITABLE[kind]);
  const hint = document.getElementById('requestKindHint');
  if (hint) {
    hint.textContent = kind
      ? 'A ' + kind + ' grant is scoped by the allowlist below. Ask for the narrowest one that does the job — a reviewer can shorten the lifetime, but widening means filing again.'
      : 'Store a secret first: a request names a credential that already exists, it cannot ask for one to be created.';
  }
};

window.submitRequest = function() {
  const errEl = document.getElementById('requestError');
  const btn   = document.getElementById('requestSubmitBtn');
  const secretID = ((document.getElementById('requestSecret') || {}).value) || '';
  const kind = _reqKindOf(secretID);

  const body = {
    secret_ref:    secretID,
    subject:       (((document.getElementById('requestSubject') || {}).value) || '').trim(),
    scope:         (((document.getElementById('requestScope') || {}).value) || '').trim(),
    ttl_minutes:   parseInt(((document.getElementById('requestTTL') || {}).value) || '1440', 10),
    wait_minutes:  parseInt(((document.getElementById('requestWait') || {}).value) || '4320', 10),
    justification: (((document.getElementById('requestJustification') || {}).value) || '').trim()
  };
  if (!body.secret_ref) {
    _secFormError(errEl, 'Pick a secret. A request names a credential that already exists.');
    return;
  }
  if (!body.subject) {
    _secFormError(errEl, 'A subject is required — a grant with no subject would match nothing.');
    return;
  }
  if (!body.justification) {
    _secFormError(errEl, 'A justification is required. The reviewer is deciding whether this credential should exist for you, and an ask with no stated reason can only be rubber-stamped.');
    return;
  }
  _secReadConstraints('request', kind, body);
  if (SEC_KIND_WRITABLE[kind]) {
    body.writable = !!((document.getElementById('requestWritable') || {}).checked);
  }

  if (errEl) errEl.style.display = 'none';
  if (btn) btn.disabled = true;
  api('/api/grant-requests', body).then(() => {
    if (btn) btn.disabled = false;
    closeRequestModal();
    toast('Request filed — a maintainer has to approve it', 'ok');
    loadGrantRequests();
  }).catch(err => {
    if (btn) btn.disabled = false;
    _secFormError(errEl, (err && err.message) || String(err));
  });
};

window.withdrawRequest = function(id) {
  const r = reqState.requests.filter(x => x.id === id)[0];
  const what = (r && (r.secret_name || r.secret_id)) || id;
  if (!confirm('Withdraw your request for "' + what + '"?\n\nIt stops waiting for a decision. Nothing was granted, so nothing is revoked — file a new one if you still need it.')) return;
  api(_reqURL(id, 'withdraw'), {}).then(() => {
    toast('Request withdrawn', 'ok');
    loadGrantRequests();
  }).catch(err => toast('Withdraw failed: ' + ((err && err.message) || String(err)), 'err'));
};

// ── decide a request ──

window.approveRequest = function(id) { _reqOpenDecision(id, 'approve'); };
window.denyRequest    = function(id) { _reqOpenDecision(id, 'deny'); };

function _reqOpenDecision(id, action) {
  const r = reqState.requests.filter(x => x.id === id)[0];
  if (!r) { toast('That request is no longer in the list — refresh', 'err'); return; }
  reqState.decide = {id: id, action: action};

  const title = document.getElementById('requestDecideTitle');
  if (title) title.textContent = (action === 'approve' ? 'Approve request' : 'Deny request');

  // The summary is the whole point of the modal: a decision made without
  // reading the ask is the thing this feature was built to stop being normal.
  const sum = document.getElementById('requestDecideSummary');
  if (sum) {
    sum.innerHTML =
      '<div><strong>' + esc(r.requested_by || '') + '</strong> asks for <strong>' +
        esc(r.secret_name || r.secret_id || '') + '</strong>' +
        (r.kind ? ' <span class="sec-chip kind">' + esc(r.kind) + '</span>' : '') + '</div>' +
      '<div style="margin-top:4px"><span class="sec-count">for</span> ' + esc(r.subject || '') +
        (r.scope ? ' <span class="sec-chip">' + esc(r.scope) + '</span>' : '') + '</div>' +
      '<div style="margin-top:4px"><span class="sec-count">allowlist</span> ' +
        esc(r.constraints || 'none') + '</div>' +
      '<div style="margin-top:4px"><span class="sec-count">asked for</span> ' +
        esc(_secFmtDuration((Number(r.ttl_minutes) || 0) * 60)) + '</div>' +
      '<div style="margin-top:8px;white-space:pre-wrap">' + esc(r.justification || '') + '</div>';
  }

  const ttlGroup = document.getElementById('requestDecideTTLGroup');
  if (ttlGroup) ttlGroup.style.display = (action === 'approve') ? '' : 'none';
  const ttl = document.getElementById('requestDecideTTL');
  if (ttl) ttl.value = '0';
  const note = document.getElementById('requestDecideNote');
  if (note) note.value = '';
  const noteHint = document.getElementById('requestDecideNoteHint');
  if (noteHint) {
    noteHint.textContent = (action === 'approve')
      ? 'Optional. Recorded on the grant and read back during review.'
      : 'Required. The requester sees this and it is the only thing that tells them what to ask for instead.';
  }
  const btn = document.getElementById('requestDecideSubmitBtn');
  if (btn) {
    btn.textContent = (action === 'approve') ? 'Approve and mint the grant' : 'Deny';
    btn.className = 'btn ' + (action === 'approve' ? 'primary' : 'danger');
    btn.disabled = false;
  }
  const err = document.getElementById('requestDecideError');
  if (err) err.style.display = 'none';

  openOverlay('request-decide-overlay', {dismiss: closeRequestDecideModal, focus: note});
  _secApplyGating();
}

window.closeRequestDecideModal = function() {
  reqState.decide = null;
  closeOverlay('request-decide-overlay');
};

window.submitDecision = function() {
  const d = reqState.decide;
  if (!d) { closeRequestDecideModal(); return; }
  const errEl = document.getElementById('requestDecideError');
  const btn   = document.getElementById('requestDecideSubmitBtn');
  const note  = (((document.getElementById('requestDecideNote') || {}).value) || '').trim();

  // Refused here as well as in the broker. The server's 400 would be correct
  // and useless: it arrives after the modal has closed over the text the
  // approver would have had to retype.
  if (d.action === 'deny' && !note) {
    _secFormError(errEl, 'A denial needs a reason. It is the only thing the requester gets back, and without it they can only ask again identically.');
    return;
  }

  const body = {note: note};
  if (d.action === 'approve') {
    const ttl = parseInt(((document.getElementById('requestDecideTTL') || {}).value) || '0', 10);
    if (ttl > 0) body.ttl_minutes = ttl;
  }

  if (errEl) errEl.style.display = 'none';
  if (btn) btn.disabled = true;
  api(_reqURL(d.id, d.action), body).then(resp => {
    if (btn) btn.disabled = false;
    closeRequestDecideModal();
    // The server's note is the honest description of when the approval lands —
    // a grant is authority, and authority takes effect at the next lease.
    toast((resp && resp.note) || (d.action === 'approve' ? 'Approved' : 'Denied'), 'ok');
    loadGrantRequests();
    if (d.action === 'approve') { loadGrants(); loadSecrets(); }
  }).catch(err => {
    if (btn) btn.disabled = false;
    const msg = (err && err.message) || String(err);
    _secFormError(errEl, /409|conflict|not pending/i.test(msg)
      ? msg + '\n\nSomebody else decided this first. Close and refresh.'
      : msg);
    loadGrantRequests();
  });
};


// ── API tokens (Task 20175) ─────────────────────────────────────────────────
//
// Scoped credentials for callers with no browser. The panel's job is narrow:
// show what exists, mint one under the copy-once contract, and revoke.
//
// The value is handled in exactly one place — the result step of the modal —
// and is dropped from both the DOM and this closure when the modal closes.
// Nothing here writes it to localStorage, to a data-* attribute, or to a URL,
// because all three survive the modal and two of them survive the tab.

const tokState = {
  tokens: [],
  grantableRoles: [],
  projects: [],
  staticActive: false,

  // plaintext holds the freshly minted value for as long as the result step
  // is open, so the Copy button has something to copy. Cleared by
  // closeTokenModal.
  plaintext: '',
};

window.loadTokens = function() {
  return api('/api/tokens').then(d => {
    d = d || {};
    tokState.tokens         = Array.isArray(d.tokens) ? d.tokens : [];
    tokState.grantableRoles = Array.isArray(d.grantable_roles) ? d.grantable_roles : [];
    tokState.projects       = Array.isArray(d.projects) ? d.projects : [];
    tokState.staticActive   = !!d.static_token_active;
    _tokRenderBanner();
    _tokRender();
    return d;
  }).catch(err => _secFail('secTokensEmpty', 'secTokensTable', err, 'API tokens'));
};

// _tokRenderBanner surfaces the static-token deprecation where an operator
// will act on it: next to the feature that replaces it, not only in a startup
// log line they scrolled past weeks ago.
function _tokRenderBanner() {
  const el = document.getElementById('secTokensBanner');
  if (!el) return;
  if (!tokState.staticActive) { el.style.display = 'none'; return; }
  el.style.display = '';
  el.innerHTML = '<span aria-hidden="true">&#9888;</span><span>' +
    '<strong>This hub still accepts the static <code>--token</code>.</strong><br>' +
    'It bypasses RBAC, sees every project, and cannot be revoked for one caller without ' +
    'breaking the rest. Mint scoped tokens for each caller, then drop ' +
    '<code>--token</code> / <code>CLOOP_UI_TOKEN</code>.</span>';
}

function _tokRender() {
  const body  = document.getElementById('secTokensBody');
  const table = document.getElementById('secTokensTable');
  const empty = document.getElementById('secTokensEmpty');
  const count = document.getElementById('secTokensCount');
  if (!body) return;

  const rows = tokState.tokens;
  const live = rows.filter(t => t.status === 'active').length;
  if (count) count.textContent = rows.length ? '(' + live + ' active / ' + rows.length + ')' : '';
  if (!rows.length) {
    if (table) table.style.display = 'none';
    if (empty) empty.style.display = '';
    body.innerHTML = '';
    _secApplyGating();
    return;
  }
  if (empty) empty.style.display = 'none';
  if (table) table.style.display = '';

  body.innerHTML = rows.map(t => {
    const revocable = t.status !== 'revoked';
    return '<tr' + (t.status === 'active' ? '' : ' style="opacity:.6"') + '>' +
      '<td><strong>' + esc(t.name || '(unnamed)') + '</strong>' +
        (t.created_by ? '<br><span class="sec-count">by ' + esc(t.created_by) + '</span>' : '') + '</td>' +
      '<td class="sec-fp sec-hide-sm" title="The public half of the token. The secret is not stored and cannot be shown again.">' +
        esc(t.prefix || '—') + '</td>' +
      // A confined token's roles overstate it: a glasses link lists `operator`
      // but is pinned by path to the glasses views. Say so on the row, or the
      // honest reading is "a URL in someone's phone can start runs".
      '<td>' + (t.roles || []).map(r => '<span class="sec-chip kind">' + esc(r) + '</span>').join(' ') +
        (t.confinement ? ' <span class="sec-count" title="' + esc(t.confinement) + '">confined</span>' : '') + '</td>' +
      '<td>' + _tokScopeCell(t.project_scope) + '</td>' +
      '<td>' + _tokStatusCell(t.status) + '</td>' +
      '<td class="audit-time">' + esc(t.expires_at ? _secFmtTime(t.expires_at) : 'never') + '</td>' +
      '<td class="audit-time sec-hide-sm">' + esc(t.last_used_at ? _secFmtTime(t.last_used_at) : 'never') + '</td>' +
      '<td><div class="sec-actions">' +
        '<button class="btn" data-global-perm="audit.read" data-perm-hide data-tok-audit="' + esc(t.prefix || '') + '">Audit</button>' +
        (revocable
          ? '<button class="btn" data-global-perm="token.admin" data-tok-revoke="' + esc(t.id) + '">Revoke</button>'
          : '') +
      '</div></td>' +
    '</tr>';
  }).join('');

  body.querySelectorAll('[data-tok-revoke]').forEach(btn => {
    btn.addEventListener('click', () => revokeToken(btn.getAttribute('data-tok-revoke')));
  });
  body.querySelectorAll('[data-tok-audit]').forEach(btn => {
    btn.addEventListener('click', () => secretsAuditFor('secret', btn.getAttribute('data-tok-audit')));
  });
  _secApplyGating();
}

function _tokScopeCell(scope) {
  if (!scope || !scope.length) {
    return '<span class="sec-count" title="Every project this token’s roles allow">all projects</span>';
  }
  return scope.map(p => '<span class="sec-chip">' + esc(p) + '</span>').join(' ');
}

function _tokStatusCell(status) {
  const cls = status === 'active' ? 'sec-ttl' : 'sec-ttl gone';
  return '<span class="' + cls + '">' + esc(status || 'unknown') + '</span>';
}

// ── mutations ──

window.revokeToken = function(id) {
  const t = tokState.tokens.filter(x => x.id === id)[0];
  const name = (t && t.name) || id;
  if (!confirm('Revoke token "' + name + '"?\n\nAny CI job, script, or device still using it starts failing on its next request. This cannot be undone — issue a new token instead.')) return;
  apiMethod('DELETE', '/api/tokens/' + encodeURIComponent(id)).then(() => {
    toast('Token revoked', 'ok');
    loadTokens();
  }).catch(err => toast('Revoke failed: ' + ((err && err.message) || String(err)), 'err'));
};

// ── mint modal ──

window.openTokenModal = function() {
  const roles = document.getElementById('tokenRoles');
  if (roles) {
    const available = tokState.grantableRoles.length ? tokState.grantableRoles : ['viewer'];
    roles.innerHTML = available.map(r =>
      '<option value="' + esc(r) + '"' + (r === 'viewer' ? ' selected' : '') + '>' + esc(r) + '</option>'
    ).join('');
  }
  const projects = document.getElementById('tokenProjects');
  if (projects) {
    projects.innerHTML = tokState.projects.length
      ? tokState.projects.map(p => '<option value="' + esc(p) + '">' + esc(p) + '</option>').join('')
      : '<option disabled>(no named projects registered)</option>';
  }
  const name = document.getElementById('tokenName');
  if (name) name.value = '';
  const err = document.getElementById('tokenError');
  if (err) err.style.display = 'none';

  _tokShowStep('form');
  openOverlay('token-overlay', {dismiss: closeTokenModal, focus: name});
  _secApplyGating();
};

window.closeTokenModal = function() {
  // Drop the value from the DOM and from this closure together. Leaving it in
  // a hidden input is the browser-side equivalent of leaving a credential in a
  // buffer, and unlike the secret modal there is no way to re-fetch it, so
  // there is nothing to gain by keeping it around.
  tokState.plaintext = '';
  const pt = document.getElementById('tokenPlaintext');
  if (pt) pt.value = '';
  closeOverlay('token-overlay');
  _tokShowStep('form');
};

function _tokShowStep(which) {
  const form = document.getElementById('tokenFormStep');
  const res  = document.getElementById('tokenResultStep');
  if (form) form.style.display = (which === 'form') ? '' : 'none';
  if (res)  res.style.display  = (which === 'result') ? '' : 'none';
}

window.submitToken = function() {
  const errEl = document.getElementById('tokenError');
  const btn   = document.getElementById('tokenSubmitBtn');
  const body = {
    name:            ((document.getElementById('tokenName') || {}).value || '').trim(),
    roles:           _tokSelected('tokenRoles'),
    project_scope:   _tokSelected('tokenProjects'),
    expires_in_days: parseInt(((document.getElementById('tokenExpiry') || {}).value) || '90', 10),
  };
  if (!body.name)         { _secFormError(errEl, 'A name is required — it is how you decide later whether to revoke it.'); return; }
  if (!body.roles.length) { _secFormError(errEl, 'Pick at least one role. A token with no role can authenticate and do nothing.'); return; }
  if (isNaN(body.expires_in_days)) body.expires_in_days = 90;

  if (errEl) errEl.style.display = 'none';
  if (btn) btn.disabled = true;

  api('/api/tokens', body).then(d => {
    if (btn) btn.disabled = false;
    d = d || {};
    tokState.plaintext = d.plaintext || '';
    const pt = document.getElementById('tokenPlaintext');
    if (pt) pt.value = tokState.plaintext;
    const meta = document.getElementById('tokenResultMeta');
    if (meta) {
      const t = d.token || {};
      meta.innerHTML =
        '<strong>' + esc(t.name || '') + '</strong> &middot; ' +
        esc((t.roles || []).join(', ')) + ' &middot; ' +
        (t.project_scope && t.project_scope.length ? esc(t.project_scope.join(', ')) : 'all projects') +
        ' &middot; expires ' + esc(t.expires_at ? _secFmtTime(t.expires_at) : 'never');
    }
    _tokShowStep('result');
    setTimeout(() => { if (pt) { pt.focus(); pt.select(); } }, 50);
    loadTokens();
  }).catch(err => {
    if (btn) btn.disabled = false;
    _secFormError(errEl, (err && err.message) || String(err));
  });
};

window.copyTokenPlaintext = function() {
  const value = tokState.plaintext;
  if (!value) return;
  const done = () => {
    const btn = document.getElementById('tokenCopyBtn');
    if (btn) {
      btn.textContent = 'Copied';
      setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
    }
    toast('Token copied to clipboard', 'ok');
  };
  // navigator.clipboard needs a secure context, which a hub behind plaintext
  // HTTP on a LAN will not have. Fall back to selecting the field so the value
  // is still one keystroke away instead of unreachable.
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(value).then(done).catch(() => _tokSelectField());
    return;
  }
  _tokSelectField();
};

function _tokSelectField() {
  const pt = document.getElementById('tokenPlaintext');
  if (!pt) return;
  pt.focus();
  pt.select();
  toast('Press Ctrl/Cmd+C to copy', 'ok');
}

function _tokSelected(id) {
  const el = document.getElementById(id);
  if (!el || !el.options) return [];
  return Array.prototype.slice.call(el.options)
    .filter(o => o.selected && !o.disabled)
    .map(o => o.value);
}
