// CI/CD pipeline federation panel (Task 20278).
//
// Lives on the Settings tab because that is where the task asked for it and
// because the thing it edits is a deployment-wide policy, not a per-project
// one. Every call here is global-scope — no pUrl() — for the same reason.
//
// The panel has four parts, in the order an operator needs them:
//   1. the switch, plus whether there is actually a credential to relay with
//   2. the allowlist, which is the security-relevant part
//   3. live sessions, so "who is spending right now" is answerable
//   4. recent exchanges, which is where a refused pipeline is diagnosed

const ciState = {
  settings: null,
  rules: [],
  sessions: [],
  exchanges: [],
  editing: null,   // rule id being edited, or null for "new"
};

// ---------------------------------------------------------------------------
// settings
// ---------------------------------------------------------------------------

function ciRenderSettings(d) {
  ciState.settings = d;
  const status = document.getElementById('ciStatus');
  const note = document.getElementById('ciStatusNote');
  const snippet = document.getElementById('ciSnippet');
  if (!status || !note) return;

  status.innerHTML = d.enabled
    ? '<span class="badge complete" style="font-size:10px">enabled</span>'
    : '<span class="badge unknown" style="font-size:10px">disabled</span>';

  const parts = [];
  if (d.enabled) {
    // The order matters: a hub with federation on and nothing to relay with
    // answers every exchange with a 503, and the operator should learn that
    // here rather than from a pipeline three days later.
    if (!d.upstream_ready) {
      parts.push('<strong>No Anthropic credential to relay with.</strong> ' +
                 'Set <code>anthropic.api_key</code> above, or ' +
                 '<code>ui.ci.upstream_auth_token</code> in config.yaml — until then ' +
                 'every pipeline gets a 503.');
    } else {
      parts.push('Pipelines federate at <code>' + esc(d.base_url.replace(/\/api\/ci\/anthropic$/, '')) +
                 '/api/ci/token</code> and relay through <code>' + esc(d.base_url) + '</code>.');
      parts.push('Relaying to ' + esc(d.upstream) + '.');
    }
    parts.push('Tokens must be minted with audience <code>' + esc(d.audience) + '</code>.');
  } else {
    parts.push('CI federation is off. The exchange and relay endpoints refuse, ' +
               'whatever rules are listed below.');
  }
  if (d.error) {
    parts.push('<span style="color:var(--danger)">Service error: ' + esc(d.error) + '</span>');
  }
  note.innerHTML = parts.join('<br>');

  const toggle = document.getElementById('ciEnabled');
  if (toggle) toggle.checked = !!d.enabled;
  const aud = document.getElementById('ciAudience');
  if (aud && document.activeElement !== aud) aud.value = d.audience || '';
  const iss = document.getElementById('ciIssuer');
  if (iss && document.activeElement !== iss) iss.value = d.issuer || '';
  const models = document.getElementById('ciDefaultModels');
  if (models && document.activeElement !== models) {
    models.value = (d.default_models || []).join(', ');
  }
  if (snippet) snippet.textContent = d.snippet || '';
}

window.loadCISettings = function() {
  if (typeof canGlobal === 'function' && !canGlobal('secret.grant')) return Promise.resolve();
  return api('/api/ci/config').then(d => {
    if (!d || d.error) return;
    ciRenderSettings(d);
  }).catch(() => {});
};

window.saveCISettings = function() {
  const body = {
    enabled: !!document.getElementById('ciEnabled').checked,
    issuer: document.getElementById('ciIssuer').value.trim(),
    audience: document.getElementById('ciAudience').value.trim(),
    default_models: document.getElementById('ciDefaultModels').value
      .split(',').map(s => s.trim()).filter(Boolean),
  };
  apiMethod('PUT', '/api/ci/config', body).then(d => {
    if (d && d.error) { toast(d.error, 'err'); return; }
    toast('CI federation settings saved', 'ok');
    ciRenderSettings(d);
    window.loadCIRules();
    window.loadCISessions();
  }).catch(() => toast('Request failed', 'err'));
};

window.copyCISnippet = function() {
  const el = document.getElementById('ciSnippet');
  if (!el) return;
  const text = el.textContent || '';
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text)
      .then(() => toast('Workflow snippet copied', 'ok'))
      .catch(() => toast('Could not copy — select the text instead', 'info'));
    return;
  }
  toast('Copy is unavailable here — select the text instead', 'info');
};

// ---------------------------------------------------------------------------
// rules
// ---------------------------------------------------------------------------

function ciMatcherSummary(r) {
  const bits = [];
  if (r.repository) bits.push('repo ' + esc(r.repository));
  if (r.ref) bits.push('ref ' + esc(r.ref));
  if (r.workflow) bits.push('workflow ' + esc(r.workflow));
  if (r.environment) bits.push('env ' + esc(r.environment));
  if (r.actor) bits.push('actor ' + esc(r.actor));
  if (r.event_name) bits.push('on ' + esc(r.event_name));
  if (r.condition) bits.push('<code>' + esc(r.condition) + '</code>');
  return bits.length ? bits.join(' · ') : '<em>matches nothing</em>';
}

function ciRenderRules() {
  const body = document.getElementById('ciRulesBody');
  const empty = document.getElementById('ciRulesEmpty');
  if (!body) return;
  if (!ciState.rules.length) {
    body.innerHTML = '';
    if (empty) {
      empty.style.display = '';
      empty.textContent = 'No pipelines are allowlisted. Until one is, every ' +
        'exchange is refused even with federation enabled.';
    }
    return;
  }
  if (empty) empty.style.display = 'none';

  body.innerHTML = ciState.rules.map((r, i) => {
    const state = r.broken
      ? '<span class="badge failed" title="' + esc(r.broken) + '">not in force</span>'
      : (r.enabled ? '<span class="badge complete">enabled</span>'
                   : '<span class="badge unknown">disabled</span>');
    const live = r.live_sessions
      ? ' <span class="badge running">' + r.live_sessions + ' live</span>' : '';
    const matched = r.last_matched_at && !r.last_matched_at.startsWith('0001')
      ? relTime(r.last_matched_at) : 'never';
    return '<tr>' +
      '<td><strong>' + esc(r.name || '(unnamed)') + '</strong>' + live +
        '<div class="muted" style="font-size:11px">' + ciMatcherSummary(r) + '</div></td>' +
      '<td>' + state + '</td>' +
      '<td style="font-size:11px">' + (r.effective_models || []).map(esc).join('<br>') + '</td>' +
      '<td style="font-size:11px">' + r.effective_max_requests + ' req<br>' +
        Math.round(r.effective_ttl_seconds / 60) + ' min</td>' +
      '<td style="font-size:11px">' + esc(matched) + '</td>' +
      '<td><button class="btn btn-sm" data-ci-edit="' + i + '">Edit</button> ' +
        '<button class="btn btn-sm btn-danger" data-ci-delete="' + i + '">Delete</button></td>' +
      '</tr>';
  }).join('');

  // Listeners rather than inline onclick with interpolated data: a rule name
  // containing a quote has broken this dashboard before (Tasks 163, 20033),
  // and an index is the one thing that cannot carry a quote.
  body.querySelectorAll('[data-ci-edit]').forEach(btn => {
    btn.addEventListener('click', () => ciEditRule(+btn.getAttribute('data-ci-edit')));
  });
  body.querySelectorAll('[data-ci-delete]').forEach(btn => {
    btn.addEventListener('click', () => ciDeleteRule(+btn.getAttribute('data-ci-delete')));
  });
}

window.loadCIRules = function() {
  if (typeof canGlobal === 'function' && !canGlobal('secret.grant')) return Promise.resolve();
  return api('/api/ci/rules').then(d => {
    if (!d || d.error) return;
    ciState.rules = d.rules || [];
    ciRenderRules();
  }).catch(() => {});
};

function ciFormValues() {
  const val = id => (document.getElementById(id) || {value: ''}).value.trim();
  const num = id => parseInt(val(id), 10) || 0;
  return {
    name: val('ciRuleName'),
    enabled: !!(document.getElementById('ciRuleEnabled') || {}).checked,
    repository: val('ciRuleRepo'),
    ref: val('ciRuleRef'),
    workflow: val('ciRuleWorkflow'),
    environment: val('ciRuleEnv'),
    actor: val('ciRuleActor'),
    event_name: val('ciRuleEvent'),
    condition: val('ciRuleCondition'),
    models: val('ciRuleModels').split(',').map(s => s.trim()).filter(Boolean),
    max_requests: num('ciRuleMaxRequests'),
    max_output_tokens: num('ciRuleMaxOutput'),
    ttl_seconds: num('ciRuleTTL') * 60,
    project: val('ciRuleProject'),
  };
}

function ciSetForm(r) {
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v || ''; };
  set('ciRuleName', r.name);
  set('ciRuleRepo', r.repository);
  set('ciRuleRef', r.ref);
  set('ciRuleWorkflow', r.workflow);
  set('ciRuleEnv', r.environment);
  set('ciRuleActor', r.actor);
  set('ciRuleEvent', r.event_name);
  set('ciRuleCondition', r.condition);
  set('ciRuleModels', (r.models || []).join(', '));
  set('ciRuleMaxRequests', r.max_requests || '');
  set('ciRuleMaxOutput', r.max_output_tokens || '');
  set('ciRuleTTL', r.ttl_seconds ? Math.round(r.ttl_seconds / 60) : '');
  set('ciRuleProject', r.project);
  const en = document.getElementById('ciRuleEnabled');
  if (en) en.checked = r.enabled !== false;
  const testOut = document.getElementById('ciRuleTestResult');
  if (testOut) testOut.innerHTML = '';
  const title = document.getElementById('ciRuleFormTitle');
  if (title) title.textContent = ciState.editing ? 'Edit pipeline rule' : 'Add pipeline rule';
}

function ciEditRule(i) {
  const r = ciState.rules[i];
  if (!r) return;
  ciState.editing = r.id;
  ciSetForm(r);
  const form = document.getElementById('ciRuleForm');
  if (form) { form.style.display = ''; form.scrollIntoView({behavior: 'smooth', block: 'nearest'}); }
}

window.ciNewRule = function() {
  ciState.editing = null;
  ciSetForm({enabled: true});
  const form = document.getElementById('ciRuleForm');
  if (form) form.style.display = '';
};

window.ciCancelRule = function() {
  ciState.editing = null;
  const form = document.getElementById('ciRuleForm');
  if (form) form.style.display = 'none';
};

window.ciSaveRule = function() {
  const body = ciFormValues();
  const editing = ciState.editing;
  const req = editing
    ? apiMethod('PUT', '/api/ci/rules/' + encodeURIComponent(editing), body)
    : apiMethod('POST', '/api/ci/rules', body);
  req.then(d => {
    if (d && d.error) { toast(d.error, 'err'); return; }
    // An edit revokes the sessions the old text minted. Saying so is the
    // difference between a surprising 401 in a running pipeline and an
    // expected one.
    if (d && d.revoked_sessions) {
      toast('Rule saved — ' + d.revoked_sessions + ' live session(s) revoked', 'ok');
    } else {
      toast('Rule saved', 'ok');
    }
    window.ciCancelRule();
    window.loadCIRules();
    window.loadCISessions();
  }).catch(() => toast('Request failed', 'err'));
};

function ciDeleteRule(i) {
  const r = ciState.rules[i];
  if (!r) return;
  const extra = r.live_sessions
    ? '\n\n' + r.live_sessions + ' live session(s) will be revoked immediately.' : '';
  if (!confirm('Delete the rule "' + (r.name || r.id) + '"?' + extra)) return;
  apiMethod('DELETE', '/api/ci/rules/' + encodeURIComponent(r.id)).then(d => {
    if (d && d.error) { toast(d.error, 'err'); return; }
    toast('Rule deleted', 'ok');
    window.loadCIRules();
    window.loadCISessions();
  }).catch(() => toast('Request failed', 'err'));
}

window.ciTestRule = function() {
  const body = ciFormValues();
  const out = document.getElementById('ciRuleTestResult');
  apiMethod('POST', '/api/ci/rules/test', body).then(d => {
    if (!out) return;
    if (d && d.error) { out.innerHTML = '<span style="color:var(--danger)">' + esc(d.error) + '</span>'; return; }
    if (!d.valid) {
      out.innerHTML = '<span style="color:var(--danger)">Will not save: ' + esc(d.error) + '</span>';
      return;
    }
    if (d.matched) {
      out.innerHTML = '<span style="color:var(--success)">Valid — admits the sample ' +
        'acme/tool pipeline (push to refs/heads/main, workflow "release", actor "dana").</span>';
      return;
    }
    out.innerHTML = '<span class="muted">Valid, but does not admit the sample pipeline' +
      (d.reason ? ': ' + esc(d.reason) : '.') +
      ' That is expected if your rule names a different repository.</span>';
  }).catch(() => { if (out) out.textContent = 'Request failed'; });
};

// ---------------------------------------------------------------------------
// live sessions
// ---------------------------------------------------------------------------

function ciRenderSessions() {
  const body = document.getElementById('ciSessionsBody');
  const empty = document.getElementById('ciSessionsEmpty');
  if (!body) return;
  if (!ciState.sessions.length) {
    body.innerHTML = '';
    if (empty) { empty.style.display = ''; empty.textContent = 'No pipeline is federated right now.'; }
    return;
  }
  if (empty) empty.style.display = 'none';
  body.innerHTML = ciState.sessions.map((s, i) => {
    const who = s.run_url
      ? '<a href="' + esc(s.run_url) + '" target="_blank" rel="noopener">' + esc(s.repository || s.id) + '</a>'
      : esc(s.repository || s.id);
    const u = s.usage || {};
    const tokens = (u.input_tokens || 0) + (u.output_tokens || 0) +
                   (u.cache_read_input_tokens || 0) + (u.cache_creation_input_tokens || 0);
    return '<tr>' +
      '<td>' + who + '<div class="muted" style="font-size:11px">' +
        esc(s.ref || '') + ' ' + esc(s.workflow || '') + '</div></td>' +
      '<td style="font-size:11px">' + esc(s.rule_name || '') + '</td>' +
      '<td style="font-size:11px">' + (u.requests || 0) + ' req' +
        (u.denied ? ' <span class="badge failed">' + u.denied + ' denied</span>' : '') +
        '<br>' + tokens.toLocaleString() + ' tokens</td>' +
      '<td style="font-size:11px">' + (s.remaining_requests < 0 ? '∞' : s.remaining_requests) + ' left<br>' +
        'expires ' + esc(relTime(s.expires_at)) + '</td>' +
      '<td><button class="btn btn-sm btn-danger" data-ci-revoke="' + i + '">Revoke</button></td>' +
      '</tr>';
  }).join('');
  body.querySelectorAll('[data-ci-revoke]').forEach(btn => {
    btn.addEventListener('click', () => ciRevokeSession(+btn.getAttribute('data-ci-revoke')));
  });
}

window.loadCISessions = function() {
  if (typeof canGlobal === 'function' && !canGlobal('secret.grant')) return Promise.resolve();
  return api('/api/ci/sessions').then(d => {
    if (!d || d.error) return;
    ciState.sessions = d.sessions || [];
    ciRenderSessions();
  }).catch(() => {});
};

function ciRevokeSession(i) {
  const s = ciState.sessions[i];
  if (!s) return;
  if (!confirm('Revoke this session? The pipeline stops being able to relay immediately.')) return;
  apiMethod('DELETE', '/api/ci/sessions/' + encodeURIComponent(s.id)).then(d => {
    if (d && d.error) { toast(d.error, 'err'); return; }
    toast('Session revoked', 'ok');
    window.loadCISessions();
  }).catch(() => toast('Request failed', 'err'));
}

// ---------------------------------------------------------------------------
// exchanges
// ---------------------------------------------------------------------------

function ciRenderExchanges() {
  const body = document.getElementById('ciExchangesBody');
  const empty = document.getElementById('ciExchangesEmpty');
  if (!body) return;
  if (!ciState.exchanges.length) {
    body.innerHTML = '';
    if (empty) { empty.style.display = ''; empty.textContent = 'No pipeline has tried to federate yet.'; }
    return;
  }
  if (empty) empty.style.display = 'none';
  body.innerHTML = ciState.exchanges.map(e => {
    const verdict = e.accepted
      ? '<span class="badge complete">accepted</span>'
      : '<span class="badge failed">' + esc(e.reason || 'refused') + '</span>';
    const who = e.repository
      ? esc(e.repository) + (e.ref ? ' <span class="muted">' + esc(e.ref) + '</span>' : '')
      : '<em>unverified token</em>';
    return '<tr>' +
      '<td style="font-size:11px">' + esc(relTime(e.at)) + '</td>' +
      '<td>' + who + '</td>' +
      '<td>' + verdict + '</td>' +
      '<td style="font-size:11px">' + esc(e.rule_name || '') + '</td>' +
      '<td style="font-size:11px">' + esc(e.detail || '') + '</td>' +
      '</tr>';
  }).join('');
}

window.loadCIExchanges = function() {
  if (typeof canGlobal === 'function' && !canGlobal('secret.grant')) return Promise.resolve();
  return api('/api/ci/exchanges').then(d => {
    if (!d || d.error) return;
    ciState.exchanges = d.exchanges || [];
    ciRenderExchanges();
  }).catch(() => {});
};

// loadCIPanel is the single entry point the Settings tab calls.
window.loadCIPanel = function() {
  if (typeof canGlobal === 'function' && !canGlobal('secret.grant')) {
    const panel = document.getElementById('ciPanel');
    if (panel) panel.style.display = 'none';
    return Promise.resolve();
  }
  return Promise.all([
    window.loadCISettings(),
    window.loadCIRules(),
    window.loadCISessions(),
    window.loadCIExchanges(),
  ]);
};
