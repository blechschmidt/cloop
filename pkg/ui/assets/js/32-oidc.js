// Single sign-on settings (Task 20308).
//
// The panel that edits ui.oidc. Three things make it different from the other
// Settings sections, and all three come from the same property: this is the
// block that decides who can sign in, and it is read at startup rather than
// per request.
//
//  1. It refuses rather than warns. The backend validates a prospective block
//     through the constructors the next startup will run, so a save that would
//     stop the hub booting comes back as a 400 with the offending field named.
//     This file's job is to put that message next to the right input.
//
//  2. It says when a save is not live yet. `restart_required` in the view is
//     the answer to the one confusing thing about the feature — "I turned SSO
//     on and nothing happened" — so it gets a banner rather than a footnote.
//
//  3. It never round-trips the client secret. The input is always blank on
//     load; blank on save means "keep what is stored", and clearing needs the
//     explicit button. So the panel cannot leak the credential into the DOM,
//     and an operator editing the issuer cannot accidentally erase it.
//
// Bounds, role names and claim kinds all come from the server rather than being
// written here, because they are already constants in pkg/config and pkg/authz.
// A copy in this file would be the copy that goes stale, and the symptom would
// be a form that accepts a value the next startup rejects.

const oidcState = {
  // The last view the server sent. Role mappings are edited in place against
  // this copy, so the table is the model rather than the DOM being parsed.
  view: null,
  mappings: [],
};

window.loadOIDCSettings = function() {
  // Gate the fetch as well as the panel. Without this an operator without
  // user.manage would 403 on every Settings visit, which shows up as a console
  // full of errors and a toast they can do nothing about.
  if (typeof canGlobal === 'function' && !canGlobal('user.manage')) {
    const panel = document.getElementById('oidcPanel');
    if (panel) panel.style.display = 'none';
    return Promise.resolve();
  }
  return api('/api/config/oidc').then(d => {
    if (!d || d.error) return;
    oidcState.view = d;
    oidcState.mappings = (d.role_mappings || []).map(m => Object.assign({}, m));
    renderOIDCSettings(d);
  }).catch(() => {});
};

function renderOIDCSettings(d) {
  const set = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.value = value;
  };
  const check = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.checked = !!value;
  };

  check('oidcEnabled', d.enabled);
  set('oidcIssuer', d.issuer || '');
  set('oidcClientId', d.client_id || '');
  set('oidcRedirectUrl', d.redirect_url || '');
  set('oidcScopes', (d.scopes || []).join(', '));
  set('oidcAdminEmails', (d.admin_emails || []).join(', '));
  set('oidcCookieSecure', d.cookie_secure || 'auto');
  check('oidcRequireIdp', d.require_idp);

  // The numeric fields show the effective default when unset rather than a
  // bare 0, because "0" reads as "no session lifetime" to someone who has not
  // read the config reference.
  const lim = d.limits || {};
  const num = (id, value, bound) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.value = value || (bound ? bound.default : 0);
    if (bound) {
      // A field with a disable sentinel accepts a value below its lower bound,
      // so min would reject the very thing the label tells you to type.
      el.min = bound.disable !== undefined && bound.disable !== 0 ? bound.disable : bound.lower;
      el.max = bound.upper;
    }
  };
  num('oidcSessionTtl', d.session_ttl_hours, lim.session_ttl_hours);
  num('oidcIdleTimeout', d.idle_timeout_hours, lim.idle_timeout_hours);
  num('oidcRefreshInterval', d.refresh_interval_minutes, lim.refresh_interval_minutes);
  num('oidcMaxClaimAge', d.max_claim_age_minutes, lim.max_claim_age_minutes);
  num('oidcClockSkew', d.clock_skew_seconds, lim.clock_skew_seconds);

  renderOIDCRoleOptions(d.roles || [], d.default_role || '');
  renderOIDCSecretState(d);
  renderOIDCStatus(d);
  renderOIDCMappings();
}

function renderOIDCRoleOptions(roles, selected) {
  const sel = document.getElementById('oidcDefaultRole');
  if (!sel) return;
  sel.innerHTML = roles.map(r => {
    const label = r === 'none' ? 'none — deny by default (recommended)' : r;
    return '<option value="' + esc(r) + '">' + esc(label) + '</option>';
  }).join('');
  sel.value = selected || 'none';
}

function renderOIDCSecretState(d) {
  const state = document.getElementById('oidcSecretState');
  const clearBtn = document.getElementById('oidcClearSecretBtn');
  if (clearBtn) clearBtn.style.display = d.client_secret_source === 'file' ? '' : 'none';
  if (!state) return;
  if (d.client_secret_source === 'env') {
    // Worth saying explicitly: on this hub a value typed into the box would be
    // stored and then overridden on every load, so the box is the wrong place
    // to change it.
    state.textContent = '— supplied by CLOOP_OIDC_CLIENT_SECRET; a value typed here is ignored';
  } else if (d.client_secret_set) {
    state.textContent = '— stored';
  } else {
    state.textContent = '— not set';
  }
}

function renderOIDCStatus(d) {
  const badge = document.getElementById('oidcStatus');
  if (badge) {
    if (d.active && d.active.enabled) {
      badge.innerHTML = d.active.idp_ready
        ? '<span class="badge complete">active</span>'
        : '<span class="badge failed" title="' + esc(d.active.error || '') + '">IdP unresolved</span>';
    } else {
      badge.innerHTML = '<span class="badge unknown">off</span>';
    }
  }

  const note = document.getElementById('oidcRestartNote');
  if (!note) return;
  if (!d.restart_required) {
    note.style.display = 'none';
    note.textContent = '';
    return;
  }
  // The authenticator is built once at startup, so a saved change is inert
  // until the process restarts. Saying which direction the gap runs matters:
  // "saved on, running off" is a hub still wide open.
  const running = d.active && d.active.enabled
    ? 'currently running SSO against ' + (d.active.issuer || 'an unnamed issuer')
    : 'currently running without SSO';
  note.style.display = '';
  note.style.cssText = 'display:block;font-size:12px;padding:8px 10px;margin-bottom:12px;' +
    'border:1px solid var(--border);border-left:3px solid var(--warn,#d29922);border-radius:4px';
  note.textContent = 'Saved, but not in force yet: this hub is ' + running +
    '. Restart the hub to apply the saved configuration.';
}

function renderOIDCMappings() {
  const body = document.getElementById('oidcMappingsBody');
  const empty = document.getElementById('oidcMappingsEmpty');
  if (!body) return;
  if (!oidcState.mappings.length) {
    body.innerHTML = '';
    if (empty) {
      empty.style.display = '';
      empty.textContent = 'No role mappings. Every signed-in user gets the default role above; ' +
        'admin emails still apply.';
    }
    return;
  }
  if (empty) empty.style.display = 'none';

  const claims = (oidcState.view && oidcState.view.claims) || ['group', 'role', 'email', 'sub'];
  const roles = (oidcState.view && oidcState.view.roles) || ['none', 'viewer', 'operator', 'maintainer', 'admin'];
  const options = (values, selected) => values.map(v =>
    '<option value="' + esc(v) + '"' + (v === selected ? ' selected' : '') + '>' + esc(v) + '</option>'
  ).join('');

  // Index-addressed handlers, never interpolated values: a project name or a
  // claim value with a quote in it would otherwise break out of the attribute.
  // This is the bug class that broke per-project switching four times.
  body.innerHTML = oidcState.mappings.map((m, i) =>
    '<tr>' +
      '<td><select class="form-select" data-oidc-field="claim" data-oidc-row="' + i + '">' +
        options(claims, m.claim) + '</select></td>' +
      '<td><input class="form-input" data-oidc-field="value" data-oidc-row="' + i + '" value="' +
        esc(m.value || '') + '" placeholder="cloop-admins"></td>' +
      '<td><select class="form-select" data-oidc-field="role" data-oidc-row="' + i + '">' +
        options(roles, m.role) + '</select></td>' +
      '<td><input class="form-input" data-oidc-field="project" data-oidc-row="' + i + '" value="' +
        esc(m.project || '') + '" placeholder="all"></td>' +
      '<td><input class="form-input" data-oidc-field="executor" data-oidc-row="' + i + '" value="' +
        esc(m.executor || '') + '" placeholder="all"></td>' +
      '<td><button class="btn danger" data-oidc-remove="' + i + '">Remove</button></td>' +
    '</tr>'
  ).join('');

  body.querySelectorAll('[data-oidc-field]').forEach(el => {
    el.addEventListener('change', () => {
      const row = parseInt(el.getAttribute('data-oidc-row'), 10);
      if (!oidcState.mappings[row]) return;
      oidcState.mappings[row][el.getAttribute('data-oidc-field')] = el.value;
    });
  });
  body.querySelectorAll('[data-oidc-remove]').forEach(el => {
    el.addEventListener('click', () => {
      oidcState.mappings.splice(parseInt(el.getAttribute('data-oidc-remove'), 10), 1);
      renderOIDCMappings();
    });
  });
}

window.oidcAddMapping = function() {
  oidcState.mappings.push({claim: 'group', value: '', role: 'viewer', project: '', executor: ''});
  renderOIDCMappings();
};

function oidcNum(id) {
  const el = document.getElementById(id);
  if (!el) return 0;
  const n = parseInt(el.value, 10);
  return isNaN(n) ? 0 : n;
}

function oidcList(id) {
  const el = document.getElementById(id);
  if (!el) return [];
  return el.value.split(',').map(s => s.trim()).filter(Boolean);
}

window.saveOIDCSettings = function() {
  const secretEl = document.getElementById('oidcClientSecret');
  const body = {
    enabled: !!document.getElementById('oidcEnabled').checked,
    issuer: document.getElementById('oidcIssuer').value,
    client_id: document.getElementById('oidcClientId').value,
    redirect_url: document.getElementById('oidcRedirectUrl').value,
    scopes: oidcList('oidcScopes'),
    admin_emails: oidcList('oidcAdminEmails'),
    default_role: document.getElementById('oidcDefaultRole').value,
    role_mappings: oidcState.mappings,
    session_ttl_hours: oidcNum('oidcSessionTtl'),
    idle_timeout_hours: oidcNum('oidcIdleTimeout'),
    refresh_interval_minutes: oidcNum('oidcRefreshInterval'),
    max_claim_age_minutes: oidcNum('oidcMaxClaimAge'),
    clock_skew_seconds: oidcNum('oidcClockSkew'),
    require_idp: !!document.getElementById('oidcRequireIdp').checked,
    cookie_secure: document.getElementById('oidcCookieSecure').value,
  };
  // Only send the secret when one was typed. Absent means keep, which is what
  // makes every other field editable without re-entering a credential the
  // panel cannot display.
  const typed = secretEl ? secretEl.value.trim() : '';
  if (typed) body.client_secret = typed;

  apiMethod('PUT', '/api/config/oidc', body).then(d => {
    if (d && d.error) {
      oidcShowFieldError(d);
      return;
    }
    if (secretEl) secretEl.value = '';
    oidcState.view = d;
    oidcState.mappings = (d.role_mappings || []).map(m => Object.assign({}, m));
    renderOIDCSettings(d);
    toast(d.restart_required
      ? 'Saved — restart the hub to apply it'
      : 'Single sign-on settings saved', 'ok');
  }).catch(() => toast('Request failed', 'err'));
};

// oidcErrText pulls a human message out of either error shape the hub emits.
//
// jsonErr writes {"error": "..."} and apierror.WriteError writes
// {"error": {code, message, details}}. These routes use the second, but a
// middleware refusal on the way in — a body-size limit, a permission gate —
// can produce the first, and "[object Object]" is a worse thing to show an
// operator than either message.
function oidcErrText(d) {
  if (!d || !d.error) return 'Request failed';
  if (typeof d.error === 'string') return d.error;
  return d.error.message || 'Request failed';
}

// oidcErrField is the input the hub blamed, if it named one.
function oidcErrField(d) {
  if (!d || !d.error || typeof d.error === 'string') return '';
  return (d.error.details && d.error.details.field) || '';
}

// oidcShowFieldError puts a refusal beside the input that caused it.
//
// The backend names the field in the error details precisely so this can focus
// it: "issuer must be https" is actionable next to the issuer box and merely
// annoying in a toast.
function oidcShowFieldError(d) {
  const msg = oidcErrText(d);
  const note = document.getElementById('oidcStatusNote');
  if (note) {
    note.textContent = msg;
    note.style.color = 'var(--err,#f85149)';
  }
  const field = oidcErrField(d);
  const input = field ? document.getElementById(oidcFieldElementID(field)) : null;
  if (input) {
    input.focus();
    if (typeof input.scrollIntoView === 'function') {
      input.scrollIntoView({block: 'center', behavior: 'smooth'});
    }
  }
  toast(msg, 'err');
}

// oidcFieldElementID maps a config field name onto the input that edits it.
function oidcFieldElementID(field) {
  const map = {
    issuer: 'oidcIssuer',
    client_id: 'oidcClientId',
    client_secret: 'oidcClientSecret',
    redirect_url: 'oidcRedirectUrl',
    cookie_secure: 'oidcCookieSecure',
    admin_emails: 'oidcAdminEmails',
    default_role: 'oidcDefaultRole',
    max_claim_age_minutes: 'oidcMaxClaimAge',
    clock_skew_seconds: 'oidcClockSkew',
  };
  return map[field] || '';
}

window.oidcClearSecret = function() {
  if (!confirm('Remove the stored client secret? Sign-in will fail until a new one is set.')) return;
  apiMethod('PUT', '/api/config/oidc', {clear_client_secret: true}).then(d => {
    if (d && d.error) { toast(oidcErrText(d), 'err'); return; }
    oidcState.view = d;
    renderOIDCSettings(d);
    toast('Client secret removed', 'ok');
  }).catch(() => toast('Request failed', 'err'));
};

// oidcTestIssuer contacts the issuer currently in the box without saving it.
//
// Reachability is the one thing static validation cannot answer, and it is the
// most common thing to get wrong — a fat-fingered tenant id is a perfectly
// valid https URL that will fail every sign-in. Testing before saving turns
// that from an outage into a line of red text.
window.oidcTestIssuer = function() {
  const note = document.getElementById('oidcTestNote');
  const issuer = document.getElementById('oidcIssuer').value.trim();
  if (note) {
    note.style.color = 'var(--muted)';
    note.textContent = 'Contacting ' + (issuer || 'the saved issuer') + '…';
  }
  api('/api/config/oidc/test', {issuer: issuer}).then(d => {
    if (!note) return;
    if (!d || (d.error && !('ok' in d))) {
      note.style.color = 'var(--err,#f85149)';
      note.textContent = oidcErrText(d);
      return;
    }
    if (d.ok) {
      note.style.color = 'var(--ok,#3fb950)';
      const keys = d.result ? d.result.signing_keys : 0;
      note.textContent = 'Reached ' + d.issuer + ' — ' + keys + ' usable signing key(s).';
      return;
    }
    note.style.color = 'var(--err,#f85149)';
    note.textContent = d.error + (d.remediation ? ' — ' + d.remediation : '');
  }).catch(() => {
    if (note) {
      note.style.color = 'var(--err,#f85149)';
      note.textContent = 'Request failed';
    }
  });
};
