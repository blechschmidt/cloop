// ── Quotas panel (Task 20182) ───────────────────────────────────────────────
//
// Global and admin-only: the tab is hidden unless /api/me reports user.manage,
// and every write goes through PUT /api/quotas/{identity}, which is gated on
// the same permission server-side. Hiding the tab is a convenience — the gate
// is the route, and a tenant who forges the request gets the same 403.
//
// Editing is inline. A quota conversation is "give Alice two more projects",
// not "fill in this form", so each cell is a number input that commits on
// blur and the row shows what changed. An empty cell means "inherit from
// policy", which is different from 0 ("allowed none") — the placeholder shows
// the inherited value so the difference is visible rather than remembered.

const quotaState = {
  rows: [],
  resources: [],
  enabled: false,
  notice: '',
  dirty: {},        // identity -> {resource: value|null} pending commit
  saving: false,
};

// _quotaLabels are the column headers. Keyed by the wire name so a resource
// added server-side shows up with its raw name rather than disappearing.
const _quotaLabels = {
  max_projects: 'Projects',
  max_concurrent_tasks: 'Concurrent runs',
  max_executors: 'Executors',
  max_sessions: 'Sessions',
  daily_token_budget: 'Tokens / day',
  daily_cost_usd: 'USD / day',
};

function _quotaLabel(res) { return _quotaLabels[res] || res; }

// _quotaFmt renders a usage or limit. Money keeps two decimals; everything
// else is a count and should not read as "3.0 projects".
function _quotaFmt(res, v) {
  if (v === null || v === undefined) return '';
  if (res === 'daily_cost_usd') return Number(v).toFixed(2);
  if (res === 'daily_token_budget') return _quotaCompact(v);
  return String(Math.round(Number(v)));
}

function _quotaCompact(v) {
  const n = Number(v);
  if (!isFinite(n)) return '';
  if (n >= 1e9) return (n / 1e9).toFixed(1).replace(/\.0$/, '') + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'k';
  return String(Math.round(n));
}

// _quotaSaturation returns a 0..1 fill ratio, or null when unlimited.
function _quotaSaturation(limit, used) {
  if (limit === null || limit === undefined) return null;
  if (Number(limit) <= 0) return Number(used) > 0 ? 1 : 0;
  return Math.min(1, Number(used) / Number(limit));
}

function _quotaCellClass(ratio) {
  if (ratio === null) return '';
  if (ratio >= 1) return 'quota-full';
  if (ratio >= 0.8) return 'quota-warn';
  return '';
}

window.loadQuotas = function() {
  return api(pUrl('/api/quotas'))
    .then(d => {
      d = d || {};
      quotaState.rows = Array.isArray(d.quotas) ? d.quotas : [];
      quotaState.resources = Array.isArray(d.resources) ? d.resources : [];
      quotaState.enabled = !!d.enabled;
      quotaState.notice = d.notice || '';
      quotaState.dirty = {};
      _renderQuotas();
      return d;
    })
    .catch(err => {
      // 403 here is the expected answer for a non-admin, not a fault.
      const empty = document.getElementById('quotaEmpty');
      const table = document.getElementById('quotaTable');
      if (table) table.style.display = 'none';
      if (empty) {
        empty.style.display = '';
        const msg = (err && err.message) ? String(err.message) : String(err);
        empty.textContent = /forbidden|not permit|403/i.test(msg)
          ? 'Your role does not permit managing quotas. This panel requires the user.manage permission (admin).'
          : 'Could not load quotas: ' + msg;
      }
    });
};

function _renderQuotas() {
  const table  = document.getElementById('quotaTable');
  const head   = document.getElementById('quotaHead');
  const body   = document.getElementById('quotaBody');
  const empty  = document.getElementById('quotaEmpty');
  const banner = document.getElementById('quotaBanner');
  if (!table || !body || !head) return;

  if (banner) {
    if (quotaState.notice) {
      banner.style.display = '';
      banner.textContent = quotaState.notice;
    } else {
      banner.style.display = 'none';
    }
  }

  const resources = quotaState.resources.length ? quotaState.resources : Object.keys(_quotaLabels);

  if (!quotaState.rows.length) {
    table.style.display = 'none';
    if (empty) {
      empty.style.display = '';
      empty.textContent = quotaState.enabled
        ? 'No identities yet. Quotas appear here once somebody signs in or owns a project.'
        : 'No quota policy is configured and nobody has signed in yet.';
    }
    return;
  }
  if (empty) empty.style.display = 'none';
  table.style.display = '';

  head.innerHTML =
    '<tr><th style="min-width:200px">Identity</th>' +
    resources.map(r =>
      '<th style="width:130px" title="' + esc(_quotaLabel(r)) + ' (' + esc(r) + ')">' +
        esc(_quotaLabel(r)) + '</th>').join('') +
    '<th style="width:110px"></th></tr>';

  body.innerHTML = quotaState.rows.map((row, idx) => {
    const limits  = row.limits  || {};
    const usage   = row.usage   || {};
    const sources = row.sources || {};
    const cells = resources.map(res => {
      const limit = (res in limits) ? limits[res] : null;
      const used  = usage[res] || 0;
      const ratio = _quotaSaturation(limit, used);
      const src   = sources[res] || '';
      const title = limit === null
        ? 'Unlimited — no binding sets this resource'
        : 'Limit ' + _quotaFmt(res, limit) + ' from ' + (src || 'policy') +
          '; in use ' + _quotaFmt(res, used);
      return '<td class="quota-cell ' + _quotaCellClass(ratio) + '" title="' + esc(title) + '">' +
        '<input type="number" min="0" step="any" class="quota-input" ' +
          'data-identity-idx="' + idx + '" data-resource="' + esc(res) + '" ' +
          'value="' + (limit === null ? '' : esc(String(limit))) + '" ' +
          'placeholder="&#8734;" aria-label="' + esc(_quotaLabel(res) + ' limit for ' + row.identity) + '">' +
        '<span class="quota-used">' + esc(_quotaFmt(res, used)) +
          (limit === null ? '' : ' / ' + esc(_quotaFmt(res, limit))) + '</span>' +
      '</td>';
    }).join('');
    return '<tr>' +
      '<td class="quota-identity">' + esc(row.identity) +
        (row.overridden ? ' <span class="quota-badge" title="An admin has edited this identity">edited</span>' : '') +
      '</td>' + cells +
      '<td style="text-align:right">' +
        '<button class="btn" style="padding:3px 8px;font-size:11px" ' +
          'data-quota-save="' + idx + '" title="Save the edited limits for this identity">Save</button>' +
        (row.overridden
          ? ' <button class="btn" style="padding:3px 8px;font-size:11px" data-quota-reset="' + idx + '" ' +
            'title="Drop the override and return this identity to the configured policy">Reset</button>'
          : '') +
      '</td></tr>';
  }).join('');

  _quotaBindHandlers();
  applyPermissionGating(document.getElementById('tab-quotas'));
}

// Event delegation rather than inline onclick: the identity is
// user-influenced (an IdP releases the email), and interpolating it into an
// attribute is the exact bug that has broken this dashboard repeatedly. The
// row index is a number and the identity is looked up from state.
function _quotaBindHandlers() {
  const body = document.getElementById('quotaBody');
  if (!body || body._quotaBound) return;
  body._quotaBound = true;

  body.addEventListener('click', function(ev) {
    const saveBtn  = ev.target.closest('[data-quota-save]');
    const resetBtn = ev.target.closest('[data-quota-reset]');
    if (saveBtn)  { _quotaSaveRow(Number(saveBtn.getAttribute('data-quota-save'))); return; }
    if (resetBtn) { _quotaResetRow(Number(resetBtn.getAttribute('data-quota-reset'))); return; }
  });

  body.addEventListener('keydown', function(ev) {
    if (ev.key !== 'Enter') return;
    const input = ev.target.closest('.quota-input');
    if (!input) return;
    ev.preventDefault();
    _quotaSaveRow(Number(input.getAttribute('data-identity-idx')));
  });
}

// _quotaCollect reads one row's inputs. A blank field is null, which the API
// reads as "clear this override" — distinct from 0, which caps at none.
function _quotaCollect(idx) {
  const inputs = document.querySelectorAll('.quota-input[data-identity-idx="' + idx + '"]');
  const limits = {};
  let bad = null;
  inputs.forEach(input => {
    const res = input.getAttribute('data-resource');
    const raw = String(input.value || '').trim();
    if (raw === '') { limits[res] = null; return; }
    const n = Number(raw);
    if (!isFinite(n) || n < 0) { bad = _quotaLabel(res); return; }
    limits[res] = n;
  });
  return { limits, bad };
}

function _quotaSaveRow(idx) {
  const row = quotaState.rows[idx];
  if (!row || quotaState.saving) return;
  const collected = _quotaCollect(idx);
  if (collected.bad) {
    toast(collected.bad + ' must be a number of zero or more', 'error');
    return;
  }
  quotaState.saving = true;
  apiMethod('PUT', pUrl('/api/quotas/' + encodeURIComponent(row.identity)),
            { limits: collected.limits })
    .then(() => {
      toast('Quota updated for ' + row.identity, 'success');
      return loadQuotas();
    })
    .catch(err => toast('Could not update quota: ' + (err && err.message ? err.message : err), 'error'))
    .finally(() => { quotaState.saving = false; });
}

function _quotaResetRow(idx) {
  const row = quotaState.rows[idx];
  if (!row || quotaState.saving) return;
  if (!confirm('Drop the quota override for ' + row.identity + '?\n\n' +
               'They will fall back to the limits configured in ui.quotas.')) return;
  quotaState.saving = true;
  apiMethod('DELETE', pUrl('/api/quotas/' + encodeURIComponent(row.identity)))
    .then(() => {
      toast('Override cleared for ' + row.identity, 'success');
      return loadQuotas();
    })
    .catch(err => toast('Could not clear override: ' + (err && err.message ? err.message : err), 'error'))
    .finally(() => { quotaState.saving = false; });
}

// ── the caller's own quota ──────────────────────────────────────────────────
//
// Shown in the header when any of the caller's own limits is at or near its
// ceiling, so a refused run is explained before the user goes looking. It
// reads /api/quota/me, which is scoped to the caller by construction and
// therefore available to every role.

window.refreshMyQuota = function() {
  return api('/api/quota/me')
    .then(d => {
      const badge = document.getElementById('quotaSelfBadge');
      if (!badge) return d;
      const q = d && d.quota;
      if (!d || !d.enabled || !q) { badge.style.display = 'none'; return d; }

      const limits = q.limits || {}, usage = q.usage || {};
      let worst = null;
      Object.keys(limits).forEach(res => {
        const ratio = _quotaSaturation(limits[res], usage[res] || 0);
        if (ratio !== null && (worst === null || ratio > worst.ratio)) {
          worst = { res, ratio, limit: limits[res], used: usage[res] || 0 };
        }
      });
      if (!worst || worst.ratio < 0.8) { badge.style.display = 'none'; return d; }

      badge.style.display = '';
      badge.className = 'quota-self-badge ' + (worst.ratio >= 1 ? 'quota-full' : 'quota-warn');
      badge.textContent = _quotaLabel(worst.res) + ' ' +
        _quotaFmt(worst.res, worst.used) + '/' + _quotaFmt(worst.res, worst.limit);
      badge.title = worst.ratio >= 1
        ? 'You are at your ' + _quotaLabel(worst.res).toLowerCase() + ' quota. ' +
          'Further requests will be refused until it frees up or an administrator raises it.'
        : 'You are close to your ' + _quotaLabel(worst.res).toLowerCase() + ' quota.';
      return d;
    })
    .catch(() => { /* advisory only — never surface a failure to read a badge */ });
};
