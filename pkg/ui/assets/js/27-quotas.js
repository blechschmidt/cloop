// ── The caller's own quota, and the Quotas panel's formatting (Task 20182) ───
//
// The Quotas tab itself is deferred/quotas.js, fetched on its first open
// (Task 20386). What stays in the bundle is the header badge below, which
// first paint can show, and the formatting it shares with the tab — handed to
// the panel through panelHelpers().quota rather than written twice.

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
