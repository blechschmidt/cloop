// ── Budget tab ─────────────────────────────────────────────────
let _budgetData = null;

window.loadBudget = function() {
  api(pUrl('/api/budget')).then(d => {
    _budgetData = d;
    _renderBudget(d);
  }).catch(err => {
    console.warn('budget load error', err);
  });
};

function _fmtUSD(v) {
  if (!v && v !== 0) return '—';
  return '$' + Number(v).toFixed(4);
}
function _fmtTokens(v) {
  if (!v && v !== 0) return '—';
  if (v >= 1e6) return (v / 1e6).toFixed(2) + 'M';
  if (v >= 1e3) return (v / 1e3).toFixed(1) + 'K';
  return String(v);
}
function _budgetBarPct(used, limit) {
  if (!limit || limit <= 0) return 0;
  return Math.min(100, Math.round(used * 100 / limit));
}
function _barColor(pct, alertPct) {
  if (pct >= 100) return 'var(--red)';
  if (pct >= (alertPct || 80)) return '#f0a500';
  return null; // use default CSS var
}

function _renderBudget(d) {
  if (!d) return;
  const global  = d.global  || {};
  const usage   = d.usage   || {};
  const project = d.project || {};
  const eff     = d.effective || {};

  const alertPct = global.alert_threshold_pct || project.alert_threshold_pct || 80;

  // ── USD bar ──
  const usdLimit = global.daily_usd_limit || 0;
  const usdUsed  = usage.total_usd || 0;
  const usdPct   = _budgetBarPct(usdUsed, usdLimit);
  const usdBar   = document.getElementById('budgetUSDBar');
  const usdLabel = document.getElementById('budgetUSDLabel');
  if (usdBar) {
    usdBar.style.width = usdPct + '%';
    const col = _barColor(usdPct, alertPct);
    if (col) usdBar.style.background = col;
  }
  if (usdLabel) {
    if (usdLimit > 0)
      usdLabel.textContent = _fmtUSD(usdUsed) + ' / ' + _fmtUSD(usdLimit) + ' (' + usdPct + '%)';
    else
      usdLabel.textContent = _fmtUSD(usdUsed) + ' (no limit set)';
  }

  // ── Token bar ──
  const tokLimit = global.daily_token_limit || 0;
  const tokUsed  = usage.total_tokens || 0;
  const tokPct   = _budgetBarPct(tokUsed, tokLimit);
  const tokBar   = document.getElementById('budgetTokenBar');
  const tokLabel = document.getElementById('budgetTokenLabel');
  if (tokBar) {
    tokBar.style.width = tokPct + '%';
    const col = _barColor(tokPct, alertPct);
    if (col) { tokBar.style.background = col; }
  }
  if (tokLabel) {
    if (tokLimit > 0)
      tokLabel.textContent = _fmtTokens(tokUsed) + ' / ' + _fmtTokens(tokLimit) + ' (' + tokPct + '%)';
    else
      tokLabel.textContent = _fmtTokens(tokUsed) + ' (no limit set)';
  }

  // ── Populate global config inputs ──
  _setVal('bgDailyUSD',    global.daily_usd_limit   || '');
  _setVal('bgDailyTokens', global.daily_token_limit || '');
  _setVal('bgAlertPct',    global.alert_threshold_pct || '');

  // ── Populate project config inputs ──
  _setVal('bpGlobalUSDPct',   project.global_usd_pct    || '');
  _setVal('bpGlobalTokenPct', project.global_token_pct  || '');
  _setVal('bpDailyUSD',       project.daily_usd_limit   || '');
  _setVal('bpDailyTokens',    project.daily_token_limit || '');
  _setVal('bpMonthlyUSD',     project.monthly_usd       || '');
  _setVal('bpAlertPct',       project.alert_threshold_pct || '');
  _setVal('bpMaxWeekly',      project.max_weekly_pct || '');
  _setVal('bpMaxFiveHour',    project.max_five_hour_pct || '');
  const beuEl = document.getElementById('bpBlockExtraUsage');
  if (beuEl) beuEl.checked = project.block_extra_usage !== false;

  // ── Effective limits table ──
  const effSection = document.getElementById('budgetEffectiveSection');
  const effBody    = document.getElementById('budgetEffectiveBody');
  if (effBody) {
    const rows = [
      { label: 'Daily USD',    eff: eff.daily_usd_limit,   used: usdUsed },
      { label: 'Daily Tokens', eff: eff.daily_token_limit, used: tokUsed },
    ];
    let html = '';
    rows.forEach(row => {
      const hasLimit = row.eff && row.eff > 0;
      const effText  = hasLimit
        ? (row.label.includes('USD') ? _fmtUSD(row.eff) : _fmtTokens(row.eff))
        : '<span style="color:var(--muted)">no cap</span>';
      const usedText = row.label.includes('USD') ? _fmtUSD(row.used) : _fmtTokens(row.used);
      const pct2     = hasLimit ? _budgetBarPct(row.used, row.eff) : 0;
      const pctText  = hasLimit ? ' (' + pct2 + '%)' : '';
      html += '<tr style="border-bottom:1px solid var(--border)">';
      html += '<td style="padding:6px 0;font-size:12px">' + row.label + '</td>';
      html += '<td style="padding:6px 0;font-size:12px;text-align:right">' + effText + '</td>';
      html += '<td style="padding:6px 0;font-size:12px;text-align:right">' + usedText + pctText + '</td>';
      html += '</tr>';
    });
    effBody.innerHTML = html;
    if (effSection) effSection.style.display = '';
  }
}

function _setVal(id, v) {
  const el = document.getElementById(id);
  if (el) el.value = (v === null || v === undefined) ? '' : v;
}

// ── Anthropic rate-limits panel ──────────────────────────────────────────────
// ── Claude Code subscription usage ──────────────────────────────────────────
window.loadClaudeUsage = function() {
  var panel = document.getElementById('claudeUsagePanel');
  if (!panel) return;
  panel.innerHTML = '<div style="font-size:13px;color:var(--muted)">Loading usage data...</div>';
  api(pUrl('/api/claude-usage')).then(function(d) {
    if (d.error) {
      panel.innerHTML = '<div style="font-size:13px;color:var(--muted)">' + esc(d.error) + '</div>';
      return;
    }
    var fetched = d.fetched_at ? new Date(d.fetched_at).toLocaleTimeString() : '';
    var h = '<div style="display:flex;flex-direction:column;gap:12px">';
    function addBar(label, win) {
      if (!win) return;
      var pct = Math.round(win.utilization || 0);
      var color = pct >= 80 ? '#e74c3c' : pct >= 50 ? '#f39c12' : '#27ae60';
      var resetStr = '';
      if (win.resets_at) {
        try { var rd = new Date(win.resets_at); resetStr = 'Resets ' + rd.toLocaleString(); } catch(e) {}
      }
      h += '<div>';
      h += '<div style="display:flex;justify-content:space-between;margin-bottom:3px">';
      h += '<span style="font-size:13px;font-weight:600">' + label + '</span>';
      h += '<span style="font-size:13px;font-weight:700;color:' + color + '">' + pct + '%</span>';
      h += '</div>';
      h += '<div style="background:var(--border,#333);border-radius:4px;height:10px;overflow:hidden">';
      h += '<div style="background:' + color + ';height:100%;width:' + pct + '%;border-radius:4px;transition:width 0.3s"></div>';
      h += '</div>';
      if (resetStr) h += '<div style="font-size:11px;color:var(--muted);margin-top:2px">' + esc(resetStr) + '</div>';
      h += '</div>';
    }
    addBar('5-Hour Window', d.five_hour);
    addBar('Weekly (All Models)', d.seven_day);
    addBar('Weekly Opus', d.seven_day_opus);
    addBar('Weekly Sonnet', d.seven_day_sonnet);
    if (d.extra_usage && d.extra_usage.is_enabled) {
      var eu = d.extra_usage;
      var euPct = Math.round(eu.utilization || 0);
      var euColor = euPct >= 80 ? '#e74c3c' : euPct >= 50 ? '#f39c12' : '#27ae60';
      var euLimit = (eu.monthly_limit || 0) / 100;
      var euUsed = (eu.used_credits || 0) / 100;
      var euCurrency = eu.currency || 'USD';
      var sym = euCurrency === 'EUR' ? '\u20ac' : '$';
      h += '<div>';
      h += '<div style="display:flex;justify-content:space-between;margin-bottom:3px">';
      h += '<span style="font-size:13px;font-weight:600">Extra Usage (Monthly)</span>';
      h += '<span style="font-size:13px;font-weight:700;color:' + euColor + '">' + sym + euUsed.toFixed(2) + ' / ' + sym + euLimit.toFixed(2) + ' (' + euPct + '%)</span>';
      h += '</div>';
      h += '<div style="background:var(--border,#333);border-radius:4px;height:10px;overflow:hidden">';
      h += '<div style="background:' + euColor + ';height:100%;width:' + euPct + '%;border-radius:4px;transition:width 0.3s"></div>';
      h += '</div></div>';
    }
    if (fetched) h += '<div style="font-size:11px;color:var(--muted);margin-top:4px">Updated ' + esc(fetched) + '</div>';
    h += '</div>';
    panel.innerHTML = h;
  }).catch(function(err) {
    panel.innerHTML = '<div style="font-size:13px;color:var(--muted)">Failed to load usage data</div>';
  });
};

window.loadRateLimits = function() {
  api(pUrl('/api/ratelimits')).then(d => {
    _renderRateLimits(d);
  }).catch(err => {
    console.warn('ratelimits load error', err);
  });
};

