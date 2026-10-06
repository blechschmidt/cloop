// ── Budget tab (Tasks 20002, 20016, 20131, 20229) ────────────────────────────
//
// Spend and rate limits, global and per project; the Claude Code login that
// the claudecode provider runs under and its subscription usage; the Anthropic
// API's own rate-limit headers; and what this project's .cloop directory costs
// on disk and what reclaims it.
//
// Fetched on the tab's first open since Task 20386 (static.go,
// deferredScripts), markup included: first paint has no room for a panel most
// sessions never open. Its pieces used to live in four bundle fragments
// (20-budget.js, 28-retention.js, and the Claude login and limit forms in
// 23-executors.js); they are one panel on screen, so they are one script here.
// It runs outside the dashboard's IIFE, so it is handed the helpers it calls,
// and the only name it puts on window is the factory.
(function () {
  'use strict';

  window.cloopBudgetPanel = function (h) {
    const {api, apiMethod, esc, toast, pUrl, canGlobal} = h;
    const _duFmtBytes = h.fmtBytes;

    // ── Budget tab ─────────────────────────────────────────────────
    let _budgetData = null;

    function loadBudget() {
      api(pUrl('/api/budget')).then(d => {
        _budgetData = d;
        _renderBudget(d);
      }).catch(err => {
        console.warn('budget load error', err);
      });
    }

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
    function loadClaudeUsage() {
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
    }

    function loadRateLimits() {
      api(pUrl('/api/ratelimits')).then(d => {
        _renderRateLimits(d);
      }).catch(err => {
        console.warn('ratelimits load error', err);
      });
    }


    function _rlBar(used, limit, pct) {
      const colour = pct >= 100 ? 'var(--red)' : (pct >= 80 ? '#f0a500' : 'var(--accent)');
      return '<div style="height:8px;background:var(--border);border-radius:4px;overflow:hidden;margin-top:4px">'
        +    '<div style="height:100%;width:' + pct + '%;background:' + colour + ';transition:width .4s ease"></div>'
        +  '</div>';
    }

    function _rlRow(label, w, fmt) {
      if (!w || !w.limit || w.limit <= 0) {
        return '<div style="margin:6px 0;font-size:12px;color:var(--muted)">' + label + ': <em>not reported</em></div>';
      }
      const used = w.used || 0;
      const lim  = w.limit;
      const pct  = w.pct || 0;
      const usedTxt = fmt ? fmt(used) : used;
      const limTxt  = fmt ? fmt(lim) : lim;
      let resetTxt = '';
      if (w.reset) {
        try {
          const dt = new Date(w.reset);
          if (!isNaN(dt.getTime())) {
            const diff = Math.max(0, Math.round((dt.getTime() - Date.now()) / 1000));
            if (diff > 0) {
              const mins = Math.floor(diff / 60);
              const secs = diff % 60;
              resetTxt = ' &nbsp;<span style="color:var(--muted);font-size:11px">resets in '
                + (mins > 0 ? (mins + 'm ') : '') + secs + 's</span>';
            }
          }
        } catch(_) {}
      }
      return '<div style="margin:8px 0">'
        +    '<div style="display:flex;justify-content:space-between;font-size:12px">'
        +      '<span>' + label + '</span>'
        +      '<span>' + usedTxt + ' / ' + limTxt + ' (' + pct + '%)' + resetTxt + '</span>'
        +    '</div>'
        +    _rlBar(used, lim, pct)
        +  '</div>';
    }

    function _renderRateLimits(d) {
      const empty = document.getElementById('rlEmpty');
      const list  = document.getElementById('rlList');
      if (!list) return;
      const models = (d && d.models) || [];
      if (models.length === 0) {
        if (empty) empty.style.display = '';
        list.innerHTML = '';
        return;
      }
      if (empty) empty.style.display = 'none';

      let html = '';
      models.forEach(m => {
        const updated = m.updated_at ? new Date(m.updated_at).toLocaleTimeString() : '—';
        const tier    = m.tier ? '<span style="display:inline-block;padding:2px 8px;background:var(--border);border-radius:10px;font-size:11px;margin-left:8px">tier: ' + m.tier + '</span>' : '';
        const spend   = (m.monthly_spend_usd && m.monthly_spend_usd > 0)
          ? '<span style="display:inline-block;padding:2px 8px;background:var(--border);border-radius:10px;font-size:11px;margin-left:8px">monthly spend cap: $' + Number(m.monthly_spend_usd).toFixed(2) + '</span>'
          : '';
        html += '<div style="border:1px solid var(--border);border-radius:var(--radius);padding:14px;margin-top:12px">';
        html += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">';
        html += '<div style="font-weight:600;font-size:13px"><code>' + (m.model || '?') + '</code>' + tier + spend + '</div>';
        html += '<div style="font-size:11px;color:var(--muted)">updated ' + updated + '</div>';
        html += '</div>';
        html += _rlRow('Requests / min (RPM)',         m.requests,      _fmtTokens);
        html += _rlRow('Input tokens / min (ITPM)',    m.input_tokens,  _fmtTokens);
        html += _rlRow('Output tokens / min (OTPM)',   m.output_tokens, _fmtTokens);
        if (m.tokens && m.tokens.limit > 0)            html += _rlRow('Tokens / min (legacy)',      m.tokens,        _fmtTokens);
        if (m.five_hour && m.five_hour.limit > 0)      html += _rlRow('5-hour rolling window',      m.five_hour,     _fmtTokens);
        if (m.weekly && m.weekly.limit > 0)            html += _rlRow('Weekly window',              m.weekly,        _fmtTokens);
        html += '</div>';
      });
      list.innerHTML = html;
    }

    function saveBudgetGlobal() {
      const payload = {
        daily_usd_limit:    parseFloat(document.getElementById('bgDailyUSD').value)    || 0,
        daily_token_limit:  parseInt(document.getElementById('bgDailyTokens').value)   || 0,
        alert_threshold_pct: parseInt(document.getElementById('bgAlertPct').value)     || 0,
      };
      _budgetSave('/api/budget/global', payload, 'budgetGlobalSaveMsg');
    }

    function saveBudgetProject() {
      const payload = {
        global_usd_pct:    parseFloat(document.getElementById('bpGlobalUSDPct').value)   || 0,
        global_token_pct:  parseFloat(document.getElementById('bpGlobalTokenPct').value) || 0,
        daily_usd_limit:   parseFloat(document.getElementById('bpDailyUSD').value)       || 0,
        daily_token_limit: parseInt(document.getElementById('bpDailyTokens').value)      || 0,
        monthly_usd:       parseFloat(document.getElementById('bpMonthlyUSD').value)     || 0,
        alert_threshold_pct: parseInt(document.getElementById('bpAlertPct').value)       || 0,
        max_weekly_pct: parseFloat(document.getElementById('bpMaxWeekly').value)   || 0,
        max_five_hour_pct: parseFloat(document.getElementById('bpMaxFiveHour').value) || 0,
        block_extra_usage: document.getElementById('bpBlockExtraUsage').checked,
      };
      _budgetSave('/api/budget/project', payload, 'budgetProjectSaveMsg');
    }


    // _budgetSave writes one of the two limit forms. Through apiMethod, not a raw
    // fetch: the one these saves used to make sent a TOKEN that is defined nowhere,
    // so both buttons threw a ReferenceError and saved nothing (Task 20386 found it
    // moving them here) — and it skipped parseAPIResponse, so a refusal was lost.
    function _budgetSave(path, payload, msgID) {
      return apiMethod('PUT', pUrl(path), payload).then(d => {
        if (d && d.error) { toast(d.error, 'err'); return; }
        const msg = document.getElementById(msgID);
        if (msg) { msg.style.display = ''; setTimeout(() => msg.style.display = 'none', 2000); }
        loadBudget();
      }).catch(err => toast('Save failed: ' + ((err && err.message) || err), 'err'));
    }

    // ── Claude Code authentication panel ───────────────────────────────────────
    function loadClaudeAuthStatus() {
      var panel = document.getElementById('ccAuthPanel');
      if (!panel) return;
      panel.innerHTML = '<div style="font-size:13px;color:var(--muted)">Checking login status...</div>';
      api('/api/claudecode/auth/status').then(function(d) {
        _renderClaudeAuth(d);
      }).catch(function(err) {
        panel.innerHTML = '<div style="font-size:13px;color:var(--red,#e74c3c)">Failed to load auth status: ' + esc(err && err.message || String(err)) + '</div>';
      });
    }

    function _renderClaudeAuth(d) {
      var panel = document.getElementById('ccAuthPanel');
      if (!panel) return;
      d = d || {};
      var status = d.status || {};
      var sess = d.session || {};
      var h = '';

      if (d.status_error) {
        h += '<div style="background:var(--surface-alt,#1a1a1a);border:1px solid var(--red,#e74c3c);border-radius:6px;padding:12px;margin-bottom:12px;font-size:12px;color:var(--red,#e74c3c)">';
        h += 'Status check failed: ' + esc(d.status_error);
        h += '</div>';
      }

      // With OIDC on, this panel shows the signed-in user's own Claude account.
      // Say so: otherwise a hub-wide settings page reads like a shared setting,
      // and a user cannot tell whether signing out affects their colleagues.
      if (d.per_user) {
        h += '<div style="background:var(--surface-alt,#1a1a1a);border:1px solid var(--border);border-radius:6px;padding:10px 12px;margin-bottom:12px;font-size:12px;color:var(--muted)">';
        h += 'This Claude Code login is yours alone. Other users of this hub sign in separately, your tasks run on your subscription, and signing out here does not sign anyone else out.';
        h += '</div>';
      }

      if (sess && sess.active && sess.url && !sess.done) {
        // In-flight login session: show URL + code input.
        h += '<div style="background:var(--surface-alt,#1a1a1a);border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:12px">';
        h += '<div style="font-size:13px;font-weight:600;margin-bottom:8px">Sign-in in progress</div>';
        h += '<ol style="font-size:13px;color:var(--muted);margin:0 0 10px 18px;padding:0;line-height:1.7">';
        h += '<li>Open this URL in your browser and sign in:</li>';
        h += '</ol>';
        h += '<div style="display:flex;gap:8px;margin-bottom:12px;align-items:center">';
        h += '<a href="' + esc(sess.url) + '" target="_blank" rel="noopener" style="font-size:12px;word-break:break-all;color:var(--link,#3a8bdc);flex:1;padding:6px 8px;background:var(--bg,#0d0d0d);border-radius:4px;border:1px solid var(--border)">' + esc(sess.url) + '</a>';
        h += '<button class="btn" type="button" data-act="copyClaudeAuthURL" style="font-size:12px;padding:6px 10px">Copy</button>';
        h += '</div>';
        h += '<ol start="2" style="font-size:13px;color:var(--muted);margin:0 0 10px 18px;padding:0;line-height:1.7">';
        h += '<li>Authorize the app, then paste the code shown:</li>';
        h += '</ol>';
        h += '<div style="display:flex;gap:8px;align-items:center">';
        h += '<input id="ccAuthCode" class="form-input" type="text" placeholder="Paste authorization code" style="flex:1;font-family:monospace">';
        h += '<button class="btn primary" type="button" data-act="submitClaudeAuthCode" style="white-space:nowrap">Sign in</button>';
        h += '<button class="btn" type="button" data-act="cancelClaudeAuthLogin">Cancel</button>';
        h += '</div>';
        h += '<div id="ccAuthMsg" style="font-size:12px;color:var(--muted);margin-top:8px;min-height:16px"></div>';
        h += '</div>';
      } else if (status.loggedIn) {
        // Already logged in: show identity + logout.
        h += '<div style="background:var(--surface-alt,#1a1a1a);border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:12px">';
        h += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">';
        h += '<span style="font-size:13px;font-weight:600;color:var(--green,#27ae60)">Signed in</span>';
        if (status.subscriptionType) {
          h += '<span style="font-size:11px;padding:2px 8px;border-radius:10px;background:var(--bg,#0d0d0d);border:1px solid var(--border);color:var(--muted)">' + esc(status.subscriptionType) + '</span>';
        }
        h += '</div>';
        h += '<table style="font-size:12px;color:var(--muted);width:100%;border-collapse:collapse">';
        function row(label, value) {
          if (!value) return;
          h += '<tr><td style="padding:2px 12px 2px 0;color:var(--muted)">' + esc(label) + '</td><td style="padding:2px 0;color:var(--fg,#eee);word-break:break-all">' + esc(value) + '</td></tr>';
        }
        row('Email', status.email);
        row('Auth method', status.authMethod);
        row('API provider', status.apiProvider);
        row('Organization', status.orgName || status.orgId);
        h += '</table>';
        h += '<div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">';
        h += '<button class="btn" type="button" data-act="claudeLogin">Re-authenticate</button>';
        h += '<button class="btn" type="button" data-act="logoutClaudeAuth">Sign out</button>';
        h += '</div>';
        h += '</div>';
      } else {
        // Not logged in.
        h += '<div style="background:var(--surface-alt,#1a1a1a);border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:12px">';
        h += '<div style="font-size:13px;color:var(--muted);margin-bottom:12px">Not signed in to Claude Code. Sign in to use the <code>claudecode</code> provider for task execution.</div>';
        h += '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">';
        h += '<button class="btn primary" type="button" data-act="claudeLogin">Sign in with Claude.ai</button>';
        h += '<button class="btn" type="button" data-act="claudeLogin" data-arg="console">Sign in with Anthropic Console</button>';
        h += '<button class="btn" type="button" data-act="claudeLogin" data-arg="sso">SSO login</button>';
        h += '</div>';
        h += '</div>';
      }

      if (sess && sess.done && sess.error) {
        h += '<div style="font-size:12px;color:var(--red,#e74c3c);margin-top:4px">Last attempt failed: ' + esc(sess.error) + '</div>';
      }
      panel.innerHTML = h;
    }

    // api()/apiMethod(), not fetch(): reaching for fetch() here is what skipped
    // parseAPIResponse, so 401/403 went unhandled and an apierror body rendered as
    // "[object Object]" (Task 20320).
    function startClaudeAuthLogin(opts) {
      var panel = document.getElementById('ccAuthPanel');
      if (panel) panel.innerHTML = '<div style="font-size:13px;color:var(--muted)">Launching <code>claude auth login</code>...</div>';
      api('/api/claudecode/auth/login', opts || {}).then(function(d) {
        if (d.error) {
          panel.innerHTML = '<div style="font-size:13px;color:var(--red,#e74c3c)">' + esc(d.error) + '</div><div style="margin-top:8px"><button class="btn" type="button" data-act="loadClaudeAuthStatus">Back</button></div>';
          return;
        }
        _renderClaudeAuth({session: d.session});
      }).catch(function(err) {
        // parseAPIResponse already showed 401/403; a bare code would say less.
        var m = (err && err.message) || String(err);
        if (m === '401' || m === 'FORBIDDEN') { loadClaudeAuthStatus(); return; }
        if (panel) panel.innerHTML = '<div style="font-size:13px;color:var(--red,#e74c3c)">' + esc(m) + '</div>';
      });
    }

    function submitClaudeAuthCode() {
      var input = document.getElementById('ccAuthCode');
      var msg = document.getElementById('ccAuthMsg');
      if (!input) return;
      var code = (input.value || '').trim();
      if (!code) {
        if (msg) msg.textContent = 'Paste the authorization code first.';
        return;
      }
      if (msg) msg.textContent = 'Submitting...';
      api('/api/claudecode/auth/login/code', {code: code}).then(function(d) {
        if (d.error) {
          if (msg) msg.textContent = d.error;
          return;
        }
        _renderClaudeAuth(d);
      }).catch(function(err) {
        var m = (err && err.message) || String(err);
        if (msg) msg.textContent = (m === '401' || m === 'FORBIDDEN') ? '' : m;
      });
    }

    function cancelClaudeAuthLogin() {
      apiMethod('POST', '/api/claudecode/auth/login/cancel').then(function() {
        loadClaudeAuthStatus();
      }).catch(function() { loadClaudeAuthStatus(); });
    }

    function logoutClaudeAuth() {
      if (!confirm('Sign out of Claude Code? You will need to sign in again to use the claudecode provider.')) return;
      apiMethod('POST', '/api/claudecode/auth/logout').then(function(d) {
        if (d.error) toast('Logout failed: ' + d.error, 'err');
        loadClaudeAuthStatus();
      }).catch(function() { loadClaudeAuthStatus(); });
    }

    function copyClaudeAuthURL() {
      var link = document.querySelector('#ccAuthPanel a[target="_blank"]');
      if (!link) return;
      var url = link.href;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url);
      } else {
        var ta = document.createElement('textarea');
        ta.value = url; document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); } catch(_) {}
        document.body.removeChild(ta);
      }
      var msg = document.getElementById('ccAuthMsg');
      if (msg) { msg.textContent = 'URL copied to clipboard.'; setTimeout(function(){ if(msg.textContent==='URL copied to clipboard.') msg.textContent=''; }, 2000); }
    }


    // ── Disk & Retention panel (Task 20229) ─────────────────────────────────────
    //
    // Answers the question nothing in cloop could previously answer: where is this
    // project's disk going, and is anything going to reclaim it.
    //
    // Two of the three numbers here are invisible to every other tool an operator
    // has. `du` cannot see SQLite's freelist — the hub this was built on had a
    // 2.3 GB state.db that was 87% dead pages — and nobody counts files in
    // .cloop/plan-history until it is already 2 GB across four thousand of them.
    // So the panel leads with the breakdown and the reclaimable estimate, then
    // says what the janitor will do about it and when, because "87% reclaimable"
    // means something very different depending on whether a pass runs tonight.
    //
    // Read-only by design. Changing retention means editing config, which the rest
    // of this tab already does; a second way to write the same keys would be a
    // second thing to keep in sync.

    // _duFmtAgo renders an RFC3339 instant as a relative time. Past and future
    // both occur here: last_run is behind us, next_due ahead.
    function _duFmtAgo(iso) {
      if (!iso) return '—';
      const then = new Date(iso).getTime();
      if (isNaN(then)) return '—';
      const secs = Math.round((Date.now() - then) / 1000);
      const ahead = secs < 0;
      let n = Math.abs(secs), unit = 's';
      if (n >= 86400) { n = Math.round(n / 86400); unit = 'd'; }
      else if (n >= 3600) { n = Math.round(n / 3600); unit = 'h'; }
      else if (n >= 60) { n = Math.round(n / 60); unit = 'm'; }
      return ahead ? ('in ' + n + unit) : (n + unit + ' ago');
    }

    // _duAdvice is the one-line "what governs this" note per entry. The breakdown
    // is only actionable if each row says which knob controls it.
    const _duAdvice = {
      'plan-history': 'bounded by retention.keep_snapshots',
      'audit-archive': 'sealed audit exports — retention limits are off by default',
      'state.db': 'reclaimed by VACUUM; see the freelist figure',
      'state.db-wal': 'write-ahead log, folded into state.db at the next checkpoint',
      'tasks': 'task artifacts — bounded by cloop compact',
      'artifacts': 'live task output — bounded by cloop compact',
      'task-checkpoints': 'resume points — bounded by cloop compact',
    };

    function loadDiskUsage() {
      // The hub's free-space floor (Task 20381), for those who may set it.
      if (canGlobal('user.manage')) {
        h.panel('diskfloor', {api, apiMethod, esc, toast, fmt: _duFmtBytes})
          .then(p => p.load()).catch(() => {});
      }
      return api(pUrl('/api/disk-usage'))
        .then(d => { _renderDiskUsage(d || {}); return d; })
        .catch(err => {
          const el = document.getElementById('diskUsageBody');
          if (el) {
            el.innerHTML = '<div class="empty-state"><p>Could not load disk usage: ' +
              esc(err && err.message ? err.message : String(err)) + '</p></div>';
          }
        });
    }

    function _renderDiskUsage(d) {
      const el = document.getElementById('diskUsageBody');
      if (!el) return;

      const entries = Array.isArray(d.entries) ? d.entries : [];
      const pol = d.policy || {};
      const total = d.total_bytes || 0;

      let html = '';

      // Headline: total, and the part of it that is not really data.
      html += '<div class="du-headline">';
      html += '<div class="du-stat"><div class="du-stat-val">' + _duFmtBytes(total) +
              '</div><div class="du-stat-label">.cloop total</div></div>';

      if (d.db_error) {
        html += '<div class="du-stat"><div class="du-stat-val">—</div>' +
                '<div class="du-stat-label">reclaimable (' + esc(d.db_error) + ')</div></div>';
      } else if (d.db_bytes) {
        const pct = Math.round((d.free_ratio || 0) * 100);
        const warn = d.free_ratio >= (pol.vacuum_free_ratio || 0.3);
        html += '<div class="du-stat"><div class="du-stat-val' + (warn ? ' du-warn' : '') + '">' +
                _duFmtBytes(d.reclaimable_bytes || 0) + '</div>' +
                '<div class="du-stat-label">reclaimable by VACUUM (' + pct + '% of state.db)</div></div>';
      }
      html += '</div>';

      // Per-entry breakdown, largest first (the server sorts it).
      if (!entries.length) {
        html += '<div class="empty-state"><p>Nothing in .cloop yet.</p></div>';
      } else {
        html += '<table class="audit-table du-table"><thead><tr>' +
                '<th>Entry</th><th class="du-num">Size</th><th class="du-num">Files</th><th>Retention</th>' +
                '</tr></thead><tbody>';
        for (const e of entries) {
          const share = total > 0 ? (e.bytes / total) * 100 : 0;
          html += '<tr>' +
            '<td><span class="du-bar" style="width:' + Math.max(2, Math.round(share)) + '%"></span>' +
            esc(e.name) + '</td>' +
            '<td class="du-num">' + _duFmtBytes(e.bytes) + '</td>' +
            '<td class="du-num">' + (e.is_dir ? e.files : '') + '</td>' +
            '<td class="du-note">' + esc(_duAdvice[e.name] || '') + '</td>' +
            '</tr>';
        }
        html += '</tbody></table>';
      }

      // What the janitor will do, and when.
      html += '<div class="du-policy">';
      if (!pol.enabled) {
        html += '<strong class="du-warn">Retention is disabled.</strong> Nothing reclaims this ' +
                'directory automatically — it grows until the disk fills. Remove ' +
                '<code>retention.enabled: false</code> from .cloop/config.yaml to re-enable it.';
      } else {
        html += '<strong>Retention is on.</strong> A pass runs every ' +
                (pol.interval_hours || 24) + 'h, keeping the newest ' +
                (pol.keep_snapshots || 0) + ' plan snapshots and vacuuming once the freelist ' +
                'passes ' + Math.round((pol.vacuum_free_ratio || 0.3) * 100) + '% of the database.';
        if (pol.archive_max_bytes || pol.archive_max_age_days) {
          html += ' Audit seals are capped at ' +
                  (pol.archive_max_bytes ? _duFmtBytes(pol.archive_max_bytes) : 'no size limit') +
                  (pol.archive_max_age_days ? ' / ' + pol.archive_max_age_days + ' days' : '') + '.';
        } else {
          html += ' Audit seals are kept indefinitely (each is the only copy of the rows it holds).';
        }
        html += '<br><span class="du-note">Last pass: ' + _duFmtAgo(d.last_run) +
                ' · Next due: ' + _duFmtAgo(d.next_due);
        if (d.will_vacuum) {
          html += ' · <strong>the next pass will VACUUM</strong>';
        }
        html += '</span>';
      }
      html += '</div>';

      el.innerHTML = html;
    }

    // open runs on every visit to the tab. Disk & Retention used to load only
    // when Settings was opened, which left it saying "Loading..." here.
    function open() {
      loadBudget(); loadClaudeUsage(); loadRateLimits(); loadClaudeAuthStatus(); loadDiskUsage();
    }
    // The three sign-in buttons: Claude.ai, the Anthropic Console, or SSO.
    function claudeLogin(kind) { return startClaudeAuthLogin(kind ? {[kind]: true} : {}); }

    return h.mount({
      open, claudeLogin, loadBudget, loadClaudeUsage, loadRateLimits, saveBudgetGlobal,
      saveBudgetProject, loadClaudeAuthStatus, startClaudeAuthLogin, submitClaudeAuthCode,
      cancelClaudeAuthLogin, logoutClaudeAuth, copyClaudeAuthURL, loadDiskUsage
    }, 'budget', `
      <div class="section">
        <div class="section-title" style="display:flex;align-items:center;gap:12px">
          Global Budget
          <button class="btn" style="padding:4px 10px;font-size:12px;margin-left:auto" data-act="loadBudget">&#8635; Refresh</button>
        </div>

        <div id="budgetUsageBars" style="margin-top:12px">
          <div style="margin-bottom:14px">
            <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
              <span>Daily USD Spend</span>
              <span id="budgetUSDLabel" style="color:var(--muted)">—</span>
            </div>
            <div style="height:10px;background:var(--border);border-radius:5px;overflow:hidden">
              <div id="budgetUSDBar" style="height:100%;width:0%;background:var(--accent);border-radius:5px;transition:width .4s ease"></div>
            </div>
          </div>
          <div>
            <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
              <span>Daily Token Usage</span>
              <span id="budgetTokenLabel" style="color:var(--muted)">—</span>
            </div>
            <div style="height:10px;background:var(--border);border-radius:5px;overflow:hidden">
              <div id="budgetTokenBar" style="height:100%;width:0%;background:var(--cyan);border-radius:5px;transition:width .4s ease"></div>
            </div>
          </div>
        </div>

        <div class="settings-section" style="margin-top:20px">
          <h3>Global Limits (applied across all projects)</h3>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Daily USD limit (0 = unlimited)</label>
              <input class="form-input" id="bgDailyUSD" type="number" min="0" step="0.01" placeholder="e.g. 5.00">
            </div>
            <div class="form-group">
              <label class="form-label">Daily token limit (0 = unlimited)</label>
              <input class="form-input" id="bgDailyTokens" type="number" min="0" placeholder="e.g. 1000000">
            </div>
            <div class="form-group">
              <label class="form-label">Alert threshold %</label>
              <input class="form-input" id="bgAlertPct" type="number" min="1" max="100" placeholder="80">
            </div>
          </div>
          <button class="btn primary" data-act="saveBudgetGlobal">Save Global Limits</button>
          <span id="budgetGlobalSaveMsg" style="font-size:12px;color:var(--green);margin-left:12px;display:none">Saved!</span>
        </div>
      </div>

      <div class="section">
        <div class="section-title">Per-Project Caps</div>
        <p style="font-size:12px;color:var(--muted);margin-bottom:12px">
          Set percentage-based caps relative to the global limits, or absolute per-project limits.
          Effective limits are resolved at runtime and shown below.
        </p>

        <div class="settings-section">
          <h3>Percentage Caps (% of global limit)</h3>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Global USD % (0 = no cap)</label>
              <input class="form-input" id="bpGlobalUSDPct" type="number" min="0" max="100" step="0.1" placeholder="e.g. 50">
            </div>
            <div class="form-group">
              <label class="form-label">Global Token % (0 = no cap)</label>
              <input class="form-input" id="bpGlobalTokenPct" type="number" min="0" max="100" step="0.1" placeholder="e.g. 50">
            </div>
          </div>

          <h3 style="margin-top:14px">Absolute Per-Project Limits</h3>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Daily USD limit (0 = unlimited)</label>
              <input class="form-input" id="bpDailyUSD" type="number" min="0" step="0.01" placeholder="e.g. 2.00">
            </div>
            <div class="form-group">
              <label class="form-label">Daily token limit (0 = unlimited)</label>
              <input class="form-input" id="bpDailyTokens" type="number" min="0" placeholder="e.g. 500000">
            </div>
            <div class="form-group">
              <label class="form-label">Monthly USD limit (0 = unlimited)</label>
              <input class="form-input" id="bpMonthlyUSD" type="number" min="0" step="0.01" placeholder="e.g. 50.00">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Alert threshold % (0 = use global)</label>
              <input class="form-input" id="bpAlertPct" type="number" min="0" max="100" placeholder="80">
            </div>
          </div>
          <h4 style="margin-top:16px;margin-bottom:8px">Claude Code Subscription Caps</h4>
          <p style="font-size:12px;color:var(--muted);margin-bottom:8px">Stop task execution when Claude Code subscription usage exceeds these percentages. Shared with the &quot;Set Caps&quot; modal on the project overview.</p>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Max weekly usage % (0 = no cap)</label>
              <input class="form-input" id="bpMaxWeekly" type="number" min="0" max="100" placeholder="e.g. 30">
            </div>
            <div class="form-group">
              <label class="form-label">Max 5-hour usage % (0 = no cap)</label>
              <input class="form-input" id="bpMaxFiveHour" type="number" min="0" max="100" placeholder="e.g. 80">
            </div>
          </div>

          <div class="form-row" style="margin-top:12px">
            <div class="form-group">
              <label class="form-label" style="display:flex;align-items:center;gap:8px">
                <input type="checkbox" id="bpBlockExtraUsage" checked>
                Block extra usage (prevent per-token billing beyond subscription)
              </label>
            </div>
          </div>

          <button class="btn primary" data-act="saveBudgetProject">Save Project Limits</button>
          <span id="budgetProjectSaveMsg" style="font-size:12px;color:var(--green);margin-left:12px;display:none">Saved!</span>
        </div>

        <div class="settings-section" id="budgetEffectiveSection" style="display:none">
          <h3>Effective Resolved Limits</h3>
          <p style="font-size:12px;color:var(--muted);margin-bottom:8px">
            These are the actual limits that will be enforced for this project today.
          </p>
          <table style="width:100%;font-size:13px;border-collapse:collapse">
            <thead>
              <tr style="border-bottom:1px solid var(--border)">
                <th style="text-align:left;padding:6px 0;color:var(--muted);font-weight:500">Dimension</th>
                <th style="text-align:right;padding:6px 0;color:var(--muted);font-weight:500">Effective Limit</th>
                <th style="text-align:right;padding:6px 0;color:var(--muted);font-weight:500">Today's Usage</th>
              </tr>
            </thead>
            <tbody id="budgetEffectiveBody"></tbody>
          </table>
        </div>
      </div>

      <div class="section">
        <div class="section-title" style="display:flex;align-items:center;gap:12px">
          Disk &amp; Retention
          <button class="btn" style="padding:4px 10px;font-size:12px;margin-left:auto" data-act="loadDiskUsage">&#8635; Refresh</button>
        </div>
        <p style="font-size:12px;color:var(--muted);margin-top:6px;margin-bottom:12px">
          What this project's <code>.cloop</code> directory costs, and what reclaims it. The
          reclaimable figure is SQLite free pages — space the database holds but no longer
          uses, which <code>du</code> cannot see.
        </p>
        <div id="diskUsageBody">
          <div style="font-size:13px;color:var(--muted)">Loading...</div>
        </div>
        <div id="diskFloorBody" data-global-perm="user.manage" data-perm-hide style="margin-top:12px"></div>
      </div>

      <div class="section">
        <div class="section-title" style="display:flex;align-items:center;gap:12px">
          Claude Code Authentication
          <button class="btn" style="padding:4px 10px;font-size:12px;margin-left:auto" data-act="loadClaudeAuthStatus">&#8635; Refresh</button>
        </div>
        <p style="font-size:12px;color:var(--muted);margin-top:6px;margin-bottom:12px">
          Manage the local <code>claude</code> CLI login that the claudecode provider uses for task execution.
        </p>
        <div id="ccAuthPanel" style="margin-top:8px">
          <div style="font-size:13px;color:var(--muted)">Loading...</div>
        </div>
      </div>

      <div class="section">
        <div class="section-title" style="display:flex;align-items:center;gap:12px">
          Claude Code Subscription Usage
          <button class="btn" style="padding:4px 10px;font-size:12px;margin-left:auto" data-act="loadClaudeUsage">&#8635; Refresh</button>
        </div>
        <div id="claudeUsagePanel" style="margin-top:8px">
          <div style="font-size:13px;color:var(--muted)">Loading...</div>
        </div>
      </div>

      <div class="section">
        <div class="section-title" style="display:flex;align-items:center;gap:12px">
          Anthropic API Rate Limits
          <button class="btn" style="padding:4px 10px;font-size:12px;margin-left:auto" data-act="loadRateLimits">&#8635; Refresh</button>
        </div>
        <p style="font-size:12px;color:var(--muted);margin-top:6px;margin-bottom:12px">
          Per-model limits captured from <code>anthropic-ratelimit-*</code> response headers.
          Values update on every Anthropic API call. Tier and monthly spend limit (when exposed
          by the API) are shown alongside per-model RPM, ITPM, OTPM, and any 5-hour / weekly windows.
        </p>
        <div id="rlEmpty" style="font-size:13px;color:var(--muted)">
          No Anthropic rate-limit data captured yet. Make a call with the anthropic provider to populate this panel.
        </div>
        <div id="rlList"></div>
      </div>`);
  };
})();
