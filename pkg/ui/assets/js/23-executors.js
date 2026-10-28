// ── Executors (Task 20160) ──────────────────────────────────────────────────
//
// What first paint draws from the fleet: the Overview's executor card and its
// picker, and the Claude Code caps. The Executors tab itself — the cards, the
// auto-upgrade bar, the forwarders — is deferred/executors.js since Task 20456.
//
// The fleet is global: executors are shared infrastructure, not project state.
// It still calls pUrl() because the backend enriches the response with the
// *selected* project's binding, which is what powers the Overview card and
// the picker's "currently bound" preselection.
let execData = null;

act('loadExecutors', function() {
  // The fleet is not a project's to read: a member whose only role is on a
  // shared project would draw a refusal on every Overview (Task 20366).
  if (!canGlobal('executor.read')) return Promise.resolve(null);
  return api(pUrl('/api/executors')).then(d => {
    execData = d || {};
    // The Executors tab's list is deferred/executors.js (Task 20456): drawn
    // where that tab has been opened, read afresh by its open() where not.
    panelIf('executors', 'render', execData);
    _renderExecutorCard(execData);
    // The project's firewall card shows its executor's rules, so it moves with
    // every fleet change the Overview hears about (Task 20363).
    // And the Claude credential card, which exists only on an isolating
    // executor (Task 20379).
    if (activeTab === 'overview') { loadProjectFirewall(); loadHarnessCred(); }
    return execData;
  }).catch(err => {
    console.warn('executors load error', err);
    const list = document.getElementById('execList');
    if (list) {
      list.innerHTML = '<div style="font-size:13px;color:var(--red)">Failed to load executors: '
        + esc(err && err.message || String(err)) + '</div>';
    }
  });
});


function _execKindLabel(kind) {
  if (kind === 'localprocess') return 'host';
  if (kind === 'container') return 'container';
  if (kind === 'remote') return 'remote';
  return kind || 'unknown';
}

// The Executors tab's buttons that open a dialog of deferred/execadmin.js
// without naming a card (Tasks 20386, 20408).
ACTIONS.openEnrollModal      = () => panelAct('execadmin', 'openEnrollModal');

// Device forwarders (Task 20429) render in their own section of this tab; their
// card buttons dispatch through the same deferred panel as the executor ones.
const fwdAct = fn => function() { panelAct('execadmin', fn, +this.dataset.arg); };
ACTIONS.loadForwarders      = () => panelAct('execadmin', 'loadForwarders');
ACTIONS.openForwarderEnroll = () => panelAct('execadmin', 'openForwarderEnroll');
ACTIONS.forwarderRevoke     = fwdAct('forwarderRevoke');
ACTIONS.forwarderExpose     = fwdAct('forwarderExpose');
ACTIONS.forwarderBind       = fwdAct('forwarderBind');
ACTIONS.forwarderUnbind     = fwdAct('forwarderUnbind');

// _execAt resolves a card index to its executor, or null. Indices, never
// names: an executor name or an operator-typed reason in markup is the bug
// class of Tasks 163/20033.
function _execAt(idx) {
  return (execData && execData.executors && execData.executors[idx]) || null;
}


// _execDetailErrText pulls a sentence out of whatever the failure arrived as:
// a structured API error body, a bare string, or a rejected promise.
function _execDetailErrText(e) {
  if (!e) return '';
  if (typeof e === 'string') return e;
  if (e.message) return e.message;
  if (e.error) return _execDetailErrText(e.error);
  return String(e);
}

// ── Per-project executor selection ──────────────────────────────────────────
function _renderExecutorCard(d) {
  const valueEl = document.getElementById('statExecutor');
  const subEl = document.getElementById('statExecutorSub');
  const card = document.getElementById('executorCard');
  if (!valueEl || !subEl) return;

  const proj = (d && d.project) || null;
  if (!proj) {
    valueEl.textContent = '—';
    subEl.textContent = '';
    return;
  }
  const id = proj.effective_id || proj.executor_id || '';
  const byId = {};
  ((d && d.executors) || []).forEach(ex => { byId[ex.id] = ex; });
  const ex = byId[id];

  valueEl.textContent = ex ? (ex.name || id) : (id || 'none');
  if (proj.blocked) {
    valueEl.style.color = 'var(--red)';
    subEl.textContent = 'blocked by policy';
  } else {
    valueEl.style.color = '';
    const kind = ex ? _execKindLabel(ex.kind) : '';
    subEl.textContent = (proj.bound ? 'pinned' : 'default') + (kind ? ' · ' + kind : '');
  }
  if (card) {
    card.title = proj.blocked
      ? (proj.blocked_reason || 'This project cannot run: its executor is blocked by policy.')
      : 'Click to change where this project’s harness runs';
  }
}

// The project's execution target, chosen in deferred/execpicker.js (Task
// 20456): fetched on the first press of the card.
act('openExecutorPickerModal', function() {
  // A feature runs where its project runs (Task 20341).
  if (isFeatureSelected()) { toast('A feature runs on its project\'s executor — change it on the project', 'err'); return; }
  panelAct('execpicker', 'open');
});

// ── Claude Code per-project caps (overview panel) ──────────────────────────
//
// This panel used to reload from render(), which runs on every state diff —
// ~1 request/second during a run (Task 20326). Nothing here moves that fast:
// caps change only on save, and the server serves usage from a cache floored
// at ratelimit.MinUsageCacheTTL. The surplus requests bought nothing and cost
// two things: they rewrote the inputs under whoever was typing in them, and
// they kept a refresh permanently due the moment that cache expired — the
// traffic that gets the usage API answering "Rate limited".
//
// So: fetch on becoming visible, at most once a window after that, and
// whenever the operator asks. Renders still call in, but a call is now cheap.
var CC_LIMITS_REFRESH_MS = 60000;   // == MinUsageCacheTTL; faster cannot be newer
var _ccLimitsLastFetch = 0;
var _ccLimitsLastKey   = null;      // project the displayed figures belong to

// _ccSetVal fills a field, unless it is the one being typed into.
function _ccSetVal(id, v) {
  var el = document.getElementById(id);
  if (!el || el === document.activeElement) return;
  el.value = (v === null || v === undefined) ? '' : v;
}

// {force:true} skips the throttle: the ↻ button and the reload after a save.
ACTIONS.refreshCCLimits = () => loadCCLimits({force: true});
window.loadCCLimits = function(opts) {
  var section = document.getElementById('ccLimitsSection');
  if (!section) return;
  var force = !!(opts && opts.force);
  var key   = (typeof selectedProjectIdx !== 'undefined') ? String(selectedProjectIdx) : 'single';
  // Switching projects invalidates the figures on screen regardless of age.
  if (key !== _ccLimitsLastKey) force = true;
  if (!force && (Date.now() - _ccLimitsLastFetch) < CC_LIMITS_REFRESH_MS) return;
  _ccLimitsLastFetch = Date.now();
  _ccLimitsLastKey   = key;
  api(pUrl('/api/claudecode-limits')).then(function(d) {
    var limits = d.limits || {};
    _ccSetVal('ccMaxWeeklyPct',       limits.max_weekly_pct        || '');
    _ccSetVal('ccMaxFiveHourPct',     limits.max_five_hour_pct     || '');
    _ccSetVal('ccMaxWeeklyOpusPct',   limits.max_weekly_opus_pct   || '');
    _ccSetVal('ccMaxWeeklySonnetPct', limits.max_weekly_sonnet_pct || '');

    // Authentication banner. When the OAuth credential has expired or been
    // revoked the caps simply stop advancing, which on its own looks like
    // "nothing is happening" rather than "you must log in again" — so say it.
    var authBox = document.getElementById('ccLimitsAuth');
    if (authBox) {
      if (d.reauth_required) {
        authBox.style.display = '';
        authBox.innerHTML =
          '<strong>&#9888; Claude Code sign-in required — subscription usage is not updating.</strong>'
          + '<div style="margin-top:6px">' + esc(d.hint || '') + '</div>'
          + (d.stale_since
              ? '<div style="margin-top:6px;color:var(--muted)">Figures below are frozen at ' + esc(fmtDate(d.stale_since)) + '.</div>'
              : '')
          + '<div style="margin-top:8px"><button class="btn" style="padding:4px 10px;font-size:12px" '
          + 'data-action="switchTab" data-arg="budget">Open Claude Code sign-in</button></div>';
      } else if (d.usage_error) {
        // Not an auth problem: transient, so keep it low-key.
        authBox.style.display = '';
        authBox.innerHTML = '<strong>Usage temporarily unavailable.</strong><div style="margin-top:6px;color:var(--muted)">'
          + esc(d.usage_error) + '</div>';
      } else {
        authBox.style.display = 'none';
        authBox.innerHTML = '';
      }
    }

    var usagePanel = document.getElementById('ccLimitsUsage');
    if (usagePanel) {
      var rows = '';
      var reported = 0;
      var u = d.usage || {};
      function row(label, win, cap) {
        if (!win) {
          rows += '<div style="font-size:12px;color:var(--muted)">' + label + ': <em>not reported</em></div>';
          return;
        }
        reported++;
        var pct = Math.round(win.utilization || 0);
        var capN = parseFloat(cap) || 0;
        var capped = capN > 0 && pct >= capN;
        var color = capped ? 'var(--red)' : (pct >= 80 ? '#e74c3c' : pct >= 50 ? '#f39c12' : '#27ae60');
        rows += '<div>';
        rows += '<div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:2px">';
        rows += '<span><strong>' + label + '</strong>' + (capN > 0 ? ' <span style="color:var(--muted)">(cap ' + capN + '%)</span>' : '') + '</span>';
        rows += '<span style="color:' + color + ';font-weight:600">' + pct + '%</span>';
        rows += '</div>';
        rows += '<div style="background:var(--border);border-radius:4px;height:6px;overflow:hidden">';
        rows += '<div style="background:' + color + ';height:100%;width:' + Math.min(pct, 100) + '%"></div>';
        if (capN > 0 && capN <= 100) {
          rows += '<div style="position:relative;height:0"><div style="position:absolute;top:-6px;left:' + capN + '%;width:2px;height:6px;background:var(--text);opacity:0.6"></div></div>';
        }
        rows += '</div></div>';
      }
      row('Weekly (all)', u.seven_day,        limits.max_weekly_pct);
      row('5-Hour',       u.five_hour,        limits.max_five_hour_pct);
      row('Weekly Opus',  u.seven_day_opus,   limits.max_weekly_opus_pct);
      row('Weekly Sonnet',u.seven_day_sonnet, limits.max_weekly_sonnet_pct);
      // `rows` is never empty (every window emits at least "not reported"),
      // so gate the empty-state hint on whether any window actually reported.
      // Keying it off `rows` made this hint unreachable, which is part of why
      // a dead credential showed up as four blank rows and no explanation.
      if (reported === 0 && !d.reauth_required) {
        usagePanel.innerHTML = '<div style="font-size:12px;color:var(--muted)">No usage data available — make sure '
          + '~/.claude/.credentials.json exists or set CLAUDE_CODE_OAUTH_TOKEN.</div>';
      } else {
        usagePanel.innerHTML = rows;
      }
    }

    var violationBox = document.getElementById('ccLimitsViolation');
    if (violationBox) {
      var vs = d.violations || [];
      if (vs.length > 0) {
        violationBox.style.display = '';
        violationBox.innerHTML = '<strong>Cap reached — runs blocked:</strong><br>' + vs.map(esc).join('<br>');
      } else {
        violationBox.style.display = 'none';
      }
    }
  }).catch(function(err) {
    console.warn('cc-limits load error', err);
  });
};

act('saveCCLimits', function() {
  var body = {
    max_weekly_pct:        parseFloat(document.getElementById('ccMaxWeeklyPct').value)       || 0,
    max_five_hour_pct:     parseFloat(document.getElementById('ccMaxFiveHourPct').value)     || 0,
    max_weekly_opus_pct:   parseFloat(document.getElementById('ccMaxWeeklyOpusPct').value)   || 0,
    max_weekly_sonnet_pct: parseFloat(document.getElementById('ccMaxWeeklySonnetPct').value) || 0,
  };
  fetch(pUrl('/api/claudecode-limits'), {
    method: 'PUT',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  }).then(function(resp) {
    if (!resp.ok) { throw new Error('save failed'); }
    var msg = document.getElementById('ccLimitsSaveMsg');
    if (msg) {
      msg.style.display = '';
      setTimeout(function() { msg.style.display = 'none'; }, 2000);
    }
    loadCCLimits({force: true});
  }).catch(function(err) { alert('Save failed: ' + err); });
});

// Returning to a backgrounded tab is when staleness shows, so refresh then.
// Throttled, so tab-flicking costs nothing, and a hidden tab asks for nothing —
// its share of the traffic is part of what gets the usage API to rate-limit us.
//
// A listener rather than a repeating timer, deliberately. setInterval would
// also hold open the event loop of the headless harness that drives this
// bundle under node (TestDashboard_BackgroundWorkIsVisible), which exits when
// the loop drains. It is not needed either: render() fires on every state diff,
// so while anything is happening the throttled call below keeps the figures
// current, and while nothing is happening they are not moving.
document.addEventListener('visibilitychange', function() {
  if (document.hidden) return;
  var section = document.getElementById('ccLimitsSection');
  if (section && section.style.display !== 'none') loadCCLimits();
});

// Show the cc-limits section only when active provider is claudecode.
//
// Called from render(), so it runs on every state diff and must stay a pure
// visibility toggle: the fetch belongs to the *transition* into visibility, not
// to the render that happened to observe it (Task 20326).
window.updateCCLimitsVisibility = function(provider) {
  var section = document.getElementById('ccLimitsSection');
  if (!section) return;
  if ((provider || '').toLowerCase() === 'claudecode') {
    var wasHidden = section.style.display === 'none';
    section.style.display = '';
    if (wasHidden) loadCCLimits({force: true});
    else           loadCCLimits();   // throttled; a no-op inside the window
  } else {
    section.style.display = 'none';
  }
};

// The fleet's auto-update policy (Task 20331), cached here for the Executors
// tab's bar and execadmin's dialog (panelHelpers().fleet), which both read
// and replace it.
let fleetAutoUpdate = null;
