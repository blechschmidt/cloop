(function() {
'use strict';

let appState = null;
let evtSource = null;
let activeTab = 'overview';
let showCompletedTasks    = false;
let showCompletedProjects = false;

// ── Filter bar state ─────────────────────────────────────────────────────────
let filterState = { q: '', status: [], tags: [], assignee: '', priority: '' };
const FILTER_TABS = new Set(['tasks','kanban','timeline','deps']);

(function _loadFilterState() {
  try {
    const saved = localStorage.getItem('cloop_filter_state');
    if (saved) filterState = Object.assign({ q:'', status:[], tags:[], assignee:'', priority:'' }, JSON.parse(saved));
  } catch(e) {}
})();

// ── Multi-project mode ───────────────────────────────────────────────────────
let isMultiProject      = false;  // true when multiple projects are registered
let selectedProjectIdx  = null;   // null = no project selected (Projects landing page)
let selectedProjectName = '';

// pUrl appends ?project_idx=N to a URL when a project is selected in multi-project mode.
function pUrl(url) {
  if (selectedProjectIdx === null) return url;
  const sep = url.includes('?') ? '&' : '?';
  return url + sep + 'project_idx=' + selectedProjectIdx;
}

// ── Auth token (stored in sessionStorage) ───────────────────────────────────
let authToken = sessionStorage.getItem('cloop_token') || '';

function authHeaders() {
  return authToken ? {'Authorization': 'Bearer ' + authToken} : {};
}

function showLoginModal() {
  // No dismiss: Escape must not close the login gate, because everything
  // behind it is unusable until a token is accepted.
  openOverlay('loginOverlay', {focus: '#loginTokenInput'});
}

function hideLoginModal() {
  closeOverlay('loginOverlay');
  document.getElementById('loginError').classList.remove('visible');
  document.getElementById('loginTokenInput').value = '';
}

window.submitLogin = function() {
  const input = document.getElementById('loginTokenInput');
  const token = input.value.trim();
  if (!token) return;
  // Test the token against the state endpoint.
  fetch('/api/state', {headers: {'Authorization': 'Bearer ' + token}}).then(r => {
    if (r.status === 401) {
      document.getElementById('loginError').classList.add('visible');
      input.select();
    } else {
      authToken = token;
      sessionStorage.setItem('cloop_token', token);
      hideLoginModal();
      checkAuthAndInit();
    }
  }).catch(() => {
    document.getElementById('loginError').classList.add('visible');
  });
};

// ── Drag-and-drop state ──────────────────────────────────────────────────────
let dragSrcId = null;
let pendingDeleteId = null;

// The run queue exactly as renderTasks last laid it out: the ids of every task
// that can still run, in the order the rows appear. onDrop splices this rather
// than re-deriving an order of its own — the drop target is a position on
// screen, so the only list it can be an index into is the one on screen
// (Task 20299).
let renderedQueue = [];

// ── Live output state ────────────────────────────────────────────────────────
let liveLogText = '';         // accumulated text for the panel
let liveLogAutoScroll = true; // whether to auto-scroll (user can disable by scrolling up)

// setTasksRunBarVisible shows or hides the Tasks tab's Start/Stop bar
// (Task 20253). The bar acts on whichever project is selected, so it must be
// hidden whenever that is nobody: with no selection apiRun() would fall back to
// the hub's own working directory and start a run on a project the user is not
// even looking at.
function setTasksRunBarVisible(visible) {
  const bar = document.getElementById('tasksRunBar');
  if (bar) bar.style.display = visible ? '' : 'none';
}

// clearProjectScopedPanels blanks every panel rendered from appState, for use
// when the selection changes and the new project's first frame has not arrived.
//
// Setting appState = null is not enough by itself: the panels keep the markup
// they were last rendered with, so without this the previous project's task
// rows, kanban cards and live log stay on screen — indistinguishable, to the
// user, from the new project genuinely having those tasks (Task 20197).
//
// The placeholder says "Loading" rather than reusing the "No tasks yet" empty
// state, which would be a false claim about a project we have not read yet.
function clearProjectScopedPanels() {
  const loading = '<div class="empty-state"><h3>Loading…</h3></div>';

  const taskList = document.getElementById('taskListFull');
  if (taskList) taskList.innerHTML = loading;
  const badge = document.getElementById('taskCountBadge');
  if (badge) badge.textContent = '';

  const board = document.getElementById('kanbanBoard');
  if (board) board.innerHTML = loading;

  const steps = document.getElementById('stepList');
  if (steps) steps.innerHTML = loading;

  // The live log is per-project too, and its buffer is client-side: a stale
  // buffer would keep scrolling the old project's output under the new one
  // until a replay overwrote it.
  liveLogText = '';
  try { renderLiveLog(); } catch(_) {}

  // Nothing is known to be running on a project we have not loaded.
  try { updateBrowserTitle(); } catch(_) {}

  // Likewise for the run bar: until the new project's first frame arrives we
  // cannot say whether it is running, and offering the wrong half of the pair
  // is worse than offering neither. render() puts it back.
  setTasksRunBarVisible(false);
}

// ── Deferred chart library (Task 20289) ─────────────────────────────────────

// The single in-flight or settled load of chart.js. Memoised so that several
// panels asking at once share one script element, and so returning to a chart
// tab does not refetch.
let _chartLibPromise = null;

// ensureChartLib resolves once window.Chart is usable, fetching the library on
// first demand instead of from the document head.
//
// The URL is read from the <meta> index.html renders rather than written here,
// because it carries the asset's content hash: it changes whenever the library
// does and is served `immutable`. A path hard-coded in JS would either pin a
// stale revision forever or have to give up that caching.
//
// A failed load clears the memo, so the caller's retry is a real second attempt
// rather than the first attempt's rejection replayed for the life of the page.
// That matters because the hub is often reached over a slow or flaky link, and
// a chart that silently never appears is worse than one that says so.
function ensureChartLib() {
  if (window.Chart) return Promise.resolve(window.Chart);
  if (_chartLibPromise) return _chartLibPromise;

  const p = new Promise((resolve, reject) => {
    const meta = document.querySelector && document.querySelector('meta[name="cloop-chart-src"]');
    const src  = meta && meta.getAttribute && meta.getAttribute('content');
    if (!src) {
      reject(new Error('the chart library URL is missing from the page'));
      return;
    }
    if (!document.head || !document.createElement) {
      reject(new Error('no document head to load the chart library into'));
      return;
    }
    const el = document.createElement('script');
    el.src   = src;
    el.async = true;
    el.onload = () => {
      // A 200 that is not the library — a captive portal or an error page
      // served as JS — loads without error but defines no global. Treat that
      // as the failure it is rather than letting `new Chart` throw later.
      if (window.Chart) resolve(window.Chart);
      else reject(new Error('the chart library loaded but defined no Chart global'));
    };
    el.onerror = () => reject(new Error('the chart library could not be fetched'));
    document.head.appendChild(el);
  });

  _chartLibPromise = p;
  // Attaching the handler to p (not to a reassigned variable) also marks p as
  // handled, so a rejection the caller catches does not also surface as an
  // unhandled promise rejection in the console.
  p.catch(() => { if (_chartLibPromise === p) _chartLibPromise = null; });
  return p;
}
window.ensureChartLib = ensureChartLib;

// ── Tab switching ───────────────────────────────────────────────────────────

window.switchTab = function(name) {
  activeTab = name;
  // Name the screen for the diagnostic trail (Task 20251). Done here rather
  // than left to the reporter's DOM query, because this is the authoritative
  // moment the view changes — and a trail whose view column is one tab behind
  // attributes every error to the panel the user just left.
  try { if (window.cloopTelemetry) window.cloopTelemetry.setView(name); } catch (_) {}
  document.querySelectorAll('.tab-panel').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.m-tab-btn').forEach(el => el.classList.remove('active'));
  const panel  = document.getElementById('tab-'   + name);
  const btn    = document.getElementById('tbtn-'  + name);
  const mBtn   = document.getElementById('mtbtn-' + name);
  if (panel) panel.classList.add('active');
  if (btn)   btn.classList.add('active');
  if (mBtn)  mBtn.classList.add('active');

  // Show/hide unified filter bar.
  _syncFilterBarVisibility(name);

  // Close mobile nav when a tab is selected.
  closeMobileNav();

  // Show/hide FAB: only on tasks tab.
  const fab = document.getElementById('fab-add-task');
  if (fab) fab.style.display = (name === 'tasks') ? 'flex' : 'none';

  // In multi-project mode, re-fetch state for the selected project when
  // switching to any project-scoped tab so the data is always current.
  const projectScopedTabs = ['overview','tasks','queue','kanban','timeline','kb','deps','risk-matrix','analytics','chat','assistant','replay','provider-calls'];
  if (isMultiProject && selectedProjectIdx === null && name === 'overview') {
    // No project selected: show the all-projects summary panel.
    // Always reload so the cards reflect the latest project statuses.
    loadProjects();
  } else if (isMultiProject && selectedProjectIdx !== null && projectScopedTabs.includes(name)) {
    // Task 20134: no /api/state refetch — appState is hydrated by the WS
    // task_update on initial subscribe (openProject -> connectWS) and kept
    // fresh by state_diff events. Re-render the affected panel directly from
    // the cached state.
    if (appState) {
      if (name === 'tasks')  renderTasks(appState);
      if (name === 'kanban') renderKanban(appState);
    }
    if (name === 'timeline') loadTimeline();
    if (name === 'kb') loadKB();
    if (name === 'deps') loadDeps();
    if (name === 'risk-matrix') loadRiskMatrix();
    if (name === 'analytics') loadAnalytics();
    if (name === 'queue') loadQueue();
    if (name === 'budget') { loadBudget(); loadClaudeUsage(); loadRateLimits(); loadClaudeAuthStatus(); }
    if (name === 'executors') loadExecutors();
    if (name === 'audit') { loadAudit(); verifyAuditChain(); }
    if (name === 'secrets') loadSecretsPanel();
    if (name === 'quotas') loadQuotas();
    // The Overview's Executor card needs the same payload; it is the only
    // per-project field on that page the state diff does not carry, because
    // bindings live in the control plane's database rather than in project
    // state.
    if (name === 'overview') loadExecutors();
    if (name === 'overview') loadProjectRepositories();
    if (name === 'chat') loadChatHistory();
    if (name === 'assistant') loadAssistantHistory();
    if (name === 'replay') { loadReplayRuns(); try { window._populateReplayTaskSelector && window._populateReplayTaskSelector(); } catch(_) {} }
    if (name === 'provider-calls') loadProviderCalls();
  } else {
    if (name === 'settings') { loadConfig(); loadSTTSettings(); loadOIDCSettings(); loadCIPanel(); loadGitHubApps(); loadGlassesLink(); loadHiddenProjects(); loadDiskUsage(); loadBuildInfo(); }
    if (name === 'overview') loadExecutors();
    if (name === 'overview') loadProjectRepositories();
    if (name === 'tasks'  && appState) renderTasks(appState);
    if (name === 'kanban' && appState) renderKanban(appState);
    if (name === 'projects') loadProjects();
    if (name === 'chat') loadChatHistory();
    if (name === 'assistant') loadAssistantHistory();
    if (name === 'timeline') loadTimeline();
    if (name === 'kb') loadKB();
    if (name === 'deps') loadDeps();
    if (name === 'risk-matrix') loadRiskMatrix();
    if (name === 'analytics') loadAnalytics();
    if (name === 'queue') loadQueue();
    if (name === 'budget') { loadBudget(); loadClaudeUsage(); loadRateLimits(); loadClaudeAuthStatus(); }
    if (name === 'executors') loadExecutors();
    if (name === 'audit') { loadAudit(); verifyAuditChain(); }
    if (name === 'secrets') loadSecretsPanel();
    if (name === 'replay') { loadReplayRuns(); try { window._populateReplayTaskSelector && window._populateReplayTaskSelector(); } catch(_) {} }
    if (name === 'provider-calls') loadProviderCalls();
  }

  // In multi-project mode, show/hide breadcrumb and project selector.
  if (isMultiProject) {
    const bc = document.getElementById('projectBreadcrumb');
    updateProjectSelector();
    if (name === 'projects' || name === 'settings' || name === 'budget' || name === 'executors' || name === 'audit' || name === 'secrets' || name === 'quotas') {
      // Global tabs: hide breadcrumb
      if (bc) bc.style.display = 'none';
    } else {
      // Project-scoped tabs: show breadcrumb when a project is selected
      if (bc) bc.style.display = selectedProjectIdx !== null ? 'flex' : 'none';
    }
  }

  // Update scope hint badge in header to make project-vs-global clear.
  updateScopeHint(name);
};

// updateScopeHint reflects whether the active tab is per-project or global.
// In single-project mode the hint still appears so the distinction is clear.
function updateScopeHint(name) {
  const globalTabs = ['projects','budget','settings','executors','audit','secrets','quotas'];
  const hint = document.getElementById('scopeHint');
  if (!hint) return;
  hint.classList.remove('visible','project','global');
  if (globalTabs.includes(name)) {
    hint.textContent = 'Global';
    hint.classList.add('visible','global');
    hint.title = 'This tab applies across all projects (global configuration).';
  } else {
    if (isMultiProject && selectedProjectIdx === null) {
      hint.textContent = 'All projects';
      hint.classList.add('visible','global');
      hint.title = 'No project selected — choose one from the project selector to see project data.';
    } else {
      hint.textContent = 'Project';
      hint.classList.add('visible','project');
      const projHint = (isMultiProject && selectedProjectName) ? selectedProjectName : 'this project';
      hint.title = 'This tab shows data for ' + projHint + '.';
    }
  }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// estimateCost returns estimated USD cost or null if the model is unknown.
// Returns 0 for local (ollama) providers. Prices are per 1M tokens.
// ── Provider → Model mapping for dropdowns ──
const providerModels = {
  claudecode: [
    {value: '', label: '(default — claude-sonnet-4-6)'},
    {value: 'claude-fable-5', label: 'Claude Fable 5'},
    {value: 'claude-opus-5', label: 'Claude Opus 5'},
    {value: 'claude-opus-4-8', label: 'Claude Opus 4.8'},
    {value: 'claude-opus-4-7', label: 'Claude Opus 4.7'},
    {value: 'claude-opus-4-6', label: 'Claude Opus 4.6'},
    {value: 'claude-opus-4-5', label: 'Claude Opus 4.5'},
    {value: 'claude-sonnet-5', label: 'Claude Sonnet 5'},
    {value: 'claude-sonnet-4-6', label: 'Claude Sonnet 4.6'},
    {value: 'claude-sonnet-4-5', label: 'Claude Sonnet 4.5'},
    {value: 'claude-haiku-4-5', label: 'Claude Haiku 4.5'},
  ],
  anthropic: [
    {value: '', label: '(default — claude-opus-4-6)'},
    {value: 'claude-fable-5', label: 'Claude Fable 5'},
    {value: 'claude-opus-5', label: 'Claude Opus 5'},
    {value: 'claude-opus-4-8', label: 'Claude Opus 4.8'},
    {value: 'claude-opus-4-7', label: 'Claude Opus 4.7'},
    {value: 'claude-opus-4-6', label: 'Claude Opus 4.6'},
    {value: 'claude-opus-4-5', label: 'Claude Opus 4.5'},
    {value: 'claude-sonnet-5', label: 'Claude Sonnet 5'},
    {value: 'claude-sonnet-4-6', label: 'Claude Sonnet 4.6'},
    {value: 'claude-sonnet-4-5', label: 'Claude Sonnet 4.5'},
    {value: 'claude-haiku-4-5', label: 'Claude Haiku 4.5'},
  ],
  openai: [
    {value: '', label: '(default — gpt-4o)'},
    {value: 'gpt-4o', label: 'GPT-4o'},
    {value: 'gpt-4o-mini', label: 'GPT-4o Mini'},
    {value: 'gpt-4-turbo', label: 'GPT-4 Turbo'},
    {value: 'o1', label: 'o1'},
    {value: 'o1-mini', label: 'o1-mini'},
    {value: 'o3-mini', label: 'o3-mini'},
  ],
  ollama: [
    {value: '', label: '(default — llama3.2)'},
    {value: 'llama3.2', label: 'Llama 3.2'},
    {value: 'llama3.1', label: 'Llama 3.1'},
    {value: 'llama3', label: 'Llama 3'},
    {value: 'mistral', label: 'Mistral'},
    {value: 'mixtral', label: 'Mixtral'},
    {value: 'phi3', label: 'Phi-3'},
    {value: 'qwen', label: 'Qwen'},
    {value: 'deepseek', label: 'DeepSeek'},
  ],
};
function updateModelDropdown() {
  const sel = document.getElementById('initModel');
  const prov = document.getElementById('initProvider').value;
  const models = providerModels[prov] || [{value:'', label:'(default)'}];
  sel.innerHTML = models.map(m => '<option value="'+m.value+'">'+m.label+'</option>').join('');
}

// Track current project's provider+model+effort for pre-populating the
// Provider/Model picker modal opened from the Provider stat card.
let _currentProvider = '';
let _currentModel = '';
let _currentEffort = '';

function prepopulateAdvancedRunOptions(s) {
  _currentProvider = s.provider || '';
  _currentModel    = s.model    || '';
  _currentEffort   = s.effort   || '';
}

// Render the "Active Options" badge grid showing which CLI flags are persistently
// enabled for the current project (from state). Each badge has a unicode icon, a
// human label, and the corresponding CLI flag name. Disabled options are shown
// muted so the user can see which features are available but inactive.
function renderActiveOptions(s) {
  const grid = document.getElementById('activeOptionsGrid');
  if (!grid) return;
  // Each entry: [enabled, icon, label, flag, tooltip, toggleKey]
  // toggleKey (optional) makes the badge clickable and POSTs to /api/options/toggle.
  const opts = [
    [!!s.auto_evolve,   '🧬', 'Evolve Mode',   '--auto-evolve',  'Click to toggle. Automatically discovers and adds new tasks after the plan completes', 'auto_evolve'],
    [!!s.innovate_mode, '✨', 'Innovate Mode', '--innovate',     'Click to toggle. Creative/experimental feature exploration in evolve prompts', 'innovate_mode'],
    [!!s.skip_clarify,  '⏭️', 'Skip Clarify',  '--skip-clarify', 'Click to toggle. Bypass the interactive goal-clarification Q&A before plan decomposition (applies on next run)', 'skip_clarify'],
    [!!s.parallel,      '⚡', 'Parallel',      '--parallel',     'Click to toggle. Run dependency-ready tasks concurrently (applies on next run)', 'parallel'],
    [!!s.plan_only,     '📝', 'Plan Only',     '--plan-only',    'Click to toggle. Decompose goal into tasks but do not execute', 'plan_only'],
    [!!s.retry_failed,  '🔁', 'Retry Failed',  '--retry-failed', 'Click to toggle. Reset previously-failed tasks to pending before the next run', 'retry_failed'],
    [!!s.dry_run,       '🧪', 'Dry Run',       '--dry-run',      'Click to toggle. Show prompts without invoking the provider (no API calls, no side effects)', 'dry_run'],
  ];
  const mp = parseInt(s.max_parallel, 10);
  const mpVal = (Number.isFinite(mp) && mp >= 1 && mp <= 64) ? mp : 1;
  const mpDisplay = String(mpVal);
  const parallelControls =
    '<div class="option-badge ' + (s.parallel ? 'on' : 'off') + ' option-config" ' +
      'title="Worker pool cap when Parallel mode is on. Must be between 1 and 64.">' +
      '<span class="opt-icon">🧵</span>' +
      '<span>Max Parallel</span>' +
      '<input type="number" id="maxParallelInput" min="1" max="64" step="1" value="' + mpVal + '" ' +
        'style="width:56px;background:transparent;color:var(--text);border:1px solid var(--border);' +
        'border-radius:4px;padding:2px 4px;font-family:inherit;font-size:inherit;text-align:right;" ' +
        'onchange="setMaxParallel(this.value)" />' +
      '<span class="opt-flag" title="Currently: ' + mpDisplay + ' worker(s)">-j ' + mpDisplay + '</span>' +
    '</div>';
  // Step timeout control. Disabled by default (Task 20147): an unset/empty
  // value means "no timeout", so it renders as "off" rather than implying a
  // 10m default that was never actually applied.
  const stRaw = s.step_timeout;
  const stVal = (stRaw === undefined || stRaw === null || stRaw === '') ? '0' : stRaw;
  const stepTimeoutControl =
    '<div class="option-badge option-config" ' +
      'title="Max duration per task step. Set to 0 (or off) to disable. Disabled by default.">' +
      '<span class="opt-icon">⏱</span>' +
      '<span>Step Timeout</span>' +
      '<input type="text" id="stepTimeoutInput" value="' + (stVal === '0' ? 'off' : stVal) + '" ' +
        'style="width:56px;background:transparent;color:var(--text);border:1px solid var(--border);' +
        'border-radius:4px;padding:2px 4px;font-family:inherit;font-size:inherit;text-align:right;" ' +
        'onchange="setStepTimeout(this.value)" />' +
    '</div>';
  // Per-task default wall-clock budget (Task 20143). 0 = "no timeout"
  // (Task 20148: tasks have no timeout by default). Changes here take effect
  // on all currently-running tasks within a few seconds via the orchestrator's
  // live-deadline poller, not just future tasks.
  const ttRaw = parseInt(s.default_max_minutes, 10);
  const ttVal = (Number.isFinite(ttRaw) && ttRaw > 0) ? ttRaw : 0;
  const ttDisplay = ttVal === 0 ? 'off' : (String(ttVal) + 'm');
  const taskTimeoutControl =
    '<div class="option-badge option-config" ' +
      'title="Default wall-clock budget per task (minutes). 0 means no timeout — tasks run until they finish. Applies immediately to running tasks.">' +
      '<span class="opt-icon">⏲</span>' +
      '<span>Task Timeout</span>' +
      '<input type="number" id="taskTimeoutInput" min="0" max="10080" step="1" value="' + ttVal + '" ' +
        'style="width:64px;background:transparent;color:var(--text);border:1px solid var(--border);' +
        'border-radius:4px;padding:2px 4px;font-family:inherit;font-size:inherit;text-align:right;" ' +
        'onchange="setTaskTimeout(this.value)" />' +
      '<span class="opt-flag" title="0 = no timeout">' + ttDisplay + '</span>' +
    '</div>';
  const enabledCount = opts.filter(o => o[0]).length;
  if (enabledCount === 0) {
    grid.innerHTML =
      '<div class="options-empty">No persistent CLI options are currently enabled. ' +
      'Run with <code>--auto-evolve</code> or <code>--innovate</code> to activate.</div>' +
      buildOptionBadges(opts) + parallelControls + stepTimeoutControl + taskTimeoutControl;
    return;
  }
  grid.innerHTML = buildOptionBadges(opts) + parallelControls + stepTimeoutControl + taskTimeoutControl;
}

// Exposed on window because the Active Options badges use inline onchange
// handlers that resolve in the global scope, while this whole script is
// wrapped in an IIFE.
window.setMaxParallel = function(raw) {
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 1 || n > 64) {
    toast('Max Parallel must be between 1 and 64', 'error');
    return;
  }
  // Optimistic update so the badge label flips instantly; revert on failure.
  const prev = appState ? appState.max_parallel : 0;
  if (appState) {
    appState.max_parallel = n;
    try { renderActiveOptions(appState); } catch(_) {}
  }
  apiMethod('POST', pUrl('/api/options/max-parallel'), {value: n}).then(d => {
    if (d && d.ok) {
      toast('Max Parallel set to ' + n, 'success');
    } else {
      if (appState) {
        appState.max_parallel = prev;
        try { renderActiveOptions(appState); } catch(_) {}
      }
      toast('Update failed: ' + (d && d.error ? d.error : 'unknown error'), 'error');
    }
  }).catch(err => {
    if (appState) {
      appState.max_parallel = prev;
      try { renderActiveOptions(appState); } catch(_) {}
    }
    toast('Update failed: ' + err.message, 'error');
  });
};

// setTaskTimeout updates the project-level default wall-clock budget per
// task (Task 20143). Submitting 0 means no timeout (Task 20148) — tasks run
// until they finish. Affects currently-running tasks within ~3 seconds via
// the orchestrator's live-deadline poller.
window.setTaskTimeout = function(raw) {
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 0 || n > 10080) {
    toast('Task Timeout must be 0 (off) or 1..10080 minutes', 'error');
    return;
  }
  const prev = appState ? appState.default_max_minutes : 0;
  if (appState) {
    appState.default_max_minutes = n;
    try { renderActiveOptions(appState); } catch(_) {}
  }
  apiMethod('POST', pUrl('/api/options/task-timeout'), {value: n}).then(d => {
    if (d && d.ok) {
      toast('Task Timeout set to ' + (n === 0 ? 'off (no timeout)' : n + 'm'), 'success');
    } else {
      if (appState) {
        appState.default_max_minutes = prev;
        try { renderActiveOptions(appState); } catch(_) {}
      }
      toast('Update failed: ' + (d && d.error ? d.error : 'unknown error'), 'error');
    }
  }).catch(err => {
    if (appState) {
      appState.default_max_minutes = prev;
      try { renderActiveOptions(appState); } catch(_) {}
    }
    toast('Update failed: ' + err.message, 'error');
  });
};

window.setStepTimeout = function(raw) {
  const val = raw.trim().toLowerCase();
  const sendVal = (val === 'off' || val === '0' || val === '') ? '0' : val;
  apiMethod('POST', pUrl('/api/options/step-timeout'), {value: sendVal}).then(d => {
    if (d && d.ok) {
      toast('Step timeout set to ' + (sendVal === '0' ? 'disabled' : sendVal), 'success');
      if (appState) { appState.step_timeout = sendVal; }
    } else {
      toast('Update failed: ' + (d && d.error ? d.error : 'unknown error'), 'error');
    }
  }).catch(err => toast('Error: ' + err, 'error'));
};

function buildOptionBadges(opts) {
  return opts.map(o => {
    const cls = o[0] ? 'on' : 'off';
    const toggleKey = o[5];
    if (toggleKey) {
      return '<button class="option-badge ' + cls + ' togglable" type="button" ' +
        'title="' + esc(o[4]) + '" ' +
        'onclick="toggleOption(\'' + toggleKey + '\', ' + (o[0] ? 'false' : 'true') + ')">' +
        '<span class="opt-icon">' + o[1] + '</span>' +
        '<span>' + esc(o[2]) + '</span>' +
        '<span class="opt-flag">' + esc(o[3]) + '</span>' +
      '</button>';
    }
    return '<span class="option-badge ' + cls + '" title="' + esc(o[4]) + '">' +
      '<span class="opt-icon">' + o[1] + '</span>' +
      '<span>' + esc(o[2]) + '</span>' +
      '<span class="opt-flag">' + esc(o[3]) + '</span>' +
    '</span>';
  }).join('');
}

// Exposed on window because the Active Options badges use inline onclick
// handlers that resolve in the global scope, while this whole script is
// wrapped in an IIFE.
//
// The badge is flipped optimistically in the DOM before the POST so the click
// feels instant — without this, the user waits for one HTTP round-trip plus a
// full render(s) (which re-fetches /api/steps) before seeing any visual
// change. On HTTP error the optimistic update is reverted.
window.toggleOption = function(flag, value) {
  const prev = appState ? !!appState[flag] : !value;
  if (appState) {
    appState[flag] = value;
    try { renderActiveOptions(appState); } catch(_) {}
  }
  apiMethod('POST', pUrl('/api/options/toggle'), {flag: flag, value: value}).then(d => {
    if (d && d.ok) {
      const labels = {auto_evolve: 'Evolve Mode', innovate_mode: 'Innovate Mode', skip_clarify: 'Skip Clarify', parallel: 'Parallel Mode', plan_only: 'Plan Only', retry_failed: 'Retry Failed', dry_run: 'Dry Run'};
      toast((labels[flag] || flag) + (value ? ' enabled' : ' disabled'), 'success');
      // No explicit /api/state refetch — the backend's task_update WebSocket
      // broadcast (or the next render trigger) carries authoritative state.
    } else {
      if (appState) {
        appState[flag] = prev;
        try { renderActiveOptions(appState); } catch(_) {}
      }
      toast('Toggle failed: ' + (d && d.error ? d.error : 'unknown error'), 'error');
    }
  }).catch(err => {
    if (appState) {
      appState[flag] = prev;
      try { renderActiveOptions(appState); } catch(_) {}
    }
    toast('Toggle failed: ' + err.message, 'error');
  });
};

function estimateCost(provider, model, inputTok, outputTok) {
  const p = (provider || '').toLowerCase();
  if (p === 'ollama') return 0;
  const m = (model || '').toLowerCase();
  // Pricing table: [inputPerM, outputPerM] in USD
  const prices = {
    'claude-fable-5':             [10.00, 50.00],
    'claude-opus-5':              [5.00,  25.00],
    'claude-sonnet-5':            [3.00,  15.00],
    'claude-opus-4-8':            [5.00,  25.00],
    'claude-opus-4-7':            [5.00,  25.00],
    'claude-opus-4-6':            [15.00, 75.00],
    'claude-opus-4-5':            [15.00, 75.00],
    'claude-sonnet-4-6':          [3.00,  15.00],
    'claude-sonnet-4-5':          [3.00,  15.00],
    'claude-haiku-4-5':           [0.80,  4.00],
    'claude-3-opus-20240229':     [15.00, 75.00],
    'claude-3-5-sonnet-20241022': [3.00,  15.00],
    'claude-3-5-haiku-20241022':  [0.80,  4.00],
    'claude-3-haiku-20240307':    [0.25,  1.25],
    'gpt-4o':                     [2.50,  10.00],
    'gpt-4o-mini':                [0.15,  0.60],
    'gpt-4-turbo':                [10.00, 30.00],
    'gpt-4':                      [30.00, 60.00],
    'gpt-3.5-turbo':              [0.50,  1.50],
    'o1':                         [15.00, 60.00],
    'o1-mini':                    [3.00,  12.00],
    'o3-mini':                    [1.10,  4.40],
    'gemini-1.5-pro':             [1.25,  5.00],
    'gemini-1.5-flash':           [0.075, 0.30],
    'llama3':                     [0,     0],
    'llama3.1':                   [0,     0],
    'llama3.2':                   [0,     0],
    'mistral':                    [0,     0],
    'mixtral':                    [0,     0],
  };
  // Exact match
  if (prices[m]) {
    const [inM, outM] = prices[m];
    return (inputTok / 1e6) * inM + (outputTok / 1e6) * outM;
  }
  // Prefix match (longest wins)
  let best = null, bestLen = 0;
  for (const key of Object.keys(prices)) {
    if (key.length > bestLen && m.startsWith(key)) {
      best = prices[key]; bestLen = key.length;
    }
  }
  if (best) {
    return (inputTok / 1e6) * best[0] + (outputTok / 1e6) * best[1];
  }
  // claudecode without explicit model: assume sonnet
  if (p === 'claudecode' || p === '') {
    const [inM, outM] = prices['claude-sonnet-4-6'];
    return (inputTok / 1e6) * inM + (outputTok / 1e6) * outM;
  }
  return null;
}

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleDateString(undefined,{month:'short',day:'numeric'})+' '+
         d.toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'});
}

function fmtNum(n) {
  if (!n) return '0';
  if (n >= 1e6) return (n/1e6).toFixed(1)+'M';
  if (n >= 1e3) return (n/1e3).toFixed(1)+'K';
  return String(n);
}

function esc(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// errText: any API error value -> one line of readable text (Task 20320).
// Cases and rationale: claude_login_frontend_test.go. Terse: ships on first paint.
function errText(x) {
  if (x == null) return '';
  if (typeof x === 'string') return x;
  if (typeof x !== 'object') return String(x);
  if (typeof x.message === 'string' && x.message) {
    var need = x.details && x.details.required_permission;
    return need ? x.message + ' (requires ' + need + ')' : x.message;
  }
  // Unwrap once; the identity test stops a self-referential body.
  if (x.error != null && x.error !== x) return errText(x.error);
  if (typeof x.code === 'string' && x.code) return x.code;
  try { var j = JSON.stringify(x); return j === '{}' ? '' : j; } catch (_) { return String(x); }
}

function toast(msg, type) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'show ' + (type || '');
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.className = ''; }, 3000);
}

// ── Permissions (Task 20164) ─────────────────────────────────────────────────
// myPerms/myGlobalPerms mirror what /api/me reports for the selected project
// and for fleet-wide actions. With OIDC disabled the server reports every
// permission, so the same gating code runs unchanged in single-tenant use.
// Until /api/me answers we assume full access: the alternative — starting
// locked down — makes the dashboard flicker every control on first paint.
let myPerms = null;
let myGlobalPerms = null;
let myRole = '';

function can(perm) {
  return myPerms === null || myPerms.indexOf(perm) !== -1;
}
function canGlobal(perm) {
  return myGlobalPerms === null || myGlobalPerms.indexOf(perm) !== -1;
}

// applyPermissionGating hides or disables every element that declares a
// required permission via data-perm / data-global-perm. Elements marked
// data-perm-hide are removed from the layout entirely; the rest are disabled
// in place with an explanatory title, which is friendlier for controls whose
// absence would make a panel look broken.
function applyPermissionGating(root) {
  const scope = root || document;
  scope.querySelectorAll('[data-perm],[data-global-perm]').forEach(el => {
    const need = el.getAttribute('data-perm');
    const needGlobal = el.getAttribute('data-global-perm');
    const ok = (!need || can(need)) && (!needGlobal || canGlobal(needGlobal));
    if (el.hasAttribute('data-perm-hide')) {
      el.style.display = ok ? '' : 'none';
      return;
    }
    el.disabled = !ok;
    el.classList.toggle('perm-denied', !ok);
    if (!ok) {
      el.title = 'Your role (' + (myRole || 'none') + ') does not permit this action';
    } else if (el.title && el.title.indexOf('does not permit') !== -1) {
      el.title = '';
    }
  });
}

// refreshPermissions re-reads /api/me for the currently selected project and
// re-applies gating. Called on load and whenever the project changes, since
// a user may hold different roles on different projects.
function refreshPermissions() {
  return fetch(pUrl('/api/me'), {headers: authHeaders()})
    .then(r => r.ok ? r.json() : null)
    .then(me => {
      if (!me) return null;
      myPerms = Array.isArray(me.permissions) ? me.permissions : null;
      myGlobalPerms = Array.isArray(me.global_permissions) ? me.global_permissions : null;
      myRole = me.role || '';
      applyPermissionGating();
      // The caller's own quota badge rides the same refresh: it changes for
      // exactly the reasons permissions do (a new project selected, an admin
      // edit) and one round trip fewer is one fewer to keep in sync.
      try { window.refreshMyQuota && window.refreshMyQuota(); } catch (_) {}
      return me;
    })
    .catch(() => null);
}

// handleForbidden renders a 403/404-from-authorization as an explanation
// rather than letting the caller fail silently or show a raw error. The
// permission set is refreshed afterwards because a 403 means the client's
// view of what it may do is stale — the operator may have just changed it.
function handleForbidden(r, payload) {
  const err = (payload && payload.error) || {};
  const need = (err.details && err.details.required_permission) || '';
  // The server's sentence first: a claim-freshness denial names the config
  // changes that fix the hub, which required_permission alone threw away.
  toast(errText(err) || (need
    ? 'Not permitted: this action needs "' + need + '"'
    : 'Not permitted by your role'), 'error');
  refreshPermissions();
  return Promise.reject(new Error(err.code || 'FORBIDDEN'));
}

// parseAPIResponse centralises the auth/authorization outcomes so every
// caller degrades the same way: 401 re-opens the login modal, 403 explains
// the denial, and everything else resolves to the decoded body.
function parseAPIResponse(r) {
  if (r.status === 401) { showLoginModal(); return Promise.reject(new Error('401')); }
  if (r.status === 403) {
    return r.json().catch(() => null).then(body => handleForbidden(r, body));
  }
  return r.json().then(normalizeAPIError);
}

// normalizeAPIError flattens apierror's {"error":{code,message}} into the
// {"error":"text"} every caller already reads, so the hub's two dialects become
// one here rather than at ~100 render sites (Task 20320).
function normalizeAPIError(body) {
  if (body && typeof body === 'object' && body.error != null && typeof body.error !== 'string') {
    body.error = errText(body.error);
  }
  return body;
}

function api(url, body) {
  const ah = authHeaders();
  const opts = body !== undefined
    ? { method: 'POST', headers: Object.assign({'Content-Type':'application/json'}, ah), body: JSON.stringify(body) }
    : { method: 'GET',  headers: ah };
  return fetch(url, opts).then(parseAPIResponse);
}

function apiMethod(method, url, body) {
  const opts = { method, headers: authHeaders() };
  if (body !== null && body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  return fetch(url, opts).then(parseAPIResponse);
}

// pauseReasonLabels is the operator-facing noun for each pausereason.Code
// (pkg/pausereason). Kept in sync with the Go enum by
// TestEveryPauseReasonCodeIsRenderable in tests/arch — a code with no entry
// here would render its raw identifier to the operator.
const pauseReasonLabels = {
  usage_cap:    'subscription usage cap reached',
  budget:       'budget limit reached',
  token_budget: 'token budget reached',
  step_limit:   'step limit reached',
  approval:     'waiting for approval',
  abort:        'run aborted',
  cancelled:    'run interrupted',
  plan_only:    'plan-only mode',
  idle:         'no runnable tasks',
  operator:     'stopped by operator',
  stale:        'previous run ended unexpectedly',
};

// pauseReasonText renders a pause reason as one line of prose:
//
//   5-hour cap reached, resumes 14:50
//
// The clock is formatted in the browser's zone, which is why the server sends
// resumes_at as an RFC3339 instant and does not format it: only the browser
// knows what time it is where the reader is sitting. A reset that has already
// passed is not shown as a future time — the hub's sweep may not have run yet,
// and "resumes 14:50" at 15:10 reads as broken rather than as pending.
function pauseReasonText(pr) {
  if (!pr || !pr.code) return '';
  const label = pr.detail || pauseReasonLabels[pr.code] || pr.code;
  if (!pr.resumes_at) return label;
  const at = new Date(pr.resumes_at);
  if (isNaN(at.getTime())) return label;
  if (at.getTime() <= Date.now()) return label + ', resuming';
  const hh = String(at.getHours()).padStart(2, '0');
  const mm = String(at.getMinutes()).padStart(2, '0');
  return label + ', resumes ' + hh + ':' + mm;
}

// statusBadge renders the run status. A paused run carries why it paused when
// the caller has it, so the dashboard distinguishes a run waiting on a human
// from one that restarts by itself at 14:50 — before this the two were the
// same word.
function statusBadge(status, pauseReason) {
  const s = status || 'unknown';
  const labels = {running:'Running',complete:'Complete',failed:'Failed',
                  paused:'Paused',initialized:'Ready',evolving:'Evolving'};
  let label = labels[s] || s;
  if (s === 'paused') {
    const why = pauseReasonText(pauseReason);
    if (why) label += ': ' + why;
  }
  return '<span class="badge '+esc(s)+'"><span class="badge-dot"></span>'+esc(label)+'</span>';
}

function taskIcon(status) {
  const icons = {pending:'◦',in_progress:'◎',done:'✓',failed:'✗',skipped:'⊘'};
  return icons[status] || '◦';
}

function priorityBadge(p) {
  const cls = p<=1?'p1':p<=3?'p2':'p3';
  return '<span class="task-priority '+cls+'">P'+p+'</span>';
}

