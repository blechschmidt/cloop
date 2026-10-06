// ── Render overview ─────────────────────────────────────────────────────────

// ── Deferred panels (Tasks 20366, 20379, 20386) ─────────────────────────────
// Fetched the first time the page needs them rather than bundled: first paint
// has no room for panels most sessions never open (static.go,
// deferredScripts). Each runs outside this IIFE, so it is handed the helpers
// it calls — panelHelpers() unless the caller passes its own — and the one
// global it defines is its factory, window.cloop<Name>Panel. A fetch or a
// factory that fails is retried by the next call, not replayed forever.
const _deferred = {};
function deferredPanel(name, helpers) {
  if (!_deferred[name]) {
    const p = _deferred[name] = new Promise((ok, no) => {
      const m = document.querySelector('meta[name="cloop-' + name + '-src"]');
      const el = document.createElement('script');
      el.src = m ? m.getAttribute('content') : '';
      el.onload = () => {
        const f = window['cloop' + name[0].toUpperCase() + name.slice(1) + 'Panel'];
        try { f ? ok(f(helpers || panelHelpers())) : no(new Error(name + ' defined no panel')); } catch (e) { no(e); }
      };
      el.onerror = () => no(new Error(name + ' could not be fetched'));
      document.head.appendChild(el);
    });
    p.catch(() => { if (_deferred[name] === p) delete _deferred[name]; });
  }
  return _deferred[name];
}

// What the Settings and admin panels are handed (Task 20386): their whole view
// of this IIFE, built on first use. fleet reads the executor list's cached
// auto-update policy, or stores and draws a new one; oidc says whether the hub
// has sign-on.
let _ph;
function panelHelpers() {
  return _ph || (_ph = {
    api, apiMethod, esc, toast, canGlobal, pUrl, relTime, refreshState, applyPermissionGating,
    mount: mountPanel, panel: deferredPanel, fmtBytes: _duFmtBytes,
    execAt: _execAt, execKind: _execKindLabel, execErr: _execDetailErrText,
    fleet: d => d ? _renderAutoUpdateBar(fleetAutoUpdate = d) : fleetAutoUpdate, oidc: () => myOIDC,
    fw: {sum: _fwSum, form: _fwForm, read: _fwRead, refusal: _fwRefusal},
    quota: {label: _quotaLabel, labels: _quotaLabels, fmt: _quotaFmt, saturation: _quotaSaturation},
  });
}

// mountPanel puts a deferred panel's markup on the page — its tab's contents,
// and its dialogs appended to the document body — and routes its data-act,
// data-change, data-input, data-enter and data-dismiss (a backdrop click) to
// the panel's own functions in fns, which its script may not put on window
// for an inline handler to reach. Delegated from each root, so markup the
// panel redraws later is routed too. Returns fns.
function mountPanel(fns, tab, html, dialogs) {
  const roots = [];
  if (tab) {
    const box = document.getElementById('tab-' + tab);
    box.innerHTML = html;
    roots.push(box);
  }
  if (dialogs) {
    const t = document.createElement('div');
    t.innerHTML = dialogs;
    Array.from(t.children).forEach(el => roots.push(document.body.appendChild(el)));
  }
  roots.forEach(root => ['click', 'change', 'input', 'keydown'].forEach(type => root.addEventListener(type, e => {
    if (type === 'click' && e.target === root && root.dataset.dismiss) return fns[root.dataset.dismiss]();
    const key = type === 'click' ? 'act' : type === 'keydown' ? 'enter' : type;
    const el = e.target.closest && e.target.closest('[data-' + key + ']');
    if (!el || (type === 'keydown' && e.key !== 'Enter')) return;
    if (type === 'keydown') e.preventDefault();
    fns[el.dataset[key]].call(el, el.dataset.arg);
  })));
  applyPermissionGating();
  return fns;
}

// The tabs whose markup and code arrive on their first open (Task 20386). The
// panel's open() runs on every visit, as their bundled loaders used to.
const DEFERRED_TABS = ['settings', 'budget', 'secrets', 'audit', 'quotas', 'telemetry'];
function openDeferredTab(name) {
  const box = document.getElementById('tab-' + name);
  if (!_deferred[name]) box.innerHTML = '<p class="deferred-note">Loading…</p>';
  return deferredPanel(name).then(p => { if (activeTab === name) p.open(); },
    () => deferredFailed(() => openDeferredTab(name), box));
}

// deferredFailed says a deferred panel did not arrive and offers to fetch it
// again — in box, the tab that would otherwise stay empty, or for a dialog in
// a banner of its own.
function deferredFailed(retry, box) {
  const banner = !box;
  if (banner) {
    box = document.getElementById('deferredFail') || document.body.appendChild(document.createElement('div'));
    box.id = 'deferredFail';
  }
  box.innerHTML = '<p class="deferred-note" role="alert">This part of the dashboard did not load. ' +
    '<button class="btn">Retry</button>' + (banner ? ' <button class="btn" aria-label="Dismiss">&times;</button>' : '') + '</p>';
  const [again, dismiss] = box.querySelectorAll('button');
  if (again) again.onclick = () => { if (banner) box.remove(); retry(); };
  if (dismiss) dismiss.onclick = () => box.remove();
}

// panelAct runs fn of a deferred panel, fetching the panel first: the shim
// through which bundled markup — an executor card's buttons — reaches a
// deferred dialog. With no fn it resolves to the panel itself.
function panelAct(name, fn, ...a) {
  return deferredPanel(name).then(p => fn ? p[fn](...a) : p,
    () => deferredFailed(() => panelAct(name, fn, ...a)));
}
window.panelAct = panelAct;

// panelIf calls fn of a panel that has been loaded, and does nothing for one
// that has not: a broadcast refreshes what is on screen, it never fetches code.
function panelIf(name, fn) {
  const p = _deferred[name];
  if (p) p.then(x => x[fn] && x[fn](), () => {});
}
// No project on screen: none selected, or in single-project mode none loaded.
const _noProject = () => isMultiProject ? selectedProjectIdx === null : !appState;
const _overviewIdx = () => selectedProjectIdx === null ? 0 : selectedProjectIdx;
// The Members card (Task 20366): project sharing exists only with sign-on.
const _membersOff = () => !myOIDC || _noProject();
function loadProjectMembers() {
  loadHarnessCred();
  if (_membersOff()) return;
  return deferredPanel('members', {
    api, apiMethod, esc, toast, left: clearProjectSelection, idx: _overviewIdx, hidden: _membersOff,
  }).then(p => p.load()).catch(() => {});
}
// The Claude credential card and dialog (Task 20379). opts.open shows the
// dialog — for opts.idx, the grid's project, and with opts.refusal, the 409
// that sent the user there.
function loadHarnessCred(opts) {
  if (!opts && _noProject()) return;
  return deferredPanel('harness', {
    api, esc, toast, openOverlay, closeOverlay, idx: _overviewIdx,
  }).then(p => p.load(opts)).catch(() => opts && opts.refusal && toast(opts.refusal.error, 'err'));
}
// harnessRefused handles a dispatch's 409 for a sandbox with no Claude login:
// a short toast, and the dialog that grants one opens with the full reason —
// the whole sentence in a toast would sit over the dialog's own buttons on a
// phone for as long as it shows.
function harnessRefused(d, idx) {
  if (!d || !/^harness_cred/.test(d.code)) return false;
  toast('Refused: this sandbox has no usable Claude credential', 'err');
  loadHarnessCred({open: true, refusal: d, idx});
  return true;
}

// applyStateDiff merges a server-side state_diff envelope into the local
// appState and then re-renders. The envelope shape (Task 20132):
//
//   {
//     tasks_added:   [<full task obj>, ...],
//     tasks_removed: [<id>, ...],
//     tasks_changed: [{id, ...changed fields}, ...],
//     state_changed: {<top-level field>: <value>, ...}
//   }
//
// Applied idempotently: adding a task that already exists by ID is treated
// as a field-merge; removing a task that's already gone is a no-op. This
// keeps the client consistent if it receives a diff before its initial
// /api/state response (race on first connect) or after a reconnect/resync.
function applyStateDiff(diff) {
  if (!diff || typeof diff !== 'object') return;
  if (!appState) appState = {};
  if (!appState.plan)       appState.plan       = {tasks: []};
  if (!appState.plan.tasks) appState.plan.tasks = [];

  // Top-level scalar fields (goal, status, model, etc.).
  if (diff.state_changed && typeof diff.state_changed === 'object') {
    for (const [k, v] of Object.entries(diff.state_changed)) {
      if (k === 'plan') {
        // Plan-level fields (goal, version). Tasks are handled separately.
        if (v && typeof v === 'object') {
          if (!appState.plan) appState.plan = {tasks: []};
          for (const [pk, pv] of Object.entries(v)) {
            if (pk === 'tasks') continue;
            if (pv === null) delete appState.plan[pk];
            else             appState.plan[pk] = pv;
          }
        } else if (v === null) {
          appState.plan = {tasks: []};
        }
      } else if (v === null) {
        delete appState[k];
      } else {
        appState[k] = v;
      }
    }
  }

  // Removed tasks.
  if (Array.isArray(diff.tasks_removed) && diff.tasks_removed.length) {
    const removed = new Set(diff.tasks_removed);
    appState.plan.tasks = appState.plan.tasks.filter(t => !removed.has(t.id));
  }

  // Added tasks (idempotent: existing ID becomes a field merge).
  if (Array.isArray(diff.tasks_added) && diff.tasks_added.length) {
    const byId = new Map();
    for (let i = 0; i < appState.plan.tasks.length; i++) {
      const t = appState.plan.tasks[i];
      if (t && typeof t.id === 'number') byId.set(t.id, i);
    }
    for (const t of diff.tasks_added) {
      if (!t || typeof t.id !== 'number') continue;
      if (byId.has(t.id)) {
        appState.plan.tasks[byId.get(t.id)] = Object.assign({}, appState.plan.tasks[byId.get(t.id)], t);
      } else {
        appState.plan.tasks.push(t);
      }
    }
  }

  // Changed tasks — shallow field merge. Null values clear the field.
  if (Array.isArray(diff.tasks_changed) && diff.tasks_changed.length) {
    const byId = new Map();
    for (let i = 0; i < appState.plan.tasks.length; i++) {
      const t = appState.plan.tasks[i];
      if (t && typeof t.id === 'number') byId.set(t.id, i);
    }
    for (const change of diff.tasks_changed) {
      if (!change || typeof change.id !== 'number') continue;
      const idx = byId.get(change.id);
      if (idx === undefined) continue; // unknown ID — wait for tasks_added on next round
      const target = appState.plan.tasks[idx];
      for (const [k, v] of Object.entries(change)) {
        if (k === 'id') continue;
        if (v === null) delete target[k];
        else            target[k] = v;
      }
    }
  }

  render(appState);
}

function render(s) {
  appState = s;

  // Sync Run/Stop button state from project status.
  if (typeof updateRunButtonState === 'function') {
    updateRunButtonState(isActiveRunStatus(s.status) || runWaits(s));
  }

  // In multi-project mode with no project selected, don't overwrite the UI
  // with single-project data from WebSocket events or stale fetches.
  if (isMultiProject && selectedProjectIdx === null) return;

  const multiPanel = document.getElementById('multiProjectOverview');
  if (multiPanel) multiPanel.style.display = 'none';

  const hasProject = s && s.goal;
  document.getElementById('initPanel').style.display    = hasProject ? 'none' : '';
  document.getElementById('projectPanel').style.display = hasProject ? '' : 'none';
  // The Tasks tab's run bar (Task 20253) has nothing to start until a project
  // exists, and an uninitialised project would only answer Start with an error.
  setTasksRunBarVisible(!!hasProject);
  if (!hasProject) return;

  // Goal
  const goalEl = document.getElementById('goalText');
  goalEl.textContent = s.goal;
  goalEl.classList.toggle('empty', !s.goal);

  // Instructions / constraints (persisted in state.json:instructions)
  const instrEl = document.getElementById('instructionsText');
  if (instrEl) {
    const instr = (typeof s.instructions === 'string') ? s.instructions : '';
    instrEl.textContent = instr || 'No instructions set';
    instrEl.classList.toggle('empty', !instr);
  }

  // Update the "Overview" section title to show the selected project name in multi-project mode.
  const overviewTitle = document.getElementById('overviewSectionTitle');
  if (overviewTitle) {
    overviewTitle.textContent = (isMultiProject && selectedProjectName) ? 'Overview — ' + selectedProjectName : 'Overview';
  }

  // Status badge — carries the pause reason, so "paused" says which wall the
  // run hit and, for a usage cap, when it lifts (Task 20285).
  document.getElementById('statusBadge').innerHTML = statusBadge(s.status, s.pause_reason);

  renderAbortedLedgerBanner(s);

  // Sync Run/Stop button visibility from project status. Without this the
  // buttons rely on WebSocket 'run_state' events, which may not have arrived
  // yet on initial render, page refresh, or project tab switch — leaving
  // both buttons visible (default HTML state).
  updateRunButtonState(isActiveRunStatus(s.status) || runWaits(s));

  // Stats
  // Task 20125: backend now ships steps_count instead of the full steps[]
  // array. Fall back to steps.length for older payloads.
  const steps = (typeof s.steps_count === 'number') ? s.steps_count : (s.steps || []).length;
  document.getElementById('statSteps').textContent    = steps;
  document.getElementById('statStepsSub').textContent = s.max_steps > 0 ? 'of '+s.max_steps+' max' : 'unlimited';
  document.getElementById('statProvider').textContent = s.provider || 'claudecode';
  document.getElementById('statModel').textContent    = (s.model || '') + (s.effort ? ' @ ' + s.effort : '');
  prepopulateAdvancedRunOptions(s);
  renderActiveOptions(s);
  renderReviewGateCard(s);
  renderFeaturePanels();
  if (typeof updateCCLimitsVisibility === 'function') updateCCLimitsVisibility(s.provider || 'claudecode');
  document.getElementById('statMode').textContent     = 'Product Manager';
  document.getElementById('statCreated').textContent  = fmtDate(s.created_at);
  document.getElementById('statUpdated').textContent  = fmtDate(s.updated_at);

  const ti = s.total_input_tokens || 0, to = s.total_output_tokens || 0;
  document.getElementById('statTokens').textContent    = fmtNum(ti + to);
  document.getElementById('statTokensSub').textContent = ti > 0 ? fmtNum(ti)+' in / '+fmtNum(to)+' out' : '';

  // Estimated cost
  const usd = estimateCost(s.provider || '', s.model || '', ti, to);
  const costCard = document.getElementById('statCostCard');
  if (usd !== null && (ti > 0 || to > 0)) {
    costCard.style.display = '';
    document.getElementById('statCost').textContent = usd === 0 ? '$0 (local)' : '$' + usd.toFixed(usd < 0.01 ? 4 : 2);
    document.getElementById('statCostSub').textContent = (s.provider || '') + (s.model ? ' / '+s.model : '');
  } else {
    costCard.style.display = 'none';
  }

  // Event history: a project switch loads the newest page; rows written
  // later arrive as history_append pushes, never by re-reading (Task 20384).
  syncStepHistory(s);

  // Rebuild filter dropdowns from current task list.
  if (s.plan && s.plan.tasks) {
    rebuildTagOptions(s.plan.tasks);
    rebuildAssigneeOptions(s.plan.tasks);
    _restoreFilterInputs();
    _updateFilterClearBtn();
  }

  // Tasks tab
  if (activeTab === 'tasks')  renderTasks(s);
  // Kanban tab
  if (activeTab === 'kanban') renderKanban(s);

  // Timeline tab: refresh on state change so the 'now' cursor and bar colors stay current.
  if (activeTab === 'timeline') loadTimeline();

  document.getElementById('updatedAt').textContent = s.updated_at ? fmtDate(s.updated_at) : '';

  // Update live output running indicator.
  renderLiveLog();

  // Reflect the currently-running task in the browser tab title and
  // sidebar tooltips. Driven entirely by the state already pushed via
  // task_update / run_state events — no extra polling.
  updateBrowserTitle();

  // Re-gate after every render: panels rebuild their controls from scratch,
  // so a control created by this pass has not been through
  // applyPermissionGating yet. Cheap — one querySelectorAll over the
  // elements that opt in via data-perm.
  applyPermissionGating();
}

// _runningTaskTitle holds the title of the in-progress task on the
// currently-selected project (empty when nothing is running). Used by
// updateBrowserTitle() and renderProjects() so the browser tab and the
// sidebar tooltip stay in sync without re-fetching state.
let _runningTaskTitle = '';

function updateBrowserTitle() {
  let title = '';
  if (appState && appState.plan && Array.isArray(appState.plan.tasks)) {
    const inProg = appState.plan.tasks.find(t => t && t.status === 'in_progress');
    if (inProg) title = inProg.title || ('Task #' + inProg.id);
  }
  if (!title && appState && isActiveRunStatus(appState.status)) {
    title = appState.status === 'evolving' ? 'Evolving the plan…' : 'Running…';
  }
  const prev = _runningTaskTitle;
  _runningTaskTitle = title;
  // Truncate so the OS tab doesn't overflow.
  const display = title.length > 60 ? title.slice(0, 57) + '…' : title;
  document.title = display ? '▶ ' + display + ' — cloop' : 'cloop';
  // If the running title flipped, refresh the project sidebar so the
  // tooltip on the selected project entry reflects the new task.
  if (prev !== title && window._lastProjectsData) {
    try { renderProjects(window._lastProjectsData.projects, window._lastProjectsData.stats); } catch(_) {}
  }
}

// renderMultiProjectOverview shows a card grid summary of all projects on the
// Overview tab when no specific project is selected in multi-project mode.
// renderAbortedLedgerBanner surfaces tasks the plan believes it finished whose
// entire recorded summary is a provider or harness refusal (Task 20224).
//
// The overview is where this belongs because of what it invalidates. Every
// figure on this page — steps, tokens, the task counts the progress bar is
// drawn from — is computed over a plan that counts those tasks as done. On this
// project fourteen of them were counted for roughly a hundred iterations while
// three of the features they named were absent from the tree entirely.
function renderAbortedLedgerBanner(s) {
  const el = document.getElementById('abortedLedgerBanner');
  if (!el) return;
  const tasks = (s && s.plan && s.plan.tasks) || [];
  // Only tasks still *filed as finished* count. A reopened one is pending and
  // already queued to run, so it is no longer a claim the plan is making about
  // work that happened — same condition as pm.Plan.UnverifiedAborts.
  const open = tasks.filter(isOpenAbortFinding);
  if (!open.length) { el.style.display = 'none'; el.innerHTML = ''; return; }

  // Group by class so the banner names the cause rather than just a count:
  // "8 usage_limit" tells an operator to wait, "3 harness_refused" tells them
  // to go and fix the host.
  const byClass = {};
  open.forEach(t => { byClass[t.abort.class] = (byClass[t.abort.class] || 0) + 1; });
  const parts = Object.keys(byClass).sort().map(c =>
    byClass[c] + ' × ' + esc(abortClassLabel(c)));

  const ids = open.slice(0, 12).map(t => '#' + t.id).join(', ') +
              (open.length > 12 ? ', …' : '');

  el.style.display = '';
  el.innerHTML =
    '<div class="ledger-banner-head"><span class="lb-glyph">⚠</span>' +
    open.length + ' task' + (open.length === 1 ? '' : 's') +
    ' recorded as done never actually ran</div>' +
    '<div class="ledger-banner-body">' +
      'Their stored summary is a provider or harness refusal, not a description of work: ' +
      parts.join(', ') + '. The plan does not count them as complete and auto-evolve ' +
      'will not plan new work on top of them. Reopen each one from the Tasks tab to run it ' +
      'for real, or record there that a later task already did it.' +
    '</div>' +
    '<div class="ledger-banner-ids">' + esc(ids) + '</div>';
}

function renderMultiProjectOverview() {
  const panel    = document.getElementById('multiProjectOverview');
  const initP    = document.getElementById('initPanel');
  const projP    = document.getElementById('projectPanel');
  if (!panel) return;
  if (initP) initP.style.display = 'none';
  if (projP) projP.style.display = 'none';
  panel.style.display = '';

  const data = window._lastProjectsData;
  const grid = document.getElementById('multiProjectCards');
  if (!grid) return;
  if (!data || !data.projects || !data.projects.length) {
    grid.innerHTML = '<div class="empty-state"><h3>No projects loaded</h3><p>Use <code>cloop ui --projects /path/a /path/b</code> to add projects.</p></div>';
    return;
  }
  // This is the second place the project list is drawn, and hiding has to
  // reach both — a project that disappears from the Projects tab but still
  // fills a card here has not been hidden, it has been misplaced. Index
  // before filtering: the card's openProject() call addresses the project by
  // its position in the *unfiltered* payload.
  // Features (Task 20341) are summarised by their project, as on the grid.
  const listed = function(path) { return data.projects.some(function(q) { return q.path === path; }); };
  const shown = data.projects.map(function(p, i) { return {p: p, i: i}; })
                             .filter(function(e) { return !e.p.hidden && !(e.p.parent && listed(e.p.parent)); });
  if (!shown.length) {
    grid.innerHTML = '<div class="empty-state"><h3>All projects hidden</h3><p>Restore them under <strong>Settings &rarr; Hidden Projects</strong>.</p></div>';
    return;
  }
  grid.innerHTML = shown.map(function(entry) {
    const p = entry.p, i = entry.i;
    const health   = p.health || 'unknown';
    const hCol     = healthColor(health);
    const total    = p.total_tasks || 0;
    const done     = p.done_tasks  || 0;
    const pct      = total > 0 ? Math.round(100 * done / total) : -1;
    const nameSafe = JSON.stringify(p.name).replace(/"/g, '&quot;');
    const valueStr = pct >= 0 ? pct + '% done' : (p.total_steps || 0) + ' steps';
    const subStr   = pct >= 0 ? done + '/' + total + ' tasks' : (p.status || '');
    const modelStr = [p.provider, p.model].filter(Boolean).join(' / ');
    return '<div class="stat-card" style="cursor:pointer" onclick="openProject('+i+','+nameSafe+')" title="Open project">' +
      '<div class="stat-label" style="font-weight:600">' + esc(p.name) + '</div>' +
      '<div style="font-size:11px;margin:3px 0"><span style="color:' + hCol + '">&#9679;</span> ' + esc(health) + '</div>' +
      '<div class="stat-value" style="font-size:15px;margin-top:4px">' + esc(valueStr) + '</div>' +
      '<div class="stat-sub">' + esc(subStr) + '</div>' +
      (modelStr ? '<div style="font-size:10px;color:var(--muted);margin-top:4px" title="Provider / Model">' + esc(modelStr) + '</div>' : '') +
    '</div>';
  }).join('');
}

// ── Event history (Tasks 20118, 20384) ──────────────────────────────────────
//
// One feed of the project's steps and events — task starts, completions,
// skips, kills, evolve rounds, status changes — newest first, read from
// GET /api/event-history a page at a time. Rows written after the newest page
// arrive pushed (history_append, handled in 04-realtime.js), so a live run
// costs the panel no requests. It fetches only to fill a gap the cursors
// show: when the hub's sync point on connect is above the list's top, when a
// push does not continue from it, or after a resync. Pages it holds are never
// read again.
//
// Two positions, sent back as the hub gave them: top, the newest step and
// event the list has seen ([step, event]), and bottom, the place of its last
// row ([day, kind, key]), where the next page down starts.
//
// State variable names keep the "steps" prefix for git-blame readability —
// they hold heterogeneous entries now (each has a .kind discriminator).

const STEP_PAGE_SIZE = 50;

// loaded: entries, newest first (kind === "step" or an event type); top and
// bottom: the positions above; held: frames that arrived during the fetch in
// flight, unset when none is; hasMore: more pages may exist; scopeKey: which
// project's entries these are. Unset fields read as their empty values.
let stepsState = {loaded: []};

function _stepsScopeKey() {
  return (isMultiProject ? ('p' + (selectedProjectIdx === null ? '-' : selectedProjectIdx)) : 'single');
}

function _resetStepsState() {
  stepsState = {loaded: [], hasMore: true, scopeKey: _stepsScopeKey()};
}

// _entryKey returns a stable identifier for an entry across re-renders so
// the expand/collapse state survives re-fetches. Steps key on step number;
// events key on the (negative) server id from the events table.
function _entryKey(e) {
  if (!e) return '';
  if (e.kind === 'step') return 's' + (typeof e.step === 'number' ? e.step : e.id);
  return 'e' + e.id;
}

// An expanded row whose output or details the feed shortened loads in full.
window.toggleStep = function(el) {
  el.classList.toggle('expanded');
  const e = stepsState.loaded.find(x => _entryKey(x) === el.dataset.idx);
  if (e && e.cut) api(pUrl('/api/event-history?' + (e.kind === 'step' ? 'step=' + e.step : 'event=' + -e.id))).then(d => {
    Object.assign(e, d.entries[0], {cut: 0});
    renderStepListPanel();
  }, () => {});
};

// syncStepHistory is called from render(s): a project switch loads the new
// project's newest page; anything else only redraws (the running step).
function syncStepHistory(s) {
  if (_stepsScopeKey() !== stepsState.scopeKey) {
    _resetStepsState();
    _historyFetch('limit=' + STEP_PAGE_SIZE);
  } else renderStepListPanel();
}

// _historyFetch reads one page. how: 'older' for the page below bottom, 1 for
// the rows above top, absent for the newest page — which an above-top read
// answering with a gap also is.
async function _historyFetch(q, how) {
  const st = stepsState;
  if (st.held) return;
  st.held = [];
  renderStepListPanel();
  try {
    const d = await api(pUrl('/api/event-history?' + q)), e = d.entries || [];
    if (st !== stepsState) return;
    if (how === 'older') { _historyAdd(e); st.bottom = d.bottom; st.hasMore = d.more; }
    else if (how && !d.gap) { _historyAdd(e, 1); st.top = d.top; }
    else Object.assign(st, {loaded: e, top: d.top, bottom: d.bottom, hasMore: d.more});
  } catch (_) { /* a failed page down keeps what arrived meanwhile; a failed first page waits for the next push */ }
  const held = st.held;
  st.held = null;
  if (st.top) held.forEach(_historyPush);
  renderStepListPanel();
}

// _historyPush applies a history_append frame: rows written above m.from, up
// to m.to. One that does not continue from the list's top means the list
// missed rows, which one read past the top fills.
function _historyPush(m) {
  const st = stepsState, t = st.top;
  if (st.held) return st.held.push(m);
  // Nothing loaded: a failed first page is retried; before the first one
  // starts, the page will be newer than the frame anyway.
  if (!t) return st.scopeKey === _stepsScopeKey() && _historyFetch('limit=' + STEP_PAGE_SIZE);
  if (m.gap || m.from[0] > t[0] || m.from[1] > t[1]) return _historyFetch('after=' + t + '&limit=500', 1);
  _historyAdd(m.entries, 1);
  st.top = [Math.max(t[0], m.to[0]), Math.max(t[1], m.to[1])];
  renderStepListPanel();
}

// _historyAdd puts entries above (atTop) or below the list, skipping any it
// already holds.
function _historyAdd(list, atTop) {
  const seen = new Set(stepsState.loaded.map(_entryKey));
  const add = (list || []).filter(e => !seen.has(_entryKey(e)));
  stepsState.loaded = atTop ? add.concat(stepsState.loaded) : stepsState.loaded.concat(add);
}

function loadMoreSteps() {
  const b = stepsState.bottom;
  if (b && stepsState.hasMore) _historyFetch('before=' + b + '&limit=' + STEP_PAGE_SIZE, 'older');
}

// _eventVisuals maps an event kind to icon glyph + CSS class + short label.
// Unknown kinds fall back to a neutral bullet so the row still renders.
function _eventVisuals(kind) {
  switch (kind) {
    case 'task_started':        return { glyph:'▶', cls:'ev-task-start',  label:'started'   };
    case 'task_done':           return { glyph:'✓', cls:'ev-task-done',   label:'done'      };
    case 'task_failed':         return { glyph:'✗', cls:'ev-task-fail',   label:'failed'    };
    case 'task_skipped':        return { glyph:'⊘', cls:'ev-task-skip',   label:'skipped'   };
    case 'task_killed':         return { glyph:'☠', cls:'ev-task-kill',   label:'killed'    };
    case 'task_heal':           return { glyph:'⚠', cls:'ev-task-heal',   label:'heal'      };
    case 'task_added':          return { glyph:'+',      cls:'ev-task-add',    label:'added'     };
    case 'task_added_external': return { glyph:'+',      cls:'ev-task-add',    label:'external'  };
    case 'task_deleted':        return { glyph:'−', cls:'ev-task-del',    label:'deleted'   };
    case 'task_status_change':  return { glyph:'⇄', cls:'ev-task-status', label:'status'    };
    // Work an agent left running after reporting the task complete. Its own
    // row because it explains the two things a status cannot: why a task sat
    // running long after its agent stopped talking, and why a task whose
    // output said TASK_DONE was not accepted as done.
    case 'task_background':     return { glyph:'⏳', cls:'ev-task-bg',     label:'background'};
    case 'task_review':         return { glyph:'🔍', cls:'ev-task-review', label:'review'};
    // A run that produced no work — a provider limit, a rejected credential,
    // a harness that refused to start. Distinct from 'failed': the task went
    // back in the queue rather than being judged, so the row must not read as
    // a terminal outcome.
    case 'task_aborted':        return { glyph:'⚠', cls:'ev-task-abort',  label:'aborted'   };
    // The run stopped while the task was executing, so the task went back to
    // pending for the next run. Not a verdict on the task, so not 'failed'.
    case 'task_interrupted':    return { glyph:'⏸', cls:'ev-task-status', label:'interrupted'};
    case 'evolve_round_start':  return { glyph:'↻', cls:'ev-evolve',      label:'evolve'    };
    case 'evolve_discovered':   return { glyph:'✨', cls:'ev-evolve',      label:'discovered'};
    case 'evolve_no_op':        return { glyph:'—', cls:'ev-evolve',      label:'no-op'     };
    // What an isolated executor returned of a task's work. Its own row rather
    // than a note on task_done: a task can succeed and its work still fail to
    // come back, and that run has to be visible as its own line.
    case 'write_back':          return { glyph:'⎇', cls:'ev-writeback',   label:'write-back'};
    case 'plan_complete':       return { glyph:'★', cls:'ev-plan',        label:'plan done' };
    case 'feature_created':     return { glyph:'⎇', cls:'ev-feature',     label:'feature'   };
    case 'feature_removed':     return { glyph:'⎇', cls:'ev-feature',     label:'removed'   };
    case 'feature_pr':          return { glyph:'⇪', cls:'ev-feature',     label:'pull req.' };
    case 'session_started':     return { glyph:'▷', cls:'ev-session',     label:'session'   };
    case 'session_paused':      return { glyph:'⏸', cls:'ev-session',     label:'paused'    };
    case 'session_failed':      return { glyph:'✗', cls:'ev-session',     label:'failed'    };
    default:                    return { glyph:'•', cls:'ev-other',       label:kind || ''  };
  }
}

// Local HH:MM:SS: toTimeString starts with exactly that (ECMA-262 TimeString).
function _formatEntryTime(ts) {
  const d = new Date(ts || NaN);
  return isNaN(d) ? '' : d.toTimeString().slice(0, 8);
}

function _renderStepRow(e, expanded) {
  const idx = _entryKey(e);
  const isExp = expanded[idx] ? ' expanded' : '';
  const exitCls = e.exit_code === 0 ? 'step-ok' : 'step-bad';
  return '<div class="step-item'+isExp+'" data-idx="'+idx+'" onclick="toggleStep(this)">'+
    '<div class="step-header">'+
      '<span class="step-num">#'+((e.step||0)+1)+'</span>'+
      '<span class="step-task">'+esc(e.message||'(no description)')+'</span>'+
      '<div class="step-meta">'+
        (e.duration?'<span>'+esc(e.duration)+'</span>':'')+
        '<span class="'+exitCls+'">'+(e.exit_code===0?'OK':'exit '+e.exit_code)+'</span>'+
      '</div>'+
      '<span class="step-chevron">&#9654;</span>'+
    '</div>'+
    '<div class="step-output">'+esc(e.output||'')+'</div>'+
  '</div>';
}

function _renderEventRow(e, expanded) {
  if (!e) return '';
  const idx = _entryKey(e);
  const isExp = expanded[idx] ? ' expanded' : '';
  const v = _eventVisuals(e.kind);
  const taskRef = e.task_id ? ('#' + e.task_id + (e.task_title ? ' ' + e.task_title : '')) : '';
  const detailsTxt = (e.details && typeof e.details === 'object' && Object.keys(e.details).length)
    ? JSON.stringify(e.details, null, 2) : '';
  const expandable = !!(detailsTxt || e.cut);
  const cls = 'step-item event-row' + (expandable ? ' expandable' : '') + isExp;
  const onclick = expandable ? ' onclick="toggleStep(this)"' : '';
  const chevron = expandable ? '<span class="step-chevron">&#9654;</span>' : '';
  const msg = e.message || (taskRef ? (v.label + ' ' + taskRef) : v.label);
  const showRef = taskRef && (!e.message || e.message.indexOf('#'+e.task_id) === -1);
  return '<div class="'+cls+'" data-idx="'+idx+'"'+onclick+'>'+
    '<div class="step-header">'+
      '<span class="event-icon '+v.cls+'" title="'+esc(e.kind||'')+'">'+v.glyph+'</span>'+
      '<span class="event-msg">'+esc(msg)+'</span>'+
      '<div class="step-meta">'+
        (showRef ? '<span class="event-task-ref">'+esc(taskRef)+'</span>' : '')+
        '<span class="event-time">'+esc(_formatEntryTime(e.timestamp))+'</span>'+
      '</div>'+
      chevron+
    '</div>'+
    (expandable ? '<div class="step-output">'+esc(detailsTxt)+'</div>' : '')+
  '</div>';
}

function renderStepListPanel() {
  const stepListEl = document.getElementById('stepList');
  if (!stepListEl) return;
  const s = appState || {};
  const isRunning = isActiveRunStatus(s.status);

  if (!stepsState.loaded.length && !isRunning && !stepsState.held) {
    stepListEl.innerHTML = '<div class="empty-state"><h3>No events yet</h3><p>Start a run to see history here.</p></div>';
    return;
  }

  // Preserve expand/collapse state across re-renders.
  const expanded = {};
  stepListEl.querySelectorAll('.step-item.expanded').forEach(el => { expanded[el.dataset.idx] = true; });

  let html = '';
  if (isRunning) {
    const runningExp = expanded['running'] ? ' expanded' : '';
    // Use steps_count (not the history's length — which counts events too)
    // as the running step number; the orchestrator increments per shell step.
    const stepsTotal = (typeof s.steps_count === 'number') ? s.steps_count : 0;
    const runningStepNum = (typeof s.current_step === 'number' ? s.current_step : stepsTotal) + 1;
    let runningTitle = '';
    if (s.plan && s.plan.tasks) {
      const inProg = s.plan.tasks.find(t => t.status === 'in_progress');
      if (inProg) runningTitle = '#' + inProg.id + ' ' + (inProg.title || '');
    }
    if (!runningTitle) runningTitle = s.status === 'evolving' ? 'Evolving the plan…' : 'Running…';
    const runningOut = (typeof liveLogText !== 'undefined' && liveLogText) ? liveLogText.slice(-4000) : '(awaiting output…)';
    html += '<div class="step-item step-running'+runningExp+'" data-idx="running" onclick="toggleStep(this)">'+
      '<div class="step-header">'+
        '<span class="step-num">#'+runningStepNum+'</span>'+
        '<span class="step-task">'+esc(runningTitle)+'</span>'+
        '<div class="step-meta">'+
          '<span class="step-running-dot" aria-hidden="true"></span>'+
          '<span class="step-running-label">running</span>'+
        '</div>'+
        '<span class="step-chevron">&#9654;</span>'+
      '</div>'+
      '<div class="step-output" id="stepRunningOutput">'+esc(runningOut)+'</div>'+
    '</div>';
  }

  // stepsState.loaded is already latest-first; entries are heterogeneous —
  // step rows render in the original chrome, non-step events render compactly
  // with a coloured icon + human-readable message (Task 20118).
  html += stepsState.loaded.map((entry) => {
    return (entry && entry.kind === 'step')
      ? _renderStepRow(entry, expanded)
      : _renderEventRow(entry, expanded);
  }).join('');

  // Footer: progress + sentinel for the IntersectionObserver. No total: the
  // feed does not count its rows (Task 20384), so the sum is shown once known.
  if (stepsState.loaded.length) {
    html += stepsState.hasMore
      ? '<div class="step-load-more" id="stepLoadMore">' + (stepsState.held ? 'Loading more events…' : 'Scroll to load more') + '</div>'
      : '<div class="step-load-more">All ' + stepsState.loaded.length + ' events loaded</div>';
  }

  stepListEl.innerHTML = html;
  _attachStepScrollObserver();
}

let _stepIO = null;
function _attachStepScrollObserver() {
  const sentinel = document.getElementById('stepLoadMore');
  if (!sentinel) return;
  if (!('IntersectionObserver' in window)) return; // fall back to scroll handler below
  if (_stepIO) { try { _stepIO.disconnect(); } catch(_){} _stepIO = null; }
  _stepIO = new IntersectionObserver(entries => {
    for (const e of entries) {
      if (e.isIntersecting) loadMoreSteps();
    }
  }, { rootMargin: '300px' });
  _stepIO.observe(sentinel);
}

// Defensive scroll fallback for browsers without IntersectionObserver, and to
// catch the case where the sentinel is already in-viewport on render (rare).
window.addEventListener('scroll', function() {
  if (activeTab !== 'overview') return;
  if (!stepsState.hasMore || stepsState.held) return;
  const sentinel = document.getElementById('stepLoadMore');
  if (!sentinel) return;
  const rect = sentinel.getBoundingClientRect();
  if (rect.top < window.innerHeight + 300) loadMoreSteps();
}, { passive: true });

