// ── Render overview ─────────────────────────────────────────────────────────

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
    updateRunButtonState(s.status === 'running');
  }

  // In multi-project mode with no project selected, don't overwrite the UI
  // with single-project data from WebSocket events or stale fetches.
  if (isMultiProject && selectedProjectIdx === null) return;

  const multiPanel = document.getElementById('multiProjectOverview');
  if (multiPanel) multiPanel.style.display = 'none';

  const hasProject = s && s.goal;
  document.getElementById('initPanel').style.display    = hasProject ? 'none' : '';
  document.getElementById('projectPanel').style.display = hasProject ? '' : 'none';
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

  // Status badge
  document.getElementById('statusBadge').innerHTML = statusBadge(s.status);

  // Sync Run/Stop button visibility from project status. Without this the
  // buttons rely on WebSocket 'run_state' events, which may not have arrived
  // yet on initial render, page refresh, or project tab switch — leaving
  // both buttons visible (default HTML state).
  updateRunButtonState(s.status === 'running');

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

  // Steps — lazy-loaded from /api/steps with infinite scroll. The state's
  // s.steps.length tells us when new steps appear so we can refresh the top
  // page; older steps stay loaded and scroll-position is preserved.
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
  if (!title && appState && appState.status === 'running') {
    title = 'Running…';
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
  grid.innerHTML = data.projects.map(function(p, i) {
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

window.toggleStep = function(el) { el.classList.toggle('expanded'); };

// ── Event history lazy loading (Task 20118) ─────────────────────────────────
//
// The history panel was previously a step-only feed sourced from /api/steps.
// Task 20118 replaced it with a unified event journal that merges step
// results with task starts, completions, skips, kills, evolve rounds,
// status changes, etc. Backend feed: GET /api/event-history.
//
// State variable names keep the "steps" prefix for git-blame readability —
// they hold heterogeneous entries now (each has a .kind discriminator).

const STEP_PAGE_SIZE = 50;

let stepsState = {
  loaded: [],     // entries, latest-first (kind === "step" or event type)
  total: 0,       // total entry count on the server (steps + events)
  loading: false, // a fetch is in flight
  hasMore: true,  // more pages may exist
  scopeKey: '',   // identifies which project's entries are loaded
};

function _stepsScopeKey() {
  return (isMultiProject ? ('p' + (selectedProjectIdx === null ? '-' : selectedProjectIdx)) : 'single');
}

function _resetStepsState() {
  stepsState = { loaded: [], total: 0, loading: false, hasMore: true, scopeKey: _stepsScopeKey() };
}

async function _fetchStepsPage(offset, limit) {
  return api(pUrl('/api/event-history?offset=' + offset + '&limit=' + limit));
}

// _entryKey returns a stable identifier for an entry across re-renders so
// the expand/collapse state survives re-fetches. Steps key on step number;
// events key on the (negative) server id from the events table.
function _entryKey(e) {
  if (!e) return '';
  if (e.kind === 'step') return 's' + (typeof e.step === 'number' ? e.step : e.id);
  return 'e' + e.id;
}

// syncStepHistory is called from render(s). It decides whether to reload the
// top page (because new entries appeared, or the project changed) or just
// re-render the panel (e.g. running-step indicator update). Non-step events
// are picked up via _scheduleEventHistoryRefresh() called from the WS handler.
function syncStepHistory(s) {
  const newScope = _stepsScopeKey();
  if (newScope !== stepsState.scopeKey) {
    _resetStepsState();
    _loadInitialSteps();
    return;
  }
  // s.steps_count is a strict lower bound on the merged entry total — enough
  // to detect new step writes from the orchestrator. Non-step events arrive
  // via the WS-triggered refresh in handleRealtimeMsg.
  let stepsCount = 0;
  if (s && typeof s.steps_count === 'number') stepsCount = s.steps_count;
  else if (s && Array.isArray(s.steps))       stepsCount = s.steps.length;
  if (stepsCount > 0 && stepsState.loaded.length === 0) {
    _reloadStepsTopPage(STEP_PAGE_SIZE);
    return;
  }
  renderStepListPanel();
}

// _scheduleEventHistoryRefresh debounces refetches of the top page after
// WebSocket events that may have appended event rows (task starts, task
// completions, evolves, etc.). Multiple rapid events collapse into a single
// /api/event-history fetch.
let _eventHistoryRefreshTimer = null;
function _scheduleEventHistoryRefresh() {
  if (_eventHistoryRefreshTimer) clearTimeout(_eventHistoryRefreshTimer);
  _eventHistoryRefreshTimer = setTimeout(() => {
    _eventHistoryRefreshTimer = null;
    const wanted = Math.max(STEP_PAGE_SIZE, stepsState.loaded.length);
    _reloadStepsTopPage(wanted);
  }, 250);
}

async function _loadInitialSteps() {
  await _reloadStepsTopPage(STEP_PAGE_SIZE);
}

async function _reloadStepsTopPage(limit) {
  if (stepsState.loading) return;
  stepsState.loading = true;
  renderStepListPanel();
  try {
    const data = await _fetchStepsPage(0, limit);
    if (data && Array.isArray(data.entries)) {
      stepsState.loaded = data.entries;
      stepsState.total  = (typeof data.total === 'number') ? data.total : data.entries.length;
      stepsState.hasMore = stepsState.loaded.length < stepsState.total;
    }
  } catch (_) { /* leave previous loaded list intact */ }
  stepsState.loading = false;
  renderStepListPanel();
}

async function loadMoreSteps() {
  if (stepsState.loading || !stepsState.hasMore) return;
  stepsState.loading = true;
  renderStepListPanel();
  try {
    const data = await _fetchStepsPage(stepsState.loaded.length, STEP_PAGE_SIZE);
    if (data && Array.isArray(data.entries) && data.entries.length) {
      // Server may have more entries now than when we started; keep total fresh.
      stepsState.total = (typeof data.total === 'number') ? data.total : (stepsState.loaded.length + data.entries.length);
      // Dedup by stable key (rare race when a new entry arrives mid-fetch).
      const seen = new Set(stepsState.loaded.map(_entryKey));
      for (const ent of data.entries) {
        const k = _entryKey(ent);
        if (!seen.has(k)) { stepsState.loaded.push(ent); seen.add(k); }
      }
      stepsState.hasMore = stepsState.loaded.length < stepsState.total;
    } else if (data && typeof data.total === 'number') {
      stepsState.total = data.total;
      stepsState.hasMore = stepsState.loaded.length < stepsState.total;
    }
  } catch (_) { /* swallow; user can scroll again */ }
  stepsState.loading = false;
  renderStepListPanel();
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
    case 'evolve_round_start':  return { glyph:'↻', cls:'ev-evolve',      label:'evolve'    };
    case 'evolve_discovered':   return { glyph:'✨', cls:'ev-evolve',      label:'discovered'};
    case 'evolve_no_op':        return { glyph:'—', cls:'ev-evolve',      label:'no-op'     };
    // What an isolated executor returned of a task's work. Its own row rather
    // than a note on task_done: a task can succeed and its work still fail to
    // come back, and that run has to be visible as its own line.
    case 'write_back':          return { glyph:'⎇', cls:'ev-writeback',   label:'write-back'};
    case 'plan_complete':       return { glyph:'★', cls:'ev-plan',        label:'plan done' };
    case 'session_started':     return { glyph:'▷', cls:'ev-session',     label:'session'   };
    case 'session_paused':      return { glyph:'⏸', cls:'ev-session',     label:'paused'    };
    case 'session_failed':      return { glyph:'✗', cls:'ev-session',     label:'failed'    };
    default:                    return { glyph:'•', cls:'ev-other',       label:kind || ''  };
  }
}

function _formatEntryTime(ts) {
  if (!ts) return '';
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return '';
    const hh = String(d.getHours()).padStart(2,'0');
    const mm = String(d.getMinutes()).padStart(2,'0');
    const ss = String(d.getSeconds()).padStart(2,'0');
    return hh + ':' + mm + ':' + ss;
  } catch(_) { return ''; }
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
  const expandable = !!detailsTxt;
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
  const isRunning = s.status === 'running';

  if (!stepsState.loaded.length && !isRunning && !stepsState.loading) {
    stepListEl.innerHTML = '<div class="empty-state"><h3>No events yet</h3><p>Start a run to see history here.</p></div>';
    return;
  }

  // Preserve expand/collapse state across re-renders.
  const expanded = {};
  stepListEl.querySelectorAll('.step-item.expanded').forEach(el => { expanded[el.dataset.idx] = true; });

  let html = '';
  if (isRunning) {
    const runningExp = expanded['running'] ? ' expanded' : '';
    // Use steps_count (not stepsState.total — which now counts events) as
    // the running step number; the orchestrator increments per shell step.
    const stepsTotal = (typeof s.steps_count === 'number') ? s.steps_count : 0;
    const runningStepNum = (typeof s.current_step === 'number' ? s.current_step : stepsTotal) + 1;
    let runningTitle = '';
    if (s.plan && s.plan.tasks) {
      const inProg = s.plan.tasks.find(t => t.status === 'in_progress');
      if (inProg) runningTitle = '#' + inProg.id + ' ' + (inProg.title || '');
    }
    if (!runningTitle) runningTitle = 'Running…';
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

  // Footer: progress + sentinel for the IntersectionObserver.
  if (stepsState.total > 0) {
    if (stepsState.hasMore) {
      const label = stepsState.loading
        ? 'Loading more events…'
        : 'Showing ' + stepsState.loaded.length + ' of ' + stepsState.total + ' — scroll to load more';
      html += '<div class="step-load-more" id="stepLoadMore">'+esc(label)+'</div>';
    } else {
      html += '<div class="step-load-more">All ' + stepsState.total + ' events loaded</div>';
    }
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
      if (e.isIntersecting && stepsState.hasMore && !stepsState.loading) {
        loadMoreSteps();
      }
    }
  }, { rootMargin: '300px' });
  _stepIO.observe(sentinel);
}

// Defensive scroll fallback for browsers without IntersectionObserver, and to
// catch the case where the sentinel is already in-viewport on render (rare).
window.addEventListener('scroll', function() {
  if (activeTab !== 'overview') return;
  if (!stepsState.hasMore || stepsState.loading) return;
  const sentinel = document.getElementById('stepLoadMore');
  if (!sentinel) return;
  const rect = sentinel.getBoundingClientRect();
  if (rect.top < window.innerHeight + 300) loadMoreSteps();
}, { passive: true });

