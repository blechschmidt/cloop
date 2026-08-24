// ── Live output ──────────────────────────────────────────────────────────────

function appendLiveLog(chunk) {
  liveLogText += chunk;
  // Keep at most ~liveLogMaxLines worth of content (trimmed from top).
  const lines = liveLogText.split('\n');
  if (lines.length > 500) {
    liveLogText = lines.slice(lines.length - 500).join('\n');
  }
  renderLiveLog();
}

function renderLiveLog() {
  const box = document.getElementById('liveOutputBox');
  if (!box) return;
  // Use a text node for safe rendering of raw output.
  box.textContent = liveLogText;
  // Blinking cursor appended when running.
  const wrap = document.getElementById('liveOutputWrap');
  const isRunning = appState && appState.status === 'running';
  if (wrap) wrap.classList.toggle('live-output-running', isRunning);
  if (isRunning) {
    const cur = document.createElement('span');
    cur.className = 'live-cursor';
    cur.setAttribute('aria-hidden', 'true');
    box.appendChild(cur);
  }
  if (liveLogAutoScroll) {
    box.scrollTop = box.scrollHeight;
  }
  // Mirror live output into the synthetic "current step" entry in Step History,
  // so the running step shows up-to-date output without rebuilding the list.
  const runningOut = document.getElementById('stepRunningOutput');
  if (runningOut) {
    runningOut.textContent = liveLogText ? liveLogText.slice(-4000) : '(awaiting output…)';
  }
}

window.clearLiveLog = function() {
  liveLogText = '';
  renderLiveLog();
};

// ── Real-time push: WebSocket (primary) with SSE fallback ────────────────────

// wsBackoff tracks the reconnect delay for WebSocket (ms).
let wsBackoff = 1000;
let wsConn = null;      // active WebSocket
let sseUsed = false;    // true when we fell back to SSE

// ── Presence ─────────────────────────────────────────────────────────────────

// myClientID: set on first WS presence message so we can highlight "you".
let myClientID = null;

// renderPresenceBar updates the presence indicator strip below the header.
function renderPresenceBar(users) {
  const bar = document.getElementById('presenceBar');
  if (!bar) return;
  if (!users || users.length === 0) { bar.innerHTML = ''; return; }

  let html = '<span class="presence-label">&#x1F465; Online:</span>';
  for (const u of users) {
    const isYou = u.id === myClientID;
    const initials = u.name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2);
    const cls = isYou ? 'presence-avatar you' : 'presence-avatar';
    const tip = isYou ? u.name + ' (you)' : u.name;
    html += '<div class="' + cls + '" style="background:' + u.color + '" title="' + tip + '">'
          + initials
          + '<span class="presence-tooltip">' + tip + '</span>'
          + '</div>';
  }
  bar.innerHTML = html;
}

// ── Conflict toast ────────────────────────────────────────────────────────────

let _conflictDismissTimer = null;

function showConflictToast(msg) {
  const toast = document.getElementById('conflictToast');
  const msgEl = document.getElementById('conflictMsg');
  if (!toast) return;
  if (msgEl) msgEl.textContent = msg || 'Another user edited this task recently.';
  toast.classList.add('visible');
  clearTimeout(_conflictDismissTimer);
  _conflictDismissTimer = setTimeout(dismissConflictToast, 6000);
}

window.dismissConflictToast = function() {
  const toast = document.getElementById('conflictToast');
  if (toast) toast.classList.remove('visible');
  clearTimeout(_conflictDismissTimer);
};

// ── Client ID (sent with every REST mutation for conflict detection) ──────────

// Persist a per-tab client ID so the server can detect concurrent edits.
let _clientID = sessionStorage.getItem('cloop-client-id');
if (!_clientID) {
  _clientID = 'ui-' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
  sessionStorage.setItem('cloop-client-id', _clientID);
}

// Intercept fetch to inject X-Client-ID on every mutating request.
(function() {
  const _orig = window.fetch.bind(window);
  window.fetch = function(url, opts) {
    if (opts && opts.method && opts.method !== 'GET' && opts.method !== 'HEAD') {
      opts.headers = Object.assign({}, opts.headers || {}, { 'X-Client-ID': _clientID });
    }
    return _orig(url, opts);
  };
})();

// ── Stream scoping (Task 20197) ──────────────────────────────────────────────
//
// A realtime frame carries no project identity. The server puts that identity
// in the *subscription*: a stream opened with ?project_idx=N joins that
// project's hub room and receives only its events. So the project a frame
// belongs to is a property of the stream that delivered it, and the client has
// to remember it — nothing in the payload can be consulted after the fact.
//
// Two interleavings make that remembering necessary, and both were reproduced
// against this bundle before the guard existed (see testdata/scoping_-
// scenarios.js):
//
//   1. Switching projects closes the old socket and opens a new one, but
//      close() only *starts* a handshake. Frames already in flight on the old
//      socket still reach onmessage, after selectedProjectIdx has moved on.
//   2. The projects landing page holds a stream with no project_idx, which
//      resolveWorkDir resolves to the primary project. Clicking into a project
//      leaves that stream's in-flight frames — full state for a project the
//      user did not open — arriving under the new selection.
//
// In both cases the old guard (`selectedProjectIdx === null`) let the frame
// through: it answers "is a project selected", not "is this frame for the
// project that is selected".
//
// Types that carry one project's data. Everything else (projects, executor_-
// update, audit_append, secrets_update, resync, error) is fleet-wide and is
// broadcast to every room, so it must not be filtered.
//
// presence is deliberately absent: it describes who is connected to the room,
// which is meaningful on the projects landing page too. It is filtered by
// stream identity rather than by project — see below.
const PROJECT_SCOPED_EVENTS = new Set([
  'task_update', 'state_diff', 'task_added', 'task_deleted', 'task_mutation',
  'step_output', 'run_state', 'suggest_status', 'provider_call',
]);

// _streamScope captures what the current selection is, to be frozen into a
// stream at the moment it is opened.
function _streamScope() {
  return {idx: selectedProjectIdx};
}

// _isCurrentStream reports whether `scope` describes the stream the UI is
// currently driven by. null matches null: the landing page's fleet-wide stream
// is the current one while no project is selected.
function _isCurrentStream(scope) {
  if (!isMultiProject) return true;   // one project, one stream, no index space
  return (scope ? scope.idx : null) === selectedProjectIdx;
}

// _scopeAccepts reports whether a project-scoped frame delivered by a stream
// opened for `scope` may be applied to the UI now.
//
// Identity is the stream's captured index, not anything in the frame: an
// unscoped stream (idx null) is bound server-side to the primary project, so
// it is never a match for a selected project — which is precisely case 2.
function _scopeAccepts(scope) {
  if (!isMultiProject) return true;
  // Landing page: no project is being rendered, so no per-project frame is.
  // Belt to the server's braces — a current server sends no project frames on
  // a scope=global stream at all, but an older one predates that contract.
  if (selectedProjectIdx === null) return false;
  return _isCurrentStream(scope);
}

// handleRealtimeMsg dispatches a typed message from either WebSocket or SSE.
// scope is the stream's captured selection (see _streamScope); it is absent
// only for synthetic calls, which are treated as belonging to the current
// selection.
function handleRealtimeMsg(type, data, scope) {
  const from = scope === undefined ? _streamScope() : scope;
  if (PROJECT_SCOPED_EVENTS.has(type) && !_scopeAccepts(from)) return;
  // Presence is per-room, so a superseded stream would paint the previous
  // project's collaborators over the current one's.
  if (type === 'presence' && !_isCurrentStream(from)) return;

  // Set after the scope gate, not before: a frame from a superseded stream
  // says nothing about whether the *current* stream is healthy.
  const dot = document.getElementById('liveDot');
  if (dot) dot.classList.add('connected');

  // Task 20118: every realtime kind below corresponds to one or more rows
  // freshly written to the events journal (task_started, task_done,
  // evolve_round_start, plan_complete, …). Schedule a debounced top-page
  // reload so the Event History panel stays live without polling.
  switch (type) {
    case 'task_update':
    case 'state_diff':
    case 'task_added':
    case 'task_deleted':
    case 'task_mutation':
    case 'run_state':
      try { _scheduleEventHistoryRefresh(); } catch(_) {}
      break;
  }

  // Task 20126: any push that could change a chart triggers a debounced
  // analytics refresh; if the analytics tab is hidden, the scheduler is a
  // cheap no-op. Replaces the old 30s self-poll inside loadAnalytics.
  switch (type) {
    case 'task_update':
    case 'state_diff':
    case 'task_added':
    case 'task_deleted':
    case 'task_mutation':
    case 'run_state':
    case 'step_output':
    case 'provider_call':
      try { _scheduleAnalyticsRefresh(); } catch(_) {}
      break;
  }

  // Note: 'plan_complete' is *not* a WebSocket type — it lives only in
  // the persisted event log and webhook channel. Plan completion arrives
  // here as the final task_update flipping the last task to 'done', plus
  // a 'run_state' event flipping running=false. See TestDashboard_NoDead-
  // FrontendWSCases for the architectural invariant.
  switch (type) {
    case 'task_update':
      // Visibility is settled by the scope gate at the top of this function
      // (Task 20197): reaching here means the delivering stream is the one
      // opened for the currently-selected project.
      try { render(data); } catch(_) {}
      // Analytics refresh is scheduled by the dispatch switch above
      // (Task 20126) — no inline call here.
      break;
    case 'state_diff':
      // Task 20132: server ships only the delta against its cached snapshot
      // (tasks_added / tasks_removed / tasks_changed / state_changed). Apply
      // to local appState and re-render.
      //
      // A delta is the more dangerous of the two to misroute: applyStateDiff
      // merges into whatever appState holds, so a frame from the wrong stream
      // splices another project's tasks into this project's list rather than
      // replacing it. The scope gate above is what keeps that from happening.
      try { applyStateDiff(data); } catch(_) {}
      break;
    case 'step_output':
      try { if (data.chunk) appendLiveLog(data.chunk); } catch(_) {}
      break;
    case 'projects':
      try {
        renderProjects(data.projects || [], data.stats || {});
        updateProjectSelector();
        // Task 20134: no per-project /api/state refetch here. The selected
        // project's state is kept fresh via the state_diff events delivered
        // on the same WS subscription (see broadcastStateDiff in watchProjects).
        // Refresh the overview cards if on the overview tab with no project selected.
        if (isMultiProject && selectedProjectIdx === null && activeTab === 'overview') {
          renderMultiProjectOverview();
        }
      } catch(_) {}
      break;
    case 'presence':
      try {
        // Remember own ID on first presence message.
        if (data.you && !myClientID) myClientID = data.you;
        renderPresenceBar(data.users || []);
      } catch(_) {}
      break;
    case 'task_mutation':
      // Task 20132: the actual state change rides on a paired state_diff
      // event. This handler only surfaces the conflict toast / hint UI.
      try {
        if (data.state) {
          // Legacy server (pre Task 20132): payload still has full state.
          // Scope-gated above like every other project-scoped kind.
          render(data.state);
        }
        if (data.conflict) {
          const taskTitle = data.task && data.task.title ? '"' + data.task.title + '"' : 'a task';
          showConflictToast('Another user edited ' + taskTitle + ' at the same time. Review the latest version.');
        }
      } catch(_) {}
      break;
    case 'task_added':
    case 'task_deleted':
      // Task 20132: state mutation is delivered as a separate state_diff
      // event broadcast just before this one. Legacy server may still ship
      // the full state in data.state — apply it if present for backwards
      // compat with older daemons.
      try {
        if (data.state) { render(data.state); }
      } catch(_) {}
      break;
    case 'run_state':
      // Server pushes this whenever the cloop process running flag flips
      // for this project (start/stop/external-detect). Replaces the old
      // /api/livelog poll loop.
      //
      // Task 20134: no /api/state refetch when running flips to false — the
      // server's watchProjects loop pushes a state_diff for any task whose
      // status transitions, and the run-stop handlers in handleRun/handleStop
      // also broadcast a fresh state_diff. The tab title (▶ <task>) clears
      // naturally on the next state_diff.
      try {
        if (data && typeof data.running !== 'undefined') {
          updateRunButtonState(!!data.running);
        }
      } catch(_) {}
      break;
    case 'suggest_status':
      // Server pushes this on suggest job state changes. Replaces the old
      // /api/suggest/status poll loop.
      try { applySuggestStatus(data); } catch(_) {}
      break;
    case 'provider_call':
      // pkg/provideraudit pushes one envelope per Provider.Complete with the
      // summary fields (no prompt/response — those come from the detail
      // endpoint when the user opens the modal). Append to the live list.
      try { _pcAppendLive(data); } catch(_) {}
      break;
    case 'executor_update':
      // A device enrolled, went online/offline, was revoked, or a project
      // was re-pointed (Task 20160). The envelope carries only the event
      // name and executor ID; the join of registry + storage + bindings
      // lives in one place, so we re-read it rather than patching a local
      // mirror that would drift from it. Cheap: this fires on fleet
      // transitions, not on a timer.
      try {
        if (activeTab === 'executors' || activeTab === 'overview') { loadExecutors(); }
        // A fleet change is an audited event, so the trail grew too.
        if (activeTab === 'audit') { loadAudit(); }
      } catch(_) {}
      break;
    case 'audit_append':
      // The trail grew (Task 20167). The envelope carries only the action
      // name, never row contents: this fans out to every connected client
      // regardless of role, and the trail is admin-only. Clients re-read
      // GET /api/audit, where the permission is actually enforced — so a
      // viewer receiving this message learns nothing and their refetch is
      // refused. Only refresh when the panel is open and the user is on
      // page one; paging back to the top under someone reading page 4
      // would be worse than a slightly stale view.
      try {
        if (activeTab === 'audit' && auditState.offset === 0) { loadAudit(); }
      } catch(_) {}
      break;
    case 'secrets_update':
      // A secret, grant, or lease changed (Task 20171). Same discipline as
      // audit_append: the envelope carries only the event name and an ID, so
      // a viewer who receives it learns nothing and the refetch it would
      // trigger is refused by the route gate. Only the open panel re-reads.
      try {
        if (activeTab === 'secrets') { loadSecretsPanel(); }
      } catch(_) {}
      break;
    case 'resync':
      // Server signalled that this client fell behind and dropped events.
      // Re-fetch full state so the UI catches up. (See Task 20040.)
      try {
        const url = (typeof pUrl === 'function' && isMultiProject) ? pUrl('/api/state') : '/api/state';
        api(url).then(s => { try { render(s); } catch(_) {} }).catch(() => {});
        if (isMultiProject) {
          api('/api/projects').then(d => {
            try {
              renderProjects(d.projects || [], d.stats || {});
              updateProjectSelector();
            } catch(_) {}
          }).catch(() => {});
        }
      } catch(_) {}
      break;
    case 'error':
      console.warn('cloop ws error:', data);
      break;
  }
}

// Builds the /api/ws URL with auth + project_idx params so the server-side
// hub registers this connection under the currently-selected project. The
// resulting subscription delivers task_update / state_diff events for that
// project only, removing the need to refetch /api/state on project switch
// (Task 20134).
function _streamParams() {
  const params = [];
  if (authToken) params.push('token=' + encodeURIComponent(authToken));
  if (isMultiProject && selectedProjectIdx !== null) {
    params.push('project_idx=' + encodeURIComponent(selectedProjectIdx));
  } else if (isMultiProject) {
    // The projects landing page wants fleet-wide events only. Saying so is
    // what stops the server from resolving the missing index to the primary
    // project and streaming its state to a client that renders none of it —
    // frames that used to arrive under whichever project the user opened next
    // (Task 20197). Single-project mode never sends this, so its stream keeps
    // being primed exactly as before.
    params.push('scope=global');
  }
  return params.length ? '?' + params.join('&') : '';
}

function _wsURL() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return proto + '//' + location.host + '/api/ws' + _streamParams();
}

function connectWS() {
  // Already fell back to SSE: re-open that stream instead of retrying an
  // upgrade this proxy has shown it will block. The reconnect still matters
  // — every caller of connectWS() is a project switch, and the server scopes
  // an SSE stream to the project it resolved at connect time (Task 20189),
  // so without this the fallback path would stay pinned to whichever project
  // was selected when the page loaded.
  if (sseUsed) {
    connectSSE();
    return;
  }
  if (wsConn) {
    // Mark this close as intentional so onclose doesn't probe /api/state and
    // schedule a backoff reconnect — the immediate new WebSocket() handles it.
    wsConn._intentional = true;
    wsConn.close();
    wsConn = null;
  }
  const url   = _wsURL();
  const dot   = document.getElementById('liveDot');

  // Frozen with the URL: _wsURL() encodes this same selection as project_idx,
  // so the scope and the subscription the server creates from it are decided
  // in the same breath and cannot drift apart (Task 20197).
  const scope = _streamScope();

  let ws;
  try { ws = new WebSocket(url); } catch(_) { _fallbackToSSE(); return; }
  wsConn = ws;

  ws.onopen = () => {
    wsBackoff = 1000; // reset on successful connect
    sseUsed = false;
    if (dot) dot.classList.add('connected');
    // A socket for a project the user has already navigated away from must not
    // hydrate the log panel: pUrl() would resolve against the *current*
    // selection, pulling the new project's log on the old project's event.
    if (!_scopeAccepts(scope)) return;
    // On reconnect also refresh the live log buffer in case we missed output.
    api(pUrl('/api/livelog')).then(d => {
      if (d.lines && d.lines.length) {
        liveLogText = d.lines.join('');
        renderLiveLog();
      }
    }).catch(() => {});
  };

  ws.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      handleRealtimeMsg(msg.type, msg.data, scope);
    } catch(_) {}
  };

  ws.onclose = (ev) => {
    const intentional = !!(ws && ws._intentional);
    wsConn = null;
    if (dot) dot.classList.remove('connected');
    // Intentional close (project switch) is already followed by a new
    // WebSocket() in the same call stack — don't probe or backoff.
    if (intentional) return;
    // If the close was a normal shutdown or we haven't tried SSE yet on the
    // first connection, probe the state endpoint to detect auth failures.
    fetch('/api/state', {headers: authHeaders()}).then(r => {
      if (r.status === 401) { showLoginModal(); return; }
      // Exponential backoff reconnect (cap at 30 s).
      const delay = Math.min(wsBackoff, 30000);
      wsBackoff = Math.min(wsBackoff * 2, 30000);
      setTimeout(connectWS, delay);
    }).catch(() => {
      const delay = Math.min(wsBackoff, 30000);
      wsBackoff = Math.min(wsBackoff * 2, 30000);
      setTimeout(connectWS, delay);
    });
  };

  ws.onerror = () => {
    // onerror is always followed by onclose; fallback only if WebSocket is
    // not supported at all (readyState stuck at CONNECTING).
    if (ws.readyState !== WebSocket.OPEN && ws.readyState !== WebSocket.CONNECTING) {
      _fallbackToSSE();
    }
  };
}

// _fallbackToSSE: used when WebSocket upgrades are blocked by a proxy.
function _fallbackToSSE() {
  if (sseUsed) return; // already in SSE mode
  sseUsed = true;
  connectSSE();
}

function connectSSE() {
  if (evtSource) evtSource.close();
  // Carries project_idx for the same reason _wsURL() does: the server binds
  // the stream to the project it resolves here and filters project-scoped
  // events against it (Task 20189).
  evtSource = new EventSource('/api/events' + _streamParams());
  // Same capture as the WebSocket path, for the same reason: an EventSource is
  // bound server-side to the project it resolved at connect time, and close()
  // does not retract frames already written to the response (Task 20197).
  const scope = _streamScope();
  const dot = document.getElementById('liveDot');
  evtSource.onopen = () => {
    dot.classList.add('connected');
    if (!_scopeAccepts(scope)) return;
    api(pUrl('/api/livelog')).then(d => {
      if (d.lines && d.lines.length) {
        liveLogText = d.lines.join('');
        renderLiveLog();
      }
    }).catch(() => {});
  };
  evtSource.onmessage = (e) => {
    try {
      handleRealtimeMsg('task_update', JSON.parse(e.data), scope);
    } catch(_) {}
  };
  evtSource.addEventListener('log', (e) => {
    try { handleRealtimeMsg('step_output', JSON.parse(e.data), scope); } catch(_) {}
  });
  evtSource.addEventListener('projects', (e) => {
    try { handleRealtimeMsg('projects', JSON.parse(e.data), scope); } catch(_) {}
  });
  evtSource.addEventListener('run_state', (e) => {
    try { handleRealtimeMsg('run_state', JSON.parse(e.data), scope); } catch(_) {}
  });
  evtSource.addEventListener('suggest_status', (e) => {
    try { handleRealtimeMsg('suggest_status', JSON.parse(e.data), scope); } catch(_) {}
  });
  evtSource.addEventListener('resync', (e) => {
    try { handleRealtimeMsg('resync', JSON.parse(e.data), scope); } catch(_) {}
  });
  evtSource.onerror = () => {
    dot.classList.remove('connected');
    evtSource.close();
    evtSource = null;
    // SSE fallback reconnect probe — detect auth failures before reconnect.
    // Intentionally global (no pUrl): selectedProjectIdx context is rebuilt
    // by the projects payload that arrives after reconnect.
    fetch('/api/state', {headers: authHeaders()}).then(r => {
      if (r.status === 401) {
        showLoginModal();
      } else {
        setTimeout(connectSSE, 3000);
      }
    }).catch(() => setTimeout(connectSSE, 3000));
  };
}

// Track user scroll in live output to disable auto-scroll when they scroll up.
