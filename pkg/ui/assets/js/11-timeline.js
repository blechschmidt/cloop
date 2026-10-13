// ── Timeline (Gantt) tab ─────────────────────────────────────────────────────
// The chart itself is deferred/timeline.js (Task 20427). loadTimeline redraws
// it where it is loaded: a state change, a filter or a theme toggle never
// fetches its code.
function loadTimeline() { panelIf('timeline', 'open'); }

// ── Actions ─────────────────────────────────────────────────────────────────

act('refreshState', function() {
  api(pUrl('/api/state')).then(s => { render(s); toast('Refreshed', 'ok'); }).catch(() => toast('Load failed', 'err'));
});

// updateRunButtonState shows the Run button when not running, Stop when running.
//
// It positions every copy of that pair: the Overview tab's Controls section and
// the Tasks tab's run bar (Task 20253). Driving them from one function is the
// point — two independently-updated pairs would eventually disagree, and a
// "Start run" button on a project that is already running invites the duplicate
// dispatch that handleRun now refuses.
function updateRunButtonState(running) {
  const showIds = running ? ['ctrlStop', 'tasksCtrlStop'] : ['ctrlRun', 'tasksCtrlRun'];
  const hideIds = running ? ['ctrlRun', 'tasksCtrlRun'] : ['ctrlStop', 'tasksCtrlStop'];
  showIds.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = ''; });
  hideIds.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = 'none'; });

  // Say which of the two states the button belongs to. Without it a lone
  // "Start run" reads as an offer that may or may not have been acted on
  // already, since this page shows no project status of its own.
  const status = document.getElementById('tasksRunStatus');
  if (status) {
    const p = runBarStatus(running);
    status.className = 'badge ' + p.cls;
    status.innerHTML = '<span class="badge-dot"></span>' + esc(p.label);
  }
}

// runBarStatus is what the Tasks tab's run bar says beside its button: the
// project's own status in the Overview's words, so an evolve round reads
// "Evolving" there too and a paused run says why (Task 20358). Where the status
// and `running` (what the button was just positioned from) disagree, the
// button wins, or the two would contradict each other side by side: a run that
// has started but not yet written its status is Running, and a stored
// running/evolving claim the button no longer believes (a stop just sent, a run
// that died without saying so) is only "Not running".
function runBarStatus(running) {
  const st = appState ? appState.status : '';
  if (running && runWaits(appState)) return statusParts(st, appState.pause_reason);
  if (running) return statusParts(isActiveRunStatus(st) ? st : 'running');
  if (!st || isActiveRunStatus(st)) return {cls: 'unknown', label: 'Not running'};
  return statusParts(st, appState.pause_reason);
}

// Run-state changes are pushed by the server as 'run_state' WebSocket events
// (see handleRealtimeMsg). No polling required.

// apiRun starts a run. All run options are read by the server from persisted
// project state — toggle them via the Active Options badges or Provider card.
act('apiRun', function() {
  api(pUrl('/api/run'), {}).then(d => {
    if (d.ok) {
      toast('Started: '+d.command, 'ok');
      updateRunButtonState(true);
    } else if (!harnessRefused(d)) {
      toast(d.error||'Failed to start', 'err');
      // The server refuses a second harness on a project that is already
      // running (Task 20253) and says so with running:true. Believe it over
      // whatever this tab last saw, so the button the user just proved wrong
      // turns into the Stop button that is actually applicable.
      if (d.running) updateRunButtonState(true);
    }
  }).catch(() => toast('Request failed', 'err'));
});

act('apiStop', function() {
  // pUrl scopes the stop to the selected project (?project_idx=N) — without
  // it the server falls back to its own WorkDir, so pressing Stop on any
  // other project's page could never find that project's run (Task 20153).
  api(pUrl('/api/stop'), {}).then(d => {
    toast(d.message || (d.ok ? 'Pause signal sent' : 'Stop failed'), d.ok ? 'ok' : 'err');
    if (d.ok) updateRunButtonState(false);
    // Final running flag is pushed via the 'run_state' WS event when the
    // child process actually exits or the projects watcher samples PID
    // liveness; no client-side poll required.
  }).catch(() => toast('Request failed', 'err'));
});

// ── Init ─────────────────────────────────────────────────────────────────────

act('submitInit', function() {
  const goal = document.getElementById('initGoal').value.trim();
  if (!goal) { toast('Goal is required', 'err'); return; }
  api(pUrl('/api/init'), {
    goal:         goal,
    provider:     document.getElementById('initProvider').value,
    model:        document.getElementById('initModel').value,
    effort:       (document.getElementById('initEffort') || {}).value || '',
    maxSteps:     parseInt(document.getElementById('initMaxSteps').value)||0,
    instructions: document.getElementById('initInstructions').value.trim(),
    pmMode:       document.getElementById('initPMMode').checked,
  }).then(d => {
    if (d.ok) { toast('Project initialized!', 'ok'); refreshState(); }
    else toast(d.error||'Init failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
});

