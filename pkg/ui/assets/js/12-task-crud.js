// ── Task CRUD ────────────────────────────────────────────────────────────────

function parseDepsInput(val) {
  if (!val || !val.trim()) return [];
  return val.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n) && n > 0);
}

window.submitAddTask = function() {
  const title = document.getElementById('newTaskTitle').value.trim();
  if (!title) { toast('Title is required', 'err'); return; }
  api(pUrl('/api/task/add'), {
    title:       title,
    description: document.getElementById('newTaskDesc').value.trim(),
    priority:    parseInt(document.getElementById('newTaskPriority').value)||0,
    depends_on:  parseDepsInput(document.getElementById('newTaskDeps').value),
  }).then(d => {
    if (d.ok) {
      document.getElementById('newTaskTitle').value    = '';
      document.getElementById('newTaskDesc').value     = '';
      document.getElementById('newTaskPriority').value = '';
      document.getElementById('newTaskDeps').value     = '';
      toast('Task added: '+title, 'ok');
      // Optimistically merge the returned task into appState so the row
      // appears immediately, without waiting for the WS state_diff round-trip
      // or a full /api/state refetch. The server still broadcasts a state_diff
      // for this mutation; applyStateDiff is idempotent for adds (existing IDs
      // become a field merge), so the dupe arrival is harmless.
      if (d.task && typeof applyStateDiff === 'function') {
        try { applyStateDiff({tasks_added: [d.task]}); } catch(_) {}
      }
    } else toast(d.error||'Add failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

window.setStatus = function(id, status) {
  api(pUrl('/api/task/status'), {id, status}).then(d => {
    if (d.ok) { toast('Task '+id+': '+status, 'ok'); refreshState(); }
    else toast(d.error||'Update failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

// reopenAbortedTask and clearAbortedTask record the two verdicts available on a
// task whose stored summary is a provider refusal rather than work
// (Task 20224). Until now the only way to act on one of these findings was
// `cloop task audit-ledger --reopen` on the CLI — which is why fourteen of them
// sat unnoticed in this project's own plan for about a hundred iterations.
window.reopenAbortedTask = function(id) {
  api(pUrl('/api/tasks/'+id+'/reopen-aborted'), {}).then(d => {
    if (d.ok) { toast('Task '+id+' reopened — it never ran', 'ok'); refreshState(); }
    else toast(d.error||'Reopen failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

// The note is mandatory server-side: a clearance without a reason cannot be
// told apart from giving up on the audit, and an audit nobody can close is an
// audit that gets ignored. Prompt rather than a modal because the answer is one
// line ("re-landed by Task N") and this is a rare, deliberate action.
window.clearAbortedTask = function(id) {
  const note = window.prompt(
    'This task is recorded as done but its summary is a provider refusal.\n\n' +
    'Where did the work actually land? (e.g. "re-implemented by Task 20016")');
  if (note === null) return;
  if (!note.trim()) { toast('A note is required', 'err'); return; }
  api(pUrl('/api/tasks/'+id+'/clear-aborted'), {note: note.trim()}).then(d => {
    if (d.ok) { toast('Task '+id+': ledger entry checked', 'ok'); refreshState(); }
    else toast(d.error||'Could not clear the finding', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

window.moveTask = function(id, direction) {
  api(pUrl('/api/task/move'), {id, direction}).then(d => {
    if (d.ok) { refreshState(); }
    else toast(d.error||'Move failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

window.removeTask = function(id) {
  pendingDeleteId = id;
  const task = appState && appState.plan && appState.plan.tasks
    ? appState.plan.tasks.find(t => t.id === id) : null;
  const title = task ? task.title : '#' + id;
  document.getElementById('deleteModalMsg').textContent =
    'Delete task "' + title + '"? This action cannot be undone.';
  openOverlay('delete-modal-overlay', {dismiss: closeDeleteModal});
};

window.closeDeleteModal = function() {
  closeOverlay('delete-modal-overlay');
  pendingDeleteId = null;
};

window.executeDeleteTask = function() {
  const id = pendingDeleteId;
  closeDeleteModal();
  if (!id) return;
  apiMethod('DELETE', pUrl('/api/tasks/' + id), null).then(d => {
    if (d.ok) { toast('Task #' + id + ' removed', 'ok'); refreshState(); }
    else toast(d.error || 'Remove failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

// ── Drag-and-drop handlers ───────────────────────────────────────────────────

window.onDragStart = function(e, id) {
  dragSrcId = id;
  e.dataTransfer.effectAllowed = 'move';
  // Use setTimeout so the class is applied after browser snapshot
  setTimeout(() => {
    const el = document.querySelector('.task-item[data-task-id="'+id+'"]');
    if (el) el.classList.add('dragging');
  }, 0);
};

window.onDragOver = function(e, id) {
  e.preventDefault();
  e.dataTransfer.dropEffect = 'move';
  document.querySelectorAll('.task-item').forEach(el => el.classList.remove('drag-over'));
  const el = document.querySelector('.task-item[data-task-id="'+id+'"]');
  if (el && id !== dragSrcId) el.classList.add('drag-over');
};

window.onDragLeave = function(e) {
  e.currentTarget.classList.remove('drag-over');
};

window.onDrop = function(e, targetId) {
  e.preventDefault();
  document.querySelectorAll('.task-item').forEach(el => el.classList.remove('drag-over', 'dragging'));
  const srcId = dragSrcId;
  dragSrcId = null;
  if (srcId === null || srcId === targetId) return;
  if (!appState || !appState.plan || !appState.plan.tasks) return;

  // Splice the queue the user is looking at. This used to re-sort every task in
  // the plan by priority alone and index into *that*, which is a different list
  // from the rendered one whenever a pinned or running row has floated to the
  // top — so a drag across that boundary moved the task somewhere the user had
  // not pointed at, and often nowhere at all: dropping a task onto the pinned
  // row above it produced exactly the order that was already on screen, and the
  // row snapped back (Task 20299).
  const ids = renderedQueue.slice();
  const fromIdx = ids.indexOf(srcId);
  const toIdx   = ids.indexOf(targetId);
  if (fromIdx === -1 || toIdx === -1) return;

  // Pinned tasks lead the queue by definition, so a drop that would interleave
  // the two groups cannot be honoured — priorities alone cannot express it, and
  // silently clamping the task to its own group's edge would look like the drag
  // landed somewhere it did not. Say so instead.
  const byId = appState.plan.tasks;
  const pinnedOf = id => { const t = byId.find(x => x.id === id); return !!(t && t.pinned); };
  if (pinnedOf(srcId) !== pinnedOf(targetId)) {
    // Name the task and the command: pinning has no control in this dashboard,
    // so "unpin it" alone leaves the user with a rule and no way to satisfy it.
    const pinnedId = pinnedOf(srcId) ? srcId : targetId;
    toast('Task #' + pinnedId + ' is pinned, and pinned tasks always run first. ' +
          'Run "cloop task unpin ' + pinnedId + '" to reorder across it.', 'err');
    return;
  }

  ids.splice(fromIdx, 1);
  ids.splice(toIdx, 0, srcId);

  apiMethod('POST', pUrl('/api/tasks/reorder'), {ids}).then(d => {
    if (d.ok) refreshState();
    else toast(d.error || 'Reorder failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

window.onDragEnd = function(e) {
  document.querySelectorAll('.task-item').forEach(el => el.classList.remove('dragging', 'drag-over'));
  dragSrcId = null;
};

// ── Edit modal ───────────────────────────────────────────────────────────────

window.openEditModal = function(id) {
  const tasks = (appState && appState.plan && appState.plan.tasks) || [];
  const t = tasks.find(x => x.id === id);
  if (!t) { toast('Task #' + id + ' not found', 'err'); return; }
  document.getElementById('modalTaskId').value   = t.id;
  document.getElementById('modalTitle_').value   = t.title || '';
  document.getElementById('modalDesc').value     = t.description || '';
  document.getElementById('modalPriority').value = t.priority || 0;
  document.getElementById('modalDeps').value     = (t.depends_on && t.depends_on.length) ? t.depends_on.join(',') : '';
  const mmEl = document.getElementById('modalMaxMinutes');
  if (mmEl) mmEl.value = t.max_minutes || 0;
  openOverlay('modal-overlay', {dismiss: closeModal, focus: '#modalTitle_'});
};

window.closeModal = function() {
  closeOverlay('modal-overlay');
};

// ── Task details modal (read-only execution view) ──────────────────────────

let _tdCurrentId = null;

window.openTaskDetails = function(id) {
  _tdCurrentId = id;
  const overlay = document.getElementById('td-overlay');
  const body    = document.getElementById('td-body');
  if (!overlay || !body) return;
  body.innerHTML = '<div class="td-empty">Loading…</div>';
  openOverlay(overlay, {dismiss: closeTaskDetails});
  // Independent of the details call and of _tdLoadReproductions: attachability
  // is a property of the *live* executor session, not of the stored task, so it
  // must not wait on — or be skipped by a failure of — either (Task 20265).
  _atLoadInfo(id);
  fetch(pUrl('/api/tasks/'+id+'/details'), {credentials:'same-origin'})
    .then(r => r.json())
    .then(d => {
      if (!d || !d.ok) { body.innerHTML = '<div class="td-empty">'+esc(d && d.error || 'Failed to load task details')+'</div>'; return; }
      _renderTaskDetails(d);
    })
    .catch(() => { body.innerHTML = '<div class="td-empty">Request failed</div>'; });
};

// Leaves an open sandbox terminal alone (Task 20265). The two are independent
// modals: the terminal is a live session the reader deliberately opened, and
// tearing it down because they dismissed the task summary behind it would drop
// the output they opened it to watch.
window.closeTaskDetails = function() {
  closeOverlay('td-overlay');
  _tdCurrentId = null;
};

window.taskDetailsEditCurrent = function() {
  const id = _tdCurrentId;
  closeTaskDetails();
  if (id) openEditModal(id);
};

// ── Reproduction (Task 20221) ─────────────────────────────────────────────
//
// The provenance call is cheap and runs when the modal opens; it decides
// whether the button is even pressable and supplies the tooltip explaining
// why not. That ordering matters: a Reproduce button that is always enabled
// and fails with "no recorded commit" on every host-run task would train
// people to ignore it, and the tasks it cannot answer for are the majority on
// a hub that has not adopted isolated executors yet.

// _tdOnHost mirrors orchestrator.RanOnHost: did this task's harness run as a
// process on the hub's own machine, with its filesystem and network?
//
// Either signal alone is enough. The two are written together and should always
// agree; a disagreement is exactly when the warning should fire rather than
// resolve to "fine". A task with no attribution at all — recorded before
// Task 20244 — is unknown, not host, because saying otherwise would
// retroactively accuse every historical task of touching the host.
function _tdOnHost(t) {
  if (!t) return false;
  return t.executor_kind === 'localprocess' ||
         (t.isolation === 'none' && !!t.executor_kind);
}

// _tdExecutorChip renders where a task ran, or nothing when that was never
// recorded. An unattributed task says so rather than defaulting to a
// reassuring value.
function _tdExecutorChip(t) {
  if (!t || (!t.executor_id && !t.executor_kind)) return '';
  const onHost = _tdOnHost(t);
  const label = t.executor_id || t.executor_kind;
  const title = onHost
    ? 'This task ran as a process on the hub host, sharing its filesystem and network — no sandbox boundary.'
    : 'Executor this task was placed on when it started.';
  return '<span class="td-chip'+(onHost ? ' host' : '')+'" title="'+esc(title)+'">'+
         (onHost ? '⚠ Host' : 'Executor')+'<strong>'+esc(label)+'</strong></span>';
}

function _tdVerdictChip(v) {
  const known = ['identical','equivalent','divergent','inconclusive'];
  const cls = known.indexOf(v) >= 0 ? v : 'inconclusive';
  return '<span class="td-verdict '+cls+'">'+esc(v||'inconclusive')+'</span>';
}

function _tdRenderReproductions(list) {
  const host = document.getElementById('td-repro-list');
  if (!host) return;
  if (!list || !list.length) {
    host.innerHTML = '<div class="td-empty">This task has never been reproduced.</div>';
    return;
  }
  host.innerHTML = list.map(r => {
    const c = r.comparison || {};
    let files = '';
    if (c.files_differing && c.files_differing.length) {
      files = '<div class="td-repro-when">'+c.files_differing.length+' file(s) differ</div>';
    }
    return '<div class="td-repro-row">'+
      '<div class="td-repro-head">'+_tdVerdictChip(r.verdict)+
        '<span class="td-repro-when">'+esc(_fmtDateTime(r.created_at))+
        (r.executor_kind ? ' · '+esc(r.executor_kind) : '')+'</span></div>'+
      '<div class="td-repro-reason">'+esc(r.reason||'')+'</div>'+files+
      (r.error ? '<div class="td-repro-warn">'+esc(r.error)+'</div>' : '')+
    '</div>';
  }).join('');
}

function _tdLoadReproductions(id) {
  const btn = document.getElementById('td-reproduce-btn');
  if (btn) { btn.disabled = true; btn.title = 'Checking whether this task can be reproduced…'; }

  fetch(pUrl('/api/tasks/'+id+'/provenance'), {credentials:'same-origin'})
    .then(r => r.json())
    .then(d => {
      if (!btn || _tdCurrentId !== id) return;
      const ok = !!(d && d.ok && d.reproducible);
      btn.disabled = !ok;
      btn.title = (d && d.reason) || 'Reproduce this task in a fresh sandbox and compare the commit';
      const note = document.getElementById('td-repro-note');
      if (note && d) {
        const warns = (d.provenance && d.provenance.warnings) || [];
        note.innerHTML = '<div class="td-repro-reason">'+esc(d.reason||'')+'</div>'+
          warns.map(wm => '<div class="td-repro-warn">'+esc(wm)+'</div>').join('');
      }
    })
    .catch(() => {});

  fetch(pUrl('/api/tasks/'+id+'/reproductions'), {credentials:'same-origin'})
    .then(r => r.json())
    .then(d => { if (_tdCurrentId === id) _tdRenderReproductions(d && d.reproductions); })
    .catch(() => {});
}

window.taskDetailsReproduce = function() {
  const id = _tdCurrentId;
  if (!id) return;
  const btn = document.getElementById('td-reproduce-btn');
  const host = document.getElementById('td-repro-list');
  if (btn) { btn.disabled = true; btn.textContent = 'Reproducing…'; }
  if (host) {
    host.innerHTML = '<div class="td-empty">Running the task again in a fresh sandbox and comparing the '+
      'commit. This takes as long as the original run did.</div>';
  }
  // No timeout on the client: the server bounds this at 20 minutes and a
  // client-side abort would orphan the sandbox without releasing its quota.
  fetch(pUrl('/api/tasks/'+id+'/reproduce'), {
    method:'POST', credentials:'same-origin',
    headers:{'Content-Type':'application/json'}, body:'{}'
  })
    .then(r => r.json())
    .then(d => {
      if (btn) { btn.textContent = 'Reproduce'; btn.disabled = false; }
      if (!d || !d.ok) {
        const msg = (d && (d.message || d.error)) || 'The reproduction could not be run';
        if (host) host.innerHTML = '<div class="td-empty">'+esc(msg)+'</div>';
        toast(msg, false);
        return;
      }
      if (_tdCurrentId === id) _tdLoadReproductions(id);
      toast('Verdict: '+String(d.reproduction && d.reproduction.verdict || '').toUpperCase(),
            !!(d.reproduction && (d.reproduction.verdict === 'identical' || d.reproduction.verdict === 'equivalent')));
    })
    .catch(() => {
      if (btn) { btn.textContent = 'Reproduce'; btn.disabled = false; }
      if (host) host.innerHTML = '<div class="td-empty">Request failed</div>';
    });
};

function _fmtDateTime(s) {
  if (!s) return '';
  const d = new Date(s);
  if (isNaN(d.getTime())) return s;
  return d.toLocaleString();
}

function _fmtDuration(start, end) {
  if (!start) return '';
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  if (isNaN(s) || isNaN(e) || e < s) return '';
  const ms = e - s;
  const sec = Math.round(ms/1000);
  if (sec < 60) return sec + 's';
  const m = Math.floor(sec/60), rs = sec%60;
  if (m < 60) return m + 'm ' + rs + 's';
  const h = Math.floor(m/60), rm = m%60;
  return h + 'h ' + rm + 'm';
}

function _resultSectionLabel(status) {
  if (status === 'failed' || status === 'timed_out') return { cls:'fail', label:'Failure summary' };
  if (status === 'skipped')                          return { cls:'skip', label:'Skip reason' };
  if (status === 'done')                             return { cls:'done', label:'Execution summary' };
  return { cls:'', label:'Latest result' };
}

function _renderTaskDetails(d) {
  const t = d.task || {};
  const body = document.getElementById('td-body');
  document.getElementById('td-title').textContent = 'Task #'+t.id+': '+(t.title||'');

  const status = t.status || 'pending';
  const chips = [];
  chips.push('<span class="td-chip">Status<strong>'+esc(status)+'</strong></span>');
  if (t.priority) chips.push('<span class="td-chip">Priority<strong>P'+t.priority+'</strong></span>');
  if (t.role)     chips.push('<span class="td-chip">Role<strong>'+esc(t.role)+'</strong></span>');
  if (t.assignee) chips.push('<span class="td-chip">Assignee<strong>'+esc(t.assignee)+'</strong></span>');
  if (t.depends_on && t.depends_on.length) chips.push('<span class="td-chip">Deps<strong>#'+t.depends_on.join(', #')+'</strong></span>');
  if (t.tags && t.tags.length) chips.push('<span class="td-chip">Tags<strong>'+t.tags.map(esc).join(', ')+'</strong></span>');
  if (t.estimated_minutes) chips.push('<span class="td-chip">Est<strong>'+t.estimated_minutes+'m</strong></span>');
  if (t.actual_minutes)    chips.push('<span class="td-chip">Actual<strong>'+t.actual_minutes+'m</strong></span>');
  if (t.max_minutes)       chips.push('<span class="td-chip" title="Per-task timeout override. 0 = inherits project default.">Timeout<strong>'+t.max_minutes+'m</strong></span>');
  if (t.fail_count)        chips.push('<span class="td-chip">Failures<strong>'+t.fail_count+'</strong></span>');
  if (t.heal_attempts)     chips.push('<span class="td-chip">Heal attempts<strong>'+t.heal_attempts+'</strong></span>');
  // Where the task ran (Task 20244). The host case is styled as a warning
  // rather than as one more grey chip: the hub's claim is that it never spawns
  // a harness on the host, so a task that did is the one thing on this row an
  // operator must not be able to scroll past.
  chips.push(_tdExecutorChip(t));
  if (t.isolation) chips.push('<span class="td-chip'+(_tdOnHost(t) ? ' host' : '')+'" title="Isolation boundary the executor advertised when this task was placed.">Isolation<strong>'+esc(t.isolation)+'</strong></span>');
  if (t.write_back_branch) chips.push('<span class="td-chip" title="Branch an isolated executor left this task\'s work on. Local runs commit into the working tree and have no branch.">Branch<strong>'+esc(t.write_back_branch)+'</strong></span>');
  if (t.write_back_commit) chips.push('<span class="td-chip" title="'+esc(t.write_back_commit)+'">Commit<strong>'+esc(t.write_back_commit.slice(0,12))+'</strong></span>');
  if (t.started_at)        chips.push('<span class="td-chip">Started<strong>'+esc(_fmtDateTime(t.started_at))+'</strong></span>');
  if (t.completed_at)      chips.push('<span class="td-chip">Completed<strong>'+esc(_fmtDateTime(t.completed_at))+'</strong></span>');
  const dur = _fmtDuration(t.started_at, t.completed_at);
  if (dur) chips.push('<span class="td-chip">Duration<strong>'+esc(dur)+'</strong></span>');

  let html = '<div class="td-meta">'+chips.join('')+'</div>';

  // Background work the agent left running (Task 20205). Placed above the
  // result, because when it is present it qualifies everything below it: a
  // result written while the work was still running describes something that
  // had not happened yet.
  if (t.background && t.background.state) {
    const bg = t.background;
    const n = bg.detected || 0;
    const procs = n + ' process' + (n === 1 ? '' : 'es');
    let cls, head, note;
    if (bg.state === 'waiting') {
      cls = 'warn'; head = 'Background work running';
      note = 'This task is still waiting for ' + procs + ' its agent started. ' +
             'It is not finished, whatever its status shows.';
    } else if (bg.state === 'abandoned') {
      cls = 'fail'; head = 'Background work never finished';
      note = 'The agent reported completion while ' + procs + ' it started were still ' +
             'running after ' + fmtDurationShort(bg.waited_seconds) + '. The task was not ' +
             'accepted as complete, and tasks depending on it are blocked.' +
             (bg.terminated ? ' ' + bg.terminated + ' process(es) were terminated so a retry ' +
              'cannot race the leftovers.' : '');
    } else {
      cls = ''; head = 'Background work';
      note = 'The agent left ' + procs + ' running; cloop waited ' +
             fmtDurationShort(bg.waited_seconds) + ' for them to finish before accepting the result.';
    }
    html += '<div class="td-section '+cls+'"><h3>'+esc(head)+'</h3>'+
      '<div class="td-text">'+esc(note)+'</div>'+
      (bg.commands && bg.commands.length
        ? '<div class="td-text"><code>'+bg.commands.map(esc).join('</code>, <code>')+'</code></div>'
        : '')+
      '</div>';
  }

  // The stored summary is a provider or harness refusal (Task 20224). Placed
  // above the result for the same reason as background work: it qualifies
  // everything below it. The "Result" section is about to render an error
  // message under a heading that implies it describes work, and the reader
  // needs to know that before they read it.
  if (t.abort && t.abort.class) {
    const ab = t.abort;
    const label = (typeof abortClassLabel === 'function') ? abortClassLabel(ab.class) : ab.class;
    if (ab.cleared) {
      html += '<div class="td-section"><h3>Ledger entry checked</h3>'+
        '<div class="td-text">This task was recorded as done on a '+esc(label)+
        ', so its summary below is not a description of work. It was verified anyway'+
        (ab.cleared_by ? ' by '+esc(ab.cleared_by) : '')+': '+esc(ab.cleared_note || '')+'</div>'+
        '</div>';
    } else {
      html += '<div class="td-section fail"><h3>This task never ran</h3>'+
        '<div class="td-text">Its entire recorded summary is a '+esc(label)+
        ', not a description of work, so the plan does not count it as done. '+
        'Reopen it to run the work for real, or — if a later task already did it — '+
        'record that from the task list so it stops blocking completion.</div>'+
        (ab.evidence ? '<div class="td-text"><code>'+esc(ab.evidence)+'</code></div>' : '')+
        '</div>';
    }
  }

  if (t.description) {
    html += '<div class="td-section"><h3>Description</h3>'+
      '<div class="td-text">'+esc(t.description)+'</div></div>';
  }

  // Result / failure / skip section — driven by status.
  const lbl = _resultSectionLabel(status);
  if (t.result) {
    html += '<div class="td-section '+lbl.cls+'"><h3>'+lbl.label+'</h3>'+
      '<div class="td-text">'+esc(t.result)+'</div></div>';
  } else if (status === 'pending' || status === 'in_progress') {
    // No result yet — that's expected, not an error.
  } else {
    html += '<div class="td-section '+lbl.cls+'"><h3>'+lbl.label+'</h3>'+
      '<div class="td-empty">No summary recorded for this task.</div></div>';
  }

  if (t.failure_diagnosis) {
    html += '<div class="td-section fail"><h3>AI failure diagnosis</h3>'+
      '<div class="td-text">'+esc(t.failure_diagnosis)+'</div></div>';
  }

  if (t.annotations && t.annotations.length) {
    const annos = t.annotations.slice().reverse().map(a => {
      const when = a.timestamp ? _fmtDateTime(a.timestamp) : '';
      return '<div class="td-anno"><div class="td-anno-head">'+esc(a.author||'')+(when?' · '+esc(when):'')+'</div>'+
        '<div>'+esc(a.text||'')+'</div></div>';
    }).join('');
    html += '<div class="td-section"><h3>Annotations ('+t.annotations.length+')</h3>'+annos+'</div>';
  }

  if (d.live_body) {
    html += '<div class="td-section"><h3>Live output'+
      (d.live_path ? ' <span class="td-trunc-note">'+esc(d.live_path)+'</span>' : '')+'</h3>'+
      '<pre class="td-pre">'+esc(d.live_body)+'</pre>'+
      (d.live_truncated ? '<div class="td-trunc-note">Output truncated; tail shown.</div>' : '')+'</div>';
  }

  if (d.artifact_body) {
    html += '<div class="td-section"><h3>Output log'+
      (d.artifact_path ? ' <span class="td-trunc-note">'+esc(d.artifact_path)+'</span>' : '')+'</h3>'+
      '<pre class="td-pre">'+esc(d.artifact_body)+'</pre>'+
      (d.artifact_truncated ? '<div class="td-trunc-note">Output truncated; tail shown.</div>' : '')+'</div>';
  } else if (!d.live_body && (status === 'done' || status === 'failed' || status === 'timed_out')) {
    html += '<div class="td-section"><h3>Output log</h3>'+
      '<div class="td-empty">No persisted artifact for this task.</div></div>';
  }

  if (t.links && t.links.length) {
    const items = t.links.map(l => '<div class="td-link-row">• <a href="'+esc(l.url)+'" target="_blank" rel="noopener">'+esc(l.label||l.url)+'</a> <span class="td-trunc-note">['+esc(l.kind||'link')+']</span></div>').join('');
    html += '<div class="td-section"><h3>Links</h3>'+items+'</div>';
  }

  // Reproduction (Task 20221). Rendered as an empty shell here and filled by
  // _tdLoadReproductions, because both of its fetches are independent of the
  // details call and must not delay the rest of the modal.
  html += '<div class="td-section"><h3>Reproduction</h3>'+
    '<div id="td-repro-note"></div>'+
    '<div id="td-repro-list"><div class="td-empty">Loading…</div></div></div>';

  body.innerHTML = html;
  _tdLoadReproductions(t.id);
}

// Triggered from the task list. Ignore clicks that originated on action
// buttons or the drag handle so existing edit/remove/status flows still work.
window.taskRowClick = function(e, id) {
  const t = e && e.target;
  if (t && t.closest) {
    if (t.closest('.task-actions') || t.closest('.drag-handle') || t.closest('a') || t.closest('button')) return;
  }
  openTaskDetails(id);
};

window.submitEditTask = function() {
  const id       = parseInt(document.getElementById('modalTaskId').value);
  const title    = document.getElementById('modalTitle_').value.trim();
  const desc     = document.getElementById('modalDesc').value.trim();
  const priority = parseInt(document.getElementById('modalPriority').value)||0;
  if (!title) { toast('Title is required', 'err'); return; }
  // Per-task max_minutes. 0 means "inherit project default" — send it through
  // so the server clears any prior override. Negative/NaN inputs are coerced
  // to 0 (the safest default) rather than being sent as garbage.
  const mmRaw  = document.getElementById('modalMaxMinutes');
  const mmVal  = mmRaw ? parseInt(mmRaw.value, 10) : NaN;
  const payload = {
    id,
    title,
    description: desc,
    priority,
    depends_on: parseDepsInput(document.getElementById('modalDeps').value),
  };
  if (Number.isFinite(mmVal) && mmVal >= 0) {
    payload.max_minutes = mmVal;
  }
  api(pUrl('/api/task/edit'), payload).then(d => {
    if (d.ok) { closeModal(); toast('Task updated', 'ok'); refreshState(); }
    else toast(d.error||'Edit failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

// ── Sandbox attach terminal (Task 20265) ───────────────────────────────────
//
// A shell inside the sandbox a *running* task is executing in. Two independent
// questions decide whether the button is pressable, and the server answers
// both — in one call, while the details modal is still painting:
//
//   sandbox.attach  — may this caller enter a sandbox at all? Without it
//                     /attach/info answers non-2xx, and the button stays
//                     disabled rather than offering a click that 403s.
//   a live handle   — is this task running on an executor that supports
//                     sessions? A finished task, or one that ran as a process
//                     on the hub host, has nothing to enter. The server says
//                     which case it is in `reason`, and that string becomes
//                     the button's tooltip, so a disabled button always
//                     explains itself.
//
// Writing is a second permission (sandbox.attach.write). Its absence downgrades
// the session to read-only instead of refusing it, so the input is disabled and
// says so rather than silently swallowing keystrokes.
//
// The screen is a <pre>, not a terminal emulator: escape sequences are stripped
// rather than interpreted, and input is submitted a line at a time. That is
// deliberate — this is the convenience path for "what is it doing right now",
// and `cloop task attach --write` is the full-fidelity one.

let _atInfo   = null; // last /attach/info answer for the task in the details modal
let _atSock   = null; // live terminal socket, or null
let _atTaskID = null; // task the socket belongs to (independent of _tdCurrentId)
let _atBuf    = '';   // retained screen text, capped at _AT_MAX_CHARS

// A chatty sandbox — a build log, a test suite — emits megabytes in seconds.
// The cap is on the retained string rather than on the DOM node, because the
// node is rewritten from the string on every frame; without it the tab grows
// until it dies, on the one screen an operator leaves open the longest.
const _AT_MAX_CHARS = 200000;

// CSI (colour, cursor movement) and OSC (window title) sequences. Anything the
// server sends that is not one of these — including a sequence split across two
// frames — renders as-is. That is the accepted cost of not shipping a terminal
// emulator: garbage on screen is recoverable, a swallowed line is not.
const _AT_CSI_RE = /\x1b\[[0-9;?]*[ -\/]*[@-~]/g;
const _AT_OSC_RE = /\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g;

// _atStripANSI makes sandbox output safe to drop into a <pre>.
//
// A lone \r becomes a newline rather than being dropped. A terminal would use
// it to overwrite the line in place; a <pre> cannot, so the choice is between
// a progress bar that mashes every update onto one unreadable line (dropping)
// and one that leaves a readable line per update (newline). The verbose option
// is the one that never hides output.
function _atStripANSI(s) {
  return String(s == null ? '' : s)
    .replace(_AT_OSC_RE, '')
    .replace(_AT_CSI_RE, '')
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n');
}

// _atAppend writes to the screen, preserving the reader's scroll position.
//
// Auto-scrolling unconditionally would yank a reader who has scrolled up to
// read an error back to the bottom on the next output frame — which, on a
// running build, is immediately.
function _atAppend(text) {
  _atBuf += text;
  if (_atBuf.length > _AT_MAX_CHARS) {
    _atBuf = _atBuf.slice(_atBuf.length - _AT_MAX_CHARS);
  }
  const scr = document.getElementById('at-screen');
  if (!scr) return;
  const nearBottom = (scr.scrollHeight - scr.scrollTop - scr.clientHeight) < 40;
  scr.textContent = _atBuf;
  if (nearBottom) scr.scrollTop = scr.scrollHeight;
}

// _atNote appends a hub-generated line (an error, a close reason). Bracketed so
// it cannot be mistaken for something the sandbox printed.
function _atNote(msg) {
  _atAppend('\n[' + String(msg == null ? '' : msg) + ']\n');
}

function _atSetBanner(html) {
  const el = document.getElementById('at-banner');
  if (el) el.innerHTML = html;
}

// _atGeometry estimates a character grid from the screen's pixel box, so the
// PTY the server allocates is roughly the size of what the reader can see and
// the sandbox's own line wrapping lands in the right place. The divisors track
// .at-screen's 12px monospace / 17px line-height in app.css; the clamps keep a
// collapsed or not-yet-laid-out element (width 0) from asking for a 0x0 PTY.
function _atGeometry() {
  let cols = 80, rows = 24;
  const scr = document.getElementById('at-screen');
  if (scr) {
    const box = (typeof scr.getBoundingClientRect === 'function') ? scr.getBoundingClientRect() : null;
    const w = (box && box.width)  || scr.offsetWidth  || 0;
    const h = (box && box.height) || scr.clientHeight || 0;
    if (w > 0) cols = Math.floor(w / 8);
    if (h > 0) rows = Math.floor(h / 17);
  }
  cols = Math.max(20, Math.min(400, cols));
  rows = Math.max(5,  Math.min(200, rows));
  return {rows: rows, cols: cols};
}

// _atSocketURL turns the project-scoped HTTP path into an absolute ws:// one.
//
// pUrl() is what carries ?project_idx, and it returns a relative URL, so the
// scheme swap has to happen after resolving it against the page. Building the
// string by hand instead would mean re-implementing pUrl's query handling —
// exactly the omission behind the recurring "acts on the wrong project" bug.
//
// The token rides as a query parameter because a WebSocket handshake cannot
// carry an Authorization header; /api/ws does the same.
function _atSocketURL(id) {
  const u = new URL(pUrl('/api/tasks/' + id + '/attach'), location.href);
  u.protocol = (location.protocol === 'https:') ? 'wss:' : 'ws:';
  const geo = _atGeometry();
  u.searchParams.set('rows', String(geo.rows));
  u.searchParams.set('cols', String(geo.cols));
  if (authToken) u.searchParams.set('token', authToken);
  return u.toString();
}

function _atSetInput(enabled, placeholder) {
  const inp = document.getElementById('at-input');
  if (!inp) return;
  inp.disabled = !enabled;
  inp.placeholder = placeholder;
}

// _atLoadInfo runs when the details modal opens, for the same reason
// _tdLoadReproductions does: a button that is always enabled and fails with
// "task 41 is not running on any executor" on every click is a button people
// learn to ignore, and on most tasks that is the honest answer.
function _atLoadInfo(id) {
  const btn = document.getElementById('td-attach-btn');
  _atInfo = null;
  if (btn) { btn.disabled = true; btn.title = 'Checking whether this task has an attachable sandbox…'; }

  fetch(pUrl('/api/tasks/' + id + '/attach/info'), {credentials:'same-origin'})
    .then(r => (r.ok ? r.json() : null))
    .then(d => {
      if (!btn || _tdCurrentId !== id) return;
      // A 403/404 means this account has no sandbox.attach at all. Say that
      // rather than leaving the "checking…" tooltip up forever.
      if (!d || !d.ok) {
        btn.disabled = true;
        btn.title = 'Attaching to a sandbox is not available for this account.';
        return;
      }
      _atInfo = d;
      btn.disabled = !d.attachable;
      btn.title = d.reason || (d.attachable
        ? 'Open a shell in this task\'s sandbox.'
        : 'This task has no attachable sandbox.');
    })
    .catch(() => {
      if (!btn || _tdCurrentId !== id) return;
      btn.disabled = true;
      btn.title = 'Attaching to a sandbox is not available right now.';
    });
}

// Deliberately does not close the task details modal behind it: the terminal is
// a side view of the task being read, and closing it has to return the reader
// to where they were.
window.taskDetailsAttach = function() {
  const id = _tdCurrentId;
  if (!id) return;
  const overlay = document.getElementById('at-overlay');
  if (!overlay) return;

  // A second Attach on a live session would leak the first socket.
  _atCloseSocket('replaced by a new session');

  _atTaskID = id;
  _atBuf = '';
  const scr = document.getElementById('at-screen');
  if (scr) scr.textContent = '';
  const title = document.getElementById('at-title');
  if (title) title.textContent = 'Sandbox Terminal — Task #' + id;
  _atSetBanner('Connecting…');
  // can_write from /attach/info is only a preview. The server re-decides it
  // when the socket opens and the `ready` frame is authoritative — this just
  // avoids telling someone who may write "Read-only session" for the length of
  // a handshake, which reads as a refusal rather than as a wait.
  _atSetInput(false, (_atInfo && _atInfo.can_write) ? 'Connecting…' : 'Read-only session');
  openOverlay(overlay, {dismiss: closeAttachTerminal});

  let sock;
  try { sock = new WebSocket(_atSocketURL(id)); }
  catch (_) { _atSetBanner('<span class="at-ro">Could not open a terminal session.</span>'); return; }
  _atSock = sock;

  sock.onmessage = ev => {
    // A frame that arrives on a socket we have already replaced belongs to a
    // session the reader has left; rendering it would interleave two sandboxes.
    if (_atSock !== sock) return;
    let m;
    try { m = JSON.parse(ev.data); } catch (_) { return; }
    if (!m || !m.type) return;
    switch (m.type) {
      case 'ready': {
        const where = m.executor ? ' on <strong>' + esc(m.executor) + '</strong>' : '';
        const mode  = m.writable
          ? '<span class="at-rw">read-write</span>'
          : '<span class="at-ro">read-only</span>';
        _atSetBanner('Task #' + esc(String(_atTaskID)) + where + ' — ' + mode +
          (m.tty ? ' · TTY' : '') +
          (m.message ? ' · ' + esc(m.message) : ''));
        _atSetInput(!!m.writable, m.writable
          ? 'Type a command and press Enter'
          : 'Read-only session');
        break;
      }
      case 'data':
        _atAppend(_atStripANSI(m.data));
        break;
      case 'error':
        _atNote(m.message || 'session error');
        break;
      case 'closed':
        _atNote(m.message || 'session closed');
        _atSetInput(false, 'Session closed');
        break;
    }
  };
  sock.onerror = () => {
    if (_atSock !== sock) return;
    _atSetBanner('<span class="at-ro">The terminal connection failed.</span>');
  };
  sock.onclose = () => {
    if (_atSock !== sock) return;
    _atSock = null;
    _atNote('disconnected');
    _atSetInput(false, 'Session closed');
  };
};

// _atCloseSocket ends the session politely — the server releases the sandbox's
// attach slot on {"type":"close"}, whereas a bare socket close leaves it held
// until the read side times out.
function _atCloseSocket(reason) {
  const sock = _atSock;
  _atSock = null;
  if (!sock) return;
  try {
    if (sock.readyState === WebSocket.OPEN) sock.send(JSON.stringify({type:'close'}));
  } catch (_) {}
  try { sock.close(); } catch (_) {}
  if (reason) _atNote(reason);
}

window.closeAttachTerminal = function() {
  _atCloseSocket('');
  _atTaskID = null;
  _atBuf = '';
  const scr = document.getElementById('at-screen');
  if (scr) scr.textContent = '';
  _atSetBanner('');
  _atSetInput(false, 'Read-only session');
  const inp = document.getElementById('at-input');
  if (inp) inp.value = '';
  closeOverlay('at-overlay');
};

// A line-at-a-time input rather than raw key capture. Capturing keys in the
// browser would promise an interactive terminal this transport does not
// deliver (no local echo, no signal keys); a text field promises exactly what
// it does.
//
// A named function rather than a trailing IIFE: a fragment whose last line is
// `})();` closes the bundle's shared IIFE early, and every fragment after it
// would load at global scope (see TestDashboard_MainIIFEClosesInLastFragment).
function _atBindInput() {
  const inp = document.getElementById('at-input');
  if (!inp) return;
  inp.addEventListener('keydown', function(e) {
    if (e.key !== 'Enter') return;
    e.preventDefault();
    if (!_atSock || _atSock.readyState !== WebSocket.OPEN) return;
    const line = inp.value;
    inp.value = '';
    try { _atSock.send(JSON.stringify({type:'stdin', data: line + '\n'})); }
    catch (_) { _atNote('could not send input'); }
  });
}
_atBindInput();

