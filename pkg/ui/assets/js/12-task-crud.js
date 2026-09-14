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
  const overlay = document.getElementById('delete-modal-overlay');
  overlay.style.display = 'flex';
};

window.closeDeleteModal = function() {
  document.getElementById('delete-modal-overlay').style.display = 'none';
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
  if (dragSrcId === null || dragSrcId === targetId) { dragSrcId = null; return; }
  if (!appState || !appState.plan || !appState.plan.tasks) { dragSrcId = null; return; }

  const sorted = [...appState.plan.tasks].sort((a,b) => a.priority - b.priority);
  const ids = sorted.map(t => t.id);
  const fromIdx = ids.indexOf(dragSrcId);
  const toIdx   = ids.indexOf(targetId);
  if (fromIdx === -1 || toIdx === -1) { dragSrcId = null; return; }

  ids.splice(fromIdx, 1);
  ids.splice(toIdx, 0, dragSrcId);
  dragSrcId = null;

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
  document.getElementById('modal-overlay').classList.add('open');
  document.getElementById('modalTitle_').focus();
};

window.closeModal = function() {
  document.getElementById('modal-overlay').classList.remove('open');
};

// ── Task details modal (read-only execution view) ──────────────────────────

let _tdCurrentId = null;

window.openTaskDetails = function(id) {
  _tdCurrentId = id;
  const overlay = document.getElementById('td-overlay');
  const body    = document.getElementById('td-body');
  if (!overlay || !body) return;
  body.innerHTML = '<div class="td-empty">Loading…</div>';
  overlay.classList.add('open');
  fetch(pUrl('/api/tasks/'+id+'/details'), {credentials:'same-origin'})
    .then(r => r.json())
    .then(d => {
      if (!d || !d.ok) { body.innerHTML = '<div class="td-empty">'+esc(d && d.error || 'Failed to load task details')+'</div>'; return; }
      _renderTaskDetails(d);
    })
    .catch(() => { body.innerHTML = '<div class="td-empty">Request failed</div>'; });
};

window.closeTaskDetails = function() {
  const overlay = document.getElementById('td-overlay');
  if (overlay) overlay.classList.remove('open');
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

