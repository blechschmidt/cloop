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
  if (t.started_at)        chips.push('<span class="td-chip">Started<strong>'+esc(_fmtDateTime(t.started_at))+'</strong></span>');
  if (t.completed_at)      chips.push('<span class="td-chip">Completed<strong>'+esc(_fmtDateTime(t.completed_at))+'</strong></span>');
  const dur = _fmtDuration(t.started_at, t.completed_at);
  if (dur) chips.push('<span class="td-chip">Duration<strong>'+esc(dur)+'</strong></span>');

  let html = '<div class="td-meta">'+chips.join('')+'</div>';

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

  body.innerHTML = html;
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

