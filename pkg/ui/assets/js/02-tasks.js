// ── Filter bar ───────────────────────────────────────────────────────────────

function _saveFilterState() {
  try { localStorage.setItem('cloop_filter_state', JSON.stringify(filterState)); } catch(e) {}
}

// Returns whether any filter is active.
function _filterActive() {
  return !!(filterState.q || filterState.status.length || filterState.tags.length || filterState.assignee || filterState.priority);
}

// Apply filterState to a task array; returns a new filtered array.
function applyFilters(tasks) {
  if (!tasks) return [];
  let result = tasks;
  const q = filterState.q ? filterState.q.toLowerCase() : '';
  if (q) result = result.filter(t => (t.title||'').toLowerCase().includes(q) || (t.description||'').toLowerCase().includes(q));
  if (filterState.status && filterState.status.length) {
    const ss = new Set(filterState.status);
    result = result.filter(t => ss.has(t.status || 'pending'));
  }
  if (filterState.tags && filterState.tags.length) {
    const ts = new Set(filterState.tags);
    result = result.filter(t => (t.tags||[]).some(tg => ts.has(tg)));
  }
  if (filterState.assignee) result = result.filter(t => (t.assignee||'') === filterState.assignee);
  if (filterState.priority) result = result.filter(t => String(t.priority) === filterState.priority);
  return result;
}

// Update the "N of M tasks" badge.
function updateFilterBadge(visible, total) {
  const badge = document.getElementById('filterBadge');
  if (!badge) return;
  badge.textContent = _filterActive() ? visible + ' of ' + total + ' tasks' : '';
}

// Sync all filter DOM inputs to the current filterState (called on page load).
function _restoreFilterInputs() {
  const qEl = document.getElementById('filterQ');
  if (qEl) qEl.value = filterState.q || '';
  document.querySelectorAll('.filter-status-cb').forEach(cb => {
    cb.checked = (filterState.status||[]).includes(cb.value);
  });
  const prEl = document.getElementById('filterPriority');
  if (prEl) prEl.value = filterState.priority || '';
  const asEl = document.getElementById('filterAssignee');
  if (asEl) asEl.value = filterState.assignee || '';
  // Tags are rebuilt dynamically via rebuildTagOptions().
}

// Rebuild tag checkboxes from current task list.
function rebuildTagOptions(tasks) {
  const panel = document.getElementById('filterTagsPanel');
  if (!panel) return;
  const tagSet = new Set();
  (tasks||[]).forEach(t => (t.tags||[]).forEach(tg => tagSet.add(tg)));
  const tags = [...tagSet].sort();
  if (!tags.length) {
    panel.innerHTML = '<span style="color:var(--muted);padding:4px 8px;display:block;font-size:11px">No tags</span>';
    return;
  }
  panel.innerHTML = tags.map(tag =>
    '<label class="filter-tag-item"><input type="checkbox" class="filter-tag-cb" value="'+esc(tag)+'" onchange="onFilterChange()"'+
    ((filterState.tags||[]).includes(tag) ? ' checked' : '')+'> '+esc(tag)+'</label>'
  ).join('');
}

// Rebuild assignee dropdown from current task list.
function rebuildAssigneeOptions(tasks) {
  const sel = document.getElementById('filterAssignee');
  if (!sel) return;
  const people = [...new Set((tasks||[]).map(t => t.assignee||'').filter(Boolean))].sort();
  const cur = filterState.assignee || '';
  sel.innerHTML = '<option value="">Any</option>' +
    people.map(a => '<option value="'+esc(a)+'"'+(a===cur?' selected':'')+'>'+esc(a)+'</option>').join('');
}

window.onFilterChange = function() {
  const qEl = document.getElementById('filterQ');
  filterState.q = qEl ? qEl.value : '';
  filterState.status = Array.from(document.querySelectorAll('.filter-status-cb:checked')).map(cb => cb.value);
  filterState.tags   = Array.from(document.querySelectorAll('.filter-tag-cb:checked')).map(cb => cb.value);
  const asEl = document.getElementById('filterAssignee');
  filterState.assignee = asEl ? asEl.value : '';
  const prEl = document.getElementById('filterPriority');
  filterState.priority = prEl ? prEl.value : '';
  _saveFilterState();
  _updateFilterClearBtn();
  const tagCnt = document.getElementById('filterTagCount');
  if (tagCnt) tagCnt.textContent = filterState.tags.length ? '('+filterState.tags.length+') ' : '';
  // Re-render active panel.
  if (appState) {
    if (activeTab === 'tasks')    renderTasks(appState);
    if (activeTab === 'kanban')   renderKanban(appState);
    if (activeTab === 'deps' && _depsData)   renderDepsGraph(_depsData);
  }
  if (activeTab === 'timeline') loadTimeline();
};

window.clearFilters = function() {
  filterState = { q: '', status: [], tags: [], assignee: '', priority: '' };
  _saveFilterState();
  _restoreFilterInputs();
  document.querySelectorAll('.filter-tag-cb').forEach(cb => { cb.checked = false; });
  _updateFilterClearBtn();
  const tagCnt = document.getElementById('filterTagCount');
  if (tagCnt) tagCnt.textContent = '';
  if (appState) {
    if (activeTab === 'tasks')    renderTasks(appState);
    if (activeTab === 'kanban')   renderKanban(appState);
    if (activeTab === 'deps' && _depsData)   renderDepsGraph(_depsData);
  }
  if (activeTab === 'timeline') loadTimeline();
};

function _updateFilterClearBtn() {
  const btn = document.getElementById('filterClearBtn');
  if (btn) btn.style.display = _filterActive() ? '' : 'none';
}

window.toggleTagDropdown = function(e) {
  if (e) e.stopPropagation();
  const panel = document.getElementById('filterTagsPanel');
  const btn   = document.getElementById('filterTagToggle');
  if (!panel) return;
  const open = panel.classList.toggle('open');
  if (btn) {
    btn.classList.toggle('active', open);
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  }
};

// Close tag dropdown when clicking outside.
document.addEventListener('click', function(e) {
  const wrap = document.getElementById('filterTagsWrap');
  if (wrap && !wrap.contains(e.target)) {
    const panel = document.getElementById('filterTagsPanel');
    const btn   = document.getElementById('filterTagToggle');
    if (panel) panel.classList.remove('open');
    if (btn) { btn.classList.remove('active'); btn.setAttribute('aria-expanded','false'); }
  }
});

// Show or hide the filter bar based on the active tab.
function _syncFilterBarVisibility(tabName) {
  const bar = document.getElementById('filterBar');
  if (bar) bar.style.display = FILTER_TABS.has(tabName) ? '' : 'none';
}

// ── Render tasks tab ─────────────────────────────────────────────────────────

window.toggleCompletedTasks = function() {
  showCompletedTasks = !showCompletedTasks;
  const btn = document.getElementById('toggleCompletedBtn');
  if (btn) btn.textContent = showCompletedTasks ? 'Hide completed' : 'Show completed';
  if (appState) renderTasks(appState);
};

function renderTasks(s) {
  const container = document.getElementById('taskListFull');
  const badge     = document.getElementById('taskCountBadge');
  if (!s || !s.plan || !s.plan.tasks || !s.plan.tasks.length) {
    badge.textContent = '';
    updateFilterBadge(0, 0);
    container.innerHTML = '<div class="empty-state"><h3>No tasks yet</h3><p>Add a task above, or run <code>cloop run --pm</code> to generate a task plan.</p></div>';
    return;
  }
  const byId = [...s.plan.tasks].sort((a,b) => a.id - b.id);
  const hidden  = ['done', 'skipped', 'failed', 'timed_out'];
  // Non-completed tasks (pending + in_progress) are ordered: running first,
  // highest priority first (lower priority value = higher priority), then
  // add time ascending (id ascending). Pinned tasks always float above all.
  const sortNonCompleted = (a, b) => {
    const ar = a.status === 'in_progress' ? 0 : 1;
    const br = b.status === 'in_progress' ? 0 : 1;
    if (ar !== br) return ar - br;
    const ap = (a.priority ?? 99);
    const bp = (b.priority ?? 99);
    if (ap !== bp) return ap - bp;
    return a.id - b.id;
  };
  let sorted;
  if (showCompletedTasks) {
    // Show completed: latest completed/in-progress tasks at the top by
    // completed_at/started_at, then truly pending tasks below sorted by the
    // non-completed rule (running first — none here — then priority, add time).
    const ts = t => {
      const v = t.completed_at || t.started_at;
      return v ? new Date(v).getTime() : 0;
    };
    const isRecent = t => hidden.includes(t.status) || t.status === 'in_progress';
    const recent  = byId.filter(t => !t.pinned && isRecent(t)).sort((a,b) => ts(b) - ts(a));
    const pending = byId.filter(t => !t.pinned && !isRecent(t)).sort(sortNonCompleted);
    sorted = [...byId.filter(t=>t.pinned), ...recent, ...pending];
  } else {
    const active = byId.filter(t => !t.pinned).sort(sortNonCompleted);
    sorted = [...byId.filter(t=>t.pinned), ...active];
  }
  const done    = sorted.filter(t => t.status==='done').length;

  // Apply search/filter bar. When status filters are active they override the showCompleted toggle.
  let visible = applyFilters(sorted);
  if (!filterState.status.length) {
    visible = showCompletedTasks ? visible : visible.filter(t => !hidden.includes(t.status || 'pending'));
  }

  const hiddenCount = sorted.length - visible.length;
  badge.textContent = '(' + done + '/' + sorted.length + ' done' +
    (hiddenCount > 0 && !showCompletedTasks && !filterState.status.length ? ', ' + hiddenCount + ' hidden' : '') + ')';
  updateFilterBadge(visible.length, sorted.length);

  if (!visible.length) {
    const msg = _filterActive()
      ? '<div class="empty-state"><h3>No matching tasks</h3><p>Try adjusting your search or filters.</p></div>'
      : '<div class="empty-state"><h3>All tasks completed</h3><p>Click <strong>Show completed</strong> to view all tasks.</p></div>';
    container.innerHTML = msg;
    return;
  }

  container.innerHTML = visible.map(t => {
    const cls = t.status || 'pending';
    const statusActions = buildStatusActions(t);
    const tid = t.id;
    return '<div class="task-item '+esc(cls)+'" draggable="true" data-task-id="'+tid+'" '+
      'onclick="taskRowClick(event,'+tid+')" '+
      'style="cursor:pointer" '+
      'title="Click to view execution summary, output, and history" '+
      'ondragstart="onDragStart(event,'+tid+')" '+
      'ondragover="onDragOver(event,'+tid+')" '+
      'ondragleave="onDragLeave(event)" '+
      'ondrop="onDrop(event,'+tid+')" '+
      'ondragend="onDragEnd(event)">'+
      '<div class="drag-handle" title="Drag to reorder">&#8597;</div>'+
      '<div class="task-icon">'+taskIcon(cls)+'</div>'+
      '<div class="task-body">'+
        '<div class="task-title">'+(t.pinned?'<span class="pin-badge" title="Pinned">📌</span> ':'')+esc(t.title)+'</div>'+
        (t.description ? '<div class="task-desc">'+esc(t.description)+'</div>' : '')+
        '<div class="task-meta">'+
          '<span>'+esc(cls)+'</span>'+
          (t.role?'<span>'+esc(t.role)+'</span>':'')+
          (t.depends_on&&t.depends_on.length?'<span>deps: #'+t.depends_on.join(', #')+'</span>':'')+
          (t.tags&&t.tags.length?'<span class="task-tags">'+t.tags.map(function(tg){return '<span class="task-tag">'+esc(tg)+'</span>';}).join('')+'</span>':'')+
          fmtTimeEstimate(t)+
        '</div>'+
        fmtTaskLinks(t)+
      '</div>'+
      '<div class="task-actions">'+
        statusActions+
        (cls !== 'done' && cls !== 'in_progress'
          ? '<button class="act split"  title="AI-decompose into sub-tasks" onclick="openDecomposeModal('+tid+')">Split</button>' : '')+
        '<button class="act edit"   title="Edit"   onclick="openEditModal('+tid+')">Edit</button>'+
        '<button class="act remove" title="Remove" onclick="removeTask('+tid+')">Remove</button>'+
        priorityBadge(t.priority)+
        '<span style="font-size:11px;color:var(--muted)">#'+tid+'</span>'+
      '</div>'+
    '</div>';
  }).join('');
}

function fmtTimeEstimate(t) {
  const est = t.estimated_minutes || 0;
  const act = t.actual_minutes || 0;
  if (!est && !act) return '';
  let s = '';
  if (est > 0) s += 'est: ' + est + 'm';
  if (act > 0) {
    if (s) s += ' / ';
    s += 'actual: ' + act + 'm';
    if (est > 0) {
      const variance = Math.round((act - est) / est * 100);
      const sign = variance >= 0 ? '+' : '';
      s += ' (' + sign + variance + '%)';
    }
  }
  return '<span title="Time estimate vs actual">⏱ ' + s + '</span>';
}

function fmtTaskLinks(t) {
  if (!t.links || !t.links.length) return '';
  const kindIcon = { ticket: '🎫', pr: '🔀', doc: '📄', artifact: '📦' };
  const items = t.links.map(function(lnk) {
    const icon = kindIcon[lnk.kind] || '🔗';
    const label = lnk.label || lnk.url;
    return '<a class="task-link-item" href="'+esc(lnk.url)+'" target="_blank" rel="noopener" title="['+esc(lnk.kind)+'] '+esc(lnk.url)+'">'+icon+' '+esc(label)+'</a>';
  });
  return '<div class="task-links">'+items.join('')+'</div>';
}

function buildStatusActions(t) {
  const cls = t.status || 'pending';
  let btns = '';
  if (cls !== 'done')        btns += '<button class="act done"  onclick="setStatus('+t.id+',\'done\')">Done</button>';
  if (cls !== 'skipped')     btns += '<button class="act skip"  onclick="setStatus('+t.id+',\'skipped\')">Skip</button>';
  if (cls !== 'failed')      btns += '<button class="act fail"  onclick="setStatus('+t.id+',\'failed\')">Fail</button>';
  if (cls !== 'pending')     btns += '<button class="act reset" onclick="setStatus('+t.id+',\'pending\')">Reset</button>';
  return btns;
}

