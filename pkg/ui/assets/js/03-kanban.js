// ── Kanban board ──────────────────────────────────────────────────────────────

let kanbanCompact = false;
let kbDragTaskId  = null;

window.toggleKanbanCompact = function() {
  kanbanCompact = !kanbanCompact;
  const btn = document.getElementById('kanbanCompactBtn');
  if (btn) btn.textContent = kanbanCompact ? 'Expanded' : 'Compact';
  if (appState) renderKanban(appState);
};

// Map status values to their column bucket (failed + skipped + timed_out → 'failed' col)
function kbColFor(status) {
  if (!status || status === 'pending')               return 'pending';
  if (status === 'in_progress')                      return 'in_progress';
  if (status === 'done')                             return 'done';
  return 'failed'; // failed | skipped | timed_out
}

function kbPriorityClass(p) {
  if (!p || p <= 0) return '';
  return p <= 1 ? 'kbp1' : p <= 3 ? 'kbp2' : 'kbp3';
}

function kbAvatarHtml(assignee) {
  if (!assignee) return '';
  const initials = assignee.split(/[\s._@-]+/).map(w => w[0]||'').join('').slice(0,2).toUpperCase() || '?';
  return '<div class="kb-avatar" title="'+esc(assignee)+'">'+esc(initials)+'</div>';
}

function kbDeadlineBadge(deadline) {
  if (!deadline) return '';
  const d = new Date(deadline);
  if (isNaN(d.getTime())) return '';
  const now = Date.now();
  const diff = d - now; // ms
  const label = d.toLocaleDateString();
  let cls = 'kb-deadline';
  if (diff < 0)              cls += ''; // overdue — red (default)
  else if (diff < 86400000*2) cls += ' kb-due-soon'; // < 2 days — yellow
  else                        cls += ' kb-ok';       // fine — green
  return '<span class="'+cls+'" title="Deadline: '+esc(label)+'">'+esc(label)+'</span>';
}

function renderKanban(s) {
  const board = document.getElementById('kanbanBoard');
  if (!board) return;
  if (!s || !s.plan || !s.plan.tasks || !s.plan.tasks.length) {
    ['pending','in_progress','done','failed'].forEach(col => {
      const body = document.getElementById('kb-body-'+col);
      const cnt  = document.getElementById('kb-cnt-'+col);
      if (body) body.innerHTML = '<div style="font-size:11px;color:var(--muted);padding:8px 0;text-align:center">No tasks</div>';
      if (cnt)  cnt.textContent = '0';
    });
    updateFilterBadge(0, 0);
    return;
  }

  // Apply filter bar before grouping into columns.
  const filteredTasks = applyFilters(s.plan.tasks);
  updateFilterBadge(filteredTasks.length, s.plan.tasks.length);

  // Group tasks by column
  const groups = { pending:[], in_progress:[], done:[], failed:[] };
  for (const t of filteredTasks) {
    const col = kbColFor(t.status);
    groups[col].push(t);
  }

  // Sort each group: pinned first, then by priority
  for (const col of Object.keys(groups)) {
    groups[col].sort((a,b) => (a.priority||99) - (b.priority||99));
    groups[col] = [...groups[col].filter(t=>t.pinned), ...groups[col].filter(t=>!t.pinned)];
  }

  // Render each column
  for (const col of ['pending','in_progress','done','failed']) {
    const body = document.getElementById('kb-body-'+col);
    const cnt  = document.getElementById('kb-cnt-'+col);
    if (!body || !cnt) continue;
    cnt.textContent = groups[col].length;

    if (!groups[col].length) {
      body.innerHTML = '<div style="font-size:11px;color:var(--muted);padding:10px 0;text-align:center">Drop tasks here</div>';
      continue;
    }

    body.innerHTML = groups[col].map(t => {
      const pc     = kbPriorityClass(t.priority);
      const avatar = kbAvatarHtml(t.assignee || '');
      const tags   = (t.tags && t.tags.length)
        ? '<div class="kb-card-tags">'+t.tags.map(tg=>'<span class="kb-chip">'+esc(tg)+'</span>').join('')+'</div>' : '';
      const dl     = kbDeadlineBadge(t.deadline || '');
      const compact = kanbanCompact ? ' kb-compact' : '';
      return (
        '<div class="kb-card '+pc+compact+'" draggable="true" data-task-id="'+t.id+'" '+
          'onclick="taskRowClick(event,'+t.id+')" '+
          'title="Click to view execution summary, output, and history" '+
          'ondragstart="kbDragStart(event,'+t.id+')" '+
          'ondragend="kbDragEnd(event)">'+
          '<div class="kb-card-header">'+
            '<div class="kb-card-title">'+(t.pinned?'<span class="pin-badge" title="Pinned">📌</span> ':'')+esc(t.title)+'</div>'+
            avatar+
          '</div>'+
          (t.description ? '<div class="kb-card-desc">'+esc(t.description)+'</div>' : '')+
          tags+
          '<div class="kb-card-meta">'+
            dl+
            '<span class="kb-taskid">#'+t.id+'</span>'+
          '</div>'+
        '</div>'
      );
    }).join('');
  }
}

// ── Kanban drag-and-drop ─────────────────────────────────────────────────────

window.kbDragStart = function(e, id) {
  kbDragTaskId = id;
  e.dataTransfer.effectAllowed = 'move';
  e.dataTransfer.setData('text/plain', String(id));
  setTimeout(() => {
    const el = document.querySelector('.kb-card[data-task-id="'+id+'"]');
    if (el) el.classList.add('kb-dragging');
  }, 0);
};

window.kbDragEnd = function(e) {
  kbDragTaskId = null;
  document.querySelectorAll('.kb-card').forEach(el => el.classList.remove('kb-dragging'));
  document.querySelectorAll('.kanban-col-body').forEach(el => el.classList.remove('kb-drag-over'));
};

window.kanbanColDragOver = function(e, col) {
  e.preventDefault();
  e.dataTransfer.dropEffect = 'move';
  document.querySelectorAll('.kanban-col-body').forEach(el => el.classList.remove('kb-drag-over'));
  const body = document.getElementById('kb-body-'+col);
  if (body) body.classList.add('kb-drag-over');
};

window.kanbanColDragLeave = function(e, col) {
  // Only remove if leaving the column body itself (not entering a child card)
  if (!e.currentTarget.contains(e.relatedTarget)) {
    const body = document.getElementById('kb-body-'+col);
    if (body) body.classList.remove('kb-drag-over');
  }
};

window.kanbanColDrop = function(e, col) {
  e.preventDefault();
  document.querySelectorAll('.kanban-col-body').forEach(el => el.classList.remove('kb-drag-over'));
  const id = kbDragTaskId || parseInt(e.dataTransfer.getData('text/plain'), 10);
  if (!id) return;

  // Map column key to status string
  const statusMap = { pending:'pending', in_progress:'in_progress', done:'done', failed:'failed' };
  const newStatus = statusMap[col];
  if (!newStatus) return;

  // Check current status to avoid no-op
  const task = appState && appState.plan && appState.plan.tasks
    ? appState.plan.tasks.find(t => t.id === id) : null;
  if (task && kbColFor(task.status) === col) return; // already in this column

  apiMethod('PATCH', pUrl('/api/tasks/'+id), {status: newStatus}).then(d => {
    if (d.ok) {
      toast('Task #'+id+': moved to '+newStatus.replace('_',' '), 'ok');
      refreshState();
    } else {
      toast(d.error || 'Update failed', 'err');
    }
  }).catch(() => toast('Request failed', 'err'));
};

