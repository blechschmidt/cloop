// ── Kanban board ──────────────────────────────────────────────────────────────
//
// The plan as four columns, filtered by the filter bar, with cards dragged
// between columns to change a task's status. Fetched on the tab's first open
// since Task 20456, markup included; it was 03-kanban.js.
//
// It runs outside the dashboard's IIFE, so it is handed the helpers it calls —
// tl reads the shared plan and the filter bar — and the only name it puts on
// window is the factory. open() and render() draw from the plan the page
// already holds; the bundle calls render() through panelIf on every state
// change, a no-op until the tab has been opened once. The drag events are
// delegated from the tab itself rather than named in the markup: the
// dispatcher's drag tables (00-core.js) are the bundle's, and a deferred
// script may register nothing there.
(function () {
  'use strict';

  window.cloopKanbanPanel = function (h) {
    const {apiMethod, esc, toast, pUrl, refreshState, tl} = h;

    let kanbanCompact = false;
    let kbDragTaskId  = null;

    function compact() {
      kanbanCompact = !kanbanCompact;
      const btn = document.getElementById('kanbanCompactBtn');
      if (btn) btn.textContent = kanbanCompact ? 'Expanded' : 'Compact';
      render();
    }

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

    function render() {
      const s = tl.state();
      const board = document.getElementById('kanbanBoard');
      if (!board) return;
      if (!s || !s.plan || !s.plan.tasks || !s.plan.tasks.length) {
        ['pending','in_progress','done','failed'].forEach(col => {
          const body = document.getElementById('kb-body-'+col);
          const cnt  = document.getElementById('kb-cnt-'+col);
          if (body) body.innerHTML = '<div style="font-size:11px;color:var(--muted);padding:8px 0;text-align:center">No tasks</div>';
          if (cnt)  cnt.textContent = '0';
        });
        tl.badge(0, 0);
        return;
      }

      // Apply filter bar before grouping into columns.
      const filteredTasks = tl.apply(s.plan.tasks);
      tl.badge(filteredTasks.length, s.plan.tasks.length);

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
          const compactCls = kanbanCompact ? ' kb-compact' : '';
          return (
            '<div class="kb-card '+pc+compactCls+'" draggable="true" data-task-id="'+t.id+'" '+
              'data-action="taskRowClick" data-arg="'+t.id+'" '+
              'title="Click to view execution summary, output, and history">'+
              '<div class="kb-card-header">'+
                '<div class="kb-card-title">'+(t.pinned?'<span class="pin-badge" title="Pinned">📌</span> ':'')+esc(t.title)+'</div>'+
                avatar+
              '</div>'+
              (t.description ? '<div class="kb-card-desc">'+esc(t.description)+'</div>' : '')+
              tags+
              '<div class="kb-card-meta">'+
                dl+h.filesChip(t)+
                '<span class="kb-taskid">#'+t.id+'</span>'+
              '</div>'+
            '</div>'
          );
        }).join('');
      }
    }

    // ── Kanban drag-and-drop ─────────────────────────────────────────────────

    const clearOver = () => document.querySelectorAll('.kanban-col-body').forEach(el => el.classList.remove('kb-drag-over'));
    // The column a drag event is over, or null outside every column.
    const colOf = e => (e.target && e.target.closest) ? e.target.closest('.kanban-col-body') : null;

    function wireDrag(box) {
      box.addEventListener('dragstart', e => {
        const card = e.target && e.target.closest && e.target.closest('.kb-card');
        if (!card) return;
        const id = +card.dataset.taskId;
        kbDragTaskId = id;
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', String(id));
        setTimeout(() => card.classList.add('kb-dragging'), 0);
      });
      box.addEventListener('dragend', () => {
        kbDragTaskId = null;
        document.querySelectorAll('.kb-card').forEach(el => el.classList.remove('kb-dragging'));
        clearOver();
      });
      box.addEventListener('dragover', e => {
        const body = colOf(e);
        if (!body) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        clearOver();
        body.classList.add('kb-drag-over');
      });
      box.addEventListener('dragleave', e => {
        // Only remove if leaving the column body itself (not entering a child card)
        const body = colOf(e);
        if (body && !body.contains(e.relatedTarget)) body.classList.remove('kb-drag-over');
      });
      box.addEventListener('drop', e => {
        const body = colOf(e);
        if (!body) return;
        e.preventDefault();
        clearOver();
        drop(body.dataset.col, kbDragTaskId || parseInt(e.dataTransfer.getData('text/plain'), 10));
      });
    }

    function drop(col, id) {
      if (!id) return;

      // Map column key to status string
      const statusMap = { pending:'pending', in_progress:'in_progress', done:'done', failed:'failed' };
      const newStatus = statusMap[col];
      if (!newStatus) return;

      // Check current status to avoid no-op
      const s = tl.state();
      const task = s && s.plan && s.plan.tasks ? s.plan.tasks.find(t => t.id === id) : null;
      if (task && kbColFor(task.status) === col) return; // already in this column

      return apiMethod('PATCH', pUrl('/api/tasks/'+id), {status: newStatus}).then(d => {
        if (d.ok) {
          toast('Task #'+id+': moved to '+newStatus.replace('_',' '), 'ok');
          refreshState();
        } else {
          toast(d.error || 'Update failed', 'err');
        }
      }).catch(() => toast('Request failed', 'err'));
    }

    const p = h.mount({open: render, render, compact, drop}, 'kanban', `
    <div class="kanban-toolbar">
      <span class="section-title" style="margin:0">Kanban Board</span>
      <button class="btn" id="kanbanCompactBtn" style="padding:3px 10px;font-size:11px" data-act="compact">Compact</button>
      <button class="btn" style="padding:3px 10px;font-size:11px" data-action="refreshState">Refresh</button>
    </div>
    <div id="kanbanBoard" class="kanban-board">
      <div class="kanban-col" id="kb-col-pending"     data-status="pending">
        <div class="kanban-col-header"><span class="kanban-col-title">Pending</span><span class="kanban-col-count" id="kb-cnt-pending">0</span></div>
        <div class="kanban-col-body" id="kb-body-pending" data-col="pending">
        </div>
      </div>
      <div class="kanban-col" id="kb-col-in_progress" data-status="in_progress">
        <div class="kanban-col-header"><span class="kanban-col-title">In Progress</span><span class="kanban-col-count" id="kb-cnt-in_progress">0</span></div>
        <div class="kanban-col-body" id="kb-body-in_progress" data-col="in_progress">
        </div>
      </div>
      <div class="kanban-col" id="kb-col-done"        data-status="done">
        <div class="kanban-col-header"><span class="kanban-col-title">Done</span><span class="kanban-col-count" id="kb-cnt-done">0</span></div>
        <div class="kanban-col-body" id="kb-body-done" data-col="done">
        </div>
      </div>
      <div class="kanban-col" id="kb-col-failed"      data-status="failed">
        <div class="kanban-col-header"><span class="kanban-col-title">Failed / Skipped</span><span class="kanban-col-count" id="kb-cnt-failed">0</span></div>
        <div class="kanban-col-body" id="kb-body-failed" data-col="failed">
        </div>
      </div>
    </div>
    `);
    wireDrag(document.getElementById('tab-kanban'));
    return p;
  };
})();
