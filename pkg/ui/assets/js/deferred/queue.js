// ── Activity tab (per-task work log) ─────────────────────────────────────────
//
// The queue surfaces every unit of work cloop performs (PM tasks, heal retries,
// evolve discoveries, external merges). The view is read-only: rows are written
// by the orchestrator and exposed via /api/queue. Fetched on the tab's first
// open since Task 20456, markup included; it was 07-queue.js.
//
// It runs outside the dashboard's IIFE, so it is handed the helpers it calls,
// and the only name it puts on window is the factory. open() runs on every
// visit and reads the log afresh.
(function () {
  'use strict';

  window.cloopQueuePanel = function (h) {
    const {api, esc, pUrl} = h;

    function _queueKindBadge(kind) {
      const map = {
        task:     { label: 'PM task',  cls: 'running' },
        heal:     { label: 'Heal',     cls: 'paused' },
        evolve:   { label: 'Evolve',   cls: 'evolving' },
        external: { label: 'External', cls: 'unknown' },
        session:  { label: 'Session',  cls: 'unknown' },
      };
      const m = map[kind] || { label: kind || '?', cls: 'unknown' };
      return '<span class="badge ' + m.cls + '">' + esc(m.label) + '</span>';
    }

    function _queueStatusBadge(status) {
      const map = {
        queued:  { label: 'Queued',  cls: 'unknown' },
        running: { label: 'Running', cls: 'running' },
        done:    { label: 'Done',    cls: 'complete' },
        failed:  { label: 'Failed',  cls: 'failed' },
        skipped: { label: 'Skipped', cls: 'unknown' },
      };
      const m = map[status] || { label: status || '?', cls: 'unknown' };
      return '<span class="badge ' + m.cls + '"><span class="badge-dot"></span>' + esc(m.label) + '</span>';
    }

    function _queueDuration(e) {
      if (!e.started_at) return '';
      const start = new Date(e.started_at).getTime();
      const end = e.completed_at ? new Date(e.completed_at).getTime() : Date.now();
      const sec = Math.max(0, Math.floor((end - start) / 1000));
      if (sec < 60) return sec + 's';
      if (sec < 3600) return Math.floor(sec / 60) + 'm ' + (sec % 60) + 's';
      return Math.floor(sec / 3600) + 'h ' + Math.floor((sec % 3600) / 60) + 'm';
    }

    function loadQueue() {
      const kind = (document.getElementById('queueFilterKind') || {}).value || '';
      const status = (document.getElementById('queueFilterStatus') || {}).value || '';
      const params = new URLSearchParams();
      if (kind) params.set('kind', kind);
      if (status) params.set('status', status);
      params.set('limit', '300');

      const baseUrl = pUrl('/api/queue');
      const url = baseUrl + (baseUrl.includes('?') ? '&' : '?') + params.toString();
      api(url).then(data => {
        renderQueue(data);
      }).catch(err => {
        const empty = document.getElementById('queueEmpty');
        const tbl = document.getElementById('queueTable');
        if (tbl) tbl.style.display = 'none';
        if (empty) {
          empty.style.display = '';
          empty.innerHTML = '<h3>Queue unavailable</h3><p>' + esc(String(err && err.message || err || 'unknown error')) + '</p>';
        }
      });

      // Stats bar.
      const statsUrl = pUrl('/api/queue/stats');
      api(statsUrl).then(stats => {
        const bar = document.getElementById('queueStatsBar');
        if (!bar) return;
        const cards = [
          { label: 'Running', value: stats.running || 0 },
          { label: 'Queued',  value: stats.queued  || 0 },
          { label: 'Done',    value: stats.done    || 0 },
          { label: 'Failed',  value: stats.failed  || 0 },
          { label: 'Skipped', value: stats.skipped || 0 },
        ];
        bar.innerHTML = cards.map(c =>
          '<div class="stat-card"><div class="stat-value">' + c.value + '</div><div class="stat-label">' + esc(c.label) + '</div></div>'
        ).join('');
      }).catch(() => {});
    }

    function renderQueue(data) {
      const entries = (data && data.entries) || [];
      const tbody = document.getElementById('queueTbody');
      const tbl = document.getElementById('queueTable');
      const empty = document.getElementById('queueEmpty');
      if (!tbody) return;
      if (entries.length === 0) {
        if (tbl) tbl.style.display = 'none';
        if (empty) {
          empty.style.display = '';
          empty.innerHTML = '<h3>No activity yet</h3><p>Once cloop runs a task, heal retry, or evolve cycle, it will appear here.</p>';
        }
        return;
      }
      if (empty) empty.style.display = 'none';
      if (tbl) tbl.style.display = '';

      const cellStyle = 'padding:6px 10px;border-top:1px solid var(--border);vertical-align:top';
      const muteStyle = cellStyle + ';font-size:11px;color:var(--muted)';
      const rows = entries.map(e => {
        const started = e.started_at ? new Date(e.started_at).toLocaleString() : '—';
        const result = (e.status === 'failed' && e.error_message)
          ? '<span style="color:var(--red)">' + esc(e.error_message) + '</span>'
          : esc(e.output_summary || '');
        const taskCell = e.task_id ? '#' + e.task_id : '—';
        let title = esc(e.title || '');
        if (e.attempt) {
          title += ' <span style="font-size:11px;color:var(--muted)">(attempt ' + e.attempt + ')</span>';
        }
        return '<tr>' +
          '<td style="' + cellStyle + ';font-family:var(--font-mono,monospace);font-size:11px">' + e.id + '</td>' +
          '<td style="' + cellStyle + '">' + _queueKindBadge(e.kind) + '</td>' +
          '<td style="' + cellStyle + '">' + _queueStatusBadge(e.status) + '</td>' +
          '<td style="' + muteStyle + '">' + taskCell + '</td>' +
          '<td style="' + cellStyle + '">' + title + '</td>' +
          '<td style="' + muteStyle + '">' + esc(started) + '</td>' +
          '<td style="' + muteStyle + '">' + esc(_queueDuration(e)) + '</td>' +
          '<td style="' + cellStyle + ';font-size:12px">' + result + '</td>' +
          '</tr>';
      });
      tbody.innerHTML = rows.join('');
    }

    return h.mount({open: loadQueue, load: loadQueue}, 'queue', `
    <div class="kanban-toolbar">
      <span class="section-title" style="margin:0">Task Activity</span>
      <span style="font-size:11px;color:var(--muted)">Every execution, heal retry, evolve discovery, and external merge — tied to its task. The single source of truth for what cloop is doing.</span>
      <span class="spacer"></span>
      <select id="queueFilterKind" class="filter-select" data-change="load" aria-label="Filter by kind">
        <option value="">All kinds</option>
        <option value="task">PM task</option>
        <option value="heal">Auto-heal</option>
        <option value="evolve">Evolve</option>
        <option value="external">External</option>
        <option value="session">Session</option>
      </select>
      <select id="queueFilterStatus" class="filter-select" data-change="load" aria-label="Filter by status">
        <option value="">All statuses</option>
        <option value="queued">Queued</option>
        <option value="running">Running</option>
        <option value="done">Done</option>
        <option value="failed">Failed</option>
        <option value="skipped">Skipped</option>
      </select>
      <button class="btn" style="padding:3px 10px;font-size:11px" data-act="load">Refresh</button>
    </div>
    <div id="queueStatsBar" class="stats-grid" style="margin-top:10px;margin-bottom:12px"></div>
    <div id="queueEmpty" class="empty-state" style="display:none">
      <h3>No activity yet</h3>
      <p>Once cloop runs a task, heal retry, or evolve cycle, it will appear here.</p>
    </div>
    <div class="section table-scroll" style="overflow-x:auto">
      <table id="queueTable" style="display:none;border-collapse:collapse;width:100%;font-size:13px">
        <thead>
          <tr>
            <th style="text-align:left;padding:6px 10px;background:var(--surface);color:var(--muted);font-weight:500;width:60px">ID</th>
            <th style="text-align:left;padding:6px 10px;background:var(--surface);color:var(--muted);font-weight:500;width:90px">Kind</th>
            <th style="text-align:left;padding:6px 10px;background:var(--surface);color:var(--muted);font-weight:500;width:100px">Status</th>
            <th style="text-align:left;padding:6px 10px;background:var(--surface);color:var(--muted);font-weight:500;width:60px">Task</th>
            <th style="text-align:left;padding:6px 10px;background:var(--surface);color:var(--muted);font-weight:500">Title</th>
            <th style="text-align:left;padding:6px 10px;background:var(--surface);color:var(--muted);font-weight:500;width:140px">Started</th>
            <th style="text-align:left;padding:6px 10px;background:var(--surface);color:var(--muted);font-weight:500;width:90px">Duration</th>
            <th style="text-align:left;padding:6px 10px;background:var(--surface);color:var(--muted);font-weight:500">Result</th>
          </tr>
        </thead>
        <tbody id="queueTbody"></tbody>
      </table>
    </div>
    `);
  };
})();
