// ── Activity tab (per-task work log) ─────────────────────────────────────────
//
// The queue surfaces every unit of work cloop performs (PM tasks, heal retries,
// evolve discoveries, external merges). The view is read-only: rows are written
// by the orchestrator and exposed via /api/queue.

window.loadQueue = function() { loadQueue(); };

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

