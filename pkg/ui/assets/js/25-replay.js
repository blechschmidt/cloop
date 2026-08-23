// ── Replay tab handlers (Task 20124) ──────────────────────────────────────
// The replay tab's HTML and the /api/replay-runs backend exist, but its JS
// handlers were never wired up — clicks on Run replay / Refresh / Close
// (modal) all threw ReferenceError. These provide the minimum needed for
// the tab to function: list, create, and the side-by-side diff modal.
window.loadReplayRuns = function() {
  const list  = document.getElementById('replayRuns');
  const count = document.getElementById('replayCount');
  if (!list) return;
  list.textContent = 'Loading…';
  api(pUrl('/api/replay-runs?limit=50')).then(data => {
    const runs = (data && data.runs) || [];
    if (count) count.textContent = runs.length + ' run' + (runs.length === 1 ? '' : 's');
    if (!runs.length) {
      list.innerHTML = '<div style="font-size:12px;color:var(--muted);padding:8px">No replay runs yet — pick a completed task above and click Run replay.</div>';
      return;
    }
    list.innerHTML = runs.map(r => {
      const created = (r.created_at || '').replace('T', ' ').slice(0, 19);
      const tgt = (r.target_provider || '?') + (r.target_model ? ':' + r.target_model : '');
      const orig = (r.original_provider || '?') + (r.original_model ? ':' + r.original_model : '');
      const score = (typeof r.similarity_score === 'number') ? (Math.round(r.similarity_score * 100) + '%') : '—';
      const errText = r.error ? '<span style="color:var(--red)">error: ' + esc(r.error) + '</span>' : '';
      return '<div class="replay-row" data-replay-id="' + r.id + '" style="border:1px solid var(--border);border-radius:var(--radius);padding:10px 12px;cursor:pointer">' +
        '<div style="display:flex;gap:12px;align-items:center;font-size:12px">' +
        '<span style="font-weight:600">#' + r.id + '</span>' +
        '<span style="color:var(--muted)">' + esc(created) + '</span>' +
        '<span>task ' + r.task_id + ': ' + esc(r.task_title || '') + '</span>' +
        '</div>' +
        '<div style="display:flex;gap:12px;align-items:center;font-size:11px;color:var(--muted);margin-top:4px">' +
        '<span>' + esc(orig) + ' → ' + esc(tgt) + '</span>' +
        '<span>similarity: ' + score + '</span>' +
        '<span>' + (r.duration_ms || 0) + ' ms</span>' +
        errText +
        '</div></div>';
    }).join('');
    list.querySelectorAll('.replay-row').forEach(row => {
      row.addEventListener('click', () => {
        const id = row.getAttribute('data-replay-id');
        _openReplayDiff(id);
      });
    });
  }).catch(err => {
    list.innerHTML = '<div style="color:var(--red);font-size:12px">Failed to load replay runs: ' + esc(String(err)) + '</div>';
  });
};

function _openReplayDiff(id) {
  const modal = document.getElementById('replayDiffModal');
  const orig  = document.getElementById('replayDiffOriginal');
  const repl  = document.getElementById('replayDiffReplayed');
  const meta  = document.getElementById('replayDiffMeta');
  const title = document.getElementById('replayDiffTitle');
  if (!modal) return;
  modal.style.display = 'flex';
  if (orig) orig.textContent = 'Loading…';
  if (repl) repl.textContent = '';
  api(pUrl('/api/replay-runs/' + encodeURIComponent(id))).then(d => {
    if (title) title.textContent = 'Replay diff #' + (d.id || id);
    if (meta) {
      const score = (typeof d.similarity_score === 'number') ? Math.round(d.similarity_score * 100) + '%' : '—';
      meta.textContent = 'task ' + (d.task_id || '?') + ' · ' +
        (d.original_provider || '?') + ':' + (d.original_model || '?') + ' → ' +
        (d.target_provider || '?') + ':' + (d.target_model || '?') + ' · similarity ' + score;
    }
    if (orig) orig.textContent = d.original_output || '(empty)';
    if (repl) repl.textContent = d.replayed_output || '(empty)';
  }).catch(err => {
    if (orig) orig.textContent = 'Failed to load: ' + String(err);
  });
}

window.closeReplayDiff = function() {
  const modal = document.getElementById('replayDiffModal');
  if (modal) modal.style.display = 'none';
};

window.submitReplay = function() {
  const sel    = document.getElementById('replayTaskSel');
  const prov   = document.getElementById('replayProvider');
  const model  = document.getElementById('replayModel');
  const judge  = document.getElementById('replayJudge');
  const status = document.getElementById('replayStatus');
  if (!sel || !sel.value) {
    if (status) status.textContent = 'Pick a task to replay.';
    return;
  }
  const body = {
    task_id: parseInt(sel.value, 10),
    provider: prov ? prov.value.trim() : '',
    model:    model ? model.value.trim() : '',
    judge:    judge ? judge.value.trim() : '',
  };
  if (!body.provider || !body.model) {
    if (status) status.textContent = 'Provider and model are required.';
    return;
  }
  if (status) status.textContent = 'Replaying… (may take a minute)';
  fetch(pUrl('/api/replay-runs'), {
    method: 'POST',
    headers: Object.assign({'Content-Type': 'application/json'}, authHeaders()),
    body: JSON.stringify(body),
  }).then(r => r.json()).then(d => {
    if (d && d.ok === false) {
      if (status) status.textContent = 'Replay failed: ' + (d.error || 'unknown error');
      return;
    }
    if (status) status.textContent = 'Replay complete.';
    loadReplayRuns();
  }).catch(err => {
    if (status) status.textContent = 'Replay failed: ' + String(err);
  });
};

// Populate the replay task selector with completed tasks from current state
// whenever the replay tab becomes active. Exposed on window so switchTab
// (which lives in the IIFE above) can call it without polling activeTab
// (Task 20126 — replaces a 500ms setInterval that watched for tab changes).
window._populateReplayTaskSelector = function _populateReplayTaskSelector() {
  const sel = document.getElementById('replayTaskSel');
  if (!sel || !appState || !appState.plan || !Array.isArray(appState.plan.tasks)) return;
  const opts = appState.plan.tasks
    .filter(t => t.status === 'done' || t.status === 'failed')
    .map(t => '<option value="' + t.id + '">#' + t.id + ' ' + esc(t.title || '') + '</option>')
    .join('');
  sel.innerHTML = '<option value="">— pick a completed task —</option>' + opts;
};

