// ── Task replay tab ──────────────────────────────────────────────────────────
//
// Re-runs a finished task against another provider or model and keeps each
// run, with a side-by-side diff of the two outputs. Fetched on the tab's first
// open since Task 20456, markup included, its diff dialog appended to the
// document; it was 25-replay.js.
//
// It runs outside the dashboard's IIFE, so it is handed the helpers it calls —
// tl reads the shared plan — and the only name it puts on window is the
// factory. open() lists the runs afresh and refills the task picker from the
// plan on every visit.
(function () {
  'use strict';

  window.cloopReplayPanel = function (h) {
    const {api, esc, pUrl, authHeaders, tl} = h;
    const {openOverlay, closeOverlay} = window;

    // The replay tab's HTML and the /api/replay-runs backend exist, but its JS
    // handlers were never wired up — clicks on Run replay / Refresh / Close
    // (modal) all threw ReferenceError. These provide the minimum needed for
    // the tab to function: list, create, and the side-by-side diff modal.
    function loadReplayRuns() {
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
    }

    function _openReplayDiff(id) {
      const modal = document.getElementById('replayDiffModal');
      const orig  = document.getElementById('replayDiffOriginal');
      const repl  = document.getElementById('replayDiffReplayed');
      const meta  = document.getElementById('replayDiffMeta');
      const title = document.getElementById('replayDiffTitle');
      if (!modal) return;
      openOverlay(modal, {dismiss: closeReplayDiff});
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

    function closeReplayDiff() {
      closeOverlay('replayDiffModal');
    }

    function submitReplay() {
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
    }

    // Populate the replay task selector with completed tasks from current state
    // whenever the replay tab becomes active. Exposed on window so switchTab
    // (which lives in the IIFE above) can call it without polling activeTab
    // (Task 20126 — replaces a 500ms setInterval that watched for tab changes).
    function populate() {
      const sel = document.getElementById('replayTaskSel');
      const appState = tl.state();
      if (!sel || !appState || !appState.plan || !Array.isArray(appState.plan.tasks)) return;
      const opts = appState.plan.tasks
        .filter(t => t.status === 'done' || t.status === 'failed')
        .map(t => '<option value="' + t.id + '">#' + t.id + ' ' + esc(t.title || '') + '</option>')
        .join('');
      sel.innerHTML = '<option value="">— pick a completed task —</option>' + opts;
    }

    // Every visit lists the runs afresh and offers the plan's finished tasks.
    function open() { loadReplayRuns(); populate(); }

    return h.mount({open, load: loadReplayRuns, submit: submitReplay, closeDiff: closeReplayDiff}, 'replay', `
    <div class="section">
      <div class="section-title">&#9851; Task Replay</div>
      <div style="font-size:12px;color:var(--text-dim);margin-bottom:12px;">
        Re-execute a completed task against a different provider/model and compare the output.
        Useful for validating model upgrades, comparing providers, and A/B testing prompt changes.
      </div>

      <div style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;align-items:center">
        <select id="replayTaskSel" class="form-input" style="max-width:340px"></select>
        <input id="replayProvider" class="form-input" placeholder="provider (e.g. anthropic)" style="max-width:170px"/>
        <input id="replayModel" class="form-input" placeholder="model" style="max-width:240px"/>
        <input id="replayJudge" class="form-input" placeholder="judge: provider:model (optional)" style="max-width:260px"/>
        <button class="btn primary" data-act="submit">Run replay</button>
        <button class="btn" data-act="load" title="Refresh">&#x21bb;</button>
      </div>
      <div id="replayStatus" style="font-size:12px;color:var(--text-dim);min-height:18px;margin-bottom:8px"></div>
    </div>

    <div class="section">
      <div class="section-title" style="display:flex;align-items:center;gap:8px">
        <span>Replay history</span>
        <span id="replayCount" style="font-size:11px;color:var(--text-dim)"></span>
      </div>
      <div id="replayRuns" style="display:flex;flex-direction:column;gap:8px"></div>
    </div>
    `, `
    <div id="replayDiffModal" data-overlay="flex" class="modal-backdrop" style="display:none" data-dismiss="closeDiff">
      <div class="modal-card" style="max-width:1200px;width:96%;max-height:90vh;display:flex;flex-direction:column">
        <div class="modal-header">
          <span class="section-title" id="replayDiffTitle" style="margin:0">Replay diff</span>
          <button class="btn" data-act="closeDiff">Close</button>
        </div>
        <div id="replayDiffMeta" style="font-size:12px;color:var(--text-dim);padding:6px 12px"></div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:0 12px;flex:1;min-height:0">
          <div style="display:flex;flex-direction:column;min-height:0">
            <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.6px;padding:4px 0">Original</div>
            <pre id="replayDiffOriginal" class="diff-pane" style="flex:1;overflow:auto;border:1px solid var(--border);padding:8px;font-size:12px;background:var(--bg-elev);border-radius:6px;white-space:pre-wrap;word-break:break-word"></pre>
          </div>
          <div style="display:flex;flex-direction:column;min-height:0">
            <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.6px;padding:4px 0">Replayed</div>
            <pre id="replayDiffReplayed" class="diff-pane" style="flex:1;overflow:auto;border:1px solid var(--border);padding:8px;font-size:12px;background:var(--bg-elev);border-radius:6px;white-space:pre-wrap;word-break:break-word"></pre>
          </div>
        </div>
        <div style="padding:8px 12px 12px">
          <details>
            <summary style="cursor:pointer;font-size:12px;color:var(--text-dim)">Show prompt</summary>
            <pre id="replayDiffPrompt" style="margin-top:6px;max-height:240px;overflow:auto;border:1px solid var(--border);padding:8px;font-size:11px;background:var(--bg-elev);border-radius:6px;white-space:pre-wrap;word-break:break-word"></pre>
          </details>
        </div>
      </div>
    </div>
    `);
  };
})();
