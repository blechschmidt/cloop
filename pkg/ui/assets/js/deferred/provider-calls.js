// ── Provider Call Inspector tab (Task 20123) ────────────────────────────────
//
// Lists recent Provider.Complete invocations recorded by pkg/provideraudit.
// New rows arrive over WebSocket as type:"provider_call" envelopes, which the
// bundle's realtime handler hands to live() through panelIf. Clicking a row
// opens a dialog with the full prompt/response/headers and a Replay tab that
// re-runs the call (optionally with edits) against the project's current
// provider config and shows a side-by-side diff of original vs replayed
// response. Fetched on the tab's first open since Task 20456, markup included,
// its dialog appended to the document; it was 08-provider-calls.js.
//
// It runs outside the dashboard's IIFE, so it is handed the helpers it calls,
// and the only name it puts on window is the factory. open() reads the list
// afresh on every visit, so a call pushed before the tab was ever opened is in
// it; live() drops a push for a filter it does not match.
(function () {
  'use strict';

  window.cloopProviderCallsPanel = function (h) {
    const {api, esc, toast, pUrl} = h;
    const {openOverlay, closeOverlay} = window;

    let _pcRows         = [];      // most-recent-first cached list of summaries
    let _pcCurrent      = null;    // detail row currently open in the modal
    let _pcAutoFollow   = true;    // when true, new live calls scroll to top
    let _pcReloadTimer  = null;    // debounce for filter changes
    const _PC_MAX_ROWS  = 500;     // cap in-memory list to keep render cheap


    function _pcDebouncedReload() {
      if (_pcReloadTimer) clearTimeout(_pcReloadTimer);
      _pcReloadTimer = setTimeout(() => loadProviderCalls(), 250);
    }

    function _pcAutoFollowChange() {
      const cb = document.getElementById('pcAutoFollow');
      _pcAutoFollow = !!(cb && cb.checked);
    }

    function _pcStatusBadge(status) {
      const map = {
        ok:               { label: 'OK',      cls: 'complete' },
        error:            { label: 'Error',   cls: 'failed' },
        timeout:          { label: 'Timeout', cls: 'failed' },
        context_canceled: { label: 'Cancel',  cls: 'unknown' },
      };
      const m = map[status] || { label: status || '?', cls: 'unknown' };
      return '<span class="badge ' + m.cls + '"><span class="badge-dot"></span>' + esc(m.label) + '</span>';
    }

    function _pcLatency(ms) {
      if (ms == null) return '—';
      if (ms < 1000)  return ms + ' ms';
      const s = ms / 1000;
      if (s < 60) return s.toFixed(1) + ' s';
      return Math.floor(s / 60) + 'm ' + Math.floor(s % 60) + 's';
    }

    function _pcTimeShort(ts) {
      if (!ts) return '—';
      try {
        const d = new Date(ts);
        if (isNaN(d.getTime())) return esc(ts);
        return d.toLocaleTimeString();
      } catch (_) { return esc(String(ts)); }
    }

    function loadProviderCalls() {
      const provider = (document.getElementById('pcFilterProvider') || {}).value || '';
      const taskID   = (document.getElementById('pcFilterTaskID')   || {}).value || '';
      const params   = new URLSearchParams();
      if (provider) params.set('provider', provider);
      if (taskID)   params.set('task_id',  String(parseInt(taskID, 10) || 0));
      params.set('limit', String(_PC_MAX_ROWS));

      const baseUrl = pUrl('/api/provider-calls');
      const url = baseUrl + (baseUrl.includes('?') ? '&' : '?') + params.toString();
      return api(url).then(data => {
        _pcRows = (data && data.calls) || [];
        renderProviderCalls();
        const c = document.getElementById('pcCount');
        if (c) {
          const total = (data && typeof data.total === 'number') ? data.total : _pcRows.length;
          c.textContent = _pcRows.length + ' shown · ' + total + ' total';
        }
      }).catch(err => {
        const empty = document.getElementById('pcEmpty');
        const wrap  = document.getElementById('pcTableWrap');
        if (wrap)  wrap.style.display = 'none';
        if (empty) {
          empty.style.display = '';
          empty.innerHTML = '<h3>Provider call inspector unavailable</h3><p>' + esc(String(err && err.message || err || 'unknown error')) + '</p>';
        }
      });
    }

    function renderProviderCalls() {
      const tbody = document.getElementById('pcTbody');
      const empty = document.getElementById('pcEmpty');
      const wrap  = document.getElementById('pcTableWrap');
      if (!tbody) return;
      if (!_pcRows.length) {
        if (wrap)  wrap.style.display = 'none';
        if (empty) {
          empty.style.display = '';
          empty.innerHTML = '<h3>No provider calls yet</h3><p>Trigger a task or use any AI command. Calls appear here in real time.</p>';
        }
        tbody.innerHTML = '';
        return;
      }
      if (empty) empty.style.display = 'none';
      if (wrap)  wrap.style.display  = '';

      const cellStyle = 'padding:5px 10px;border-top:1px solid var(--border);vertical-align:top;cursor:pointer';
      const muteStyle = cellStyle + ';font-size:11px;color:var(--muted)';
      const numStyle  = cellStyle + ';text-align:right;font-variant-numeric:tabular-nums';

      const rows = _pcRows.map(r => {
        const taskCell = r.task_id ? ('#' + r.task_id + (r.task_title ? ' ' + esc(r.task_title) : '')) : '—';
        const errCell  = r.status !== 'ok' && r.error_message
          ? '<div style="color:var(--red);font-size:10px;margin-top:2px;max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(r.error_message) + '">' + esc(r.error_message) + '</div>'
          : '';
        return '<tr class="pc-row" data-act="show" data-arg="' + parseInt(r.id, 10) + '" data-pc-id="' + parseInt(r.id, 10) + '">' +
          '<td style="' + cellStyle + ';font-family:var(--font-mono,monospace);font-size:11px">' + esc(_pcTimeShort(r.timestamp)) + '</td>' +
          '<td style="' + cellStyle + '">' + _pcStatusBadge(r.status) + errCell + '</td>' +
          '<td style="' + cellStyle + '">' + esc(r.provider || '—') + '</td>' +
          '<td style="' + muteStyle + ';font-family:var(--font-mono,monospace)">' + esc(r.model || '—') + '</td>' +
          '<td style="' + cellStyle + ';font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(taskCell) + '">' + esc(taskCell) + '</td>' +
          '<td style="' + numStyle + '">' + (r.input_tokens || 0) + '</td>' +
          '<td style="' + numStyle + '">' + (r.output_tokens || 0) + '</td>' +
          '<td style="' + numStyle + '">' + esc(_pcLatency(r.latency_ms)) + '</td>' +
          '</tr>';
      });
      tbody.innerHTML = rows.join('');
    }

    // _pcAppendLive prepends a single newly-pushed call summary, dropping the
    // oldest if the cache exceeds the cap. Called by the WebSocket handler.
    function _pcAppendLive(summary) {
      if (!summary || typeof summary.id !== 'number') return;
      // Apply current filters client-side: if the user has a filter set and this
      // row doesn't match, ignore it so the live view stays consistent with the
      // filtered list. The next manual refresh will re-fetch authoritative rows.
      const provider = (document.getElementById('pcFilterProvider') || {}).value || '';
      if (provider && summary.provider !== provider) return;
      const taskFilter = (document.getElementById('pcFilterTaskID') || {}).value || '';
      if (taskFilter && parseInt(taskFilter, 10) !== (summary.task_id || 0)) return;

      // De-duplicate (server occasionally retransmits on reconnect).
      if (_pcRows.length && _pcRows[0].id === summary.id) return;
      _pcRows.unshift(summary);
      if (_pcRows.length > _PC_MAX_ROWS) _pcRows.length = _PC_MAX_ROWS;

      // Only re-render if the inspector tab is active to avoid wasted DOM work.
      if (h.tab() === 'provider-calls') {
        renderProviderCalls();
        const c = document.getElementById('pcCount');
        if (c) c.textContent = _pcRows.length + ' shown';
        if (_pcAutoFollow) {
          const wrap = document.getElementById('pcTableWrap');
          if (wrap) wrap.scrollTop = 0;
        }
      }
    }

    function openProviderCallModal(id) {
      id = parseInt(id, 10);
      const url = pUrl('/api/provider-calls/' + encodeURIComponent(id));
      api(url).then(detail => {
        _pcCurrent = detail || null;
        _pcRenderModal(detail);
        openOverlay('pcModal', {dismiss: closeProviderCallModal});
        pcSwitchSub('prompt');
      }).catch(err => {
        toast('Failed to load call: ' + (err && err.message || err), 'error');
      });
    }

    function closeProviderCallModal() {
      closeOverlay('pcModal');
      const r = document.getElementById('pcReplayResult');
      if (r) r.style.display = 'none';
      _pcCurrent = null;
    }

    function _pcRenderModal(d) {
      if (!d) return;
      const title = document.getElementById('pcModalTitle');
      if (title) title.textContent = 'Call #' + d.id + ' · ' + (d.provider || '?') + ' · ' + (d.model || '?');

      const meta = document.getElementById('pcModalMeta');
      if (meta) {
        const taskCell = d.task_id ? ('Task #' + d.task_id + (d.task_title ? ' · ' + esc(d.task_title) : '')) : 'Ad-hoc';
        const reqCell  = d.request_id ? ('<span title="X-Request-ID">req: <code>' + esc(d.request_id) + '</code></span>') : '';
        meta.innerHTML = [
          '<span>' + esc(_pcTimeShort(d.timestamp)) + '</span>',
          _pcStatusBadge(d.status),
          '<span>' + esc(taskCell) + '</span>',
          '<span>in: ' + (d.input_tokens || 0) + ' tok</span>',
          '<span>out: ' + (d.output_tokens || 0) + ' tok</span>',
          d.thinking_tokens ? ('<span>think: ' + d.thinking_tokens + ' tok</span>') : '',
          '<span>latency: ' + esc(_pcLatency(d.latency_ms)) + '</span>',
          reqCell,
        ].filter(Boolean).join('');
      }

      // A call whose bodies retention dropped (Task 20291) still has every
      // metadata field above; what it no longer has is the text. Say so, because
      // "" rendered in the prompt pane is otherwise indistinguishable from a call
      // that really was made with an empty prompt.
      const pruned = !!d.bodies_pruned;
      const prunedNote = pruned
        ? '(dropped by retention' + (d.bodies_pruned_at ? ' on ' + _pcTimeShort(d.bodies_pruned_at) : '') + ')'
        : '';

      // Prompt tab
      const sys = document.getElementById('pcSystemPrompt');
      if (sys) sys.textContent = d.system_prompt || (pruned ? prunedNote : '(no system prompt)');
      const prompt = document.getElementById('pcPrompt');
      if (prompt) prompt.textContent = d.prompt || (pruned ? prunedNote : '');

      // Response tab
      const respErr = document.getElementById('pcResponseError');
      const resp    = document.getElementById('pcResponse');
      if (d.status !== 'ok' && d.error_message) {
        if (respErr) {
          respErr.style.display = '';
          respErr.textContent = d.error_message;
        }
        if (resp) resp.textContent = d.response || '(no response — call failed)';
      } else {
        if (respErr) respErr.style.display = 'none';
        if (resp)    resp.textContent     = d.response || (pruned ? prunedNote : '(empty response)');
      }

      // Headers tab
      const headers = document.getElementById('pcHeaders');
      if (headers) {
        try {
          headers.textContent = JSON.stringify(d.headers || {}, null, 2);
        } catch (_) {
          headers.textContent = String(d.headers || '');
        }
      }

      // Replay tab — pre-fill with the original values so users can edit and
      // re-run, or just hit "Run replay" for a verbatim re-execution.
      const rModel  = document.getElementById('pcReplayModel');
      const rSystem = document.getElementById('pcReplaySystem');
      const rPrompt = document.getElementById('pcReplayPrompt');
      if (rModel)  rModel.value  = d.model || '';
      if (rSystem) rSystem.value = d.system_prompt || '';
      if (rPrompt) {
        rPrompt.value = d.prompt || '';
        // A verbatim re-run is impossible once the prompt is gone — the server
        // refuses rather than completing the empty string and calling the result a
        // replay — so the field has to ask for one instead of looking merely blank.
        rPrompt.placeholder = pruned
          ? 'The original prompt was dropped by retention. Type a prompt to replay this call.'
          : '';
      }

      const rRes = document.getElementById('pcReplayResult');
      if (rRes) rRes.style.display = 'none';
    }

    function pcSwitchSub(name) {
      document.querySelectorAll('.pc-subtab').forEach(b => {
        if (b.getAttribute('data-pc-sub') === name) b.classList.add('active');
        else b.classList.remove('active');
      });
      document.querySelectorAll('.pc-subpanel').forEach(p => { p.style.display = 'none'; });
      const panel = document.getElementById('pcSub-' + name);
      if (panel) panel.style.display = 'block';
    }

    function pcResetReplayPrompt() {
      if (!_pcCurrent) return;
      const rSystem = document.getElementById('pcReplaySystem');
      const rPrompt = document.getElementById('pcReplayPrompt');
      const rModel  = document.getElementById('pcReplayModel');
      if (rSystem) rSystem.value = _pcCurrent.system_prompt || '';
      if (rPrompt) rPrompt.value = _pcCurrent.prompt || '';
      if (rModel)  rModel.value  = _pcCurrent.model || '';
    }

    function submitProviderCallReplay() {
      if (!_pcCurrent) { toast('No call selected', 'error'); return; }
      const id      = _pcCurrent.id;
      const prompt  = (document.getElementById('pcReplayPrompt') || {}).value || '';
      const sysVal  = (document.getElementById('pcReplaySystem') || {}).value || '';
      const model   = (document.getElementById('pcReplayModel')  || {}).value || '';

      const btn = document.getElementById('pcReplayRun');
      if (btn) { btn.disabled = true; btn.textContent = 'Running…'; }

      const meta = document.getElementById('pcReplayMeta');
      if (meta) meta.textContent = 'Running replay against project provider config…';
      const result = document.getElementById('pcReplayResult');
      if (result) result.style.display = '';

      const url = pUrl('/api/provider-calls/' + encodeURIComponent(id) + '/replay');
      api(url, { prompt: prompt, system_prompt: sysVal, model: model }).then(data => {
        const orig = (data && data.original)  || _pcCurrent;
        const repl = (data && data.replayed)  || {};
        const origPane = document.getElementById('pcReplayOriginal');
        const newPane  = document.getElementById('pcReplayNew');
        if (origPane) origPane.textContent = (orig.response || orig.error_message || '(no original output)');
        if (newPane) {
          if (repl.error) {
            newPane.textContent = 'ERROR: ' + repl.error;
            newPane.style.color = 'var(--red)';
          } else {
            newPane.textContent = (repl.response != null ? repl.response : '(empty response)');
            newPane.style.color = '';
          }
        }
        if (meta) {
          const parts = [];
          parts.push('model: ' + esc(repl.model || model || orig.model || '?'));
          parts.push('latency: ' + esc(_pcLatency(repl.latency_ms)));
          if (repl.input_tokens != null)  parts.push('in: '  + repl.input_tokens  + ' tok');
          if (repl.output_tokens != null) parts.push('out: ' + repl.output_tokens + ' tok');
          meta.innerHTML = parts.join(' · ');
        }
        toast('Replay complete', 'success');
      }).catch(err => {
        if (meta) meta.innerHTML = '<span style="color:var(--red)">Replay failed: ' + esc(String(err && err.message || err)) + '</span>';
        toast('Replay failed', 'error');
      }).finally(() => {
        if (btn) { btn.disabled = false; btn.textContent = '♻ Run replay'; }
      });
    }

    return h.mount({open: loadProviderCalls, load: loadProviderCalls, reload: _pcDebouncedReload, follow: _pcAutoFollowChange, live: _pcAppendLive, show: openProviderCallModal, close: closeProviderCallModal, sub: pcSwitchSub, replay: submitProviderCallReplay, reset: pcResetReplayPrompt}, 'provider-calls', `
    <div class="section">
      <div class="section-title" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <span>&#128268; Provider Call Inspector</span>
        <span id="pcLiveDot" class="badge" style="font-size:11px;background:var(--green,#22c55e);color:white">LIVE</span>
        <span id="pcCount" style="font-size:11px;color:var(--text-dim)"></span>
        <div style="margin-left:auto;display:flex;gap:6px;flex-wrap:wrap;align-items:center">
          <select id="pcFilterProvider" class="filter-select" data-change="load" aria-label="Filter by provider">
            <option value="">All providers</option>
            <option value="anthropic">anthropic</option>
            <option value="openai">openai</option>
            <option value="ollama">ollama</option>
            <option value="claudecode">claudecode</option>
            <option value="copilot">copilot</option>
            <option value="mock">mock</option>
          </select>
          <input id="pcFilterTaskID" class="form-input" type="number" min="0" placeholder="task id" style="max-width:90px;padding:3px 6px;font-size:11px" data-input="reload" aria-label="Filter by task id">
          <label class="filter-check" style="font-size:11px"><input type="checkbox" id="pcAutoFollow" checked data-change="follow"> Auto-follow</label>
          <button class="btn" style="padding:3px 10px;font-size:11px" data-act="load" title="Refresh">&#x21bb; Refresh</button>
        </div>
      </div>
      <div style="font-size:12px;color:var(--text-dim);margin-bottom:8px">
        Every Provider.Complete invocation is recorded with full prompt, response, and synthetic headers (secrets redacted). Click any row to inspect or replay.
      </div>
      <div id="pcEmpty" style="display:none;color:var(--muted);font-size:13px;padding:18px 0;text-align:center">
        <h3>No provider calls yet</h3>
        <p>Trigger a task or use any AI command. Calls appear here in real time.</p>
      </div>
      <div id="pcTableWrap" class="table-scroll" style="overflow:auto;max-height:70vh;border:1px solid var(--border);border-radius:6px">
        <table id="pcTable" style="width:100%;border-collapse:collapse;font-size:12px">
          <thead style="position:sticky;top:0;background:var(--bg-elev);z-index:1">
            <tr>
              <th style="padding:6px 10px;text-align:left;border-bottom:1px solid var(--border);font-weight:600">Time</th>
              <th style="padding:6px 10px;text-align:left;border-bottom:1px solid var(--border);font-weight:600">Status</th>
              <th style="padding:6px 10px;text-align:left;border-bottom:1px solid var(--border);font-weight:600">Provider</th>
              <th style="padding:6px 10px;text-align:left;border-bottom:1px solid var(--border);font-weight:600">Model</th>
              <th style="padding:6px 10px;text-align:left;border-bottom:1px solid var(--border);font-weight:600">Task</th>
              <th style="padding:6px 10px;text-align:right;border-bottom:1px solid var(--border);font-weight:600">In tok</th>
              <th style="padding:6px 10px;text-align:right;border-bottom:1px solid var(--border);font-weight:600">Out tok</th>
              <th style="padding:6px 10px;text-align:right;border-bottom:1px solid var(--border);font-weight:600">Latency</th>
            </tr>
          </thead>
          <tbody id="pcTbody"></tbody>
        </table>
      </div>
    </div>
    `, `
    <div id="pcModal" data-overlay="flex" class="modal-backdrop" style="display:none" data-dismiss="close">
      <div class="modal-card" style="max-width:1280px;width:97%;max-height:92vh;display:flex;flex-direction:column">
        <div class="modal-header">
          <span class="section-title" id="pcModalTitle" style="margin:0">Provider call</span>
          <button class="btn" data-act="close" aria-label="Close">Close</button>
        </div>

        <div id="pcModalMeta" style="font-size:12px;color:var(--text-dim);padding:6px 14px;display:flex;flex-wrap:wrap;gap:14px"></div>

        <div style="padding:0 14px;display:flex;flex-wrap:wrap;gap:8px;border-bottom:1px solid var(--border)" role="tablist">
          <button class="tab-btn pc-subtab active" data-pc-sub="prompt"   data-act="sub" data-arg="prompt">Prompt</button>
          <button class="tab-btn pc-subtab"        data-pc-sub="response" data-act="sub" data-arg="response">Response</button>
          <button class="tab-btn pc-subtab"        data-pc-sub="headers"  data-act="sub" data-arg="headers">Headers</button>
          <button class="tab-btn pc-subtab"        data-pc-sub="replay"   data-act="sub" data-arg="replay">Replay</button>
        </div>

        <div style="flex:1;min-height:0;overflow:auto;padding:10px 14px">
          <div id="pcSub-prompt" class="pc-subpanel" style="display:block">
            <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.6px;margin-bottom:4px">System prompt</div>
            <pre id="pcSystemPrompt" class="pc-pre" style="border:1px solid var(--border);padding:8px;font-size:12px;background:var(--bg-elev);border-radius:6px;white-space:pre-wrap;word-break:break-word;max-height:200px;overflow:auto;margin-bottom:10px"></pre>
            <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.6px;margin-bottom:4px">User prompt</div>
            <pre id="pcPrompt" class="pc-pre" style="border:1px solid var(--border);padding:8px;font-size:12px;background:var(--bg-elev);border-radius:6px;white-space:pre-wrap;word-break:break-word"></pre>
          </div>

          <div id="pcSub-response" class="pc-subpanel" style="display:none">
            <div id="pcResponseError" style="display:none;color:var(--red);font-size:12px;border:1px solid var(--red);padding:8px;border-radius:6px;background:rgba(239,68,68,0.08);margin-bottom:8px"></div>
            <pre id="pcResponse" class="pc-pre" style="border:1px solid var(--border);padding:8px;font-size:12px;background:var(--bg-elev);border-radius:6px;white-space:pre-wrap;word-break:break-word"></pre>
          </div>

          <div id="pcSub-headers" class="pc-subpanel" style="display:none">
            <div style="font-size:12px;color:var(--text-dim);margin-bottom:6px">Synthetic request headers (secrets redacted before persistence).</div>
            <pre id="pcHeaders" class="pc-pre" style="border:1px solid var(--border);padding:8px;font-size:12px;background:var(--bg-elev);border-radius:6px;white-space:pre-wrap;word-break:break-word"></pre>
          </div>

          <div id="pcSub-replay" class="pc-subpanel" style="display:none">
            <div style="font-size:12px;color:var(--text-dim);margin-bottom:8px">Re-run this call against the project's current provider config. Edits below are applied; leave fields blank to replay verbatim.</div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px">
              <input id="pcReplayModel" class="form-input" placeholder="Model (e.g. claude-opus-4-7)" style="flex:1;min-width:220px"/>
              <button class="btn primary" id="pcReplayRun" data-act="replay">&#9851; Run replay</button>
              <button class="btn" data-act="reset" title="Reset edits to the original prompt">Reset</button>
            </div>
            <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.6px;margin-bottom:4px">System prompt (editable)</div>
            <textarea id="pcReplaySystem" class="form-input" rows="3" style="width:100%;font-family:monospace;font-size:12px;margin-bottom:8px"></textarea>
            <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.6px;margin-bottom:4px">User prompt (editable)</div>
            <textarea id="pcReplayPrompt" class="form-input" rows="10" style="width:100%;font-family:monospace;font-size:12px"></textarea>

            <div id="pcReplayResult" style="margin-top:14px;display:none">
              <div id="pcReplayMeta" style="font-size:12px;color:var(--text-dim);margin-bottom:6px"></div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;min-height:280px">
                <div style="display:flex;flex-direction:column;min-height:0">
                  <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.6px;padding:4px 0">Original</div>
                  <pre id="pcReplayOriginal" class="diff-pane" style="flex:1;overflow:auto;border:1px solid var(--border);padding:8px;font-size:12px;background:var(--bg-elev);border-radius:6px;white-space:pre-wrap;word-break:break-word;min-height:240px"></pre>
                </div>
                <div style="display:flex;flex-direction:column;min-height:0">
                  <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.6px;padding:4px 0">Replayed</div>
                  <pre id="pcReplayNew" class="diff-pane" style="flex:1;overflow:auto;border:1px solid var(--border);padding:8px;font-size:12px;background:var(--bg-elev);border-radius:6px;white-space:pre-wrap;word-break:break-word;min-height:240px"></pre>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    `);
  };
})();
