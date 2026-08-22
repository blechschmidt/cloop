// ── Provider Call Inspector tab (Task 20123) ────────────────────────────────
//
// Lists recent Provider.Complete invocations recorded by pkg/provideraudit.
// New rows arrive over WebSocket as type:"provider_call" envelopes (see
// handleRealtimeMsg below). Clicking a row opens a modal with the full
// prompt/response/headers and a Replay tab that re-runs the call (optionally
// with edits) against the project's current provider config and shows a
// side-by-side diff of original vs replayed response.

let _pcRows         = [];      // most-recent-first cached list of summaries
let _pcCurrent      = null;    // detail row currently open in the modal
let _pcAutoFollow   = true;    // when true, new live calls scroll to top
let _pcReloadTimer  = null;    // debounce for filter changes
const _PC_MAX_ROWS  = 500;     // cap in-memory list to keep render cheap

window.loadProviderCalls = function() { loadProviderCalls(); };
window.openProviderCallModal = function(id) { openProviderCallModal(id); };
window.closeProviderCallModal = function() { closeProviderCallModal(); };
window.submitProviderCallReplay = function() { submitProviderCallReplay(); };
window.pcSwitchSub = function(name) { pcSwitchSub(name); };
window.pcResetReplayPrompt = function() { pcResetReplayPrompt(); };

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
  api(url).then(data => {
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
    const onclick = 'onclick="openProviderCallModal(' + parseInt(r.id, 10) + ')"';
    return '<tr ' + onclick + ' data-pc-id="' + parseInt(r.id, 10) + '" style="transition:background .1s" onmouseover="this.style.background=\'var(--hover-bg,rgba(127,127,127,0.08))\'" onmouseout="this.style.background=\'\'">' +
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
  if (activeTab === 'provider-calls') {
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
  const url = pUrl('/api/provider-calls/' + encodeURIComponent(id));
  api(url).then(detail => {
    _pcCurrent = detail || null;
    _pcRenderModal(detail);
    document.getElementById('pcModal').style.display = 'flex';
    pcSwitchSub('prompt');
  }).catch(err => {
    toast('Failed to load call: ' + (err && err.message || err), 'error');
  });
}

function closeProviderCallModal() {
  document.getElementById('pcModal').style.display = 'none';
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

  // Prompt tab
  const sys = document.getElementById('pcSystemPrompt');
  if (sys) sys.textContent = d.system_prompt || '(no system prompt)';
  const prompt = document.getElementById('pcPrompt');
  if (prompt) prompt.textContent = d.prompt || '';

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
    if (resp)    resp.textContent     = d.response || '(empty response)';
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
  if (rPrompt) rPrompt.value = d.prompt || '';

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

