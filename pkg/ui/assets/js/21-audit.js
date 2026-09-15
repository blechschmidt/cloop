// ── Audit panel (Task 20167) ────────────────────────────────────────────────
//
// Global and admin-only. Every filter is applied server-side in SQLite: the
// trail is unbounded, so filtering in the browser would work in development
// and fail on the deployments that actually need an audit panel.
//
// Rows accumulate across pages rather than being replaced, so "Load more"
// extends the view the way a log reader expects. auditState.offset is the
// paging cursor; it doubles as the "am I on page one" test the WebSocket
// handler uses before auto-refreshing under the reader.
//
// Merged mode (Task 20292) asks the server for both chains — this project's
// journal and the hub's — because the two record different halves of the same
// story and reading one gives a confident, incomplete answer.
const auditState = {
  rows: [],
  offset: 0,
  total: 0,
  limit: 100,
  expanded: null,   // key of the row whose detail is open, or null
  loading: false,
  chains: [],       // what the last response said it read
};

// _auditRowKey identifies a row across a merge. ids restart per chain, so
// "#41" names two different events in merged mode and would expand both; the
// source qualifies it, mirroring auditmerge's control-plane#41 reference form.
function _auditRowKey(ev) {
  return (ev && ev.source ? ev.source + '#' : '') + String(ev ? ev.id : '');
}

// _auditMergedEnabled reads the toggle. Absent element means off, so the panel
// still works if the control is ever removed.
function _auditMergedEnabled() {
  const el = document.getElementById('auditMergeSources');
  return !!(el && el.checked);
}

window.loadAudit = function(opts) {
  const append = !!(opts && opts.append);
  if (auditState.loading) return Promise.resolve();
  auditState.loading = true;

  if (!append) {
    auditState.offset = 0;
    auditState.expanded = null;
  }

  const params = new URLSearchParams();
  const actor      = _auditFieldValue('auditFilterActor');
  const entityType = _auditFieldValue('auditFilterEntityType');
  const entityID   = _auditFieldValue('auditFilterEntityID');
  const eventType  = _auditFieldValue('auditFilterEventType');
  const since      = _auditFieldValue('auditFilterSince');
  const until      = _auditFieldValue('auditFilterUntil');
  const search     = _auditFieldValue('auditFilterSearch');
  if (actor)      params.set('actor', actor);
  if (entityType) params.set('entity_type', entityType);
  if (entityID)   params.set('entity_id', entityID);
  if (eventType)  params.set('event_type', eventType);
  if (since)      params.set('since', since);
  if (until)      params.set('until', until);
  if (search)     params.set('q', search);
  params.set('limit', String(auditState.limit));
  params.set('offset', String(append ? auditState.offset : 0));
  if (_auditMergedEnabled()) params.set('source', 'all');

  const base = pUrl('/api/audit');
  return api(base + (base.indexOf('?') === -1 ? '?' : '&') + params.toString())
    .then(d => {
      d = d || {};
      const events = Array.isArray(d.events) ? d.events : [];
      auditState.rows   = append ? auditState.rows.concat(events) : events;
      auditState.offset = (append ? auditState.offset : 0) + events.length;
      auditState.total  = typeof d.total === 'number' ? d.total : auditState.rows.length;
      auditState.chains = Array.isArray(d.chains) ? d.chains : [];
      _auditPopulateFacets(d);
      _renderAudit(d);
      return d;
    })
    .catch(err => {
      console.warn('audit load error', err);
      const body = document.getElementById('auditBody');
      const table = document.getElementById('auditTable');
      const empty = document.getElementById('auditEmpty');
      if (table) table.style.display = 'none';
      if (empty) {
        empty.style.display = '';
        // 403/404 here is the expected answer for a non-admin, not a fault:
        // say so plainly rather than showing a scary failure.
        const msg = (err && err.message) ? String(err.message) : String(err);
        empty.innerHTML = /forbidden|not permit|403|404|not exist/i.test(msg)
          ? 'Your role does not permit reading the audit trail.'
          : 'Failed to load the audit trail: ' + esc(msg);
      }
      if (body) body.innerHTML = '';
    })
    .finally(() => { auditState.loading = false; });
};

window.loadMoreAudit = function() { return loadAudit({append: true}); };

window.applyAuditFilters = function() { return loadAudit(); };

// toggleAuditMerged re-reads the trail under the new scope and re-verifies with
// it. The badge has to move too: in merged mode it speaks for both chains, and
// leaving it reporting only the project's would put a green light over a hub
// chain nobody checked.
window.toggleAuditMerged = function() {
  return loadAudit().then(() => verifyAuditChain());
};

window.resetAuditFilters = function() {
  ['auditFilterActor','auditFilterEntityType','auditFilterEntityID',
   'auditFilterEventType','auditFilterSince','auditFilterUntil','auditFilterSearch']
    .forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
  return loadAudit();
};

function _auditFieldValue(id) {
  const el = document.getElementById(id);
  return el && el.value ? String(el.value).trim() : '';
}

// _auditPopulateFacets refills the actor and entity-type dropdowns from the
// values the server actually saw, preserving the current selection so a
// refresh does not silently drop the filter the user is reading under.
function _auditPopulateFacets(d) {
  _auditFillSelect('auditFilterActor', d.actors);
  _auditFillSelect('auditFilterEntityType', d.entity_types);
}

function _auditFillSelect(id, values) {
  const sel = document.getElementById(id);
  if (!sel || !Array.isArray(values)) return;
  const current = sel.value;
  const opts = ['<option value="">Any</option>'];
  values.forEach(v => {
    opts.push('<option value="' + esc(v) + '">' + esc(v) + '</option>');
  });
  sel.innerHTML = opts.join('');
  // Keep a selection the server no longer lists: it is still a valid filter
  // and clearing it under the user would silently widen their view.
  if (current) {
    if (values.indexOf(current) === -1) {
      sel.insertAdjacentHTML('beforeend', '<option value="' + esc(current) + '">' + esc(current) + '</option>');
    }
    sel.value = current;
  }
}

// _auditSeverityClass mirrors severityFor() in pkg/auditexport so a row that
// would page someone in the SIEM is also the row that stands out here.
function _auditSeverityClass(eventType) {
  const t = String(eventType || '');
  if (/^authz\.denied/.test(t) || /\.den(y|ied)$/.test(t)) return 'sev-high';
  if (/^(secret|egress)\./.test(t)) return 'sev-high';
  if (/^executor\./.test(t) || /^config\./.test(t) || t === 'task.delete') return 'sev-mid';
  return 'sev-low';
}

function _renderAudit(d) {
  const body    = document.getElementById('auditBody');
  const table   = document.getElementById('auditTable');
  const empty   = document.getElementById('auditEmpty');
  const more    = document.getElementById('auditMore');
  const summary = document.getElementById('auditSummary');
  if (!body) return;

  const rows = auditState.rows;
  if (!rows.length) {
    if (table) table.style.display = 'none';
    if (more)  more.style.display = 'none';
    if (empty) { empty.style.display = ''; empty.textContent = 'No audit events match these filters.'; }
    // Coverage survives an empty result: "nothing matched" only means
    // something once the reader knows what was searched.
    if (summary) summary.textContent = _auditCoverage();
    body.innerHTML = '';
    return;
  }
  if (empty) empty.style.display = 'none';
  if (table) table.style.display = '';

  const html = [];
  rows.forEach(ev => {
    const key = _auditRowKey(ev);
    const open = auditState.expanded === key;
    const ts = String(ev.timestamp || '').replace('T', ' ').replace(/\.\d+Z?$/, '').replace('Z', '');
    // The source cell is always rendered so the column never goes ragged; a
    // single-chain read sends no source and the cell says so with a dash
    // rather than guessing which chain the row came from.
    const src = ev.source
      ? '<span class="audit-type" title="' + esc(ev.dir || '') + '">' + esc(ev.source) + '</span>'
      : '—';
    html.push(
      '<tr class="audit-row' + (open ? ' expanded' : '') + '" data-audit-id="' + esc(key) + '">' +
        '<td class="audit-id">#' + esc(String(ev.id)) + '</td>' +
        '<td class="audit-time">' + esc(ts) + '</td>' +
        '<td class="audit-src">' + src + '</td>' +
        '<td class="audit-actor">' + esc(ev.actor || '—') + '</td>' +
        '<td><span class="audit-type ' + _auditSeverityClass(ev.event_type) + '">' + esc(ev.event_type || '—') + '</span></td>' +
        '<td class="audit-entity audit-hide-sm">' + esc(ev.entity_type || '') +
          (ev.entity_id ? ' / ' + esc(ev.entity_id) : '') + '</td>' +
      '</tr>'
    );
    if (open) {
      html.push(
        '<tr class="audit-detail"><td colspan="6"><div class="audit-detail-inner">' +
          '<div class="audit-hashes">' +
            (ev.dir ? '<span>chain <code>' + esc(ev.source || '') + ' &mdash; ' + esc(ev.dir) + '</code></span>' : '') +
            '<span>row_hash <code>' + esc(ev.row_hash || '') + '</code></span>' +
            '<span>prev_hash <code>' + esc(ev.prev_hash || '') + '</code></span>' +
          '</div>' +
          '<pre>' + esc(_auditPrettyPayload(ev.payload)) + '</pre>' +
          '<div style="display:flex;gap:8px">' +
            '<button class="btn" style="padding:4px 10px;font-size:11.5px" data-audit-copy="' + esc(key) + '">Copy this row as JSON</button>' +
          '</div>' +
        '</div></td></tr>'
      );
    }
  });
  body.innerHTML = html.join('');

  // Listeners rather than inline onclick: the ids are numeric here, but the
  // panel renders actor strings and payloads that would need escaping twice
  // to survive an HTML attribute, and that is the bug this codebase keeps
  // rediscovering. See the note on data-* dispatch in renderProjects.
  body.querySelectorAll('.audit-row').forEach(tr => {
    tr.addEventListener('click', () => {
      const key = tr.getAttribute('data-audit-id');
      auditState.expanded = (auditState.expanded === key) ? null : key;
      _renderAudit(d);
    });
  });
  body.querySelectorAll('[data-audit-copy]').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const key = btn.getAttribute('data-audit-copy');
      const row = auditState.rows.filter(r => _auditRowKey(r) === key)[0];
      if (row) _auditCopy(JSON.stringify(row, null, 2), 'Row copied as JSON');
    });
  });

  if (summary) {
    const shown = rows.length;
    const total = auditState.total;
    const coverage = _auditCoverage();
    summary.textContent = 'Showing ' + shown + ' of ' + total + ' matching event' +
      (total === 1 ? '' : 's') +
      (typeof d.all === 'number' && d.all !== total ? ' (' + d.all + ' in the trail)' : '') +
      (coverage ? ' · ' + coverage : '');
  }
  if (more) more.style.display = (rows.length < auditState.total) ? '' : 'none';
}

// _auditCoverage names the databases the current view was read from.
//
// "No results" is only an answer if you know what was searched. In merged mode
// the summary therefore states the chains rather than leaving the operator to
// infer them from the toggle — and when the two collapse to one it says so,
// because on the hub's own project both scopes resolve to the same file and an
// unexplained "1 chain" reads like half the merge failed.
function _auditCoverage() {
  if (!_auditMergedEnabled()) return '';
  const chains = auditState.chains;
  if (!chains.length) return 'merged view: no audit database found to read';
  const names = chains.map(c => String(c.source || '?') + ' (' + String(c.dir || '?') + ')');
  return 'merged across ' + chains.length + ' chain' + (chains.length === 1 ? '' : 's') +
    ': ' + names.join(', ') +
    (chains.length === 1 ? ' — this project is the hub, so both scopes are one database' : '');
}

// _auditPrettyPayload re-indents the payload when it is JSON, which it is for
// every emitter in pkg/statedb. Non-JSON is shown verbatim rather than
// hidden: a row that does not parse is exactly the row worth looking at.
function _auditPrettyPayload(payload) {
  const raw = payload == null ? '' : String(payload);
  if (!raw) return '(no payload)';
  try { return JSON.stringify(JSON.parse(raw), null, 2); } catch(_) { return raw; }
}

window.copyAuditAsJSON = function() {
  if (!auditState.rows.length) { toast('Nothing to copy', 'err'); return; }
  _auditCopy(JSON.stringify(auditState.rows, null, 2),
    auditState.rows.length + ' events copied as JSON');
};

function _auditCopy(text, okMsg) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text)
      .then(() => toast(okMsg, 'ok'))
      .catch(() => toast('Copy failed — select the text manually', 'err'));
  } else {
    toast('Clipboard unavailable — select the text manually', 'err');
  }
}

window.verifyAuditChain = function() {
  const badge = document.getElementById('auditIntegrity');
  const text  = document.getElementById('auditIntegrityText');
  if (badge) { badge.className = 'audit-integrity unknown'; }
  if (text)  { text.textContent = 'verifying…'; }

  const vBase = pUrl('/api/audit/verify');
  const vUrl = _auditMergedEnabled()
    ? vBase + (vBase.indexOf('?') === -1 ? '?' : '&') + 'source=all'
    : vBase;

  return api(vUrl).then(d => {
    d = d || {};
    if (!badge || !text) return d;
    // A merged verification carries one verdict per chain, and the top-level
    // fields describe only the project's. Branching on the array rather than on
    // the toggle keeps the badge honest against a server that ignored ?source=.
    if (Array.isArray(d.chains) && d.chains.length) {
      _auditRenderMergedVerdict(badge, text, d);
    } else if (d.ok && d.anchored) {
      // A pruned chain verifies, but not from the beginning. Saying only
      // "intact" over a trail whose early history has been archived elsewhere
      // is true and misleading; the badge has to name the boundary.
      badge.className = 'audit-integrity ok';
      text.textContent = 'Chain intact from #' + (d.verified_from_id || '?') +
        ' — ' + (d.total || 0) + ' event' + (d.total === 1 ? '' : 's') + ' verified, ' +
        (d.pruned_count || 0) + ' archived';
      badge.title = 'Every row hash matched, and the first row links to the retention anchor ' +
        'for the pruned prefix.\n' +
        (d.archive_path   ? 'archive: ' + d.archive_path   + '\n' : '') +
        (d.archive_sha256 ? 'sha256:  ' + d.archive_sha256 + '\n' : '') +
        'Checked at ' + (d.checked_at || '');
    } else if (d.ok) {
      badge.className = 'audit-integrity ok';
      text.textContent = 'Chain intact — ' + (d.total || 0) + ' event' + (d.total === 1 ? '' : 's') + ' verified';
      badge.title = 'Every row hash was recomputed from the genesis row and matched. Checked at ' + (d.checked_at || '');
    } else {
      badge.className = 'audit-integrity broken';
      text.textContent = 'CHAIN BROKEN at #' + (d.break_at_id || '?');
      // The full hashes go in the tooltip: they are the evidence, and
      // truncating them would leave an operator unable to act on the finding.
      badge.title = (d.reason || 'chain verification failed') +
        (d.expected_hash ? '\nexpected: ' + d.expected_hash : '') +
        (d.actual_hash   ? '\nactual:   ' + d.actual_hash   : '');
    }
    return d;
  }).catch(err => {
    if (badge) badge.className = 'audit-integrity unknown';
    if (text)  text.textContent = 'integrity unknown';
    if (badge) badge.title = 'Could not verify: ' + ((err && err.message) || String(err));
  });
};

// _auditRenderMergedVerdict renders the badge over every chain that was
// checked.
//
// The two chains are independent, so the badge fails if any of them does: an
// intact project chain must not be allowed to vouch for a tampered hub one. A
// chain that could not be read at all is also a failure — a verifier that
// reports success for a database it never opened is worse than no verifier.
function _auditRenderMergedVerdict(badge, text, d) {
  const chains = d.chains;
  const bad = chains.filter(c => !c.ok);
  const total = chains.reduce((n, c) => n + (c.total || 0), 0);
  const detail = chains.map(c =>
    (c.ok ? 'OK   ' : 'FAIL ') + (c.source || '?') + ' — ' + (c.dir || '?') +
    ' (' + (c.total || 0) + ' event' + (c.total === 1 ? '' : 's') + ')' +
    (c.break_at_id ? ', break at #' + c.break_at_id : '') +
    (c.error ? ', unreadable: ' + c.error : '') +
    (!c.ok && c.reason ? ', ' + c.reason : '')
  ).join('\n');

  if (!bad.length) {
    badge.className = 'audit-integrity ok';
    text.textContent = chains.length + ' chain' + (chains.length === 1 ? '' : 's') +
      ' intact — ' + total + ' event' + (total === 1 ? '' : 's') + ' verified';
    badge.title = 'Every row hash matched in each chain read.\n' + detail +
      '\nChecked at ' + (d.checked_at || '');
    return;
  }
  badge.className = 'audit-integrity broken';
  text.textContent = bad.length + ' of ' + chains.length + ' chain' +
    (chains.length === 1 ? '' : 's') + ' FAILED — ' + (bad[0].source || '?') +
    (bad[0].break_at_id ? ' at #' + bad[0].break_at_id : '');
  badge.title = detail + '\nChecked at ' + (d.checked_at || '');
}

