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
const auditState = {
  rows: [],
  offset: 0,
  total: 0,
  limit: 100,
  expanded: null,   // id of the row whose detail is open, or null
  loading: false,
};

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

  const base = pUrl('/api/audit');
  return api(base + (base.indexOf('?') === -1 ? '?' : '&') + params.toString())
    .then(d => {
      d = d || {};
      const events = Array.isArray(d.events) ? d.events : [];
      auditState.rows   = append ? auditState.rows.concat(events) : events;
      auditState.offset = (append ? auditState.offset : 0) + events.length;
      auditState.total  = typeof d.total === 'number' ? d.total : auditState.rows.length;
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
    if (summary) summary.textContent = '';
    body.innerHTML = '';
    return;
  }
  if (empty) empty.style.display = 'none';
  if (table) table.style.display = '';

  const html = [];
  rows.forEach(ev => {
    const open = auditState.expanded === ev.id;
    const ts = String(ev.timestamp || '').replace('T', ' ').replace(/\.\d+Z?$/, '').replace('Z', '');
    html.push(
      '<tr class="audit-row' + (open ? ' expanded' : '') + '" data-audit-id="' + esc(String(ev.id)) + '">' +
        '<td class="audit-id">#' + esc(String(ev.id)) + '</td>' +
        '<td class="audit-time">' + esc(ts) + '</td>' +
        '<td class="audit-actor">' + esc(ev.actor || '—') + '</td>' +
        '<td><span class="audit-type ' + _auditSeverityClass(ev.event_type) + '">' + esc(ev.event_type || '—') + '</span></td>' +
        '<td class="audit-entity audit-hide-sm">' + esc(ev.entity_type || '') +
          (ev.entity_id ? ' / ' + esc(ev.entity_id) : '') + '</td>' +
      '</tr>'
    );
    if (open) {
      html.push(
        '<tr class="audit-detail"><td colspan="5"><div class="audit-detail-inner">' +
          '<div class="audit-hashes">' +
            '<span>row_hash <code>' + esc(ev.row_hash || '') + '</code></span>' +
            '<span>prev_hash <code>' + esc(ev.prev_hash || '') + '</code></span>' +
          '</div>' +
          '<pre>' + esc(_auditPrettyPayload(ev.payload)) + '</pre>' +
          '<div style="display:flex;gap:8px">' +
            '<button class="btn" style="padding:4px 10px;font-size:11.5px" data-audit-copy="' + esc(String(ev.id)) + '">Copy this row as JSON</button>' +
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
      const id = Number(tr.getAttribute('data-audit-id'));
      auditState.expanded = (auditState.expanded === id) ? null : id;
      _renderAudit(d);
    });
  });
  body.querySelectorAll('[data-audit-copy]').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const id = Number(btn.getAttribute('data-audit-copy'));
      const row = auditState.rows.filter(r => r.id === id)[0];
      if (row) _auditCopy(JSON.stringify(row, null, 2), 'Row copied as JSON');
    });
  });

  if (summary) {
    const shown = rows.length;
    const total = auditState.total;
    summary.textContent = 'Showing ' + shown + ' of ' + total + ' matching event' +
      (total === 1 ? '' : 's') +
      (typeof d.all === 'number' && d.all !== total ? ' (' + d.all + ' in the trail)' : '');
  }
  if (more) more.style.display = (rows.length < auditState.total) ? '' : 'none';
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

  return api(pUrl('/api/audit/verify')).then(d => {
    d = d || {};
    if (!badge || !text) return d;
    if (d.ok) {
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

