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
//
// Fetched on the tab's first open since Task 20386 (static.go,
// deferredScripts), markup included: first paint has no room for an admin-only
// panel most sessions never open. It runs outside the dashboard's IIFE, so it
// is handed the helpers it calls, and the only name it puts on window is the
// factory.
(function () {
  'use strict';

  window.cloopAuditPanel = function (h) {
    const {api, esc, toast, pUrl} = h;

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

    function loadAudit(opts) {
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
    }

    function loadMoreAudit() { return loadAudit({append: true}); }

    function applyAuditFilters() { return loadAudit(); }

    // toggleAuditMerged re-reads the trail under the new scope and re-verifies with
    // it. The badge has to move too: in merged mode it speaks for both chains, and
    // leaving it reporting only the project's would put a green light over a hub
    // chain nobody checked.
    function toggleAuditMerged() {
      return loadAudit().then(() => verifyAuditChain());
    }

    function resetAuditFilters() {
      ['auditFilterActor','auditFilterEntityType','auditFilterEntityID',
       'auditFilterEventType','auditFilterSince','auditFilterUntil','auditFilterSearch']
        .forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
      return loadAudit();
    }

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

    function copyAuditAsJSON() {
      if (!auditState.rows.length) { toast('Nothing to copy', 'err'); return; }
      _auditCopy(JSON.stringify(auditState.rows, null, 2),
        auditState.rows.length + ' events copied as JSON');
    }

    function _auditCopy(text, okMsg) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text)
          .then(() => toast(okMsg, 'ok'))
          .catch(() => toast('Copy failed — select the text manually', 'err'));
      } else {
        toast('Clipboard unavailable — select the text manually', 'err');
      }
    }

    // A chain with audit.gap rows verifies but is not complete; amber, not green.
    function _auditBadgeClass(badge, cls) {
      badge.className = cls === 'gaps' ? 'audit-integrity' : 'audit-integrity ' + cls;
      badge.style.cssText = cls === 'gaps'
        ? 'border-color:var(--yellow);background:rgba(210,153,34,.12);color:var(--yellow)' : '';
    }

    function _auditGapText(gaps, events) {
      return gaps + ' recorded gap' + (gaps === 1 ? '' : 's') + ' covering ' +
        (events || 0) + ' lost event' + (events === 1 ? '' : 's');
    }

    // Failed appends this hub has not recorded yet: in no chain, so only here.
    function _auditRenderUnrecorded(list) {
      const el = document.getElementById('auditUnrecorded');
      if (!el) return;
      list = Array.isArray(list) ? list : [];
      el.style.display = list.length ? '' : 'none';
      el.textContent = list.map(c => {
        const u = c.unrecorded || {};
        return 'This hub could not append ' + (u.events || 0) + ' audit event' + (u.events === 1 ? '' : 's') +
          ' to ' + (c.path || '?') + ' since ' + (u.first_at || '?') + ' and has not recorded them yet' +
          (u.last_error ? ' (last error: ' + u.last_error + ')' : '') +
          '. They are written as an audit.gap row once the database takes writes.';
      }).join('\n');
    }

    function verifyAuditChain() {
      const badge = document.getElementById('auditIntegrity');
      const text  = document.getElementById('auditIntegrityText');
      if (badge) { _auditBadgeClass(badge, 'unknown'); }
      if (text)  { text.textContent = 'verifying…'; }

      const vBase = pUrl('/api/audit/verify');
      const vUrl = _auditMergedEnabled()
        ? vBase + (vBase.indexOf('?') === -1 ? '?' : '&') + 'source=all'
        : vBase;

      return api(vUrl).then(d => {
        d = d || {};
        _auditRenderUnrecorded(d.unrecorded);
        if (!badge || !text) return d;
        // A merged verification carries one verdict per chain, and the top-level
        // fields describe only the project's. Branching on the array rather than on
        // the toggle keeps the badge honest against a server that ignored ?source=.
        if (Array.isArray(d.chains) && d.chains.length) {
          _auditRenderMergedVerdict(badge, text, d);
        } else if (d.ok && d.gaps) {
          _auditBadgeClass(badge, 'gaps');
          text.textContent = 'Chain intact — ' + (d.total || 0) + ' events verified, ' +
            _auditGapText(d.gaps, d.gap_events);
          badge.title = 'Every row hash matched, and audit.gap rows record events that could not be ' +
            'appended (the database was locked, read-only or full).\n' +
            (d.gap_ids && d.gap_ids.length ? 'gap rows: #' + d.gap_ids.join(', #') + '\n' : '') +
            'Checked at ' + (d.checked_at || '');
        } else if (d.ok && d.anchored) {
          // A pruned chain verifies, but not from the beginning. Saying only
          // "intact" over a trail whose early history has been archived elsewhere
          // is true and misleading; the badge has to name the boundary.
          _auditBadgeClass(badge, 'ok');
          text.textContent = 'Chain intact from #' + (d.verified_from_id || '?') +
            ' — ' + (d.total || 0) + ' event' + (d.total === 1 ? '' : 's') + ' verified, ' +
            (d.pruned_count || 0) + ' archived';
          badge.title = 'Every row hash matched, and the first row links to the retention anchor ' +
            'for the pruned prefix.\n' +
            (d.archive_path   ? 'archive: ' + d.archive_path   + '\n' : '') +
            (d.archive_sha256 ? 'sha256:  ' + d.archive_sha256 + '\n' : '') +
            'Checked at ' + (d.checked_at || '');
        } else if (d.ok) {
          _auditBadgeClass(badge, 'ok');
          text.textContent = 'Chain intact — ' + (d.total || 0) + ' event' + (d.total === 1 ? '' : 's') + ' verified';
          badge.title = 'Every row hash was recomputed from the genesis row and matched. Checked at ' + (d.checked_at || '');
        } else {
          _auditBadgeClass(badge, 'broken');
          text.textContent = 'CHAIN BROKEN at #' + (d.break_at_id || '?');
          // The full hashes go in the tooltip: they are the evidence, and
          // truncating them would leave an operator unable to act on the finding.
          badge.title = (d.reason || 'chain verification failed') +
            (d.expected_hash ? '\nexpected: ' + d.expected_hash : '') +
            (d.actual_hash   ? '\nactual:   ' + d.actual_hash   : '');
        }
        return d;
      }).catch(err => {
        if (badge) _auditBadgeClass(badge, 'unknown');
        if (text)  text.textContent = 'integrity unknown';
        if (badge) badge.title = 'Could not verify: ' + ((err && err.message) || String(err));
      });
    }

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
        (c.ok ? (c.gaps ? 'GAPS ' : 'OK   ') : 'FAIL ') + (c.source || '?') + ' — ' + (c.dir || '?') +
        ' (' + (c.total || 0) + ' event' + (c.total === 1 ? '' : 's') + ')' +
        (c.gaps ? ', ' + _auditGapText(c.gaps, c.gap_events) : '') +
        (c.break_at_id ? ', break at #' + c.break_at_id : '') +
        (c.error ? ', unreadable: ' + c.error : '') +
        (!c.ok && c.reason ? ', ' + c.reason : '')
      ).join('\n');
      const gaps = chains.reduce((n, c) => n + (c.ok && c.gaps ? c.gaps : 0), 0);
      const gapEvents = chains.reduce((n, c) => n + (c.ok && c.gaps ? (c.gap_events || 0) : 0), 0);

      if (!bad.length) {
        _auditBadgeClass(badge, gaps ? 'gaps' : 'ok');
        text.textContent = chains.length + ' chain' + (chains.length === 1 ? '' : 's') +
          ' intact — ' + total + ' event' + (total === 1 ? '' : 's') + ' verified' +
          (gaps ? ', ' + _auditGapText(gaps, gapEvents) : '');
        badge.title = 'Every row hash matched in each chain read.\n' + detail +
          '\nChecked at ' + (d.checked_at || '');
        return;
      }
      _auditBadgeClass(badge, 'broken');
      text.textContent = bad.length + ' of ' + chains.length + ' chain' +
        (chains.length === 1 ? '' : 's') + ' FAILED — ' + (bad[0].source || '?') +
        (bad[0].break_at_id ? ' at #' + bad[0].break_at_id : '');
      badge.title = detail + '\nChecked at ' + (d.checked_at || '');
    }

    // open runs on every visit to the tab: the trail, and whether it is intact.
    function open() { loadAudit(); verifyAuditChain(); }
    // A fleet change is an audited event, so the trail grew (04-realtime.js).
    function refresh() { return loadAudit(); }
    // The trail grew (audit_append). Only page one is redrawn: paging back to
    // the top under someone reading page 4 would be worse than a stale view.
    function onAppend() { if (auditState.offset === 0) loadAudit(); }

    // filterTo opens the trail scoped to one secret or grant, for the Secrets
    // panel's Audit buttons. The two use different filters because the trail
    // indexes them differently: the broker's auditor records the *secret* as
    // the row's entity and carries the grant id inside the payload, so a grant
    // is found by payload search.
    function filterTo(kind, id) {
      const entity = document.getElementById('auditFilterEntityID');
      const search = document.getElementById('auditFilterSearch');
      if (entity) entity.value = (kind === 'secret') ? (id || '') : '';
      if (search) search.value = (kind === 'secret') ? '' : (id || '');
      window.switchTab('audit');
    }

    return h.mount({
      open, refresh, onAppend, filterTo, loadAudit, loadMoreAudit, applyAuditFilters,
      toggleAuditMerged, resetAuditFilters, copyAuditAsJSON, verifyAuditChain
    }, 'audit', `
      <div class="section">
        <div class="section-title" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
          Audit trail
          <span style="font-size:11px;font-weight:400;color:var(--muted)">global &mdash; admin only</span>
          <span id="auditIntegrity" class="audit-integrity unknown" title="Hash-chain integrity">
            <span class="audit-integrity-dot"></span><span id="auditIntegrityText">checking&hellip;</span>
          </span>
          <button class="btn" style="padding:4px 10px;font-size:12px;margin-left:auto" data-act="verifyAuditChain" title="Recompute the SHA-256 chain from the genesis row">&#128274; Verify chain</button>
          <button class="btn" style="padding:4px 10px;font-size:12px" data-act="copyAuditAsJSON" title="Copy the rows currently shown as JSON">&#128203; Copy as JSON</button>
          <button class="btn" style="padding:4px 10px;font-size:12px" data-act="loadAudit" title="Reload the trail">&#8635; Refresh</button>
          <label for="auditMergeSources" style="display:flex;align-items:center;gap:5px;font-size:11.5px;font-weight:400;color:var(--muted);cursor:pointer" title="Read this project's journal and the hub's control-plane journal as one trail, ordered by timestamp. Verification then covers both chains.">
            <input type="checkbox" id="auditMergeSources" data-change="toggleAuditMerged" style="margin:0;cursor:pointer">Merge both chains
          </label>
        </div>
        <p style="font-size:12px;color:var(--muted);margin-top:4px;margin-bottom:12px">
          Append-only, hash-chained record of every state mutation: task changes, config writes,
          authorization decisions, credential leases, egress grants, and executor fleet changes.
          Each row's hash covers the one before it, so any edit, deletion, or insertion made behind
          cloop's back breaks the chain and is reported above. The trail is kept in <em>two</em>
          independently chained journals &mdash; this project's <code>.cloop/state.db</code> holds its
          own task and config history, while the hub's control-plane database holds the fleet-wide
          record of executors, secret leases, workspaces and image policy. &ldquo;Merge both chains&rdquo;
          reads them together, labels every row with the chain it came from, and verifies each one
          separately. Export the same data with
          <code>cloop audit-log export --format jsonl|csv|cef</code>.
        </p>

        <div class="audit-filters">
          <div class="audit-field">
            <label class="form-label" for="auditFilterActor">Actor</label>
            <select id="auditFilterActor" class="form-select" data-change="applyAuditFilters"><option value="">Any</option></select>
          </div>
          <div class="audit-field">
            <label class="form-label" for="auditFilterEntityType">Entity type</label>
            <select id="auditFilterEntityType" class="form-select" data-change="applyAuditFilters"><option value="">Any</option></select>
          </div>
          <div class="audit-field">
            <label class="form-label" for="auditFilterEntityID">Entity ID</label>
            <input id="auditFilterEntityID" class="form-input" type="text" placeholder="e.g. 42" data-change="applyAuditFilters">
          </div>
          <div class="audit-field">
            <label class="form-label" for="auditFilterEventType">Event type</label>
            <input id="auditFilterEventType" class="form-input" type="text" placeholder="e.g. secret.lease" data-change="applyAuditFilters">
          </div>
          <div class="audit-field">
            <label class="form-label" for="auditFilterSince">Since</label>
            <input id="auditFilterSince" class="form-input" type="text" placeholder="24h, 7d, 2026-01-31" data-change="applyAuditFilters">
          </div>
          <div class="audit-field">
            <label class="form-label" for="auditFilterUntil">Until</label>
            <input id="auditFilterUntil" class="form-input" type="text" placeholder="1h, 2026-02-01" data-change="applyAuditFilters">
          </div>
          <div class="audit-field wide">
            <label class="form-label" for="auditFilterSearch">Payload contains</label>
            <input id="auditFilterSearch" class="form-input" type="text" placeholder="substring match" data-change="applyAuditFilters">
          </div>
          <div class="audit-field" style="flex:0 0 auto;min-width:0">
            <label class="form-label">&nbsp;</label>
            <button class="btn" style="padding:5px 12px;font-size:12px" data-act="resetAuditFilters">Clear</button>
          </div>
        </div>

        <div id="auditUnrecorded" class="exec-banner warn" role="status" style="display:none;white-space:pre-line;margin-bottom:10px"></div>
        <div id="auditSummary" style="font-size:11.5px;color:var(--muted);margin-bottom:8px"></div>
        <div id="auditEmpty" class="audit-empty" style="display:none">No audit events match these filters.</div>
        <div style="overflow-x:auto">
          <table class="audit-table" id="auditTable" style="display:none">
            <thead>
              <tr>
                <th style="width:60px">ID</th>
                <th style="width:170px">Time (UTC)</th>
                <th style="width:110px">Source</th>
                <th style="width:180px">Actor</th>
                <th style="width:170px">Event</th>
                <th class="audit-hide-sm">Entity</th>
              </tr>
            </thead>
            <tbody id="auditBody"></tbody>
          </table>
        </div>
        <div id="auditMore" style="display:none;text-align:center;padding:12px 0">
          <button class="btn" style="padding:5px 14px;font-size:12px" data-act="loadMoreAudit">Load more</button>
        </div>
      </div>`);
  };
})();
