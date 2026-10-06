// ── Front-end telemetry panel (Task 20251) ──────────────────────────────────
//
// The read side of the diagnostic trail the dashboard and the glasses page
// write. Global and admin-only: a trail carries URLs, view names, user agents
// and error text from other people's sessions, which is the same class of
// cross-tenant record the Audit panel holds and is gated the same way.
//
// Two tables, in the order an investigation actually proceeds. Somebody arrives
// knowing "a wearer said it stopped responding around ten past four" and has to
// turn that into a session id before any per-event view means anything — so the
// session roll-up comes first and clicking a row filters the events below it.
//
// Filtering is server-side, like the Audit panel and for the same reason: the
// table holds tens of thousands of rows and a browser-side filter would work in
// development and fail on the deployment that needs it.
//
// Fetched on the tab's first open since Task 20386 (static.go,
// deferredScripts), markup included; the collection policy that switches the
// trail on and off is a Settings section and lives in deferred/settings.js. It
// runs outside the dashboard's IIFE, so it is handed the helpers it calls, and
// the only name it puts on window is the factory.
(function () {
  'use strict';

  window.cloopTelemetryPanel = function (h) {
    const {api, esc, toast} = h;

    const telemetryState = {
      rows: [],
      offset: 0,
      total: 0,
      limit: 200,
      loading: false,
      sessions: [],
    };

    function loadTelemetry(opts) {
      const append = !!(opts && opts.append);
      if (telemetryState.loading) return Promise.resolve();
      telemetryState.loading = true;

      if (!append) telemetryState.offset = 0;

      const params = new URLSearchParams();
      const source  = _telFieldValue('telemetryFilterSource');
      const kind    = _telFieldValue('telemetryFilterKind');
      const session = _telFieldValue('telemetryFilterSession');
      const search  = _telFieldValue('telemetryFilterSearch');
      if (source)  params.set('source', source);
      if (kind)    params.set('kind', kind);
      if (session) params.set('session', session);
      if (search)  params.set('q', search);
      params.set('limit', String(telemetryState.limit));
      params.set('offset', String(append ? telemetryState.offset : 0));

      return api('/api/telemetry?' + params.toString())
        .then(d => {
          d = d || {};
          const events = Array.isArray(d.events) ? d.events : [];
          telemetryState.rows   = append ? telemetryState.rows.concat(events) : events;
          telemetryState.offset = (append ? telemetryState.offset : 0) + events.length;
          telemetryState.total  = typeof d.total === 'number' ? d.total : telemetryState.rows.length;
          _telFillSelect('telemetryFilterSource', d.sources);
          _telFillSelect('telemetryFilterKind', d.kinds);
          _telRenderState(d);
          _telRenderEvents();
          // The session roll-up is a second query and only worth re-running when
          // the view is rebuilt, not when the reader pages further into one trail.
          if (!append) _telLoadSessions();
          return d;
        })
        .catch(err => {
          const table = document.getElementById('telemetryTable');
          const empty = document.getElementById('telemetryEmpty');
          const body  = document.getElementById('telemetryBody');
          if (table) table.style.display = 'none';
          if (body)  body.innerHTML = '';
          if (empty) {
            empty.style.display = '';
            // 403/404 is the expected answer for a non-admin, not a fault.
            const msg = (err && err.message) ? String(err.message) : String(err);
            empty.innerHTML = /forbidden|not permit|403|404|not exist/i.test(msg)
              ? 'Your role does not permit reading telemetry.'
              : 'Failed to load telemetry: ' + esc(msg);
          }
        })
        .finally(() => { telemetryState.loading = false; });
    }

    function loadMoreTelemetry() { return loadTelemetry({append: true}); }
    function applyTelemetryFilters() { return loadTelemetry(); }

    function resetTelemetryFilters() {
      ['telemetryFilterSource','telemetryFilterKind','telemetryFilterSession','telemetryFilterSearch']
        .forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
      return loadTelemetry();
    }

    // copyTelemetryAsJSON puts the rows currently on screen on the clipboard. The
    // realistic next step after finding a trail is pasting it into an issue, and
    // re-querying the API by hand to do that is friction at exactly the wrong
    // moment.
    function copyTelemetryAsJSON() {
      const text = JSON.stringify(telemetryState.rows, null, 2);
      const done = () => toast('Copied ' + telemetryState.rows.length + ' event(s)', 'ok');
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done).catch(() => {});
          return;
        }
      } catch (_) {}
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        done();
      } catch (_) {}
    }

    function _telFieldValue(id) {
      const el = document.getElementById(id);
      return el && el.value ? String(el.value).trim() : '';
    }

    // _telFillSelect refills a dropdown from the vocabulary the server reports,
    // preserving the current selection so a refresh does not silently drop the
    // filter the reader is working under.
    function _telFillSelect(id, values) {
      const sel = document.getElementById(id);
      if (!sel || !Array.isArray(values)) return;
      const current = sel.value;
      const opts = ['<option value="">Any</option>'];
      values.forEach(v => { opts.push('<option value="' + esc(v) + '">' + esc(v) + '</option>'); });
      sel.innerHTML = opts.join('');
      if (current) sel.value = current;
    }

    function _telRenderState(d) {
      const el = document.getElementById('telemetryState');
      if (!el) return;
      // Distinguishing "no events yet" from "collection is off" matters: the empty
      // table looks identical either way, and an operator who has switched it off
      // and forgotten would otherwise read the silence as a working instrument.
      el.textContent = (d && d.enabled === false)
        ? '— collection is off (Settings → Telemetry)'
        : '';
    }

    // _telTime renders the hub-side timestamp. Only this one: the client clock is
    // on the row for the gaps it explains, not as something to sort or display —
    // a wearable's absolute clock is routinely wrong.
    function _telTime(s) {
      return String(s || '').replace('T', ' ').replace(/\.\d+Z?$/, '').replace('Z', '');
    }

    function _telKindClass(kind) {
      switch (String(kind || '')) {
        case 'error':
        case 'rejection': return 'sev-high';
        case 'fetch':     return 'sev-mid';
        default:          return 'sev-low';
      }
    }

    function _telRenderEvents() {
      const body    = document.getElementById('telemetryBody');
      const table   = document.getElementById('telemetryTable');
      const empty   = document.getElementById('telemetryEmpty');
      const more    = document.getElementById('telemetryMore');
      const summary = document.getElementById('telemetrySummary');
      if (!body) return;

      const rows = telemetryState.rows;
      if (!rows.length) {
        if (table) table.style.display = 'none';
        if (more)  more.style.display = 'none';
        if (empty) { empty.style.display = ''; empty.textContent = 'No telemetry events match these filters.'; }
        if (summary) summary.textContent = '';
        body.innerHTML = '';
        return;
      }
      if (empty) empty.style.display = 'none';
      if (table) table.style.display = '';

      const html = [];
      rows.forEach(ev => {
        // The detail blob and the stack go in a title attribute rather than an
        // expander: this panel is read by someone who already knows what they are
        // looking for, and a hover is cheaper than a click per row.
        const extra = [ev.url, ev.detail, ev.stack].filter(Boolean).join('\n');
        html.push(
          '<tr class="audit-row">' +
            '<td class="audit-time">' + esc(_telTime(ev.at)) + '</td>' +
            '<td class="audit-id">' + esc(String(ev.seq || 0)) + '</td>' +
            '<td>' + esc(ev.source || '') + '</td>' +
            '<td><span class="audit-type ' + _telKindClass(ev.kind) + '">' + esc(ev.kind || '') + '</span></td>' +
            '<td class="audit-hide-sm">' + esc(ev.view || '—') + '</td>' +
            '<td title="' + esc(extra) + '">' + esc(ev.message || '') + '</td>' +
          '</tr>'
        );
      });
      body.innerHTML = html.join('');

      if (summary) {
        summary.textContent = 'Showing ' + rows.length + ' of ' + telemetryState.total + ' event(s)'
          + (_telFieldValue('telemetryFilterSession') ? ' in this session' : '');
      }
      if (more) more.style.display = (rows.length < telemetryState.total) ? '' : 'none';
    }

    function _telLoadSessions() {
      const source = _telFieldValue('telemetryFilterSource');
      const params = new URLSearchParams();
      if (source) params.set('source', source);
      return api('/api/telemetry/sessions' + (source ? '?' + params.toString() : ''))
        .then(d => {
          telemetryState.sessions = (d && Array.isArray(d.sessions)) ? d.sessions : [];
          _telRenderSessions();
        })
        .catch(() => { /* the events table is the panel; sessions are a convenience */ });
    }

    function _telRenderSessions() {
      const body  = document.getElementById('telemetrySessionsBody');
      const table = document.getElementById('telemetrySessionsTable');
      const empty = document.getElementById('telemetrySessionsEmpty');
      if (!body) return;

      const rows = telemetryState.sessions;
      if (!rows.length) {
        if (table) table.style.display = 'none';
        if (empty) empty.style.display = '';
        body.innerHTML = '';
        return;
      }
      if (empty) empty.style.display = 'none';
      if (table) table.style.display = '';

      const html = [];
      rows.forEach(s => {
        const who = [s.actor, s.user_agent].filter(Boolean).join(' · ');
        html.push(
          '<tr class="audit-row" data-tel-session="' + esc(s.session) + '" style="cursor:pointer">' +
            '<td class="audit-id"><code>' + esc(s.session) + '</code></td>' +
            '<td>' + esc(s.source || '') + '</td>' +
            '<td>' + esc(String(s.events || 0)) + '</td>' +
            '<td>' + (s.errors ? '<span class="audit-type sev-high">' + esc(String(s.errors)) + '</span>' : '0') + '</td>' +
            '<td class="audit-time">' + esc(_telTime(s.last_seen)) + '</td>' +
            '<td class="audit-hide-sm" title="' + esc(who) + '">' + esc(who || '—') + '</td>' +
          '</tr>'
        );
      });
      body.innerHTML = html.join('');

      // Listeners rather than inline onclick. The session id is hex from the
      // server, but the release and user-agent strings on these rows come from a
      // browser, and interpolating client data into an HTML attribute that is then
      // parsed as JavaScript is the bug this codebase keeps rediscovering.
      body.querySelectorAll('[data-tel-session]').forEach(tr => {
        tr.addEventListener('click', () => {
          const input = document.getElementById('telemetryFilterSession');
          if (input) input.value = tr.getAttribute('data-tel-session') || '';
          loadTelemetry();
        });
      });
    }

    // The tab's loader on every visit: it used to populate only when the
    // reader pressed Refresh, which every other panel does on open (Task 20311).
    function open() { return loadTelemetry(); }

    return h.mount({
      open, loadTelemetry, loadMoreTelemetry, applyTelemetryFilters, resetTelemetryFilters,
      copyTelemetryAsJSON
    }, 'telemetry', `
      <div class="section">
        <div class="section-title" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
          Front-end telemetry
          <span style="font-size:11px;font-weight:400;color:var(--muted)">global &mdash; admin only</span>
          <span id="telemetryState" style="font-size:11px;font-weight:400;color:var(--muted)"></span>
          <button class="btn" style="padding:4px 10px;font-size:12px;margin-left:auto" data-act="copyTelemetryAsJSON" title="Copy the events currently shown as JSON">&#128203; Copy as JSON</button>
          <button class="btn" style="padding:4px 10px;font-size:12px" data-act="loadTelemetry" title="Reload">&#8635; Refresh</button>
        </div>
        <p style="font-size:12px;color:var(--muted);margin-top:4px;margin-bottom:12px">
          What the dashboard and the display-glasses page actually did, as an ordered trail per page
          load: gestures received, views opened, requests and their status, and uncaught errors.
          Built for the front ends this hub cannot otherwise observe &mdash; the glasses have no
          console and no network inspector. Credentials are stripped at ingest and the table trims
          itself. Collection is off until an admin switches it on in Settings &rarr; Telemetry, and each
          front end asks before it sends anything. Read the same data from a terminal with
          <code>cloop hub telemetry</code>.
        </p>

        <div class="audit-filters">
          <div class="audit-field">
            <label class="form-label" for="telemetryFilterSource">Source</label>
            <select id="telemetryFilterSource" class="form-select" data-change="applyTelemetryFilters"><option value="">Any</option></select>
          </div>
          <div class="audit-field">
            <label class="form-label" for="telemetryFilterKind">Kind</label>
            <select id="telemetryFilterKind" class="form-select" data-change="applyTelemetryFilters"><option value="">Any</option></select>
          </div>
          <div class="audit-field">
            <label class="form-label" for="telemetryFilterSession">Session</label>
            <input id="telemetryFilterSession" class="form-input" type="text" placeholder="click a session below" data-change="applyTelemetryFilters">
          </div>
          <div class="audit-field wide">
            <label class="form-label" for="telemetryFilterSearch">Message contains</label>
            <input id="telemetryFilterSearch" class="form-input" type="text" placeholder="substring match" data-change="applyTelemetryFilters">
          </div>
          <div class="audit-field" style="flex:0 0 auto;min-width:0">
            <label class="form-label">&nbsp;</label>
            <button class="btn" style="padding:5px 12px;font-size:12px" data-act="resetTelemetryFilters">Clear</button>
          </div>
        </div>

        <div style="font-size:12px;font-weight:600;margin:14px 0 6px">Recent sessions</div>
        <div id="telemetrySessionsEmpty" class="audit-empty" style="display:none">No sessions recorded yet.</div>
        <div style="overflow-x:auto">
          <table class="audit-table" id="telemetrySessionsTable" style="display:none">
            <thead>
              <tr>
                <th style="width:150px">Session</th>
                <th style="width:90px">Source</th>
                <th style="width:70px">Events</th>
                <th style="width:70px">Errors</th>
                <th style="width:170px">Last seen</th>
                <th>Who / device</th>
              </tr>
            </thead>
            <tbody id="telemetrySessionsBody"></tbody>
          </table>
        </div>

        <div style="font-size:12px;font-weight:600;margin:18px 0 6px">Events</div>
        <div id="telemetrySummary" style="font-size:11.5px;color:var(--muted);margin-bottom:8px"></div>
        <div id="telemetryEmpty" class="audit-empty" style="display:none">No telemetry events match these filters.</div>
        <div style="overflow-x:auto">
          <table class="audit-table" id="telemetryTable" style="display:none">
            <thead>
              <tr>
                <th style="width:170px">Time</th>
                <th style="width:50px">Seq</th>
                <th style="width:85px">Source</th>
                <th style="width:85px">Kind</th>
                <th style="width:110px">View</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody id="telemetryBody"></tbody>
          </table>
        </div>
        <div id="telemetryMore" style="display:none;text-align:center;padding:12px 0">
          <button class="btn" style="padding:5px 14px;font-size:12px" data-act="loadMoreTelemetry">Load more</button>
        </div>
      </div>`);
  };
})();
