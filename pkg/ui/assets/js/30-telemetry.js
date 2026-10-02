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

const telemetryState = {
  rows: [],
  offset: 0,
  total: 0,
  limit: 200,
  loading: false,
  sessions: [],
};

window.loadTelemetry = function(opts) {
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
};

// ── collection policy (Task 20311) ──────────────────────────────────────────
//
// The switch that decides whether any of the above exists. Collection is off
// unless an operator turns it on, and editing a YAML key and restarting was the
// only way to do that — a poor place for the control of a feature whose subject
// is what the hub records about its users.
//
// user.manage, which is admin-only. The markup carries data-global-perm so the
// block is hidden for everyone else; the guard below keeps a reader without it
// from also firing a request that can only 403.

// An error answer resolves like any other body (api() normalises it to
// {error}), so it is turned back into a failure here: rendered as a policy, a
// refused save would read as collection switched off.
function _telPolicyBody(d) {
  if (!d || d.error) throw new Error((d && d.error) || 'no answer');
  return d;
}

function _telPolicyNote(text) {
  const note = document.getElementById('telemetryPolicyNote');
  if (note) note.textContent = text;
}
const _telPolicyFailed = what => err => _telPolicyNote(what + ': ' + ((err && err.message) || err));

window.loadTelemetryPolicy = function() {
  if (!canGlobal('user.manage')) return Promise.resolve();
  return api('/api/config/telemetry')
    .then(_telPolicyBody)
    .then(_telRenderPolicy)
    .catch(_telPolicyFailed('Could not read the collection policy'));
};

function _telRenderPolicy(d) {
  const sources = Array.isArray(d.sources) ? d.sources : [];
  const enabled = !!d.enabled;
  const box = document.getElementById('telemetryPolicyEnabled');
  if (box) box.checked = enabled;

  const badge = document.getElementById('telemetryPolicyBadge');
  if (badge) {
    const on = sources.filter(s => s.collect).length;
    badge.textContent = !enabled
      ? (d.configured ? 'off' : 'off (default)')
      : (on === sources.length ? 'collecting' : 'collecting · ' + on + ' of ' + sources.length);
    badge.className = 'badge ' + (enabled ? 'running' : 'unknown');
  }

  // One checkbox per source, from the server's list: the set of front ends is a
  // Go constant, and a hardcoded pair here would be the copy that goes stale
  // the day a third one ships. Ticked from the stored selection, not from what
  // is collected now, so a narrowing reads the same while switched off.
  const host = document.getElementById('telemetryPolicySources');
  if (host) {
    host.innerHTML = sources.map(s => '<label class="tel-src"><input type="checkbox" data-tel-source="' +
      esc(s.name) + '"' + (s.selected ? ' checked' : '') + (enabled ? '' : ' disabled') + '>' +
      (s.name === 'glasses' ? 'display glasses' : esc(s.name)) + '</label>').join('');
  }

  const stored = d.stored || {};
  const chip = document.getElementById('telemetryPolicyStored');
  if (chip) {
    if (stored.error) {
      chip.textContent = 'stored: unknown (' + stored.error + ')';
    } else {
      const sess = (stored.sessions || 0) + (stored.sessions_capped ? '+' : '');
      chip.textContent = (stored.events || 0) + ' event(s) stored · ' + sess + ' session(s)' +
        (stored.oldest ? ' · oldest ' + _telTime(stored.oldest) : '');
    }
  }

  // The last clause is the one worth saying out loud: an operator switching
  // collection off for a privacy reason has not thereby deleted anything, and
  // the count above is what remains.
  _telPolicyNote((d.retention_days
    ? 'Events age out after ' + d.retention_days + ' day(s)'
    : 'Events are kept until the table fills') +
    '; the table holds at most ' + (d.max_rows || 0).toLocaleString() + ' rows' +
    '; turning collection off stops new events and deletes none — remove them with ' +
    'cloop hub telemetry prune.');
}

// onTelemetryPolicyToggle greys the per-source boxes while the master switch is
// off, and ticks them all when it goes on with none ticked.
//
// The boxes show the stored selection, which is every front end on a hub that
// never narrowed it, so normally they are already ticked. The fallback is not
// cosmetic: with every box clear, ticking the master and pressing Save would
// submit "collect, from nowhere", which is stored as off — the operator turns
// the feature on and watches it stay off, with the form agreeing with them.
window.onTelemetryPolicyToggle = function() {
  const enabled = !!(document.getElementById('telemetryPolicyEnabled') || {}).checked;
  const boxes = Array.from(document.querySelectorAll('#telemetryPolicySources input[data-tel-source]'));
  const none = boxes.every(cb => !cb.checked);
  boxes.forEach(cb => {
    cb.disabled = !enabled;
    if (enabled && none) cb.checked = true;
  });
};

window.saveTelemetryPolicy = function() {
  const enabled = !!(document.getElementById('telemetryPolicyEnabled') || {}).checked;
  const picked = [];
  document.querySelectorAll('#telemetryPolicySources input[data-tel-source]').forEach(cb => {
    if (cb.checked) picked.push(cb.getAttribute('data-tel-source'));
  });
  // Three cases; the middle one is the trap. An empty list sent with the master
  // on reaches the hub as "no restriction" and collects precisely what was just
  // unticked, so it is read as "no front end left to collect from", i.e. off.
  //
  // Switching the master off sends no source list at all, so a narrowing
  // survives being turned off and on again rather than silently widening.
  const body = enabled ? {enabled: picked.length > 0, sources: picked} : {enabled: false};

  const btn = document.getElementById('telemetryPolicySave');
  if (btn) btn.disabled = true;
  return apiMethod('PUT', '/api/config/telemetry', body)
    .then(_telPolicyBody)
    .then(d => {
      _telRenderPolicy(d);
      toast(d.enabled ? 'Telemetry collection on' : 'Telemetry collection off', 'ok');
    })
    .catch(_telPolicyFailed('Save failed'))
    .finally(() => { if (btn) btn.disabled = false; });
};

window.loadMoreTelemetry    = function() { return loadTelemetry({append: true}); };
window.applyTelemetryFilters = function() { return loadTelemetry(); };

window.resetTelemetryFilters = function() {
  ['telemetryFilterSource','telemetryFilterKind','telemetryFilterSession','telemetryFilterSearch']
    .forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
  return loadTelemetry();
};

// copyTelemetryAsJSON puts the rows currently on screen on the clipboard. The
// realistic next step after finding a trail is pasting it into an issue, and
// re-querying the API by hand to do that is friction at exactly the wrong
// moment.
window.copyTelemetryAsJSON = function() {
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
};

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
