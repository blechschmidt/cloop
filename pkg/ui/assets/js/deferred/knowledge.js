// ── Knowledge tab (Task 20473) ───────────────────────────────────────────────
//
// What enterprise knowledge a project's runs read (Tasks 20467–20472): the
// sources bound to it, each with how its sync stands and what narrows it; the
// way to bind another or take one off; whether a run's task prompts carry
// cited reference material, and how much; and a search to try, ranked as a
// run would see it, with each passage's source and a link to where it lives.
//
// Sources are connected in Settings → Knowledge sources (deferred/ksources.js);
// here they are bound. Binding needs project.write on the project and a source
// the caller may bind — the organisation's for an administrator, their own
// personal one for anyone — which the hub decides again; the list offers only
// those. A source's sync arrives as knowledge_source pushes (knowledge_push.go)
// and redraws its card in place: nothing here polls.
//
// Everything a source holds came from a wiki page, an issue or a person, so
// every string is escaped, a link is drawn only for an http(s) URL, and a
// snippet's match markers become <mark> only after escaping.
//
// Fetched on the tab's first open, markup included, like every tab but
// Overview, Tasks and Projects (Task 20456). It runs outside the dashboard's
// IIFE, so it is handed the helpers it calls, and the only name it puts on
// window is the factory.
(function () {
  'use strict';

  window.cloopKnowledgePanel = function (h) {
    const {api, apiMethod, esc, toast, relTime} = h;
    const el = id => document.getElementById(id);

    let bound = null;   // GET /api/projects/{idx}/knowledge/sources
    let all = null;     // GET /api/knowledge/sources; null when the caller may not list sources
    let setting = null; // GET /api/projects/{idx}/knowledge/retrieval
    let editing = 0;    // the binding whose narrowing form is open
    let seq = 0;        // numbers loads: an answer to an older one is dropped
    let searchSeq = 0;

    const base = () => '/api/projects/' + h.pidx() + '/knowledge';
    const when = t => t ? relTime(new Date(t)) : '';
    // ahead says how far off t is; relTime only says how long ago.
    const ahead = t => {
      const d = new Date(t).getTime() - Date.now();
      if (!(d > 60000)) return 'within a minute';
      return d < 3600000 ? 'in ' + Math.round(d / 60000) + ' min' : d < 86400000 ? 'in ' + Math.round(d / 3600000) + ' h' :
        'in ' + Math.round(d / 86400000) + ' d';
    };
    const href = u => /^https?:\/\//i.test(u || '') ? u : '';
    const plural = (n, one, many) => n + ' ' + (n === 1 ? one : (many || one + 's'));
    const KIND = {confluence: 'Confluence', jira: 'Jira'};
    // What narrows a binding, by the source's kind: Confluence spaces, Jira
    // projects, and each one's own query language.
    const SPACES = {jira: 'Projects'};
    const QUERY = {confluence: 'CQL', jira: 'JQL'};

    // syncBadge is how a source's sync stands, in one badge.
    function syncBadge(src) {
      const s = src.sync || {};
      if (!src.enabled) return '<span class="sec-status expired">disabled</span>';
      if (s.running) return '<span class="sec-status pending">syncing…</span>';
      if (s.status === 'ok') return '<span class="sec-status approved" title="' + esc(s.at || '') + '">synced ' + esc(when(s.at)) + '</span>';
      if (s.status === 'error') return '<span class="sec-status denied" title="' + esc(s.at || '') + '">sync failed ' + esc(when(s.at)) + '</span>';
      if (s.status === 'interrupted') return '<span class="sec-status pending">interrupted, resumes</span>';
      return '<span class="sec-status expired">never synced</span>';
    }

    // known settles once /api/me has said who this is, or after ten seconds:
    // a tab opened by a link can be drawing before it has.
    const known = () => new Promise(done => {
      let n = 0;
      const look = () => (h.known() || ++n > 40 ? done() : setTimeout(look, 250));
      look();
    });

    function load() {
      if (h.pidx() === null) {
        if (el('knBound')) el('knBound').innerHTML = '<p class="form-hint">Open a project to see its knowledge.</p>';
        return Promise.resolve();
      }
      const n = ++seq;
      // Listing every source is for the people who connect them; a viewer is
      // not asked, rather than refused.
      const listing = known().then(() => h.canGlobal('secret.own') ? api('/api/knowledge/sources').catch(() => null) : null);
      return Promise.all([api(base() + '/sources'), api(base() + '/retrieval'), listing]).then(([b, r, a]) => {
        if (n !== seq) return;
        bound = b && !b.error ? b : {sources: [], error: (b && b.error) || 'the project’s sources could not be read'};
        setting = r && !r.error ? r.retrieval : null;
        all = a && !a.error ? a : null;
        render();
      }).catch(() => toast('Failed to load the project’s knowledge', 'err'));
    }

    function open() { return load(); }

    function render() {
      if (!bound || !el('knBound')) return;
      renderBound();
      renderBind();
      renderRun();
      h.applyPermissionGating();
    }

    function renderBound() {
      const list = bound.sources || [];
      if (bound.error) {
        el('knBound').innerHTML = '<p class="form-hint" role="alert">' + esc(bound.error) + '</p>';
        return;
      }
      el('knBound').innerHTML = list.length ? '<div class="exec-grid">' + list.map(card).join('') + '</div>' :
        '<p class="form-hint">No source is bound to this project yet, so its runs read no enterprise knowledge.</p>';
    }

    function card(b) {
      const src = b.source || {}, bd = b.binding || {};
      const s = src.sync || {};
      const owner = src.scope === 'personal' ? 'Personal · ' + (src.mine ? 'yours' : src.owner || 'someone') : 'Organisation';
      const narrow = [];
      if ((bd.spaces || []).length) narrow.push((SPACES[src.kind] || 'Spaces') + ': ' + bd.spaces.join(', '));
      if (bd.query) narrow.push((QUERY[src.kind] || 'Query') + ': ' + bd.query + (bd.narrowed_at ? ' (matched ' + when(bd.narrowed_at) + ')' : ' (matches nothing until the next sync)'));
      let html = '<div class="exec-card kn-card" data-src="' + (+src.id) + '"><div class="exec-card-head"><strong class="exec-name">' + esc(src.name || '') + '</strong>' +
        syncBadge(src) + '</div><div class="exec-chips"><span class="exec-chip">' + esc(KIND[src.kind] || src.kind || '') + '</span>' +
        '<span class="exec-chip">' + esc(owner) + '</span></div>' +
        '<div class="exec-meta"><span>' + plural(+src.documents || 0, 'document') + ' · ' + plural(+src.chunks || 0, 'passage') +
        (s.running ? ' · syncing since ' + esc(when(s.running.since)) : s.next_at && src.enabled ? ' · next sync ' + esc(ahead(s.next_at)) : '') + '</span>' +
        '<span>' + (narrow.length ? 'Narrowed to ' + esc(narrow.join(' · ')) : 'Everything the source holds') + '</span></div>';
      if (s.status === 'error' && s.error) html += '<div class="exec-blocked-note kn-err" role="alert">' + esc(s.error) + '</div>';
      if (s.warning) html += '<div class="exec-sched-note">' + esc(s.warning) + '</div>';
      html += '<div class="exec-actions"><button class="btn" data-perm="project.write" data-act="editNarrow" data-arg="' + (+bd.id) + '">Narrow…</button>' +
        '<button class="btn danger" data-perm="project.write" data-act="unbind" data-arg="' + (+bd.id) + '">Unbind</button></div>';
      if (editing === +bd.id) {
        html += '<div class="kb-add-form kn-narrow"><div class="kb-form-row"><label class="form-label" for="knNarrowSpaces">' +
          esc(SPACES[src.kind] || 'Spaces') + '</label><input class="form-input" id="knNarrowSpaces" value="' + esc((bd.spaces || []).join(', ')) +
          '" placeholder="Keys, comma-separated; empty for all" data-enter="saveNarrow"></div><div class="kb-form-row"><label class="form-label" for="knNarrowQuery">' +
          esc(QUERY[src.kind] || 'Query') + '</label><input class="form-input" id="knNarrowQuery" value="' + esc(bd.query || '') +
          '" placeholder="Only what this query matches; empty for all" data-enter="saveNarrow" spellcheck="false"></div>' +
          '<div class="exec-actions"><button class="btn primary" data-perm="project.write" data-act="saveNarrow" data-arg="' + (+src.id) + '">Save</button>' +
          '<button class="btn" data-act="cancelNarrow">Cancel</button></div></div>';
      }
      return html + '</div>';
    }

    // bindable lists the sources the caller could bind here and has not: the
    // organisation's for an administrator, their own personal ones.
    function bindable() {
      if (!all) return [];
      const have = new Set((bound.sources || []).map(b => +(b.source || {}).id));
      return (all.sources || []).filter(s => !have.has(+s.id) && (s.scope === 'org' ? all.can_create_org : s.mine));
    }

    function renderBind() {
      const box = el('knBind');
      if (!all) {
        box.innerHTML = '<p class="form-hint">Binding a source is for the people who connect sources; ask a maintainer or an administrator.</p>';
        return;
      }
      const opts = bindable();
      if (!opts.length) {
        box.innerHTML = '<p class="form-hint">Nothing left to bind. Connect a Confluence or Jira source in ' +
          '<button class="btn" data-action="switchTab" data-arg="settings" style="padding:1px 8px;font-size:11.5px">Settings</button> first.</p>';
        return;
      }
      const was = el('knBindSrc') ? el('knBindSrc').value : '';
      box.innerHTML = '<div class="kb-add-form"><div class="section-title" style="margin-top:0">Bind a source</div>' +
        '<div class="kb-form-row"><label class="form-label" for="knBindSrc">Source</label><select class="form-select" id="knBindSrc" data-change="bindKind" style="flex:1;min-width:0">' +
        opts.map(s => '<option value="' + (+s.id) + '">' + esc(s.name + ' — ' + (KIND[s.kind] || s.kind) + (s.scope === 'org' ? '' : ', yours') +
          (s.enabled ? '' : ', disabled')) + '</option>').join('') + '</select></div>' +
        '<div class="kb-form-row"><label class="form-label" for="knBindSpaces" id="knBindSpacesL">Spaces</label><input class="form-input" id="knBindSpaces" placeholder="Only these keys, comma-separated (optional)"></div>' +
        '<div class="kb-form-row"><label class="form-label" for="knBindQuery" id="knBindQueryL">Query</label><input class="form-input" id="knBindQuery" spellcheck="false" placeholder="Only what this query matches (optional)" data-enter="bind"></div>' +
        '<button class="btn primary" data-perm="project.write" data-act="bind">Bind</button>' +
        '<p class="form-hint">A query is checked by the source at each sync: until the next one, the binding serves nothing — the safe way to be wrong.</p></div>';
      if (opts.some(s => String(s.id) === was)) el('knBindSrc').value = was;
      bindKind();
    }

    // bindKind labels the narrowing fields for the chosen source's kind.
    function bindKind() {
      const src = ((all && all.sources) || []).find(s => String(s.id) === (el('knBindSrc') || {}).value);
      if (!src || !el('knBindSpacesL')) return;
      el('knBindSpacesL').textContent = SPACES[src.kind] || 'Spaces';
      el('knBindQueryL').textContent = QUERY[src.kind] || 'Query';
    }

    const keys = v => (v || '').split(',').map(x => x.trim()).filter(Boolean);

    function bind() {
      const id = +(el('knBindSrc') || {}).value;
      if (!id) return;
      return api(base() + '/bindings', {source_id: id, spaces: keys(el('knBindSpaces').value), query: el('knBindQuery').value.trim()}).then(d => {
        if (!d || d.error) { toast((d && d.error) || 'Binding failed', 'err'); return; }
        toast('Bound: its documents are searchable from this project', 'ok');
        return load();
      }).catch(() => toast('Binding failed', 'err'));
    }

    function editNarrow(arg) { editing = +arg; renderBound(); h.applyPermissionGating(); if (el('knNarrowSpaces')) el('knNarrowSpaces').focus(); }
    function cancelNarrow() { editing = 0; renderBound(); h.applyPermissionGating(); }

    // saveNarrow re-binds the source with the form's narrowing: a binding is
    // one per source and project, and binding again changes it.
    function saveNarrow(arg) {
      const b = (bound.sources || []).find(x => +(x.binding || {}).id === editing);
      const id = +arg || (b && +b.source.id);
      if (!id) return;
      return api(base() + '/bindings', {source_id: id, spaces: keys(el('knNarrowSpaces').value), query: el('knNarrowQuery').value.trim()}).then(d => {
        if (!d || d.error) { toast((d && d.error) || 'Saving the narrowing failed', 'err'); return; }
        editing = 0;
        toast('Narrowing saved', 'ok');
        return load();
      }).catch(() => toast('Saving the narrowing failed', 'err'));
    }

    function unbind(arg) {
      const b = (bound.sources || []).find(x => +(x.binding || {}).id === +arg);
      if (!b || !confirm('Take ' + (b.source.name || 'this source') + ' off the project? Its runs stop reading it at once.')) return;
      return apiMethod('DELETE', base() + '/bindings/' + (+arg), null).then(d => {
        if (!d || d.error) { toast((d && d.error) || 'Unbinding failed', 'err'); return; }
        toast('Unbound', 'ok');
        return load();
      }).catch(() => toast('Unbinding failed', 'err'));
    }

    function renderRun() {
      const box = el('knRun');
      if (!setting) { box.innerHTML = '<p class="form-hint">The project’s retrieval setting could not be read.</p>'; return; }
      box.innerHTML = '<label class="form-hint" style="display:flex;gap:6px;align-items:flex-start;color:var(--text);font-size:12.5px">' +
        '<input type="checkbox" id="knInject"' + (setting.enabled ? ' checked' : '') + ' style="margin-top:2px"> Put cited reference material in each task’s prompt</label>' +
        '<div class="exec-actions" style="align-items:center;margin-top:8px">' +
        '<label class="form-hint" for="knPassages" style="margin:0">Passages</label><input class="form-input" id="knPassages" inputmode="numeric" value="' + (+setting.k) + '" style="width:70px">' +
        '<label class="form-hint" for="knBudget" style="margin:0">Token budget</label><input class="form-input" id="knBudget" inputmode="numeric" value="' + (+setting.token_budget) + '" style="width:90px">' +
        '<button class="btn" data-perm="project.write" data-act="saveRun">Save</button></div>' +
        '<p class="form-hint">' + (setting.sources ? plural(setting.sources, 'source') + ' bound. ' : 'No source is bound, so runs get no knowledge whatever this says. ') +
        'The agent can search the project’s knowledge during a run either way; this decides what its prompt starts with.' +
        (setting.default ? ' These are the defaults.' : '') + '</p>';
    }

    function saveRun() {
      const num = id => { const v = el(id).value.trim(); return v === '' ? 0 : Number(v); };
      const k = num('knPassages'), budget = num('knBudget');
      if (!Number.isInteger(k) || !Number.isInteger(budget) || k < 0 || budget < 0) { toast('Passages and the token budget are whole numbers', 'err'); return; }
      return apiMethod('PUT', base() + '/retrieval', {enabled: el('knInject').checked, k, token_budget: budget}).then(d => {
        if (!d || d.error) { toast((d && d.error) || 'Saving failed', 'err'); return; }
        setting = d.retrieval;
        renderRun();
        h.applyPermissionGating();
        toast('Saved: the next task’s prompt follows it', 'ok');
      }).catch(() => toast('Saving failed', 'err'));
    }

    // snippet escapes a passage, then marks the words that matched: the
    // markers are characters (« »), so they survive escaping untouched.
    const snippet = t => esc(t || '').replace(/«([^«»]*)»/g, '<mark>$1</mark>');

    function search() {
      const q = el('knQ').value.trim();
      if (h.pidx() === null) { toast('Open a project first', 'info'); return; }
      if (!q) { toast('Type what a task might ask about', 'info'); return; }
      const n = ++searchSeq;
      el('knMode').textContent = 'Searching…';
      return api(base() + '/search?q=' + encodeURIComponent(q) + '&k=' + (+el('knK').value || 10)).then(d => {
        if (n !== searchSeq) return;
        if (!d || d.error) { el('knMode').textContent = ''; el('knHits').innerHTML = '<li class="form-hint" role="alert">' + esc((d && d.error) || 'The search failed') + '</li>'; return; }
        renderHits(d);
      }).catch(() => { el('knMode').textContent = ''; toast('The search failed', 'err'); });
    }

    function renderHits(d) {
      const hits = d.hits || [], rt = d.retrieval || {};
      el('knMode').textContent = plural(hits.length, 'passage') + ', ranked ' + (rt.mode === 'hybrid' ? 'by words and meaning' : 'by words') +
        (rt.warning ? ' — ' + rt.warning : '');
      el('knHits').innerHTML = hits.length ? hits.map(hit).join('') : '<li class="form-hint">Nothing this project can read matched.</li>';
    }

    function hit(x) {
      const url = href(x.url), src = x.source || {};
      const title = url ? '<a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + esc(x.title || x.external_id || '') + '</a>' :
        '<strong>' + esc(x.title || x.external_id || '') + '</strong>';
      const path = (x.ancestors || []).concat(x.heading ? [x.heading] : []);
      return '<li class="kn-hit"><div class="kn-hit-head"><span class="kn-rank">' + (+x.rank) + '</span>' + title + '</div>' +
        '<div class="form-hint">' + esc([src.name, KIND[src.kind] || src.kind, x.space].filter(Boolean).join(' · ')) +
        (path.length ? ' — ' + esc(path.join(' › ')) : '') + '</div>' +
        '<div class="kn-snip">' + snippet(x.snippet) + '</div>' +
        ((x.found_by || []).length ? '<div class="form-hint">found by ' + esc(x.found_by.map(f => f === 'semantic' ? 'meaning' : 'words').join(' and ')) + '</div>' : '') +
        '</li>';
    }

    // pushed is a knowledge_source push: a source's sync moved, or it was
    // changed or deleted. A bound one is redrawn in place.
    function pushed(d) {
      if (!d || !bound) return;
      const id = +(d.source ? d.source.id : d.id);
      if (all && all.sources) {
        const i = all.sources.findIndex(s => +s.id === id);
        if (d.deleted) { if (i >= 0) all.sources.splice(i, 1); }
        else if (i >= 0) all.sources[i] = d.source;
      }
      const b = (bound.sources || []).find(x => +(x.source || {}).id === id);
      if (b && d.deleted) bound.sources = bound.sources.filter(x => x !== b);
      else if (b && d.source) b.source = Object.assign({}, d.source, {config: undefined, secret_ref: undefined});
      else return;
      if (h.tab() === 'knowledge' && el('knBound') && !editing) { renderBound(); h.applyPermissionGating(); }
    }

    return h.mount({open, load, bind, bindKind, editNarrow, cancelNarrow, saveNarrow, unbind, saveRun, search, pushed}, 'knowledge', `
    <style>
    #tab-knowledge .kn-hits{list-style:none;margin:8px 0 0;padding:0;display:flex;flex-direction:column;gap:10px}
    #tab-knowledge .kn-hit{border:1px solid var(--border);border-radius:var(--radius);padding:10px 12px;background:var(--surface);overflow-wrap:anywhere;min-width:0}
    #tab-knowledge .kn-hit-head{display:flex;gap:8px;align-items:baseline;font-size:13px}
    #tab-knowledge .kn-rank{flex:none;font-size:11px;color:var(--muted);border:1px solid var(--border);border-radius:9px;padding:0 6px}
    #tab-knowledge .kn-snip{font-size:12.5px;line-height:1.5;margin-top:6px;white-space:pre-wrap}
    #tab-knowledge .kn-snip mark{background:rgba(210,153,34,.28);color:inherit;border-radius:2px;padding:0 1px}
    #tab-knowledge .kn-card .kb-add-form{margin:6px 0 0}
    #tab-knowledge .kb-form-row .form-label{width:64px}
    #tab-knowledge .kn-err{white-space:pre-wrap}
    </style>
    <div class="kb-tab-toolbar">
      <span class="section-title" style="margin:0">Knowledge</span>
      <button class="btn" style="padding:4px 10px;font-size:12px" data-act="load">Refresh</button>
    </div>
    <p class="form-hint" style="margin:0 0 12px">Confluence spaces and Jira projects this project’s runs read: bound here, synced by the hub,
      cited in each task’s prompt and searchable by the agent. Sources are connected in Settings → Knowledge sources.</p>
    <div class="settings-section">
      <h3>Bound sources</h3>
      <div id="knBound"><p class="form-hint">Loading…</p></div>
      <div id="knBind" data-perm="project.write" data-perm-hide style="margin-top:12px"></div>
    </div>
    <div class="settings-section">
      <h3>In runs</h3>
      <div id="knRun"></div>
    </div>
    <div class="settings-section">
      <h3>Try a search</h3>
      <div class="exec-actions" style="align-items:center">
        <input class="form-input" id="knQ" type="search" placeholder="What a task might ask about" data-enter="search" style="flex:1 1 180px;min-width:0">
        <label class="form-hint" for="knK" style="margin:0">Top</label>
        <select class="form-select" id="knK" style="flex:0 0 auto;width:auto"><option>5</option><option selected>10</option><option>20</option></select>
        <button class="btn primary" id="knSearchBtn" data-act="search">Search</button>
      </div>
      <div id="knMode" class="form-hint" aria-live="polite"></div>
      <ol id="knHits" class="kn-hits"></ol>
    </div>
    `);
  };
})();
