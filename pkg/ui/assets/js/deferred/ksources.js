// ── Settings → Knowledge sources (Task 20473) ────────────────────────────────
//
// The enterprise knowledge sources the hub indexes (Tasks 20467–20471): each
// Confluence site or Jira project with how its sync stands — running, its last
// outcome and error, what it holds, when it runs next — and the way to connect
// one, change it, try its connection, sync it now, switch it off or delete it.
//
// Who sees what is the hub's rule, which the listing already applies: an
// administrator sees every source; anyone else who may keep credentials sees
// the organisation's and their own, and never learns of another person's. The
// controls follow from what each source says the caller may do (manageable,
// mine) — an administrator may delete someone's personal source, never point
// it, and so its owner's credential, somewhere else — and the hub decides
// every request again.
//
// A source signs in with a credential in the secret store, by reference: the
// form picks one of the caller's env secrets — the organisation's shared ones
// for an organisation source, the caller's own for a personal one — or stores
// a new one first through POST /api/secrets. The value is typed into a
// password field, sent once, and never comes back: the hub shows references,
// not secrets. Test connection lists one small page with what the form holds
// (POST /api/knowledge/test-connection) and says what came back, or why
// nothing did, in the hub's own scrubbed words.
//
// Nothing here polls: a sync moving on any hub member, and every change to a
// source, arrives as a knowledge_source push rendered for this dashboard
// (knowledge_push.go), and redraws its card. On an SSO hub the writes ask for
// a recent sign-in; api() opens the "Confirm it's you" dialog and replays.
//
// It draws into the section deferred/settings.js mounts, whose root routes
// data-act to the Settings panel's own functions, so the section's buttons
// carry data-ks and are routed here; the dialog is this panel's own root.
// Everything a source holds came from a person or a remote, so every string is
// escaped. It runs outside the dashboard's IIFE, so it is handed the helpers it
// calls, and the only name it puts on window is the factory.
(function () {
  'use strict';

  window.cloopKsourcesPanel = function (h) {
    const {api, apiMethod, esc, toast, relTime} = h;
    const el = id => document.getElementById(id);

    let data = null;    // GET /api/knowledge/sources
    let secrets = null; // the caller's env secrets, read when the dialog opens
    let form = null;    // the dialog's source: {id: 0 for a new one, kind, scope, ref}
    let busy = false;   // a save or a test from the dialog is under way
    let seq = 0;
    const tests = {};   // a card's last test: id → {busy} or {result} or {error}

    const KIND = {confluence: 'Confluence', jira: 'Jira'};
    // What each known connector's form asks for: its configuration's names
    // for the keys that scope it, its query and the switch that admits what
    // its readers restricted.
    const SHAPE = {
      confluence: {keys: 'spaces', query: 'cql', more: 'include_restricted', keysLabel: 'Spaces', queryLabel: 'CQL',
        keysHint: 'Space keys, comma-separated: ENG, OPS', queryHint: 'space = ENG and label = "runbook"',
        moreLabel: 'Also index pages with view restrictions — every member of a bound project could then search them',
        base: 'https://corp.atlassian.net/wiki, or https://wiki.corp.example/confluence'},
      jira: {keys: 'projects', query: 'jql', more: 'include_secured', keysLabel: 'Projects', queryLabel: 'JQL',
        keysHint: 'Project keys, comma-separated: ENG, OPS', queryHint: 'project = ENG and labels = runbook',
        moreLabel: 'Also index issues with a security level and restricted comments — every member of a bound project could then search them',
        base: 'https://corp.atlassian.net, or https://jira.corp.example/jira'},
    };
    const when = t => t ? relTime(new Date(t)) : '';
    // ahead says how far off t is; relTime only says how long ago.
    const ahead = t => {
      const d = new Date(t).getTime() - Date.now();
      if (!(d > 60000)) return 'within a minute';
      return d < 3600000 ? 'in ' + Math.round(d / 60000) + ' min' : d < 86400000 ? 'in ' + Math.round(d / 3600000) + ' h' :
        'in ' + Math.round(d / 86400000) + ' d';
    };
    const plural = (n, one, many) => n + ' ' + (n === 1 ? one : (many || one + 's'));
    const keys = v => (v || '').split(',').map(x => x.trim()).filter(Boolean);
    const admin = () => !!(data && data.can_create_org);

    function load() {
      const n = ++seq;
      wire();
      return api('/api/knowledge/sources').then(d => {
        if (n !== seq) return;
        if (!d || d.error) { body('<p class="form-hint" role="alert">' + esc((d && d.error) || 'The sources could not be read') + '</p>'); return; }
        data = d;
        render();
      }).catch(() => body('<p class="form-hint" role="alert">The sources could not be read.</p>'));
    }

    const body = html => { const b = el('ksBody'); if (b) b.innerHTML = html; };

    // wire routes the section's buttons, once: the Settings tab routes data-act
    // to the Settings panel's own functions, so these carry data-ks.
    function wire() {
      const sec = el('ksSection');
      if (!sec || sec.dataset.ksWired) return;
      sec.dataset.ksWired = '1';
      sec.addEventListener('click', e => {
        const b = e.target.closest && e.target.closest('[data-ks]');
        if (b && !b.disabled) cardAct(b.dataset.ks, +b.dataset.id);
      });
    }

    function render() {
      if (!data || !el('ksBody')) return;
      const list = data.sources || [];
      const e = data.embeddings || {};
      const canAdd = data.can_create_org || data.can_create_personal;
      body('<div class="exec-actions" style="align-items:center;margin-bottom:10px">' +
        (canAdd ? '<button class="btn primary" data-ks="add">+ Connect a source</button>' : '') +
        '<span class="form-hint" style="margin:0">Semantic search: ' + (e.enabled ? 'on, ' + esc(e.model || '') : 'off — passages are ranked by their words') +
        (e.broken ? ' — <span style="color:var(--red)">' + esc(e.broken) + '</span>' : '') + '</span></div>' +
        (list.length ? '<div class="exec-grid" id="ksList">' + list.map(card).join('') + '</div>' :
          '<div id="ksList" class="form-hint">No knowledge source is connected' + (canAdd ? ' yet.' : '.') + '</div>'));
    }

    function syncBadge(src) {
      const s = src.sync || {};
      if (!src.enabled) return '<span class="sec-status expired">disabled</span>';
      if (s.running) return '<span class="sec-status pending">syncing…</span>';
      if (s.status === 'ok') return '<span class="sec-status approved" title="' + esc(s.at || '') + '">synced ' + esc(when(s.at)) + '</span>';
      if (s.status === 'error') return '<span class="sec-status denied" title="' + esc(s.at || '') + '">sync failed ' + esc(when(s.at)) + '</span>';
      if (s.status === 'interrupted') return '<span class="sec-status pending">interrupted, resumes</span>';
      return '<span class="sec-status expired">never synced</span>';
    }

    // lastSync says what the last sync did, from its counts.
    function lastSync(s) {
      const c = s.counts;
      if (!s.started_at || !c) return '';
      const did = [];
      if (c.created) did.push(c.created + ' new');
      if (c.updated) did.push(c.updated + ' changed');
      if (c.deleted + c.removed) did.push((c.deleted + c.removed) + ' removed');
      if (c.rejected) did.push(c.rejected + ' refused');
      return 'Last sync ' + when(s.started_at) + (s.origin === 'manual' ? ', asked for' : '') +
        (s.duration_ms ? ', ' + (s.duration_ms < 1000 ? s.duration_ms + ' ms' : Math.round(s.duration_ms / 1000) + ' s') : '') +
        ': ' + (did.length ? did.join(', ') : 'nothing changed') + (s.more ? '; more to list' : '');
    }

    function card(src) {
      const s = src.sync || {};
      const owner = src.scope === 'personal' ? 'Personal · ' + (src.mine ? 'yours' : src.owner || 'someone') : 'Organisation';
      const base = src.config && typeof src.config.base_url === 'string' ? src.config.base_url : '';
      const manage = !!src.manageable;
      const id = +src.id;
      const btn = (act, label, cls, title) => '<button class="btn' + (cls ? ' ' + cls : '') + '" data-ks="' + act + '" data-id="' + id + '"' +
        (title ? ' title="' + esc(title) + '"' : '') + '>' + label + '</button>';
      const acts = [];
      if (src.enabled && (admin() || (src.scope === 'personal' && src.mine))) acts.push(btn('sync', 'Sync now', '', 'Sync the source now, on this hub member'));
      if (manage) acts.push(btn('test', 'Test connection'), btn('edit', 'Edit'), btn('toggle', src.enabled ? 'Disable' : 'Enable'));
      if (manage || admin()) acts.push(btn('del', 'Delete…', 'danger', 'Delete the source and everything it indexed; asks first'));
      let html = '<div class="exec-card ks-card" data-src="' + id + '"><div class="exec-card-head"><strong class="exec-name">' + esc(src.name || '') + '</strong>' +
        syncBadge(src) + '</div><div class="exec-chips"><span class="exec-chip">' + esc(KIND[src.kind] || src.kind || '') + '</span>' +
        '<span class="exec-chip">' + esc(owner) + '</span><span class="exec-chip">every ' + plural(+(s.interval_minutes || 30), 'min', 'min') +
        (s.default_interval ? ' (default)' : '') + '</span></div><div class="exec-meta">' +
        '<span>' + plural(+src.documents || 0, 'document') + ' · ' + plural(+src.chunks || 0, 'passage') +
        (src.vectors ? ' · ' + plural(+src.vectors, 'vector') : '') + ' · bound to ' + plural(+src.bindings || 0, 'project') + '</span>' +
        (base ? '<span>' + esc(base) + (src.secret_ref ? ' · signs in with ' + esc(src.secret_ref) : src.has_credential ? ' · has a credential' : ' · no credential') + '</span>' : '') +
        (s.running ? '<span>Syncing on ' + esc(s.running.member || 'a hub member') + ' since ' + esc(when(s.running.since)) +
          (s.running.actor ? ', asked for by ' + esc(s.running.actor) : '') + '</span>' : '') +
        (lastSync(s) ? '<span>' + esc(lastSync(s)) + '</span>' : '') +
        (!s.running && s.next_at && src.enabled ? '<span>Next sync ' + esc(ahead(s.next_at)) + '</span>' : '') + '</div>';
      if (s.status === 'error' && s.error) html += '<div class="exec-blocked-note" role="alert" style="white-space:pre-wrap">' + esc(s.error) + '</div>';
      if (s.warning) html += '<div class="exec-sched-note">' + esc(s.warning) + '</div>';
      html += '<div class="ks-test" id="ksTest' + id + '"' + (tests[id] ? '>' + testHTML(tests[id]) : ' style="display:none">') + '</div>';
      return html + (acts.length ? '<div class="exec-actions">' + acts.join('') + '</div>' : '') + '</div>';
    }

    // testHTML is how a test went: what the first page held, or why the hub
    // could not list it, in its own scrubbed words.
    function testHTML(t) {
      if (t.busy) return '<span class="form-hint">Testing the connection…</span>';
      if (t.error) return '<div class="exec-blocked-note" role="alert">' + esc(t.error) + '</div>';
      const r = t.result || {};
      if (!r.ok) {
        return '<div class="exec-blocked-note" role="alert" style="white-space:pre-wrap">' + (r.reason === 'credential' ? 'The credential could not be opened: ' :
          'The connection failed: ') + esc(r.failure || 'no reason given') + '</div>';
      }
      const what = r.documents ? 'listed ' + plural(r.documents, 'document') + (r.more ? ' on the first page, and more' : '') :
        'connected, and the first page held nothing to index — check the scope';
      return '<div class="form-hint" role="status" style="color:var(--green)">Connected in ' + (+r.duration_ms) + ' ms: ' + esc(what) +
        (r.withheld ? ' (' + plural(r.withheld, 'more withheld', 'more withheld') + ': restricted or deleted)' : '') + '.' +
        ((r.titles || []).length ? ' First: ' + r.titles.map(t => '“' + esc(t) + '”').join(', ') : '') + '</div>';
    }

    function cardAct(act, id) {
      if (act === 'add') return openForm(0);
      const src = ((data && data.sources) || []).find(s => +s.id === id);
      if (!src) return;
      switch (act) {
        case 'edit': return openForm(id);
        case 'sync': return syncNow(src);
        case 'test': return testCard(src);
        case 'toggle': return toggle(src);
        case 'del': return del(src);
      }
    }

    function syncNow(src) {
      return api('/api/knowledge/sources/' + (+src.id) + '/sync', {}).then(d => {
        if (!d || d.error) { toast((d && d.error) || 'The sync could not start', 'err'); return; }
        toast('Syncing ' + src.name, 'ok');
        if (d.source) replace(d.source);
      }).catch(() => toast('The sync could not start', 'err'));
    }

    // testCard tries a source as it is saved, and says how it went on its
    // card — redrawing that line alone, so the card's buttons stay where the
    // person is.
    function testCard(src) {
      const id = +src.id;
      const show = t => {
        tests[id] = t;
        const box = el('ksTest' + id);
        if (box) { box.innerHTML = testHTML(t); box.style.display = ''; }
      };
      show({busy: true});
      return api('/api/knowledge/test-connection', {source_id: id}).then(d => {
        show(d && d.result ? {result: d.result} : {error: (d && d.error) || 'The test could not run'});
      }).catch(e => show({error: 'The test could not run: ' + ((e && e.message) || e)}));
    }

    function toggle(src) {
      return apiMethod('PATCH', '/api/knowledge/sources/' + (+src.id), {enabled: !src.enabled}).then(d => {
        if (!d || d.error) { toast((d && d.error) || 'The change failed', 'err'); return; }
        toast(d.source.enabled ? 'Enabled: the hub syncs it again' : 'Disabled: no more syncs, and its documents are not searched', 'ok');
        replace(d.source);
      }).catch(() => toast('The change failed', 'err'));
    }

    function del(src) {
      if (!confirm('Delete ' + src.name + '? Every document it indexed goes with it, and ' + plural(+src.bindings || 0, 'project') +
        ' bound to it stop reading it at once.')) return;
      return apiMethod('DELETE', '/api/knowledge/sources/' + (+src.id), null).then(d => {
        if (!d || d.error) { toast((d && d.error) || 'Deleting failed', 'err'); return; }
        toast('Deleted ' + src.name, 'ok');
        remove(+src.id);
      }).catch(() => toast('Deleting failed', 'err'));
    }

    function replace(src) {
      if (!data || !src) return;
      const i = data.sources.findIndex(s => +s.id === +src.id);
      if (i >= 0) data.sources[i] = src; else data.sources.push(src);
      render();
    }
    function remove(id) {
      if (!data) return;
      data.sources = data.sources.filter(s => +s.id !== id);
      delete tests[id];
      render();
    }

    // pushed is a knowledge_source push: a source this dashboard may see
    // moved, changed or was deleted, on this hub member or another.
    function pushed(d) {
      if (!d || !data) return;
      if (d.deleted) remove(+d.id); else if (d.source) replace(d.source);
    }

    // ── the dialog ──

    function shape() { return SHAPE[form && form.kind] || null; }

    // openForm opens the dialog for source id, or for a new one.
    function openForm(id) {
      const src = id ? data.sources.find(s => +s.id === id) : null;
      if (id && !src) return;
      const kinds = (data.connectors || []).slice();
      form = {id: +id || 0, kind: src ? src.kind : (kinds.includes('confluence') ? 'confluence' : kinds[0] || ''),
        scope: src ? src.scope : data.can_create_personal ? 'personal' : 'org', ref: src ? src.secret_ref || '' : ''};
      el('ks-title').textContent = src ? 'Edit ' + src.name : 'Connect a knowledge source';
      el('ksKind').innerHTML = (src && !kinds.includes(src.kind) ? [src.kind] : kinds).map(k => '<option value="' + esc(k) + '">' + esc(KIND[k] || k) + '</option>').join('');
      el('ksKind').value = form.kind;
      el('ksKind').disabled = !!src;
      el('ksScopePersonal').checked = form.scope === 'personal';
      el('ksScopeOrg').checked = form.scope === 'org';
      el('ksScopePersonal').disabled = !!src || !data.can_create_personal;
      el('ksScopeOrg').disabled = !!src || !data.can_create_org;
      el('ksName').value = src ? src.name : '';
      const c = (src && src.config) || {};
      el('ksDeploy').value = c.deployment || '';
      el('ksBase').value = c.base_url || '';
      el('ksAuth').value = c.auth || (c.email || !src ? 'basic' : 'bearer');
      el('ksEmail').value = c.email || '';
      const sh = SHAPE[form.kind];
      el('ksByQuery').checked = !!(sh && c[sh.query]);
      el('ksByKeys').checked = !el('ksByQuery').checked;
      el('ksKeys').value = sh && Array.isArray(c[sh.keys]) ? c[sh.keys].join(', ') : '';
      el('ksQuery').value = (sh && c[sh.query]) || '';
      el('ksMore').checked = !!(sh && c[sh.more]);
      el('ksJSON').value = src && !sh ? JSON.stringify(c, null, 2) : '{}';
      el('ksInterval').value = src && src.sync && !src.sync.default_interval ? src.sync.interval_minutes : '';
      el('ksEnabled').checked = src ? !!src.enabled : true;
      el('ksCredName').value = '';
      el('ksCredValue').value = '';
      el('ksTestOut').innerHTML = '';
      kindChanged();
      creds();
      window.openOverlay('ks-overlay', {dismiss: close, focus: src ? '#ksName' : '#ksKind'});
    }

    function close() {
      if (el('ksCredValue')) el('ksCredValue').value = '';
      window.closeOverlay('ks-overlay');
      form = null;
    }

    // kindChanged shows the fields the chosen connector reads: the Atlassian
    // ones for Confluence and Jira, a JSON configuration for any other.
    function kindChanged() {
      form.kind = el('ksKind').value;
      const sh = shape();
      el('ksAtlassian').style.display = sh ? '' : 'none';
      el('ksRaw').style.display = sh ? 'none' : '';
      if (sh) {
        el('ksBase').placeholder = sh.base;
        el('ksKeysL').textContent = sh.keysLabel;
        el('ksQueryL').textContent = sh.queryLabel;
        el('ksByKeysL').textContent = sh.keysLabel;
        el('ksByQueryL').textContent = sh.queryLabel + ' query';
        el('ksKeys').placeholder = sh.keysHint;
        el('ksQuery').placeholder = sh.queryHint;
        el('ksMoreL').textContent = sh.moreLabel;
      }
      authChanged();
      byChanged();
    }

    function scopeChanged() {
      form.scope = el('ksScopeOrg').checked ? 'org' : 'personal';
      creds();
    }

    function authChanged() {
      el('ksEmailRow').style.display = el('ksAuth').value === 'basic' ? '' : 'none';
      el('ksCredHint').textContent = el('ksAuth').value === 'basic' ? 'The API token of the account above.' :
        'A Data Center personal access token, or an OAuth access token.';
    }

    function byChanged() {
      const q = el('ksByQuery').checked;
      el('ksKeysRow').style.display = q ? 'none' : '';
      el('ksQueryRow').style.display = q ? '' : 'none';
    }

    // creds fills the credential picker: the caller's env secrets a source of
    // this scope may sign in with — the organisation's shared ones for an
    // organisation source, the caller's own for a personal one.
    function creds() {
      const sel = el('ksCred');
      const draw = () => {
        const fits = (secrets || []).filter(s => s.kind === 'env' && (form.scope === 'personal' ? s.personal && s.mine : !s.personal));
        const names = fits.map(s => s.name);
        let opts = '<option value="">No credential</option>' + names.map(n => '<option value="' + esc(n) + '">' + esc(n) + '</option>').join('');
        if (form.ref && !names.includes(form.ref)) opts += '<option value="' + esc(form.ref) + '">' + esc(form.ref) + ' (current)</option>';
        sel.innerHTML = opts + '<option value="__new">Add a new credential…</option>';
        sel.value = form.ref || (fits.length ? '' : '__new');
        credChanged();
      };
      if (secrets) { draw(); return Promise.resolve(); }
      sel.innerHTML = '<option value="">Loading the secret store…</option>';
      return api('/api/secrets').then(d => {
        secrets = (d && d.secrets) || [];
        if (d && d.broker && d.broker.secrets_available === false) {
          el('ksCredHint').textContent = 'This hub has no secret store: ' + [d.broker.reason, d.broker.remediation].filter(Boolean).join(' ');
        }
      }).catch(() => { secrets = []; }).then(() => { if (form) draw(); });
    }

    function credChanged() {
      const fresh = el('ksCred').value === '__new';
      el('ksCredNew').style.display = fresh ? '' : 'none';
      if (fresh && !el('ksCredName').value) {
        const slug = (el('ksName').value || form.kind || 'source').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60);
        el('ksCredName').value = 'knowledge-' + (slug || 'source');
      }
    }

    // configOf is the configuration the form holds, or null after saying
    // what is wrong with it.
    function configOf() {
      const sh = shape();
      if (!sh) {
        try {
          const c = JSON.parse(el('ksJSON').value || '{}');
          if (!c || typeof c !== 'object' || Array.isArray(c)) throw new Error('not an object');
          return c;
        } catch (e) { toast('The configuration is not a JSON object', 'err'); return null; }
      }
      const c = {base_url: el('ksBase').value.trim(), auth: el('ksAuth').value};
      if (el('ksDeploy').value) c.deployment = el('ksDeploy').value;
      if (c.auth === 'basic') c.email = el('ksEmail').value.trim();
      if (el('ksByQuery').checked) c[sh.query] = el('ksQuery').value.trim(); else c[sh.keys] = keys(el('ksKeys').value);
      if (el('ksMore').checked) c[sh.more] = true;
      return c;
    }

    // credential settles with the reference the form names — storing a new
    // credential first, whose value then leaves the form — or false.
    function credential() {
      const v = el('ksCred').value;
      if (v !== '__new') return Promise.resolve(v);
      const name = el('ksCredName').value.trim(), value = el('ksCredValue').value;
      if (!name || !value) { toast('Name the new credential and paste its value', 'err'); return Promise.resolve(false); }
      return api('/api/secrets', {name, kind: 'env', payload: JSON.stringify({TOKEN: value}), personal: form.scope === 'personal'}).then(d => {
        if (!d || d.error) { toast((d && d.error) || 'The credential could not be stored', 'err'); return false; }
        el('ksCredValue').value = '';
        el('ksCredName').value = '';
        form.ref = name;
        secrets = null;
        return creds().then(() => name);
      });
    }

    function interval() {
      const v = el('ksInterval').value.trim();
      const n = v === '' ? 0 : Number(v);
      if (!Number.isInteger(n) || n < 0) { toast('The sync interval is a whole number of minutes', 'err'); return null; }
      return n;
    }

    function save() {
      if (busy || !form) return;
      const config = configOf(), every = interval(), name = el('ksName').value.trim();
      if (!config || every === null) return;
      if (!name) { toast('Name the source', 'err'); el('ksName').focus(); return; }
      busy = true;
      const id = form.id;
      return credential().then(ref => {
        if (ref === false) return;
        const req = {name, config, secret_ref: ref, enabled: el('ksEnabled').checked, sync_interval_minutes: every};
        const p = id ? apiMethod('PATCH', '/api/knowledge/sources/' + id, req) :
          api('/api/knowledge/sources', Object.assign({kind: form.kind, scope: form.scope}, req));
        return p.then(d => {
          if (!d || d.error) { toast((d && d.error) || 'Saving failed', 'err'); return; }
          toast(id ? 'Saved' : 'Connected: the hub syncs it within a minute', 'ok');
          close();
          replace(d.source);
        });
      }).catch(e => toast('Saving failed: ' + ((e && e.message) || e), 'err')).then(() => { busy = false; });
    }

    // testForm tries what the form holds, before it is saved.
    function testForm() {
      if (busy || !form) return;
      const config = configOf();
      if (!config) return;
      busy = true;
      const out = el('ksTestOut');
      return credential().then(ref => {
        if (ref === false) return;
        out.innerHTML = testHTML({busy: true});
        const req = form.id ? {source_id: form.id, config, secret_ref: ref} :
          {kind: form.kind, scope: form.scope, name: el('ksName').value.trim(), config, secret_ref: ref};
        return api('/api/knowledge/test-connection', req).then(d => {
          out.innerHTML = testHTML(d && d.result ? {result: d.result} : {error: (d && d.error) || 'The test could not run'});
        });
      }).catch(e => { out.innerHTML = testHTML({error: 'The test could not run: ' + ((e && e.message) || e)}); }).then(() => { busy = false; });
    }

    return h.mount({load, pushed, close, kindChanged, scopeChanged, authChanged, byChanged, credChanged, save, testForm}, null, null, `
    <div id="ks-overlay" data-overlay="flex" data-dismiss="close"
      style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:60;align-items:center;justify-content:center">
      <div role="dialog" aria-modal="true" aria-labelledby="ks-title" style="background:var(--surface);border:1px solid var(--border);
        border-radius:var(--radius);width:640px;max-width:96vw;max-height:90vh;display:flex;flex-direction:column">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;padding:14px 18px;border-bottom:1px solid var(--border)">
          <h2 id="ks-title" style="font-size:14px;font-weight:600;margin:0;overflow-wrap:anywhere;min-width:0">Connect a knowledge source</h2>
          <button class="btn" data-act="close" aria-label="Close" style="padding:2px 10px">&times;</button>
        </div>
        <div style="padding:14px 18px;overflow-y:auto;flex:1;min-height:0">
          <div class="form-group"><label class="form-label" for="ksKind">Kind</label>
            <select class="form-select" id="ksKind" data-change="kindChanged"></select></div>
          <div class="form-group" role="radiogroup" aria-label="Who the source is for">
            <label class="sec-own-opt"><input type="radio" name="ksScope" id="ksScopePersonal" data-change="scopeChanged">
              <span><strong>Personal</strong> — yours: it reads with your own credential, and only you bind it to projects.</span></label>
            <label class="sec-own-opt"><input type="radio" name="ksScope" id="ksScopeOrg" data-change="scopeChanged">
              <span><strong>Organisation</strong> — the hub’s: it reads with a shared credential; administrators bind it.</span></label>
          </div>
          <div class="form-group"><label class="form-label" for="ksName">Name</label>
            <input class="form-input" id="ksName" maxlength="200" placeholder="Engineering wiki"></div>
          <div id="ksAtlassian">
            <div class="form-group"><label class="form-label" for="ksDeploy">Deployment</label>
              <select class="form-select" id="ksDeploy"><option value="">Cloud, for an Atlassian address</option><option value="cloud">Cloud</option>
                <option value="datacenter">Data Center or Server</option></select></div>
            <div class="form-group"><label class="form-label" for="ksBase">Base URL</label>
              <input class="form-input" id="ksBase" type="url" spellcheck="false" autocomplete="off"></div>
            <div class="form-group"><label class="form-label" for="ksAuth">Signs in with</label>
              <select class="form-select" id="ksAuth" data-change="authChanged"><option value="basic">An email and an API token (Cloud)</option>
                <option value="bearer">A bearer token: a personal access token or an OAuth token</option></select></div>
            <div class="form-group" id="ksEmailRow"><label class="form-label" for="ksEmail">Email</label>
              <input class="form-input" id="ksEmail" type="email" autocomplete="off" placeholder="the account the API token belongs to"></div>
            <div class="form-group" role="radiogroup" aria-label="What the source holds">
              <span class="form-label">Holds</span>
              <label class="sec-own-opt"><input type="radio" name="ksBy" id="ksByKeys" data-change="byChanged"> <span id="ksByKeysL">Spaces</span></label>
              <label class="sec-own-opt"><input type="radio" name="ksBy" id="ksByQuery" data-change="byChanged"> <span id="ksByQueryL">Query</span></label>
            </div>
            <div class="form-group" id="ksKeysRow"><label class="form-label" for="ksKeys" id="ksKeysL">Spaces</label>
              <input class="form-input" id="ksKeys" spellcheck="false"></div>
            <div class="form-group" id="ksQueryRow"><label class="form-label" for="ksQuery" id="ksQueryL">Query</label>
              <textarea class="form-input" id="ksQuery" rows="2" spellcheck="false" style="font-family:var(--mono,monospace)"></textarea></div>
            <label class="sec-own-opt"><input type="checkbox" id="ksMore"> <span id="ksMoreL"></span></label>
          </div>
          <div class="form-group" id="ksRaw" style="display:none"><label class="form-label" for="ksJSON">Configuration (JSON)</label>
            <textarea class="form-input" id="ksJSON" rows="5" spellcheck="false" style="font-family:var(--mono,monospace)"></textarea>
            <p class="form-hint">What this connector reads. A credential never goes here: the hub refuses one.</p></div>
          <div class="form-group"><label class="form-label" for="ksCred">Credential</label>
            <select class="form-select" id="ksCred" data-change="credChanged"></select>
            <p class="form-hint" id="ksCredHint"></p>
            <div id="ksCredNew" style="display:none">
              <input class="form-input" id="ksCredName" maxlength="128" spellcheck="false" autocomplete="off" aria-label="The new credential’s name in the secret store"
                placeholder="Its name in the secret store" style="margin-bottom:6px">
              <input class="form-input" id="ksCredValue" type="password" autocomplete="new-password" aria-label="The new credential’s value"
                placeholder="Paste the token: stored sealed, never shown again">
            </div></div>
          <div class="form-group"><label class="form-label" for="ksInterval">Sync every (minutes)</label>
            <input class="form-input" id="ksInterval" inputmode="numeric" placeholder="30, the hub’s default; 5 to 1440" style="max-width:260px"></div>
          <label class="sec-own-opt"><input type="checkbox" id="ksEnabled"> <span>Enabled: the hub syncs it, and bound projects search it</span></label>
          <div id="ksTestOut" aria-live="polite" style="margin-top:8px"></div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;padding:12px 18px;border-top:1px solid var(--border)">
          <button class="btn" data-act="testForm" title="List one small page with what the form holds; nothing is saved">Test connection</button>
          <button class="btn" data-act="close">Cancel</button>
          <button class="btn primary" data-act="save">Save</button>
        </div>
      </div>
    </div>
    `);
  };
})();
