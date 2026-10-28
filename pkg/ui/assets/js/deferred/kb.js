// ── Knowledge Base tab ───────────────────────────────────────────────────────
//
// A project's knowledge base: entries searched client-side, added and deleted
// through /api/kb. Fetched on the tab's first open since Task 20456, markup
// included, like the Settings and admin tabs before it (Task 20386): first
// paint has no room for a tab most sessions never open. It was 06-kb.js.
//
// It runs outside the dashboard's IIFE, so it is handed the helpers it calls,
// and the only name it puts on window is the factory. open() runs on every
// visit and reads the entries afresh, so nothing written while the tab was
// unloaded is missed.
(function () {
  'use strict';

  window.cloopKbPanel = function (h) {
    const {api, apiMethod, esc, toast, pUrl} = h;

    let _kbEntries = [];  // full entry list for client-side search

    function loadKB() {
      return api(pUrl('/api/kb')).then(data => {
        _kbEntries = data.entries || [];
        renderKBCards(_kbEntries);
      }).catch(() => toast('Failed to load knowledge base', 'err'));
    }

    function renderKBCards(entries) {
      const grid  = document.getElementById('kbGrid');
      const empty = document.getElementById('kbEmpty');
      if (!grid) return;
      if (!entries || entries.length === 0) {
        grid.innerHTML = '';
        if (empty) empty.style.display = '';
        return;
      }
      if (empty) empty.style.display = 'none';
      grid.innerHTML = entries.map(e => {
        const tags = (e.tags || []).map(t => '<span class="kb-tag">' + esc(t) + '</span>').join('');
        const bodyText = (e.content || '').replace(/\n/g, '\n');
        return '<div class="kb-entry-card" data-id="' + e.id + '">' +
          '<button class="kb-card-del" data-act="del" data-arg="' + e.id + '" title="Delete entry">&#x2715;</button>' +
          '<div class="kb-entry-title">' + esc(e.title) + '</div>' +
          (tags ? '<div class="kb-tags">' + tags + '</div>' : '') +
          (bodyText ? '<div class="kb-entry-body">' + esc(bodyText) + '</div>' : '') +
          '</div>';
      }).join('');
    }

    // The search box names it (data-input), with its value as the query.
    function filter() {
      const q = this.value;
      if (!q) { renderKBCards(_kbEntries); return; }
      const lq = q.toLowerCase();
      const filtered = _kbEntries.filter(e =>
        (e.title || '').toLowerCase().includes(lq) ||
        (e.content || '').toLowerCase().includes(lq) ||
        (e.tags || []).some(t => t.toLowerCase().includes(lq))
      );
      renderKBCards(filtered);
    }

    function toggleAdd() {
      const form = document.getElementById('kbAddForm');
      if (!form) return;
      const visible = form.style.display !== 'none';
      form.style.display = visible ? 'none' : '';
      if (!visible) {
        document.getElementById('kbNewTitle').value = '';
        document.getElementById('kbNewBody').value = '';
        document.getElementById('kbNewTags').value = '';
        document.getElementById('kbNewTitle').focus();
      }
    }

    function add() {
      const title = (document.getElementById('kbNewTitle').value || '').trim();
      const body  = (document.getElementById('kbNewBody').value  || '').trim();
      const tagsRaw = (document.getElementById('kbNewTags').value || '').trim();
      const tags = tagsRaw ? tagsRaw.split(',').map(t => t.trim()).filter(Boolean) : [];
      if (!title) { toast('Title is required', 'err'); return; }
      return apiMethod('POST', pUrl('/api/kb'), {title, body, tags}).then(d => {
        if (d.ok || d.entry) {
          toast('Entry added', 'ok');
          toggleAdd();
          loadKB();
        } else {
          toast(d.error || 'Failed to add entry', 'err');
        }
      }).catch(() => toast('Failed to add entry', 'err'));
    }

    // Asks first, naming the entry; one the tab is not showing is not deleted
    // (Task 20422).
    function del(arg) {
      const id = +arg;
      const e = _kbEntries.find(x => x.id === id);
      if (!e || !confirm('Delete "' + e.title + '" from the knowledge base?\n\nThis cannot be undone.')) return;
      return apiMethod('DELETE', pUrl('/api/kb/' + id), null).then(d => {
        if (d.ok) { toast('Entry deleted', 'ok'); loadKB(); }
        else toast(d.error || 'Delete failed', 'err');
      }).catch(() => toast('Delete failed', 'err'));
    }

    return h.mount({open: loadKB, load: loadKB, filter, toggleAdd, add, del}, 'kb', `
    <div class="kb-tab-toolbar">
      <span class="section-title" style="margin:0">Knowledge Base</span>
      <div class="kb-search-wrap">
        <input class="form-input kb-search-input" id="kbSearchInput" placeholder="Search entries..." data-input="filter">
      </div>
      <button class="btn primary" data-perm="task.mutate" style="padding:4px 12px;font-size:12px" data-act="toggleAdd">+ Add Entry</button>
      <button class="btn" style="padding:4px 10px;font-size:12px" data-act="load">Refresh</button>
    </div>
    <div id="kbAddForm" class="kb-add-form" style="display:none">
      <div class="section-title">New Entry</div>
      <div class="kb-form-row">
        <label class="form-label">Title</label>
        <input class="form-input" id="kbNewTitle" placeholder="Entry title..." style="flex:1">
      </div>
      <div class="kb-form-row">
        <label class="form-label">Body</label>
        <textarea class="form-input kb-new-body" id="kbNewBody" placeholder="Entry content..." rows="4"></textarea>
      </div>
      <div class="kb-form-row">
        <label class="form-label">Tags</label>
        <input class="form-input" id="kbNewTags" placeholder="Comma-separated tags, e.g. api,auth" style="flex:1">
      </div>
      <div style="display:flex;gap:8px;margin-top:6px">
        <button class="btn primary" data-perm="task.mutate" data-act="add">Save Entry</button>
        <button class="btn" data-act="toggleAdd">Cancel</button>
      </div>
    </div>
    <div id="kbEmpty" class="empty-state" style="display:none">
      <h3>No entries yet</h3>
      <p>Click <strong>+ Add Entry</strong> to add your first knowledge base entry.</p>
    </div>
    <div id="kbGrid" class="kb-grid"></div>
    `);
  };
})();
