// ── Knowledge Base tab ───────────────────────────────────────────────────────

let _kbEntries = [];  // full entry list for client-side search

window.loadKB = function() { loadKB(); };

function loadKB() {
  api(pUrl('/api/kb')).then(data => {
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
      '<button class="kb-card-del" onclick="deleteKBEntry(' + e.id + ')" title="Delete entry">&#x2715;</button>' +
      '<div class="kb-entry-title">' + esc(e.title) + '</div>' +
      (tags ? '<div class="kb-tags">' + tags + '</div>' : '') +
      (bodyText ? '<div class="kb-entry-body">' + esc(bodyText) + '</div>' : '') +
      '</div>';
  }).join('');
}

function filterKBCards(q) {
  if (!q) { renderKBCards(_kbEntries); return; }
  const lq = q.toLowerCase();
  const filtered = _kbEntries.filter(e =>
    (e.title || '').toLowerCase().includes(lq) ||
    (e.content || '').toLowerCase().includes(lq) ||
    (e.tags || []).some(t => t.toLowerCase().includes(lq))
  );
  renderKBCards(filtered);
}

window.toggleKBAddForm = function() {
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
};

window.submitKBAdd = function() {
  const title = (document.getElementById('kbNewTitle').value || '').trim();
  const body  = (document.getElementById('kbNewBody').value  || '').trim();
  const tagsRaw = (document.getElementById('kbNewTags').value || '').trim();
  const tags = tagsRaw ? tagsRaw.split(',').map(t => t.trim()).filter(Boolean) : [];
  if (!title) { toast('Title is required', 'err'); return; }
  apiMethod('POST', pUrl('/api/kb'), {title, body, tags}).then(d => {
    if (d.ok || d.entry) {
      toast('Entry added', 'ok');
      toggleKBAddForm();
      loadKB();
    } else {
      toast(d.error || 'Failed to add entry', 'err');
    }
  }).catch(() => toast('Failed to add entry', 'err'));
};

window.deleteKBEntry = function(id) {
  apiMethod('DELETE', pUrl('/api/kb/' + id), null).then(d => {
    if (d.ok) { toast('Entry deleted', 'ok'); loadKB(); }
    else toast(d.error || 'Delete failed', 'err');
  }).catch(() => toast('Delete failed', 'err'));
};

