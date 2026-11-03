// ── The knowledge a task's run cited (Task 20473) ────────────────────────────
//
// What a run of the task read from its project's enterprise knowledge (Task
// 20472): the passages the orchestrator put in its prompt, and the documents
// the agent fetched itself with its knowledge search, each with its source and
// a link to where it lives. Drawn into #td-cite in the task's details;
// 12-task-crud.js draws the empty section and calls show() through panelAct
// the first time a task with citations is opened (static.go, deferredScripts).
//
// A citation's title and URL came from a wiki page or an issue, so the title is
// escaped and the URL is a link only when it is http(s).
(function () {
  'use strict';

  window.cloopCitationsPanel = function (h) {
    const {esc} = h;
    const KIND = {confluence: 'Confluence', jira: 'Jira'};
    const HOW = {injected: 'in its prompt', fetched: 'read by the agent'};

    function row(c) {
      const url = /^https?:\/\//i.test(c.url || '') ? c.url : '';
      const title = esc(c.title || c.url || 'untitled');
      const where = [c.source, KIND[c.source_kind] || c.source_kind].filter(Boolean).join(' · ');
      return '<li>' + (url ? '<a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer" style="color:var(--accent)">' + title + '</a>' :
        '<strong>' + title + '</strong>') +
        ' <span class="td-trunc-note">' + esc([where, HOW[c.kind] || c.kind].filter(Boolean).join(' — ')) + '</span></li>';
    }

    // show draws list, the task's citations as its details read them.
    function show(list) {
      const box = document.getElementById('td-cite');
      if (!box) return;
      const items = Array.isArray(list) ? list : [];
      const given = items.filter(c => c.kind === 'injected').length;
      box.innerHTML = '<h3>Knowledge cited (' + items.length + ')</h3><div class="td-text">' +
        (given ? given + ' given in its prompt' : 'None given in its prompt') + (items.length > given ? ', ' + (items.length - given) + ' read by the agent' : '') +
        '.</div><ul style="margin:6px 0 0 18px;padding:0;overflow-wrap:anywhere">' + items.map(row).join('') + '</ul>';
    }

    return h.mount({show}, null);
  };
})();
