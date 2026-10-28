// ── Requirements tab (Task 20458) ────────────────────────────────────────────
//
// What the project must keep doing, each with its latest verdict, and the way
// to check them again. A check is started here and runs on the project's
// executor (requirements_api.go); its progress and its end arrive as
// requirements_update pushes, which reread the list (pushed). Fetched on the
// tab's first open, markup included, like every tab but Overview, Tasks and
// Projects (Task 20456).
//
// It runs outside the dashboard's IIFE, so it is handed the helpers it calls,
// and the only name it puts on window is the factory.
(function () {
  'use strict';

  window.cloopRequirementsPanel = function (h) {
    const {api, apiMethod, esc, toast, pUrl, relTime} = h;

    let data = null;        // the last GET /api/requirements
    let query = '';         // the search box
    let editing = null;     // the requirement the form edits; 0 adds one
    let openID = null;      // the requirement whose details are shown
    let reloadTimer = null;

    const el = id => document.getElementById(id);
    const VERDICT = {fulfilled: 'approved', unfulfilled: 'denied', error: 'pending', unverified: 'expired'};
    const badge = v => '<span class="sec-status ' + (VERDICT[v] || 'expired') + '">' + esc(v || 'never checked') + '</span>';
    const when = t => t ? relTime(new Date(t)) : '';
    const wrap = 'overflow-wrap:anywhere;word-break:break-word';

    function load() {
      return api(pUrl('/api/requirements')).then(d => {
        if (d && d.error) { toast(d.error, 'err'); return; }
        data = d;
        render();
      }).catch(() => toast('Failed to load the requirements', 'err'));
    }

    // A push says something changed: a check made progress or ended, or a
    // requirement was written. Read again while the tab is on screen.
    function pushed() {
      if (h.tab() !== 'requirements') return;
      clearTimeout(reloadTimer);
      reloadTimer = setTimeout(load, 250);
    }

    function render() {
      if (!data || !el('reqList')) return;
      const reqs = data.requirements || [];
      const c = data.counts || {};
      const parts = [reqs.length + ' requirement' + (reqs.length === 1 ? '' : 's')];
      if (c.fulfilled) parts.push(c.fulfilled + ' fulfilled');
      if (c.unfulfilled) parts.push(c.unfulfilled + ' unfulfilled');
      if (c.unverified) parts.push(c.unverified + ' unverified');
      if (c.error) parts.push(c.error + ' could not be checked');
      if (data.never) parts.push(data.never + ' never checked');
      if (data.stale) parts.push(data.stale + ' stale');
      el('reqSummary').textContent = reqs.length ? parts.join(' · ') : '';
      renderRun();

      const q = query.toLowerCase();
      const shown = reqs.filter(r => !q || (r.title + ' ' + (r.description || '') + ' ' + (r.tags || []).join(' ') +
        ' R-' + r.id).toLowerCase().includes(q));
      el('reqEmpty').style.display = reqs.length ? 'none' : '';
      el('reqList').innerHTML = shown.map(card).join('') ||
        (reqs.length ? '<p class="form-hint">No requirement matches the search.</p>' : '');
      if (openID !== null && shown.some(r => r.id === openID)) showDetails(openID);
      h.applyPermissionGating();
    }

    function renderRun() {
      const box = el('reqRun');
      const a = data.active;
      if (a) {
        const n = (a.requirement_ids || []).length;
        const done = (data.requirements || []).filter(r => r.last_check && r.last_check.run_id === a.run_id).length;
        box.innerHTML = '<span class="badge running"><span class="badge-dot"></span>Checking</span> ' +
          esc(done + ' of ' + n + ' checked on ' + (a.executor_id || 'the project\'s executor') +
            ', started ' + when(a.started_at) + (a.started_by ? ' by ' + a.started_by : '')) +
          ' <button class="btn" data-perm="run.stop" data-act="stop" data-arg="' + esc(a.run_id) + '">Stop</button>';
        box.style.display = '';
        el('reqCheckAll').disabled = true;
        return;
      }
      el('reqCheckAll').disabled = false;
      const last = (data.runs || [])[0];
      if (!last) { box.style.display = 'none'; return; }
      const k = last.counts || {};
      const how = last.state === 'done'
        ? k.fulfilled + ' fulfilled, ' + k.unfulfilled + ' unfulfilled, ' + k.unverified + ' unverified, ' + k.error + ' errors'
        : last.state + (last.error ? ': ' + last.error : '');
      box.innerHTML = '<span class="form-hint" style="' + wrap + '">' + esc('Last check ' + when(last.finished_at || last.started_at) +
        (last.started_by ? ' by ' + last.started_by : '') + (last.source === 'cli' ? ' (cloop requirements check)' : '') +
        ' — ' + how) + '</span>';
      box.style.display = '';
    }

    function card(r) {
      const lc = r.last_check;
      const tests = (r.tests || []).length;
      const chips = [];
      if (r.priority) chips.push('<span class="exec-chip' + (r.priority === 'must' ? ' pos' : '') + '">' + esc(r.priority) + '</span>');
      chips.push('<span class="exec-chip">' + (tests ? tests + ' test' + (tests === 1 ? '' : 's') : 'no tests') + '</span>');
      (r.tags || []).forEach(t => chips.push('<span class="exec-chip">' + esc(t) + '</span>'));
      let meta = 'Never checked.';
      if (lc) {
        meta = 'Checked ' + when(lc.checked_at) + (lc.checked_by ? ' by ' + lc.checked_by : '') + ' via ' + lc.method +
          (lc.commit ? ' at ' + lc.commit.slice(0, 10) + (lc.dirty ? ' (uncommitted changes)' : '') : '');
      }
      let stale = '';
      if (r.stale === 'changed') stale = 'Stale: the requirement changed since it was checked.';
      else if (r.stale === 'tasks') stale = 'Stale: ' + r.tasks_done_since + ' task' + (r.tasks_done_since === 1 ? '' : 's') + ' done since it was checked.';
      return '<div class="exec-card" data-req="' + r.id + '">' +
        '<div class="exec-card-head"><span class="exec-id">R-' + r.id + '</span>' +
        '<span class="exec-name" style="' + wrap + '">' + esc(r.title) + '</span>' + badge(lc && lc.verdict) + '</div>' +
        '<div class="exec-chips">' + chips.join('') + '</div>' +
        (r.description ? '<div class="form-hint" style="white-space:pre-wrap;' + wrap + '">' + esc(r.description.length > 400 ? r.description.slice(0, 400) + '…' : r.description) + '</div>' : '') +
        '<div class="exec-meta"><span style="' + wrap + '">' + esc(meta) + '</span>' +
        (lc && lc.summary ? '<span style="' + wrap + '">' + esc(lc.summary) + '</span>' : '') +
        (stale ? '<span style="color:var(--yellow,#d29922)">' + esc(stale) + '</span>' : '') + '</div>' +
        '<div class="exec-actions">' +
        (tests ? '<button class="btn" data-perm="run.start" data-act="checkOne" data-arg="' + r.id + '">Check</button>'
          : '<button class="btn" data-perm="run.start" data-act="assessOne" data-arg="' + r.id + '" title="It has no tests: the model reads the code">Ask the model</button>') +
        '<button class="btn" data-act="details" data-arg="' + r.id + '">' + (openID === r.id ? 'Hide details' : 'Details') + '</button>' +
        '<button class="btn" data-perm="task.mutate" data-act="edit" data-arg="' + r.id + '">Edit</button>' +
        '<button class="btn" data-perm="task.mutate" data-act="del" data-arg="' + r.id + '">Delete</button>' +
        '</div><div class="req-details" id="reqDetails' + r.id + '" style="display:none"></div></div>';
    }

    function filter() { query = (this.value || '').trim(); render(); }

    // ── checking ──
    function start(ids, ask) {
      const assess = ask || !!(el('reqAssess') && el('reqAssess').checked);
      return api(pUrl('/api/requirement-runs'), {ids, assess}).then(d => {
        if (h.harnessRefused(d)) return;
        if (d && d.ok) {
          const n = d.run.requirement_ids.length, k = (d.skipped || []).length;
          toast('Checking ' + n + ' requirement' + (n === 1 ? '' : 's') + '…' +
            (k ? ' ' + k + ' with no tests left as they are.' : ''), 'ok');
          return load();
        }
        toast((d && d.error) || 'The check did not start', 'err');
        if (d && d.active) load();
      }).catch(() => toast('The check did not start', 'err'));
    }
    function checkAll() { return start([]); }
    function checkOne(arg) { return start([+arg]); }
    function assessOne(arg) { return start([+arg], true); }
    function stop(arg) {
      return api(pUrl('/api/requirement-runs/' + encodeURIComponent(arg) + '/cancel'), {}).then(d => {
        if (d && d.ok) toast('Stopping the check…', 'ok');
        else toast((d && d.error) || 'Could not stop the check', 'err');
        load();
      }).catch(() => toast('Could not stop the check', 'err'));
    }

    // ── the form ──
    function add() { openForm(0); }
    function edit(arg) { openForm(+arg); }
    function openForm(id) {
      const r = id ? (data.requirements || []).find(x => x.id === id) : null;
      if (id && !r) return;
      editing = id;
      el('reqFormTitle').textContent = r ? 'Edit R-' + r.id : 'New requirement';
      el('reqTitle').value = r ? r.title : '';
      el('reqDesc').value = r ? (r.description || '') : '';
      el('reqPriority').value = r ? (r.priority || '') : '';
      el('reqTags').value = r ? (r.tags || []).join(', ') : '';
      el('reqTests').value = r ? (r.tests || []).map(t => t.command).join('\n') : '';
      const secs = r && (r.tests || []).length ? r.tests[0].timeout_seconds || '' : '';
      el('reqTimeout').value = r && (r.tests || []).every(t => (t.timeout_seconds || '') === secs) ? secs : '';
      el('reqForm').style.display = '';
      el('reqTitle').focus();
    }
    function cancelForm() { editing = null; el('reqForm').style.display = 'none'; }

    // Tests, one command per line; a line ending in a backslash goes on, as
    // in a shell. A command kept from before keeps its name and timeout.
    function readTests(prev) {
      const out = [];
      let cur = '';
      el('reqTests').value.split('\n').forEach(line => {
        cur = cur ? cur + '\n' + line : line;
        if (/\\$/.test(line)) return;
        if (cur.trim()) out.push(cur.trim());
        cur = '';
      });
      if (cur.trim()) out.push(cur.trim().replace(/\\$/, ''));
      const raw = el('reqTimeout').value.trim();
      const secs = raw === '' ? null : Math.round(+raw);
      return out.map(command => {
        const old = (prev || []).find(t => t.command === command) || {};
        const t = {command, name: old.name || ''};
        const s = secs === null ? old.timeout_seconds : secs;
        if (s > 0) t.timeout_seconds = s;
        return t;
      });
    }
    function save() {
      const title = el('reqTitle').value.trim();
      if (!title) { toast('A requirement needs a title', 'err'); return; }
      const raw = el('reqTimeout').value.trim();
      if (raw !== '' && !(+raw > 0)) { toast('The timeout is a number of seconds', 'err'); return; }
      const prev = editing ? ((data.requirements || []).find(x => x.id === editing) || {}).tests : null;
      const body = {
        title, description: el('reqDesc').value, priority: el('reqPriority').value,
        tags: el('reqTags').value.split(',').map(t => t.trim()).filter(Boolean), tests: readTests(prev),
      };
      const req = editing ? apiMethod('PUT', pUrl('/api/requirements/' + editing), body) : api(pUrl('/api/requirements'), body);
      return req.then(d => {
        if (!d || !d.ok) { toast((d && d.error) || 'Save failed', 'err'); return; }
        toast((editing ? 'Updated ' : 'Added ') + 'R-' + d.requirement.id, 'ok');
        cancelForm();
        return load();
      }).catch(() => toast('Save failed', 'err'));
    }

    // Asks first, naming the requirement; one the tab is not showing is not
    // deleted.
    function del(arg) {
      const r = (data.requirements || []).find(x => x.id === +arg);
      if (!r || !confirm('Delete R-' + r.id + ' "' + r.title + '" and the history of its checks?\n\nThis cannot be undone.')) return;
      return apiMethod('DELETE', pUrl('/api/requirements/' + r.id), null).then(d => {
        if (d && d.ok) { toast('Deleted R-' + r.id, 'ok'); if (openID === r.id) openID = null; load(); }
        else toast((d && d.error) || 'Delete failed', 'err');
      }).catch(() => toast('Delete failed', 'err'));
    }

    // ── details ──
    function details(arg) {
      const id = +arg;
      openID = openID === id ? null : id;
      render();
    }
    function showDetails(id) {
      const box = el('reqDetails' + id);
      if (!box) return;
      box.style.display = '';
      box.innerHTML = '<p class="form-hint">Loading…</p>';
      api(pUrl('/api/requirements/' + id + '/checks?limit=10')).then(d => {
        if (openID !== id || !el('reqDetails' + id)) return;
        if (!d || !d.ok) { box.innerHTML = '<p class="form-hint">' + esc((d && d.error) || 'Could not load its checks') + '</p>'; return; }
        box.innerHTML = detailsHTML(d);
        h.applyPermissionGating();
      }).catch(() => { box.innerHTML = '<p class="form-hint">Could not load its checks.</p>'; });
    }
    function detailsHTML(d) {
      const r = d.requirement;
      let html = '<div class="exec-meta" style="margin-top:6px">';
      if ((r.tests || []).length) {
        html += '<strong>Tests</strong>' + r.tests.map(t => '<code style="' + wrap + '">' + esc((t.name ? t.name + ': ' : '') + t.command) + '</code>').join('');
      } else {
        html += '<span>No tests: a check passes it by unless the model is asked.</span>';
      }
      html += '</div>';
      html += '<div class="exec-actions" style="margin-top:8px">' +
        '<input class="form-input" id="reqNote' + r.id + '" placeholder="Note for a recorded verdict" style="flex:1;min-width:140px">' +
        '<button class="btn" data-perm="task.mutate" data-act="verdict" data-arg="' + r.id + ':fulfilled">Mark fulfilled</button>' +
        '<button class="btn" data-perm="task.mutate" data-act="verdict" data-arg="' + r.id + ':unfulfilled">Mark unfulfilled</button></div>' +
        '<div class="exec-actions">' +
        '<button class="btn" data-perm="task.mutate" data-act="makeTask" data-arg="' + r.id + ':fix">Add a task to restore it</button>' +
        ((r.tests || []).length ? '' : '<button class="btn" data-perm="task.mutate" data-act="makeTask" data-arg="' + r.id + ':test">Add a task to test it</button>') +
        '</div>';
      const checks = d.checks || [];
      if (!checks.length) return html + '<p class="form-hint">Never checked.</p>';
      html += '<div class="section-title" style="margin:10px 0 4px">Recent checks</div>';
      return html + checks.map(c => {
        const stale = c.fingerprint && c.fingerprint !== d.fingerprint ? ' · before the requirement last changed' : '';
        let s = '<div style="border-top:1px solid var(--border);padding:6px 0">' + badge(c.verdict) +
          ' <span class="form-hint" style="' + wrap + '">' + esc(when(c.checked_at) + ' · ' + c.method + (c.checked_by ? ' · ' + c.checked_by : '') +
            (c.executor_id ? ' · ' + c.executor_id : '') + (c.commit ? ' · ' + c.commit.slice(0, 10) + (c.dirty ? '+' : '') : '') + stale) + '</span>';
        if (c.summary) s += '<div style="font-size:12px;' + wrap + '">' + esc(c.summary) + '</div>';
        (c.evidence || []).forEach(e => { s += '<div class="form-hint" style="' + wrap + '">• ' + esc(e) + '</div>'; });
        (c.tests || []).forEach(t => {
          s += '<div class="form-hint" style="' + wrap + '">' + esc('[' + t.outcome + '] ' + (t.name || t.command) +
            ' — exit ' + t.exit_code + ', ' + t.duration_ms + ' ms' + (t.error ? ' — ' + t.error : '')) + '</div>';
          if (t.output && t.outcome !== 'pass') {
            s += '<pre style="max-height:220px;overflow:auto;white-space:pre-wrap;' + wrap + ';font-size:11px;background:var(--bg);' +
              'border:1px solid var(--border);border-radius:6px;padding:6px;margin:4px 0">' + esc((t.truncated ? '…' : '') + t.output) + '</pre>';
          }
        });
        return s + '</div>';
      }).join('');
    }

    function verdict(arg) {
      const [id, v] = String(arg).split(':');
      const note = el('reqNote' + id) ? el('reqNote' + id).value.trim() : '';
      return api(pUrl('/api/requirements/' + id + '/verdict'), {verdict: v, note}).then(d => {
        if (d && d.ok) { toast('Recorded R-' + id + ' as ' + v, 'ok'); load(); }
        else toast((d && d.error) || 'Could not record the verdict', 'err');
      }).catch(() => toast('Could not record the verdict', 'err'));
    }
    function makeTask(arg) {
      const [id, kind] = String(arg).split(':');
      return api(pUrl('/api/requirements/' + id + '/task'), {kind}).then(d => {
        if (d && d.ok) toast('Added task #' + d.task.id + ': ' + d.task.title, 'ok');
        else toast((d && d.error) || 'Could not add the task', 'err');
      }).catch(() => toast('Could not add the task', 'err'));
    }

    return h.mount({open: load, load, pushed, filter, checkAll, checkOne, assessOne, stop, add, edit, cancelForm, save, del,
      details, verdict, makeTask}, 'requirements', `
    <div class="kb-tab-toolbar">
      <span class="section-title" style="margin:0">Requirements</span>
      <div class="kb-search-wrap">
        <input class="form-input kb-search-input" id="reqSearch" placeholder="Search requirements..." data-input="filter">
      </div>
      <button class="btn primary" id="reqCheckAll" data-perm="run.start" style="padding:4px 12px;font-size:12px" data-act="checkAll">Check all</button>
      <label class="form-hint" style="display:flex;gap:5px;align-items:center" title="A requirement with no tests is otherwise skipped, its last verdict kept">
        <input type="checkbox" id="reqAssess"> Ask the model about untested ones</label>
      <button class="btn" data-perm="task.mutate" style="padding:4px 12px;font-size:12px" data-act="add">+ Add requirement</button>
      <button class="btn" style="padding:4px 10px;font-size:12px" data-act="load">Refresh</button>
    </div>
    <div id="reqSummary" class="form-hint" style="margin-bottom:6px"></div>
    <div id="reqRun" class="exec-actions" style="display:none;align-items:center;margin-bottom:10px"></div>
    <div id="reqForm" class="kb-add-form" style="display:none">
      <div class="section-title" id="reqFormTitle">New requirement</div>
      <div class="kb-form-row"><label class="form-label" for="reqTitle">Title</label>
        <input class="form-input" id="reqTitle" maxlength="300" placeholder="What must stay true" style="flex:1" data-enter="save"></div>
      <div class="kb-form-row"><label class="form-label" for="reqDesc">Details</label>
        <textarea class="form-input kb-new-body" id="reqDesc" rows="3" placeholder="What it means, in detail: what the model reads when it has no test to run"></textarea></div>
      <div class="kb-form-row"><label class="form-label" for="reqTests">Tests</label>
        <textarea class="form-input kb-new-body" id="reqTests" rows="3" spellcheck="false" style="font-family:var(--mono,monospace)"
          placeholder="One shell command per line, run in the project's root; it passes when it exits 0. Optional."></textarea></div>
      <div class="kb-form-row" style="flex-wrap:wrap"><label class="form-label" for="reqPriority">Priority</label>
        <select class="form-select" id="reqPriority" style="flex:0 0 110px;width:110px"><option value="">—</option><option value="must">must</option>
          <option value="should">should</option><option value="could">could</option></select>
        <input class="form-input" id="reqTags" placeholder="Tags, comma-separated" style="flex:1;min-width:120px">
        <input class="form-input" id="reqTimeout" inputmode="numeric" placeholder="Timeout (s)" style="flex:0 0 110px;width:110px"
          title="How long each test may run; empty is 10 minutes"></div>
      <div style="display:flex;gap:8px;margin-top:6px">
        <button class="btn primary" data-perm="task.mutate" data-act="save">Save</button>
        <button class="btn" data-act="cancelForm">Cancel</button>
      </div>
    </div>
    <div id="reqEmpty" class="empty-state" style="display:none">
      <h3>No requirements yet</h3>
      <p>Add what the project must keep doing. A requirement with a test is checked by running it on the project's executor.</p>
    </div>
    <div id="reqList" class="exec-grid" style="align-items:start"></div>
    `);
  };
})();
