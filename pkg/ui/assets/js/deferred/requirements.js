// ── Requirements tab (Task 20458) ────────────────────────────────────────────
//
// What the project must keep doing, each with its latest verdict, and the way
// to check them again. A check is started here and runs on the project's
// executor (requirements_api.go); its progress and its end arrive as
// requirements_update pushes, which reread the list (pushed). Fetched on the
// tab's first open, markup included, like every tab but Overview, Tasks and
// Projects (Task 20456).
//
// The project's spec file, .cloop/requirements.yaml (Task 20459), shows above
// the list: read on the project's executor when the tab opens and the last
// read is old (requirements_spec_api.go), a change in it shows as "spec
// changed", and Review lists what an import would do — each conflict with the
// choice that settles it — before Import applies exactly that.
//
// A requirement's details list the tasks that implement it (Task 20460), and a
// task's R-n chip opens the requirement here (show).
//
// Draft requirements (Task 20462) opens a dialog in which the model drafts
// requirements from the project's goal or a pasted specification — on the
// project's executor, with the caller's account (requirements_draft_api.go).
// The drafts are stored as drafts, which nothing checks: the dialog lists every
// draft awaiting approval with what lint says of it, and approves one, all of
// them, or opens one in the form to edit first. Everything in it came from a
// model, so every string is escaped like the rest of the tab.
//
// Plan from requirements (Task 20463) has the model plan the tasks that close
// the open gaps — the approved requirements that fail, that nothing shows to
// hold, that changed since they held, or that lack only a test — on the
// project's executor. The plan is a suggest job, reviewed in the Tasks tab's
// suggestions panel, which the button opens. Each card says what is open
// about its requirement and what closes it.
//
// Prove (Task 20464) runs a requirement's tests red-green on the project's
// executor (requirements_prove_api.go): at the base — the commit before the
// test's implementation — and on the change. Each tested requirement's card
// carries a badge with its latest proof — proven, vacuous, broken,
// inconclusive — and its details the recent proofs, each side's tests.
//
// Traceability (Task 20465) is the tab's second view: one row per approved
// requirement with the tasks that implement it and their states, the commits
// those tasks produced, its latest verdict with its age and staleness, its
// latest proof and how it is verified, filtered by priority, tag and gap, a
// SQL keyset page at a time (requirements_trace_api.go); above it the spec
// coverage — how many musts are tested, proven, passing and linked. Nothing
// polls: a requirements_coverage push carries the coverage, which redraws at
// once, and a digest of the whole matrix, which reads the rows again when it
// moved. The Overview's Spec coverage card opens it (trace).
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
    let review = null;      // GET /api/requirements/spec, while reviewing an import
    let settle = {};        // how each conflict under review is settled: R-<id> → file | hub
    let reading = false;    // a read of the spec file is under way
    let drafted = null;     // the last draft's answer: what it refused, and the model's notes
    let lint = null;        // the last lint: {findings, notes, checked, model}
    let drafting = '';      // what the dialog is waiting on: draft, lint, approve — or nothing
    let view = 'list';      // the view on screen: list, or trace (Task 20465)
    let tr = null;          // the matrix as read: {rows, coverage, matched, next, digest}
    let trStale = false;    // a push moved the matrix while it was not on screen
    let trTimer = null;
    let trSeq = 0;          // numbers reads of the matrix: an answer to an older one is dropped

    const el = id => document.getElementById(id);
    const VERDICT = {fulfilled: 'approved', unfulfilled: 'denied', error: 'pending', unverified: 'expired'};
    const badge = v => '<span class="sec-status ' + (VERDICT[v] || 'expired') + '">' + esc(v || 'never checked') + '</span>';
    // A proof's outcome as its badge shows it (Task 20464).
    const PROOF = {proven: 'approved', vacuous: 'denied', broken: 'denied', inconclusive: 'expired', error: 'pending'};
    const proofBadge = (p, stale) => {
      if (!p) return '<span class="sec-status expired" title="Prove shows whether its tests fail without the change">unproven</span>';
      const o = p.outcome || 'error';
      const word = o === 'error' ? 'proof failed' : o;
      return '<span class="sec-status ' + (PROOF[o] || 'expired') + '" title="' + esc('Red-green proof: ' + (p.summary || o) +
        (stale ? ' — of tests it no longer has' : '')) + '">' + esc(word + (stale ? ' (stale)' : '')) + '</span>';
    };
    const when = t => t ? relTime(new Date(t)) : '';
    const wrap = 'overflow-wrap:anywhere;word-break:break-word';
    // What closes a requirement's gap (requirements.Assess), as its card says.
    const ACTION = {fix: 'needs a fix', implement: 'needs implementing', verify: 'changed: needs verifying', test: 'needs a test',
      check: 'needs a check', attach_test: 'needs the test a task wrote', stuck: 'a task meant to close it failed'};

    function load() {
      return api(pUrl('/api/requirements')).then(d => {
        if (d && d.error) { toast(d.error, 'err'); return; }
        const was = data && data.spec;
        data = d;
        reading = !!(d.spec && d.spec.reading);
        render();
        // A read that brought another file, or another plan, makes the one
        // under review out of date.
        const sp = d.spec;
        if (review && sp && was && (sp.digest !== was.digest || (sp.read && sp.read.sha256) !== (was.read && was.read.sha256))) {
          review = null;
          reviewSpec();
        }
      }).catch(() => toast('Failed to load the requirements', 'err'));
    }

    // open asks for the spec file to be read again, for someone who may
    // import what it finds; the hub decides whether a read is due — each one
    // starts a workload where the project runs.
    function open() {
      if (view === 'trace') traceLoad(true);
      return load().then(() => {
        if (h.can && h.can('task.mutate') && !reading) readSpec(true);
      });
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
      if (data.targets) parts.push(data.targets + ' open gap' + (data.targets === 1 ? '' : 's') + ' to plan' +
        (data.must_gaps ? ' (' + data.must_gaps + ' must)' : ''));
      el('reqSummary').textContent = reqs.length ? parts.join(' · ') : '';
      el('reqPlan').textContent = 'Plan from requirements' + (data.targets ? ' (' + data.targets + ')' : '');
      renderRun();
      renderSpec();

      const q = query.toLowerCase();
      const shown = reqs.filter(r => !q || (r.title + ' ' + (r.description || '') + ' ' + (r.tags || []).join(' ') +
        ' R-' + r.id).toLowerCase().includes(q));
      el('reqEmpty').style.display = reqs.length ? 'none' : '';
      el('reqList').innerHTML = shown.map(card).join('') ||
        (reqs.length ? '<p class="form-hint">No requirement matches the search.</p>' : '');
      if (openID !== null && shown.some(r => r.id === openID)) showDetails(openID);
      const nDrafts = draftsOf().length;
      el('reqDrafts').innerHTML = nDrafts ? '<span class="form-hint" style="' + wrap + '">' + nDrafts + ' draft' +
        (nDrafts === 1 ? ' awaits' : 's await') + ' approval: nothing checks a draft until a person approves it.</span> ' +
        '<button class="btn" data-perm="task.mutate" data-act="draftOpen">Review drafts</button>' : '';
      el('reqDrafts').style.display = nDrafts ? '' : 'none';
      if (window.isOverlayOpen('rd-overlay')) renderDraft();
      h.applyPermissionGating();
    }

    function renderRun() {
      const box = el('reqRun');
      const a = data.active;
      if (a) {
        const n = (a.requirement_ids || []).length;
        const done = (data.requirements || []).filter(r => r.last_check && r.last_check.run_id === a.run_id).length;
        const where = ' on ' + (a.executor_id || 'the project\'s executor') + ', started ' + when(a.started_at) +
          (a.started_by ? ' by ' + a.started_by : '');
        const proving = a.kind === 'prove';
        box.innerHTML = '<span class="badge running"><span class="badge-dot"></span>' + (proving ? 'Proving' : 'Checking') + '</span> ' +
          esc(proving ? (a.requirement_ids || []).map(i => 'R-' + (+i)).join(', ') + ': its tests at the base, then on the change' + where
            : done + ' of ' + n + ' checked' + where) +
          ' <button class="btn" data-perm="run.stop" data-act="stop" data-arg="' + esc(a.run_id) + '">Stop</button>';
        box.style.display = '';
        el('reqCheckAll').disabled = true;
        return;
      }
      el('reqCheckAll').disabled = false;
      const last = (data.runs || [])[0];
      if (!last) { box.style.display = 'none'; return; }
      const k = last.counts || {};
      const proved = last.kind === 'prove';
      const outcomes = (data.requirements || []).filter(r => r.last_proof && r.last_proof.run_id === last.run_id)
        .map(r => 'R-' + r.id + ' ' + r.last_proof.outcome).join(', ');
      const how = last.state !== 'done' ? last.state + (last.error ? ': ' + last.error : '')
        : proved ? (outcomes || 'done')
        : k.fulfilled + ' fulfilled, ' + k.unfulfilled + ' unfulfilled, ' + k.unverified + ' unverified, ' + k.error + ' errors';
      box.innerHTML = '<span class="form-hint" style="' + wrap + '">' + esc((proved ? 'Last proof ' : 'Last check ') +
        when(last.finished_at || last.started_at) + (last.started_by ? ' by ' + last.started_by : '') +
        (last.source === 'cli' ? (proved ? ' (cloop requirements prove)' : ' (cloop requirements check)') : '') +
        ' — ' + how) + '</span>';
      box.style.display = '';
    }

    // ── the spec file ──
    const shortSha = c => c ? String(c).slice(0, 10) : '';
    function specMeta(sp) {
      const rd = sp.read;
      if (!rd) return '';
      return 'Read ' + when(rd.read_at) + (rd.commit ? ' at ' + shortSha(rd.commit) : '') +
        (rd.dirty ? ' (uncommitted changes)' : '') + (rd.executor_id ? ' on ' + rd.executor_id : '') +
        (rd.read_by ? ' by ' + rd.read_by : '') + '.';
    }
    function attemptNote(sp) {
      const a = sp.attempt;
      return a ? '<div style="color:var(--yellow,#d29922);font-size:12px;margin-top:4px">' +
        esc('Reading it again ' + when(a.at) + ' got nothing: ' + a.error) + '</div>' : '';
    }
    function renderSpec() {
      const box = el('reqSpec');
      const sp = data.spec;
      if (!box) return;
      if (!sp || (sp.state === 'unread' && !reading && !sp.attempt) || (sp.state === 'missing' && !(data.requirements || []).length)) {
        box.style.display = 'none';
        box.innerHTML = '';
        return;
      }
      const file = '<code>' + esc(sp.path) + '</code>';
      const n = k => k + ' requirement' + (k === 1 ? '' : 's');
      let msg = '', tone = '';
      const btns = [];
      switch (sp.state) {
        case 'unread':
          msg = reading ? 'Reading the spec file ' + file + ' on the project\'s executor…' : 'The spec file ' + file + ' has not been read.';
          break;
        case 'failed': msg = 'The spec file ' + file + ' could not be read: ' + esc(sp.read.error); tone = 'warn'; break;
        case 'missing':
          msg = 'The project\'s checkout has no spec file. Keep the requirements beside the code: download ' + file +
            ', commit it, and changes made to it in a pull request show here.';
          btns.push('<button class="btn" data-act="download">Download requirements.yaml</button>');
          break;
        case 'invalid':
          msg = 'The spec file ' + file + ' does not validate (' + sp.error_count + ' problem' + (sp.error_count === 1 ? '' : 's') +
            '):<ul style="margin:4px 0 0 18px;padding:0">' + (sp.errors || []).map(e =>
            '<li>' + esc((e.line ? 'line ' + e.line + ': ' : '') + e.message) + '</li>').join('') +
            (sp.error_count > (sp.errors || []).length ? '<li>…</li>' : '') + '</ul>';
          tone = 'warn';
          break;
        case 'conflict': case 'changed':
          msg = '<strong>Spec changed.</strong> ' + file + ' has ' + [
            sp.imports ? n(sp.imports) + ' to import' : '', sp.conflicts ? sp.conflicts + ' in conflict with the hub' : '',
            sp.refused ? sp.refused + ' refused' : ''].filter(Boolean).join(', ') + '.';
          tone = sp.state === 'conflict' ? 'warn' : 'info';
          btns.push('<button class="btn primary" data-perm="task.mutate" data-perm-hide data-act="reviewSpec">' + (review ? 'Hide' : 'Review') + '</button>');
          break;
        case 'ahead':
          msg = 'The hub has ' + n(sp.exports) + ' changed that ' + file + ' does not. Download it, or run ' +
            '<code>cloop requirements export</code>, and commit it.';
          btns.push('<button class="btn" data-act="download">Download requirements.yaml</button>');
          break;
        default:
          msg = 'The spec file ' + file + ' and the hub agree (' + n(sp.in_sync) + ').';
      }
      if (sp.read && sp.read.ignored) {
        msg += ' <span style="color:var(--yellow,#d29922)">Git ignores it in the checkout, so it reaches no other: ' +
          'ignore <code>.cloop/*</code> rather than <code>.cloop/</code>, and add <code>!' + esc(sp.path) + '</code>.</span>';
      }
      btns.push('<button class="btn" data-perm="task.mutate" data-perm-hide data-act="readSpec"' + (reading ? ' disabled' : '') + '>' +
        (reading ? 'Reading…' : 'Read again') + '</button>');
      const border = tone === 'warn' ? 'var(--yellow,#d29922)' : tone === 'info' ? 'var(--accent,#58a6ff)' : 'var(--border)';
      box.innerHTML = '<div style="border:1px solid ' + border + ';border-radius:8px;padding:8px 10px;margin-bottom:10px;' + wrap + '">' +
        '<div style="font-size:13px">' + msg + '</div>' +
        '<div class="form-hint" style="margin-top:4px">' + esc(specMeta(sp)) + '</div>' + attemptNote(sp) +
        '<div class="exec-actions" style="margin-top:6px;flex-wrap:wrap">' + btns.join('') + '</div>' +
        '<div id="reqSpecReview"></div></div>';
      box.style.display = '';
      if (review) renderReview();
    }

    // readSpec asks the hub to read the spec file on the project's executor.
    // It answers at once: the read's end arrives as a push, which reloads.
    // auto is the tab's own read when it opens.
    function readSpec(auto) {
      if (reading) return;
      auto = auto === true;
      return api(pUrl('/api/requirements/spec/read'), {auto}).then(d => {
        if (!d || !d.ok) {
          if (!auto && !h.harnessRefused(d)) toast((d && d.error) || 'The spec file could not be read', 'err');
          return;
        }
        reading = !!d.reading;
        if (reading) { if (data) renderSpec(); return; }
        return load();
      }).catch(() => { if (!auto) toast('The spec file could not be read', 'err'); });
    }

    function reviewSpec() {
      if (review) { review = null; settle = {}; renderSpec(); return; }
      return api(pUrl('/api/requirements/spec')).then(d => {
        if (!d || !d.ok) { toast((d && d.error) || 'Could not load the import', 'err'); return; }
        review = d.spec;
        settle = {};
        renderSpec();
      }).catch(() => toast('Could not load the import', 'err'));
    }

    // A field as a person reads it, bounded.
    function fieldText(r, f) {
      if (!r) return '—';
      let v;
      switch (f) {
        case 'details': v = r.description || ''; break;
        case 'tags': v = (r.tags || []).join(', '); break;
        case 'tests': v = (r.tests || []).map(t => t.command).join(' ; '); break;
        case 'status': v = r.status || 'approved'; break;
        default: v = r[f] || '';
      }
      v = String(v);
      return v === '' ? '—' : v.length > 240 ? v.slice(0, 240) + '…' : v;
    }
    const KIND = {import: 'import', merge: 'import (merged)', export: 'hub only', conflict: 'conflict', refused: 'refused'};
    function renderReview() {
      const box = el('reqSpecReview');
      if (!box || !review) return;
      const plan = review.plan || {changes: []};
      const changes = plan.changes || [];
      if (!changes.length) { box.innerHTML = '<p class="form-hint">Nothing to import.</p>'; return; }
      const rows = changes.map(c => {
        const conflict = c.kind === 'conflict';
        let html = '<div style="border-top:1px solid var(--border);padding:6px 0">' +
          '<span class="exec-id">R-' + c.id + '</span> <span class="exec-chip"' + (conflict || c.kind === 'refused'
          ? ' style="border-color:var(--red);color:var(--red)"' : '') + '>' +
          esc(KIND[c.kind] || c.kind) + (c.action ? ' · ' + esc(c.action) : '') + '</span> ' +
          '<span style="' + wrap + '">' + esc(c.reason) + (c.stales ? ' — its verdicts go stale' : '') + '</span>';
        const title = (c.file || c.hub || c.base || {}).title;
        if (title) html += '<div class="form-hint" style="' + wrap + '">' + esc(title) + '</div>';
        (c.fields || []).forEach(f => {
          html += '<div class="form-hint" style="' + wrap + '">' + esc(f + ': hub «' + fieldText(c.hub, f) + '» · file «' +
            fieldText(c.file, f) + '»') + '</div>';
        });
        if (conflict) {
          const k = 'R-' + c.id;
          html += '<div class="exec-actions" style="flex-wrap:wrap">' + [['hub', 'Keep the hub\'s'], ['file', 'Take the file\'s']].map(o =>
            '<label class="form-hint" style="display:flex;gap:4px;align-items:center"><input type="radio" name="reqSettle' + c.id +
            '" value="' + o[0] + '" data-change="settleOne" data-arg="' + k + '"' + (settle[k] === o[0] ? ' checked' : '') + '> ' +
            o[1] + '</label>').join('') + '</div>';
        }
        return html + '</div>';
      }).join('');
      const open = changes.filter(c => c.kind === 'conflict' && !settle['R-' + c.id]).length;
      const refused = changes.filter(c => c.kind === 'refused').length;
      const can = plan.imports + plan.conflicts > 0 && !open && !refused;
      const why = refused ? 'Renumber the refused requirements in the file: an id is never given to a second requirement.'
        : open ? 'Settle each conflict to import.' : '';
      box.innerHTML = '<div style="margin-top:8px">' + rows + '</div>' +
        '<div class="exec-actions" style="margin-top:6px;align-items:center;flex-wrap:wrap">' +
        '<button class="btn primary" data-perm="task.mutate" data-perm-hide data-act="importSpec"' + (can ? '' : ' disabled') + '>Import</button>' +
        (why ? '<span class="form-hint">' + esc(why) + '</span>' : '') + '</div>';
      h.applyPermissionGating(box);
    }
    function settleOne(arg) {
      settle[arg] = this.value;
      renderReview();
    }

    function importSpec() {
      if (!review || !review.read) return;
      return api(pUrl('/api/requirements/import'), {sha256: review.read.sha256, digest: review.digest, resolutions: settle}).then(d => {
        if (d && d.ok) {
          const done = d.done || {};
          const said = Object.keys(done).map(a => done[a].length + ' ' + ({add: 'added', restore: 'restored', update: 'updated',
            delete: 'deleted'}[a] || a)).join(', ');
          toast('Imported from the spec file' + (said ? ': ' + said : ''), 'ok');
          review = null;
          settle = {};
          return load();
        }
        toast((d && d.error) || 'The import failed', 'err');
        if (d && d.spec) { review = d.spec; settle = {}; }
        return load();
      }).catch(() => toast('The import failed', 'err'));
    }

    function download() {
      return api(pUrl('/api/requirements/export')).then(d => {
        if (!d || !d.ok) { toast((d && d.error) || 'The export failed', 'err'); return; }
        const href = URL.createObjectURL(new Blob([d.content], {type: 'application/yaml'}));
        const a = document.createElement('a');
        a.href = href;
        a.download = 'requirements.yaml';
        a.rel = 'noopener';
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(href), 60000);
        toast('Save it as ' + d.path + ' in the repository, and commit it', 'ok');
      }).catch(() => toast('The export failed', 'err'));
    }

    function card(r) {
      const lc = r.last_check;
      const tests = (r.tests || []).length;
      const chips = [];
      const status = r.status || 'approved';
      if (status !== 'approved') chips.push('<span class="exec-chip">' + esc(status) + '</span>');
      if (r.priority) chips.push('<span class="exec-chip' + (r.priority === 'must' ? ' pos' : '') + '">' + esc(r.priority) + '</span>');
      chips.push('<span class="exec-chip">' + (tests ? tests + ' test' + (tests === 1 ? '' : 's') : 'no tests') + '</span>');
      const impl = (r.tasks || []).length;
      if (impl) chips.push('<span class="exec-chip" title="Tasks that implement it — its details list them">' + impl + ' task' + (impl === 1 ? '' : 's') + '</span>');
      if (ACTION[r.action]) chips.push('<span class="exec-chip" style="color:var(--yellow,#d29922)" title="' +
        esc('Open: ' + (r.gaps || []).join(', ')) + '">' + ACTION[r.action] + '</span>');
      (r.tags || []).forEach(t => chips.push('<span class="exec-chip">' + esc(t) + '</span>'));
      let meta = status === 'draft' ? 'A draft: nothing checks it until a person approves it.' : 'Never checked.';
      if (lc) {
        meta = 'Checked ' + when(lc.checked_at) + (lc.checked_by ? ' by ' + lc.checked_by : '') + ' via ' + lc.method +
          (lc.commit ? ' at ' + lc.commit.slice(0, 10) + (lc.dirty ? ' (uncommitted changes)' : '') : '') +
          // The requirements gate checked it for a task (Task 20461).
          (lc.task_id ? ' for task #' + (+lc.task_id) : '');
        if (lc.regression) chips.push('<span class="exec-chip" style="color:var(--red)" title="It passed at its previous check of this definition">regression</span>');
      }
      let stale = '';
      if (r.stale === 'changed') stale = 'Stale: the requirement changed since it was checked.';
      else if (r.stale === 'tasks') stale = 'Stale: ' + r.tasks_done_since + ' task' + (r.tasks_done_since === 1 ? '' : 's') + ' done since it was checked.';
      return '<div class="exec-card" data-req="' + r.id + '"' + (status === 'deprecated' ? ' style="opacity:.6"' : '') + '>' +
        '<div class="exec-card-head"><span class="exec-id">R-' + r.id + '</span>' +
        '<span class="exec-name" style="' + wrap + '">' + esc(r.title) + '</span>' + badge(lc && lc.verdict) +
        (tests && status !== 'draft' ? ' ' + proofBadge(r.last_proof, r.proof_stale) : '') + '</div>' +
        '<div class="exec-chips">' + chips.join('') + '</div>' +
        (r.description ? '<div class="form-hint" style="white-space:pre-wrap;' + wrap + '">' + esc(r.description.length > 400 ? r.description.slice(0, 400) + '…' : r.description) + '</div>' : '') +
        '<div class="exec-meta"><span style="' + wrap + '">' + esc(meta) + '</span>' +
        (r.approved_by ? '<span style="' + wrap + '">' + esc('Approved by ' + r.approved_by + ' ' + when(r.approved_at)) + '</span>' : '') +
        (lc && lc.summary ? '<span style="' + wrap + '">' + esc(lc.summary) + '</span>' : '') +
        (stale ? '<span style="color:var(--yellow,#d29922)">' + esc(stale) + '</span>' : '') + '</div>' +
        '<div class="exec-actions">' +
        (status === 'draft' ? '<button class="btn" data-perm="task.mutate" data-act="draftApproveOne" data-arg="' + r.id + '">Approve</button>'
          : tests ? '<button class="btn" data-perm="run.start" data-act="checkOne" data-arg="' + r.id + '">Check</button>' +
            '<button class="btn" data-perm="run.start" data-act="prove" data-arg="' + r.id + '" title="Runs its tests at the commit before ' +
            'their implementation and on the change: they should fail there and pass here">Prove</button>'
          : '<button class="btn" data-perm="run.start" data-act="assessOne" data-arg="' + r.id + '" title="It has no tests: the model reads the code">Ask the model</button>') +
        '<button class="btn" data-act="details" data-arg="' + r.id + '">' + (openID === r.id ? 'Hide details' : 'Details') + '</button>' +
        '<button class="btn" data-perm="task.mutate" data-act="edit" data-arg="' + r.id + '">Edit</button>' +
        '<button class="btn" data-perm="task.mutate" data-act="del" data-arg="' + r.id + '">Delete</button>' +
        '</div><div class="req-details" id="reqDetails' + r.id + '" style="display:none"></div></div>';
    }

    function filter() { query = (this.value || '').trim(); render(); renderTrace(); }

    // ── checking ──
    function start(ids, ask) {
      const assess = ask || !!(el('reqAssess') && el('reqAssess').checked);
      return api(pUrl('/api/requirement-runs'), {ids, assess}).then(d => {
        if (h.harnessRefused(d)) return;
        if (d && d.ok) {
          const n = d.run.requirement_ids.length, k = (d.skipped || []).length, u = (d.unapproved || []).length;
          toast('Checking ' + n + ' requirement' + (n === 1 ? '' : 's') + '…' +
            (k ? ' ' + k + ' with no tests left as they are.' : '') +
            (u ? ' ' + u + ' not approved left out.' : ''), 'ok');
          return load();
        }
        toast((d && d.error) || 'The check did not start', 'err');
        if (d && d.active) load();
      }).catch(() => toast('The check did not start', 'err'));
    }
    // planGaps has the model plan the tasks that close the open gaps. A plan
    // that starts arrives in the Tasks tab's suggestions panel, to review.
    function planGaps() {
      return api(pUrl('/api/requirements/plan'), {}).then(d => {
        if (h.harnessRefused(d)) return;
        if (!d || !d.ok) { toast((d && d.error) || 'Planning did not start', 'err'); return; }
        if (!d.started) { toast(d.message || 'Nothing to plan', 'ok'); return; }
        toast('Planning ' + d.targets + ' open gap' + (d.targets === 1 ? '' : 's') + ' with the model: review the plan in the suggestions panel', 'ok');
        window.showSuggestions();
      }).catch(() => toast('Planning did not start', 'err'));
    }

    // prove runs one requirement's tests red-green on the project's executor.
    // It answers at once; the proof's end arrives as a push.
    function prove(arg) {
      return api(pUrl('/api/requirements/' + (+arg) + '/prove'), {}).then(d => {
        if (h.harnessRefused(d)) return;
        if (d && d.ok) { toast('Proving R-' + (+arg) + ': its tests run at their base, then on the change…', 'ok'); return load(); }
        toast((d && d.error) || 'The proof did not start', 'err');
        if (d && d.active) load();
      }).catch(() => toast('The proof did not start', 'err'));
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
      setView('list');
      editing = id;
      el('reqFormTitle').textContent = r ? 'Edit R-' + r.id : 'New requirement';
      el('reqTitle').value = r ? r.title : '';
      el('reqDesc').value = r ? (r.description || '') : '';
      el('reqPriority').value = r ? (r.priority || '') : '';
      el('reqStatus').value = r ? (r.status || 'approved') : 'approved';
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
        title, description: el('reqDesc').value, priority: el('reqPriority').value, status: el('reqStatus').value,
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
      const n = (r && r.tasks || []).length;
      if (!r || !confirm('Delete R-' + r.id + ' "' + r.title + '" and the history of its checks?' +
        (n ? '\n\n' + n + ' task' + (n === 1 ? ' implements' : 's implement') + ' it and will no longer be held to it.' : '') +
        '\n\nThis cannot be undone.')) return;
      return apiMethod('DELETE', pUrl('/api/requirements/' + r.id), null).then(d => {
        if (d && d.ok) {
          const n = (d.unlinked_tasks || []).length;
          toast('Deleted R-' + r.id + (n ? '; ' + n + ' task' + (n === 1 ? ' no longer implements' : 's no longer implement') + ' it' : ''), 'ok');
          if (openID === r.id) openID = null;
          load();
        }
        else toast((d && d.error) || 'Delete failed', 'err');
      }).catch(() => toast('Delete failed', 'err'));
    }

    // ── details ──
    function details(arg) {
      const id = +arg;
      openID = openID === id ? null : id;
      render();
    }
    // show opens one requirement's details, for a task's R-n chip (Task
    // 20460). The tab's own open() is loading the list when it is new; its
    // render shows them.
    function show(arg) {
      setView('list');
      openID = +arg;
      query = '';
      if (el('reqSearch')) el('reqSearch').value = '';
      if (!data) return;
      render();
      const c = el('reqList').querySelector('[data-req="' + openID + '"]');
      if (c) c.scrollIntoView({block: 'center'});
    }
    function openTask(arg) { window.openTaskDetails(+arg); }
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
      // The tasks that implement it (Task 20460): each holds its run to it.
      const tasks = d.tasks || [];
      html += '<div class="exec-meta" style="margin-top:6px"><strong>Implemented by</strong>' + (tasks.length
        ? tasks.map(t => '<span><button class="btn" style="padding:2px 8px;font-size:11px" data-act="openTask" data-arg="' + (+t.id) + '">#' + (+t.id) +
          '</button> <span style="' + wrap + '">' + esc(t.title) + '</span> <span class="form-hint">' + esc(t.status || 'pending') + '</span></span>').join('')
        : '<span>No task yet. A task linked to it — from its own edit dialog, or added below — is given it as its contract.</span>') + '</div>';
      const retired = (r.status || 'approved') === 'deprecated';
      // A draft has no verdict until it is approved (Task 20462).
      html += (r.status === 'draft' ? '<p class="form-hint" style="margin-top:8px">A draft has no verdict: approve it first.</p>'
        : '<div class="exec-actions" style="margin-top:8px">' +
        '<input class="form-input" id="reqNote' + r.id + '" placeholder="Note for a recorded verdict" style="flex:1;min-width:140px">' +
        '<button class="btn" data-perm="task.mutate" data-act="verdict" data-arg="' + r.id + ':fulfilled">Mark fulfilled</button>' +
        '<button class="btn" data-perm="task.mutate" data-act="verdict" data-arg="' + r.id + ':unfulfilled">Mark unfulfilled</button></div>') +
        (retired ? '' : '<div class="exec-actions">' +
        '<button class="btn" data-perm="task.mutate" data-act="makeTask" data-arg="' + r.id + ':fix">Add a task to restore it</button>' +
        ((r.tests || []).length ? '' : '<button class="btn" data-perm="task.mutate" data-act="makeTask" data-arg="' + r.id + ':test">Add a task to test it</button>') +
        '</div>');
      html += proofsHTML(d);
      const checks = d.checks || [];
      if (!checks.length) return html + '<p class="form-hint">Never checked.</p>';
      html += '<div class="section-title" style="margin:10px 0 4px">Recent checks</div>';
      return html + checks.map(c => {
        const stale = c.fingerprint && c.fingerprint !== d.fingerprint ? ' · before the requirement last changed' : '';
        let s = '<div style="border-top:1px solid var(--border);padding:6px 0">' + badge(c.verdict) +
          (c.regression ? ' <span class="exec-chip" style="color:var(--red)">regression</span>' : '') +
          ' <span class="form-hint" style="' + wrap + '">' + esc(when(c.checked_at) + ' · ' + c.method + (c.checked_by ? ' · ' + c.checked_by : '') +
            (c.task_id ? ' · task #' + c.task_id : '') +
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

    // proofsHTML lists a requirement's recent red-green proofs: what each
    // decided, at which base, and each side's tests.
    const FROM = {task: 'where the task started', test: 'the commit before the test\'s implementation',
      worktree: 'HEAD: the test is uncommitted', given: 'the commit asked for'};
    function proofsHTML(d) {
      const proofs = d.proofs || [];
      if (!proofs.length) return '';
      const testLine = (t, side) => {
        let s = '<div class="form-hint" style="' + wrap + '">' + esc('[' + t.outcome + ' ' + side + '] ' + (t.name || t.command) +
          ' — exit ' + t.exit_code + ', ' + t.duration_ms + ' ms' + (t.error ? ' — ' + t.error : '')) + '</div>';
        if (t.output && t.outcome !== 'pass') {
          s += '<pre style="max-height:180px;overflow:auto;white-space:pre-wrap;' + wrap + ';font-size:11px;background:var(--bg);' +
            'border:1px solid var(--border);border-radius:6px;padding:6px;margin:4px 0">' + esc((t.truncated ? '…' : '') + t.output) + '</pre>';
        }
        return s;
      };
      return '<div class="section-title" style="margin:10px 0 4px">Recent proofs</div>' + proofs.map(p => {
        const b = p.before || {}, a = p.after || {};
        const stale = p.fingerprint && p.fingerprint !== d.fingerprint ? ' · of tests it no longer has' : '';
        let s = '<div style="border-top:1px solid var(--border);padding:6px 0">' + proofBadge(p, false) +
          ' <span class="form-hint" style="' + wrap + '">' + esc(when(p.proved_at) + (p.proved_by ? ' · ' + p.proved_by : '') +
            (p.task_id ? ' · task #' + p.task_id : '') + (p.executor_id ? ' · ' + p.executor_id : '') +
            (b.commit ? ' · base ' + b.commit.slice(0, 10) + (FROM[p.base_from] ? ' (' + FROM[p.base_from] + ')' : '') : '') +
            (a.commit ? ' · change ' + a.commit.slice(0, 10) + (a.dirty ? '+' : '') : '') + stale) + '</span>';
        if (p.summary) s += '<div style="font-size:12px;' + wrap + '">' + esc(p.summary) + '</div>';
        if (p.fallback && (p.test_files || []).length) {
          s += '<div class="form-hint" style="' + wrap + '">' + esc('Laid over the base: ' + p.test_files.map(f => f.path +
            (f.status === 'D' ? ' (removed)' : '')).join(', ')) + '</div>';
        }
        (b.tests || []).forEach(t => { s += testLine(t, 'at the base'); });
        if (b.skipped) s += '<div class="form-hint" style="' + wrap + '">' + esc('At the base: ' + b.skipped) + '</div>';
        (a.tests || []).forEach(t => { s += testLine(t, 'on the change'); });
        if (a.skipped) s += '<div class="form-hint" style="' + wrap + '">' + esc('On the change: ' + a.skipped) + '</div>';
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
        if (d && d.ok) { toast('Added task #' + d.task.id + ', linked to R-' + id, 'ok'); load(); }
        else toast((d && d.error) || 'Could not add the task', 'err');
      }).catch(() => toast('Could not add the task', 'err'));
    }

    // ── traceability (Task 20465) ──
    const GAPS = ['unfulfilled', 'stale', 'untested', 'unlinked', 'unchecked'];
    const yellow = 'color:var(--yellow,#d29922)';

    // setView shows the list or the matrix; the toolbar, the summary and a
    // check under way show in both.
    function setView(v) {
      view = v;
      if (!el('reqTrace')) return;
      el('reqListView').style.display = v === 'list' ? '' : 'none';
      el('reqTrace').style.display = v === 'trace' ? '' : 'none';
      [['reqViewList', 'list'], ['reqViewTrace', 'trace']].forEach(([id, k]) => {
        el(id).classList.toggle('primary', v === k);
        el(id).setAttribute('aria-pressed', String(v === k));
      });
    }
    function showList() { setView('list'); }
    // trace shows the matrix: the toggle's, and the Overview card's through
    // panelAct. Read again when a push moved it while it was off screen.
    function trace() {
      setView('trace');
      if (!tr || trStale) return traceLoad(!!tr);
      renderTrace();
    }
    function traceURL(after, limit) {
      const p = new URLSearchParams();
      [['priority', 'rtPriority'], ['tag', 'rtTag'], ['gap', 'rtGap']].forEach(([k, id]) => {
        if (el(id) && el(id).value) p.set(k, el(id).value);
      });
      if (after) p.set('after', String(after));
      p.set('limit', String(limit));
      return pUrl('/api/requirements/trace?' + p);
    }
    // traceLoad reads the first page again: as many rows as are shown, when
    // keep, so a push does not take away the rows a person paged to.
    function traceLoad(keep) {
      const n = keep && tr ? Math.min(200, Math.max(50, (tr.rows || []).length)) : 50;
      const seq = ++trSeq;
      trStale = false;
      return api(traceURL(0, n)).then(d => {
        if (seq !== trSeq) return;
        if (!d || !d.ok) { toast((d && d.error) || 'Could not load the traceability matrix', 'err'); return; }
        tr = {rows: d.rows || [], coverage: d.coverage, matched: d.matched, next: d.next || 0, digest: d.digest};
        renderTrace();
      }).catch(() => toast('Could not load the traceability matrix', 'err'));
    }
    function traceMore() {
      if (!tr || !tr.next) return;
      const seq = trSeq;
      return api(traceURL(tr.next, 50)).then(d => {
        if (seq !== trSeq || !tr) return;
        if (!d || !d.ok) { toast((d && d.error) || 'Could not load more rows', 'err'); return; }
        tr.rows = tr.rows.concat(d.rows || []);
        tr.next = d.next || 0;
        renderTrace();
      }).catch(() => toast('Could not load more rows', 'err'));
    }
    function traceFilter() { return traceLoad(false); }
    // traceGap filters by a gap the coverage counts.
    function traceGap(arg) {
      el('rtGap').value = arg;
      return traceLoad(false);
    }
    function traceShow(arg) { show(arg); }
    function traceTask(arg) { window.openTaskDetails(+arg); }
    // coverage is a requirements_coverage push: the coverage redraws at once,
    // and the rows are read again when the digest moved — later, when the view
    // is not on screen.
    function coverage(d) {
      if (!d || !tr) return;
      if (d.coverage) tr.coverage = d.coverage;
      if (d.digest === tr.digest) return;
      if (view !== 'trace' || h.tab() !== 'requirements') { trStale = true; return; }
      renderTrace();
      clearTimeout(trTimer);
      trTimer = setTimeout(() => traceLoad(true), 250);
    }

    function covHTML(c) {
      if (!c.approved) return '<p class="form-hint">No approved requirements yet: the matrix traces the approved ones.</p>';
      const m = c.musts.total ? c.musts : c.all;
      const meter = (label, n, pct) => '<div style="border:1px solid var(--border);border-radius:8px;padding:8px 10px;min-width:0">' +
        '<div class="form-hint">' + label + '</div><div style="font-size:16px;font-weight:600">' + (+pct) + '%</div>' +
        '<div class="form-hint">' + (+n) + ' of ' + (+m.total) + '</div>' +
        '<div style="height:4px;background:var(--border);border-radius:2px;margin-top:4px"><div style="height:4px;border-radius:2px;width:' +
        (+pct) + '%;background:' + (pct >= 80 ? 'var(--green,#3fb950)' : pct >= 50 ? 'var(--yellow,#d29922)' : 'var(--red,#f85149)') + '"></div></div></div>';
      const a = c.all;
      const gaps = GAPS.filter(g => c.gaps && c.gaps[g]);
      return '<div class="section-title" style="margin:0 0 6px">Spec coverage of ' + (c.musts.total ? m.total + ' must requirement' +
        (m.total === 1 ? '' : 's') : 'every approved requirement: none is a must') + '</div>' +
        '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px">' +
        meter('Tested', m.tested, m.tested_pct) + meter('Proven', m.proven, m.proven_pct) + meter('Passing', m.passing, m.passing_pct) +
        meter('Linked to a task', m.linked, m.linked_pct) + '</div>' +
        '<div class="form-hint" style="margin-top:6px;' + wrap + '">' + esc('All ' + a.total + ' approved: ' + a.tested_pct + '% tested, ' +
          a.proven_pct + '% proven, ' + a.passing_pct + '% passing, ' + a.linked_pct + '% linked' +
          (c.stale ? '; ' + c.stale + ' stale verdict' + (c.stale === 1 ? '' : 's') : '') + '.') + '</div>' +
        (gaps.length ? '<div class="exec-chips" style="margin-top:6px">' + gaps.map(g => '<button class="exec-chip" data-act="traceGap" data-arg="' + g +
          '" style="background:transparent;cursor:pointer;font-family:inherit;' + yellow + '" title="Show the requirements with this gap">' +
          (+c.gaps[g]) + ' ' + g + '</button>').join('') + '</div>' : '');
    }
    // An entry in a list cell: one a line in a table column, side by side
    // once a phone stacks the cells.
    const entry = 'display:inline-block;margin:0 8px 2px 0;max-width:100%';
    function taskHTML(t) {
      if (t.deleted) return '<span class="form-hint" style="' + entry + '">#' + (+t.id) + ' deleted</span>';
      return '<span style="' + entry + '"><button class="btn" style="padding:1px 6px;font-size:11px" data-act="traceTask" data-arg="' + (+t.id) +
        '" title="' + esc(t.title || '') + '">#' + (+t.id) + '</button> <span class="form-hint">' + esc(t.status || '') + '</span></span>';
    }
    function rowHTML(r) {
      const v = r.verdict, p = r.proof;
      const more = n => n ? '<span class="form-hint" style="' + entry + '">+' + (+n) + ' more</span>' : '';
      const tasks = (r.tasks || []).map(taskHTML).join('') + more(r.tasks_omitted);
      const commits = (r.commits || []).map(c => '<code style="font-size:11px;' + entry + '" title="' + esc((c.subject ? c.subject + ' — ' : '') +
        'task #' + c.task_id + ', from the ' + c.source + (c.confidence ? ' (' + c.confidence + ' confidence)' : '')) + '">' +
        esc(String(c.hash).slice(0, 10)) + '</code>').join('') + more(r.commits_omitted);
      let verdict = '<span class="form-hint">never checked</span>';
      if (v) {
        verdict = badge(v.verdict) + ' <span class="form-hint">' + esc((v.method ? v.method + ' · ' : '') + when(v.checked_at)) + '</span>' +
          (v.stale ? '<div style="font-size:11px;' + yellow + '">' + esc(v.stale === 'changed' ? 'stale: changed since' : 'stale: ' +
            v.tasks_done_since + ' task' + (v.tasks_done_since === 1 ? '' : 's') + ' done since') + '</div>' : '') +
          (v.task ? '<div class="form-hint">' + esc('for task #' + v.task.id + (v.task.deleted ? ' (deleted)' : '')) + '</div>' : '') +
          (v.regression ? '<div style="font-size:11px;color:var(--red)">regression</div>' : '');
      }
      const tags = (r.tags || []).map(t => '<span class="exec-chip" style="' + wrap + '">' + esc(t) + '</span>').join('');
      return '<tr data-trace="' + (+r.id) + '"><td><button class="btn" style="padding:1px 6px;font-size:11px" data-act="traceShow" data-arg="' +
        (+r.id) + '" title="Show it in the list">R-' + (+r.id) + '</button> <span style="' + wrap + '">' + esc(r.title) + '</span>' +
        (tags ? '<div class="exec-chips" style="margin-top:2px">' + tags + '</div>' : '') +
        ((r.gaps || []).length ? '<div style="font-size:11px;' + yellow + ';' + wrap + '">' + esc('open: ' + r.gaps.join(', ')) + '</div>' : '') +
        '</td><td data-l="Priority">' + esc(r.priority || '—') + '</td><td data-l="Tasks">' + (tasks || '<span class="form-hint">none</span>') +
        '</td><td data-l="Commits">' + (commits || '<span class="form-hint">none</span>') + '</td><td data-l="Latest verdict">' + verdict +
        '</td><td data-l="Proof">' + (r.tests ? proofBadge(p, p && p.stale) : '<span class="form-hint">no tests</span>') +
        (p && p.task ? '<div class="form-hint">' + esc('for task #' + p.task.id + (p.task.deleted ? ' (deleted)' : '')) + '</div>' : '') +
        '</td><td data-l="Verified"><span class="exec-chip"' + (r.verification === 'unverified' ? ' style="' + yellow + '"' : '') + '>' +
        esc(r.verification) + '</span></td></tr>';
    }
    function renderTrace() {
      if (!tr || !el('rtTable')) return;
      const c = tr.coverage;
      if (c) {
        el('rtCov').innerHTML = covHTML(c);
        // A tag the requirements no longer carry stays chosen until changed.
        const sel = el('rtTag'), cur = sel.value, tags = (c.tags || []).slice();
        if (cur && !tags.includes(cur)) tags.push(cur);
        sel.innerHTML = '<option value="">any</option>' + tags.map(t => '<option value="' + esc(t) + '"' + (t === cur ? ' selected' : '') + '>' +
          esc(t) + '</option>').join('');
      }
      const q = query.toLowerCase();
      const rows = tr.rows.filter(r => !q || ('r-' + r.id + ' ' + r.title + ' ' + (r.tags || []).join(' ') + ' ' + (r.tasks || []).map(t =>
        '#' + t.id + ' ' + (t.title || '')).join(' ') + ' ' + (r.commits || []).map(x => x.hash + ' ' + (x.subject || '')).join(' ')).toLowerCase().includes(q));
      el('rtCount').textContent = tr.matched === undefined || tr.matched === null ? '' : (q ? rows.length + ' found of ' + tr.rows.length +
        ' shown' : tr.rows.length + ' of ' + tr.matched + ' shown') + (c && tr.matched !== c.approved ? ' (' + c.approved + ' approved)' : '');
      el('rtTable').innerHTML = rows.length ? '<table class="rt"><colgroup><col style="width:26%"><col style="width:7%"><col style="width:14%">' +
        '<col style="width:12%"><col style="width:19%"><col style="width:10%"><col style="width:12%"></colgroup><thead><tr><th>Requirement</th>' +
        '<th>Priority</th><th>Tasks</th><th>Commits</th><th>Latest verdict</th><th>Proof</th><th>Verified</th></tr></thead><tbody>' +
        rows.map(rowHTML).join('') + '</tbody></table>'
        : '<p class="form-hint">' + (tr.rows.length ? 'No row matches the search.' : c && !c.approved ? '' :
          'No approved requirement matches the filter.') + '</p>';
      el('rtMore').style.display = tr.next ? '' : 'none';
    }

    // ── drafting with the model (Task 20462) ──
    const draftsOf = () => ((data && data.requirements) || []).filter(r => r.status === 'draft');
    const SEV = {error: 'var(--red,#f85149)', warning: 'var(--yellow,#d29922)'};

    function draftOpen() {
      if (!el('rd-overlay')) return;
      const goal = (h.tl.state() || {}).goal || '';
      el('rdGoal').textContent = goal || 'The project has no goal yet.';
      draftSource();
      renderDraft();
      window.openOverlay('rd-overlay', {dismiss: draftClose, focus: '#rdText'});
      return lintRules();
    }
    function draftClose() { window.closeOverlay('rd-overlay'); }
    function draftSource() {
      const fromGoal = !!(el('rdSrcGoal') && el('rdSrcGoal').checked);
      el('rdGoal').style.display = fromGoal ? '' : 'none';
      el('rdText').style.display = fromGoal ? 'none' : '';
      el('rdFileRow').style.display = fromGoal ? 'none' : '';
    }
    // draftFile puts a file chosen from the computer into the text: read here,
    // never uploaded as a file.
    function draftFile() {
      const f = this.files && this.files[0];
      if (!f) return;
      if (f.size > 64 * 1024) { toast('That file is larger than 64 KiB: draft from it a part at a time', 'err'); this.value = ''; return; }
      const rd = new FileReader();
      rd.onload = () => { el('rdText').value = String(rd.result || ''); };
      rd.onerror = () => toast('The file could not be read', 'err');
      rd.readAsText(f);
    }
    function busy(what, msg) {
      drafting = what;
      el('rdStatus').innerHTML = what ? '<span class="spinner"></span> ' + esc(msg) : '';
      footer();
    }

    function draftGo() {
      if (drafting) return;
      const fromGoal = el('rdSrcGoal').checked;
      const text = el('rdText').value;
      if (!fromGoal && !text.trim()) { toast('Paste the text to draft from, or draft from the goal', 'err'); return; }
      const max = Math.round(+el('rdMax').value || 0);
      busy('draft', 'The model is drafting on the project\'s executor… this can take a few minutes.');
      return api(pUrl('/api/requirements/draft'), {source: fromGoal ? 'goal' : 'text', text: fromGoal ? '' : text, max}).then(d => {
        busy('', '');
        if (!d || !d.ok) {
          if (!h.harnessRefused(d)) el('rdStatus').textContent = (d && d.error) || 'Drafting failed';
          return;
        }
        drafted = {refused: d.refused || [], notes: d.notes || ''};
        const n = (d.drafts || []).length;
        toast('Drafted ' + n + ' requirement' + (n === 1 ? '' : 's') + ': review them before approving', 'ok');
        if (!fromGoal) el('rdText').value = '';
        return load().then(lintRules);
      }).catch(() => { busy('', ''); el('rdStatus').textContent = 'Drafting failed: could not reach the server'; });
    }

    // lintRules asks the hub what the rules say of every requirement: words
    // only, so it answers at once — but never over a model's lint still on
    // its way. draftLintModel asks the model too, on the project's executor,
    // about the drafts.
    function lintRules() {
      return api(pUrl('/api/requirements/lint')).then(d => {
        if (d && d.ok && drafting !== 'lint') { lint = {findings: d.findings || [], notes: [], checked: d.checked}; renderDraft(); }
      }).catch(() => {});
    }
    function draftLintModel() {
      if (drafting) return;
      busy('lint', 'The model is reading the requirements on the project\'s executor…');
      return api(pUrl('/api/requirements/lint'), {ids: draftsOf().map(r => r.id)}).then(d => {
        busy('', '');
        if (!d || !d.ok) {
          if (!h.harnessRefused(d)) el('rdStatus').textContent = (d && d.error) || 'The model\'s lint failed';
          return;
        }
        lint = {findings: d.findings || [], notes: d.notes || [], checked: d.checked, model: true};
        renderDraft();
      }).catch(() => { busy('', ''); el('rdStatus').textContent = 'The model\'s lint failed: could not reach the server'; });
    }

    function findingHTML(f) {
      const others = (f.others || []).map(o => 'R-' + (+o)).join(', ');
      return '<div style="border-left:3px solid ' + (SEV[f.severity] || 'var(--border)') + ';padding:2px 0 2px 8px;margin-top:6px;' + wrap + '">' +
        '<div style="font-size:12px">' + esc(f.severity + ' · ' + f.kind + (f.by === 'model' ? ' (model)' : '') + ' — ' + f.message) +
        (others ? ' <span class="form-hint">' + esc('(' + others + ')') + '</span>' : '') + '</div>' +
        (f.hint ? '<div class="form-hint">' + esc(f.hint) + '</div>' : '') + '</div>';
    }
    function draftCard(r, fs) {
      const chips = [];
      const chip = v => '<span style="' + wrap + ';max-width:100%">' + esc(v) + '</span>';
      if (r.priority) chips.push(chip(r.priority));
      (r.tags || []).forEach(t => chips.push(chip(t)));
      const tests = (r.tests || []).map(t => '<code style="display:block;white-space:pre-wrap;' + wrap + ';font-size:11px;margin-top:2px">' +
        esc(t.command) + '</code>').join('');
      return '<div class="dc-sub" style="cursor:default;display:block" data-draft="' + r.id + '">' +
        '<div class="dc-sub-title" style="' + wrap + '"><span class="exec-id">R-' + r.id + '</span> ' + esc(r.title) + '</div>' +
        (chips.length ? '<div class="dc-sub-meta">' + chips.join('') + '</div>' : '') +
        (r.description ? '<div class="dc-sub-desc">' + esc(r.description) + '</div>' : '') +
        (tests ? '<div class="form-hint" style="margin-top:6px">Proposed test — read it before approving: approving lets checks ' +
          'and the requirements gate run it.</div>' + tests : '<div class="form-hint" style="margin-top:6px">No test: only the model ' +
          'or a person can say it holds.</div>') +
        fs.map(findingHTML).join('') +
        '<div class="exec-actions" style="margin-top:8px;flex-wrap:wrap">' +
        '<button class="btn primary" data-perm="task.mutate" data-act="draftApproveOne" data-arg="' + r.id + '">Approve</button>' +
        '<button class="btn" data-perm="task.mutate" data-act="draftEdit" data-arg="' + r.id + '">Edit first</button>' +
        '<button class="btn" data-perm="task.mutate" data-act="draftDiscard" data-arg="' + r.id + '">Discard</button></div></div>';
    }
    function renderDraft() {
      const box = el('rdReview');
      if (!box) return;
      const drafts = draftsOf();
      const fs = (lint && lint.findings) || [];
      const byID = {};
      fs.forEach(f => { (byID[f.id] = byID[f.id] || []).push(f); });
      let html = '';
      if (drafted && drafted.refused.length) {
        html += '<div class="form-hint" style="margin-bottom:8px;' + wrap + '"><strong>' + drafted.refused.length + ' proposal' +
          (drafted.refused.length === 1 ? ' was' : 's were') + ' refused</strong>' + drafted.refused.map(f =>
          '<div>' + esc((f.index ? f.index + '. ' : '') + (f.title ? f.title + ' — ' : '') + f.reason) + '</div>').join('') + '</div>';
      }
      if (drafted && drafted.notes) html += '<div class="form-hint" style="margin-bottom:8px;' + wrap + '">' + esc('The model: ' + drafted.notes) + '</div>';
      html += '<div class="section-title" style="margin:8px 0 6px">' + (drafts.length ? drafts.length + ' draft' +
        (drafts.length === 1 ? '' : 's') + ' awaiting approval' : 'No drafts await approval') + '</div>';
      html += drafts.map(r => draftCard(r, byID[r.id] || [])).join('');
      const elsewhere = fs.filter(f => !drafts.some(r => r.id === f.id));
      if (elsewhere.length) html += '<div class="section-title" style="margin:12px 0 2px">Elsewhere in the project</div>' +
        elsewhere.map(f => '<div><span class="exec-id">R-' + (+f.id) + '</span>' + findingHTML(f) + '</div>').join('');
      if (lint && !fs.length) html += '<p class="form-hint">' + esc('Lint found nothing to fix in ' + (lint.checked || 0) + ' requirement' +
        (lint.checked === 1 ? '' : 's') + (lint.model ? ', the model included.' : '.')) + '</p>';
      ((lint && lint.notes) || []).forEach(n => { html += '<div class="form-hint" style="color:var(--yellow,#d29922);' + wrap + '">' + esc('Note: ' + n) + '</div>'; });
      box.innerHTML = html;
      footer();
      h.applyPermissionGating(el('rd-overlay'));
    }
    function footer() {
      const n = draftsOf().length;
      const all = el('rdApproveAll');
      if (!all) return;
      all.textContent = n ? 'Approve all ' + n : 'Approve all';
      all.disabled = !n || !!drafting;
      el('rdGo').disabled = !!drafting;
      el('rdLint').disabled = !!drafting;
    }

    function approve(ids) {
      if (!ids.length || drafting) return;
      busy('approve', 'Approving…');
      return api(pUrl('/api/requirements/approve'), {ids}).then(d => {
        busy('', '');
        if (!d || !d.ok) { toast((d && d.error) || 'Approval failed', 'err'); return; }
        const keys = (d.approved || []).map(r => 'R-' + (+r.id));
        toast(keys.length ? 'Approved ' + keys.join(', ') + ': checks and the gate count ' + (keys.length === 1 ? 'it' : 'them') + ' now'
          : 'Already approved', 'ok');
        return load().then(lintRules);
      }).catch(() => { busy('', ''); toast('Approval failed', 'err'); });
    }
    function draftApproveOne(arg) { return approve([+arg]); }
    function draftApproveAll() {
      const ids = draftsOf().map(r => r.id);
      if (!ids.length || !confirm('Approve all ' + ids.length + ' draft' + (ids.length === 1 ? '' : 's') + '? From then on checks and ' +
        'the requirements gate run their tests — read each first.')) return;
      return approve(ids);
    }
    // draftEdit opens a draft in the tab's form: saving it approved approves
    // it, as whoever saves it.
    function draftEdit(arg) {
      draftClose();
      openForm(+arg);
      if (el('reqForm').scrollIntoView) el('reqForm').scrollIntoView({block: 'center'});
    }
    function draftDiscard(arg) {
      const r = draftsOf().find(x => x.id === +arg);
      if (!r || !confirm('Discard the draft R-' + r.id + ' "' + r.title + '"?')) return;
      return apiMethod('DELETE', pUrl('/api/requirements/' + r.id), null).then(d => {
        if (d && d.ok) { toast('Discarded R-' + r.id, 'ok'); return load().then(lintRules); }
        toast((d && d.error) || 'Discard failed', 'err');
      }).catch(() => toast('Discard failed', 'err'));
    }

    return h.mount({open, load, pushed, filter, planGaps, checkAll, checkOne, assessOne, prove, stop, add, edit, cancelForm, save, del,
      details, show, openTask, verdict, makeTask, readSpec, reviewSpec, settleOne, importSpec, download,
      draftOpen, draftClose, draftSource, draftFile, draftGo, draftLintModel, draftApproveOne, draftApproveAll, draftEdit,
      draftDiscard, showList, trace, traceMore, traceFilter, traceGap, traceShow, traceTask, coverage}, 'requirements', `
    <div class="kb-tab-toolbar">
      <span class="section-title" style="margin:0">Requirements</span>
      <div class="kb-search-wrap">
        <input class="form-input kb-search-input" id="reqSearch" placeholder="Search requirements..." data-input="filter">
      </div>
      <button class="btn primary" id="reqCheckAll" data-perm="run.start" style="padding:4px 12px;font-size:12px" data-act="checkAll"
        title="Checks the approved requirements">Check all</button>
      <label class="form-hint" style="display:flex;gap:5px;align-items:center" title="A requirement with no tests is otherwise skipped, its last verdict kept">
        <input type="checkbox" id="reqAssess"> Ask the model about untested ones</label>
      <button class="btn" data-perm="task.mutate" style="padding:4px 12px;font-size:12px" data-act="add">+ Add requirement</button>
      <button class="btn" data-perm="task.mutate" style="padding:4px 12px;font-size:12px" data-act="draftOpen"
        title="The model drafts testable requirements from the goal or a specification; you approve them">Draft requirements</button>
      <button class="btn" id="reqPlan" data-perm="task.mutate" style="padding:4px 12px;font-size:12px" data-act="planGaps"
        title="The model plans the tasks that close the open gaps — must first — each linked to what it closes; you review the plan in the Tasks tab">Plan from requirements</button>
      <button class="btn" style="padding:4px 10px;font-size:12px" data-act="load">Refresh</button>
    </div>
    <div id="reqSummary" class="form-hint" style="margin-bottom:6px"></div>
    <div class="exec-actions" role="group" aria-label="View" style="margin-bottom:8px">
      <button class="btn primary" id="reqViewList" aria-pressed="true" data-act="showList">Requirements</button>
      <button class="btn" id="reqViewTrace" aria-pressed="false" data-act="trace"
        title="Each requirement's tasks, their commits, its latest verdict and proof — and the spec coverage">Traceability</button>
    </div>
    <div id="reqRun" class="exec-actions" style="display:none;align-items:center;margin-bottom:10px"></div>
    <div id="reqTrace" style="display:none">
      <style>
      #reqTrace .rt{width:100%;border-collapse:collapse;table-layout:fixed;font-size:12px}
      #reqTrace .rt th{text-align:left;font-weight:600;color:var(--muted);padding:6px;border-bottom:1px solid var(--border)}
      #reqTrace .rt td{vertical-align:top;padding:6px;border-top:1px solid var(--border);overflow-wrap:anywhere;word-break:break-word}
      @media (max-width:900px){#reqTrace .rt,#reqTrace .rt tbody,#reqTrace .rt tr,#reqTrace .rt td{display:block;width:auto}
        #reqTrace .rt colgroup,#reqTrace .rt thead{display:none}#reqTrace .rt tr{border-top:1px solid var(--border);padding:8px 0}
        #reqTrace .rt td{border:0;padding:2px 0}#reqTrace .rt td[data-l]::before{content:attr(data-l) ": ";color:var(--muted);font-size:11px}}
      </style>
      <div id="rtCov"></div>
      <div class="exec-actions" style="flex-wrap:wrap;align-items:center;margin:10px 0 6px">
        <label class="form-hint" for="rtPriority">Priority</label>
        <select class="form-select" id="rtPriority" data-change="traceFilter" style="flex:0 0 auto;width:auto">
          <option value="">any</option><option value="must">must</option><option value="should">should</option>
          <option value="could">could</option><option value="none">none</option></select>
        <label class="form-hint" for="rtTag">Tag</label>
        <select class="form-select" id="rtTag" data-change="traceFilter" style="flex:0 1 auto;width:auto;min-width:0;max-width:100%">
          <option value="">any</option></select>
        <label class="form-hint" for="rtGap">Gap</label>
        <select class="form-select" id="rtGap" data-change="traceFilter" style="flex:0 0 auto;width:auto">
          <option value="">any</option><option value="unfulfilled">unfulfilled</option><option value="stale">stale</option>
          <option value="untested">untested</option><option value="unlinked">unlinked</option><option value="unchecked">unchecked</option>
          <option value="none">no gap</option></select>
        <span id="rtCount" class="form-hint" style="overflow-wrap:anywhere"></span>
      </div>
      <div id="rtTable"></div>
      <div id="rtMore" style="display:none;margin-top:8px"><button class="btn" data-act="traceMore">Load more</button></div>
    </div>
    <div id="reqListView">
    <div id="reqDrafts" class="exec-actions" style="display:none;align-items:center;margin-bottom:10px;flex-wrap:wrap"></div>
    <div id="reqSpec" style="display:none"></div>
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
        <select class="form-select" id="reqStatus" style="flex:0 0 130px;width:130px" title="A check checks the approved requirements">
          <option value="approved">approved</option><option value="draft">draft</option><option value="deprecated">deprecated</option></select>
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
    </div>
    `, `
    <div id="rd-overlay" data-overlay="flex" data-dismiss="draftClose"
      style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:60;align-items:center;justify-content:center">
      <div role="dialog" aria-modal="true" aria-labelledby="rd-title" style="background:var(--surface);border:1px solid var(--border);
        border-radius:var(--radius);width:720px;max-width:96vw;max-height:90vh;display:flex;flex-direction:column">
        <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--border)">
          <h2 id="rd-title" style="font-size:14px;font-weight:600;margin:0">Draft requirements</h2>
          <button class="btn" data-act="draftClose" aria-label="Close" style="padding:2px 10px">&times;</button>
        </div>
        <div style="padding:14px 18px;overflow-y:auto;flex:1;min-height:0">
          <p class="dc-hint">The model turns the text into atomic, testable requirements — "When &lt;trigger&gt;, the system shall
            &lt;response&gt;" — each with acceptance criteria, a priority, tags and, where the repository makes one obvious, a test.
            It runs where the project runs, with your account. The drafts count for nothing until you approve them.</p>
          <div class="exec-actions" style="flex-wrap:wrap;margin-bottom:6px">
            <label class="form-hint" style="display:flex;gap:5px;align-items:center"><input type="radio" name="rdSource" id="rdSrcText" checked
              data-change="draftSource"> A specification</label>
            <label class="form-hint" style="display:flex;gap:5px;align-items:center"><input type="radio" name="rdSource" id="rdSrcGoal"
              data-change="draftSource"> The project's goal</label>
          </div>
          <div id="rdGoal" class="form-hint" style="display:none;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;
            max-height:140px;overflow-y:auto;border:1px solid var(--border);border-radius:6px;padding:6px 8px"></div>
          <textarea id="rdText" class="form-input" rows="6" style="width:100%" aria-label="The specification to draft from"
            placeholder="Paste a specification, user stories or meeting notes (up to 64 KiB)"></textarea>
          <div id="rdFileRow" class="exec-actions" style="flex-wrap:wrap;align-items:center;margin-top:6px">
            <label class="form-hint" for="rdFile">Or read a file:</label>
            <input type="file" id="rdFile" accept=".md,.markdown,.txt,text/plain,text/markdown" data-change="draftFile" style="max-width:100%">
          </div>
          <div class="exec-actions" style="flex-wrap:wrap;align-items:center;margin-top:8px">
            <label class="form-hint" for="rdMax">At most</label>
            <input type="number" id="rdMax" class="form-input" min="1" max="30" value="12" style="width:80px;flex:0 0 80px">
            <button class="btn primary" id="rdGo" data-perm="task.mutate" data-act="draftGo">Draft</button>
          </div>
          <div id="rdStatus" class="form-hint" role="status" style="margin-top:6px;overflow-wrap:anywhere;word-break:break-word"></div>
          <div id="rdReview" style="margin-top:6px"></div>
        </div>
        <div class="modal-footer" style="padding:12px 18px;border-top:1px solid var(--border);margin-top:0;flex-wrap:wrap;gap:8px">
          <button class="btn" id="rdLint" data-perm="task.mutate" data-act="draftLintModel" style="margin-right:auto"
            title="Asks the model whether a draft repeats a requirement in other words, and which contradict each other">Check with the model</button>
          <button class="btn" data-act="draftClose">Close</button>
          <button class="btn primary" id="rdApproveAll" data-perm="task.mutate" data-act="draftApproveAll">Approve all</button>
        </div>
      </div>
    </div>`);
  };
})();
