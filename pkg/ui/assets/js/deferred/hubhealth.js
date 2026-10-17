// ── Settings → Hub health (Task 20434) ───────────────────────────────────────
//
// The hub doctor's checks as the hub answering this page ran them on itself:
// what fails, what is fragile and what passes, each with what was observed,
// what fixes it and the runbook section that explains its group. GET
// /api/hub/health computes a report at most once a minute, and again once the
// configuration changes, and names the hub member that answered: the listener
// checks are about that process. It never runs --smoke or
// --probe-network-policy, which start work, and the panel says how to run them
// on the host instead.
//
// Fetched when an administrator's Settings tab opens, or when the header's
// indicator is pressed (static.go, deferredScripts): first paint has no room
// for a panel most sessions never see. It draws into the section
// deferred/settings.js mounts, and wires its one button itself, since the
// Settings tab routes data-act to the Settings panel's own functions. It runs
// outside the dashboard's IIFE, so it is handed the helpers it calls, and the
// only name it puts on window is the factory.
//
// Everything a check wrote is rendered as text. The hub has already taken the
// credentials out of it; what is left can still be a name somebody chose.
//
// Below the findings sits the hub's own certificate authority (Task 20438):
// where a rotation of it stands — GET /api/hub/ca — and its steps, POSTed to
// /api/hub/ca/rotate as `cloop hub ca rotate` takes them. A step that destroys
// a key or breaks running runs asks first, saying which, and repeats its name
// in the request's confirm.
(function () {
  'use strict';

  window.cloopHubhealthPanel = function (h) {
    const box = () => document.getElementById('hubHealthBody');
    const GROUPS = [
      {key: 'fail', title: 'Failing', badge: 'failed', sym: '✗'},
      {key: 'warn', title: 'Warnings', badge: 'paused', sym: '!'},
      {key: 'pass', title: 'Passing', badge: 'complete', sym: '✔'},
    ];
    const DOCS = /^https:\/\/[^\s"'<>]+$/;
    const muted = 'font-size:12px;color:var(--muted)';
    let pending = null, shown = null;

    // load reads the report — the cached one, or with fresh a new run — and
    // draws it. Concurrent calls share one request.
    function load(fresh) {
      const el = box();
      if (!el || !h.known() || !h.canGlobal('config.write')) return Promise.resolve();
      if (pending && !fresh) return pending;
      if (!shown) el.innerHTML = '<p style="' + muted + '">Running the hub’s checks…</p>';
      const was = shown && shown.checked_at;
      const p = pending = h.api('/api/hub/health' + (fresh ? '?fresh=1' : '')).then(d => {
        if (!d || d.error) throw new Error((d && d.error) || 'the hub sent no report');
        shown = d;
        render(d);
        // The hub answers a rerun from a report seconds old; say so, or the
        // button looks like it did nothing.
        if (fresh && d.checked_at === was) h.toast('The checks ran seconds ago; this is that report', 'info');
      }).catch(e => {
        const b = box();
        if (!b) return;
        b.innerHTML = '<p role="alert" style="font-size:13px;color:var(--red)">The checks could not run: ' +
          h.esc((e && e.message) || e) + '</p>' + rerunButton();
        wire();
      }).finally(() => { if (pending === p) pending = null; });
      return p;
    }

    function rerunButton() {
      return '<button class="btn" id="hubHealthRerun" style="font-size:12px;padding:4px 10px">Run the checks again</button>';
    }

    function wire() {
      const b = document.getElementById('hubHealthRerun');
      if (b) b.addEventListener('click', () => { b.disabled = true; load(true); });
    }

    function render(d) {
      const el = box();
      if (!el) return;
      // A redraw keeps the Passing group as the reader left it.
      const open = el.querySelector && el.querySelector('details');
      const passOpen = !!(open && open.open);
      const m = d.member || {}, c = d.counts || {};
      const files = ((d.config && d.config.files) || []).map(f => '<code>' + h.esc(f) + '</code>');
      const checked = Date.parse(d.checked_at);
      const steps = d.steps || [];
      let html = '<p style="' + muted + ';margin-bottom:8px;overflow-wrap:anywhere">Answered by hub member <code>' +
        h.esc(m.id) + '</code>' + (m.hostname ? ' on <code>' + h.esc(m.hostname) + '</code>' : '') +
        (m.port ? ', port ' + h.esc(m.port) : '') +
        (m.clustered ? (m.leader ? ', the cluster’s leader' : ', one of the cluster’s members') : '') +
        ' — the checks of what listens are its own. ' + h.esc(steps.length) + ' checks ran ' +
        (checked ? h.esc(h.relTime(new Date(checked))) + ' ' : '') + 'in ' + h.esc(d.duration_ms) + ' ms, reading ' +
        (files.join(' with the overlay ') || 'no configuration file') + '.</p>';
      if (d.config && d.config.error) {
        html += '<p role="alert" style="font-size:13px;color:var(--red);overflow-wrap:anywhere">The configuration ' +
          'could not be loaded: ' + h.esc(d.config.error) + '</p>';
      }
      html += '<p style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:4px">' +
        GROUPS.map(g => '<span class="badge ' + g.badge + '">' + h.esc(c[g.key] || 0) + ' ' + g.title.toLowerCase() +
          '</span>').join('') + rerunButton() + '</p>';

      const by = {fail: [], warn: [], pass: []};
      (d.findings || []).forEach(f => (by[f.severity] || by.warn).push(f));
      GROUPS.forEach(g => {
        const list = by[g.key];
        if (!list.length) return;
        const items = list.map(f => item(f, g)).join('');
        html += g.key === 'pass'
          ? '<details style="margin-top:12px"' + (passOpen ? ' open' : '') + '><summary style="cursor:pointer;' +
            'font-size:13px;font-weight:600">' + g.title + ' (' + list.length + ')</summary>' + items + '</details>'
          : '<h4 style="margin:14px 0 4px;font-size:13px">' + g.title + ' (' + list.length + ')</h4>' + items;
      });

      if ((d.not_run || []).length) {
        html += '<p style="' + muted + ';margin-top:14px;overflow-wrap:anywhere">Never run from the dashboard, ' +
          'because they start work: ' + d.not_run.map(n => '<code>' + h.esc(n.command) + '</code> ' +
            h.esc(n.why)).join('; ') + '. Run them on the hub host.</p>';
      }
      html += '<div id="hubCASection" style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">' +
        (caShown ? caHTML(caShown) : '<p style="' + muted + '">Reading the hub CA…</p>') + '</div>';
      el.innerHTML = html;
      wire();
      wireCA();
      loadCA();
      const status = document.getElementById('hubHealthStatus');
      if (status) {
        status.className = 'badge ' + (c.fail ? 'failed' : c.warn ? 'paused' : 'complete');
        status.textContent = c.fail ? c.fail + ' failing' : 'no failures';
      }
    }

    // item draws one finding: what was checked, what was seen, what to do
    // about it, its details and its documentation.
    function item(f, g) {
      const details = Object.entries(f.details || {}).map(([k, v]) =>
        '<div><span style="color:var(--muted)">' + h.esc(k) + ':</span> ' + h.esc(detail(v)) + '</div>').join('');
      return '<div class="hh-finding" style="border:1px solid var(--border);border-radius:6px;padding:8px 10px;' +
        'margin:6px 0;overflow-wrap:anywhere;font-size:13px">' +
        '<div style="display:flex;gap:6px;align-items:baseline;flex-wrap:wrap"><span aria-hidden="true">' + g.sym +
        '</span><strong>' + h.esc(f.title) + '</strong><code style="' + muted + '">' + h.esc(f.check) + '</code>' +
        (Date.parse(f.as_of) ? '<span style="' + muted + '">as of ' + h.esc(new Date(f.as_of).toLocaleTimeString()) +
          '</span>' : '') + '</div>' +
        '<div style="margin-top:4px">' + h.esc(f.message) + '</div>' +
        (f.remediation ? '<div style="margin-top:4px"><span aria-hidden="true">→</span> ' + h.esc(f.remediation) +
          '</div>' : '') +
        (details ? '<div style="' + muted + ';margin-top:4px">' + details + '</div>' : '') +
        (DOCS.test(f.docs || '') ? '<div style="margin-top:4px;font-size:12px"><a href="' + h.esc(f.docs) +
          '" target="_blank" rel="noopener noreferrer" aria-label="' + h.esc('How ' + f.check + ' is checked and fixed') +
          '">How this is checked and fixed</a></div>' : '') +
        '</div>';
    }

    // ── The hub's certificate authority (Task 20438) ───────────────────────
    let caShown = null, caPending = null;

    function loadCA() {
      if (caPending) return caPending;
      const p = caPending = h.api('/api/hub/ca').then(d => {
        if (!d || d.error) throw new Error((d && d.error) || 'no answer');
        caShown = d;
        drawCA();
      }).catch(e => {
        const box = document.getElementById('hubCASection');
        if (box) box.innerHTML = '<p role="alert" style="font-size:13px;color:var(--red)">The hub CA could not be read: ' +
          h.esc((e && e.message) || e) + '</p>';
      }).finally(() => { if (caPending === p) caPending = null; });
      return p;
    }

    function drawCA() {
      const box = document.getElementById('hubCASection');
      if (box && caShown) box.innerHTML = caHTML(caShown);
    }

    const PHASE = {none: ['complete', 'no CA'], steady: ['complete', 'steady'], staged: ['paused', 'staged'],
      activated: ['paused', 'activated']};
    const short = s => h.esc(String(s || '').slice(0, 12));
    const day = t => { const d = Date.parse(t); return d ? h.esc(new Date(d).toISOString().slice(0, 10)) : ''; };

    function caHTML(d) {
      const [badge, label] = PHASE[d.phase] || ['paused', d.phase];
      let out = '<h4 style="margin:0 0 6px;font-size:13px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
        'Certificate authority <span class="badge ' + badge + '">' + h.esc(label) + '</span></h4>' +
        '<p style="' + muted + ';margin-bottom:8px">The CA the git proxy’s and Kubernetes monitor’s certificates ' +
        'come from under <code>tls: auto</code>. Replacing it is staged: every sandbox dispatched after the stage ' +
        'trusts both CAs, the activation waits for the runs dispatched before, and the retirement destroys the old ' +
        'key. <code>cloop hub ca rotate</code> takes the same steps.</p>';
      const cas = [d.active, d.next, d.previous].filter(Boolean);
      cas.forEach(c => {
        out += '<div style="font-size:12px;margin:2px 0;overflow-wrap:anywhere"><strong>' + h.esc(c.slot) +
          '</strong> <code>' + short(c.serial) + '</code> until ' + day(c.not_after) +
          (c.names && c.names.length ? ' · permits ' + h.esc(c.names.join(', ')) : ' · no name constraints') + '</div>';
      });
      const r = d.rotation;
      if (r) {
        out += '<div style="' + muted + ';margin-top:4px;overflow-wrap:anywhere">Rotation <code>' + h.esc(r.ID) +
          '</code> staged ' + h.esc(h.relTime(new Date(r.StagedAt))) + (r.StagedBy ? ' by ' + h.esc(r.StagedBy) : '') +
          (Date.parse(r.ActivatedAt) > 0 ? ', activated ' + h.esc(h.relTime(new Date(r.ActivatedAt))) : '') +
          (d.longest_session_minutes ? ' — the longest monitor session is ' + h.esc(d.longest_session_minutes) + ' min' : '') +
          '</div>';
      }
      const behind = (d.members || []).filter(m => !m.caught_up);
      if (behind.length) {
        out += '<div style="margin-top:6px;font-size:12px"><strong>Members not caught up</strong>' +
          behind.map(m => '<div style="overflow-wrap:anywhere"><code>' + h.esc(m.id) + '</code>: ' +
            h.esc(m.behind) + '</div>').join('') + '</div>';
      }
      const blocking = d.blocking || [];
      if (blocking.length) {
        out += '<div style="margin-top:6px;font-size:12px"><strong>' + h.esc(blocking.length) + ' run(s) the next ' +
          'step would break</strong>' + blocking.slice(0, 20).map(b => '<div style="overflow-wrap:anywhere">' +
            h.esc(runLabel(b)) + '</div>').join('') + (blocking.length > 20 ? '<div>…</div>' : '') + '</div>';
      }
      out += '<p style="font-size:13px;margin:8px 0;overflow-wrap:anywhere">' + h.esc(d.next_step) + '</p>';
      out += caActions(d);
      return out;
    }

    function runLabel(b) {
      return 'run ' + (b.run_id || b.session_id) + (b.project ? ' of ' + b.project : '') +
        (b.task_id ? ' (task ' + b.task_id + ')' : '') + (b.executor_id ? ' on ' + b.executor_id : '');
    }

    function caButton(act, text, danger) {
      return '<button class="btn' + (danger ? ' danger' : '') + '" data-hubca="' + act +
        '" style="font-size:12px;padding:4px 10px">' + text + '</button>';
    }

    function caActions(d) {
      const row = inner => '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:6px">' + inner + '</div>';
      switch (d.phase) {
        case 'steady':
          return row('<input class="form-input" id="hubCANames" placeholder="Also permit (comma-separated)" ' +
              'aria-label="Names the new CA also permits" style="font-size:12px;min-width:0;flex:1 1 180px">' +
              '<label style="font-size:12px;display:flex;gap:4px;align-items:center"><input type="checkbox" ' +
              'id="hubCANoConstraints"> without name constraints</label>') +
            row(caButton('stage', 'Stage a new CA') + caButton('now', 'Emergency: replace now…', true));
        case 'staged':
          return row((d.ready ? caButton('activate', 'Activate') :
              ((d.blocking || []).length ? caButton('force', 'Activate anyway…', true) : '')) +
            caButton('abort', 'Abort the stage…', true));
        case 'activated':
          return row((d.ready ? caButton('retire', 'Retire the previous CA…', true) : '') +
            caButton('now', 'Emergency: replace now…', true));
      }
      return '';
    }

    // wireCA routes the section's buttons: the Settings tab routes data-act to
    // the Settings panel's own functions, so this section uses its own.
    function wireCA() {
      const box = document.getElementById('hubCASection');
      if (!box) return;
      box.addEventListener('click', e => {
        const b = e.target.closest && e.target.closest('[data-hubca]');
        if (b) caStep(b, b.dataset.hubca);
      });
    }

    function caStep(btn, act) {
      const d = caShown || {};
      const serial = c => (c && c.serial ? c.serial.slice(0, 12) : '');
      let body;
      switch (act) {
        case 'stage': {
          const names = ((document.getElementById('hubCANames') || {}).value || '').split(',').map(x => x.trim()).filter(Boolean);
          const free = !!(document.getElementById('hubCANoConstraints') || {}).checked;
          body = {step: 'stage', names, no_name_constraints: free};
          break;
        }
        case 'activate':
          body = {step: 'activate'};
          break;
        case 'force': {
          const runs = (d.blocking || []).slice(0, 10).map(runLabel).join('\n');
          if (!window.confirm('Activate now? ' + (d.blocking || []).length + ' run(s) dispatched before the stage trust ' +
            'only the old CA, and stop verifying the git proxy and the Kubernetes monitor:\n\n' + runs)) return;
          body = {step: 'activate', force: true, confirm: 'activate'};
          break;
        }
        case 'retire':
          if (!window.confirm('Retire hub CA ' + serial(d.previous) + '? It leaves every bundle and its sealed key is ' +
            'destroyed; only a backup taken before now still holds it.')) return;
          body = {step: 'retire_previous', confirm: 'retire_previous'};
          break;
        case 'abort':
          if (!window.confirm('Destroy the staged CA ' + serial(d.next) + '? Sandboxes dispatched while it was staged ' +
            'trust the active CA too.')) return;
          body = {step: 'abort', confirm: 'abort'};
          break;
        case 'now':
          if (!window.confirm('Replace every hub CA now? A fresh CA is minted and activated at once, the monitors’ ' +
            'certificates are reissued and the old CA is retired. Every run that trusted only the old CA loses its ' +
            'git proxy, Kubernetes and model relay sessions, and has to be restarted.')) return;
          body = {step: 'now', confirm: 'now'};
          break;
        default:
          return;
      }
      btn.disabled = true;
      h.apiMethod('POST', '/api/hub/ca/rotate', body).then(res => {
        if (!res || res.error) throw new Error((res && res.error) || 'no answer');
        h.toast({stage: 'New CA staged', activate: 'CA activated', force: 'CA activated', retire: 'Previous CA retired',
          abort: 'Staged CA destroyed', now: 'Every hub CA replaced'}[act] || 'Done', 'ok');
        if (res.status) { caShown = res.status; drawCA(); } else loadCA();
      }).catch(e => {
        btn.disabled = false;
        h.toast('The hub CA step was refused: ' + ((e && e.message) || e), 'err');
        loadCA();
      });
    }

    function detail(v) {
      if (Array.isArray(v)) return v.map(detail).join(', ');
      if (v && typeof v === 'object') return JSON.stringify(v);
      return String(v);
    }

    // reveal is what the header's indicator does: Settings is on its way to
    // the screen, so wait for its markup, read the report and bring the
    // section into view. Not with scrollIntoView: the header is sticky and
    // stays over the top of the page, so the section has to land below it,
    // or its heading and the member line are under the tabs.
    function reveal() {
      return h.panel('settings').then(() => load()).then(() => {
        const s = document.getElementById('hubHealthSection');
        if (!s || !s.getBoundingClientRect) return;
        const head = document.querySelector('header');
        const pos = head ? getComputedStyle(head).position : '';
        const cover = pos === 'sticky' || pos === 'fixed' ? Math.max(0, head.getBoundingClientRect().bottom) : 0;
        window.scrollTo(0, Math.max(0, (window.scrollY || 0) + s.getBoundingClientRect().top - cover - 8));
      });
    }

    // refresh re-reads the report while Settings is on screen, when the
    // indicator did: the first time, it is what draws the section that
    // Settings left empty because /api/me had not answered yet.
    function refresh() {
      return load();
    }

    return h.mount({load, reveal, refresh}, null);
  };
})();
