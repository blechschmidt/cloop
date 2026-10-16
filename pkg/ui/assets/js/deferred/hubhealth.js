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
      el.innerHTML = html;
      wire();
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

    function detail(v) {
      if (Array.isArray(v)) return v.map(detail).join(', ');
      if (v && typeof v === 'object') return JSON.stringify(v);
      return String(v);
    }

    // reveal is what the header's indicator does: Settings is on its way to
    // the screen, so wait for its markup, read the report and bring the
    // section into view.
    function reveal() {
      return h.panel('settings').then(() => load()).then(() => {
        const s = document.getElementById('hubHealthSection');
        if (s && s.scrollIntoView) s.scrollIntoView({block: 'start'});
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
