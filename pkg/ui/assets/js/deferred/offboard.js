// ── Offboarding: sever every credential one identity holds (Task 20261) ─────
//
// Renders into the Secrets tab beside the sessions table, because that is
// where an operator already goes to answer "what can this person still do".
//
// Two-step by construction, and the first step is not optional. The preview is
// a real dry run against the server — the same resolution the write performs —
// rather than a client-side guess, so what the confirmation names is exactly
// what the write will act on. Nothing is severed until the operator has seen
// the blast radius and typed a reason.
//
// Plain paths rather than pUrl(): an identity is a control-plane object, so a
// ?project_idx would imply a per-project scope the backend does not have.
//
// Fetched on demand since Task 20379 (static.go, deferredScripts): an
// admin-only form most sessions never open has no claim on first paint. It
// runs outside the dashboard's IIFE, so offboardPreview in the Secrets panel
// (deferred/secrets.js since Task 20386) hands over the helpers it calls, and
// the only name it puts on window is the factory.
(function () {
  'use strict';

  window.cloopOffboardPanel = function (h) {
    const offbState = {plan: null, identity: ''};

    // _offbRun posts to the one route. dryRun chooses preview or write; both go
    // through the same gate, because enumerating somebody's credential footprint
    // is the read a stolen operator cookie would want.
    function _offbRun(identity, reason, dryRun) {
      return h.apiMethod('POST', '/api/users/offboard',
        {identity: identity, reason: reason || '', dry_run: !!dryRun});
    }

    function offboardPreview() {
      const input = document.getElementById('offboardIdentity');
      const identity = ((input && input.value) || '').trim();
      if (!identity) { h.toast('Enter an email address or IdP subject', 'err'); return; }

      const box = document.getElementById('offboardResult');
      if (box) { box.style.display = ''; box.innerHTML = '<p class="sec-hint">Resolving&hellip;</p>'; }

      _offbRun(identity, '', true).then(rep => {
        offbState.plan = rep;
        offbState.identity = identity;
        _offbRenderPreview(rep);
      }).catch(err => {
        offbState.plan = null;
        if (box) {
          box.innerHTML = '<div class="sec-banner">' +
            h.esc('Preview failed: ' + ((err && err.message) || String(err))) + '</div>';
        }
      });
    }

    // _offbRenderPreview shows what the write would touch. Every surface is listed
    // even when it is empty, so "0 API tokens" is visibly a finding rather than a
    // row that was left out — and the warnings are rendered prominently, because
    // the one that matters says a token could not be attributed to anybody.
    function _offbRenderPreview(rep) {
      const box = document.getElementById('offboardResult');
      if (!box) return;
      const t = (rep && rep.target) || {};
      const n = k => ((rep && rep[k]) || []).length;

      const rows = [
        ['Sessions',      n('sessions'), 'ended'],
        ['API tokens',    n('tokens'),   'revoked'],
        ['Glasses links', n('glasses'),  'revoked'],
        ['Deny bindings', n('denies'),   'written'],
        ['Secret leases', n('leases'),   'released'],
        ['Running tasks', n('tasks'),    'stopped'],
        ['Project memberships', n('memberships'), 'removed'],
      ].map(r =>
        '<tr><td>' + h.esc(r[0]) + '</td><td style="text-align:right"><strong>' + r[1] +
        '</strong></td><td class="sec-count">' + h.esc(r[2]) + '</td></tr>').join('');

      const ids = []
        .concat((t.emails || []))
        .concat((t.subjects || []).map(s => 'sub:' + s));

      let html =
        '<div class="sec-subtitle" style="margin-top:4px">Blast radius &mdash; nothing changed yet</div>' +
        '<p class="sec-hint">Resolved to ' + h.esc(ids.join(', ') || '(nothing on this hub)') + '</p>' +
        '<table class="audit-table"><tbody>' + rows + '</tbody></table>';

      const projects = (rep && rep.projects) || [];
      if (projects.length) {
        html += '<p class="sec-hint" style="margin-top:10px"><strong>' + projects.length +
          ' project' + (projects.length === 1 ? '' : 's') + ' owned by this identity will NOT be deleted' +
          '</strong> &mdash; reassign them: ' +
          projects.map(p => '<code>' + h.esc(p.name || p.path) + '</code>').join(', ') + '</p>';
      }
      ((rep && rep.warnings) || []).forEach(w => {
        html += '<div class="sec-banner" style="margin-top:8px">' + h.esc(w) + '</div>';
      });

      html += '<div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">' +
        '<button class="btn danger" id="offboardConfirmBtn" data-global-perm="user.manage">' +
          'Offboard ' + h.esc(t.key || offbState.identity) + '</button>' +
        '<button class="btn" id="offboardCancelBtn">Cancel</button></div>';

      box.innerHTML = html;
      const confirmBtn = document.getElementById('offboardConfirmBtn');
      if (confirmBtn) confirmBtn.addEventListener('click', offboardConfirm);
      const cancelBtn = document.getElementById('offboardCancelBtn');
      if (cancelBtn) cancelBtn.addEventListener('click', () => {
        offbState.plan = null;
        box.style.display = 'none';
        box.innerHTML = '';
      });
      h.gate();
    }

    function offboardConfirm() {
      if (!offbState.plan) { h.toast('Preview first', 'err'); return; }
      const who = (offbState.plan.target && offbState.plan.target.key) || offbState.identity;

      // The reason is required by the server too. Asking here keeps the operator
      // from discovering that after clicking a destructive button.
      const reason = prompt(
        'Offboarding ' + who + '.\n\n' +
        'Why? This is recorded on every audit event and read back during review ' +
        '(e.g. "left the company, HR-882").');
      if (reason === null) return;
      if (reason.trim().length < 4) { h.toast('A reason is required', 'err'); return; }

      if (!confirm(
          'Sever every credential ' + who + ' holds?\n\n' +
          'Their sessions, API tokens and glasses links stop working immediately, ' +
          'their running tasks are stopped, and a deny binding blocks a fresh sign-in.\n\n' +
          'Projects they own are kept and reported for reassignment.')) return;

      _offbRun(offbState.identity, reason, false).then(rep => {
        _offbRenderResult(rep);
        h.sessions();
      }).catch(err => h.toast('Offboard failed: ' + ((err && err.message) || String(err)), 'err'));
    }

    // _offbRenderResult reports what was actually severed, and any surface that
    // was not. A partial run comes back 200 with failures attached — the report
    // names what *did* happen, which an error body would not carry — so the
    // failures have to be shown rather than inferred from the absence of a toast.
    function _offbRenderResult(rep) {
      const box = document.getElementById('offboardResult');
      offbState.plan = null;
      const n = k => ((rep && rep[k]) || []).length;
      const failures = (rep && rep.failures) || [];

      const rows = [
        ['Sessions ended',      n('sessions_revoked')],
        ['API tokens revoked',  n('tokens_revoked')],
        ['Glasses links revoked', n('glasses_revoked')],
        ['Deny bindings written', n('denies_written')],
        ['Secret leases released', n('leases_released')],
        ['Running tasks stopped', n('tasks_stopped')],
        ['Project memberships removed', n('memberships_revoked')],
      ].map(r => '<tr><td>' + h.esc(r[0]) + '</td><td style="text-align:right"><strong>' +
        r[1] + '</strong></td></tr>').join('');

      let html = '<div class="sec-subtitle" style="margin-top:4px">' +
        (failures.length ? 'Offboarded with failures' : 'Offboarded') + '</div>' +
        '<table class="audit-table"><tbody>' + rows + '</tbody></table>';

      failures.forEach(f => {
        html += '<div class="sec-banner" style="margin-top:8px">' +
          h.esc('[' + (f.surface || '?') + '] ' + (f.detail || '')) + '</div>';
      });
      const projects = (rep && rep.projects) || [];
      if (projects.length) {
        html += '<p class="sec-hint" style="margin-top:10px"><strong>Reassign ' +
          projects.length + ' project' + (projects.length === 1 ? '' : 's') + ':</strong> ' +
          projects.map(p => '<code>' + h.esc(p.name || p.path) + '</code>').join(', ') + '</p>';
      }
      if (box) { box.style.display = ''; box.innerHTML = html; }

      h.toast(failures.length
        ? 'Offboarded, but ' + failures.length + ' surface(s) failed'
        : 'Offboarded', failures.length ? 'err' : 'ok');
    }

    return {preview: offboardPreview};
  };
})();
