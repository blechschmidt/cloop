// ── What a run's firewall refused (Task 20437) ──────────────────────────────
//
// Two views of the refusals a sandbox's firewall logged, both fetched only
// when there is something to show (static.go, deferredScripts):
//
//   task(id) fills the task details' Network section (#td-net, drawn empty by
//   12-task-crud.js): each destination the task's runs were refused, how often
//   and why, and the egress proxy's refusals beside them — or why nothing could
//   be recorded on its executor.
//
//   card(view) fills the project firewall card's recently blocked list
//   (#pfwBlocked, drawn empty by 23-firewall.js) from the card's own answer,
//   with a Propose allow rule button for admins: one click proposes the
//   project's rule set with that destination added, and saves it through the
//   same PUT the card's form uses — every containment check included, so a
//   destination the device does not reach is refused with the reason.
(function () {
  'use strict';

  window.cloopNetworkPanel = function (h) {
    let shownTask = null;
    let view = null;
    let rows = [];

    const when = t => (t ? h.relTime(new Date(t)) : '');
    const dest = r => (r.port ? (r.dst.indexOf(':') >= 0 ? '[' + r.dst + ']' : r.dst) + ':' + r.port : r.dst) + '/' + r.proto;
    const item = (r, extra) => '<li><code>' + h.esc(dest(r)) + '</code>' + (r.count > 1 ? ' ×' + r.count : '') +
      (r.why ? ' — ' + h.esc(r.why) : '') + ' <span class="td-trunc-note">' + h.esc(when(r.last_seen)) + '</span>' +
      (extra || '') + '</li>';

    // task draws a task's Network section.
    function task(id) {
      shownTask = id;
      const sec = document.getElementById('td-net');
      if (!sec) return;
      sec.innerHTML = '<h3>Network</h3><div class="td-empty">Loading…</div>';
      return h.api(h.pUrl('/api/tasks/' + id + '/network')).then(d => {
        if (shownTask !== id) return;
        let html = '<h3>Network</h3>';
        if (!d || d.error) {
          sec.innerHTML = html + '<div class="td-empty">' + h.esc((d && d.error) || 'Could not load what was refused') + '</div>';
          return;
        }
        const denied = d.denials || [], egress = d.egress || [];
        if (d.note) html += '<div class="td-text">' + h.esc(d.note) + '</div>';
        if (denied.length) {
          html += '<div class="td-text">Refused by the sandbox’s firewall:</div><ul>' + denied.map(r => item(r)).join('') + '</ul>';
        }
        if (d.unitemised) {
          html += '<div class="td-trunc-note">and ' + d.unitemised + ' more refused, counted but not itemised</div>';
        }
        if (egress.length) {
          html += '<div class="td-text">Refused by the egress proxy:</div><ul>' + egress.map(e => '<li><code>' +
            h.esc(e.host + (e.port ? ':' + e.port : '')) + '</code> — ' + h.esc(e.reason || 'refused') +
            ' <span class="td-trunc-note">' + h.esc(when(e.at)) + '</span></li>').join('') + '</ul>';
        }
        if (!d.note && !denied.length && !egress.length && !d.unitemised) {
          html += '<div class="td-empty">Nothing was refused.</div>';
        }
        sec.innerHTML = html;
      }, () => {});
    }

    // card draws the firewall card's recently blocked list. v is the card's
    // own answer from /api/firewall, which a proposal starts from.
    function card(v) {
      view = v;
      const box = document.getElementById('pfwBlocked');
      if (!box) return;
      const idx = v && v.project;
      return h.api(h.pUrl('/api/firewall/blocked')).then(d => {
        if (!view || view.project !== idx || !d || d.error || !d.visible) return;
        rows = d.blocked || [];
        let html = '<div class="form-label">Recently blocked</div>';
        if (d.note) html += '<div class="form-hint">' + h.esc(d.note) + '</div>';
        if (rows.length) {
          html += '<ul class="form-hint">' + rows.map((r, i) => item(r, d.can_propose && r.proposable
            ? ' <button class="btn" data-net="propose" data-arg="' + i + '">Propose allow rule</button>' : '')).join('') + '</ul>';
        } else if (!d.note) {
          html += '<div class="form-hint">Nothing was refused in the last week.</div>';
        }
        box.innerHTML = html + '<div id="pfwBlockedNote"></div>';
        box.onclick = e => {
          const b = e.target && e.target.closest ? e.target.closest('button[data-net]') : null;
          if (b && b.dataset.net === 'propose') propose(+b.dataset.arg);
        };
      }, () => {});
    }

    // propose saves the project's rule set with one blocked destination
    // allowed: its own rules if it has some, else the ones governing it, plus
    // the address and — when the rule set names ports — its port.
    function propose(i) {
      const r = rows[i];
      if (!r || !view) return;
      const base = (view.configured ? view.rules : view.governing) || {};
      const cidr = r.dst + (r.dst.indexOf(':') >= 0 ? '/128' : '/32');
      const ports = (base.allow_ports || []).slice();
      const addPort = ports.length && ports.indexOf(r.port) < 0;
      if (addPort) ports.push(r.port);
      const next = {
        allow_public_internet: !!base.allow_public_internet,
        allow_cidrs: (base.allow_cidrs || []).concat([cidr]),
        deny_cidrs: base.deny_cidrs || [],
        allow_ports: ports,
        resolvers: base.resolvers || [],
        drop_denied: !!base.drop_denied,
      };
      const msg = 'Allow TCP to ' + cidr + ' for this project’s runs' +
        (addPort ? ', and add port ' + r.port + ' to the ports its rules open (' + base.allow_ports.join(', ') + ')' : '') +
        '?\n\nThe project’s firewall is saved with it and checked against the rules that govern it, like any save.';
      if (!confirm(msg)) return;
      const note = document.getElementById('pfwBlockedNote');
      h.apiMethod('PUT', h.pUrl('/api/firewall'), next).then(d => {
        if (!d || d.error) {
          if (note) note.innerHTML = h.fw.refusal(d);
          return;
        }
        h.toast('Allowed ' + cidr + ' for this project', 'ok');
        if (window.loadProjectFirewall) window.loadProjectFirewall();
      }, () => {});
    }

    // Mounted with no markup of its own: it draws into the sections the
    // bundle renders, and mountPanel hands back the functions panelAct calls.
    return h.mount({task, card, propose});
  };
})();
