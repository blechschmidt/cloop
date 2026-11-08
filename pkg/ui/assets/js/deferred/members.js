// ── Members card (Tasks 20366, 20478) ────────────────────────────────────────
//
// Who may reach this project, at which role: its owner, who created it and is
// its administrator, and the people and teams it is shared with. Fetched on
// demand rather than bundled: most sessions never share a project, and the
// first paint has no room for a panel they do not use (static.go,
// deferredScripts). It therefore runs outside the dashboard's IIFE and sees
// none of its helpers; loadProjectMembers in 01-overview.js hands over the
// few it needs, and the only name this file puts on window is the factory.
//
// The server decides everything that depends on who is asking — can_share,
// grantable_roles, the teams on offer, and per row self and manageable — so
// the card never offers a control the hub would refuse. Roles on offer are the
// caller's own and below: a maintainer cannot mint an admin and act through
// them.
(function () {
  'use strict';

  window.cloopMembersPanel = function (h) {
    let inflight = null;
    let inflightIdx = null;
    let shownIdx = null;

    function el(id) { return document.getElementById(id); }

    // What each role lets somebody do, said once for the select and the rows.
    const ROLE_HINT = {
      viewer: 'view the project',
      operator: 'also run it and change its tasks',
      maintainer: 'also reshape it and share it',
      admin: 'everything, sharing as admin included',
    };

    // The card's markup, built once and placed after the Features section.
    function section() {
      let sec = el('membersSection');
      if (sec) return sec;
      sec = document.createElement('div');
      sec.className = 'section';
      sec.id = 'membersSection';
      sec.style.display = 'none';
      sec.innerHTML =
        '<div class="section-title" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">Members' +
          '<span id="membersVisibility" class="feat-opt" style="font-weight:400"></span>' +
          '<span id="membersYourRole" style="font-size:11px;font-weight:400;color:var(--muted)"></span></div>' +
        '<div id="membersList"></div>' +
        '<form id="membersAddForm" style="display:none;flex-wrap:wrap;gap:8px;align-items:center;margin-top:4px">' +
          '<select class="form-input form-select" id="memberKind" aria-label="Share with" style="flex:0 1 110px">' +
            '<option value="person">A person</option><option value="team">A team</option></select>' +
          '<input class="form-input" id="memberIdentity" type="text" autocomplete="off" spellcheck="false" ' +
            'placeholder="Email, or sub:&lt;subject&gt;" aria-label="Identity to add" style="flex:2 1 200px;min-width:0">' +
          '<select class="form-input form-select" id="memberTeam" aria-label="Team" style="display:none;flex:2 1 200px;min-width:0"></select>' +
          '<select class="form-input form-select" id="memberRole" aria-label="Role" style="flex:0 1 130px"></select>' +
          '<input class="form-input" id="memberReason" type="text" maxlength="500" placeholder="Reason (optional)" ' +
            'aria-label="Reason" style="flex:2 1 180px;min-width:0">' +
          '<button class="btn primary" id="memberAddBtn" type="submit" style="padding:6px 14px">Share</button>' +
        '</form>' +
        '<div id="membersNote" class="form-hint" style="margin-top:8px"></div>';
      const anchor = el('featuresSection');
      const panel = el('projectPanel');
      if (anchor && anchor.parentNode) anchor.parentNode.insertBefore(sec, anchor.nextSibling);
      else if (panel) panel.appendChild(sec);
      else return null;

      sec.querySelector('#membersAddForm').addEventListener('submit', function (ev) {
        ev.preventDefault();
        add();
      });
      sec.querySelector('#memberKind').addEventListener('change', kindChanged);
      sec.querySelector('#membersList').addEventListener('click', function (ev) {
        const btn = ev.target && ev.target.closest ? ev.target.closest('button[data-act]') : null;
        if (!btn) return;
        if (btn.dataset.act === 'remove') remove(btn.dataset.identity, btn.dataset.label);
        if (btn.dataset.act === 'leave') leave();
      });
      sec.querySelector('#membersList').addEventListener('change', function (ev) {
        const sel = ev.target;
        if (sel && sel.dataset && sel.dataset.act === 'role') change(sel.dataset.identity, sel.value, sel, sel.dataset.label);
      });
      return sec;
    }

    // A person is named by email; a team is picked from the hub's teams.
    function kindChanged() {
      const team = el('memberKind').value === 'team';
      el('memberIdentity').style.display = team ? 'none' : '';
      el('memberTeam').style.display = team ? '' : 'none';
    }

    function base() { return '/api/projects/' + h.idx() + '/members'; }

    function fail(what, err) {
      // A refusal (403) or a lapsed session (401) has already been reported
      // in the hub's own words; repeating its code would replace them.
      if (err && /^(FORBIDDEN|401)$/.test(err.message)) return;
      h.toast((err && err.message ? err.message : 'Could not ' + what), 'error');
    }

    function row(identity, label, roleHTML, meta, actions) {
      return '<div class="feat-row" data-member="' + h.esc(identity) + '">' +
        '<div class="feat-main" style="cursor:default">' +
          '<span style="font-weight:600;word-break:break-all">' + h.esc(label) + '</span>' + roleHTML +
          (meta ? '<span class="feat-branch">' + h.esc(meta) + '</span>' : '') +
        '</div>' +
        (actions ? '<div class="feat-actions">' + actions + '</div>' : '') +
      '</div>';
    }

    function chip(text, title) {
      return '<span class="feat-opt"' + (title ? ' title="' + h.esc(title) + '"' : '') + '>' + h.esc(text) + '</span>';
    }

    // How a team row describes who is on the team.
    function teamMeta(t) {
      if (!t) return '';
      if (t.builtin) return 'every signed-in identity';
      const parts = [t.members === 1 ? '1 person by name' : t.members + ' people by name'];
      if (t.idp_group) parts.push('everyone in group ' + t.idp_group);
      if (t.scim_group) parts.push('everyone in provisioned group ' + t.scim_group);
      return parts.join(' + ');
    }

    function teamLabel(t, slug) {
      if (!t) return 'Team ' + slug;
      return t.builtin ? t.name : 'Team ' + t.name + (t.name !== t.slug ? ' (' + t.slug + ')' : '');
    }

    const VISIBILITY = {
      private: ['private', 'Only its owner, the hub’s administrators and the people and teams below can see it'],
      everyone: ['everyone', 'Every signed-in user of this hub can see it'],
      policy: ['role policy', 'Nobody owns it: the hub’s role mappings decide who can see it'],
    };

    function render(d) {
      const sec = section();
      if (!sec) return;
      sec.style.display = '';
      const you = el('membersYourRole');
      if (you) you.textContent = d.your_role && d.your_role !== 'none' ? 'your role: ' + d.your_role : '';
      const vis = el('membersVisibility');
      const v = VISIBILITY[d.visibility];
      if (vis) {
        vis.style.display = v && d.available ? '' : 'none';
        vis.textContent = v ? v[0] : '';
        vis.title = v ? v[1] : '';
      }

      const members = Array.isArray(d.members) ? d.members : [];
      const roles = Array.isArray(d.grantable_roles) ? d.grantable_roles : [];
      const rows = [];
      if (d.owner) {
        rows.push(row(d.owner, d.owner, chip('owner', 'Created this project'),
          'created this project · ' + (d.owner_role || 'admin'), ''));
      }
      members.forEach(function (m) {
        const isTeam = m.kind === 'team';
        const label = isTeam ? teamLabel(m.team, m.identity.replace(/^team:/, '')) : m.identity;
        const meta = [];
        if (isTeam) meta.push(teamMeta(m.team));
        if (m.granted_by) meta.push('added by ' + m.granted_by);
        if (m.reason) meta.push(m.reason);
        let role = chip(m.role, ROLE_HINT[m.role]);
        let actions = '';
        if (m.manageable && roles.indexOf(m.role) !== -1) {
          role = '<select class="form-input form-select" data-act="role" data-identity="' + h.esc(m.identity) +
            '" data-label="' + h.esc(label) + '" aria-label="Role of ' + h.esc(label) +
            '" style="width:auto;padding:2px 24px 2px 6px;font-size:12px">' +
            roles.map(function (r) {
              return '<option value="' + h.esc(r) + '"' + (r === m.role ? ' selected' : '') + '>' + h.esc(r) + '</option>';
            }).join('') + '</select>';
        }
        if (m.manageable) {
          actions = '<button class="btn" type="button" data-act="remove" data-identity="' + h.esc(m.identity) +
            '" data-label="' + h.esc(label) + '" title="Stop sharing with ' + h.esc(label) + '">Remove</button>';
        } else if (m.self && !d.inherited_from) {
          actions = '<button class="btn" type="button" data-act="leave" title="Give up your access to this project">Leave</button>';
        }
        rows.push(row(m.identity, label, role, meta.join(' · '), actions));
      });
      if (!members.length) {
        rows.push('<div class="feat-note" style="font-size:12px;color:var(--muted);margin-bottom:8px">' +
          (d.owner ? 'Not shared with anyone yet: only its owner and the hub’s administrators can see it.'
                   : 'Not shared with anyone by name.') + '</div>');
      }
      el('membersList').innerHTML = rows.join('');

      const form = el('membersAddForm');
      const canAdd = !!d.can_share && !!d.available && roles.length > 0;
      form.style.display = canAdd ? 'flex' : 'none';
      if (canAdd) {
        const sel = el('memberRole');
        const keep = sel.value;
        sel.innerHTML = roles.map(function (r) {
          return '<option value="' + h.esc(r) + '" title="' + h.esc(ROLE_HINT[r] || '') + '">' + h.esc(r) + '</option>';
        }).join('');
        // Least privilege first: sharing starts at the weakest role on offer.
        sel.value = roles.indexOf(keep) !== -1 ? keep : roles[0];
        const teams = Array.isArray(d.teams) ? d.teams : [];
        const tsel = el('memberTeam');
        const keepTeam = tsel.value;
        tsel.innerHTML = teams.map(function (t) {
          return '<option value="' + h.esc(t.slug) + '">' + h.esc(teamLabel(t, t.slug)) + '</option>';
        }).join('');
        if (keepTeam) tsel.value = keepTeam;
        el('memberKind').querySelector('option[value="team"]').disabled = !teams.length;
        kindChanged();
      }
      let note = d.note || '';
      if (d.inherited_from) note = 'A feature is shared with its project, ' + d.inherited_from + '. Change its members there.';
      el('membersNote').textContent = note;
      el('membersNote').style.display = note ? '' : 'none';
    }

    function load() {
      const idx = h.idx();
      if (h.hidden()) {
        const sec = el('membersSection');
        if (sec) sec.style.display = 'none';
        shownIdx = null;
        return Promise.resolve(null);
      }
      if (inflight && inflightIdx === idx) return inflight;
      if (shownIdx !== idx) {
        // A roster belongs to one project: never leave the previous one on
        // screen while the next is fetched.
        const sec = el('membersSection');
        if (sec) sec.style.display = 'none';
      }
      inflightIdx = idx;
      const p = h.api(base()).then(function (d) {
        if (idx !== h.idx() || h.hidden()) return null;
        if (!d || d.error) {
          const sec = el('membersSection');
          if (sec) sec.style.display = 'none';
          return null;
        }
        render(d);
        shownIdx = idx;
        return d;
      }).catch(function () {
        const sec = el('membersSection');
        if (sec) sec.style.display = 'none';
        return null;
      });
      inflight = p;
      p.then(function () { if (inflight === p) inflight = null; });
      return p;
    }

    function done(r, ok, what) {
      if (r && r.error) { fail(what, {message: r.error}); return false; }
      h.toast(ok, 'success');
      return true;
    }

    function add() {
      const team = el('memberKind').value === 'team';
      const idEl = el('memberIdentity');
      const body = {role: el('memberRole').value, reason: el('memberReason').value};
      let label;
      if (team) {
        const tsel = el('memberTeam');
        if (!tsel.value) {
          h.toast('Pick a team to share with', 'error');
          return;
        }
        body.team = tsel.value;
        label = tsel.options[tsel.selectedIndex] ? tsel.options[tsel.selectedIndex].textContent : tsel.value;
      } else {
        const identity = (idEl.value || '').trim();
        if (!identity) {
          h.toast('Enter the email, or sub:<subject>, of the person to add', 'error');
          idEl.focus();
          return;
        }
        body.identity = identity;
        label = identity;
      }
      const btn = el('memberAddBtn');
      btn.disabled = true;
      h.api(base(), body)
        .then(function (m) {
          if (done(m, 'Shared with ' + label + (m && m.role ? ' as ' + m.role : ''), 'share the project')) {
            idEl.value = '';
            el('memberReason').value = '';
          }
          return load();
        })
        .catch(function (err) { fail('share the project', err); })
        .then(function () { btn.disabled = false; });
    }

    function change(identity, role, sel, label) {
      sel.disabled = true;
      h.apiMethod('PATCH', base() + '?identity=' + encodeURIComponent(identity), {role: role})
        .then(function (r) { done(r, (label || identity) + ' is now ' + role, 'change the role'); return load(); })
        .catch(function (err) { fail('change the role', err); return load(); });
    }

    function remove(identity, label) {
      if (!identity) return;
      const who = label || identity;
      if (!window.confirm('Stop sharing this project with ' + who + '? Access through this share ends at once, ' +
          'including any dashboard open on it.')) return;
      h.apiMethod('DELETE', base() + '?identity=' + encodeURIComponent(identity))
        .then(function (r) { done(r, 'Removed ' + who, 'remove the share'); return load(); })
        .catch(function (err) { fail('remove the share', err); });
    }

    function leave() {
      if (!window.confirm('Leave this project? It disappears from your dashboard, and a maintainer ' +
          'has to add you again.')) return;
      h.apiMethod('DELETE', base() + '/self')
        .then(function (r) { if (done(r, 'You have left the project', 'leave the project')) h.left(); })
        .catch(function (err) { fail('leave the project', err); });
    }

    return {load: load};
  };
})();
