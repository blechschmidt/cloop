// ── Members card (Task 20366) ────────────────────────────────────────────────
//
// Who besides its owner may reach this project, at which role. Fetched on
// demand rather than bundled: most sessions never share a project, and the
// first paint has no room for a panel they do not use (static.go,
// deferredScripts). It therefore runs outside the dashboard's IIFE and sees
// none of its helpers; loadProjectMembers in 01-overview.js hands over the
// few it needs, and the only name this file puts on window is the factory.
//
// The server decides everything that depends on who is asking — can_share,
// grantable_roles, and per row self and manageable — so the card never offers
// a control the hub would refuse. Roles on offer are the caller's own and
// below: a maintainer cannot mint an admin and act through them.
(function () {
  'use strict';

  window.cloopMembersPanel = function (h) {
    let inflight = null;
    let inflightIdx = null;
    let shownIdx = null;

    function el(id) { return document.getElementById(id); }

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
          '<span id="membersYourRole" style="font-size:11px;font-weight:400;color:var(--muted)"></span></div>' +
        '<div id="membersList"></div>' +
        '<form id="membersAddForm" style="display:none;flex-wrap:wrap;gap:8px;align-items:center;margin-top:4px">' +
          '<input class="form-input" id="memberIdentity" type="text" autocomplete="off" spellcheck="false" ' +
            'placeholder="Email, or sub:&lt;subject&gt;" aria-label="Identity to add" style="flex:2 1 200px;min-width:0">' +
          '<select class="form-input form-select" id="memberRole" aria-label="Role" style="flex:0 1 130px"></select>' +
          '<input class="form-input" id="memberReason" type="text" maxlength="500" placeholder="Reason (optional)" ' +
            'aria-label="Reason" style="flex:2 1 180px;min-width:0">' +
          '<button class="btn primary" id="memberAddBtn" type="submit" style="padding:6px 14px">Add member</button>' +
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
      sec.querySelector('#membersList').addEventListener('click', function (ev) {
        const btn = ev.target && ev.target.closest ? ev.target.closest('button[data-act]') : null;
        if (!btn) return;
        if (btn.dataset.act === 'remove') remove(btn.dataset.identity);
        if (btn.dataset.act === 'leave') leave();
      });
      sec.querySelector('#membersList').addEventListener('change', function (ev) {
        const sel = ev.target;
        if (sel && sel.dataset && sel.dataset.act === 'role') change(sel.dataset.identity, sel.value, sel);
      });
      return sec;
    }

    function base() { return '/api/projects/' + h.idx() + '/members'; }

    function fail(what, err) {
      // A refusal (403) or a lapsed session (401) has already been reported
      // in the hub's own words; repeating its code would replace them.
      if (err && /^(FORBIDDEN|401)$/.test(err.message)) return;
      h.toast((err && err.message ? err.message : 'Could not ' + what), 'error');
    }

    function row(identity, roleHTML, meta, actions) {
      return '<div class="feat-row" data-member="' + h.esc(identity) + '">' +
        '<div class="feat-main" style="cursor:default">' +
          '<span style="font-weight:600;word-break:break-all">' + h.esc(identity) + '</span>' + roleHTML +
          (meta ? '<span class="feat-branch">' + h.esc(meta) + '</span>' : '') +
        '</div>' +
        (actions ? '<div class="feat-actions">' + actions + '</div>' : '') +
      '</div>';
    }

    function chip(text) { return '<span class="feat-opt">' + h.esc(text) + '</span>'; }

    function render(d) {
      const sec = section();
      if (!sec) return;
      sec.style.display = '';
      const you = el('membersYourRole');
      if (you) you.textContent = d.your_role && d.your_role !== 'none' ? 'your role: ' + d.your_role : '';

      const members = Array.isArray(d.members) ? d.members : [];
      const roles = Array.isArray(d.grantable_roles) ? d.grantable_roles : [];
      const rows = [];
      if (d.owner) rows.push(row(d.owner, chip('owner'), 'created this project', ''));
      members.forEach(function (m) {
        const meta = [];
        if (m.granted_by) meta.push('added by ' + m.granted_by);
        if (m.reason) meta.push(m.reason);
        let role = chip(m.role);
        let actions = '';
        if (m.manageable && roles.indexOf(m.role) !== -1) {
          role = '<select class="form-input form-select" data-act="role" data-identity="' + h.esc(m.identity) +
            '" aria-label="Role of ' + h.esc(m.identity) + '" style="width:auto;padding:2px 6px;font-size:12px">' +
            roles.map(function (r) {
              return '<option value="' + h.esc(r) + '"' + (r === m.role ? ' selected' : '') + '>' + h.esc(r) + '</option>';
            }).join('') + '</select>';
        }
        if (m.manageable) {
          actions = '<button class="btn" type="button" data-act="remove" data-identity="' + h.esc(m.identity) +
            '" title="Remove this member">Remove</button>';
        } else if (m.self && !d.inherited_from) {
          actions = '<button class="btn" type="button" data-act="leave" title="Give up your access to this project">Leave</button>';
        }
        rows.push(row(m.identity, role, meta.join(' · '), actions));
      });
      if (!members.length) {
        rows.push('<div class="feat-note" style="font-size:12px;color:var(--muted);margin-bottom:8px">' +
          (d.owner ? 'Not shared with anyone yet — only its owner and the hub’s admins can see it.'
                   : 'Not shared with anyone by name.') + '</div>');
      }
      el('membersList').innerHTML = rows.join('');

      const form = el('membersAddForm');
      const canAdd = !!d.can_share && !!d.available && roles.length > 0;
      form.style.display = canAdd ? 'flex' : 'none';
      if (canAdd) {
        const sel = el('memberRole');
        const keep = sel.value;
        sel.innerHTML = roles.map(function (r) { return '<option value="' + h.esc(r) + '">' + h.esc(r) + '</option>'; }).join('');
        // Least privilege first: sharing starts at the weakest role on offer.
        sel.value = roles.indexOf(keep) !== -1 ? keep : roles[0];
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
      const idEl = el('memberIdentity');
      const identity = (idEl.value || '').trim();
      if (!identity) {
        h.toast('Enter the email, or sub:<subject>, of the person to add', 'error');
        idEl.focus();
        return;
      }
      const btn = el('memberAddBtn');
      btn.disabled = true;
      h.api(base(), {identity: identity, role: el('memberRole').value, reason: el('memberReason').value})
        .then(function (m) {
          if (done(m, 'Added ' + identity + (m && m.role ? ' as ' + m.role : ''), 'add the member')) {
            idEl.value = '';
            el('memberReason').value = '';
          }
          return load();
        })
        .catch(function (err) { fail('add the member', err); })
        .then(function () { btn.disabled = false; });
    }

    function change(identity, role, sel) {
      sel.disabled = true;
      h.apiMethod('PATCH', base() + '?identity=' + encodeURIComponent(identity), {role: role})
        .then(function (r) { done(r, identity + ' is now ' + role, 'change the role'); return load(); })
        .catch(function (err) { fail('change the role', err); return load(); });
    }

    function remove(identity) {
      if (!identity) return;
      if (!window.confirm('Remove ' + identity + ' from this project? They lose access at once, ' +
          'including any dashboard they have open on it.')) return;
      h.apiMethod('DELETE', base() + '?identity=' + encodeURIComponent(identity))
        .then(function (r) { done(r, 'Removed ' + identity, 'remove the member'); return load(); })
        .catch(function (err) { fail('remove the member', err); });
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
