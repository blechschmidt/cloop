// ── Readers section (Task 20503) ─────────────────────────────────────────────
//
// A project's readers list on its Overview: the other projects whose runs get
// this project's files read-only, and below it the projects this one may read.
// Next to the Members card, because both say who reaches the project. Fetched
// on demand like that card: first paint has no room for a section most
// projects never change. It runs outside the dashboard's IIFE and sees only
// the helpers it is handed (panelHelpers in 01-overview.js); the one name it
// puts on window is its factory.
//
// The hub decides everything that depends on who is asking: can_manage, the
// candidates a manager may add (projects they can see, not this one, not a
// feature, not listed already), and which projects are named rather than
// counted. A manager gets the controls; everyone else on the project sees the
// lists alone. On a hub with single sign-on a change asks for a recent
// sign-in, which h.api's 401 handling turns into the "Confirm it's you"
// dialog and a replay. Every dashboard showing either project of a changed
// entry is pushed its new lists (project_readers, readers_push.go), so the
// section never polls; a reader is named in a change by its path or its
// entry's id, never by its index, which shifts when the project list changes.
(function () {
  'use strict';

  window.cloopReadersPanel = function (h) {
    let shown = null;     // the path whose lists are on screen
    let shownIdx = null;  // its index when they were read
    let inflight = null;
    let inflightIdx = null;
    // Every push bumps seq and is kept as last: a read that a push overtook
    // answers with lists no newer than the push's, so the push is drawn.
    let seq = 0;
    let last = null;
    // reads numbers each read, and drawn is the newest one drawn: a read
    // that began before it answers with older lists and is not drawn.
    let reads = 0;
    let drawn = 0;

    function el(id) { return document.getElementById(id); }

    // The section's markup, built once and placed after the Members card, or
    // where that card goes when there is none: after Features.
    function section() {
      let sec = el('readersSection');
      if (sec) return sec;
      sec = document.createElement('div');
      sec.className = 'section';
      sec.id = 'readersSection';
      sec.style.display = 'none';
      sec.innerHTML =
        '<div class="section-title" id="readersTitle" tabindex="-1" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">Readers' +
          '<span id="readersCount" class="feat-opt" style="font-weight:400"></span></div>' +
        '<div id="readersBody">' +
          '<p class="form-hint" style="margin:0 0 8px">Runs of these projects get this project’s files, read-only. ' +
            'No other project can read it.</p>' +
          '<div id="readersList" role="list" aria-labelledby="readersTitle"></div>' +
          '<form id="readersAddForm" style="display:none;flex-wrap:wrap;gap:8px;align-items:center;margin-top:4px">' +
            '<select class="form-input form-select" id="readersPick" aria-label="Project that may read this one" ' +
              'style="flex:2 1 220px;min-width:0"></select>' +
            '<button class="btn primary" id="readersAddBtn" type="submit" style="padding:6px 14px">Add reader</button>' +
          '</form>' +
        '</div>' +
        '<div id="readersNote" class="form-hint" style="margin-top:8px"></div>' +
        '<div id="readableBody">' +
          '<div class="section-title" id="readableTitle" style="margin-top:16px">Can read</div>' +
          '<p class="form-hint" style="margin:0 0 8px">This project’s runs get these projects’ files, read-only. ' +
            'Each one’s administrators decide who may read it.</p>' +
          '<div id="readableList" role="list" aria-labelledby="readableTitle"></div>' +
        '</div>';
      const anchor = el('membersSection') || el('featuresSection');
      const panel = el('projectPanel');
      if (anchor && anchor.parentNode) anchor.parentNode.insertBefore(sec, anchor.nextSibling);
      else if (panel) panel.appendChild(sec);
      else return null;

      sec.querySelector('#readersAddForm').addEventListener('submit', function (ev) {
        ev.preventDefault();
        add();
      });
      sec.querySelector('#readersList').addEventListener('click', function (ev) {
        const btn = ev.target && ev.target.closest ? ev.target.closest('button[data-label]') : null;
        if (btn) remove(btn);
      });
      return sec;
    }

    function hide() {
      const sec = el('readersSection');
      if (sec) sec.style.display = 'none';
      shown = null;
      shownIdx = null;
    }

    // The path of the project at idx in the page's project list, where the
    // page has one (a hub of several projects): what the Overview is showing.
    function pathAt(idx) {
      const d = window._lastProjectsData;
      const p = idx !== null && d && Array.isArray(d.projects) ? d.projects[idx] : null;
      return p ? p.path : null;
    }

    // Whether the lists on screen are the shown project's: a project opened
    // at the index another had must not act on, or show, the other's.
    function current() {
      const idx = h.pidx();
      if (idx === null || !shown) return false;
      const want = pathAt(idx);
      return !want || want === shown;
    }

    function base() { return '/api/projects/' + h.pidx() + '/readers'; }

    function fail(what, err) {
      // A lapsed session (401) is being signed in again; nothing to redraw.
      if (err && err.message === '401') return null;
      // A refusal (403) has already been reported in the hub's own words;
      // repeating its code would replace them.
      if (!(err && err.message === 'FORBIDDEN')) {
        h.toast((err && err.message ? err.message : 'Could not ' + what), 'error');
      }
      // What was refused may have been drawn from lists that have moved on.
      return load(true);
    }

    // When and by whom an entry was made, for its row.
    function made(verb, e) {
      const parts = [];
      if (e.added_by) parts.push(verb + ' by ' + e.added_by);
      const at = Date.parse(e.added_at);
      if (at > 0) parts.push(h.relTime(new Date(at)));
      return parts.join(' · ');
    }

    function row(name, meta, action, title) {
      return '<div class="feat-row" role="listitem">' +
        '<div class="feat-main" style="cursor:default">' +
          '<span style="font-weight:600;word-break:break-all"' + (title ? ' title="' + h.esc(title) + '"' : '') + '>' +
            h.esc(name) + '</span>' +
          (meta ? '<span class="feat-branch">' + h.esc(meta) + '</span>' : '') +
        '</div>' +
        (action ? '<div class="feat-actions">' + action + '</div>' : '') +
      '</div>';
    }

    // A reader the viewer can see is removed by its path; one they cannot,
    // by the entry's id, which is all they are told of it.
    function removeBtn(attr, value, label) {
      return '<button class="btn" type="button" data-' + attr + '="' + h.esc(value) + '" data-label="' + h.esc(label) +
        '" aria-label="Remove ' + h.esc(label) + ' from the readers">Remove</button>';
    }

    function note(text) {
      return '<div class="feat-note" role="listitem" style="margin-bottom:8px">' + h.esc(text) + '</div>';
    }

    // n more projects than are named: the ones this viewer cannot see.
    function unseen(n) {
      return n === 1 ? '1 more project you can’t see' : n + ' more projects you can’t see';
    }

    // The control holding the keyboard inside the section, as something the
    // next drawing can find again: a redraw replaces every row.
    function focusKey() {
      const a = document.activeElement;
      const sec = el('readersSection');
      if (!a || a === document.body || !sec || !sec.contains(a)) return null;
      const d = a.dataset || {};
      return {id: d.id || '', path: d.path || '', el: a.id || ''};
    }

    function focusIn(to) {
      const t = to && to.offsetParent ? to : el('readersTitle');
      if (t) t.focus();
    }

    function refocus(key) {
      if (!key) return;
      const sec = el('readersSection');
      let to = key.el ? el(key.el) : null;
      if (!to && sec) {
        to = Array.prototype.find.call(sec.querySelectorAll('button[data-label]'), function (b) {
          return (key.id && b.dataset.id === key.id) || (key.path && b.dataset.path === key.path);
        });
      }
      focusIn(to);
    }

    function render(d) {
      const sec = section();
      if (!sec) return;
      const keep = focusKey();
      shown = d.path;
      sec.style.display = '';
      const feature = !!d.feature;
      el('readersBody').style.display = feature ? 'none' : '';
      el('readableBody').style.display = feature ? 'none' : '';
      const readers = Array.isArray(d.readers) ? d.readers : [];
      const hidden = Array.isArray(d.hidden) ? d.hidden : [];
      const total = readers.length + (d.hidden_readers || 0);
      const count = el('readersCount');
      count.textContent = feature ? '' : total === 1 ? '1 project' : total + ' projects';
      count.style.display = feature ? 'none' : '';

      const rows = readers.map(function (r) {
        return row(r.project, made('added', r), d.can_manage ? removeBtn('path', r.path, r.project) : '', r.path);
      });
      if (d.can_manage) {
        // An administrator may take back what was given without learning
        // whom it was given to.
        hidden.forEach(function (x) {
          rows.push(row('A project you can’t see', made('added', x), removeBtn('id', x.id, 'a project you can’t see'), ''));
        });
      } else if (d.hidden_readers) {
        rows.push(note(unseen(d.hidden_readers)));
      }
      if (!total) rows.push(note('No other project can read this one.'));
      el('readersList').innerHTML = rows.join('');

      const form = el('readersAddForm');
      const candidates = Array.isArray(d.candidates) ? d.candidates : [];
      form.style.display = d.can_manage && candidates.length ? 'flex' : 'none';
      if (d.can_manage) {
        const pick = el('readersPick');
        const was = pick.value;
        // Two projects may share a name; their paths tell them apart.
        const names = {};
        candidates.forEach(function (c) { names[c.project] = (names[c.project] || 0) + 1; });
        pick.innerHTML = '<option value="">Choose a project…</option>' + candidates.map(function (c) {
          const label = names[c.project] > 1 ? c.project + ' (' + c.path + ')' : c.project;
          return '<option value="' + h.esc(c.path) + '" title="' + h.esc(c.path) + '">' + h.esc(label) + '</option>';
        }).join('');
        pick.value = candidates.some(function (c) { return c.path === was; }) ? was : '';
      }
      let text = '';
      if (feature) text = d.note || '';
      else if (!d.can_manage) text = 'Only this project’s administrators can change who may read it.';
      else if (!candidates.length) text = 'There is no other project you can see to add.';
      el('readersNote').textContent = text;
      el('readersNote').style.display = text ? '' : 'none';

      const readable = Array.isArray(d.readable) ? d.readable : [];
      const can = readable.map(function (r) { return row(r.project, made('listed', r), '', r.path); });
      if (d.hidden_readable) can.push(note(unseen(d.hidden_readable)));
      if (!readable.length && !d.hidden_readable) can.push(note('This project reads no other project.'));
      el('readableList').innerHTML = can.join('');
      refocus(keep);
    }

    // load reads the lists of the project the Overview shows. A read already
    // under way for it is shared, unless fresh asks for one that starts after
    // whatever the caller just changed.
    function load(fresh) {
      const idx = h.pidx();
      if (idx === null) {
        hide();
        return Promise.resolve(null);
      }
      if (!fresh && inflight && inflightIdx === idx) return inflight;
      // Lists belong to one project: never leave another's on screen while
      // this one's are fetched.
      if (shownIdx !== idx || !current()) hide();
      inflightIdx = idx;
      const before = seq;
      const mine = ++reads;
      const p = h.api('/api/projects/' + idx + '/readers').then(function (d) {
        if (idx !== h.pidx() || mine < drawn) return null;
        if (!d || d.error) {
          hide();
          return null;
        }
        drawn = mine;
        render(seq !== before && last && last.path === d.path ? last : d);
        shownIdx = idx;
        return d;
      }).catch(function () {
        if (mine >= drawn) hide();
        return null;
      });
      inflight = p;
      p.then(function () { if (inflight === p) inflight = null; });
      return p;
    }

    // pushed draws the lists the hub sent this dashboard's socket, rendered
    // for its viewer. The socket is the shown project's; the path check keeps
    // a frame that raced a project switch off the screen, and one that comes
    // before the first read has answered is kept for it.
    function pushed(d) {
      if (!d || !d.path) return;
      seq++;
      last = d;
      if (d.path === shown && current()) render(d);
    }

    // refresh reads the lists again where they are on screen: the page's
    // socket came back, or the hub said it dropped frames, either of which
    // may have taken a push with it.
    function refresh() {
      if (h.tab() === 'overview' && shown) load(true);
    }

    // Act only on the lists of the project that is shown.
    function stale() {
      if (current()) return false;
      h.toast('The project on screen changed; check the list and try again', 'error');
      load(true);
      return true;
    }

    function add() {
      if (stale()) return;
      const pick = el('readersPick');
      const path = pick.value;
      if (!path) {
        h.toast('Choose the project that may read this one', 'error');
        pick.focus();
        return;
      }
      const label = pick.options[pick.selectedIndex] ? pick.options[pick.selectedIndex].textContent : path;
      const btn = el('readersAddBtn');
      btn.disabled = true;
      h.apiMethod('PUT', base(), {reader: path})
        .then(function (r) {
          if (r && r.error) return fail('add the reader', {message: r.error});
          h.toast(label + ' may now read this project', 'success');
          return load(true).then(function () { focusIn(el('readersPick')); });
        })
        .catch(function (err) { return fail('add the reader', err); })
        .then(function () { btn.disabled = false; });
    }

    function remove(btn) {
      if (stale()) return;
      const label = btn.dataset.label;
      const q = btn.dataset.id ? '?id=' + encodeURIComponent(btn.dataset.id)
        : btn.dataset.path ? '?reader=' + encodeURIComponent(btn.dataset.path) : '';
      if (!q) return;
      if (!window.confirm('Remove ' + label + ' from this project’s readers? Its runs stop getting this ' +
          'project’s files at their next task.')) return;
      btn.disabled = true;
      h.apiMethod('DELETE', base() + q)
        .then(function (r) {
          if (r && r.error) return fail('remove the reader', {message: r.error});
          h.toast('Removed ' + label + ' from the readers', 'success');
          // The row and its button are gone: keep the keyboard in the
          // section.
          return load(true).then(function () { focusIn(el('readersPick')); });
        })
        .catch(function (err) { return fail('remove the reader', err); })
        .then(function () { btn.disabled = false; });
    }

    return {load: load, pushed: pushed, refresh: refresh};
  };
})();
