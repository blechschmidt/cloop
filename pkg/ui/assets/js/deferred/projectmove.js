// ── Move a project (Task 20496) ─────────────────────────────────────────────
//
// The dialog the Overview executor card's "Move to…" opens. Four faces, one
// overlay:
//
//   choose   where the project goes: the executors and pools the caller may
//            use, the one it is on marked;
//   review   the preflight's findings grouped as blockers, warnings and what
//            the move carries, each with its remedy. Every warning has to be
//            ticked before Move can be pressed, and a blocker keeps it
//            pressed in;
//   progress the move's phases as the hub pushes them (project_move over the
//            dashboard's socket — no polling);
//   result   how it ended, what it kept, and the cleanup of what it kept,
//            which removes the source's own copy only after a verified move
//            and only once the box saying so is ticked.
//
// Fetched on the first press of the button. It runs outside the dashboard's
// IIFE: it is handed the helpers it calls, reads the projects list the page
// keeps on window, and puts nothing on window but its factory.
(function () {
  'use strict';

  const PHASES = [
    ['preflight', 'Preflight', 'Checking what the move would carry, lose or break'],
    ['quiesce', 'Stop runs', 'Stopping the project’s runs; a task in progress goes back to pending'],
    ['capture', 'Capture', 'Capturing the source: its trees, commits and .cloop files'],
    ['switch', 'Switch', 'Pointing the project at its new executor'],
    ['seed', 'Seed', 'Giving the target what was captured'],
    ['verify', 'Verify', 'Checking the target holds exactly what was captured'],
  ];
  const GROUPS = [
    ['blocker', 'Blocks the move', 'Resolve these first, then check again.'],
    ['warning', 'Lost or changed by the move', 'Tick each one to say you accept it.'],
    ['will-carry', 'Carried by the move', 'Nothing to do: the move takes these along.'],
  ];

  window.cloopProjectmovePanel = function (h) {
    const {api, esc, toast} = h;
    const {openOverlay, closeOverlay, loadExecutors} = window;
    // The dialog's state: the project, the face, the target chosen, the
    // preflight read for it, the move on screen and what cleaning up after
    // it removes.
    let idx = null, face = '', target = '', abandon = false, report = null, move = null, plan = null;
    let choices = [], here = {}, last = null, busy = false, early = {}, ignored = null;
    // gen counts the dialog's opens: an answer to a request an earlier open
    // made — another project's preflight, say — is dropped, not drawn.
    let gen = 0;
    const fresh = g => g === gen;

    const el = id => document.getElementById(id);
    const project = () => (((window._lastProjectsData || {}).projects || [])[idx]) || {};
    const fmtTime = s => { const d = new Date(s); return !s || isNaN(d) || d.getFullYear() < 2 ? '' : d.toLocaleString(); };
    const took = st => {
      const a = new Date(st.started), b = new Date(st.ended);
      if (isNaN(a) || isNaN(b) || b.getFullYear() < 2) return '';
      const ms = b - a;
      return ms < 1000 ? ms + ' ms' : ms < 60000 ? (ms / 1000).toFixed(1) + ' s' : Math.round(ms / 60000) + ' min';
    };
    const nameOf = binding => {
      const c = choices.find(x => x.value === binding);
      return c ? c.name : binding ? binding : 'the hub’s default executor';
    };

    function error(msg) {
      const e = el('pm-error');
      if (!e) return;
      e.textContent = msg || '';
      e.style.display = msg ? '' : 'none';
    }

    // show draws a face: its title, its lead, its body and its buttons. A new
    // face takes the focus to its title, since the control that led there is
    // gone; the same face drawn again (a pushed step) keeps it where it is.
    function show(name, title, lead, body, foot) {
      const fresh = name !== face;
      face = name;
      el('pm-title').textContent = title;
      el('pm-lead').textContent = lead;
      el('pm-body').innerHTML = body;
      if (fresh || foot !== el('pm-foot').dataset.was) {
        el('pm-foot').innerHTML = foot;
        el('pm-foot').dataset.was = foot;
      }
      el('pm-box').dataset.face = name;
      if (fresh) {
        error('');
        el('pm-title').focus();
      }
    }

    // say tells a screen reader where the move is.
    function say(text) {
      const l = el('pm-live');
      if (l && l.textContent !== text) l.textContent = text;
    }

    // ── choose ──────────────────────────────────────────────────────────────

    function open() {
      idx = h.pidx();
      if (idx === null) { toast('Select a project first', 'err'); return; }
      move = plan = report = last = ignored = null; target = ''; abandon = false; early = {}; busy = false;
      const g = ++gen;
      openOverlay('pm-overlay', {dismiss: close, focus: '#pm-title'});
      show('loading', 'Move ' + (project().name || 'project'), '', '<p class="pm-muted">Loading…</p>', cancelBtn('Close'));
      const mv = project().moving;
      if (mv && mv.id) return follow(mv.id);
      const pools = h.canGlobal('executor.manage')
        ? api('/api/executor-pools').then(p => (p && p.pools) || [], () => []) : Promise.resolve([]);
      const moves = api('/api/projects/' + idx + '/moves').then(d => (d && d.moves) || [], () => []);
      return Promise.all([loadExecutors(), pools, moves]).then(([d, p, list]) => {
        if (!fresh(g)) return;
        here = (d && d.project) || {};
        choices = targetsOf(d || {}, p);
        // The last move that kept something to clean up, offered beside the
        // choice: what a person comes back to the dialog for.
        last = list.find(m => !isOpen(m) && m.detail && m.detail.capture &&
          !(m.detail.retained && fmtTime(m.detail.retained.cleaned_at))) || null;
        choose();
      }).catch(e => { if (fresh(g)) error('Could not load the executors: ' + (e && e.message || e)); });
    }

    // targetsOf lists where the project may go: the executors the caller is on
    // the access list of and the live pools, the current binding marked.
    function targetsOf(d, pools) {
      const proj = d.project || {};
      // Where it runs now: its binding, or the default it inherits.
      const cur = proj.executor_id || proj.effective_id || '';
      const out = [];
      (d.executors || []).forEach(ex => {
        if (ex.pool_runner || ex.admitted === false) return;
        const why = ex.blocked ? (ex.blocked_reason || 'blocked by the hub’s policy') : ex.registered === false ? 'not registered on this hub' : '';
        out.push({value: ex.id, name: ex.name || ex.id, current: ex.id === cur,
          sub: [h.execKind(ex.kind), ex.status, ex.virtual && ex.virtual.parent ? 'on ' + ex.virtual.parent : ''].filter(Boolean).join(' · '),
          why});
      });
      (pools || []).filter(p => p.admitted !== false && (!p.revoked_at || p.revoked_at.slice(0, 4) === '0001')).forEach(p => {
        out.push({value: p.binding, name: p.name, current: p.binding === cur, pool: true,
          sub: 'pool · up to ' + p.max_runners + ' runners' + (p.cordoned ? ' · cordoned' : ''), why: ''});
      });
      return out;
    }

    function choose() {
      const cur = choices.find(c => c.current);
      const opts = choices.map((c, i) => {
        const off = c.current || !!c.why;
        return '<label class="pm-opt' + (off ? ' off' : '') + '"><input type="radio" name="pmTarget" data-change="pick" data-arg="' + i + '"' +
          (off ? ' disabled' : '') + (c.value === target ? ' checked' : '') + '><span><strong>' + esc(c.name) + '</strong>' +
          (c.current ? ' <em>· where it is now</em>' : '') + '<small>' + esc(c.sub) + (c.why ? ' — ' + esc(c.why) : '') + '</small></span></label>';
      }).join('');
      const back = last ? '<p class="pm-note">The last move, to ' + esc(nameOf(last.target)) + ', ended ' + esc(phaseWord(last.phase)) +
        ' and kept what cleanup removes. <button class="btn" data-act="review">Review it</button></p>' : '';
      show('choose', 'Move ' + (project().name || 'project'),
        'A move stops the project’s runs, captures what its executor holds — uncommitted changes, commits no remote has, its ' +
        'features’ branches and the files under .cloop — and checks the new executor holds all of it before it is done. ' +
        'The old copy is kept until you clean up after the move.',
        back + '<p class="pm-muted">Now on ' + esc(cur ? cur.name : 'the hub’s default executor') + (cur && !here.bound ? ', the hub’s default' : '') + '.</p>' +
        (opts ? '<fieldset class="pm-list"><legend>Move to</legend>' + opts + '</fieldset>'
          : '<p class="pm-muted">No other executor or pool is open to you. An administrator can put you on one’s access list.</p>') +
        '<label class="pm-ack"><input type="checkbox" id="pmAbandon" data-change="abandon"' + (abandon ? ' checked' : '') + '> ' +
        'Abandon the source: move without capturing it. Only for a source that is gone for good — what it holds is lost.</label>',
        cancelBtn('Cancel') + '<button class="btn primary" id="pmCheck" data-act="check"' + (target ? '' : ' disabled') + '>Review the move</button>');
    }

    function pick() {
      const c = choices[+this.dataset.arg];
      if (!c) return;
      target = c.value;
      const b = el('pmCheck');
      if (b) b.disabled = false;
    }

    function setAbandon() { abandon = !!this.checked; }

    // ── review ──────────────────────────────────────────────────────────────

    function check() {
      if (!target || busy) return;
      busy = true;
      show('loading', 'Move to ' + nameOf(target), '', '<p class="pm-muted" role="status">Reading what the move would carry, lose or break…</p>', cancelBtn('Cancel'));
      const q = 'target=' + encodeURIComponent(target) + '&quiesce=1' + (abandon ? '&abandon_source=1' : '');
      const g = gen;
      return api('/api/projects/' + idx + '/move/preflight?' + q).then(rep => {
        if (!fresh(g)) return;
        busy = false;
        if (!rep || rep.error) { choose(); error(rep && rep.error || 'The preflight did not answer'); return; }
        report = rep;
        review();
      }, e => { if (!fresh(g)) return; busy = false; choose(); error(refusal(e)); });
    }

    function review() {
      const r = report, warn = [];
      let body = '<p class="pm-muted">' + esc(endName(r.source)) + ' → <strong>' + esc(endName(r.target)) + '</strong>' +
        (r.abandon_source ? ' · the source is abandoned' : '') + '</p><p class="pm-counts">' +
        r.counts.blockers + ' blocking · ' + r.counts.warnings + ' to accept · ' + r.counts.will_carry + ' carried</p>';
      GROUPS.forEach(([sev, head, hint]) => {
        const fs = r.findings.filter(f => f.severity === sev);
        if (!fs.length) return;
        body += '<section class="pm-group pm-' + sev + '" aria-label="' + head + '"><h3>' + head + ' (' + fs.length + ')</h3><p class="pm-muted">' + hint + '</p>' +
          fs.map(f => {
            const i = r.findings.indexOf(f);
            if (sev === 'warning') warn.push(i);
            return '<div class="pm-finding"><div class="pm-ft">' + esc(f.title) + '</div>' +
              (f.message ? '<div>' + esc(f.message) + '</div>' : '') +
              (f.items && f.items.length ? '<ul>' + f.items.slice(0, 12).map(itemLine).join('') +
                (f.items.length > 12 ? '<li>and ' + (f.items.length - 12) + ' more</li>' : '') + '</ul>' : '') +
              (f.remedy ? '<div class="pm-remedy"><strong>What to do:</strong> ' + esc(f.remedy) + '</div>' : '') +
              (sev === 'warning' ? '<label class="pm-ack"><input type="checkbox" data-change="ack" data-arg="' + i + '"> I accept this</label>' : '') +
              '</div>';
          }).join('') + '</section>';
      });
      report.acks = {};
      show('review', 'Move to ' + endName(r.target),
        r.blocked ? 'The move cannot start until the blockers are resolved.'
          : warn.length ? 'Read what the move would lose or change, and tick each warning to go ahead.'
            : 'Nothing blocks the move and nothing is lost.',
        body,
        '<button class="btn" data-act="choose">Back</button>' + cancelBtn('Cancel') +
        (r.blocked ? '<button class="btn" data-act="check">Check again</button>'
          : '<button class="btn primary" id="pmGo" data-act="start"' + (warn.length ? ' disabled' : '') + '>Move</button>'));
      report.warnings = warn;
      say(r.blocked ? r.counts.blockers + ' finding(s) block the move' : r.counts.warnings + ' warning(s) to accept');
    }

    function itemLine(it) {
      const n = [it.count ? it.count + '' : '', it.bytes ? h.fmtBytes(it.bytes) : ''].filter(Boolean).join(', ');
      return '<li>' + esc(it.name) + (it.path && it.path !== it.name ? ' <code>' + esc(it.path) + '</code>' : '') +
        (n ? ': ' + esc(n) : '') + (it.detail ? ' — ' + esc(it.detail) : '') +
        (it.examples && it.examples.length ? ' <span class="pm-muted">[' + esc(it.examples.join(', ')) + ']</span>' : '') + '</li>';
    }

    function endName(e) {
      if (!e) return '';
      const n = e.name || e.executor_id || e.pool_id || '';
      return (e.pool_id ? 'pool ' : '') + (n || nameOf(e.binding));
    }

    function ack() {
      report.acks[this.dataset.arg] = !!this.checked;
      const go = el('pmGo');
      if (go) go.disabled = !report.warnings.every(i => report.acks[i]);
    }

    // ── start, and progress ─────────────────────────────────────────────────

    function start() {
      if (busy || !report || report.blocked || !report.warnings.every(i => report.acks[i])) return;
      busy = true;
      const go = el('pmGo');
      if (go) go.disabled = true;
      const g = gen;
      return api('/api/projects/' + idx + '/move', {target, abandon_source: abandon}).then(d => {
        if (!fresh(g)) return;
        busy = false;
        if (!d || !d.move || d.error) {
          if (d && d.code === 'move_blocked' && d.report) { report = d.report; review(); }
          else if (go) go.disabled = false;
          error((d && d.error) || 'The move did not start');
          return;
        }
        const e = early[d.move.id];
        move = e && e.version > d.move.version ? e : d.move;
        early = {};
        if (isOpen(move)) progress(); else follow(move.id);
      }, e => { if (!fresh(g)) return; busy = false; if (go) go.disabled = false; error(refusal(e)); });
    }

    // follow reads a move whole — a move under way the dialog opens on, or one
    // that ended — with what cleaning up after it removes. A step pushed while
    // the read was in flight wins over it; one that ended the move is read
    // again for its plan.
    function follow(id) {
      const g = gen;
      move = null;
      return api('/api/projects/' + idx + '/move/' + encodeURIComponent(id)).then(d => {
        if (!fresh(g)) return;
        if (!d || !d.move) { error((d && d.error) || 'Could not read the move'); return; }
        const e = early[id];
        early = {};
        if (e && e.version > d.move.version) {
          move = e;
          if (!isOpen(e)) return follow(id);
        } else {
          move = d.move; plan = d.cleanup || null;
        }
        if (isOpen(move)) progress(); else result();
      }, e => { if (fresh(g)) error(refusal(e)); });
    }

    function isOpen(m) { return !!m && !/^(done|failed|rolled_back)$/.test(m.phase); }

    // steps lists the move's phases: done, in progress, failed or to come.
    function steps(m) {
      const at = PHASES.findIndex(p => p[0] === m.phase);
      const runs = (m.detail && m.detail.timeline) || [];
      return '<ol class="pm-steps">' + PHASES.map(([key, label, says], i) => {
        const st = runs.filter(s => s.phase === key).pop();
        const state = st && st.error ? 'failed' : i < at || (st && fmtTime(st.ended)) ? 'done' : i === at ? 'now' : 'todo';
        return '<li class="pm-step ' + state + '"' + (state === 'now' ? ' aria-current="step"' : '') + '><span class="pm-dot" aria-hidden="true"></span>' +
          '<span><strong>' + label + '</strong> <span class="pm-muted">' + (state === 'done' && st ? esc(took(st)) : state === 'now' ? 'in progress' :
            state === 'failed' ? 'failed' : '') + '</span><small>' + says + '</small></span></li>';
      }).join('') + '</ol>';
    }

    function progress() {
      const m = move, now = PHASES.find(p => p[0] === m.phase);
      show('progress', 'Moving ' + (project().name || 'project') + ' to ' + nameOf(m.target),
        'No run of the project starts until the move ends. You can close this: the move goes on at the hub, and Move to… on the executor card opens it again.',
        steps(m), cancelBtn('Close'));
      say((now ? now[1] + ': ' + now[2] : 'Working') + '…');
    }

    // pushed takes a project_move frame (04-realtime.js): the move on screen
    // as the hub now has it.
    function pushed(data) {
      const m = data && data.move;
      if (!m || !m.id) return;
      if (!move) {
        if (!early[m.id] || early[m.id].version < m.version) early[m.id] = m;
        return;
      }
      if (m.id !== move.id || m.version < move.version || !isOverlayOpen()) return;
      move = m;
      if (isOpen(m)) { if (face === 'progress') progress(); return; }
      if (face !== 'progress' && face !== 'result') return;
      follow(m.id);
    }

    function isOverlayOpen() { const o = el('pm-overlay'); return !!o && o.style.display !== 'none'; }

    // ── result, and cleanup ─────────────────────────────────────────────────

    function reviewLast() {
      if (last) follow(last.id);
    }

    function result() {
      const m = move, p = plan || {};
      const ok = m.phase === 'done';
      const r = (m.detail && m.detail.retained) || {};
      const cap = (m.detail && m.detail.capture) || {};
      const v = (m.detail && m.detail.verify) || {};
      let body = ok
        ? '<p class="pm-ok">Moved and verified' + (v.checked ? ': ' + v.checked + ' refs, trees and files checked at the target.' : '.') + '</p>' +
          (cap.bytes ? '<p class="pm-muted">Captured ' + esc(h.fmtBytes(cap.bytes)) + (cap.from ? ' from ' + esc(cap.from) : '') + '.</p>' : '')
        : '<p class="pm-bad">' + (m.phase === 'rolled_back' ? 'Rolled back after ' : 'Failed at ') + esc(m.failed_phase || m.phase) + ': ' + esc(m.error || '') +
          '</p><p class="pm-muted">The project stays on ' + esc(nameOf(m.source)) + '.</p>';
      if (fmtTime(r.source_removed_at)) body += '<p><strong>Removed:</strong> the working copy on ' + esc(r.source_removed) + ', ' + esc(fmtTime(r.source_removed_at)) + '.</p>';
      else if (r.source) body += '<p><strong>Kept:</strong> ' + esc(r.source) + '</p>';
      body += steps(m) + cleanupBlock(p);
      const can = p.allowed && h.can('executor.manage');
      const s = p.source, copy = s && !s.removed_at;
      show('result', ok ? 'Moved to ' + nameOf(m.target) : 'The move did not finish', '', body,
        '<button class="btn" data-act="again">Move somewhere else</button>' + cancelBtn('Close') +
        (can && copy && !s.removable && !p.cleaned_at ? '<button class="btn" id="pmKeep" data-act="keep" disabled>Clean up, keep the copy</button>' : '') +
        (can && (!copy || s.removable) ? '<button class="btn primary" id="pmClean" data-act="clean" disabled>' +
          (copy ? 'Remove the retained source copy' : 'Clean up') + '</button>' : ''));
      say(ok ? 'Moved and verified' : 'The move did not finish');
    }

    function cleanupBlock(p) {
      const s = p.source, copy = s && !s.removed_at;
      const done = p.cleaned_at ? '<p class="pm-ok">Cleaned up ' + esc(fmtTime(p.cleaned_at)) + (p.cleaned_by ? ' by ' + esc(p.cleaned_by) : '') + '.</p>' : '';
      const stays = copy && !s.removable ? '<p class="pm-muted">The copy on ' + esc(s.name || s.executor) + ' cannot be removed now: ' + esc(s.reason || '') +
        (p.cleaned_at ? '.' : '. Clean up keeping it, and you can remove it from here later once it can be.') + '</p>' : '';
      if (!p.allowed) return done + (p.cleaned_at ? stays : p.reason ? '<p class="pm-muted">' + esc(p.reason) + '</p>' : '');
      const gone = [];
      if (p.store) gone.push('the move’s bundle and files in the hub’s move store (' + esc(h.fmtBytes(p.store_bytes || 0)) + ')');
      if (p.refs && p.refs.length) gone.push(p.refs.length + ' hidden ref(s) the capture wrote into the project’s repository on the hub');
      if (copy && s.removable) {
        gone.push('<strong>the working copy on ' + esc(s.name || s.executor) + ', at <code>' + esc(s.work_dir) + '</code></strong> — once the device has ' +
          'checked it holds nothing the move did not carry');
      }
      if (!gone.length) gone.push('the move’s record of what it kept, nothing else');
      let out = done + '<section class="pm-group" aria-label="Clean up"><h3>Clean up</h3><p>Cleaning up removes:</p><ul>' +
        gone.map(g => '<li>' + g + '</li>').join('') + '</ul>' + stays;
      if (ignored) {
        out += '<p class="pm-bad">The copy holds ' + ignored.n + ' file(s) git ignores, which no move carries: ' +
          esc(ignored.examples.join(', ')) + '.</p><label class="pm-ack"><input type="checkbox" id="pmIgnored"> ' +
          'Remove those too — I have copied off anything I need</label>';
      }
      (p.kept || []).forEach(k => { out += '<p class="pm-muted">It keeps ' + esc(k) + '.</p>'; });
      return out + '<label class="pm-ack"><input type="checkbox" id="pmConfirm" data-change="confirm"> I understand this cannot be undone</label></section>';
    }

    function confirmTick() {
      ['pmClean', 'pmKeep'].forEach(id => { const b = el(id); if (b) b.disabled = !this.checked; });
    }

    // clean removes what the move kept — the source's copy too where it can —
    // or, from Clean up keeping the copy, all but that copy.
    function clean(keep) {
      const box = el('pmConfirm');
      if (busy || !move || !box || !box.checked) return;
      const body = {confirm: true, keep_source: keep === true};
      if (ignored && el('pmIgnored') && el('pmIgnored').checked) body.discard_ignored = true;
      busy = true;
      ['pmClean', 'pmKeep'].forEach(id => { const b = el(id); if (b) b.disabled = true; });
      const g = gen;
      return api('/api/projects/' + idx + '/move/' + encodeURIComponent(move.id) + '/cleanup', body).then(d => {
        if (!fresh(g)) return;
        busy = false;
        if (d && d.code === 'source_copy_ignored') {
          ignored = {n: d.ignored || 0, examples: d.examples || []};
          result();
          error('The copy was kept: it holds files no move carries. Tick the box to remove them too, or keep the copy.');
          return;
        }
        if (!d || d.error || !d.move) { error((d && d.error) || 'Cleanup did not run'); result(); return; }
        move = d.move; plan = d.cleanup || null; ignored = null;
        result();
        error('');
        toast('Cleaned up after the move', 'ok');
      }, e => { if (!fresh(g)) return; busy = false; result(); error(refusal(e)); });
    }

    function keep() { return clean(true); }

    // ── shared ──────────────────────────────────────────────────────────────

    function phaseWord(p) { return p === 'done' ? 'verified' : p === 'rolled_back' ? 'rolled back' : p; }

    function refusal(e) {
      const m = (e && e.message) || String(e);
      return m === 'FORBIDDEN' || /audience/.test(m) ? 'Not permitted: the message above says why.' : m;
    }

    function cancelBtn(label) { return '<button class="btn" data-act="close">' + label + '</button>'; }

    function again() { move = plan = report = null; target = ''; open(); }

    function close() { closeOverlay('pm-overlay'); }

    return h.mount({open, close, pick, abandon: setAbandon, check, choose, ack, start, pushed, review: reviewLast,
      clean: () => clean(false), keep, confirm: confirmTick, again}, null, null, `
    <div id="pm-overlay" data-overlay="flex" data-dismiss="close" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:50;align-items:center;justify-content:center">
      <style>
        #pm-box { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); width:680px; max-width:95vw;
          max-height:90vh; display:flex; flex-direction:column; overflow-wrap:anywhere; }
        .pm-head { padding:18px 22px 6px; border-bottom:1px solid var(--border); }
        #pm-title { font-size:15px; font-weight:600; margin:0 0 6px; outline:none; }
        #pm-lead { font-size:12px; color:var(--muted); line-height:1.5; margin:0; }
        #pm-body { padding:6px 22px 10px; overflow:auto; min-height:0; flex:1 1 auto; font-size:12.5px; line-height:1.5; }
        #pm-box .modal-footer { padding:10px 22px 16px; margin:0; flex-wrap:wrap; }
        .pm-muted { color:var(--muted); }
        .pm-list { border:0; padding:0; margin:8px 0; }
        .pm-list legend { font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:var(--muted); margin-bottom:4px; }
        .pm-opt { display:flex; gap:8px; align-items:flex-start; padding:7px 8px; border:1px solid var(--border); border-radius:6px; margin-bottom:6px; cursor:pointer; }
        .pm-opt.off { opacity:.6; cursor:default; }
        .pm-opt small, .pm-step small { display:block; color:var(--muted); font-size:11.5px; }
        .pm-ack { display:flex; gap:8px; align-items:flex-start; margin:8px 0 2px; font-size:12px; }
        .pm-group { margin:12px 0; }
        .pm-group h3 { font-size:12.5px; margin:0 0 2px; }
        .pm-finding { border-left:3px solid var(--border); padding:6px 10px; margin:8px 0; background:var(--hover-bg, transparent); }
        .pm-blocker .pm-finding { border-left-color:var(--red); }
        .pm-warning .pm-finding { border-left-color:var(--yellow, #d29922); }
        .pm-will-carry .pm-finding { border-left-color:var(--green); }
        .pm-ft { font-weight:600; }
        .pm-finding ul, #pm-body ul { margin:4px 0 0 18px; padding:0; }
        .pm-remedy { margin-top:4px; }
        .pm-counts { font-size:12px; }
        .pm-steps { list-style:none; padding:0; margin:6px 0; }
        .pm-step { display:flex; gap:10px; padding:6px 0; }
        .pm-dot { width:12px; height:12px; flex:0 0 12px; margin-top:3px; border-radius:50%; border:2px solid var(--border); }
        .pm-step.done .pm-dot { background:var(--green); border-color:var(--green); }
        .pm-step.now .pm-dot { border-color:var(--accent); animation:pmPulse 1.2s infinite; }
        .pm-step.failed .pm-dot { background:var(--red); border-color:var(--red); }
        .pm-step.todo { opacity:.6; }
        @keyframes pmPulse { 50% { background:var(--accent); } }
        @media (prefers-reduced-motion: reduce) { .pm-step.now .pm-dot { animation:none; background:var(--accent); } }
        .pm-ok { color:var(--green); font-weight:600; }
        .pm-bad { color:var(--red); font-weight:600; }
        .pm-note { border:1px solid var(--border); border-radius:6px; padding:6px 8px; }
        .pm-err { color:var(--red); font-size:12px; padding:0 22px; }
        .pm-sr { position:absolute; width:1px; height:1px; margin:-1px; overflow:hidden; clip:rect(0 0 0 0); white-space:nowrap; }
      </style>
      <div id="pm-box" role="dialog" aria-modal="true" aria-labelledby="pm-title" aria-describedby="pm-lead">
        <div class="pm-head"><h2 id="pm-title" tabindex="-1">Move project</h2><p id="pm-lead"></p></div>
        <div id="pm-body"></div>
        <div id="pm-error" class="pm-err" role="alert" style="display:none"></div>
        <p id="pm-live" class="pm-sr" role="status" aria-live="polite"></p>
        <div class="modal-footer" id="pm-foot"></div>
      </div>
    </div>
    `);
  };
})();
