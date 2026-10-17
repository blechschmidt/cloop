// ── The executor dialogs (Tasks 20158, 20258, 20307, 20310, 20331, 20345, 20363)
//
// Everything an executor card's buttons open: what ran on it, where its
// payloads run, its virtual executors, its firewall, its resource ceiling and
// access list, an upgrade, the fleet's automatic upgrades — and the dialog that
// enrolls a new device.
//
// Fetched the first time any of them is opened since Task 20386 (static.go,
// deferredScripts), dialogs included: first paint has no room for admin
// dialogs most sessions never open. The list and cards that open them stay in
// the bundle (23-executors.js), because the Overview's executor card renders
// from the same fetch; their buttons reach these functions through panelAct.
// It runs outside the dashboard's IIFE, so it is handed the helpers it calls —
// the executor lookups through h.execAt and friends, the firewall form shared
// with the Overview's project card through h.fw — and the only name it puts on
// window is the factory.
(function () {
  'use strict';

  window.cloopExecadminPanel = function (h) {
    const {api, apiMethod, esc, toast, relTime, canGlobal} = h;
    const {openOverlay, closeOverlay, loadExecutors, fwSync, openProject, switchTab, openTaskDetails} = window;
    const _execAt = h.execAt, _execKindLabel = h.execKind, _execDetailErrText = h.execErr;
    const {sum: _fwSum, form: _fwForm, read: _fwRead, refusal: _fwRefusal, meta: _fwMeta} = h.fw;

    // ── Executor detail drill-in (Task 20258) ───────────────────────────────────
    //
    // GET /api/executors/{id} is where the hub's central promise stops being a
    // claim and becomes checkable: it reports, per executor, what is running now,
    // what recently finished, and how many of those tasks ran as a process on the
    // hub's own machine. The endpoint had computed all of that since Task 20244
    // and no frontend code called it, so the one screen that could audit the
    // no-host-execution guarantee did not exist.
    //
    // Two rules shape everything below, because getting either wrong turns an
    // audit view into false reassurance:
    //
    //   1. A number that was not measured is never rendered as a measurement.
    //      A capped sweep says "lower bound"; a request that was refused or failed
    //      says so and renders no figures at all. "We found no host runs" and "we
    //      could not look" must never paint the same pixels.
    //   2. host_total is stated in words, not buried in a counter. An operator
    //      scanning this panel should not have to notice that a 3 is not a 0.

    // execDetailRefs backs the index dispatch for task rows, the same way execData
    // backs the card actions: a project path or task title interpolated into an
    // onclick attribute is the bug class of Tasks 163/20033.
    let execDetailRefs = [];

    function openExecutorDetail(idx) {
      const ex = _execAt(idx);
      if (!ex) return;
      execDetailRefs = [];

      const title = document.getElementById('execDetailTitle');
      if (title) title.textContent = 'What ran on ' + (ex.name || ex.id);
      const sub = document.getElementById('execDetailSub');
      if (sub) sub.textContent = ex.id + ' · ' + _execKindLabel(ex.kind);
      const body = document.getElementById('execDetailBody');
      if (body) body.innerHTML = '<div class="exec-detail-note">Loading…</div>';
      openOverlay('executor-detail-overlay', {dismiss: closeExecutorDetail});

      // Not pUrl(): this is fleet data, gated by executor.read on an executor
      // scope. Appending the selected project would suggest a project filter the
      // route does not apply.
      api('/api/executors/' + encodeURIComponent(ex.id))
        .then(d => {
          // A 404 body arrives here rather than as a rejection — parseAPIResponse
          // only diverts 401 and 403 — and on this route 404 is also the answer a
          // caller who may not read the fleet gets, because require() withholds
          // existence rather than confirming it with a 403. Both must land in the
          // same "we could not look" branch.
          if (!d || d.error) { _renderExecutorDetailError(d && d.error); return; }
          _renderExecutorDetail(d);
        })
        .catch(err => _renderExecutorDetailError(err));
    }

    function closeExecutorDetail() {
      closeOverlay('executor-detail-overlay');
      execDetailRefs = [];
    }


    // _renderExecutorDetailError is the honest failure state. It deliberately
    // renders no counts: a panel that showed "0 tasks ran on the host" after a
    // refused or failed request would be reporting the absence of an answer as a
    // clean bill of health, which is the single worst thing this view could do.
    function _renderExecutorDetailError(e) {
      const body = document.getElementById('execDetailBody');
      if (!body) return;
      const detail = _execDetailErrText(e);
      let h = '<div class="exec-detail-verdict unknown">';
      h += '<strong>&#9888; This executor’s history could not be read.</strong>';
      h += '<div>No counts are shown, on purpose. An unread history is not an empty one, '
        + 'so no figure here would mean anything &mdash; least of all a zero.</div>';
      if (detail) {
        h += '<div class="exec-detail-note">' + esc(detail) + '</div>';
      }
      h += '<div class="exec-detail-note">If your role does not cover the fleet, this is what '
        + 'you are meant to see: the hub answers &ldquo;no such executor&rdquo; rather than '
        + 'confirming one exists that you may not read.</div>';
      h += '</div>';
      body.innerHTML = h;
    }

    // _execHostVerdict is the headline. Three outcomes, and the middle one is the
    // reason this function exists rather than an inline ternary: a sweep that hit
    // its cap cannot distinguish "nothing ran on the host" from "the host runs are
    // in the projects we did not read".
    function _execHostVerdict(w) {
      const n = w.host_total || 0;
      if (n > 0) {
        const one = n === 1;
        return '<div class="exec-detail-verdict bad">'
          + '<strong>&#9888; ' + esc(n) + ' task' + (one ? '' : 's')
          + ' ran directly on this host.</strong>'
          + '<div>No sandbox stood between ' + (one ? 'it' : 'them') + ' and the hub’s own '
          + 'filesystem, network and credentials. On a hub configured never to execute a harness '
          + 'on the host, ' + (one ? 'this run is' : 'these runs are') + ' the finding.</div>'
          + (w.projects_truncated
              ? '<div>The sweep was capped, so the real count may be higher.</div>'
              : '')
          + '</div>';
      }
      if (w.projects_truncated) {
        return '<div class="exec-detail-verdict unknown">'
          + '<strong>No host execution found &mdash; but not every project was read.</strong>'
          + '<div>The sweep stopped at its cap, so zero is a lower bound rather than a clean '
          + 'record. Narrow the fleet, or check the projects beyond the cap directly, before '
          + 'treating this as evidence.</div></div>';
      }
      // A sweep that read nothing is the same false reassurance as a capped one,
      // reached by a different route: every project the hub serves can fail to
      // load — no plan yet, a directory that moved, a database it cannot open —
      // and the sweep skips each one silently. A fresh hub hits this on its first
      // day, which is exactly when someone checks the guarantee for the first
      // time and is least placed to know that a green tick meant "nothing read".
      if (!w.projects_scanned) {
        return '<div class="exec-detail-verdict unknown">'
          + '<strong>No project history was read.</strong>'
          + '<div>Not one project could be loaded, so there is nothing here to support a '
          + 'claim either way. On a hub whose projects have plans, this points at the '
          + 'projects themselves &mdash; moved, never initialised, or an unreadable '
          + 'state database.</div></div>';
      }
      return '<div class="exec-detail-verdict good">'
        + '<strong>&#10003; Nothing attributed to this executor ran on the host.</strong>'
        + '<div>Every task below was placed inside an isolation boundary.</div></div>';
    }

    // _execCoverageNote says how much of the fleet the figures cover. Without it an
    // empty history is indistinguishable from an unread one — the same failure the
    // error state above guards against, one step less severe.
    function _execCoverageNote(w) {
      const scanned = w.projects_scanned || 0;
      let s = 'Swept ' + scanned + ' project' + (scanned === 1 ? '' : 's') + '.';
      if (w.projects_truncated) {
        s += ' The sweep stopped at the hub’s cap: projects past it were not read at all, '
           + 'so every number on this panel is a lower bound.';
      } else if (!scanned) {
        // A literal em dash, not an entity: this string goes through esc() below,
        // which would render "&mdash;" as those seven characters.
        s += ' Every project the hub serves was skipped — none has a plan this '
           + 'sweep could read.';
      }
      const off = w.projects_truncated || !scanned;
      return '<div class="exec-detail-note' + (off ? ' warn' : '') + '">' + esc(s) + '</div>';
    }

    // _execTaskRow renders one attributed task and registers it for index dispatch.
    function _execTaskRow(ref) {
      const i = execDetailRefs.push(ref) - 1;
      let h = '<div class="exec-task-row' + (ref.on_host ? ' on-host' : '') + '">';
      h += '<button class="exec-task-link" data-act="openExecutorTaskRef" data-arg="' + i + '" '
        + 'title="Open this task in its project">#' + esc(ref.id) + ' '
        + esc(ref.title || '(untitled)') + '</button>';
      h += '<div class="exec-task-meta">';
      h += '<span class="exec-chip">' + esc(ref.project_name || ref.project_path || 'unknown project') + '</span>';
      h += '<span class="exec-chip">' + esc(ref.status || 'unknown') + '</span>';
      if (ref.isolation) {
        h += '<span class="exec-chip ' + (ref.isolation === 'none' ? 'neg' : 'pos') + '">'
          + esc(ref.isolation) + '</span>';
      }
      // Repeated per row even though the verdict above already counts them: the
      // verdict says how many, this says which, and an operator needs the second
      // to do anything about the first.
      if (ref.on_host) {
        h += '<span class="exec-chip neg" title="This task ran as a process on the hub’s '
          + 'own machine.">ran on host</span>';
      }
      if (ref.completed_at) {
        h += '<span>finished ' + esc(relTime(new Date(ref.completed_at))) + '</span>';
      } else if (ref.started_at) {
        h += '<span>started ' + esc(relTime(new Date(ref.started_at))) + '</span>';
      }
      h += '</div></div>';
      return h;
    }

    function _renderExecutorDetail(d) {
      const body = document.getElementById('execDetailBody');
      if (!body) return;
      const w = (d && d.workload) || {};
      const inFlight = w.in_flight || [];
      const completed = w.completed || [];
      let h = '';

      // Liveness first and briefly — the card already carries it, and repeating it
      // here only matters because "last heartbeat two days ago" changes how the
      // history below should be read.
      h += '<div class="exec-detail-meta">';
      h += '<span>Status: ' + esc(d.status || 'unknown') + '</span>';
      if (d.sched_state) h += '<span>Scheduling: ' + esc(d.sched_state) + '</span>';
      h += '<span>Last heartbeat: '
        + (d.last_heartbeat ? esc(relTime(new Date(d.last_heartbeat))) : 'never reported') + '</span>';
      if (d.last_seen) h += '<span>Last seen: ' + esc(relTime(new Date(d.last_seen))) + '</span>';
      if (d.projects && d.projects.length) {
        h += '<span>Bound to ' + esc(d.projects.length) + ' project'
          + (d.projects.length === 1 ? '' : 's') + '</span>';
      }
      h += '</div>';

      h += _execHostVerdict(w);
      h += _execCoverageNote(w);

      // In flight. Never truncated by the backend, so the count is exact.
      h += '<div class="exec-detail-section"><h3>In flight (' + esc(inFlight.length) + ')</h3>';
      h += inFlight.length
        ? inFlight.map(_execTaskRow).join('')
        : '<div class="exec-detail-note">Nothing is running here right now.</div>';
      h += '</div>';

      // Recent completions. The backend caps the list but counts the total, so say
      // both rather than letting 25 rows imply 25 tasks.
      const total = w.completed_total || completed.length;
      let head = 'Recent completions';
      if (total > completed.length) {
        head += ' (showing ' + completed.length + ' of ' + total + ')';
      } else {
        head += ' (' + completed.length + ')';
      }
      h += '<div class="exec-detail-section"><h3>' + esc(head) + '</h3>';
      h += completed.length
        ? completed.map(_execTaskRow).join('')
        : '<div class="exec-detail-note">No finished task is attributed to this executor.</div>';
      h += '</div>';

      // Attributed but neither running nor finished — reset after a previous run,
      // most often. Shown because otherwise a non-zero host count above two short
      // lists reads as a bug in this panel rather than as the history it is.
      if (w.not_running) {
        const one = w.not_running === 1;
        h += '<div class="exec-detail-note">' + esc(w.not_running) + ' further task'
          + (one ? ' carries' : 's carry') + ' this executor’s attribution but '
          + (one ? 'is' : 'are') + ' neither running nor finished — reset after '
          + 'a previous run. ' + (one ? 'It is' : 'They are') + ' counted in the host '
          + 'figure above, because the run that stamped ' + (one ? 'it' : 'them')
          + ' did happen.</div>';
      }

      body.innerHTML = h;
    }

    // openExecutorTaskRef walks back from a fleet row to the project that owns it.
    //
    // The executor sweep reads every project the hub serves, which is not the same
    // set as the project list this browser holds. When the two disagree, say so
    // rather than navigating to whatever sits at that index — sending an operator
    // to the wrong project's task #7 is worse than not moving at all.
    function openExecutorTaskRef(i) {
      const ref = execDetailRefs[i];
      if (!ref) return;
      const projects = (window._lastProjectsData && window._lastProjectsData.projects) || [];
      let pIdx = -1;
      for (let k = 0; k < projects.length; k++) {
        if (projects[k] && projects[k].path === ref.project_path) { pIdx = k; break; }
      }
      if (pIdx < 0) {
        toast('Not in your project list: ' + (ref.project_name || ref.project_path || 'unknown project'), 'err');
        return;
      }
      closeExecutorDetail();
      openProject(pIdx, projects[pIdx].name || ref.project_name || '');
      switchTab('tasks');
      openTaskDetails(ref.id);
    }


    // ── Sandbox configuration (Task 20307) ──────────────────────────────────────
    //
    // Where an executor's payloads run: on the device's host, or in a container on
    // it, and under which engine, runtime and image. Before this panel the answer
    // was unconfigurable for the one executor kind where it is not implied by the
    // driver — an enrolled remote device, which always ran the harness as a host
    // process while the card above advertised the container runtimes it had found.
    //
    // The dialog reads its options from the API rather than hardcoding them, so the
    // engines it offers are the ones the backend will accept. A frontend with its
    // own copy of that allowlist drifts, and the admin reads the resulting 400 as a
    // bug rather than as a stale build.

    // execSandboxTarget is the executor the open dialog is editing. Held rather than
    // re-derived from the card index, because loadExecutors may reorder the list
    // while the dialog is open and saving into whichever executor now sits at that
    // index would be the worst possible outcome of a race.
    let execSandboxTarget = null;

    function openExecutorSandbox(idx) {
      const ex = _execAt(idx);
      if (!ex) return;
      execSandboxTarget = {id: ex.id, name: ex.name || ex.id};

      const sub = document.getElementById('execSandboxSub');
      if (sub) sub.textContent = ex.id + ' · ' + _execKindLabel(ex.kind);
      _execSandboxWarn('');
      // Cleared before the fetch so a previous executor's settings are never on
      // screen under this one's name.
      _execSandboxFill({settings: {}, modes: [], engines: []});
      openOverlay('executor-sandbox-overlay', {dismiss: closeExecutorSandbox});

      api('/api/executors/' + encodeURIComponent(ex.id) + '/sandbox')
        .then(d => {
          if (!d || d.error) {
            _execSandboxWarn((d && d.error) || 'Could not read this executor’s sandbox configuration.');
            return;
          }
          _execSandboxFill(d);
        })
        .catch(err => _execSandboxWarn(_execDetailErrText(err)
          || 'Could not read this executor’s sandbox configuration.'));
    }

    function closeExecutorSandbox() {
      closeOverlay('executor-sandbox-overlay');
      execSandboxTarget = null;
    }

    // _execSandboxWarn shows or hides the caveat line.
    function _execSandboxWarn(text) {
      const el = document.getElementById('execSandboxWarn');
      if (!el) return;
      if (!text) { el.style.display = 'none'; el.textContent = ''; return; }
      el.style.display = '';
      el.textContent = text;
    }

    // _execSandboxFill populates the form from an API view.
    function _execSandboxFill(d) {
      const s = (d && d.settings) || {};
      const mode = document.getElementById('execSandboxMode');
      if (mode) mode.value = s.mode || '';

      // The engine list is the backend's, plus whatever the device reported. A
      // device advertising an engine the backend does not accept would otherwise be
      // invisible here; listing it and letting the save fail with a real message is
      // more use than silently omitting it.
      const engine = document.getElementById('execSandboxEngine');
      if (engine) {
        const offered = (d && d.engines) || [];
        const seen = {};
        let opts = '<option value="">Auto-detect on the device</option>';
        offered.forEach(e => {
          if (seen[e]) return;
          seen[e] = true;
          const present = ((d && d.device_engines) || []).indexOf(e) >= 0;
          opts += '<option value="' + esc(e) + '">' + esc(e)
            + (present ? ' — found on the device' : '') + '</option>';
        });
        engine.innerHTML = opts;
        engine.value = s.engine || '';
      }

      const rt = document.getElementById('execSandboxRuntime');
      if (rt) rt.value = s.runtime || '';
      const img = document.getElementById('execSandboxImage');
      if (img) img.value = s.image || '';

      // A datalist rather than a select: the two the backend offers are the two
      // every engine has, but an operator may have created a named network on the
      // device that this hub cannot enumerate, and a closed list would make that
      // network unselectable.
      const netList = document.getElementById('execSandboxNetworkList');
      if (netList) {
        netList.innerHTML = ((d && d.networks) || []).map(n =>
          '<option value="' + esc(n) + '">' + esc(n)
            + (n === 'none' ? ' — no network at all' : '')
            + (n === 'bridge' ? ' — the engine\u2019s default network' : '')
            + '</option>').join('');
      }
      const net = document.getElementById('execSandboxNetwork');
      if (net) net.value = s.network || '';

      const hint = document.getElementById('execSandboxModeHint');
      if (hint) {
        hint.textContent = d && d.configured
          ? 'Set by ' + (d.set_by || 'an admin') + (d.set_at ? ' · ' + relTime(new Date(d.set_at)) : '')
          : 'Never configured — this executor runs payloads the way its driver always has.';
      }
      const engineHint = document.getElementById('execSandboxEngineHint');
      if (engineHint) {
        const found = (d && d.device_engines) || [];
        engineHint.textContent = found.length
          ? 'This device reported: ' + found.join(', ')
          : 'This device reported no container engine at its last connect.';
      }
      if (d && d.warning) _execSandboxWarn(d.warning);
      // What the runtime saved last was found to be (Task 20439): the name is a
      // claim, and this is the probe's answer to it.
      const iso = document.getElementById('execSandboxIso');
      if (iso) {
        const e = d && d.isolation_evidence;
        iso.style.display = e ? '' : 'none';
        iso.innerHTML = e ? 'Isolation: ' + _isoChip(e) + ' ' + esc(_isoWhen(e)) : '';
      }
      _execSandboxSyncFields();
    }

    // _execSandboxSyncFields shows the container fields only for container mode.
    //
    // The values are left in the inputs when they are hidden rather than cleared,
    // so an admin who switches to host to read the hint and switches back has not
    // lost their typing. What must not happen is those values being *saved* under
    // host mode — and they are not: the backend normalizes them away, and does so
    // as the single rule for every writer rather than trusting this function.
    function _execSandboxSyncFields() {
      const mode = document.getElementById('execSandboxMode');
      const box = document.getElementById('execSandboxContainerFields');
      if (!box) return;
      box.style.display = (mode && mode.value === 'container') ? '' : 'none';
    }

    function onExecSandboxModeChange() { _execSandboxSyncFields(); }

    function saveExecutorSandbox() {
      const t = execSandboxTarget;
      if (!t) return;
      const payload = {
        mode:    (document.getElementById('execSandboxMode') || {}).value || '',
        engine:  (document.getElementById('execSandboxEngine') || {}).value || '',
        runtime: ((document.getElementById('execSandboxRuntime') || {}).value || '').trim(),
        image:   ((document.getElementById('execSandboxImage') || {}).value || '').trim(),
        network: ((document.getElementById('execSandboxNetwork') || {}).value || '').trim(),
      };
      apiMethod('PUT', '/api/executors/' + encodeURIComponent(t.id) + '/sandbox', payload)
        .then(d => {
          if (!d || d.error) { toast((d && d.error) || 'Failed to save sandbox configuration', 'err'); return; }
          const where = (d.settings && d.settings.mode === 'container')
            ? 'a container on ' + t.name
            : (d.settings && d.settings.mode === 'host') ? t.name + '’s host' : 'the executor default';
          toast('Payloads on ' + t.name + ' now run in ' + where, 'ok');
          closeExecutorSandbox();
          loadExecutors();
        })
        .catch(() => toast('Failed to save sandbox configuration', 'err'));
    }

    function clearExecutorSandbox() {
      const t = execSandboxTarget;
      if (!t) return;
      if (!confirm('Reset ' + t.name + ' to its default?\n\nIts payloads will run the way its driver '
          + 'always has — for an enrolled device, that is a process on the device’s own host.')) {
        return;
      }
      apiMethod('PUT', '/api/executors/' + encodeURIComponent(t.id) + '/sandbox', {clear: true})
        .then(d => {
          if (!d || d.error) { toast((d && d.error) || 'Failed to reset', 'err'); return; }
          toast(t.name + ' reset to its default', 'ok');
          closeExecutorSandbox();
          loadExecutors();
        })
        .catch(() => toast('Failed to reset sandbox configuration', 'err'));
    }


    // ── Isolation evidence (Task 20439) ─────────────────────────────────────────
    //
    // A card's "kata / VM" chip is read off its runtime's name. The hub checks
    // the name: it runs the isolation probe under the runtime and compares what
    // the kernel serving the sandbox said about itself with the host's own, so a
    // runtime named kata that is runc reads "claims kata, runs on the host
    // kernel". isolationChips adds that verdict to every card the list just drew
    // — panelIf calls it after each redraw — and the dialogs above and below
    // show it beside the runtime they set.
    // A contradiction is a warning, not a missing capability, so it does not
    // wear the dimmed look of one; an unverified claim is a caution.
    const _isoTone = {contradicted: 'color:var(--red);border-color:var(--red)',
      unverified: 'color:var(--yellow);border-color:var(--yellow)'};

    function _isoChip(e) {
      const cls = e.status === 'verified' ? 'pos' : 'neg';
      const tone = e.claim !== 'host-kernel' && _isoTone[e.status];
      const tip = [e.detail, e.error ? 'The latest probe could not run: ' + e.error : '', _isoWhen(e),
        e.refused ? 'Projects whose .cloop/sandbox.yaml requires kernel isolation or a hypervisor are refused here.' : '']
        .filter(Boolean).join('\n');
      return '<span class="exec-chip ' + cls + '" data-iso="' + esc(e.status) + '"'
        + (tone ? ' style="opacity:1;' + tone + '"' : '') + ' title="' + esc(tip) + '">' + esc(e.summary) + '</span>';
    }

    function _isoWhen(e) {
      if (e.probed_at) return 'Probed ' + relTime(new Date(e.probed_at)) + (e.point ? ' (' + e.point + ')' : '') + '.';
      if (e.attempted_at) return 'Last attempt ' + relTime(new Date(e.attempted_at)) + '.';
      return 'Never probed.';
    }

    function isolationChips() {
      const manage = canGlobal('executor.manage');
      document.querySelectorAll('#execList .exec-card').forEach(card => {
        const main = card.querySelector('.exec-card-main');
        const ex = main && _execAt(+main.dataset.arg);
        const e = ex && ex.isolation_evidence;
        const row = card.querySelector('.exec-chips');
        if (!e || !row || row.querySelector('[data-iso]')) return;
        // The name's own chip says what the probe found, when it found less.
        if (e.status === 'contradicted') {
          row.querySelectorAll('.exec-chip.pos').forEach(c => {
            if (c.textContent === 'kata / VM') { c.className = 'exec-chip neg'; c.title = 'Named for a VM — ' + e.summary; }
          });
        }
        row.insertAdjacentHTML('beforeend', _isoChip(e));
        if (!manage) return;
        // Wired here, not by attribute: the card is the bundle's markup, and
        // its actions are the bundle's registry; this one is the panel's own.
        const b = document.createElement('button');
        b.className = 'btn';
        b.style.cssText = 'padding:2px 8px;font-size:11px';
        b.textContent = 'Re-probe';
        b.title = 'Run the isolation probe under this executor’s runtime now';
        b.onclick = ev => { ev.stopPropagation(); _reprobe(ex.id, ex.name || ex.id); };
        row.appendChild(b);
      });
    }

    function _reprobe(id, name) {
      apiMethod('POST', '/api/executors/' + encodeURIComponent(id) + '/isolation-probe', {})
        .then(d => {
          if (!d || d.error) { toast((d && d.error) || 'Could not start the probe', 'err'); return; }
          toast(d.started ? 'Probing ' + name + '’s runtime…' : 'A probe of ' + name + ' is already running', 'ok');
        })
        .catch(err => toast(_execDetailErrText(err) || 'Could not start the probe', 'err'));
    }

    function reprobeExecutorVirtual(i) {
      const v = execVx && ((execVx.data || {}).virtual_executors || [])[+i];
      if (v) _reprobe(v.id, v.name || v.id);
    }

    // ── Virtual executors (Task 20345) ──────────────────────────────────────────
    //
    // A virtual executor is a sub-executor of an enrolled device: its own engine,
    // runtime and image, an IP firewall with an allowlist and a denylist, and the
    // host devices its sandboxes are given. The dialog is opened from the device's
    // card (to add one, and to see the device's USB hardware) or from a virtual
    // executor's own card (to edit it). Its form is built here rather than in
    // the dialog's static markup because every field depends on what the
    // device reported.
    let execVx = null;

    function openExecutorVirtual(idx) {
      const ex = _execAt(idx);
      if (!ex) return;
      const virtual = ex.kind === 'virtual';
      execVx = {parent: virtual ? (ex.virtual || {}).parent_id : ex.id, edit: virtual ? ex.id : ''};
      document.getElementById('evxBody').innerHTML = '<div class="form-hint">Loading…</div>';
      openOverlay('executor-virtual-overlay', {dismiss: closeExecutorVirtual});
      _evxLoad(false);
    }

    function closeExecutorVirtual() {
      closeOverlay('executor-virtual-overlay');
      execVx = null;
    }

    function refreshExecutorVirtual() { if (execVx) _evxLoad(true); }

    function _evxLoad(refresh) {
      api('/api/executors/' + encodeURIComponent(execVx.parent) + '/virtuals' + (refresh ? '?refresh=1' : ''))
        .then(d => {
          if (!execVx) return;
          if (!d || d.error) { document.getElementById('evxBody').textContent = (d && d.error) || 'Failed to load'; return; }
          execVx.data = d;
          _evxRender();
        })
        .catch(e => { document.getElementById('evxBody').textContent = _execDetailErrText(e); });
    }

    // _evxOpts renders <option>s, marking the selected one.
    function _evxOpts(values, cur) {
      return values.map(v => '<option value="' + esc(v) + '"' + (v === cur ? ' selected' : '') + '>'
        + esc(v || '—') + '</option>').join('');
    }

    function _evxField(label, html, hint) {
      return '<div class="form-group"><label class="form-label">' + label + '</label>' + html
        + (hint ? '<div class="form-hint">' + hint + '</div>' : '') + '</div>';
    }

    function _evxRender() {
      const d = execVx.data;
      const cur = (d.virtual_executors || []).find(v => v.id === execVx.edit) || {spec: {sandbox: {}}};
      const sp = cur.spec, sb = sp.sandbox || {}, fw = sp.firewall;
      const lines = a => esc((a || []).join('\n'));
      const chosen = {};
      (sp.devices || []).forEach(x => { if (x.usb) chosen[x.usb.vendor_id + ':' + x.usb.product_id + ':' + (x.usb.serial || '')] = x; });
      // Whether the device can install a firewall is said under the Firewalled
      // choice (_evxNet), where it decides something, rather than up here.
      // unsupported_note is the hub's sentence for an agent too old to apply a
      // firewall or devices: which protocol it speaks, which one that needs, and
      // the remedy for the hub's own build — none of which this script can know.
      let h = '<div class="form-hint" style="margin-bottom:10px">' + esc(d.name) + ' · '
        + (d.connected ? 'connected, protocol v' + esc(d.protocol_version) : 'offline — showing its last report')
        + (d.unsupported_note ? '<br><b>' + esc(d.unsupported_note) + '</b>' : '') + '</div>';
      // The device's own rule set, read-only (Task 20363): every network chosen
      // below has to fit inside it. It is edited from the device's Firewall button.
      if (d.device_firewall) {
        h += '<div class="form-hint" style="margin-bottom:10px"><b>Device firewall</b>: ' + esc(_fwSum(d.device_firewall))
          + '. Each virtual executor’s network must fit inside it.</div>';
      }
      h += (d.virtual_executors || []).map((v, i) => '<div class="exec-chips">'
        + '<span class="exec-chip' + (v.id === execVx.edit ? ' pos' : '') + '">' + esc(v.name) + ' · ' + esc(v.id) + '</span>'
        + (v.issue ? '<span class="exec-chip neg" title="' + esc(v.issue) + '">cannot apply</span>' : '')
        + (v.exceeds_device ? '<span class="exec-chip neg" title="' + esc(v.exceeds_device.join('; '))
          + '">exceeds device firewall</span>' : '')
        + (v.metadata ? '<span class="exec-chip neg" title="' + esc(v.metadata.join('; '))
          + '">contains a metadata service</span>' : '')
        + (v.isolation_evidence ? _isoChip(v.isolation_evidence) : '')
        + '<button class="btn" style="padding:2px 8px;font-size:11px" data-act="editExecutorVirtual" data-arg="' + i + '">Edit</button>'
        + (v.isolation_evidence ? '<button class="btn" style="padding:2px 8px;font-size:11px" data-act="reprobeExecutorVirtual" data-arg="'
          + i + '" title="Run the isolation probe under this runtime now">Re-probe</button>' : '') + '</div>').join('');
      h += '<h3 style="font-size:13px;margin:12px 0 4px">USB devices on ' + esc(d.name)
        + ' <button class="btn" style="padding:2px 8px;font-size:11px" data-act="refreshExecutorVirtual">Refresh</button></h3>';
      if (d.usb_error) h += '<div class="form-hint">' + esc(d.usb_error) + '</div>';
      const usb = (d.usb_devices || []).filter(u => u.class !== '09');
      h += usb.length ? usb.map((u, i) => {
        const k = u.vendor_id + ':' + u.product_id + ':' + (u.serial || '');
        const perm = u.mode ? ' · ' + esc(u.mode) + (u.group ? ' ' + esc(u.group) : '') : '';
        return '<label style="display:block;font-size:12px;margin:3px 0"><input type="checkbox" id="evxUsb' + i + '"'
          + (chosen[k] ? ' checked' : '') + '> ' + esc(((u.manufacturer || '') + ' ' + (u.product || '')).trim() || 'USB device')
          + ' <code>' + esc(u.vendor_id + ':' + u.product_id) + '</code>' + (u.serial ? ' serial ' + esc(u.serial) : '')
          + ' <span style="color:var(--muted)">' + esc(u.node) + ' port ' + esc(u.port) + perm + '</span></label>';
      }).join('') : '<div class="form-hint">No USB devices reported.</div>';
      const g = (sp.devices || []).find(x => x.group);
      h += _evxField('Device group', '<input class="form-input" id="evxGroup" value="' + esc(g ? g.group : '') + '" placeholder="plugdev">',
        'The group the device nodes belong to (set by a udev rule), so the unprivileged sandbox user can open them read-write. Never root.');
      h += _evxField('Other device nodes', '<textarea class="form-input" id="evxPaths" rows="2" placeholder="/dev/ttyS0">'
        + lines((sp.devices || []).filter(x => x.path).map(x => x.path)) + '</textarea>');
      h += '<h3 style="font-size:13px;margin:12px 0 4px">' + (execVx.edit ? 'Edit ' + esc(cur.name) : 'New virtual executor') + '</h3>';
      h += _evxField('Name', '<input class="form-input" id="evxName" value="' + esc(cur.name || '') + '" placeholder="HSM sandbox">');
      h += '<div class="form-row">' + _evxField('Engine', '<select class="form-select" id="evxEngine">'
          + _evxOpts([''].concat(d.engines || []), sb.engine || '') + '</select>')
        + _evxField('Runtime', '<input class="form-input" id="evxRuntime" list="evxRuntimes" value="' + esc(sb.runtime || '')
          + '" placeholder="engine default"><datalist id="evxRuntimes">' + _evxOpts(d.oci_runtimes || [], '') + '</datalist>')
        + '</div>';
      h += _evxField('Image', '<input class="form-input" id="evxImage" value="' + esc(sb.image || '') + '" placeholder="the device default">');
      h += _fwMeta(cur.metadata);
      h += _evxNet(d, sb, fw);
      h += '<div class="modal-footer">'
        + (execVx.edit ? '<button class="btn danger" data-act="deleteExecutorVirtual">Delete</button>'
          + '<button class="btn" data-act="editExecutorVirtual" data-arg="-1">New</button>' : '')
        + '<button class="btn primary" data-act="saveExecutorVirtual">' + (execVx.edit ? 'Save' : 'Create') + '</button></div>';
      document.getElementById('evxBody').innerHTML = h;
      evxSync();
    }

    // _evxNet renders the network access choice (Task 20356).
    //
    // It used to be a Network select, then an "IP firewall" checkbox, then the
    // rules — all on screen and editable at once. Nothing said whether "Allow the
    // public Internet" needed the firewall, or whether an allowlist typed with the
    // firewall off did anything (it did not: save dropped it). The three ways a
    // sandbox can be networked are now one choice, and the rules are on screen only
    // under the choice that applies them. The order is the order of reach.
    //
    // A named network (one an operator created on the device) is Unfiltered with
    // that name; the old select could not show one, so saving an edit reset it to
    // none.
    function _evxNet(d, sb, fw) {
      const net = sb.network || 'none', mode = fw ? 'fw' : net === 'none' ? 'none' : 'open';
      // A new firewall starts as the device's own rules when it has some: the
      // widest rule set that fits, for the admin to narrow (Task 20363).
      const f = fw || d.device_firewall || {allow_public_internet: true, resolvers: ['1.1.1.1']};
      const lines = a => esc((a || []).join('\n'));
      const ev = ' data-input="evxSync"';
      const opt = (m, id, title, text, off) => '<label class="sec-own-opt"><input type="radio" name="evxNet" id="' + id + '"'
        + (m === mode ? ' checked' : '') + (off ? ' disabled' : '') + ' data-change="evxSync"><span><strong>' + title
        + '</strong> — ' + text + '</span></label>';
      // Rendered in the state evxSync would leave it in, so nothing flashes.
      const sub = (id, m, html) => '<div class="evx-sub" id="' + id + '"' + (m === mode ? '' : ' style="display:none"') + '>' + html + '</div>';
      return '<div class="form-group"><label class="form-label">Network access</label>'
        + opt('none', 'evxNetNone', 'No network', 'no interface at all. Sandboxes cannot clone a repository, reach the git '
          + 'proxy or resolve a name.')
        + opt('fw', 'evxNetFw', 'Firewalled', 'a bridge of this executor’s own, filtered on ' + esc(d.name) + ' before any '
          + 'sandbox joins it. Nothing is reachable unless a rule below allows it.')
        + (d.packet_filter ? '' : '<div class="evx-sub form-hint" style="color:var(--yellow)">&#9888; <b>' + esc(d.name)
          + ' cannot install a firewall</b>: '
          + esc(d.packet_filter_issue || 'not reported') + '. Work sent here is refused, never run unfiltered, until it can.</div>')
        + sub('evxFwRules', 'fw', '<label class="sec-own-opt"><input type="checkbox" id="evxPublic"'
          + (f.allow_public_internet ? ' checked' : '') + ' data-change="evxSync"><span><strong>Allow the public Internet</strong> — '
          + 'every public address, over TCP. Private (RFC 1918), link-local, CGNAT, loopback and multicast addresses stay '
          + 'closed unless the allowlist names them, and a cloud metadata service unless it names its own address — a '
          + 'range around one is refused until it is named or denied.</span></label>'
          + '<div class="form-row">' + _evxField('Allowlist', '<textarea class="form-input" id="evxAllow" rows="3" placeholder="10.8.0.0/24"'
            + ev + '>' + lines(f.allow_cidrs) + '</textarea>', 'Also reachable, private ranges included.')
          + _evxField('Denylist', '<textarea class="form-input" id="evxDeny" rows="3" placeholder="203.0.113.0/24"' + ev + '>'
            + lines(f.deny_cidrs) + '</textarea>', 'Never reachable, over any protocol: checked before every allow, the '
            + 'resolvers included.') + '</div>'
          + '<div class="form-row">' + _evxField('Ports', '<input class="form-input" id="evxPorts" value="'
            + esc((f.allow_ports || []).join(', ')) + '" placeholder="all ports"' + ev + '>',
            'Limits the public Internet and the allowlist to these TCP ports. Empty means every port.')
          + _evxField('DNS resolvers', '<input class="form-input" id="evxDns" value="' + esc((f.resolvers || []).join(', '))
            + '"' + ev + '>', 'Reachable for DNS over UDP and TCP, and what sandboxes resolve names through.') + '</div>'
          + '<label class="sec-own-opt"><input type="checkbox" id="evxDrop"' + (f.drop_denied ? ' checked' : '')
          + ' data-change="evxSync"><span><strong>Drop denied connections silently</strong> — instead of refusing them at once with a reset or '
          + 'an ICMP “administratively prohibited”, so a sandbox cannot tell a filtered destination from one that is '
          + 'not there, and waits out its own timeout instead.</span></label>'
          + '<div class="evx-sum" id="evxFwSum"></div>')
        + opt('open', 'evxNetOpen', 'Unfiltered', d.device_firewall ? 'not available: the device’s firewall bounds every sandbox on it.'
          : 'a network of the engine’s, with no firewall. On <code>bridge</code>, sandboxes reach '
          + 'whatever ' + esc(d.name) + ' can, private networks and the cloud metadata service included.', !!d.device_firewall)
        + sub('evxOpenNet', 'open', _evxField('Network', '<input class="form-input" id="evxNetName" list="evxNetNames" value="'
          + esc(mode === 'open' ? net : 'bridge') + '"><datalist id="evxNetNames"><option value="bridge"></datalist>',
          '<code>bridge</code>, or a network created on the device.'))
        + '</div>';
    }

    function _evxMode() {
      const on = id => (document.getElementById(id) || {}).checked;
      return on('evxNetFw') ? 'fw' : on('evxNetOpen') ? 'open' : 'none';
    }

    // evxSync shows the settings of the chosen network access and hides the others,
    // then reads the firewall rules back as a sentence. Hidden values are kept, so
    // switching away and back loses no typing; save sends only the chosen one's.
    function evxSync() {
      const m = _evxMode(), sum = document.getElementById('evxFwSum');
      [['evxFwRules', 'fw'], ['evxOpenNet', 'open']].forEach(p => {
        const e = document.getElementById(p[0]);
        if (e) e.style.display = m === p[1] ? '' : 'none';
      });
      if (!sum) return;
      const s = _evxFwSum();
      sum.innerHTML = s[1];
      sum.classList.toggle('warn', s[0]);
    }

    // _evxFwSum says what the rules let through, in the order the device applies
    // them (netfilter.Compile): the denylist, then the allows, then a drop for
    // everything else. Allows are TCP; only the resolvers are open to UDP. Returns
    // [warn, html].
    function _evxFwSum() {
      const to = [], allow = _evxList('evxAllow'), deny = _evxList('evxDeny'), ports = _evxList('evxPorts'), dns = _evxList('evxDns');
      if ((document.getElementById('evxPublic') || {}).checked) to.push('the public Internet');
      if (allow.length) to.push(allow.join(', '));
      if (!to.length && !dns.length) {
        // The agent turns this into no network at all (egressFilterFor).
        return [true, '<b>In effect:</b> nothing is allowed, so sandboxes get no network at all — the same as <b>No network</b>.'];
      }
      let s = '<b>In effect:</b> ' + (to.length
        ? 'sandboxes can open TCP connections to ' + esc(to.join(' and ')) + ' on '
          + (ports.length ? 'port' + (ports.length > 1 ? 's ' : ' ') + esc(ports.join(', ')) : 'any port')
          + (dns.length ? ', and query DNS at ' + esc(dns.join(', ')) : '') + '.'
        : 'sandboxes can only query DNS at ' + esc(dns.join(', ')) + '.');
      if (deny.length) s += ' Never reachable: ' + esc(deny.join(', ')) + '.';
      s += (document.getElementById('evxDrop') || {}).checked
        ? ' Everything else is dropped silently.'
        : ' Everything else is refused at once, and shown on the run that tried it.';
      const noDNS = to.length > 0 && !dns.length;
      return [noDNS, noDNS ? s + ' <b>With no DNS resolver, host names will not resolve.</b>' : s];
    }

    // Index-based, like every other handler in this file: see _renderExecutors.
    function editExecutorVirtual(i) {
      if (!execVx || !execVx.data) return;
      const v = (execVx.data.virtual_executors || [])[i];
      execVx.edit = v ? v.id : '';
      _evxRender();
    }

    // _evxList splits a textarea or a comma list into trimmed entries.
    function _evxList(id) {
      return ((document.getElementById(id) || {}).value || '').split(/[\s,]+/).map(x => x.trim()).filter(Boolean);
    }

    function _evxVal(id) { return ((document.getElementById(id) || {}).value || '').trim(); }

    function saveExecutorVirtual() {
      const d = execVx && execVx.data;
      if (!d) return;
      const group = _evxVal('evxGroup');
      const devices = [];
      (d.usb_devices || []).filter(u => u.class !== '09').forEach((u, i) => {
        const box = document.getElementById('evxUsb' + i);
        if (!box || !box.checked) return;
        const base = ((u.product || 'usb') + '').toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^[^a-z0-9]+/, '') || 'usb';
        devices.push({name: (base + '-' + i).slice(0, 60), group: group,
          usb: {vendor_id: u.vendor_id, product_id: u.product_id, serial: u.serial || ''}});
      });
      _evxList('evxPaths').forEach((p, i) => devices.push({name: 'dev-' + i + '-' + p.split('/').pop(), path: p, group: group}));
      const m = _evxMode();
      const spec = {
        sandbox: {mode: 'container', engine: _evxVal('evxEngine'), runtime: _evxVal('evxRuntime'), image: _evxVal('evxImage'),
          network: m === 'fw' ? '' : m === 'open' ? _evxVal('evxNetName') || 'bridge' : 'none'},
        devices: devices,
      };
      // Only the chosen access is sent. Rules left under Firewalled after choosing
      // another are not applied — and are off screen, so the form never shows a
      // rule that is not in force.
      if (m === 'fw') {
        spec.firewall = {
          allow_public_internet: !!(document.getElementById('evxPublic') || {}).checked,
          allow_cidrs: _evxList('evxAllow'), deny_cidrs: _evxList('evxDeny'),
          allow_ports: _evxList('evxPorts').map(Number), resolvers: _evxList('evxDns'),
          drop_denied: !!(document.getElementById('evxDrop') || {}).checked,
        };
      }
      const body = {name: _evxVal('evxName'), spec: spec};
      const call = execVx.edit
        ? apiMethod('PUT', '/api/executors/' + encodeURIComponent(execVx.edit) + '/virtual', body)
        : api('/api/executors/' + encodeURIComponent(execVx.parent) + '/virtuals', body);
      call.then(r => {
        if (!r || r.error) { toast((r && r.error) || 'Failed to save the virtual executor', 'err'); return; }
        toast('Virtual executor ' + (r.name || r.id) + ' saved', 'ok');
        execVx.edit = r.id;
        _evxLoad(false);
        loadExecutors();
      }).catch(e => toast(_execDetailErrText(e) || 'Failed to save the virtual executor', 'err'));
    }

    function deleteExecutorVirtual() {
      const id = execVx && execVx.edit;
      if (!id || !confirm('Delete virtual executor ' + id + '?\n\nProjects bound to it are unbound; running tasks finish.')) return;
      apiMethod('DELETE', '/api/executors/' + encodeURIComponent(id) + '/virtual').then(r => {
        if (!r || r.error) { toast((r && r.error) || 'Failed to delete', 'err'); return; }
        toast('Virtual executor ' + id + ' deleted', 'ok');
        execVx.edit = '';
        _evxLoad(false);
        loadExecutors();
      }).catch(e => toast(_execDetailErrText(e) || 'Failed to delete', 'err'));
    }


    // ── A device's rule set ─────────────────────────────────────────────────────

    // efwTarget is the executor the dialog edits, held by ID for the reason
    // execLimitsTarget is: the list may reorder while the dialog is open.
    let efwTarget = null;

    function openExecutorFirewall(idx) {
      const ex = _execAt(idx);
      if (!ex) return;
      efwTarget = {id: ex.id, name: ex.name || ex.id};
      document.getElementById('efwBody').innerHTML = '<div class="form-hint">Loading…</div>';
      openOverlay('executor-firewall-overlay', {dismiss: closeExecutorFirewall});
      api('/api/executors/' + encodeURIComponent(ex.id) + '/firewall')
        .then(d => _efwRender(d, ''))
        .catch(e => _efwRender({error: _execDetailErrText(e)}, ''));
    }

    function closeExecutorFirewall() {
      closeOverlay('executor-firewall-overlay');
      efwTarget = null;
    }

    function _efwRender(d, note) {
      const body = document.getElementById('efwBody');
      if (!body || !efwTarget) return;
      if (!d || d.error) { body.innerHTML = _fwRefusal(d); return; }
      efwTarget.configured = d.configured;
      let h = '<div class="form-hint">The most any sandbox on ' + esc(efwTarget.name) + ' may reach. Its virtual '
        + 'executors’ firewalls and its projects’ rules can only narrow this. '
        + (d.configured ? 'Set by ' + esc(d.set_by || 'an admin') + '.' : '<b>No rule set: nothing here bounds it.</b>') + '</div>';
      if (d.config) h += '<div class="form-hint">Its configuration file allows at most: ' + esc(_fwSum(d.config)) + '.</div>';
      if (d.warning) h += '<div class="form-hint" style="color:var(--yellow)">&#9888; ' + esc(d.warning) + '</div>';
      h += _fwMeta(d.metadata);
      h += note + '<div id="efwWarn"></div>';
      h += _fwForm('efw', d.configured ? d.rules : {allow_public_internet: true, allow_ports: [443], resolvers: ['1.1.1.1']});
      const kids = d.children || [];
      if (kids.length) {
        h += '<div class="form-hint">Bounded by it: ' + kids.map(c => esc(c.kind === 'virtual' ? (c.name || c.id) : c.id)
          + (c.fits ? '' : ' <b style="color:var(--red)" title="' + esc((c.reasons || []).join('; ')) + '">(exceeds it)</b>')
          + (c.metadata ? ' <b style="color:var(--yellow)" title="' + esc(c.metadata.join('; '))
            + '">(contains a metadata service)</b>' : ''))
          .join(', ') + '</div>';
      }
      h += '<div class="modal-footer">'
        + (d.configured ? '<button class="btn danger" data-act="clearExecutorFirewall">Remove rules</button>' : '')
        + '<button class="btn" data-act="closeExecutorFirewall">Close</button>'
        + '<button class="btn primary" data-act="saveExecutorFirewall">Save</button></div>';
      body.innerHTML = h;
      fwSync('efw');
    }

    function _efwSave(payload) {
      const t = efwTarget;
      if (!t) return;
      apiMethod('PUT', '/api/executors/' + encodeURIComponent(t.id) + '/firewall', payload)
        .then(d => {
          if (!d || d.error) {
            const w = document.getElementById('efwWarn');
            if (w) w.innerHTML = _fwRefusal(d);
            return;
          }
          const n = d.constrained || [];
          _efwRender(d, n.length ? '<div class="form-hint" style="color:var(--yellow)">Narrowed to fit: '
            + n.map(c => '<b>' + esc(c.name || c.subject) + '</b> — ' + esc((c.notes || []).join('; '))).join('<br>')
            + '</div>' : '');
          toast(payload.clear ? 'Firewall removed from ' + t.name
            : 'Firewall saved for ' + t.name + (n.length ? ' · ' + n.length + ' rule set(s) narrowed' : ''), 'ok');
          loadExecutors();
        })
        .catch(e => toast(_execDetailErrText(e) || 'Save failed', 'err'));
    }

    function saveExecutorFirewall() { _efwSave(_fwRead('efw')); }

    function clearExecutorFirewall() {
      if (efwTarget && confirm('Remove the firewall rule set on ' + efwTarget.name + '?\n\nIts sandboxes will be '
          + 'bounded only by their own firewalls and its configuration.')) {
        _efwSave({clear: true});
      }
    }


    // ── Resource ceiling and access list (Task 20310) ───────────────────────────
    //
    // The two policies a hub holds *about* an executor that the Sandbox dialog
    // above does not cover: how much any one workload on it may be given, and who
    // may run work on it at all.
    //
    // Both dialogs follow the Sandbox one's shape deliberately — hold the target
    // rather than the card index, clear the form before the fetch, and render the
    // backend's own vocabulary rather than a hardcoded copy — because the reasons
    // it does those things apply identically here.

    // execLimitsTarget / execAudienceTarget are the executors the open dialogs are
    // editing. Held rather than re-derived from the card index for the reason
    // execSandboxTarget is: loadExecutors may reorder the list while a dialog is
    // open, and saving into whichever executor now sits at that index would be the
    // worst possible outcome of a race.
    let execLimitsTarget = null;
    let execAudienceTarget = null;

    // _execFmtMB renders a megabyte count the way an admin would type it back in,
    // so a form that was saved as "8g" does not reopen reading "8192".
    function _execFmtMB(mb) {
      if (!mb) return '';
      if (mb % 1024 === 0) return (mb / 1024) + 'g';
      return mb + 'm';
    }

    function openExecutorLimits(idx) {
      const ex = _execAt(idx);
      if (!ex) return;
      execLimitsTarget = {id: ex.id, name: ex.name || ex.id};

      const sub = document.getElementById('execLimitsSub');
      if (sub) sub.textContent = ex.id + ' · ' + _execKindLabel(ex.kind);
      _execLimitsWarn('');
      _execLimitsUntouch();
      _execLimitsFill({ceiling: {}, fleet: {}});
      openOverlay('executor-limits-overlay', {dismiss: closeExecutorLimits});

      api('/api/executors/' + encodeURIComponent(ex.id) + '/limits')
        .then(d => {
          if (!d || d.error) {
            _execLimitsWarn((d && d.error) || 'Could not read this executor’s resource ceiling.');
            return;
          }
          _execLimitsFill(d);
        })
        .catch(err => _execLimitsWarn(_execDetailErrText(err)
          || 'Could not read this executor’s resource ceiling.'));
    }

    function closeExecutorLimits() {
      closeOverlay('executor-limits-overlay');
      execLimitsTarget = null;
    }

    // The dialog opens before the stored ceiling arrives, so a field typed
    // into in between must not be overwritten by it — the stored value, or a
    // blank, would then be what Save sends.
    const _execLimitsFields = ['execLimitsCPU', 'execLimitsMemory', 'execLimitsDisk', 'execLimitsPIDs'];
    function _execLimitsUntouch() {
      _execLimitsFields.forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        el.dataset.touched = '';
        if (!el.dataset.watched) {
          el.dataset.watched = '1';
          el.addEventListener('input', () => { el.dataset.touched = '1'; });
        }
      });
    }
    function _execLimitsSet(id, value) {
      const el = document.getElementById(id);
      if (el && el.dataset.touched !== '1') el.value = value;
    }

    function _execLimitsWarn(text) {
      const el = document.getElementById('execLimitsWarn');
      if (!el) return;
      if (!text) { el.style.display = 'none'; el.textContent = ''; return; }
      el.style.display = '';
      el.textContent = text;
    }

    function _execLimitsFill(d) {
      const c = (d && d.ceiling) || {};
      _execLimitsSet('execLimitsCPU', c.cpu_millis ? (c.cpu_millis / 1000) : '');
      _execLimitsSet('execLimitsMemory', _execFmtMB(c.memory_mb));
      _execLimitsSet('execLimitsDisk', _execFmtMB(c.disk_mb));
      _execLimitsSet('execLimitsPIDs', c.pids || '');

      const hint = document.getElementById('execLimitsHint');
      if (hint) {
        hint.textContent = d && d.configured
          ? 'Set by ' + (d.set_by || 'an admin') + (d.set_at ? ' · ' + relTime(new Date(d.set_at)) : '')
          : 'No ceiling — workloads here are bounded only by the hub-wide limit, if there is one.';
      }

      // The fleet ceiling, shown because the tighter of the two wins. An admin who
      // cannot see it would set 16g here, read it back as 16g, and watch workloads
      // get 8 — and have no way to discover why.
      const fleet = document.getElementById('execLimitsFleet');
      if (fleet) {
        const f = (d && d.fleet) || {};
        const parts = [];
        if (f.cpu_millis) parts.push((f.cpu_millis / 1000) + ' cores');
        if (f.memory_mb) parts.push(_execFmtMB(f.memory_mb) + ' memory');
        if (f.disk_mb) parts.push(_execFmtMB(f.disk_mb) + ' disk');
        if (f.pids) parts.push(f.pids + ' processes');
        fleet.textContent = parts.length
          ? 'Hub-wide ceiling: ' + parts.join(', ') + '. The tighter of the two applies.'
          : 'No hub-wide ceiling is configured, so this one applies on its own.';
      }

      // Whether the device will actually hold a workload to the number. A remote
      // agent reports its capacity for placement and then runs the payload without
      // confining it, and an admin who is not told that has a cap they believe in
      // rather than one they have.
      if (d && d.configured && d.enforced === false) {
        _execLimitsWarn('This executor does not enforce resource limits: the ceiling will be recorded '
          + 'on each run’s spec but nothing will hold the workload to it. Bind projects to a container '
          + 'or Kubernetes executor for an enforced cap.');
      } else if (d && ((d.effective || {}).disk_mb || 0) > 0 && !d.disk_enforcement) {
        // Task 20405: limits enforced, disk not — a device on an agent older
        // than protocol v20, or one running payloads on its host.
        _execLimitsWarn('This executor does not hold a workload to a disk limit, so the disk ceiling '
          + 'will not bound runs here; each run’s journal says so. Upgrade the device’s agent, or run '
          + 'its payloads in a container.');
      }
    }

    function saveExecutorLimits() {
      const t = execLimitsTarget;
      if (!t) return;
      const payload = {
        max_cpu:    parseFloat((document.getElementById('execLimitsCPU') || {}).value || '0') || 0,
        max_memory: ((document.getElementById('execLimitsMemory') || {}).value || '').trim(),
        max_disk:   ((document.getElementById('execLimitsDisk') || {}).value || '').trim(),
        max_pids:   parseInt((document.getElementById('execLimitsPIDs') || {}).value || '0', 10) || 0,
      };
      apiMethod('PUT', '/api/executors/' + encodeURIComponent(t.id) + '/limits', payload)
        .then(d => {
          if (!d || d.error) { toast((d && d.error) || 'Failed to save resource ceiling', 'err'); return; }
          toast('Resource ceiling saved for ' + t.name, 'ok');
          closeExecutorLimits();
          loadExecutors();
        })
        .catch(err => toast(_execDetailErrText(err) || 'Failed to save resource ceiling', 'err'));
    }

    function clearExecutorLimits() {
      const t = execLimitsTarget;
      if (!t) return;
      if (!confirm('Remove the resource ceiling on ' + t.name + '?\n\nWorkloads here will be bounded '
          + 'only by the hub-wide limit, if one is configured.')) {
        return;
      }
      apiMethod('PUT', '/api/executors/' + encodeURIComponent(t.id) + '/limits', {clear: true})
        .then(d => {
          if (!d || d.error) { toast((d && d.error) || 'Failed to clear', 'err'); return; }
          toast('Resource ceiling removed from ' + t.name, 'ok');
          closeExecutorLimits();
          loadExecutors();
        })
        .catch(() => toast('Failed to clear resource ceiling', 'err'));
    }

    // ── Access list ─────────────────────────────────────────────────────────────

    function openExecutorAudience(idx) {
      const ex = _execAt(idx);
      if (!ex) return;
      execAudienceTarget = {id: ex.id, name: ex.name || ex.id};

      const sub = document.getElementById('execAudienceSub');
      if (sub) sub.textContent = ex.id + ' · ' + _execKindLabel(ex.kind);
      _execAudienceWarn('');
      _execAudienceFill({members: [], restricted: false});
      openOverlay('executor-audience-overlay', {dismiss: closeExecutorAudience});
      _execAudienceLoad(ex.id);
    }

    function _execAudienceLoad(id) {
      api('/api/executors/' + encodeURIComponent(id) + '/audience')
        .then(d => {
          if (!d || d.error) {
            _execAudienceWarn((d && d.error) || 'Could not read this executor’s access list.');
            return;
          }
          _execAudienceFill(d);
        })
        .catch(err => _execAudienceWarn(_execDetailErrText(err)
          || 'Could not read this executor’s access list.'));
    }

    function closeExecutorAudience() {
      closeOverlay('executor-audience-overlay');
      execAudienceTarget = null;
    }

    // ── Labels (Task 20432) ─────────────────────────────────────────────────────
    //
    // A device's labels are what a grant to label:region=eu,… is matched
    // against: chosen at enrollment, changed here. The hub audits the edit and
    // takes back, from every running task on the device or its virtual
    // executors, a label grant the new labels no longer match.
    let execLabelsTarget = null;

    function openExecutorLabels(idx) {
      const ex = _execAt(idx);
      if (!ex) return;
      execLabelsTarget = {id: ex.id};
      const sub = document.getElementById('execLabelsSub');
      if (sub) sub.textContent = ex.id + ' · ' + _execKindLabel(ex.kind);
      const input = document.getElementById('execLabelsInput');
      if (input) {
        const labels = ex.labels || {};
        input.value = Object.keys(labels).sort().map(k => k + '=' + labels[k]).join(', ');
      }
      _execLabelsNote('');
      openOverlay('executor-labels-overlay', {dismiss: closeExecutorLabels, focus: '#execLabelsInput'});
    }

    function closeExecutorLabels() {
      closeOverlay('executor-labels-overlay');
      execLabelsTarget = null;
    }

    function _execLabelsNote(text) {
      const el = document.getElementById('execLabelsNote');
      if (!el) return;
      el.style.display = text ? '' : 'none';
      el.textContent = text || '';
    }

    // _execLabelsParse reads "k=v, k2=v2" into a map, or throws naming the pair
    // that is not one. A value may contain '=': a selector splits at the first.
    function _execLabelsParse(text) {
      const out = {};
      String(text || '').split(/[,\n]/).map(p => p.trim()).filter(Boolean).forEach(p => {
        const at = p.indexOf('=');
        if (at <= 0) throw new Error('"' + p + '" is not key=value');
        out[p.slice(0, at).trim()] = p.slice(at + 1).trim();
      });
      return out;
    }

    function saveExecutorLabels() {
      const t = execLabelsTarget;
      if (!t) return;
      let labels;
      try {
        labels = _execLabelsParse((document.getElementById('execLabelsInput') || {}).value);
      } catch (e) {
        _execLabelsNote(e.message);
        return;
      }
      apiMethod('PUT', '/api/executors/' + encodeURIComponent(t.id) + '/labels', {labels}).then(d => {
        if (!d || d.error) {
          _execLabelsNote(_execDetailErrText(d && d.error) || 'Could not save the labels.');
          return;
        }
        const taken = ((d.recheck || {}).taken_back || []).length;
        toast(taken
          ? 'Labels saved; ' + taken + ' credential' + (taken === 1 ? '' : 's') + ' taken back from running work'
          : 'Labels saved', 'ok');
        closeExecutorLabels();
        loadExecutors();
      }).catch(err => _execLabelsNote(_execDetailErrText(err) || 'Could not save the labels.'));
    }

    function _execAudienceWarn(text) {
      const el = document.getElementById('execAudienceWarn');
      if (!el) return;
      if (!text) { el.style.display = 'none'; el.textContent = ''; return; }
      el.style.display = '';
      el.textContent = text;
    }

    // _execAudienceMembers is the list the open dialog is showing. The remove
    // buttons dispatch by index into it rather than interpolating the principal
    // into an onclick attribute — a group path or an email is attacker-influenced
    // text, and Tasks 163/20033 are what that costs.
    let _execAudienceMembers = [];

    function _execAudienceFill(d) {
      _execAudienceMembers = (d && d.members) || [];
      const box = document.getElementById('execAudienceList');
      if (box) {
        if (!_execAudienceMembers.length) {
          box.innerHTML = '<div style="color:var(--muted);font-size:12.5px;padding:6px 0">'
            + 'Unrestricted — every user who can reach this hub may run work here. '
            + 'Add a user or group below to restrict it.</div>';
        } else {
          let h = '';
          _execAudienceMembers.forEach((m, i) => {
            h += '<div style="display:flex;align-items:center;gap:8px;padding:5px 0;'
              + 'border-bottom:1px solid var(--border)">'
              + '<span class="badge" style="font-size:10.5px">' + esc(m.kind || '') + '</span>'
              + '<span style="flex:1;font-size:12.5px">' + esc(m.value || '') + '</span>'
              + '<span style="font-size:11px;color:var(--muted)">'
              + esc(m.added_by || '') + '</span>'
              + '<button class="btn danger" style="padding:2px 8px;font-size:11px" '
              + 'data-act="removeExecutorAudience" data-arg="' + i + '">Remove</button>'
              + '</div>';
          });
          box.innerHTML = h;
        }
      }

      const state = document.getElementById('execAudienceState');
      if (state) {
        if (!(d && d.restricted)) {
          state.textContent = 'This executor is available to everyone on the hub.';
        } else if (d.caller_admitted === false) {
          // Managing an executor and being allowed to use it are separate rights,
          // so this is a reachable and legitimate state — but an admin who is not
          // told would discover it at their next run instead.
          state.textContent = 'Restricted to ' + _execAudienceMembers.length + ' principal'
            + (_execAudienceMembers.length === 1 ? '' : 's')
            + '. You are not on this list, so you cannot run work here yourself.';
        } else {
          state.textContent = 'Restricted to ' + _execAudienceMembers.length + ' principal'
            + (_execAudienceMembers.length === 1 ? '' : 's') + ', including you.';
        }
      }
    }

    function addExecutorAudience() {
      const t = execAudienceTarget;
      if (!t) return;
      const kind = (document.getElementById('execAudienceKind') || {}).value || 'group';
      const value = ((document.getElementById('execAudienceValue') || {}).value || '').trim();
      if (!value) {
        _execAudienceWarn('Enter a group name, email address or subject to admit.');
        return;
      }
      _execAudienceWarn('');
      apiMethod('POST', '/api/executors/' + encodeURIComponent(t.id) + '/audience',
          {kind: kind, value: value})
        .then(d => {
          if (!d || d.error) {
            _execAudienceWarn((d && d.error) || 'Failed to admit that principal.');
            return;
          }
          const input = document.getElementById('execAudienceValue');
          if (input) input.value = '';
          _execAudienceFill(d);
          toast('Admitted ' + value + ' to ' + t.name, 'ok');
          loadExecutors();
        })
        .catch(err => _execAudienceWarn(_execDetailErrText(err) || 'Failed to admit that principal.'));
    }

    function removeExecutorAudience(i) {
      const t = execAudienceTarget;
      const m = _execAudienceMembers[i];
      if (!t || !m) return;
      // Named in the prompt, because withdrawing the last entry does not narrow
      // this executor — it opens it to the whole hub, which is the opposite of
      // what "Remove" reads like.
      const last = _execAudienceMembers.length === 1;
      const msg = last
        ? 'Remove ' + m.value + ' from ' + t.name + '?\n\nIt is the only entry, so this executor '
          + 'will become available to every user on the hub.'
        : 'Remove ' + m.value + ' from ' + t.name + '?';
      if (!confirm(msg)) return;

      apiMethod('DELETE', '/api/executors/' + encodeURIComponent(t.id) + '/audience',
          {kind: m.kind, value: m.value})
        .then(d => {
          if (!d || d.error) {
            _execAudienceWarn((d && d.error) || 'Failed to withdraw that principal.');
            return;
          }
          _execAudienceFill(d);
          toast('Withdrew ' + m.value + ' from ' + t.name, 'ok');
          loadExecutors();
        })
        .catch(err => _execAudienceWarn(_execDetailErrText(err) || 'Failed to withdraw that principal.'));
    }


    // ── Enrollment ──────────────────────────────────────────────────────────────
    function openEnrollModal() {
      const form = document.getElementById('enrollForm');
      const result = document.getElementById('enrollResult');
      const err = document.getElementById('enrollError');
      if (form) form.style.display = 'block';
      if (result) result.style.display = 'none';
      if (err) err.style.display = 'none';
      const name = document.getElementById('enrollName');
      if (name) name.value = '';
      const ttl = document.getElementById('enrollTTL');
      if (ttl) ttl.value = '';
      const root = document.getElementById('enrollRoot');
      if (root) root.value = '';
      const labels = document.getElementById('enrollLabels');
      if (labels) labels.value = '';
      openOverlay('enroll-overlay', {dismiss: closeEnrollModal, focus: name});
    }

    function closeEnrollModal() {
      closeOverlay('enroll-overlay');
      // Refresh on close so a token minted moments ago is reflected even before
      // the device redeems it.
      loadExecutors();
    }

    function submitEnroll() {
      const errEl = document.getElementById('enrollError');
      const btn = document.getElementById('enrollSubmitBtn');
      const body = {
        name: (document.getElementById('enrollName') || {}).value || '',
        workdir_root: (document.getElementById('enrollRoot') || {}).value || ''
      };
      const ttlRaw = (document.getElementById('enrollTTL') || {}).value;
      if (ttlRaw) body.ttl_minutes = parseInt(ttlRaw, 10);
      try {
        body.labels = _execLabelsParse((document.getElementById('enrollLabels') || {}).value);
      } catch (e) {
        if (errEl) { errEl.textContent = e.message; errEl.style.display = 'block'; }
        return;
      }
      if (errEl) errEl.style.display = 'none';
      if (btn) btn.disabled = true;

      api('/api/executors/enroll', body).then(d => {
        if (btn) btn.disabled = false;
        if (!d || d.error) {
          if (errEl) { errEl.textContent = (d && d.error) || 'Enrollment failed'; errEl.style.display = 'block'; }
          return;
        }
        const form = document.getElementById('enrollForm');
        const result = document.getElementById('enrollResult');
        if (form) form.style.display = 'none';
        if (result) result.style.display = 'block';
        const cmd = document.getElementById('enrollCommand');
        if (cmd) cmd.textContent = d.command || '';
        const notice = document.getElementById('enrollNotice');
        if (notice) notice.textContent = d.notice || '';

        // The installer snippet is present only when the hub is served over
        // HTTPS: /install.sh refuses plaintext, so showing the command anyway
        // would send the operator to a device to watch curl fail.
        const installGroup = document.getElementById('enrollInstallGroup');
        const installCmd = document.getElementById('enrollInstallCommand');
        const installNote = document.getElementById('enrollInstallNote');
        const installNoteText = document.getElementById('enrollInstallNoteText');
        if (installCmd) installCmd.textContent = d.install_command || '';
        if (installGroup) installGroup.style.display = d.install_command ? 'block' : 'none';
        // What the command installs and why (Task 20421): this hub's own build
        // with a visible --channel edge, or the latest release. Red when no
        // signed build speaks the hub's protocol, so the installer will stop.
        const installSource = document.getElementById('enrollInstallSource');
        if (installSource) {
          installSource.textContent = d.install_note || '';
          installSource.style.display = d.install_note ? 'block' : 'none';
          installSource.style.color = d.install_stopped ? 'var(--red)' : 'var(--muted)';
        }
        if (installNoteText) installNoteText.textContent = d.install_unavailable || '';
        if (installNote) installNote.style.display = d.install_unavailable ? 'flex' : 'none';

        // Say plainly when there is no pin. An unpinned enrollment trusts
        // whichever server answers at that hostname, and its absence is not
        // something an operator will notice on their own.
        const pin = document.getElementById('enrollPin');
        if (pin) {
          pin.textContent = d.pin
            ? 'Pinned to this hub’s key: ' + d.pin
            : 'No certificate pin — this hub has no ui.tls certificate, so the device will trust '
              + 'the system store only.';
          pin.style.color = d.pin ? 'var(--muted)' : 'var(--red)';
        }

        const exp = document.getElementById('enrollExpiry');
        if (exp) {
          exp.textContent = 'Token ' + (d.id || '') + ' expires '
            + (d.expires_at ? new Date(d.expires_at).toLocaleString() : 'soon') + '.';
        }
      }).catch(err => {
        if (btn) btn.disabled = false;
        if (errEl) {
          errEl.textContent = 'Enrollment failed: ' + (err && err.message || String(err));
          errEl.style.display = 'block';
        }
      });
    }

    // _copyFromElement is shared by both copy buttons in the enroll dialog. The
    // clipboard API is unavailable on a page served over plaintext HTTP, so the
    // fallback has to say something useful rather than silently doing nothing.
    function _copyFromElement(id, label) {
      const el = document.getElementById(id);
      if (!el) return;
      const text = el.textContent || '';
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text)
          .then(() => toast(label + ' copied', 'ok'))
          .catch(() => toast('Copy failed — select the text manually', 'err'));
      } else {
        toast('Clipboard unavailable — select the text manually', 'err');
      }
    }

    function copyEnrollCommand() {
      _copyFromElement('enrollCommand', 'Command');
    }

    function copyEnrollInstall() {
      _copyFromElement('enrollInstallCommand', 'Install command');
    }


    // upgradeExecutor asks one device to roll forward.
    function upgradeExecutor(idx) {
      const ex = _execAt(idx);
      if (!ex) return;
      const name = ex.name || ex.id;
      // The hub picks the release to prefill (upgrade_target) and says why
      // (upgrade_note), Task 20371. It used to be the hub's own version, which on a
      // hub running an unreleased build is "dev+g…" — no release at all — and
      // "latest" there is a release older than the device. Prefilled with a
      // concrete tag rather than "latest" still: "latest" evaluated separately on
      // each device is how a fleet ends up split across two releases when one is
      // published mid-rollout. With no release that would not move the device
      // backwards there is nothing for this button to do, so it shows the note —
      // which says what to do instead — and offers no prompt.
      const note = ex.upgrade_note || '';
      if (!ex.upgrade_target) { alert(note); return; }
      // upgrade_label names an edge build, "this hub's build (a0f3870)" (Task 20376).
      const target = prompt(
        'Upgrade ' + name + ' to ' + (ex.upgrade_label || 'which release') + '?\n\n' + (note && note + '\n\n')
        + 'The device downloads it itself and verifies the signature before installing; '
        + 'it will restart and drop off the fleet briefly.',
        ex.upgrade_target);
      if (target === null) return;

      apiMethod('POST', '/api/executors/' + encodeURIComponent(ex.id) + '/upgrade',
        {target_version: (target || '').trim()})
        .then(d => {
          if (!d || d.error) { toast((d && d.error) || 'Failed to request the upgrade', 'err'); return; }
          // already_current and a refusal are both "nothing is happening", but only
          // one of them is a problem — surfacing them with the same severity would
          // make a benign no-op look like a failure.
          toast(d.message || 'Upgrade requested', d.accepted ? 'ok' : (d.already_current ? 'ok' : 'err'));
          loadExecutors();
        })
        .catch(() => toast('Failed to request the upgrade', 'err'));
    }


    // editFleetAutoUpdate edits the fleet's automatic upgrades from the bar
    // above the cards; the bar and its cached policy (h.fleet) stay in the
    // bundle, which draws them with every executor list.
    function editFleetAutoUpdate() {
      const d = h.fleet() || {};
      const eff = d.effective || {};
      const on = confirm(
        'Turn automatic executor upgrades ' + (d.enabled ? 'OFF' : 'ON') + '?\n\n'
        + 'When on, the hub rolls idle devices forward on its own. It never interrupts '
        + 'running work, never touches a cordoned device, and upgrades only a few at a time.\n\n'
        + 'OK = turn it ' + (d.enabled ? 'off' : 'on') + ', Cancel = leave it as it is.')
        ? !d.enabled : d.enabled;

      let target = d.target_version || '';
      let maxInFlight = eff.max_in_flight || 1;
      if (on) {
        const t = prompt(
          'Which release should the fleet converge on?\n\n'
          + 'Leave empty to track this hub’s own build, or pin a tag such as v0.1.4.',
          target);
        if (t === null) return;
        target = t.trim();
        const m = prompt('How many devices may upgrade at the same time?\n\n'
          + 'Keep this small: each one restarts and is briefly unavailable.', String(maxInFlight));
        if (m === null) return;
        const parsed = parseInt(m, 10);
        if (isNaN(parsed) || parsed < 1) { toast('That is not a number of devices', 'err'); return; }
        maxInFlight = parsed;
      }

      apiMethod('PUT', '/api/fleet/autoupdate',
        {enabled: on, target_version: target, max_in_flight: maxInFlight})
        .then(r => {
          if (!r || r.error) { toast((r && r.error) || 'Failed to save the policy', 'err'); return; }
          h.fleet(r);
          toast('Automatic upgrades are ' + (r.enabled ? 'on' : 'off'), 'ok');
        })
        .catch(() => toast('Failed to save the policy', 'err'));
    }

    // ── Revoke, cordon, uncordon, drain ─────────────────────────────────────
    //
    // The executor cards' admin actions (Tasks 20158, 20162), deferred with the
    // dialogs by Task 20408: they are an admin's, so first paint need not carry
    // them. Cordon, drain and uncordon change where the scheduler places work
    // without touching what is already running, which is what revoking cannot.

    function revokeExecutor(idx) {
      const ex = _execAt(idx);
      if (!ex) return;
      if (!confirm('Revoke ' + ex.name + '?\n\nIts credential stops working immediately, its session is '
          + 'closed, and every project bound to it is unbound. The device must be re-enrolled to come back.')) {
        return;
      }
      apiMethod('DELETE', '/api/executors/' + encodeURIComponent(ex.id))
        .then(d => {
          if (d && d.error) { toast(d.error, 'err'); return; }
          toast('Executor revoked', 'ok');
          loadExecutors();
        })
        .catch(() => toast('Failed to revoke executor', 'err'));
    }

    function cordonExecutor(idx) {
      const ex = _execAt(idx);
      if (!ex) return;
      const reason = prompt('Cordon ' + ex.name + '?\n\nNew work goes elsewhere; whatever it is '
        + 'running now continues untouched. Optional reason:', '');
      if (reason === null) return;
      apiMethod('POST', '/api/executors/' + encodeURIComponent(ex.id) + '/cordon', {reason: reason})
        .then(d => {
          if (!d || d.error) { toast((d && d.error) || 'Failed to cordon', 'err'); return; }
          toast(ex.name + ' is ' + (d.state || 'cordoned'), 'ok');
          loadExecutors();
        })
        .catch(() => toast('Failed to cordon executor', 'err'));
    }

    function uncordonExecutor(idx) {
      const ex = _execAt(idx);
      if (!ex) return;
      apiMethod('POST', '/api/executors/' + encodeURIComponent(ex.id) + '/uncordon')
        .then(d => {
          if (!d || d.error) { toast((d && d.error) || 'Failed to uncordon', 'err'); return; }
          // Uncordon returns a node to the state its probes justify, not
          // unconditionally to ready. Reporting the state it actually came back in
          // is the difference between "uncordon is broken" and "it is still sick".
          const state = d.state || 'ready';
          let msg = ex.name + ' is ' + state;
          if (state !== 'ready' && d.reason) msg += ' — ' + d.reason;
          toast(msg, d.schedulable ? 'ok' : 'err');
          loadExecutors();
        })
        .catch(() => toast('Failed to uncordon executor', 'err'));
    }

    function drainExecutor(idx) {
      const ex = _execAt(idx);
      if (!ex) return;
      const reason = prompt('Drain ' + ex.name + '?\n\nIt stops taking new work immediately; work '
        + 'already running finishes. Put it back with Uncordon. Optional reason:', '');
      if (reason === null) return;
      // No timeout_seconds: the drain takes effect at once and the request must not
      // hang the dashboard waiting on a task that may run for an hour.
      apiMethod('POST', '/api/executors/' + encodeURIComponent(ex.id) + '/drain', {reason: reason})
        .then(d => {
          if (!d || d.error) { toast((d && d.error) || 'Failed to drain', 'err'); return; }
          if (d.drained) {
            toast(ex.name + ' is drained — nothing in flight', 'ok');
          } else if (d.in_flight_known) {
            toast(ex.name + ' is draining — ' + d.in_flight + ' session(s) still running', 'ok');
          } else {
            toast(ex.name + ' is draining', 'ok');
          }
          loadExecutors();
        })
        .catch(() => toast('Failed to drain executor', 'err'));
    }

    // ── Device forwarders (Task 20429) ───────────────────────────────────────
    //
    // A forwarder is not an executor, so it renders in its own section of the
    // Executors tab. The list lives in the eager DOM (#fwdList) like #execList,
    // so its card buttons dispatch through bundled ACTIONS (fwdAct); the dialogs
    // are this deferred panel's and route through data-act.
    //
    // Each card lists the forwarder's bindings (Task 20430): the projects whose
    // runs get its device in their sandbox, until when, and on which virtual
    // executor. Binding takes executor.manage; anyone else asks from the
    // project's Overview, through the grant-request flow.
    let fwdData = null;
    let fwdBindings = [];
    let fwdBindTarget = null;

    function loadForwarders() {
      if (!canGlobal('executor.read')) return Promise.resolve(null);
      const list = document.getElementById('fwdList');
      return Promise.all([api('/api/forwarders'), api('/api/forwarders/bindings').catch(() => ({bindings: []}))]).then(([d, b]) => {
        fwdData = d || {};
        fwdBindings = (b && b.bindings) || [];
        _renderForwarders(fwdData);
        return fwdData;
      }).catch(err => {
        if (list) list.innerHTML = '<div style="font-size:13px;color:var(--red)">Failed to load forwarders: '
          + esc(err && err.message || String(err)) + '</div>';
      });
    }

    function _fwdAt(idx) {
      return (fwdData && fwdData.forwarders && fwdData.forwarders[idx]) || null;
    }

    // _fwdUntil says how long a binding has left.
    function _fwdUntil(iso) {
      const ms = Date.parse(iso) - Date.now();
      if (!(ms > 0)) return 'lapsing';
      if (ms < 3600000) return 'for ' + Math.max(1, Math.round(ms / 60000)) + 'm';
      if (ms < 172800000) return 'for ' + Math.round(ms / 3600000) + 'h';
      return 'for ' + Math.round(ms / 86400000) + 'd';
    }

    function _fwdBindingRows(f, manage) {
      const rows = [];
      fwdBindings.forEach((b, bi) => {
        if (b.forwarder_id !== f.id) return;
        const where = esc(b.project_name || b.project) + (b.virtual_executor ? ' <span style="color:var(--muted)">on ' + esc(b.virtual_executor) + '</span>' : '');
        const until = b.expires_at ? ' <span style="color:var(--muted)">' + esc(_fwdUntil(b.expires_at)) + '</span>' : '';
        const used = (b.in_use && b.in_use.length) ? ' <span class="badge" style="font-size:10.5px">in use</span>' : '';
        const unbind = manage ? '<button class="btn" style="padding:2px 8px;font-size:11px;margin-left:auto" data-action="forwarderUnbind" data-arg="' + bi + '">Unbind</button>' : '';
        rows.push('<div style="display:flex;align-items:center;gap:6px;font-size:11.5px;margin-top:4px;min-width:0">'
          + '<span style="min-width:0;overflow-wrap:anywhere">&rarr; ' + where + until + used + '</span>' + unbind + '</div>');
      });
      if (!rows.length) return '<div style="font-size:11.5px;color:var(--muted);margin-top:6px">Bound to no project.</div>';
      return '<div style="margin-top:6px">' + rows.join('') + '</div>';
    }

    function _renderForwarders(d) {
      const list = document.getElementById('fwdList');
      if (!list) return;
      const fwds = (d && d.forwarders) || [];
      if (!fwds.length) {
        list.innerHTML = '<div style="font-size:12.5px;color:var(--muted)">No forwarders enrolled. '
          + 'Use <strong>+ Enroll forwarder</strong> to bridge an on-prem USB device or interface.</div>';
        return;
      }
      const manage = canGlobal('executor.manage');
      list.innerHTML = fwds.map((f, i) => {
        const dot = f.connected ? 'online' : (f.revoked ? 'unknown' : 'offline');
        let status = f.revoked ? 'revoked' : (f.connected ? 'connected' : 'offline');
        if (f.connected && f.connected_via) status += ' via ' + f.connected_via;
        let detail = '';
        if (f.connected && !f.available && f.detail) {
          detail = '<div style="font-size:11.5px;color:var(--red);margin-top:4px">' + esc(f.detail) + '</div>';
        }
        let resolved = '';
        if (f.resolved && f.resolved.node) {
          resolved = '<div style="font-size:11px;color:var(--muted);margin-top:2px">resolved: '
            + esc(f.resolved.node) + '</div>';
        }
        const test = (manage && f.connected && !f.revoked)
          ? '<button class="btn" style="padding:3px 9px;font-size:11.5px" data-action="forwarderExpose" data-arg="' + i + '">Test</button>' : '';
        const bind = (manage && !f.revoked)
          ? '<button class="btn" style="padding:3px 9px;font-size:11.5px" data-action="forwarderBind" data-arg="' + i + '">Bind…</button>' : '';
        const revoke = (manage && !f.revoked)
          ? '<button class="btn" style="padding:3px 9px;font-size:11.5px" data-action="forwarderRevoke" data-arg="' + i + '">Revoke</button>' : '';
        return '<div class="exec-card">'
          + '<div style="display:flex;align-items:center;gap:8px;min-width:0">'
          + '<span class="exec-dot ' + dot + '"></span>'
          + '<strong style="font-size:13px;min-width:0;overflow-wrap:anywhere">' + esc(f.name || f.id) + '</strong>'
          + '<span style="font-size:11px;color:var(--muted);margin-left:auto;text-align:right">' + esc(status) + '</span></div>'
          + '<div style="font-size:12px;color:var(--muted);margin-top:6px;overflow-wrap:anywhere">' + esc(f.device_str || f.kind) + '</div>'
          + resolved + detail + (f.revoked ? '' : _fwdBindingRows(f, manage))
          + '<div style="display:flex;gap:6px;margin-top:10px;flex-wrap:wrap">' + test + bind + revoke + '</div>'
          + '</div>';
      }).join('');
    }

    function openForwarderEnroll() {
      const form = document.getElementById('fwdEnrollForm');
      const result = document.getElementById('fwdEnrollResult');
      const err = document.getElementById('fwdEnrollError');
      if (form) form.style.display = 'block';
      if (result) result.style.display = 'none';
      if (err) err.style.display = 'none';
      const name = document.getElementById('fwdName');
      if (name) name.value = '';
      const usb = document.getElementById('fwdUSB'); if (usb) usb.value = '';
      const iface = document.getElementById('fwdIface'); if (iface) iface.value = '';
      const ttl = document.getElementById('fwdTTL'); if (ttl) ttl.value = '';
      onFwdKindChange();
      openOverlay('forwarder-enroll-overlay', {dismiss: closeForwarderEnroll, focus: name});
    }

    function closeForwarderEnroll() {
      closeOverlay('forwarder-enroll-overlay');
      loadForwarders();
    }

    function onFwdKindChange() {
      const kind = (document.getElementById('fwdKind') || {}).value || 'usb';
      const usbRow = document.getElementById('fwdUSBRow');
      const ifaceRow = document.getElementById('fwdIfaceRow');
      if (usbRow) usbRow.style.display = kind === 'usb' ? 'block' : 'none';
      if (ifaceRow) ifaceRow.style.display = kind === 'l2' ? 'block' : 'none';
    }

    function submitForwarderEnroll() {
      const errEl = document.getElementById('fwdEnrollError');
      const btn = document.getElementById('fwdEnrollSubmitBtn');
      const kind = (document.getElementById('fwdKind') || {}).value || 'usb';
      const body = { name: (document.getElementById('fwdName') || {}).value || '', kind: kind };
      if (kind === 'usb') {
        const spec = ((document.getElementById('fwdUSB') || {}).value || '').trim();
        const parts = spec.split(':');
        if (parts.length < 2) {
          if (errEl) { errEl.textContent = 'USB must be vendor:product[:serial], e.g. 1050:0030'; errEl.style.display = 'block'; }
          return;
        }
        body.usb = { vendor_id: parts[0], product_id: parts[1] };
        if (parts.length >= 3) body.usb.serial = parts[2];
      } else {
        body.interface = ((document.getElementById('fwdIface') || {}).value || '').trim();
      }
      const ttlRaw = (document.getElementById('fwdTTL') || {}).value;
      if (ttlRaw) body.ttl_minutes = parseInt(ttlRaw, 10);
      if (errEl) errEl.style.display = 'none';
      if (btn) btn.disabled = true;
      api('/api/forwarders/enroll', body).then(d => {
        if (btn) btn.disabled = false;
        if (!d || d.error) {
          if (errEl) { errEl.textContent = (d && d.error) || 'Enrollment failed'; errEl.style.display = 'block'; }
          return;
        }
        const form = document.getElementById('fwdEnrollForm');
        const result = document.getElementById('fwdEnrollResult');
        if (form) form.style.display = 'none';
        if (result) result.style.display = 'block';
        const cmd = document.getElementById('fwdEnrollCommand');
        if (cmd) cmd.textContent = d.command || '';
        const exp = document.getElementById('fwdEnrollExpiry');
        if (exp) exp.textContent = d.expires ? ('Token expires ' + d.expires) : '';
      }).catch(() => {
        if (btn) btn.disabled = false;
        if (errEl) { errEl.textContent = 'Enrollment failed'; errEl.style.display = 'block'; }
      });
    }

    function copyForwarderCommand() {
      const cmd = (document.getElementById('fwdEnrollCommand') || {}).textContent || '';
      if (cmd && navigator.clipboard) navigator.clipboard.writeText(cmd).then(() => toast('Copied', 'ok'));
    }

    function forwarderRevoke(idx) {
      const f = _fwdAt(idx);
      if (!f) return;
      if (!confirm('Revoke forwarder "' + (f.name || f.id) + '"? Its device will stop being reachable.')) return;
      api('/api/forwarders/' + encodeURIComponent(f.id), null, {method: 'DELETE'})
        .then(() => { toast('Forwarder revoked', 'ok'); loadForwarders(); })
        .catch(() => toast('Failed to revoke forwarder', 'err'));
    }

    // forwarderExpose probes the device through the hub (Task 20430): a stream
    // to the forwarder and, for USB, its device list. Nothing is attached.
    function forwarderExpose(idx) {
      const f = _fwdAt(idx);
      if (!f) return;
      const box = document.getElementById('fwdExposeResult');
      api('/api/forwarders/' + encodeURIComponent(f.id) + '/expose', {}).then(d => {
        if (!box) return;
        const ok = d && d.reachable;
        const ex = (d && d.exported) || {};
        const what = f.kind === 'usb'
          ? (ex.vendor_id ? 'exports ' + ex.vendor_id + ':' + ex.product_id + ' as ' + ex.bus_id + ' (' + (ex.interfaces || 0) + ' interface(s))' : '')
          : (ex.interface ? 'opened interface ' + ex.interface : '');
        box.innerHTML = '<div class="exec-banner" style="margin-top:4px"><div style="min-width:0">'
          + '<strong style="font-size:12.5px">' + esc(f.name || f.id) + '</strong> '
          + (ok ? '<span style="color:var(--green)">reachable</span>' : '<span style="color:var(--red)">not reachable</span>')
          + '<div style="font-size:11.5px;color:var(--muted);margin-top:6px;overflow-wrap:anywhere">'
          + esc(ok ? what : ((d && d.error) || 'the probe failed')) + '</div></div></div>';
      }).catch(err => toast((err && err.message) || 'Failed to reach the device', 'err'));
    }

    function forwarderBind(idx) {
      const f = _fwdAt(idx);
      if (!f) return;
      fwdBindTarget = f;
      const title = document.getElementById('fwdBindTitle');
      if (title) title.textContent = 'Bind ' + (f.name || f.id);
      const err = document.getElementById('fwdBindError');
      if (err) err.style.display = 'none';
      const l2 = document.getElementById('fwdBindL2');
      if (l2) l2.style.display = f.kind === 'l2' ? 'block' : 'none';
      ['fwdBindVX', 'fwdBindTarget', 'fwdBindAddress', 'fwdBindNote'].forEach(id => {
        const el = document.getElementById(id); if (el) el.value = '';
      });
      const ttl = document.getElementById('fwdBindTTL'); if (ttl) ttl.value = '24';
      const sel = document.getElementById('fwdBindProject');
      api('/api/projects').then(d => {
        if (!sel) return;
        const ps = ((d && d.projects) || []).filter(p => !p.parent);
        sel.innerHTML = ps.map(p => '<option value="' + esc(p.path) + '">' + esc(p.name || p.path) + '</option>').join('');
      }).catch(() => {});
      openOverlay('forwarder-bind-overlay', {dismiss: closeForwarderBind, focus: sel});
    }

    function closeForwarderBind() {
      closeOverlay('forwarder-bind-overlay');
      fwdBindTarget = null;
    }

    function submitForwarderBind() {
      const f = fwdBindTarget;
      if (!f) return;
      const val = id => ((document.getElementById(id) || {}).value || '').trim();
      const errEl = document.getElementById('fwdBindError');
      const body = {project: val('fwdBindProject'), virtual_executor: val('fwdBindVX'), note: val('fwdBindNote')};
      const hours = parseFloat(val('fwdBindTTL') || '24');
      if (hours > 0) body.ttl_minutes = Math.round(hours * 60);
      if (f.kind === 'l2' && (val('fwdBindTarget') || val('fwdBindAddress'))) {
        body.interface = {target: val('fwdBindTarget'), address: val('fwdBindAddress')};
      }
      api('/api/forwarders/' + encodeURIComponent(f.id) + '/bindings', body).then(d => {
        if (!d || d.error) {
          if (errEl) { errEl.textContent = (d && d.error) || 'Binding failed'; errEl.style.display = 'block'; }
          return;
        }
        toast('Bound ' + (f.name || f.id), 'ok');
        closeForwarderBind();
        loadForwarders();
      }).catch(e => {
        if (errEl) { errEl.textContent = (e && e.message) || 'Binding failed'; errEl.style.display = 'block'; }
      });
    }

    function forwarderUnbind(bi) {
      const b = fwdBindings[bi];
      if (!b) return;
      if (!confirm('Unbind ' + (b.forwarder_name || b.forwarder_id) + ' from ' + (b.project_name || b.project) +
          '? A run holding the device has it detached at once.')) return;
      apiMethod('DELETE', '/api/forwarders/bindings/' + encodeURIComponent(b.id))
        .then(() => { toast('Unbound', 'ok'); loadForwarders(); })
        .catch(() => toast('Failed to unbind', 'err'));
    }

    return h.mount({
      loadForwarders, openForwarderEnroll, closeForwarderEnroll, onFwdKindChange,
      submitForwarderEnroll, copyForwarderCommand, forwarderRevoke, forwarderExpose,
      forwarderBind, closeForwarderBind, submitForwarderBind, forwarderUnbind,
      openExecutorDetail, closeExecutorDetail, openExecutorTaskRef, openExecutorSandbox,
      closeExecutorSandbox, onExecSandboxModeChange, saveExecutorSandbox, clearExecutorSandbox,
      isolationChips, reprobeExecutorVirtual,
      openExecutorVirtual, closeExecutorVirtual, refreshExecutorVirtual, evxSync,
      editExecutorVirtual, saveExecutorVirtual, deleteExecutorVirtual, openExecutorFirewall,
      closeExecutorFirewall, saveExecutorFirewall, clearExecutorFirewall, openExecutorLimits,
      closeExecutorLimits, saveExecutorLimits, clearExecutorLimits, openExecutorAudience,
      closeExecutorAudience, addExecutorAudience, removeExecutorAudience, openExecutorLabels,
      closeExecutorLabels, saveExecutorLabels, openEnrollModal,
      closeEnrollModal, submitEnroll, copyEnrollCommand, copyEnrollInstall, upgradeExecutor,
      editFleetAutoUpdate, revokeExecutor, cordonExecutor, uncordonExecutor, drainExecutor
    }, null, null, `
      <div id="forwarder-bind-overlay" data-overlay="flex" data-dismiss="closeForwarderBind" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:50;align-items:center;justify-content:center">
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;width:560px;max-width:95vw;max-height:90vh;overflow:auto">
          <h2 id="fwdBindTitle" style="font-size:15px;font-weight:600;margin-bottom:6px;overflow-wrap:anywhere">Bind forwarder</h2>
          <p style="font-size:12px;color:var(--muted);margin-bottom:16px;line-height:1.5">
            Every run of the project gets the device in its sandbox while the binding lasts: the hub relays the forwarder to
            the executor that runs the sandbox, which attaches it there. A run whose forwarder is offline is refused.
          </p>
          <div class="form-group">
            <label class="form-label" for="fwdBindProject">Project</label>
            <select class="form-input form-select" id="fwdBindProject"></select>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label" for="fwdBindVX">Only on virtual executor (optional)</label>
              <input class="form-input" id="fwdBindVX" placeholder="virtual executor id">
            </div>
            <div class="form-group">
              <label class="form-label" for="fwdBindTTL">Lasts (hours)</label>
              <input class="form-input" id="fwdBindTTL" type="number" min="1" max="2160" value="24">
            </div>
          </div>
          <div id="fwdBindL2" style="display:none">
            <div class="form-row">
              <div class="form-group">
                <label class="form-label" for="fwdBindTarget">Interface in the sandbox</label>
                <input class="form-input" id="fwdBindTarget" placeholder="fwd0">
              </div>
              <div class="form-group">
                <label class="form-label" for="fwdBindAddress">Address (optional CIDR)</label>
                <input class="form-input" id="fwdBindAddress" placeholder="10.77.0.2/24">
              </div>
            </div>
          </div>
          <div class="form-group">
            <label class="form-label" for="fwdBindNote">Note (optional)</label>
            <input class="form-input" id="fwdBindNote" maxlength="1024">
          </div>
          <div id="fwdBindError" class="form-error" style="display:none;color:var(--red);font-size:12px;margin-bottom:8px"></div>
          <div style="display:flex;gap:8px;justify-content:flex-end">
            <button class="btn" data-act="closeForwarderBind">Cancel</button>
            <button class="btn primary" id="fwdBindSubmitBtn" data-act="submitForwarderBind">Bind</button>
          </div>
        </div>
      </div>
      <div id="forwarder-enroll-overlay" data-overlay="flex" data-dismiss="closeForwarderEnroll" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:50;align-items:center;justify-content:center">
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;width:620px;max-width:95vw;max-height:90vh;overflow:auto">
          <h2 style="font-size:15px;font-weight:600;margin-bottom:6px">Enroll a device forwarder</h2>
          <p style="font-size:12px;color:var(--muted);margin-bottom:16px;line-height:1.5">
            The forwarder dials <em>out</em> to this control plane and bridges one device. This mints a
            single-use token and prints the command to run on the on-prem machine &mdash; nothing is contacted from here.
          </p>
          <div id="fwdEnrollForm">
            <div class="form-row">
              <div class="form-group">
                <label class="form-label">Forwarder name</label>
                <input class="form-input" id="fwdName" placeholder="e.g. bench-usb">
              </div>
              <div class="form-group">
                <label class="form-label">Token lifetime (minutes)</label>
                <input class="form-input" id="fwdTTL" type="number" min="1" max="1440" placeholder="15">
              </div>
            </div>
            <div class="form-group">
              <label class="form-label">Device type</label>
              <select class="form-select" id="fwdKind" data-change="onFwdKindChange">
                <option value="usb">USB device</option>
                <option value="l2">Network interface (layer 2)</option>
              </select>
            </div>
            <div class="form-group" id="fwdUSBRow">
              <label class="form-label">USB identity (vendor:product[:serial])</label>
              <input class="form-input" id="fwdUSB" placeholder="e.g. 1050:0030 or 1050:0030:0001234">
            </div>
            <div class="form-group" id="fwdIfaceRow" style="display:none">
              <label class="form-label">Interface name on the on-prem host</label>
              <input class="form-input" id="fwdIface" placeholder="e.g. eth1">
            </div>
            <div id="fwdEnrollError" style="font-size:12px;color:var(--red);margin-bottom:8px;display:none"></div>
            <div class="modal-footer">
              <button class="btn" data-act="closeForwarderEnroll">Cancel</button>
              <button class="btn primary" id="fwdEnrollSubmitBtn" data-global-perm="executor.manage" data-act="submitForwarderEnroll">Mint token</button>
            </div>
          </div>
          <div id="fwdEnrollResult" style="display:none">
            <div class="form-group">
              <label class="form-label">Run this on the on-prem device</label>
              <div class="exec-token" id="fwdEnrollCommand"></div>
              <div style="font-size:11.5px;color:var(--muted);margin-top:6px">
                The token is single-use and shown only once. The forwarder runs nothing but this one device bridge.
              </div>
            </div>
            <div style="font-size:11.5px;color:var(--muted);margin-bottom:12px" id="fwdEnrollExpiry"></div>
            <div class="modal-footer">
              <button class="btn" data-act="copyForwarderCommand">Copy command</button>
              <button class="btn primary" data-act="closeForwarderEnroll">Done</button>
            </div>
          </div>
        </div>
      </div>
      <div id="enroll-overlay" data-overlay="flex" data-dismiss="closeEnrollModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:50;align-items:center;justify-content:center">
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;width:640px;max-width:95vw;max-height:90vh;overflow:auto">
          <h2 style="font-size:15px;font-weight:600;margin-bottom:6px">Enroll a remote executor</h2>
          <p style="font-size:12px;color:var(--muted);margin-bottom:16px;line-height:1.5">
            The device dials <em>out</em> to this control plane, so it works behind NAT with no inbound firewall rule.
            This mints a single-use token and prints the command to run there &mdash; nothing is contacted from here.
          </p>
          <div id="enrollForm">
            <div class="form-row">
              <div class="form-group">
                <label class="form-label">Device name</label>
                <input class="form-input" id="enrollName" placeholder="e.g. edge-1">
              </div>
              <div class="form-group">
                <label class="form-label">Token lifetime (minutes)</label>
                <input class="form-input" id="enrollTTL" type="number" min="1" max="1440" placeholder="15">
              </div>
            </div>
            <div class="form-group">
              <label class="form-label">Workspace root on the device (optional)</label>
              <input class="form-input" id="enrollRoot" placeholder="/var/lib/cloop/workspaces">
            </div>
            <div class="form-group">
              <label class="form-label" for="enrollLabels">Labels (optional)</label>
              <input class="form-input" id="enrollLabels" placeholder="region=eu, gpu=true" spellcheck="false">
              <div class="form-hint">What a grant to <code>label:region=eu</code> is matched against. Change them later with Labels on the device&#39;s card.</div>
            </div>
            <div id="enrollError" style="font-size:12px;color:var(--red);margin-bottom:8px;display:none"></div>
            <div class="modal-footer">
              <button class="btn" data-act="closeEnrollModal">Cancel</button>
              <button class="btn primary" id="enrollSubmitBtn" data-global-perm="executor.manage" data-act="submitEnroll">Mint token</button>
            </div>
          </div>
          <div id="enrollResult" style="display:none">
            <div class="exec-banner warn" style="margin-bottom:12px">
              <span class="exec-banner-icon">&#9888;</span>
              <span id="enrollNotice"></span>
            </div>
            <div class="form-group" id="enrollInstallGroup" style="display:none">
              <label class="form-label">Install as a service (recommended)</label>
              <div class="exec-token" id="enrollInstallCommand"></div>
              <div id="enrollInstallSource" style="display:none;font-size:11.5px;margin-top:6px"></div>
              <div style="font-size:11.5px;color:var(--muted);margin-top:6px">
                Fetches <code>/install.sh</code> from this hub and installs a systemd service with
                <code>Restart=always</code>, a dedicated non-login user, and the token stored at mode 0600 &mdash;
                never on the command line. It refuses a cloop that speaks an older executor protocol than this
                hub. Requires root on the device.
              </div>
              <div style="margin-top:8px">
                <button class="btn" data-act="copyEnrollInstall">Copy install command</button>
              </div>
            </div>
            <div class="exec-banner warn" id="enrollInstallNote" style="display:none;margin-bottom:12px">
              <span class="exec-banner-icon">&#9888;</span>
              <span id="enrollInstallNoteText"></span>
            </div>
            <div class="form-group">
              <label class="form-label">Or run the agent in the foreground</label>
              <div class="exec-token" id="enrollCommand"></div>
              <div style="font-size:11.5px;color:var(--muted);margin-top:6px">
                Nothing is installed and nothing restarts after a reboot. Good for a first check;
                use the installer above for a device you intend to keep.
              </div>
            </div>
            <div style="font-size:11.5px;color:var(--muted);margin-bottom:4px" id="enrollPin"></div>
            <div style="font-size:11.5px;color:var(--muted);margin-bottom:12px" id="enrollExpiry"></div>
            <div class="modal-footer">
              <button class="btn" data-act="copyEnrollCommand">Copy command</button>
              <button class="btn primary" data-act="closeEnrollModal">Done</button>
            </div>
          </div>
        </div>
      </div>
      <div id="executor-detail-overlay" data-overlay="flex" data-dismiss="closeExecutorDetail" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:50;align-items:center;justify-content:center">
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;width:760px;max-width:95vw;max-height:90vh;overflow:auto">
          <h2 id="execDetailTitle" style="font-size:15px;font-weight:600;margin-bottom:2px">Executor</h2>
          <div id="execDetailSub" style="font-family:monospace;font-size:11px;color:var(--muted);margin-bottom:16px"></div>
          <div id="execDetailBody"></div>
          <div class="modal-footer">
            <button class="btn" data-act="closeExecutorDetail">Close</button>
          </div>
        </div>
      </div>
      <div id="executor-sandbox-overlay" data-overlay="flex" data-dismiss="closeExecutorSandbox" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:50;align-items:center;justify-content:center">
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;width:620px;max-width:95vw;max-height:90vh;overflow:auto">
          <h2 style="font-size:15px;font-weight:600;margin-bottom:2px">Sandbox</h2>
          <div id="execSandboxSub" style="font-family:monospace;font-size:11px;color:var(--muted);margin-bottom:16px"></div>
          <div id="execSandboxWarn" class="exec-sched-note" style="display:none;margin-bottom:14px"></div>

          <div class="form-group">
            <label class="form-label" for="execSandboxMode">Where payloads run</label>
            <select class="form-select" id="execSandboxMode" data-change="onExecSandboxModeChange">
              <option value="">Executor default (unset)</option>
              <option value="host">On the executor host</option>
              <option value="container">In a container on the executor host</option>
            </select>
            <div class="form-hint" id="execSandboxModeHint"></div>
          </div>

          <div id="execSandboxContainerFields" style="display:none">
            <div class="form-row">
              <div class="form-group" style="flex:1">
                <label class="form-label" for="execSandboxEngine">Container engine</label>
                <select class="form-select" id="execSandboxEngine"></select>
                <div class="form-hint" id="execSandboxEngineHint"></div>
              </div>
              <div class="form-group" style="flex:1">
                <label class="form-label" for="execSandboxRuntime">Container runtime</label>
                <input class="form-input" id="execSandboxRuntime" list="execSandboxRuntimeList" placeholder="default (runc)" spellcheck="false">
                <datalist id="execSandboxRuntimeList">
                  <option value="runc">runc — host kernel, namespaces only</option>
                  <option value="crun">crun — host kernel, namespaces only</option>
                  <option value="runsc">runsc — gVisor userspace kernel</option>
                  <option value="kata">kata — hypervisor, own guest kernel</option>
                  <option value="kata-qemu">kata-qemu</option>
                  <option value="kata-clh">kata-clh</option>
                </datalist>
                <div class="form-hint">The <code>--runtime</code> name the engine resolves against its own root-owned config. A path is refused.</div>
                <div class="form-hint" id="execSandboxIso" style="display:none"></div>
              </div>
            </div>
            <div class="form-group">
              <label class="form-label" for="execSandboxImage">Container image</label>
              <input class="form-input" id="execSandboxImage" placeholder="executor default" spellcheck="false">
              <div class="form-hint">Left empty, the executor uses its own configured image. A project's <code>.cloop/sandbox.yaml</code> may still override it, subject to the image trust policy.</div>
            </div>
            <div class="form-group">
              <label class="form-label" for="execSandboxNetwork">Container network</label>
              <input class="form-input" id="execSandboxNetwork" list="execSandboxNetworkList" placeholder="none" spellcheck="false">
              <datalist id="execSandboxNetworkList"></datalist>
              <div class="form-hint">Empty means <code>none</code>. A payload with no network cannot reach the git proxy, the Kubernetes monitor or the egress broker — each is a service it resolves by name — so a project that fetches repositories here needs <code>bridge</code> or a network you created on the device. <code>host</code> is refused.</div>
            </div>
          </div>

          <div class="modal-footer">
            <button class="btn danger" id="execSandboxClear" data-act="clearExecutorSandbox">Reset to default</button>
            <button class="btn" data-act="closeExecutorSandbox">Cancel</button>
            <button class="btn primary" data-act="saveExecutorSandbox">Save</button>
          </div>
        </div>
      </div>
      <div id="executor-limits-overlay" data-overlay="flex" data-dismiss="closeExecutorLimits" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:50;align-items:center;justify-content:center">
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;width:620px;max-width:95vw;max-height:90vh;overflow:auto">
          <h2 style="font-size:15px;font-weight:600;margin-bottom:2px">Resource limits</h2>
          <div id="execLimitsSub" style="font-family:monospace;font-size:11px;color:var(--muted);margin-bottom:16px"></div>
          <div id="execLimitsWarn" class="exec-sched-note" style="display:none;margin-bottom:14px"></div>

          <div class="form-hint" style="margin-bottom:14px">The most any <em>one</em> workload on this executor may be given. This is a ceiling, not a default: a project asking for more in its <code>.cloop/sandbox.yaml</code> is lowered to it. Leave a field empty to leave that resource uncapped.</div>

          <div class="form-row">
            <div class="form-group" style="flex:1">
              <label class="form-label" for="execLimitsCPU">CPU cores</label>
              <input class="form-input" id="execLimitsCPU" placeholder="uncapped" spellcheck="false">
              <div class="form-hint">Fractional allowed, e.g. <code>1.5</code>.</div>
            </div>
            <div class="form-group" style="flex:1">
              <label class="form-label" for="execLimitsMemory">Memory</label>
              <input class="form-input" id="execLimitsMemory" placeholder="uncapped" spellcheck="false">
              <div class="form-hint">Size string, e.g. <code>2g</code> or <code>512m</code>.</div>
            </div>
          </div>
          <div class="form-row">
            <div class="form-group" style="flex:1">
              <label class="form-label" for="execLimitsDisk">Disk</label>
              <input class="form-input" id="execLimitsDisk" placeholder="uncapped" spellcheck="false">
              <div class="form-hint">Bounds the workspace. A container executor measures it while the workload runs and stops one that outgrows it, so a burst can overshoot by the time between samples.</div>
            </div>
            <div class="form-group" style="flex:1">
              <label class="form-label" for="execLimitsPIDs">Processes</label>
              <input class="form-input" id="execLimitsPIDs" placeholder="uncapped" spellcheck="false">
              <div class="form-hint">Processes and threads in one workload.</div>
            </div>
          </div>

          <div class="form-hint" id="execLimitsHint" style="margin-bottom:6px"></div>
          <div class="form-hint" id="execLimitsFleet"></div>

          <div class="modal-footer">
            <button class="btn danger" id="execLimitsClear" data-act="clearExecutorLimits">Remove ceiling</button>
            <button class="btn" data-act="closeExecutorLimits">Cancel</button>
            <button class="btn primary" data-act="saveExecutorLimits">Save</button>
          </div>
        </div>
      </div>
      <div id="executor-labels-overlay" data-overlay="flex" data-dismiss="closeExecutorLabels" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:50;align-items:center;justify-content:center">
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;width:560px;max-width:95vw;max-height:90vh;overflow:auto">
          <h2 style="font-size:15px;font-weight:600;margin-bottom:2px">Labels</h2>
          <div id="execLabelsSub" style="font-family:monospace;font-size:11px;color:var(--muted);margin-bottom:16px"></div>
          <div class="form-hint" style="margin-bottom:14px">What a grant to <code>label:region=eu,gpu=true</code> is matched against: it reaches this device, and every virtual executor on it, while the device carries all of those labels. When you save, a running task that holds a credential from a label grant the new labels no longer match gives it back. Labels the device&#39;s agent reports about itself never count.</div>
          <div class="form-group">
            <label class="form-label" for="execLabelsInput">Labels</label>
            <input class="form-input" id="execLabelsInput" placeholder="region=eu, gpu=true" spellcheck="false" data-enter="saveExecutorLabels">
            <div class="form-hint">key=value pairs separated by commas. Leave it empty for none.</div>
          </div>
          <div id="execLabelsNote" class="exec-sched-note" style="display:none;margin-bottom:10px"></div>
          <div class="modal-footer">
            <button class="btn" data-act="closeExecutorLabels">Cancel</button>
            <button class="btn primary" data-act="saveExecutorLabels">Save</button>
          </div>
        </div>
      </div>
      <div id="executor-audience-overlay" data-overlay="flex" data-dismiss="closeExecutorAudience" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:50;align-items:center;justify-content:center">
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;width:620px;max-width:95vw;max-height:90vh;overflow:auto">
          <h2 style="font-size:15px;font-weight:600;margin-bottom:2px">Access</h2>
          <div id="execAudienceSub" style="font-family:monospace;font-size:11px;color:var(--muted);margin-bottom:16px"></div>
          <div id="execAudienceWarn" class="exec-sched-note" style="display:none;margin-bottom:14px"></div>

          <div class="form-hint" style="margin-bottom:14px">Who may bind a project to this executor and run work on it. An empty list means everyone; adding the first entry restricts it. Managing an executor and being allowed to use it are separate rights, so admit yourself if you need to run work here.</div>

          <div id="execAudienceList" style="margin-bottom:12px"></div>
          <div class="form-hint" id="execAudienceState" style="margin-bottom:14px"></div>

          <div class="form-row">
            <div class="form-group" style="width:150px">
              <label class="form-label" for="execAudienceKind">Kind</label>
              <select class="form-select" id="execAudienceKind">
                <option value="group">Group</option>
                <option value="user">User</option>
                <option value="role">Role</option>
              </select>
            </div>
            <div class="form-group" style="flex:1">
              <label class="form-label" for="execAudienceValue">Group name, email or subject</label>
              <input class="form-input" id="execAudienceValue" placeholder="platform-team" spellcheck="false">
              <div class="form-hint">Matched against your identity provider's claims. A group path such as <code>/platform-team</code> and the bare name are interchangeable.</div>
            </div>
          </div>

          <div class="modal-footer">
            <button class="btn" data-act="closeExecutorAudience">Close</button>
            <button class="btn primary" data-act="addExecutorAudience">Admit</button>
          </div>
        </div>
      </div>
      <div id="executor-virtual-overlay" data-overlay="flex" data-dismiss="closeExecutorVirtual" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:50;align-items:center;justify-content:center">
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;width:680px;max-width:95vw;max-height:90vh;overflow:auto">
          <h2 style="font-size:15px;font-weight:600;margin-bottom:8px">Virtual executors <button class="btn" style="float:right" data-act="closeExecutorVirtual">Close</button></h2>
          <div id="evxBody"></div>
        </div>
      </div>
      <div id="executor-firewall-overlay" data-overlay="flex" data-dismiss="closeExecutorFirewall" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:50;align-items:center;justify-content:center">
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;width:640px;max-width:95vw;max-height:90vh;overflow:auto">
          <h2 style="font-size:15px;font-weight:600;margin-bottom:8px">Device firewall</h2>
          <div id="efwBody"></div>
        </div>
      </div>`);
  };
})();
