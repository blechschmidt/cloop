// ── Executors tab (Task 20160) ──────────────────────────────────────────────
//
// The fleet: every executor as a card with its capabilities, inventory, load
// and state, the fleet's automatic-upgrade bar, and the Device forwarders
// section. Fetched on the tab's first open since Task 20456, markup included;
// it was most of 23-executors.js. What stayed there is what the Overview
// draws on first paint: loadExecutors, the project's executor card and its
// picker, and the Claude Code caps.
//
// It runs outside the dashboard's IIFE, so it is handed the helpers it calls,
// and the only name it puts on window is the factory. render() is what the
// bundle's loadExecutors calls, through panelIf, after every fetch — so an
// executor_update that arrives before this tab was ever opened is drawn from
// the fetch open() makes instead.
(function () {
  'use strict';

  window.cloopExecutorsPanel = function (h) {
    const {api, apiMethod, esc, toast, relTime, execKind: _execKindLabel} = h;

    // The executor dialogs and admin actions are deferred/execadmin.js (Tasks
    // 20386, 20408), fetched when this tab opens. Each card button names one action
    // here, with the card's index as its argument; fwd forwards it. One action per
    // function rather than a generic one taking the panel function's name, which
    // would let an attribute reach any function that panel has.
    let ea = null;
    const fwd = fn => arg => h.panelAct('execadmin', fn, +arg);

    function _execDotClass(status) {
      if (status === 'online' || status === 'offline' || status === 'degraded') return status;
      return 'unknown';
    }

    // _execStateClass maps a scheduling state onto its badge class. An unknown
    // value yields '' and the badge is skipped rather than defaulting to 'ready':
    // painting an unrecognised state green would be an outright lie about whether
    // the node takes work.
    function _execStateClass(state) {
      const known = ['ready','degraded','unreachable','cordoned','draining'];
      return known.indexOf(state) >= 0 ? state : '';
    }

    // _execStateTitle explains the badge on hover, in terms of the only thing the
    // state is for: whether new work lands here.
    function _execStateTitle(ex) {
      if (ex.admin_held) {
        return 'Held by an operator. No probe result will lift it; in-flight work continues.';
      }
      return ex.schedulable
        ? 'The scheduler will place new work here.'
        : 'The scheduler will not place new work here.';
    }

    // _execCapChips renders the capability flags as chips. A capability the
    // executor lacks is shown greyed rather than hidden: "this backend cannot
    // stream output" is information an operator needs before binding to it, and
    // an absent chip reads as an oversight rather than as a "no".
    function _execCapChips(ex) {
      const caps = ex.capabilities || {};
      const chips = [];
      if (ex.isolation) {
        const isolated = ex.isolation !== 'none';
        chips.push('<span class="exec-chip ' + (isolated ? 'pos' : 'neg') + '">isolation: '
          + esc(ex.isolation) + '</span>');
      }
      // Where payloads run, for an enrolled device (Task 20307).
      //
      // The isolation chip above says `remote` for every device and says it whether
      // or not the machine contains its workloads, because "remote" is a fact about
      // the network and not about containment. This chip is the one that answers the
      // question an admin auditing the fleet is actually asking, and it names the
      // runtime with it: a container on runc and a container on kata are different
      // boundaries.
      if (ex.virtual) {
        // Network access, in the dialog's three words (Task 20356). This chip was
        // "firewall: off", greyed like a missing capability, on every virtual
        // executor without a firewall — including one with no network at all, the
        // tightest there is. Only an unfiltered network is the negative one now.
        const v = ex.virtual, net = (ex.sandbox && ex.sandbox.network) || 'none';
        const k = v.firewall ? 'firewalled' : net === 'none' ? 'none' : 'unfiltered';
        chips.push('<span class="exec-chip ' + (k === 'unfiltered' ? 'neg' : 'pos') + '" title="' + esc(v.firewall
          ? 'IP firewall: ' + v.firewall : k === 'none' ? 'No network interface at all' : 'The ' + net + ' network, with no firewall')
          + '">network: ' + k + '</span>');
        if (v.devices && v.devices.length) {
          chips.push('<span class="exec-chip" title="' + esc(v.devices.join('\n')) + '">devices: ' + esc(v.devices.length) + '</span>');
        }
        if (v.issue) chips.push('<span class="exec-chip neg" title="' + esc(v.issue) + '">cannot apply</span>');
      }
      if (ex.kind === 'remote' || ex.kind === 'virtual') {
        const sb = ex.sandbox;
        if (sb && sb.mode === 'container') {
          const rt = sb.runtime ? ' / ' + sb.runtime : '';
          // The network is named in the tooltip because "container, no network" is
          // a working configuration that cannot fetch a repository, and the failure
          // it produces shows up inside the sandbox as a DNS error rather than here.
          const net = sb.network || 'none';
          chips.push('<span class="exec-chip pos" title="Payloads run in a container on this '
            + 'device' + (sb.runtime ? ', under the ' + esc(sb.runtime) + ' runtime' : '')
            + ', on the ' + esc(net) + ' network'
            + (net === 'none' ? ' — so they cannot reach the git proxy or any other hub service' : '')
            + '. Set in this executor\'s Sandbox panel.">sandbox: container' + esc(rt) + '</span>');
        } else if (sb && sb.mode === 'host') {
          chips.push('<span class="exec-chip neg" title="Payloads run directly on this device\'s '
            + 'host, with the agent\'s own privileges and filesystem. Chosen in this executor\'s '
            + 'Sandbox panel.">sandbox: host</span>');
        } else {
          // Unset is not host, and the distinction is the point: nobody has decided.
          // Rendered as a caution rather than a negative for that reason — what it
          // reports is an open question, not a configuration.
          chips.push('<span class="exec-chip neg" title="No sandbox mode configured, so this '
            + 'device runs payloads the way it always has — as a process on its own host. '
            + 'Set one in its Sandbox panel.">sandbox: unset</span>');
        }
      }
      // Access (Task 20310). Shown only when restricted, for the reason the
      // virtualization chip below is: an unrestricted executor is the norm, and a
      // chip on every row saying so would read as a warning rather than a default.
      //
      // The two restricted states render differently because they mean different
      // things to the person reading the card: one is "you may use this", the other
      // is "do not bind a project here, you will be refused".
      if (ex.restricted) {
        if (ex.admitted) {
          chips.push('<span class="exec-chip pos" title="This executor has an access list and '
            + 'you are on it. Managed in its Access panel.">access: restricted</span>');
        } else {
          chips.push('<span class="exec-chip neg" title="This executor has an access list and '
            + 'your account is not on it — binding a project here or starting a run will be '
            + 'refused. Managed in its Access panel.">access: denied</span>');
        }
      }
      // Shown only when true, unlike the flags below. Virtualization is not a
      // capability an executor is expected to have — the great majority of
      // correctly-configured backends share a kernel — so a "no kata" chip on
      // every row would read as a deficiency rather than as the norm.
      if (caps.virtualized) {
        chips.push('<span class="exec-chip pos" title="Workloads run in a VM with '
          + 'their own kernel (Kata Containers), so a kernel exploit reaches the '
          + 'guest rather than the executing host.">kata / VM</span>');
      }
      const flags = [
        ['stream',   caps.supports_stream],
        ['signal',   caps.supports_signal],
        ['limits',   caps.supports_resource_limits],
        ['egress',   caps.network_egress],
      ];
      flags.forEach(f => {
        chips.push('<span class="exec-chip ' + (f[1] ? 'pos' : 'neg') + '">'
          + (f[1] ? '' : 'no ') + esc(f[0]) + '</span>');
      });
      // How resources.disk is held here (Task 20405).
      const de = caps.disk_enforcement;
      chips.push('<span class="exec-chip ' + (de ? 'pos' : 'neg') + '">disk: '
        + (de ? 'enforced (' + esc(de) + ')' : 'not supported') + '</span>');
      if (caps.shares_host_filesystem) {
        chips.push('<span class="exec-chip neg">host fs</span>');
      }
      if (caps.platform) {
        chips.push('<span class="exec-chip">' + esc(caps.platform)
          + (caps.arch ? '/' + esc(caps.arch) : '') + '</span>');
      }
      if (caps.max_concurrent) {
        chips.push('<span class="exec-chip">max ' + esc(caps.max_concurrent) + '</span>');
      }
      return chips.join('');
    }

    // _execInventoryChips renders what an edge device reported about itself: its
    // cloop build, its hardware, and the harnesses it can actually invoke.
    //
    // These fields crossed the wire from the day remote executors existed, and the
    // panel showed none of them — the backend handed the browser an opaque
    // capabilities blob and nothing unpacked it. So an operator could not tell which
    // build a device was running, nor why placement had skipped it. Every chip here
    // answers one of those two questions.
    function _execInventoryChips(ex) {
      const inv = ex.inventory;
      if (!inv) return '';
      const chips = [];

      // Build first: it is the field an operator is looking for, and the one the
      // skew banner below refers to.
      if (inv.agent_version_label) {
        const skew = (ex.version_skew && ex.version_skew.skew) || '';
        // Only a material skew is coloured. Patch drift across a fleet is normal,
        // and colouring it would train operators to ignore the colour.
        const cls = (ex.version_skew && ex.version_skew.material) ? 'neg' : '';
        chips.push('<span class="exec-chip ' + cls + '" title="'
          + esc(skew ? 'Build skew: ' + skew : 'Reported cloop build') + '">build '
          + esc(inv.agent_version_label) + '</span>');
      }
      // Task 20376: the device follows the hub's signed builds, not releases only.
      if (ex.update_channel === 'edge') chips.push('<span class="exec-chip" title="Edge channel: installs this hub\'s signed builds">edge</span>');
      // Task 20380: its build's place on main; it refuses any earlier build.
      if (inv.build_sequence) chips.push('<span class="exec-chip" title="Sequence on main: the device refuses any build earlier than this">seq ' + esc(inv.build_sequence) + '</span>');
      if (inv.os) {
        chips.push('<span class="exec-chip">' + esc(inv.os)
          + (inv.arch ? '/' + esc(inv.arch) : '') + '</span>');
      }
      if (inv.cpus) {
        chips.push('<span class="exec-chip">' + esc(inv.cpus) + ' cores</span>');
      }
      // memory_label is computed server-side so every client renders the unit
      // identically; an absent one means the agent could not detect memory, which
      // is not the same as a device with none.
      if (inv.memory_label) {
        chips.push('<span class="exec-chip">' + esc(inv.memory_label) + '</span>');
      }
      (inv.harnesses || []).forEach(h => {
        chips.push('<span class="exec-chip pos" title="Harness available on this device">'
          + esc(h) + '</span>');
      });
      (inv.container_runtimes || []).forEach(r => {
        chips.push('<span class="exec-chip pos" title="Container runtime this device can drive">'
          + esc(r) + '</span>');
      });
      // Marked when the numbers came from the stored row rather than a live
      // session, so an offline device's inventory does not read as current.
      if (!inv.live && chips.length) {
        chips.push('<span class="exec-chip" title="Last reported when the device was '
          + 'connected; it is offline now.">last known</span>');
      }
      return chips.join('');
    }

    // _renderExecSweep shows the last periodic orphan sweep (Task 20281).
    //
    // It is fleet-level rather than per-card because one pass covers every driver.
    // The line is deliberately quiet when the last pass collected nothing — which
    // is the healthy steady state — and becomes loud only when a driver's sweep is
    // failing, because that is the condition an operator has to act on: a Role that
    // lost its list rule leaves a namespace filling with Pods and nothing else in
    // the UI would ever say why.
    function _renderExecSweep(sweep) {
      const box = document.getElementById('execSweep');
      if (!box) return;
      if (!sweep || !sweep.at) {
        // Not an error state. A hub that started five minutes ago has not swept
        // yet, and claiming a problem would train the operator to ignore this row.
        box.style.display = 'none';
        return;
      }
      const failures = sweep.failures || 0;
      const removed = sweep.removed || 0;
      let text = 'Orphan sweep ran ' + esc(_execAgo(sweep.at)) + ' and collected '
        + removed + (removed === 1 ? ' object' : ' objects') + '.';
      if (failures) {
        const failed = (sweep.executors || []).filter(e => e.error);
        text += ' ' + failures + (failures === 1 ? ' executor' : ' executors')
          + ' could not be swept: '
          + failed.map(e => esc(e.id) + ' (' + esc(e.error) + ')').join('; ');
      }
      box.className = 'exec-warning' + (failures ? '' : ' muted');
      box.innerHTML = text;
      box.style.display = 'block';
    }

    // _execAgo renders a timestamp as a rough age. Exact times are not useful for a
    // background job whose whole point is that nobody watches it.
    function _execAgo(iso) {
      const then = Date.parse(iso);
      if (isNaN(then)) return 'recently';
      const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
      if (secs < 90) return secs + 's ago';
      const mins = Math.round(secs / 60);
      if (mins < 90) return mins + 'm ago';
      return Math.round(mins / 60) + 'h ago';
    }

    function render(d) {
      const banner = document.getElementById('execPolicyBanner');
      const warnBox = document.getElementById('execWarnings');
      const list = document.getElementById('execList');
      const empty = document.getElementById('execEmpty');
      if (!list) return;

      const policy = (d && d.policy) || {};
      if (banner) {
        if (policy.banner) {
          const icon = policy.severity === 'ok' ? '&#128274;'
                     : policy.severity === 'warn' ? '&#9888;' : '&#8505;';
          banner.className = 'exec-banner ' + (policy.severity || 'info');
          banner.innerHTML = '<span class="exec-banner-icon">' + icon + '</span><span>'
            + esc(policy.banner) + '</span>';
          banner.style.display = 'flex';
        } else {
          banner.style.display = 'none';
        }
      }
      if (warnBox) {
        const warnings = policy.warnings || [];
        if (warnings.length) {
          warnBox.innerHTML = warnings.map(wtext =>
            '<div class="exec-warning">' + esc(wtext) + '</div>').join('');
          warnBox.style.display = 'block';
        } else {
          warnBox.style.display = 'none';
        }
      }

      // No separate "not ready" banner: executorPolicy() already renders one for
      // the identical condition (strict mode with no isolating executor) and its
      // wording names the config key. The response still carries the ready and
      // remediation fields so a client can act on the verdict without re-deriving
      // it. (No backticks in this file's JS comments — the whole dashboard is a
      // Go raw string literal and one would close it.)

      _renderExecSweep(d && d.sweep);

      const execs = (d && d.executors) || [];
      // A pool's runners are drawn on their pool's card (Task 20486), not as
      // devices: they come and go with each run. The index stays the one into
      // the full list, which every card button names.
      if (empty) empty.style.display = execs.some(ex => !ex.pool_runner) ? 'none' : 'block';

      list.innerHTML = execs.map((ex, i) => {
        if (ex.pool_runner) return '';
        const kind = _execKindLabel(ex.kind);
        let h = '<div class="exec-card' + (ex.blocked ? ' blocked' : '') + '">';
        // Everything above the action row is the drill-in target (Task 20258).
        // The wrapper exists so the buttons below stay outside it rather than
        // inside an action they would each have to fence off.
        h += '<div class="exec-card-main" data-act="detail" data-arg="' + i + '" '
          + 'title="Show what has actually run on this executor">';
        h += '<div class="exec-card-head">';
        h += '<span class="exec-dot ' + _execDotClass(ex.status) + '" title="' + esc(ex.status || 'unknown') + '"></span>';
        h += '<span class="exec-name">' + esc(ex.name || ex.id) + '</span>';
        h += '<span class="exec-kind ' + esc(kind) + '">' + esc(kind) + '</span>';
        const sched = _execStateClass(ex.sched_state);
        if (sched) {
          h += '<span class="exec-state ' + sched + '" title="' + esc(_execStateTitle(ex)) + '">'
            + esc(ex.sched_state) + '</span>';
        }
        if (ex.default) h += '<span class="exec-chip">default</span>';
        h += '</div>';
        h += '<div class="exec-id">' + esc(ex.id) + '</div>';
        h += '<div class="exec-chips">' + _execCapChips(ex) + '</div>';
        // A second row rather than appended to the first: driver capabilities are
        // about what the backend can do, device inventory is about what this
        // particular machine is, and mixing them made both unreadable.
        const invChips = _execInventoryChips(ex);
        if (invChips) {
          h += '<div class="exec-chips">' + invChips + '</div>';
        }
        // The labels label grants are matched against (Task 20432).
        if (ex.labels) {
          h += '<div class="exec-chips">' + Object.keys(ex.labels).sort().map(k =>
            '<span class="exec-chip">' + esc(k + '=' + ex.labels[k]) + '</span>').join('') + '</div>';
        }

        h += '<div class="exec-meta">';
        h += '<span>Load: ' + (ex.running_known ? esc(ex.running) + ' running' : 'unknown') + '</span>';
        // The scheduler's own count, which is not the driver's handle count above:
        // an unreadable one renders as an em dash, because claiming a node is idle
        // when it may be saturated is the worse of the two wrong answers.
        h += '<span>In flight: '
          + (ex.in_flight_known ? esc(ex.in_flight) + ' running' : '&mdash;') + '</span>';
        if (ex.last_seen) {
          h += '<span>Last seen: ' + esc(relTime(new Date(ex.last_seen))) + '</span>';
        }
        if (ex.last_heartbeat) {
          h += '<span>Last heartbeat: ' + esc(relTime(new Date(ex.last_heartbeat))) + '</span>';
        }
        if (ex.projects && ex.projects.length) {
          h += '<span>Projects: ' + esc(ex.projects.length) + ' bound</span>';
        }
        // The sandbox boundary, which an operator auditing isolation would
        // otherwise have to read out of the database.
        if (ex.inventory && ex.inventory.workdir_root) {
          h += '<span title="Every workload on this device is confined beneath this '
            + 'directory.">Workdir: ' + esc(ex.inventory.workdir_root) + '</span>';
        }
        if (ex.health) {
          h += '<span style="color:var(--yellow,#d29922)">' + esc(ex.health) + '</span>';
        }
        h += '</div>';

        if (ex.sched_reason) {
          h += '<div class="exec-sched-note">' + esc(ex.sched_reason) + '</div>';
        }
        // A device that cannot honour a revoke frame is shown before it matters,
        // not at dispatch time. The hub refuses to place brokered credentials on
        // such an agent, so without this the first symptom of a half-upgraded
        // fleet is a run that will not start.
        if (ex.revocation_note) {
          h += '<div class="exec-blocked-note">&#9888; ' + esc(ex.revocation_note) + '</div>';
        }
        // Build skew, shown only when it is material. A device trailing by a patch
        // release is normal across a fleet and a warning on every card would cost
        // the operator the one that matters. The note names the upgrade procedure
        // that actually works — it used to name a flag that did not exist.
        if (ex.version_skew && ex.version_skew.material && ex.version_skew.note) {
          h += '<div class="exec-blocked-note">&#9888; ' + esc(ex.version_skew.note) + '</div>';
        }
        // Task 20421: a build carrying no sequence is not covered by rollback
        // protection; the note says how to cover it (the doctor says the same).
        if (ex.rollback_note) h += '<div class="exec-blocked-note">&#9888; ' + esc(ex.rollback_note) + '</div>';
        if (ex.blocked && ex.blocked_reason) {
          h += '<div class="exec-blocked-note">&#9888; Blocked by policy. ' + esc(ex.blocked_reason) + '</div>';
        }
        // Startup reconciliation (Task 20170). Distinct from health above: health
        // probes a registered executor, this says whether it came up from config
        // at all — the only thing there is to report about one that did not.
        if (ex.reconcile_status && ex.reconcile_status !== 'ok') {
          h += '<div class="exec-blocked-note">&#9888; Startup ' + esc(ex.reconcile_status) + '. '
            + esc(ex.reconcile_message || '') + '</div>';
          if (ex.reconcile_remediation) {
            h += '<div class="exec-sched-note">Fix: ' + esc(ex.reconcile_remediation) + '</div>';
          }
          const fails = (ex.preflight_findings || []).filter(f => f.level === 'fail');
          if (fails.length) {
            h += '<div class="exec-sched-note">' + fails.map(f =>
              esc(f.name) + ': ' + esc(f.message)).join('<br>') + '</div>';
          }
        }

        h += '</div>'; // .exec-card-main

        h += '<div class="exec-actions">';
        // Index-based dispatch, never an interpolated string: an executor name
        // with a quote in it is exactly how Tasks 163/20033 broke.
        h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" '
          + 'data-act="detail" data-arg="' + i + '" '
          + 'title="In-flight work, recent completions, and whether anything ran on the host">History</button>';
        // Only for enrolled devices. For a driver the hub builds itself the mode is
        // implied by the driver and lives in config.yaml, so offering the button
        // would promise a control that could not take effect (Task 20307).
        if (ex.kind === 'remote') {
          h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" '
            + 'data-act="sandbox" data-arg="' + i + '" '
            + 'title="Whether payloads run on this device&#39;s host or in a container on it, and under which runtime">Sandbox</button>'
            + '<button class="btn" style="padding:3px 9px;font-size:11.5px" data-act="labels" data-arg="' + i + '">Labels</button>';
        }
        // Sub-executors with their own firewall and devices (Task 20345).
        if (ex.kind === 'remote' || ex.kind === 'virtual') {
          h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" data-act="virtual" data-arg="' + i + '" '
            + 'title="Sandboxes on this device with their own runtime, IP firewall and USB devices">'
            + (ex.kind === 'virtual' ? 'Edit' : 'Virtual' + (ex.virtual_count ? ' (' + esc(ex.virtual_count) + ')' : '')) + '</button>';
        }
        // A device's firewall rule set (Task 20363): the superset its sandboxes
        // and its virtual executors' must fit inside. Not for a virtual executor,
        // whose firewall is part of its definition, nor the host-process driver,
        // which has no network of a workload's own to filter.
        if (ex.kind === 'remote' || ex.kind === 'container' || ex.kind === 'kubernetes') {
          h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" data-act="firewall" data-arg="' + i + '" '
            + 'title="The most any sandbox here may reach">Firewall</button>';
        }
        // Limits and Access apply to every executor kind, unlike Sandbox above: a
        // ceiling bounds whatever the driver hands out, and an access list names
        // who may reach the device at all. Neither is implied by the driver, so
        // both are offered for hub-configured backends as well as enrolled ones
        // (Task 20310).
        h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" '
          + 'data-act="limits" data-arg="' + i + '" '
          + 'title="The most CPU, memory, disk and processes any one workload here may be given">Limits</button>';
        h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" '
          + 'data-act="audience" data-arg="' + i + '" '
          + 'title="Which users and groups may run work on this executor">Access</button>';
        if (ex.admin_held) {
          h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" data-act="uncordon" data-arg="' + i + '">Uncordon</button>';
        } else {
          h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" data-act="cordon" data-arg="' + i + '">Cordon</button>';
          h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" data-act="drain" data-arg="' + i + '">Drain</button>';
        }
        if (ex.enrolled && ex.kind === 'remote') {
          h += _execUpgradeButton(ex, i);
          h += '<button class="btn danger" style="padding:3px 9px;font-size:11.5px" data-act="revoke" data-arg="' + i + '">Revoke</button>';
        } else if (ex.virtual) {
          h += '<span style="font-size:11px;color:var(--muted)">Virtual executor on ' + esc(ex.virtual.parent_name || ex.virtual.parent_id) + '</span>';
        } else {
          h += '<span style="font-size:11px;color:var(--muted)">Configured in .cloop/config.yaml</span>';
        }
        h += '</div>';
        h += '</div>';
        return h;
      }).join('');
      // Each runtime's claim against what the isolation probe found (Task 20439).
      if (ea) ea.isolationChips();
      loadFleetAutoUpdate();
      // And the pools, which every executor_update may have changed: a runner
      // enrolling or retiring, or the hub's notice that a pool changed.
      loadPools();
    }

    // ── Rolling the fleet forward (Task 20331) ──────────────────────────────────
    //
    // The panel has always been able to say a device was out of date — the skew
    // chip and its note have been rendered since the fleet inventory landed — and
    // the note's advice was to go and SSH into the machine. For the edge devices
    // this hub is built to adopt, sitting behind NAT in buildings nobody is
    // visiting, that advice is not something an operator can act on.
    //
    // So the skew becomes a button. Two things it deliberately does not do:
    //
    //   It does not promise the upgrade worked. The device restarts to finish, so
    //   the session carrying the request dies mid-flight and the only honest report
    //   the hub can make is "it accepted and is trying". The confirmation is the
    //   device reconnecting with a new build, which arrives as an ordinary executor
    //   update and repaints the row. The toast says so rather than claiming success.
    //
    //   It does not hide itself when a device looks current. "Current" is a
    //   comparison against a build the *hub* is running, and an operator pinning
    //   the fleet to an older release, or reinstalling one that was interrupted
    //   halfway, has a legitimate reason to press it anyway. It is styled down to
    //   a plain button instead, and says why in its tooltip.

    // _execUpgradeButton renders the per-device Upgrade control.
    function _execUpgradeButton(ex, i) {
      const skew = ex.version_skew || {};
      const material = !!skew.material;
      const current = (ex.inventory && ex.inventory.agent_version_label) || 'an unreported build';
      // Highlighted only when the device is genuinely behind. A panel where every
      // row shows an emphasised Upgrade button trains an operator to ignore it,
      // which is the opposite of what a fleet with one stale device needs.
      const cls = material ? 'btn primary' : 'btn';
      const title = material
        ? 'This device is running ' + current + ' and the hub is on '
          + (skew.hub_version || 'a newer build') + '. Roll it forward now.'
        : 'Reinstall or change this device’s build. It reports ' + current + '.';
      return '<button class="' + cls + '" style="padding:3px 9px;font-size:11.5px" '
        + 'data-act="upgrade" data-arg="' + i + '" title="' + esc(title) + '">Upgrade</button>';
    }

    // ── Fleet auto-update policy ────────────────────────────────────────────────
    //
    // The bar is built here rather than in index.html so the panel's markup stays
    // in one place with the code that fills it, and so this lands without an edit
    // to the shared page shell.


    function _autoUpdateBar() {
      let bar = document.getElementById('fleetAutoUpdateBar');
      if (bar) return bar;
      const list = document.getElementById('execList');
      if (!list || !list.parentNode) return null;
      bar = document.createElement('div');
      bar.id = 'fleetAutoUpdateBar';
      bar.style.cssText = 'margin:0 0 12px;padding:10px 12px;border:1px solid var(--border);'
        + 'border-radius:8px;font-size:12.5px;display:flex;align-items:center;gap:10px;flex-wrap:wrap';
      list.parentNode.insertBefore(bar, list);
      return bar;
    }

    function loadFleetAutoUpdate(force) {
      // Served from cache unless an edit invalidated it: render() runs on every
      // executor event, and a policy re-fetched with it would put a second request
      // behind each one for a value that only changes when an admin edits it — the
      // shape of the caps-panel regression in Task 20326.
      const cached = h.fleet();
      if (cached && !force) { _renderAutoUpdateBar(cached); return Promise.resolve(cached); }
      return api('/api/fleet/autoupdate').then(d => {
        if (!d || d.error) return null;
        h.fleet(d);   // kept by the bundle for execadmin's dialog, and drawn by fleetBar
        return d;
      }).catch(() => null);
    }

    function _renderAutoUpdateBar(d) {
      const bar = _autoUpdateBar();
      if (!bar) return;
      const eff = d.effective || {};
      const on = !!d.enabled;
      const target = eff.target_version || d.hub_version || 'this hub’s build';
      let h = '<strong>Automatic upgrades</strong>';
      h += '<span class="exec-chip ' + (on ? 'pos' : 'neg') + '">' + (on ? 'on' : 'off') + '</span>';
      if (on) {
        // The effective values, not the stored ones: an empty target means "match
        // the hub", and showing a blank would leave the operator to guess.
        h += '<span style="color:var(--muted)">converging the fleet on <code>' + esc(target)
          + '</code>, ' + esc(String(eff.max_in_flight || 1)) + ' at a time</span>';
      } else {
        h += '<span style="color:var(--muted)">devices stay on their current build until '
          + 'upgraded by hand</span>';
      }
      h += '<button class="btn" style="padding:3px 9px;font-size:11.5px;margin-left:auto" '
        + 'data-act="editFleet">Configure</button>';
      bar.innerHTML = h;
    }


    // ── Executor pools (Task 20486) ─────────────────────────────────────────────
    //
    // A pool's runners are Pods the executor controller starts on a Kubernetes
    // cluster as the pool's queued runs need them. This section lists the pools
    // with what the hub knows of each: its demand, its runners, its volumes, its
    // controller's build and when that controller last made contact, and the
    // problems hub doctor reports for it, from the same assessment. The dialog
    // adds one in a single step: the pool, its access list and a controller
    // credential, and the commands that install the controller with all of it
    // filled in, shown once like an edge device's join command.
    //
    // Administrators only: every pool route needs executor.manage, so the
    // section is hidden from anyone else and never fetched for them. Every
    // change asks a session on a hub with sign-on for a recent sign-in, which
    // the shared request path handles.
    let pools = [], poolMeta = {}, poolSeq = 0, poolCreated = false;

    function loadPools() {
      const sec = document.getElementById('poolSection');
      if (!sec) return;
      if (!h.canGlobal('executor.manage')) { sec.style.display = 'none'; return; }
      sec.style.display = '';
      const seq = ++poolSeq;
      api('/api/executor-pools').then(d => {
        if (seq !== poolSeq) return; // a newer read is on its way
        if (!d || d.error) { _renderPools(null, (d && d.error) || 'The executor pools could not be read.'); return; }
        poolMeta = d;
        pools = (d.pools || []).filter(p => !_poolRevoked(p));
        _renderPools(pools, '', (d.pools || []).length - pools.length);
      }).catch(err => {
        if (seq === poolSeq) _renderPools(null, h.execErr(err) || 'The executor pools could not be read.');
      });
    }

    // A zero time is how the API writes "never": 0001-01-01.
    const _poolSet = t => !!t && t.slice(0, 4) !== '0001';
    const _poolRevoked = p => _poolSet(p.revoked_at);

    function _renderPools(list, err, revoked) {
      const box = document.getElementById('poolList'), empty = document.getElementById('poolEmpty');
      if (!box) return;
      if (err) {
        if (empty) empty.style.display = 'none';
        box.innerHTML = '<div class="exec-warning" role="alert">' + esc(err) + '</div>';
        return;
      }
      if (empty) empty.style.display = list.length ? 'none' : 'block';
      box.innerHTML = list.map(_poolCard).join('') + (revoked
        ? '<div class="form-hint" style="grid-column:1/-1">' + revoked + ' revoked pool' + (revoked === 1 ? ' is' : 's are')
          + ' not shown: cloop executor pool list shows them.</div>' : '');
    }

    // _poolCard draws one pool. The dot answers "will my runs start": green
    // when its controller made contact in the last five minutes and nothing
    // needs a person, yellow for a warning, red when runs wait that nothing
    // will start.
    function _poolCard(p, i) {
      const s = p.snapshot || {}, hl = p.health || {}, ctl = hl.controller, st = hl.storage;
      const problems = hl.problems || [];
      const fail = problems.some(x => x.severity === 'fail');
      const recent = _poolSet(hl.last_contact) && Date.now() - Date.parse(hl.last_contact) < 300000;
      const dot = fail ? 'unknown' : problems.length ? 'degraded' : recent ? 'online' : 'offline';
      const dotTitle = fail ? 'Runs wait that nothing will start' : problems.length ? 'Needs attention'
        : recent ? 'Its controller is in contact' : 'No recent contact from a controller';
      let c = '<div class="exec-card' + (fail ? ' blocked' : '') + '" data-pool="' + esc(p.id) + '">';
      c += '<div class="exec-card-head"><span class="exec-dot ' + dot + '" title="' + esc(dotTitle) + '"></span>'
        + '<span class="exec-name">' + esc(p.name) + '</span><span class="exec-kind remote">pool</span>'
        + (p.cordoned
          ? '<span class="exec-state cordoned" title="Held by an administrator: no run is handed to its runners and no runner is started. Busy runners finish.">cordoned</span>'
          : '<span class="exec-state ready" title="Its waiting runs are handed to runners as they start.">live</span>')
        + '</div><div class="exec-id">' + esc(p.binding || 'pool:' + p.id) + '</div>';
      const chips = Object.keys(p.labels || {}).sort().map(k => '<span class="exec-chip">' + esc(k + '=' + p.labels[k]) + '</span>')
        .concat(((p.capabilities || {}).harnesses || []).map(x => '<span class="exec-chip pos" title="A harness its runners have">' + esc(x) + '</span>'));
      if (ctl) {
        chips.push('<span class="exec-chip' + (ctl.behind ? ' neg' : '') + '" title="' + esc(ctl.behind
          ? 'Its controller speaks pool-controller protocol ' + ctl.protocol + '; this hub speaks ' + (poolMeta.hub_protocol || '?') + '. Upgrade it.'
          : 'The build its controller named on its last request') + '">controller ' + esc(ctl.version || 'unnamed build')
          + (ctl.behind ? ', behind' : '') + '</span>');
      }
      if (p.owner) chips.push('<span class="exec-chip" title="Its runners run only projects this person may read">owner: ' + esc(p.owner) + '</span>');
      if (chips.length) c += '<div class="exec-chips">' + chips.join('') + '</div>';
      // Its runners, one chip each, the busy first: what scaling looks like.
      const rs = (s.runner_states || []).slice().sort((a, b) => (a.state === 'busy' ? 0 : 1) - (b.state === 'busy' ? 0 : 1));
      if (rs.length) {
        c += '<div class="exec-chips">' + rs.slice(0, 12).map(r => '<span class="exec-chip' + (r.state === 'busy' ? ' pos' : '')
          + '" title="' + esc('Runner ' + r.name + ': ' + r.state + (r.project_name ? ', running ' + r.project_name : '')) + '">'
          + esc(r.name) + ' · ' + esc(r.state === 'pending' ? 'starting' : r.state) + '</span>').join('')
          + (rs.length > 12 ? '<span class="exec-chip">+' + (rs.length - 12) + ' more</span>' : '') + '</div>';
      }
      c += '<div class="exec-meta">';
      c += '<span>Demand: ' + esc(s.waiting || 0) + ' run' + (s.waiting === 1 ? '' : 's') + ' waiting</span>';
      c += '<span>Runners: ' + esc(s.busy || 0) + ' busy, ' + esc(s.idle || 0) + ' idle, ' + esc(s.pending || 0)
        + ' starting, of ' + esc(p.max_runners) + '</span>';
      if (st) {
        c += '<span>Volumes: ' + esc(st.bound) + ' of ' + esc(st.claims) + ' bound'
          + (st.pending ? ', ' + esc(st.pending) + ' pending' : '') + (st.in_use ? ', ' + esc(st.in_use) + ' in use' : '')
          + (st.bytes_capacity ? ', ' + esc(h.fmtBytes(st.bytes_used)) + ' of ' + esc(h.fmtBytes(st.bytes_capacity)) + ' used' : '')
          + '</span>';
      }
      c += '<span>Controller: ' + (ctl ? 'protocol ' + esc(ctl.protocol) : 'none has made contact')
        + ' · last contact ' + (_poolSet(hl.last_contact) ? esc(relTime(new Date(hl.last_contact))) : 'never') + '</span>';
      if (p.cordoned) {
        c += '<span>Cordoned by ' + esc(p.cordoned_by || 'an administrator') + (_poolSet(p.cordoned_at)
          ? ' ' + esc(relTime(new Date(p.cordoned_at))) : '') + (p.cordon_reason ? ': ' + esc(p.cordon_reason) : '') + '</span>';
      }
      c += '</div>';
      problems.forEach(pr => {
        c += '<div class="exec-' + (pr.severity === 'fail' ? 'blocked' : 'sched') + '-note">&#9888; ' + esc(pr.message)
          + (pr.remedy ? '<br>Fix: ' + esc(pr.remedy) : '') + '</div>';
      });
      const b = (act, label, title, cls) => '<button class="btn' + (cls || '') + '" style="padding:3px 9px;font-size:11.5px" data-act="'
        + act + '" data-arg="' + i + '" title="' + esc(title) + '">' + label + '</button>';
      c += '<div class="exec-actions">' + (p.cordoned
        ? b('uncordonPool', 'Uncordon', 'Hand its waiting runs to runners again')
        : b('cordonPool', 'Cordon', 'Stop handing runs to its runners and starting new ones; busy runners finish'))
        + b('revokePool', 'Revoke', 'Revoke the pool: its credentials, runners and queued runs go with it', ' danger') + '</div>';
      return c + '</div>';
    }

    function _poolChange(i, path, body, done) {
      const p = pools[+i];
      if (!p) return;
      apiMethod('POST', '/api/executor-pools/' + encodeURIComponent(p.id) + path, body).then(d => {
        if (!d || d.error) { toast((d && d.error) || 'The pool was not changed', 'err'); return; }
        toast(done(p, d), 'ok');
        loadPools();
      }).catch(err => toast(h.execErr(err) || 'The pool was not changed', 'err'));
    }

    function cordonPool(i) {
      const p = pools[+i];
      if (!p) return;
      const reason = prompt('Cordon ' + p.name + '? No run is handed to its runners and no runner is started until '
        + 'you uncordon it. Busy runners finish their runs.\n\nWhy (optional, shown to the people whose runs wait):', '');
      if (reason === null) return;
      _poolChange(i, '/cordon', {reason: reason.trim()}, x => 'Cordoned ' + x.name);
    }

    function uncordonPool(i) {
      _poolChange(i, '/uncordon', {}, x => 'Uncordoned ' + x.name);
    }

    function revokePool(i) {
      const p = pools[+i];
      if (!p) return;
      const busy = (p.snapshot || {}).busy || 0;
      if (!confirm('Revoke executor pool ' + p.name + '?\n\nIts controller credentials stop working, its runners are '
        + 'retired and the leases of their runs closed, and the runs waiting for it are cancelled'
        + (busy ? ', including ' + busy + ' in progress' : '') + '. This cannot be undone.')) return;
      _poolChange(i, '/revoke', {}, (x, d) => 'Revoked ' + x.name + ': ' + ((d.runners || []).length) + ' runner'
        + ((d.runners || []).length === 1 ? '' : 's') + ' retired');
    }

    // ── The dialog ──────────────────────────────────────────────────────────────

    const _pv = id => (document.getElementById(id) || {}).value || '';

    function addPool() {
      poolCreated = false;
      document.getElementById('poolForm').style.display = '';
      document.getElementById('poolResult').style.display = 'none';
      _poolError('');
      ['poolName', 'poolLabels', 'poolAudience', 'poolNamespace', 'poolStorageClass'].forEach(id => {
        document.getElementById(id).value = '';
      });
      document.getElementById('poolMax').value = '4';
      document.getElementById('poolSize').value = '20Gi';
      document.getElementById('poolReclaim').selectedIndex = 0; // delete what the pool no longer needs
      document.getElementById('poolPersist').checked = false;
      poolPersist();
      poolNameInput();
      window.openOverlay('pool-overlay', {dismiss: closePool, focus: document.getElementById('poolName')});
    }

    function closePool() {
      window.closeOverlay('pool-overlay');
      // The credential leaves the page with the dialog, wherever it was shown:
      // in the commands, or beside the reason there are none.
      ['poolCommand', 'poolUnavailable', 'poolNotice', 'poolPin', 'poolCreatedLine'].forEach(id => {
        document.getElementById(id).textContent = '';
      });
      if (poolCreated) loadPools();
    }

    function poolPersist() {
      document.getElementById('poolPersistFields').style.display = document.getElementById('poolPersist').checked ? '' : 'none';
    }

    // The namespace the install goes to unless another is typed: one per pool.
    function poolNameInput() {
      const n = _pv('poolName').trim().toLowerCase();
      document.getElementById('poolNamespace').placeholder = n ? ('cloop-' + n).slice(0, 63).replace(/-+$/, '') : 'cloop-<name>';
    }

    function _poolError(msg) {
      const el = document.getElementById('poolError');
      el.textContent = msg;
      el.style.display = msg ? '' : 'none';
    }

    // _poolList reads a comma- or line-separated list; each must match re, or
    // the entry is named in the error.
    function _poolList(raw, re, what) {
      const out = [];
      raw.split(/[\n,]+/).map(x => x.trim()).filter(Boolean).forEach(x => {
        if (!re.test(x)) throw new Error('"' + x + '" is not ' + what);
        out.push(x);
      });
      return out;
    }

    function submitPool() {
      let labels = {}, audience = [];
      try {
        _poolList(_pv('poolLabels'), /^[^=\s]+=[^=]*$/, 'a label as key=value').forEach(x => {
          const k = x.slice(0, x.indexOf('=')); labels[k] = x.slice(k.length + 1);
        });
        audience = _poolList(_pv('poolAudience'), /^(user|group|role):\S+$/i, 'user:<email>, group:<name> or role:<role>')
          .map(x => ({kind: x.slice(0, x.indexOf(':')).toLowerCase(), value: x.slice(x.indexOf(':') + 1)}));
      } catch (e) { _poolError(e.message); return; }
      const max = parseInt(_pv('poolMax'), 10);
      if (!(max >= 1 && max <= 1000)) { _poolError('Max runners must be between 1 and 1000.'); return; }
      const body = {name: _pv('poolName').trim(), max_runners: max, labels, audience, credential: true,
        kubernetes: {namespace: _pv('poolNamespace').trim()}};
      if (document.getElementById('poolPersist').checked) {
        body.kubernetes.persistence = {enabled: true, size: _pv('poolSize').trim(),
          storage_class: _pv('poolStorageClass').trim(), reclaim_policy: _pv('poolReclaim')};
      }
      _poolError('');
      const btn = document.getElementById('poolSubmitBtn');
      btn.disabled = true;
      api('/api/executor-pools', body).then(d => {
        btn.disabled = false;
        if (!d || d.error || !d.pool) { _poolError((d && d.error) || 'The pool was not created.'); return; }
        poolCreated = true;
        _poolResult(d);
        loadPools();
      }).catch(err => {
        btn.disabled = false;
        _poolError(h.execErr(err) || 'The pool was not created.');
      });
    }

    function _poolResult(d) {
      const ins = d.install || {};
      document.getElementById('poolForm').style.display = 'none';
      document.getElementById('poolResult').style.display = '';
      document.getElementById('poolNotice').textContent = d.notice || '';
      document.getElementById('poolCreatedLine').textContent = 'Created ' + d.pool.name + ' (' + d.pool.binding
        + '). Bind a project to it from the project’s executor picker.';
      document.getElementById('poolCommand').textContent = ins.command || '';
      document.getElementById('poolCommandGroup').style.display = ins.command ? '' : 'none';
      const un = document.getElementById('poolUnavailable');
      un.textContent = ins.unavailable ? ins.unavailable + (d.token ? ' The credential, shown once: ' + d.token : '') : '';
      un.style.display = ins.unavailable ? '' : 'none';
      document.getElementById('poolNotes').innerHTML = (ins.notes || []).map(n => '<li>' + esc(n) + '</li>').join('');
      document.getElementById('poolPin').textContent = ins.pin ? 'The controller pins this hub’s key: ' + ins.pin : '';
      const focus = document.getElementById(ins.command ? 'poolCopyBtn' : 'poolDoneBtn');
      if (focus) focus.focus();
    }

    function copyPoolCommand() {
      const text = document.getElementById('poolCommand').textContent || '';
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => toast('Install commands copied', 'ok'),
          () => toast('Copy failed: select the text yourself', 'err'));
      } else {
        toast('No clipboard here: select the text yourself', 'err');
      }
    }

    // Every visit reads the fleet afresh: loadExecutors is the bundle's, since the
    // Overview's executor card needs the same payload, and draws this list through
    // render(). The Forwarders section below is execadmin's, which the bundle
    // started fetching when the tab was chosen.
    function open() {
      window.loadExecutors();
      return h.panel('execadmin').then(p => { ea = p; p.isolationChips(); p.loadForwarders(); }, () => {});
    }

    return h.mount({open, render, loadPools, addPool, closePool, poolPersist, poolNameInput, submitPool, copyPoolCommand,
      cordonPool, uncordonPool, revokePool, fleetBar: _renderAutoUpdateBar, detail: fwd('openExecutorDetail'), sandbox: fwd('openExecutorSandbox'), labels: fwd('openExecutorLabels'), virtual: fwd('openExecutorVirtual'), firewall: fwd('openExecutorFirewall'), limits: fwd('openExecutorLimits'), audience: fwd('openExecutorAudience'), upgrade: fwd('upgradeExecutor'), revoke: fwd('revokeExecutor'), cordon: fwd('cordonExecutor'), uncordon: fwd('uncordonExecutor'), drain: fwd('drainExecutor'), editFleet: () => h.panelAct('execadmin', 'editFleetAutoUpdate')}, 'executors', `
    <div class="section">
      <div class="section-title" style="display:flex;flex-wrap:wrap;align-items:center;gap:12px">
        Executors
        <span style="font-size:11px;font-weight:400;color:var(--muted)">global &mdash; shared by every project</span>
        <button class="btn" style="padding:4px 10px;font-size:12px;margin-left:auto" data-action="loadExecutors" title="Refresh executor list">&#8635; Refresh</button>
        <button class="btn primary" data-global-perm="executor.manage" style="padding:4px 10px;font-size:12px" data-action="openEnrollModal" title="Mint an enrollment token for a remote device">+ Enroll device</button>
      </div>
      <p style="font-size:12px;color:var(--muted);margin-top:4px;margin-bottom:12px">
        An executor is where a harness actually runs. <strong>Host</strong> forks a child process of this
        server with its user, filesystem, and network &mdash; no isolation. <strong>Container</strong> runs
        the workload in a Docker/Podman sandbox on this machine. <strong>Remote</strong> dispatches it to an
        enrolled edge device that dialled out to this control plane. Bind a project to one from its Overview tab.
      </p>

      <div id="execPolicyBanner" class="exec-banner" style="display:none"></div>
      <div id="execWarnings" style="display:none;margin-bottom:12px"></div>
      <div id="execSweep" style="display:none;margin-bottom:12px"></div>

      <div id="execEmpty" class="empty-state" style="display:none;text-align:left;max-width:720px;margin:0 auto">
        <h3 style="text-align:center">No executors yet</h3>
        <p style="text-align:center;margin-bottom:16px">
          Expected on a hardened hub: with <code>executors.allow_host_process: false</code> the built-in
          host driver is refused, so the first executor is one you add. Runs are refused until then.
        </p>

        <p style="margin-bottom:6px"><strong>1.</strong> Mint a single-use enrollment token on this hub:</p>
        <div class="exec-token" style="margin-bottom:12px">cloop executor enroll --name edge-1</div>

        <p style="margin-bottom:6px"><strong>2.</strong> Run the printed command on the device. It dials
          <em>outward</em>, so the device needs no inbound port and may sit behind NAT:</p>
        <div class="exec-token" style="margin-bottom:16px">cloop executor agent --bundle &lt;bundle-from-step-1&gt;</div>

        <p style="text-align:center;margin-bottom:16px">
          <button class="btn primary" data-global-perm="executor.manage"
                  style="padding:6px 14px;font-size:13px" data-action="openEnrollModal">+ Enroll a device</button>
        </p>

        <p style="text-align:center">
          A container or Kubernetes executor needs no enrollment &mdash; enable one under
          <code>executors:</code> in <code>.cloop/config.yaml</code>. Run <code>cloop hub doctor</code>
          to check the whole configuration, and see
          <a href="https://github.com/blechschmidt/cloop/blob/main/docs/architecture/executors.md"
             target="_blank" rel="noopener noreferrer">docs/architecture/executors.md</a>
          for what each backend isolates.
        </p>
      </div>
      <div id="execList" class="exec-grid"></div>
    </div>

    <div class="section" id="poolSection" style="display:none">
      <div class="section-title" style="display:flex;flex-wrap:wrap;align-items:center;gap:12px">
        Executor pools
        <span style="font-size:11px;font-weight:400;color:var(--muted)">global &mdash; runners a Kubernetes cluster starts on demand</span>
        <button class="btn" style="padding:4px 10px;font-size:12px;margin-left:auto" data-act="loadPools" title="Refresh the pool list">&#8635; Refresh</button>
        <button class="btn primary" style="padding:4px 10px;font-size:12px" data-act="addPool" title="Create a pool and get the commands that install its controller">+ Add Kubernetes pool</button>
      </div>
      <p style="font-size:12px;color:var(--muted);margin-top:4px;margin-bottom:12px">
        A project bound to a pool queues its runs there. The executor controller on your cluster starts a runner Pod
        for each waiting run, up to the pool&#39;s maximum, and each runner takes one run and exits.
      </p>
      <div id="poolEmpty" class="form-hint" style="display:none;margin-bottom:12px">No executor pools yet. Add one to run projects on a Kubernetes cluster.</div>
      <div id="poolList" class="exec-grid"></div>
    </div>

    <div class="section">
      <div class="section-title" style="display:flex;flex-wrap:wrap;align-items:center;gap:12px">
        Device forwarders
        <span style="font-size:11px;font-weight:400;color:var(--muted)">global &mdash; on-prem hardware bridged to this hub</span>
        <button class="btn" style="padding:4px 10px;font-size:12px;margin-left:auto" data-action="loadForwarders" title="Refresh forwarder list">&#8635; Refresh</button>
        <button class="btn primary" data-global-perm="executor.manage" style="padding:4px 10px;font-size:12px" data-action="openForwarderEnroll" title="Enroll a device forwarder">+ Enroll forwarder</button>
      </div>
      <p style="font-size:12px;color:var(--muted);margin-top:4px;margin-bottom:12px">
        A forwarder is a minimal binary on an on-prem machine that bridges <strong>one</strong> USB device or
        network interface to this hub over a single outbound connection &mdash; and does nothing else. It lets an
        agent in an isolated cloud sandbox reach on-prem hardware without that machine running the agent itself.
      </p>
      <div id="fwdList" class="exec-grid"></div>
      <div id="fwdExposeResult" style="margin-top:10px"></div>
    </div>
    `, `
      <div id="pool-overlay" data-overlay="flex" data-dismiss="closePool" aria-labelledby="poolTitle" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:50;align-items:center;justify-content:center">
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;width:640px;max-width:95vw;max-height:90vh;overflow:auto">
          <h2 id="poolTitle" style="font-size:15px;font-weight:600;margin-bottom:6px">Add a Kubernetes executor pool</h2>
          <p style="font-size:12px;color:var(--muted);margin-bottom:14px;line-height:1.5">
            This creates the pool and a credential for its controller, then shows the commands that install the
            controller on your cluster with this hub&#39;s address and the credential filled in. The controller dials
            <em>out</em> to this hub, so the cluster needs no inbound access.
          </p>
          <div id="poolForm">
            <div class="form-row">
              <div class="form-group">
                <label class="form-label" for="poolName">Name</label>
                <input class="form-input" id="poolName" placeholder="e.g. gpu" maxlength="63" autocomplete="off" spellcheck="false" data-input="poolNameInput" data-enter="submitPool">
                <div class="form-hint">Lowercase letters, digits and dashes.</div>
              </div>
              <div class="form-group">
                <label class="form-label" for="poolMax">Max runners</label>
                <input class="form-input" id="poolMax" type="number" min="1" max="1000" value="4" data-enter="submitPool">
                <div class="form-hint">The most Pods it runs at once.</div>
              </div>
            </div>
            <div class="form-group">
              <label class="form-label" for="poolLabels">Labels (optional)</label>
              <input class="form-input" id="poolLabels" placeholder="region=eu, gpu=true" spellcheck="false" data-enter="submitPool">
              <div class="form-hint">Its runners enroll with these: what a grant to <code>label:gpu=true</code> reaches.</div>
            </div>
            <div class="form-group">
              <label class="form-label" for="poolAudience">Who may run work on it (optional)</label>
              <input class="form-input" id="poolAudience" placeholder="group:ml-team, user:alice@example.com" spellcheck="false" data-enter="submitPool">
              <div class="form-hint">Users, groups or roles. Leave it empty to let every project bound to the pool run there.</div>
            </div>
            <div class="form-group">
              <label class="form-label" for="poolNamespace">Kubernetes namespace (optional)</label>
              <input class="form-input" id="poolNamespace" placeholder="cloop-&lt;name&gt;" spellcheck="false" data-enter="submitPool">
              <div class="form-hint">One controller per namespace. The commands create it and hold it to the restricted Pod Security profile.</div>
            </div>
            <div class="form-group">
              <label style="display:flex;gap:8px;align-items:flex-start;font-size:13px;cursor:pointer">
                <input type="checkbox" id="poolPersist" data-change="poolPersist" style="margin-top:3px">
                <span>Keep a volume per project, so a project&#39;s next run starts with its workspace and caches
                  <span class="form-hint" style="display:block">A volume that held one project&#39;s data is wiped before another project&#39;s run gets it.</span></span>
              </label>
            </div>
            <div id="poolPersistFields" style="display:none">
              <div class="form-row">
                <div class="form-group">
                  <label class="form-label" for="poolSize">Volume size</label>
                  <input class="form-input" id="poolSize" value="20Gi" spellcheck="false" data-enter="submitPool">
                </div>
                <div class="form-group">
                  <label class="form-label" for="poolStorageClass">Storage class (optional)</label>
                  <input class="form-input" id="poolStorageClass" placeholder="the cluster&#39;s default" spellcheck="false" data-enter="submitPool">
                </div>
              </div>
              <div class="form-group">
                <label class="form-label" for="poolReclaim">Volumes the pool no longer needs</label>
                <select class="form-input form-select" id="poolReclaim">
                  <option value="Delete">Delete them</option>
                  <option value="Retain">Keep them, with the record of whose data they hold</option>
                </select>
              </div>
            </div>
            <div id="poolError" role="alert" style="font-size:12px;color:var(--red);margin-bottom:8px;display:none"></div>
            <div class="modal-footer">
              <button class="btn" data-act="closePool">Cancel</button>
              <button class="btn primary" id="poolSubmitBtn" data-act="submitPool">Create pool</button>
            </div>
          </div>
          <div id="poolResult" style="display:none">
            <div class="exec-banner warn" style="margin-bottom:12px">
              <span class="exec-banner-icon">&#9888;</span>
              <span id="poolNotice"></span>
            </div>
            <p id="poolCreatedLine" style="font-size:12.5px;margin-bottom:10px"></p>
            <div class="form-group" id="poolCommandGroup">
              <label class="form-label" for="poolCommand">Run these where kubectl and helm reach the cluster</label>
              <pre class="exec-token" id="poolCommand" tabindex="0" style="white-space:pre-wrap;margin:0;max-height:40vh;overflow:auto"></pre>
            </div>
            <div class="exec-banner warn" id="poolUnavailable" style="display:none;margin-bottom:12px;overflow-wrap:anywhere"></div>
            <ul id="poolNotes" style="font-size:11.5px;color:var(--muted);margin:0 0 10px 18px;line-height:1.5"></ul>
            <div id="poolPin" style="font-size:11.5px;color:var(--muted);margin-bottom:12px;overflow-wrap:anywhere"></div>
            <div class="modal-footer">
              <button class="btn" id="poolCopyBtn" data-act="copyPoolCommand">Copy commands</button>
              <button class="btn primary" id="poolDoneBtn" data-act="closePool">Done</button>
            </div>
          </div>
        </div>
      </div>
    `);
  };
})();
