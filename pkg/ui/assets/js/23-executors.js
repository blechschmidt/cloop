// ── Executors panel (Task 20160) ────────────────────────────────────────────
//
// The panel is global: executors are shared infrastructure, not project state.
// It still calls pUrl() because the backend enriches the response with the
// *selected* project's binding, which is what powers the Overview card and
// the picker's "currently bound" preselection.
let execData = null;

window.loadExecutors = function() {
  // The fleet is not a project's to read: a member whose only role is on a
  // shared project would draw a refusal on every Overview (Task 20366).
  if (!canGlobal('executor.read')) return Promise.resolve(null);
  return api(pUrl('/api/executors')).then(d => {
    execData = d || {};
    _renderExecutors(execData);
    _renderExecutorCard(execData);
    // The project's firewall card shows its executor's rules, so it moves with
    // every fleet change the Overview hears about (Task 20363).
    // And the Claude credential card, which exists only on an isolating
    // executor (Task 20379).
    if (activeTab === 'overview') { loadProjectFirewall(); loadHarnessCred(); }
    // Cached behind its own guard. loadExecutors runs on every executor event,
    // and a policy that re-fetched with it would put a second request behind
    // each one for a value that only changes when an admin edits it — the
    // shape of the caps-panel regression in Task 20326.
    loadFleetAutoUpdate();
    return execData;
  }).catch(err => {
    console.warn('executors load error', err);
    const list = document.getElementById('execList');
    if (list) {
      list.innerHTML = '<div style="font-size:13px;color:var(--red)">Failed to load executors: '
        + esc(err && err.message || String(err)) + '</div>';
    }
  });
};

function _execDotClass(status) {
  if (status === 'online' || status === 'offline' || status === 'degraded') return status;
  return 'unknown';
}

function _execKindLabel(kind) {
  if (kind === 'localprocess') return 'host';
  if (kind === 'container') return 'container';
  if (kind === 'remote') return 'remote';
  return kind || 'unknown';
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

function _renderExecutors(d) {
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
  if (empty) empty.style.display = execs.length ? 'none' : 'block';

  list.innerHTML = execs.map((ex, i) => {
    const kind = _execKindLabel(ex.kind);
    let h = '<div class="exec-card' + (ex.blocked ? ' blocked' : '') + '">';
    // Everything above the action row is the drill-in target (Task 20258).
    // The wrapper exists so the buttons below stay outside it: a card-wide
    // handler would need the buttons to stopPropagation, and an onclick whose
    // first token is `event` is invisible to the reachability gate in
    // frontend_test.go — the fix would have quietly disabled the check that
    // keeps Cordon and Drain wired.
    h += '<div class="exec-card-main" onclick="panelAct(\'execadmin\',\'openExecutorDetail\',' + i + ')" '
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
      + 'onclick="panelAct(\'execadmin\',\'openExecutorDetail\',' + i + ')" '
      + 'title="In-flight work, recent completions, and whether anything ran on the host">History</button>';
    // Only for enrolled devices. For a driver the hub builds itself the mode is
    // implied by the driver and lives in config.yaml, so offering the button
    // would promise a control that could not take effect (Task 20307).
    if (ex.kind === 'remote') {
      h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" '
        + 'onclick="panelAct(\'execadmin\',\'openExecutorSandbox\',' + i + ')" '
        + 'title="Whether payloads run on this device&#39;s host or in a container on it, and under which runtime">Sandbox</button>';
    }
    // Sub-executors with their own firewall and devices (Task 20345).
    if (ex.kind === 'remote' || ex.kind === 'virtual') {
      h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" onclick="panelAct(\'execadmin\',\'openExecutorVirtual\',' + i + ')" '
        + 'title="Sandboxes on this device with their own runtime, IP firewall and USB devices">'
        + (ex.kind === 'virtual' ? 'Edit' : 'Virtual' + (ex.virtual_count ? ' (' + esc(ex.virtual_count) + ')' : '')) + '</button>';
    }
    // A device's firewall rule set (Task 20363): the superset its sandboxes
    // and its virtual executors' must fit inside. Not for a virtual executor,
    // whose firewall is part of its definition, nor the host-process driver,
    // which has no network of a workload's own to filter.
    if (ex.kind === 'remote' || ex.kind === 'container' || ex.kind === 'kubernetes') {
      h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" onclick="panelAct(\'execadmin\',\'openExecutorFirewall\',' + i + ')" '
        + 'title="The most any sandbox here may reach">Firewall</button>';
    }
    // Limits and Access apply to every executor kind, unlike Sandbox above: a
    // ceiling bounds whatever the driver hands out, and an access list names
    // who may reach the device at all. Neither is implied by the driver, so
    // both are offered for hub-configured backends as well as enrolled ones
    // (Task 20310).
    h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" '
      + 'onclick="panelAct(\'execadmin\',\'openExecutorLimits\',' + i + ')" '
      + 'title="The most CPU, memory, disk and processes any one workload here may be given">Limits</button>';
    h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" '
      + 'onclick="panelAct(\'execadmin\',\'openExecutorAudience\',' + i + ')" '
      + 'title="Which users and groups may run work on this executor">Access</button>';
    if (ex.admin_held) {
      h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" onclick="uncordonExecutor(' + i + ')">Uncordon</button>';
    } else {
      h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" onclick="cordonExecutor(' + i + ')">Cordon</button>';
      h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" onclick="drainExecutor(' + i + ')">Drain</button>';
    }
    if (ex.enrolled && ex.kind === 'remote') {
      h += _execUpgradeButton(ex, i);
      h += '<button class="btn danger" style="padding:3px 9px;font-size:11.5px" onclick="revokeExecutor(' + i + ')">Revoke</button>';
    } else if (ex.virtual) {
      h += '<span style="font-size:11px;color:var(--muted)">Virtual executor on ' + esc(ex.virtual.parent_name || ex.virtual.parent_id) + '</span>';
    } else {
      h += '<span style="font-size:11px;color:var(--muted)">Configured in .cloop/config.yaml</span>';
    }
    h += '</div>';
    h += '</div>';
    return h;
  }).join('');
}

window.revokeExecutor = function(idx) {
  const ex = execData && execData.executors && execData.executors[idx];
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
};

// ── Scheduling actions (Task 20162) ─────────────────────────────────────────
//
// Cordon/drain/uncordon are the non-destructive half of executor management:
// they change where the scheduler places work without touching what is already
// running there, which is what revoking cannot do.
//
// All three take an *index* and look the executor up in execData for the same
// reason revokeExecutor does — an executor name, or an operator-typed reason,
// interpolated into an onclick attribute is the bug class of Tasks 163/20033.

// _execAt resolves a card index to its executor, or null.
function _execAt(idx) {
  return (execData && execData.executors && execData.executors[idx]) || null;
}

window.cordonExecutor = function(idx) {
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
};

window.uncordonExecutor = function(idx) {
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
};

window.drainExecutor = function(idx) {
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
};

// _execDetailErrText pulls a sentence out of whatever the failure arrived as:
// a structured API error body, a bare string, or a rejected promise.
function _execDetailErrText(e) {
  if (!e) return '';
  if (typeof e === 'string') return e;
  if (e.message) return e.message;
  if (e.error) return _execDetailErrText(e.error);
  return String(e);
}

// ── Per-project executor selection ──────────────────────────────────────────
function _renderExecutorCard(d) {
  const valueEl = document.getElementById('statExecutor');
  const subEl = document.getElementById('statExecutorSub');
  const card = document.getElementById('executorCard');
  if (!valueEl || !subEl) return;

  const proj = (d && d.project) || null;
  if (!proj) {
    valueEl.textContent = '—';
    subEl.textContent = '';
    return;
  }
  const id = proj.effective_id || proj.executor_id || '';
  const byId = {};
  ((d && d.executors) || []).forEach(ex => { byId[ex.id] = ex; });
  const ex = byId[id];

  valueEl.textContent = ex ? (ex.name || id) : (id || 'none');
  if (proj.blocked) {
    valueEl.style.color = 'var(--red)';
    subEl.textContent = 'blocked by policy';
  } else {
    valueEl.style.color = '';
    const kind = ex ? _execKindLabel(ex.kind) : '';
    subEl.textContent = (proj.bound ? 'pinned' : 'default') + (kind ? ' · ' + kind : '');
  }
  if (card) {
    card.title = proj.blocked
      ? (proj.blocked_reason || 'This project cannot run: its executor is blocked by policy.')
      : 'Click to change where this project’s harness runs';
  }
}

window.openExecutorPickerModal = function() {
  // A feature runs where its project runs (Task 20341).
  if (isFeatureSelected()) { toast('A feature runs on its project\'s executor — change it on the project', 'err'); return; }
  const sel = document.getElementById('epExecutor');
  const err = document.getElementById('epError');
  if (err) err.style.display = 'none';
  openOverlay('executor-picker-overlay', {dismiss: closeExecutorPickerModal});
  if (sel) sel.innerHTML = '<option value="">Loading…</option>';
  // Always refetch: an executor may have gone offline, or the policy may
  // have changed, since the tab was last painted.
  loadExecutors().then(d => _populateExecutorPicker(d));
};

function _populateExecutorPicker(d) {
  const sel = document.getElementById('epExecutor');
  if (!sel) return;
  d = d || {};
  const proj = d.project || {};
  const execs = d.executors || [];
  let h = '<option value="">Registry default'
    + (d.default_id ? ' (' + esc(d.default_id) + ')' : '') + '</option>';
  execs.forEach(ex => {
    const label = (ex.name || ex.id) + ' · ' + _execKindLabel(ex.kind)
      + (ex.status ? ' · ' + ex.status : '')
      + (ex.blocked ? ' · blocked by policy' : '');
    h += '<option value="' + esc(ex.id) + '"' + (ex.blocked ? ' disabled' : '')
      + (proj.executor_id === ex.id ? ' selected' : '') + '>' + esc(label) + '</option>';
  });
  sel.innerHTML = h;
  const hint = document.getElementById('epHint');
  if (hint) {
    hint.textContent = proj.bound
      ? 'Currently pinned to ' + proj.executor_id + '.'
      : 'Currently inheriting the registry default'
        + (proj.effective_id ? ' (' + proj.effective_id + ')' : '') + '.';
  }
}

window.closeExecutorPickerModal = function() {
  closeOverlay('executor-picker-overlay');
};

window.submitExecutorBind = function() {
  const sel = document.getElementById('epExecutor');
  const errEl = document.getElementById('epError');
  const btn = document.getElementById('epSaveBtn');
  if (!sel) return;
  if (selectedProjectIdx === null && isMultiProject) {
    if (errEl) { errEl.textContent = 'Select a project first.'; errEl.style.display = 'block'; }
    return;
  }
  const idx = selectedProjectIdx === null ? 0 : selectedProjectIdx;
  if (errEl) errEl.style.display = 'none';
  if (btn) btn.disabled = true;

  api('/api/projects/' + idx + '/executor', {executor_id: sel.value}).then(d => {
    if (btn) btn.disabled = false;
    if (!d || d.error) {
      if (errEl) {
        // A 409 body carries a remediation sentence naming the alternatives;
        // showing it verbatim is the whole point of returning it.
        errEl.textContent = ((d && d.error) || 'Failed to set executor')
          + (d && d.remediation ? ' — ' + d.remediation : '');
        errEl.style.display = 'block';
      }
      return;
    }
    toast('Execution target updated', 'ok');
    closeExecutorPickerModal();
    loadExecutors();
  }).catch(err => {
    if (btn) btn.disabled = false;
    if (errEl) {
      errEl.textContent = 'Failed to set executor: ' + (err && err.message || String(err));
      errEl.style.display = 'block';
    }
  });
};

// ── Claude Code per-project caps (overview panel) ──────────────────────────
//
// This panel used to reload from render(), which runs on every state diff —
// ~1 request/second during a run (Task 20326). Nothing here moves that fast:
// caps change only on save, and the server serves usage from a cache floored
// at ratelimit.MinUsageCacheTTL. The surplus requests bought nothing and cost
// two things: they rewrote the inputs under whoever was typing in them, and
// they kept a refresh permanently due the moment that cache expired — the
// traffic that gets the usage API answering "Rate limited".
//
// So: fetch on becoming visible, at most once a window after that, and
// whenever the operator asks. Renders still call in, but a call is now cheap.
var CC_LIMITS_REFRESH_MS = 60000;   // == MinUsageCacheTTL; faster cannot be newer
var _ccLimitsLastFetch = 0;
var _ccLimitsLastKey   = null;      // project the displayed figures belong to

// _ccSetVal fills a field, unless it is the one being typed into.
function _ccSetVal(id, v) {
  var el = document.getElementById(id);
  if (!el || el === document.activeElement) return;
  el.value = (v === null || v === undefined) ? '' : v;
}

// {force:true} skips the throttle: the ↻ button and the reload after a save.
window.loadCCLimits = function(opts) {
  var section = document.getElementById('ccLimitsSection');
  if (!section) return;
  var force = !!(opts && opts.force);
  var key   = (typeof selectedProjectIdx !== 'undefined') ? String(selectedProjectIdx) : 'single';
  // Switching projects invalidates the figures on screen regardless of age.
  if (key !== _ccLimitsLastKey) force = true;
  if (!force && (Date.now() - _ccLimitsLastFetch) < CC_LIMITS_REFRESH_MS) return;
  _ccLimitsLastFetch = Date.now();
  _ccLimitsLastKey   = key;
  api(pUrl('/api/claudecode-limits')).then(function(d) {
    var limits = d.limits || {};
    _ccSetVal('ccMaxWeeklyPct',       limits.max_weekly_pct        || '');
    _ccSetVal('ccMaxFiveHourPct',     limits.max_five_hour_pct     || '');
    _ccSetVal('ccMaxWeeklyOpusPct',   limits.max_weekly_opus_pct   || '');
    _ccSetVal('ccMaxWeeklySonnetPct', limits.max_weekly_sonnet_pct || '');

    // Authentication banner. When the OAuth credential has expired or been
    // revoked the caps simply stop advancing, which on its own looks like
    // "nothing is happening" rather than "you must log in again" — so say it.
    var authBox = document.getElementById('ccLimitsAuth');
    if (authBox) {
      if (d.reauth_required) {
        authBox.style.display = '';
        authBox.innerHTML =
          '<strong>&#9888; Claude Code sign-in required — subscription usage is not updating.</strong>'
          + '<div style="margin-top:6px">' + esc(d.hint || '') + '</div>'
          + (d.stale_since
              ? '<div style="margin-top:6px;color:var(--muted)">Figures below are frozen at ' + esc(fmtDate(d.stale_since)) + '.</div>'
              : '')
          + '<div style="margin-top:8px"><button class="btn" style="padding:4px 10px;font-size:12px" '
          + 'onclick="switchTab(\'budget\')">Open Claude Code sign-in</button></div>';
      } else if (d.usage_error) {
        // Not an auth problem: transient, so keep it low-key.
        authBox.style.display = '';
        authBox.innerHTML = '<strong>Usage temporarily unavailable.</strong><div style="margin-top:6px;color:var(--muted)">'
          + esc(d.usage_error) + '</div>';
      } else {
        authBox.style.display = 'none';
        authBox.innerHTML = '';
      }
    }

    var usagePanel = document.getElementById('ccLimitsUsage');
    if (usagePanel) {
      var rows = '';
      var reported = 0;
      var u = d.usage || {};
      function row(label, win, cap) {
        if (!win) {
          rows += '<div style="font-size:12px;color:var(--muted)">' + label + ': <em>not reported</em></div>';
          return;
        }
        reported++;
        var pct = Math.round(win.utilization || 0);
        var capN = parseFloat(cap) || 0;
        var capped = capN > 0 && pct >= capN;
        var color = capped ? 'var(--red)' : (pct >= 80 ? '#e74c3c' : pct >= 50 ? '#f39c12' : '#27ae60');
        rows += '<div>';
        rows += '<div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:2px">';
        rows += '<span><strong>' + label + '</strong>' + (capN > 0 ? ' <span style="color:var(--muted)">(cap ' + capN + '%)</span>' : '') + '</span>';
        rows += '<span style="color:' + color + ';font-weight:600">' + pct + '%</span>';
        rows += '</div>';
        rows += '<div style="background:var(--border);border-radius:4px;height:6px;overflow:hidden">';
        rows += '<div style="background:' + color + ';height:100%;width:' + Math.min(pct, 100) + '%"></div>';
        if (capN > 0 && capN <= 100) {
          rows += '<div style="position:relative;height:0"><div style="position:absolute;top:-6px;left:' + capN + '%;width:2px;height:6px;background:var(--text);opacity:0.6"></div></div>';
        }
        rows += '</div></div>';
      }
      row('Weekly (all)', u.seven_day,        limits.max_weekly_pct);
      row('5-Hour',       u.five_hour,        limits.max_five_hour_pct);
      row('Weekly Opus',  u.seven_day_opus,   limits.max_weekly_opus_pct);
      row('Weekly Sonnet',u.seven_day_sonnet, limits.max_weekly_sonnet_pct);
      // `rows` is never empty (every window emits at least "not reported"),
      // so gate the empty-state hint on whether any window actually reported.
      // Keying it off `rows` made this hint unreachable, which is part of why
      // a dead credential showed up as four blank rows and no explanation.
      if (reported === 0 && !d.reauth_required) {
        usagePanel.innerHTML = '<div style="font-size:12px;color:var(--muted)">No usage data available — make sure '
          + '~/.claude/.credentials.json exists or set CLAUDE_CODE_OAUTH_TOKEN.</div>';
      } else {
        usagePanel.innerHTML = rows;
      }
    }

    var violationBox = document.getElementById('ccLimitsViolation');
    if (violationBox) {
      var vs = d.violations || [];
      if (vs.length > 0) {
        violationBox.style.display = '';
        violationBox.innerHTML = '<strong>Cap reached — runs blocked:</strong><br>' + vs.map(esc).join('<br>');
      } else {
        violationBox.style.display = 'none';
      }
    }
  }).catch(function(err) {
    console.warn('cc-limits load error', err);
  });
};

window.saveCCLimits = function() {
  var body = {
    max_weekly_pct:        parseFloat(document.getElementById('ccMaxWeeklyPct').value)       || 0,
    max_five_hour_pct:     parseFloat(document.getElementById('ccMaxFiveHourPct').value)     || 0,
    max_weekly_opus_pct:   parseFloat(document.getElementById('ccMaxWeeklyOpusPct').value)   || 0,
    max_weekly_sonnet_pct: parseFloat(document.getElementById('ccMaxWeeklySonnetPct').value) || 0,
  };
  fetch(pUrl('/api/claudecode-limits'), {
    method: 'PUT',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  }).then(function(resp) {
    if (!resp.ok) { throw new Error('save failed'); }
    var msg = document.getElementById('ccLimitsSaveMsg');
    if (msg) {
      msg.style.display = '';
      setTimeout(function() { msg.style.display = 'none'; }, 2000);
    }
    loadCCLimits({force: true});
  }).catch(function(err) { alert('Save failed: ' + err); });
};

// Returning to a backgrounded tab is when staleness shows, so refresh then.
// Throttled, so tab-flicking costs nothing, and a hidden tab asks for nothing —
// its share of the traffic is part of what gets the usage API to rate-limit us.
//
// A listener rather than a repeating timer, deliberately. setInterval would
// also hold open the event loop of the headless harness that drives this
// bundle under node (TestDashboard_BackgroundWorkIsVisible), which exits when
// the loop drains. It is not needed either: render() fires on every state diff,
// so while anything is happening the throttled call below keeps the figures
// current, and while nothing is happening they are not moving.
document.addEventListener('visibilitychange', function() {
  if (document.hidden) return;
  var section = document.getElementById('ccLimitsSection');
  if (section && section.style.display !== 'none') loadCCLimits();
});

// Show the cc-limits section only when active provider is claudecode.
//
// Called from render(), so it runs on every state diff and must stay a pure
// visibility toggle: the fetch belongs to the *transition* into visibility, not
// to the render that happened to observe it (Task 20326).
window.updateCCLimitsVisibility = function(provider) {
  var section = document.getElementById('ccLimitsSection');
  if (!section) return;
  if ((provider || '').toLowerCase() === 'claudecode') {
    var wasHidden = section.style.display === 'none';
    section.style.display = '';
    if (wasHidden) loadCCLimits({force: true});
    else           loadCCLimits();   // throttled; a no-op inside the window
  } else {
    section.style.display = 'none';
  }
};

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
    + 'onclick="panelAct(\'execadmin\',\'upgradeExecutor\',' + i + ')" title="' + esc(title) + '">Upgrade</button>';
}

// ── Fleet auto-update policy ────────────────────────────────────────────────
//
// The bar is built here rather than in index.html so the panel's markup stays
// in one place with the code that fills it, and so this lands without an edit
// to the shared page shell.

let fleetAutoUpdate = null;

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

window.loadFleetAutoUpdate = function(force) {
  // Served from cache unless an edit invalidated it. See the call site in
  // loadExecutors for why re-fetching per render is the wrong default.
  if (fleetAutoUpdate && !force) { _renderAutoUpdateBar(fleetAutoUpdate); return Promise.resolve(fleetAutoUpdate); }
  return api('/api/fleet/autoupdate').then(d => {
    if (!d || d.error) return null;
    fleetAutoUpdate = d;
    _renderAutoUpdateBar(d);
    return d;
  }).catch(() => null);
};

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
    + 'onclick="panelAct(\'execadmin\',\'editFleetAutoUpdate\')">Configure</button>';
  bar.innerHTML = h;
}
