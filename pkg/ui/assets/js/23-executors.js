// ── Executors panel (Task 20160) ────────────────────────────────────────────
//
// The panel is global: executors are shared infrastructure, not project state.
// It still calls pUrl() because the backend enriches the response with the
// *selected* project's binding, which is what powers the Overview card and
// the picker's "currently bound" preselection.
let execData = null;

window.loadExecutors = function() {
  return api(pUrl('/api/executors')).then(d => {
    execData = d || {};
    _renderExecutors(execData);
    _renderExecutorCard(execData);
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

  const execs = (d && d.executors) || [];
  if (empty) empty.style.display = execs.length ? 'none' : 'block';

  list.innerHTML = execs.map((ex, i) => {
    const kind = _execKindLabel(ex.kind);
    let h = '<div class="exec-card' + (ex.blocked ? ' blocked' : '') + '">';
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

    h += '<div class="exec-actions">';
    // Index-based dispatch, never an interpolated string: an executor name
    // with a quote in it is exactly how Tasks 163/20033 broke.
    if (ex.admin_held) {
      h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" onclick="uncordonExecutor(' + i + ')">Uncordon</button>';
    } else {
      h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" onclick="cordonExecutor(' + i + ')">Cordon</button>';
      h += '<button class="btn" style="padding:3px 9px;font-size:11.5px" onclick="drainExecutor(' + i + ')">Drain</button>';
    }
    if (ex.enrolled && ex.kind === 'remote') {
      h += '<button class="btn danger" style="padding:3px 9px;font-size:11.5px" onclick="revokeExecutor(' + i + ')">Revoke</button>';
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

// ── Enrollment ──────────────────────────────────────────────────────────────
window.openEnrollModal = function() {
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
  const ov = document.getElementById('enroll-overlay');
  if (ov) ov.style.display = 'flex';
  setTimeout(() => { if (name) name.focus(); }, 50);
};

window.closeEnrollModal = function() {
  const ov = document.getElementById('enroll-overlay');
  if (ov) ov.style.display = 'none';
  // Refresh on close so a token minted moments ago is reflected even before
  // the device redeems it.
  loadExecutors();
};

window.submitEnroll = function() {
  const errEl = document.getElementById('enrollError');
  const btn = document.getElementById('enrollSubmitBtn');
  const body = {
    name: (document.getElementById('enrollName') || {}).value || '',
    workdir_root: (document.getElementById('enrollRoot') || {}).value || ''
  };
  const ttlRaw = (document.getElementById('enrollTTL') || {}).value;
  if (ttlRaw) body.ttl_minutes = parseInt(ttlRaw, 10);
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
};

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

window.copyEnrollCommand = function() {
  _copyFromElement('enrollCommand', 'Command');
};

window.copyEnrollInstall = function() {
  _copyFromElement('enrollInstallCommand', 'Install command');
};

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
  const sel = document.getElementById('epExecutor');
  const err = document.getElementById('epError');
  if (err) err.style.display = 'none';
  const ov = document.getElementById('executor-picker-overlay');
  if (ov) ov.style.display = 'flex';
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
  const ov = document.getElementById('executor-picker-overlay');
  if (ov) ov.style.display = 'none';
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

// ── Claude Code authentication panel ───────────────────────────────────────
window.loadClaudeAuthStatus = function() {
  var panel = document.getElementById('ccAuthPanel');
  if (!panel) return;
  panel.innerHTML = '<div style="font-size:13px;color:var(--muted)">Checking login status...</div>';
  api('/api/claudecode/auth/status').then(function(d) {
    _renderClaudeAuth(d);
  }).catch(function(err) {
    panel.innerHTML = '<div style="font-size:13px;color:var(--red,#e74c3c)">Failed to load auth status: ' + esc(err && err.message || String(err)) + '</div>';
  });
};

function _renderClaudeAuth(d) {
  var panel = document.getElementById('ccAuthPanel');
  if (!panel) return;
  d = d || {};
  var status = d.status || {};
  var sess = d.session || {};
  var h = '';

  if (d.status_error) {
    h += '<div style="background:var(--surface-alt,#1a1a1a);border:1px solid var(--red,#e74c3c);border-radius:6px;padding:12px;margin-bottom:12px;font-size:12px;color:var(--red,#e74c3c)">';
    h += 'Status check failed: ' + esc(d.status_error);
    h += '</div>';
  }

  if (sess && sess.active && sess.url && !sess.done) {
    // In-flight login session: show URL + code input.
    h += '<div style="background:var(--surface-alt,#1a1a1a);border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:12px">';
    h += '<div style="font-size:13px;font-weight:600;margin-bottom:8px">Sign-in in progress</div>';
    h += '<ol style="font-size:13px;color:var(--muted);margin:0 0 10px 18px;padding:0;line-height:1.7">';
    h += '<li>Open this URL in your browser and sign in:</li>';
    h += '</ol>';
    h += '<div style="display:flex;gap:8px;margin-bottom:12px;align-items:center">';
    h += '<a href="' + esc(sess.url) + '" target="_blank" rel="noopener" style="font-size:12px;word-break:break-all;color:var(--link,#3a8bdc);flex:1;padding:6px 8px;background:var(--bg,#0d0d0d);border-radius:4px;border:1px solid var(--border)">' + esc(sess.url) + '</a>';
    h += '<button class="btn" type="button" onclick="copyClaudeAuthURL()" style="font-size:12px;padding:6px 10px">Copy</button>';
    h += '</div>';
    h += '<ol start="2" style="font-size:13px;color:var(--muted);margin:0 0 10px 18px;padding:0;line-height:1.7">';
    h += '<li>Authorize the app, then paste the code shown:</li>';
    h += '</ol>';
    h += '<div style="display:flex;gap:8px;align-items:center">';
    h += '<input id="ccAuthCode" class="form-input" type="text" placeholder="Paste authorization code" style="flex:1;font-family:monospace">';
    h += '<button class="btn primary" type="button" onclick="submitClaudeAuthCode()" style="white-space:nowrap">Sign in</button>';
    h += '<button class="btn" type="button" onclick="cancelClaudeAuthLogin()">Cancel</button>';
    h += '</div>';
    h += '<div id="ccAuthMsg" style="font-size:12px;color:var(--muted);margin-top:8px;min-height:16px"></div>';
    h += '</div>';
  } else if (status.loggedIn) {
    // Already logged in: show identity + logout.
    h += '<div style="background:var(--surface-alt,#1a1a1a);border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:12px">';
    h += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">';
    h += '<span style="font-size:13px;font-weight:600;color:var(--green,#27ae60)">Signed in</span>';
    if (status.subscriptionType) {
      h += '<span style="font-size:11px;padding:2px 8px;border-radius:10px;background:var(--bg,#0d0d0d);border:1px solid var(--border);color:var(--muted)">' + esc(status.subscriptionType) + '</span>';
    }
    h += '</div>';
    h += '<table style="font-size:12px;color:var(--muted);width:100%;border-collapse:collapse">';
    function row(label, value) {
      if (!value) return;
      h += '<tr><td style="padding:2px 12px 2px 0;color:var(--muted)">' + esc(label) + '</td><td style="padding:2px 0;color:var(--fg,#eee);word-break:break-all">' + esc(value) + '</td></tr>';
    }
    row('Email', status.email);
    row('Auth method', status.authMethod);
    row('API provider', status.apiProvider);
    row('Organization', status.orgName || status.orgId);
    h += '</table>';
    h += '<div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">';
    h += '<button class="btn" type="button" onclick="startClaudeAuthLogin({})">Re-authenticate</button>';
    h += '<button class="btn" type="button" onclick="logoutClaudeAuth()">Sign out</button>';
    h += '</div>';
    h += '</div>';
  } else {
    // Not logged in.
    h += '<div style="background:var(--surface-alt,#1a1a1a);border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:12px">';
    h += '<div style="font-size:13px;color:var(--muted);margin-bottom:12px">Not signed in to Claude Code. Sign in to use the <code>claudecode</code> provider for task execution.</div>';
    h += '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">';
    h += '<button class="btn primary" type="button" onclick="startClaudeAuthLogin({})">Sign in with Claude.ai</button>';
    h += '<button class="btn" type="button" onclick="startClaudeAuthLogin({console:true})">Sign in with Anthropic Console</button>';
    h += '<button class="btn" type="button" onclick="startClaudeAuthLogin({sso:true})">SSO login</button>';
    h += '</div>';
    h += '</div>';
  }

  if (sess && sess.done && sess.error) {
    h += '<div style="font-size:12px;color:var(--red,#e74c3c);margin-top:4px">Last attempt failed: ' + esc(sess.error) + '</div>';
  }
  panel.innerHTML = h;
}

window.startClaudeAuthLogin = function(opts) {
  var panel = document.getElementById('ccAuthPanel');
  if (panel) panel.innerHTML = '<div style="font-size:13px;color:var(--muted)">Launching <code>claude auth login</code>...</div>';
  fetch('/api/claudecode/auth/login', {
    method: 'POST',
    headers: Object.assign({'Content-Type':'application/json'}, authHeaders()),
    body: JSON.stringify(opts || {})
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (d.error) {
      panel.innerHTML = '<div style="font-size:13px;color:var(--red,#e74c3c)">' + esc(d.error) + '</div><div style="margin-top:8px"><button class="btn" type="button" onclick="loadClaudeAuthStatus()">Back</button></div>';
      return;
    }
    _renderClaudeAuth({session: d.session});
  }).catch(function(err) {
    if (panel) panel.innerHTML = '<div style="font-size:13px;color:var(--red,#e74c3c)">' + esc(err && err.message || String(err)) + '</div>';
  });
};

window.submitClaudeAuthCode = function() {
  var input = document.getElementById('ccAuthCode');
  var msg = document.getElementById('ccAuthMsg');
  if (!input) return;
  var code = (input.value || '').trim();
  if (!code) {
    if (msg) msg.textContent = 'Paste the authorization code first.';
    return;
  }
  if (msg) msg.textContent = 'Submitting...';
  fetch('/api/claudecode/auth/login/code', {
    method: 'POST',
    headers: Object.assign({'Content-Type':'application/json'}, authHeaders()),
    body: JSON.stringify({code: code})
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (d.error) {
      if (msg) msg.textContent = d.error;
      return;
    }
    _renderClaudeAuth(d);
  }).catch(function(err) {
    if (msg) msg.textContent = (err && err.message) || String(err);
  });
};

window.cancelClaudeAuthLogin = function() {
  fetch('/api/claudecode/auth/login/cancel', {
    method: 'POST',
    headers: authHeaders()
  }).then(function() {
    loadClaudeAuthStatus();
  });
};

window.logoutClaudeAuth = function() {
  if (!confirm('Sign out of Claude Code? You will need to sign in again to use the claudecode provider.')) return;
  fetch('/api/claudecode/auth/logout', {
    method: 'POST',
    headers: authHeaders()
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (d.error) alert('Logout failed: ' + d.error);
    loadClaudeAuthStatus();
  });
};

window.copyClaudeAuthURL = function() {
  var link = document.querySelector('#ccAuthPanel a[target="_blank"]');
  if (!link) return;
  var url = link.href;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(url);
  } else {
    var ta = document.createElement('textarea');
    ta.value = url; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch(_) {}
    document.body.removeChild(ta);
  }
  var msg = document.getElementById('ccAuthMsg');
  if (msg) { msg.textContent = 'URL copied to clipboard.'; setTimeout(function(){ if(msg.textContent==='URL copied to clipboard.') msg.textContent=''; }, 2000); }
};

// ── Claude Code per-project caps (overview panel) ──────────────────────────
window.loadCCLimits = function() {
  var section = document.getElementById('ccLimitsSection');
  if (!section) return;
  api(pUrl('/api/claudecode-limits')).then(function(d) {
    var limits = d.limits || {};
    _setVal('ccMaxWeeklyPct',       limits.max_weekly_pct        || '');
    _setVal('ccMaxFiveHourPct',     limits.max_five_hour_pct     || '');
    _setVal('ccMaxWeeklyOpusPct',   limits.max_weekly_opus_pct   || '');
    _setVal('ccMaxWeeklySonnetPct', limits.max_weekly_sonnet_pct || '');

    var usagePanel = document.getElementById('ccLimitsUsage');
    if (usagePanel) {
      var rows = '';
      var u = d.usage || {};
      function row(label, win, cap) {
        if (!win) {
          rows += '<div style="font-size:12px;color:var(--muted)">' + label + ': <em>not reported</em></div>';
          return;
        }
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
      usagePanel.innerHTML = rows || '<div style="font-size:12px;color:var(--muted)">No usage data available — make sure ~/.claude/.credentials.json exists or set CLAUDE_CODE_OAUTH_TOKEN.</div>';
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
    loadCCLimits();
  }).catch(function(err) { alert('Save failed: ' + err); });
};

// Show the cc-limits section only when active provider is claudecode.
window.updateCCLimitsVisibility = function(provider) {
  var section = document.getElementById('ccLimitsSection');
  if (!section) return;
  if ((provider || '').toLowerCase() === 'claudecode') {
    section.style.display = '';
    loadCCLimits();
  } else {
    section.style.display = 'none';
  }
};

function _rlBar(used, limit, pct) {
  const colour = pct >= 100 ? 'var(--red)' : (pct >= 80 ? '#f0a500' : 'var(--accent)');
  return '<div style="height:8px;background:var(--border);border-radius:4px;overflow:hidden;margin-top:4px">'
    +    '<div style="height:100%;width:' + pct + '%;background:' + colour + ';transition:width .4s ease"></div>'
    +  '</div>';
}

function _rlRow(label, w, fmt) {
  if (!w || !w.limit || w.limit <= 0) {
    return '<div style="margin:6px 0;font-size:12px;color:var(--muted)">' + label + ': <em>not reported</em></div>';
  }
  const used = w.used || 0;
  const lim  = w.limit;
  const pct  = w.pct || 0;
  const usedTxt = fmt ? fmt(used) : used;
  const limTxt  = fmt ? fmt(lim) : lim;
  let resetTxt = '';
  if (w.reset) {
    try {
      const dt = new Date(w.reset);
      if (!isNaN(dt.getTime())) {
        const diff = Math.max(0, Math.round((dt.getTime() - Date.now()) / 1000));
        if (diff > 0) {
          const mins = Math.floor(diff / 60);
          const secs = diff % 60;
          resetTxt = ' &nbsp;<span style="color:var(--muted);font-size:11px">resets in '
            + (mins > 0 ? (mins + 'm ') : '') + secs + 's</span>';
        }
      }
    } catch(_) {}
  }
  return '<div style="margin:8px 0">'
    +    '<div style="display:flex;justify-content:space-between;font-size:12px">'
    +      '<span>' + label + '</span>'
    +      '<span>' + usedTxt + ' / ' + limTxt + ' (' + pct + '%)' + resetTxt + '</span>'
    +    '</div>'
    +    _rlBar(used, lim, pct)
    +  '</div>';
}

function _renderRateLimits(d) {
  const empty = document.getElementById('rlEmpty');
  const list  = document.getElementById('rlList');
  if (!list) return;
  const models = (d && d.models) || [];
  if (models.length === 0) {
    if (empty) empty.style.display = '';
    list.innerHTML = '';
    return;
  }
  if (empty) empty.style.display = 'none';

  let html = '';
  models.forEach(m => {
    const updated = m.updated_at ? new Date(m.updated_at).toLocaleTimeString() : '—';
    const tier    = m.tier ? '<span style="display:inline-block;padding:2px 8px;background:var(--border);border-radius:10px;font-size:11px;margin-left:8px">tier: ' + m.tier + '</span>' : '';
    const spend   = (m.monthly_spend_usd && m.monthly_spend_usd > 0)
      ? '<span style="display:inline-block;padding:2px 8px;background:var(--border);border-radius:10px;font-size:11px;margin-left:8px">monthly spend cap: $' + Number(m.monthly_spend_usd).toFixed(2) + '</span>'
      : '';
    html += '<div style="border:1px solid var(--border);border-radius:var(--radius);padding:14px;margin-top:12px">';
    html += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">';
    html += '<div style="font-weight:600;font-size:13px"><code>' + (m.model || '?') + '</code>' + tier + spend + '</div>';
    html += '<div style="font-size:11px;color:var(--muted)">updated ' + updated + '</div>';
    html += '</div>';
    html += _rlRow('Requests / min (RPM)',         m.requests,      _fmtTokens);
    html += _rlRow('Input tokens / min (ITPM)',    m.input_tokens,  _fmtTokens);
    html += _rlRow('Output tokens / min (OTPM)',   m.output_tokens, _fmtTokens);
    if (m.tokens && m.tokens.limit > 0)            html += _rlRow('Tokens / min (legacy)',      m.tokens,        _fmtTokens);
    if (m.five_hour && m.five_hour.limit > 0)      html += _rlRow('5-hour rolling window',      m.five_hour,     _fmtTokens);
    if (m.weekly && m.weekly.limit > 0)            html += _rlRow('Weekly window',              m.weekly,        _fmtTokens);
    html += '</div>';
  });
  list.innerHTML = html;
}

window.saveBudgetGlobal = function() {
  const payload = {
    daily_usd_limit:    parseFloat(document.getElementById('bgDailyUSD').value)    || 0,
    daily_token_limit:  parseInt(document.getElementById('bgDailyTokens').value)   || 0,
    alert_threshold_pct: parseInt(document.getElementById('bgAlertPct').value)     || 0,
  };
  fetch(pUrl('/api/budget/global'), {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...(TOKEN ? { Authorization: 'Bearer ' + TOKEN } : {}) },
    body: JSON.stringify(payload),
  }).then(r => r.json()).then(() => {
    const msg = document.getElementById('budgetGlobalSaveMsg');
    if (msg) { msg.style.display = ''; setTimeout(() => msg.style.display = 'none', 2000); }
    loadBudget();
  }).catch(err => console.warn('budget global save error', err));
};

window.saveBudgetProject = function() {
  const payload = {
    global_usd_pct:    parseFloat(document.getElementById('bpGlobalUSDPct').value)   || 0,
    global_token_pct:  parseFloat(document.getElementById('bpGlobalTokenPct').value) || 0,
    daily_usd_limit:   parseFloat(document.getElementById('bpDailyUSD').value)       || 0,
    daily_token_limit: parseInt(document.getElementById('bpDailyTokens').value)      || 0,
    monthly_usd:       parseFloat(document.getElementById('bpMonthlyUSD').value)     || 0,
    alert_threshold_pct: parseInt(document.getElementById('bpAlertPct').value)       || 0,
    max_weekly_pct: parseFloat(document.getElementById('bpMaxWeekly').value)   || 0,
    max_five_hour_pct: parseFloat(document.getElementById('bpMaxFiveHour').value) || 0,
    block_extra_usage: document.getElementById('bpBlockExtraUsage').checked,
  };
  fetch(pUrl('/api/budget/project'), {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...(TOKEN ? { Authorization: 'Bearer ' + TOKEN } : {}) },
    body: JSON.stringify(payload),
  }).then(r => r.json()).then(() => {
    const msg = document.getElementById('budgetProjectSaveMsg');
    if (msg) { msg.style.display = ''; setTimeout(() => msg.style.display = 'none', 2000); }
    loadBudget();
  }).catch(err => console.warn('budget project save error', err));
};

