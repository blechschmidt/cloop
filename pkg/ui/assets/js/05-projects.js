// ── OIDC session UI ──────────────────────────────────────────────────────────
// When the server runs with OIDC single sign-on enabled, /api/me reports the
// signed-in user; render a user chip + sign-out button in the header. With
// OIDC disabled the endpoint reports oidc_enabled=false and nothing changes.
function initAuthUI() {
  // refreshPermissions performs the /api/me fetch and applies gating; reuse
  // its result so the chip and the permission set come from one round-trip
  // and can never disagree.
  refreshPermissions().then(me => {
    if (!me || !me.oidc_enabled || !me.authenticated) return;
    const chip = document.getElementById('userChip');
    if (chip) {
      chip.textContent = me.name || me.email || 'signed in';
      // Surfacing the role makes "why is this button greyed out?"
      // answerable without reading the server config.
      const roleLabel = me.role && me.role !== 'none' ? me.role : 'no role';
      chip.title = (me.email || '') + ' — ' + roleLabel;
      chip.style.display = 'flex';
    }
    const btn = document.getElementById('logoutBtn');
    if (btn) {
      btn.style.display = '';
      btn.addEventListener('click', () => {
        fetch('/auth/logout', {method: 'POST'})
          .catch(() => {})
          .finally(() => { window.location.href = '/auth/login'; });
      });
    }
  }).catch(() => {});
}

document.addEventListener('DOMContentLoaded', () => {
  // Initialize model dropdown based on default provider selection
  if (document.getElementById('initProvider')) updateModelDropdown();

  initAuthUI();

  const box = document.getElementById('liveOutputBox');
  if (box) {
    box.addEventListener('scroll', () => {
      const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
      liveLogAutoScroll = atBottom;
    });
  }
});

// ── Projects tab ─────────────────────────────────────────────────────────────

function loadProjects() {
  api('/api/projects').then(d => {
    const projects = d.projects || [];
    isMultiProject = d.multi_project === true || projects.length > 1;
    renderProjects(projects, d.stats || {});
    updateProjectSelector();
    // Refresh the overview cards if we're on the overview tab with no project selected.
    if (isMultiProject && selectedProjectIdx === null && activeTab === 'overview') {
      renderMultiProjectOverview();
    }
  }).catch(() => {});
}

window.toggleCompletedProjects = function() {
  showCompletedProjects = !showCompletedProjects;
  const btn = document.getElementById('toggleCompletedProjectsBtn');
  if (btn) btn.textContent = showCompletedProjects ? 'Hide completed' : 'Show completed';
  // Re-render with cached state.
  if (window._lastProjectsData) renderProjects(window._lastProjectsData.projects, window._lastProjectsData.stats);
};

function renderProjects(projects, stats) {
  window._lastProjectsData = {projects, stats};
  // Update aggregate stats.
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v === undefined ? '—' : v; };
  set('paTotal',  stats.total_projects  ?? projects.length);
  set('paActive', stats.active_runs     ?? 0);
  set('paTasks',  stats.total_tasks     ?? 0);
  set('paDone',   stats.done_tasks      ?? 0);
  set('paFailed', stats.failed_tasks    ?? 0);
  set('paSteps',  stats.total_steps     ?? 0);

  const list  = document.getElementById('projList');
  const empty = document.getElementById('projListEmpty');
  if (!list) return;

  if (!projects.length) {
    empty.style.display = '';
    list.innerHTML = '';
    return;
  }
  empty.style.display = 'none';

  // Filter out fully-completed projects unless toggle is on; preserve original index for API calls.
  const isCompleted = p => p.total_tasks > 0 && p.done_tasks >= p.total_tasks;
  const indexed  = projects.map((p, i) => ({p, i}));
  const visibleI = showCompletedProjects ? indexed : indexed.filter(({p}) => !isCompleted(p));
  const hiddenCount = projects.length - visibleI.length;
  const btn = document.getElementById('toggleCompletedProjectsBtn');
  if (btn && hiddenCount > 0 && !showCompletedProjects) {
    btn.textContent = 'Show completed (' + hiddenCount + ')';
  } else if (btn) {
    btn.textContent = showCompletedProjects ? 'Hide completed' : 'Show completed';
  }

  if (!visibleI.length) {
    list.innerHTML = '<div class="empty-state" style="padding:16px 0"><h3>All projects completed</h3><p>Click <strong>Show completed</strong> to view them.</p></div>';
    return;
  }

  list.innerHTML = visibleI.map(({p, i: idx}) => {
    const health  = p.health || 'unknown';
    const pct     = p.total_tasks > 0 ? Math.round(p.done_tasks / p.total_tasks * 100) : 0;
    const goal    = p.goal ? esc(p.goal.substring(0, 80)) : '<em style="color:var(--muted)">no goal set</em>';
    const lastAct = p.last_activity ? relTime(new Date(p.last_activity)) : '—';
    const taskInfo = p.done_tasks + '/' + p.total_tasks + ' tasks';
    const selCls  = (selectedProjectIdx === idx) ? ' selected' : '';
    const nameSafe = JSON.stringify(p.name).replace(/"/g, '&quot;');
    // Build a tooltip that surfaces the running task across projects.
    // For the selected project we know the in-progress task title from
    // appState (kept fresh by task_update events). For other projects we
    // only know the running flag, so fall back to a generic label.
    let _tip = 'Open project';
    if (p.running) {
      _tip = (selectedProjectIdx === idx && _runningTaskTitle)
        ? 'Running: ' + _runningTaskTitle
        : 'Currently running…';
    }
    const tipSafe = esc(_tip);
    const pathSafe = JSON.stringify(p.path || '').replace(/"/g, '&quot;');
    return `
      <div class="proj-card${selCls}" onclick="openProject(${idx},${nameSafe})" title="${tipSafe}">
        <div class="proj-health-dot ${health}"></div>
        <div class="proj-name">${esc(p.name)}</div>
        <div class="proj-goal" title="${esc(p.goal || '')}">${goal}</div>
        <div class="proj-meta">
          <span class="badge ${health}" style="font-size:10px">${health}</span>
          <div class="proj-progress-wrap"><div class="proj-progress-bar"><div class="proj-progress-fill" style="width:${pct}%"></div></div><span>${pct}%</span></div>
          <span>${taskInfo}</span>
          <span title="last activity">${lastAct}</span>
          ${(p.provider || p.model) ? `<span title="Provider / Model">${esc([p.provider, p.model].filter(Boolean).join(' / '))}</span>` : ''}
        </div>
        <div class="proj-actions" onclick="event.stopPropagation()">
          ${p.running
            ? '<button class="btn danger" onclick="projectStop('+idx+')" title="Stop">&#9632; Stop</button>'
            : '<button class="btn success" onclick="projectRun('+idx+',false)" title="Run">&#9654; Run</button><button class="btn primary" onclick="projectRun('+idx+',true)" title="Run PM">&#9654; PM</button>'
          }
          <button class="btn danger" onclick="projectDelete(${idx},${nameSafe},${pathSafe})" title="Remove project">&#10005; Delete</button>
        </div>
      </div>
    `;
  }).join('');
}

function relTime(date) {
  const diff = Date.now() - date.getTime();
  if (diff < 60000)  return 'just now';
  if (diff < 3600000) return Math.floor(diff/60000) + 'm ago';
  if (diff < 86400000) return Math.floor(diff/3600000) + 'h ago';
  return Math.floor(diff/86400000) + 'd ago';
}

window.projectRun = function(idx, pm) {
  // No client poll — the server pushes 'projects' + 'run_state' WS events
  // immediately after the run starts so the card and Run/Stop button
  // refresh on their own (Task 20126).
  api('/api/projects/' + idx + '/run', {method:'POST', body: JSON.stringify({pm})})
    .then(() => { toast('Run started', 'ok'); })
    .catch(() => toast('Failed to start run', 'err'));
};

window.projectStop = function(idx) {
  // No client poll — the server pushes 'projects' + 'run_state' WS events
  // once the SIGINT'd process actually exits (handleProjectStop observer).
  api('/api/projects/' + idx + '/stop', {method:'POST'})
    .then(d => { toast(d.ok ? 'Stopped' : 'Nothing running', d.ok ? 'ok' : 'err'); })
    .catch(() => toast('Failed to stop', 'err'));
};

// projectDelete opens the confirmation modal for removing a project from the
// registry. The user can optionally check "also delete the project root dir"
// before confirming — the actual DELETE request is sent by submitDeleteProject.
window.projectDelete = function(idx, name, path) {
  const overlay = document.getElementById('delproj-overlay');
  if (!overlay) return;
  document.getElementById('delproj-name').textContent = name || ('project #' + idx);
  document.getElementById('delproj-path').textContent = path || '';
  document.getElementById('delproj-idx').value = String(idx);
  document.getElementById('delproj-deleteRoot').checked = false;
  overlay.style.display = 'flex';
};

window.closeDeleteProjectModal = function() {
  const overlay = document.getElementById('delproj-overlay');
  if (overlay) overlay.style.display = 'none';
};

window.submitDeleteProject = function() {
  const idx = parseInt(document.getElementById('delproj-idx').value, 10);
  if (isNaN(idx)) { closeDeleteProjectModal(); return; }
  const deleteRoot = document.getElementById('delproj-deleteRoot').checked;
  // If the user is currently viewing the project that's about to disappear,
  // bounce them back to the projects landing page so they don't end up on a
  // ghost overview after the WS 'projects' broadcast.
  const wasViewingDeleted = (selectedProjectIdx === idx);
  apiMethod('DELETE', '/api/projects/' + idx, {delete_root: deleteRoot}).then(d => {
    closeDeleteProjectModal();
    if (d && d.ok) {
      toast(d.root_deleted ? 'Project and root dir deleted' : 'Project removed', 'ok');
      if (wasViewingDeleted && typeof window.clearProjectSelection === 'function') {
        window.clearProjectSelection();
      }
      // The server pushes a 'projects' WS event so the list refreshes on its
      // own, but call loadProjects() to cover the SSE-disconnected case.
      if (typeof loadProjects === 'function') loadProjects();
    } else {
      toast((d && d.error) || 'Failed to delete project', 'err');
    }
  }).catch(err => {
    closeDeleteProjectModal();
    toast('Failed to delete project: ' + (err && err.message ? err.message : 'error'), 'err');
  });
};

// Opens a project in scoped-tabs mode: sets selectedProjectIdx and drills into Overview.
//
// Task 20134: the WebSocket is reconnected with the new project_idx so the
// server-side hub registers this client under the new project's workDir and
// pushes its initial task_update + future state_diff events automatically —
// removing the per-switch /api/state polling cost.
window.openProject = function(idx, name) {
  selectedProjectIdx  = idx;
  selectedProjectName = name;
  // Drop stale per-project state so the new project's initial WS task_update
  // is the first thing the renderer sees.
  appState = null;
  const bc = document.getElementById('projectBreadcrumb');
  if (bc) { bc.style.display = 'flex'; }
  const bn = document.getElementById('breadcrumbName');
  if (bn) bn.textContent = name;
  // Update selector label immediately.
  const label = document.getElementById('projSelectorLabel');
  if (label) label.textContent = name;
  const wrap = document.getElementById('projSelectorWrap');
  if (wrap) wrap.classList.add('visible');
  // Refresh project list highlight without changing tab.
  if (window._lastProjectsData) {
    renderProjects(window._lastProjectsData.projects, window._lastProjectsData.stats);
  }
  switchTab('overview');
  // Roles are per-project, so the permission set must be re-resolved for the
  // project just opened before its controls render.
  refreshPermissions();
  // Reconnect WS scoped to the new project — initial state arrives as a
  // task_update event in the new hub subscription.
  connectWS();
};

// Returns to the Projects landing page from a scoped project view.
window.clearProjectSelection = function() {
  selectedProjectIdx  = null;
  selectedProjectName = '';
  appState            = null;
  const bc = document.getElementById('projectBreadcrumb');
  if (bc) bc.style.display = 'none';
  const sw = document.getElementById('projSelectorWrap');
  if (sw) sw.classList.remove('visible');
  // Back to the global view: re-resolve against the unscoped permission set.
  refreshPermissions();
  switchTab('projects');
  // Reconnect WS without project_idx so the hub registration falls back to
  // the primary project for global events (projects list, presence) — the
  // landing view ignores any per-project event payloads via the guard in
  // handleRealtimeMsg (selectedProjectIdx === null).
  connectWS();
  // No project selected → no per-project running task to advertise.
  updateBrowserTitle();
};

// ── Project selector dropdown ─────────────────────────────────────────────────

// Populates and shows/hides the project selector based on isMultiProject.
function updateProjectSelector() {
  const wrap = document.getElementById('projSelectorWrap');
  const label = document.getElementById('projSelectorLabel');
  if (!wrap) return;
  if (!isMultiProject) { wrap.classList.remove('visible'); return; }
  wrap.classList.add('visible');
  if (label) label.textContent = selectedProjectIdx !== null ? selectedProjectName : 'All Projects';
  // Populate dropdown items from cached project data.
  const drop = document.getElementById('projSelectorDropdown');
  if (!drop) return;
  const projects = (window._lastProjectsData && window._lastProjectsData.projects) || [];
  drop.innerHTML = projects.map((p, i) => {
    const health = p.health || 'unknown';
    const activeCls = selectedProjectIdx === i ? ' active' : '';
    const dotStyle = 'background:' + healthColor(health);
    return '<div class="proj-selector-item'+activeCls+'" onclick="selectProjectFromDropdown('+i+','+JSON.stringify(p.name).replace(/"/g,'&quot;')+')">' +
      '<span class="pi-dot" style="'+dotStyle+'"></span>' +
      '<span class="pi-name">'+esc(p.name)+'</span>' +
      '<span style="font-size:10px;color:var(--muted)">'+health+'</span>' +
      '</div>';
  }).join('');
}

function healthColor(h) {
  const map = {running:'var(--cyan)',complete:'var(--green)',failed:'var(--red)',stalled:'var(--yellow)',idle:'var(--muted)',unknown:'var(--border)'};
  return map[h] || map.unknown;
}

window.toggleProjectSelector = function() {
  const drop = document.getElementById('projSelectorDropdown');
  if (!drop) return;
  drop.classList.toggle('open');
};

// Close dropdown on outside click.
document.addEventListener('click', function(e) {
  const wrap = document.getElementById('projSelectorWrap');
  if (wrap && !wrap.contains(e.target)) {
    const drop = document.getElementById('projSelectorDropdown');
    if (drop) drop.classList.remove('open');
  }
});

window.selectProjectFromDropdown = function(idx, name) {
  const drop = document.getElementById('projSelectorDropdown');
  if (drop) drop.classList.remove('open');
  if (selectedProjectIdx === idx) return; // already selected
  openProject(idx, name);
};

// ── Provider / Model picker modal ─────────────────────────────────────────────

window.openProviderModelModal = function() {
  const provSel  = document.getElementById('pmProvider');
  const errEl    = document.getElementById('pmError');
  if (errEl) errEl.style.display = 'none';
  const curProv  = _currentProvider || 'claudecode';
  if (provSel) {
    for (let i = 0; i < provSel.options.length; i++) {
      if (provSel.options[i].value === curProv) { provSel.selectedIndex = i; break; }
    }
  }
  populatePMModelDropdown(_currentModel || '');
  const effSel = document.getElementById('pmEffort');
  if (effSel) effSel.value = _currentEffort || '';
  updatePMEffortAvailability();
  const el = document.getElementById('provider-model-overlay');
  if (el) el.style.display = 'flex';
};

// Effort is only honored by the claudecode provider — gray it out (but keep
// the saved value) for the others so the modal doesn't imply support.
function updatePMEffortAvailability() {
  const prov   = (document.getElementById('pmProvider') || {}).value || 'claudecode';
  const effSel = document.getElementById('pmEffort');
  const hint   = document.getElementById('pmEffortHint');
  const isCC   = prov === 'claudecode';
  if (effSel) effSel.disabled = !isCC;
  if (hint) hint.style.display = isCC ? 'none' : '';
}

window.closeProviderModelModal = function() {
  const el = document.getElementById('provider-model-overlay');
  if (el) el.style.display = 'none';
};

window.onPMProviderChange = function() {
  populatePMModelDropdown('');
  updatePMEffortAvailability();
};

function populatePMModelDropdown(preselect) {
  const sel  = document.getElementById('pmModel');
  if (!sel) return;
  const prov = (document.getElementById('pmProvider') || {}).value || 'claudecode';
  const models = providerModels[prov] || [{value:'', label:'(default)'}];
  sel.innerHTML = models.map(m =>
    '<option value="'+esc(m.value)+'"'+(m.value===preselect?' selected':'')+'>'+esc(m.label)+'</option>'
  ).join('');
}

window.saveProviderModel = function() {
  const provider = (document.getElementById('pmProvider') || {}).value || '';
  const model    = (document.getElementById('pmModel')    || {}).value || '';
  const effort   = (document.getElementById('pmEffort')   || {}).value || '';
  const errEl    = document.getElementById('pmError');
  if (errEl) errEl.style.display = 'none';
  apiMethod('POST', pUrl('/api/options/provider'), {provider, model, effort}).then(d => {
    if (!d || !d.ok) {
      if (errEl) { errEl.textContent = (d && d.error) || 'Failed to save'; errEl.style.display = ''; }
      return;
    }
    closeProviderModelModal();
    toast('Provider saved: ' + (d.provider || provider) + (d.model ? ' / ' + d.model : '') + (d.effort ? ' @ ' + d.effort : ''), 'ok');
    // Task 20134: handleProviderModelSet (server) calls broadcastStateDiff
    // after saving — the resulting state_diff WebSocket event keeps the UI
    // in sync without a redundant /api/state refetch.
  }).catch(e => {
    if (errEl) { errEl.textContent = 'Request failed: ' + e.message; errEl.style.display = ''; }
  });
};

// ── New Project modal ─────────────────────────────────────────────────────────

window.openGoalEditModal = function() {
  const cur = (document.getElementById('goalText') || {}).textContent || '';
  document.getElementById('goalEditInput').value = cur;
  document.getElementById('goalEditError').style.display = 'none';
  const el = document.getElementById('goal-edit-overlay');
  if (el) el.style.display = 'flex';
  setTimeout(() => { try { document.getElementById('goalEditInput').focus(); } catch(e) {} }, 0);
};

window.closeGoalEditModal = function() {
  const el = document.getElementById('goal-edit-overlay');
  if (el) el.style.display = 'none';
};

window.saveGoalEdit = function() {
  const goal  = document.getElementById('goalEditInput').value.trim();
  const errEl = document.getElementById('goalEditError');
  if (!goal) { errEl.textContent = 'Goal cannot be empty'; errEl.style.display = ''; return; }
  errEl.style.display = 'none';
  apiMethod('PUT', pUrl('/api/goal'), {goal}).then(d => {
    if (!d.ok) { errEl.textContent = d.error || 'Failed to update goal'; errEl.style.display = ''; return; }
    closeGoalEditModal();
    toast('Goal updated', 'ok');
    const goalEl = document.getElementById('goalText');
    if (goalEl) {
      goalEl.textContent = d.goal;
      goalEl.classList.toggle('empty', !d.goal);
    }
    if (typeof refreshState === 'function') refreshState();
  }).catch(e => {
    errEl.textContent = 'Request failed: ' + e.message;
    errEl.style.display = '';
  });
};

// ── Instructions edit modal ──────────────────────────────────────────────────
window.openInstructionsEditModal = function() {
  const errEl = document.getElementById('instructionsEditError');
  if (errEl) errEl.style.display = 'none';
  const inputEl = document.getElementById('instructionsEditInput');
  if (inputEl) inputEl.value = '';
  // Fetch latest persisted value rather than scraping the rendered text,
  // so a long/unwrapped value is round-tripped exactly.
  api(pUrl('/api/instructions')).then(d => {
    if (inputEl) inputEl.value = (d && typeof d.instructions === 'string') ? d.instructions : '';
  }).catch(() => {});
  const el = document.getElementById('instructions-edit-overlay');
  if (el) el.style.display = 'flex';
  setTimeout(() => { try { document.getElementById('instructionsEditInput').focus(); } catch(e) {} }, 0);
};

window.closeInstructionsEditModal = function() {
  const el = document.getElementById('instructions-edit-overlay');
  if (el) el.style.display = 'none';
};

window.saveInstructionsEdit = function() {
  const instructions = document.getElementById('instructionsEditInput').value;
  const errEl = document.getElementById('instructionsEditError');
  errEl.style.display = 'none';
  apiMethod('PUT', pUrl('/api/instructions'), {instructions}).then(d => {
    if (!d.ok) { errEl.textContent = d.error || 'Failed to update instructions'; errEl.style.display = ''; return; }
    closeInstructionsEditModal();
    toast('Instructions updated', 'ok');
    const el = document.getElementById('instructionsText');
    if (el) {
      const v = (typeof d.instructions === 'string') ? d.instructions : '';
      el.textContent = v || 'No instructions set';
      el.classList.toggle('empty', !v);
    }
    if (typeof refreshState === 'function') refreshState();
  }).catch(e => {
    errEl.textContent = 'Request failed: ' + e.message;
    errEl.style.display = '';
  });
};

// Populate the model dropdown based on the selected provider.
function _npUpdateModels() {
  var prov = document.getElementById('npProvider').value || 'claudecode';
  var sel  = document.getElementById('npModel');
  if (!sel) return;
  var models = (typeof providerModels !== 'undefined' && providerModels[prov]) || [{value:'', label:'(default)'}];
  sel.innerHTML = '';
  models.forEach(function(m) {
    var opt = document.createElement('option');
    opt.value = m.value;
    opt.textContent = m.label;
    sel.appendChild(opt);
  });
}
// Wire up provider change to update models.
(function() {
  var np = document.getElementById('npProvider');
  if (np) np.addEventListener('change', _npUpdateModels);
})();

window.openNewProjectModal = function() {
  document.getElementById('npDir').value     = '';
  document.getElementById('npGoal').value    = '';
  document.getElementById('npProvider').value = '';
  _npUpdateModels();
  const npEff = document.getElementById('npEffort');
  if (npEff) npEff.value = '';
  document.getElementById('npPMMode').checked = false;
  document.getElementById('npAutoRun').checked = false;
  document.getElementById('npError').style.display = 'none';
  const el = document.getElementById('new-project-overlay');
  if (el) { el.style.display = 'flex'; }
};

window.closeNewProjectModal = function() {
  const el = document.getElementById('new-project-overlay');
  if (el) el.style.display = 'none';
};

window.submitNewProject = function() {
  const dir      = document.getElementById('npDir').value.trim();
  const goal     = document.getElementById('npGoal').value.trim();
  const provider = document.getElementById('npProvider').value;
  const model    = document.getElementById('npModel').value.trim();
  const effort   = (document.getElementById('npEffort') || {}).value || '';
  const pmMode   = document.getElementById('npPMMode').checked;
  const autoRun  = document.getElementById('npAutoRun').checked;
  const errEl    = document.getElementById('npError');
  if (!dir)  { errEl.textContent = 'Directory is required'; errEl.style.display = ''; return; }
  if (!goal) { errEl.textContent = 'Goal is required'; errEl.style.display = ''; return; }
  errEl.style.display = 'none';
  api('/api/projects/new', {dir, goal, provider, model, effort, pmMode, autoRun}).then(d => {
    if (!d.ok) { errEl.textContent = d.error || 'Failed to create project'; errEl.style.display = ''; return; }
    closeNewProjectModal();
    toast('Project created: ' + dir, 'ok');
    // Reload projects list and open the new project.
    api('/api/projects').then(pd => {
      const projects = pd.projects || [];
      isMultiProject = pd.multi_project === true || projects.length > 1;
      renderProjects(projects, pd.stats || {});
      updateProjectSelector();
      if (d.project_idx !== undefined && d.project_idx >= 0) {
        openProject(d.project_idx, dir.split('/').pop());
      }
    }).catch(() => {});
  }).catch(() => toast('Request failed', 'err'));
};

