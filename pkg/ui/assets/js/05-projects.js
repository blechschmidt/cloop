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
      btn.addEventListener('click', () => { signOut(); });
    }
    const allBtn = document.getElementById('logoutAllBtn');
    if (allBtn) allBtn.style.display = '';
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
  // is the first thing the renderer sees. Dropping appState is not enough on
  // its own — the panels rendered from it keep their markup until something
  // rewrites them, so the previous project's rows stay on screen for as long
  // as the new project's first frame takes to arrive (Task 20197).
  appState = null;
  clearProjectScopedPanels();
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
  clearProjectScopedPanels();
  const bc = document.getElementById('projectBreadcrumb');
  if (bc) bc.style.display = 'none';
  const sw = document.getElementById('projSelectorWrap');
  if (sw) sw.classList.remove('visible');
  // Back to the global view: re-resolve against the unscoped permission set.
  refreshPermissions();
  switchTab('projects');
  // Reconnect WS without project_idx. That stream carries only fleet-wide
  // events; its per-project frames are dropped by the scope gate in
  // handleRealtimeMsg, which is what stops the primary project's state from
  // landing under whichever project the user opens next (Task 20197).
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
// ── New Project → Access (Task 20187) ───────────────────────────────────────
//
// The dialog can pin the new project to an executor and open its credentials
// in the same request that creates it, instead of sending the developer to the
// Executors panel and then to Secrets to hand-type "project:/path" as a grant
// subject. Both halves are optional and are left out of the body entirely when
// untouched, so an ordinary creation posts exactly what it always did.
//
// Everything below is assembled with DOM calls rather than an HTML string.
// What goes into these rows is secret names, executor IDs and operator-typed
// allowlists; interpolating those into markup — or into an inline onclick — is
// the bug class this dashboard has re-learned more than once.

// _npAccess caches what the section is built from. It is fetched when the
// dialog opens rather than at page load, so a user who never creates a project
// never pays for the two requests.
var _npAccess = {executors: [], secrets: [], byID: {}, brokerNote: ''};

// _NP_GRANT_FIELDS maps a secret's kind to the constraint dimensions that
// actually gate it, mirroring secretbroker.Constraints.ValidateFor. Showing a
// namespace box for a GitHub PAT would invite a grant the broker rejects
// ("writable applies to local_repo grants, not …"), and hiding the repository
// box for a local_repo would guarantee one.
var _NP_GRANT_FIELDS = {
  github_pat:   ['repos', 'permissions'],
  github_app:   ['repos', 'permissions'],
  kubeconfig:   ['contexts', 'namespaces'],
  local_repo:   ['repos', 'writable'],
  registry:     ['registries'],
  env:          ['env_keys'],
  egress_proxy: ['hosts']
};

// _NP_FIELD_META is the label and placeholder for each dimension. Every one of
// them is a comma-separated list except `writable`, which is a checkbox.
var _NP_FIELD_META = {
  repos:       {label: 'Repositories',     ph: 'api, shared-*'},
  permissions: {label: 'Permissions',      ph: 'contents:read, pull_requests:write'},
  contexts:    {label: 'Contexts',         ph: 'prod, staging'},
  namespaces:  {label: 'Namespaces',       ph: 'default, team-a'},
  registries:  {label: 'Registries',       ph: 'ghcr.io, docker.io'},
  env_keys:    {label: 'Environment keys', ph: 'NPM_TOKEN, SENTRY_DSN'},
  hosts:       {label: 'Hosts',            ph: 'api.github.com, *.npmjs.org'}
};

// _NP_KIND_HINT explains, per kind, which of the row's boxes the broker
// insists on — the same sentences it would refuse the grant with, said before
// the request instead of after it.
var _NP_KIND_HINT = {
  github_pat:   'A repository allowlist is required — use * to allow every repository.',
  github_app:   'A repository allowlist is required — use * to allow every repository.',
  kubeconfig:   'At least one context or namespace is required; the delivered kubeconfig is rewritten to hold only these.',
  local_repo:   'A repository allowlist is required. The directories are bind-mounted read-only unless writable is ticked.',
  registry:     'A registry allowlist is required.',
  env:          'Leave empty to deliver every key the secret holds.',
  egress_proxy: 'A host allowlist is required.'
};

// _npList splits a comma-separated field into a clean list.
function _npList(raw) {
  return String(raw == null ? '' : raw).split(',')
    .map(function(v) { return v.trim(); })
    .filter(function(v) { return v !== ''; });
}

function _npEl(tag, cls, text) {
  var el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text !== undefined && text !== null) el.textContent = text;
  return el;
}

// _npOption appends one <option>; the label is set as text, never as markup.
function _npOption(sel, value, label, disabled) {
  var opt = _npEl('option', null, label);
  opt.value = value;
  if (disabled) opt.disabled = true;
  sel.appendChild(opt);
  return opt;
}

// _npFieldGroup is one labelled list input, tagged with the constraint
// dimension it fills so the row can be read back without any per-row IDs.
function _npFieldGroup(field) {
  var meta = _NP_FIELD_META[field] || {label: field, ph: ''};
  var g = _npEl('div', 'form-group');
  g.setAttribute('data-np-group', field);
  g.appendChild(_npEl('label', 'form-label', meta.label));
  var input = _npEl('input', 'form-input');
  input.setAttribute('data-np-field', field);
  input.placeholder = meta.ph;
  g.appendChild(input);
  return g;
}

// _npWritableGroup is the local_repo-only checkbox. The broker rejects
// writable on every other kind, so it is hidden rather than merely ignored.
function _npWritableGroup() {
  var g = _npEl('div', 'form-group');
  g.setAttribute('data-np-group', 'writable');
  var lab = _npEl('label', 'adv-label');
  var cb = document.createElement('input');
  cb.type = 'checkbox';
  cb.setAttribute('data-np-field', 'writable');
  lab.appendChild(cb);
  lab.appendChild(document.createTextNode(' Writable (the project may commit into these checkouts)'));
  g.appendChild(lab);
  return g;
}

// _npRowInput finds one field inside a grant row.
function _npRowInput(row, field) {
  return row.querySelector('[data-np-field="' + field + '"]');
}

function _npRowValue(row, field) {
  var el = _npRowInput(row, field);
  return el ? el.value : '';
}

// _npFillSecretSelect (re)populates one row's secret picker. Called again when
// the list arrives, since a row can be added before the fetch resolves.
function _npFillSecretSelect(sel) {
  var keep = sel.value;
  sel.innerHTML = '';
  if (!_npAccess.secrets.length) {
    _npOption(sel, '', '— no stored secrets —');
    return;
  }
  _npOption(sel, '', 'Choose a secret…');
  _npAccess.secrets.forEach(function(s) {
    _npOption(sel, s.id, (s.name || s.id) + ' (' + (s.kind || 'unknown') + ')');
  });
  if (keep) sel.value = keep;
}

// _npApplyKind shows the dimensions the selected secret's kind is gated on and
// hides the rest.
function _npApplyKind(row) {
  var sel = row.querySelector('[data-np-grant-secret]');
  var secret = sel ? _npAccess.byID[sel.value] : null;
  var kind = secret ? secret.kind : '';
  var show = _NP_GRANT_FIELDS[kind] || [];
  row.querySelectorAll('[data-np-group]').forEach(function(g) {
    var field = g.getAttribute('data-np-group');
    g.style.display = show.indexOf(field) === -1 ? 'none' : '';
  });
  var hint = row.querySelector('[data-np-kind-hint]');
  if (hint) {
    hint.textContent = kind
      ? (_NP_KIND_HINT[kind] || '')
      : (_npAccess.secrets.length
          ? 'Pick the secret this project should hold.'
          : (_npAccess.brokerNote
              || 'No secrets are stored on this hub yet — add one in the Secrets tab first.'));
  }
}

function _npUpdateGrantsEmpty() {
  var host = document.getElementById('npGrantRows');
  var empty = document.getElementById('npGrantsEmpty');
  if (empty) empty.style.display = host && host.children.length ? 'none' : '';
}

// _npAddGrantRow appends one grant row and returns it.
function _npAddGrantRow() {
  var host = document.getElementById('npGrantRows');
  if (!host) return null;
  var row = _npEl('div', 'np-grant-row');

  var head = _npEl('div', 'np-grant-head');
  var secGroup = _npEl('div', 'form-group');
  secGroup.appendChild(_npEl('label', 'form-label', 'Secret'));
  var sec = _npEl('select', 'form-select');
  sec.setAttribute('data-np-grant-secret', '');
  sec.addEventListener('change', function() { _npApplyKind(row); });
  secGroup.appendChild(sec);
  head.appendChild(secGroup);

  var del = _npEl('button', 'btn', 'Remove');
  del.type = 'button';
  del.addEventListener('click', function() {
    row.remove();
    _npUpdateGrantsEmpty();
  });
  head.appendChild(del);
  row.appendChild(head);

  var hint = _npEl('div', 'sec-hint');
  hint.setAttribute('data-np-kind-hint', '');
  hint.style.margin = '8px 0';
  row.appendChild(hint);

  // Scope and lifetime apply to every kind, so they are not part of the
  // kind-driven show/hide below.
  var meta = _npEl('div', 'form-row');
  var scopeGroup = _npEl('div', 'form-group');
  scopeGroup.appendChild(_npEl('label', 'form-label', 'Scope (label)'));
  var scope = _npEl('input', 'form-input');
  scope.setAttribute('data-np-field', 'scope');
  scope.placeholder = 'build';
  scopeGroup.appendChild(scope);
  meta.appendChild(scopeGroup);

  var ttlGroup = _npEl('div', 'form-group');
  ttlGroup.appendChild(_npEl('label', 'form-label', 'Lifetime'));
  var ttl = _npEl('select', 'form-select');
  ttl.setAttribute('data-np-field', 'ttl');
  // The blank option means "whatever the API's default is" rather than a
  // number copied here that could drift away from it.
  _npOption(ttl, '', 'Default');
  [[60, '1 hour'], [480, '8 hours'], [1440, '24 hours'],
   [10080, '7 days'], [43200, '30 days']].forEach(function(o) {
    _npOption(ttl, String(o[0]), o[1]);
  });
  ttlGroup.appendChild(ttl);
  meta.appendChild(ttlGroup);
  row.appendChild(meta);

  // Every dimension is built once and hidden; which ones are visible is the
  // selected secret's kind's business.
  var pairs = _npEl('div', 'form-row');
  pairs.appendChild(_npFieldGroup('repos'));
  pairs.appendChild(_npFieldGroup('permissions'));
  row.appendChild(pairs);
  var pairs2 = _npEl('div', 'form-row');
  pairs2.appendChild(_npFieldGroup('contexts'));
  pairs2.appendChild(_npFieldGroup('namespaces'));
  row.appendChild(pairs2);
  var rest = _npEl('div', 'form-row');
  rest.appendChild(_npFieldGroup('registries'));
  rest.appendChild(_npFieldGroup('env_keys'));
  rest.appendChild(_npFieldGroup('hosts'));
  row.appendChild(rest);
  row.appendChild(_npWritableGroup());

  host.appendChild(row);
  _npFillSecretSelect(sec);
  _npApplyKind(row);
  _npUpdateGrantsEmpty();
  return row;
}

// _npFillExecutors renders the executor picker from GET /api/executors.
function _npFillExecutors(d) {
  var sel = document.getElementById('npExecutor');
  if (!sel) return;
  var execs = (d && d.executors) || [];
  _npAccess.executors = execs;
  var keep = sel.value;
  sel.innerHTML = '';
  _npOption(sel, '', 'Default (hub decides)'
    + (d && d.default_id ? ' — ' + d.default_id : ''));
  execs.forEach(function(ex) {
    // "id — kind", then whatever makes it a poor choice. An executor the hub
    // would refuse is offered disabled rather than hidden: a fleet member that
    // silently vanishes from the list reads as a bug, and the reason it cannot
    // be used is the useful part.
    var notes = [];
    if (ex.blocked) notes.push('blocked by policy');
    if (ex.registered === false) notes.push('not registered here');
    if (ex.status && ex.status !== 'ready') notes.push(ex.status);
    if (ex.health) notes.push('unhealthy');
    var label = ex.id + ' — ' + (ex.kind || 'unknown')
      + (notes.length ? ' · ' + notes.join(', ') : '');
    _npOption(sel, ex.id, label, !!ex.blocked || ex.registered === false);
  });
  if (keep) sel.value = keep;
  var hint = document.getElementById('npExecutorHint');
  if (hint && !execs.length) {
    hint.textContent = 'No executors are registered on this hub; the project runs wherever the hub does.';
  }
}

// _npLoadAccessSources fetches the two lists the section is built from. Each
// endpoint is permission-gated server-side, so a caller who cannot use a half
// is not asked to fetch it — the controls for it are hidden anyway.
function _npLoadAccessSources() {
  if (typeof canGlobal !== 'function' || canGlobal('executor.manage')) {
    api('/api/executors').then(function(d) { _npFillExecutors(d); }).catch(function() {});
  }
  if (typeof canGlobal !== 'function' || canGlobal('secret.grant')) {
    api('/api/secrets').then(function(d) {
      _npAccess.secrets = (d && d.secrets) || [];
      // An unadopted broker is a legitimate state, and "no secrets" is the
      // wrong explanation for it: the store is what is missing, not the
      // secrets, and the response says how to fix that.
      var b = (d && d.broker) || {};
      _npAccess.brokerNote = b.secrets_available === false
        ? ((b.reason || 'The secret store is not available on this hub.')
            + (b.remediation ? ' ' + b.remediation : ''))
        : '';
      _npAccess.byID = {};
      _npAccess.secrets.forEach(function(s) { _npAccess.byID[s.id] = s; });
      // A row may have been added before this resolved.
      document.querySelectorAll('#npGrantRows [data-np-grant-secret]').forEach(function(sel) {
        _npFillSecretSelect(sel);
      });
      document.querySelectorAll('#npGrantRows .np-grant-row').forEach(_npApplyKind);
    }).catch(function() {});
  }
}

// _npSectionHidden reports whether a group was hidden by permission gating.
function _npSectionHidden(id) {
  var el = document.getElementById(id);
  return !el || el.style.display === 'none';
}

// _npResetAccess returns the section to "nothing asked for", which is what
// makes a reopened dialog post the same body a first-time one does.
function _npResetAccess() {
  _npAccess = {executors: [], secrets: [], byID: {}, brokerNote: ''};
  var det = document.getElementById('npAccessSection');
  if (det) {
    det.open = false;
    // With neither permission there is nothing behind the disclosure, and an
    // "Access (optional)" toggle that opens onto an empty box reads as a
    // broken panel rather than as a permission boundary.
    det.style.display = _npSectionHidden('npExecutorGroup') && _npSectionHidden('npGrantsGroup')
      ? 'none' : '';
  }
  var rows = document.getElementById('npGrantRows');
  if (rows) rows.innerHTML = '';
  var sel = document.getElementById('npExecutor');
  if (sel) {
    sel.innerHTML = '';
    _npOption(sel, '', 'Default (hub decides)');
  }
  _npUpdateGrantsEmpty();
}

// _npCollectAccess reads the section into the optional half of the request
// body. It returns {access: {...}} — empty when the section was left alone —
// or {error: "…"} for the one thing worth catching client-side: a row with no
// secret chosen, which the server can only report as an index.
function _npCollectAccess() {
  var out = {};
  var execSel = document.getElementById('npExecutor');
  if (execSel && !_npSectionHidden('npExecutorGroup') && execSel.value) {
    out.executor_id = execSel.value;
  }

  var grants = [];
  var rows = _npSectionHidden('npGrantsGroup')
    ? [] : document.querySelectorAll('#npGrantRows .np-grant-row');
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    var secSel = row.querySelector('[data-np-grant-secret]');
    var ref = secSel ? secSel.value : '';
    if (!ref) {
      return {error: 'Grant ' + (i + 1) + ': choose a secret, or remove the row.'};
    }
    var secret = _npAccess.byID[ref] || {};
    var g = {secret_ref: ref};
    var scope = _npRowValue(row, 'scope').trim();
    if (scope) g.scope = scope;
    var ttl = parseInt(_npRowValue(row, 'ttl') || '0', 10);
    if (ttl > 0) g.ttl_minutes = ttl;
    // Only the dimensions this kind is gated on are sent: an allowlist the
    // broker does not read for this kind is rejected, not ignored.
    (_NP_GRANT_FIELDS[secret.kind] || []).forEach(function(field) {
      if (field === 'writable') {
        var cb = _npRowInput(row, 'writable');
        if (cb && cb.checked) g.writable = true;
        return;
      }
      var list = _npList(_npRowValue(row, field));
      if (list.length) g[field] = list;
    });
    grants.push(g);
  }
  if (grants.length) out.grants = grants;
  return {access: out};
}

// Wire up provider change to update models, and the Access section's one
// static button. Listeners rather than inline onclick: the rows they build
// carry operator-supplied strings.
(function() {
  var np = document.getElementById('npProvider');
  if (np) np.addEventListener('change', _npUpdateModels);
  var add = document.getElementById('npAddGrantBtn');
  if (add) add.addEventListener('click', function() { _npAddGrantRow(); });
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
  // Access starts collapsed and empty on every open, then fills itself from
  // the fleet and the secret store as those answer.
  _npResetAccess();
  _npLoadAccessSources();
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
  // Access (Task 20187): executor_id and grants are added only when the
  // operator asked for them, so an untouched dialog posts the body it always
  // did and takes the server's unchanged path.
  const collected = _npCollectAccess();
  if (collected.error) { errEl.textContent = collected.error; errEl.style.display = ''; return; }
  const body = {dir, goal, provider, model, effort, pmMode, autoRun};
  Object.keys(collected.access).forEach(k => { body[k] = collected.access[k]; });
  errEl.style.display = 'none';
  api('/api/projects/new', body).then(d => {
    // Verbatim: the access failures name the executor, the grant index and the
    // constraint that was missing, and any paraphrase of that is worse.
    if (!d || !d.ok) {
      errEl.textContent = (d && d.error) || 'Failed to create project';
      errEl.style.display = '';
      return;
    }
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
  }).catch(err => {
    // 401 and 403 have already been shown by parseAPIResponse (login modal,
    // "not permitted" toast); anything else is a transport failure whose
    // message belongs next to the form the operator is still looking at.
    const msg = (err && err.message) || String(err);
    if (msg === '401' || msg === 'FORBIDDEN') return;
    errEl.textContent = 'Request failed: ' + msg;
    errEl.style.display = '';
    toast('Request failed', 'err');
  });
};

