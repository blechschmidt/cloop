// Parallel features (Task 20341). A feature is a git worktree of a project with
// its own task list and run settings; the hub lists it as one more project
// (carrying `parent` and `feature`), so run, stop, tasks and options all work on
// it by index unchanged. This fragment nests features under their project and
// drives /api/projects/{idx}/features. Listeners are delegated and keyed by
// numeric index: names and branches never reach an inline handler.

function projList() {
  return (window._lastProjectsData && window._lastProjectsData.projects) || [];
}

// currentProject is the project the Overview shows: the selection, or on a
// single-project hub the only one.
function currentProject() {
  const list = projList();
  if (selectedProjectIdx !== null) return list[selectedProjectIdx] || null;
  return isMultiProject ? null : (list[0] || null);
}

function currentProjectIdx() {
  if (selectedProjectIdx !== null) return selectedProjectIdx;
  return isMultiProject ? null : 0;
}

function isFeatureSelected() {
  const p = currentProject();
  return !!(p && p.parent);
}

function featuresOf(path) {
  return projList().map((p, i) => ({p, i})).filter(({p}) => p.parent === path);
}

function projectIdxByPath(path) {
  return projList().findIndex(p => p.path === path);
}

function safeURL(u) {
  return /^https?:\/\//i.test(u || '') ? u : '';
}

function featurePRBadge(f) {
  const pr = f && f.pr;
  if (!pr || !pr.number) return '';
  const cls = pr.state === 'merged' ? 'complete' : pr.state === 'closed' ? 'failed' : 'running';
  const label = 'PR #' + (pr.number | 0) + ' ' + esc(pr.state || 'open');
  const url = safeURL(pr.url);
  return url
    ? '<a class="badge ' + cls + '" href="' + esc(url) + '" target="_blank" rel="noopener">' + label + '</a>'
    : '<span class="badge ' + cls + '">' + label + '</span>';
}

// What became of an isolated run's work when it was not applied to the feature
// (Task 20367): kept on a branch of its own, or refused. The message is the
// whole account, so it is the badge's title.
function featureReturnBadge(f) {
  const r = f && f.return;
  if (!r || r.outcome === 'fast_forwarded' || r.outcome === 'nothing') return '';
  return '<span class="badge failed" title="' + esc(r.message || '') + '">' +
    (r.kept_on ? 'work kept on ' + esc(r.kept_on) : 'work not returned') + '</span>';
}

function featureOptionBadges(f) {
  let h = '';
  if (f && f.auto_evolve) h += '<span class="feat-opt" title="Auto-evolve">&#8635; evolve</span>';
  if (f && f.innovate) h += '<span class="feat-opt" title="Innovate">&#10024; innovate</span>';
  if (f && f.auto_pr && !f.pr) h += '<span class="feat-opt" title="Opens its pull request when complete">auto PR</span>';
  return h;
}

// featureChips renders a project card's features for the Projects grid.
function featureChips(path) {
  const fs = featuresOf(path);
  if (!fs.length) return '';
  return '<div class="feat-chips" onclick="event.stopPropagation();openFeatureFromEvent(event)">' +
    fs.map(({p, i}) => {
      const f = p.feature || {};
      const pct = p.total_tasks > 0 ? Math.round(p.done_tasks / p.total_tasks * 100) : 0;
      return '<button class="feat-chip" data-open-idx="' + i + '" title="' + esc(f.branch || '') + '">' +
        '<span class="proj-health-dot ' + esc(p.health || 'unknown') + '"></span>&#9095; ' + esc(f.title || f.slug || p.name) +
        ' <span class="feat-chip-meta">' + (p.running ? 'running' : pct + '%') + '</span></button>';
    }).join('') + '</div>';
}

window.openFeatureFromEvent = function(e) {
  const el = e.target && e.target.closest ? e.target.closest('[data-open-idx]') : null;
  if (!el) return;
  const i = parseInt(el.getAttribute('data-open-idx'), 10);
  const p = projList()[i];
  if (p) openProject(i, p.name);
};

// renderFeaturePanels draws the Features section on a project's Overview and
// the banner on a feature's. Called from render() and on every projects push.
function renderFeaturePanels() {
  const sec = document.getElementById('featuresSection');
  const banner = document.getElementById('featureBanner');
  const cur = currentProject();
  if (sec) sec.style.display = (cur && !cur.parent) ? '' : 'none';
  if (banner) banner.style.display = (cur && cur.parent) ? '' : 'none';
  if (!cur) return;
  if (cur.parent) renderFeatureBanner(banner, cur);
  else renderFeaturesList(cur);
}

function renderFeaturesList(cur) {
  const box = document.getElementById('featuresList');
  if (!box) return;
  const btn = document.getElementById('newFeatureBtn');
  if (btn) btn.style.display = cur.has_git ? '' : 'none';
  const fs = featuresOf(cur.path);
  if (!cur.has_git) {
    box.innerHTML = '<div class="empty-state" style="padding:10px 0"><p>Features are git worktrees, so this project needs to be the top of a git repository to have any.</p></div>';
    return;
  }
  if (!fs.length) {
    box.innerHTML = '<div class="empty-state" style="padding:10px 0"><p>Develop several features in parallel, each on its own branch with its own task list and settings.</p></div>';
    return;
  }
  box.innerHTML = fs.map(({p, i}) => {
    const f = p.feature || {};
    const pct = p.total_tasks > 0 ? Math.round(p.done_tasks / p.total_tasks * 100) : 0;
    const runBtn = p.running
      ? '<button class="btn danger" data-act="stop" data-idx="' + i + '" data-perm="run.stop">&#9632; Stop</button>'
      : '<button class="btn success" data-act="run" data-idx="' + i + '" data-perm="run.start">&#9654; Run</button>';
    const prBtn = '<button class="btn" data-act="pr" data-idx="' + i + '" data-perm="project.write">' +
      (f.pr && f.pr.state === 'open' ? 'Update PR' : 'Open PR') + '</button>';
    return '<div class="feat-row" data-idx="' + i + '">' +
      '<div class="feat-main" data-act="open" data-idx="' + i + '">' +
        '<span class="proj-health-dot ' + esc(p.health || 'unknown') + '"></span>' +
        '<strong>' + esc(f.title || f.slug) + '</strong>' +
        '<code class="feat-branch">' + esc(f.branch || '') + ' &rarr; ' + esc(f.base || '') + '</code>' +
        statusBadge(p.running && !isActiveRunStatus(p.status) ? 'running' : p.status, p.pause_reason) +
        featureOptionBadges(f) + featurePRBadge(f) + featureReturnBadge(f) +
      '</div>' +
      '<div class="feat-progress"><div class="proj-progress-bar"><div class="proj-progress-fill" style="width:' + pct + '%"></div></div>' +
        '<span>' + (p.done_tasks | 0) + '/' + (p.total_tasks | 0) + ' tasks</span></div>' +
      '<div class="feat-actions">' +
        '<button class="btn" data-act="open" data-idx="' + i + '">Open</button>' + runBtn + prBtn +
        '<button class="btn danger" data-act="remove" data-idx="' + i + '" data-perm="project.write" title="Remove feature">&#10005;</button>' +
      '</div></div>';
  }).join('');
  applyPermissionGating(box);
}

function renderFeatureBanner(banner, cur) {
  const f = cur.feature || {};
  const parentIdx = projectIdxByPath(cur.parent);
  const parent = projList()[parentIdx];
  const prOpen = f.pr && f.pr.state === 'open';
  banner.innerHTML =
    '<div class="feat-banner-main">&#9095; Feature <strong>' + esc(f.title || f.slug) + '</strong> of ' +
      (parent ? '<button class="btn" data-act="parent" data-idx="' + parentIdx + '">&larr; ' + esc(parent.name) + '</button>' : esc(cur.parent)) +
      ' on <code>' + esc(f.branch || '') + '</code> from <code>' + esc(f.base || '') + '</code> ' + featurePRBadge(f) + '</div>' +
    '<div class="feat-actions">' +
      '<button class="btn primary" data-act="pr" data-idx="' + selectedIdxOr(cur) + '" data-perm="project.write">' + (prOpen ? 'Update pull request' : 'Open pull request') + '</button>' +
      (f.pr ? '<button class="btn" data-act="refresh" data-idx="' + selectedIdxOr(cur) + '" data-perm="project.write" title="Re-read the pull request state from GitHub">&#8635; PR state</button>' : '') +
      '<button class="btn danger" data-act="remove" data-idx="' + selectedIdxOr(cur) + '" data-perm="project.write">Remove feature</button>' +
    '</div>' +
    '<div class="feat-note">Executor, repository access and credentials are the project\'s. Its run, tasks and options below are this feature\'s own.</div>';
  applyPermissionGating(banner);
}

function selectedIdxOr(cur) {
  const i = currentProjectIdx();
  return i === null ? projectIdxByPath(cur.path) : i;
}

// One delegated listener for both panels.
function onFeatureAction(e) {
  const el = e.target && e.target.closest ? e.target.closest('[data-act]') : null;
  if (!el || el.disabled) return;
  const i = parseInt(el.getAttribute('data-idx'), 10);
  const p = projList()[i];
  if (!p) return;
  switch (el.getAttribute('data-act')) {
    case 'open': case 'parent': openProject(i, p.name); break;
    case 'run': featureRun(i); break;
    case 'stop': projectStop(i); break;
    case 'pr': openFeaturePRModal(i); break;
    case 'refresh': refreshFeaturePR(i); break;
    case 'remove': openRemoveFeatureModal(i); break;
  }
}

['featuresList', 'featureBanner'].forEach(id => {
  const el = document.getElementById(id);
  if (el) el.addEventListener('click', onFeatureAction);
});

// featureRun starts a feature through /api/run, the route with the admission
// gates (quota, executor audience) the Overview's own Run button goes through.
function featureRun(i) {
  api('/api/run?project_idx=' + i, {}).then(d => {
    if (d && d.ok) toast('Run started', 'ok');
    else toast(errText(d && d.error) || 'Failed to start run', 'err');
  }).catch(() => toast('Failed to start run', 'err'));
}

// featureRef captures which feature a dialog is about by identity, not by
// index: indices shift when any feature is created or removed, and a dialog
// submitted after that must not act on whichever feature moved into the slot.
function featureRef(i) {
  const p = projList()[i];
  return (p && p.parent && p.feature) ? {parent: p.parent, path: p.path, slug: p.feature.slug} : null;
}

// featureRoute builds /api/projects/{parent}/features/{slug}… from a ref,
// resolving the parent's index now, or '' when the feature is gone.
function featureRoute(ref, suffix) {
  if (!ref || projectIdxByPath(ref.path) < 0) return '';
  const pi = projectIdxByPath(ref.parent);
  if (pi < 0) return '';
  return '/api/projects/' + pi + '/features/' + encodeURIComponent(ref.slug) + (suffix || '');
}

// ── New feature ──────────────────────────────────────────────────────────────

let _nfParentPath = '';

function slugify(name) {
  return String(name || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40).replace(/-+$/, '');
}

window.openNewFeatureModal = function() {
  const cur = currentProject();
  if (!cur || cur.parent) return;
  _nfParentPath = cur.path;
  document.getElementById('nfParent').textContent = cur.name;
  ['nfName', 'nfDesc', 'nfTasks', 'nfBase'].forEach(id => { document.getElementById(id).value = ''; });
  ['nfEvolve', 'nfInnovate', 'nfParallel', 'nfAutoPR'].forEach(id => { document.getElementById(id).checked = false; });
  document.getElementById('nfStart').checked = can('run.start');
  document.getElementById('nfSlug').textContent = '';
  document.getElementById('nfError').style.display = 'none';
  openOverlay('newfeat-overlay', {dismiss: closeNewFeatureModal, focus: '#nfName'});
};

window.closeNewFeatureModal = function() { closeOverlay('newfeat-overlay'); };

(function() {
  const name = document.getElementById('nfName');
  if (name) name.addEventListener('input', () => {
    const s = slugify(name.value);
    document.getElementById('nfSlug').textContent = s ? 'Branch: cloop/feature/' + s : '';
  });
})();

function formError(id, msg) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg;
  el.style.display = msg ? '' : 'none';
}

window.submitNewFeature = function() {
  const name = document.getElementById('nfName').value.trim();
  const desc = document.getElementById('nfDesc').value.trim();
  if (!name || !slugify(name)) return formError('nfError', 'Give the feature a name with letters or digits.');
  if (!desc) return formError('nfError', 'Say what the feature should achieve.');
  const parentIdx = projectIdxByPath(_nfParentPath);
  if (parentIdx < 0) return formError('nfError', 'The project is no longer listed.');
  const body = {
    name: name, description: desc,
    base: document.getElementById('nfBase').value.trim(),
    tasks: document.getElementById('nfTasks').value.split('\n').map(t => t.trim()).filter(Boolean),
    auto_evolve: document.getElementById('nfEvolve').checked,
    innovate: document.getElementById('nfInnovate').checked,
    parallel: document.getElementById('nfParallel').checked,
    auto_pr: document.getElementById('nfAutoPR').checked,
  };
  const start = document.getElementById('nfStart').checked;
  const btn = document.getElementById('nfSubmit');
  btn.disabled = true;
  btn.textContent = 'Creating…';
  formError('nfError', '');
  api('/api/projects/' + parentIdx + '/features', body).then(d => {
    if (!d || !d.ok) { formError('nfError', errText(d && d.error) || 'Could not create the feature'); return; }
    closeNewFeatureModal();
    toast('Feature created on ' + d.branch, 'ok');
    // The create response's index is fresh; the projects push that carries
    // the new entry may still be in flight, so fetch the list before opening.
    api('/api/projects').then(pd => {
      applyProjects(pd);
      const i = projectIdxByPath(d.path);
      if (i < 0) return;
      openProject(i, projList()[i].name);
      if (start) {
        api('/api/run?project_idx=' + i, {}).then(r => {
          if (!r || !r.ok) toast(errText(r && r.error) || 'Could not start the feature', 'err');
        }).catch(() => {});
      }
    }).catch(() => {});
  }).catch(err => formError('nfError', (err && err.message) || 'Could not create the feature'))
    .finally(() => { btn.disabled = false; btn.textContent = 'Create feature'; });
};

// ── Pull requests ────────────────────────────────────────────────────────────

let _fprRef = null;

window.openFeaturePRModal = function(i) {
  const p = projList()[i];
  if (!p || !p.feature) return;
  const f = p.feature;
  _fprRef = featureRef(i);
  const update = f.pr && f.pr.state === 'open';
  document.getElementById('fprTitle').textContent = update ? 'Update pull request #' + (f.pr.number | 0) : 'Open pull request';
  document.getElementById('fprIntro').textContent = update
    ? 'Pushes new commits on ' + f.branch + ' to the open pull request.'
    : 'Pushes ' + f.branch + ' and opens a pull request into ' + f.base + ' on GitHub.';
  document.getElementById('fprFields').style.display = update ? 'none' : '';
  document.getElementById('fprName').value = f.title || f.slug || '';
  document.getElementById('fprBody').value = '';
  document.getElementById('fprDraft').checked = false;
  document.getElementById('fprSubmit').textContent = update ? 'Push and update' : 'Open pull request';
  formError('fprError', '');
  openOverlay('featpr-overlay', {dismiss: closeFeaturePRModal, focus: '#fprSubmit'});
};

window.closeFeaturePRModal = function() { closeOverlay('featpr-overlay'); };

window.submitFeaturePR = function() {
  const route = featureRoute(_fprRef, '/pr');
  if (!route) return formError('fprError', 'The feature is no longer listed.');
  const btn = document.getElementById('fprSubmit');
  const label = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Pushing…';
  formError('fprError', '');
  api(route, {
    title: document.getElementById('fprName').value.trim(),
    body: document.getElementById('fprBody').value,
    draft: document.getElementById('fprDraft').checked,
  }).then(d => {
    const pr = d && d.result && d.result.pr;
    if (!d || !d.ok || !pr) {
      let msg = errText(d && d.error) || 'Could not open the pull request';
      if (d && d.partial && d.partial.pushed) msg += ' (the branch was pushed)';
      formError('fprError', msg);
      return;
    }
    closeFeaturePRModal();
    const dirty = (d.result.dirty || []).length;
    toast('Pull request #' + pr.number + (d.result.existing ? ' updated' : ' opened') +
      (dirty ? ' — ' + dirty + ' uncommitted change(s) not included' : ''), 'ok');
    const url = safeURL(pr.url);
    if (url && !d.result.existing) window.open(url, '_blank', 'noopener');
  }).catch(err => formError('fprError', (err && err.message) || 'Could not open the pull request'))
    .finally(() => { btn.disabled = false; btn.textContent = label; });
};

window.refreshFeaturePR = function(i) {
  const route = featureRoute(featureRef(i), '/pr/refresh');
  if (!route) return;
  api(route, {}).then(d => {
    if (d && d.ok && d.pr) toast('Pull request #' + d.pr.number + ' is ' + d.pr.state, 'ok');
    else toast(errText(d && d.error) || 'Could not refresh the pull request', 'err');
  }).catch(() => toast('Could not refresh the pull request', 'err'));
};

// ── Removal ──────────────────────────────────────────────────────────────────

let _dfRef = null;

window.openRemoveFeatureModal = function(i) {
  const p = projList()[i];
  if (!p || !p.feature) return;
  _dfRef = featureRef(i);
  document.getElementById('dfName').textContent = p.feature.title || p.feature.slug;
  document.getElementById('dfBranch').textContent = p.feature.branch || '';
  document.getElementById('dfBranchToo').checked = false;
  document.getElementById('dfForce').checked = false;
  formError('dfError', '');
  openOverlay('delfeat-overlay', {dismiss: closeRemoveFeatureModal});
};

window.closeRemoveFeatureModal = function() { closeOverlay('delfeat-overlay'); };

window.submitRemoveFeature = function() {
  const ref = _dfRef;
  const route = featureRoute(ref, '');
  if (!route) return formError('dfError', 'The feature is no longer listed.');
  const viewing = selectedProjectPath === ref.path;
  const btn = document.getElementById('dfSubmit');
  btn.disabled = true;
  apiMethod('DELETE', route, {
    delete_branch: document.getElementById('dfBranchToo').checked,
    force: document.getElementById('dfForce').checked,
  }).then(d => {
    if (!d || !d.ok) { formError('dfError', errText(d && d.error) || 'Could not remove the feature'); return; }
    closeRemoveFeatureModal();
    toast(d.branch_deleted ? 'Feature and branch removed' : 'Feature removed; branch ' + d.branch + ' kept', 'ok');
    const parentIdx = projectIdxByPath(ref.parent);
    const parent = projList()[parentIdx];
    if (viewing && parent) openProject(parentIdx, parent.name);
    loadProjects();
  }).catch(err => formError('dfError', (err && err.message) || 'Could not remove the feature'))
    .finally(() => { btn.disabled = false; });
};
