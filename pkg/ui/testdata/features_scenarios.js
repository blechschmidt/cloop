// features_scenarios.js — drives the real dashboard bundle through parallel
// features (Task 20341).
//
// A feature is a project in the /api/projects list that carries `parent` and
// `feature`. The dashboard must nest it under its project instead of drawing
// it as a card of its own, address every action on it by *its* index, and
// keep addressing the right project when a feature appearing or disappearing
// shifts the indices after it. Those are properties of the rendered DOM and
// of the requests the bundle makes, so they are read back from both.
//
// Run by TestDashboard_Features*. Each scenario returns a plain object; the
// Go side asserts on it. Printed as one JSON document.
//
// Usage: node features_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const ALPHA = '/srv/alpha';
const LOGIN = ALPHA + '/.cloop/features/login';
const DARK = ALPHA + '/.cloop/features/dark-mode';

function projectsPayload() {
  return {
    multi_project: true,
    stats: {total_projects: 2},
    projects: [
      {name: 'alpha', path: ALPHA, goal: 'alpha goal', total_tasks: 3, done_tasks: 1, health: 'idle', status: 'initialized', has_git: true},
      {name: 'beta', path: '/srv/beta', goal: 'beta goal', total_tasks: 1, done_tasks: 0, health: 'idle', status: 'initialized'},
      {name: 'alpha/login', path: LOGIN, parent: ALPHA, goal: 'Users sign in', total_tasks: 3, done_tasks: 3,
        health: 'complete', status: 'complete',
        feature: {slug: 'login', title: 'Login', branch: 'cloop/feature/login', base: 'main',
          pr: {number: 12, url: 'https://github.com/acme/app/pull/12', state: 'open'}}},
      {name: 'alpha/dark-mode', path: DARK, parent: ALPHA, goal: 'Dark theme', total_tasks: 2, done_tasks: 0,
        health: 'running', status: 'running', running: true,
        feature: {slug: 'dark-mode', title: 'Dark <mode>', branch: 'cloop/feature/dark-mode', base: 'main',
          auto_evolve: true, innovate: true,
          pr: {number: 13, url: 'javascript:alert(1)', state: 'open'}}},
    ],
  };
}

const STATE = {goal: 'goal', status: 'initialized', plan: {goal: 'goal', tasks: []}};

function clone(o) { return JSON.parse(JSON.stringify(o)); }

async function boot() {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.projects = projectsPayload();
  h.states = {0: clone(STATE)};
  h.opened = [];
  globalThis.open = (url) => { h.opened.push(String(url)); return null; };
  require(bundlePath);
  await globalThis.__settle(5);
  const ws0 = h.sockets[h.sockets.length - 1];
  if (ws0) ws0.open();
  return h;
}

function currentSocket(h) { return h.sockets[h.sockets.length - 1]; }

// open selects project i the way a click does and delivers its first frame.
async function open(h, i, name) {
  window.openProject(i, name);
  await globalThis.__settle();
  const ws = currentSocket(h);
  ws.open();
  ws.deliver('task_update', clone(STATE));
  await globalThis.__settle();
  return ws;
}

function html(id) { return String(document.getElementById(id).innerHTML || ''); }

function all(re, s) {
  const out = [];
  let m;
  while ((m = re.exec(s)) !== null) out.push(m[1]);
  return out;
}

function mutations(h) {
  return h.requests.filter(r => r.method !== 'GET').map(r => ({method: r.method, url: r.url, body: r.body ? JSON.parse(r.body) : null}));
}

const scenarios = {
  // The grid draws projects as cards and features as chips inside their
  // project's card — never as cards of their own.
  async grid_nests_features() {
    await boot();
    window.switchTab('projects');
    await globalThis.__settle();
    const grid = html('projList');
    const cardIdx = all(/openProject\((\d+),/g, grid).map(Number);
    const chipIdx = all(/data-open-idx="(\d+)"/g, grid).map(Number);
    const alphaCard = grid.indexOf('openProject(0,');
    const betaCard = grid.indexOf('openProject(1,');
    const chipPos = grid.indexOf('data-open-idx="2"');
    return {
      cards: cardIdx,
      chips: chipIdx,
      chipsInsideAlpha: alphaCard >= 0 && chipPos > alphaCard && chipPos < betaCard,
      escaped: grid.includes('Dark &lt;mode&gt;') && !grid.includes('Dark <mode>'),
      total: String(document.getElementById('paTotal').textContent),
    };
  },

  // The multi-project Overview (no project selected) summarises projects, not
  // features — the same nesting as the grid.
  async overview_cards() {
    await boot();
    window.switchTab('overview');
    await globalThis.__settle();
    return {cards: all(/openProject\((\d+),/g, html('multiProjectCards')).map(Number)};
  },

  // The header dropdown lists each project followed by its features.
  async dropdown_nests_features() {
    await boot();
    await open(globalThis.__harness, 0, 'alpha');
    const drop = html('projSelectorDropdown');
    return {
      order: all(/selectProjectFromDropdown\((\d+),/g, drop).map(Number),
      sub: (drop.match(/proj-selector-item[^"]* sub/g) || []).length,
    };
  },

  // A project's Overview lists its features with actions keyed by index.
  async parent_panel() {
    const h = await boot();
    await open(h, 0, 'alpha');
    const list = html('featuresList');
    return {
      section: document.getElementById('featuresSection').style.display,
      banner: document.getElementById('featureBanner').style.display,
      runIdx: all(/data-act="run" data-idx="(\d+)"/g, list).map(Number),
      stopIdx: all(/data-act="stop" data-idx="(\d+)"/g, list).map(Number),
      prIdx: all(/data-act="pr" data-idx="(\d+)"/g, list).map(Number),
      removeIdx: all(/data-act="remove" data-idx="(\d+)"/g, list).map(Number),
      updatePR: (list.match(/Update PR/g) || []).length,
      prLink: list.includes('href="https://github.com/acme/app/pull/12"') && list.includes('target="_blank"'),
      unsafeLink: list.includes('javascript:'),
      options: list.includes('evolve') && list.includes('innovate'),
      newButton: document.getElementById('newFeatureBtn').style.display,
    };
  },

  // A project that is not a git repository cannot have features, and says so.
  async non_git_project() {
    const h = await boot();
    await open(h, 1, 'beta');
    return {
      section: document.getElementById('featuresSection').style.display,
      says: html('featuresList').includes('git repository'),
      newButton: document.getElementById('newFeatureBtn').style.display,
    };
  },

  // A feature's Overview shows where it came from, and the project-level
  // panels it inherits step aside.
  async feature_banner() {
    const h = await boot();
    await open(h, 2, 'alpha/login');
    const banner = html('featureBanner');
    return {
      banner: document.getElementById('featureBanner').style.display,
      section: document.getElementById('featuresSection').style.display,
      parentIdx: all(/data-act="parent" data-idx="(\d+)"/g, banner).map(Number),
      prIdx: all(/data-act="pr" data-idx="(\d+)"/g, banner).map(Number),
      updates: banner.includes('Update pull request'),
      branch: banner.includes('cloop/feature/login'),
      repos: document.getElementById('projectReposPanel').style.display,
    };
  },

  // New feature: the dialog posts to the parent, then opens the new feature
  // by the index the refreshed list gives it and starts it.
  async create_flow() {
    const h = await boot();
    await open(h, 0, 'alpha');
    window.openNewFeatureModal();
    document.getElementById('nfName').value = 'Payments';
    document.getElementById('nfDesc').value = 'Take payments';
    document.getElementById('nfTasks').value = 'Stripe\n\n  Invoices  \n';
    document.getElementById('nfBase').value = 'develop';
    document.getElementById('nfEvolve').checked = true;
    document.getElementById('nfInnovate').checked = false;
    document.getElementById('nfParallel').checked = true;
    document.getElementById('nfAutoPR').checked = true;
    document.getElementById('nfStart').checked = true;
    const created = ALPHA + '/.cloop/features/payments';
    h.routes['/api/projects/0/features'] = {ok: true, path: created, branch: 'cloop/feature/payments', project_idx: 4};
    h.routes['/api/run'] = {ok: true, command: 'cloop run'};
    const next = projectsPayload();
    next.projects.push({name: 'alpha/payments', path: created, parent: ALPHA, total_tasks: 2, done_tasks: 0,
      health: 'idle', status: 'initialized', feature: {slug: 'payments', title: 'Payments', branch: 'cloop/feature/payments', base: 'develop'}});
    h.projects = next;
    const before = h.requests.length;
    window.submitNewFeature();
    await globalThis.__settle(8);
    return {
      requests: mutations({requests: h.requests.slice(before)}),
      socketIdx: currentSocket(h).projectIdx,
      overlay: document.getElementById('newfeat-overlay').style.display,
    };
  },

  // Validation happens before anything is sent.
  async create_requires_goal() {
    const h = await boot();
    await open(h, 0, 'alpha');
    window.openNewFeatureModal();
    document.getElementById('nfName').value = 'x';
    document.getElementById('nfDesc').value = '   ';
    const before = h.requests.length;
    window.submitNewFeature();
    await globalThis.__settle();
    return {
      sent: mutations({requests: h.requests.slice(before)}).length,
      errorText: String(document.getElementById('nfError').textContent),
    };
  },

  // Pull request: posts to the parent's feature route and opens the result.
  async pr_flow() {
    const h = await boot();
    await open(h, 0, 'alpha');
    window.openFeaturePRModal(2);
    const updateTitle = String(document.getElementById('fprTitle').textContent);
    const updateFields = document.getElementById('fprFields').style.display;
    window.closeFeaturePRModal();

    // A feature with no PR yet.
    const np = projectsPayload();
    delete np.projects[3].feature.pr;
    h.projects = np;
    const ws = currentSocket(h);
    ws.deliver('projects', np);
    await globalThis.__settle();
    window.openFeaturePRModal(3);
    const openTitle = String(document.getElementById('fprTitle').textContent);
    document.getElementById('fprName').value = 'Dark mode (WIP)';
    document.getElementById('fprDraft').checked = true;
    h.routes['/api/projects/0/features/dark-mode/pr'] = {ok: true, result: {
      pr: {number: 14, url: 'https://github.com/acme/app/pull/14', state: 'open'}, existing: false, dirty: ['?? x']}};
    const before = h.requests.length;
    window.submitFeaturePR();
    await globalThis.__settle(5);
    return {
      updateTitle, updateFields, openTitle,
      requests: mutations({requests: h.requests.slice(before)}),
      opened: h.opened,
    };
  },

  // Removal from the feature's own page returns to its project.
  async remove_flow() {
    const h = await boot();
    await open(h, 3, 'alpha/dark-mode');
    window.openRemoveFeatureModal(3);
    document.getElementById('dfBranchToo').checked = true;
    h.routes['/api/projects/0/features/dark-mode'] = {ok: true, branch: 'cloop/feature/dark-mode', branch_deleted: true};
    const before = h.requests.length;
    window.submitRemoveFeature();
    await globalThis.__settle(5);
    return {
      requests: mutations({requests: h.requests.slice(before)}),
      socketIdx: currentSocket(h).projectIdx,
    };
  },

  // The selected feature removed elsewhere — another tab, a terminal — must
  // not leave the dashboard addressing whatever now has its index.
  async selection_vanishes() {
    const h = await boot();
    const ws = await open(h, 3, 'alpha/dark-mode');
    const without = projectsPayload();
    without.projects.splice(3, 1);
    ws.deliver('projects', without);
    await globalThis.__settle();
    return {socketIdx: currentSocket(h).projectIdx, landing: document.getElementById('projSelectorLabel').textContent};
  },

  // A dialog opened on one feature stays on that feature when the list is
  // renumbered underneath it — and does nothing if the feature is gone.
  async dialogs_follow_identity() {
    const h = await boot();
    const ws = await open(h, 0, 'alpha');
    window.openRemoveFeatureModal(3);          // dark-mode, force ticked
    document.getElementById('dfForce').checked = true;
    const shifted = projectsPayload();
    shifted.projects.splice(2, 1);            // login removed: dark-mode is now 2
    h.projects = shifted;
    ws.deliver('projects', shifted);
    await globalThis.__settle();
    h.routes['/api/projects/0/features/'] = {ok: true, branch: 'b', branch_deleted: false};
    let before = h.requests.length;
    window.submitRemoveFeature();
    await globalThis.__settle(5);
    const removal = mutations({requests: h.requests.slice(before)});

    window.openFeaturePRModal(2);              // dark-mode at its new index
    const gone = projectsPayload();
    gone.projects.splice(2, 2);               // both features gone
    h.projects = gone;
    ws.deliver('projects', gone);
    await globalThis.__settle();
    before = h.requests.length;
    window.submitFeaturePR();
    await globalThis.__settle(5);
    return {
      requests: removal,
      prAfterGone: mutations({requests: h.requests.slice(before)}).length,
      prError: String(document.getElementById('fprError').textContent),
    };
  },

  // A feature disappearing earlier in the list shifts the selected feature's
  // index; the next action must still reach it, not its new neighbour.
  async reanchors_after_shift() {
    const h = await boot();
    const ws = await open(h, 3, 'alpha/dark-mode');
    const shifted = projectsPayload();
    shifted.projects.splice(2, 1); // login removed: dark-mode is now index 2
    ws.deliver('projects', shifted);
    await globalThis.__settle();
    // The stream was reopened under the new index, so its frames are still
    // accepted: a task_update on it reaches the page.
    const ws2 = currentSocket(h);
    ws2.open();
    const moved = Object.assign(clone(STATE), {goal: 'after the shift'});
    ws2.deliver('task_update', moved);
    await globalThis.__settle();
    h.routes['/api/run'] = {ok: true, command: 'cloop run'};
    const before = h.requests.length;
    window.apiRun();
    await globalThis.__settle();
    return {
      requests: mutations({requests: h.requests.slice(before)}),
      socketIdx: ws2.projectIdx,
      rendered: String(document.getElementById('goalText').textContent),
    };
  },
};

(async () => {
  const out = {};
  for (const [name, fn] of Object.entries(scenarios)) {
    try {
      out[name] = await fn();
    } catch (e) {
      out[name] = {error: String(e && e.stack || e)};
    }
  }
  process.stdout.write(JSON.stringify(out));
  process.exit(0);
})();
