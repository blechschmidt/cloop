// hidden_scenarios.js — drives the real dashboard bundle through hiding and
// unhiding projects (Task 20206).
//
// The property worth running the actual bundle for is index stability. The
// dashboard addresses projects by their position in the /api/projects list —
// openProject, projectRun, projectStop, projectDelete and every
// ?project_idx=N call — and this feature makes the grid show a *subset* of
// that list. If the grid renumbers as it filters, hiding project 1 makes the
// Delete button on project 2 delete project 1. That is a bug about the
// relationship between two lists, which no grep over the source can express;
// it needs the DOM the user actually clicks.
//
// Run by TestDashboard_HidingPreservesProjectIndices. Each scenario returns a
// plain object; the Go side asserts on it. Printed as one JSON document.
//
// Usage: node hidden_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

// Three projects so "hide the middle one" has a distinguishable answer: the
// survivors are indices 0 and 2, never 0 and 1.
function projectsPayload(hiddenIdx) {
  const mk = (name, i) => ({
    name,
    path: '/srv/' + name,
    goal: name + ' goal',
    total_tasks: 2,
    done_tasks: 0,
    health: 'idle',
    hidden: i === hiddenIdx,
  });
  const projects = ['alpha', 'beta', 'gamma'].map(mk);
  // The server discounts hidden projects from the aggregate; mirror that so
  // the scenario exercises the same numbers a real payload carries.
  const visible = projects.filter(p => !p.hidden).length;
  return {multi_project: true, stats: {total_projects: visible}, projects};
}

function clone(o) { return JSON.parse(JSON.stringify(o)); }

async function boot(payload) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.projects = clone(payload);
  h.states = {0: {goal: 'alpha goal', status: 'idle', plan: {goal: 'alpha goal', tasks: []}}};

  require(bundlePath);
  await globalThis.__settle(5);
  return h;
}

// gridIndices returns the project index each rendered card dispatches on, in
// render order. It reads the openProject() call on the card itself — the
// same string the browser would run on click — rather than any convenient
// data-* attribute added for testing.
function gridIndices() {
  const html = document.getElementById('projList').innerHTML || '';
  const out = [];
  const re = /openProject\((\d+),/g;
  let m;
  while ((m = re.exec(html)) !== null) out.push(Number(m[1]));
  return out;
}

// gridNames returns the project names on screen, in render order.
function gridNames() {
  const html = document.getElementById('projList').innerHTML || '';
  const out = [];
  const re = /class="proj-name">([^<]*)</g;
  let m;
  while ((m = re.exec(html)) !== null) out.push(m[1]);
  return out;
}

// hiddenPanel returns what the Settings list offers to restore: the index
// each Unhide button posts to, and the names shown beside them.
function hiddenPanel() {
  const html = document.getElementById('hiddenProjectsList').innerHTML || '';
  const indices = [];
  const names = [];
  let m;
  const reIdx = /projectUnhide\((\d+),/g;
  while ((m = reIdx.exec(html)) !== null) indices.push(Number(m[1]));
  const reName = /class="hidden-proj-name">([^<]*)</g;
  while ((m = reName.exec(html)) !== null) names.push(m[1]);
  return {indices, names, empty: /No hidden projects/.test(html)};
}

const scenarios = {
  // Nothing hidden: the baseline the other cases are read against.
  async nothing_hidden() {
    await boot(projectsPayload(-1));
    window.switchTab('projects');
    await globalThis.__settle();
    return {
      grid: gridIndices(),
      names: gridNames(),
      panel: hiddenPanel(),
      total: String(document.getElementById('paTotal').textContent),
    };
  },

  // The load-bearing case. beta (index 1) is hidden: the grid must show alpha
  // and gamma still carrying indices 0 and 2. A renumbering bug renders
  // [0, 1] here, and every button on the gamma card then acts on beta.
  async middle_hidden_keeps_indices() {
    await boot(projectsPayload(1));
    window.switchTab('projects');
    await globalThis.__settle();
    return {
      grid: gridIndices(),
      names: gridNames(),
      panel: hiddenPanel(),
      total: String(document.getElementById('paTotal').textContent),
    };
  },

  // Hiding through the UI: the button must post the preference for the index
  // it was rendered with, and to the hide endpoint rather than the delete one.
  async hide_button_posts_preference() {
    const h = await boot(projectsPayload(-1));
    window.switchTab('projects');
    await globalThis.__settle();

    h.requests.length = 0;
    window.projectHide(2, 'gamma');
    await globalThis.__settle();

    const posts = h.requests.filter(r => r.method === 'POST');
    return {
      posts: posts.map(r => r.url),
      // Nothing may be deleted by a hide, ever.
      deletes: h.requests.filter(r => r.method === 'DELETE').map(r => r.url),
    };
  },

  // Unhiding from Settings posts against the same index namespace, which is
  // only true because hidden projects stayed in the list.
  async unhide_button_posts_preference() {
    const h = await boot(projectsPayload(1));
    window.switchTab('projects');
    await globalThis.__settle();

    h.requests.length = 0;
    window.projectUnhide(1, 'beta');
    await globalThis.__settle();

    return {posts: h.requests.filter(r => r.method === 'POST').map(r => r.url)};
  },

  // Every project hidden: the grid must explain itself and name the way back,
  // not fall through to the "all completed" message for a different cause.
  async all_hidden_explains_itself() {
    const payload = projectsPayload(-1);
    payload.projects.forEach(p => { p.hidden = true; });
    payload.stats.total_projects = 0;
    await boot(payload);
    window.switchTab('projects');
    await globalThis.__settle();

    const html = document.getElementById('projList').innerHTML || '';
    return {
      grid: gridIndices(),
      mentionsSettings: /Settings/.test(html),
      mentionsCompleted: /completed/i.test(html),
      panel: hiddenPanel(),
    };
  },

  // The Overview tab draws its own card grid from the same payload. It is a
  // second render path, and per-project filtering has been fixed in one path
  // while being forgotten in the other often enough in this codebase that it
  // is worth pinning both.
  async overview_grid_also_hides() {
    await boot(projectsPayload(1));
    window.switchTab('projects');           // populates the cached payload
    await globalThis.__settle();
    window.clearProjectSelection();         // overview, no project selected
    window.switchTab('overview');
    await globalThis.__settle();

    const html = document.getElementById('multiProjectCards').innerHTML || '';
    const indices = [];
    const re = /openProject\((\d+),/g;
    let m;
    while ((m = re.exec(html)) !== null) indices.push(Number(m[1]));

    // The header dropdown is the third render path, and the one that would
    // quietly undo the feature by offering the hidden project for selection.
    const dropHtml = document.getElementById('projSelectorDropdown').innerHTML || '';
    const dropIndices = [];
    const reDrop = /selectProjectFromDropdown\((\d+),/g;
    while ((m = reDrop.exec(dropHtml)) !== null) dropIndices.push(Number(m[1]));

    return {
      grid: indices,
      names: /beta/.test(html) ? ['beta'] : [],
      dropdown: dropIndices,
    };
  },

  // Opening Settings before ever visiting the Projects tab must still list
  // what is hidden — that path renders from a fetch, not from a cached
  // payload.
  async settings_first_still_lists_hidden() {
    await boot(projectsPayload(1));
    window.switchTab('settings');
    await globalThis.__settle(5);
    return {panel: hiddenPanel()};
  },
};

(async () => {
  const out = {};
  for (const [name, fn] of Object.entries(scenarios)) {
    try {
      out[name] = await fn();
    } catch (e) {
      out[name] = {error: String((e && e.stack) || e)};
    }
  }
  process.stdout.write(JSON.stringify(out, null, 2));
})();
