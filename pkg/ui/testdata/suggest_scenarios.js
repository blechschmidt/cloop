// suggest_scenarios.js — drives the Tasks tab's AI suggestions panel against
// the real dashboard bundle (Task 20342).
//
// The panel does two jobs through one set of controls: with the request box
// empty it brainstorms ideas, and with it filled it has the AI plan that
// request, the count becoming the plan's length (blank: as many as needed).
// What is worth running the bundle for is behaviour no grep can see:
//
//   * what Generate actually posts for each combination of request and count;
//   * that a plan's cards say which step they are and what they follow;
//   * that accepting sends IDs and the generation, not client-side copies;
//   * that the server re-sending a generation after an add neither re-toasts
//     nor brings back a card this page skipped;
//   * that leaving a project leaves none of its cards behind to be added to
//     the next one.
//
// Run by TestDashboard_SuggestPanelPlansARequest. Printed as one JSON document.
//
// Usage: node suggest_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const ALPHA = {goal: 'alpha goal', status: 'initialized', plan: {goal: 'alpha goal', tasks: []}};
const BETA = {goal: 'beta goal', status: 'initialized', plan: {goal: 'beta goal', tasks: []}};
const PROJECTS = {
  multi_project: true,
  stats: {total_projects: 2},
  projects: [
    {name: 'alpha', path: '/srv/alpha', goal: 'alpha goal', total_tasks: 0, done_tasks: 0, health: 'idle'},
    {name: 'beta',  path: '/srv/beta',  goal: 'beta goal',  total_tasks: 0, done_tasks: 0, health: 'idle'},
  ],
};

// A plan as the hub sends it: normalized, and marked by its request.
const PLAN = {
  gen: 7, running: false, done: true, error: '',
  request: 'Add OAuth login', summary: 'OAuth login in four steps',
  suggestions: [
    {id: 1, title: 'Add provider config', description: 'd1', category: 'feature', effort: 'l'},
    {id: 2, title: 'Callback handler', description: 'd2', category: 'security', effort: 'xs', depends_on: [1]},
    {id: 3, title: 'Login button', description: 'd3', category: 'ux', effort: 's', depends_on: [1]},
    {id: 4, title: 'Document <login>', description: 'd4', category: 'docs', effort: 'm', depends_on: [2, 3]},
  ],
};

const IDEAS = {
  gen: 9, running: false, done: true, error: '', request: '', summary: 'two ideas',
  suggestions: [
    {id: 1, title: 'Dark mode', category: 'ux', effort: 's'},
    {id: 2, title: 'Rate limits', category: 'security', effort: 'm'},
  ],
};

function clone(o) { return JSON.parse(JSON.stringify(o)); }

async function boot() {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.states = {0: clone(ALPHA), 1: clone(BETA)};
  h.projects = clone(PROJECTS);
  h.routes['/api/suggest/generate'] = {ok: true, gen: 7};
  h.routes['/api/suggest/add'] = {ok: true, added: [], tasks: []};

  require(bundlePath);
  await globalThis.__settle(5);
  const ws = h.sockets[h.sockets.length - 1];
  if (ws) ws.open();
  await globalThis.__settle(2);
  return h;
}

function currentSocket(h) { return h.sockets[h.sockets.length - 1]; }

// openBeta walks to beta's Tasks tab and opens the panel, where every
// scenario starts.
async function openBeta(h) {
  window.openProject(1, 'beta');
  await globalThis.__settle();
  const ws = currentSocket(h);
  ws.open();
  ws.deliver('task_update', clone(BETA));
  window.switchTab('tasks');
  window.toggleSuggestPanel();
  await globalThis.__settle(2);
  return ws;
}

const el = id => document.getElementById(id);
const vis = id => el(id).style.display !== 'none';

// panel reads back what the user sees in the panel.
function panel() {
  const html = el('suggestList').innerHTML || '';
  const titles = [];
  let m;
  const re = /class="suggest-card-title">([^<]*(?:&lt;[^<]*)*)</g;
  while ((m = re.exec(html)) !== null) titles.push(m[1]);
  const after = [];
  const reAfter = /suggest-tag-dep">after ([^<]*)</g;
  while ((m = reAfter.exec(html)) !== null) after.push(m[1]);
  return {
    titles,
    after,
    badge: String(el('suggestCountBadge').textContent || ''),
    summary: vis('suggestSummary') ? String(el('suggestSummary').textContent || '') : '',
    addAll: vis('suggestAddAllBtn'),
    label: String(el('suggestCountLabel').textContent || ''),
    placeholder: String(el('suggestCount').placeholder || ''),
    input: String(el('suggestInput').value || ''),
    toast: String(el('toast').textContent || ''),
  };
}

function posts(h, path) {
  return h.requests
    .filter(r => r.method === 'POST' && r.url.startsWith(path))
    .map(r => ({url: r.url, body: JSON.parse(r.body || 'null')}));
}

const scenarios = {
  // The count field says what it means for what Generate will do.
  async mode_follows_the_input() {
    const h = await boot();
    await openBeta(h);
    window.syncSuggestMode();
    const brainstorm = panel();
    el('suggestInput').value = '  Add OAuth login ';
    window.syncSuggestMode();
    const plan = panel();
    el('suggestInput').value = '   ';
    window.syncSuggestMode();
    const blank = panel();
    return {brainstorm, plan, blank};
  },

  // What Generate posts, and to which project, for each combination.
  async generate_posts_request_and_optional_count() {
    const h = await boot();
    await openBeta(h);
    const cases = [
      {input: 'Add OAuth login', count: ''},
      {input: 'Add OAuth login', count: '4'},
      {input: '', count: ''},
      {input: '', count: '-3'},
    ];
    const out = [];
    for (const c of cases) {
      el('suggestInput').value = c.input;
      el('suggestCount').value = c.count;
      h.requests.length = 0;
      window.runSuggest();
      const status = String(el('suggestStatusText').textContent || '');
      await globalThis.__settle();
      const p = posts(h, '/api/suggest/generate');
      out.push({status, url: p.length ? p[0].url : '', body: p.length ? p[0].body : null});
    }
    return {cases: out};
  },

  // A plan arrives: its cards are numbered steps that say what they follow,
  // and titles are escaped like every other card.
  async plan_renders_as_steps() {
    const h = await boot();
    const ws = await openBeta(h);
    ws.deliver('suggest_status', clone(PLAN));
    await globalThis.__settle();
    return panel();
  },

  // Accepting sends the generation and IDs — the server holds the plan — and
  // takes the accepted cards off the list.
  async accepting_sends_ids_and_generation() {
    const h = await boot();
    const ws = await openBeta(h);
    ws.deliver('suggest_status', clone(PLAN));
    await globalThis.__settle();

    h.routes['/api/suggest/add'] = {ok: true, added: [12], tasks: [{id: 12, title: 'Login button', status: 'pending', priority: 3}]};
    window.acceptSuggestion(2); // the third card: step 3
    await globalThis.__settle();
    const one = panel();

    h.routes['/api/suggest/add'] = {ok: true, added: [13, 14, 15], tasks: []};
    window.addAllSuggestions();
    await globalThis.__settle();
    const all = panel();

    return {adds: posts(h, '/api/suggest/add'), one, all,
            rendered: globalThis.__renderedTaskIds ? globalThis.__renderedTaskIds() : []};
  },

  // The hub re-sends the generation after every add, from any tab. That must
  // only drop what was added: no second toast, and a card skipped here stays
  // skipped rather than coming back.
  async same_generation_update_keeps_skips() {
    const h = await boot();
    const ws = await openBeta(h);
    ws.deliver('suggest_status', clone(PLAN));
    await globalThis.__settle();
    window.rejectSuggestion(1); // skip step 2
    el('toast').textContent = '';

    const update = clone(PLAN);
    update.suggestions = update.suggestions.filter(s => s.id !== 1); // step 1 added elsewhere
    ws.deliver('suggest_status', update);
    await globalThis.__settle();
    return panel();
  },

  // A brainstorm is still a brainstorm: no step numbers, counted as ideas.
  async ideas_render_as_ideas() {
    const h = await boot();
    const ws = await openBeta(h);
    ws.deliver('suggest_status', clone(IDEAS));
    await globalThis.__settle();
    return panel();
  },

  // An add whose reply lands after the user has moved to another project must
  // leave that project alone: beta's new task is not merged into alpha's list,
  // and beta's IDs do not strike alpha's cards that happen to share them.
  async add_reply_after_switching_projects_stays_out() {
    const h = await boot();
    const ws = await openBeta(h);
    ws.deliver('suggest_status', clone(PLAN));
    await globalThis.__settle();

    let release;
    const realFetch = globalThis.fetch;
    globalThis.fetch = (url, opts) => {
      if (!String(url).startsWith('/api/suggest/add')) return realFetch(url, opts);
      realFetch(url, opts); // recorded like any other request
      const body = JSON.stringify({ok: true, added: [12], tasks: [{id: 12, title: 'Login button', status: 'pending', priority: 3}]});
      return new Promise(r => { release = () => r({
        ok: true, status: 200, headers: {get: () => null},
        json: () => Promise.resolve(JSON.parse(body)), text: () => Promise.resolve(body),
      }); });
    };
    window.addAllSuggestions();
    window.openProject(0, 'alpha');
    await globalThis.__settle();
    const ws2 = currentSocket(h);
    ws2.open();
    ws2.deliver('task_update', clone(ALPHA));
    ws2.deliver('suggest_status', {gen: 8, running: false, done: true, error: '', request: '',
      summary: 'alpha ideas', suggestions: [{id: 3, title: 'Alpha idea', category: 'ux', effort: 's'}]});
    await globalThis.__settle();
    release();
    await globalThis.__settle(5);
    globalThis.fetch = realFetch;
    return Object.assign(panel(), {rendered: globalThis.__renderedTaskIds()});
  },

  // Leaving the project leaves nothing behind: no cards to add to the next
  // project, and no half-typed request.
  async leaving_the_project_clears_the_panel() {
    const h = await boot();
    const ws = await openBeta(h);
    el('suggestInput').value = 'Add OAuth login';
    window.syncSuggestMode();
    ws.deliver('suggest_status', clone(PLAN));
    await globalThis.__settle();

    window.openProject(0, 'alpha');
    await globalThis.__settle();
    const after = panel();
    h.requests.length = 0;
    window.addAllSuggestions();
    await globalThis.__settle();
    return Object.assign(after, {adds: posts(h, '/api/suggest/add')});
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
