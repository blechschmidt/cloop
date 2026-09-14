// stt_settings_scenarios.js — drives the Settings tab's speech-to-text panel
// against the real dashboard bundle (Task 20250).
//
// The property worth holding is the scoping one. Every other field in that tab
// is written through /api/config/set, which the bundle calls via pUrl() — so it
// carries ?project_idx and lands in the selected project. Dictation reads the
// other way round: /api/dictate and /api/transcribe are called unscoped and
// resolve against the hub alone. A future edit that "tidies" these calls into
// pUrl() for consistency would restore the exact bug this panel was built to
// avoid — a key that saves, reports success, and switches nothing on — and a
// text grep cannot tell the two call styles apart. Running the bundle can.
//
// Run by TestDashboard_STTSettingsPanel. Each scenario returns a flat object
// and the Go side asserts on it. Printed as one JSON document on stdout.
//
// Usage: node stt_settings_scenarios.js <domshim.js> <bundle.js>

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

// NO_KEY / HAS_KEY are the two shapes GET /api/config/stt actually returns.
const NO_KEY = {
  has_key: false, stored: false, from_env: false, available: false,
  reason: 'speech-to-text is not configured: set stt.groq_api_key',
  endpoint: 'https://api.groq.com/openai/v1/audio/transcriptions',
};
const HAS_KEY = {
  has_key: true, stored: true, from_env: false, available: true,
  endpoint: 'https://api.groq.com/openai/v1/audio/transcriptions',
};

function clone(o) { return JSON.parse(JSON.stringify(o)); }

async function boot(sttResponse) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.states = {0: clone(ALPHA), 1: clone(BETA)};
  h.projects = clone(PROJECTS);
  h.routes['/api/config/stt'] = clone(sttResponse);
  // The dictate probe runs at DOMContentLoaded and again after a save.
  h.routes['/api/dictate'] = {available: sttResponse.available, can_add_tasks: true, backend: 'groq'};

  require(bundlePath);
  await globalThis.__settle(5);
  const ws = h.sockets[h.sockets.length - 1];
  if (ws) ws.open();
  await globalThis.__settle(2);
  return h;
}

function vis(id) {
  const el = document.getElementById(id);
  return !el || el.style.display !== 'none';
}

function sttRequests(h) {
  return h.requests.filter(r => r.url.startsWith('/api/config/stt'));
}

// openSettingsOnBeta selects the second project and lands on Settings, which is
// the arrangement that makes a project-scoped request possible at all.
async function openSettingsOnBeta(h) {
  window.openProject(1, 'beta');
  await globalThis.__settle(2);
  const ws = h.sockets[h.sockets.length - 1];
  if (ws) ws.open();
  window.switchTab('settings');
  await globalThis.__settle(3);
}

// reopenSettingsWith swaps the canned answer and walks away and back, which is
// what re-runs the panel's loader. Returns whether Clear is then offered.
async function reopenSettingsWith(h, sttResponse) {
  h.routes['/api/config/stt'] = clone(sttResponse);
  window.switchTab('overview');
  await globalThis.__settle(2);
  window.switchTab('settings');
  await globalThis.__settle(3);
  return vis('sttClearBtn');
}

const scenarios = {
  // The anti-regression property: with beta selected, the panel must still ask
  // the hub. A request carrying ?project_idx=1 would be reading a config that
  // dictation never consults.
  async load_is_hub_scoped_even_with_a_project_selected() {
    const h = await boot(NO_KEY);
    await openSettingsOnBeta(h);

    const reqs = sttRequests(h);
    return {
      requested: reqs.length > 0,
      urls: reqs.map(r => r.url),
      anyScoped: reqs.some(r => r.url.includes('project_idx')),
    };
  },

  // Saving has to PUT, must not leave the credential sitting in the DOM, and
  // has to re-ask /api/dictate: the Tasks tab decides once at load whether to
  // show its button, so without the re-probe the key works while the button
  // the user came to Settings to enable stays hidden until a reload.
  async save_puts_clears_the_field_and_rechecks_dictation() {
    const h = await boot(NO_KEY);
    await openSettingsOnBeta(h);

    document.getElementById('cfgGroqKey').value = '  gsk_typed_by_hand  ';
    h.routes['/api/config/stt'] = clone(HAS_KEY);
    h.routes['/api/dictate'] = {available: true, can_add_tasks: true, backend: 'groq'};

    const dictateBefore = h.requests.filter(r => r.url.startsWith('/api/dictate')).length;
    window.saveSTTCfg();
    await globalThis.__settle(4);

    const puts = sttRequests(h).filter(r => r.method === 'PUT');
    return {
      putCount: puts.length,
      anyScoped: puts.some(r => r.url.includes('project_idx')),
      fieldAfter: document.getElementById('cfgGroqKey').value,
      dictateRechecked:
        h.requests.filter(r => r.url.startsWith('/api/dictate')).length > dictateBefore,
      clearOffered: vis('sttClearBtn'),
    };
  },

  // A key from GROQ_API_KEY is the environment's. Offering to clear it would
  // be a button that silently does nothing, so it is withheld.
  //
  // Driven by re-entering the tab rather than by calling the renderer, which
  // is IIFE-local: going through switchTab is both the only reachable path and
  // the one a user takes.
  async clear_is_offered_only_for_a_stored_key() {
    const h = await boot(NO_KEY);
    await openSettingsOnBeta(h);
    const withNothing = vis('sttClearBtn');

    const withEnvKey = await reopenSettingsWith(
      h, {has_key: true, stored: false, from_env: true, available: true});
    const withStoredKey = await reopenSettingsWith(h, clone(HAS_KEY));

    return {withNothing, withEnvKey, withStoredKey};
  },

  // A blank Save must not reach the network: the hub answers 400, and spending
  // a round trip to be told what the field already knows reads as a failure.
  async blank_save_does_not_reach_the_network() {
    const h = await boot(NO_KEY);
    await openSettingsOnBeta(h);

    document.getElementById('cfgGroqKey').value = '   ';
    const before = sttRequests(h).filter(r => r.method === 'PUT').length;
    window.saveSTTCfg();
    await globalThis.__settle(3);

    return {putsBefore: before, putsAfter: sttRequests(h).filter(r => r.method === 'PUT').length};
  },

  // Clearing takes the Dictate button away again. initTaskDictation only ever
  // revealed it before this panel existed, because nothing could revoke a key
  // at runtime; now something can.
  async clearing_hides_the_dictate_button() {
    const h = await boot(HAS_KEY);
    await openSettingsOnBeta(h);
    window.switchTab('tasks');
    await globalThis.__settle(3);
    const before = vis('dictateTaskBtn');

    window.switchTab('settings');
    await globalThis.__settle(2);
    h.routes['/api/config/stt'] = clone(NO_KEY);
    h.routes['/api/dictate'] = {available: false, can_add_tasks: true};
    window.clearSTTCfg();
    await globalThis.__settle(4);

    return {visibleBefore: before, visibleAfter: vis('dictateTaskBtn')};
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
  process.stdout.write(JSON.stringify(out));
})();
