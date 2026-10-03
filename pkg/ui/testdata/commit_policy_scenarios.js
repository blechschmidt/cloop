// commit_policy_scenarios.js — drives the Overview's "Done = Committed" and
// "…and Pushed" badges against the real dashboard bundle (Task 20370).
//
// Run by TestDashboard_CommitPolicyBadges. Each scenario returns a flat object
// and the Go side asserts on it. Printed as one JSON document on stdout.
//
// Usage: node commit_policy_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const PROJECT = {
  goal: 'ship it',
  status: 'initialized',
  plan: {goal: 'ship it', tasks: [{id: 1, title: 'one', status: 'pending', priority: 1}]},
};

const PROJECTS = {
  multi_project: true,
  stats: {total_projects: 1},
  projects: [{name: 'alpha', path: '/srv/alpha', goal: 'ship it', total_tasks: 1, done_tasks: 0, health: 'idle'}],
};

function clone(o) { return JSON.parse(JSON.stringify(o)); }

async function open(st) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.states = {0: clone(st)};
  h.projects = clone(PROJECTS);
  require(bundlePath);
  await globalThis.__settle(5);
  window.openProject(0, 'alpha');
  await globalThis.__settle();
  const ws = h.sockets[h.sockets.length - 1];
  ws.open();
  ws.deliver('task_update', clone(st));
  await globalThis.__settle(2);
  return {h, ws};
}

// badge reports whether the badge whose label is text is rendered, and on.
function badge(text) {
  const html = document.getElementById('activeOptionsGrid').innerHTML || '';
  const i = html.indexOf('<span>' + text + '</span>');
  if (i < 0) return 'absent';
  const start = html.lastIndexOf('<button', i);
  const tag = html.slice(start, html.indexOf('>', start));
  return /class="option-badge on /.test(tag) ? 'on' : 'off';
}

function badges() {
  return {committed: badge('Done = Committed'), pushed: badge('…and Pushed')};
}

const scenarios = {
  // Off by default; the badges follow the policy a state_diff carries.
  async badges_follow_the_policy() {
    const {ws} = await open(PROJECT);
    const off = badges();
    ws.deliver('state_diff', {state_changed: {commit_policy: {enabled: true}}});
    await globalThis.__settle(2);
    const committed = badges();
    ws.deliver('state_diff', {state_changed: {commit_policy: {enabled: true, pushed: true}}});
    await globalThis.__settle(2);
    const pushed = badges();
    // Off with "pushed" remembered shows both off.
    ws.deliver('state_diff', {state_changed: {commit_policy: {enabled: false, pushed: true}}});
    await globalThis.__settle(2);
    return {off, committed, pushed, remembered: badges()};
  },

  // Clicking "…and Pushed" asks the hub for it, and the badges show what the
  // hub answered without waiting for the broadcast.
  async pushed_badge_posts_and_applies_the_answer() {
    const st = clone(PROJECT);
    st.commit_policy = {enabled: true};
    const {h} = await open(st);
    h.routes['/api/options/toggle'] = {ok: true, commit_policy: {enabled: true, pushed: true}};
    window.toggleOption('require_pushed', true);
    await globalThis.__settle(4);
    const posts = h.requests.filter(r => r.url.startsWith('/api/options/toggle')).map(r => r.body);
    return {posts, after: badges()};
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
