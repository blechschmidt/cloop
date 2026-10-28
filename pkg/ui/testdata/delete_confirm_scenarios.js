// delete_confirm_scenarios.js — the two DELETEs the dashboard sent without
// asking (Task 20422), clicked through the dispatcher the way a browser does.
//
// Deleting a knowledge-base entry and revoking a project's repository grant
// each went straight to the API on one click, and the GitHub App panel routed
// its data-gh-* attributes from a listener on the whole document, so a revoke
// control injected anywhere on the page — a task's output, say — revoked a
// grant. Each attempt below records whether the page asked and what it sent:
// a declined confirmation sends nothing, an accepted one sends the DELETE, and
// a control outside the panel, or naming something the panel does not show,
// neither asks nor sends.
//
// Run by TestDashboard_DeletesAskFirst. Usage:
//   node delete_confirm_scenarios.js <domshim.js> <bundle.js> [scenario]

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];
const only = process.argv[4];

// An element as the dispatcher sees one: its attributes as dataset and as what
// closest() matches, and the GitHub App panel among its ancestors or not.
function elementFrom(attrs, inPanel) {
  const dataset = {};
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith('data-')) dataset[k.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = v;
  }
  const el = {tagName: 'BUTTON', dataset, disabled: false, matches: () => false,
    getAttribute: name => (Object.prototype.hasOwnProperty.call(attrs, name) ? attrs[name] : null)};
  el.closest = sel => {
    if (sel === '#projectReposPanel') return inPanel ? {id: 'projectReposPanel'} : null;
    const m = /^\[([\w-]+)\]$/.exec(String(sel));
    return m && Object.prototype.hasOwnProperty.call(attrs, m[1]) ? el : null;
  };
  return el;
}

async function boot() {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  // One project, so the Overview's repository panel has a subject.
  h.projects = {multi_project: false, projects: [], stats: {}};
  h.states = {0: {goal: 'g', status: 'idle', plan: {goal: 'g', tasks: []}}};
  h.routes['/api/projects/0/repositories'] = {
    apps: [],
    assignments: [{grant_id: 'grant-api', repos: ['acme/api', 'acme/web'], access: 'write',
      secret_name: 'acme-app', kind: 'github_app', replaceable: true}],
    git_proxy: {running: true, push_refs: ['refs/heads/cloop/**']},
  };
  h.routes['/api/kb'] = {entries: [{id: 7, title: 'Deploy runbook', content: 'x', tags: []}]};
  require(bundlePath);
  await globalThis.__settle(5);
  // The Knowledge Base tab is a deferred panel since Task 20456: fetched the
  // way opening the tab fetches it, and opened.
  globalThis.KB = await window.panelAct('kb');
  await globalThis.KB.open();
  await window.loadProjectRepositories();
  await globalThis.__settle(5);
  return h;
}

const scenarios = {
  async delete_confirmations() {
    const h = await boot();
    const tried = [];
    const attempt = async (label, attrs, inPanel, answer) => {
      h.requests.length = 0;
      const asked = [];
      globalThis.confirm = msg => { asked.push(String(msg)); return answer; };
      let error = '';
      try {
        // The entry's delete button is the KB panel's (data-act="del"), which
        // mountPanel routes from the tab to the panel's own del(); anything
        // else is a click the document's dispatcher answers.
        if (attrs['data-act'] === 'del') globalThis.KB.del.call(elementFrom(attrs, inPanel), attrs['data-arg']);
        else document.dispatchEvent({type: 'click', target: elementFrom(attrs, inPanel)});
      } catch (e) {
        error = String((e && e.message) || e);
      }
      await globalThis.__settle(5);
      tried.push({label, asked, error,
        sent: h.requests.filter(r => r.method === 'DELETE').map(r => r.method + ' ' + r.url)});
    };
    const kb = {'data-act': 'del', 'data-arg': '7'};
    const revoke = {'data-action': 'ghRevoke', 'data-arg': 'grant-api'};
    await attempt('kb declined', kb, false, false);
    await attempt('kb accepted', kb, false, true);
    await attempt('kb unknown entry', {'data-act': 'del', 'data-arg': '99'}, false, true);
    await attempt('revoke outside the panel', revoke, false, true);
    // The attribute the panel's own document-wide router used to answer.
    await attempt('old revoke attribute outside the panel', {'data-gh-revoke': 'grant-api'}, false, true);
    await attempt('revoke declined', revoke, true, false);
    await attempt('revoke accepted', revoke, true, true);
    await attempt('revoke unknown grant', {'data-action': 'ghRevoke', 'data-arg': 'grant-other'}, true, true);
    return {tried};
  },
};

(async () => {
  const out = {};
  for (const [name, fn] of Object.entries(scenarios)) {
    if (only && name !== only) continue;
    try {
      out[name] = await fn();
    } catch (e) {
      out[name] = {error: String((e && e.stack) || e)};
    }
  }
  process.stdout.write(JSON.stringify(out), () => process.exit(0));
})();
