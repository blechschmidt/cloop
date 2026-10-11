// xss_scenarios.js — the five places a project's name reached an inline
// handler (Task 20408), rendered from projects with hostile names and clicked
// through the dispatcher.
//
// The names are what anybody allowed to create a project can choose: the
// directory's base name, any byte but '/' and NUL. The first is the reported
// proof of concept — the literal text &quot; survives JSON.stringify, the HTML
// parser decodes it inside the attribute, and the JavaScript it was spliced
// into ends its string there. The sites: a Projects card (open, Hide, Delete),
// the Overview's project cards, the header's project dropdown, and the hidden
// projects dialog (Unhide).
//
// The rendered markup is read the way a browser reads it — tags split on
// quoted attribute values, character references decoded — so a name that
// broke out of its attribute shows up as an attribute of its own. Each control
// is then clicked as the browser would: an event, with that element as its
// target, through the dispatcher's document listener. What the action did is
// read back from the page.
//
// A second scenario holds the dispatcher to its tables: an event the user does
// not aim at an element — the pointer entering it, a drag crossing it — runs
// only what was registered for that event, never a click's action, and a
// click never runs one of those.
//
// Run by TestDashboard_HostileProjectNamesStayData and
// TestDashboard_PassingEventsRunOnlyTheirOwnActions. Usage:
//   node xss_scenarios.js <domshim.js> <bundle.js> [scenario]

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];
const only = process.argv[4];

const HOSTILE = [
  `demo&quot;+(document.title='PWNED')+&quot;`,
  `x"><img src=x onerror="globalThis.__xss=1">`,
  `x'><svg onload=globalThis.__xss=1>`,
  `</script><script>globalThis.__xss=1</script>`,
  `javascript:globalThis.__xss=1`,
  `line sep &amp;&#39;\``,
];

// Every name twice: shown (the card, the Overview, the dropdown) and hidden
// (the dialog), at indices i and i + HOSTILE.length.
function payload() {
  const mk = (name, i, hidden) => ({
    name,
    path: (hidden ? '/srv/hidden/' : '/srv/work/') + name,
    goal: 'goal ' + i,
    total_tasks: 1,
    done_tasks: 0,
    health: 'idle',
    hidden,
  });
  const projects = HOSTILE.map((n, i) => mk(n, i, false)).concat(HOSTILE.map((n, i) => mk(n, i, true)));
  return {multi_project: true, stats: {total_projects: HOSTILE.length}, projects};
}

// The HTML parser's view of a fragment: each start tag's name and attributes,
// values decoded. Values are matched quote-aware, so an escape that failed
// splits the tag where a browser would.
function tagsOf(html) {
  const out = [];
  const tagRe = /<([a-zA-Z][a-zA-Z0-9-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>/g;
  let m;
  while ((m = tagRe.exec(html)) !== null) {
    const attrs = {};
    const attrRe = /\s+([^\s=/>"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+)))?/g;
    let a;
    while ((a = attrRe.exec(m[2])) !== null) {
      attrs[a[1].toLowerCase()] = decode(a[2] ?? a[3] ?? a[4] ?? '');
    }
    out.push({tag: m[1].toLowerCase(), attrs});
  }
  return out;
}

function decode(s) {
  const named = {amp: '&', lt: '<', gt: '>', quot: '"', apos: "'"};
  return s.replace(/&(?:#(\d+)|#[xX]([0-9a-fA-F]+)|(amp|lt|gt|quot|apos));/g,
    (_, d, x, n) => (d ? String.fromCodePoint(+d) : x ? String.fromCodePoint(parseInt(x, 16)) : named[n]));
}

// An element as the dispatcher sees one: the attributes the tag carried, as
// dataset and as what closest() can match.
function elementFrom(attrs) {
  const dataset = {};
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith('data-')) dataset[k.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = v;
  }
  const el = {tagName: 'BUTTON', dataset, disabled: false, matches: () => false};
  el.closest = sel => {
    const m = /^\[([\w-]+)\]$/.exec(String(sel));
    return m && Object.prototype.hasOwnProperty.call(attrs, m[1]) ? el : null;
  };
  return el;
}

const text = id => String(document.getElementById(id).textContent);

async function click(attrs) {
  document.dispatchEvent({type: 'click', target: elementFrom(attrs)});
  await globalThis.__settle(5);
}

// boot loads a fresh shim and bundle over the hostile projects.
async function boot() {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.projects = payload();
  h.states = {0: {goal: 'goal 0', status: 'idle', plan: {goal: 'goal 0', tasks: []}}};
  require(bundlePath);
  await globalThis.__settle(5);
  return h;
}

const scenarios = {
  async hostile_names() {
    const h = await boot();

    window.switchTab('projects');
    await globalThis.__settle(5);
    const grid = String(document.getElementById('projList').innerHTML);
    window.clearProjectSelection();
    window.switchTab('overview');
    await globalThis.__settle(5);
    const overview = String(document.getElementById('multiProjectCards').innerHTML);
    const dropdown = String(document.getElementById('projSelectorDropdown').innerHTML);
    window.openHiddenProjectsModal();
    await globalThis.__settle(5);
    const hidden = String(document.getElementById('hiddenProjectsList').innerHTML);

    const containers = {
      projList: tagsOf(grid),
      multiProjectCards: tagsOf(overview),
      projSelectorDropdown: tagsOf(dropdown),
      hiddenProjectsList: tagsOf(hidden),
    };

    // Click every control the five sites draw, and read back what it did.
    const effects = [];
    for (const [where, tags] of Object.entries(containers)) {
      for (const {attrs} of tags) {
        const action = attrs['data-action'];
        if (!['openProject', 'selectProjectFromDropdown', 'projectHide', 'projectUnhide', 'projectDelete'].includes(action)) continue;
        window.clearProjectSelection();
        await globalThis.__settle(5);
        h.requests.length = 0;
        await click(attrs);
        const e = {where, action, idx: Number(attrs['data-arg'])};
        if (action === 'openProject' || action === 'selectProjectFromDropdown') {
          e.label = text('projSelectorLabel');
          e.breadcrumb = text('breadcrumbName');
        } else if (action === 'projectDelete') {
          e.name = text('delproj-name');
          e.path = text('delproj-path');
          e.deleteIdx = String(document.getElementById('delproj-idx').value);
          window.closeDeleteProjectModal();
        } else {
          const post = h.requests.find(r => r.method === 'POST');
          e.post = post ? post.url : '';
          e.body = post ? String(post.body) : '';
        }
        effects.push(e);
      }
    }
    return {
      names: HOSTILE,
      containers,
      effects,
      title: String(document.title),
      xss: globalThis.__xss === undefined ? null : String(globalThis.__xss),
    };
  },

  // What injected markup could try: a click's action named on mouseenter or a
  // drag event, and a drag's action named on a click. Each must be refused —
  // the dispatcher throws, as for any name it does not hold — and send
  // nothing. The last is the control: the same action, clicked, posts.
  async passing_events() {
    const h = await boot();
    const tried = [];
    const attempt = async (type, attrs) => {
      h.requests.length = 0;
      let error = '';
      try {
        document.dispatchEvent({type, target: elementFrom(attrs), preventDefault() {},
          dataTransfer: {getData: () => '', setData() {}}});
      } catch (e) {
        error = String((e && e.message) || e);
      }
      await globalThis.__settle(5);
      tried.push({type, attrs, error,
        sent: h.requests.filter(r => r.method && r.method !== 'GET').map(r => r.method + ' ' + r.url)});
    };
    await attempt('mouseenter', {'data-action-mouseenter': 'projectHide', 'data-arg': '0'});
    await attempt('dragover', {'data-action-dragover': 'projectHide', 'data-arg': '0'});
    await attempt('drop', {'data-action-drop': 'projectHide', 'data-arg': '0'});
    await attempt('dragstart', {'data-action-dragstart': 'projectHide', 'data-arg': '0'});
    await attempt('click', {'data-action': 'kanbanColDrop', 'data-arg': 'done'});
    await attempt('click', {'data-action': 'projectHide', 'data-arg': '0'});
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
