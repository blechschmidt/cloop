// glasses_scenarios.js — drives assets/glasses.html in node against
// glassesdom.js and reports what a wearer would see (Task 20237).
//
// Usage: node glasses_scenarios.js <glassesdom.js> <glasses-script.js>
//
// The two questions every scenario here exists to answer are the two a grep
// cannot: where does focus end up after a gesture, and does the node the
// wearer is looking at survive the minute poll. Both are properties of a live
// tree, so the real page script runs against a real tree.

'use strict';

const path = require('path');
const shimPath = path.resolve(process.argv[2]);
const scriptPath = path.resolve(process.argv[3]);
const { makeDOM } = require(shimPath);

const PROJECTS = [
  { idx: 0, name: 'alpha', status: 'idle', running: false, done: 2, total: 5, failed: 0 },
  { idx: 1, name: 'beta', status: 'running', running: true, done: 1, total: 4, failed: 1 },
  { idx: 2, name: 'gamma', status: 'complete', running: false, done: 3, total: 3, failed: 0 },
];

function mkTasks(n, status) {
  const out = [];
  for (let i = 1; i <= n; i++) {
    out.push({ id: i, title: 'task ' + i, status: status || (i % 2 ? 'pending' : 'done'), priority: 1 });
  }
  return out;
}

// tasksRoute answers like the real endpoint: honour offset and limit, and
// report the unpaged total, so the paging assertions mean something.
function tasksRoute(all, seen) {
  return url => {
    const q = new URLSearchParams(url.split('?')[1] || '');
    const offset = parseInt(q.get('offset') || '0', 10);
    const limit = parseInt(q.get('limit') || '25', 10);
    const status = q.get('status') || '';
    if (seen) { seen.push({ offset, limit, status }); }
    const matched = status ? all.filter(t => status.split(',').indexOf(t.status) >= 0) : all;
    return {
      status: 200,
      body: { tasks: matched.slice(offset, offset + limit), total: matched.length, goal: 'ship it' },
    };
  };
}

function boot(opts) {
  const dom = makeDOM(opts);
  dom.install();
  delete require.cache[scriptPath];
  require(scriptPath);
  return dom;
}

const scenarios = {};

// ── the reported bug ────────────────────────────────────────────────────────
// "Swiping right or left selects the first element once and then does not move
// to the previous element anymore." Walk the ring both ways and record every
// stop; a stuck selection shows up as a repeated name.

scenarios.swipe_right_walks_the_ring = async () => {
  const dom = boot({ routes: { '/api/glasses/projects': { projects: PROJECTS } } });
  await dom.settle();

  const start = dom.focusName();
  const stops = [];
  for (let i = 0; i < 6; i++) { dom.press('ArrowRight'); stops.push(dom.focusName()); }
  return { start, stops, ring: dom.ring() };
};

scenarios.swipe_left_walks_back = async () => {
  const dom = boot({ routes: { '/api/glasses/projects': { projects: PROJECTS } } });
  await dom.settle();

  dom.press('ArrowRight');
  dom.press('ArrowRight');
  const before = dom.focusName();
  const back = [];
  for (let i = 0; i < 4; i++) { dom.press('ArrowLeft'); back.push(dom.focusName()); }
  return { before, back };
};

scenarios.arrow_keys_are_consumed = async () => {
  const dom = boot({ routes: { '/api/glasses/projects': { projects: PROJECTS } } });
  await dom.settle();
  return {
    right: dom.press('ArrowRight').defaultPrevented,
    left: dom.press('ArrowLeft').defaultPrevented,
    // Anything the page does not act on has to keep its default, or the
    // device's own handling is suppressed for no reason.
    other: dom.press('PageDown').defaultPrevented,
  };
};

// ── the scroll axis the wearer asked to keep ────────────────────────────────

scenarios.updown_scrolls_while_the_page_scrolls = async () => {
  const dom = boot({
    routes: { '/api/glasses/projects': { projects: PROJECTS } },
    scrollHeight: 2000, clientHeight: 600,
  });
  await dom.settle();
  const before = dom.focusName();
  const ev = dom.press('ArrowDown');
  return { before, after: dom.focusName(), prevented: ev.defaultPrevented };
};

scenarios.updown_moves_focus_when_nothing_scrolls = async () => {
  const dom = boot({
    routes: { '/api/glasses/projects': { projects: PROJECTS } },
    scrollHeight: 600, clientHeight: 600,
  });
  await dom.settle();
  const before = dom.focusName();
  dom.press('ArrowDown');
  return { before, after: dom.focusName() };
};

// ── activation ──────────────────────────────────────────────────────────────

scenarios.pinch_activates_the_focused_row = async () => {
  const dom = boot({
    routes: {
      '/api/glasses/projects': { projects: PROJECTS },
      '/api/glasses/tasks': tasksRoute(mkTasks(3)),
    },
  });
  await dom.settle();
  const focused = dom.focusName();
  dom.press('Enter');
  await dom.settle();
  return { focused, title: dom.text('title'), rows: dom.rows(), focusAfter: dom.focusName() };
};

scenarios.pinch_recovers_a_lost_cursor = async () => {
  const dom = boot({ routes: { '/api/glasses/projects': { projects: PROJECTS } } });
  await dom.settle();
  dom.doc.activeElement = dom.doc.body;      // nothing focused, as after a cold start
  dom.press('Enter');
  return { after: dom.focusName() };
};

// ── the smooth refresh ──────────────────────────────────────────────────────

scenarios.refresh_keeps_focus_and_nodes = async () => {
  const dom = boot({ routes: { '/api/glasses/projects': { projects: PROJECTS } } });
  await dom.settle();

  dom.press('ArrowRight');                    // land on a row
  dom.press('ArrowRight');
  const focusBefore = dom.focusName();
  const nodesBefore = dom.rowNodes();

  // The same three projects, one of them further along: exactly what a poll a
  // minute later returns.
  const moved = PROJECTS.map(p => (p.name === 'beta' ? Object.assign({}, p, { done: 3 }) : p));
  dom.setRoutes({ '/api/glasses/projects': { projects: moved } });
  dom.tick();
  await dom.settle();

  const nodesAfter = dom.rowNodes();
  return {
    focusBefore,
    focusAfter: dom.focusName(),
    reused: nodesBefore.length === nodesAfter.length &&
      nodesBefore.every((n, i) => n === nodesAfter[i]),
    msg: dom.text('msg'),
    rows: dom.rows(),
    sub: dom.text('sub'),
  };
};

scenarios.refresh_never_blanks_the_list = async () => {
  const dom = boot({ routes: { '/api/glasses/projects': { projects: PROJECTS } } });
  await dom.settle();

  // Watch the list across the whole refresh, not just at the end: the old
  // failure mode emptied it and said "Loading…" for one paint.
  const seen = [];
  const list = dom.doc.getElementById('list');
  const sample = () => seen.push({ rows: list.childNodes.length, msg: dom.text('msg') });

  dom.tick();
  sample();
  for (let i = 0; i < 6; i++) { await Promise.resolve(); sample(); }
  return { seen };
};

scenarios.focus_survives_its_row_disappearing = async () => {
  const dom = boot({ routes: { '/api/glasses/projects': { projects: PROJECTS } } });
  await dom.settle();

  dom.press('ArrowRight');                    // the middle project
  const focusBefore = dom.focusName();

  dom.setRoutes({ '/api/glasses/projects': { projects: PROJECTS.filter(p => p.name !== 'beta') } });
  dom.tick();
  await dom.settle();
  return { focusBefore, focusAfter: dom.focusName(), rows: dom.rows() };
};

scenarios.refresh_keeps_the_paged_window = async () => {
  const seen = [];
  const dom = boot({
    routes: {
      '/api/glasses/projects': { projects: PROJECTS },
      '/api/glasses/tasks': tasksRoute(mkTasks(60), seen),
    },
  });
  await dom.settle();

  dom.press('Enter');                         // the first project already has the cursor
  await dom.settle();
  const afterOpen = dom.rows().length;

  dom.click(dom.doc.getElementById('more'));  // page forward
  await dom.settle();
  const afterMore = dom.rows().length;

  dom.tick();                                 // the poll
  await dom.settle();
  return { afterOpen, afterMore, afterRefresh: dom.rows().length, requests: seen };
};

// ── the ring itself ─────────────────────────────────────────────────────────

scenarios.hidden_controls_are_not_stops = async () => {
  const dom = boot({
    routes: {
      '/api/glasses/projects': { projects: PROJECTS },
      '/api/glasses/tasks': tasksRoute(mkTasks(2)),
    },
  });
  await dom.settle();
  const onProjects = dom.ring();

  dom.press('Enter');
  await dom.settle();
  return { onProjects, onTasks: dom.ring() };
};

scenarios.filter_keeps_the_chip_under_the_cursor = async () => {
  const dom = boot({
    routes: {
      '/api/glasses/projects': { projects: PROJECTS },
      '/api/glasses/tasks': tasksRoute(mkTasks(6)),
    },
  });
  await dom.settle();
  dom.press('Enter');
  await dom.settle();

  // Put the cursor on the "Done" chip and pinch it.
  const chips = dom.doc.getElementById('filters').childNodes;
  chips[2].focus();
  const chipNode = chips[2];
  dom.press('Enter');
  await dom.settle();

  return {
    focusAfter: dom.focusName(),
    sameChipNode: dom.doc.getElementById('filters').childNodes[2] === chipNode,
    rows: dom.rows(),
  };
};

scenarios.detail_refreshes_in_place = async () => {
  const dom = boot({
    routes: {
      '/api/glasses/projects': { projects: PROJECTS },
      '/api/glasses/tasks': tasksRoute(mkTasks(3)),
      '/api/glasses/tasks/1': { id: 1, title: 'task 1', status: 'in_progress', priority: 1, description: 'do it', result: '' },
    },
  });
  await dom.settle();
  dom.press('Enter');
  await dom.settle();                         // tasks list
  dom.press('Enter');                         // first task row already has focus
  await dom.settle();

  const paneBefore = dom.doc.getElementById('list').firstChild;
  const focusBefore = dom.focusName();

  dom.setRoutes({
    '/api/glasses/tasks/1': { id: 1, title: 'task 1', status: 'done', priority: 1, description: 'do it', result: 'shipped' },
  });
  dom.tick();
  await dom.settle();

  const paneAfter = dom.doc.getElementById('list').firstChild;
  return {
    focusBefore,
    focusAfter: dom.focusName(),
    reused: paneBefore === paneAfter,
    sub: dom.text('sub'),
    body: paneAfter ? paneAfter.textContent : '',
  };
};

// ── escaping, now that there is none ────────────────────────────────────────
// Titles used to be concatenated into an HTML string. They are textContent
// now, so a title carrying markup has to appear verbatim and create no nodes.

scenarios.markup_in_a_title_stays_text = async () => {
  const nasty = '<img src=x onerror=alert(1)> & "quoted"';
  const dom = boot({
    routes: { '/api/glasses/projects': { projects: [Object.assign({}, PROJECTS[0], { name: nasty })] } },
  });
  await dom.settle();
  const row = dom.rowNodes()[0];
  return { text: row.textContent, nasty, nodes: row.childNodes.length };
};

// ── run ─────────────────────────────────────────────────────────────────────

(async () => {
  const results = {};
  for (const name of Object.keys(scenarios)) {
    try {
      results[name] = await scenarios[name]();
    } catch (err) {
      results[name] = { error: (err && err.stack) || String(err) };
    }
  }
  process.stdout.write(JSON.stringify(results));
})();
