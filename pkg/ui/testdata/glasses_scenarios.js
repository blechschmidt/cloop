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
// report the unpaged total, so the paging assertions mean something. extras is
// merged into the body for the capability blocks the real route carries
// alongside the page — dictation and the Add screen's ready-made rows.
function tasksRoute(all, seen, extras) {
  return url => {
    const q = new URLSearchParams(url.split('?')[1] || '');
    const offset = parseInt(q.get('offset') || '0', 10);
    const limit = parseInt(q.get('limit') || '25', 10);
    const status = q.get('status') || '';
    if (seen) { seen.push({ offset, limit, status }); }
    const matched = status ? all.filter(t => status.split(',').indexOf(t.status) >= 0) : all;
    return {
      status: 200,
      body: Object.assign({
        tasks: matched.slice(offset, offset + limit),
        total: matched.length,
        goal: 'ship it',
      }, extras || {}),
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
  const stops = [], painted = [];
  for (let i = 0; i < 6; i++) {
    dom.press('ArrowRight');
    stops.push(dom.focusName());
    painted.push(dom.selName());
  }
  // The painted ring and the document's focus have to agree in a runtime where
  // both work; they diverge only where the runtime refuses one of them.
  return { start, stops, painted, ring: dom.ring() };
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

// ── the channel the device actually speaks ──────────────────────────────────
// Task 20279. Everything above this line presses keys, because that is what the
// page was built to receive — and the telemetry from a real session says the
// device does not send them for a swipe. It sent one gesture in that trail, a
// pinch, as Enter/13. For a sideways swipe it sent nothing the page could see:
// not an arrow, not a legacy spelling, not an unrecognised keyCode, all three of
// which the handler records. The wearer described the same gap from outside —
// sideways gestures moved a scrollbar, which is a touch pan.
//
// So these drive the page the way the hardware does, with a fingertip.

scenarios.sideways_touch_walks_the_ring = async () => {
  const dom = boot({ routes: { '/api/glasses/projects': { projects: PROJECTS } } });
  await dom.settle();

  const start = dom.selName();
  const stops = [];
  for (let i = 0; i < 4; i++) { dom.swipe(-120, 0); stops.push(dom.selName()); }
  // And back the way they came: "cannot reach the previous element" was half
  // the report, and a ring that only walks one way still fails it.
  const back = [];
  for (let i = 0; i < 2; i++) { dom.swipe(120, 0); back.push(dom.selName()); }
  return { start, stops, back, ring: dom.ring() };
};

scenarios.vertical_touch_is_left_for_reading = async () => {
  const dom = boot({ routes: { '/api/glasses/projects': { projects: PROJECTS } } });
  await dom.settle();
  dom.layout(80, 0, 240);             // a column taller than the display
  const before = dom.selName();
  const ev = dom.swipe(0, -200);
  // Untouched selection and an unprevented event: the page hands the vertical
  // axis back to the browser so it can scroll, which is what the wearer asked
  // to keep.
  return { before, after: dom.selName(), prevented: ev.defaultPrevented };
};

scenarios.a_tap_is_not_a_swipe = async () => {
  const dom = boot({ routes: { '/api/glasses/projects': { projects: PROJECTS } } });
  await dom.settle();
  const before = dom.selName();
  // A fingertip never lands perfectly still. A few pixels of drift is someone
  // pressing the control under it, and reading that as a swipe would move the
  // cursor out from under the press.
  const ev = dom.swipe(6, 3);
  return { before, after: dom.selName(), prevented: ev.defaultPrevented };
};

scenarios.sideways_touch_is_consumed = async () => {
  const dom = boot({ routes: { '/api/glasses/projects': { projects: PROJECTS } } });
  await dom.settle();
  // The click a browser synthesises after a touch is the hazard here: a swipe
  // that ends over a row would otherwise open that row, so the wearer asks for
  // the next item and lands two screens away.
  return { prevented: dom.swipe(-120, 0).defaultPrevented };
};

// The other half of the same trail, and the more literal one. That session's
// last recorded gesture is `go → -1` on a ring of 6: the wearer had opened a
// project, the view had switched, and while the task list was in flight the
// page offered six reachable controls and had selected none of them. On a
// device that aims its key events at document.activeElement, an unanchored page
// is one with nowhere to deliver the next gesture.
scenarios.navigation_never_leaves_the_ring_unanchored = async () => {
  const dom = boot({
    routes: {
      '/api/glasses/projects': { projects: PROJECTS },
      '/api/glasses/tasks': tasksRoute(mkTasks(4)),
    },
  });
  await dom.settle();

  const before = dom.selName();
  dom.press('Enter');                  // open the selected project

  // Deliberately not settled. This is the instant the trail captured: the view
  // has switched and cleared its list, and the request has not come back.
  //
  // anchorScrolls is the guard on the cure. reanchor() also runs on the minute
  // poll, and the control it lands on lives in the header: if that selection
  // scrolled, a wearer part way down a long task result would be pulled back to
  // the top once a minute by a cursor move they never asked for.
  const anchored = dom.focused();
  const during = {
    sel: dom.selName(), focus: dom.focusName(), ring: dom.ring().length,
    anchorScrolls: anchored ? anchored.scrollIntoViewCalls : -1,
  };

  await dom.settle();
  return { before, during, after: dom.selName() };
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

// ── the runtime the page cannot be tested against ───────────────────────────
// Task 20242. The previous fix walked the ring in a desktop browser and did
// nothing whatsoever on the hardware, and the report contained the tell: a
// sideways swipe scrolled the tasks page sideways. A handler that runs calls
// preventDefault, and a prevented arrow key cannot scroll — so the handler was
// never matching the events the device sends. These scenarios send what a
// runtime that synthesises key events from gestures plausibly sends instead,
// and take away the two facilities the page used to lean on.

const SPELLINGS = {
  modern: { next: { key: 'ArrowRight' }, prev: { key: 'ArrowLeft' } },
  // The IE-era names, still emitted by embedded and TV engines.
  legacy: { next: { key: 'Right' }, prev: { key: 'Left' } },
  // No usable name at all, which is what a synthesised event often carries.
  keycode_only: { next: { key: 'Unidentified', keyCode: 39 }, prev: { key: 'Unidentified', keyCode: 37 } },
  // The physical key without the logical one.
  code_only: { next: { code: 'ArrowRight' }, prev: { code: 'ArrowLeft' } },
};

scenarios.every_spelling_of_a_swipe_steers = async () => {
  const out = {};
  for (const name of Object.keys(SPELLINGS)) {
    const dom = boot({ routes: { '/api/glasses/projects': { projects: PROJECTS } } });
    await dom.settle();
    const forward = [];
    for (let i = 0; i < 3; i++) { dom.press(SPELLINGS[name].next); forward.push(dom.cursorName()); }
    const ev = dom.press(SPELLINGS[name].prev);
    out[name] = { forward, back: dom.cursorName(), prevented: ev.defaultPrevented };
  }
  return out;
};

// The keyCode fallback must not be a net that catches ordinary typing: a page
// that swallowed every key would break the phone the glasses tether through.
scenarios.an_ordinary_key_is_left_alone = async () => {
  const dom = boot({ routes: { '/api/glasses/projects': { projects: PROJECTS } } });
  await dom.settle();
  const before = dom.cursorName();
  const ev = dom.press({ key: 'a', keyCode: 65 });
  return { before, after: dom.cursorName(), prevented: ev.defaultPrevented };
};

// A runtime that will not focus a <button> makes document.activeElement useless
// as a cursor: reading it back gives "nothing" every time, the ring restarts
// from the first control on every swipe, and the wearer sees exactly what was
// reported — the first item selected once, then nothing.
scenarios.cursor_survives_a_runtime_that_will_not_focus = async () => {
  const dom = boot({ focus: 'dead', routes: {
    '/api/glasses/projects': { projects: PROJECTS },
    '/api/glasses/tasks': tasksRoute(mkTasks(2)),
  } });
  await dom.settle();
  const stops = [];
  for (let i = 0; i < 2; i++) { dom.press('ArrowRight'); stops.push(dom.selName()); }
  dom.press('Enter');                       // must activate what is painted
  await dom.settle();
  return { stops, focus: dom.focusName(), title: dom.text('title') };
};

// ...and a runtime that has its own opinion about where the cursor belongs and
// re-aims focus after every gesture. The page must keep steering, and a pinch
// must activate what the wearer can see rather than what the engine grabbed.
scenarios.cursor_survives_a_runtime_that_reclaims_focus = async () => {
  const dom = boot({ focus: 'hijack', routes: {
    '/api/glasses/projects': { projects: PROJECTS },
    '/api/glasses/tasks': tasksRoute(mkTasks(2)),
  } });
  await dom.settle();
  const stops = [];
  for (let i = 0; i < 2; i++) { dom.press('ArrowRight'); stops.push(dom.selName()); }
  dom.press('Enter');
  await dom.settle();
  return { stops, focus: dom.focusName(), title: dom.text('title') };
};

// The handler is a capture listener so nothing downstream can consume the
// gesture first. A bubble-phase handler on the document would never run here.
scenarios.a_swallowed_event_still_steers = async () => {
  const dom = boot({ routes: { '/api/glasses/projects': { projects: PROJECTS } } });
  await dom.settle();
  dom.rowNodes()[0].addEventListener('keydown', ev => ev.stopPropagation(), false);
  const before = dom.cursorName();
  dom.press('ArrowRight');
  return { before, after: dom.cursorName() };
};

// The "after a vertical scroll" half of the report. Up and down move the page
// and deliberately not the cursor, so the two drift apart; the next sideways
// swipe has to continue from what the wearer is looking at rather than drag the
// column back to a row that left the screen several gestures ago.
scenarios.swipe_after_a_scroll_lands_on_screen = async () => {
  const many = [];
  for (let i = 0; i < 10; i++) {
    many.push({ idx: i, name: 'proj-' + i, status: 'idle', running: false, done: i, total: i + 2, failed: 0 });
  }
  const dom = boot({ routes: { '/api/glasses/projects': { projects: many } } });
  await dom.settle();

  const start = dom.cursorName();
  // 150px rows in a 600px viewport, scrolled 700px down: the cursor's row and
  // everything above it is now off the top.
  const placed = dom.layout(150, 700, 600);
  dom.press('ArrowRight');

  return {
    start,
    landed: dom.cursorName(),
    visible: placed.filter(p => p.visible).map(p => p.name),
    // The one directly after the cursor, which is where a naive step would go
    // and which is nowhere near the screen.
    naiveStep: placed[2].name,
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
  // Take the cursor's row out from under it and leave nothing focused — the
  // one state where the page genuinely has no selection. A pinch here has to
  // hand one back rather than be dropped: it is the only key the wearer has.
  const list = dom.doc.getElementById('list');
  list.childNodes.slice().forEach(n => list.removeChild(n));
  dom.doc.activeElement = dom.doc.body;
  dom.press('Enter');
  return { after: dom.focusName(), painted: dom.selName() };
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

  // Swipe to the "Done" chip the way a wearer reaches it. Deliberately not
  // chip.focus(): focus is not the cursor any more, so calling it would test a
  // path no gesture can produce.
  const chipNode = dom.doc.getElementById('filters').childNodes[2];
  let reached = false;
  for (let i = 0; i < 20 && !reached; i++) {
    dom.press('ArrowRight');
    reached = dom.cursorName() === 'f:done';
  }
  dom.press('Enter');
  await dom.settle();

  return {
    reached,
    focusAfter: dom.cursorName(),
    // Activating a filter rewrites the class attribute of every chip, which is
    // the one routine way the cursor marker can be scrubbed off the node the
    // wearer is looking at.
    paintedAfter: dom.selName(),
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

// ── executor attribution on the detail pane (Task 20244) ────────────────────
// The wearer has to be able to see where a task ran, and a host run has to be
// distinguishable from a sandboxed one. The block is built inside the same
// reuse branch as Description and Result, so this also re-checks that adding
// it did not turn the refresh back into a rebuild.

scenarios.detail_shows_executor = async () => {
  const detail = (extra) => Object.assign({
    id: 1, title: 'task 1', status: 'done', priority: 1,
    description: 'do it', result: 'shipped',
  }, extra);

  const dom = boot({
    routes: {
      '/api/glasses/projects': { projects: PROJECTS },
      '/api/glasses/tasks': tasksRoute(mkTasks(3)),
      '/api/glasses/tasks/1': detail({ executor: 'docker-1 — container', on_host: false }),
    },
  });
  await dom.settle();
  dom.press('Enter');
  await dom.settle();
  dom.press('Enter');
  await dom.settle();

  // The shim's selector engine matches a single class, so `.host` rather than
  // `.detail .block.host`. Only the executor block ever carries it.
  const hostBlocks = () => dom.doc.querySelectorAll('.host').length;

  const paneBefore = dom.doc.getElementById('list').firstChild;
  const sandboxed = paneBefore ? paneBefore.textContent : '';
  const sandboxedHost = hostBlocks() > 0;

  // The same task, re-reported as a host run.
  dom.setRoutes({
    '/api/glasses/tasks/1': detail({ executor: '⚠ HOST — local (no sandbox)', on_host: true }),
  });
  dom.tick();
  await dom.settle();

  const paneAfter = dom.doc.getElementById('list').firstChild;
  const hostText = paneAfter ? paneAfter.textContent : '';
  const hostFlagged = hostBlocks() > 0;

  // And a task with no attribution: the block must hide rather than render an
  // empty, reassuring row.
  dom.setRoutes({
    '/api/glasses/tasks/1': detail({ executor: '', on_host: false }),
  });
  dom.tick();
  await dom.settle();

  const unattributedHidden = dom.doc.querySelectorAll('.block')
    .some((b) => b.textContent.indexOf('Executor') === 0 && b.hidden === true);

  return {
    sandboxed,
    sandboxedHost,
    hostText,
    hostFlagged,
    reused: paneBefore === paneAfter,
    unattributedHidden,
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

// ── adding a task (Tasks 20238, 20243) ──────────────────────────────────────
// The device cannot record: Meta lists camera, microphone and getUserMedia as
// unsupported for Ray-Ban Display web apps. Dictation therefore only works when
// the same link is opened on the paired phone — which is why the way in is a
// button that is always there (Task 20243) rather than a microphone control
// that hides itself, and why the screen behind it also offers ready-made rows.
//
// The scenarios that matter are: the button is reachable on the device that
// cannot record; the screen behind it offers something there; and the whole
// circuit, both ways in, ends with exactly one task posted.

const DICTATION_ON = { available: true, can_add_tasks: true, backend: 'groq' };

// What /api/glasses/tasks sends as the Add screen's rows. Shaped like the real
// response: repairs naming a specific failure first, then the standing set.
const QUICK = [
  { title: 'Fix the failure in task #2: task 2', description: 'Task #2 ("task 2") ended as failed. Read its recorded result…' },
  { title: 'Review the recent changes and fix any bugs found', description: 'Go over the work committed most recently…' },
  { title: 'Add tests for the code that changed most recently', description: 'Identify the packages touched…' },
];

// The real /api/glasses/tasks carries the dictation status too, and it is the
// authoritative copy — the project list's is resolved against the default
// project. A fixture that omitted it would leave the refresh path untested.
// quick rides on the same response, and the server sends none of it to a link
// that may not add tasks, so the fixture does not either.
function tasksRouteWithDictation(all, dictation, quick) {
  return tasksRoute(all, null, {
    dictation: dictation,
    quick: quick || (dictation.can_add_tasks ? QUICK : []),
  });
}

function dictationRoutes(dictation, extra, quick) {
  const routes = {
    '/api/glasses/projects': { projects: PROJECTS, dictation: dictation },
    '/api/glasses/tasks': tasksRouteWithDictation(mkTasks(3), dictation, quick),
  };
  return Object.assign(routes, extra || {});
}

// openAlpha walks from the project list into a project, which is the only
// screen where adding is offered — a task needs somewhere to belong.
async function openAlpha(dom) {
  await dom.settle();
  dom.click(dom.doc.getElementById('list').childNodes[0]);
  await dom.settle();
}

// openAddScreen goes one further, through the button this task added.
async function openAddScreen(dom) {
  await openAlpha(dom);
  dom.click(dom.doc.getElementById('add'));
  await dom.settle();
}

// ── the reported gap (Task 20243) ───────────────────────────────────────────
// "I don't see any button to add tasks." The device that cannot record is the
// one that must still show the way in, so this is the no-microphone runtime.

scenarios.add_button_offered_without_a_microphone = async () => {
  const dom = boot({ routes: dictationRoutes(DICTATION_ON) });
  await openAlpha(dom);
  const onTasks = dom.ring();
  dom.click(dom.doc.getElementById('add'));
  await dom.settle();
  return {
    onTasks: onTasks,
    title: dom.text('title'),
    rows: dom.rows(),
    rowText: dom.rowNodes().map(n => n.textContent),
    note: dom.text('micnote'),
    ring: dom.ring(),
    cursor: dom.cursorName(),
  };
};

// ...and with one, where speech is the better option and should be where the
// cursor lands.
scenarios.add_screen_leads_with_speech_when_possible = async () => {
  const dom = boot({ mic: true, routes: dictationRoutes(DICTATION_ON) });
  await openAddScreen(dom);
  return { ring: dom.ring(), cursor: dom.cursorName(), note: dom.text('micnote'), rows: dom.rows() };
};

// A read-only link must not draw the button at all — every row behind it would
// be refused.
scenarios.add_button_absent_for_a_read_only_link = async () => {
  const dom = boot({ mic: true, routes: dictationRoutes({ available: true, can_add_tasks: false }) });
  await openAlpha(dom);
  return { ring: dom.ring(), note: dom.text('micnote') };
};

// A hub with no speech backend still has to offer the button: the ready-made
// rows behind it do not need one.
scenarios.add_button_survives_a_hub_with_no_speech = async () => {
  const dom = boot({ mic: true, routes: dictationRoutes({ available: false, can_add_tasks: true }) });
  await openAlpha(dom);
  const onTasks = dom.ring();
  dom.click(dom.doc.getElementById('add'));
  await dom.settle();
  return { onTasks: onTasks, ring: dom.ring(), note: dom.text('micnote'), rows: dom.rows() };
};

// The second way in, end to end: pinch a ready-made row, confirm, task posted —
// with the brief the row carries, which never appears on screen.
scenarios.add_ready_made_task_round_trip = async () => {
  const dom = boot({ routes: dictationRoutes(DICTATION_ON) });
  await openAddScreen(dom);

  const first = dom.rowNodes()[0];
  dom.click(first);
  await dom.settle();
  const confirmRows = dom.rows();
  const shown = dom.text('list');
  const cursorOnConfirm = dom.cursorName();   // before the pinch navigates away

  const go = dom.rowNodes().filter(n => n.dataset.act === 'confirm')[0];
  if (go) { dom.click(go); }
  await dom.settle();

  const posts = dom.sent.filter(s => s.method === 'POST');
  return {
    confirmRows: confirmRows,
    shown: shown,
    cursorOnConfirm: cursorOnConfirm,
    posted: posts.map(p => ({ url: p.url.split('?')[0], body: p.body })),
    view: dom.text('title'),
  };
};

// Backing out of a ready-made row returns to the Add screen, not the task
// list: the next thing a wearer wants after rejecting one is another one.
scenarios.add_discard_returns_to_the_add_screen = async () => {
  const dom = boot({ routes: dictationRoutes(DICTATION_ON) });
  await openAddScreen(dom);
  dom.click(dom.rowNodes()[0]);
  await dom.settle();

  const discard = dom.rowNodes().filter(n => n.dataset.act === 'discard')[0];
  if (discard) { dom.click(discard); }
  await dom.settle();

  const posts = dom.sent.filter(s => s.method === 'POST');
  return { title: dom.text('title'), rows: dom.rows(), posts: posts.length };
};

// Two of the rows name a failure by id, so the button must not appear until
// *this* project's rows have arrived. Offering the previous project's — the
// gap between pinching a project and its task list landing — would file work
// against the wrong plan, which is this dashboard's oldest bug class.
scenarios.add_button_waits_for_this_projects_rows = async () => {
  const BETA_QUICK = [{ title: 'Fix the failure in task #9: beta only', description: 'beta brief' }];
  const perProject = url => {
    const idx = new URLSearchParams(url.split('?')[1] || '').get('project_idx');
    return tasksRouteWithDictation(mkTasks(2), DICTATION_ON, idx === '1' ? BETA_QUICK : QUICK)(url);
  };
  const dom = boot({ routes: {
    '/api/glasses/projects': { projects: PROJECTS, dictation: DICTATION_ON },
    '/api/glasses/tasks': perProject,
  } });
  await dom.settle();

  const open = async (n) => {
    dom.click(dom.doc.getElementById('list').childNodes[n]);
    const during = dom.ring();          // the response has not landed yet
    await dom.settle();
    dom.click(dom.doc.getElementById('add'));
    await dom.settle();
    return { during: during, rows: dom.rowNodes().map(r => r.textContent) };
  };

  const alpha = await open(0);
  dom.click(dom.doc.getElementById('back'));   // back to alpha's task list
  await dom.settle();
  dom.click(dom.doc.getElementById('back'));   // back to the project list
  await dom.settle();
  const beta = await open(1);

  return { alpha: alpha, beta: beta };
};

// The Add screen does not poll. A refresh that rebuilt it would move the cursor
// out from under a wearer part way through a decision.
scenarios.add_screen_does_not_poll = async () => {
  const dom = boot({ routes: dictationRoutes(DICTATION_ON) });
  await openAddScreen(dom);
  const before = dom.calls.length;
  dom.tick();
  await dom.settle();
  return { before: before, after: dom.calls.length, rows: dom.rows(), cursor: dom.cursorName() };
};

// ── dictation (Task 20238) ──────────────────────────────────────────────────

scenarios.dictate_offered_when_a_microphone_exists = async () => {
  const dom = boot({ mic: true, routes: dictationRoutes(DICTATION_ON) });
  await openAddScreen(dom);
  return { ring: dom.ring(), note: dom.text('micnote'), label: dom.text('dictate') };
};

// The glasses case: no getUserMedia anywhere in the runtime.
scenarios.dictate_explains_when_no_microphone = async () => {
  const dom = boot({ routes: dictationRoutes(DICTATION_ON) });
  await openAddScreen(dom);
  return { ring: dom.ring(), note: dom.text('micnote') };
};

// A read-only link must not draw the control at all — it would be refused.
// The button that opens this screen is gone too, so reach it the only other
// way there is and confirm nothing is offered.
scenarios.dictate_absent_for_a_read_only_link = async () => {
  const dom = boot({ mic: true, routes: dictationRoutes({ available: true, can_add_tasks: false }) });
  await openAlpha(dom);
  return { ring: dom.ring(), note: dom.text('micnote') };
};

// And absent when the hub has no speech backend configured at all.
scenarios.dictate_absent_when_hub_has_no_backend = async () => {
  const dom = boot({ mic: true, routes: dictationRoutes({ available: false, can_add_tasks: true }) });
  await openAddScreen(dom);
  return { ring: dom.ring(), note: dom.text('micnote') };
};

// The whole circuit: pinch to record, pinch to stop, confirm, task created.
scenarios.dictate_round_trip_creates_a_task = async () => {
  const dom = boot({
    mic: true,
    routes: dictationRoutes(DICTATION_ON, {
      '/api/glasses/transcribe': { text: 'add a retention policy' },
    }),
  });
  await openAddScreen(dom);

  const before = dom.text('dictate');
  dom.click(dom.doc.getElementById('dictate'));      // start recording
  await dom.settle();
  const recording = dom.text('dictate');

  dom.click(dom.doc.getElementById('dictate'));      // stop -> upload
  await dom.settle();

  const confirmRows = dom.rows();
  const heard = dom.text('list');
  const focusOnConfirm = dom.focusName();

  // Pinch "Add task".
  const add = dom.rowNodes().filter(n => n.dataset.act === 'confirm')[0];
  if (add) { dom.click(add); }
  await dom.settle();

  const posts = dom.sent.filter(s => s.method === 'POST');
  return {
    before: before,
    recording: recording,
    confirmRows: confirmRows,
    heard: heard,
    focusOnConfirm: focusOnConfirm,
    micReleased: dom.mic.stopped,
    posted: posts.map(p => ({ url: p.url.split('?')[0], body: typeof p.body === 'string' ? p.body : 'form' })),
  };
};

// Discarding must drop the transcript rather than keep offering it, and land
// back where the wearer started it.
scenarios.dictate_discard_returns_to_the_add_screen = async () => {
  const dom = boot({
    mic: true,
    routes: dictationRoutes(DICTATION_ON, { '/api/glasses/transcribe': { text: 'never mind' } }),
  });
  await openAddScreen(dom);
  dom.click(dom.doc.getElementById('dictate'));
  await dom.settle();
  dom.click(dom.doc.getElementById('dictate'));
  await dom.settle();

  const discard = dom.rowNodes().filter(n => n.dataset.act === 'discard')[0];
  if (discard) { dom.click(discard); }
  await dom.settle();

  const posts = dom.sent.filter(s => s.method === 'POST' && s.url.indexOf('/tasks') >= 0);
  return { title: dom.text('title'), rows: dom.rows(), taskPosts: posts.length, ring: dom.ring() };
};

// Navigating away mid-recording must release the microphone, and must not
// leave mic.rec set behind a button relabelled "Speak a new task" — the next
// pinch would otherwise upload the walk through the menus.
scenarios.dictate_navigating_away_releases_the_mic = async () => {
  const dom = boot({ mic: true, routes: dictationRoutes(DICTATION_ON) });
  await openAddScreen(dom);

  dom.click(dom.doc.getElementById('dictate'));   // start recording
  await dom.settle();
  const recorderBefore = dom.recorder();

  // Back out to the task list while still recording.
  dom.click(dom.doc.getElementById('back'));
  await dom.settle();

  const posts = dom.sent.filter(s => s.method === 'POST');
  return {
    micReleased: dom.mic.stopped,
    recorderState: recorderBefore ? recorderBefore.state : 'none',
    label: dom.text('dictate'),
    uploads: posts.length,
  };
};

// Two quick pinches must not start two recorders.
scenarios.dictate_double_press_starts_one_recorder = async () => {
  const dom = boot({ mic: true, routes: dictationRoutes(DICTATION_ON) });
  await openAddScreen(dom);
  dom.click(dom.doc.getElementById('dictate'));
  dom.click(dom.doc.getElementById('dictate'));   // before getUserMedia resolves
  await dom.settle();
  return { starts: dom.micStarts(), label: dom.text('dictate') };
};

// A transcript that lands after the wearer navigated away must be dropped, not
// painted over whatever they are now looking at.
scenarios.dictate_stale_transcript_is_dropped = async () => {
  const dom = boot({
    mic: true,
    routes: dictationRoutes(DICTATION_ON, { '/api/glasses/transcribe': { text: 'too late' } }),
  });
  await openAddScreen(dom);
  dom.click(dom.doc.getElementById('dictate'));
  await dom.settle();
  dom.click(dom.doc.getElementById('dictate'));   // stop -> upload in flight
  dom.click(dom.doc.getElementById('back'));      // leave before it resolves
  await dom.settle();
  return { view: dom.text('title'), rows: dom.rows() };
};

// The minute poll must not repaint a control that is mid-recording.
scenarios.dictate_poll_does_not_disturb_recording = async () => {
  const dom = boot({ mic: true, routes: dictationRoutes(DICTATION_ON) });
  await openAddScreen(dom);
  dom.click(dom.doc.getElementById('dictate'));
  await dom.settle();
  const during = dom.text('dictate');
  const classDuring = dom.doc.getElementById('dictate').className;

  dom.tick();                 // the once-a-minute refresh
  await dom.settle();

  return {
    labelBefore: during,
    labelAfter: dom.text('dictate'),
    recBefore: classDuring.indexOf('rec') >= 0,
    recAfter: dom.doc.getElementById('dictate').className.indexOf('rec') >= 0,
  };
};

// Saying nothing must not produce a task. Whisper answers an empty clip with a
// stock phrase ("Thank you."), and no field in the response distinguishes it —
// so the page has to notice before it uploads.
scenarios.dictate_silence_is_not_uploaded = async () => {
  const dom = boot({
    mic: true, audio: 'silent',
    routes: dictationRoutes(DICTATION_ON, { '/api/glasses/transcribe': { text: 'Thank you.' } }),
  });
  await openAddScreen(dom);
  dom.click(dom.doc.getElementById('dictate'));
  await dom.settle();
  dom.tick();                       // let the level poll observe the silence
  await dom.settle();
  dom.click(dom.doc.getElementById('dictate'));   // stop
  await dom.settle();

  const posts = dom.sent.filter(s => s.method === 'POST');
  return { uploads: posts.length, msg: dom.text('msg'), label: dom.text('dictate') };
};

// ...and actual sound must still go through, so the guard is not just "never
// upload anything".
scenarios.dictate_sound_is_uploaded = async () => {
  const dom = boot({
    mic: true, audio: 'sound',
    routes: dictationRoutes(DICTATION_ON, { '/api/glasses/transcribe': { text: 'real words' } }),
  });
  await openAddScreen(dom);
  dom.click(dom.doc.getElementById('dictate'));
  await dom.settle();
  dom.tick();
  await dom.settle();
  dom.click(dom.doc.getElementById('dictate'));
  await dom.settle();

  const posts = dom.sent.filter(s => s.method === 'POST');
  return { uploads: posts.length, rows: dom.rows() };
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
