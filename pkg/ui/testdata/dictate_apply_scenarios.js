// dictate_apply_scenarios.js — drives the real dashboard bundle through what
// happens to a transcript dictated into the edit modal (Task 20302).
//
// The microphone beside the Add Task field has one answer: put the words in the
// box. The one in the edit modal does not, because the box already has words in
// it — "and make sure it works on mobile" and "scrap that, this is really about
// the migration" are the same sound, and one of them destroys a paragraph if
// guessed wrong. So it asks, and these scenarios pin what each answer does.
//
// Run against domshim rather than a headless browser on purpose. Everything
// above openDictateApply is audio — a capture device, a MediaRecorder, a
// gesture — and dictate_ptt_browser.js already drives that in real Chromium.
// Everything below it is what happens to a string, which is where the damage
// lives and which needs no microphone to reach.
//
// Run by TestDashboard_DictatedDetailsAskBeforeOverwriting. Each scenario
// returns a plain object; the Go side asserts on it. Printed as one JSON
// document.
//
// Usage: node dictate_apply_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const EXISTING = 'Cap each read at 1 MiB and log the truncation.';
const HEARD    = 'also cover the glasses page';
const REVISED  = 'Cap each read at 1 MiB, log the truncation, and cover the glasses page.';

// boot loads a fresh copy of the bundle with a one-task plan, opens the edit
// modal on it, and returns the harness.
//
// description is what the Description field starts with — the whole variable
// under test, since an empty one is the case that must not ask.
async function boot(description, reviseRoute, reviseStatus) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;

  // The task lives in project 1, not 0. A scoping mistake — the bug class this
  // dashboard has re-grown eight times — then shows up as an empty plan rather
  // than silently as the right answer.
  h.projects = {multi_project: true, stats: {total_projects: 2}, projects: [
    {name: 'alpha', path: '/srv/alpha', goal: 'a'},
    {name: 'beta', path: '/srv/beta', goal: 'b'},
  ]};
  h.states = {1: {
    goal: 'b', status: 'idle',
    plan: {goal: 'b', tasks: [
      {id: 7, title: 'Bound the artifact reads', description, status: 'pending', priority: 1},
    ]},
  }};
  h.routes['/api/tasks/7/revise'] = reviseRoute || {ok: true, description: REVISED};
  if (reviseStatus) h.routeStatus['/api/tasks/7/revise'] = reviseStatus;
  h.routes['/api/dictate'] = {available: true, can_add_tasks: true, backend: 'groq'};

  require(bundlePath);
  await globalThis.__settle(5);

  // The shim has no stylesheet, so an overlay it has never opened reports an
  // undefined display and reads as open. The markup's own `display:none` is
  // what the page starts from; state it here so isOverlayOpen means something.
  document.getElementById('dr-overlay').style.display = 'none';

  // DOMContentLoaded never fires in the shim, so the reveal that normally runs
  // at load is invoked here. It is also the assertion for scenario 0: a hub
  // that can transcribe must show *both* microphones, not just the first.
  window.initTaskDictation();
  await globalThis.__settle(5);

  // openProject selects the project and drops appState, expecting the new
  // project's first WebSocket frame to refill it. The shim's socket delivers
  // nothing on its own, so the fetch the browser would have raced is made
  // explicitly here.
  window.openProject(1, 'beta');
  await globalThis.__settle(5);
  await window.refreshState();
  await globalThis.__settle(5);

  window.openEditModal(7);
  await globalThis.__settle(2);
  // String(), because the shim stores whatever it is assigned while a real
  // input coerces to text — openEditModal writes the numeric id.
  if (String(document.getElementById('modalTaskId').value) !== '7') {
    throw new Error('the edit modal did not open on task 7 — the rest of this ' +
                    'scenario would assert against an empty form');
  }
  return h;
}

const desc     = () => document.getElementById('modalDesc');
const chooser  = () => !!window.isOverlayOpen('dr-overlay');
const heardBox = () => (document.getElementById('dr-heard').textContent || '');

// revisePosts returns the bodies this run POSTed to the revise endpoint, with
// the URL, so a scenario can assert both what was asked and which project it
// was asked about.
function revisePosts(h) {
  return h.requests
    .filter(r => r.method === 'POST' && r.url.indexOf('/api/tasks/7/revise') === 0)
    .map(r => ({url: r.url, body: r.body}));
}

async function main() {
  const out = {};

  // 0. Both microphones appear when the hub can transcribe. The edit modal's
  //    is useless if it never shows up, and it is revealed by the same probe
  //    as the Add Task one rather than by a second, drifting copy.
  {
    await boot(EXISTING);
    out.both_microphones_revealed = {
      add:  document.getElementById('dictateTaskBtn').style.display !== 'none',
      edit: document.getElementById('dictateEditBtn').style.display !== 'none',
    };
  }

  // 1. The question itself. Words arrive, and nothing has happened to the
  //    details yet — that is the entire point of the feature.
  {
    await boot(EXISTING);
    window.openDictateApply(HEARD);
    await globalThis.__settle(2);
    out.asks_before_overwriting = {
      chooser_open: chooser(),
      details: desc().value,
      heard: heardBox(),
    };
  }

  // 2. Replace. The spoken words become the details.
  {
    await boot(EXISTING);
    window.openDictateApply(HEARD);
    await globalThis.__settle(2);
    window.dictateApplyReplace();
    await globalThis.__settle(2);
    out.replace_overwrites = {chooser_open: chooser(), details: desc().value};
  }

  // 3. Add to the end. The existing paragraph survives, separated by a blank
  //    line rather than run together with the new sentence.
  {
    await boot(EXISTING);
    window.openDictateApply(HEARD);
    await globalThis.__settle(2);
    window.dictateApplyAppend();
    await globalThis.__settle(2);
    out.append_keeps_existing = {chooser_open: chooser(), details: desc().value};
  }

  // 4. Edit with AI. The model's answer lands in the field, and — the part
  //    that makes this different from Replace — what was sent up is the text
  //    in the *editor*, including anything typed since the modal opened.
  {
    const h = await boot(EXISTING);
    const typed = EXISTING + ' TODO: decide the limit.';
    desc().value = typed;
    window.openDictateApply(HEARD);
    await globalThis.__settle(2);
    window.dictateApplyRevise();
    await globalThis.__settle(8);
    out.revise_sends_the_draft = {
      chooser_open: chooser(),
      details: desc().value,
      posts: revisePosts(h),
      typed,
    };
  }

  // 5. An empty Description has one sensible answer, so asking would be a
  //    dialog whose buttons all do the same thing.
  {
    await boot('');
    window.openDictateApply(HEARD);
    await globalThis.__settle(2);
    out.empty_details_do_not_ask = {chooser_open: chooser(), details: desc().value};
  }

  // 6. The model is the only part of this that can fail. When it does, the
  //    chooser stays up — Replace and Add to the end are still right there,
  //    and closing would make the user say the sentence again to reach them.
  {
    await boot(EXISTING, {ok: false, error: 'model is having a day'}, 502);
    window.openDictateApply(HEARD);
    await globalThis.__settle(2);
    window.dictateApplyRevise();
    await globalThis.__settle(8);
    out.revise_failure_keeps_the_chooser = {
      chooser_open: chooser(),
      details: desc().value,
    };
  }

  // 6b. Cancelling while the model is thinking. The reply still arrives — the
  //     request was already in flight — and must be dropped: by the time it
  //     lands the user has dismissed the dialog and may have typed something
  //     else into the field it wants to overwrite.
  {
    await boot(EXISTING);
    window.openDictateApply(HEARD);
    await globalThis.__settle(2);
    window.dictateApplyRevise();
    window.closeDictateApply();          // before the canned reply resolves
    desc().value = EXISTING + ' typed after cancelling';
    await globalThis.__settle(8);
    out.cancelled_revision_is_dropped = {
      chooser_open: chooser(),
      details: desc().value,
    };
  }

  // 7. Dismissing the editor underneath has to take the chooser with it.
  //    A dialog left open over a closed modal answers into a field that is no
  //    longer on screen.
  {
    await boot(EXISTING);
    window.openDictateApply(HEARD);
    await globalThis.__settle(2);
    window.closeModal();
    await globalThis.__settle(2);
    out.closing_the_editor_dismisses_the_chooser = {chooser_open: chooser()};
  }

  process.stdout.write(JSON.stringify(out));
}

main().catch(e => {
  process.stdout.write(JSON.stringify({fatal: {error: String(e && e.stack || e)}}));
  process.exit(1);
});
