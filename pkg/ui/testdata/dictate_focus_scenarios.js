// dictate_focus_scenarios.js — drives the real dashboard bundle through where a
// dictated transcript lands (Task 20309).
//
// Before this, each microphone owned exactly one field: the Add Task one wrote
// into the title, the edit modal's into the description, and every other text
// box on those two screens was unreachable by voice. Now the caret decides. The
// scenarios below pin both halves of that rule, because only one of them is
// obvious:
//
//   * the caret wins when the *user* put it somewhere — the new behaviour;
//   * the button's own field wins when the *page* put it somewhere — which is
//     the state the edit modal opens in, since openOverlay focuses its Title.
//     Miss this and every transcript dictated in that dialog lands in the Title
//     and the chooser that protects the description (Task 20302) is dead code.
//
// Driven end to end through window.toggleTaskDictation rather than through some
// internal seam: domshim ships a one-chunk microphone, so press → record →
// release → POST /api/transcribe → route is all reachable from here, and the
// destination is fixed when the session *starts*, which a seam taking a string
// could not express.
//
// What is deliberately not here: the gesture. Pointer capture, the click a
// browser synthesises after touchend and the empty-clip analyser are real
// browser behaviour — ptt_browser.js drives those in Chromium.
//
// Run by TestDashboard_DictationFollowsTheCaret. Each scenario returns a plain
// object; the Go side asserts on it. Printed as one JSON document.
//
// Usage: node dictate_focus_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const HEARD = 'also cover the glasses page';
const EXISTING = 'Cap each read at 1 MiB and log the truncation.';

// The fields on the two screens under test, with the tag and type the real
// index.html gives them. domshim auto-vivifies elements and cannot know either,
// so a scenario states them — and TestDashboard_DictationFieldsAreDictatable on
// the Go side checks these claims against the actual markup, so a field that
// silently became a number input cannot keep passing here.
const FIELDS = {
  newTaskTitle:    {tagName: 'INPUT', type: 'text'},
  newTaskDesc:     {tagName: 'TEXTAREA', type: ''},
  newTaskPriority: {tagName: 'INPUT', type: 'number'},
  filterQ:         {tagName: 'INPUT', type: 'search'},
  modalTitle_:     {tagName: 'INPUT', type: 'text'},
  modalDesc:       {tagName: 'TEXTAREA', type: ''},
};

// boot loads a fresh copy of the bundle with a one-task plan and returns the
// harness, with the dictation microphones revealed and the fields shaped.
async function boot() {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;

  // Project 1, not 0. A scoping mistake — this dashboard's most re-grown bug
  // class — then shows up as an empty plan rather than as the right answer.
  h.projects = {multi_project: true, stats: {total_projects: 2}, projects: [
    {name: 'alpha', path: '/srv/alpha', goal: 'a'},
    {name: 'beta', path: '/srv/beta', goal: 'b'},
  ]};
  h.states = {1: {
    goal: 'b', status: 'idle',
    plan: {goal: 'b', tasks: [
      {id: 7, title: 'Bound the artifact reads', description: EXISTING, status: 'pending', priority: 1},
    ]},
  }};
  h.routes['/api/dictate'] = {available: true, can_add_tasks: true, backend: 'groq'};
  h.routes['/api/transcribe'] = {text: HEARD};

  require(bundlePath);
  await globalThis.__settle(5);

  for (const id of Object.keys(FIELDS)) {
    Object.assign(document.getElementById(id), FIELDS[id], {value: ''});
  }
  // No stylesheet here, so an overlay never opened reports an undefined display
  // and reads as open. The markup's own display:none is what the page starts
  // from; state it so isOverlayOpen means something.
  document.getElementById('dr-overlay').style.display = 'none';

  // DOMContentLoaded never fires in the shim, so the reveal that normally runs
  // at load is invoked here.
  window.initTaskDictation();
  await globalThis.__settle(5);

  window.openProject(1, 'beta');
  await globalThis.__settle(5);
  await window.refreshState();
  await globalThis.__settle(5);
  return h;
}

const val = id => document.getElementById(id).value;

// dictate performs one complete session on the named microphone: press to
// start, press to stop, then wait for the transcribe round trip and the write
// that follows it. Mirrors what a mouse user does, which is the gesture that
// had to stop stealing the caret for any of this to work.
async function dictate(which) {
  if (which === 'edit') window.toggleEditDictation(); else window.toggleTaskDictation();
  await globalThis.__settle(5);
  if (which === 'edit') window.toggleEditDictation(); else window.toggleTaskDictation();
  await globalThis.__settle(8);
}

// caretIn simulates the user clicking into a field. focus() is what a click
// does, and the shim dispatches the focusin the router listens for.
function caretIn(id) { document.getElementById(id).focus(); }

async function openEditor() {
  window.openEditModal(7);
  await globalThis.__settle(2);
  if (String(document.getElementById('modalTaskId').value) !== '7') {
    throw new Error('the edit modal did not open on task 7 — the rest of this ' +
                    'scenario would assert against an empty form');
  }
}

async function main() {
  const out = {};

  // 1. The Add Task microphone with no caret anywhere. Its own field, exactly
  //    as before Task 20309 — the fallback is most of the behaviour, not an
  //    edge case, because most presses follow no click into a text box.
  {
    await boot();
    await dictate('add');
    out.no_caret_uses_the_button_field = {title: val('newTaskTitle'), desc: val('newTaskDesc')};
  }

  // 2. The caret in the *other* half of the Add Task row. This is the whole
  //    request: the description field was unreachable by voice, and the only
  //    way to fill it was to dictate into the title and retype.
  {
    await boot();
    caretIn('newTaskDesc');
    await dictate('add');
    out.caret_wins = {title: val('newTaskTitle'), desc: val('newTaskDesc')};
  }

  // 3. A field that is not on the Add Task row at all. The filter box is the
  //    one a user is most likely to have the caret in when they reach for the
  //    microphone, and "wherever the caret is" has to mean it.
  {
    await boot();
    caretIn('filterQ');
    await dictate('add');
    out.caret_outside_the_row = {filter: val('filterQ'), title: val('newTaskTitle')};
  }

  // 4. A number input is not a destination. Speech arrives as words, and a
  //    number field discards a value it cannot parse without saying so — the
  //    sentence would vanish with nothing on screen to explain it.
  {
    await boot();
    caretIn('newTaskPriority');
    await dictate('add');
    out.number_field_is_not_a_destination = {
      priority: val('newTaskPriority'),
      title: val('newTaskTitle'),
    };
  }

  // 5. Words join what is already in the field rather than replacing it, and
  //    with a space — a transcript carries no spacing of its own.
  {
    await boot();
    document.getElementById('newTaskDesc').value = 'bound the reads';
    caretIn('newTaskDesc');
    await dictate('add');
    out.appends_with_a_space = {desc: val('newTaskDesc')};
  }

  // 5b. Two sessions in a row extend one field rather than fighting over it:
  //     the write leaves the caret where it finished, which is the caret the
  //     next session reads.
  {
    await boot();
    caretIn('newTaskDesc');
    await dictate('add');
    await dictate('add');
    out.second_session_extends = {desc: val('newTaskDesc'), title: val('newTaskTitle')};
  }

  // 5c. No caret anywhere, but the title remembers a selection from the last
  //     time it had focus — mid-word, where nobody can see it now. The
  //     fallback is what the Add Task microphone always did: append, with a
  //     space, and leave the caret at the end.
  {
    await boot();
    const t = document.getElementById('newTaskTitle');
    t.value = 'Fix the';
    t.selectionStart = t.selectionEnd = 3;
    await dictate('add');
    out.fallback_appends = {title: val('newTaskTitle'), caret: t.selectionStart};
  }

  // 6. The edit modal, untouched. openOverlay focuses its Title on the way in,
  //    and that caret is the page's choice — so the microphone beside the
  //    Description still speaks to the Description, and the chooser Task 20302
  //    built still opens. This is the regression the whole programmatic-focus
  //    distinction exists to prevent.
  {
    await boot();
    await openEditor();
    await dictate('edit');
    out.dialog_focus_does_not_retarget = {
      chooser_open: !!window.isOverlayOpen('dr-overlay'),
      title: val('modalTitle_'),
      heard: (document.getElementById('dr-heard').textContent || ''),
    };
  }

  // 7. The same dialog after the user clicks into the Title. Now the caret is
  //    theirs, the words go there, and the chooser stays shut — the Title is a
  //    one-line field whose whole content is visible, so there is nothing to
  //    ask about.
  {
    await boot();
    await openEditor();
    caretIn('modalTitle_');
    await dictate('edit');
    out.caret_in_the_editor_title = {
      chooser_open: !!window.isOverlayOpen('dr-overlay'),
      title: val('modalTitle_'),
      desc: val('modalDesc'),
    };
  }

  // 7b. The same, but the user presses on the Title the dialog already
  //     focused. No focusin follows a press on the focused element, so only
  //     the press itself can say the caret is now theirs.
  {
    await boot();
    await openEditor();
    document.dispatchEvent({type: 'pointerdown', target: document.getElementById('modalTitle_')});
    await dictate('edit');
    out.press_on_the_focused_title_claims_it = {
      chooser_open: !!window.isOverlayOpen('dr-overlay'),
      title: val('modalTitle_'),
      desc: val('modalDesc'),
    };
  }

  // 8. The caret deliberately back in the Description. Still the chooser: the
  //    question it asks is about the field's contents, not about which button
  //    was pressed, so aiming at it explicitly must not skip the protection.
  {
    await boot();
    await openEditor();
    caretIn('modalDesc');
    await dictate('edit');
    out.caret_in_the_description_still_asks = {
      chooser_open: !!window.isOverlayOpen('dr-overlay'),
      desc: val('modalDesc'),
    };
  }

  // 9. The destination is fixed when the session starts, not when the words
  //    come back. A transcription round trip is seconds long and the page stays
  //    live throughout; resolving late would let a click made while waiting
  //    redirect a sentence already spoken.
  {
    await boot();
    caretIn('newTaskDesc');
    window.toggleTaskDictation();
    await globalThis.__settle(5);
    caretIn('filterQ');              // the user clicks away mid-sentence
    window.toggleTaskDictation();
    await globalThis.__settle(8);
    out.destination_is_fixed_at_start = {desc: val('newTaskDesc'), filter: val('filterQ')};
  }

  // 10. The microphone is released whichever field the words went to. Routing
  //     runs on the same path that stops the tracks, and a live one is the
  //     browser's recording indicator left lit with nothing able to turn it off.
  {
    const h = await boot();
    caretIn('newTaskDesc');
    await dictate('add');
    out.microphone_released = {live: h.micTracks.filter(t => t.live).length};
  }

  process.stdout.write(JSON.stringify(out));
}

main().catch(e => {
  process.stdout.write(JSON.stringify({fatal: {error: String(e && e.stack || e)}}));
  process.exit(1);
});
