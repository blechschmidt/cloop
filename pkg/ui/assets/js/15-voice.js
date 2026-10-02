// ── Voice / STT ───────────────────────────────────────────────────────────────

let voiceMediaRecorder = null;
let voiceChunks = [];
let voiceRecording = false;
let voiceBlob = null;

window.openVoiceModal = function() {
  document.getElementById('voiceStatus').textContent = 'Click Record to start recording...';
  document.getElementById('voiceTranscript').textContent = 'Transcription will appear here';
  document.getElementById('voiceTranscript').style.color = 'var(--muted)';
  document.getElementById('voiceOutput').style.display = 'none';
  document.getElementById('voiceOutput').textContent = '';
  document.getElementById('voiceSendBtn').disabled = true;
  voiceBlob = null; voiceChunks = [];
  // Opened last, so the initial focus lands on a button whose state the lines
  // above have already settled.
  openOverlay('voiceModalBackdrop', {dismiss: closeVoiceModal});
};

window.closeVoiceModal = function() {
  if (voiceRecording) stopVoiceRecording();
  closeOverlay('voiceModalBackdrop');
};

window.toggleVoiceRecording = async function() {
  if (voiceRecording) { stopVoiceRecording(); return; }

  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    voiceChunks = [];
    voiceBlob = null;
    document.getElementById('voiceSendBtn').disabled = true;
    document.getElementById('voiceOutput').style.display = 'none';

    // Prefer webm/opus; fallback to whatever the browser supports.
    const mimeType = MediaRecorder.isTypeSupported('audio/webm;codecs=opus')
      ? 'audio/webm;codecs=opus'
      : (MediaRecorder.isTypeSupported('audio/ogg') ? 'audio/ogg' : '');
    const options = mimeType ? { mimeType } : {};
    voiceMediaRecorder = new MediaRecorder(stream, options);

    voiceMediaRecorder.ondataavailable = e => { if (e.data.size > 0) voiceChunks.push(e.data); };
    voiceMediaRecorder.onstop = () => {
      stream.getTracks().forEach(t => t.stop());
      const ext = (voiceMediaRecorder.mimeType || '').includes('ogg') ? 'ogg' : 'webm';
      voiceBlob = new Blob(voiceChunks, { type: voiceMediaRecorder.mimeType || 'audio/webm' });
      voiceBlob._ext = ext;
      document.getElementById('voiceStatus').textContent = 'Recorded ' + (voiceBlob.size/1024).toFixed(1) + ' KB. Click Execute to transcribe and run.';
      document.getElementById('voiceSendBtn').disabled = false;
      document.getElementById('voiceRecordBtn').classList.remove('recording');
      document.getElementById('voiceRecordBtn').innerHTML = '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M5 3a3 3 0 0 1 6 0v5a3 3 0 0 1-6 0V3z"/></svg> Record';
      voiceRecording = false;
    };

    voiceMediaRecorder.start(200);
    voiceRecording = true;
    document.getElementById('voiceStatus').textContent = 'Recording... click Stop to finish.';
    document.getElementById('voiceRecordBtn').classList.add('recording');
    document.getElementById('voiceRecordBtn').innerHTML = '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0zM5.5 5.5h5v5h-5z"/></svg> Stop';
  } catch (err) {
    document.getElementById('voiceStatus').textContent = 'Microphone error: ' + err.message;
  }
};

function stopVoiceRecording() {
  if (voiceMediaRecorder && voiceMediaRecorder.state !== 'inactive') voiceMediaRecorder.stop();
  voiceRecording = false;
}

// ── Dictate a task (Task 20238) ───────────────────────────────────────────────
//
// Separate from the voice modal above, and deliberately much smaller. That one
// records a *command* — it uploads to /api/voice, which shells out to `cloop
// listen`, asks a model to classify the sentence into one of a dozen intents,
// and executes the result. This one records a *task title*: it posts to
// /api/transcribe, which transcribes and stops, and drops the words into the
// field the user is already looking at.
//
// The transcript is not submitted automatically. Speech recognition is good,
// not perfect, and the difference between a wrong word here and a wrong word
// in a chat message is that this one becomes a row in someone's plan. The
// field is inches away, so review costs a glance.
//
// Two buttons, one recorder (Task 20302). The second lives in the edit modal
// and speaks into a field that already has words in it, which is the whole
// difference between them: see openDictateApply below.
//
// Each button has a field it belongs to, but neither is nailed to it any more
// (Task 20309): if the caret is in a text field when the microphone is pressed,
// that is where the words go. See dictateDestination.

let dictateRecorder = null;
let dictateChunks = [];
let dictateActive = false;
let dictateStarting = false;
let dictateHeardSound = false;
let dictateAudioCtx = null;

// Where this session's words are going, {el, atCaret}: resolved when the
// session starts and consumed when its transcript arrives (Task 20309).
let dictateField = null;

// Push-to-talk state (Task 20252). dictateHeldPointer is the pointerId of the
// finger currently on the button, or null when no hold is in progress — it is
// also what tells the rest of the code whether this session came from a hold
// or from a click, which changes the wording and nothing else.
let dictateHeldPointer = null;
let dictateHoldStart = 0;
let dictateSuppressClick = false;
let dictateAbortPending = false;    // released before the recorder went live
let dictateAbortMsg = '';

// Shorter than this is a stray tap, not a sentence — a fingertip brushing the
// button on the way to the text field beside it. Whisper answers a clip that
// short with a hallucinated stock phrase, so the cost of guessing wrong is a
// bogus task title, not a wasted round trip. No task title is spoken in under
// four tenths of a second.
const DICTATE_MIN_HOLD_MS = 400;

// Whisper does not answer "silence" — handed a clip with nothing in it, it
// confidently returns a stock phrase: "Thank you.", "Thanks for watching!", a
// subtitle credit. Measured against the live endpoint, the metadata that
// should catch this does not: no_speech_prob comes back 0.0000 for digital
// silence and for real speech alike, and avg_logprob differs by less than the
// gap between two real sentences. There is no server-side discriminator.
//
// The browser has the one signal that works — the samples themselves. Watching
// the level while recording means an empty clip is never uploaded at all,
// which also saves the round trip and the API call.
function listenForSound(stream, onSound) {
  const Ctx = window.AudioContext || window.webkitAudioContext;
  if (!Ctx) { onSound(); return; }   // cannot measure: assume speech, do not block
  try {
    dictateAudioCtx = new Ctx();
    const analyser = dictateAudioCtx.createAnalyser();
    analyser.fftSize = 2048;
    dictateAudioCtx.createMediaStreamSource(stream).connect(analyser);
    const buf = new Uint8Array(analyser.fftSize);
    const poll = setInterval(() => {
      if (!dictateAudioCtx) { clearInterval(poll); return; }
      analyser.getByteTimeDomainData(buf);
      for (let i = 0; i < buf.length; i++) {
        // 128 is silence in this encoding; anything meaningfully off it is
        // sound. The threshold is deliberately low — a quiet talker must get
        // through, and the cost of a false positive is one wasted upload.
        if (Math.abs(buf[i] - 128) > 6) { onSound(); clearInterval(poll); return; }
      }
    }, 100);
  } catch (e) { onSound(); }
}

function closeDictateAudioCtx() {
  if (dictateAudioCtx) { try { dictateAudioCtx.close(); } catch (e) {} dictateAudioCtx = null; }
}

const DICTATE_IDLE_ICON = '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M5 3a3 3 0 0 1 6 0v5a3 3 0 0 1-6 0V3z"/><path d="M3.5 6.5A.5.5 0 0 1 4 7v1a4 4 0 0 0 8 0V7a.5.5 0 0 1 1 0v1a5 5 0 0 1-4.5 4.975V15h2a.5.5 0 0 1 0 1h-5a.5.5 0 0 1 0-1h2v-2.025A5 5 0 0 1 3 8V7a.5.5 0 0 1 .5-.5z"/></svg>';
const DICTATE_STOP_ICON = '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M5 5h6v6H5z"/></svg>';

// Which field the microphone is speaking into (Task 20302). One value rather
// than per-button state, because there is one recorder: the two buttons can
// never be pressed at once — the edit modal inerts the page behind it, which
// includes the Add Task row — so "which button is live" is always a single
// answer.
//
//   'add'  → the Add Task title field. The transcript goes straight in.
//   'edit' → the edit modal's Description. The transcript opens a chooser,
//            because overwriting what is already there may not be what the
//            speaker meant.
const DICTATE_TARGETS = {
  add:  {btn: 'dictateTaskBtn', label: 'dictateTaskLabel'},
  edit: {btn: 'dictateEditBtn', label: 'dictateEditLabel'},
};
let dictateTarget = 'add';

function dictateIDs()   { return DICTATE_TARGETS[dictateTarget] || DICTATE_TARGETS.add; }
function dictateBtn()   { return document.getElementById(dictateIDs().btn); }
function dictateLabel() { return document.getElementById(dictateIDs().label); }

// ── Where the words land (Task 20309) ────────────────────────────────────────
//
// The two microphones above each owned a field: the Add Task one wrote into the
// title and nothing else, the edit modal's into the description and nothing
// else. Every other text box on those two screens — the description under the
// Add Task title, the task filter, the Title in the editor — was unreachable by
// voice, and the only way to get words into one was to dictate into the field
// the button did own and then retype them.
//
// So the caret decides. If it is sitting in a text field when the microphone is
// pressed, that is where the transcript goes; the button's own field is what
// happens when it is not. That rule needs two things to be true, and both are
// arranged rather than assumed:
//
//   * The press must not move the caret. A <button> takes focus on mousedown,
//     which would empty the very field the rule reads — see the mousedown
//     handler in bindTaskDictationGestures.
//   * A caret the *page* placed must not count. Opening the edit modal focuses
//     its Title field, so without this every transcript dictated in that dialog
//     would land in the Title whether the speaker aimed there or not, and the
//     chooser that exists to protect the description (Task 20302) would almost
//     never be reached. overlayMovingFocus draws that line.

// The field the user has put the caret in, or null. Maintained from events
// rather than read on demand because by the time anything asks, the answer has
// to include *how* the caret got there, which activeElement cannot say: a
// dialog focusing its own first field (overlayMovingFocus, 00-overlay.js) is
// the page's choice and does not count.
let dictateCaretField = null;

document.addEventListener('focusin', e => {
  dictateCaretField = !overlayMovingFocus && dictateTextField(e.target) ? e.target : null;
}, true);

// Pressing on a field, or typing into one, is the user's choice even when the
// field already had focus — the edit modal's Title has it from the moment the
// dialog opens, so a click into it dispatches no focusin and would otherwise
// leave the caret looking like the page's.
const dictateClaimCaret = e => { if (dictateTextField(e.target)) dictateCaretField = e.target; };
document.addEventListener('pointerdown', dictateClaimCaret, true);
document.addEventListener('input', dictateClaimCaret, true);

// A field whose value is prose. Number and date inputs are deliberately out:
// speech arrives as words — "forty two" — and those inputs discard a value they
// cannot parse without saying so, which would lose the sentence with nothing on
// screen to explain it. Password is out for the obvious reason. So is a field
// on a tab the user has switched away from (no client rects): dictating on the
// Tasks tab must not write into the Overview tab's goal box, off screen.
function dictateTextField(el) {
  const tag = el && !el.disabled && !el.readOnly && el.tagName;
  if (tag !== 'TEXTAREA' && !(tag === 'INPUT' && /^(text|search|url|tel|email)$/.test(el.type))) return false;
  return !el.getClientRects || el.getClientRects().length > 0;
}

// dictateDestination resolves where a session's words go: {el, atCaret}.
//
// The caret is checked against the live activeElement as well as remembered:
// clicking a region that takes no focus drops it to the body without a
// focusin, which would leave a field the user has left looking like the one
// they are in. In the edit modal a caret outside the dialog is stale by
// construction — the page behind it is inert.
function dictateDestination() {
  const el = dictateCaretField, modal = document.getElementById('modal-overlay');
  if (el && el === document.activeElement && dictateTextField(el) &&
      (dictateTarget !== 'edit' || !modal || modal.contains(el))) {
    return {el: el, atCaret: true};
  }
  const own = document.getElementById(dictateTarget === 'edit' ? 'modalDesc' : 'newTaskTitle');
  return own && {el: own, atCaret: false};
}

// insertDictated writes the words in at the caret: with a selection it
// replaces it, and mid-paragraph it does the thing that used to be impossible.
// A field the caret is not in gets what the Add Task title always got — the
// words appended — because a selection the user cannot see is no place for
// them. A transcript carries no spacing of its own, so a space is added on
// either side where the text it lands against has none ("budgetsand").
//
// The input event is for a field with a handler behind it — the task filter
// is one — or the page shows words nothing has reacted to.
function insertDictated(field, text, atCaret) {
  let v = field.value || '', a = v.length, b = a;
  if (!atCaret) { v = v.trim(); a = b = v.length; }
  else if (typeof field.selectionStart === 'number') { a = field.selectionStart; b = field.selectionEnd; }
  const before = v.slice(0, a), after = v.slice(b);
  const head = before + (before && !/\s$/.test(before) ? ' ' : '') + text;
  field.value = head + (after && !/^\s/.test(after) ? ' ' : '') + after;
  try {
    field.focus();
    field.dispatchEvent(new Event('input', {bubbles: true}));
    field.setSelectionRange(head.length, head.length);
  } catch (e) { /* detached, or a type without a selection */ }
}

// What to call the field in the confirmation. Every destination has an
// aria-label or a placeholder; placeholders trail off ("Task title…").
const dictateFieldName = f => String(f.getAttribute('aria-label') || f.placeholder || f.id).replace(/[.…\s]+$/, '');

// A touch press is push-to-talk; a mouse click still toggles (Task 20252).
// This media query only picks the *wording* — the behaviour is decided per
// gesture from pointerType further down — so a hybrid device that guesses
// wrong here is merely mislabelled, never broken.
function dictateTouchPrimary() {
  try { return !!(window.matchMedia && window.matchMedia('(pointer: coarse)').matches); }
  catch (e) { return false; }
}
function dictateIdleLabel() { return dictateTouchPrimary() ? 'Hold to talk' : 'Dictate'; }

// Paint one button. Kept in one place because three call sites (start, stop,
// failure) all have to leave it in a consistent state, and a mic button stuck
// on "Stop" with no recorder behind it is unrecoverable without a reload.
//
// The label span is rebuilt with the id it had, because setting innerHTML
// destroys the previous one — a single hard-coded id would silently move the
// add-task label into the edit modal's button the first time it was painted.
function paintDictate(key, state, text) {
  const ids = DICTATE_TARGETS[key];
  if (!ids) return;
  const btn = document.getElementById(ids.btn);
  if (!btn) return;
  const prev = document.getElementById(ids.label);
  const carry = text || (prev ? prev.textContent : 'Dictate');
  btn.classList.toggle('recording', state === 'recording');
  btn.disabled = (state === 'busy');
  btn.innerHTML = (state === 'recording' ? DICTATE_STOP_ICON : DICTATE_IDLE_ICON) +
                  ' <span id="' + ids.label + '"></span>';
  const fresh = document.getElementById(ids.label);
  if (fresh) fresh.textContent = carry;
}

function setDictateState(state, text) { paintDictate(dictateTarget, state, text); }

// Reveal the button only when the hub can actually transcribe. Called at load,
// and again by the Settings panel when the speech-to-text key changes
// (Task 20250) — which is why it sets visibility both ways rather than only
// revealing: clearing the key has to take the button away again, or it stays on
// screen and fails the next time someone speaks into it.
window.initTaskDictation = function() {
  const keys = Object.keys(DICTATE_TARGETS);
  keys.forEach(k => bindTaskDictationGestures(document.getElementById(DICTATE_TARGETS[k].btn), k));
  const showAll = ok => keys.forEach(k => {
    const btn = document.getElementById(DICTATE_TARGETS[k].btn);
    if (btn) btn.style.display = ok ? '' : 'none';
  });
  // api() with no second argument is a GET; passing null would make it a POST.
  // Both halves have to hold: a hub with no speech backend, and a viewer who
  // could not create the task anyway, each get no button rather than one that
  // fails or sits permanently disabled.
  api('/api/dictate').then(d => {
    const ok = !!(d && d.available && d.can_add_tasks);
    showAll(ok);
    if (!ok) return;
    const how = dictateTouchPrimary() ? 'Hold to dictate' : 'Dictate';
    const backend = ' (' + (d.backend || 'speech') + ')';
    keys.forEach(k => {
      const btn = document.getElementById(DICTATE_TARGETS[k].btn);
      if (!btn) return;
      // Says both halves of the rule, because the second only shows itself when
      // the caret happens to be somewhere: into whichever field has the caret,
      // and failing that into the one the button sits beside.
      btn.title = how + ' into the focused field, otherwise ' +
                  (k === 'edit' ? 'these details' : 'the task title') + backend;
      paintDictate(k, 'idle', dictateIdleLabel());
    });
  }).catch(() => showAll(false));
};

document.addEventListener('DOMContentLoaded', () => { window.initTaskDictation(); });

// The click path: mouse and keyboard, where a press-and-hold means nothing and
// a toggle is the only gesture available. Touch never reaches the toggle — the
// pointer handlers below claim the gesture and suppress the click the browser
// synthesises after touchend, which would otherwise start a second recording
// the instant the first one ended.
function beginDictation(key) {
  if (dictateSuppressClick) { dictateSuppressClick = false; return; }
  if (dictateActive) {
    // A second press on the button that is recording ends it. A press on the
    // *other* one is somebody reaching for the wrong control mid-sentence:
    // stopping here would post the audio into a field they did not aim at, so
    // it does nothing instead.
    if (key === dictateTarget) stopTaskDictation();
    return;
  }
  // startTaskDictation guards this too, but bailing here as well keeps a
  // double click from retargeting a session that is already coming up.
  if (dictateStarting) return;
  dictateTarget = key;
  startTaskDictation();
}

window.toggleTaskDictation = function() { beginDictation('add'); };

// The edit modal's microphone (Task 20302). Same recorder, different landing
// place — what changes is only what happens to the transcript.
window.toggleEditDictation = function() { beginDictation('edit'); };

async function startTaskDictation() {
  // dictateActive is only set after getUserMedia resolves, so a double click
  // would otherwise start two recorders and orphan the first one's microphone
  // track — the browser's recording indicator then stays lit with nothing able
  // to turn it off. Claim the slot synchronously.
  if (dictateStarting) return;
  dictateStarting = true;

  // Fixed here rather than read back when the transcript arrives, so the words
  // go where the caret was when they were spoken. A transcription round trip is
  // seconds long and the page stays live throughout it; resolving late would
  // let a click made while waiting redirect a sentence already said.
  dictateField = dictateDestination();

  // getUserMedia is absent on an insecure origin and on platforms that refuse
  // it outright — the Meta Ray-Ban Display web runtime being the one this
  // project cares about. Say which, because the two have different fixes.
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia || typeof MediaRecorder === 'undefined') {
    dictateStarting = false;
    endDictateHold();
    // A touch press has already painted "Starting…", so this path has to put
    // the label back even though the click path never changed it.
    setDictateState('idle', dictateIdleLabel());
    toast(window.isSecureContext === false
      ? 'Dictation needs an https connection to reach the microphone'
      : 'This browser cannot record audio', 'err');
    return;
  }

  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      audio: { channelCount: 1, echoCancellation: true, noiseSuppression: true, autoGainControl: true }
    });
  } catch (err) {
    dictateStarting = false;
    endDictateHold();
    setDictateState('idle', dictateIdleLabel());
    toast('Microphone unavailable: ' + (err && err.message ? err.message : err), 'err');
    return;
  }

  const mime = MediaRecorder.isTypeSupported('audio/webm;codecs=opus') ? 'audio/webm;codecs=opus'
             : MediaRecorder.isTypeSupported('audio/ogg;codecs=opus')  ? 'audio/ogg;codecs=opus'
             : (MediaRecorder.isTypeSupported('audio/webm') ? 'audio/webm' : '');

  dictateChunks = [];
  dictateHeardSound = false;
  listenForSound(stream, () => { dictateHeardSound = true; });
  try {
    dictateRecorder = new MediaRecorder(stream, mime ? { mimeType: mime } : {});
  } catch (err) {
    // A constructor that rejects the mime type would otherwise leave
    // dictateStarting set and the button dead until a reload, with the
    // microphone still open.
    stream.getTracks().forEach(t => t.stop());
    closeDictateAudioCtx();
    dictateStarting = false;
    endDictateHold();
    setDictateState('idle', dictateIdleLabel());
    toast('This browser cannot record ' + (mime || 'audio'), 'err');
    return;
  }
  dictateRecorder.ondataavailable = e => { if (e.data && e.data.size > 0) dictateChunks.push(e.data); };
  dictateRecorder.onstop = () => {
    // Release the mic before the upload, not after: the browser's recording
    // indicator stays lit for as long as a track is live, and leaving it on
    // through a network round trip reads as "this page is still listening".
    stream.getTracks().forEach(t => t.stop());
    closeDictateAudioCtx();
    dictateActive = false;
    if (!dictateHeardSound) {
      setDictateState('idle', dictateIdleLabel());
      toast('No sound was recorded — check the microphone', 'err');
      return;
    }
    sendTaskDictation(new Blob(dictateChunks, { type: dictateRecorder.mimeType || 'audio/webm' }));
  };

  dictateRecorder.start();
  dictateActive = true;
  dictateStarting = false;

  // The finger already lifted while getUserMedia was resolving, so this hold
  // captured no audio and there is nothing to send. Common exactly once per
  // browser: the permission prompt eats the whole press, and the user taps
  // "Allow" long after releasing. Say the microphone is ready rather than
  // reporting a failure, because the next hold will work.
  if (dictateAbortPending) {
    cancelTaskDictation(dictateAbortMsg);
    return;
  }
  setDictateState('recording', dictateHeldPointer !== null ? 'Release to send' : 'Stop');
}

function stopTaskDictation() {
  if (dictateRecorder && dictateRecorder.state !== 'inactive') dictateRecorder.stop();
  dictateActive = false;
  setDictateState('busy', 'Transcribing…');
}

// End a session without uploading it, and leave the button usable. Every path
// here is one where we already know the clip is not speech — a tap too short to
// be speech, or a hold that ran out before the microphone was live — so the
// recorder is stopped purely to release the microphone, and uploading would
// send a clip we know is empty and answer it with a misleading "check the
// microphone".
//
// The recorder's handlers are detached before it is stopped, as abandonDictation
// in glasses.html does, and the microphone is released here rather than in
// onstop. The stop event is asynchronous: this used to leave a flag for onstop
// to honour, and a press landing before the event fired started the next
// session and reset the flag — so the discarded clip was uploaded after all,
// and its reply repainted the new, live session as idle (Task 20344).
function cancelTaskDictation(msg) {
  const rec = dictateRecorder;
  if (rec && rec.state !== 'inactive') {
    rec.ondataavailable = rec.onstop = null;
    rec.stop();
    rec.stream.getTracks().forEach(t => t.stop());
  }
  closeDictateAudioCtx();
  dictateActive = false;
  endDictateHold();
  setDictateState('idle', dictateIdleLabel());
  if (msg) toast(msg, 'info');
}

// ── Push-to-talk on touch (Task 20252) ───────────────────────────────────────
//
// On a phone the toggle this button used to be is the wrong shape. It leaves
// the microphone live between two taps, which on a device that is usually in a
// pocket or a hand is exactly how a recording gets left running; and it costs
// two deliberate presses to say four words. Holding is self-limiting — the
// recording cannot outlive the finger — and it is the gesture every other
// voice control on a phone already uses.
//
// The decision is made per gesture from pointerType rather than per device
// from a media query, so a laptop with a touchscreen gets both: a mouse click
// still toggles, a finger still holds. Nothing has to guess what kind of
// machine this is.

function endDictateHold() {
  const btn = dictateBtn();
  if (btn && dictateHeldPointer !== null) {
    try { btn.releasePointerCapture(dictateHeldPointer); } catch (e) {}
  }
  dictateHeldPointer = null;
  dictateHoldStart = 0;
  dictateAbortPending = false;
  dictateAbortMsg = '';
}

function dictatePointerDown(e, key) {
  const btn = document.getElementById(DICTATE_TARGETS[key].btn);
  if (!btn || btn.disabled) return;

  // A mouse keeps the toggle. Clearing the suppression flag here matters on a
  // hybrid machine: a touch gesture that never produced its synthetic click —
  // a pointercancel, a finger dragged off — would otherwise leave the flag set
  // and swallow the next real mouse click.
  if (e.pointerType === 'mouse') { dictateSuppressClick = false; return; }

  // Whatever happens next, the click the browser synthesises after touchend
  // belongs to this gesture and must not be read as a second press.
  dictateSuppressClick = true;

  if (dictateActive || dictateStarting) {   // already listening: this press ends it
    releaseDictateHold(e.timeStamp);
    return;
  }

  e.preventDefault();   // no text selection, no long-press callout
  // Before any painting: setDictateState below resolves the button through
  // dictateTarget, so getting this wrong would light up the other microphone.
  dictateTarget = key;
  dictateHoldStart = e.timeStamp;
  dictateHeldPointer = e.pointerId;
  dictateAbortPending = false;
  // Capture, so a fingertip that drifts off the button still delivers its
  // pointerup here. Without it the release lands on whatever is underneath and
  // the recording runs on with nothing holding it.
  try { btn.setPointerCapture(e.pointerId); } catch (err) {}
  // Deliberately not painted as recording yet: the microphone is not live for
  // another beat, and saying "speak now" before it is loses the first word.
  setDictateState('idle', 'Starting…');
  startTaskDictation();
}

// at is the releasing event's timeStamp. A hold is measured between the two
// events' own timestamps — when the finger went down and came up — not by the
// clock when each handler got to run: a release delivered late by a busy main
// thread would otherwise stretch a stray tap past DICTATE_MIN_HOLD_MS and upload
// it (Task 20344).
function releaseDictateHold(at) {
  // A zero start means this session did not come from a hold — it was started
  // by a click or a keypress and is only being *ended* by this touch. There is
  // no hold to be too short, and a real recording is waiting: measure nothing
  // and send it, or a tablet user who started with the keyboard loses what they
  // just said.
  const fromHold = dictateHoldStart !== 0;
  const held = fromHold ? at - dictateHoldStart : 0;

  if (dictateActive) {
    if (fromHold && held < DICTATE_MIN_HOLD_MS) {
      cancelTaskDictation('Hold the button while you speak');
      return;
    }
    endDictateHold();
    stopTaskDictation();
    return;
  }

  // The microphone has not gone live yet. Leave a note for startTaskDictation
  // to act on when it does — stopping a recorder that does not exist would do
  // nothing and leak the stream getUserMedia is still about to hand us.
  if (dictateStarting) {
    dictateAbortPending = true;
    // Silent when this was not a hold: a click that started dictation and a
    // touch that stopped it before it began is a deliberate cancel, and telling
    // that user how to hold the button answers a question they did not ask.
    dictateAbortMsg = !fromHold ? ''
      : held < DICTATE_MIN_HOLD_MS ? 'Hold the button while you speak'
      : 'Microphone ready — hold and speak again';
    return;
  }
  endDictateHold();
}

function dictatePointerUp(e) {
  if (dictateHeldPointer === null) return;
  if (e && e.pointerId !== undefined && e.pointerId !== dictateHeldPointer) return;
  releaseDictateHold(e ? e.timeStamp : performance.now());
}

// Wired once, on the button, rather than per render: the buttons are never
// re-created, only relabelled by paintDictate, which replaces their children
// and would drop listeners bound to them.
function bindTaskDictationGestures(btn, key) {
  if (!btn || btn.dataset.pttBound === '1') return;
  btn.dataset.pttBound = '1';

  // Keep the caret where the user put it (Task 20309). A <button> takes focus
  // on mousedown, so without this the press empties the very field the router
  // reads and every mouse click would fall back to the button's own default.
  // Cancelling the default costs nothing else: the click still fires, and Tab
  // still reaches the button for anyone driving the page from the keyboard.
  btn.addEventListener('mousedown', e => { e.preventDefault(); });

  if (typeof window.PointerEvent === 'undefined') return;  // click-toggle still works
  btn.addEventListener('pointerdown', e => dictatePointerDown(e, key));
  btn.addEventListener('pointerup', dictatePointerUp);
  // A pointercancel is the system taking the gesture away — a scroll it decided
  // was really a scroll, a call arriving. Same release path: a hold long enough
  // to be speech is still sent, a short one is still discarded.
  btn.addEventListener('pointercancel', dictatePointerUp);
  btn.addEventListener('contextmenu', e => e.preventDefault());
}

async function sendTaskDictation(blob) {
  if (!blob || !blob.size) { setDictateState('idle', dictateIdleLabel()); toast('Nothing was recorded', 'info'); return; }
  setDictateState('busy', 'Transcribing…');

  const ext = (blob.type || '').indexOf('ogg') >= 0 ? 'ogg' : 'webm';
  const form = new FormData();
  form.append('audio', blob, 'dictation.' + ext);

  try {
    const headers = authHeaders();
    delete headers['Content-Type']; // FormData sets its own boundary
    const resp = await fetch('/api/transcribe', { method: 'POST', headers, body: form });
    const data = await resp.json().catch(() => ({}));

    if (!resp.ok || !data.text) {
      toast((data && (data.message || data.error)) || 'Transcription failed', 'err');
      setDictateState('idle', dictateIdleLabel());
      return;
    }

    // Resolved when the session started. Re-resolved only when the edit modal
    // closed under a transcription in flight (cancelEditDictation), whose
    // fields went with it.
    const dest = dictateField || dictateDestination();
    dictateField = null;
    if (dest && dest.el.id === 'modalDesc') {
      // The edit modal's Description is the one destination whose answer is a
      // question rather than an assignment: it already holds a paragraph the
      // speaker may have meant to replace or to build on (Task 20302).
      window.openDictateApply(data.text);
    } else if (dest) {
      insertDictated(dest.el, data.text, dest.atCaret);
      // Named, because the whole point of Task 20309 is that this is no longer
      // always the same box — and the one time it is worth saying out loud is
      // when the words went somewhere the speaker was not watching.
      toast('Heard: ' + data.text + ' → ' + dictateFieldName(dest.el), 'ok');
    } else {
      toast('Heard: ' + data.text, 'ok');
    }
  } catch (err) {
    toast('Transcription request failed', 'err');
  }
  setDictateState('idle', dictateIdleLabel());
}

// ── Applying what was dictated into an open edit modal (Task 20302) ──────────
//
// The microphone beside the Add Task field never has to ask anything: the
// field is empty or holds a half-typed title the speaker is plainly extending.
// The one in the edit modal speaks into a description somebody already wrote,
// and "and make sure it works on mobile" and "scrap that, this is really about
// the migration" are the same sound to a transcriber. Guessing wrong in one
// direction loses a paragraph; guessing wrong in the other buries the new
// instruction at the end of text that contradicts it.
//
// So it asks, with three answers:
//
//   Replace        the spoken words become the details
//   Add to the end the details keep their text and gain a paragraph
//   Edit with AI   the spoken words are an *instruction*, and the model
//                  applies them to the details that are there
//
// Only the third leaves the browser, and none of the three writes to the plan:
// every one lands in the textarea, and the modal's own Save Changes is still
// the only way in. That is what makes letting a model rewrite somebody's task
// description defensible — a misheard instruction is a visible paragraph they
// can Cancel, never a silent edit.

let dictateHeardText = '';

// Bumped every time the chooser opens or closes, so a revision that comes back
// after the user gave up on it can tell. Without this, dismissing the dialog
// and carrying on typing ends with the model's answer landing in the textarea
// seconds later, over whatever was written in the meantime — the one way this
// feature could still edit a description nobody accepted.
let dictateApplySeq = 0;

// openDictateApply asks the question — but only when there is something to
// lose. An empty description has exactly one sensible answer, and a dialog
// whose buttons all do the same thing teaches people to dismiss dialogs.
//
// On window because it is this feature's entry point: everything above it is a
// microphone, everything below is what happens to words. That seam is also
// where dictate_apply_scenarios.js drives the bundle — the alternative is a
// headless browser with a fake capture device just to reach a branch that has
// nothing to do with audio.
window.openDictateApply = function(text) {
  dictateApplySeq++;
  dictateHeardText = String(text == null ? '' : text).trim();
  if (!dictateHeardText) return;

  const desc = document.getElementById('modalDesc');
  if (!desc) { toast('Heard: ' + dictateHeardText, 'ok'); return; }
  if (!desc.value.trim()) {
    applyDictatedDetails(dictateHeardText, 'Details dictated — review, then Save Changes');
    return;
  }

  const heard = document.getElementById('dr-heard');
  if (heard) heard.textContent = dictateHeardText;
  setDictateApplyBusy(false);
  openOverlay('dr-overlay', {dismiss: closeDictateApply});
};

window.closeDictateApply = function() {
  dictateApplySeq++;
  closeOverlay('dr-overlay');
};

// applyDictatedDetails writes the chosen text into the editor and leaves the
// cursor at the end of it, so the next thing the user does is read what landed.
function applyDictatedDetails(text, msg) {
  const desc = document.getElementById('modalDesc');
  if (!desc) return;
  desc.value = text;
  desc.focus();
  try { desc.setSelectionRange(desc.value.length, desc.value.length); } catch (e) {}
  toast(msg, 'ok');
}

window.dictateApplyReplace = function() {
  const text = dictateHeardText;
  closeDictateApply();
  applyDictatedDetails(text, 'Details replaced — review, then Save Changes');
};

window.dictateApplyAppend = function() {
  const desc = document.getElementById('modalDesc');
  const text = dictateHeardText;
  closeDictateApply();
  const existing = desc ? desc.value.replace(/\s+$/, '') : '';
  applyDictatedDetails(existing ? existing + '\n\n' + text : text,
                       'Added to the details — review, then Save Changes');
};

// setDictateApplyBusy disables the three answers while the model is working.
// Without it a second click posts a second revision, and whichever reply lands
// last wins — which on a slow provider is not the one the user waited for.
function setDictateApplyBusy(on) {
  const busy = document.getElementById('dr-busy');
  if (busy) busy.style.display = on ? '' : 'none';
  ['dr-append-btn', 'dr-replace-btn', 'dr-revise-btn'].forEach(id => {
    const b = document.getElementById(id);
    if (b) b.disabled = !!on;
  });
}

window.dictateApplyRevise = function() {
  const idEl = document.getElementById('modalTaskId');
  const desc = document.getElementById('modalDesc');
  const id = idEl ? parseInt(idEl.value, 10) : NaN;
  if (!desc || !Number.isFinite(id) || id <= 0) { toast('No task is open to edit', 'err'); return; }

  const titleEl = document.getElementById('modalTitle_');
  const seq = dictateApplySeq;
  setDictateApplyBusy(true);
  // The *draft* description, deliberately, not the stored one: the user may
  // have typed into this field since the modal opened, and revising the saved
  // copy would discard exactly the edits this dialog exists to protect.
  api(pUrl('/api/tasks/' + id + '/revise'), {
    instruction: dictateHeardText,
    description: desc.value,
    title: titleEl ? titleEl.value : '',
  }).then(d => {
    setDictateApplyBusy(false);
    // Dismissed, or a second transcript arrived, while the model was thinking.
    // Silent on purpose: the user has moved on, and a toast about a revision
    // they cancelled is noise about work they already decided against.
    if (seq !== dictateApplySeq) return;
    if (!d || !d.ok || !d.description) {
      // Leaves the dialog open on purpose. The model is the only part of this
      // that can fail, and Replace and Add to the end are still right there —
      // closing would make the user say the sentence again to reach them.
      toast((d && (d.message || d.error)) || 'Editing the details failed', 'err');
      return;
    }
    closeDictateApply();
    applyDictatedDetails(d.description, 'Details edited — review, then Save Changes');
  }).catch(() => {
    setDictateApplyBusy(false);
    if (seq !== dictateApplySeq) return;
    toast('Request failed', 'err');
  });
};

// cancelEditDictation releases the microphone when the edit modal closes
// underneath it. Without it, dismissing the modal mid-sentence leaves the
// recorder running against a field that is no longer on screen — and the
// browser's recording indicator lit with nothing able to turn it off.
//
// Called from closeModal in 12-task-crud.js, which loads earlier in the same
// IIFE; function declarations hoist across the whole bundle, so the call site
// resolves regardless of fragment order.
function cancelEditDictation() {
  closeDictateApply();
  dictateHeardText = '';
  // The destination is one of the fields going off screen with the dialog, so
  // it must not survive into whatever the next session resolves.
  dictateField = null;
  if (dictateTarget !== 'edit') return;
  if (dictateActive || dictateStarting) cancelTaskDictation('');
  paintDictate('edit', 'idle', dictateIdleLabel());
  dictateTarget = 'add';
}

window.sendVoiceAudio = async function() {
  if (!voiceBlob) { toast('No recording yet', 'info'); return; }

  document.getElementById('voiceStatus').textContent = 'Uploading and transcribing...';
  document.getElementById('voiceSendBtn').disabled = true;

  const ext = voiceBlob._ext || 'webm';
  const formData = new FormData();
  formData.append('audio', voiceBlob, 'recording.' + ext);

  try {
    const headers = authHeaders();
    // FormData sets its own Content-Type; remove explicit header.
    delete headers['Content-Type'];

    const resp = await fetch('/api/voice', { method: 'POST', headers, body: formData });
    const data = await resp.json();

    document.getElementById('voiceOutput').style.display = 'block';
    document.getElementById('voiceOutput').textContent = data.output || '';

    // Extract transcription line from output for display.
    const lines = (data.output || '').split('\n');
    const tLine = lines.find(l => l.includes('Transcription:'));
    const tVal  = lines.find(l => l.trim().startsWith('"') && l.trim().endsWith('"'));
    if (tVal) {
      document.getElementById('voiceTranscript').textContent = tVal.trim().replace(/^"|"$/g, '');
      document.getElementById('voiceTranscript').style.color = 'var(--text)';
    }

    if (data.ok) {
      document.getElementById('voiceStatus').textContent = 'Done! Check output below.';
      toast('Voice command executed', 'ok');
      refreshState();
    } else {
      document.getElementById('voiceStatus').textContent = 'Error: ' + (data.error || 'unknown');
      toast('Voice command failed', 'err');
    }
    document.getElementById('voiceSendBtn').disabled = false;
  } catch (err) {
    document.getElementById('voiceStatus').textContent = 'Request failed: ' + err.message;
    document.getElementById('voiceSendBtn').disabled = false;
    toast('Voice request failed', 'err');
  }
};

