// ── Voice / STT ───────────────────────────────────────────────────────────────

let voiceMediaRecorder = null;
let voiceChunks = [];
let voiceRecording = false;
let voiceBlob = null;

window.openVoiceModal = function() {
  document.getElementById('voiceModalBackdrop').style.display = 'flex';
  document.getElementById('voiceStatus').textContent = 'Click Record to start recording...';
  document.getElementById('voiceTranscript').textContent = 'Transcription will appear here';
  document.getElementById('voiceTranscript').style.color = 'var(--muted)';
  document.getElementById('voiceOutput').style.display = 'none';
  document.getElementById('voiceOutput').textContent = '';
  document.getElementById('voiceSendBtn').disabled = true;
  voiceBlob = null; voiceChunks = [];
};

window.closeVoiceModal = function() {
  if (voiceRecording) stopVoiceRecording();
  document.getElementById('voiceModalBackdrop').style.display = 'none';
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

let dictateRecorder = null;
let dictateChunks = [];
let dictateActive = false;
let dictateStarting = false;

const DICTATE_IDLE_ICON = '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M5 3a3 3 0 0 1 6 0v5a3 3 0 0 1-6 0V3z"/><path d="M3.5 6.5A.5.5 0 0 1 4 7v1a4 4 0 0 0 8 0V7a.5.5 0 0 1 1 0v1a5 5 0 0 1-4.5 4.975V15h2a.5.5 0 0 1 0 1h-5a.5.5 0 0 1 0-1h2v-2.025A5 5 0 0 1 3 8V7a.5.5 0 0 1 .5-.5z"/></svg>';
const DICTATE_STOP_ICON = '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M5 5h6v6H5z"/></svg>';

function dictateBtn()   { return document.getElementById('dictateTaskBtn'); }
function dictateLabel() { return document.getElementById('dictateTaskLabel'); }

// Paint the button. Kept in one place because three call sites (start, stop,
// failure) all have to leave it in a consistent state, and a mic button stuck
// on "Stop" with no recorder behind it is unrecoverable without a reload.
function setDictateState(state, text) {
  const btn = dictateBtn(), lab = dictateLabel();
  if (!btn) return;
  btn.classList.toggle('recording', state === 'recording');
  btn.disabled = (state === 'busy');
  btn.innerHTML = (state === 'recording' ? DICTATE_STOP_ICON : DICTATE_IDLE_ICON) +
                  ' <span id="dictateTaskLabel"></span>';
  const fresh = document.getElementById('dictateTaskLabel');
  if (fresh) fresh.textContent = text || (lab ? lab.textContent : 'Dictate');
}

// Reveal the button only when the hub can actually transcribe. One call at
// load; the answer depends on hub config, which does not change under the
// user's feet often enough to be worth re-checking.
window.initTaskDictation = function() {
  const btn = dictateBtn();
  if (!btn) return;
  // api() with no second argument is a GET; passing null would make it a POST.
  // Both halves have to hold: a hub with no speech backend, and a viewer who
  // could not create the task anyway, each get no button rather than one that
  // fails or sits permanently disabled.
  api('/api/dictate').then(d => {
    if (d && d.available && d.can_add_tasks) {
      btn.style.display = '';
      btn.title = 'Dictate the task title (' + (d.backend || 'speech') + ')';
    }
  }).catch(() => { /* leave it hidden — no backend, no button */ });
};

document.addEventListener('DOMContentLoaded', () => { window.initTaskDictation(); });

window.toggleTaskDictation = async function() {
  if (dictateActive) { stopTaskDictation(); return; }

  // dictateActive is only set after getUserMedia resolves, so a double click
  // would otherwise start two recorders and orphan the first one's microphone
  // track — the browser's recording indicator then stays lit with nothing able
  // to turn it off. Claim the slot synchronously.
  if (dictateStarting) return;
  dictateStarting = true;

  // getUserMedia is absent on an insecure origin and on platforms that refuse
  // it outright — the Meta Ray-Ban Display web runtime being the one this
  // project cares about. Say which, because the two have different fixes.
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia || typeof MediaRecorder === 'undefined') {
    dictateStarting = false;
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
    setDictateState('idle', 'Dictate');
    toast('Microphone unavailable: ' + (err && err.message ? err.message : err), 'err');
    return;
  }

  const mime = MediaRecorder.isTypeSupported('audio/webm;codecs=opus') ? 'audio/webm;codecs=opus'
             : MediaRecorder.isTypeSupported('audio/ogg;codecs=opus')  ? 'audio/ogg;codecs=opus'
             : (MediaRecorder.isTypeSupported('audio/webm') ? 'audio/webm' : '');

  dictateChunks = [];
  dictateRecorder = new MediaRecorder(stream, mime ? { mimeType: mime } : {});
  dictateRecorder.ondataavailable = e => { if (e.data && e.data.size > 0) dictateChunks.push(e.data); };
  dictateRecorder.onstop = () => {
    // Release the mic before the upload, not after: the browser's recording
    // indicator stays lit for as long as a track is live, and leaving it on
    // through a network round trip reads as "this page is still listening".
    stream.getTracks().forEach(t => t.stop());
    dictateActive = false;
    sendTaskDictation(new Blob(dictateChunks, { type: dictateRecorder.mimeType || 'audio/webm' }));
  };

  dictateRecorder.start();
  dictateActive = true;
  dictateStarting = false;
  setDictateState('recording', 'Stop');
};

function stopTaskDictation() {
  if (dictateRecorder && dictateRecorder.state !== 'inactive') dictateRecorder.stop();
  dictateActive = false;
  setDictateState('busy', 'Transcribing…');
}

async function sendTaskDictation(blob) {
  if (!blob || !blob.size) { setDictateState('idle', 'Dictate'); toast('Nothing was recorded', 'info'); return; }
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
      setDictateState('idle', 'Dictate');
      return;
    }

    const title = document.getElementById('newTaskTitle');
    if (title) {
      // Append rather than replace when the field already has words in it, so
      // a second press extends a sentence instead of discarding the first.
      title.value = title.value.trim() ? (title.value.trim() + ' ' + data.text) : data.text;
      title.focus();
      title.setSelectionRange(title.value.length, title.value.length);
    }
    toast('Heard: ' + data.text, 'ok');
  } catch (err) {
    toast('Transcription request failed', 'err');
  }
  setDictateState('idle', 'Dictate');
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

