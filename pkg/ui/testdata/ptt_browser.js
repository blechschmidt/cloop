// ptt_browser.js — drives the Dictate button's push-to-talk gesture in a real
// browser (Task 20252).
//
// Why a browser and not testdata/domshim.js, which every other frontend gate in
// this package uses: the properties that matter here are ones only a real
// implementation of the input pipeline has.
//
//   * After a touch gesture the browser synthesises a `click`. The button's
//     onclick still toggles dictation, so if that click is not suppressed the
//     release that ends a recording immediately starts another one — the mic
//     stays live and the next tap uploads a second clip. A shim that never
//     synthesises the click cannot fail this test, which is exactly why it is
//     worth running: the bug it catches is invisible without one.
//   * Pointer capture, pointercancel and touch-action are the browser's, not
//     the page's.
//   * getUserMedia/MediaRecorder are real here. Chrome's fake capture device
//     plays a 440 Hz tone (see toneWAV), so listenForSound's analyser sees
//     genuine samples and the empty-clip guard is exercised rather than
//     stubbed past.
//
// Chrome is launched with a fake microphone and auto-granted permission, so no
// prompt appears and getUserMedia resolves in milliseconds on a quiet machine —
// the same timing a user gets on every hold after the first. Nothing below
// relies on that, though: under a loaded CI run the same call takes hundreds of
// milliseconds, so every step waits for what the page shows (the button going
// live, the session ending) rather than for a fixed time. See holdAndSpeak.
//
// Usage: node ptt_browser.js <chrome-binary> <base-url>
// Prints one JSON document on stdout: {scenario: {...}, ...}.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];

const sleep = ms => new Promise(r => setTimeout(r, ms));

// SPEAK_MS is how long a hold that is meant to be transcribed keeps talking
// once the microphone is live: the input to those scenarios, not a wait for
// anything. The length of the old fixed hold, now counted from the moment the
// page says it is listening rather than from the press. The page's level check
// (listenForSound) polls every 100ms and, with toneWAV as the microphone, hears
// it on the first poll, so this is seven polls' worth of speech.
const SPEAK_MS = 700;

// MID_HOLD_MS is when, into a hold, the mid-hold scenario looks at the button:
// comfortably past the 400ms below which a release is treated as a stray tap
// (DICTATE_MIN_HOLD_MS in 15-voice.js), so what it sees is a hold in progress.
const MID_HOLD_MS = 500;

// WAIT_MS bounds each wait for the page to reach a state; it is how long to
// keep looking before reporting what is there, never a pause a healthy run sits
// out. The slowest thing waited on is the first getUserMedia of a page's life,
// which opens the capture device and has taken over a second on a loaded box.
// 30s is far beyond that, and the waits a run makes stay inside the 4-minute
// bound the Go side puts on this driver even if several of them expire.
const WAIT_MS = 30000;

// waitFor polls a page expression until it is truthy or WAIT_MS passes, and
// reports which. It never throws on the deadline: every condition waited on is
// also what a scenario then reads, so a state that never arrives shows up in
// the Go test's assertion with the value that was there instead.
async function waitFor(cdp, expr) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    try {
      if (await cdp.eval(expr)) return true;
    } catch (_) { /* mid-navigation: no context to evaluate in yet */ }
    if (Date.now() >= deadline) return false;
    await sleep(25);
  }
}

// ── a minimal CDP client ────────────────────────────────────────────────────

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.handlers = [];
    ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id !== undefined) {
        const p = this.pending.get(msg.id);
        if (!p) return;
        this.pending.delete(msg.id);
        msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
        return;
      }
      for (const h of this.handlers) h(msg);
    });
  }
  on(fn) { this.handlers.push(fn); }
  send(method, params) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, {resolve, reject});
      this.ws.send(JSON.stringify({id, method, params: params || {}}));
      setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(method + ' timed out'));
      }, 20000);
    });
  }
  // eval returns the JS value of an expression, awaiting promises.
  async eval(expr) {
    const r = await this.send('Runtime.evaluate', {
      expression: expr, awaitPromise: true, returnByValue: true,
    });
    if (r.exceptionDetails) {
      throw new Error('eval failed: ' + JSON.stringify(r.exceptionDetails.exception || r.exceptionDetails));
    }
    return r.result.value;
  }
}

// toneWAV is the microphone: one second of a 440 Hz sine, 16-bit mono PCM,
// which Chrome loops for as long as a capture runs.
//
// Without it the fake capture device plays short periodic beeps instead, the
// first of them about half a second into each capture: measured, the page's
// 100ms level poll first heard a capture 597-610ms after it started, across
// sixteen holds. A hold shorter than that is, to the page, a silent clip, which
// it rightly refuses to upload ("No sound was recorded"). The old fixed 700ms
// hold cleared that by 700ms minus however long getUserMedia took, which on a
// loaded CI runner was not always anything: the transcript never came, and the
// failure read as a gesture bug (Task 20344). With this file the first poll
// hears it (~100ms, same measurement). A continuous tone is what this driver
// always assumed the microphone produced.
function toneWAV() {
  const rate = 48000, n = rate;
  const wav = Buffer.alloc(44 + n * 2);
  wav.write('RIFF', 0); wav.writeUInt32LE(36 + n * 2, 4); wav.write('WAVE', 8);
  wav.write('fmt ', 12); wav.writeUInt32LE(16, 16);
  wav.writeUInt16LE(1, 20); wav.writeUInt16LE(1, 22);          // PCM, mono
  wav.writeUInt32LE(rate, 24); wav.writeUInt32LE(rate * 2, 28);
  wav.writeUInt16LE(2, 32); wav.writeUInt16LE(16, 34);         // 16-bit
  wav.write('data', 36); wav.writeUInt32LE(n * 2, 40);
  for (let i = 0; i < n; i++) {
    wav.writeInt16LE(Math.round(Math.sin(2 * Math.PI * 440 * i / rate) * 0.5 * 32767), 44 + i * 2);
  }
  return wav;
}

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-ptt-'));
  // In the profile directory, so the cleanup that removes one removes both.
  const tone = path.join(dir, 'tone.wav');
  fs.writeFileSync(tone, toneWAV());
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    // This suite runs as root in the project's dev box and as an unprivileged
    // user in CI. Chrome's sandbox needs privileges it does not have in the
    // first case and already has in the second; disabling it is safe for a
    // throwaway profile loading only a local httptest server.
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    // The flags that make this test possible: a synthetic microphone, playing
    // a tone rather than the default beep (see toneWAV), and permission
    // granted without a prompt.
    '--use-fake-ui-for-media-stream',
    '--use-fake-device-for-media-stream',
    '--use-file-for-fake-audio-capture=' + tone,
    '--autoplay-policy=no-user-gesture-required',
    'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe']});

  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });

  // A launch that fails after the spawn must take Chrome with it. Left
  // running, it holds this process's stderr pipe open, node never exits,
  // and the Go test waiting on node hangs until the package timeout — the
  // 20-minute CI hang Task 20340 traced to a Chrome slow to report its port.
  try {
    // Chrome writes the chosen port to DevToolsActivePort once it is listening.
    const portFile = path.join(dir, 'DevToolsActivePort');
    let port = 0;
    for (let i = 0; i < 600 && !port; i++) {
      await sleep(50);
      if (proc.exitCode !== null) throw new Error('chrome exited: ' + stderr);
      try {
        const txt = fs.readFileSync(portFile, 'utf8').split('\n');
        if (txt[0] && txt[0].trim()) port = Number(txt[0].trim());
      } catch (e) { /* not written yet */ }
    }
    if (!port) throw new Error('chrome never reported a debugging port within 30s: ' + stderr);

    const list = await (await fetch('http://127.0.0.1:' + port + '/json/list', {signal: AbortSignal.timeout(15000)})).json();
    const page = list.find(t => t.type === 'page');
    if (!page) throw new Error('no page target');

    const ws = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((res, rej) => {
      setTimeout(() => rej(new Error('cdp connect timed out')), 15000).unref();
      ws.addEventListener('open', res, {once: true});
      ws.addEventListener('error', () => rej(new Error('cdp connect failed')), {once: true});
    });
    return {cdp: new CDP(ws), proc, dir};
  } catch (e) {
    try { proc.kill('SIGKILL'); } catch (_) { /* already gone */ }
    throw e;
  }
}

// ── page setup ──────────────────────────────────────────────────────────────

// Every request the page makes, in order, so a scenario can assert on what did
// and did not reach the network. Reset between scenarios.
let requests = [];

async function boot(cdp) {
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Network.enable');
  cdp.on(msg => {
    if (msg.method === 'Network.requestWillBeSent') requests.push(msg.params.request.url);
  });

  // A phone: touch is the primary pointer, which is also what makes
  // matchMedia('(pointer: coarse)') true and the button label read "Hold to
  // talk" rather than "Dictate".
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: 390, height: 844, deviceScaleFactor: 3, mobile: true,
  });
  await cdp.send('Emulation.setTouchEmulationEnabled', {enabled: true, maxTouchPoints: 5});

  const loaded = new Promise(res => cdp.on(m => { if (m.method === 'Page.loadEventFired') res(); }));
  await cdp.send('Page.navigate', {url: BASE + '/'});
  await loaded;

  // The dictate button is hidden until GET /api/dictate answers, and it lives
  // on the Tasks tab.
  await cdp.eval("window.switchTab && window.switchTab('tasks')");
  const visible = await waitFor(cdp, `(() => {
    const b = document.getElementById('dictateTaskBtn');
    return !!(b && b.style.display !== 'none' && b.getClientRects().length);
  })()`);
  if (!visible) throw new Error('dictate button never became visible');
  // The label the button returns to between sessions. Read once, here, where
  // nothing has pressed it yet; every "has this session ended" check below
  // compares against it.
  idleLabel = (await state(cdp)).label;
}

// idleLabel is what the button says at rest ("Hold to talk" on this device).
let idleLabel = '';

// The button's own account of a session, from what it paints (15-voice.js):
// pressed, it says "Starting…" until the microphone is live; live, it carries
// .recording; after the release it is disabled while "Transcribing…"; and only
// when the session is over, whichever way it ended, does it go back to idle.
const LIVE = `document.getElementById('dictateTaskBtn').classList.contains('recording')`;
const idleExpr = () => `(() => {
  const b = document.getElementById('dictateTaskBtn');
  return !b.classList.contains('recording') && !b.disabled
    && (b.textContent || '').trim() === ${JSON.stringify(idleLabel)};
})()`;

// sessionOver waits for the button to be back at rest, which is the page
// saying it has finished with the last gesture: uploaded and filled the title,
// or discarded the clip and said why. A touch press repaints the button
// synchronously, so right after one it is never already at rest by accident.
const sessionOver = cdp => waitFor(cdp, idleExpr());

// warmUp performs one hold whose result is thrown away.
//
// The first getUserMedia of a page's life costs far more than every later one —
// the capture device is being opened — and on this box it routinely outlasts a
// 700ms hold. That is a real condition with deliberate handling (see the
// dictateAbortPending path in 15-voice.js, and slow_microphone_recovers below,
// which pins it), but it is not the condition the gesture scenarios are about.
// Running it once here puts the page in the state a user is in from their
// second hold onwards, which is every hold but one.
//
// Waited out rather than slept through. The warm-up's getUserMedia is exactly
// the slow one, and a fixed pause that it outlasted left the first scenario's
// press landing on a session still starting — which the button reads as "this
// press ends it", so the scenario's hold produced nothing at all.
async function warmUp(cdp) {
  await touchHold(cdp, 800);
  await sessionOver(cdp);
  await cdp.eval("(() => { const t = document.getElementById('newTaskTitle'); if (t) t.value = ''; })()");
}

// centre returns viewport coordinates of the dictate button.
async function centre(cdp) {
  return cdp.eval(`(() => {
    const r = document.getElementById('dictateTaskBtn').getBoundingClientRect();
    return {x: r.left + r.width/2, y: r.top + r.height/2};
  })()`);
}

// touchHold presses for ms and lets go, whatever the page is doing meanwhile.
// That is the right gesture for the holds that are meant to fail — a stray tap,
// a release before the microphone is live — and the wrong one for a hold that
// is meant to be heard; see holdAndSpeak.
//
// The two events are stamped ms apart (touchStamps), because the page measures
// a hold between the events' own timestamps, not by when it gets to handle
// them. Without the stamps the gesture's length would be however long this
// process took to send the release, and a loaded machine that stalls it for a
// few hundred milliseconds turns a 120ms tap into a hold.
async function touchHold(cdp, ms) {
  const p = await centre(cdp);
  const pt = [{x: p.x, y: p.y, radiusX: 12, radiusY: 12, force: 1, id: 1}];
  const [down, up] = touchStamps(ms);
  await cdp.send('Input.dispatchTouchEvent', {type: 'touchStart', touchPoints: pt, timestamp: down});
  await sleep(ms);
  await cdp.send('Input.dispatchTouchEvent', {type: 'touchEnd', touchPoints: [], timestamp: up});
}

// touchStamps returns CDP event timestamps (seconds since the epoch) for a
// press starting now and lasting ms.
function touchStamps(ms) {
  const down = Date.now() / 1000;
  return [down, down + ms / 1000];
}

// holdAndSpeak is a hold as a person makes one: press, wait for the button to
// say the microphone is live, talk for SPEAK_MS, let go.
//
// The button withholds "Release to send" until getUserMedia has resolved,
// precisely so nobody starts talking into a microphone that is not open yet
// (15-voice.js). A fixed-length hold ignores that signal, so the amount of it
// that was actually recorded shrank by however long getUserMedia took — and
// under load that was enough to leave a silent clip, no upload and an empty
// title (Task 20344).
async function holdAndSpeak(cdp) {
  const p = await centre(cdp);
  const pt = [{x: p.x, y: p.y, radiusX: 12, radiusY: 12, force: 1, id: 1}];
  await cdp.send('Input.dispatchTouchEvent', {type: 'touchStart', touchPoints: pt});
  await waitFor(cdp, LIVE);
  await sleep(SPEAK_MS);
  await cdp.send('Input.dispatchTouchEvent', {type: 'touchEnd', touchPoints: []});
}

async function mouseClick(cdp) {
  const p = await centre(cdp);
  const base = {x: p.x, y: p.y, button: 'left', buttons: 1, clickCount: 1, pointerType: 'mouse'};
  await cdp.send('Input.dispatchMouseEvent', {type: 'mousePressed', ...base});
  await sleep(20);
  await cdp.send('Input.dispatchMouseEvent', {type: 'mouseReleased', ...base, buttons: 0});
}

// state reports everything a scenario asserts on, read straight from the DOM.
async function state(cdp) {
  return cdp.eval(`(() => {
    const b = document.getElementById('dictateTaskBtn');
    const t = document.getElementById('newTaskTitle');
    const toast = document.getElementById('toast');
    return {
      recording: b.classList.contains('recording'),
      disabled: !!b.disabled,
      label: (b.textContent || '').trim(),
      title: t ? t.value : null,
      touchAction: getComputedStyle(b).touchAction,
      // Cleared 3s after it is shown; every read here happens well inside that.
      toast: toast ? (toast.textContent || '').trim() : '',
    };
  })()`);
}

async function reset(cdp) {
  requests = [];
  await cdp.eval("(() => { const t = document.getElementById('newTaskTitle'); if (t) t.value = ''; })()");
}


// Matches both speech routes: the dashboard posts to /api/transcribe and the
// glasses link to /api/glasses/transcribe, which is not a superstring of it.
function transcribes() { return requests.filter(u => /\/api\/(glasses\/)?transcribe$/.test(u)).length; }

// ── scenarios ───────────────────────────────────────────────────────────────

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  const out = {};
  try {
    await boot(cdp);

    // The label is an affordance: on a touch-primary device the button has to
    // say it wants to be held, because nothing else on screen does.
    out.labels_say_hold_on_touch = {idle_label: (await state(cdp)).label};

    await warmUp(cdp);

    // 1. A real hold: press, speak, release. The transcript must land in the
    //    title field, and — the part a shim cannot check — the synthesised
    //    click that follows touchend must not start a second recording.
    await reset(cdp);
    await holdAndSpeak(cdp);
    await sessionOver(cdp);
    {
      const s = await state(cdp);
      out.hold_transcribes_then_stops = {
        title: s.title,
        recording_after: s.recording,
        disabled_after: s.disabled,
        label_after: s.label,
        transcribe_requests: transcribes(),
      };
    }

    // 2. A stray tap — a fingertip brushing the button on the way to the text
    //    field. Too short to be speech, so nothing should reach the network.
    //
    //    The reported message is what makes this scenario load-bearing rather
    //    than merely true. Three different guards can end a hold without
    //    uploading, and each says something different:
    //
    //      too short                  "Hold the button while you speak"
    //      released before mic ready  "Microphone ready — hold and speak again"
    //      recorded, but silent       "No sound was recorded — check the microphone"
    //
    //    Only the first is right for a tap, and only the first sends the user
    //    back to the button rather than to their OS sound settings.
    await reset(cdp);
    await touchHold(cdp, 120);
    await sessionOver(cdp);
    {
      const s = await state(cdp);
      out.short_tap_sends_nothing = {
        title: s.title,
        recording_after: s.recording,
        transcribe_requests: transcribes(),
        toast: s.toast,
      };
    }

    // 3. Mid-hold state: while the finger is down the button must show it is
    //    listening, and must still be enabled so the release can reach it.
    //
    //    Read once the microphone is live and MID_HOLD_MS into the hold,
    //    whichever is later: before the microphone is live the button says
    //    "Starting…" by design, and a fixed instant could land on either side.
    await reset(cdp);
    {
      const p = await centre(cdp);
      const pt = [{x: p.x, y: p.y, radiusX: 12, radiusY: 12, force: 1, id: 1}];
      const pressed = Date.now();
      await cdp.send('Input.dispatchTouchEvent', {type: 'touchStart', touchPoints: pt});
      await waitFor(cdp, LIVE);
      await sleep(Math.max(0, MID_HOLD_MS - (Date.now() - pressed)));
      const mid = await state(cdp);
      await cdp.send('Input.dispatchTouchEvent', {type: 'touchEnd', touchPoints: []});
      await sessionOver(cdp);
      out.mid_hold_shows_listening = {
        recording_during: mid.recording,
        disabled_during: mid.disabled,
        label_during: mid.label,
        touch_action: mid.touchAction,
      };
    }

    // 4. A mouse keeps the toggle it always had: one click starts, a second
    //    stops. Holding a mouse button means nothing, so push-to-talk must not
    //    be imposed on it — and a hybrid laptop has both pointers at once.
    //
    //    A click paints nothing until the microphone is live, so the first
    //    read waits for that and then talks for SPEAK_MS, as a hold does.
    await reset(cdp);
    await mouseClick(cdp);
    await waitFor(cdp, LIVE);
    await sleep(SPEAK_MS);
    const afterFirst = await state(cdp);
    await mouseClick(cdp);
    await sessionOver(cdp);
    const afterSecond = await state(cdp);
    out.mouse_click_still_toggles = {
      recording_after_first_click: afterFirst.recording,
      recording_after_second_click: afterSecond.recording,
      title: afterSecond.title,
      transcribe_requests: transcribes(),
    };

    // 5. Two holds in a row. The second must work exactly like the first —
    //    this is what fails if a release leaves pointer capture, the
    //    suppression flag or the recorder in a stale state.
    await reset(cdp);
    await holdAndSpeak(cdp);
    await sessionOver(cdp);
    await holdAndSpeak(cdp);
    await sessionOver(cdp);
    {
      const s = await state(cdp);
      out.consecutive_holds_both_work = {
        title: s.title,
        recording_after: s.recording,
        transcribe_requests: transcribes(),
      };
    }

    // 6. The finger lifts before the microphone is live. This is what a user
    //    hits on the very first hold in a browser that has not granted
    //    permission yet: the prompt eats the whole press and "Allow" is tapped
    //    long after releasing. Forced here rather than waited for, by delaying
    //    getUserMedia — cold-start timing is not reproducible on its own.
    //
    //    The requirements are that nothing is uploaded (the clip captured no
    //    speech), the button returns to idle rather than sticking on "Starting…"
    //    or "Transcribing…", and — the leak that matters — the microphone
    //    getUserMedia hands over after the release is still stopped.
    await reset(cdp);
    await cdp.eval(`(() => {
      const md = navigator.mediaDevices;
      const real = md.getUserMedia.bind(md);
      window.__liveTracks = () => window.__ptt_tracks.filter(t => t.readyState === 'live').length;
      window.__ptt_tracks = [];
      md.getUserMedia = c => new Promise(res => setTimeout(
        () => real(c).then(s => { window.__ptt_tracks.push(...s.getTracks()); res(s); }), 1200));
    })()`);
    await touchHold(cdp, 500);
    // Over when the button is back at rest — the delayed getUserMedia has
    // resolved and the session was dropped — and then once the stream it
    // handed over has been stopped. The page stops the tracks in the
    // recorder's onstop, which fires after the button is repainted, so the
    // count is waited on rather than sampled; a leak still reads as live here
    // once the wait expires.
    await sessionOver(cdp);
    await waitFor(cdp, 'window.__liveTracks() === 0');
    {
      const s = await state(cdp);
      out.slow_microphone_recovers = {
        title: s.title,
        recording_after: s.recording,
        disabled_after: s.disabled,
        label_after: s.label,
        transcribe_requests: transcribes(),
        live_tracks: await cdp.eval('window.__liveTracks()'),
      };
    }
    // ── the glasses link ────────────────────────────────────────────────────
    //
    // Same gesture, a second implementation. /glasses is a standalone document
    // that loads no bundle — it cannot share 15-voice.js and keep the size that
    // lets the wearable fetch it — so its copy of push-to-talk has to be
    // exercised separately or it is not covered at all.
    //
    // Reached by walking the real UI — project row, then "+ Add task". The
    // page's whole script is inside an IIFE, so its state is unreachable from
    // here and there is no shortcut; the hub stubs the two read endpoints that
    // walk needs. Clicking through the DOM is fine for navigation: the gesture
    // under test is dispatched as real touch input below.
    await cdp.send('Page.navigate', {url: BASE + '/glasses'});

    const mustReach = async (expr, what) => {
      if (!(await waitFor(cdp, expr))) throw new Error('timed out waiting for ' + what);
    };

    // openTasks fires on a row carrying data-idx; openAdd on #add.
    await mustReach("!!document.querySelector('#list [data-idx]')", 'the glasses project list');
    await cdp.eval("document.querySelector('#list [data-idx]').click()");
    await mustReach("(() => { const b = document.getElementById('add'); return !!b && b.classList.contains('on'); })()",
                    'the glasses "+ Add task" button');
    await cdp.eval("document.getElementById('add').click()");
    const onAddScreen = "(() => { const b = document.getElementById('dictate'); return !!b && b.classList.contains('on'); })()";
    await mustReach(onAddScreen, 'the glasses dictate button');

    // A completed hold lands on the confirmation screen, which is where the
    // wearer approves a transcript they cannot edit. #back runs goBack, which
    // returns to the screen the transcript came from — the Add screen.
    const backToAdd = async () => {
      if (await cdp.eval(onAddScreen)) return;
      await cdp.eval("document.getElementById('back').click()");
      await mustReach(onAddScreen, 'the glasses Add screen');
    };

    // The same session states as the dashboard's button, painted by this
    // page's own copy (glasses.html): "Starting…", then .rec while live, then
    // disabled while "Transcribing…", then back to its resting label — or, for
    // a transcript, on to the confirmation screen, which hides the button.
    const gIdleLabel = await cdp.eval("(document.getElementById('dictate').textContent || '').trim()");
    const gLive = "document.getElementById('dictate').classList.contains('rec')";
    const gOver = `(() => {
      if ((document.getElementById('title').textContent || '').trim() === 'Add this task?') return true;
      const b = document.getElementById('dictate');
      return !b.classList.contains('rec') && !b.disabled
        && (b.textContent || '').trim() === ${JSON.stringify(gIdleLabel)};
    })()`;

    const gCentre = `(() => {
      const r = document.getElementById('dictate').getBoundingClientRect();
      return {x: r.left + r.width/2, y: r.top + r.height/2};
    })()`;
    // state.view is inside the IIFE, so the screen is read off what it paints:
    // openHeard titles the page "Add this task?" and appends #heard holding the
    // transcript; openAdd titles it "Add task".
    const gState = `(() => {
      const b = document.getElementById('dictate');
      const h = document.getElementById('heard');
      return {
        recording: b.classList.contains('rec'),
        label: (b.textContent || '').trim(),
        msg: (document.getElementById('msg').textContent || '').trim(),
        heard: h ? (h.textContent || '').trim() : '',
        view: (document.getElementById('title').textContent || '').trim(),
        touchAction: getComputedStyle(b).touchAction,
      };
    })()`;
    // gHold is touchHold's counterpart and gHoldAndSpeak holdAndSpeak's, for
    // the same reasons.
    const gHold = async ms => {
      const p = await cdp.eval(gCentre);
      const pt = [{x: p.x, y: p.y, radiusX: 12, radiusY: 12, force: 1, id: 1}];
      const [down, up] = touchStamps(ms);
      await cdp.send('Input.dispatchTouchEvent', {type: 'touchStart', touchPoints: pt, timestamp: down});
      await sleep(ms);
      await cdp.send('Input.dispatchTouchEvent', {type: 'touchEnd', touchPoints: [], timestamp: up});
    };
    const gHoldAndSpeak = async () => {
      const p = await cdp.eval(gCentre);
      const pt = [{x: p.x, y: p.y, radiusX: 12, radiusY: 12, force: 1, id: 1}];
      await cdp.send('Input.dispatchTouchEvent', {type: 'touchStart', touchPoints: pt});
      await waitFor(cdp, gLive);
      await sleep(SPEAK_MS);
      await cdp.send('Input.dispatchTouchEvent', {type: 'touchEnd', touchPoints: []});
    };

    // The microphone is cold again after the navigation, so warm it the same
    // way the dashboard run does before measuring anything.
    await gHold(800);
    await waitFor(cdp, gOver);
    await backToAdd();

    requests = [];
    await gHoldAndSpeak();
    await waitFor(cdp, gOver);
    {
      const s = await cdp.eval(gState);
      out.glasses_hold_transcribes = {
        recording_after: s.recording,
        view: s.view,                       // the confirmation screen
        title: s.heard,                     // the transcript it is asking about
        transcribe_requests: transcribes(),
      };
    }

    await backToAdd();
    requests = [];
    await gHold(120);
    await waitFor(cdp, gOver);
    {
      const s = await cdp.eval(gState);
      out.glasses_tap_sends_nothing = {
        recording_after: s.recording,
        view: s.view,                       // still 'add': nothing was created
        toast: s.msg,
        touch_action: s.touchAction,
        transcribe_requests: transcribes(),
      };
    }
  } catch (err) {
    out.error = String(err && err.stack ? err.stack : err);
  } finally {
    try { proc.kill('SIGKILL'); } catch (e) {}
    try { fs.rmSync(dir, {recursive: true, force: true}); } catch (e) {}
  }
  process.stdout.write(JSON.stringify(out, null, 2));
  process.exit(0);
}

main();
