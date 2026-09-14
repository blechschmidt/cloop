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
//     emits a 440 Hz tone, so listenForSound's analyser sees genuine samples
//     and the empty-clip guard is exercised rather than stubbed past.
//
// Chrome is launched with a fake microphone and auto-granted permission, so no
// prompt appears and getUserMedia resolves in milliseconds — the same timing a
// user gets on every hold after the first.
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

const MIN_HOLD_MS = 400;   // must match DICTATE_MIN_HOLD_MS in 15-voice.js

const sleep = ms => new Promise(r => setTimeout(r, ms));

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

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-ptt-'));
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
    // The two flags that make this test possible: a synthetic microphone, and
    // permission granted without a prompt.
    '--use-fake-ui-for-media-stream',
    '--use-fake-device-for-media-stream',
    '--autoplay-policy=no-user-gesture-required',
    'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe']});

  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });

  // Chrome writes the chosen port to DevToolsActivePort once it is listening.
  const portFile = path.join(dir, 'DevToolsActivePort');
  let port = 0;
  for (let i = 0; i < 200 && !port; i++) {
    await sleep(50);
    if (proc.exitCode !== null) throw new Error('chrome exited: ' + stderr);
    try {
      const txt = fs.readFileSync(portFile, 'utf8').split('\n');
      if (txt[0] && txt[0].trim()) port = Number(txt[0].trim());
    } catch (e) { /* not written yet */ }
  }
  if (!port) throw new Error('chrome never reported a debugging port: ' + stderr);

  const list = await (await fetch('http://127.0.0.1:' + port + '/json/list')).json();
  const page = list.find(t => t.type === 'page');
  if (!page) throw new Error('no page target');

  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((res, rej) => {
    ws.addEventListener('open', res, {once: true});
    ws.addEventListener('error', () => rej(new Error('cdp connect failed')), {once: true});
  });
  return {cdp: new CDP(ws), proc, dir};
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
  for (let i = 0; i < 100; i++) {
    const vis = await cdp.eval(`(() => {
      const b = document.getElementById('dictateTaskBtn');
      return !!(b && b.style.display !== 'none' && b.getClientRects().length);
    })()`);
    if (vis) return;
    await sleep(50);
  }
  throw new Error('dictate button never became visible');
}

// warmUp performs one hold whose result is thrown away.
//
// The first getUserMedia of a page's life costs far more than every later one —
// the capture device is being opened — and on this box it routinely outlasts a
// 700ms hold. That is a real condition with deliberate handling (see the
// dictateAbortPending path in 15-voice.js, and slow_microphone_recovers below,
// which pins it), but it is not the condition the gesture scenarios are about.
// Running it once here puts the page in the state a user is in from their
// second hold onwards, which is every hold but one.
async function warmUp(cdp) {
  await touchHold(cdp, 800);
  await sleep(1500);
  await cdp.eval("(() => { const t = document.getElementById('newTaskTitle'); if (t) t.value = ''; })()");
}

// centre returns viewport coordinates of the dictate button.
async function centre(cdp) {
  return cdp.eval(`(() => {
    const r = document.getElementById('dictateTaskBtn').getBoundingClientRect();
    return {x: r.left + r.width/2, y: r.top + r.height/2};
  })()`);
}

async function touchHold(cdp, ms) {
  const p = await centre(cdp);
  const pt = [{x: p.x, y: p.y, radiusX: 12, radiusY: 12, force: 1, id: 1}];
  await cdp.send('Input.dispatchTouchEvent', {type: 'touchStart', touchPoints: pt});
  await sleep(ms);
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

// settle waits for the transcribe round trip and the repaint that follows it.
async function settle(cdp, ms) {
  await sleep(ms || 900);
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
    await touchHold(cdp, 700);
    await settle(cdp);
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
    await settle(cdp);
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
    await reset(cdp);
    {
      const p = await centre(cdp);
      const pt = [{x: p.x, y: p.y, radiusX: 12, radiusY: 12, force: 1, id: 1}];
      await cdp.send('Input.dispatchTouchEvent', {type: 'touchStart', touchPoints: pt});
      await sleep(500);
      const mid = await state(cdp);
      await cdp.send('Input.dispatchTouchEvent', {type: 'touchEnd', touchPoints: []});
      await settle(cdp);
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
    await reset(cdp);
    await mouseClick(cdp);
    await sleep(900);   // long enough for the analyser to see the fake device's tone
    const afterFirst = await state(cdp);
    await mouseClick(cdp);
    await settle(cdp);
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
    await touchHold(cdp, 700);
    await settle(cdp);
    await touchHold(cdp, 700);
    await settle(cdp);
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
    await settle(cdp, 2500);
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
    await sleep(1200);

    const waitFor = async (expr, what) => {
      for (let i = 0; i < 120; i++) {
        if (await cdp.eval(expr)) return;
        await sleep(50);
      }
      throw new Error('timed out waiting for ' + what);
    };

    // openTasks fires on a row carrying data-idx; openAdd on #add.
    await waitFor("!!document.querySelector('#list [data-idx]')", 'the glasses project list');
    await cdp.eval("document.querySelector('#list [data-idx]').click()");
    await waitFor("(() => { const b = document.getElementById('add'); return !!b && b.classList.contains('on'); })()",
                  'the glasses "+ Add task" button');
    await cdp.eval("document.getElementById('add').click()");
    const onAddScreen = "(() => { const b = document.getElementById('dictate'); return !!b && b.classList.contains('on'); })()";
    await waitFor(onAddScreen, 'the glasses dictate button');

    // A completed hold lands on the confirmation screen, which is where the
    // wearer approves a transcript they cannot edit. #back runs goBack, which
    // returns to the screen the transcript came from — the Add screen.
    const backToAdd = async () => {
      if (await cdp.eval(onAddScreen)) return;
      await cdp.eval("document.getElementById('back').click()");
      await waitFor(onAddScreen, 'the glasses Add screen');
    };

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
    const gHold = async ms => {
      const p = await cdp.eval(gCentre);
      const pt = [{x: p.x, y: p.y, radiusX: 12, radiusY: 12, force: 1, id: 1}];
      await cdp.send('Input.dispatchTouchEvent', {type: 'touchStart', touchPoints: pt});
      await sleep(ms);
      await cdp.send('Input.dispatchTouchEvent', {type: 'touchEnd', touchPoints: []});
    };

    // The microphone is cold again after the navigation, so warm it the same
    // way the dashboard run does before measuring anything.
    await gHold(800);
    await sleep(1800);
    await backToAdd();

    requests = [];
    await gHold(700);
    await settle(cdp, 1400);
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
    await settle(cdp, 1200);
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
