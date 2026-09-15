// glasses_browser.js — drives the display-glasses page in a real browser
// (Task 20279).
//
// Every other gate on assets/glasses.html runs the page under
// testdata/glassesdom.js, and that shim delivers exactly one kind of input:
// a keydown. That is not a limitation of the shim so much as a restatement of
// what the page believed about the device — and the telemetry from a real
// Ray-Ban Display session says the belief is wrong. In that trail a pinch
// arrived as `Enter` (keyCode 13) and was handled correctly, while a sideways
// swipe produced no key of any spelling: not ArrowLeft, not Left, not a
// keyCode the tables missed. The handler records `unmapped: <key>` for a
// keydown it does not recognise, and there is not one such row.
//
// So a swipe on this device is not a key. It is a touch, which is also what
// the wearer described twice: sideways gestures moved a scrollbar. A shim
// cannot express that, because touch, scrolling, layout and touch-action are
// all the browser's. This runs the shipped page in Chromium with touch
// emulation and swipes at it.
//
// Usage: node glasses_browser.js <chrome-binary> <base-url>
// Prints one JSON document on stdout: {scenario: {...}, ...}.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ── a minimal CDP client ────────────────────────────────────────────────────
// Same shape as testdata/ptt_browser.js. Duplicated rather than shared because
// these two drivers are each a single file that node runs directly, and a
// require() between them would make the pair a package with a load order.

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
  async eval(expr) {
    const r = await this.send('Runtime.evaluate', {
      expression: expr, awaitPromise: true, returnByValue: true,
    });
    if (r.exceptionDetails) {
      throw new Error('eval failed: ' +
        JSON.stringify(r.exceptionDetails.exception || r.exceptionDetails));
    }
    return r.result.value;
  }
}

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-glasses-'));
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    // Root on the dev box, unprivileged in CI: the sandbox needs privileges it
    // does not have in the first case. A throwaway profile loading a local
    // httptest server is safe without it.
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe']});

  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });

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

// The display is small and the list is long, so the page scrolls — which is the
// state the whole report is about. A viewport that fits everything would hide
// the interaction between the reading axis and the selection axis.
const VIEW_W = 480, VIEW_H = 420;

async function boot(cdp) {
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');

  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: VIEW_W, height: VIEW_H, deviceScaleFactor: 2, mobile: true,
  });
  // The device is a touchscreen-class client with no pointer and no keyboard.
  await cdp.send('Emulation.setTouchEmulationEnabled', {enabled: true, maxTouchPoints: 5});

  const loaded = new Promise(res => cdp.on(m => { if (m.method === 'Page.loadEventFired') res(); }));
  // The link authenticates from the query string; the stub API ignores it, but
  // the page reads it and it must be present or the page runs its dead-link
  // path instead of its normal one.
  await cdp.send('Page.navigate', {url: BASE + '/glasses?token=probe-token'});
  await loaded;
  await waitForRows(cdp);
}

// waitForRows blocks until the project list has painted.
async function waitForRows(cdp) {
  for (let i = 0; i < 200; i++) {
    const n = await cdp.eval("document.querySelectorAll('#list .row').length");
    if (n > 0) return n;
    await sleep(25);
  }
  throw new Error('project rows never appeared');
}

// ── reading the cursor from outside the IIFE ────────────────────────────────
// The page's script is an IIFE, so `cursor` is unreachable. It is observable
// though: select() puts `.sel` on the cursor node, which is the same thing the
// wearer sees. Every assertion below is therefore made on what is on screen.

const CURSOR = `(() => {
  const ring = Array.from(document.querySelectorAll('.focusable'))
    .filter(n => !n.hidden && !n.disabled);
  const sel = document.querySelector('.sel');
  const active = document.activeElement;
  return {
    ring: ring.length,
    at: sel ? ring.indexOf(sel) : -1,
    label: sel ? (sel.textContent || '').trim().slice(0, 40) : '',
    id: sel ? (sel.id || sel.dataset.key || '') : '',
    activeTag: active ? active.tagName.toLowerCase() : '',
    activeIsRing: !!(active && ring.indexOf(active) >= 0),
    scrollY: Math.round((document.scrollingElement || document.documentElement).scrollTop),
    // The page keeps its view in an IIFE-local; the header is the observable
    // proxy, and the only thing a scenario here needs it for is "did we in fact
    // move between screens".
    title: (document.getElementById('title').textContent || '').trim(),
  };
})()`;

const cursorNow = cdp => cdp.eval(CURSOR);

// ── input ───────────────────────────────────────────────────────────────────

async function key(cdp, k, code, which) {
  const base = {key: k, code: code, windowsVirtualKeyCode: which, nativeVirtualKeyCode: which};
  await cdp.send('Input.dispatchKeyEvent', {type: 'rawKeyDown', ...base});
  await cdp.send('Input.dispatchKeyEvent', {type: 'keyUp', ...base});
  await sleep(40);
}

// swipe drags one finger across the middle of the display.
//
// dx/dy are the finger's travel. The move is broken into steps because a
// single jump from start to end is not what a touchscreen produces, and a
// recogniser that only ever sees one touchmove is not the one the device will
// exercise. The pause before touchEnd matters for the same reason: the
// compositor decides which axis it is claiming from the first few moves.
async function swipe(cdp, dx, dy, steps = 8) {
  const x0 = VIEW_W / 2, y0 = VIEW_H / 2;
  const pt = (x, y) => [{x, y, radiusX: 12, radiusY: 12, force: 1, id: 1}];
  await cdp.send('Input.dispatchTouchEvent', {type: 'touchStart', touchPoints: pt(x0, y0)});
  for (let i = 1; i <= steps; i++) {
    await cdp.send('Input.dispatchTouchEvent', {
      type: 'touchMove', touchPoints: pt(x0 + dx * i / steps, y0 + dy * i / steps),
    });
    await sleep(12);
  }
  await cdp.send('Input.dispatchTouchEvent', {type: 'touchEnd', touchPoints: []});
  await sleep(90);
}

// ── scenarios ───────────────────────────────────────────────────────────────

const out = {};

// The keydown path, which the shim suite already covers, re-checked here so a
// touch recogniser that breaks it fails loudly rather than silently trading one
// channel for the other.
async function keyboardStillWalksTheRing(cdp) {
  await cdp.eval("document.querySelectorAll('#list .row')[0].focus()");
  const before = await cursorNow(cdp);
  await key(cdp, 'ArrowRight', 'ArrowRight', 39);
  const right = await cursorNow(cdp);
  await key(cdp, 'ArrowLeft', 'ArrowLeft', 37);
  const left = await cursorNow(cdp);
  out.keyboard = {before, right, left};
}

// The scenario the device is actually in. No key is sent at all — only a
// fingertip moving sideways, which is what the trail says a swipe is.
async function sidewaysTouchMovesTheCursor(cdp) {
  const start = await cursorNow(cdp);
  await swipe(cdp, -160, 0);       // finger travels left: "next"
  const next = await cursorNow(cdp);
  await swipe(cdp, -160, 0);
  const next2 = await cursorNow(cdp);
  await swipe(cdp, 160, 0);        // and back: "previous"
  const prev = await cursorNow(cdp);
  out.sideways = {start, next, next2, prev};
}

// The half of the report the wearer asked to keep: up and down are for reading.
async function verticalTouchStillScrolls(cdp) {
  await cdp.eval("(document.scrollingElement||document.documentElement).scrollTop = 0");
  await sleep(50);
  const before = await cursorNow(cdp);
  await swipe(cdp, 0, -200, 10);   // finger travels up: page scrolls down
  await sleep(150);
  const after = await cursorNow(cdp);
  out.vertical = {before, after};
}

// The defect the trail shows directly: one gesture ended with `after: -1` on a
// ring of 6. Between the view switch and the list landing, the page had a
// non-empty ring and no cursor — and on a device whose key events are aimed at
// document.activeElement, no focused element either. The stub delays
// /api/glasses/tasks so that window is wide enough to sample.
async function navigationNeverDropsTheCursor(cdp) {
  await cdp.eval("(document.scrollingElement||document.documentElement).scrollTop = 0");
  await sleep(50);
  // Put the cursor on a project row and activate it the way a pinch does.
  await cdp.eval("document.querySelectorAll('#list .row')[0].focus()");
  await key(cdp, 'ArrowRight', 'ArrowRight', 39);
  const before = await cursorNow(cdp);
  await key(cdp, 'Enter', 'Enter', 13);

  // Sample across the whole in-flight window rather than once: the question is
  // whether the cursor is ever lost, not whether it happens to be present at
  // some convenient instant.
  const samples = [];
  for (let i = 0; i < 24; i++) {
    samples.push(await cursorNow(cdp));
    await sleep(25);
  }
  const settled = await cursorNow(cdp);
  out.navigation = {
    before, settled, samples,
    worst: samples.reduce((w, s) => (s.at < w.at ? s : w), samples[0]),
    // A swipe landing inside that window has to work too — it is the one the
    // wearer makes while waiting for a slow tether.
    unfocusedSamples: samples.filter(s => !s.activeIsRing).length,
  };
}

// A swipe made during the in-flight window, which is where the trail ends.
async function swipeDuringNavigationIsNotLost(cdp) {
  await cdp.eval("history.length");                   // no-op, keeps ordering clear
  await backToProjects(cdp);
  await cdp.eval("document.querySelectorAll('#list .row')[0].focus()");
  await key(cdp, 'ArrowRight', 'ArrowRight', 39);
  await key(cdp, 'Enter', 'Enter', 13);
  await sleep(30);                                    // still fetching
  const during = await cursorNow(cdp);
  await swipe(cdp, -160, 0);
  const after = await cursorNow(cdp);
  out.midFlight = {during, after};
}

async function backToProjects(cdp) {
  await cdp.eval(`(() => {
    const b = document.getElementById('back');
    if (b && !b.hidden) { b.click(); }
  })()`);
  await waitForRows(cdp);
  await sleep(120);
}

// What the page reports about the gesture it just saw. This is the metric the
// investigation needed and did not have: the trail could say "a key arrived and
// was unmapped", but had no way to say "no key arrived, a touch did".
async function telemetryNamesTheChannel(cdp) {
  await backToProjects(cdp);
  // The page batches and flushes at 32 events, or after ten seconds. A gesture
  // costs two events, so swiping past the threshold is the deterministic way to
  // make a batch leave the device without waiting out the timer.
  const swipes = 20;
  for (let i = 0; i < swipes; i++) { await swipe(cdp, -160, 0); }
  await sleep(700);
  out.telemetry = {swipes};
}

// ── main ────────────────────────────────────────────────────────────────────

(async () => {
  let chrome;
  try {
    chrome = await launchChrome();
    const {cdp} = chrome;
    await boot(cdp);

    await keyboardStillWalksTheRing(cdp);
    await sidewaysTouchMovesTheCursor(cdp);
    await verticalTouchStillScrolls(cdp);
    await navigationNeverDropsTheCursor(cdp);
    await swipeDuringNavigationIsNotLost(cdp);
    await telemetryNamesTheChannel(cdp);

    process.stdout.write(JSON.stringify(out, null, 2));
  } catch (e) {
    process.stderr.write('driver failed: ' + (e && e.stack || e) + '\n');
    process.stdout.write(JSON.stringify({error: String(e && e.message || e)}));
    process.exitCode = 1;
  } finally {
    if (chrome) {
      try { chrome.proc.kill('SIGKILL'); } catch (e) {}
      try { fs.rmSync(chrome.dir, {recursive: true, force: true}); } catch (e) {}
    }
  }
})();
