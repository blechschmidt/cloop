// overlay_browser.js — drives modal focus containment in a real browser
// (Task 20288).
//
// Why a browser and not testdata/domshim.js, which every other frontend gate in
// this package uses: every property this file asserts is one the shim does not
// have.
//
//   * Focusability is a layout question. "Is this element focusable" means "is
//     it rendered, not display:none, not inside an [inert] subtree, not
//     disabled" — and the shim models no layout at all, so it cannot answer it.
//   * Tab is the user agent's. Nothing in the page moves focus on Tab; the
//     browser does, and the whole point of the containment handler is to
//     override that default at the two edges of the dialog. A shim that never
//     moves focus on Tab cannot fail this test, which is exactly why it is
//     worth running: the bug is invisible without one.
//   * `inert` is enforced by the browser, not by the page. The attribute is
//     what actually stops a click or a Tab reaching the controls behind the
//     dialog; asserting it is set is not the same as asserting it works.
//   * document.activeElement only means something where focus is real.
//
// The fixture is the executor-enrolment dialog, chosen because its form is
// static markup with five focusable controls — enough for first/last wrapping
// to be a real question — and because opening it needs no project, no task and
// no backend data, so nothing here depends on a seeded state.db.
//
// Usage: node overlay_browser.js <chrome-binary> <base-url>
// Prints one JSON document on stdout: {scenario: {...}, ...}.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];

const OVERLAY = 'enroll-overlay';
const OPEN_FN = 'openEnrollModal';
// A header tab button: always rendered, never gated, and a plausible place for
// focus to be sitting when a dialog is opened. The in-panel "+ Enroll device"
// button would be more faithful but lives in a tab that is hidden until
// switched to and is permission-gated, so it cannot be relied on to be
// focusable; the driver prefers it when it is, and says which it used.
const FALLBACK_INVOKER = 'tbtn-executors';

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ── a minimal CDP client ────────────────────────────────────────────────────

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id === undefined) return;
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    });
  }
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
      throw new Error('eval failed: ' + JSON.stringify(r.exceptionDetails.exception || r.exceptionDetails));
    }
    return r.result.value;
  }

  // ── input ──
  async key(key, code, vk, modifiers) {
    const base = {key, code, windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk, modifiers: modifiers || 0};
    await this.send('Input.dispatchKeyEvent', Object.assign({type: 'rawKeyDown'}, base));
    await this.send('Input.dispatchKeyEvent', Object.assign({type: 'keyUp'}, base));
    await sleep(15);
  }
  tab(shift)  { return this.key('Tab', 'Tab', 9, shift ? 8 : 0); }
  escape()    { return this.key('Escape', 'Escape', 27, 0); }
  ctrlK()     { return this.key('k', 'KeyK', 75, 2); }
  async clickAt(x, y) {
    const base = {x, y, button: 'left', clickCount: 1};
    await this.send('Input.dispatchMouseEvent', Object.assign({type: 'mousePressed'}, base));
    await this.send('Input.dispatchMouseEvent', Object.assign({type: 'mouseReleased'}, base));
    await sleep(30);
  }
}

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-overlay-'));
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    // Same reasoning as testdata/ptt_browser.js: this suite runs as root on the
    // project's dev box and unprivileged in CI, and the profile is a throwaway
    // loading only a local httptest server.
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--window-size=1280,900',
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
  return {proc, port, dir};
}

async function connect(port) {
  const res = await fetch('http://127.0.0.1:' + port + '/json/list');
  const targets = await res.json();
  const page = targets.find(t => t.type === 'page');
  if (!page) throw new Error('no page target');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((ok, bad) => {
    ws.addEventListener('open', ok, {once: true});
    ws.addEventListener('error', () => bad(new Error('CDP socket failed')), {once: true});
  });
  return new CDP(ws);
}

// ── page helpers, evaluated in the document ─────────────────────────────────

// describeActive reports what currently holds focus and whether it is inside
// the dialog. Returned as data rather than asserted here so the Go test owns
// every judgement and its failure messages can explain what broke.
const ACTIVE = id => `(() => {
  const a = document.activeElement;
  const ov = document.getElementById(${JSON.stringify(id)});
  return {
    id: a ? (a.id || '') : '',
    tag: a ? a.tagName : '',
    inDialog: !!(a && ov && ov.contains(a)),
    isBody: a === document.body,
  };
})()`;

const FOCUSABLE_IDS = id => `(() => {
  const ov = document.getElementById(${JSON.stringify(id)});
  if (!ov || !window.overlayFocusables) return [];
  return window.overlayFocusables(ov).map(e => e.id || e.textContent.trim().slice(0, 20));
})()`;

async function openFixture(cdp, invokerId) {
  await cdp.eval(`(() => {
    const b = document.getElementById(${JSON.stringify(invokerId)});
    if (b) b.focus();
    window.${OPEN_FN}();
    return true;
  })()`);
  await sleep(60);
}

async function closeFixture(cdp) {
  await cdp.eval(`window.closeEnrollModal && window.closeEnrollModal()`);
  await sleep(40);
}

// ── scenarios ───────────────────────────────────────────────────────────────

async function run(cdp) {
  const out = {};

  // Pick the most faithful invoker that is actually focusable.
  const invoker = await cdp.eval(`(() => {
    // The real in-panel button, if the Executors tab will show it.
    if (typeof switchTab === 'function') { try { switchTab('executors'); } catch (e) {} }
    const real = Array.from(document.querySelectorAll('button'))
      .find(b => (b.getAttribute('onclick') || '').indexOf('${OPEN_FN}') === 0
                 && !b.disabled && b.getClientRects().length);
    if (real) { if (!real.id) real.id = '_test_enroll_invoker'; return real.id; }
    return ${JSON.stringify(FALLBACK_INVOKER)};
  })()`);

  out.preflight = {
    invoker_id: invoker,
    login_overlay_open: await cdp.eval(`!!(window.isOverlayOpen && window.isOverlayOpen('loginOverlay'))`),
    helper_present: await cdp.eval(`typeof window.openOverlay === 'function'`),
    focusables: [],
  };

  // 1. Opening moves focus inside, onto the control the caller named.
  await openFixture(cdp, invoker);
  // Counted with the dialog open: a hidden dialog has no focusable controls at
  // all, so measuring before this point reports zero and every count-derived
  // assertion below becomes vacuous.
  out.preflight.focusables = await cdp.eval(FOCUSABLE_IDS(OVERLAY));
  out.focus_starts_inside = {
    active: await cdp.eval(ACTIVE(OVERLAY)),
    focusables: out.preflight.focusables,
    aria_modal: await cdp.eval(`document.getElementById('${OVERLAY}').getAttribute('aria-modal')`),
    role: await cdp.eval(`document.getElementById('${OVERLAY}').getAttribute('role')`),
  };

  // 2. Tab walks the dialog and wraps from the last control back to the first.
  {
    const n = out.preflight.focusables.length;
    const seen = [];
    for (let i = 0; i < n + 1; i++) {
      await cdp.tab(false);
      seen.push(await cdp.eval(ACTIVE(OVERLAY)));
    }
    out.tab_cycles_forward = {sequence: seen, count: n};
  }

  // 3. Shift+Tab off the first control wraps to the last, rather than reaching
  //    the page behind the dialog.
  await closeFixture(cdp);
  await openFixture(cdp, invoker);
  await cdp.tab(true);
  out.shift_tab_wraps_backward = {
    active: await cdp.eval(ACTIVE(OVERLAY)),
  };

  // 4. However long the user holds Tab, focus never lands on the page behind.
  //    This is the assertion the whole task is about.
  {
    await closeFixture(cdp);
    await openFixture(cdp, invoker);
    let escaped = null, steps = 0;
    for (let i = 0; i < 14; i++) {
      await cdp.tab(false);
      steps++;
      const a = await cdp.eval(ACTIVE(OVERLAY));
      if (!a.inDialog) { escaped = a; break; }
    }
    out.tab_never_escapes = {escaped, steps};
  }

  // 5. The page behind is inert — the browser's own enforcement, not just an
  //    attribute we set. Focusing a background control must not take.
  out.background_is_inert = await cdp.eval(`(() => {
    const bg = document.getElementById(${JSON.stringify(FALLBACK_INVOKER)});
    if (!bg) return {found: false};
    const before = document.activeElement;
    bg.focus();
    return {
      found: true,
      has_inert_ancestor: !!bg.closest('[inert]'),
      focus_took: document.activeElement === bg,
      focus_unchanged: document.activeElement === before,
    };
  })()`);

  // 6. Closing with the dialog's own button hands focus back to the invoker.
  await closeFixture(cdp);
  await sleep(40);
  out.close_restores_focus = {
    active: await cdp.eval(`(() => { const a=document.activeElement; return {id:a?a.id:'', isBody:a===document.body}; })()`),
    expect: invoker,
    still_inert: await cdp.eval(`!!document.getElementById(${JSON.stringify(FALLBACK_INVOKER)}).closest('[inert]')`),
  };

  // 7. Escape is the second close path, and must restore focus like the first.
  await openFixture(cdp, invoker);
  await cdp.escape();
  await sleep(40);
  out.escape_restores_focus = {
    open: await cdp.eval(`window.isOverlayOpen('${OVERLAY}')`),
    active: await cdp.eval(`(() => { const a=document.activeElement; return {id:a?a.id:'', isBody:a===document.body}; })()`),
    expect: invoker,
  };

  // 8. A backdrop click is the third. (5,5) is on the backdrop itself — the
  //    card is centred — so this is the real `event.target===this` path.
  await openFixture(cdp, invoker);
  await cdp.clickAt(5, 5);
  await sleep(40);
  out.backdrop_click_restores_focus = {
    open: await cdp.eval(`window.isOverlayOpen('${OVERLAY}')`),
    active: await cdp.eval(`(() => { const a=document.activeElement; return {id:a?a.id:'', isBody:a===document.body}; })()`),
    expect: invoker,
  };

  // 9. Two dialogs at once: Escape closes the one in front and leaves focus in
  //    the one behind, which stays open.
  await openFixture(cdp, invoker);
  await cdp.ctrlK();
  await sleep(60);
  const paletteOpen = await cdp.eval(`window.isOverlayOpen('cmd-backdrop')`);
  const paletteFocus = await cdp.eval(ACTIVE('cmd-backdrop'));
  await cdp.escape();
  await sleep(60);
  out.stacked_escape_closes_front_only = {
    palette_open_before: paletteOpen,
    palette_focus_before: paletteFocus,
    palette_open_after: await cdp.eval(`window.isOverlayOpen('cmd-backdrop')`),
    fixture_open_after: await cdp.eval(`window.isOverlayOpen('${OVERLAY}')`),
    active_after: await cdp.eval(ACTIVE(OVERLAY)),
  };
  await cdp.escape();
  await sleep(40);

  // 10. The regression the old Escape chain carried: its last branch ran
  //     document.querySelector('.voice-modal-backdrop').remove() on a *static*
  //     node, so the first Escape anywhere on the page deleted the voice modal
  //     for the life of the document and the next open threw on a null.
  await cdp.escape();
  await cdp.escape();
  await sleep(40);
  out.voice_modal_survives_escape = await cdp.eval(`(() => {
    const present = !!document.getElementById('voiceModalBackdrop');
    let threw = '';
    try { window.openVoiceModal(); } catch (e) { threw = String(e && e.message || e); }
    const open = !!(window.isOverlayOpen && window.isOverlayOpen('voiceModalBackdrop'));
    try { window.closeVoiceModal(); } catch (e) {}
    return {present, open, threw};
  })()`);

  return out;
}

(async () => {
  let chrome;
  try {
    chrome = await launchChrome();
    const cdp = await connect(chrome.port);
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Page.navigate', {url: BASE});

    // Wait for the bundle to have run, not merely for the document to exist.
    let ready = false;
    for (let i = 0; i < 200 && !ready; i++) {
      await sleep(50);
      try {
        ready = await cdp.eval(
          `typeof window.openOverlay === 'function' && !!document.getElementById('${OVERLAY}')`);
      } catch (e) { /* navigating */ }
    }
    if (!ready) throw new Error('dashboard bundle never became ready');
    await sleep(150); // let the first render settle

    const out = await run(cdp);
    process.stdout.write(JSON.stringify(out, null, 2));
  } catch (err) {
    process.stdout.write(JSON.stringify({error: {message: String(err && err.stack || err)}}, null, 2));
    process.exitCode = 1;
  } finally {
    if (chrome) {
      try { chrome.proc.kill('SIGKILL'); } catch (e) {}
      try { fs.rmSync(chrome.dir, {recursive: true, force: true}); } catch (e) {}
    }
  }
})();
