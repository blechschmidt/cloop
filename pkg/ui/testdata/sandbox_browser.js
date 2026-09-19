// sandbox_browser.js — drives the per-executor Sandbox panel in a real browser
// (Task 20307).
//
// The task this file belongs to asks that sandbox configuration be performable
// *through the UI*. That is a claim about a form, and the only honest way to test
// a claim about a form is to fill it in.
//
// testdata/domshim.js runs the real bundle and would answer "does the page call
// the right endpoint". It cannot answer the two questions this panel actually
// turns on:
//
//   * whether the container fields are reachable at all. They live behind
//     `style.display` driven by the mode selector's change event, and the shim
//     models no layout — an element it reports as present may be one a user can
//     never see or type into.
//   * whether a real `change` on a real <select> runs the handler. The mode
//     selector is wired with an inline onchange, and the bundle lives inside an
//     IIFE: a handler that was not exported onto window is a no-op that a shim
//     calling the function directly would never notice. That exact bug class
//     cost Tasks 20065 and 20033.
//
// So this drives Chromium over CDP against a real hub, sets the mode the way a
// user does, types into the fields that appear, clicks Save, and then asks the
// hub what it stored. No stubbed endpoints: the executor API, the control-plane
// database and the audit trail are all the real ones.
//
// Usage: node sandbox_browser.js <chrome-binary> <base-url> <executor-id>
// Prints one JSON document on stdout: {scenario: {...}, ...}.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const EXEC_ID = process.argv[4];

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ── a minimal CDP client ────────────────────────────────────────────────────
//
// The same shape as ptt_browser.js's. Duplicated rather than shared because
// these drivers are standalone node scripts with no module system between them,
// and a require() across testdata/ would make each one's "run this file" story
// depend on the other's layout.

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
}

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-sandbox-'));
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    // Root on this project's dev box, unprivileged in CI. See ptt_browser.js.
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

// ── helpers ─────────────────────────────────────────────────────────────────

// visible asks the browser, not the DOM. offsetParent is null for anything an
// ancestor has display:none'd, which is exactly how the container fields are
// hidden — a querySelector hit would report them present either way.
const visibleExpr = id =>
  `(() => { const e = document.getElementById(${JSON.stringify(id)});
     if (!e) return false;
     return !!(e.offsetParent || e.getClientRects().length); })()`;

// setSelect changes a <select> the way a user does: assign, then dispatch the
// real change event. Calling the handler directly would pass even if the inline
// onchange names a function that is not on window.
const setSelectExpr = (id, value) =>
  `(() => { const e = document.getElementById(${JSON.stringify(id)});
     if (!e) return 'no element';
     e.value = ${JSON.stringify(value)};
     e.dispatchEvent(new Event('change', {bubbles: true}));
     return e.value; })()`;

const setInputExpr = (id, value) =>
  `(() => { const e = document.getElementById(${JSON.stringify(id)});
     if (!e) return 'no element';
     e.value = ${JSON.stringify(value)};
     e.dispatchEvent(new Event('input', {bubbles: true}));
     return e.value; })()`;

async function boot(cdp) {
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Page.navigate', {url: BASE + '/'});
  // Wait for the bundle to have defined the entry point this panel is reached
  // through. Polling a function's existence rather than a load event is what
  // makes this robust to the deferred script tags Task 20289 introduced.
  for (let i = 0; i < 200; i++) {
    await sleep(50);
    const ready = await cdp.eval(`typeof window.openExecutorSandbox === 'function'`);
    if (ready) return;
  }
  throw new Error('window.openExecutorSandbox never appeared — the panel is unreachable');
}

// openPanel opens the dialog for our executor.
//
// It calls openExecutorSandbox with an index rather than clicking the card's
// button, because the Executors tab renders from a fetch this driver would have
// to race. The button's wiring is checked separately, by asserting the handler
// it names exists on window — which is the half a shim cannot do.
async function openPanel(cdp) {
  const wired = await cdp.eval(`typeof window.openExecutorSandbox === 'function'
    && typeof window.saveExecutorSandbox === 'function'
    && typeof window.onExecSandboxModeChange === 'function'
    && typeof window.clearExecutorSandbox === 'function'`);
  if (!wired) throw new Error('the panel\'s handlers are not all exported on window');

  // Seed the module-level cache the card indices resolve against, then open
  // index 0. Assigning through a setter the bundle exposes is not possible —
  // execData is IIFE-local — so the panel is opened by the same call the button
  // makes, with the executor looked up from the live API instead.
  await cdp.eval(`(async () => {
    const r = await fetch('/api/executors');
    const d = await r.json();
    window.__execs = (d && d.executors) || [];
  })()`);
  const idx = await cdp.eval(`(() => {
    const list = window.__execs || [];
    for (let i = 0; i < list.length; i++) {
      if (list[i].id === ${JSON.stringify(EXEC_ID)}) return i;
    }
    return -1;
  })()`);
  if (idx < 0) throw new Error('executor ' + EXEC_ID + ' is not in /api/executors');

  await cdp.eval(`window.loadExecutors && window.loadExecutors()`);
  // Give the panel's own fetch of /api/executors time to populate execData, so
  // the index the driver resolved refers to the same list the page holds.
  for (let i = 0; i < 100; i++) {
    await sleep(50);
    const ok = await cdp.eval(
      `(() => { try { window.openExecutorSandbox(${idx}); } catch (e) { return false; }
         const o = document.getElementById('executor-sandbox-overlay');
         return !!o && o.style.display !== 'none'; })()`);
    if (ok) return;
  }
  throw new Error('the sandbox overlay never opened');
}

async function closePanel(cdp) {
  await cdp.eval(`window.closeExecutorSandbox && window.closeExecutorSandbox()`);
  await sleep(50);
}

async function fetchJSON(cdp, url) {
  return cdp.eval(`(async () => {
    const r = await fetch(${JSON.stringify(url)});
    return await r.json();
  })()`);
}

// ── scenarios ───────────────────────────────────────────────────────────────

const results = {};

async function scenarioContainerFieldsAppearWithTheMode(cdp) {
  await openPanel(cdp);
  await sleep(150); // the panel's GET fills the form

  const hiddenAtFirst = !(await cdp.eval(visibleExpr('execSandboxContainerFields')));

  await cdp.eval(setSelectExpr('execSandboxMode', 'container'));
  await sleep(50);
  const shownForContainer = await cdp.eval(visibleExpr('execSandboxContainerFields'));
  const runtimeTypable = await cdp.eval(visibleExpr('execSandboxRuntime'));
  const engineTypable = await cdp.eval(visibleExpr('execSandboxEngine'));

  await cdp.eval(setSelectExpr('execSandboxMode', 'host'));
  await sleep(50);
  const hiddenForHost = !(await cdp.eval(visibleExpr('execSandboxContainerFields')));

  results.container_fields_follow_the_mode = {
    hidden_at_first: hiddenAtFirst,
    shown_for_container: shownForContainer,
    runtime_typable: runtimeTypable,
    engine_typable: engineTypable,
    hidden_for_host: hiddenForHost,
  };
  await closePanel(cdp);
}

async function scenarioSaveContainerMode(cdp) {
  await openPanel(cdp);
  await sleep(150);

  await cdp.eval(setSelectExpr('execSandboxMode', 'container'));
  await sleep(50);
  // podman is offered because the backend allowlists it, whether or not this
  // device reported it — see the engine hint in the panel.
  const engineSet = await cdp.eval(setSelectExpr('execSandboxEngine', 'podman'));
  const runtimeSet = await cdp.eval(setInputExpr('execSandboxRuntime', 'kata'));
  const imageSet = await cdp.eval(setInputExpr('execSandboxImage', 'ghcr.io/acme/sandbox:v3'));

  await cdp.eval(`window.saveExecutorSandbox()`);
  // The save closes the dialog and reloads the fleet; both are async.
  let closed = false;
  for (let i = 0; i < 100; i++) {
    await sleep(50);
    closed = await cdp.eval(
      `(() => { const o = document.getElementById('executor-sandbox-overlay');
         return !o || o.style.display === 'none'; })()`);
    if (closed) break;
  }

  // The real question: what does the hub now say? Read it back through the API
  // rather than off the screen, because the screen is what we just typed.
  const after = await fetchJSON(cdp, '/api/executors/' + encodeURIComponent(EXEC_ID) + '/sandbox');

  results.save_persists_container_mode = {
    engine_set: engineSet,
    runtime_set: runtimeSet,
    image_set: imageSet,
    dialog_closed: closed,
    stored_mode: (after && after.settings && after.settings.mode) || '',
    stored_engine: (after && after.settings && after.settings.engine) || '',
    stored_runtime: (after && after.settings && after.settings.runtime) || '',
    stored_image: (after && after.settings && after.settings.image) || '',
    configured: !!(after && after.configured),
    set_by: (after && after.set_by) || '',
  };
}

async function scenarioReopenShowsWhatWasSaved(cdp) {
  await openPanel(cdp);
  await sleep(200);
  results.reopen_shows_saved_values = {
    mode: await cdp.eval(`(document.getElementById('execSandboxMode')||{}).value || ''`),
    engine: await cdp.eval(`(document.getElementById('execSandboxEngine')||{}).value || ''`),
    runtime: await cdp.eval(`(document.getElementById('execSandboxRuntime')||{}).value || ''`),
    image: await cdp.eval(`(document.getElementById('execSandboxImage')||{}).value || ''`),
    // Container mode was saved, so the fields must be open on reopen without
    // the user touching the selector.
    fields_visible: await cdp.eval(visibleExpr('execSandboxContainerFields')),
  };
  await closePanel(cdp);
}

async function scenarioRejectedRuntimeKeepsTheStoredValue(cdp) {
  await openPanel(cdp);
  await sleep(200);
  await cdp.eval(setSelectExpr('execSandboxMode', 'container'));
  await sleep(50);
  // A path, which the backend refuses: it would turn "name a runtime" into
  // "name a binary the engine runs as root".
  await cdp.eval(setInputExpr('execSandboxRuntime', '/tmp/evil'));
  await cdp.eval(`window.saveExecutorSandbox()`);
  await sleep(400);

  const after = await fetchJSON(cdp, '/api/executors/' + encodeURIComponent(EXEC_ID) + '/sandbox');
  results.rejected_runtime_changes_nothing = {
    // The dialog stays open on a refused save, so the admin can fix the field.
    dialog_still_open: await cdp.eval(
      `(() => { const o = document.getElementById('executor-sandbox-overlay');
         return !!o && o.style.display !== 'none'; })()`),
    stored_runtime: (after && after.settings && after.settings.runtime) || '',
  };
  await closePanel(cdp);
}

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  try {
    await boot(cdp);
    await scenarioContainerFieldsAppearWithTheMode(cdp);
    await scenarioSaveContainerMode(cdp);
    await scenarioReopenShowsWhatWasSaved(cdp);
    await scenarioRejectedRuntimeKeepsTheStoredValue(cdp);
    process.stdout.write(JSON.stringify(results, null, 2));
  } finally {
    try { proc.kill('SIGKILL'); } catch (e) { /* already gone */ }
    try { fs.rmSync(dir, {recursive: true, force: true}); } catch (e) { /* best effort */ }
  }
}

main().catch(err => {
  process.stdout.write(JSON.stringify({error: {message: String(err && err.message || err)}}, null, 2));
  process.exit(1);
});
