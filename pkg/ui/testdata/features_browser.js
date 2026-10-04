// features_browser.js — drives parallel features through the dashboard in a
// real browser (Task 20341).
//
// The DOM shim (features_scenarios.js) proves which index every action is
// addressed to; it cannot prove a person can reach them. The feature panels
// use delegated listeners — no inline handler ever sees a feature's name or
// branch — and the shim's addEventListener is a no-op, so only a browser can
// show that clicking a chip, a row's Open or the banner's back link actually
// navigates, and that the dialogs open, take focus and close on Escape. Clicks
// are real mouse events at the element's centre.
//
// Usage: node features_browser.js <chrome-binary> <base-url> <parent-name>
// Prints one JSON document on stdout: {scenario: {...}, ...}.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const PARENT = process.argv[4];

const sleep = ms => new Promise(r => setTimeout(r, ms));

// Chrome runs in its own process group (spawned detached), so one signal takes
// its helpers with it; killing only the browser leaves them writing into a
// profile that is being deleted.
function killChrome(proc) {
  try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) {
    try { proc.kill('SIGKILL'); } catch (_) { /* already gone */ }
  }
}

// closeChrome kills Chrome, waits for it to be gone (bounded, and unref'd so
// the wait cannot hold node open) and removes the profile, retrying while the
// last helpers let go of it. Best effort: cleanup never fails a run.
async function closeChrome(proc, dir) {
  killChrome(proc);
  if (proc.exitCode === null && proc.signalCode === null) {
    await new Promise(r => { proc.once('exit', r); setTimeout(r, 5000).unref(); });
  }
  try { fs.rmSync(dir, {recursive: true, force: true, maxRetries: 10, retryDelay: 100}); } catch (_) { /* best effort */ }
}

// A minimal CDP client, the same shape as sandbox_browser.js's; duplicated for
// the reason given there.
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
      clearTimeout(p.timer);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    });
  }
  send(method, params) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      // Cleared when the answer arrives: left pending, each call's timer held
      // node open for up to 20 s after the driver had finished.
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(method + ' timed out'));
      }, 20000);
      this.pending.set(id, {resolve, reject, timer});
      this.ws.send(JSON.stringify({id, method, params: params || {}}));
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-features-'));
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--window-size=1400,1000',
    'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe'], detached: true});

  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });

  // A launch that fails after the spawn must take Chrome with it. Left
  // running, it holds this process's stderr pipe open, node never exits,
  // and the Go test waiting on node hangs until the package timeout — the
  // 20-minute CI hang Task 20340 traced to a Chrome slow to report its port.
  try {
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

    // Both steps are bounded: a Chrome that accepts the connection and never
    // answers would otherwise hang this driver, and the test waiting on it, with
    // nothing to say why.
    const list = await (await fetch('http://127.0.0.1:' + port + '/json/list',
      {signal: AbortSignal.timeout(15000)})).json();
    const page = list.find(t => t.type === 'page');
    if (!page) throw new Error('no page target');

    const ws = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((res, rej) => {
      const timer = setTimeout(() => rej(new Error('cdp connect timed out')), 15000);
      ws.addEventListener('open', () => { clearTimeout(timer); res(); }, {once: true});
      ws.addEventListener('error', () => { clearTimeout(timer); rej(new Error('cdp connect failed')); }, {once: true});
    });
    return {cdp: new CDP(ws), proc, dir};
  } catch (e) {
    killChrome(proc);
    throw e;
  }
}

// ── helpers ─────────────────────────────────────────────────────────────────

// visible asks the layout engine: display:none on the element or any ancestor
// leaves it with no client rects.
const visibleExpr = sel =>
  `(() => { const e = document.querySelector(${JSON.stringify(sel)});
     return !!e && e.getClientRects().length > 0; })()`;

// click scrolls an element into view and clicks its centre with the mouse.
//
// It waits for the element to be there, laid out and on top first, for up to
// five seconds: the dashboard re-renders panels as its own start-up requests
// land, and on a loaded machine that can still be happening when a scenario
// begins. A button that never becomes clickable is still a failure.
async function click(cdp, sel) {
  let pt = null, hit = false;
  for (let i = 0; i < 100 && !hit; i++) {
    if (i) await sleep(50);
    pt = await cdp.eval(`(() => {
      const e = document.querySelector(${JSON.stringify(sel)});
      if (!e) return null;
      e.scrollIntoView({block: 'center'});
      const r = e.getBoundingClientRect();
      if (!r.width || !r.height) return null;
      return {x: r.left + r.width / 2, y: r.top + r.height / 2};
    })()`);
    if (!pt) continue;
    // What is actually on top at that point is what the click lands on.
    hit = await cdp.eval(`(() => {
      const e = document.elementFromPoint(${pt.x}, ${pt.y});
      const want = document.querySelector(${JSON.stringify(sel)});
      return !!e && !!want && (e === want || want.contains(e));
    })()`);
  }
  if (!pt) throw new Error('nothing clickable at ' + sel);
  if (!hit) throw new Error(sel + ' is covered by another element');
  for (const type of ['mousePressed', 'mouseReleased']) {
    await cdp.send('Input.dispatchMouseEvent', {type, x: pt.x, y: pt.y, button: 'left', clickCount: 1});
  }
}

// A deadline rather than a count of polls: on a loaded machine — the whole
// suite running beside this test — creating a feature through the stub CLI and
// the dashboard's refresh after it can take several seconds, and each poll is
// itself a CDP round trip of unbounded length.
async function waitFor(cdp, expr, what, ms = 30000) {
  const deadline = Date.now() + ms;
  for (;;) {
    if (await cdp.eval(expr)) return;
    if (Date.now() > deadline) throw new Error('timed out waiting for ' + what);
    await sleep(50);
  }
}


const crumb = cdp => cdp.eval(`(document.getElementById('breadcrumbName') || {}).textContent || ''`);

async function waitCrumb(cdp, want) {
  await waitFor(cdp, `(document.getElementById('breadcrumbName') || {}).textContent === ${JSON.stringify(want)}`,
    'the breadcrumb to read ' + want);
}

async function boot(cdp) {
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Page.navigate', {url: BASE + '/'});
  await waitFor(cdp, `typeof window.openNewFeatureModal === 'function' && typeof window.switchTab === 'function'`,
    'the bundle to load');
  await waitFor(cdp, `!!window._lastProjectsData && window._lastProjectsData.projects.length >= 4`, 'the project list');
}

async function key(cdp, k) {
  for (const type of ['keyDown', 'keyUp']) {
    await cdp.send('Input.dispatchKeyEvent', {type, key: k, code: k, windowsVirtualKeyCode: k === 'Escape' ? 27 : 0});
  }
}

const results = {};

async function scenarioChipOpensFeature(cdp) {
  await cdp.eval(`window.switchTab('projects')`);
  await waitFor(cdp, visibleExpr('.feat-chip[data-open-idx="2"]'), 'the feature chips on the project card');
  const chips = await cdp.eval(`document.querySelectorAll('#projList .feat-chip').length`);
  const cards = await cdp.eval(`document.querySelectorAll('#projList .proj-card').length`);
  await click(cdp, '.feat-chip[data-open-idx="2"]');
  await waitCrumb(cdp, PARENT + '/login');
  await waitFor(cdp, visibleExpr('#featureBanner'), 'the feature banner');
  results.chip_opens_feature = {
    chips, cards,
    banner_names_branch: await cdp.eval(`document.getElementById('featureBanner').textContent.indexOf('cloop/feature/login') >= 0`),
    features_section_hidden: !(await cdp.eval(visibleExpr('#featuresSection'))),
  };
}

async function scenarioBannerReturnsToParent(cdp) {
  await click(cdp, '#featureBanner [data-act="parent"]');
  await waitCrumb(cdp, PARENT);
  await waitFor(cdp, visibleExpr('#featuresSection .feat-row'), 'the parent\'s features list');
  results.banner_returns_to_parent = {
    rows: await cdp.eval(`document.querySelectorAll('#featuresList .feat-row').length`),
    banner_hidden: !(await cdp.eval(visibleExpr('#featureBanner'))),
  };
}

async function scenarioRowOpens(cdp) {
  await click(cdp, '.feat-row[data-idx="3"] button[data-act="open"]');
  await waitCrumb(cdp, PARENT + '/dark-mode');
  results.row_opens = {crumb: await crumb(cdp)};
  await click(cdp, '#featureBanner [data-act="parent"]');
  await waitCrumb(cdp, PARENT);
}

async function scenarioNewFeature(cdp) {
  await waitFor(cdp, visibleExpr('#newFeatureBtn'), 'the New feature button');
  await click(cdp, '#newFeatureBtn');
  await waitFor(cdp, visibleExpr('#newfeat-overlay'), 'the New feature dialog');
  const focused = await cdp.eval(`document.activeElement && document.activeElement.id`);
  await cdp.send('Input.insertText', {text: 'Payments'});
  const slugHint = await cdp.eval(`document.getElementById('nfSlug').textContent`);
  await click(cdp, '#nfDesc');
  await cdp.send('Input.insertText', {text: 'Take payments'});
  await click(cdp, '#nfStart'); // untick: this stub hub cannot run it
  await click(cdp, '#nfSubmit');
  await waitCrumb(cdp, PARENT + '/payments');
  // The Overview paints when the new feature's first state frame arrives.
  let banner = true;
  try {
    await waitFor(cdp, visibleExpr('#featureBanner'), 'the new feature\'s banner');
  } catch (e) {
    banner = false;
  }
  results.new_feature = {
    focused, slug_hint: slugHint,
    dialog_closed: !(await cdp.eval(visibleExpr('#newfeat-overlay'))),
    banner,
  };
  await click(cdp, '#featureBanner [data-act="parent"]');
  await waitCrumb(cdp, PARENT);
}

async function scenarioPRDialogEscape(cdp) {
  await click(cdp, '.feat-row[data-idx="2"] button[data-act="pr"]');
  await waitFor(cdp, visibleExpr('#featpr-overlay'), 'the pull request dialog');
  const title = await cdp.eval(`document.getElementById('fprName').value`);
  const heading = await cdp.eval(`document.getElementById('fprTitle').textContent`);
  const focusInside = await cdp.eval(`document.getElementById('featpr-overlay').contains(document.activeElement)`);
  await key(cdp, 'Escape');
  await waitFor(cdp, `!(${visibleExpr('#featpr-overlay')})`, 'Escape to close the dialog');
  results.pr_dialog = {title, heading, focus_inside: focusInside, closed: true};
}

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  try {
    await boot(cdp);
    await scenarioChipOpensFeature(cdp);
    await scenarioBannerReturnsToParent(cdp);
    await scenarioRowOpens(cdp);
    await scenarioNewFeature(cdp);
    await scenarioPRDialogEscape(cdp);
    process.stdout.write(JSON.stringify(results, null, 2));
  } finally {
    await closeChrome(proc, dir);
  }
}

main().then(() => process.exit(0), err => {
  process.stdout.write(JSON.stringify({error: {message: String(err && err.message || err), partial: results}}, null, 2));
  process.exit(1);
});
