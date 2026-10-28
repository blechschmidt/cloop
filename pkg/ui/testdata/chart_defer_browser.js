// chart_defer_browser.js — proves chart.js is fetched on demand, not on load,
// and that the Analytics tab recovers when that fetch fails (Task 20289).
//
// Why a browser and not testdata/domshim.js, which most frontend gates here
// use: every property this file asserts is one the shim cannot have.
//
//   * "Was it fetched?" is a network question. The shim issues no requests, so
//     it cannot tell a deferred asset from an eager one — which is the entire
//     claim being made.
//   * Loading a script is the user agent's job. ensureChartLib appends a
//     <script> and waits on its load/error events; nothing in the page
//     implements those, so only a real browser can run the path.
//   * The failure path needs a real failed request. Blocking the URL at the
//     protocol level and watching the retry recover is the only way to show
//     the memo is actually cleared rather than replaying its rejection.
//
// Usage: node chart_defer_browser.js <chrome-binary> <base-url>
// Prints one JSON document on stdout.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];

const CHART_URL_RE = /\/assets\/chart\.[0-9a-f]+\.js$/;
// The Analytics tab's own script (Task 20456): its markup — the canvases, the
// banner, Retry — arrives with it, the first time the tab opens.
const PANEL_URL_RE = /\/assets\/analytics\.[0-9a-f]{16}\.js$/;

const sleep = ms => new Promise(r => setTimeout(r, ms));

// waitFor polls a page expression until it is truthy, for at most 30 s: what
// the tab is waited on, rather than a pause a fast machine sits out and a slow
// one overruns.
async function waitFor(cdp, expr, what) {
  const deadline = Date.now() + 30000;
  for (;;) {
    let v = false;
    try { v = await cdp.eval(expr); } catch (e) { /* navigating */ }
    if (v) return v;
    if (Date.now() >= deadline) throw new Error('timed out waiting for ' + what);
    await sleep(25);
  }
}

// How long Chrome gets to report its DevTools port, in 50 ms polls: 90 s.
// A cold start on a CI runner that is also running three race-instrumented
// test binaries has taken longer than the 30 s this used to allow (Task 20372).
const CHROME_START_POLLS = 1800;

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

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.handlers = new Map();
    ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id === undefined) {
        const h = this.handlers.get(msg.method);
        if (h) h(msg.params);
        return;
      }
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    });
  }
  on(method, fn) { this.handlers.set(method, fn); }
  send(method, params) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      // Cleared on the reply: a timer left armed keeps node alive for its
      // whole span after the last command, which cost every run of this
      // driver up to 20 s (Task 20372).
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(method + ' timed out'));
      }, 20000);
      this.pending.set(id, {
        resolve: v => { clearTimeout(timer); resolve(v); },
        reject: e => { clearTimeout(timer); reject(e); },
      });
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-chartdefer-'));
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    // Same reasoning as testdata/overlay_browser.js: this suite runs as root on
    // the project's dev box and unprivileged in CI, and the profile is a
    // throwaway loading only a local httptest server.
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--window-size=1280,900',
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
    for (let i = 0; i < CHROME_START_POLLS && !port; i++) {
      await sleep(50);
      if (proc.exitCode !== null) throw new Error('chrome exited: ' + stderr);
      try {
        const txt = fs.readFileSync(portFile, 'utf8').split('\n');
        if (txt[0] && txt[0].trim()) port = Number(txt[0].trim());
      } catch (e) { /* not written yet */ }
    }
    if (!port) throw new Error('chrome never reported a debugging port within ' + CHROME_START_POLLS * 50 / 1000 + 's: ' + stderr);
    return {proc, port, dir};
  } catch (e) {
    killChrome(proc);
    throw e;
  }
}

async function connect(port) {
  const res = await fetch('http://127.0.0.1:' + port + '/json/list', {signal: AbortSignal.timeout(15000)});
  const targets = await res.json();
  const page = targets.find(t => t.type === 'page');
  if (!page) throw new Error('no page target');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((ok, bad) => {
    setTimeout(() => bad(new Error('cdp connect timed out')), 15000).unref();
    ws.addEventListener('open', ok, {once: true});
    ws.addEventListener('error', () => bad(new Error('CDP socket failed')), {once: true});
  });
  return new CDP(ws);
}

// The banner's visible state, as the user would read it.
const BANNER = `(() => {
  const box   = document.getElementById('analyticsChartStatus');
  const text  = document.getElementById('analyticsChartStatusText');
  const retry = document.getElementById('analyticsChartRetry');
  const cards = document.getElementById('analyticsCharts');
  const shown = el => !!el && el.style.display !== 'none';
  return {
    visible: shown(box),
    text: text ? text.textContent : '',
    retryVisible: shown(retry),
    cardsVisible: !!cards && cards.style.display !== 'none',
  };
})()`;

// How many of the five canvases actually carry a Chart instance. Chart.getChart
// is the library's own registry, so this is the library's answer to "did you
// draw this", not a guess from the DOM.
const DRAWN = `(() => {
  if (!window.Chart || !window.Chart.getChart) return 0;
  const ids = ['chartStatusDonut','chartVelocity','chartBurndown','chartCostTrend','chartLatency'];
  let n = 0;
  for (const id of ids) {
    const el = document.getElementById(id);
    if (el && window.Chart.getChart(el)) n++;
  }
  return n;
})()`;

(async () => {
  let chrome;
  const out = {};
  try {
    chrome = await launchChrome();
    const cdp = await connect(chrome.port);

    let chartRequests = [];
    let panelRequests = [];
    cdp.on('Network.requestWillBeSent', p => {
      const path = new URL(p.request.url).pathname;
      if (CHART_URL_RE.test(path)) chartRequests.push(p.request.url);
      if (PANEL_URL_RE.test(path)) panelRequests.push(p.request.url);
    });

    await cdp.send('Network.enable');
    await cdp.send('Page.enable');
    await cdp.send('Network.setCacheDisabled', {cacheDisabled: true});

    // ── 1. First paint: the library must not be fetched ──────────────────────
    await cdp.send('Page.navigate', {url: BASE + '/'});
    await sleep(2500);

    out.first_paint = {
      chart_requests: chartRequests.length,
      chart_global: await cdp.eval('typeof window.Chart !== "undefined"'),
      loader_present: await cdp.eval('typeof window.ensureChartLib === "function"'),
      meta_src: await cdp.eval(`(() => {
        const m = document.querySelector('meta[name="cloop-chart-src"]');
        return m ? m.getAttribute('content') : '';
      })()`),
      // Nor the tab's own script, whose markup — the banner and its Retry —
      // is therefore not on the page yet.
      panel_requests: panelRequests.length,
      panel_absent: await cdp.eval('!document.getElementById("analyticsChartRetry")'),
      banner: await cdp.eval(BANNER),
    };

    // ── 2. Opening Analytics fetches it and draws ────────────────────────────
    chartRequests = [];
    panelRequests = [];
    await cdp.eval(`switchTab('analytics')`);
    await waitFor(cdp, DRAWN + ' >= 3', 'the charts to draw');

    out.on_demand = {
      chart_requests: chartRequests.length,
      panel_requests: panelRequests.length,
      chart_global: await cdp.eval('typeof window.Chart !== "undefined"'),
      charts_drawn: await cdp.eval(DRAWN),
      banner: await cdp.eval(BANNER),
    };

    // Returning to the tab must not refetch: the memo is the whole point.
    chartRequests = [];
    await cdp.eval(`switchTab('overview')`);
    await sleep(200);
    await cdp.eval(`switchTab('analytics')`);
    await waitFor(cdp, DRAWN + ' >= 3', 'the charts to draw again');
    out.second_visit = {
      chart_requests: chartRequests.length,
      charts_drawn: await cdp.eval(DRAWN),
    };

    // ── 3. A failed fetch says so, and Retry recovers ────────────────────────
    // Fresh page so the memo and the loaded global are gone.
    await cdp.send('Network.setBlockedURLs', {urls: ['*/assets/chart.*']});
    await cdp.send('Page.navigate', {url: BASE + '/'});
    await sleep(2500);
    chartRequests = [];
    await cdp.eval(`switchTab('analytics')`);
    await waitFor(cdp, '(' + BANNER + ').retryVisible', 'the failure banner');

    out.blocked = {
      chart_requests: chartRequests.length,
      chart_global: await cdp.eval('typeof window.Chart !== "undefined"'),
      charts_drawn: await cdp.eval(DRAWN),
      banner: await cdp.eval(BANNER),
      // The epics panel is plain DOM and must survive a dead chart library:
      // the tab's own script, which draws it, did arrive.
      epics_reachable: await cdp.eval('!!document.getElementById("epicsCard")'),
    };

    await cdp.send('Network.setBlockedURLs', {urls: []});
    chartRequests = [];
    // Click the real button, so the panel's own routing drives the retry.
    await cdp.eval(`document.getElementById('analyticsChartRetry').click()`);
    await waitFor(cdp, DRAWN + ' >= 3', 'the charts to draw after Retry');

    out.after_retry = {
      chart_requests: chartRequests.length,
      chart_global: await cdp.eval('typeof window.Chart !== "undefined"'),
      charts_drawn: await cdp.eval(DRAWN),
      banner: await cdp.eval(BANNER),
    };

    console.log(JSON.stringify(out, null, 2));
    cdp.ws.close();
  } catch (e) {
    out.error = {message: String((e && e.message) || e)};
    console.log(JSON.stringify(out, null, 2));
    process.exitCode = 1;
  } finally {
    if (chrome) await closeChrome(chrome.proc, chrome.dir);
  }
})().then(() => process.exit(process.exitCode ?? 0));
