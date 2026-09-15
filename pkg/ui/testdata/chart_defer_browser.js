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

const sleep = ms => new Promise(r => setTimeout(r, ms));

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
    cdp.on('Network.requestWillBeSent', p => {
      if (CHART_URL_RE.test(new URL(p.request.url).pathname)) chartRequests.push(p.request.url);
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
      // The retry handler must survive the IIFE the whole bundle is wrapped in;
      // a bare `function` here would be unreachable from the inline onclick.
      retry_exposed: await cdp.eval('typeof window.retryAnalyticsCharts === "function"'),
      banner: await cdp.eval(BANNER),
    };

    // ── 2. Opening Analytics fetches it and draws ────────────────────────────
    chartRequests = [];
    await cdp.eval(`switchTab('analytics')`);
    await sleep(3000);

    out.on_demand = {
      chart_requests: chartRequests.length,
      chart_global: await cdp.eval('typeof window.Chart !== "undefined"'),
      charts_drawn: await cdp.eval(DRAWN),
      banner: await cdp.eval(BANNER),
    };

    // Returning to the tab must not refetch: the memo is the whole point.
    chartRequests = [];
    await cdp.eval(`switchTab('overview')`);
    await sleep(200);
    await cdp.eval(`switchTab('analytics')`);
    await sleep(1500);
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
    await sleep(3000);

    out.blocked = {
      chart_requests: chartRequests.length,
      chart_global: await cdp.eval('typeof window.Chart !== "undefined"'),
      charts_drawn: await cdp.eval(DRAWN),
      banner: await cdp.eval(BANNER),
      // The epics panel is plain DOM and must survive a dead chart library.
      epics_reachable: await cdp.eval('typeof window.loadAnalytics === "function"'),
    };

    await cdp.send('Network.setBlockedURLs', {urls: []});
    chartRequests = [];
    // Click the real button, so the inline onclick is what drives the retry.
    await cdp.eval(`document.getElementById('analyticsChartRetry').click()`);
    await sleep(3500);

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
    if (chrome) {
      try { chrome.proc.kill('SIGKILL'); } catch (_) {}
      try { fs.rmSync(chrome.dir, {recursive: true, force: true}); } catch (_) {}
    }
  }
})();
