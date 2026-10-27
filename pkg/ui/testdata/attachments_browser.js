// attachments_browser.js — opens a task's attachments in a real browser
// (Task 20428).
//
// What a person does with a task's files is a question about a browser, not a
// bundle: whether the paperclip shows on the row, whether the details list
// the files, whether a PNG decodes as pixels from the bytes the hub serves,
// whether text lands as text, whether Download saves a file under its name,
// whether Delete asks before it deletes, and whether the section fits a
// phone. testdata/domshim.js has no image decoder, no downloads, no dialogs
// and no layout, so this drives Chromium over CDP against a real hub; the Go
// side asks the hub what it holds afterwards.
//
// Usage: node attachments_browser.js <chrome-binary> <base-url> <download-dir>
// Prints one JSON document on stdout: {scenario: {...}, ...}.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const DOWNLOADS = process.argv[4];

const sleep = ms => new Promise(r => setTimeout(r, ms));

// How long Chrome gets to report its DevTools port, in 50 ms polls: 90 s.
// A cold start on a CI runner that is also running three race-instrumented
// test binaries has taken longer than the 30 s this used to allow (Task 20372).
const CHROME_START_POLLS = 1800;

// WAIT_MS bounds every wait for the page to reach a state. Under a loaded -race
// run a hub round trip takes seconds, so this is how long to keep looking, never
// a pause a healthy run sits out.
const WAIT_MS = 30000;

// A minimal CDP client, the same shape as features_browser.js's; duplicated
// for the reason given in sandbox_browser.js.
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

// killChrome takes the browser's whole process group: a helper outliving the
// browser goes on writing into the profile while it is deleted.
function killChrome(proc) {
  try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) {
    try { proc.kill('SIGKILL'); } catch (_) { /* already gone */ }
  }
}

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-attachments-'));
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
    for (let i = 0; i < CHROME_START_POLLS && !port; i++) {
      await sleep(50);
      if (proc.exitCode !== null) throw new Error('chrome exited: ' + stderr);
      try {
        const txt = fs.readFileSync(portFile, 'utf8').split('\n');
        if (txt[0] && txt[0].trim()) port = Number(txt[0].trim());
      } catch (e) { /* not written yet */ }
    }
    if (!port) throw new Error('chrome never reported a debugging port within ' + CHROME_START_POLLS * 50 / 1000 + 's: ' + stderr);

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

async function waitFor(cdp, expr, what) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    if (await cdp.eval(expr)) return;
    if (Date.now() >= deadline) throw new Error('timed out waiting for ' + what);
    await sleep(50);
  }
}

// click scrolls an element into view and clicks its centre with the mouse,
// once it is laid out and on top — a control covered by another element fails
// here the way it would fail a user.
async function click(cdp, sel) {
  let pt = null, hit = false;
  const deadline = Date.now() + WAIT_MS;
  for (let i = 0; !hit && (i === 0 || Date.now() < deadline); i++) {
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

// ── the page ────────────────────────────────────────────────────────────────

const rowSel = id => `.task-item[data-task-id="${id}"]`;
const filesExpr = `Array.from(document.querySelectorAll('#td-files .td-file'))`;

// Dialogs are answered here rather than by replacing window.confirm in the
// page: the point is that a real confirmation is asked for, and what it says.
const dialogs = [];

async function boot(cdp) {
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Page.setDownloadBehavior', {behavior: 'allow', downloadPath: DOWNLOADS});
  cdp.ws.addEventListener('message', ev => {
    const msg = JSON.parse(ev.data);
    if (msg.method === 'Page.javascriptDialogOpening') {
      dialogs.push(msg.params.message);
      cdp.send('Page.handleJavaScriptDialog', {accept: true}).catch(() => {});
    }
  });
  // Boot's last step (resumeView) removes this marker, so its absence says
  // boot is over and will not switch the tab out from under the driver.
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
    source: "try { sessionStorage.setItem('cloop_resume', '{\"at\":0}'); } catch (e) {}",
  });
  await cdp.send('Page.navigate', {url: BASE + '/'});
  await waitFor(cdp, `typeof window.openProject === 'function' && typeof window.openTaskDetails === 'function'`,
    'the bundle to load');
  await waitFor(cdp, `sessionStorage.getItem('cloop_resume') === null`, 'boot to finish');
  const name = await cdp.eval(`(async () => {
    const d = await (await fetch('/api/projects')).json();
    return ((d && d.projects) || [])[0] ? d.projects[0].name : '';
  })()`);
  await cdp.eval(`window.openProject(0, ${JSON.stringify(name)})`);
  await cdp.eval(`window.switchTab('tasks')`);
  await waitFor(cdp, `!!document.querySelector('#toggleCompletedBtn')`, 'the Tasks tab');
  // The task with files is done, and done tasks are hidden until asked for.
  // The first render can land after a click and draw the button afresh, so
  // the click is repeated until the button says completed tasks are shown.
  const showing = `document.getElementById('toggleCompletedBtn').textContent.indexOf('Hide') === 0`;
  const deadline = Date.now() + WAIT_MS;
  while (!(await cdp.eval(showing))) {
    if (Date.now() >= deadline) throw new Error('the Show completed button never took');
    await click(cdp, '#toggleCompletedBtn');
    for (let i = 0; i < 20 && !(await cdp.eval(showing)); i++) await sleep(50);
  }
  try {
    await waitFor(cdp, `!!document.querySelector(${JSON.stringify(rowSel(1))}) && !!document.querySelector(${JSON.stringify(rowSel(2))})`,
      'both task rows');
  } catch (e) {
    const seen = await cdp.eval(`JSON.stringify({
      toggle: (document.getElementById('toggleCompletedBtn') || {}).textContent,
      list: ((document.getElementById('taskListFull') || {}).innerHTML || '').slice(0, 600),
      tab: (document.querySelector('.tab-panel.active') || {}).id,
    })`).catch(err => 'unreadable: ' + err.message);
    throw new Error(e.message + ' — page: ' + seen);
  }
}

const badgeOf = id => `(() => {
  const row = document.querySelector(${JSON.stringify(rowSel(id))});
  const chip = row && Array.from(row.querySelectorAll('.task-meta span')).find(s => s.textContent.indexOf('📎') === 0);
  return chip ? chip.textContent : '';
})()`;

const results = {};

async function scenarioBadge(cdp) {
  results.badge = {task1: await cdp.eval(badgeOf(1)), task2: await cdp.eval(badgeOf(2))};
}

async function openDetails(cdp, n) {
  await click(cdp, rowSel(1) + ' .task-title');
  await waitFor(cdp, `document.getElementById('td-overlay').classList.contains('open')`, 'the task details');
  await waitFor(cdp, `${filesExpr}.length === ${n}`, n + ' attachments in the details');
}

async function scenarioListed(cdp) {
  await openDetails(cdp, 3);
  results.listed = await cdp.eval(`(() => {
    const files = ${filesExpr};
    return {
      names: files.map(f => f.querySelector('.td-file-name').textContent),
      previews: files.filter(f => f.querySelector('button[data-act="preview"]'))
        .map(f => f.querySelector('.td-file-name').textContent),
    };
  })()`);
}

const fileSel = name => `${filesExpr}.find(f => f.querySelector('.td-file-name').textContent === ${JSON.stringify(name)})`;

// clickIn clicks a control inside the attachment row named name.
async function clickIn(cdp, name, act) {
  const id = await cdp.eval(`(${fileSel(name)} || {dataset: {}}).dataset.file || ''`);
  if (!id) throw new Error('no attachment row ' + name);
  await click(cdp, `#td-files .td-file[data-file="${id}"] button[data-act="${act}"]`);
  return id;
}

async function scenarioImagePreview(cdp) {
  const id = await clickIn(cdp, 'plots/latency.png', 'preview');
  const img = `document.querySelector('#td-files .td-file[data-file="${id}"] img.td-file-img')`;
  try {
    await waitFor(cdp, `!!${img} && ${img}.complete && ${img}.naturalWidth > 0`, 'the image to decode');
  } catch (e) {
    // Timed out once in CI only (fe48b3a8, pkg/ui shard 1/3), with nothing
    // saying whether the preview was never asked for, failed with a message,
    // or was drawn into a pane a re-render had replaced: say which.
    const seen = await cdp.eval(`(() => {
      const row = document.querySelector('#td-files .td-file[data-file="${id}"]');
      const pane = row && row.querySelector('.td-file-preview');
      const im = row && row.querySelector('img.td-file-img');
      return JSON.stringify({
        rows: document.querySelectorAll('#td-files .td-file').length,
        row: !!row,
        button: row ? (row.querySelector('button[data-act="preview"]') || {}).textContent : null,
        pane_hidden: pane ? pane.hidden : null,
        pane: pane ? pane.innerHTML.slice(0, 300) : null,
        img: im ? {complete: im.complete, width: im.naturalWidth, src: (im.getAttribute('src') || '').slice(0, 40)} : null,
        details_open: document.getElementById('td-overlay').classList.contains('open'),
      });
    })()`).catch(err => 'unreadable: ' + err.message);
    throw new Error(e.message + ' — preview: ' + seen);
  }
  results.image_preview = await cdp.eval(`({width: ${img}.naturalWidth, height: ${img}.naturalHeight,
    src: ${img}.getAttribute('src').slice(0, 40)})`);
}

async function scenarioTextPreview(cdp) {
  const id = await clickIn(cdp, 'bench.log', 'preview');
  const pre = `document.querySelector('#td-files .td-file[data-file="${id}"] pre')`;
  await waitFor(cdp, `!!${pre}`, 'the text preview');
  results.text_preview = {text: await cdp.eval(`${pre}.textContent`)};
}

async function scenarioDownload(cdp) {
  await clickIn(cdp, 'bench.log', 'download');
  const file = path.join(DOWNLOADS, 'bench.log');
  const deadline = Date.now() + WAIT_MS;
  // Chrome writes to a .crdownload first and renames it when it is complete.
  while (!fs.existsSync(file)) {
    if (Date.now() >= deadline) throw new Error('the download never arrived in ' + DOWNLOADS + ': ' + fs.readdirSync(DOWNLOADS).join(', '));
    await sleep(50);
  }
  results.download = {file: path.basename(file), bytes: fs.statSync(file).size};
}

async function scenarioDelete(cdp) {
  const before = dialogs.length;
  await clickIn(cdp, 'plots/latency.png', 'remove');
  await waitFor(cdp, `${filesExpr}.length === 2`, 'the list to drop the deleted file');
  await cdp.eval(`window.closeTaskDetails && window.closeTaskDetails()`);
  // The row's count comes back from the hub's push, not from the panel.
  await waitFor(cdp, `${badgeOf(1)}.indexOf('📎 2') === 0`, 'the badge to count two files');
  results.deleted = {
    dialog: dialogs.slice(before).join(' | '),
    left: await cdp.eval(`${filesExpr}.map(f => f.querySelector('.td-file-name').textContent)`),
    badge: await cdp.eval(badgeOf(1)),
  };
}

async function scenarioPhone(cdp) {
  await cdp.send('Emulation.setDeviceMetricsOverride', {width: 360, height: 780, deviceScaleFactor: 3, mobile: true});
  await waitFor(cdp, `window.innerWidth === 360`, 'the phone viewport');
  await openDetails(cdp, 2);
  results.phone = await cdp.eval(`(() => {
    const de = document.documentElement;
    const modal = document.getElementById('td-modal').getBoundingClientRect();
    const sec = document.getElementById('td-files');
    const buttons = Array.from(sec.querySelectorAll('button')).map(b => b.getBoundingClientRect());
    return {
      overflow_px: de.scrollWidth - de.clientWidth,
      modal_fits: modal.left >= 0 && modal.right <= window.innerWidth && sec.scrollWidth <= sec.clientWidth,
      buttons_show: buttons.length > 0 && buttons.every(b => b.width > 0 && b.left >= modal.left && b.right <= modal.right),
    };
  })()`);
}

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  try {
    await boot(cdp);
    await scenarioBadge(cdp);
    await scenarioListed(cdp);
    await scenarioImagePreview(cdp);
    await scenarioTextPreview(cdp);
    await scenarioDownload(cdp);
    await scenarioDelete(cdp);
    await scenarioPhone(cdp);
    process.stdout.write(JSON.stringify(results, null, 2));
  } finally {
    try { cdp.ws.close(); } catch (e) { /* already closed */ }
    killChrome(proc);
    if (proc.exitCode === null && proc.signalCode === null) {
      await new Promise(r => { proc.once('exit', r); setTimeout(r, 5000).unref(); });
    }
    try { fs.rmSync(dir, {recursive: true, force: true, maxRetries: 10, retryDelay: 100}); } catch (e) { /* best effort */ }
  }
}

main().then(() => process.exit(0), err => {
  process.stdout.write(JSON.stringify({error: {message: String(err && err.message || err)}, partial: results}, null, 2));
  process.exit(1);
});
