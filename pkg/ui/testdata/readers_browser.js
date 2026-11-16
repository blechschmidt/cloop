// readers_browser.js — a project's Readers section in a real browser (Task
// 20503).
//
// Two people, one browser, one after the other. Alice owns the project, so she
// is its administrator: she picks a reader from the projects she can see, is
// asked to confirm it is her — her session signed in three hours ago — and the
// add goes through once she has; then she removes a reader she can see, by
// name, and one she cannot, by its entry. Bob is a viewer of the project: he
// sees the lists and no control, and while he watches, the Go test lists
// another project and then shares the reader with him, through its control
// endpoint; both changes must reach his page as pushes, with no request of its
// own. Each view is measured at a phone, a tablet and a desktop width.
//
// Their sessions come from the Go test, which signed both in through the fake
// identity provider before Chrome started; the driver installs the cookie.
//
// Usage: node readers_browser.js <chrome> <hub-url> <control-url>
// with READERS_CONFIG='{"project":…, "reader":…, "shared":…, "library":…,
// "names":{…}, "cookies":{"alice":…, "bob":…}}' in the environment.
// READERS_SHOTS=<dir> saves screenshots of the section at each width.
// Prints one JSON document on stdout.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const CONTROL = process.argv[4];
const CFG = JSON.parse(process.env.READERS_CONFIG || '{}');

const sleep = ms => new Promise(r => setTimeout(r, ms));
// How long Chrome gets to report its DevTools port, in 50 ms polls: 90 s.
const CHROME_START_POLLS = 1800;
// A bound on how long to keep looking, not a pause: under -race on a loaded
// machine a control-plane round trip takes seconds.
const WAIT_MS = 30000;

// The widths both views are measured at: the users' phones, a tablet in
// portrait, a desktop.
const WIDTHS = [
  {width: 360, height: 780, deviceScaleFactor: 3, mobile: true},
  {width: 768, height: 1024, deviceScaleFactor: 2, mobile: true},
  {width: 1280, height: 800, deviceScaleFactor: 1, mobile: false},
];

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.handlers = new Map();
    ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id === undefined) {
        for (const fn of this.handlers.get(msg.method) || []) fn(msg.params);
        return;
      }
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      clearTimeout(p.timer);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    });
  }
  on(method, fn) {
    if (!this.handlers.has(method)) this.handlers.set(method, []);
    this.handlers.get(method).push(fn);
  }
  send(method, params) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      // Cleared on the reply: an armed timer would hold node open after the
      // last command.
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(method + ' timed out'));
      }, 20000);
      this.pending.set(id, {resolve, reject, timer});
      this.ws.send(JSON.stringify({id, method, params: params || {}}));
    });
  }
  async eval(expr, gesture) {
    const r = await this.send('Runtime.evaluate',
      {expression: expr, awaitPromise: true, returnByValue: true, userGesture: !!gesture});
    if (r.exceptionDetails) {
      throw new Error('eval failed: ' + JSON.stringify(r.exceptionDetails.exception || r.exceptionDetails));
    }
    return r.result.value;
  }
}

function killChrome(proc) {
  try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) {
    try { proc.kill('SIGKILL'); } catch (_) { /* already gone */ }
  }
}

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-readers-'));
  // Its own process group, so killChrome takes every helper with it and the
  // profile can be deleted.
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--window-size=1280,900',
    'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe'], detached: true});
  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });
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
    if (!port) throw new Error('chrome never reported a debugging port: ' + stderr);
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

async function evalSafe(cdp, expr) {
  try { return await cdp.eval(expr); } catch (_) { return undefined; }
}

async function waitFor(cdp, expr, what) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    if (await evalSafe(cdp, expr)) return;
    if (Date.now() > deadline) {
      const diag = await evalSafe(cdp, `JSON.stringify({loc: location.href,
        section: (document.getElementById('readersSection') || {}).innerText,
        ra: (document.getElementById('ra-overlay') || {style: {}}).style.display,
        toasts: window.__toasts})`);
      throw new Error('timed out waiting for ' + what + ' (' + diag + ')');
    }
    await sleep(50);
  }
}

async function ctl(method, p) {
  const r = await fetch(CONTROL + p, {method, signal: AbortSignal.timeout(15000)});
  if (!r.ok) throw new Error(method + ' ' + p + ' = ' + r.status + ' ' + await r.text());
  return r.json();
}

// click waits for the element to be laid out and on top, then clicks its
// centre with the mouse. The check and the press are separate round trips, and
// the page can move the element in between — the presence bar that ends the
// socket's connect burst pushes the whole tab down — so the check arms a guard
// that lets through only the press that reaches the element, and a swallowed
// press is aimed and made again (humangate_browser.js).
async function click(cdp, sel) {
  const deadline = Date.now() + WAIT_MS;
  let why = '';
  for (let i = 0; i === 0 || Date.now() < deadline; i++) {
    if (i) await sleep(50);
    const pt = await evalSafe(cdp, `(() => {
      const e = document.querySelector(${JSON.stringify(sel)});
      if (!e || e.disabled) return null;
      e.scrollIntoView({block: 'center'});
      const r = e.getBoundingClientRect();
      if (!r.width || !r.height) return null;
      return {x: r.left + r.width / 2, y: r.top + r.height / 2};
    })()`);
    if (!pt) { why = 'nothing clickable at ' + sel; continue; }
    const armed = await evalSafe(cdp, `(() => {
      const e = document.elementFromPoint(${pt.x}, ${pt.y});
      const want = document.querySelector(${JSON.stringify(sel)});
      if (!e || !want || !(e === want || want.contains(e))) return false;
      const seen = {}, types = ['mousedown', 'mouseup', 'click'];
      const guard = ev => {
        if (!ev.isTrusted) return;
        seen[ev.type] = ev.target === want || want.contains(ev.target);
        if (!seen[ev.type]) { ev.preventDefault(); ev.stopImmediatePropagation(); }
      };
      types.forEach(t => window.addEventListener(t, guard, true));
      window.__pressSeen = () => new Promise(res => setTimeout(() => {
        types.forEach(t => window.removeEventListener(t, guard, true));
        res(seen);
      }, 'click' in seen ? 0 : 100));
      return true;
    })()`);
    if (!armed) { why = sel + ' is covered'; continue; }
    for (const type of ['mousePressed', 'mouseReleased']) {
      await cdp.send('Input.dispatchMouseEvent', {type, x: pt.x, y: pt.y, button: 'left', clickCount: 1});
    }
    const seen = (await evalSafe(cdp, `window.__pressSeen()`)) || {};
    if (seen.click === true) return;
    why = 'click' in seen ? sel + ' moved between the aim and the press' : 'a press on ' + sel + ' brought no click';
  }
  throw new Error(why);
}

// signIn installs one person's session and boots the dashboard. The stale
// resume marker is what tells boot is over: resumeView, boot's last step,
// removes it.
async function signIn(cdp, who) {
  // Off the previous person's page first: left running, its requests start
  // failing the moment the cookie goes, and a 401 sends it through the
  // identity provider, racing the cookie set below.
  await cdp.send('Page.navigate', {url: 'about:blank'});
  await waitFor(cdp, `location.href === 'about:blank'`, 'the previous page to unload');
  await cdp.send('Network.clearBrowserCookies');
  const ok = await cdp.send('Network.setCookie', {name: 'cloop_session', value: CFG.cookies[who], url: BASE, httpOnly: true});
  if (!ok || ok.success === false) throw new Error('could not set ' + who + "'s session cookie");
  await evalSafe(cdp, 'window.__old = true');
  await cdp.send('Page.navigate', {url: BASE + '/'});
  await waitFor(cdp, `!window.__old && typeof window.openProject === 'function' &&
    sessionStorage.getItem('cloop_resume') === null`, who + "'s dashboard to finish booting");
  // Toasts as they appear, and every confirm() answered yes — with what it
  // asked recorded.
  await cdp.eval(`(() => {
    window.__toasts = [];
    window.__confirms = [];
    const t = document.getElementById('toast');
    new MutationObserver(() => {
      if (t.className.indexOf('show') !== -1) window.__toasts.push({text: t.textContent, error: /\\berror\\b/.test(t.className)});
    }).observe(t, {attributes: true, childList: true, characterData: true, subtree: true});
    window.confirm = m => { window.__confirms.push(String(m)); return true; };
    return true;
  })()`);
}

const PROJECT_IDX = `(window._lastProjectsData && window._lastProjectsData.projects || [])
  .findIndex(p => p.path === ${JSON.stringify(CFG.project)})`;

// The section is drawn: shown, and its readers list says something.
const DRAWN = `(() => { const s = document.getElementById('readersSection');
  return !!s && s.getClientRects().length > 0 && !!document.querySelector('#readersList > *'); })()`;

async function openTheProject(cdp) {
  await waitFor(cdp, `${PROJECT_IDX} >= 0`, 'the project in the list');
  await cdp.eval(`(() => {
    const list = window._lastProjectsData.projects;
    const i = ${PROJECT_IDX};
    window.openProject(i, list[i].name);
    return true;
  })()`);
  await waitFor(cdp, DRAWN, 'the Readers section');
}

// The section as a person sees it.
const VIEW = `(() => {
  const vis = e => !!e && e.getClientRects().length > 0;
  const rows = sel => [...document.querySelectorAll(sel + ' .feat-row')].map(r => ({
    name: (r.querySelector('.feat-main > span') || {}).textContent || '',
    meta: (r.querySelector('.feat-branch') || {}).textContent || '',
    remove: !!r.querySelector('button[data-label]'),
  }));
  const notes = sel => [...document.querySelectorAll(sel + ' .feat-note')].map(n => n.textContent);
  const pick = document.getElementById('readersPick');
  const opts = pick ? [...pick.options].filter(o => o.value) : [];
  return {
    shown: vis(document.getElementById('readersSection')),
    count: (document.getElementById('readersCount') || {}).textContent || '',
    rows: rows('#readersList'), notes: notes('#readersList'),
    form: vis(document.getElementById('readersAddForm')),
    options: opts.map(o => o.value), labels: opts.map(o => o.textContent),
    note: vis(document.getElementById('readersNote')) ? document.getElementById('readersNote').textContent : '',
    readable: rows('#readableList'), readable_notes: notes('#readableList'),
  };
})()`;

const listsName = n => `(${VIEW}).rows.some(r => r.name === ${JSON.stringify(n)})`;

// LAYOUT is what is wrong with the section at the current width: the page
// wider than the screen, anything in the section beyond the screen's edges or
// wider than its own box, or a control something else covers.
const LAYOUT = `(() => {
  const sec = document.getElementById('readersSection');
  if (!sec || !sec.getClientRects().length) return ['the section is not shown'];
  const vw = document.documentElement.clientWidth;
  const out = [];
  const name = e => e.id ? '#' + e.id : e.tagName.toLowerCase() +
    (typeof e.className === 'string' && e.className ? '.' + e.className.split(' ')[0] : '');
  if (document.documentElement.scrollWidth > vw + 1) {
    out.push('the page is ' + document.documentElement.scrollWidth + 'px wide on a ' + vw + 'px screen');
  }
  for (const e of [sec, ...sec.querySelectorAll('*')]) {
    if (!e.getClientRects().length || e.tagName === 'OPTION') continue;
    const r = e.getBoundingClientRect();
    if (r.left < -1 || r.right > vw + 1) out.push(name(e) + ' spans ' + Math.round(r.left) + '..' + Math.round(r.right) + 'px');
    if (e.tagName !== 'SELECT' && e.clientWidth > 0 && e.scrollWidth > e.clientWidth + 1) {
      out.push(name(e) + ' holds ' + e.scrollWidth + 'px in ' + e.clientWidth + 'px');
    }
  }
  for (const c of sec.querySelectorAll('button, select')) {
    if (!c.getClientRects().length) continue;
    c.scrollIntoView({block: 'center'});
    const r = c.getBoundingClientRect();
    const at = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    if (!at || !(at === c || c.contains(at))) out.push(name(c) + ' is covered by ' + (at ? name(at) : 'nothing'));
  }
  return out;
})()`;

// layoutAt measures the section at every width, saving a screenshot of it to
// READERS_SHOTS when that names a directory.
async function layoutAt(cdp, who) {
  const out = [];
  for (const w of WIDTHS) {
    await cdp.send('Emulation.setDeviceMetricsOverride', w);
    await waitFor(cdp, `window.innerWidth === ${w.width} && ${DRAWN}`, 'the page at ' + w.width + 'px');
    // One frame, so the layout the override asks for has been made.
    await cdp.eval('new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))');
    out.push({width: w.width, problems: await cdp.eval(LAYOUT)});
    await shot(cdp, who + '-' + w.width);
  }
  await cdp.send('Emulation.clearDeviceMetricsOverride');
  return out;
}

async function shot(cdp, name) {
  const dir = process.env.READERS_SHOTS;
  if (!dir) return;
  const r = await cdp.eval(`(() => {
    const e = document.getElementById('readersSection');
    e.scrollIntoView({block: 'center'});
    const b = e.getBoundingClientRect();
    return {x: Math.max(0, b.left - 8), y: Math.max(0, b.top - 8 + window.scrollY), width: b.width + 16, height: b.height + 16};
  })()`);
  const img = await cdp.send('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true,
    clip: {x: r.x, y: r.y, width: r.width, height: r.height, scale: 1}});
  fs.writeFileSync(path.join(dir, 'readers-' + name + '.png'), Buffer.from(img.data, 'base64'));
}

const DIALOG_OPEN = `(() => { const o = document.getElementById('ra-overlay');
  return !!o && o.style.display === 'flex'; })()`;
const DIALOG_CLOSED = `(() => { const o = document.getElementById('ra-overlay');
  return !o || o.style.display !== 'flex'; })()`;

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  const out = {error_toasts: []};
  // The requests the page makes for a readers list, and the pushes its
  // socket is sent, counted from a mark.
  let fetches = 0;
  let pushes = 0;
  try {
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Network.enable');
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `try { sessionStorage.setItem('cloop_resume', '{"at":0}'); } catch (e) {}`});
    cdp.on('Network.requestWillBeSent', p => {
      if (p.request.method === 'GET' && /\/api\/projects\/\d+\/readers/.test(p.request.url)) fetches++;
    });
    cdp.on('Network.webSocketFrameReceived', p => {
      if (/"type":"project_readers"/.test((p.response || {}).payloadData || '')) pushes++;
    });

    // ── alice, the project's administrator ──
    await signIn(cdp, 'alice');
    out.meta_names_script = await cdp.eval(`!!(document.querySelector('meta[name="cloop-readers-src"]') || {}).content`);
    out.loaded_before_overview = await cdp.eval(`!!document.querySelector('script[src*="/assets/readers."]')`);
    await openTheProject(cdp);
    out.loaded_after_overview = await cdp.eval(`document.querySelectorAll('script[src*="/assets/readers."]').length`);
    out.alice_initial = await cdp.eval(VIEW);

    // Pick the reader and add it. Her sign-in is old, so the hub asks first.
    await cdp.eval(`(() => { const p = document.getElementById('readersPick');
      p.value = ${JSON.stringify(CFG.reader)}; p.dispatchEvent(new Event('change', {bubbles: true})); return p.value; })()`);
    await click(cdp, '#readersAddBtn');
    await waitFor(cdp, DIALOG_OPEN, 'the dialog asking her to confirm it is her');
    out.reauth_asked = true;
    await cdp.eval(`document.getElementById('ra-go').click()`, true);
    await waitFor(cdp, listsName(CFG.names.reader), 'the reader on the list after she signed in');
    await waitFor(cdp, DIALOG_CLOSED, 'the dialog to close');
    out.after_add = await cdp.eval(VIEW);
    out.add_toast = await cdp.eval(`(window.__toasts.find(t => /may now read this project/.test(t.text)) || {}).text || ''`);
    out.server_after_add = await ctl('GET', '/readers');

    // Remove the shared reader by name, then the one she cannot see.
    await click(cdp, `#readersList button[data-path=${JSON.stringify(CFG.shared)}]`);
    await waitFor(cdp, `!${listsName(CFG.names.shared)}`, 'the shared reader to leave the list');
    out.after_remove = await cdp.eval(VIEW);
    await click(cdp, '#readersList button[data-id]');
    await waitFor(cdp, `!document.querySelector('#readersList button[data-id]')`, 'the unseen reader to leave the list');
    out.after_hidden_remove = await cdp.eval(VIEW);
    out.confirm_texts = await cdp.eval('window.__confirms');
    out.server_after_removals = await ctl('GET', '/readers');
    out.alice_layout = await layoutAt(cdp, 'admin');
    out.error_toasts.push(...await cdp.eval(`window.__toasts.filter(t => t.error).map(t => 'alice: ' + t.text)`));

    // ── bob, a viewer ──
    await signIn(cdp, 'bob');
    await openTheProject(cdp);
    await waitFor(cdp, `(${VIEW}).notes.length > 0`, "bob's count of the readers he cannot see");
    out.bob_view = await cdp.eval(VIEW);
    // Opening the project reads the lists, once for the tab and once when
    // its permissions arrive: let those reads finish before counting.
    let last = fetches, quietSince = Date.now();
    for (const deadline = Date.now() + WAIT_MS; Date.now() - quietSince < 1500 && Date.now() < deadline;) {
      await sleep(100);
      if (fetches !== last) { last = fetches; quietSince = Date.now(); }
    }
    const fetchMark = fetches;
    const pushMark = pushes;
    await ctl('POST', '/hide');
    await waitFor(cdp, `(${VIEW}).notes.includes('2 more projects you can’t see')`, "carol's project counted on bob's page");
    out.bob_after_hidden_add = await cdp.eval(VIEW);
    await ctl('POST', '/share');
    await waitFor(cdp, `${listsName(CFG.names.reader)} && (${VIEW}).notes.includes('1 more project you can’t see')`,
      'the reader named on bob\'s page once it is shared with him');
    out.bob_after_share = await cdp.eval(VIEW);
    out.bob_pushes = pushes - pushMark;
    out.bob_readers_fetches = fetches - fetchMark;
    out.bob_layout = await layoutAt(cdp, 'viewer');
    out.error_toasts.push(...await cdp.eval(`window.__toasts.filter(t => t.error).map(t => 'bob: ' + t.text)`));

    process.stdout.write(JSON.stringify(out, null, 2));
  } catch (e) {
    out.error = {message: String(e && e.message || e)};
    process.stdout.write(JSON.stringify(out, null, 2));
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
  process.stdout.write(JSON.stringify({error: {message: String(err && err.message || err)}}, null, 2));
  process.exit(0);
});
