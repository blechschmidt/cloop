// knowledge_browser.js — Settings → Knowledge sources, a project's Knowledge
// tab and a task's citations, in a real browser, as a maintainer who is not an
// administrator sees them on an SSO hub with a role policy (Task 20473).
//
// What it drives, end to end against the hub and its fake connector
// (uifake, knowledge_connection_test.go):
//
//   - RBAC visibility: the maintainer's Settings lists the organisation's
//     source — with no control an administrator's would have — and never a
//     colleague's personal one; and no WebSocket frame the page receives
//     names that colleague's source, even while the colleague changes it.
//   - The connect dialog: a new credential stored through the secret store
//     from the form, a Test connection that fails in the remote's words with
//     the credential redacted out of them, and one that lists, then Save.
//   - Live sync status: Sync now, and the card turns to "synced" with its
//     counts from pushes alone — the list is never fetched again — as does
//     the organisation source's when an administrator syncs it elsewhere.
//   - Bind → search: the Knowledge tab offers the maintainer's own source to
//     bind (not the organisation's, which is an administrator's to bind),
//     binds it, and a search ranks its passages with source links, escaping
//     the hostile document's title, path and snippet; narrowing to a space,
//     the retrieval setting, and unbinding.
//   - A task's details list the knowledge its run cited, linking only http(s).
//
// Usage: node knowledge_browser.js <chrome> <hub-url> <control-url> <task-id>
// with KNOWLEDGE_COOKIE (the maintainer's session) and KNOWLEDGE_TOKEN (the
// credential the dialog stores) in the environment. Prints one JSON document
// on stdout.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const CONTROL = process.argv[4];
const TASK = Number(process.argv[5]);
const COOKIE = process.env.KNOWLEDGE_COOKIE || '';
const TOKEN = process.env.KNOWLEDGE_TOKEN || '';
const SHOTS = process.env.KNOWLEDGE_BROWSER_SHOTS || '';
const MINE = "Lead's runbooks";
const ORG = 'kb-browser-org-wiki';
const BOB = 'kb-browser-bob';

const sleep = ms => new Promise(r => setTimeout(r, ms));

// How long Chrome gets to report its DevTools port, in 50 ms polls: 90 s.
// A cold start on a CI runner that is also running three race-instrumented
// test binaries has taken longer than the 30 s this used to allow (Task 20372).
const CHROME_START_POLLS = 1800;

// A bound on how long to keep looking, not a pause: under -race on a loaded
// machine a control-plane round trip takes seconds.
const WAIT_MS = 30000;

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.handlers = [];
    ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id === undefined) { for (const h of this.handlers) h(msg); return; }
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
      // Cleared on the reply: an armed timer would hold node open after the
      // last command.
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(method + ' timed out'));
      }, 20000);
      this.pending.set(id, {resolve, reject, timer});
      this.ws.send(JSON.stringify({id, method, params: params || {}}));
    });
  }
  on(fn) { this.handlers.push(fn); }
  async eval(expr) {
    const r = await this.send('Runtime.evaluate', {expression: expr, awaitPromise: true, returnByValue: true});
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-knowledge-'));
  // Its own process group, so killChrome takes every helper with it and the
  // profile can be deleted.
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
    if (Date.now() > deadline) throw new Error('timed out waiting for ' + what);
    await sleep(50);
  }
}

async function ctl(method, p) {
  const r = await fetch(CONTROL + p, {method, signal: AbortSignal.timeout(15000)});
  if (!r.ok) throw new Error(method + ' ' + p + ' = ' + r.status + ' ' + await r.text());
  return r.json();
}

// click waits for the element to be on screen and enabled, then clicks it.
// A DOM click rather than the mouse at its centre: Settings' other sections
// arrive while the driver works and move everything below them, so a point
// read before a section lands is somewhere else by the time a mouse press
// arrives there. What is under test is the panels' own handling of the click.
async function click(cdp, sel) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    const r = await evalSafe(cdp, `(() => {
      const e = document.querySelector(${JSON.stringify(sel)});
      if (!e || e.disabled || !e.checkVisibility({checkVisibilityCSS: true})) return false;
      e.scrollIntoView({block: 'center'});
      e.click();
      return true;
    })()`);
    if (r) return;
    if (Date.now() > deadline) throw new Error('nothing clickable at ' + sel);
    await sleep(50);
  }
}

// type focuses a field, empties it, and types text into it as keystrokes
// would arrive.
async function type(cdp, sel, text) {
  await click(cdp, sel);
  await cdp.eval(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); e.focus(); e.value = ''; return true; })()`);
  await cdp.send('Input.insertText', {text});
}

// signIn installs one person's session and boots the dashboard. The stale
// resume marker is what tells boot is over: resumeView, boot's last step,
// removes it (32-renew.js).
async function signIn(cdp, who) {
  // Off the previous person's page first. Left running, its background
  // requests start failing the moment the cookie is cleared, and a 401 sends
  // it through the identity provider — which signs the browser in as whoever
  // the fake provider last answered for, racing the cookie set below.
  await cdp.send('Page.navigate', {url: 'about:blank'});
  await waitFor(cdp, `location.href === 'about:blank'`, 'the previous page to unload');
  await cdp.send('Network.clearBrowserCookies');
  const ok = await cdp.send('Network.setCookie', {name: 'cloop_session', value: COOKIE, url: BASE, httpOnly: true});
  if (!ok || ok.success === false) throw new Error('could not set ' + who + "'s session cookie");
  await evalSafe(cdp, 'window.__old = true');
  await cdp.send('Page.navigate', {url: BASE + '/'});
  await waitFor(cdp, `!window.__old && typeof window.openProject === 'function' &&
    sessionStorage.getItem('cloop_resume') === null`, who + "'s dashboard to finish booting");
  // Error toasts, recorded as they appear; the card answers failures with one.
  await cdp.eval(`(() => {
    window.__toasts = [];
    const t = document.getElementById('toast');
    new MutationObserver(() => {
      if (t.className.indexOf('show') !== -1) window.__toasts.push({text: t.textContent, error: /\\berror\\b/.test(t.className)});
    }).observe(t, {attributes: true, childList: true, characterData: true, subtree: true});
    window.confirm = () => true;
    return true;
  })()`);
}


const q = JSON.stringify;
const text = sel => `((document.querySelector(${q(sel)}) || {}).textContent || '')`;

// setValue sets a field or a select the way a person's change would arrive:
// the value, then input and change events the panel's listeners hear.
async function setValue(cdp, sel, value) {
  const r = await cdp.eval(`(() => { const e = document.querySelector(${q(sel)});
    if (!e) return 'no element ' + ${q(sel)};
    e.value = ${q(value)};
    e.dispatchEvent(new Event('input', {bubbles: true}));
    e.dispatchEvent(new Event('change', {bubbles: true}));
    return 'ok'; })()`);
  if (r !== 'ok') throw new Error(r);
}

// snap saves what sel shows at a phone's and a desktop's width, when
// KNOWLEDGE_BROWSER_SHOTS names a directory: pictures of the panels for a
// person to look at, never a check.
async function snap(cdp, name, sel) {
  if (!SHOTS) return;
  for (const [w, h, scale, mobile] of [[360, 780, 3, true], [1280, 900, 1, false]]) {
    await cdp.send('Emulation.setDeviceMetricsOverride', {width: w, height: h, deviceScaleFactor: scale, mobile});
    await sleep(300);
    const r = await cdp.eval(`(() => { const e = document.querySelector(${q(sel)}); if (!e) return null;
      const b = e.getBoundingClientRect(); return {x: b.left + scrollX, y: b.top + scrollY, w: b.width, h: b.height}; })()`);
    if (r && r.w && r.h) {
      const shot = await cdp.send('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true,
        clip: {x: r.x, y: r.y, width: r.w, height: Math.min(r.h, 4000), scale: 1}});
      fs.writeFileSync(path.join(SHOTS, name + '-' + w + '.png'), Buffer.from(shot.data, 'base64'));
    }
  }
  await cdp.send('Emulation.clearDeviceMetricsOverride');
  await sleep(300);
}

// cardOf is the Settings card whose name is name.
const cardOf = name => `[...document.querySelectorAll('#ksList .ks-card')].find(c =>
  (c.querySelector('.exec-name') || {}).textContent === ${q(name)})`;

async function main() {
  const {cdp, proc, dir} = await launchChrome();
  const out = {};
  const frames = [];     // every WebSocket frame the page received
  const requests = [];   // every API request the page made: method and path
  cdp.on(msg => {
    if (msg.method === 'Network.webSocketFrameReceived') frames.push(msg.params.response.payloadData || '');
    if (msg.method === 'Network.requestWillBeSent') {
      const u = new URL(msg.params.request.url);
      if (u.pathname.startsWith('/api/')) requests.push(msg.params.request.method + ' ' + u.pathname);
    }
  });
  try {
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Network.enable');
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `try { sessionStorage.setItem('cloop_resume', '{"at":0}'); } catch (e) {}
        window.__csp = [];
        document.addEventListener('securitypolicyviolation', e => window.__csp.push(e.violatedDirective + ' ' + e.blockedURI));`});
    await signIn(cdp, 'lead');
    out.me = await cdp.eval(`fetch('/api/me').then(r => r.json()).then(m => m.email || '')`);

    // ── Settings: what a maintainer sees ──
    await cdp.eval(`switchTab('settings')`);
    await waitFor(cdp, `${text('#ksList')}.includes(${q(ORG)})`, 'the organisation source in Settings');
    out.settings_names = await cdp.eval(`[...document.querySelectorAll('#ksList .ks-card .exec-name')].map(e => e.textContent)`);
    out.org_controls = await cdp.eval(`[...(${cardOf(ORG)}).querySelectorAll('[data-ks]')].map(b => b.dataset.ks)`);
    out.bob_on_page = await cdp.eval(`document.body.textContent.includes(${q(BOB)})`);

    // ── Connect a source, with a new credential ──
    await click(cdp, '#ksBody [data-ks="add"]');
    await waitFor(cdp, `window.isOverlayOpen('ks-overlay')`, 'the connect dialog');
    out.org_scope_disabled = await cdp.eval(`document.getElementById('ksScopeOrg').disabled`);
    out.personal_scope_checked = await cdp.eval(`document.getElementById('ksScopePersonal').checked`);
    await setValue(cdp, '#ksKind', 'uifake');
    await waitFor(cdp, `document.getElementById('ksRaw').style.display !== 'none'`, 'the raw configuration field');
    await type(cdp, '#ksName', MINE);
    await setValue(cdp, '#ksJSON', '{"site":"leadsite","fail":true}');
    await waitFor(cdp, `!!document.querySelector('#ksCred option[value="__new"]')`, 'the credential picker');
    await setValue(cdp, '#ksCred', '__new');
    await waitFor(cdp, `document.getElementById('ksCredNew').style.display !== 'none'`, 'the new credential fields');
    await setValue(cdp, '#ksCredName', 'lead-browser-token');
    await type(cdp, '#ksCredValue', TOKEN);
    await click(cdp, '#ks-overlay [data-act="testForm"]');
    await waitFor(cdp, `${text('#ksTestOut')}.includes('connection failed')`, 'the failed test');
    out.fail_text = await cdp.eval(text('#ksTestOut'));
    await snap(cdp, 'connect-dialog-failed-test', '#ks-overlay [role="dialog"]');
    out.value_cleared = await cdp.eval(`document.getElementById('ksCredValue').value === ''`);
    out.cred_selected = await cdp.eval(`document.getElementById('ksCred').value`);
    out.token_in_page = await cdp.eval(`document.documentElement.outerHTML.includes(${q(TOKEN)}) ||
      [...document.querySelectorAll('input,textarea')].some(e => e.value.includes(${q(TOKEN)}))`);
    await setValue(cdp, '#ksJSON', '{"site":"leadsite"}');
    await click(cdp, '#ks-overlay [data-act="testForm"]');
    await waitFor(cdp, `${text('#ksTestOut')}.includes('Connected')`, 'the passing test');
    out.ok_text = await cdp.eval(text('#ksTestOut'));
    await click(cdp, '#ks-overlay [data-act="save"]');
    await waitFor(cdp, `!window.isOverlayOpen('ks-overlay') && !!(${cardOf(MINE)})`, 'the saved source\'s card');

    // ── Sync now: the card follows the sync from pushes alone ──
    const mineID = await cdp.eval(`(${cardOf(MINE)}).dataset.src`);
    const listsBefore = requests.filter(r => r === 'GET /api/knowledge/sources').length;
    await click(cdp, `#ksList [data-ks="sync"][data-id="${mineID}"]`);
    await waitFor(cdp, `(() => { const c = ${cardOf(MINE)}; return !!c && c.textContent.includes('synced')
      && c.textContent.includes('2 documents'); })()`, 'the synced card');
    out.synced_card = await cdp.eval(`(${cardOf(MINE)}).textContent`);
    await snap(cdp, 'settings-knowledge-sources', '#ksSection');
    out.list_refetches = requests.filter(r => r === 'GET /api/knowledge/sources').length - listsBefore;

    // A colleague renames their source, then an administrator syncs the
    // organisation's, elsewhere. The hub delivers what it owes in order, so
    // once the sync's end has arrived, whatever the rename would have sent
    // has too: none of it may name the colleague's source.
    await ctl('POST', '/bob-rename');
    await ctl('POST', '/org-sync');
    await waitFor(cdp, `(() => { const c = ${cardOf(ORG)}; return !!c && c.textContent.includes('synced') })()`,
      'the organisation source\'s sync, pushed');
    out.knowledge_frames = frames.filter(f => f.includes('"knowledge_source"')).length;
    out.frames_naming_bob = frames.filter(f => f.includes(BOB)).length;
    out.bob_on_page_after = await cdp.eval(`document.body.textContent.includes(${q(BOB)})`);

    // ── Bind → search ──
    await cdp.eval(`switchTab('knowledge')`);
    await waitFor(cdp, `!!document.getElementById('knBindSrc')`, 'the bind form');
    out.bindable = await cdp.eval(`[...document.querySelectorAll('#knBindSrc option')].map(o => o.textContent)`);
    await click(cdp, '#tab-knowledge [data-act="bind"]');
    await waitFor(cdp, `${text('#knBound')}.includes(${q(MINE)})`, 'the bound source');
    await type(cdp, '#knQ', 'roll back');
    await click(cdp, '#knSearchBtn');
    await waitFor(cdp, `document.querySelectorAll('#knHits .kn-hit').length >= 2`, 'the search results');
    const HITS = `[...document.querySelectorAll('#knHits .kn-hit')].map(li => { const a = li.querySelector('a');
      return {title: li.querySelector('.kn-hit-head').textContent, href: a ? a.getAttribute('href') : '', target: a ? a.target : '',
        rel: a ? a.rel : '', marks: li.querySelectorAll('mark').length, markup: li.querySelectorAll('img,svg,script').length,
        where: li.querySelector('.form-hint').textContent, snippet: (li.querySelector('.kn-snip') || {}).textContent || ''}; })`;
    out.hits = await cdp.eval(HITS);
    await snap(cdp, 'knowledge-tab-search', '#tab-knowledge');
    out.mode = await cdp.eval(text('#knMode'));

    // The retrieval setting.
    await cdp.eval(`(() => { const c = document.getElementById('knInject'); if (c.checked) c.click(); return true; })()`);
    await setValue(cdp, '#knPassages', '3');
    await click(cdp, '#tab-knowledge [data-act="saveRun"]');
    await waitFor(cdp, `fetch('/api/projects/0/knowledge/retrieval').then(r => r.json()).then(d => d.retrieval &&
      d.retrieval.k === 3 && !d.retrieval.enabled)`, 'the retrieval setting to be stored');
    out.retrieval_saved = true;

    // Narrowed to a space, the hostile document — in OPS — no longer matches.
    await click(cdp, '#knBound [data-act="editNarrow"]');
    await waitFor(cdp, `!!document.getElementById('knNarrowSpaces')`, 'the narrowing form');
    await type(cdp, '#knNarrowSpaces', 'ENG');
    await click(cdp, '#knBound [data-act="saveNarrow"]');
    await waitFor(cdp, `${text('#knBound')}.includes('Narrowed to Spaces: ENG')`, 'the narrowed binding');
    await click(cdp, '#knSearchBtn');
    await waitFor(cdp, `document.querySelectorAll('#knHits .kn-hit').length === 1`, 'the narrowed results');
    out.narrowed_hits = await cdp.eval(HITS);

    await cdp.eval(`window.confirm = () => true`);
    await click(cdp, '#knBound [data-act="unbind"]');
    await waitFor(cdp, `${text('#knBound')}.includes('No source is bound')`, 'the source to be unbound');
    out.unbound = true;

    // ── A task's citations ──
    await cdp.eval(`switchTab('tasks')`);
    await cdp.eval(`window.openTaskDetails(${TASK})`);
    await waitFor(cdp, `${text('#td-cite')}.includes('Knowledge cited')`, 'the task\'s citations');
    await snap(cdp, 'task-details-citations', '#td-cite');
    out.cites = await cdp.eval(`({text: ${text('#td-cite')}, links: [...document.querySelectorAll('#td-cite a')].map(a => a.getAttribute('href')),
      markup: document.querySelectorAll('#td-cite img,#td-cite svg,#td-cite script').length})`);

    out.xss = await cdp.eval(`window.__xss === undefined ? null : String(window.__xss)`);
    out.csp = await cdp.eval(`window.__csp`);
    process.stdout.write(JSON.stringify(out, null, 2));
  } catch (e) {
    out.error = {message: String(e && e.message || e)};
    out.debug = await evalSafe(cdp, `({
      toasts: window.__toasts || [],
      active: [...document.querySelectorAll('.tab-panel.active')].map(p => p.id),
      ks: ${text('#ksBody')}.slice(0, 2000), kn: ${text('#tab-knowledge')}.slice(0, 2000),
      test: ${text('#ksTestOut')}, location: location.href,
    })`);
    out.requests = requests.slice(-40);
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
