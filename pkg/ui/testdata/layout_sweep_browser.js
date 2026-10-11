// layout_sweep_browser.js — every dashboard tab and every dialog, laid out by a
// real browser at phone, tablet and desktop widths, and asked whether anything
// spills, clips or hangs off the screen (Task 20407).
//
// Usage: node layout_sweep_browser.js <chrome> <base-url> <config.json>
// Prints one JSON document on stdout; layout_sweep_browser_test.go owns every
// judgement made from it.
//
// The config names the viewports, the tabs, the elements allowed to scroll
// sideways and the fixture's strings. The dialogs are this file's: OPENERS
// below is the registry the Go side holds against every openOverlay() call
// site, so a dialog added without an opener here fails the gate.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const CONFIG = JSON.parse(fs.readFileSync(process.argv[4], 'utf8'));
const F = CONFIG.fixture;

const sleep = ms => new Promise(r => setTimeout(r, ms));

// How long Chrome gets to report its DevTools port, in 50 ms polls: 90 s
// (Task 20372).
const CHROME_START_POLLS = 1800;

// How long to keep looking for a condition, never a pause a healthy run sits
// out: under -race a control-plane round trip can take seconds.
const WAIT_MS = 30000;

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.handlers = [];
    ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id === undefined) {
        for (const h of this.handlers) h(msg);
        return;
      }
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    });
  }
  on(fn) { this.handlers.push(fn); }
  send(method, params) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      // Cleared on the reply (Task 20372).
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
    const r = await this.send('Runtime.evaluate', {expression: expr, awaitPromise: true, returnByValue: true});
    if (r.exceptionDetails) {
      throw new Error('eval failed: ' + JSON.stringify(r.exceptionDetails.exception || r.exceptionDetails));
    }
    return r.result.value;
  }
  async key(key, code, vk, modifiers) {
    const base = {key, code, windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk, modifiers: modifiers || 0};
    await this.send('Input.dispatchKeyEvent', Object.assign({type: 'rawKeyDown'}, base));
    await this.send('Input.dispatchKeyEvent', Object.assign({type: 'keyUp'}, base));
  }
}

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-layoutsweep-'));
  const proc = spawn(CHROME, ['--headless=new', '--remote-debugging-port=0', '--user-data-dir=' + dir,
    '--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', 'about:blank'],
  {stdio: ['ignore', 'ignore', 'pipe'], detached: true});
  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });
  // A launch that fails after the spawn must take Chrome with it, or node never
  // exits and the Go test hangs to the package timeout (Task 20340).
  try {
    let port = 0;
    for (let i = 0; i < CHROME_START_POLLS && !port; i++) {
      await sleep(50);
      if (proc.exitCode !== null) throw new Error('chrome exited: ' + stderr);
      try {
        const txt = fs.readFileSync(path.join(dir, 'DevToolsActivePort'), 'utf8').split('\n');
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
      setTimeout(() => rej(new Error('cdp connect timed out')), 15000).unref();
      ws.addEventListener('open', res, {once: true});
      ws.addEventListener('error', () => rej(new Error('cdp connect failed')), {once: true});
    });
    return {cdp: new CDP(ws), proc, dir};
  } catch (e) {
    try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) { /* already gone */ }
    throw e;
  }
}

// Chrome runs in its own process group (spawned detached), so one signal takes
// its helpers with it; then the profile can go.
async function closeChrome(proc, dir) {
  try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) { /* already gone */ }
  for (let i = 0; i < 100 && proc.exitCode === null && proc.signalCode === null; i++) await sleep(20);
  try { fs.rmSync(dir, {recursive: true, force: true, maxRetries: 5, retryDelay: 100}); } catch (_) { /* best effort */ }
}

// ── The probe ───────────────────────────────────────────────────────────────
//
// Installed in every document the page loads. measure() walks the visible tree
// under a scope and reports five kinds of finding, each against the width and
// height the driver asked Chrome to emulate rather than window.innerWidth: once
// a mobile page overflows, Chrome zooms it out until it fits, the layout
// viewport grows, and every rect measured afterwards describes the damage
// instead of the device — the check reads clean on exactly the broken page.
//
//   page     the document's own sideways scroll, and that zoom-out.
//   spill    an element whose content runs out of a box that does not clip
//            or scroll. scrollWidth against clientWidth, not a rect: a flex
//            item squeezed by min-width:0 reports a tidy box while its
//            unbreakable text runs straight through its side.
//   clip     the same in a box that hides its overflow — content the user
//            simply never sees. text-overflow:ellipsis is a truncation the
//            user is told about, and is not reported.
//   scroll   a box that scrolls sideways and is not on the allowlist.
//   control  a button or field that no scroll brings fully onto the screen.
//
// Only the innermost cause is reported: a spill that a spilling descendant
// already explains (its content reaches as far) is that descendant's, so one
// unbreakable word is one finding rather than one per ancestor.
const PROBE = String.raw`
window.__sweep = (function () {
  'use strict';
  const SKIP = new Set(['SCRIPT', 'STYLE', 'LINK', 'META', 'TEMPLATE', 'NOSCRIPT', 'BR', 'WBR',
    'INPUT', 'TEXTAREA', 'SELECT', 'OPTION', 'OPTGROUP', 'IFRAME', 'CANVAS', 'IMG', 'VIDEO',
    'AUDIO', 'OBJECT', 'EMBED']);
  const CONTROLS = 'button, input:not([type="hidden"]), select, textarea, [role="button"], summary';

  function describe(el) {
    let s = el.tagName.toLowerCase();
    if (el.id) s += '#' + el.id;
    const cls = typeof el.className === 'string' ? el.className.trim().split(/\s+/).filter(Boolean) : [];
    if (cls.length) s += '.' + cls.slice(0, 3).join('.');
    return s;
  }
  // A findable name: the element and its ancestors up to the nearest id.
  function where(el) {
    const parts = [];
    for (let n = el; n && n !== document.documentElement && parts.length < 5; n = n.parentElement) {
      parts.unshift(describe(n));
      if (n.id) break;
    }
    return parts.join(' > ');
  }
  function sample(node) {
    return (node.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 70);
  }
  function hiddenByDesign(el, cs, r) {
    if (r.width <= 1 || r.height <= 1) return true;
    if (cs.clip && cs.clip !== 'auto') return true;
    if (cs.clipPath && cs.clipPath !== 'none') return true;
    for (let n = el; n && n !== document.body; n = n.parentElement) {
      if (getComputedStyle(n).opacity === '0') return true;
    }
    return false;
  }
  function allowedSel(el, allow) {
    for (const a of allow) { try { if (el.matches(a)) return a; } catch (e) { /* bad selector */ } }
    return '';
  }
  // The allowlist as it applies at this width: an entry may scroll only up to
  // its own max_width (0: at every width).
  function allowedAt(allow, W) {
    return allow.filter(a => !a.max_width || W <= a.max_width).map(a => a.selector);
  }
  function inAllowedScroller(el, allow) {
    for (let n = el.parentElement; n; n = n.parentElement) if (allowedSel(n, allow)) return true;
    return false;
  }
  function extents(el, cs) {
    const r = el.getBoundingClientRect();
    const left = r.left + (parseFloat(cs.borderLeftWidth) || 0);
    return {r, boxRight: left + el.clientWidth, contentRight: left + el.scrollWidth};
  }
  // culprit names whatever reaches furthest right inside el: a descendant
  // element, or a run of text el holds directly (an unbreakable word has no
  // box of its own to blame).
  function culprit(el, limit) {
    let best = null, bestRight = limit + 1;
    const seen = [el];
    let count = 0;
    while (seen.length && count < 3000) {
      const n = seen.pop();
      count++;
      for (const c of n.childNodes) {
        if (c.nodeType === 3) {
          if (!c.textContent.trim()) continue;
          const rg = document.createRange();
          rg.selectNodeContents(c);
          const rr = rg.getBoundingClientRect();
          if (rr.right > bestRight) { bestRight = rr.right; best = {where: where(n) + ' (text)', text: sample(c)}; }
        } else if (c.nodeType === 1 && !(c instanceof SVGElement && c.tagName !== 'svg')) {
          const ccs = getComputedStyle(c);
          if (ccs.display === 'none' || !c.checkVisibility()) continue;
          const rr = c.getBoundingClientRect();
          if (rr.width > 0 && rr.right >= bestRight) { bestRight = rr.right; best = {where: where(c), text: sample(c)}; }
          if (ccs.overflowX === 'visible') seen.push(c);
        }
      }
    }
    return best;
  }

  function measure(opts) {
    const W = opts.w, H = opts.h, allow = allowedAt(opts.allow || [], W);
    const de = document.documentElement;
    const out = {
      page: {
        expected_width: W, inner_width: window.innerWidth, inner_height: window.innerHeight,
        scroll_width: de.scrollWidth, client_width: de.clientWidth,
        overflow_px: de.scrollWidth - de.clientWidth,
      },
      offenders: [], allowed: [], elements: 0, controls: 0, roots: 0,
    };
    const roots = [];
    for (const s of opts.scope) for (const el of document.querySelectorAll(s)) roots.push(el);
    const flagged = [];
    const stack = roots.slice();
    while (stack.length) {
      const el = stack.pop();
      if (!(el instanceof HTMLElement) || SKIP.has(el.tagName)) continue;
      const cs = getComputedStyle(el);
      // checkVisibility, not a rect: the body of a closed <details> keeps its
      // boxes under content-visibility:hidden, and getClientRects reports
      // them as if they were on screen.
      if (cs.display === 'none' || !el.checkVisibility()) continue;
      for (const c of el.children) stack.push(c);
      if (cs.display === 'contents' || cs.visibility === 'hidden') continue;
      out.elements++;
      const over = el.scrollWidth - el.clientWidth;
      if (over <= 1 || el.clientWidth === 0) continue;
      const ext = extents(el, cs);
      if (hiddenByDesign(el, cs, ext.r)) continue;
      const ox = cs.overflowX;
      let kind;
      if (ox === 'auto' || ox === 'scroll') kind = 'scroll';
      else if (ox === 'hidden' || ox === 'clip') {
        if (cs.textOverflow === 'ellipsis') continue;
        kind = 'clip';
      } else kind = 'spill';
      if (kind === 'scroll') {
        const a = allowedSel(el, allow);
        if (a) { out.allowed.push({selector: a, where: where(el), over_px: over}); continue; }
      }
      flagged.push({el, kind, over, ext});
    }
    for (const r of roots) if (r.checkVisibility()) out.roots++;

    // The innermost cause only.
    const keep = flagged.filter(f => !flagged.some(d => d !== f && d.kind === 'spill' &&
      f.el.contains(d.el) && d.ext.contentRight >= f.ext.contentRight - 1));
    for (const f of keep) {
      const c = f.kind === 'scroll' ? null : culprit(f.el, f.ext.boxRight);
      out.offenders.push({
        kind: f.kind, where: where(f.el), over_px: Math.round(f.over),
        text: sample(f.el), culprit: c ? c.where : '', culprit_text: c ? c.text : '',
      });
    }

    // Controls: fully on screen, or brought there by the scroll a user has.
    // Not on a page that zoomed out to fit: every rect is then in the
    // widened viewport, the zoom is already the finding, and what it hides
    // is measured again once it is fixed. Nor inside a box already reported
    // as overflowing — that box is why the control is off the edge.
    const fits = r => r.left >= -1 && r.right <= W + 1 &&
      (r.height > H ? r.top >= -1 && r.top <= H : r.top >= -1 && r.bottom <= H + 1);
    if (window.innerWidth > W + 1) roots.length = 0;
    for (const root of roots) {
      for (const el of root.querySelectorAll(CONTROLS)) {
        if (!el.checkVisibility({checkVisibilityCSS: true})) continue;
        const cs = getComputedStyle(el);
        let r = el.getBoundingClientRect();
        if (hiddenByDesign(el, cs, r)) continue;
        out.controls++;
        if (fits(r)) continue;
        if (keep.some(f => f.el.contains(el))) continue;
        // Bring it into view the way the page lets a user: every scrolling
        // ancestor, then put them all back.
        const saved = [];
        for (let n = el.parentElement; n; n = n.parentElement) saved.push([n, n.scrollLeft, n.scrollTop]);
        const wx = window.scrollX, wy = window.scrollY;
        el.scrollIntoView({block: 'nearest', inline: 'nearest', behavior: 'instant'});
        r = el.getBoundingClientRect();
        const ok = fits(r);
        for (const [n, l, t] of saved) n.scrollTo({left: l, top: t, behavior: 'instant'});
        window.scrollTo({left: wx, top: wy, behavior: 'instant'});
        if (ok) continue;
        if (r.left >= -1 && r.right <= W + 1 && inAllowedScroller(el, allow)) continue;
        out.offenders.push({
          kind: 'control', where: where(el), text: sample(el) || el.getAttribute('aria-label') || el.name || '',
          left: Math.round(r.left), right: Math.round(r.right), top: Math.round(r.top), bottom: Math.round(r.bottom),
          over_px: Math.round(Math.max(r.right - W, -r.left, r.height > H ? -r.top : r.bottom - H, 0)),
        });
      }
    }
    return out;
  }

  // seen reports which allowlisted selectors match an element on screen now,
  // so an entry for something the page no longer draws can be called stale.
  function seen(allow) {
    return allow.map(a => a.selector)
      .filter(a => [...document.querySelectorAll(a)].some(e => e.checkVisibility()));
  }

  return {measure, seen};
})();
`;

// ── Page helpers ────────────────────────────────────────────────────────────

const q = s => JSON.stringify(s);
const visible = sel => `(() => { const e = document.querySelector(${q(sel)});
  return !!e && e.checkVisibility({checkVisibilityCSS: true}); })()`;
const textOf = sel => `((document.querySelector(${q(sel)}) || {}).innerText || '')`;
const hasText = (sel, s) => `${textOf(sel)}.includes(${q(s)})`;
// hasContent reads textContent, which an SVG's text has and innerText may not.
const hasContent = (sel, s) => `((document.querySelector(${q(sel)}) || {}).textContent || '').includes(${q(s)})`;

let cdp;
let inflight = new Map();   // requestId -> url, for the requests the page is waiting on
let current = 'boot';       // the scenario running, to attribute what the page throws
const exceptions = [];      // every uncaught exception, by scenario

function track() {
  cdp.on(msg => {
    const p = msg.params || {};
    switch (msg.method) {
    case 'Network.requestWillBeSent':
      // A server-sent event stream never finishes; it is not a load.
      if (p.type !== 'EventSource') inflight.set(p.requestId, p.request.url);
      break;
    case 'Network.loadingFinished':
    case 'Network.loadingFailed':
      inflight.delete(p.requestId);
      break;
    case 'Runtime.exceptionThrown': {
      const d = p.exceptionDetails || {};
      exceptions.push({scenario: current, message: (d.exception && d.exception.description || d.text || '').split('\n')[0]});
      break;
    }
    case 'Page.javascriptDialogOpening':
      // confirm() and prompt() block the page; nothing here wants one.
      cdp.send('Page.handleJavaScriptDialog', {accept: false}).catch(() => {});
      break;
    }
  });
}

// waitFor polls expr until it is truthy. On a timeout it says what diag, an
// expression for what the page shows instead, evaluates to — usually the
// whole diagnosis.
async function waitFor(expr, what, diag) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    let v = false;
    try { v = await cdp.eval(expr); } catch (e) { /* navigating */ }
    if (v) return v;
    if (Date.now() >= deadline) {
      let said = '';
      try { said = diag ? ' — the page shows: ' + await cdp.eval(diag) : ''; } catch (e) { /* gone */ }
      throw new Error('timed out waiting for ' + what + said);
    }
    await sleep(25);
  }
}

// settled resolves once the page has rendered two frames: a
// requestAnimationFrame callback runs before its own frame is laid out.
const settled = () => cdp.eval('new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))');

// idle is the readiness signal: no request in flight, through a settle, twice
// running — so a panel that renders a response and then fetches the next thing
// it needs is waited out, not caught between the two.
async function idle(what) {
  const deadline = Date.now() + WAIT_MS;
  let quiet = 0;
  while (quiet < 2) {
    if (Date.now() >= deadline) {
      throw new Error('the page never went quiet ' + what + ': still loading ' + [...inflight.values()].join(', '));
    }
    if (inflight.size === 0) {
      await settled();
      quiet = inflight.size === 0 ? quiet + 1 : 0;
    } else {
      quiet = 0;
      await sleep(15);
    }
  }
}

async function click(sel) {
  const r = await cdp.eval(`(() => { const e = document.querySelector(${q(sel)});
    if (!e) return 'no element ' + ${q(sel)};
    e.click(); return 'ok'; })()`);
  if (r !== 'ok') throw new Error(r);
}

async function type(sel, value) {
  const r = await cdp.eval(`(() => { const e = document.querySelector(${q(sel)});
    if (!e) return 'no element ' + ${q(sel)};
    e.value = ${q(value)};
    e.dispatchEvent(new Event('input', {bubbles: true}));
    e.dispatchEvent(new Event('change', {bubbles: true}));
    return 'ok'; })()`);
  if (r !== 'ok') throw new Error(r);
}

let viewport = null;
async function setViewport(v) {
  viewport = v;
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: v.width, height: v.height, deviceScaleFactor: v.scale, mobile: v.mobile,
  });
  // A page that overflowed at the last width was zoomed out to fit; that
  // scale must not be carried into a measurement at this one.
  await cdp.send('Emulation.resetPageScaleFactor');
  await cdp.eval('window.scrollTo(0, 0)');
  await settled();
}

async function setTheme(theme) {
  const now = await cdp.eval(`document.documentElement.getAttribute('data-theme') || 'dark'`);
  if (now !== theme) await click('#themeToggleBtn');
  await waitFor(`document.documentElement.getAttribute('data-theme') === ${q(theme)}`, 'the ' + theme + ' theme');
  await settled();
  // The Timeline redraws itself in the new colours from a fresh response.
  if (inflight.size) await idle('after switching to the ' + theme + ' theme');
}

// measure probes the current frame: the probe's own reads force a layout, so
// it needs no settle of its own beyond the one that let scripts react.
const measure = scope =>
  cdp.eval(`window.__sweep.measure(${q({w: viewport.width, h: viewport.height, scope, allow: CONFIG.allow})})`);

// shot saves what was measured, when LAYOUT_SWEEP_SHOTS names a directory: a
// finding names the element, a picture shows what it did to the page.
async function shot(name) {
  if (!CONFIG.shots) return;
  const m = await cdp.send('Page.getLayoutMetrics');
  const h = Math.min(Math.ceil(m.cssContentSize.height), 6000);
  const r = await cdp.send('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true,
    clip: {x: 0, y: 0, width: viewport.width, height: h, scale: 1}});
  fs.writeFileSync(path.join(CONFIG.shots, name.replace(/[^a-z0-9_-]+/gi, '_') + '.png'), Buffer.from(r.data, 'base64'));
}

// ── Navigation ──────────────────────────────────────────────────────────────

// closeAll dismisses every open dialog through its own close path, frontmost
// first, and fails if one will not go: a dialog left open would sit over every
// later measurement.
async function closeAll() {
  for (let i = 0; i < 6; i++) {
    const top = await cdp.eval(`(() => { const t = window.topOverlay(); return t ? t.el.id || '?' : ''; })()`);
    if (!top) break;
    if (top === 'loginOverlay') await cdp.eval(`window.closeOverlay('loginOverlay')`);
    else await cdp.eval(`window.dismissTopOverlay()`);
    await settled();
  }
  const still = await cdp.eval(`(() => { const t = window.topOverlay(); return t ? t.el.id || '?' : ''; })()`);
  if (still) throw new Error('could not close the dialog ' + still);
}

async function selectProject() {
  // The fixture project, opened as a person does: from its card on the grid.
  await cdp.eval(`switchTab('projects')`);
  await waitFor(`[...document.querySelectorAll('#projList .proj-card')].some(c => c.innerText.includes(${q(F.project)}))`,
    'the fixture project on the grid');
  await cdp.eval(`(() => { const c = [...document.querySelectorAll('#projList .proj-card')]
    .find(c => c.innerText.includes(${q(F.project)})); c.click(); })()`);
  await waitFor(hasText('#projectBreadcrumb', F.project), 'the fixture project to open');
  await openTab('tasks');
  // Completed tasks too: they carry the longest content a task has, its result.
  await click('#toggleCompletedBtn');
  await waitFor(hasText('#taskListFull', F.taskTitle), 'the fixture project\'s tasks');
}

async function openTab(name) {
  await cdp.eval(`switchTab(${q(name)})`);
  await idle('on the ' + name + ' tab');
}

// ── Tabs ────────────────────────────────────────────────────────────────────
//
// TAB_READY says, for every tab, what its fixture content looks like once it
// has rendered: a tab measured while it still says "Loading…" passes every
// check and proves nothing. A tab without an entry is an error.

const TAB_READY = {
  'overview': hasContent('#goalText', F.project),
  'tasks': hasContent('#taskListFull', F.taskTitle),
  'queue': hasContent('#queueTable', F.taskTitle),
  'kanban': hasContent('#kanbanBoard', F.riskTaskTitle),
  'timeline': hasContent('#timelineChart', F.taskTitle.slice(0, 24)),
  'kb': hasContent('#tab-kb', F.taskTitle),
  'deps': `!!document.querySelector('#depsSvg .deps-node')`,
  // Titles past 57 characters are cut there.
  'risk-matrix': hasContent('#rmTable', F.riskTaskTitle.slice(0, 40)),
  'analytics': `!!window.Chart && document.getElementById('analyticsCharts').style.display !== 'none'`,
  'chat': hasContent('#chatMessages', F.deviceName),
  'assistant': hasContent('#assistantMessages', F.taskTitle),
  'replay': hasContent('#replayRuns', F.taskTitle),
  'provider-calls': hasContent('#pcTbody', F.model),
  'projects': hasContent('#projList', F.project),
  'budget': `!!document.querySelector('#diskUsageBody .du-headline')`,
  'executors': hasContent('#execList', F.deviceName),
  'secrets': hasContent('#secSecretsBody', F.secret),
  'audit': `document.querySelectorAll('#auditBody .audit-row').length > 0`,
  'quotas': hasContent('#quotaBody', F.email),
  'telemetry': hasContent('#telemetryBody', F.resultMarker),
  'settings': `${hasContent('#usbList', 'YubiHSM')} && !${hasContent('#buildInfoBody', 'Loading')}`,
};

// ── Dialogs ─────────────────────────────────────────────────────────────────
//
// OPENERS is the registry of every dialog the dashboard opens, keyed by the
// overlay root's id, with a #variant where one dialog has two faces. Each
// opener reaches its dialog the way a person does where the page offers a way
// — a card's button, a tab's toolbar, a keyboard shortcut — with the fixture's
// long content in place, and resolves once the dialog shows it. The Go side
// reads the keys from this source (TestLayoutSweep_EveryDialogHasAnOpener),
// so the list cannot fall behind the page.
//
// widths narrows a dialog to the viewports where it exists at all.

const execCard = fn => `#execList button[onclick*="'${fn}'"]`;

async function onExecutors(fn) {
  await openTab('executors');
  await waitFor(visible(execCard(fn)), 'the device card\'s ' + fn + ' button');
  await click(execCard(fn));
}

async function onSecrets(act) {
  await openTab('secrets');
  await waitFor(visible(`#tab-secrets [data-act="${act}"]`), 'the Secrets tab\'s ' + act + ' button');
  await click(`#tab-secrets [data-act="${act}"]`);
}

// onTask presses one of a task row's own buttons on the Tasks tab.
async function onTask(fn, id) {
  await openTab('tasks');
  const sel = `#taskListFull .task-item[data-task-id="${id}"] button[onclick="${fn}(${id})"]`;
  await waitFor(visible(sel), 'task #' + id + '\'s ' + fn + ' button');
  await click(sel);
}

const OPENERS = {
  'loginOverlay': {
    // Only a token hub shows it, and a token hub cannot serve its own bundle
    // before sign-in (/assets answers 401), so it is raised directly.
    open: async () => {
      await cdp.eval(`window.openOverlay('loginOverlay', {focus: '#loginTokenInput'})`);
      await type('#loginTokenInput', F.token);
    },
    ready: visible('#loginTokenInput'),
  },
  'mobileNavOverlay': {
    widths: ['phone-320', 'phone-390'],
    open: async () => { await waitFor(visible('#hamburgerBtn'), 'the hamburger'); await click('#hamburgerBtn'); },
    ready: visible('#mobileNavOverlay .mobile-nav-close'),
  },
  'voiceModalBackdrop': {
    open: async () => { await openTab('overview'); await click('#micBtn'); },
    ready: visible('#voiceRecordBtn'),
  },
  'replayDiffModal': {
    open: async () => {
      await openTab('replay');
      await waitFor(visible('#replayRuns .replay-row'), 'a replay run');
      await click('#replayRuns .replay-row');
    },
    ready: hasText('#replayDiffModal', F.replayOutput),
  },
  'pcModal': {
    open: async () => {
      await openTab('provider-calls');
      await waitFor(visible('#pcTbody [onclick*="openProviderCallModal"]'), 'a provider call');
      await click('#pcTbody [onclick*="openProviderCallModal"]');
    },
    ready: hasText('#pcModal', F.promptMarker),
  },
  'new-project-overlay': {
    open: async () => {
      await openTab('projects');
      await waitFor(visible('[onclick*="openNewProjectModal"]'), 'the New project button');
      await click('[onclick*="openNewProjectModal"]');
    },
    ready: visible('#new-project-overlay input'),
  },
  'executor-picker-overlay': {
    open: async () => { await openTab('overview'); await cdp.eval(`window.openExecutorPickerModal()`); },
    ready: hasText('#executor-picker-overlay', F.deviceName),
  },
  'provider-model-overlay': {
    open: async () => { await openTab('overview'); await cdp.eval(`window.openProviderModelModal()`); },
    ready: visible('#provider-model-overlay select'),
  },
  'review-gate-overlay': {
    open: async () => { await openTab('overview'); await cdp.eval(`window.openReviewGateModal()`); },
    ready: visible('#rgEnabled'),
  },
  'goal-edit-overlay': {
    open: async () => { await openTab('overview'); await cdp.eval(`window.openGoalEditModal()`); },
    ready: `(document.getElementById('goalEditInput') || {}).value === ${q(F.goal)}`,
  },
  'instructions-edit-overlay': {
    open: async () => { await openTab('overview'); await cdp.eval(`window.openInstructionsEditModal()`); },
    ready: `(document.getElementById('instructionsEditInput') || {}).value === ${q(F.instructions)}`,
  },
  'delete-modal-overlay': {
    open: async () => { await onTask('removeTask', F.taskID); },
    ready: visible('#delete-modal-overlay button'),
  },
  'modal-overlay': {
    // The edit dialog; adding a task is the Tasks tab's own form.
    open: async () => { await onTask('openEditModal', F.taskID); },
    ready: `(document.getElementById('modalTitle_') || {}).value === ${q(F.taskTitle)}`,
  },
  'td-overlay': {
    open: async () => {
      await openTab('tasks');
      await click(`#taskListFull .task-item[data-task-id="${F.taskID}"] .task-title`);
    },
    ready: hasText('#td-body', F.resultMarker),
  },
  'at-overlay': {
    // Over the task details it is opened from, as the page does.
    open: async () => {
      await openTab('tasks');
      await cdp.eval(`window.openTaskDetails(${F.taskID})`);
      await waitFor(hasText('#td-body', F.resultMarker), 'the task details');
      await cdp.eval(`window.taskDetailsAttach()`);
    },
    ready: visible('#at-screen'),
  },
  'dr-overlay': {
    // Over the edit dialog of a task that already has a description: the
    // only case where dictation asks how to apply what it heard.
    open: async () => {
      await onTask('openEditModal', F.taskID);
      await waitFor(`(document.getElementById('modalDesc') || {}).value.length > 0`, 'the description');
      await cdp.eval(`window.openDictateApply(${q(F.transcript)})`);
    },
    ready: hasText('#dr-overlay', F.transcriptMarker),
  },
  'dc-overlay': {
    open: async () => { await onTask('openDecomposeModal', F.pendingTaskID); },
    ready: visible('#dc-overlay button'),
  },
  'newfeat-overlay': {
    open: async () => {
      await openTab('overview');
      await waitFor(visible('#newFeatureBtn'), 'the New feature button');
      await click('#newFeatureBtn');
    },
    ready: visible('#nfName'),
  },
  'featpr-overlay': {
    open: async () => {
      await openTab('overview');
      await waitFor(visible('#featuresList [data-act="pr"]'), 'a feature row');
      await click('#featuresList [data-act="pr"]');
    },
    ready: visible('#fprSubmit'),
  },
  'delfeat-overlay': {
    open: async () => {
      await openTab('overview');
      await waitFor(visible('#featuresList [data-act="remove"]'), 'a feature row');
      await click('#featuresList [data-act="remove"]');
    },
    ready: visible('#delfeat-overlay button'),
  },
  'delproj-overlay': {
    open: async () => {
      await openTab('projects');
      await cdp.eval(`(() => { const c = [...document.querySelectorAll('#projList .proj-card')]
        .find(c => c.innerText.includes(${q(F.project)}));
        c.querySelector('[onclick*="projectDelete"]').click(); })()`);
    },
    ready: hasText('#delproj-overlay', F.project),
  },
  'hiddenproj-overlay': {
    open: async () => {
      await openTab('settings');
      await waitFor(`(() => { const b = document.getElementById('hiddenProjectsBtn'); return !!b && !b.disabled; })()`,
        'the hidden-projects button');
      await click('#hiddenProjectsBtn');
    },
    ready: hasText('#hiddenProjectsList', F.hiddenProject),
  },
  'cmd-backdrop': {
    open: async () => { await cdp.key('k', 'KeyK', 75, 2); },
    ready: visible('#cmd-input'),
  },
  'help-backdrop': {
    open: async () => { await cdp.eval(`window.openHelpModal()`); },
    ready: visible('#help-backdrop .help-row-keys'),
  },
  'enroll-overlay': {
    // Submitted, so the dialog shows what it is for: the join command, which
    // is the longest unbroken thing the hub ever prints.
    open: async () => {
      await openTab('executors');
      await click(`#tab-executors button[onclick*="'openEnrollModal'"]`);
      await waitFor(visible('#enrollName'), 'the enrollment form');
      await type('#enrollName', F.deviceName);
      await click('#enrollSubmitBtn');
    },
    ready: `${textOf('#enrollCommand')}.includes('cloop executor')`,
  },
  'executor-detail-overlay': {
    open: async () => { await onExecutors('openExecutorDetail'); },
    ready: `!!document.querySelector('#execDetailBody .exec-detail-verdict')`,
  },
  'executor-sandbox-overlay': {
    open: async () => { await onExecutors('openExecutorSandbox'); },
    ready: `(document.getElementById('execSandboxImage') || {}).value === ${q(F.image)}`,
  },
  'executor-virtual-overlay': {
    open: async () => { await onExecutors('openExecutorVirtual'); },
    ready: hasText('#executor-virtual-overlay', F.virtualName),
  },
  'executor-firewall-overlay': {
    open: async () => { await onExecutors('openExecutorFirewall'); },
    ready: visible('#efwAllow'),
  },
  'executor-limits-overlay': {
    open: async () => { await onExecutors('openExecutorLimits'); },
    ready: visible('#execLimitsMemory'),
  },
  'executor-audience-overlay': {
    open: async () => { await onExecutors('openExecutorAudience'); },
    ready: visible('#execAudienceValue'),
  },
  'secret-overlay': {
    open: async () => { await onSecrets('openSecretModal'); },
    ready: visible('#secretName'),
  },
  'grant-overlay': {
    open: async () => { await onSecrets('openGrantModal'); },
    ready: visible('#grantSubject'),
  },
  'token-overlay': {
    // Minted, so the dialog shows the one-time plaintext token.
    open: async () => {
      await onSecrets('openTokenModal');
      await waitFor(visible('#tokenName'), 'the token form');
      await type('#tokenName', F.tokenName);
      await cdp.eval(`(() => { const s = document.getElementById('tokenRoles');
        if (s.options.length) s.options[0].selected = true;
        s.dispatchEvent(new Event('change', {bubbles: true})); })()`);
      await click('#tokenSubmitBtn');
    },
    ready: `/^cloop_pat_/.test((document.getElementById('tokenPlaintext') || {}).value || '')`,
  },
  'request-overlay': {
    open: async () => { await onSecrets('openRequestModal'); },
    ready: visible('#requestSubject'),
  },
  'request-decide-overlay': {
    open: async () => {
      await openTab('secrets');
      await waitFor(`!!document.querySelector('[data-req-approve]')`, 'a request to decide');
      await click('[data-req-approve]');
    },
    ready: visible('#request-decide-overlay [data-act="submitDecision"]'),
  },
  'harness-cred-overlay': {
    open: async () => {
      await openTab('overview');
      await waitFor(visible('#harnessCredCard'), 'the Claude credential card');
      await click('#harnessCredCard');
    },
    ready: visible('#hcSecret'),
  },
};

// ── The run ─────────────────────────────────────────────────────────────────

async function sweepScenario(out, name, scope, viewports, before) {
  const rec = {name, measurements: []};
  out.scenarios.push(rec);
  current = name;
  const t0 = Date.now();
  try {
    for (const v of viewports) {
      await setViewport(v);
      // The opener's own requests are waited out in full; after a resize
      // only a request it set off is, so a quiet page is measured at once.
      if (before && v === viewports[0]) {
        await before();
        await idle('opening ' + name);
      } else if (inflight.size) {
        await idle('measuring ' + name + ' at ' + v.name);
      }
      const m = await measure(scope);
      m.viewport = v.name;
      m.theme = 'light';
      rec.measurements.push(m);
      await shot(name + '-' + v.name);
      if (v.name === CONFIG.dark_viewport) {
        await setTheme('dark');
        const d = await measure(scope);
        await shot(name + '-' + v.name + '-dark');
        d.viewport = v.name;
        d.theme = 'dark';
        rec.measurements.push(d);
        await setTheme('light');
      }
    }
  } catch (e) {
    rec.error = String(e && e.stack || e);
  }
  rec.ms = Date.now() - t0;
  return rec;
}

async function main() {
  const out = {scenarios: [], allow_seen: [], openers: Object.keys(OPENERS)};
  const launched = await launchChrome();
  cdp = launched.cdp;
  const t0 = Date.now();
  try {
    track();
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Network.enable');
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {source: PROBE});
    // The Assistant tab keeps its conversation in the session, so the fixture's
    // goes there; and a resume marker whose removal says boot is done.
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {source: `try {
      sessionStorage.setItem('cloop_resume', '{"at":0}');
      sessionStorage.setItem('cloop_assistant_history', ${q(JSON.stringify(F.assistant))});
      localStorage.setItem('cloop-theme', 'light');
    } catch (e) {}`});
    const vps = CONFIG.viewports;
    await setViewport(vps[vps.length - 1]);
    await cdp.send('Page.navigate', {url: BASE + '/'});
    await waitFor(`typeof window.switchTab === 'function' && typeof window.__sweep === 'object' &&
      sessionStorage.getItem('cloop_resume') === null`, 'the dashboard to boot');
    await idle('after boot');
    await selectProject();
    out.boot_ms = Date.now() - t0;

    const allowSeen = new Set();
    const noteAllowed = async () => {
      for (const s of await cdp.eval(`window.__sweep.seen(${q(CONFIG.allow)})`)) allowSeen.add(s);
    };

    const only = CONFIG.only ? new Set(CONFIG.only) : null;
    for (const tab of CONFIG.tabs) {
      if (only && !only.has('tab:' + tab)) continue;
      const rec = await sweepScenario(out, 'tab:' + tab, ['body'], vps, async () => {
        if (!TAB_READY[tab]) throw new Error('TAB_READY has no entry for the ' + tab + ' tab');
        await openTab(tab);
        await waitFor(TAB_READY[tab], 'the ' + tab + ' tab\'s content',
          `JSON.stringify(document.getElementById('tab-' + ${q(tab)}).innerText.slice(0, 300))`);
      });
      if (!rec.error) await noteAllowed();
    }

    for (const [key, op] of Object.entries(OPENERS)) {
      if (only && !only.has(key)) continue;
      const id = key.split('#')[0];
      const views = op.widths ? vps.filter(v => op.widths.includes(v.name)) : vps;
      const rec = await sweepScenario(out, 'dialog:' + key, ['#' + id], views, async () => {
        await closeAll();
        await op.open();
        await waitFor(`window.isOverlayOpen(${q(id)})`, 'the ' + key + ' dialog to open');
        await waitFor(op.ready, 'the ' + key + ' dialog\'s content');
      });
      if (!rec.error) await noteAllowed();
      try { await closeAll(); } catch (e) { rec.error = (rec.error ? rec.error + '; ' : '') + String(e); }
    }
    out.allow_seen = [...allowSeen];
    out.exceptions = exceptions;

    // ── The gate's own fixture ──
    // A page broken on purpose, once in each way the gate exists to catch,
    // beside the two things it must let through, measured by the same probe
    // at the narrowest width. A document of its own, so that what it proves
    // does not depend on the dashboard: on a dashboard that overflows, the
    // page zooms out and its controls go unmeasured. nowrap throughout, so no
    // inherited wrapping can mend the fixture. The document overflow goes in
    // last and alone, for the same reason.
    const v0 = vps[0];
    await setViewport(v0);
    const fixture = '<!DOCTYPE html><meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<body style="margin:8px"><div id="sweepSelfTest" style="font:14px sans-serif;white-space:nowrap">' +
      '<div id="stClip" style="width:120px;overflow:hidden">' + 'x'.repeat(60) + '</div>' +
      // In a box of its own that clips, so that the spill cannot widen the page.
      '<div style="width:250px;overflow:hidden"><div style="display:flex;width:200px">' +
        '<span id="stSpill" style="min-width:0">' + 'y'.repeat(60) + '</span></div></div>' +
      '<div id="stScroll" style="width:150px;overflow-x:auto">' + 'z '.repeat(80) + '</div>' +
      '<button id="stButton" style="position:fixed;top:40px;left:' + (v0.width - 40) + 'px;width:120px">Off the edge</button>' +
      '<div id="stEllipsis" style="width:120px;overflow:hidden;text-overflow:ellipsis">' + 'e'.repeat(60) + '</div>' +
      '<div id="stAllowed" class="sweep-selftest-allowed" style="width:150px;overflow-x:auto">' + 'a '.repeat(80) + '</div>' +
      '</div></body>';
    await cdp.send('Page.navigate', {url: 'data:text/html;charset=utf-8,' + encodeURIComponent(fixture)});
    await waitFor(`document.readyState === 'complete' && !!document.getElementById('sweepSelfTest')`, 'the self-test page');
    await cdp.eval(PROBE);
    await settled();
    const selfAllow = CONFIG.allow.concat([{selector: '.sweep-selftest-allowed', max_width: 0}]);
    const selfMeasure = () => cdp.eval(`window.__sweep.measure(${q({w: v0.width, h: v0.height,
      scope: ['#sweepSelfTest'], allow: selfAllow})})`);
    out.self_test = await selfMeasure();
    await cdp.eval(`(() => { const w = document.createElement('div'); w.id = 'stWide';
      w.style.cssText = 'width:${v0.width + 200}px;height:4px';
      document.getElementById('sweepSelfTest').append(w); })()`);
    await settled();
    out.self_test_wide = await selfMeasure();
  } catch (e) {
    out.error = String(e && e.stack || e);
  } finally {
    out.elapsed_ms = Date.now() - t0;
    try { cdp.ws.close(); } catch (e) { /* already closed */ }
    await closeChrome(launched.proc, launched.dir);
  }
  return JSON.stringify(out);
}

// Exit once stdout has drained: the report is far larger than a pipe's
// buffer, and process.exit straight after a write to a pipe truncates it.
main().then(s => process.stdout.write(s, () => process.exit(0)), e => {
  process.stdout.write(JSON.stringify({error: String(e && e.stack || e)}), () => process.exit(1));
});
