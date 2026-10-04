// mobile_overflow_browser.js — measures what a long project list does to the
// dashboard's layout on a phone (Task 20300).
//
// Why a browser and not testdata/domshim.js, which most frontend gates here
// use: every number below is a layout question. The shim has no box model, no
// viewport and no scroll, so it reports 0 for every rect and cannot tell an
// element that fits from one hanging off the side of the screen. Overflow is
// not observable without a real engine laying the page out at a real width.
//
// Usage: node mobile_overflow_browser.js <chrome-binary> <base-url>
// Prints one JSON document on stdout.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];

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

// WAIT_MS bounds each wait for a condition below; it is how long to keep
// looking before reporting what is there, never a pause a healthy run sits out.
// The slowest condition is the roster itself: /api/projects opens every
// project's database in series and took ~9s for this fleet under -race on a
// 4-core box with the CPU saturated. 30s is over three times that, and the five
// waits together stay well inside the 4-minute bound the Go side puts on this
// driver, so even a run where all of them expire still reports its own output.
const WAIT_MS = 30000;

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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-mobileoverflow-'));
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    // Same reasoning as testdata/chart_defer_browser.js: this suite runs as
    // root on the project's dev box and unprivileged in CI, and the profile is
    // a throwaway loading only a local httptest server.
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
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

// waitFor polls a page expression until it is truthy or WAIT_MS passes, and
// says which. It does not throw: everything waited on here is also measured,
// and the Go test's assertion on that measurement explains a failure far
// better than "timed out" would.
//
// This replaces fixed sleeps, which raced the dashboard's own requests: under
// load the roster lands seconds after a sleep sized on a quiet machine expires.
async function waitFor(cdp, expr) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    try {
      if (await cdp.eval(expr)) return true;
    } catch (_) { /* mid-navigation: no context to evaluate in yet */ }
    if (Date.now() >= deadline) return false;
    await sleep(50);
  }
}

// settled resolves once the page has rendered two frames since it was called.
// It stands where fixed sleeps used to, after each change a scenario makes
// before measuring — a viewport override, a dropdown opened by a click — so the
// numbers describe a frame the user would actually have been shown, including
// the page-scale a mobile viewport settles on, rather than whatever state a
// sleep sized on a quiet machine happened to catch. Two frames rather than one
// because a requestAnimationFrame callback runs *before* its own frame is
// laid out and painted.
const settled = cdp => cdp.eval(
  'new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))');

// Does the document scroll sideways? A phone has no horizontal scrollbar to
// drag, so anything past the right edge is simply unreachable — and the whole
// page rubber-bands under a finger that meant to scroll down.
//
// inner_width is reported next to the width we asked Chrome to emulate,
// because on a mobile viewport the two can disagree and that disagreement is
// itself the bug. When content overflows the initial containing block, Chrome
// honours `width=device-width` by shrinking the page to fit: the layout
// viewport grows past the device width and the entire interface zooms out.
// Every rect measured after that is in the zoomed space, which is why a naive
// "is the panel below the fold" check reads healthy on exactly the page that
// is broken — the fold moved. The Go side compares against expected_width so
// the rescale cannot hide behind its own symptom.
const pageExpr = expected => `(() => {
  const de = document.documentElement;
  return {
    expected_width: ${expected},
    inner_width: window.innerWidth,
    inner_height: window.innerHeight,
    scroll_width: de.scrollWidth,
    client_width: de.clientWidth,
    overflow_px: de.scrollWidth - de.clientWidth,
  };
})()`;

// The widest element that sticks out past the viewport's right edge, and who
// it is. Reported so a failure names the offending node instead of only the
// number of pixels.
//
// Against the width we asked Chrome to emulate, not window.innerWidth: once
// the page has zoomed out to absorb an overflow, nothing exceeds the widened
// viewport any more and this probe would report "nothing" on exactly the
// pages that are broken.
const widestExpr = expW => `(() => {
  const w = ${expW};
  let worst = null;
  for (const el of document.querySelectorAll('body *')) {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) continue;
    const over = Math.round(r.right - w);
    if (over > 1 && (!worst || over > worst.over_px)) {
      worst = {
        over_px: over,
        tag: el.tagName.toLowerCase(),
        id: el.id || '',
        cls: (typeof el.className === 'string' ? el.className : '') || '',
        right: Math.round(r.right),
        width: Math.round(r.width),
      };
    }
  }
  return worst;
})()`;

// The header dropdown, measured as the user meets it: how tall it grew, how
// far past the fold its last row sits, and whether that row can be reached by
// any scroll the page offers.
//
// Measured against the viewport we asked for (expW/expH), not against
// window.innerWidth: if the page has zoomed out to swallow an overflow, the
// live viewport is a description of the damage, not a yardstick.
const dropdownExpr = (expW, expH) => `(() => {
  const d = document.getElementById('projSelectorDropdown');
  if (!d) return {present: false};
  const items = d.querySelectorAll('.proj-selector-item');
  const r = d.getBoundingClientRect();
  const last = items.length ? items[items.length - 1].getBoundingClientRect() : null;
  const cs = getComputedStyle(d);
  const vw = ${expW}, vh = ${expH};
  return {
    present: true,
    open: d.classList.contains('open'),
    items: items.length,
    height: Math.round(r.height),
    top: Math.round(r.top),
    bottom: Math.round(r.bottom),
    left: Math.round(r.left),
    right: Math.round(r.right),
    // Scrollable in its own right? overflow:hidden and a height cap are not
    // the same thing — the first would clip the tail away with no way to see it.
    overflow_y: cs.overflowY,
    scroll_height: Math.round(d.scrollHeight),
    client_height: Math.round(d.clientHeight),
    scrollable: d.scrollHeight - d.clientHeight > 1,
    viewport_h: vh,
    viewport_w: vw,
    live_viewport_w: window.innerWidth,
    below_fold_px: Math.round(r.bottom - vh),
    right_overflow_px: Math.round(r.right - vw),
    last_item_bottom: last ? Math.round(last.bottom) : null,
    last_item_below_fold_px: last ? Math.round(last.bottom - vh) : null,
  };
})()`;

// Is the last row of the open dropdown actually clickable? elementFromPoint is
// the browser's own hit test, so this is what a finger would land on — not a
// guess from coordinates. Scrolls the dropdown to its end first, which is the
// recovery a capped, scrollable panel is supposed to offer.
const LAST_ITEM_HITTABLE = `(() => {
  const d = document.getElementById('projSelectorDropdown');
  if (!d) return {reachable: false, why: 'no dropdown'};
  const items = d.querySelectorAll('.proj-selector-item');
  if (!items.length) return {reachable: false, why: 'no items'};
  d.scrollTop = d.scrollHeight;           // pane scroll, if it has one
  window.scrollTo(0, document.body.scrollHeight); // page scroll, if that is the recovery
  const el = items[items.length - 1];
  const r = el.getBoundingClientRect();
  const x = Math.round(r.left + r.width / 2);
  const y = Math.round(r.top + r.height / 2);
  if (y < 0 || y > window.innerHeight || x < 0 || x > window.innerWidth) {
    return {reachable: false, why: 'off-viewport', x, y, bottom: Math.round(r.bottom)};
  }
  const hit = document.elementFromPoint(x, y);
  return {
    reachable: !!hit && (hit === el || el.contains(hit)),
    why: hit ? (hit.className || hit.tagName) : 'nothing at point',
    x, y,
  };
})()`;

// The header's navigation strip at a desktop width (Task 20351). Task 20349
// stopped twenty-odd tabs widening the whole page by making the strip scroll
// inside the header — which put a scrollbar under the tabs at every desktop
// width, 1920px included. The strip now wraps instead, so the questions are:
// does it overflow its own box (a scrollbar, or tabs clipped past its edge),
// can every tab be clicked, and is it still the header's last row?
//
// hidden is the browser's own hit test at each tab's centre, which is what a
// pointer would land on: a tab scrolled or clipped out of view fails it.
// stranded is a group label ending one row while its first tab starts the
// next — the Global label did that at 1280px when the strip wrapped greedily.
// below is any other header control laid out level with or under the strip,
// the extra header row the old layout spent on two buttons.
const TAB_STRIP = `(() => {
  const n = document.getElementById('tabNav');
  if (!n) return {present: false};
  const nr = n.getBoundingClientRect();
  const hittable = el => {
    const r = el.getBoundingClientRect();
    const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    return !!hit && (hit === el || el.contains(hit));
  };
  const midY = el => { const r = el.getBoundingClientRect(); return r.top + r.height / 2; };
  const tabs = [...n.querySelectorAll('.tab-btn')].filter(b => b.getClientRects().length);
  const stranded = [];
  for (const label of n.querySelectorAll('.tab-section-label')) {
    let t = label.nextElementSibling;
    while (t && !(t.classList.contains('tab-btn') && t.getClientRects().length)) t = t.nextElementSibling;
    if (t && Math.abs(midY(t) - midY(label)) > 8) stranded.push(label.textContent.trim());
  }
  const below = [...n.parentElement.children]
    .filter(c => c !== n && c.getClientRects().length && c.getBoundingClientRect().top >= nr.top - 1)
    .map(c => c.id || c.className);
  return {
    present: true,
    tabs: tabs.length,
    right: Math.round(nr.right),
    scroll_width: n.scrollWidth,
    client_width: n.clientWidth,
    scrollbar_px: n.offsetHeight - n.clientHeight,
    hidden: tabs.filter(b => !hittable(b)).map(b => b.textContent.trim()),
    stranded,
    below,
  };
})()`;

// The grid on the Projects tab. Cards are what a phone user scrolls through,
// and a single unbroken name — a path-like slug with no spaces — is the
// input that makes one refuse to shrink.
const cardsExpr = expW => `(() => {
  const list = document.getElementById('projList');
  if (!list) return {present: false};
  const cards = [...list.querySelectorAll('.proj-card')];
  const w = ${expW};
  let worst = 0, worstName = '';
  for (const c of cards) {
    const r = c.getBoundingClientRect();
    const over = Math.round(r.right - w);
    if (over > worst) { worst = over; worstName = (c.querySelector('.proj-name')||{}).textContent || ''; }
  }
  // Also ask each card whether its own content spills out of it, which is how
  // a long name pushes the layout wide in the first place.
  let innerWorst = 0, innerWho = '';
  const byClass = {};
  for (const c of cards) {
    // Against the card's *content* box, not its border box: a name that only
    // spills into the 18px of right padding is still laying out wrong, and
    // measuring to the border edge would forgive exactly that much of it.
    const ccs = getComputedStyle(c);
    const contentRight = c.getBoundingClientRect().right
      - parseFloat(ccs.paddingRight || 0) - parseFloat(ccs.borderRightWidth || 0);
    for (const kid of c.querySelectorAll('.proj-name,.proj-goal,.proj-pause,.proj-meta,.proj-actions')) {
      const over = Math.round(kid.getBoundingClientRect().right - contentRight);
      if (over > innerWorst) { innerWorst = over; innerWho = kid.className + ' ("' + kid.textContent.trim().slice(0, 40) + '")'; }
      // Per row type as well as overall: .proj-name and .proj-pause each carry
      // their own width rule, and reporting only the single worst offender
      // lets the second one hide behind the first until the first is fixed.
      const key = kid.className.split(' ')[0];
      if (!byClass[key] || over > byClass[key]) byClass[key] = over;
    }
  }
  return {
    present: true,
    count: cards.length,
    // Reported so the Go side can refuse to believe a clean result that was
    // clean only because the paused row never rendered.
    paused_rows: list.querySelectorAll('.proj-pause').length,
    worst_overflow_px: worst,
    worst_name: worstName,
    inner_overflow_px: innerWorst,
    inner_who: innerWho,
    inner_overflow_by_class: byClass,
  };
})()`;

// The Tasks tab's run bar (Task 20358): whether the status fits inside it, and
// how much of the Evolve Mode chip a phone draws. The status is the project's
// own, pause reason included, and that is an error message of any length.
const RUN_BAR = `(() => {
  const bar = document.getElementById('tasksRunBar');
  const st = document.getElementById('tasksRunStatus');
  const chip = document.getElementById('tasksRunEvolve');
  const label = chip && chip.querySelector('.tasks-run-evolve-label');
  if (!bar || !st || bar.offsetParent === null) return {present: false};
  const b = bar.getBoundingClientRect(), r = st.getBoundingClientRect();
  const l = label ? label.getBoundingClientRect() : null;
  return {
    present: true,
    status: st.textContent.trim(),
    status_overflow_px: Math.max(0, Math.round(r.right - b.right), st.scrollWidth - st.clientWidth),
    bar_overflow_px: bar.scrollWidth - bar.clientWidth,
    chip_shown: !!chip && chip.offsetParent !== null,
    chip_width: chip ? Math.round(chip.getBoundingClientRect().width) : 0,
    chip_label_area_px: l ? Math.round(l.width * l.height) : -1,
    chip_text: chip ? chip.textContent.trim() : '',
  };
})()`;

(async () => {
  const out = {};
  let chrome;
  try {
    chrome = await launchChrome();
    const cdp = await connect(chrome.port);
    await cdp.send('Runtime.enable');
    await cdp.send('Page.enable');

    // A real phone viewport. deviceScaleFactor and mobile:true matter: they
    // bring the visual viewport and the meta[viewport] rules into play, which
    // is where width-based media queries are resolved.
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 390, height: 844, deviceScaleFactor: 3, mobile: true,
    });

    await cdp.send('Page.navigate', {url: BASE + '/'});
    await waitFor(cdp, `document.readyState === 'complete' && typeof window.switchTab === 'function'`);
    // The roster arrives over HTTP; wait for the dropdown to actually carry
    // rows rather than racing first paint.
    await waitFor(cdp, `document.querySelectorAll('#projSelectorDropdown .proj-selector-item').length > 0`);

    out.multi_project = await cdp.eval(`!!document.getElementById('projSelectorWrap').classList.contains('visible')`);

    // ── 1. The landing page, closed dropdown ───────────────────────────────
    out.closed = {
      page: await cdp.eval(pageExpr(390)),
      widest: await cdp.eval(widestExpr(390)),
      dropdown: await cdp.eval(dropdownExpr(390, 844)),
    };

    // ── 2. The projects grid ───────────────────────────────────────────────
    // One project in the fleet is paused (the Go side stores it that way), so
    // the grid draws its .proj-pause row, which carries a fixed max-width of
    // its own. Waited for down to that row: the tab re-requests the roster,
    // and on a loaded machine the cards land seconds after the switch.
    //
    // The pause used to be patched into the page's cached roster at this
    // point and the grid redrawn from it. The request switchTab had just made
    // was still in flight, so when it landed it redrew the grid without the
    // pause — sometimes before this measurement, sometimes before step 4's.
    await cdp.eval(`switchTab('projects')`);
    await waitFor(cdp, `!!document.querySelector('#projList .proj-card')
      && !!document.querySelector('#projList .proj-pause')`);
    await settled(cdp);
    out.grid = {
      page: await cdp.eval(pageExpr(390)),
      widest: await cdp.eval(widestExpr(390)),
      cards: await cdp.eval(cardsExpr(390)),
    };

    // ── 3. The header dropdown, open ───────────────────────────────────────
    await cdp.eval(`document.getElementById('projSelectorBtn').click()`);
    await settled(cdp);
    out.open = {
      page: await cdp.eval(pageExpr(390)),
      dropdown: await cdp.eval(dropdownExpr(390, 844)),
      last_item: await cdp.eval(LAST_ITEM_HITTABLE),
    };

    // ── 4. A narrower phone still in the supported range ───────────────────
    // Closed and scrolled back to the top before resizing: leaving it open
    // would carry any zoom-out from step 3 into the new viewport, and every
    // number below would describe the previous scenario's damage.
    await cdp.eval(`(() => {
      const d = document.getElementById('projSelectorDropdown');
      if (d) d.classList.remove('open');
      window.scrollTo(0, 0);
    })()`);
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 320, height: 568, deviceScaleFactor: 2, mobile: true,
    });
    await settled(cdp);
    out.narrow = {
      page: await cdp.eval(pageExpr(320)),
      widest: await cdp.eval(widestExpr(320)),
      cards: await cdp.eval(cardsExpr(320)),
    };

    await cdp.eval(`document.getElementById('projSelectorBtn').click()`);
    await settled(cdp);
    out.narrow_open = {
      page: await cdp.eval(pageExpr(320)),
      dropdown: await cdp.eval(dropdownExpr(320, 568)),
      last_item: await cdp.eval(LAST_ITEM_HITTABLE),
    };

    // ── 5. Desktop ─────────────────────────────────────────────────────────
    // The mobile rules re-anchor the dropdown to the header and pin it to
    // both screen edges. Above the breakpoint it must go back to hanging off
    // the button it belongs to — so this measures that the override did not
    // leak, and that the height cap (which is deliberately not mobile-only,
    // because 24 rows do not fit a laptop window either) still applies.
    await cdp.eval(`(() => {
      const d = document.getElementById('projSelectorDropdown');
      if (d) d.classList.remove('open');
      window.scrollTo(0, 0);
    })()`);
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 1280, height: 900, deviceScaleFactor: 1, mobile: false,
    });
    await settled(cdp);
    await cdp.eval(`document.getElementById('projSelectorBtn').click()`);
    await settled(cdp);
    out.desktop = {
      page: await cdp.eval(pageExpr(1280)),
      widest: await cdp.eval(widestExpr(1280)),
      dropdown: await cdp.eval(dropdownExpr(1280, 900)),
      last_item: await cdp.eval(LAST_ITEM_HITTABLE),
      // Where the panel sits relative to the button it belongs to. On desktop
      // the two left edges line up; under the mobile rules they do not,
      // because the panel spans the screen instead.
      anchored: await cdp.eval(`(() => {
        const b = document.getElementById('projSelectorBtn');
        const d = document.getElementById('projSelectorDropdown');
        if (!b || !d) return null;
        const br = b.getBoundingClientRect(), dr = d.getBoundingClientRect();
        return {
          button_left: Math.round(br.left),
          dropdown_left: Math.round(dr.left),
          delta: Math.round(dr.left - br.left),
        };
      })()`),
    };

    // ── 5b. The navigation strip at desktop widths ─────────────────────────
    // 1280px is a common laptop, where the strip needs two rows; 1920px is
    // the screen the scrollbar was reported on. Both with the dropdown shut
    // and the page at the top: the open panel hangs over the strip, and the
    // hit test would find it rather than the tab underneath.
    await cdp.eval(`(() => {
      const d = document.getElementById('projSelectorDropdown');
      if (d) d.classList.remove('open');
      window.scrollTo(0, 0);
    })()`);
    out.tab_strip = [];
    for (const w of [1280, 1920]) {
      await cdp.send('Emulation.setDeviceMetricsOverride', {
        width: w, height: 900, deviceScaleFactor: 1, mobile: false,
      });
      await settled(cdp);
      out.tab_strip.push({
        width: w,
        page: await cdp.eval(pageExpr(w)),
        strip: await cdp.eval(TAB_STRIP),
      });
    }

    // ── 6. The hidden-projects dialog ──────────────────────────────────────
    // The third place the roster is drawn, and the one with no truncation of
    // any kind on the name. Measured at the narrowest viewport. The fleet has
    // one project hidden from the start — the Go side hides it through the API
    // before this driver runs — with a long unbroken name of its own; it is
    // not one of the projects the scenarios above lay out, because hiding one
    // of those would change the lists they measure.
    //
    // It used to be hidden here, by setting the flag on the page's cached
    // roster. Every roster that arrived afterwards — a request still in flight
    // from step 2, or a 'projects' broadcast — replaced that cache without the
    // flag, and the dialog opened empty. That is how this failed in CI.
    //
    // Reached through the Settings button rather than by reading the panel:
    // since Task 20328 the rows only exist while #hiddenproj-overlay is open,
    // so a measurement taken on the Settings page alone would find no rows and
    // report a tidy zero overflow for a layout it never laid out.
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 320, height: 568, deviceScaleFactor: 2, mobile: true,
    });
    await cdp.eval(`(() => {
      const d = document.getElementById('projSelectorDropdown');
      if (d) d.classList.remove('open');
      window.scrollTo(0, 0);
    })()`);
    await cdp.eval(`switchTab('settings')`);
    // The button counts hidden projects off the same cached roster the dialog
    // fills from, so its being enabled is the page saying it holds the hidden
    // one. Clicked, not called: this also proves the button is enabled and its
    // onclick resolves, in a real browser. A disabled button or an unexported
    // handler leaves the list empty and fails the count assertion.
    await waitFor(cdp, `(() => { const b = document.getElementById('hiddenProjectsBtn');
      return !!b && !b.disabled; })()`);
    await cdp.eval(`document.getElementById('hiddenProjectsBtn').click()`);
    await waitFor(cdp, `document.querySelectorAll('#hiddenProjectsList .hidden-proj-name').length > 0`);
    await settled(cdp);
    out.hidden_list = {
      page: await cdp.eval(pageExpr(320)),
      widest: await cdp.eval(widestExpr(320)),
      // scrollWidth against clientWidth, not a rect against its row. The name
      // sits in .hidden-proj-info, which is a flex column with min-width:0 —
      // so the name is a blockified flex item whose *box* is squeezed to fit
      // while its unbreakable text spills straight out of it. The box is
      // therefore exactly the wrong thing to measure: it reports a tidy zero
      // on precisely the layout that is broken. Asking the element how wide
      // its content is, versus how wide it can show, is what sees the spill.
      rows: await cdp.eval(`(() => {
        const box = document.getElementById('hiddenProjectsList');
        if (!box) return {present: false};
        const names = [...box.querySelectorAll('.hidden-proj-name')];
        let worst = 0, who = '';
        for (const n of names) {
          const over = Math.round(n.scrollWidth - n.clientWidth);
          if (over > worst) { worst = over; who = n.textContent.trim().slice(0, 40); }
        }
        return {present: true, count: names.length, worst_overflow_px: worst, worst_name: who};
      })()`),
    };

    // ── 7. The paused project, opened (Task 20358) ─────────────────────────
    // Its status says why it paused, in words no phone fits on one line: on
    // the Overview's badge, and since Task 20358 on the Tasks tab's run bar
    // too. Both must wrap rather than push the page sideways. The project is
    // in Evolve Mode as well, which a phone's run bar draws as the chip's icon
    // alone, or its status and button cannot share a row.
    //
    // At 360px, the width this hub's own telemetry reports for its users'
    // phones. Not at 320px: there the header alone is 3px too wide once a
    // project with a long name is open — its selector button, whatever the
    // tab — which is a separate fault and would hide this one behind it.
    await cdp.eval(`closeHiddenProjectsModal()`);
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 360, height: 780, deviceScaleFactor: 3, mobile: true,
    });
    await cdp.eval(`switchTab('projects')`);
    await waitFor(cdp, `!!document.querySelector('#projList .proj-pause')`);
    await cdp.eval(`document.querySelector('#projList .proj-pause').closest('.proj-card').click()`);
    await waitFor(cdp, `(document.getElementById('statusBadge') || {}).textContent.includes('Paused')`);
    await cdp.eval(`window.scrollTo(0, 0)`);
    await settled(cdp);
    out.paused_overview = {
      page: await cdp.eval(pageExpr(360)),
      widest: await cdp.eval(widestExpr(360)),
      status: await cdp.eval(`document.getElementById('statusBadge').textContent.trim()`),
    };
    await cdp.eval(`switchTab('tasks')`);
    await waitFor(cdp, `(() => {
      const bar = document.getElementById('tasksRunBar');
      const st = document.getElementById('tasksRunStatus');
      return !!bar && bar.offsetParent !== null && !!st && st.textContent.includes('Paused');
    })()`);
    await cdp.eval(`window.scrollTo(0, 0)`);
    await settled(cdp);
    out.run_bar = {
      page: await cdp.eval(pageExpr(360)),
      widest: await cdp.eval(widestExpr(360)),
      bar: await cdp.eval(RUN_BAR),
    };
  } catch (e) {
    out.error = {message: e && e.message ? e.message : String(e)};
  } finally {
    if (chrome) await closeChrome(chrome.proc, chrome.dir);
  }
  process.stdout.write(JSON.stringify(out, null, 2));
})().then(() => process.exit(process.exitCode ?? 0));
