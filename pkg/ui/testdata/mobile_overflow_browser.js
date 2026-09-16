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
    for (let i = 0; i < 100; i++) {
      await sleep(100);
      const ready = await cdp.eval(
        `document.readyState === 'complete' && typeof window.switchTab === 'function'`);
      if (ready) break;
    }
    // The roster arrives over HTTP; wait for the grid to actually carry cards
    // rather than racing first paint.
    for (let i = 0; i < 100; i++) {
      const n = await cdp.eval(
        `(document.querySelectorAll('#projSelectorDropdown .proj-selector-item')||[]).length`);
      if (n > 0) break;
      await sleep(100);
    }

    out.multi_project = await cdp.eval(`!!document.getElementById('projSelectorWrap').classList.contains('visible')`);

    // ── 1. The landing page, closed dropdown ───────────────────────────────
    out.closed = {
      page: await cdp.eval(pageExpr(390)),
      widest: await cdp.eval(widestExpr(390)),
      dropdown: await cdp.eval(dropdownExpr(390, 844)),
    };

    // ── 2. The projects grid ───────────────────────────────────────────────
    await cdp.eval(`switchTab('projects')`);
    await sleep(300);
    // One project reports as paused. The status arrives from the server in a
    // real deployment, but the question here is what the CSS does with the
    // .proj-pause row it produces — so the cached payload is patched and the
    // page's own renderer re-run over it, which lays out exactly the markup
    // and stylesheet a paused project would hit.
    //
    // Re-rendered through toggleCompletedProjects rather than by calling the
    // renderer directly: the whole front end is one IIFE, so renderProjects is
    // not reachable from here, and that toggle is the exposed entry point that
    // redraws the grid from cache. Twice, so the flag it flips ends where it
    // started and the grid is not left filtered.
    await cdp.eval(`(() => {
      const d = window._lastProjectsData;
      if (!d || !d.projects || !d.projects.length) return false;
      d.projects[0].status = 'paused';
      d.projects[0].pause_reason = {
        code: 'usage_cap',
        detail: 'weekly subscription cap reached at 98% of the five-hour window',
        resumes_at: new Date(Date.now() + 3600e3).toISOString(),
      };
      window.toggleCompletedProjects();
      window.toggleCompletedProjects();
      return true;
    })()`);
    await sleep(150);
    out.grid = {
      page: await cdp.eval(pageExpr(390)),
      widest: await cdp.eval(widestExpr(390)),
      cards: await cdp.eval(cardsExpr(390)),
    };

    // ── 3. The header dropdown, open ───────────────────────────────────────
    await cdp.eval(`document.getElementById('projSelectorBtn').click()`);
    await sleep(200);
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
    await sleep(400);
    out.narrow = {
      page: await cdp.eval(pageExpr(320)),
      widest: await cdp.eval(widestExpr(320)),
      cards: await cdp.eval(cardsExpr(320)),
    };

    await cdp.eval(`document.getElementById('projSelectorBtn').click()`);
    await sleep(200);
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
    await sleep(400);
    await cdp.eval(`document.getElementById('projSelectorBtn').click()`);
    await sleep(200);
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
    // ── 6. The Settings list of hidden projects ────────────────────────────
    // The third place the roster is drawn, and the one with no truncation of
    // any kind on the name. Measured last and at the narrowest viewport,
    // because hiding a project changes the grid and the dropdown and would
    // invalidate every scenario above.
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 320, height: 568, deviceScaleFactor: 2, mobile: true,
    });
    await cdp.eval(`(() => {
      const d = document.getElementById('projSelectorDropdown');
      if (d) d.classList.remove('open');
      window.scrollTo(0, 0);
      const pd = window._lastProjectsData;
      if (!pd || !pd.projects) return false;
      // The long unbroken name is the one this is about; hide that one.
      const target = pd.projects.find(p => /_/.test(p.name)) || pd.projects[pd.projects.length - 1];
      target.hidden = true;
      window.toggleCompletedProjects();
      window.toggleCompletedProjects();
      return true;
    })()`);
    await cdp.eval(`switchTab('settings')`);
    await sleep(400);
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
  } catch (e) {
    out.error = {message: e && e.message ? e.message : String(e)};
  } finally {
    if (chrome) {
      try { chrome.proc.kill('SIGKILL'); } catch (_) {}
      try { fs.rmSync(chrome.dir, {recursive: true, force: true}); } catch (_) {}
    }
  }
  process.stdout.write(JSON.stringify(out, null, 2));
})();
