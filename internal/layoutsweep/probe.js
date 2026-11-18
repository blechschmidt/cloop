// probe.js — the layout sweep's probe: what a real browser lays out, measured
// in the page itself (Task 20407). Shared by the dashboard's layout sweep
// (pkg/ui/testdata/layout_sweep_browser.js) and the documentation site demo's
// browser sweep (scripts/demo/walk.js), which inject this file into every
// document they load; layoutsweep.go turns what it reports into findings.
//
// It defines window.__sweep = {measure, seen}. measure() walks the visible tree
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
//
// measure({w, h, scope, allow}) takes the emulated width and height, a list of
// selectors to walk under, and the scroll allowlist ({selector, max_width}).
// seen(allow) names the allowlisted selectors that match something on screen.
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
