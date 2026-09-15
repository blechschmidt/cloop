// ── Overlay focus containment (Task 20288) ───────────────────────────────────
//
// One open/close path for every dialog on the page. Before this, each of the
// 25 overlays hand-rolled its own show/hide, and none of them contained focus:
// Tab out of an open dialog and you landed on the controls behind it. The page
// underneath stayed reachable and operable, so a keyboard or screen-reader user
// could start a run from a dialog that was visually covering it — and closing
// the dialog dropped focus to the top of the document instead of returning it
// to whatever opened it.
//
// The three things this fixes, and why each needs the *shared* helper rather
// than a per-modal patch:
//
//   * Inert background. Marking the rest of the page inert is not a property of
//     one dialog, it is a property of whichever dialog is on top — and two can
//     be open at once (the sandbox terminal opens over the task-details modal).
//     Only a single stack knows which that is, so applyInert() recomputes the
//     whole state from OVERLAY_STACK on every open and close rather than each
//     modal trying to remember what it hid.
//   * Tab cycling. `inert` alone stops Tab reaching the background, but the
//     browser then hands focus to its own chrome and back, so the wrap is the
//     user agent's, not ours, and nothing can assert on it. The explicit
//     handler below makes last→first and first→last deterministic.
//   * Focus restoration. This is the one that cannot be retrofitted per modal,
//     because a dialog has three close paths — its own button, Escape, and a
//     backdrop click — and restoring focus in the button handler alone silently
//     skips the other two. Routing all three through closeOverlay() is what
//     makes the restoration unskippable.
//
// The mechanic is declared in the markup, as data-overlay on the overlay root,
// because the page uses three of them and the helper has to honour whichever
// one a given dialog's CSS already implements:
//
//   data-overlay="flex"           style.display = 'flex'  / 'none'
//   data-overlay="block"          style.display = 'block' / 'none'
//   data-overlay="class:open"     classList.add/remove('open')
//   data-overlay="class:visible"  classList.add/remove('visible')
//
// TestDashboard_OverlaysUseTheSharedHelper keeps a newly added overlay from
// bypassing all of this, and overlay_focus_browser_test.go drives the real
// behaviour in headless Chromium, because none of it is observable in the
// Node DOM shim the other frontend gates run under.

// The open dialogs, innermost last. An entry is {el, invoker, dismiss}.
const OVERLAY_STACK = [];

// Every element applyInert() set the attribute on, so that un-inerting touches
// only what we hid and leaves an author-set `inert` alone.
let overlayInertMarked = [];

const OVERLAY_FOCUSABLE_SEL = [
  'a[href]', 'area[href]', 'button', 'input', 'select', 'textarea',
  'iframe', 'audio[controls]', 'video[controls]', 'summary',
  '[tabindex]', '[contenteditable]:not([contenteditable="false"])',
].join(',');

// Skipped when inerting siblings: inert on them does nothing, and the attribute
// churn would show up in every DOM diff.
const OVERLAY_INERT_SKIP = {SCRIPT: 1, STYLE: 1, LINK: 1, META: 1, TITLE: 1, TEMPLATE: 1, HEAD: 1};

function overlayMechanic(el) {
  const spec = el.getAttribute('data-overlay') || 'flex';
  if (spec.indexOf('class:') === 0) return {kind: 'class', name: spec.slice(6)};
  return {kind: 'display', value: spec};
}

function overlayShow(el) {
  const m = overlayMechanic(el);
  if (m.kind === 'class') el.classList.add(m.name);
  else el.style.display = m.value;
}

function overlayHide(el) {
  const m = overlayMechanic(el);
  if (m.kind === 'class') el.classList.remove(m.name);
  else el.style.display = 'none';
}

// isOverlayOpen reports visibility the same way the mechanic renders it, so a
// caller never has to know which of the three a given dialog uses.
function isOverlayOpen(target) {
  const el = typeof target === 'string' ? document.getElementById(target) : target;
  if (!el) return false;
  const m = overlayMechanic(el);
  if (m.kind === 'class') return el.classList.contains(m.name);
  return el.style.display !== 'none' && el.style.display !== '';
}

// overlayVisible answers "can this element be focused" without layout where
// there is none. A real browser gets the authoritative answer from
// getClientRects(); the Node DOM shim used by the other frontend gates has no
// layout at all, so there it falls back to walking inline display/visibility.
function overlayVisible(el) {
  if (typeof el.getClientRects === 'function') return el.getClientRects().length > 0;
  for (let n = el; n && n.style; n = n.parentElement) {
    if (n.style.display === 'none' || n.style.visibility === 'hidden') return false;
  }
  return true;
}

// overlayFocusables returns root's focusable descendants in tab order.
function overlayFocusables(root) {
  const out = [];
  const all = root.querySelectorAll(OVERLAY_FOCUSABLE_SEL);
  for (let i = 0; i < all.length; i++) {
    const el = all[i];
    if (el.disabled) continue;
    if (el.type === 'hidden') continue;
    const ti = el.getAttribute('tabindex');
    if (ti !== null && Number(ti) < 0) continue;
    if (typeof el.closest === 'function' && el.closest('[inert]')) continue;
    if (!overlayVisible(el)) continue;
    out.push(el);
  }
  return out;
}

// applyInert recomputes the inert background from scratch for whichever overlay
// is currently on top. Doing it wholesale rather than incrementally is what
// makes stacking correct: when the terminal opens over the task-details modal,
// the modal underneath becomes a sibling of the top overlay and is inerted like
// any other background element — and when the terminal closes, the modal is
// simply no longer a sibling of the top and comes back.
function applyInert() {
  for (let i = 0; i < overlayInertMarked.length; i++) {
    overlayInertMarked[i].removeAttribute('inert');
  }
  overlayInertMarked = [];
  if (!OVERLAY_STACK.length) return;

  let node = OVERLAY_STACK[OVERLAY_STACK.length - 1].el;
  while (node && node.parentElement) {
    const parent = node.parentElement;
    const kids = parent.children;
    for (let i = 0; i < kids.length; i++) {
      const sib = kids[i];
      if (sib === node) continue;
      if (OVERLAY_INERT_SKIP[sib.tagName]) continue;
      // Anything still carrying the attribute after the sweep above was set by
      // the markup, not by us; leaving it is the caller's business.
      if (sib.hasAttribute('inert')) continue;
      sib.setAttribute('inert', '');
      overlayInertMarked.push(sib);
    }
    node = parent;
  }
}

// openOverlay shows a dialog, remembers what opened it, seals the page behind
// it and moves focus inside.
//
//   target  element or element id of the overlay root
//   opts.focus    selector (within the overlay) or element to focus first;
//                 defaults to the first focusable descendant
//   opts.dismiss  the close function Escape should run. Omitting it traps
//                 focus but leaves the dialog undismissable by keyboard, which
//                 is only ever right for the login gate — there is nothing
//                 behind it to go back to.
function openOverlay(target, opts) {
  const el = typeof target === 'string' ? document.getElementById(target) : target;
  if (!el) return null;
  opts = opts || {};

  const already = overlayIndexOf(el);
  if (already >= 0) {
    // Re-opening an open dialog must not stack a second entry, and must not
    // overwrite the invoker with something inside the dialog itself.
    overlayShow(el);
    applyInert();
    overlayFocusInitial(el, opts.focus);
    return el;
  }

  const active = document.activeElement;
  const invoker = (active && active !== document.body && !el.contains(active)) ? active : null;

  OVERLAY_STACK.push({
    el: el,
    invoker: invoker,
    dismiss: typeof opts.dismiss === 'function' ? opts.dismiss : null,
  });

  overlayShow(el);
  // A dialog that is not announced as one leaves a screen reader still reading
  // the page behind it as if it were reachable.
  if (!el.hasAttribute('role')) el.setAttribute('role', 'dialog');
  el.setAttribute('aria-modal', 'true');
  el.removeAttribute('aria-hidden');

  applyInert();
  overlayFocusInitial(el, opts.focus);
  return el;
}

// closeOverlay hides a dialog, unseals the page and hands focus back to
// whatever opened it. Idempotent: closing an already-closed overlay still
// hides it and leaves focus alone, so the button, Escape and backdrop paths can
// all call it without coordinating.
function closeOverlay(target) {
  const el = typeof target === 'string' ? document.getElementById(target) : target;
  if (!el) return;

  overlayHide(el);
  el.removeAttribute('aria-modal');
  el.setAttribute('aria-hidden', 'true');

  const idx = overlayIndexOf(el);
  if (idx < 0) { applyInert(); return; }
  const entry = OVERLAY_STACK.splice(idx, 1)[0];
  applyInert();

  // Only the dialog the user was actually in should move focus. Closing one
  // from underneath the top (nothing does today, but it is cheap to be right)
  // would otherwise yank focus out of the dialog still on screen.
  if (idx === OVERLAY_STACK.length) overlayRestoreFocus(entry.invoker);
}

function overlayIndexOf(el) {
  for (let i = 0; i < OVERLAY_STACK.length; i++) {
    if (OVERLAY_STACK[i].el === el) return i;
  }
  return -1;
}

function overlayFocusInitial(el, want) {
  let target = null;
  if (typeof want === 'string') target = el.querySelector(want);
  else if (want && typeof want.focus === 'function') target = want;
  if (!target || !overlayVisible(target)) {
    const items = overlayFocusables(el);
    target = items.length ? items[0] : null;
  }
  // With nothing focusable inside, focus the dialog itself so the caret is at
  // least inside the trap rather than back on the page behind it.
  if (!target) {
    if (!el.hasAttribute('tabindex')) el.setAttribute('tabindex', '-1');
    target = el;
  }
  try { target.focus(); } catch (e) { /* detached or not focusable */ }
}

function overlayRestoreFocus(invoker) {
  if (!invoker) return;
  // A re-render between open and close can have replaced the invoking node.
  if (typeof document.contains === 'function' && !document.contains(invoker)) return;
  if (typeof invoker.closest === 'function' && invoker.closest('[inert]')) return;
  if (!overlayVisible(invoker)) return;
  try { invoker.focus(); } catch (e) { /* no longer focusable */ }
}

// topOverlay is the dialog currently receiving the keyboard, or null.
function topOverlay() {
  return OVERLAY_STACK.length ? OVERLAY_STACK[OVERLAY_STACK.length - 1] : null;
}

// dismissTopOverlay closes the frontmost dialog through its own close function
// — the same one its backdrop click and its Close button call — so Escape can
// never take a shortcut that skips focus restoration.
//
// Returns true when a dialog was on top, whether or not it could be dismissed:
// Escape must not fall through to the list-navigation shortcuts while a dialog
// the user cannot see past is open.
function dismissTopOverlay() {
  const top = topOverlay();
  if (!top) return false;
  if (top.dismiss) {
    try { top.dismiss(); } catch (e) { closeOverlay(top.el); }
  }
  return true;
}

// Tab containment. Capture phase so it settles before any panel's own key
// handling, and keyed off the top of the stack so a dialog opened over another
// cycles within itself.
document.addEventListener('keydown', function(e) {
  if (e.key !== 'Tab') return;
  const top = topOverlay();
  if (!top) return;

  const items = overlayFocusables(top.el);
  if (!items.length) { e.preventDefault(); return; }

  const first = items[0];
  const last  = items[items.length - 1];
  const active = document.activeElement;
  const inside = active && top.el.contains(active);

  if (e.shiftKey) {
    if (!inside || active === first) { e.preventDefault(); last.focus(); }
  } else {
    if (!inside || active === last) { e.preventDefault(); first.focus(); }
  }
}, true);

window.openOverlay        = openOverlay;
window.closeOverlay       = closeOverlay;
window.isOverlayOpen      = isOverlayOpen;
window.topOverlay         = topOverlay;
window.dismissTopOverlay  = dismissTopOverlay;
window.overlayFocusables  = overlayFocusables;
