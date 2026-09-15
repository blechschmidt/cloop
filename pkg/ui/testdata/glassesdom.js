// glassesdom.js — the smallest browser assets/glasses.html will run in.
//
// domshim.js next door serves the dashboard bundle, and deliberately models
// nothing: its elements auto-vivify, selectors return nothing, and there is no
// tree. That is enough for the questions the dashboard tests ask, and useless
// for the ones the glasses page asks, all of which are about the tree itself —
// which node has focus, whether a refresh reused it, what order a swipe walks
// the controls in. So this shim has a real parent/child tree, real document
// order, a real activeElement and real event bubbling, and nothing else.
//
// What it does NOT model is layout, except where a scenario states it: there is
// no CSS and no computed style, and getBoundingClientRect answers only for
// nodes a scenario has placed with layout(). Visibility is otherwise taken from
// the `hidden` property alone, which is exactly why the page sets `hidden`
// alongside its class contract rather than relying on a stylesheet this shim
// cannot read.
//
// Three things here exist because the page cannot trust the glasses runtime and
// this shim has to be able to play one (Task 20242):
//
//   - press() takes a bag of event fields, not just a key name, so a scenario
//     can send the legacy 'Right' spelling or a bare keyCode the way an engine
//     that synthesises key events from gestures might.
//   - focus: 'dead' makes Element.focus() a no-op and focus: 'hijack' re-aims
//     it at the first row after every keydown, which are the two ways a runtime
//     can make document.activeElement useless as a cursor.
//   - listeners record their capture flag and dispatch runs both phases in the
//     right order, because the page's gesture handler is now a capture
//     listener and a shim that ignored the phase could not tell.

'use strict';

function makeDOM(opts) {
  opts = opts || {};

  // ── elements ──────────────────────────────────────────────────────────────

  function mkClassList(el) {
    return {
      contains: c => el._classes.indexOf(c) >= 0,
      add: (...c) => c.forEach(x => { if (el._classes.indexOf(x) < 0) el._classes.push(x); }),
      remove: (...c) => { el._classes = el._classes.filter(x => c.indexOf(x) < 0); },
      get length() { return el._classes.length; },
    };
  }

  function mkElement(tag) {
    const el = {
      tagName: String(tag || 'div').toUpperCase(),
      _classes: [],
      _text: '',
      _listeners: {},
      childNodes: [],
      parentNode: null,
      dataset: {},
      style: {},
      hidden: false,
      disabled: false,
      type: '',
      id: '',
      scrollIntoViewCalls: 0,
    };
    el.classList = mkClassList(el);

    Object.defineProperty(el, 'className', {
      get() { return el._classes.join(' '); },
      set(v) { el._classes = String(v).split(/\s+/).filter(Boolean); },
    });
    Object.defineProperty(el, 'firstChild', {
      get() { return el.childNodes.length ? el.childNodes[0] : null; },
    });
    Object.defineProperty(el, 'textContent', {
      get() {
        return el.childNodes.length
          ? el.childNodes.map(c => c.textContent).join('')
          : el._text;
      },
      set(v) {
        el.childNodes.forEach(c => { c.parentNode = null; });
        el.childNodes = [];
        el._text = v == null ? '' : String(v);
      },
    });

    el.appendChild = child => el.insertBefore(child, null);

    el.insertBefore = (child, ref) => {
      if (child.parentNode) { child.parentNode.removeChild(child, true); }
      const at = ref ? el.childNodes.indexOf(ref) : -1;
      if (at < 0) { el.childNodes.push(child); } else { el.childNodes.splice(at, 0, child); }
      child.parentNode = el;
      // A node gaining children stops being a text leaf, exactly as a real
      // tree does — otherwise textContent would report the stale string.
      el._text = '';
      return child;
    };

    el.removeChild = (child, moving) => {
      const at = el.childNodes.indexOf(child);
      if (at < 0) { throw new Error('removeChild: not a child'); }
      el.childNodes.splice(at, 1);
      child.parentNode = null;
      // Losing focus with the node that held it is the browser behaviour the
      // page's focus-rescue path exists to compensate for, so model it.
      if (!moving && contains(child, doc.activeElement)) { doc.activeElement = doc.body; }
      return child;
    };

    el.addEventListener = (type, fn, capture) => {
      (el._listeners[type] = el._listeners[type] || []).push({ fn, capture: !!capture });
    };
    el.removeEventListener = (type, fn) => {
      el._listeners[type] = (el._listeners[type] || []).filter(r => r.fn !== fn);
    };

    // A runtime that will not focus a <button> is the failure the page's own
    // cursor exists to survive, so the shim can be one.
    el.focus = () => { if (opts.focus !== 'dead' && opts.focus !== 'hijack') { doc.activeElement = el; } };
    el.blur = () => { if (doc.activeElement === el) { doc.activeElement = doc.body; } };
    el.scrollIntoView = () => { el.scrollIntoViewCalls++; };
    // Undefined unless a scenario placed this node with layout(); the page
    // reads "no rectangle" as "cannot tell, assume visible".
    el.getBoundingClientRect = () => el._rect;
    el.click = () => dispatch(el, { type: 'click' });
    el.closest = sel => {
      for (let n = el; n && n !== doc; n = n.parentNode) {
        if (n.classList && matches(n, sel)) { return n; }
      }
      return null;
    };
    el.querySelectorAll = sel => collect(el, sel);
    el.getAttribute = k => (k === 'id' ? el.id : null);
    return el;
  }

  // Only the class selectors the page actually uses.
  function matches(el, sel) {
    if (sel[0] !== '.') { throw new Error('shim selector must be a class: ' + sel); }
    return el.classList.contains(sel.slice(1));
  }

  function collect(root, sel) {
    const out = [];
    (function walk(n) {
      n.childNodes.forEach(c => {
        if (c.classList && matches(c, sel)) { out.push(c); }
        walk(c);
      });
    })(root);
    return out;
  }

  function contains(root, node) {
    for (let n = node; n; n = n.parentNode) { if (n === root) { return true; } }
    return false;
  }

  // ── events ────────────────────────────────────────────────────────────────
  // Real bubbling, because every listener the page installs is delegated: the
  // list and the filter strip each take one click listener and dispatch on
  // whatever the event passed through on its way up.

  function dispatch(target, init) {
    // cancelable by default because every event this shim sends — keydown,
    // click, touch — is cancelable in a real DOM. The page guards its touch
    // preventDefault on it (calling preventDefault on a passive or
    // non-cancelable event is a console warning at best), so a shim that left
    // it undefined would silently skip the suppression it is meant to test.
    const ev = Object.assign({ target, cancelable: true, defaultPrevented: false }, init);
    ev.preventDefault = () => { ev.defaultPrevented = true; };
    const path = [];
    for (let n = target; n; n = n.parentNode) { path.push(n); }
    path.push(doc);
    let stopped = false;
    ev.stopPropagation = () => { stopped = true; };
    const fire = (n, capture) => {
      const recs = (n._listeners && n._listeners[ev.type]) || [];
      for (const rec of recs.slice()) { if (rec.capture === capture) { rec.fn(ev); } }
    };
    // Capture runs root-first, bubble target-first. The page's gesture handler
    // sits in the capture phase deliberately, so nothing downstream can consume
    // the event before it, and a shim that collapsed the two phases could not
    // tell that apart from a bubble-phase regression.
    for (let i = path.length - 1; i >= 0 && !stopped; i--) { fire(path[i], true); }
    for (const n of path) { if (stopped) { break; } fire(n, false); }
    return ev;
  }

  // ── document ──────────────────────────────────────────────────────────────

  const byId = {};
  const doc = {
    _listeners: {},
    visibilityState: 'visible',
    activeElement: null,
    createElement: mkElement,
    getElementById: id => byId[id] || null,
    querySelectorAll: sel => collect(doc.documentElement, sel),
    addEventListener: (t, fn, capture) => {
      (doc._listeners[t] = doc._listeners[t] || []).push({ fn, capture: !!capture });
    },
    removeEventListener: (t, fn) => {
      doc._listeners[t] = (doc._listeners[t] || []).filter(r => r.fn !== fn);
    },
  };

  function node(tag, id, parent) {
    const el = mkElement(tag);
    if (id) { el.id = id; byId[id] = el; }
    if (parent) { parent.appendChild(el); }
    return el;
  }

  // The page's markup. Kept in the same order as assets/glasses.html because
  // document order *is* the swipe order; a Go-side gate asserts the two
  // declare the same set of ids so this cannot drift into agreeing with a
  // page that no longer exists.
  doc.documentElement = mkElement('html');
  doc.body = node('body', null, doc.documentElement);
  const app = node('div', 'app', doc.body);
  const header = node('header', null, app);
  const back = node('button', 'back', header);
  node('div', 'title', header);
  const reload = node('button', 'reload', header);
  node('div', 'sub', app);
  node('div', 'filters', app);
  const addBtn = node('button', 'add', app);
  const dictate = node('button', 'dictate', app);
  node('div', 'micnote', app);
  node('div', 'msg', app);
  node('div', 'list', app);
  const more = node('button', 'more', app);

  // The four controls the stylesheet starts hidden.
  back.hidden = true;
  back.className = 'focusable';
  more.hidden = true;
  more.className = 'focusable';
  addBtn.hidden = true;
  addBtn.className = 'focusable';
  dictate.hidden = true;
  dictate.className = 'focusable';
  reload.className = 'focusable';
  doc.activeElement = doc.body;

  // Scrollability is a scenario input: it decides whether up/down scroll or
  // move the selection, and a shim with no layout has to be told.
  doc.documentElement.scrollHeight = opts.scrollHeight == null ? 2000 : opts.scrollHeight;
  doc.documentElement.clientHeight = opts.clientHeight == null ? 600 : opts.clientHeight;
  doc.scrollingElement = doc.documentElement;

  // ── network ───────────────────────────────────────────────────────────────

  const calls = [];
  let routes = opts.routes || {};
  function route(url) {
    const path = url.split('?')[0];
    const hit = routes[url] !== undefined ? routes[url] : routes[path];
    if (hit === undefined) { return { status: 404, body: {} }; }
    return typeof hit === 'function' ? hit(url) : { status: 200, body: hit };
  }

  // Request bodies, so a scenario can assert what the page actually sent —
  // the dictation flow's whole point is that a POST carries the transcript.
  const sent = [];

  const win = {
    fetch: (url, init) => {
      calls.push(url);
      sent.push({ url: url, method: (init && init.method) || 'GET', body: init && init.body });
      const r = route(url);
      return Promise.resolve({
        ok: r.status >= 200 && r.status < 300,
        status: r.status,
        json: () => Promise.resolve(r.body),
      });
    },
    timers: [],
  };

  // node defines globalThis.navigator as an accessor with no setter, so a
  // plain assignment throws. defineProperty replaces the whole descriptor.
  function setNavigator(value) {
    Object.defineProperty(globalThis, 'navigator', {
      value: value, writable: true, configurable: true, enumerable: true,
    });
  }

  // A fake microphone, installed only when a scenario asks for one.
  //
  // Absent by default, which is the Meta Ray-Ban Display case and therefore
  // the default worth testing: that runtime does not expose getUserMedia at
  // all, so the page has to notice and explain rather than offer a control
  // that cannot work.
  function installMic() {
    let live = null;
    class FakeRecorder {
      constructor() { this.state = 'inactive'; this.mimeType = 'audio/webm;codecs=opus'; live = this; }
      static isTypeSupported() { return true; }
      start() { this.state = 'recording'; }
      stop() {
        this.state = 'inactive';
        if (this.ondataavailable) { this.ondataavailable({ data: { size: 1024 } }); }
        if (this.onstop) { this.onstop(); }
      }
    }
    globalThis.MediaRecorder = FakeRecorder;

    // An AudioContext is installed only when a scenario names one, because the
    // page treats "cannot measure the level" as "assume speech" — so the
    // default (absent) keeps every other scenario uploading as before. With
    // one present the analyser reports a flat 128 for silence, which is what
    // the real waveform looks like when nobody spoke.
    if (opts.audio) {
      const level = opts.audio === 'silent' ? 128 : 200;
      globalThis.AudioContext = class {
        createAnalyser() {
          return { fftSize: 2048, getByteTimeDomainData(buf) { buf.fill(level); } };
        }
        createMediaStreamSource() { return { connect() {} }; }
        close() {}
      };
    } else {
      delete globalThis.AudioContext;
    }
    setNavigator({
      mediaDevices: {
        getUserMedia: () => {
          mic.starts++;
          return Promise.resolve({ getTracks: () => [{ stop() { mic.stopped++; } }] });
        },
      },
    });
    globalThis.Blob = function (parts, o) { this.size = 1024; this.type = (o && o.type) || ''; };
    globalThis.FormData = function () {
      this.parts = [];
      this.append = (k, v, n) => { this.parts.push({ k, n }); };
    };
    return { recorder: () => live };
  }
  const mic = { stopped: 0, starts: 0 };

  let micCtl = null;

  // Listeners the page installs on window itself, as opposed to on document.
  // The page uses these for the events that have no DOM target — an uncaught
  // error and the page going away — which is how the diagnostic trail learns
  // it should flush (Task 20251). Recorded rather than stubbed so a scenario
  // can fire them and assert on what the page did.
  const winListeners = {};

  return {
    doc,
    calls,
    sent,
    mic,
    recorder: () => (micCtl ? micCtl.recorder() : null),
    micStarts: () => mic.starts,
    setRoutes: r => { routes = r; },

    // fireWindow dispatches to the listeners installed on window.
    fireWindow: (type, ev) => {
      (winListeners[type] || []).forEach(fn => fn(ev || { type }));
    },

    install() {
      globalThis.window = globalThis;
      globalThis.document = doc;
      globalThis.location = { search: opts.search || '?token=test-token' };
      globalThis.fetch = win.fetch;
      for (const k of Object.keys(winListeners)) { delete winListeners[k]; }
      globalThis.addEventListener = (type, fn) => {
        (winListeners[type] || (winListeners[type] = [])).push(fn);
      };
      globalThis.removeEventListener = (type, fn) => {
        const l = winListeners[type];
        if (!l) { return; }
        const i = l.indexOf(fn);
        if (i >= 0) { l.splice(i, 1); }
      };
      globalThis.setInterval = (fn, ms) => { win.timers.push({ fn, ms }); return win.timers.length; };
      globalThis.clearInterval = id => { if (win.timers[id - 1]) { win.timers[id - 1].cleared = true; } };
      globalThis.isSecureContext = opts.insecure ? false : true;
      // Clear any microphone a previous scenario installed: these run in one
      // node process, and a leaked getUserMedia would make the no-microphone
      // case — the glasses themselves — silently untested.
      delete globalThis.MediaRecorder;
      setNavigator({ mediaDevices: undefined });
      micCtl = opts.mic ? installMic() : null;
    },

    // ── driving ─────────────────────────────────────────────────────────────

    // press models exactly what the glasses deliver: a keydown aimed at
    // activeElement (or the body when nothing has focus) that propagates.
    //
    // A string is the modern key name. An object is the whole event, so a
    // scenario can send what a gesture-synthesising engine might instead —
    // {key:'Right'}, {key:'Unidentified', keyCode:39}, {code:'ArrowRight'} —
    // which is the difference the page now has to survive.
    press: key => {
      const init = typeof key === 'string' ? { key } : key;
      const ev = dispatch(doc.activeElement || doc.body, Object.assign({ type: 'keydown' }, init));
      // 'hijack': the runtime re-aims focus at the first row after every
      // gesture, the way an engine with its own opinion about where the cursor
      // belongs would. The page must keep steering regardless.
      if (opts.focus === 'hijack') {
        const first = doc.getElementById('list').childNodes[0];
        if (first) { doc.activeElement = first; }
      }
      return ev;
    },
    // swipe models the gesture the device actually sends (Task 20279).
    //
    // The telemetry from a real Ray-Ban Display session records a pinch
    // arriving as Enter and no key whatsoever for a sideways swipe — not even
    // one the page failed to recognise, which it would have logged. The wearer
    // reported the same thing from the other side: sideways gestures moved a
    // scrollbar. That is touch, so press() is not enough to drive this page any
    // more and a suite that only presses keys cannot fail the way the hardware
    // does.
    //
    // Deliberately coarse. Real geometry, momentum and the compositor belong to
    // the browser gate in glasses_browser_test.go; what this models is the one
    // thing the page's recogniser reads — where the finger started and where it
    // left — so the recogniser cannot be deleted without something going red in
    // CI, which has no browser.
    swipe: (dx, dy, opts) => {
      const o = opts || {};
      const target = o.target || doc.activeElement || doc.body;
      const x0 = 150, y0 = 300;
      const pt = (x, y) => [{ clientX: x, clientY: y, identifier: 1 }];
      dispatch(target, { type: 'touchstart', touches: pt(x0, y0), changedTouches: pt(x0, y0) });
      // Two moves, not one: a recogniser that fires mid-drag would step the
      // cursor once per move, and one swipe has to be one stop.
      for (const f of [0.5, 1]) {
        dispatch(target, {
          type: 'touchmove',
          touches: pt(x0 + dx * f, y0 + dy * f),
          changedTouches: pt(x0 + dx * f, y0 + dy * f),
        });
      }
      return dispatch(target, {
        type: 'touchend', touches: [], changedTouches: pt(x0 + dx, y0 + dy),
      });
    },
    click: el => dispatch(el, { type: 'click' }),
    tick: () => win.timers.filter(t => !t.cleared).forEach(t => t.fn()),

    // layout stacks the ring down a column of the given row height and puts the
    // viewport at `scrollTop`, which is the only geometry any scenario needs:
    // it decides which controls the wearer can actually see. Everything not
    // placed here keeps no rectangle at all and so reads as visible.
    layout: (rowHeight, scrollTop, viewportHeight) => {
      const h = viewportHeight == null ? 600 : viewportHeight;
      globalThis.innerHeight = h;
      const ring = collect(doc.documentElement, '.focusable').filter(e => !e.hidden && !e.disabled);
      ring.forEach((e, i) => {
        const top = i * rowHeight - scrollTop;
        e._rect = { top, bottom: top + rowHeight, left: 0, right: 300, width: 300, height: rowHeight };
      });
      return ring.map((e, i) => ({
        name: e.id ? '#' + e.id : e.dataset.key || e.textContent,
        visible: e._rect.bottom > 0 && e._rect.top < h,
      }));
    },

    // settle flushes the promise chain a fetch handler turns into. Four turns
    // covers fetch -> json -> then, with room to spare; the scenarios assert
    // on the result, so an insufficient flush fails loudly rather than
    // silently passing.
    settle: async () => { for (let i = 0; i < 6; i++) { await Promise.resolve(); } },

    ids: () => Object.keys(byId),
    focused: () => doc.activeElement,
    // A stable, readable name for whatever has focus, for assertions.
    focusName: () => {
      const a = doc.activeElement;
      if (!a || a === doc.body) { return '<body>'; }
      if (a.id) { return '#' + a.id; }
      return (a.dataset && a.dataset.key) || a.textContent || '<?>';
    },
    // The cursor however the page expresses it — painted first, focus second.
    // Scenarios that ask "did this gesture steer?" use this, so that they fail
    // on the gesture and not on which mechanism the page happens to use to show
    // the answer; scenarios about the mechanism itself use selName directly.
    cursorName: () => {
      const marked = collect(doc.documentElement, '.sel');
      if (marked.length === 1) {
        const n = marked[0];
        return n.id ? '#' + n.id : (n.dataset && n.dataset.key) || n.textContent || '<?>';
      }
      if (marked.length > 1) { return '<' + marked.length + ' selected>'; }
      const a = doc.activeElement;
      if (!a || a === doc.body) { return '<none>'; }
      return a.id ? '#' + a.id : (a.dataset && a.dataset.key) || a.textContent || '<?>';
    },

    // The cursor as the wearer sees it: whatever carries the painted ring.
    // This is the assertion that still means something when the runtime will
    // not move focus, which is the whole point of the page owning a cursor.
    selName: () => {
      const marked = collect(doc.documentElement, '.sel');
      if (!marked.length) { return '<none>'; }
      if (marked.length > 1) { return '<' + marked.length + ' selected>'; }
      const n = marked[0];
      return n.id ? '#' + n.id : (n.dataset && n.dataset.key) || n.textContent || '<?>';
    },
    ring: () => collect(doc.documentElement, '.focusable')
      .filter(e => !e.hidden && !e.disabled)
      .map(e => (e.id ? '#' + e.id : e.dataset.key || e.textContent)),
    rows: () => doc.getElementById('list').childNodes.map(n => n.dataset.key),
    rowNodes: () => doc.getElementById('list').childNodes.slice(),
    text: id => doc.getElementById(id).textContent,
  };
}

module.exports = { makeDOM };
