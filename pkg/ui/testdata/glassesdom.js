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
// What it does NOT model is layout: no geometry, no computed style, no CSS.
// Visibility is therefore taken from the `hidden` property alone, which is
// exactly why the page sets `hidden` alongside its class contract rather than
// relying on a stylesheet this shim cannot read.

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

    el.addEventListener = (type, fn) => {
      (el._listeners[type] = el._listeners[type] || []).push(fn);
    };
    el.removeEventListener = (type, fn) => {
      el._listeners[type] = (el._listeners[type] || []).filter(f => f !== fn);
    };

    el.focus = () => { doc.activeElement = el; };
    el.blur = () => { if (doc.activeElement === el) { doc.activeElement = doc.body; } };
    el.scrollIntoView = () => { el.scrollIntoViewCalls++; };
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
    const ev = Object.assign({ target, defaultPrevented: false }, init);
    ev.preventDefault = () => { ev.defaultPrevented = true; };
    const path = [];
    for (let n = target; n; n = n.parentNode) { path.push(n); }
    path.push(doc);
    for (const n of path) {
      const fns = (n._listeners && n._listeners[ev.type]) || [];
      for (const fn of fns.slice()) { fn(ev); }
    }
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
    addEventListener: (t, fn) => { (doc._listeners[t] = doc._listeners[t] || []).push(fn); },
    removeEventListener: (t, fn) => {
      doc._listeners[t] = (doc._listeners[t] || []).filter(f => f !== fn);
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
  const dictate = node('button', 'dictate', app);
  node('div', 'micnote', app);
  node('div', 'msg', app);
  node('div', 'list', app);
  const more = node('button', 'more', app);

  // The three controls the stylesheet starts hidden.
  back.hidden = true;
  back.className = 'focusable';
  more.hidden = true;
  more.className = 'focusable';
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

  return {
    doc,
    calls,
    sent,
    mic,
    recorder: () => (micCtl ? micCtl.recorder() : null),
    micStarts: () => mic.starts,
    setRoutes: r => { routes = r; },
    install() {
      globalThis.window = globalThis;
      globalThis.document = doc;
      globalThis.location = { search: opts.search || '?token=test-token' };
      globalThis.fetch = win.fetch;
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
    // activeElement (or the body when nothing has focus) that bubbles.
    press: key => dispatch(doc.activeElement || doc.body, { type: 'keydown', key }),
    click: el => dispatch(el, { type: 'click' }),
    tick: () => win.timers.filter(t => !t.cleared).forEach(t => t.fn()),

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
    ring: () => collect(doc.documentElement, '.focusable')
      .filter(e => !e.hidden && !e.disabled)
      .map(e => (e.id ? '#' + e.id : e.dataset.key || e.textContent)),
    rows: () => doc.getElementById('list').childNodes.map(n => n.dataset.key),
    rowNodes: () => doc.getElementById('list').childNodes.slice(),
    text: id => doc.getElementById(id).textContent,
  };
}

module.exports = { makeDOM };
