// domshim.js — the smallest browser the dashboard bundle will run in.
//
// pkg/ui/assets/js/*.js is shipped as one IIFE that talks to a DOM, a fetch,
// and a WebSocket. Every frontend gate in this package greps that source as
// text, which is why the multi-project scoping bug class kept coming back:
// text cannot express "a frame that arrives after the user clicked another
// project must not render". Running the real bundle against this shim can.
//
// It is deliberately dumb — elements auto-vivify, selectors return nothing,
// layout does not exist. The only parts modelled with care are the two the
// scoping tests actually assert on:
//
//   fetch      — routes by ?project_idx=N, like resolveWorkDir does, so a
//                request for the wrong project returns the wrong project's
//                data rather than silently the right one.
//   WebSocket  — every instance is recorded and never delivers anything on
//                its own, so a test drives the exact frame interleaving it
//                wants, including frames on a socket the bundle has closed.

'use strict';

// The bundle assumes a browser's window === globalThis identity: it reads
// bare `fetch` but assigns `window.fetch`, and both have to be the same slot.
globalThis.window = globalThis;

// ── elements ────────────────────────────────────────────────────────────────

function mkClassList() {
  const set = new Set();
  return {
    add:      (...c) => c.forEach(x => set.add(x)),
    remove:   (...c) => c.forEach(x => set.delete(x)),
    contains: c => set.has(c),
    toggle:   (c, force) => {
      const on = force === undefined ? !set.has(c) : !!force;
      if (on) set.add(c); else set.delete(c);
      return on;
    },
    get length() { return set.size; },
    _all: set,
  };
}

function mkElement(id) {
  const attrs = {};
  const el = {
    id: id || '',
    innerHTML: '',
    textContent: '',
    value: '',
    checked: false,
    disabled: false,
    selectedIndex: 0,
    options: [],
    children: [],
    dataset: {},
    style: {},
    classList: mkClassList(),
    scrollTop: 0,
    scrollHeight: 0,
    clientHeight: 0,
    offsetWidth: 0,
    parentNode: null,
    setAttribute: (k, v) => { attrs[k] = String(v); },
    getAttribute: k => (k in attrs ? attrs[k] : null),
    removeAttribute: k => { delete attrs[k]; },
    hasAttribute: k => k in attrs,
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => true,
    appendChild: c => { el.children.push(c); return c; },
    removeChild: c => { el.children = el.children.filter(x => x !== c); return c; },
    insertAdjacentHTML: () => {},
    querySelector: () => null,
    querySelectorAll: () => [],
    closest: () => null,
    remove: () => {},
    focus: () => {},
    blur: () => {},
    click: () => {},
    select: () => {},
    scrollIntoView: () => {},
    getBoundingClientRect: () => ({top: 0, left: 0, width: 0, height: 0, right: 0, bottom: 0}),
  };
  return el;
}

const _elements = new Map();

globalThis.document = {
  // Auto-vivifying: the bundle touches hundreds of IDs across panels that no
  // scoping test cares about, and a null here would throw before reaching the
  // assertion. Tests read back the ones they named.
  getElementById(id) {
    if (!_elements.has(id)) _elements.set(id, mkElement(id));
    return _elements.get(id);
  },
  createElement: tag => mkElement('<' + tag + '>'),
  createTextNode: t => ({textContent: t}),
  querySelector: () => null,
  querySelectorAll: () => [],
  addEventListener: () => {},
  removeEventListener: () => {},
  documentElement: mkElement('html'),
  body: mkElement('body'),
  head: mkElement('head'),
  hidden: false,
  visibilityState: 'visible',
  cookie: '',
  title: '',
};

// ── storage ─────────────────────────────────────────────────────────────────

function mkStorage() {
  const m = new Map();
  return {
    getItem: k => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: k => m.delete(k),
    clear: () => m.clear(),
    key: i => Array.from(m.keys())[i] ?? null,
    get length() { return m.size; },
  };
}
globalThis.localStorage = mkStorage();
globalThis.sessionStorage = mkStorage();

// ── environment ─────────────────────────────────────────────────────────────

globalThis.location = {
  protocol: 'https:', host: 'hub.example', hostname: 'hub.example',
  origin: 'https://hub.example', pathname: '/', search: '', hash: '', href: 'https://hub.example/',
  reload: () => {}, assign: () => {}, replace: () => {},
};
// defineProperty, not assignment: node ships a getter-only global navigator.
Object.defineProperty(globalThis, 'navigator', {
  value: {userAgent: 'domshim', language: 'en-US', clipboard: {writeText: async () => {}}},
  writable: true, configurable: true,
});
globalThis.matchMedia = () => ({matches: false, addListener: () => {}, removeListener: () => {}, addEventListener: () => {}, removeEventListener: () => {}});
globalThis.addEventListener = () => {};
globalThis.removeEventListener = () => {};
globalThis.dispatchEvent = () => true;
globalThis.scrollTo = () => {};
globalThis.getComputedStyle = () => ({getPropertyValue: () => ''});
globalThis.requestAnimationFrame = fn => setTimeout(() => fn(Date.now()), 0);
globalThis.cancelAnimationFrame = id => clearTimeout(id);
globalThis.IntersectionObserver = class { observe() {} unobserve() {} disconnect() {} };
globalThis.MutationObserver = class { observe() {} disconnect() {} };
globalThis.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
globalThis.alert = () => {};
globalThis.confirm = () => true;
globalThis.prompt = () => null;
globalThis.Notification = class { static permission = 'default'; static requestPermission() { return Promise.resolve('default'); } };

// ── harness state ───────────────────────────────────────────────────────────

const harness = {
  // Per-project payloads keyed by the index the client passes as ?project_idx.
  // A test fills these; anything unset is served as the primary project, which
  // is what the server does when a stream carries no index.
  states: {},
  projects: {projects: [], stats: {}, multi_project: true},
  me: {oidc_enabled: false, authenticated: false, permissions: null},
  sockets: [],       // every WebSocket the bundle has constructed, in order
  eventSources: [],
  requests: [],      // every URL fetched, in order
  routes: {},        // extra canned responses, keyed by path prefix
};
globalThis.__harness = harness;

// projectIdxOf mirrors resolveWorkDir: an absent index means the primary
// project, not "no project". That fallback is the whole reason an unscoped
// stream can deliver another project's state.
function projectIdxOf(url) {
  const m = /[?&]project_idx=(\d+)/.exec(String(url));
  return m ? Number(m[1]) : 0;
}

function stateFor(idx) {
  return harness.states[idx] ?? harness.states[0] ?? {};
}

// ── fetch ───────────────────────────────────────────────────────────────────

function jsonResponse(body, status) {
  const text = JSON.stringify(body);
  return Promise.resolve({
    ok: (status || 200) < 400,
    status: status || 200,
    headers: {get: () => null},
    json: () => Promise.resolve(JSON.parse(text)),
    text: () => Promise.resolve(text),
  });
}

globalThis.fetch = function(url, opts) {
  const u = String(url);
  harness.requests.push({url: u, method: (opts && opts.method) || 'GET'});

  for (const prefix of Object.keys(harness.routes)) {
    if (u.startsWith(prefix)) return jsonResponse(harness.routes[prefix]);
  }
  if (u.startsWith('/api/state'))    return jsonResponse(stateFor(projectIdxOf(u)));
  if (u.startsWith('/api/projects')) return jsonResponse(harness.projects);
  if (u.startsWith('/api/me'))       return jsonResponse(harness.me);
  if (u.startsWith('/api/livelog'))  return jsonResponse({lines: [], running: false});
  return jsonResponse({});
};

// ── WebSocket ───────────────────────────────────────────────────────────────

// Nothing is delivered automatically. A browser's socket is a queue the
// network fills; here the test is the network, so it decides which socket
// delivers what and in which order — including a socket the bundle has
// already called close() on, whose frames a browser still dispatches until
// the closing handshake completes.
globalThis.WebSocket = class FakeWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  constructor(url) {
    this.url = String(url);
    this.projectIdx = /[?&]project_idx=/.test(this.url) ? projectIdxOf(this.url) : null;
    this.readyState = FakeWebSocket.CONNECTING;
    this.sent = [];
    this.onopen = this.onmessage = this.onclose = this.onerror = null;
    harness.sockets.push(this);
  }

  send(d) { this.sent.push(d); }

  close() {
    // Matches the browser: close() starts a handshake and returns. The socket
    // is not dead yet, and frames already in flight still reach onmessage.
    this.readyState = FakeWebSocket.CLOSING;
  }

  // -- test-driven -----------------------------------------------------------
  open()          { this.readyState = FakeWebSocket.OPEN; if (this.onopen) this.onopen({}); }
  deliver(type, data) { if (this.onmessage) this.onmessage({data: JSON.stringify({type, data})}); }
  finishClose()   { this.readyState = FakeWebSocket.CLOSED; if (this.onclose) this.onclose({code: 1000}); }
};

globalThis.EventSource = class FakeEventSource {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSED = 2;
  constructor(url) {
    this.url = String(url);
    this.listeners = {};
    this.readyState = FakeEventSource.CONNECTING;
    this.onopen = this.onmessage = this.onerror = null;
    harness.eventSources.push(this);
  }
  addEventListener(t, fn) { (this.listeners[t] ||= []).push(fn); }
  removeEventListener() {}
  close() { this.readyState = FakeEventSource.CLOSED; }
  open() { this.readyState = FakeEventSource.OPEN; if (this.onopen) this.onopen({}); }
  deliver(type, data) {
    const ev = {data: JSON.stringify(data)};
    if (type === 'message') { if (this.onmessage) this.onmessage(ev); return; }
    for (const fn of this.listeners[type] || []) fn(ev);
  }
};

// ── assertion helpers ───────────────────────────────────────────────────────

// A settled microtask+timer queue. The bundle chains promises off fetch, so a
// scenario step is only complete once those have run.
globalThis.__settle = async function(rounds) {
  for (let i = 0; i < (rounds || 3); i++) {
    await new Promise(r => setTimeout(r, 0));
  }
};

// What the user is looking at on the Tasks tab. IDs, not titles: the markup
// escapes titles and prefixes pinned ones with a badge, whereas data-task-id
// is what every action on the row dispatches on.
globalThis.__renderedTaskIds = function() {
  const html = document.getElementById('taskListFull').innerHTML || '';
  const out = [];
  const re = /data-task-id="(\d+)"/g;
  let m;
  while ((m = re.exec(html)) !== null) out.push(Number(m[1]));
  return out;
};
