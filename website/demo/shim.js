// shim.js — the hub the dashboard demo talks to, inside the page itself.
//
// The documentation site hosts a copy of the real dashboard at /demo/
// (scripts/build-demo.py). The dashboard expects a cloop hub at the root of
// its origin, and on github.io there is none, so this script, loaded before
// any of the dashboard's own, stands in for one:
//
//   * fetch and XMLHttpRequest. A read of a hub route (/api/…, /auth/…, or any
//     absolute path outside the demo's directory) is answered from the
//     fixtures build-demo.py compiled into this file, keyed by the method, the
//     path and the query; a read with no fixture gets an empty, well-formed
//     reply rather than an error. Every POST, PUT, PATCH and DELETE is refused
//     here, with a toast saying why, and never sent.
//   * WebSocket and EventSource. A socket opens, sends the frames recorded for
//     its URL (the state, the event-history sync point, the run flag,
//     presence), and then stays quiet. Anything the page sends is dropped.
//   * Everything that would call out, switched off: the sign-in renewal frame
//     and redirects, sign-out, telemetry (the hub's answer to whether to
//     collect is always no, and sendBeacon sends nothing), dictation and the
//     microphone. Claude sign-in starts with a POST, refused like every other,
//     so it never reaches the claude.ai page it would open. A request to
//     another origin is answered here like a hub route, so no request the page
//     makes leaves the origin.
//
// It uses nothing of the dashboard's and the dashboard knows nothing of it:
// pkg/ui serves no part of this, and the dashboard's assets are copied into the
// demo unchanged. window.cloopDemo lists the requests the page made and how
// each was answered, for the browser sweep and for finding what has no
// fixture yet. website/demo/README.md describes the fixtures.
(function() {
  'use strict';

  var MSG = 'This is a read-only demo. Install cloop to try this.';
  // Query parameters that say nothing about what a request asks for: the
  // access token, cache busters and nonces. The same list as VOLATILE_PARAMS
  // in scripts/build-demo.py, which keys the fixtures the same way.
  var VOLATILE = {token: 1, _: 1, t: 1, ts: 1, nonce: 1, n: 1, cb: 1};
  // Writes the page makes on its own rather than because someone pressed
  // something: refused like every other write, but without the toast. The
  // telemetry trail; and the Requirements tab reads its spec file with a POST
  // as it opens, quietly, and says so itself when a person asked.
  var SILENT = {'/api/telemetry': 1, '/api/requirements/spec/read': 1};
  // Answers no fixture can change, because each switches off something that
  // would otherwise call out or ask for the microphone.
  var FORCED = {
    'GET /api/telemetry/config': {body: {collect: false}},
    'GET /api/dictate': {body: {available: false, can_add_tasks: false}},
  };
  // Simulated network latency, in milliseconds. A reply that arrived in the
  // same task as its request would be a hub no browser ever talks to.
  var LATENCY = 12;

  var data = window.__cloopDemoFixtures || {fixtures: []};
  try { delete window.__cloopDemoFixtures; } catch (_) { window.__cloopDemoFixtures = undefined; }

  var realFetch = typeof window.fetch === 'function' ? window.fetch.bind(window) : null;
  var realOpen = window.open;
  // The demo's own directory. Its files — this script, the dashboard's assets
  // — are fetched for real; everything else the page asks for is the hub's.
  var home = new URL('.', location.href).pathname;
  var log = [];

  // ── Keys ──────────────────────────────────────────────────────────────────

  function parse(url) {
    try { return new URL(url, location.href); } catch (_) { return null; }
  }

  // keyOf is a request's key: `GET /api/state?project_idx=0`, the volatile
  // parameters dropped and the rest sorted. wild is whether the query ended
  // in `*`, which only a fixture's request line says.
  function keyOf(method, u) {
    var params = [], wild = false;
    u.searchParams.forEach(function(v, k) {
      if (k === '*') wild = true;
      else if (!VOLATILE[k]) params.push([k, v]);
    });
    params.sort(function(a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0; });
    var q = params.map(function(p) { return encodeURIComponent(p[0]) + '=' + encodeURIComponent(p[1]); }).join('&');
    var base = method + ' ' + u.pathname;
    return {base: base, params: params, wild: wild, key: base + (q ? '?' + q : '')};
  }

  // The fixtures, indexed: exact keys, and per method and path the wildcard
  // ones, most specific first.
  var exact = Object.create(null), wild = Object.create(null), count = 0;
  (data.fixtures || []).forEach(function(fx) {
    var sp = String(fx.request || '').indexOf(' ');
    var u = sp > 0 ? parse(fx.request.slice(sp + 1)) : null;
    if (!u) return;
    var k = keyOf(fx.request.slice(0, sp), u);
    count++;
    if (!k.wild) { exact[k.key] = fx; return; }
    (wild[k.base] = wild[k.base] || []).push({need: k.params, fx: fx});
  });
  Object.keys(wild).forEach(function(b) { wild[b].sort(function(x, y) { return y.need.length - x.need.length; }); });

  function lookup(method, u) {
    var k = keyOf(method, u);
    if (FORCED[k.base]) return {fx: FORCED[k.base], key: k.key, how: 'forced'};
    if (exact[k.key]) return {fx: exact[k.key], key: k.key, how: 'fixture'};
    var list = wild[k.base] || [];
    for (var i = 0; i < list.length; i++) {
      var ok = list[i].need.every(function(p) {
        return k.params.some(function(q) { return q[0] === p[0] && q[1] === p[1]; });
      });
      if (ok) return {fx: list[i].fx, key: k.key, how: 'fixture'};
    }
    return {fx: null, key: k.key, how: 'empty'};
  }

  // where says whose a URL is: 'local' for the demo's own files and for URLs
  // that never touch the network (data:, blob:), 'hub' for a route of the hub
  // the dashboard was written for, 'away' for another origin.
  function where(u) {
    if (u.protocol !== 'http:' && u.protocol !== 'https:' && u.protocol !== 'ws:' && u.protocol !== 'wss:') return 'local';
    var origin = u.protocol === 'ws:' ? 'http:' : u.protocol === 'wss:' ? 'https:' : u.protocol;
    if (origin + '//' + u.host !== location.origin) return 'away';
    if (/^\/(api|auth)\//.test(u.pathname)) return 'hub';
    return u.pathname.indexOf(home) === 0 ? 'local' : 'hub';
  }

  // hubPage is the parsed URL when following a link (or opening a window or a
  // frame) on raw would leave for a page of the hub: one the dashboard names
  // from the hub's root, as it names /auth/login or /glasses, or by an absolute
  // URL on this origin outside the demo. A relative link was written for the
  // demo's place in the site — the banner's to the install guide, an anchor —
  // and goes where it says, as does a link to another site.
  function hubPage(raw) {
    raw = String(raw == null ? '' : raw).trim();
    var u = parse(raw);
    if (!u || where(u) !== 'hub') return null;
    return /^(\/(?!\/)|[a-z][a-z0-9+.-]*:)/i.test(raw) ? u : null;
  }

  // The newest LOG_MAX requests are kept: a dashboard left open for a day
  // must not grow a list nobody reads.
  var LOG_MAX = 2000;
  function record(method, u, kind, how, key) {
    if (log.length >= LOG_MAX) log.shift();
    log.push({method: method, url: kind === 'away' ? u.href : u.pathname + u.search,
              key: key || '', to: kind, answer: how, at: Math.round(performance.now())});
  }

  // ── The answers ───────────────────────────────────────────────────────────

  // Each field this demo must not act on is taken out of a recorded answer.
  var SANITIZE = {
    // A recorded SSO session would otherwise schedule its silent renewal,
    // which loads the hub's /auth/renew in a frame.
    'GET /api/me': function(b) {
      if (b && typeof b === 'object') { delete b.renew_in_seconds; }
      return b;
    },
  };

  var REASONS = {200: 'OK', 404: 'Not Found', 405: 'Method Not Allowed', 409: 'Conflict', 500: 'Internal Server Error'};

  function response(status, text, type, extra) {
    var headers = {'Content-Type': type || 'application/json; charset=utf-8'};
    if (extra) Object.keys(extra).forEach(function(k) { headers[k] = extra[k]; });
    var empty = status === 204 || status === 205 || status === 304;
    return new Response(empty ? null : text, {status: status, statusText: REASONS[status] || '', headers: headers});
  }

  function answer(method, u, kind) {
    var read = method === 'GET' || method === 'HEAD';
    if (!read) {
      record(method, u, kind, 'refused');
      if (!SILENT[u.pathname]) notice();
      return response(405, JSON.stringify({error: {code: 'read_only_demo', message: MSG}}), null, {Allow: 'GET, HEAD'});
    }
    var hit = lookup('GET', u);
    record(method, u, kind, hit.how, hit.key);
    var fx = hit.fx;
    if (!fx) return response(200, method === 'HEAD' ? null : '{}');
    var text;
    if (typeof fx.text === 'string') {
      text = fx.text;
    } else {
      var body = JSON.parse(JSON.stringify(fx.body === undefined ? {} : fx.body));
      var clean = SANITIZE['GET ' + u.pathname];
      text = JSON.stringify(clean ? clean(body) : body);
    }
    return response(fx.status || 200, method === 'HEAD' ? null : text, fx.type);
  }

  function aborted() {
    return new DOMException('The operation was aborted.', 'AbortError');
  }

  // later settles after LATENCY with what make() returns, or rejects as a
  // real fetch does when signal aborts first.
  function later(make, signal) {
    return new Promise(function(resolve, reject) {
      if (signal && signal.aborted) { reject(aborted()); return; }
      var timer = setTimeout(function() {
        if (signal) signal.removeEventListener('abort', onAbort);
        try { resolve(make()); } catch (e) { reject(e); }
      }, LATENCY);
      function onAbort() { clearTimeout(timer); reject(aborted()); }
      if (signal) signal.addEventListener('abort', onAbort);
    });
  }

  // ── fetch ─────────────────────────────────────────────────────────────────

  function demoFetch(input, init) {
    var req = (typeof Request === 'function' && input instanceof Request) ? input : null;
    var u = parse(req ? req.url : String(input));
    if (!u) return Promise.reject(new TypeError('Failed to fetch'));
    var kind = where(u);
    if (kind === 'local') return realFetch(input, init);
    var method = String((init && init.method) || (req && req.method) || 'GET').toUpperCase();
    var signal = (init && init.signal) || (req && req.signal) || null;
    return later(function() { return answer(method, u, kind); }, signal);
  }
  window.fetch = demoFetch;

  // ── XMLHttpRequest ────────────────────────────────────────────────────────
  // Built on the fetch above, so it answers exactly as fetch does: the demo's
  // own files for real, everything else from the fixtures. Asynchronous only;
  // nothing in the dashboard uses XHR at all, and a synchronous request would
  // block the page.

  var XHR_STATES = ['UNSENT', 'OPENED', 'HEADERS_RECEIVED', 'LOADING', 'DONE'];

  class DemoXHR extends EventTarget {
    constructor() {
      super();
      this.readyState = 0; this.status = 0; this.statusText = '';
      this.response = ''; this.responseText = ''; this.responseURL = '';
      this.responseType = ''; this.timeout = 0; this.withCredentials = false;
      this.upload = new EventTarget();
      this._method = 'GET'; this._url = ''; this._headers = {}; this._res = null; this._ctl = null;
    }
    _emit(type, progress) {
      var ev = progress ? new ProgressEvent(type) : new Event(type);
      this.dispatchEvent(ev);
      var h = this['on' + type];
      if (typeof h === 'function') h.call(this, ev);
    }
    _state(n) {
      this.readyState = n;
      this._emit('readystatechange');
    }
    open(method, url, async) {
      if (async === false) throw new DOMException('The demo does not answer synchronous requests.', 'InvalidAccessError');
      this._method = String(method || 'GET').toUpperCase();
      this._url = String(url);
      this._headers = {}; this._res = null; this._timedOut = false;
      this.status = 0; this.statusText = ''; this.response = ''; this.responseText = '';
      this._state(1);
    }
    setRequestHeader(name, value) {
      if (this.readyState !== 1) throw new DOMException('The object is not opened.', 'InvalidStateError');
      this._headers[name] = value;
    }
    getResponseHeader(name) {
      return this._res ? this._res.headers.get(name) : null;
    }
    getAllResponseHeaders() {
      if (!this._res) return '';
      var out = '';
      this._res.headers.forEach(function(v, k) { out += k + ': ' + v + '\r\n'; });
      return out;
    }
    overrideMimeType() {}
    abort() {
      if (this._ctl) this._ctl.abort();
    }
    send(body) {
      if (this.readyState !== 1) throw new DOMException('The object is not opened.', 'InvalidStateError');
      var self = this, ctl = this._ctl = new AbortController();
      var init = {method: this._method, headers: this._headers, signal: ctl.signal};
      if (body !== undefined && body !== null && this._method !== 'GET' && this._method !== 'HEAD') init.body = body;
      var timer = this.timeout > 0 ? setTimeout(function() { self._timedOut = true; ctl.abort(); }, this.timeout) : 0;
      this._emit('loadstart', true);
      demoFetch(this._url, init).then(function(res) {
        self._res = res;
        self.status = res.status; self.statusText = res.statusText;
        self.responseURL = parse(self._url).href;
        self._state(2); self._state(3);
        var type = self.responseType;
        var body = type === 'arraybuffer' ? res.arrayBuffer() : type === 'blob' ? res.blob() : res.text();
        return body.then(function(b) {
          if (type === 'json') { try { self.response = JSON.parse(b); } catch (_) { self.response = null; } }
          else if (type === '' || type === 'text') { self.response = self.responseText = b; }
          else self.response = b;
        });
      }).then(function() {
        clearTimeout(timer);
        self._state(4);
        self._emit('progress', true); self._emit('load', true); self._emit('loadend', true);
      }, function() {
        clearTimeout(timer);
        self.status = 0;
        self._state(4);
        self._emit(self._timedOut ? 'timeout' : ctl.signal.aborted ? 'abort' : 'error', true);
        self._emit('loadend', true);
      });
    }
  }
  XHR_STATES.forEach(function(s, i) { DemoXHR[s] = i; DemoXHR.prototype[s] = i; });
  window.XMLHttpRequest = DemoXHR;

  // ── WebSocket ─────────────────────────────────────────────────────────────

  class DemoWebSocket extends EventTarget {
    constructor(url) {
      super();
      var u = parse(String(url));
      if (u && /^https?:$/.test(u.protocol)) u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:';
      if (!u || !/^wss?:$/.test(u.protocol)) throw new DOMException("The URL '" + url + "' is invalid.", 'SyntaxError');
      this.url = u.href; this.readyState = 0; this.protocol = ''; this.extensions = '';
      this.binaryType = 'blob'; this.bufferedAmount = 0;
      var kind = where(u), hit = lookup('WS', u), self = this;
      record('WS', u, kind, hit.how === 'empty' ? 'quiet' : hit.how, hit.key);
      var frames = (hit.fx && hit.fx.frames) || [];
      setTimeout(function() {
        if (self.readyState !== 0) return;
        self.readyState = 1;
        self._emit(new Event('open'));
        var i = 0;
        (function next() {
          if (self.readyState !== 1 || i >= frames.length) return;
          var f = frames[i++];
          self._emit(new MessageEvent('message', {data: typeof f === 'string' ? f : JSON.stringify(f), origin: u.origin}));
          setTimeout(next, 4);
        })();
      }, LATENCY);
    }
    _emit(ev) {
      this.dispatchEvent(ev);
      var h = this['on' + ev.type];
      if (typeof h === 'function') h.call(this, ev);
    }
    send() {
      if (this.readyState === 0) throw new DOMException('Still in CONNECTING state.', 'InvalidStateError');
    }
    close(code, reason) {
      if (this.readyState >= 2) return;
      var self = this;
      this.readyState = 2;
      setTimeout(function() {
        self.readyState = 3;
        self._emit(new CloseEvent('close', {code: code || 1005, reason: reason || '', wasClean: true}));
      }, 0);
    }
  }
  ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'].forEach(function(s, i) { DemoWebSocket[s] = i; DemoWebSocket.prototype[s] = i; });
  window.WebSocket = DemoWebSocket;

  // ── EventSource ───────────────────────────────────────────────────────────
  // Only the dashboard's fallback when a proxy blocks WebSocket upgrades, which
  // the stand-in above never does: it opens and stays quiet.

  class DemoEventSource extends EventTarget {
    constructor(url, init) {
      super();
      var u = parse(String(url)), self = this;
      if (!u) throw new DOMException("The URL '" + url + "' is invalid.", 'SyntaxError');
      this.url = u.href; this.readyState = 0; this.withCredentials = !!(init && init.withCredentials);
      record('SSE', u, where(u), 'quiet');
      setTimeout(function() {
        if (self.readyState !== 0) return;
        self.readyState = 1;
        var ev = new Event('open');
        self.dispatchEvent(ev);
        if (typeof self.onopen === 'function') self.onopen(ev);
      }, LATENCY);
    }
    close() { this.readyState = 2; }
  }
  ['CONNECTING', 'OPEN', 'CLOSED'].forEach(function(s, i) { DemoEventSource[s] = i; DemoEventSource.prototype[s] = i; });
  window.EventSource = DemoEventSource;

  // ── What would call out ───────────────────────────────────────────────────

  // Telemetry's transport for a page being closed. Nothing is sent.
  if (typeof Navigator === 'function' && Navigator.prototype.sendBeacon) {
    Navigator.prototype.sendBeacon = function(url) {
      var u = parse(String(url));
      if (u) record('BEACON', u, where(u), 'dropped');
      return true;
    };
  }

  // Dictation and the Chat tab's voice input: no microphone in a demo.
  if (typeof MediaDevices === 'function' && MediaDevices.prototype.getUserMedia) {
    MediaDevices.prototype.getUserMedia = function() {
      notice();
      return Promise.reject(new DOMException(MSG, 'NotAllowedError'));
    };
  }

  // A window onto a hub route — the confirm-it's-you sign-in, a sign-in page —
  // would open a 404 of github.io. Other sites open as they would anyway.
  window.open = function(url) {
    var u = url ? hubPage(url) : null;
    if (u) { record('OPEN', u, 'hub', 'refused'); notice(); return null; }
    return realOpen.apply(window, arguments);
  };

  // The silent sign-in renewal runs /auth/renew in a hidden frame. The answers
  // above never ask for it, and should one ever, the frame gets about:blank.
  var frameSrc = window.HTMLIFrameElement && Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');
  if (frameSrc && frameSrc.set) {
    Object.defineProperty(HTMLIFrameElement.prototype, 'src', {
      configurable: true, enumerable: frameSrc.enumerable, get: frameSrc.get,
      set: function(v) {
        var u = hubPage(v);
        if (u) { record('FRAME', u, 'hub', 'refused'); v = 'about:blank'; }
        frameSrc.set.call(this, v);
      },
    });
  }

  // Sign-out posts to the hub and then navigates to its sign-in page; the
  // dashboard calls it by its global name, which this keeps.
  Object.defineProperty(window, 'signOut', {
    configurable: true,
    get: function() { return function() { notice(); }; },
    set: function() {},
  });

  // A link to a hub route, and the controls that navigate to the hub's
  // sign-in page, act before the dashboard's own listeners see the click — a
  // middle click too, which would open the hub's page in a new tab.
  function onClick(ev) {
    var t = ev.target;
    if (!t || !t.closest) return;
    var a = t.closest('a[href]'), u = a ? hubPage(a.getAttribute('href')) : null;
    if (u || (ev.type === 'click' && t.closest('[data-action="signInAgain"], #logoutBtn'))) {
      if (u) record('LINK', u, 'hub', 'refused');
      ev.preventDefault();
      ev.stopPropagation();
      notice();
    }
  }
  window.addEventListener('click', onClick, true);
  window.addEventListener('auxclick', onClick, true);

  // ── The toast ─────────────────────────────────────────────────────────────
  // The dashboard's own #toast, so the refusal looks like any other message.
  // The dashboard then reports the failed request in the same place, in its
  // own words ("Save failed: …"); for a few seconds after a refusal every such
  // message is replaced by this one, which says what actually happened.

  var guardUntil = 0, watching = null;

  function notice() {
    var el = document.getElementById('toast');
    if (!el) return;
    guardUntil = Date.now() + 3500;
    if (watching !== el) {
      watching = el;
      new MutationObserver(function() {
        if (Date.now() > guardUntil || !/\bshow\b/.test(el.className)) return;
        if (el.textContent !== MSG) el.textContent = MSG;
        if (el.className !== 'show info') el.className = 'show info';
      }).observe(el, {childList: true, characterData: true, subtree: true, attributes: true, attributeFilter: ['class']});
    }
    el.textContent = MSG;
    el.className = 'show info';
    clearTimeout(el._t);
    el._t = setTimeout(function() { el.className = ''; }, 3500);
  }

  window.cloopDemo = Object.freeze({
    message: MSG,
    fixtures: count,
    // Every request the page made, oldest first: what it asked for, whose it
    // was, and how it was answered ('fixture', 'forced', 'empty', 'refused',
    // 'quiet' for a socket with no frames, 'dropped' for a beacon).
    requests: function() { return log.map(function(r) { return Object.assign({}, r); }); },
  });
})();
