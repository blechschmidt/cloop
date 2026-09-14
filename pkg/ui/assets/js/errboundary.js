// ── Telemetry reporter and global error boundary ────────────────────────────
//
// Loaded as its own script element BEFORE the main bundle, so exceptions thrown
// during bundle initialisation, in async callbacks, or from inline handler
// attributes are all caught, and so that the reporter exists before anything
// that might want to call it. Four responsibilities:
//
//   1. Maintain a diagnostic trail for this page load and flush it in batches
//      to POST /api/telemetry, where an operator can read it back (Task 20251).
//   2. Auto-instrument what the page cannot easily report by hand: uncaught
//      errors, unhandled rejections, every fetch and its status, and the
//      page-lifecycle transitions.
//   3. Expose window.cloopTelemetry so the bundle can add the context only it
//      has — which tab is open, which action a user took.
//   4. Show a non-blocking toast on error, escalating to a full-screen
//      recovery banner after >3 errors in a 30-second window, so a user is not
//      trapped in a loop of broken UI with only an unread toast.
//
// The trail is the part that is new and the part that matters. An exception
// report says a line threw; it does not say that the user pressed the key
// three times and the view never changed, which is the shape almost every
// front-end defect in this project has actually had.
//
// Every branch is individually try/catch-guarded. The reporter must never
// throw: if it does, the browser falls back to its default (silent) behaviour
// and the page becomes a dead end with no record of why.
(function() {
  if (window.__cloopErrBoundaryInstalled) return;
  window.__cloopErrBoundaryInstalled = true;

  var ENDPOINT   = '/api/telemetry';
  var SOURCE     = 'dashboard';

  var WINDOW_MS  = 30000;     // rolling window for the escalation check
  var THRESHOLD  = 3;         // errors within that window before the banner

  var FLUSH_MS   = 5000;      // idle flush cadence
  var BATCH_MAX  = 64;        // must not exceed telemetry.MaxBatchEvents
  // Hard ceiling on events recorded per page load. Defence in depth against a
  // render loop that would otherwise turn one bug into thousands of rows: the
  // first few hundred events of a loop describe it completely, and the rest
  // only cost storage that a later investigation needs.
  var EVENT_MAX  = 500;
  // Separate, smaller budget for routine events — the successful fetches and
  // visibility flips that give a trail its texture but are not themselves
  // findings. A dashboard left open all afternoon issues thousands of
  // successful requests, and without a second budget those would consume
  // EVENT_MAX and leave no room for the error that arrives at four o'clock.
  // Routine events stop first; the interesting ones keep their headroom.
  var ROUTINE_MAX = 150;
  // Independent cap on flushes, so a failing endpoint cannot become its own
  // traffic source.
  var POST_MAX   = 60;

  var session    = newSessionID();
  var seq        = 0;
  var recorded   = 0;
  var routine    = 0;
  var posted     = 0;
  var queue      = [];
  var timer      = null;
  var view       = '';
  var recent     = [];        // timestamps of recent errors
  var release    = '';        // hub build, filled in by the bundle when known

  function newSessionID() {
    try {
      // Random per page load: a trail describes one page's life, and the
      // reload that follows a crash is a different story worth telling apart.
      var buf = new Uint8Array(8);
      (window.crypto || window.msCrypto).getRandomValues(buf);
      var out = '';
      for (var i = 0; i < buf.length; i++) out += ('0' + buf[i].toString(16)).slice(-2);
      return out;
    } catch (_) {
      return 'n' + Math.floor(Math.random() * 1e12).toString(16);
    }
  }

  function activeTabName() {
    try {
      var el = document.querySelector('.tab-panel.active');
      if (el && el.id && el.id.indexOf('tab-') === 0) return el.id.slice(4);
    } catch (_) {}
    return '';
  }

  // ── recording ─────────────────────────────────────────────────────────────

  // record appends one event. detail may be any JSON-serialisable value; it is
  // stringified here so a caller cannot pass something that fails to encode at
  // flush time and takes the whole batch with it.
  //
  // opts.routine marks a high-volume, low-value event (see ROUTINE_MAX).
  // opts.now forces an immediate flush rather than waiting for the timer.
  function record(kind, message, opts) {
    try {
      opts = opts || {};
      if (recorded >= EVENT_MAX) return;
      if (opts.routine) {
        if (routine >= ROUTINE_MAX) return;
        routine++;
      }
      recorded++;
      var detail = '';
      if (opts.detail !== undefined && opts.detail !== null) {
        try {
          detail = typeof opts.detail === 'string'
            ? opts.detail
            : JSON.stringify(opts.detail);
        } catch (_) { detail = ''; }
      }
      queue.push({
        kind:    String(kind || 'note'),
        seq:     ++seq,
        ts:      Date.now(),
        message: String(message === undefined || message === null ? '' : message),
        stack:   String(opts.stack || ''),
        url:     String(opts.url || ''),
        view:    String(opts.view || view || activeTabName() || ''),
        detail:  detail
      });
      if (queue.length >= BATCH_MAX || opts.now) {
        flush(false);
      } else {
        schedule();
      }
    } catch (_) {}
  }

  function schedule() {
    try {
      if (timer !== null) return;
      timer = setTimeout(function() { timer = null; flush(false); }, FLUSH_MS);
    } catch (_) {}
  }

  // flush posts whatever is queued. beacon=true is the page-unload path, where
  // fetch is unreliable and sendBeacon is the only transport the browser
  // promises to finish.
  function flush(beacon) {
    try {
      if (timer !== null) { clearTimeout(timer); timer = null; }
      if (!queue.length) return;
      if (posted >= POST_MAX) { queue.length = 0; return; }
      posted++;

      var batch = queue.splice(0, BATCH_MAX);
      // A remainder is unreachable today — record() flushes exactly when the
      // queue hits BATCH_MAX, so the splice always empties it — but flush()
      // clears the timer, so a future caller that queued more would strand
      // whatever it left behind until the next unrelated event. Rescheduling
      // here keeps that from being a silent hole.
      if (queue.length) schedule();
      var body = JSON.stringify({
        source:  SOURCE,
        session: session,
        release: release,
        events:  batch
      });

      if (beacon) {
        try {
          if (navigator.sendBeacon &&
              navigator.sendBeacon(ENDPOINT, new Blob([body], {type: 'application/json'}))) {
            return;
          }
        } catch (_) {}
        // Fall through to fetch+keepalive if sendBeacon is missing or refuses.
      }

      var headers = {'Content-Type': 'application/json'};
      try {
        var t = sessionStorage.getItem('cloop_token');
        if (t) headers['Authorization'] = 'Bearer ' + t;
      } catch (_) {}

      // keepalive lets the request complete even if the user navigates away or
      // reloads immediately after the error that triggered it.
      fetch(ENDPOINT, {
        method:    'POST',
        headers:   headers,
        body:      body,
        keepalive: true,
        // The trail is diagnostic, not authoritative: a hub that rejects it
        // must not become a reason for the page to retry, so the response is
        // discarded and failures are swallowed.
        credentials: 'same-origin'
      }).catch(function() {});
    } catch (_) {}
  }

  // ── the boundary's own UX ─────────────────────────────────────────────────

  function showToast() {
    try {
      var el = document.getElementById('errboundary-toast');
      if (el) el.style.display = 'flex';
    } catch (_) {}
  }

  function showBanner() {
    try {
      var el = document.getElementById('errboundary-banner');
      if (el) el.style.display = 'flex';
    } catch (_) {}
  }

  // noteError records an error and drives the escalation UI. Errors flush
  // immediately rather than on the idle timer: the most valuable error report
  // is the one from the page that is about to be closed in frustration.
  function noteError(kind, message, opts) {
    record(kind, message, opts);
    flush(false);
    try {
      var now = Date.now();
      recent.push(now);
      var cutoff = now - WINDOW_MS;
      while (recent.length && recent[0] < cutoff) recent.shift();
      showToast();
      if (recent.length > THRESHOLD) showBanner();
    } catch (_) {}
  }

  // ── auto-instrumentation ──────────────────────────────────────────────────

  window.addEventListener('error', function(ev) {
    try {
      var msg = (ev && (ev.message || (ev.error && ev.error.message))) || 'Unknown error';
      var stack = (ev && ev.error && ev.error.stack) || '';
      noteError('error', String(msg), {
        stack:  String(stack),
        url:    String((ev && ev.filename) || location.href),
        detail: {line: (ev && ev.lineno) | 0, col: (ev && ev.colno) | 0}
      });
    } catch (_) {}
  });

  window.addEventListener('unhandledrejection', function(ev) {
    try {
      var reason = ev && ev.reason;
      var msg = '', stack = '';
      if (reason && typeof reason === 'object') {
        msg   = reason.message || String(reason);
        stack = reason.stack   || '';
      } else {
        msg = String(reason);
      }
      noteError('rejection', msg, {stack: String(stack), url: location.href});
    } catch (_) {}
  });

  // Wrap fetch so every API call the dashboard makes is on the trail with its
  // status and duration. This is the highest-value instrument here: most of
  // what goes wrong is a request that 403'd, 404'd or never returned, and none
  // of that reaches an error handler.
  //
  // Successes are recorded too, but only their shape — a trail showing the
  // calls that worked is what makes the absent one legible.
  try {
    var nativeFetch = window.fetch;
    if (typeof nativeFetch === 'function') {
      window.fetch = function(input, init) {
        var url = '';
        try {
          url = typeof input === 'string' ? input : (input && input.url) || '';
        } catch (_) {}
        // Never instrument the reporter's own POST: that is an infinite
        // regress, and one that would accelerate.
        if (url && url.indexOf(ENDPOINT) === 0) {
          return nativeFetch.apply(this, arguments);
        }
        var started = Date.now();
        var method = (init && init.method) || 'GET';
        return nativeFetch.apply(this, arguments).then(function(res) {
          try {
            var failed = !res.ok;
            record('fetch', method + ' ' + url + (failed ? ' → ' + res.status : ''), {
              url:     url,
              routine: !failed,
              detail:  {status: res.status, ms: Date.now() - started, ok: !failed}
            });
          } catch (_) {}
          return res;
        }, function(err) {
          try {
            record('fetch',
              method + ' ' + url + ' → network error: ' + String((err && err.message) || err), {
                url:    url,
                detail: {ms: Date.now() - started, ok: false}
              });
          } catch (_) {}
          throw err;
        });
      };
    }
  } catch (_) {}

  // Page lifecycle. pagehide rather than unload: it is the transition modern
  // browsers actually guarantee, including when a tab is frozen on mobile.
  try {
    record('lifecycle', 'page load', {url: location.href, detail: {
      w: (window.screen && window.screen.width) | 0,
      h: (window.screen && window.screen.height) | 0,
      dpr: window.devicePixelRatio || 1
    }});
    window.addEventListener('pagehide', function() { flush(true); });
    document.addEventListener('visibilitychange', function() {
      try {
        record('lifecycle', 'visibility: ' + document.visibilityState, {routine: true});
        if (document.visibilityState === 'hidden') flush(true);
      } catch (_) {}
    });
  } catch (_) {}

  // ── the API the bundle uses ───────────────────────────────────────────────

  window.cloopTelemetry = {
    // record(kind, message, {stack, url, view, detail, now})
    record: record,

    // setView names the screen subsequent events belong to. Called by the tab
    // switcher, which is the one piece of context the reporter cannot observe
    // reliably on its own — the DOM query is a fallback, not a source.
    setView: function(name) {
      try {
        var next = String(name || '');
        if (next === view) return;
        view = next;
        record('view', next);
      } catch (_) {}
    },

    // setRelease tags this session with the hub build that served it, so a
    // trail can be tied to the code that produced it.
    setRelease: function(v) { try { release = String(v || ''); } catch (_) {} },

    flush:   function() { flush(false); },
    session: function() { return session; }
  };
})();
