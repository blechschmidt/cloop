// ── Global JavaScript error boundary ─────────────────────────────────────
// Installed BEFORE the main IIFE so that exceptions thrown during script
// initialisation, in async callbacks (timers, fetch handlers), or from
// inline event-handler attributes are all routed through the same
// reporter. Three responsibilities:
//   1. POST {message, stack, url, userAgent, tab} to /api/client-error so
//      the structured server logger captures it alongside server errors.
//   2. Show a non-blocking toast with a Reload button.
//   3. After >3 errors in a 30-second window, escalate to a full-screen
//      recovery banner so the user is not trapped in a loop of broken UI
//      with only an unread toast.
// All branches are individually try/catch-guarded: the boundary itself
// must never throw, otherwise the browser falls back to its default
// (silent) behaviour and the page truly becomes a dead-end.
(function() {
  if (window.__cloopErrBoundaryInstalled) return;
  window.__cloopErrBoundaryInstalled = true;

  var WINDOW_MS  = 30000;
  var THRESHOLD  = 3;
  var POST_LIMIT = 20;        // hard cap on POSTs per page load — defence
                              //   in depth against an infinite-loop bug
                              //   that would otherwise spam the server
  var posted     = 0;
  var recent     = [];        // timestamps of recent errors

  function activeTabName() {
    try {
      var el = document.querySelector('.tab-panel.active');
      if (el && el.id && el.id.indexOf('tab-') === 0) return el.id.slice(4);
    } catch (_) {}
    return '';
  }

  function postError(payload) {
    if (posted >= POST_LIMIT) return;
    posted++;
    try {
      var headers = {'Content-Type': 'application/json'};
      try {
        var t = sessionStorage.getItem('cloop_token');
        if (t) headers['Authorization'] = 'Bearer ' + t;
      } catch (_) {}
      // keepalive lets the request complete even if the user navigates
      // away or reloads immediately after the error fires.
      fetch('/api/client-error', {
        method:  'POST',
        headers: headers,
        body:    JSON.stringify(payload),
        keepalive: true
      }).catch(function() {}); // swallow — boundary must not throw
    } catch (_) {}
  }

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

  function record(payload) {
    try {
      postError(payload);
      var now = Date.now();
      recent.push(now);
      // Drop timestamps outside the rolling window.
      var cutoff = now - WINDOW_MS;
      while (recent.length && recent[0] < cutoff) recent.shift();
      showToast();
      if (recent.length > THRESHOLD) showBanner();
    } catch (_) {}
  }

  window.addEventListener('error', function(ev) {
    try {
      var msg = (ev && (ev.message || (ev.error && ev.error.message))) || 'Unknown error';
      var stack = (ev && ev.error && ev.error.stack) || '';
      record({
        kind:      'error',
        message:   String(msg),
        stack:     String(stack),
        url:       String((ev && ev.filename) || location.href),
        userAgent: navigator.userAgent || '',
        tab:       activeTabName(),
        line:      (ev && ev.lineno) | 0,
        col:       (ev && ev.colno)  | 0
      });
    } catch (_) {}
  });

  window.addEventListener('unhandledrejection', function(ev) {
    try {
      var reason = ev && ev.reason;
      var msg = '';
      var stack = '';
      if (reason && typeof reason === 'object') {
        msg   = reason.message || String(reason);
        stack = reason.stack   || '';
      } else {
        msg = String(reason);
      }
      record({
        kind:      'unhandledrejection',
        message:   msg,
        stack:     String(stack),
        url:       location.href,
        userAgent: navigator.userAgent || '',
        tab:       activeTabName()
      });
    } catch (_) {}
  });
})();
