// ── Confirm it's you (Task 20448) ───────────────────────────────────────────
//
// A privileged action — creating a secret, minting a token, attaching to a
// sandbox — asked of a session whose owner last signed in longer ago than the
// hub allows is refused with 401 REAUTH_REQUIRED (X-Cloop-Reauth). This dialog
// answers it: it explains, sends the person to their identity provider in a
// window of its own (prompt=login, max_age=0), and when that window says the
// sign-in counted, replays the refused request from here — so nothing typed
// into the page is lost. Where the browser will not open a window, the tab
// itself goes and comes back to the same view, and asks for the button once
// more.
//
// Fetched on the first refusal rather than bundled (static.go,
// deferredScripts): first paint had 887 B to spare. It runs outside the
// dashboard's IIFE, so it is handed the helpers it calls, and the only name it
// puts on window is the factory.
(function () {
  'use strict';

  window.cloopReauthPanel = function (h) {
    const {toast} = h;
    const {openOverlay, closeOverlay} = window;
    const el = id => document.getElementById(id);
    // The refused requests waiting on this dialog: each replays once the
    // person has signed in again, or is rejected when they cancel.
    let waiters = [];
    let chan = null;
    let url = '/auth/login?reauth=window';
    // The nonce of the sign-in window this dialog last opened. The hub echoes
    // it in the window's verdict, and only a verdict naming it replays
    // anything: a result some other sign-in produced in this browser — one
    // somebody else started and lured it through — must not send what was
    // typed here under whoever that was.
    let nonce = '';

    // span renders a window of seconds as a person says it.
    function span(s) {
      if (!(s > 0)) return 'a little while';
      if (s % 3600 === 0) return s === 3600 ? 'hour' : s / 3600 + ' hours';
      const m = Math.max(1, Math.round(s / 60));
      return m === 1 ? 'minute' : m + ' minutes';
    }

    function status(text, bad) {
      const s = el('ra-status');
      s.textContent = text || '';
      s.style.color = bad ? 'var(--red)' : '';
    }

    // ask is what the bundle's 401 handler calls: err is the refusal's error
    // object, retry replays the request (absent when it cannot be replayed).
    function ask(err, retry) {
      const d = (err && err.details) || {};
      if (d.reauth_url) url = d.reauth_url;
      return new Promise((resolve, reject) => {
        waiters.push({retry, resolve, reject});
        if (waiters.length > 1) return;
        el('ra-window').textContent = span(+d.max_age_seconds);
        el('ra-go').textContent = 'Sign in again';
        status('');
        openOverlay('ra-overlay', {dismiss: cancel, focus: '#ra-go'});
      });
    }

    // listen hears the sign-in window's verdict: on a BroadcastChannel, which
    // reaches this tab whatever the provider's pages did to the window's
    // opener, and as a message from the window itself where it still can.
    function listen() {
      if (!chan && window.BroadcastChannel) {
        chan = new BroadcastChannel('cloop-reauth');
        chan.onmessage = e => verdict(e.data);
      }
    }
    window.addEventListener('message', e => {
      if (e.origin === location.origin) verdict(e.data);
    });

    function verdict(m) {
      if (!m || m.type !== 'cloop.oidc.reauth' || !waiters.length || !nonce || m.nonce !== nonce) return;
      if (m.outcome !== 'granted') {
        status(m.message || 'That sign-in did not confirm it is you. Try again.', true);
        el('ra-go').textContent = 'Try again';
        return;
      }
      const all = waiters;
      waiters = [];
      closeOverlay('ra-overlay');
      toast('Confirmed — it is you', 'ok');
      all.forEach(w => w.retry
        ? Promise.resolve().then(w.retry).then(w.resolve, w.reject)
        : w.reject(new Error('Confirmed — press it once more to finish')));
    }

    function go() {
      listen();
      nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
      const w = window.open(url + (url.includes('?') ? '&' : '?') + 'n=' + nonce, 'cloopReauth', 'popup,width=520,height=680');
      if (!w) {
        // No window: this tab goes, and comes back to the same view.
        status('Opening your identity provider…');
        h.signIn();
        return;
      }
      el('ra-go').textContent = 'Open the sign-in window again';
      status('Waiting for you to sign in, in the window that opened…');
    }

    function cancel() {
      const all = waiters;
      waiters = [];
      closeOverlay('ra-overlay');
      all.forEach(w => w.reject(new Error('Not done: this needs you to confirm it is you')));
    }

    return h.mount({ask, go, cancel}, null, null, `
<div id="ra-overlay" class="modal-backdrop" data-overlay="flex" data-dismiss="cancel" style="z-index:300">
  <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="ra-title" aria-describedby="ra-text" style="width:420px">
    <div class="modal-header"><h2 id="ra-title">Confirm it's you</h2></div>
    <p id="ra-text">This action needs a sign-in from the last <span id="ra-window">2 hours</span>.
      Your identity provider will ask you to sign in again; what you were doing here stays as it is.</p>
    <p id="ra-status" class="form-hint" role="status" aria-live="polite"></p>
    <div class="modal-footer">
      <button class="btn" data-act="cancel">Cancel</button>
      <button class="btn primary" id="ra-go" data-act="go">Sign in again</button>
    </div>
  </div>
</div>`);
  };
})();
