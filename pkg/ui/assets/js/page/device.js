// The approval page's script (Task 20412), served as an asset of its own: the
// hub's policy runs no inline script and no inline handler (Task 20408), so
// device.html carries markup only and everything it does is wired here.
//
// Every string the hub returns is put on the page with textContent. The host
// name and user agent shown are whatever the terminal chose to send, so they
// are data and nothing else.
(function() {
'use strict';

var $ = function(id) { return document.getElementById(id); };
var current = null;   // the user code being shown, as the hub formatted it
var busy = false;

function setStatus(text, kind) {
  var el = $('status');
  el.textContent = text || '';
  el.className = kind || '';
}

// errorMessage flattens both shapes the hub answers errors in: {"error": "…"}
// and {"error": {"code", "message"}}.
function errorMessage(body, fallback) {
  if (body && typeof body.error === 'string' && body.error) {
    return body.error_description || body.error;
  }
  if (body && body.error && typeof body.error.message === 'string') {
    return body.error.message;
  }
  return fallback;
}

// post sends one JSON request to the hub and resolves {status, body}.
function post(path, payload) {
  return fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify(payload)
  }).then(function(resp) {
    return resp.text().then(function(text) {
      var body = null;
      try { body = text ? JSON.parse(text) : null; } catch (e) { body = null; }
      return { status: resp.status, body: body };
    });
  });
}

function ago(iso) {
  var t = Date.parse(iso || '');
  if (!isFinite(t)) return '';
  var s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return s + ' seconds ago';
  var m = Math.round(s / 60);
  return m + (m === 1 ? ' minute ago' : ' minutes ago');
}

function duration(minutes) {
  if (!minutes) return '';
  if (minutes % 60 === 0) {
    var h = minutes / 60;
    return h + (h === 1 ? ' hour' : ' hours');
  }
  return minutes + ' minutes';
}

function setText(id, text) { $(id).textContent = text || '—'; }

function hideRequest() { $('request').hidden = true; }

function render(v) {
  current = v.user_code;
  var who = v.email || v.name || 'you';
  if (v.name && v.email && v.name !== v.email) who = v.name + ' <' + v.email + '>';

  if (v.status !== 'pending') {
    hideRequest();
    $('code-form').hidden = false;
    switch (v.status) {
    case 'approved':
    case 'consumed':
      if (v.decided_by_you) {
        setStatus('Approved. The terminal is signed in as ' + who + ' — you can close this tab.', 'good');
      } else {
        setStatus('That code has already been used.', 'bad');
      }
      return;
    case 'denied':
      setStatus(v.decided_by_you ? 'Denied. The terminal was told no.' : 'That code has already been used.',
        v.decided_by_you ? '' : 'bad');
      return;
    case 'expired':
      setStatus('That code has expired. Run cloop login again for a new one.', 'bad');
      return;
    }
    setStatus('That code can no longer be approved.', 'bad');
    return;
  }

  setText('who', who);
  setText('shown-code', v.user_code);
  setText('from-ip', v.client_ip);
  setText('your-ip', v.your_ip);
  setText('from-host', v.client_hostname);
  setText('from-agent', v.client_user_agent);
  var when = ago(v.requested_at);
  if (v.expires_in_seconds > 0) {
    var left = Math.max(1, Math.round(v.expires_in_seconds / 60));
    when += (when ? '; ' : '') + 'expires in ' + left + (left === 1 ? ' minute' : ' minutes');
  }
  setText('when', when);
  var life = 'up to ' + duration(v.session_minutes);
  if (v.idle_minutes) life += ', ending after ' + duration(v.idle_minutes) + ' unused';
  setText('lifetime', life);

  var net = $('network-note');
  net.hidden = false;
  if (v.same_address) {
    net.className = 'note ok';
    net.textContent = 'The request came from the same address as this browser.';
  } else {
    net.className = 'note';
    net.textContent = 'The request came from a different address than this browser. That is expected when the ' +
      'terminal runs on another machine — a server, a VM, a container — and is the first thing to check if you ' +
      'did not start it.';
  }
  var re = $('reauth-note');
  if (v.reauth) {
    re.hidden = false;
    re.textContent = 'You signed in to this dashboard ' + (ago(v.signed_in_at) || 'a while ago') +
      ', so approving will ask you to sign in again at your identity provider.';
  } else {
    re.hidden = true;
  }
  $('code-form').hidden = true;
  $('request').hidden = false;
  setStatus('');
  $('approve').focus();
}

function lookup(code) {
  if (busy) return;
  busy = true;
  setStatus('Looking up the code…');
  post('/api/device/lookup', { user_code: code }).then(function(res) {
    busy = false;
    if (res.status === 200 && res.body) {
      render(res.body);
      return;
    }
    hideRequest();
    $('code-form').hidden = false;
    if (res.status === 401) {
      setStatus('Your dashboard session has ended. Reload this page to sign in again.', 'bad');
      return;
    }
    setStatus(errorMessage(res.body, 'The hub could not look that code up.'), 'bad');
  }, function() {
    busy = false;
    setStatus('The hub could not be reached.', 'bad');
  });
}

function approve() {
  if (busy || !current) return;
  busy = true;
  $('approve').disabled = true;
  $('deny').disabled = true;
  setStatus('Approving — your identity provider will confirm it is you…');
  post('/api/device/approve', { user_code: current }).then(function(res) {
    if (res.status === 200 && res.body && /^https?:\/\//i.test(res.body.redirect || '')) {
      // Through the identity provider: its callback completes the approval
      // and sends this browser back here, where the hub says how it went.
      location.assign(res.body.redirect);
      return;
    }
    busy = false;
    $('approve').disabled = false;
    $('deny').disabled = false;
    setStatus(res.status === 401 ? 'Your dashboard session has ended. Reload this page to sign in again.'
      : errorMessage(res.body, 'The hub could not start the approval.'), 'bad');
  }, function() {
    busy = false;
    $('approve').disabled = false;
    $('deny').disabled = false;
    setStatus('The hub could not be reached.', 'bad');
  });
}

function deny() {
  if (busy || !current) return;
  busy = true;
  $('approve').disabled = true;
  $('deny').disabled = true;
  post('/api/device/deny', { user_code: current }).then(function(res) {
    busy = false;
    if (res.status === 200) {
      hideRequest();
      $('code-form').hidden = false;
      $('code').value = '';
      setStatus('Denied. The terminal was told no.');
      return;
    }
    $('approve').disabled = false;
    $('deny').disabled = false;
    setStatus(errorMessage(res.body, 'The hub could not deny the code.'), 'bad');
  }, function() {
    busy = false;
    $('approve').disabled = false;
    $('deny').disabled = false;
    setStatus('The hub could not be reached.', 'bad');
  });
}

function start() {
  $('code-form').addEventListener('submit', function(ev) {
    ev.preventDefault();
    var code = $('code').value.trim();
    if (!code) {
      setStatus('Enter the code your terminal shows.', 'bad');
      return;
    }
    lookup(code);
  });
  $('approve').addEventListener('click', approve);
  $('deny').addEventListener('click', deny);

  // A link from the terminal carries the code; it is looked up, never
  // approved — approving takes a press of the button, after reading the page.
  var code = '';
  try { code = new URLSearchParams(location.search).get('code') || ''; } catch (e) { code = ''; }
  if (code) {
    $('code').value = code;
    lookup(code);
  } else {
    $('code').focus();
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start);
} else {
  start();
}
})();
