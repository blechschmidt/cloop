package oidcauth

// The sign-in documents' script (Task 20408).
//
// Two documents this package writes need script: the landing page a browser
// sees straight after signing in, which moves on to the dashboard with
// location.replace, and the renewal result, which posts its verdict to the
// dashboard that framed it. Both used to carry it inline, with the values
// spliced into string literals. The hub's policy runs no inline script now
// (script-src 'self'), so each document carries its values in markup — the
// landing page in its Continue link, the renewal result in a data attribute
// on its root element — and loads this one same-origin script, which reads
// them as data. Nothing is ever interpolated into JavaScript, so there is no
// grammar left for a value to escape.
//
// It is served from under /auth/, the subtree a hub with single sign-on
// answers without a session: the renewal frame's callback leg carries no
// cookie, and neither document should depend on one to finish.

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

// ScriptPath is where the sign-in documents' script is served. The hub
// registers it as a route beside LoginPath and RenewPath, and the callback
// rule refuses it for the same reason it refuses them.
const ScriptPath = "/auth/sign-in.js"

// signInScript is the whole of the script. Kept to what the two documents
// need: a postMessage from the renewal result, addressed to "/" — the
// sender's own origin, as renewResultHTML explains — and the landing page's
// move to the destination its Continue link names.
const signInScript = `(function () {
  'use strict';
  var msg = document.documentElement.getAttribute('data-renew');
  if (msg !== null) {
    try { parent.postMessage(JSON.parse(msg), '/'); } catch (e) {}
    return;
  }
  var next = document.getElementById('continue');
  if (next) location.replace(next.getAttribute('href'));
})();
`

// signInScriptETag validates the script. It changes only with a build, so a
// browser revalidates it cheaply rather than caching a stale copy forever.
var signInScriptETag = func() string {
	sum := sha256.Sum256([]byte(signInScript))
	return `"` + hex.EncodeToString(sum[:8]) + `"`
}()

// ServeScript serves the sign-in documents' script. It needs no authenticator
// — the script is the same on every hub — so it works, and is harmless, on a
// hub without single sign-on too.
func ServeScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", signInScriptETag)
	if r.Header.Get("If-None-Match") == signInScriptETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(signInScript))
}
