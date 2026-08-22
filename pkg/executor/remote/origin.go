package remote

// origin.go decides which WebSocket upgrades the hub will accept based on the
// browser-supplied Origin header.
//
// The header exists for exactly one purpose: a browser sets it, and cannot be
// made not to. So it separates two populations that otherwise look identical
// on the wire:
//
//   - A real agent (Go, Python, anything non-browser) sends no Origin at all.
//     Refusing those would refuse every legitimate device.
//   - A page in a browser sends one it cannot forge. If a logged-in operator
//     visits evil.example, script on that page can open a WebSocket to the
//     hub, and the browser will attach whatever ambient credentials the hub's
//     origin has — cookies from the dashboard session on the same host. The
//     hub's own auth is a bearer token, which script cannot read; but the
//     upgrade still happens, still consumes a connection slot, and — before
//     the check moved ahead of Redeem — could burn a single-use enrollment
//     token supplied in the ?token= query parameter, which *is* readable from
//     a link the operator was tricked into loading.
//
// So: absent Origin is allowed, present-and-unrecognised is refused. That is
// the same posture as pkg/ui's wsOriginAllowed, and the two must not drift —
// the hub is mounted inside the same server, on the same host, behind the same
// proxy.

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// originDecision is the result of the check, carrying the operator-facing
// reason so the 403 body and the server log say the same thing.
type originDecision struct {
	allowed bool
	reason  string
}

// checkOrigin applies the hub's origin policy to a request.
//
// Allowed:
//   - no Origin header (a headless agent — the normal case);
//   - loopback origins (a developer's browser or a local test);
//   - same-origin: the Origin host equals the request's Host, meaning the
//     page and the socket came from this same server;
//   - the host of the configured ExternalURL, which is what the deployment
//     calls itself even when a reverse proxy rewrites Host;
//   - any entry in AllowedOrigins, matched as a full origin ("https://a.b"),
//     a host:port, or a bare host.
//
// Everything else is refused. Note that ExternalURL and AllowedOrigins are
// matched on host only, not scheme: an operator who has configured
// https://hub.example.com should not have a cross-origin page at
// http://hub.example.com treated as a stranger — it is the same deployment
// mid-migration, and TLS is enforced by HSTS and by the agent's own transport
// policy rather than by this check.
func (h *Hub) checkOrigin(r *http.Request) originDecision {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return originDecision{allowed: true, reason: "no Origin header (non-browser client)"}
	}

	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return originDecision{false, fmt.Sprintf("Origin %q is not a valid URL", origin)}
	}
	originHost := u.Hostname()

	if isLoopbackHostname(originHost) {
		return originDecision{true, "loopback origin"}
	}

	// Same-origin: the page that opened this socket was served by this very
	// server, so it is inherently as trusted as the server itself.
	if r.Host != "" {
		if strings.EqualFold(u.Host, r.Host) {
			return originDecision{true, "same-origin"}
		}
		reqHost := r.Host
		if h, _, splitErr := net.SplitHostPort(reqHost); splitErr == nil {
			reqHost = h
		}
		if strings.EqualFold(originHost, reqHost) {
			return originDecision{true, "same-origin (host match)"}
		}
	}

	for _, allowed := range h.allowedOriginHosts() {
		if strings.EqualFold(allowed, u.Host) || strings.EqualFold(allowed, originHost) {
			return originDecision{true, "configured allowed origin"}
		}
	}

	return originDecision{false, fmt.Sprintf(
		"Origin %q is not permitted; add it to ui.allowed_origins or set ui.external_url", origin)}
}

// allowedOriginHosts is the effective allowlist: the configured external URL's
// host plus every AllowedOrigins entry, normalised to a host or host:port so a
// full URL and a bare hostname both work in config.
func (h *Hub) allowedOriginHosts() []string {
	out := make([]string, 0, len(h.opts.AllowedOrigins)+1)
	if ext := strings.TrimSpace(h.opts.ExternalURL); ext != "" {
		if host := originHostOf(ext); host != "" {
			out = append(out, host)
		}
	}
	for _, a := range h.opts.AllowedOrigins {
		if host := originHostOf(a); host != "" {
			out = append(out, host)
		}
	}
	return out
}

// originHostOf normalises a config entry into a host or host:port. Accepts
// "https://a.b", "a.b:443" and "a.b" alike, because operators write all three
// and rejecting two of them is a support ticket, not a security control.
func originHostOf(s string) string {
	v := strings.TrimSpace(s)
	if v == "" {
		return ""
	}
	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil && u.Host != "" {
			return u.Host
		}
		return ""
	}
	return strings.TrimSuffix(v, "/")
}

// isLoopbackHostname delegates to tlsconf so the hub, the dashboard and the
// agent all answer "is this loopback" identically.
//
// An earlier version of this file carried its own copy, to spare
// pkg/executor/remote a dependency. The copies drifted within one change —
// this one accepted *.localhost, 127.0.0.0/8 and IPv4-mapped forms while
// pkg/ui's accepted three exact strings, so the same Origin was refused by the
// dashboard socket and accepted by the agent endpoint on the same server. The
// dependency is free anyway: the agent binary already links tlsconf.
func isLoopbackHostname(host string) bool { return tlsconf.IsLoopbackHost(host) }
