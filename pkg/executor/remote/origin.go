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
// So: absent Origin is allowed; present, it must be one of the hub's own
// origins exactly — scheme, host and port (Task 20394). That is the same
// posture as pkg/ui's wsOriginAllowed, and the two cannot drift: both ask
// pkg/sameorigin. Loopback is no longer admitted wholesale, and neither is
// every port of the hub's host name: a page on http://localhost:3000, or on
// another port of the hub's host, is another origin.

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/blechschmidt/cloop/pkg/sameorigin"
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
//   - an Origin equal to the one the request was addressed to: the scheme and
//     host the connection — or, from a trusted proxy (HubOptions.ForwardedTrusted),
//     X-Forwarded-Proto and X-Forwarded-Host — report;
//   - the origin of the configured ExternalURL, which is what the deployment
//     calls itself even when a reverse proxy rewrites Host;
//   - an AllowedOrigins entry: a full origin, or host[:port] meaning https.
//
// Everything else is refused, scheme mismatches included: an http page on the
// hub's host name is one anybody on the network path can serve.
func (h *Hub) checkOrigin(r *http.Request) originDecision {
	own, addressed := h.ownOrigins(r)
	v := sameorigin.CheckUpgrade(r, own)
	if v.Allowed {
		return originDecision{allowed: true, reason: string(v.Reason)}
	}
	if h.opts.OnOriginRefused != nil {
		h.opts.OnOriginRefused(r)
	}
	return originDecision{false, fmt.Sprintf(
		"Origin %q is not one of this hub's own origins (this request was addressed to %s); "+
			"if that is the hub's own address behind a proxy, add it to ui.allowed_origins or set ui.external_url",
		strings.TrimSpace(r.Header.Get("Origin")), addressed)}
}

// ownOrigins is every origin the hub accepts a browser's socket from, and the
// one r was addressed to, rendered for a message.
func (h *Hub) ownOrigins(r *http.Request) ([]sameorigin.Origin, string) {
	entries := append([]string{h.opts.ExternalURL}, h.opts.AllowedOrigins...)
	own, _ := sameorigin.ParseEntries(entries)
	trusted := false
	if h.opts.ForwardedTrusted != nil {
		trusted = h.opts.ForwardedTrusted(r)
	} else {
		trusted = sameorigin.Proxies{}.TrustsPeer(r)
	}
	addressed := "an origin the hub cannot determine"
	if o, ok := sameorigin.ViewOf(r, trusted).Origin(); ok {
		own = append(own, o)
		addressed = o.String()
	}
	return own, addressed
}
