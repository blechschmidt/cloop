package apiserver

// originguard.go: a web page must not be able to drive `cloop serve` either
// (Task 20394).
//
// The REST server had the dashboard's gaps and one of its own: it answered
// every origin with Access-Control-Allow-Origin: * and granted every preflight.
// Without a token — the default, on loopback — any page on the Internet could
// therefore read the plan and the artifacts with fetch() and start a run with
// POST /run/start. Now:
//
//   - CORS is granted only to a server with a token, whose requests have to
//     carry it: a tool on another origin the operator handed the token to
//     keeps working; a page that does not have it gets nothing.
//   - A state-changing request must come from the server's own origin or
//     carry a bearer token, and its body must be JSON (pkg/sameorigin, the
//     dashboard's rule).
//   - Without a token, a Host the server does not answer to is refused: DNS
//     rebinding.
//
// X-Forwarded-* are believed from loopback and ui.trusted_proxies only.

import (
	"net/http"
	"strings"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/jsonbody"
	"github.com/blechschmidt/cloop/pkg/sameorigin"
)

// originGuard applies the host, origin and media-type rules.
func (s *Server) originGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		view := sameorigin.ViewOf(r, s.TrustedProxies.TrustsPeer(r))
		if s.Token == "" && !sameorigin.HostAllowed(view.Host, s.AllowedHosts) {
			apierror.WriteError(w, apierror.Newf(apierror.CodeMisdirectedRequest,
				"this server has no token, and it does not answer to the host %q: DNS rebinding points a "+
					"name somebody else controls at a server like this one to make a page there same-origin "+
					"with it. It answers to localhost, IP addresses and the names in ui.allowed_hosts.",
				view.Host))
			return
		}
		if !sameorigin.Unsafe(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		var own []sameorigin.Origin
		if o, ok := view.Origin(); ok {
			own = append(own, o)
		}
		if v := sameorigin.CheckUnsafe(r, own); !v.Allowed {
			apierror.WriteError(w, apierror.Newf(apierror.CodeCrossOrigin,
				"refused: this %s came from a page at %q (Sec-Fetch-Site: %q), not from this server's own "+
					"origin, and it carries no bearer token. A script on another site needs the token "+
					"(Authorization: Bearer).", r.Method, v.Origin, v.FetchSite).WithDetails(map[string]any{
				"reason": string(v.Reason),
			}))
			return
		}
		if ct := strings.TrimSpace(r.Header.Get("Content-Type")); ct != "" && !sameorigin.IsJSON(ct) {
			apierror.WriteError(w, apierror.New(apierror.CodeUnsupportedMediaType, jsonbody.MediaTypeMessage(ct)))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP is the address the rate limiter keys on: the TCP peer, or behind a
// trusted proxy the first address in X-Forwarded-For, read from the right,
// that is not one. It used to be the leftmost entry from any peer, so anybody
// could pick a fresh bucket per request.
func (s *Server) clientIP(r *http.Request) string {
	return s.TrustedProxies.ClientIP(r)
}
