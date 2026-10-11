package ui

// originguard.go: a web page must not be able to drive the hub (Task 20394).
//
// A browser sends a site's cookies with every request to it, whichever page
// asked. Three things followed for the hub, each of which a page anywhere
// could exploit:
//
//   - No route checked where a state-changing request came from, and every
//     handler decoded its body as JSON whatever the Content-Type said. A form
//     with enctype=text/plain on any page reached any mutating route. SameSite
//     stopped it only for a cookie, only across *sites*: another port on the
//     hub's host, or a sibling subdomain of an enterprise domain, got the
//     session cookie sent. And a hub with no credential had none to withhold.
//   - Nothing checked Host, so DNS rebinding — a name the attacker controls,
//     re-pointed at 127.0.0.1 — made a page on attacker.example same-origin
//     with a loopback hub: able to read every API and to queue a task an agent
//     runs with bypassPermissions.
//   - The WebSocket checks admitted every loopback origin and every port of
//     the hub's host name, and judged origins by a scheme any client could
//     choose through X-Forwarded-Proto.
//
// So, in front of everything a browser can reach:
//
//   - hostGuard: on a hub with no sign-in, a Host the hub does not answer to
//     is refused with 421.
//   - forgeryGuard: a state-changing request must come from one of the hub's
//     own pages (sameorigin.CheckUnsafe) unless it carries a bearer token, and
//     its body must be JSON — multipart only on the three upload routes.
//   - wsOriginAllowed: a WebSocket's Origin must be one of the hub's own,
//     scheme, host and port.
//
// "The hub's own" is the origin the browser addressed — its scheme and host,
// as the connection or a trusted proxy says — plus ui.external_url, the SSO
// callback's origin and ui.allowed_origins. X-Forwarded-* are believed from
// loopback and ui.trusted_proxies only (sameorigin.Proxies).

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/exposure"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/jsonbody"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/sameorigin"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// multipartRoutes take a recording, not JSON: the dashboard's and the
// wearable's dictation, and the voice command. They are still subject to the
// origin check; only the media type differs.
var multipartRoutes = map[string]bool{
	"/api/voice":              true,
	"/api/transcribe":         true,
	"/api/glasses/transcribe": true,
}

// crossSiteWritable lists the routes that must accept a state-changing request
// a page on another site made, with the reason. It is empty, and the reason it
// is empty is worth stating: the one route that usually needs to be here — an
// OIDC callback the provider POSTs to with response_mode=form_post — does not
// exist, because the hub asks for the default response mode and the provider
// redirects the browser to the callback with a GET. The CI federation
// endpoints and the executor agents are not browsers and need no entry: a
// client that sends neither Sec-Fetch-Site nor Origin is admitted. A route
// added here is one any page on the Internet can drive.
var crossSiteWritable = map[string]string{}

// forwardedTrusted reports whether r's X-Forwarded-* headers are believed: it
// came from loopback, from an address in ui.trusted_proxies, or from another
// member of this hub's cluster, which signed it.
func (s *Server) forwardedTrusted(r *http.Request) bool {
	if _, ok := peerCallFrom(r); ok {
		return true
	}
	return s.TrustedProxies.TrustsPeer(r)
}

// clientView is the scheme and host the browser used to reach this hub.
func (s *Server) clientView(r *http.Request) sameorigin.View {
	return sameorigin.ViewOf(r, s.forwardedTrusted(r))
}

// requestOrigin is the origin the browser addressed this request to.
func (s *Server) requestOrigin(r *http.Request) (sameorigin.Origin, bool) {
	return s.clientView(r).Origin()
}

// configuredOrigins is what this deployment says its own origins are:
// ui.external_url, the SSO callback's origin, ui.allowed_origins and — for the
// dashboard socket alone — ui.allowed_ws_origins. Entries that do not parse
// match nothing; cmd/ui_cmd.go names them at startup.
func (s *Server) configuredOrigins(dashboardSocket bool) []sameorigin.Origin {
	entries := make([]string, 0, 2+len(s.AllowedOrigins)+len(s.AllowedWSOrigins))
	if ext := strings.TrimSpace(s.ExternalURL); ext != "" {
		entries = append(entries, ext)
	}
	if s.oidcEnabled() {
		// The provider sends browsers back to this URL, so its origin is
		// one people reach the hub at whatever else is configured.
		if cb := strings.TrimSpace(s.OIDC.RedirectURL()); cb != "" {
			entries = append(entries, cb)
		}
	}
	entries = append(entries, s.AllowedOrigins...)
	if dashboardSocket {
		entries = append(entries, s.AllowedWSOrigins...)
	}
	origins, _ := sameorigin.ParseEntries(entries)
	return origins
}

// ownOrigins is every origin a request to r's endpoint may come from: the one
// it was addressed to, and the configured ones.
func (s *Server) ownOrigins(r *http.Request, dashboardSocket bool) []sameorigin.Origin {
	own := s.configuredOrigins(dashboardSocket)
	if o, ok := s.requestOrigin(r); ok {
		own = append(own, o)
	}
	return own
}

// openHub reports a hub with no browser credential — the predicate the bind
// address is decided by (pkg/exposure), asked of this process.
func (s *Server) openHub() bool {
	return !exposure.HasSignIn(s.oidcEnabled(), s.staticTokenConfigured())
}

// answeredHosts is the configured part of an open hub's Host allowlist:
// ui.external_url's host, the advertise hosts of this hub's cluster members,
// and ui.allowed_hosts. Loopback names and IP addresses need no entry
// (sameorigin.HostAllowed).
func (s *Server) answeredHosts() []string {
	names := append([]string(nil), s.AllowedHosts...)
	if u, err := url.Parse(strings.TrimSpace(s.ExternalURL)); err == nil && u.Host != "" {
		names = append(names, u.Hostname())
	}
	if n := s.clusterNode(); n != nil {
		for _, m := range n.Members() {
			if u, err := url.Parse(strings.TrimSpace(m.AdvertiseURL)); err == nil && u.Host != "" {
				names = append(names, u.Host)
			}
		}
	}
	return names
}

// hostGuard refuses, on a hub with no sign-in, a request addressed to a host
// name the hub does not answer to.
//
// DNS rebinding is the attack: a page on attacker.example re-points its own
// name at 127.0.0.1, and from then on the browser considers the open hub on
// this machine the same origin as the page. Every check that asks the browser
// whether a request is same-origin then says yes, truthfully, so the hub has
// to notice the name itself. A hub with SSO or a token needs no such check: the
// rebound name carries none of the hub's cookies, and the page cannot know the
// token.
//
// The probes skip this (buildHandler routes them around it), and so does a
// request another member of the cluster forwarded, which that member checked.
func (s *Server) hostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.openHub() {
			next.ServeHTTP(w, r)
			return
		}
		if _, peer := peerCallFrom(r); peer {
			next.ServeHTTP(w, r)
			return
		}
		host := s.clientView(r).Host
		if sameorigin.HostAllowed(host, s.answeredHosts()) {
			next.ServeHTTP(w, r)
			return
		}
		s.refuseRequest(w, r, requestRefusal{
			action: auditaction.ActionRequestHostRefused,
			reason: sameorigin.ReasonUnknownHost,
			err: apierror.Newf(apierror.CodeMisdirectedRequest,
				"this hub has no sign-in, and it does not answer to the host name %q. DNS rebinding points "+
					"a name somebody else controls at a hub like this one to make a page there same-origin "+
					"with it, so it answers only to localhost, IP addresses, ui.external_url and the names "+
					"in ui.allowed_hosts — add %q to ui.allowed_hosts if this is how you reach it.",
				hostOnly(host), hostOnly(host)).WithDetails(map[string]any{
				"reason":  string(sameorigin.ReasonUnknownHost),
				"host":    host,
				"setting": "ui.allowed_hosts",
			}),
		})
	})
}

// forgeryGuard refuses a state-changing request that a page on another origin
// made, and one whose body is something a form on another origin can send.
//
// Every unsafe request goes through it, on every hub — not only those carrying
// the session cookie. A browser credential is not only a cookie: an
// authenticating proxy's Basic or Kerberos header, or its own cookie, rides
// along just the same; and a hub with no credential has nothing for the
// browser to carry at all. Refusing a page on another origin is right in every
// one of those cases, and costs a non-browser client nothing: it sends neither
// Sec-Fetch-Site nor Origin.
//
// What is exempt, and why:
//   - a bearer token (API tokens, the static token, the CI relay, executor
//     agents): a page on another origin can attach one only after a CORS
//     preflight, and the hub grants none;
//   - a request another cluster member forwarded: that member ran this guard
//     on it and signed what it passed on;
//   - the routes in crossSiteWritable, of which there are none.
func (s *Server) forgeryGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sameorigin.Unsafe(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if _, peer := peerCallFrom(r); peer {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := crossSiteWritable[r.URL.Path]; ok {
			next.ServeHTTP(w, r)
			return
		}
		own := s.ownOrigins(r, false)
		if v := sameorigin.CheckUnsafe(r, own); !v.Allowed {
			s.refuseRequest(w, r, requestRefusal{
				action:  auditaction.ActionRequestOriginRefused,
				reason:  v.Reason,
				verdict: v,
				err:     crossOriginError(r, v, s.requestOriginString(r)),
			})
			return
		}
		if ct := strings.TrimSpace(r.Header.Get("Content-Type")); ct != "" && !s.bodyTypeAccepted(r, ct) {
			var also []string
			if multipartRoutes[r.URL.Path] {
				also = []string{"multipart/form-data"}
			}
			s.refuseRequest(w, r, requestRefusal{
				action: auditaction.ActionRequestOriginRefused,
				reason: sameorigin.ReasonMediaType,
				err: apierror.New(apierror.CodeUnsupportedMediaType, jsonbody.MediaTypeMessage(ct, also...)).
					WithDetails(map[string]any{"reason": string(sameorigin.ReasonMediaType), "content_type": ct}),
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bodyTypeAccepted reports whether a state-changing request may carry a body
// of media type ct: JSON anywhere, multipart form data on the upload routes,
// and whatever the Anthropic API takes on the CI relay, which passes bodies
// through to it unread (and authenticates with a token a browser never holds).
func (s *Server) bodyTypeAccepted(r *http.Request, ct string) bool {
	p := r.URL.Path
	switch {
	case sameorigin.IsJSON(ct):
		return true
	case p == ciMountPath || strings.HasPrefix(p, ciMountPath+"/"):
		return true
	case sameorigin.IsMultipartForm(ct):
		return multipartRoutes[p]
	}
	return false
}

// wsOriginAllowed reports whether a WebSocket handshake's Origin is one of this
// hub's own — scheme, host and port — or absent, which is what every
// non-browser client sends (sameorigin.CheckUpgrade). The executor-agent
// endpoint applies the same rule through remote.Hub.checkOrigin, from the same
// configuration minus ui.allowed_ws_origins.
func (s *Server) wsOriginAllowed(r *http.Request) bool {
	return sameorigin.CheckUpgrade(r, s.ownOrigins(r, true)).Allowed
}

// refuseUpgrade answers a WebSocket handshake whose Origin is not the hub's,
// and records it like any other request a page elsewhere made.
func (s *Server) refuseUpgrade(w http.ResponseWriter, r *http.Request) {
	v := sameorigin.CheckUpgrade(r, s.ownOrigins(r, true))
	s.refuseRequest(w, r, requestRefusal{
		action:  auditaction.ActionRequestOriginRefused,
		reason:  sameorigin.ReasonForeignOrigin,
		verdict: v,
		err: apierror.Newf(apierror.CodeCrossOrigin,
			"refused: this WebSocket was opened by a page at %s, which is not one of this hub's own origins "+
				"(this request was addressed to %s). A page on another origin may not open a socket to the hub; "+
				"if that is this hub's own address behind a proxy, set ui.external_url or add it to "+
				"ui.allowed_origins.", quoted(v.Origin), s.requestOriginString(r)).WithDetails(map[string]any{
			"reason":     string(sameorigin.ReasonForeignOrigin),
			"origin":     v.Origin,
			"own_origin": s.requestOriginString(r),
			"setting":    "ui.allowed_origins",
		}),
	})
}

// recordAgentOriginRefusal counts and records a handshake the executor-agent
// endpoint refused for its Origin. That endpoint writes its own 403 (pkg/
// executor/remote); this is the bookkeeping the dashboard's refusals get.
func (s *Server) recordAgentOriginRefusal(r *http.Request) {
	hubmetrics.CrossOriginRefusals.Inc(string(sameorigin.ReasonForeignOrigin))
	s.recordRefusal(r, requestRefusal{
		action:  auditaction.ActionRequestOriginRefused,
		reason:  sameorigin.ReasonForeignOrigin,
		verdict: sameorigin.CheckUpgrade(r, nil),
	})
}

// requestOriginString renders requestOrigin for a message.
func (s *Server) requestOriginString(r *http.Request) string {
	if o, ok := s.requestOrigin(r); ok {
		return o.String()
	}
	return "an origin the hub cannot determine"
}

// crossOriginError is the 403 a forged request gets: which page asked, what the
// hub calls itself, and the two ways a legitimate caller gets through.
func crossOriginError(r *http.Request, v sameorigin.Verdict, own string) *apierror.APIError {
	var from string
	switch {
	case v.FetchSite != "" && v.Origin != "":
		from = "a page at " + quoted(v.Origin) + " (Sec-Fetch-Site: " + v.FetchSite + ")"
	case v.FetchSite != "":
		from = "a page the browser calls " + v.FetchSite
	default:
		from = "a page at " + quoted(v.Origin)
	}
	return apierror.Newf(apierror.CodeCrossOrigin,
		"refused: this %s came from %s, not from one of this hub's own pages (this request was addressed "+
			"to %s), and it carries no bearer token. The hub takes a state-changing request only from its own "+
			"origin. A script on another site needs an API token (Authorization: Bearer); if that origin is "+
			"this hub's own address behind a proxy that rewrites Host, set ui.external_url or add it to "+
			"ui.allowed_origins.", r.Method, from, own).WithDetails(map[string]any{
		"reason":         string(v.Reason),
		"origin":         v.Origin,
		"sec_fetch_site": v.FetchSite,
		"own_origin":     own,
		"setting":        "ui.allowed_origins",
	})
}

func quoted(s string) string {
	if s == "" {
		return "an unknown origin"
	}
	return `"` + s + `"`
}

func hostOnly(hostport string) string {
	if h, _, err := sameorigin.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// requestRefusal is one request the guards turned away.
type requestRefusal struct {
	action  auditaction.Action
	reason  sameorigin.Reason
	verdict sameorigin.Verdict
	err     *apierror.APIError
}

// refuseRequest answers a refused request, counts it, and records it.
func (s *Server) refuseRequest(w http.ResponseWriter, r *http.Request, f requestRefusal) {
	hubmetrics.CrossOriginRefusals.Inc(string(f.reason))
	s.recordRefusal(r, f)
	apierror.WriteError(w, f.err)
}

// refusalAuditPerMinute bounds the audit rows and log lines refusals write. A
// page can make a browser send requests in a loop, and every refusal that
// opened the control plane's database would let it turn a tab into a write
// load; the metric still counts each one, and the next row written says how
// many were not.
const refusalAuditPerMinute = 30

// refusalLog is the rate limit on recording refusals. The zero value is ready.
type refusalLog struct {
	mu         sync.Mutex
	window     time.Time
	written    int
	suppressed int
}

// admit reports whether a refusal at now may be written, and how many were
// suppressed since the last one that was.
func (l *refusalLog) admit(now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.window) >= time.Minute || now.Before(l.window) {
		l.window, l.written = now, 0
	}
	if l.written >= refusalAuditPerMinute {
		l.suppressed++
		return false, 0
	}
	l.written++
	n := l.suppressed
	l.suppressed = 0
	return true, n
}

// recordRefusal writes the refusal to the hub's own audit chain and its log.
//
// The row records the page that asked, not an identity: the browser belongs to
// whoever was using it, and resolving its session would be work done on the
// attacker's behalf. Whether it carried the session cookie is recorded,
// because that is what says whether the attempt had anything to ride on.
func (s *Server) recordRefusal(r *http.Request, f requestRefusal) {
	ok, suppressed := s.refusals.admit(time.Now())
	if !ok {
		return
	}
	_, cookieErr := r.Cookie(oidcauth.SessionCookieName)
	payload := map[string]any{
		"reason":   string(f.reason),
		"method":   r.Method,
		"path":     r.URL.Path,
		"host":     s.clientView(r).Host,
		"ip":       s.clientIP(r),
		"session":  cookieErr == nil,
		"open_hub": s.openHub(),
	}
	origin := f.verdict.Origin
	if origin == "" {
		origin = strings.TrimSpace(r.Header.Get("Origin"))
	}
	if origin != "" {
		payload["origin"] = truncate(origin, 256)
	}
	if site := f.verdict.FetchSite; site != "" {
		payload["sec_fetch_site"] = truncate(site, 64)
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		payload["content_type"] = truncate(ct, 128)
	}
	if ua := r.UserAgent(); ua != "" {
		payload["user_agent"] = truncate(ua, 256)
	}
	if o, ok := s.requestOrigin(r); ok {
		payload["own_origin"] = o.String()
	}
	if suppressed > 0 {
		payload["suppressed"] = suppressed
	}
	s.log().Warn(logger.EventAuthz, 0, "refused a request a page on another origin made", map[string]interface{}{
		"reason": string(f.reason), "method": r.Method, "path": r.URL.Path, "origin": origin,
		"host": payload["host"], "ip": payload["ip"],
	})

	// The hub's own database only, and only when it exists: a refusal is no
	// reason to create one, and a Server with no WorkDir would otherwise
	// resolve .cloop/state.db against the process's working directory.
	if strings.TrimSpace(s.WorkDir) == "" {
		return
	}
	if _, err := os.Stat(state.DBPath(s.WorkDir)); err != nil {
		return
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		s.log().Warn(logger.EventAuthz, 0, "refusal audit: open control plane", map[string]interface{}{"error": err.Error()})
		return
	}
	defer db.Close()
	actor := "anonymous"
	if origin != "" {
		actor = "page:" + truncate(origin, 200)
	}
	if err := db.AppendAuditEvent(&statedb.AuditEvent{
		Actor:      actor,
		EventType:  string(f.action),
		EntityType: "request",
		EntityID:   r.Method + " " + truncate(r.URL.Path, 200),
		Payload:    statedb.MarshalAuditPayload(payload),
	}); err != nil {
		s.log().Warn(logger.EventAuthz, 0, "refusal audit: append", map[string]interface{}{"error": err.Error()})
	}
}

// writeMultipartError answers a recording upload whose multipart body could
// not be parsed: 413 past the size cap, 415 for a body that is not multipart
// form data at all, 400 for one that is malformed.
func writeMultipartError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		apierror.WriteError(w, apierror.New(apierror.CodePayloadTooLarge, "request body too large"))
	case errors.Is(err, http.ErrNotMultipart):
		apierror.WriteError(w, apierror.New(apierror.CodeUnsupportedMediaType,
			"this endpoint takes the recording as Content-Type: multipart/form-data"))
	default:
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "invalid multipart form: "+err.Error()))
	}
}
