package ui

// Terminal sign-in: the hub side of `cloop login` (Task 20412).
//
//	POST /api/device/code      a terminal asks for a code     unauthenticated
//	POST /api/device/token     the terminal polls             unauthenticated
//	GET  /device               the approval page              a browser session
//	POST /api/device/lookup    what is this code              a browser session
//	POST /api/device/approve   approve it                     a browser session
//	POST /api/device/deny      deny it                        a browser session
//
// The grant itself — codes, the approval's round trip through the identity
// provider, the session it writes — is pkg/oidcauth's (device.go). This file
// is HTTP: the two endpoints a terminal reaches before it holds any credential,
// the three a signed-in browser uses to decide, and the document it decides on.
//
// # Why two routes are open, and what holds them
//
// A terminal asking for a code has nothing to authenticate with: that is what
// it is asking for. So the code and token endpoints are served before
// authentication (servedBeforeAuth) and declare authz.PermPublic. What bounds
// them instead: issuing is limited per client address and hub-wide, a code is
// worth nothing until a signed-in person approves it, and polling is held to
// the interval by slow_down. Neither answers anything about anybody: the token
// endpoint tells the holder of a device code — 256 random bits — about that
// code alone, and hands out no credential even once it is approved.
//
// # Why the browser routes are public too, and why that is not open
//
// The three decision routes declare PermPublic for the reason
// /api/session/logout-all does: approving signs the caller's own terminal in
// as the caller, so there is no role it could exceed and nobody else it could
// act for. They are not served before authentication — oidcGate has run — and
// oidcauth then insists on the one credential it will take: a browser's
// session cookie. A terminal session approving another terminal would be a
// credential that copies itself, and an API token approving one would mint a
// session with no person behind it.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

const (
	// deviceCodePath and deviceTokenPath are the two endpoints a terminal
	// reaches before it holds a credential.
	deviceCodePath  = "/api/device/code"
	deviceTokenPath = "/api/device/token"

	// deviceCodesPerAddress is how many codes one client address (an IPv6
	// one by its /64: deviceRateKey) may ask for per deviceCodeWindow. `cloop login` asks for one per attempt; a dozen
	// covers a developer retrying and a NAT shared by a team, and is far
	// short of what flooding the approval page with codes would take.
	deviceCodesPerAddress = 12
	deviceCodeWindow      = 10 * time.Minute

	// deviceMissesPerCaller is how many codes one browser session (or, for
	// a request with none, one address) may look up and miss per
	// deviceMissWindow. A real person mistypes a code a few times; enumerating
	// live codes — 2^43 of them — needs billions of guesses, and this keeps it
	// at a dozen an hour.
	deviceMissesPerCaller = 12
	deviceMissWindow      = time.Hour

	// deviceLimiterMaxKeys bounds each limiter's table, as uiAuthFailsMaxEntries
	// bounds the auth-failure one: a flood of distinct keys evicts the oldest
	// rather than growing the process.
	deviceLimiterMaxKeys = 10000
)

// isDeviceGrantEndpoint reports whether r is one of the two requests a
// terminal makes before it holds a credential — exact paths, POST only. See
// servedBeforeAuth.
func isDeviceGrantEndpoint(r *http.Request) bool {
	return r.Method == http.MethodPost && (r.URL.Path == deviceCodePath || r.URL.Path == deviceTokenPath)
}

// deviceRoutes are the routes of this file, spliced into routeTable.
func (s *Server) deviceRoutes() []routeSpec {
	public := authz.PermPublic
	return []routeSpec{
		// The terminal's two: unauthenticated by necessity, bounded as the
		// file comment says, and served before authentication
		// (isDeviceGrantEndpoint) so a hub with single sign-on does not
		// answer a terminal that has no session yet with a login redirect.
		{Pattern: "POST " + deviceCodePath, Handler: s.handleDeviceCode, Perm: public, Scope: scopeGlobal},
		{Pattern: "POST " + deviceTokenPath, Handler: s.handleDeviceToken, Perm: public, Scope: scopeGlobal},
		// The approval page. A document, like "/" and /glasses: whether this
		// caller may load anything was decided by authMiddleware, which sends
		// a browser with no session through sign-in and back here, and
		// everything the page shows comes from the routes below.
		{Pattern: "GET " + oidcauth.DevicePath, Handler: s.handleDevicePage, Perm: public},
		// Deciding a code. Self-scoped by construction — see the file
		// comment — and refused by oidcauth to anything but a browser session.
		{Pattern: "POST /api/device/lookup", Handler: s.handleDeviceLookup, Perm: public, Scope: scopeGlobal},
		{Pattern: "POST /api/device/approve", Handler: s.handleDeviceApprove, Perm: public, Scope: scopeGlobal},
		{Pattern: "POST /api/device/deny", Handler: s.handleDeviceDeny, Perm: public, Scope: scopeGlobal},
	}
}

// deviceLoginAvailable reports whether this hub signs terminals in, and
// answers when it does not.
func (s *Server) deviceLoginAvailable(w http.ResponseWriter) bool {
	switch {
	case !s.oidcEnabled():
		deviceError(w, http.StatusNotFound, "unsupported_grant_type",
			"this hub has no single sign-on, so there is no terminal sign-in to complete: authenticate with an "+
				"API token instead (cloop hub token create, or Settings → API tokens), passed as --token or CLOOP_API_TOKEN")
		return false
	case !s.OIDC.DeviceLoginEnabled():
		deviceError(w, http.StatusNotFound, "unsupported_grant_type",
			"terminal sign-in is turned off on this hub (ui.oidc.device_login: false)")
		return false
	}
	return true
}

// handleDeviceCode issues a code: RFC 8628 §3.1–3.2, with a JSON body like
// every state-changing request the hub takes (Task 20394).
func (s *Server) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	if !s.deviceLoginAvailable(w) {
		return
	}
	ip := s.clientIP(r)
	if ok, retry := s.deviceCodes.allow(deviceRateKey(ip), deviceCodesPerAddress, deviceCodeWindow, time.Now()); !ok {
		w.Header().Set("Retry-After", retryAfterSeconds(retry))
		deviceError(w, http.StatusTooManyRequests, "slow_down",
			"too many sign-in codes were requested from this address; wait "+retry.Round(time.Second).String()+" and try again")
		return
	}
	var req struct {
		// CredentialHash is the SHA-256 of the session credential the terminal
		// generated and keeps: the approval writes the session under an id
		// derived from it (oidcauth.CLISessionID).
		CredentialHash string `json:"credential_hash"`
		// Hostname is what the terminal calls its machine, for the approval
		// page. A label, never an input to a decision.
		Hostname string `json:"hostname"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	grant, err := s.OIDC.BeginDeviceAuthorization(oidcauth.DeviceRequest{
		CredentialHash: req.CredentialHash,
		Hostname:       req.Hostname,
		// The address the hub believes — the TCP peer, or a trusted proxy's
		// account of it — and never the leftmost X-Forwarded-For anyone can
		// write. The approval page sets it beside the browser's own, and a
		// spoofable one would let a phisher make their request look local.
		IP:        ip,
		UserAgent: r.UserAgent(),
	})
	switch {
	case errors.Is(err, oidcauth.ErrDeviceRequestInvalid):
		deviceError(w, http.StatusBadRequest, "invalid_request", strings.TrimPrefix(err.Error(), "oidcauth: "))
		return
	case errors.Is(err, oidcauth.ErrDeviceBusy):
		w.Header().Set("Retry-After", "60")
		deviceError(w, http.StatusServiceUnavailable, "temporarily_unavailable", strings.TrimPrefix(err.Error(), "oidcauth: "))
		return
	case err != nil:
		s.log().Error(logger.EventAuthz, 0, "device authorization: issue a code",
			map[string]interface{}{"error": err.Error()})
		deviceError(w, http.StatusInternalServerError, "server_error", "the hub could not issue a sign-in code")
		return
	}
	verify := s.deviceVerificationURI(r)
	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, map[string]any{
		"device_code":               grant.DeviceCode,
		"user_code":                 grant.UserCode,
		"verification_uri":          verify,
		"verification_uri_complete": verify + "?code=" + url.QueryEscape(grant.UserCode),
		"expires_in":                int(grant.ExpiresIn / time.Second),
		"interval":                  int(grant.Interval / time.Second),
	})
}

// deviceVerificationURI is where a person approves a code: the approval page
// at the address browsers sign in to this hub at. ui.external_url when it is
// set, then the single sign-on callback's origin — the provider sends browsers
// there, so it is reachable from wherever people sign in — and only then the
// address this request used, which for a terminal behind a tunnel may be one
// no browser can reach.
func (s *Server) deviceVerificationURI(r *http.Request) string {
	if ext := strings.TrimSpace(s.ExternalURL); ext != "" {
		return strings.TrimSuffix(ext, "/") + oidcauth.DevicePath
	}
	if u, err := url.Parse(strings.TrimSpace(s.OIDC.RedirectURL())); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host + oidcauth.DevicePath
	}
	return s.externalBaseURL(r) + oidcauth.DevicePath
}

// handleDeviceToken is one poll: RFC 8628 §3.4–3.5. Success carries no
// credential — see oidcauth.DeviceSession — and is otherwise an OAuth error
// body with a 400.
func (s *Server) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	if !s.deviceLoginAvailable(w) {
		return
	}
	var req struct {
		GrantType  string `json:"grant_type"`
		DeviceCode string `json:"device_code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if req.GrantType != "" && req.GrantType != oidcauth.DeviceGrantType {
		deviceError(w, http.StatusBadRequest, "unsupported_grant_type",
			"this endpoint takes grant_type "+oidcauth.DeviceGrantType)
		return
	}
	sess, err := s.OIDC.ExchangeDeviceCode(req.DeviceCode)
	var te *oidcauth.DeviceTokenError
	switch {
	case errors.As(err, &te):
		body := map[string]any{"error": te.Code, "error_description": te.Description}
		if te.Interval > 0 {
			body["interval"] = int(te.Interval / time.Second)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(body)
		return
	case err != nil:
		s.log().Error(logger.EventAuthz, 0, "device authorization: poll",
			map[string]interface{}{"error": err.Error()})
		deviceError(w, http.StatusInternalServerError, "server_error", "the hub could not answer the poll")
		return
	}
	body := map[string]any{
		// No access_token: the terminal has held its credential since it
		// asked for the code, and session_id — the id its commitment names
		// (oidcauth.CLISessionID) — is what lets it check this is the
		// session it committed to.
		"token_type":  "Bearer",
		"session_id":  sess.SessionID,
		"expires_in":  int(sess.ExpiresIn / time.Second),
		"revalidated": sess.Revalidated,
		"identity": map[string]string{
			"sub":   sess.Identity.Sub,
			"email": sess.Identity.Email,
			"name":  sess.Identity.Name,
		},
	}
	if sess.IdleTimeout > 0 {
		body["idle_timeout"] = int(sess.IdleTimeout / time.Second)
	}
	jsonOK(w, body)
}

// handleDevicePage serves the approval page: a document of its own with its
// own script, not a dashboard tab, so it costs the dashboard's first paint
// nothing and carries no script but its own.
func (s *Server) handleDevicePage(w http.ResponseWriter, r *http.Request) {
	if !s.oidcEnabled() || !s.OIDC.DeviceLoginEnabled() {
		http.NotFound(w, r)
		return
	}
	writeAsset(w, r, loadAssets().device)
}

// deviceLookupView is the approval page's view of one code. Strings are set as
// text by the page's script, never as markup.
type deviceLookupView struct {
	UserCode string `json:"user_code"`
	// Status is pending, approved, denied, consumed or expired.
	Status       string `json:"status"`
	DecidedByYou bool   `json:"decided_by_you"`

	ClientIP        string `json:"client_ip,omitempty"`
	ClientUserAgent string `json:"client_user_agent,omitempty"`
	ClientHostname  string `json:"client_hostname,omitempty"`
	// YourIP is the browser's own address as the hub sees it, and
	// SameAddress whether the request came from it — the one detail on the
	// page a phisher cannot choose.
	YourIP      string `json:"your_ip,omitempty"`
	SameAddress bool   `json:"same_address"`

	RequestedAt      string `json:"requested_at,omitempty"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
	DecidedAt        string `json:"decided_at,omitempty"`

	// Reauth: approving asks for a fresh sign-in at the identity provider.
	Reauth        bool   `json:"reauth"`
	SignedInAt    string `json:"signed_in_at,omitempty"`
	ReauthMinutes int64  `json:"reauth_after_minutes,omitempty"`

	// Who approving signs the terminal in as: the caller.
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`

	// SessionMinutes and IdleMinutes are the clocks the terminal's session
	// will run on, so the page can say what is being granted and for how long.
	SessionMinutes int64 `json:"session_minutes"`
	IdleMinutes    int64 `json:"idle_minutes,omitempty"`
}

// handleDeviceLookup tells the approval page about a code.
func (s *Server) handleDeviceLookup(w http.ResponseWriter, r *http.Request) {
	code, ok := s.decodeDeviceCode(w, r)
	if !ok {
		return
	}
	v, err := s.OIDC.LookupDevice(r, code)
	if err != nil {
		s.writeDeviceDecisionError(w, r, err)
		return
	}
	status := string(v.Status)
	if v.Expired {
		status = "expired"
	}
	out := deviceLookupView{
		UserCode:     v.UserCode,
		Status:       status,
		DecidedByYou: v.DecidedByCaller,

		ClientIP:        v.ClientIP,
		ClientUserAgent: v.ClientUserAgent,
		ClientHostname:  v.ClientHostname,
		YourIP:          s.clientIP(r),

		Reauth: v.Reauth,
		Email:  v.Identity.Email,
		Name:   v.Identity.Name,

		SessionMinutes: int64(s.OIDC.CLISessionTTL() / time.Minute),
	}
	out.SameAddress = out.ClientIP != "" && out.ClientIP == out.YourIP
	if v.Status == oidcauth.DeviceStatusPending && !v.Expired {
		out.RequestedAt = formatSessionTime(v.CreatedAt)
		out.ExpiresInSeconds = int64(v.ExpiresIn / time.Second)
	}
	if !v.DecidedAt.IsZero() {
		out.DecidedAt = formatSessionTime(v.DecidedAt)
	}
	if !v.SignedInAt.IsZero() {
		out.SignedInAt = formatSessionTime(v.SignedInAt)
	}
	if age := s.OIDC.DeviceApprovalMaxAge(); age > 0 {
		out.ReauthMinutes = int64(age / time.Minute)
	}
	if idle := s.OIDC.CLIIdleTimeout(); idle > 0 {
		out.IdleMinutes = int64(idle / time.Minute)
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, out)
}

// handleDeviceApprove starts approving a code. The answer is where to send
// the browser: through the identity provider, whose callback completes the
// approval and returns to the page.
func (s *Server) handleDeviceApprove(w http.ResponseWriter, r *http.Request) {
	code, ok := s.decodeDeviceCode(w, r)
	if !ok {
		return
	}
	approval, err := s.OIDC.BeginDeviceApproval(r.Context(), r, code)
	if err != nil {
		s.writeDeviceDecisionError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, map[string]any{"redirect": approval.RedirectURL, "reauth": approval.Reauth})
}

// handleDeviceDeny refuses a code.
func (s *Server) handleDeviceDeny(w http.ResponseWriter, r *http.Request) {
	code, ok := s.decodeDeviceCode(w, r)
	if !ok {
		return
	}
	if err := s.OIDC.DenyDevice(r, code); err != nil {
		s.writeDeviceDecisionError(w, r, err)
		return
	}
	jsonOK(w, map[string]any{"ok": true, "status": string(oidcauth.DeviceStatusDenied)})
}

// decodeDeviceCode reads the user code a decision route was given, refusing
// a caller who has missed too many already.
func (s *Server) decodeDeviceCode(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !s.oidcEnabled() || !s.OIDC.DeviceLoginEnabled() {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "terminal sign-in is not enabled on this hub"))
		return "", false
	}
	if retry, limited := s.deviceMisses.limited(s.deviceCaller(r), deviceMissesPerCaller, deviceMissWindow, time.Now()); limited {
		w.Header().Set("Retry-After", retryAfterSeconds(retry))
		apierror.WriteError(w, apierror.Newf(apierror.CodeRateLimited,
			"too many codes that do not exist were entered from this session; wait %s and try again",
			retry.Round(time.Minute)))
		return "", false
	}
	var req struct {
		UserCode string `json:"user_code"`
	}
	if !decodeJSON(w, r, &req) {
		return "", false
	}
	return req.UserCode, true
}

// deviceCaller keys the miss limiter: the browser session when there is one,
// so a team behind one NAT does not share a budget, and the address otherwise.
func (s *Server) deviceCaller(r *http.Request) string {
	if c, err := r.Cookie(oidcauth.SessionCookieName); err == nil && c.Value != "" {
		return "session:" + oidcauth.HashSessionID(c.Value)
	}
	return "ip:" + deviceRateKey(s.clientIP(r))
}

// deviceRateKey is the address a per-address limit counts under: an IPv4
// address as itself, an IPv6 one by its /64. A host is routinely handed a
// whole /64, and keyed by the full address it could walk through billions of
// fresh budgets without ever looking like anybody else.
func deviceRateKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.WithZone("").Prefix(64)
	if err != nil {
		return ip
	}
	return prefix.String()
}

// writeDeviceDecisionError answers a decision route's refusal, counting a
// miss against the caller.
func (s *Server) writeDeviceDecisionError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, oidcauth.ErrDeviceNotFound):
		s.deviceMisses.note(s.deviceCaller(r), deviceMissWindow, time.Now())
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound,
			"no sign-in is waiting for that code — check it against your terminal; codes expire after ten minutes"))
	case errors.Is(err, oidcauth.ErrNeedsBrowserSession):
		apierror.WriteError(w, apierror.New(apierror.CodeForbidden, strings.TrimPrefix(err.Error(), "oidcauth: ")))
	case errors.Is(err, oidcauth.ErrDeviceExpired):
		apierror.WriteError(w, apierror.New(apierror.CodeConflict, strings.TrimPrefix(err.Error(), "oidcauth: ")).
			WithDetails(map[string]any{"status": "expired"}))
	case errors.Is(err, oidcauth.ErrDeviceDecided):
		apierror.WriteError(w, apierror.New(apierror.CodeConflict, strings.TrimPrefix(err.Error(), "oidcauth: ")).
			WithDetails(map[string]any{"status": "decided"}))
	case errors.Is(err, oidcauth.ErrDeviceLoginDisabled):
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, strings.TrimPrefix(err.Error(), "oidcauth: ")))
	default:
		s.log().Error(logger.EventAuthz, 0, "device authorization: decide",
			map[string]interface{}{"error": err.Error()})
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable,
			"the hub could not reach the identity provider or its own database; try again"))
	}
}

// deviceError writes an OAuth-shaped error (RFC 6749 §5.2), the dialect a
// device-flow client reads: a code in "error" and prose in
// "error_description".
func deviceError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}

// cliSessionGate is oidcauth.Config.SessionGate: a terminal session is not
// written for an identity a runtime deny binding names hub-wide — which is
// what offboarding writes — so an account on its way out cannot start one with
// an approval it began a moment earlier.
func (s *Server) cliSessionGate(id oidcauth.Identity) error {
	// A credential is being minted, which is rare enough to pay for a fresh
	// read: the bindings as they stand, not as cached up to
	// rolestore.DefaultTTL ago, so an offboarding a moment earlier holds.
	s.invalidateRoleCache()
	if b := s.Authz.DeniedBy(subjectFromIdentity(&id), authz.GlobalScope); b != nil {
		return errors.New("a deny binding on this hub names this account (" + string(b.Claim) + " " + b.Value + ")")
	}
	return nil
}

// ── limiters ────────────────────────────────────────────────────────────────

// windowCounter counts events per key in fixed windows. The zero value is
// ready. Bounded at deviceLimiterMaxKeys keys: past that the stalest window is
// dropped, which forgets one caller's count rather than growing the process.
type windowCounter struct {
	mu   sync.Mutex
	keys map[string]*windowCount
}

type windowCount struct {
	start time.Time
	n     int
}

// allow counts one event for key and reports whether it fits under limit in
// the current window, and if not, how long until the window ends.
func (c *windowCounter) allow(key string, limit int, window time.Duration, now time.Time) (bool, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := c.windowLocked(key, window, now)
	if w.n >= limit {
		return false, w.start.Add(window).Sub(now)
	}
	w.n++
	return true, 0
}

// note counts one event for key without asking.
func (c *windowCounter) note(key string, window time.Duration, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.windowLocked(key, window, now).n++
}

// limited reports whether key has reached limit in the current window, and
// how long until it ends, without counting anything.
func (c *windowCounter) limited(key string, limit int, window time.Duration, now time.Time) (time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w, ok := c.keys[key]
	if !ok || now.Sub(w.start) >= window || w.n < limit {
		return 0, false
	}
	return w.start.Add(window).Sub(now), true
}

func (c *windowCounter) windowLocked(key string, window time.Duration, now time.Time) *windowCount {
	if c.keys == nil {
		c.keys = make(map[string]*windowCount)
	}
	w, ok := c.keys[key]
	if ok && now.Sub(w.start) < window {
		return w
	}
	if !ok && len(c.keys) >= deviceLimiterMaxKeys {
		c.evictLocked(window, now)
	}
	w = &windowCount{start: now}
	c.keys[key] = w
	return w
}

// evictLocked drops every finished window, and the oldest open one if that
// freed nothing.
func (c *windowCounter) evictLocked(window time.Duration, now time.Time) {
	var oldest string
	var oldestAt time.Time
	for k, w := range c.keys {
		if now.Sub(w.start) >= window {
			delete(c.keys, k)
			continue
		}
		if oldest == "" || w.start.Before(oldestAt) {
			oldest, oldestAt = k, w.start
		}
	}
	if len(c.keys) >= deviceLimiterMaxKeys && oldest != "" {
		delete(c.keys, oldest)
	}
}

// retryAfterSeconds renders a Retry-After value, never less than one second.
func retryAfterSeconds(d time.Duration) string {
	secs := int64(d / time.Second)
	if d%time.Second != 0 {
		secs++
	}
	if secs < 1 {
		secs = 1
	}
	return strconv.FormatInt(secs, 10)
}
