// Package oidcauth implements a minimal OpenID Connect relying party for the
// cloop web dashboard: the authorization-code flow with PKCE for a
// confidential client, ID-token validation against the provider's JWKS, and
// in-memory cookie-backed sessions.
//
// The package is intentionally dependency-free (stdlib only). Only the parts
// of OIDC that cloop needs are implemented: provider discovery, the code
// flow, RS256/ES256 signature verification, and iss/aud/exp/nonce claim
// validation. Sessions live in process memory — restarting the dashboard
// logs everyone out, which is an acceptable trade for having no session
// store to secure at rest.
package oidcauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// SessionCookieName is the browser cookie that carries the opaque
	// session ID established after a successful IdP callback.
	SessionCookieName = "cloop_session"

	// loginStateTTL bounds how long a login attempt (state + nonce + PKCE
	// verifier) stays valid between the redirect to the IdP and the
	// callback. Fifteen minutes is generous for a human completing an SSO
	// prompt while keeping abandoned attempts from accumulating.
	loginStateTTL = 15 * time.Minute

	// maxPendingLogins and maxSessions bound the two in-memory maps so a
	// client hammering /auth/login (or a burst of users) cannot grow
	// process memory without limit. Oldest entries are evicted first.
	maxPendingLogins = 5000
	maxSessions      = 10000

	// httpTimeout bounds every outbound call to the IdP (discovery, token
	// exchange, JWKS fetch).
	httpTimeout = 15 * time.Second

	// clockSkew is the leeway applied to exp/iat validation so a modest
	// clock drift between cloop and the IdP does not reject valid tokens.
	clockSkew = 5 * time.Minute

	// jwksMinRefreshInterval throttles JWKS re-fetches on unknown key IDs
	// so a flood of forged tokens with bogus kids cannot make cloop hammer
	// the IdP.
	jwksMinRefreshInterval = time.Minute

	// maxIdPResponseBytes bounds how much of any IdP HTTP response body is
	// read (discovery document, token response, JWKS).
	maxIdPResponseBytes = 1 << 20 // 1 MiB

	// DefaultSessionTTL is used when Config.SessionTTL is zero.
	DefaultSessionTTL = 24 * time.Hour

	// maxSessionTTL caps configured session lifetimes.
	maxSessionTTL = 30 * 24 * time.Hour
)

// Config holds the relying-party settings, typically mapped from
// config.OIDCConfig (ui.oidc.* in .cloop/config.yaml).
type Config struct {
	Enabled      bool
	Issuer       string // e.g. https://auth.example.com/realms/main
	ClientID     string
	ClientSecret string
	RedirectURL  string   // e.g. https://cloop.example.com/auth/callback
	Scopes       []string // default: openid profile email
	AdminEmails  []string // users who see every project regardless of owner
	SessionTTL   time.Duration
	CookieSecure string // "auto" (default), "always", "never"
}

// Identity is the authenticated user extracted from a validated ID token.
type Identity struct {
	Sub   string `json:"sub"`
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`

	// Groups and Roles carry the group/role claims the IdP released,
	// flattened from whatever shape it used. They are the input to
	// pkg/authz role mappings; an IdP that releases neither leaves both
	// empty and every identity falls back to oidc.default_role.
	Groups []string `json:"groups,omitempty"`
	Roles  []string `json:"roles,omitempty"`
}

// OwnerKey returns the stable string used to record project ownership:
// the lowercased email when present, otherwise the issuer subject. A nil
// identity yields "" (no owner / shared).
func (id *Identity) OwnerKey() string {
	if id == nil {
		return ""
	}
	if id.Email != "" {
		return strings.ToLower(id.Email)
	}
	return "sub:" + id.Sub
}

// DisplayName returns the friendliest non-empty label for the user.
func (id *Identity) DisplayName() string {
	if id == nil {
		return ""
	}
	if id.Name != "" {
		return id.Name
	}
	if id.Email != "" {
		return id.Email
	}
	return id.Sub
}

type pendingLogin struct {
	nonce    string
	verifier string
	created  time.Time
}

type session struct {
	identity Identity
	created  time.Time
	expires  time.Time
}

// Authenticator is the OIDC relying party. The zero value is not usable;
// construct via New. A nil *Authenticator is valid and reports Enabled() ==
// false, so callers can hold one optional field without nil checks.
type Authenticator struct {
	cfg    Config
	client *http.Client

	discMu sync.Mutex
	disc   *discoveryDoc

	jwksMu      sync.Mutex
	jwksKeys    map[string]any // kid -> *rsa.PublicKey | *ecdsa.PublicKey
	jwksFetched time.Time

	mu       sync.Mutex
	pending  map[string]*pendingLogin
	sessions map[string]*session
}

// New validates cfg and returns a ready Authenticator. It is an error to
// call New with Enabled=false — callers should simply not construct one.
// Validation is strict (fail closed): a dashboard that claims to require
// SSO must not silently start without it.
func New(cfg Config) (*Authenticator, error) {
	if !cfg.Enabled {
		return nil, errors.New("oidcauth: config has enabled=false")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("oidcauth: issuer is required")
	}
	iss, err := url.Parse(cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: invalid issuer URL: %w", err)
	}
	if iss.Scheme != "https" && !isLoopbackHost(iss.Hostname()) {
		return nil, fmt.Errorf("oidcauth: issuer %q must use https (plain http is only allowed for localhost development IdPs)", cfg.Issuer)
	}
	if cfg.ClientID == "" {
		return nil, errors.New("oidcauth: client_id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("oidcauth: client_secret is required (cloop acts as a confidential client)")
	}
	if cfg.RedirectURL == "" {
		return nil, errors.New("oidcauth: redirect_url is required (e.g. https://cloop.example.com/auth/callback)")
	}
	if _, err := url.Parse(cfg.RedirectURL); err != nil {
		return nil, fmt.Errorf("oidcauth: invalid redirect_url: %w", err)
	}
	switch cfg.CookieSecure {
	case "", "auto", "always", "never":
	default:
		return nil, fmt.Errorf("oidcauth: cookie_secure must be auto, always, or never (got %q)", cfg.CookieSecure)
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	} else if !containsFold(cfg.Scopes, "openid") {
		cfg.Scopes = append([]string{"openid"}, cfg.Scopes...)
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = DefaultSessionTTL
	}
	if cfg.SessionTTL > maxSessionTTL {
		cfg.SessionTTL = maxSessionTTL
	}
	return &Authenticator{
		cfg:      cfg,
		client:   &http.Client{Timeout: httpTimeout},
		jwksKeys: map[string]any{},
		pending:  map[string]*pendingLogin{},
		sessions: map[string]*session{},
	}, nil
}

// Enabled reports whether OIDC authentication is active. Safe on nil.
func (a *Authenticator) Enabled() bool {
	return a != nil && a.cfg.Enabled
}

// Issuer returns the configured issuer URL ("" when disabled).
func (a *Authenticator) Issuer() string {
	if a == nil {
		return ""
	}
	return a.cfg.Issuer
}

// IsAdmin reports whether id's email is on the configured admin list.
// Admins see (and may manage) every project regardless of owner.
func (a *Authenticator) IsAdmin(id *Identity) bool {
	if a == nil || id == nil || id.Email == "" {
		return false
	}
	for _, e := range a.cfg.AdminEmails {
		if strings.EqualFold(strings.TrimSpace(e), id.Email) {
			return true
		}
	}
	return false
}

// BeginLogin starts the authorization-code flow: it records a one-shot
// state + nonce + PKCE verifier and redirects the browser to the IdP's
// authorization endpoint.
func (a *Authenticator) BeginLogin(w http.ResponseWriter, r *http.Request) {
	disc, err := a.discover(r.Context())
	if err != nil {
		a.errorPage(w, http.StatusServiceUnavailable, "The identity provider is unreachable or misconfigured.", err)
		return
	}
	state, err1 := randToken()
	nonce, err2 := randToken()
	verifier, err3 := randToken()
	if err := errors.Join(err1, err2, err3); err != nil {
		a.errorPage(w, http.StatusInternalServerError, "Could not generate login state.", err)
		return
	}

	now := time.Now()
	a.mu.Lock()
	a.purgePendingLocked(now)
	a.pending[state] = &pendingLogin{nonce: nonce, verifier: verifier, created: now}
	a.mu.Unlock()

	challenge := sha256.Sum256([]byte(verifier))
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", a.cfg.ClientID)
	q.Set("redirect_uri", a.cfg.RedirectURL)
	q.Set("scope", strings.Join(a.cfg.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	q.Set("code_challenge_method", "S256")

	sep := "?"
	if strings.Contains(disc.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	http.Redirect(w, r, disc.AuthorizationEndpoint+sep+q.Encode(), http.StatusFound)
}

// HandleCallback completes the flow: validates state, exchanges the code,
// verifies the ID token, creates a session, and redirects to the dashboard.
func (a *Authenticator) HandleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		desc := strings.TrimSpace(e + " " + q.Get("error_description"))
		a.errorPage(w, http.StatusForbidden, "The identity provider rejected the sign-in: "+desc, nil)
		return
	}
	state, code := q.Get("state"), q.Get("code")
	if state == "" || code == "" {
		a.errorPage(w, http.StatusBadRequest, "The callback is missing its state or code parameter.", nil)
		return
	}

	now := time.Now()
	a.mu.Lock()
	p := a.pending[state]
	delete(a.pending, state) // one-shot: a replayed state must not work twice
	a.mu.Unlock()
	if p == nil || now.Sub(p.created) > loginStateTTL {
		a.errorPage(w, http.StatusBadRequest, "This sign-in attempt has expired or was not initiated here. Please try again.", nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), httpTimeout)
	defer cancel()
	tok, err := a.exchangeCode(ctx, code, p.verifier)
	if err != nil {
		a.errorPage(w, http.StatusBadGateway, "Exchanging the authorization code with the identity provider failed.", err)
		return
	}
	id, err := a.verifyIDToken(ctx, tok.IDToken, p.nonce)
	if err != nil {
		a.errorPage(w, http.StatusForbidden, "The identity token failed validation.", err)
		return
	}

	sid, err := a.createSession(*id)
	if err != nil {
		a.errorPage(w, http.StatusInternalServerError, "Could not create a session.", err)
		return
	}
	http.SetCookie(w, a.sessionCookie(r, sid, int(a.cfg.SessionTTL.Seconds())))
	http.Redirect(w, r, "/", http.StatusFound)
}

// Logout deletes the caller's session (if any) and clears the cookie.
func (a *Authenticator) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, a.sessionCookie(r, "", -1))
}

// IdentityFromRequest returns the authenticated user for r's session
// cookie, or nil when there is no valid session. Safe on nil receiver.
func (a *Authenticator) IdentityFromRequest(r *http.Request) *Identity {
	if !a.Enabled() {
		return nil
	}
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[c.Value]
	if s == nil {
		return nil
	}
	if time.Now().After(s.expires) {
		delete(a.sessions, c.Value)
		return nil
	}
	id := s.identity // copy so callers cannot mutate the stored session
	return &id
}

// SessionCount returns the number of live sessions (expired-but-unpurged
// entries included). Used by tests and /api/me diagnostics.
func (a *Authenticator) SessionCount() int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.sessions)
}

func (a *Authenticator) createSession(id Identity) (string, error) {
	sid, err := randToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.purgeSessionsLocked(now)
	for len(a.sessions) >= maxSessions {
		a.evictOldestSessionLocked()
	}
	a.sessions[sid] = &session{identity: id, created: now, expires: now.Add(a.cfg.SessionTTL)}
	return sid, nil
}

// purgePendingLocked drops expired login attempts and, if the map is still
// at capacity, evicts oldest-first. Caller holds a.mu.
func (a *Authenticator) purgePendingLocked(now time.Time) {
	for st, p := range a.pending {
		if now.Sub(p.created) > loginStateTTL {
			delete(a.pending, st)
		}
	}
	for len(a.pending) >= maxPendingLogins {
		var oldest string
		var oldestAt time.Time
		for st, p := range a.pending {
			if oldest == "" || p.created.Before(oldestAt) {
				oldest, oldestAt = st, p.created
			}
		}
		if oldest == "" {
			return
		}
		delete(a.pending, oldest)
	}
}

// purgeSessionsLocked drops expired sessions. Caller holds a.mu.
func (a *Authenticator) purgeSessionsLocked(now time.Time) {
	for sid, s := range a.sessions {
		if now.After(s.expires) {
			delete(a.sessions, sid)
		}
	}
}

// evictOldestSessionLocked removes the single oldest session. Caller holds
// a.mu and has already purged expired entries.
func (a *Authenticator) evictOldestSessionLocked() {
	var oldest string
	var oldestAt time.Time
	for sid, s := range a.sessions {
		if oldest == "" || s.created.Before(oldestAt) {
			oldest, oldestAt = sid, s.created
		}
	}
	if oldest != "" {
		delete(a.sessions, oldest)
	}
}

// sessionCookie builds the session cookie with the Secure flag resolved
// per config ("auto" inspects the request: direct TLS or an https
// X-Forwarded-Proto from a reverse proxy).
func (a *Authenticator) sessionCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	secure := false
	switch a.cfg.CookieSecure {
	case "always":
		secure = true
	case "never":
		secure = false
	default: // "auto" / ""
		secure = r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	}
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	}
}

// errorPage renders a small self-contained HTML error page with a retry
// link. err detail is included (escaped) because the dashboard's audience
// is the operator who must debug their own IdP config.
func (a *Authenticator) errorPage(w http.ResponseWriter, status int, msg string, err error) {
	detail := ""
	if err != nil {
		detail = "<p class=\"detail\">" + html.EscapeString(err.Error()) + "</p>"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><html><head><title>cloop — sign-in problem</title>
<style>body{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{max-width:520px;padding:32px;background:#161b22;border:1px solid #30363d;border-radius:12px}
h1{font-size:18px;margin:0 0 12px}p{margin:8px 0;line-height:1.5}.detail{color:#8b949e;font-size:13px;word-break:break-word}
a{color:#58a6ff}</style></head><body><div class="card"><h1>Sign-in problem</h1><p>%s</p>%s<p><a href="/auth/login">Try again</a></p></div></body></html>`,
		html.EscapeString(msg), detail)
}

// randToken returns 256 bits of CSPRNG entropy, base64url-encoded (43
// chars — also a valid PKCE code verifier).
func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oidcauth: rng: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func isLoopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

func containsFold(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// ── IdP HTTP: discovery + token exchange ────────────────────────────────────

type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// discover fetches (and caches) the issuer's well-known configuration.
// Only a successful fetch is cached, so a transient IdP outage at first
// login retries on the next attempt.
func (a *Authenticator) discover(ctx context.Context) (*discoveryDoc, error) {
	a.discMu.Lock()
	defer a.discMu.Unlock()
	if a.disc != nil {
		return a.disc, nil
	}

	wellKnown := strings.TrimSuffix(a.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	body, err := a.getJSON(ctx, wellKnown)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: discovery %s: %w", wellKnown, err)
	}
	var doc discoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("oidcauth: discovery document parse: %w", err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return nil, errors.New("oidcauth: discovery document is missing authorization_endpoint or token_endpoint")
	}
	if !issuerEqual(doc.Issuer, a.cfg.Issuer) {
		return nil, fmt.Errorf("oidcauth: discovery issuer %q does not match configured issuer %q", doc.Issuer, a.cfg.Issuer)
	}
	a.disc = &doc
	return a.disc, nil
}

// issuerEqual compares issuer URLs, tolerating a trailing-slash mismatch
// (a common config-vs-document difference).
func issuerEqual(a, b string) bool {
	return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
}

func (a *Authenticator) getJSON(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIdPResponseBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	return body, nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// exchangeCode redeems the authorization code at the token endpoint. Client
// authentication tries client_secret_basic first (the OIDC default) and
// falls back to client_secret_post for IdPs that only accept form
// credentials.
func (a *Authenticator) exchangeCode(ctx context.Context, code, verifier string) (*tokenResponse, error) {
	disc, err := a.discover(ctx)
	if err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", a.cfg.RedirectURL)
	form.Set("code_verifier", verifier)

	tok, status, err := a.postToken(ctx, disc.TokenEndpoint, form, true)
	if err != nil && (status == http.StatusUnauthorized || strings.Contains(err.Error(), "invalid_client")) {
		// Retry once with credentials in the form body.
		tok, _, err = a.postToken(ctx, disc.TokenEndpoint, form, false)
	}
	if err != nil {
		return nil, err
	}
	if tok.IDToken == "" {
		return nil, errors.New("oidcauth: token response contained no id_token (is the openid scope configured on the client?)")
	}
	return tok, nil
}

// postToken performs one token-endpoint POST. basicAuth selects
// client_secret_basic (RFC 6749 §2.3.1: credentials are form-urlencoded
// before the Basic header) vs client_secret_post.
func (a *Authenticator) postToken(ctx context.Context, endpoint string, form url.Values, basicAuth bool) (*tokenResponse, int, error) {
	f := url.Values{}
	for k, v := range form {
		f[k] = v
	}
	f.Set("client_id", a.cfg.ClientID)
	if !basicAuth {
		f.Set("client_secret", a.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(f.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basicAuth {
		req.SetBasicAuth(url.QueryEscape(a.cfg.ClientID), url.QueryEscape(a.cfg.ClientSecret))
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("oidcauth: token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIdPResponseBytes))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("oidcauth: token endpoint read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("oidcauth: token endpoint status %d: %s", resp.StatusCode, truncate(string(body), 300))
	}
	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("oidcauth: token response parse: %w", err)
	}
	return &tok, resp.StatusCode, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
