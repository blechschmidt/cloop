package oidcauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeIdP is an httptest-backed OpenID Connect provider: discovery, JWKS,
// and a token endpoint that returns an RS256-signed ID token built from the
// mutable claim fields below.
type fakeIdP struct {
	t      *testing.T
	key    *rsa.PrivateKey
	server *httptest.Server

	// claim knobs; tests set these before driving the callback.
	nonce     string
	audience  string // defaults to the client_id supplied at /token time
	issuerOut string // override iss claim ("" = server URL)
	expOffset time.Duration

	// request observations
	sawBasicAuth  bool
	tokenRequests int
	rejectBasic   bool // force fallback to client_secret_post
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	idp := &fakeIdP{t: t, key: key, expOffset: time.Hour}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 idp.server.URL,
			"authorization_endpoint": idp.server.URL + "/authorize",
			"token_endpoint":         idp.server.URL + "/token",
			"jwks_uri":               idp.server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := &idp.key.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idp.tokenRequests++
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if _, _, ok := r.BasicAuth(); ok {
			idp.sawBasicAuth = true
			if idp.rejectBasic {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
				return
			}
		}
		if r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("code") == "" {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("code_verifier") == "" {
			http.Error(w, "missing PKCE verifier", http.StatusBadRequest)
			return
		}
		aud := idp.audience
		if aud == "" {
			aud = r.PostForm.Get("client_id")
		}
		iss := idp.issuerOut
		if iss == "" {
			iss = idp.server.URL
		}
		idToken := idp.signToken(map[string]any{
			"iss":   iss,
			"sub":   "user-123",
			"aud":   aud,
			"exp":   time.Now().Add(idp.expOffset).Unix(),
			"iat":   time.Now().Unix(),
			"nonce": idp.nonce,
			"email": "Alice@Example.com",
			"name":  "Alice Dev",
		})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at-abc", "id_token": idToken, "token_type": "Bearer", "expires_in": 3600,
		})
	})
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (f *fakeIdP) signToken(claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key"})
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		f.t.Fatalf("sign: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func newTestAuthenticator(t *testing.T, idp *fakeIdP) *Authenticator {
	t.Helper()
	a, err := New(Config{
		Enabled:      true,
		Issuer:       idp.server.URL,
		ClientID:     "cloop-dashboard",
		ClientSecret: "s3cret",
		RedirectURL:  "http://localhost:8080/auth/callback",
		AdminEmails:  []string{"admin@example.com"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// beginLogin drives BeginLogin and returns the state and nonce parsed from
// the IdP redirect.
func beginLogin(t *testing.T, a *Authenticator) (state, nonce string) {
	t.Helper()
	rec := httptest.NewRecorder()
	a.BeginLogin(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("BeginLogin status = %d, want 302 (body: %s)", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("redirect location: %v", err)
	}
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("PKCE parameters missing from authorize redirect: %s", loc)
	}
	if q.Get("response_type") != "code" {
		t.Fatalf("response_type = %q, want code", q.Get("response_type"))
	}
	return q.Get("state"), q.Get("nonce")
}

func doCallback(a *Authenticator, state string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=authcode-1&state="+url.QueryEscape(state), nil)
	a.HandleCallback(rec, req)
	return rec
}

func TestFullLoginFlow(t *testing.T) {
	idp := newFakeIdP(t)
	a := newTestAuthenticator(t, idp)

	state, nonce := beginLogin(t, a)
	idp.nonce = nonce

	rec := doCallback(a, state)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302 (body: %s)", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Fatalf("callback redirect = %q, want /", loc)
	}
	var sid string
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName {
			sid = c.Value
			if !c.HttpOnly {
				t.Error("session cookie must be HttpOnly")
			}
		}
	}
	if sid == "" {
		t.Fatal("no session cookie set")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sid})
	id := a.IdentityFromRequest(req)
	if id == nil {
		t.Fatal("IdentityFromRequest returned nil for fresh session")
	}
	if id.Sub != "user-123" || id.Email != "alice@example.com" || id.Name != "Alice Dev" {
		t.Fatalf("identity = %+v", id)
	}
	if got := id.OwnerKey(); got != "alice@example.com" {
		t.Fatalf("OwnerKey = %q", got)
	}
	if a.IsAdmin(id) {
		t.Error("alice must not be admin")
	}
	if !a.IsAdmin(&Identity{Sub: "x", Email: "Admin@Example.COM"}) {
		t.Error("admin email match must be case-insensitive")
	}

	// Logout invalidates the session.
	rec2 := httptest.NewRecorder()
	lreq := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	lreq.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sid})
	a.Logout(rec2, lreq)
	if a.IdentityFromRequest(req) != nil {
		t.Fatal("session must be gone after logout")
	}
}

func TestCallbackRejectsBadState(t *testing.T) {
	idp := newFakeIdP(t)
	a := newTestAuthenticator(t, idp)
	_, nonce := beginLogin(t, a)
	idp.nonce = nonce

	rec := doCallback(a, "forged-state")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("forged state status = %d, want 400", rec.Code)
	}
	if idp.tokenRequests != 0 {
		t.Fatal("token endpoint must not be called for unknown state")
	}
}

func TestStateIsOneShot(t *testing.T) {
	idp := newFakeIdP(t)
	a := newTestAuthenticator(t, idp)
	state, nonce := beginLogin(t, a)
	idp.nonce = nonce

	if rec := doCallback(a, state); rec.Code != http.StatusFound {
		t.Fatalf("first callback = %d, want 302", rec.Code)
	}
	if rec := doCallback(a, state); rec.Code != http.StatusBadRequest {
		t.Fatalf("replayed callback = %d, want 400", rec.Code)
	}
}

func TestCallbackRejectsNonceMismatch(t *testing.T) {
	idp := newFakeIdP(t)
	a := newTestAuthenticator(t, idp)
	state, _ := beginLogin(t, a)
	idp.nonce = "some-other-nonce"

	rec := doCallback(a, state)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("nonce mismatch status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestCallbackRejectsWrongAudience(t *testing.T) {
	idp := newFakeIdP(t)
	a := newTestAuthenticator(t, idp)
	state, nonce := beginLogin(t, a)
	idp.nonce = nonce
	idp.audience = "some-other-client"

	rec := doCallback(a, state)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("aud mismatch status = %d, want 403", rec.Code)
	}
}

func TestCallbackRejectsExpiredToken(t *testing.T) {
	idp := newFakeIdP(t)
	a := newTestAuthenticator(t, idp)
	state, nonce := beginLogin(t, a)
	idp.nonce = nonce
	idp.expOffset = -time.Hour

	rec := doCallback(a, state)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expired token status = %d, want 403", rec.Code)
	}
}

func TestCallbackRejectsTamperedSignature(t *testing.T) {
	idp := newFakeIdP(t)
	a := newTestAuthenticator(t, idp)
	state, nonce := beginLogin(t, a)

	// Sign the token with a different key than the one in the JWKS.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	realKey := idp.key
	idp.key = otherKey
	idp.nonce = nonce
	defer func() { idp.key = realKey }()

	// The JWKS endpoint serves idp.key's public part — but it also swapped.
	// Serve the original public key by restoring before the JWKS fetch:
	// simplest robust approach — pre-warm the JWKS cache with the real key.
	idp.key = realKey
	if _, err := a.signingKey(t.Context(), "test-key"); err != nil {
		t.Fatalf("prewarm JWKS: %v", err)
	}
	idp.key = otherKey

	rec := doCallback(a, state)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tampered signature status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestClientSecretPostFallback(t *testing.T) {
	idp := newFakeIdP(t)
	idp.rejectBasic = true
	a := newTestAuthenticator(t, idp)
	state, nonce := beginLogin(t, a)
	idp.nonce = nonce

	rec := doCallback(a, state)
	if rec.Code != http.StatusFound {
		t.Fatalf("fallback flow status = %d, want 302 (body: %s)", rec.Code, rec.Body.String())
	}
	if !idp.sawBasicAuth {
		t.Fatal("basic auth attempt expected before fallback")
	}
	if idp.tokenRequests != 2 {
		t.Fatalf("tokenRequests = %d, want 2 (basic then post)", idp.tokenRequests)
	}
}

func TestSessionExpiry(t *testing.T) {
	idp := newFakeIdP(t)
	a := newTestAuthenticator(t, idp)
	a.cfg.SessionTTL = 10 * time.Millisecond

	sid, err := a.createSession(Identity{Sub: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sid})
	if a.IdentityFromRequest(req) == nil {
		t.Fatal("fresh session must resolve")
	}
	time.Sleep(20 * time.Millisecond)
	if a.IdentityFromRequest(req) != nil {
		t.Fatal("expired session must not resolve")
	}
	if a.SessionCount() != 0 {
		t.Fatal("expired session must be purged on lookup")
	}
}

func TestNilAndDisabledAuthenticator(t *testing.T) {
	var a *Authenticator
	if a.Enabled() {
		t.Fatal("nil authenticator must report disabled")
	}
	if a.IdentityFromRequest(httptest.NewRequest(http.MethodGet, "/", nil)) != nil {
		t.Fatal("nil authenticator must yield nil identity")
	}
	if a.IsAdmin(&Identity{Email: "x@y"}) {
		t.Fatal("nil authenticator must report non-admin")
	}
	if _, err := New(Config{Enabled: false}); err == nil {
		t.Fatal("New with Enabled=false must error")
	}
}

func TestNewValidation(t *testing.T) {
	base := func() Config {
		return Config{
			Enabled:      true,
			Issuer:       "https://idp.example.com",
			ClientID:     "cid",
			ClientSecret: "cs",
			RedirectURL:  "https://cloop.example.com/auth/callback",
		}
	}
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing issuer", func(c *Config) { c.Issuer = "" }},
		{"http issuer non-localhost", func(c *Config) { c.Issuer = "http://idp.example.com" }},
		{"missing client_id", func(c *Config) { c.ClientID = "" }},
		{"missing client_secret", func(c *Config) { c.ClientSecret = "" }},
		{"missing redirect_url", func(c *Config) { c.RedirectURL = "" }},
		{"bad cookie_secure", func(c *Config) { c.CookieSecure = "sometimes" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mutate(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatalf("New must reject %s", tc.name)
			}
		})
	}

	// http localhost issuer is allowed for dev IdPs.
	cfg := base()
	cfg.Issuer = "http://localhost:5556/dex"
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("localhost http issuer should be accepted: %v", err)
	}
	// Default scopes include openid, and openid is prepended when missing.
	if got := strings.Join(a.cfg.Scopes, " "); got != "openid profile email" {
		t.Fatalf("default scopes = %q", got)
	}
	cfg.Scopes = []string{"profile"}
	a, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if a.cfg.Scopes[0] != "openid" {
		t.Fatalf("openid must be prepended, got %v", a.cfg.Scopes)
	}
}

func TestSecureCookieModes(t *testing.T) {
	idp := newFakeIdP(t)
	plain := httptest.NewRequest(http.MethodGet, "/", nil)
	proxied := httptest.NewRequest(http.MethodGet, "/", nil)
	proxied.Header.Set("X-Forwarded-Proto", "https")

	for _, tc := range []struct {
		mode        string
		plainSecure bool
		proxySecure bool
	}{
		{"auto", false, true},
		{"always", true, true},
		{"never", false, false},
	} {
		a := newTestAuthenticator(t, idp)
		a.cfg.CookieSecure = tc.mode
		if got := a.sessionCookie(plain, "v", 60).Secure; got != tc.plainSecure {
			t.Errorf("mode %s plain: Secure = %v, want %v", tc.mode, got, tc.plainSecure)
		}
		if got := a.sessionCookie(proxied, "v", 60).Secure; got != tc.proxySecure {
			t.Errorf("mode %s proxied: Secure = %v, want %v", tc.mode, got, tc.proxySecure)
		}
	}
}

func TestPendingLoginBoundsAndTTL(t *testing.T) {
	idp := newFakeIdP(t)
	a := newTestAuthenticator(t, idp)

	state, nonce := beginLogin(t, a)
	idp.nonce = nonce
	// Age the pending entry past the TTL.
	a.mu.Lock()
	a.pending[state].created = time.Now().Add(-loginStateTTL - time.Minute)
	a.mu.Unlock()
	if rec := doCallback(a, state); rec.Code != http.StatusBadRequest {
		t.Fatalf("expired pending login status = %d, want 400", rec.Code)
	}

	// The purge keeps the map bounded even under a login flood.
	for i := 0; i < maxPendingLogins+50; i++ {
		a.mu.Lock()
		a.purgePendingLocked(time.Now())
		a.pending[fmt.Sprintf("s%d", i)] = &pendingLogin{created: time.Now()}
		a.mu.Unlock()
	}
	a.mu.Lock()
	n := len(a.pending)
	a.mu.Unlock()
	if n > maxPendingLogins {
		t.Fatalf("pending map grew to %d, cap is %d", n, maxPendingLogins)
	}
}
