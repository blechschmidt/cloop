package ui

// OIDC single sign-on and per-user project scoping tests (Task 20152).
//
// The first test pins the most important property: with OIDC disabled (the
// default, and the state of this server), the dashboard behaves exactly as
// before. The rest drive the full login flow against an httptest fake IdP
// and verify route gating, token fallback, and per-user project visibility.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// uiFakeIdP is a minimal OIDC provider whose /authorize endpoint
// immediately redirects back to the relying party with a code, so a
// cookie-jar http.Client completes the whole login in one GET.
type uiFakeIdP struct {
	t      *testing.T
	key    *rsa.PrivateKey
	server *httptest.Server

	email string
	sub   string
	name  string

	lastNonce string
}

func newUIFakeIdP(t *testing.T) *uiFakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	idp := &uiFakeIdP{t: t, key: key, email: "alice@example.com", sub: "sub-alice", name: "Alice"}
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
				"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		idp.lastNonce = q.Get("nonce")
		cb, _ := url.Parse(q.Get("redirect_uri"))
		cq := cb.Query()
		cq.Set("code", "code-1")
		cq.Set("state", q.Get("state"))
		cb.RawQuery = cq.Encode()
		http.Redirect(w, r, cb.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1"})
		payload, _ := json.Marshal(map[string]any{
			"iss":   idp.server.URL,
			"sub":   idp.sub,
			"aud":   "cloop-dashboard",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"iat":   time.Now().Unix(),
			"nonce": idp.lastNonce,
			"email": idp.email,
			"name":  idp.name,
		})
		input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
		digest := sha256.Sum256([]byte(input))
		sig, err := rsa.SignPKCS1v15(rand.Reader, idp.key, crypto.SHA256, digest[:])
		if err != nil {
			idp.t.Fatalf("sign: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
			"id_token": input + "." + base64.RawURLEncoding.EncodeToString(sig),
		})
	})
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

// newOIDCTestServer builds a UI server + httptest listener with OIDC wired
// to the fake IdP. token optionally enables the legacy bearer fallback.
func newOIDCTestServer(t *testing.T, idp *uiFakeIdP, token string, adminEmails []string) (*Server, *httptest.Server) {
	t.Helper()
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, token)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	auth, err := oidcauth.New(oidcauth.Config{
		Enabled:      true,
		Issuer:       idp.server.URL, // http, but loopback is allowed for dev IdPs
		ClientID:     "cloop-dashboard",
		ClientSecret: "test-secret",
		RedirectURL:  ts.URL + "/auth/callback",
		AdminEmails:  adminEmails,
	})
	if err != nil {
		t.Fatalf("oidcauth.New: %v", err)
	}
	srv.OIDC = auth
	return srv, ts
}

// jarClient is an http.Client with a cookie jar that follows redirects,
// letting one GET complete the entire login round-trip.
func jarClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

// login signs the jar client in via the full redirect chain and asserts it
// ends up on the dashboard. The Accept header mimics a browser navigation
// so the auth gate redirects into the login flow instead of returning the
// API-style 401.
func login(t *testing.T, c *http.Client, ts *httptest.Server) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("login GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login chain ended with %d, want 200", resp.StatusCode)
	}
	if got := resp.Request.URL.Path; got != "/" {
		t.Fatalf("login chain ended at %q, want /", got)
	}
}

func TestOIDCDisabledBehaviorUnchanged(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Dashboard and API are open, exactly as before.
	for _, path := range []string{"/", "/api/state"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, resp.StatusCode)
		}
	}

	// /api/me reports oidc_enabled=false so the frontend renders no chip.
	me := apiGET(t, ts, "/api/me")
	if me["oidc_enabled"] != false {
		t.Errorf("oidc_enabled = %v, want false", me["oidc_enabled"])
	}

	// The login machinery is a 404, not an open redirect.
	resp, err := http.Get(ts.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /auth/login = %d, want 404 when OIDC is disabled", resp.StatusCode)
	}
}

func TestOIDCFullLoginFlowAndGating(t *testing.T) {
	idp := newUIFakeIdP(t)
	_, ts := newOIDCTestServer(t, idp, "", nil)

	// Unauthenticated browser navigation → redirected into the login flow.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/auth/login" {
		t.Fatalf("unauth GET / = %d %q, want 302 /auth/login", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Unauthenticated API call → 401 JSON, not a redirect.
	resp, err = noRedirect.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth GET /api/state = %d, want 401", resp.StatusCode)
	}

	// Full login via the redirect chain: / → /auth/login → IdP → callback → /.
	c := jarClient(t)
	login(t, c, ts)

	// The session now opens the API.
	resp, err = c.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authed GET /api/state = %d, want 200", resp.StatusCode)
	}

	// /api/me reflects the IdP identity.
	resp, err = c.Get(ts.URL + "/api/me")
	if err != nil {
		t.Fatal(err)
	}
	var me map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if me["authenticated"] != true || me["email"] != "alice@example.com" || me["name"] != "Alice" {
		t.Fatalf("me = %v", me)
	}

	// Logout closes the door again.
	resp, err = c.Post(ts.URL+"/auth/logout", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = c.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-logout GET /api/state = %d, want 401", resp.StatusCode)
	}
}

func TestOIDCBearerTokenFallback(t *testing.T) {
	idp := newUIFakeIdP(t)
	_, ts := newOIDCTestServer(t, idp, "automation-token", nil)

	get := func(token string) int {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/state", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := get("automation-token"); got != http.StatusOK {
		t.Errorf("valid bearer = %d, want 200", got)
	}
	if got := get("wrong-token"); got != http.StatusUnauthorized {
		t.Errorf("wrong bearer = %d, want 401", got)
	}
	if got := get(""); got != http.StatusUnauthorized {
		t.Errorf("no credentials = %d, want 401", got)
	}
}

func TestOIDCPerUserProjectVisibility(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "automation-token", []string{"root@example.com"})

	// Registry: one project owned by alice, one by bob, one shared.
	aliceDir := setupProjectDir(t, "alice project", nil)
	bobDir := setupProjectDir(t, "bob project", nil)
	sharedDir := setupProjectDir(t, "shared project", nil)
	if err := multiui.AddPathsOwned([]string{aliceDir}, "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := multiui.AddPathsOwned([]string{bobDir}, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := multiui.AddPathsOwned([]string{sharedDir}, ""); err != nil {
		t.Fatal(err)
	}

	projectPaths := func(c *http.Client, bearer string) map[string]bool {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/projects", nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		client := c
		if client == nil {
			client = http.DefaultClient
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/projects = %d", resp.StatusCode)
		}
		var out struct {
			Projects []multiui.ProjectStatus `json:"projects"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		paths := map[string]bool{}
		for _, p := range out.Projects {
			paths[p.Path] = true
		}
		return paths
	}

	// Alice sees: primary (shared), her own project, and the shared one.
	idp.email, idp.sub, idp.name = "alice@example.com", "sub-alice", "Alice"
	alice := jarClient(t)
	login(t, alice, ts)
	got := projectPaths(alice, "")
	if !got[aliceDir] || !got[sharedDir] || got[bobDir] {
		t.Errorf("alice sees %v — want her project + shared, not bob's", got)
	}

	// Bob sees his own + shared, not alice's.
	idp.email, idp.sub, idp.name = "bob@example.com", "sub-bob", "Bob"
	bob := jarClient(t)
	login(t, bob, ts)
	got = projectPaths(bob, "")
	if !got[bobDir] || !got[sharedDir] || got[aliceDir] {
		t.Errorf("bob sees %v — want his project + shared, not alice's", got)
	}

	// The admin sees everything.
	idp.email, idp.sub, idp.name = "root@example.com", "sub-root", "Root"
	admin := jarClient(t)
	login(t, admin, ts)
	got = projectPaths(admin, "")
	if !got[aliceDir] || !got[bobDir] || !got[sharedDir] {
		t.Errorf("admin sees %v — want all projects", got)
	}

	// Token-authenticated automation sees everything too.
	got = projectPaths(nil, "automation-token")
	if !got[aliceDir] || !got[bobDir] || !got[sharedDir] {
		t.Errorf("token client sees %v — want all projects", got)
	}

	// resolveWorkDir scopes indices per user: bob's index space must never
	// resolve to alice's project.
	bobCookieReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/state", nil)
	for _, c := range bob.Jar.Cookies(mustParseURL(t, ts.URL)) {
		bobCookieReq.AddCookie(c)
	}
	for i := 0; i < 6; i++ {
		q := bobCookieReq.URL.Query()
		q.Set("project_idx", strconv.Itoa(i))
		bobCookieReq.URL.RawQuery = q.Encode()
		if wd := srv.resolveWorkDir(bobCookieReq); wd == aliceDir {
			t.Errorf("project_idx=%d resolved to alice's dir for bob", i)
		}
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestOIDCFilterHelpersUnit(t *testing.T) {
	auth, err := oidcauth.New(oidcauth.Config{
		Enabled:      true,
		Issuer:       "https://idp.example.com",
		ClientID:     "cid",
		ClientSecret: "cs",
		RedirectURL:  "https://cloop.example.com/auth/callback",
		AdminEmails:  []string{"root@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{OIDC: auth}
	entries := []multiui.ProjectEntry{
		{Name: "shared", Path: "/p/shared"},
		{Name: "alice", Path: "/p/alice", Owner: "alice@example.com"},
		{Name: "bob", Path: "/p/bob", Owner: "bob@example.com"},
	}
	alice := &oidcauth.Identity{Sub: "s1", Email: "alice@example.com"}
	admin := &oidcauth.Identity{Sub: "s2", Email: "root@example.com"}

	got := s.filterEntriesForIdentity(alice, entries)
	if len(got) != 2 || got[0].Path != "/p/shared" || got[1].Path != "/p/alice" {
		t.Errorf("alice filter = %v", got)
	}
	if got := s.filterEntriesForIdentity(admin, entries); len(got) != 3 {
		t.Errorf("admin filter = %v", got)
	}
	if got := s.filterEntriesForIdentity(nil, entries); len(got) != 3 {
		t.Errorf("nil-user filter = %v", got)
	}

	if k := s.visibilityKey(alice); k != "alice@example.com" {
		t.Errorf("alice visibilityKey = %q", k)
	}
	if k := s.visibilityKey(admin); k != "" {
		t.Errorf("admin visibilityKey = %q, want \"\" (unfiltered)", k)
	}
	if k := s.visibilityKey(nil); k != "" {
		t.Errorf("nil visibilityKey = %q, want \"\"", k)
	}

	statuses := []multiui.ProjectStatus{
		{Name: "shared", Path: "/p/shared"},
		{Name: "alice", Path: "/p/alice", TotalTasks: 3},
		{Name: "bob", Path: "/p/bob", TotalTasks: 5},
	}
	vis, stats := s.filterStatusesForIdentity(alice, entries, statuses)
	if len(vis) != 2 || stats.TotalProjects != 2 || stats.TotalTasks != 3 {
		t.Errorf("alice statuses = %v stats = %+v", vis, stats)
	}

	// With OIDC disabled every helper passes through untouched.
	off := &Server{}
	if got := off.filterEntriesForIdentity(alice, entries); len(got) != 3 {
		t.Errorf("disabled filter = %v, want passthrough", got)
	}
	vis, stats = off.filterStatusesForIdentity(alice, entries, statuses)
	if len(vis) != 3 || stats.TotalProjects != 3 {
		t.Errorf("disabled statuses = %v", vis)
	}
}
