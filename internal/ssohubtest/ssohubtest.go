// Package ssohubtest runs a hub with single sign-on in a test's own process,
// for tests of the terminal commands that talk to one (Task 20417).
//
// pkg/ui's own tests drive its handlers against uiFakeIdP, a fake identity
// provider in its _test.go files, which nothing outside the package can reach.
// The `cloop remote` commands need the same thing from cmd: a real hub — its
// middleware, its role policy, its session store, its routes — with an
// identity provider the test controls, and a terminal session minted the way
// `cloop login` mints one, so a command run in the test is refused or allowed
// exactly as the dashboard would be for the same person.
//
// Test-only (tests/arch/testonly_test.go): it imports "testing".
package ssohubtest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// The groups the default policy maps to roles, one per rung of the ladder.
const (
	GroupViewers     = "readers"
	GroupOperators   = "engineers"
	GroupMaintainers = "maintainers"
	GroupAdmins      = "owners"
)

// ClientID is the OAuth client the hub is registered as at the fake provider.
const ClientID = "cloop-terminal-tests"

// DefaultBindings maps each group above to its role.
func DefaultBindings() []authz.Binding {
	return []authz.Binding{
		{Claim: authz.ClaimGroup, Value: GroupViewers, Role: authz.RoleViewer},
		{Claim: authz.ClaimGroup, Value: GroupOperators, Role: authz.RoleOperator},
		{Claim: authz.ClaimGroup, Value: GroupMaintainers, Role: authz.RoleMaintainer},
		{Claim: authz.ClaimGroup, Value: GroupAdmins, Role: authz.RoleAdmin},
	}
}

// Options shape the hub.
type Options struct {
	// Bindings are the role mappings; nil means DefaultBindings.
	Bindings []authz.Binding
	// AdminEmails become global admins, as ui.oidc.admin_emails does.
	AdminEmails []string
	// SelfExe is the binary the hub runs for `cloop init`, `cloop feature`
	// and the rest of the work it dispatches (Server.SelfExe).
	SelfExe string
	// Goal is the hub's own project's goal.
	Goal string
	// SudoMaxAge is ui.oidc.sudo_max_age_minutes as a duration (Task 20448):
	// zero for the default window, negative to turn it off.
	SudoMaxAge time.Duration
	// Clock is the hub's session clock (oidcauth.Config.Clock); nil is the
	// real one. The identity provider's tokens always carry real time.
	Clock func() time.Time
}

// Hub is a running hub with single sign-on.
type Hub struct {
	Server *ui.Server
	// URL is the hub's base URL.
	URL string
	// Dir is the hub's own directory: its control plane.
	Dir string
	// Home is the HOME the hub runs with: its project registry, and the
	// projects root a project created by name goes under.
	Home string
	IdP  *IdP

	ts *httptest.Server
}

// Start runs a hub with single sign-on, terminal sign-in and a role policy,
// with HOME pointed at a directory of the test's own.
func Start(t testing.TB, opts Options) *Hub {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Secrets are sealed under it, and the session store seals refresh
	// grants with it, which is what lets the hub re-check a session.
	t.Setenv(secretbroker.EnvPassphraseKey, "ssohubtest-passphrase")

	idp := NewIdP(t)
	idp.mu.Lock()
	idp.now = opts.Clock
	idp.mu.Unlock()
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	goal := opts.Goal
	if goal == "" {
		goal = "the hub's own project"
	}
	if _, err := state.Init(dir, goal, 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}

	srv := ui.New(dir, 0, "")
	srv.RPS, srv.Burst = 10000, 10000
	if opts.SelfExe != "" {
		srv.SelfExe = opts.SelfExe
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	store, warn := srv.OpenSessionStore()
	if warn != nil {
		t.Fatalf("the session store is not durable: %v", warn)
	}
	cfg := oidcauth.Config{
		Enabled:     true,
		Issuer:      idp.URL(),
		ClientID:    ClientID,
		RedirectURL: ts.URL + "/auth/callback",
		AdminEmails: opts.AdminEmails,
		DeviceLogin: true,
		Store:       store,
		Audit:       srv.SessionAuditSink(),
		SudoMaxAge:  opts.SudoMaxAge,
		Clock:       opts.Clock,
	}
	srv.InstallOIDCHooks(&cfg)
	auth, err := oidcauth.New(cfg)
	if err != nil {
		t.Fatalf("oidcauth.New: %v", err)
	}
	srv.OIDC = auth
	roles, err := srv.OpenRoleStore()
	if err != nil {
		t.Fatalf("OpenRoleStore: %v", err)
	}
	if _, err := srv.OpenMemberStore(); err != nil {
		t.Fatalf("OpenMemberStore: %v", err)
	}
	bindings := opts.Bindings
	if bindings == nil {
		bindings = DefaultBindings()
	}
	resolver, err := authz.New(authz.Config{Bindings: bindings, AdminEmails: opts.AdminEmails, Runtime: roles})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return &Hub{Server: srv, URL: ts.URL, Dir: dir, Home: home, IdP: idp, ts: ts}
}

// SignIn completes a browser sign-in as email with groups and returns the
// browser: a client with the session cookie.
func (h *Hub) SignIn(t testing.TB, email string, groups ...string) *http.Client {
	t.Helper()
	h.IdP.SetIdentity(email, groups...)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Jar: jar}
	req, err := http.NewRequest(http.MethodGet, h.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("sign in as %s: %v", email, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/" {
		t.Fatalf("sign in as %s ended at %s with %d", email, resp.Request.URL, resp.StatusCode)
	}
	return c
}

// TerminalSession is `cloop login` approved in browser: it returns the
// session credential a terminal would keep in its hubs.json.
func (h *Hub) TerminalSession(t testing.TB, browser *http.Client) string {
	t.Helper()
	cred, digest, err := oidcauth.NewCLICredential()
	if err != nil {
		t.Fatal(err)
	}
	var code struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	if status := h.post(t, nil, "/api/device/code", map[string]string{"credential_hash": digest, "hostname": "terminal-test"}, &code); status != http.StatusOK {
		t.Fatalf("POST /api/device/code = %d", status)
	}
	var approve struct {
		Redirect string `json:"redirect"`
	}
	if status := h.post(t, browser, "/api/device/approve", map[string]string{"user_code": code.UserCode}, &approve); status != http.StatusOK {
		t.Fatalf("POST /api/device/approve = %d", status)
	}
	resp, err := browser.Get(approve.Redirect)
	if err != nil {
		t.Fatalf("follow the approval through the provider: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != oidcauth.DevicePath {
		t.Fatalf("the approval ended at %s with %d", resp.Request.URL, resp.StatusCode)
	}
	var tok struct {
		SessionID string `json:"session_id"`
	}
	if status := h.post(t, nil, "/api/device/token", map[string]string{
		"grant_type": oidcauth.DeviceGrantType, "device_code": code.DeviceCode,
	}, &tok); status != http.StatusOK || tok.SessionID != oidcauth.CLISessionID(digest) {
		t.Fatalf("POST /api/device/token = %d naming session %q", status, tok.SessionID)
	}
	return cred
}

// Login signs in as email with groups and returns a terminal session for
// them.
func (h *Hub) Login(t testing.TB, email string, groups ...string) string {
	t.Helper()
	return h.TerminalSession(t, h.SignIn(t, email, groups...))
}

// post sends body as JSON with c (nil: no credential) and decodes the answer
// into out.
func (h *Hub) post(t testing.TB, c *http.Client, path string, body, out any) int {
	t.Helper()
	blob, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, h.URL+path, bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c == nil {
		c = &http.Client{}
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil {
		_ = json.Unmarshal(raw, out)
	}
	return resp.StatusCode
}

// Call makes a request to the hub as browser, returning the status and the
// raw answer: what the dashboard's own call gets, for a test to compare a
// terminal's rendering against.
func (h *Hub) Call(t testing.TB, browser *http.Client, method, path string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		blob, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(blob)
	}
	req, err := http.NewRequest(method, h.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := browser.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// ControlPlane opens the hub's control-plane database, closed with the test.
func (h *Hub) ControlPlane(t testing.TB) *statedb.DB {
	t.Helper()
	db, err := statedb.Open(state.DBPath(h.Dir))
	if err != nil {
		t.Fatalf("open the control plane: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// AddExecutor registers ex in this process's executor registry and records
// it in the control plane, so a project can be bound to it. Unregistered when
// the test ends.
func (h *Hub) AddExecutor(t testing.TB, ex executor.Executor, name string) {
	t.Helper()
	if err := executor.Register(ex); err != nil {
		t.Fatalf("register executor %s: %v", ex.ID(), err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(ex.ID()) })
	if err := h.ControlPlane(t).UpsertExecutor(statedb.ExecutorRow{
		ID: ex.ID(), Name: name, Kind: ex.Kind(), Status: statedb.ExecutorStatusOnline, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("record executor %s: %v", ex.ID(), err)
	}
}

// RestrictExecutor puts an access list on an executor: only the named groups
// may use it.
func (h *Hub) RestrictExecutor(t testing.TB, id string, groups ...string) {
	t.Helper()
	db := h.ControlPlane(t)
	for _, g := range groups {
		if err := db.AddExecutorAudience(id, "group", g, "ssohubtest"); err != nil {
			t.Fatalf("restrict executor %s to %s: %v", id, g, err)
		}
	}
}

// StubExecutor isolates like a container and runs nothing: enough to be
// listed, admitted or refused, and bound to.
type StubExecutor struct {
	IDValue string
}

func (e *StubExecutor) ID() string   { return e.IDValue }
func (e *StubExecutor) Kind() string { return "stub-sandbox" }
func (e *StubExecutor) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationContainer, SupportsStream: true, SupportsProjectSeed: true}
}
func (e *StubExecutor) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, fmt.Errorf("%s runs nothing", e.IDValue)
}
func (e *StubExecutor) Signal(context.Context, string, executor.Signal) error { return nil }
func (e *StubExecutor) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, nil
}
func (e *StubExecutor) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	return nil, fmt.Errorf("%s runs nothing", e.IDValue)
}
func (e *StubExecutor) HealthCheck(context.Context) error { return nil }

// ── the identity provider ───────────────────────────────────────────────────

// IdP is a minimal OpenID provider. Its authorization endpoint answers at
// once with a code for whoever it is currently set to be, and its token
// endpoint signs an ID token for the identity that code was issued to, with a
// refresh grant of its own.
type IdP struct {
	t      testing.TB
	key    *rsa.PrivateKey
	server *httptest.Server

	mu      sync.Mutex
	email   string
	sub     string
	groups  []string
	n       int
	codes   map[string]identity
	refresh map[string]identity

	// The provider's own sign-in, which its ID tokens report as auth_time
	// (Task 20448). signedInAt zero means every token says "just now"; set,
	// it is when the person last typed a password here, and an authorization
	// request with prompt=login or max_age=0 moves it to now — the provider
	// asked — unless ignorePrompt. omitAuthTime is a provider that reports no
	// auth_time at all (Entra ID without the optional claim).
	signedInAt   time.Time
	ignorePrompt bool
	omitAuthTime bool
	loginPrompts int
	// now is the clock auth_time is read from: the hub's when a test moves
	// it (Options.Clock), so "just now" at the provider is just now to the
	// hub too. iat and exp stay on the real clock, which the hub checks them
	// against.
	now func() time.Time
}

type identity struct {
	email, sub, nonce string
	groups            []string
	authTime          time.Time
}

var (
	keyOnce sync.Once
	keyVal  *rsa.PrivateKey
	keyErr  error
)

// sharedKey is generated once per test binary: 2048-bit RSA key generation
// is slow under -race, and nothing depends on the providers' keys differing.
func sharedKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() { keyVal, keyErr = rsa.GenerateKey(rand.Reader, 2048) })
	if keyErr != nil {
		t.Fatalf("rsa key: %v", keyErr)
	}
	return keyVal
}

// NewIdP starts a provider, stopped with the test.
func NewIdP(t testing.TB) *IdP {
	t.Helper()
	idp := &IdP{t: t, key: sharedKey(t), codes: map[string]identity{}, refresh: map[string]identity{},
		email: "nobody@example.com", sub: "sub-nobody"}
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
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		idp.mu.Lock()
		idp.n++
		code := fmt.Sprintf("code-%d", idp.n)
		now := time.Now
		if idp.now != nil {
			now = idp.now
		}
		if q.Get("prompt") == "login" || q.Get("max_age") == "0" {
			idp.loginPrompts++
			if !idp.ignorePrompt && !idp.signedInAt.IsZero() {
				idp.signedInAt = now()
			}
		}
		authTime := idp.signedInAt
		if authTime.IsZero() {
			authTime = now()
		}
		if idp.omitAuthTime {
			authTime = time.Time{}
		}
		idp.codes[code] = identity{email: idp.email, sub: idp.sub, groups: append([]string(nil), idp.groups...),
			nonce: q.Get("nonce"), authTime: authTime}
		idp.mu.Unlock()
		cb, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		cq := cb.Query()
		cq.Set("code", code)
		cq.Set("state", q.Get("state"))
		cb.RawQuery = cq.Encode()
		http.Redirect(w, r, cb.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		idp.mu.Lock()
		var id identity
		var ok bool
		refresh := r.PostForm.Get("refresh_token")
		switch r.PostForm.Get("grant_type") {
		case "authorization_code":
			code := r.PostForm.Get("code")
			id, ok = idp.codes[code]
			delete(idp.codes, code)
			refresh = "rt-" + code
			if ok {
				idp.refresh[refresh] = identity{email: id.email, sub: id.sub, groups: id.groups, authTime: id.authTime}
			}
		case "refresh_token":
			id, ok = idp.refresh[refresh]
			id.nonce = ""
		}
		idp.mu.Unlock()
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
			return
		}
		claims := map[string]any{
			"iss": idp.server.URL, "sub": id.sub, "aud": ClientID,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"email": id.email, "name": strings.Split(id.email, "@")[0],
		}
		if !id.authTime.IsZero() {
			claims["auth_time"] = id.authTime.Unix()
		}
		if id.nonce != "" {
			claims["nonce"] = id.nonce
		}
		if len(id.groups) > 0 {
			claims["groups"] = id.groups
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
			"id_token": idp.sign(claims), "refresh_token": refresh,
		})
	})
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

// URL is the provider's issuer URL.
func (idp *IdP) URL() string { return idp.server.URL }

// SetIdentity sets who the next sign-in is.
func (idp *IdP) SetIdentity(email string, groups ...string) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.email, idp.groups = email, groups
	idp.sub = "sub-" + strings.NewReplacer("@", "-at-", ".", "-").Replace(email)
}

// SetSignedInAt sets when the provider last asked the person to sign in: the
// auth_time its tokens report until an authorization request asks for
// prompt=login (Task 20448). The zero time restores "just now" on every token.
func (idp *IdP) SetSignedInAt(t time.Time) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.signedInAt = t
}

// SetAuthTimeBehaviour sets whether tokens omit auth_time, and whether the
// provider ignores prompt=login and answers from its own session anyway.
func (idp *IdP) SetAuthTimeBehaviour(omit, ignorePrompt bool) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.omitAuthTime, idp.ignorePrompt = omit, ignorePrompt
}

// LoginPrompts counts authorization requests that asked for prompt=login.
func (idp *IdP) LoginPrompts() int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.loginPrompts
}

func (idp *IdP) sign(claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1"})
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, idp.key, crypto.SHA256, digest[:])
	if err != nil {
		idp.t.Fatalf("sign: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}
