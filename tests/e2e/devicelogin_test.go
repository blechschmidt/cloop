package e2e_test

// `cloop login` end to end (Task 20412): a real hub with single sign-on
// against a fake identity provider, the built ./cloop binary in subprocesses
// for every terminal command, and the approval made in real Chrome when one is
// installed.
//
// The hub runs in this test's process — ui.New plus the wiring `cloop ui`
// does for single sign-on — rather than as `cloop ui` in a subprocess, for one
// reason: attaching needs a running task's sandbox, and the only sandbox a test
// can conjure without a container runtime is a fake executor registered in the
// hub's own process. Everything the terminal touches is real: its HTTP
// requests, the hub's middleware and routes, the session store on disk, the
// WebSocket streams, and the identity provider round trips.
//
// The run whose output `cloop remote logs --follow` tails is real too: the
// hub dispatches it to the host executor, with the hub's binary swapped for a
// short shell script (Server.SelfExe) so no AI provider is involved.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/ui"
)

const deviceUser = "alice@example.com"

// ── a fake identity provider ────────────────────────────────────────────────

// deviceIdP answers every authorization request at once with a code, and its
// token endpoint mints an id_token for whoever it is currently configured to
// be — a fresh refresh token per code, so a terminal's session gets a grant of
// its own, as from a real provider.
type deviceIdP struct {
	t      *testing.T
	key    *rsa.PrivateKey
	server *httptest.Server

	mu         sync.Mutex
	nonces     map[string]string
	n          int
	email, sub string
	groups     []string
}

func newDeviceIdP(t *testing.T) *deviceIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &deviceIdP{t: t, key: key, nonces: map[string]string{}, email: deviceUser, sub: "sub-alice"}
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
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		idp.mu.Lock()
		idp.n++
		code := fmt.Sprintf("code-%d", idp.n)
		idp.nonces[code] = q.Get("nonce")
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
		defer idp.mu.Unlock()
		claims := map[string]any{
			"iss": idp.server.URL, "sub": idp.sub, "aud": "cloop-e2e",
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"email": idp.email, "name": "Alice",
		}
		if len(idp.groups) > 0 {
			claims["groups"] = idp.groups
		}
		refresh := r.PostForm.Get("refresh_token")
		if r.PostForm.Get("grant_type") == "authorization_code" {
			nonce, ok := idp.nonces[r.PostForm.Get("code")]
			if !ok {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			delete(idp.nonces, r.PostForm.Get("code"))
			claims["nonce"] = nonce
			claims["auth_time"] = time.Now().Unix()
			refresh = "rt-" + r.PostForm.Get("code")
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

func (idp *deviceIdP) sign(claims map[string]any) string {
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

// ── a sandbox to attach to ──────────────────────────────────────────────────

// greetingExecutor isolates, and each session it opens says hello and then
// stays open until it is closed — enough for a real terminal to attach to.
type greetingExecutor struct{ id string }

func (e *greetingExecutor) ID() string   { return e.id }
func (e *greetingExecutor) Kind() string { return "greeting-fake" }
func (e *greetingExecutor) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationContainer}
}
func (e *greetingExecutor) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, errors.New("greeting-fake runs nothing")
}
func (e *greetingExecutor) Signal(context.Context, string, executor.Signal) error { return nil }
func (e *greetingExecutor) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, nil
}
func (e *greetingExecutor) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	return nil, errors.New("greeting-fake runs nothing")
}
func (e *greetingExecutor) HealthCheck(context.Context) error { return nil }
func (e *greetingExecutor) Attach(context.Context, executor.AttachRequest) (executor.AttachConn, error) {
	return &greetingConn{greeting: []byte("hello from the sandbox\r\n"), closed: make(chan struct{})}, nil
}

type greetingConn struct {
	mu       sync.Mutex
	greeting []byte
	once     sync.Once
	closed   chan struct{}
}

func (c *greetingConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.greeting) > 0 {
		n := copy(p, c.greeting)
		c.greeting = c.greeting[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	<-c.closed
	return 0, io.EOF
}
func (c *greetingConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *greetingConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *greetingConn) Resize(uint16, uint16) error { return nil }

// ── the hub ─────────────────────────────────────────────────────────────────

type deviceHub struct {
	srv  *ui.Server
	ts   *httptest.Server
	idp  *deviceIdP
	dir  string
	home string
}

func startDeviceHub(t *testing.T) *deviceHub {
	t.Helper()
	// Nothing this test runs may touch the real home directory: the hub's
	// project registry and the terminal's credential file both live there.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	// The session store seals refresh tokens with it, which is what lets the
	// hub re-check a terminal's session with the identity provider.
	t.Setenv(secretbroker.EnvPassphraseKey, "e2e-device-login-passphrase")

	idp := newDeviceIdP(t)
	dir := filepath.Join(t.TempDir(), "terminal-project")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Init(dir, "Ship terminal sign-in", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}

	srv := ui.New(dir, 0, "")
	srv.RPS, srv.Burst = 10000, 10000
	// The run `cloop remote run` starts: two lines of output, then waiting
	// to be stopped.
	harness := filepath.Join(t.TempDir(), "harness.sh")
	if err := os.WriteFile(harness, []byte("#!/bin/sh\n"+
		"echo 'hello from the harness: step one'\n"+
		"echo 'hello from the harness: step two'\n"+
		"exec sleep 120\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	srv.SelfExe = harness
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	store, warn := srv.OpenSessionStore()
	if warn != nil {
		t.Fatalf("the session store is not durable: %v", warn)
	}
	cfg := oidcauth.Config{
		Enabled:     true,
		Issuer:      idp.server.URL,
		ClientID:    "cloop-e2e",
		RedirectURL: ts.URL + "/auth/callback",
		AdminEmails: []string{deviceUser},
		DeviceLogin: true,
		Store:       store,
		Audit:       srv.SessionAuditSink(),
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
	resolver, err := authz.New(authz.Config{AdminEmails: []string{deviceUser}, Runtime: roles})
	if err != nil {
		t.Fatal(err)
	}
	srv.Authz = resolver
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	// Task 1 is running in a sandbox the hub can open a terminal in.
	execID := "greeting-" + strings.ReplaceAll(t.Name(), "/", "-")
	if err := executor.Register(&greetingExecutor{id: execID}); err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(execID) })
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.OpenExecutorSession(statedb.ExecutorSessionRow{
		ID: "sess-greeting", ExecutorID: execID, HandleID: "h-greeting", ProjectPath: dir,
		TaskID: 1, ClaimToken: "tok", State: "running", Attempt: 1, StartedAt: time.Now(),
	}); err != nil {
		t.Fatalf("OpenExecutorSession: %v", err)
	}
	return &deviceHub{srv: srv, ts: ts, idp: idp, dir: dir, home: home}
}

// ── the terminal ────────────────────────────────────────────────────────────

// syncBuffer is a bytes.Buffer two goroutines may share.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// cloopProc is one cloop command running in the background.
type cloopProc struct {
	args           []string
	cmd            *exec.Cmd
	stdout, stderr *syncBuffer
	done           chan struct{}
	err            error
}

// terminalEnv is the environment every cloop subprocess runs with: the test's
// home, no hub or token from the developer's own shell, no colour.
func (h *deviceHub) terminalEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		switch k, _, _ := strings.Cut(kv, "="); k {
		case "HOME", "XDG_CONFIG_HOME", "CLOOP_HUB_URL", "CLOOP_API_TOKEN", secretbroker.EnvPassphraseKey:
			continue
		}
		env = append(env, kv)
	}
	return append(env, "HOME="+h.home, "XDG_CONFIG_HOME="+filepath.Join(h.home, ".config"), "NO_COLOR=1", "TERM=dumb")
}

func (h *deviceHub) start(t *testing.T, args ...string) *cloopProc {
	t.Helper()
	return h.startIn(t, t.TempDir(), args...) // no .cloop: nothing local for the command to find
}

// startIn is start in dir: a checkout, for `cloop remote init`.
func (h *deviceHub) startIn(t *testing.T, dir string, args ...string) *cloopProc {
	t.Helper()
	p := &cloopProc{args: args, stdout: &syncBuffer{}, stderr: &syncBuffer{}, done: make(chan struct{})}
	p.cmd = exec.Command(binaryPath(t), args...)
	p.cmd.Dir = dir
	p.cmd.Env = h.terminalEnv()
	p.cmd.Stdout, p.cmd.Stderr = p.stdout, p.stderr
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start cloop %v: %v", args, err)
	}
	go func() {
		p.err = p.cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			_ = p.cmd.Process.Kill()
			<-p.done
		}
	})
	return p
}

// run runs a cloop command to completion.
func (h *deviceHub) run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	p := h.start(t, args...)
	p.wait(t, 60*time.Second)
	return p.stdout.String() + p.stderr.String(), p.err
}

// wait waits for the process to exit.
func (p *cloopProc) wait(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(within):
		t.Fatalf("cloop %v still running after %s\nstdout:\n%s\nstderr:\n%s", p.args, within, p.stdout, p.stderr)
	}
}

// await waits for re to match what the process has written.
func (p *cloopProc) await(t *testing.T, re *regexp.Regexp, within time.Duration) []string {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if m := re.FindStringSubmatch(p.stdout.String() + p.stderr.String()); m != nil {
			return m
		}
		select {
		case <-p.done:
			if m := re.FindStringSubmatch(p.stdout.String() + p.stderr.String()); m != nil {
				return m
			}
			t.Fatalf("cloop %v exited (%v) before writing %s\nstdout:\n%s\nstderr:\n%s", p.args, p.err, re, p.stdout, p.stderr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("cloop %v did not write %s within %s\nstdout:\n%s\nstderr:\n%s", p.args, re, within, p.stdout, p.stderr)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// ── the person at the browser ───────────────────────────────────────────────

// deviceChromeCandidates are where this project's machines keep Chrome, and
// then PATH — the list pkg/ui's browser tests use.
var deviceChromeCandidates = []string{
	"/opt/cft/chrome-linux64/chrome",
	"/root/.cache/puppeteer/chrome/linux-*/chrome-linux64/chrome",
	"/root/.cache/ms-playwright/chromium-*/chrome-linux64/chrome",
	"/root/.cache/ms-playwright/chromium-*/chrome-linux/chrome",
}

func findDeviceChrome() string {
	for _, pat := range deviceChromeCandidates {
		matches, _ := filepath.Glob(pat)
		for _, m := range matches {
			if st, err := os.Stat(m); err == nil && !st.IsDir() {
				return m
			}
		}
	}
	for _, name := range []string{"google-chrome", "chromium", "chromium-browser"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// browserResult is what testdata/device_approve.js reports.
type browserResult struct {
	RequestShown   bool     `json:"request_shown"`
	Finished       bool     `json:"finished"`
	ShownCode      string   `json:"shown_code"`
	Who            string   `json:"who"`
	FromHost       string   `json:"from_host"`
	FromIP         string   `json:"from_ip"`
	Warning        string   `json:"warning"`
	NetworkNote    string   `json:"network_note"`
	StatusText     string   `json:"status_text"`
	Landed         string   `json:"landed"`
	Final          string   `json:"final"`
	CSPViolations  []string `json:"csp_violations"`
	ConsoleErrors  []string `json:"console_errors"`
	Error          string   `json:"error"`
	usedTheBrowser bool
}

// decide opens link and approves or denies the code there: in Chrome when the
// machine has it and node to drive it, and otherwise as an HTTP client with a
// cookie jar walking the same redirects — so the terminal half of this test
// runs everywhere, and the page half wherever it can.
func (h *deviceHub) decide(t *testing.T, link, action string) browserResult {
	t.Helper()
	chrome := findDeviceChrome()
	// CLOOP_E2E_NO_BROWSER=1 takes the HTTP path on a machine that has a
	// browser, so the fallback CI may take is itself exercised.
	if os.Getenv("CLOOP_E2E_NO_BROWSER") == "1" {
		chrome = ""
	}
	node, nodeErr := exec.LookPath("node")
	if nodeErr == nil {
		// The driver speaks CDP over node's built-in WebSocket, which only
		// node 22 and later have.
		if err := exec.Command(node, "-e", "process.exit(typeof WebSocket === 'function' ? 0 : 1)").Run(); err != nil {
			nodeErr = fmt.Errorf("%s has no built-in WebSocket (node 22 or later is needed)", node)
		}
	}
	if chrome != "" && nodeErr == nil && runtime.GOOS == "linux" {
		_, thisFile, _, _ := runtime.Caller(0)
		driver := filepath.Join(filepath.Dir(thisFile), "testdata", "device_approve.js")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, node, driver, chrome, link, action)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		var res browserResult
		if jerr := json.Unmarshal(bytes.TrimSpace(out), &res); jerr != nil {
			t.Fatalf("the browser driver printed %q (%v); stderr:\n%s", out, err, stderr.String())
		}
		if res.Error != "" || err != nil {
			t.Fatalf("the browser driver failed: %s (%v)\n%s", res.Error, err, stderr.String())
		}
		res.usedTheBrowser = true
		return res
	}
	t.Logf("no Chrome or node here (chrome=%q, node: %v): deciding over HTTP instead", chrome, nodeErr)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	// Sign in, as the browser is sent to on its first visit.
	req, _ := http.NewRequest(http.MethodGet, link, nil)
	req.Header.Set("Accept", "text/html")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	code := u.Query().Get("code")
	body, _ := json.Marshal(map[string]string{"user_code": code})
	post := func(path string) map[string]any {
		r, _ := http.NewRequest(http.MethodPost, h.ts.URL+path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST %s = %d %v", path, resp.StatusCode, out)
		}
		return out
	}
	view := post("/api/device/lookup")
	res := browserResult{RequestShown: true, ShownCode: fmt.Sprint(view["user_code"]), FromHost: fmt.Sprint(view["client_hostname"])}
	if action == "deny" {
		post("/api/device/deny")
		res.Finished, res.StatusText = true, "Denied"
		return res
	}
	ap := post("/api/device/approve")
	resp, err = c.Get(fmt.Sprint(ap["redirect"]))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	res.Finished = resp.StatusCode == http.StatusOK && resp.Request.URL.Path == oidcauth.DevicePath
	res.StatusText = "Approved"
	return res
}

// ── the test ────────────────────────────────────────────────────────────────

var (
	reApprovalLink = regexp.MustCompile(`\(or open (http\S+/device\?code=\S+)\)`)
	reUserCode     = regexp.MustCompile(`enter the code\s+([B-Z]{5}-[B-Z]{5})`)
)

// TestE2ETerminalSignsInToAnSSOHub is the whole of it: `cloop login` approved
// in a browser, the commands that use the session, and revocation reaching
// what the session holds open.
func TestE2ETerminalSignsInToAnSSOHub(t *testing.T) {
	h := startDeviceHub(t)
	credPath := filepath.Join(h.home, ".config", "cloop", "hubs.json")

	// ── sign in ──
	login := h.start(t, "login", h.ts.URL, "--no-browser", "--hostname", "e2e-laptop")
	link := login.await(t, reApprovalLink, 30*time.Second)[1]
	code := login.await(t, reUserCode, 5*time.Second)[1]
	res := h.decide(t, link, "approve")
	if !res.RequestShown || !res.Finished {
		t.Fatalf("the approval did not complete: %+v", res)
	}
	if res.ShownCode != code || res.FromHost != "e2e-laptop" {
		t.Errorf("the page showed code %q from %q; the terminal printed %q from e2e-laptop", res.ShownCode, res.FromHost, code)
	}
	if res.usedTheBrowser {
		if !strings.Contains(res.Warning, "Only approve a code you started yourself") || !strings.Contains(res.Who, deviceUser) {
			t.Errorf("the page's warning %q / identity %q", res.Warning, res.Who)
		}
		if len(res.CSPViolations) > 0 || len(res.ConsoleErrors) > 0 {
			t.Errorf("the approval page broke its own policy or threw: CSP %v, console %v", res.CSPViolations, res.ConsoleErrors)
		}
	}
	login.wait(t, 90*time.Second)
	if login.err != nil || !strings.Contains(login.stdout.String(), "Signed in to "+h.ts.URL+" as "+deviceUser) {
		t.Fatalf("cloop login: %v\nstdout:\n%s\nstderr:\n%s", login.err, login.stdout, login.stderr)
	}
	fi, err := os.Stat(credPath)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("credential file %s: mode %v, %v; want 0600", credPath, fi.Mode().Perm(), err)
	}
	raw, _ := os.ReadFile(credPath)
	if strings.Contains(login.stdout.String()+login.stderr.String(), credentialIn(raw)) {
		t.Fatal("cloop login echoed the credential")
	}

	// ── use it ──
	out, err := h.run(t, "whoami")
	if err != nil || !strings.Contains(out, deviceUser) || !strings.Contains(out, "cli (e2e-laptop)") {
		t.Fatalf("cloop whoami: %v\n%s", err, out)
	}
	out, err = h.run(t, "remote", "projects")
	if err != nil || !strings.Contains(out, "terminal-project") {
		t.Fatalf("cloop remote projects: %v\n%s", err, out)
	}
	out, err = h.run(t, "remote", "add", "terminal-project", "A task from the terminal", "--description", "added by cloop remote")
	if err != nil || !strings.Contains(out, "Added task #") {
		t.Fatalf("cloop remote add: %v\n%s", err, out)
	}
	out, err = h.run(t, "remote", "tasks", "terminal-project")
	if err != nil || !strings.Contains(out, "A task from the terminal") {
		t.Fatalf("cloop remote tasks: %v\n%s", err, out)
	}
	out, err = h.run(t, "remote", "run", "terminal-project")
	if err != nil || !strings.Contains(out, "Started terminal-project") {
		t.Fatalf("cloop remote run: %v\n%s", err, out)
	}
	logs := h.start(t, "remote", "logs", "terminal-project", "--follow")
	logs.await(t, regexp.MustCompile(`hello from the harness: step two`), 60*time.Second)

	attach := h.start(t, "task", "attach", "1")
	attach.await(t, regexp.MustCompile(`hello from the sandbox`), 30*time.Second)

	out, err = h.run(t, "remote", "stop", "terminal-project")
	if err != nil {
		t.Fatalf("cloop remote stop: %v\n%s", err, out)
	}
	logs.await(t, regexp.MustCompile(`run stopped`), 60*time.Second)

	// ── revoke it: what it holds open closes ──
	sessionID := sessionIDIn(raw)
	if ok, err := h.srv.OIDC.RevokeSession(sessionID, "security@example.com", ""); err != nil || !ok {
		t.Fatalf("RevokeSession(%s) = %v, %v", sessionID, ok, err)
	}
	logs.wait(t, 30*time.Second)
	if logs.err == nil || !strings.Contains(logs.stderr.String(), "cloop login") {
		t.Errorf("logs --follow after revocation: exit %v, stderr:\n%s", logs.err, logs.stderr)
	}
	attach.wait(t, 30*time.Second)
	if !strings.Contains(attach.stdout.String()+attach.stderr.String(), "session") {
		t.Errorf("the attached terminal closed without saying why:\n%s%s", attach.stdout, attach.stderr)
	}
	out, err = h.run(t, "whoami")
	if err == nil || !strings.Contains(out, "has ended") {
		t.Fatalf("whoami after revocation: %v\n%s", err, out)
	}
	out, err = h.run(t, "logout")
	if err != nil || !strings.Contains(out, "already ended") {
		t.Fatalf("logout after revocation: %v\n%s", err, out)
	}
	if _, err := os.Stat(credPath); !os.IsNotExist(err) {
		t.Fatal("logout left the credential file behind")
	}

	// ── a denial ──
	login = h.start(t, "login", h.ts.URL, "--no-browser")
	link = login.await(t, reApprovalLink, 30*time.Second)[1]
	if res := h.decide(t, link, "deny"); !res.Finished {
		t.Fatalf("the denial did not complete: %+v", res)
	}
	login.wait(t, 90*time.Second)
	if login.err == nil || !strings.Contains(login.stderr.String(), "denied") {
		t.Fatalf("cloop login after a denial: %v\n%s", login.err, login.stderr)
	}
	if _, err := os.Stat(credPath); !os.IsNotExist(err) {
		t.Fatal("a denied login wrote credentials")
	}

	// ── a credential file other users can read is refused ──
	if err := os.MkdirAll(filepath.Dir(credPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(credPath, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = h.run(t, "whoami")
	if err == nil || !strings.Contains(out, "logout --all") || strings.Contains(out, credentialIn(raw)) {
		t.Fatalf("whoami with a world-readable credential file: %v\n%s", err, out)
	}
}

// credentialIn and sessionIDIn read the single hub entry of a credential file.
func credentialIn(raw []byte) string { return hubField(raw, "credential") }
func sessionIDIn(raw []byte) string  { return hubField(raw, "session_id") }

func hubField(raw []byte, field string) string {
	var f struct {
		Hubs map[string]map[string]any `json:"hubs"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return ""
	}
	for _, h := range f.Hubs {
		if v, ok := h[field].(string); ok && v != "" {
			return v
		}
	}
	return "\x00no such field"
}
