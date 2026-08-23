// End-to-end tests for the branch allowlist, driven by a real git client
// against a real git server.
//
// The unit tests in this package feed hand-built pkt-lines to ParseReceivePack
// and hand-built RefUpdates to Policy.Decide. Both are necessary and neither
// proves the thing the package exists to claim: that a sandbox running the git
// binary, speaking the smart-HTTP protocol it actually speaks, cannot move a
// branch outside its allowlist. A parser that mis-frames a real push, a refusal
// git does not recognise as a refusal, or a capability negotiation that lands
// the client in a dialect the proxy does not answer would all pass the unit
// tests and lose the boundary.
//
// So the topology here is the production one, end to end:
//
//	git ──session token──▶ gitproxy ──PAT──▶ git-http-backend ──▶ bare repo
//
// The forge is a real git-http-backend run as CGI behind TLS, and it demands
// the PAT — so a push that reaches the bare repo is a push the proxy chose to
// authenticate, and every assertion about upstream state is an assertion about
// a real repository rather than about a mock's recorded calls.
package gitproxy_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
)

// The fixture repository. The owner/name shape is load-bearing: both
// gitproxy.UpstreamRepoPath and the proxy's own routing require exactly two
// path components, because that is what pkg/executor matches grants against.
const (
	forgeOwner = "acme"
	forgeName  = "tool"

	// The credential the proxy holds and the sandbox must never see. The forge
	// rejects any request without it, which is what makes "the ref did not
	// move" evidence that the proxy declined to forward rather than evidence
	// that the forge happened to be unreachable.
	forgeUser = "forge-bot"
	forgePAT  = "forge-pat-do-not-leak-3Qv8"

	// gitTimeout bounds one git invocation. A hung clone should name itself
	// rather than wait for the package-level test timeout.
	gitTimeout = 2 * time.Minute
)

// --- locating the tools ------------------------------------------------------

// gitTools finds the git binary and git-http-backend, or skips.
//
// git-http-backend lives in git's exec-path, which is distribution-specific
// (/usr/lib/git-core on Debian, /usr/libexec/git-core on Fedora and macOS), so
// ask git where it keeps its helpers before guessing.
func gitTools(t *testing.T) (gitBin, backend string) {
	t.Helper()

	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git binary on PATH; this suite drives a real git client")
	}

	var candidates []string
	if out, err := exec.Command(gitBin, "--exec-path").Output(); err == nil {
		candidates = append(candidates, filepath.Join(strings.TrimSpace(string(out)), "git-http-backend"))
	}
	candidates = append(candidates,
		"/usr/lib/git-core/git-http-backend",
		"/usr/libexec/git-core/git-http-backend",
	)
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() && st.Mode().Perm()&0o111 != 0 {
			return gitBin, c
		}
	}
	t.Skipf("git-http-backend not found (looked in %s); this suite needs a real git smart-HTTP server",
		strings.Join(candidates, ", "))
	return "", ""
}

// --- harness -----------------------------------------------------------------

// harness is one isolated forge + proxy + client triple.
//
// Every test builds its own so that the event log, the clock and the upstream
// refs belong to exactly one test: an assertion like "refs/heads/main did not
// move" means nothing if a sibling test could have moved it.
type harness struct {
	gitBin  string
	backend string

	projectRoot string // GIT_PROJECT_ROOT: holds <owner>/<name>.git
	bare        string // the upstream bare repository
	forgeHome   string // $HOME for server-side git
	clientHome  string // $HOME for client-side git
	scratch     string // cwd for git invocations that need no repository

	forge    *httptest.Server
	proxySrv *httptest.Server
	reg      *gitproxy.Registry

	upstream string // https://<forge>/acme/tool.git — never reaches the client

	// clock is the registry's injectable time source, as nanoseconds, so a TTL
	// can be crossed without sleeping.
	clock atomic.Int64

	mu     sync.Mutex
	events []gitproxy.Event
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	gitBin, backend := gitTools(t)
	h := &harness{
		gitBin:      gitBin,
		backend:     backend,
		projectRoot: t.TempDir(),
		forgeHome:   t.TempDir(),
		clientHome:  t.TempDir(),
		scratch:     t.TempDir(),
	}
	h.clock.Store(time.Now().UnixNano())
	h.bare = filepath.Join(h.projectRoot, forgeOwner, forgeName+".git")

	h.initUpstream(t)
	h.startForge(t)
	h.startProxy(t)
	return h
}

// initUpstream creates the bare repository and seeds it with a commit on main.
func (h *harness) initUpstream(t *testing.T) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(h.bare), 0o755); err != nil {
		t.Fatalf("creating the forge owner directory: %v", err)
	}
	h.mustGit(t, "", nil, "init", "--bare", h.bare)
	// Name the default branch explicitly rather than relying on the git
	// version's default, which changed and is what this suite calls "main".
	h.mustGit(t, "", nil, "--git-dir="+h.bare, "symbolic-ref", "HEAD", "refs/heads/main")
	// git-http-backend serves receive-pack only when http.receivepack says so
	// (or REMOTE_USER is set); say so, so a refused push is refused by the
	// proxy and not by the forge declining to offer the service at all.
	h.mustGit(t, "", nil, "--git-dir="+h.bare, "config", "http.receivepack", "true")
	h.mustGit(t, "", nil, "--git-dir="+h.bare, "config", "http.uploadpack", "true")

	// Seed over the filesystem, not over HTTP: the seed is fixture setup and
	// must not depend on the path under test.
	seed := t.TempDir()
	h.mustGit(t, "", nil, "init", seed)
	h.mustGit(t, seed, nil, "symbolic-ref", "HEAD", "refs/heads/main")
	if err := os.WriteFile(filepath.Join(seed, "README.md"), []byte("seed\n"), 0o644); err != nil {
		t.Fatalf("writing the seed file: %v", err)
	}
	h.mustGit(t, seed, nil, "add", "README.md")
	h.mustGit(t, seed, nil, append(identity(), "commit", "--no-gpg-sign", "-m", "seed")...)
	h.mustGit(t, seed, nil, "push", h.bare, "HEAD:refs/heads/main")
}

// startForge serves the bare repository over TLS via git-http-backend as CGI.
func (h *harness) startForge(t *testing.T) {
	t.Helper()
	h.forge = httptest.NewTLSServer(http.HandlerFunc(h.serveForge))
	t.Cleanup(h.forge.Close)
	h.upstream = h.forge.URL + "/" + forgeOwner + "/" + forgeName + ".git"
}

// startProxy stands the proxy up in front of the forge.
//
// The registry's BaseURL must be the proxy's own URL, and the proxy needs the
// registry — so the listener comes up first behind an indirection, and the real
// handler is installed once the URL is known. The atomic keeps that safe under
// -race even though nothing can dial the port before StartTLS returns.
func (h *harness) startProxy(t *testing.T) {
	t.Helper()

	var installed atomic.Value // http.Handler
	h.proxySrv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler, _ := installed.Load().(http.Handler)
		if handler == nil {
			http.Error(w, "proxy handler not installed yet", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	h.proxySrv.StartTLS()
	t.Cleanup(h.proxySrv.Close)

	reg, err := gitproxy.NewRegistry(h.proxySrv.URL)
	if err != nil {
		t.Fatalf("NewRegistry(%q): %v", h.proxySrv.URL, err)
	}
	reg.Now = h.now
	reg.OnEvent = h.record
	h.reg = reg

	// The proxy's upstream leg has to trust the forge's self-signed test cert.
	// That is exactly the case Options.Transport exists for.
	px, err := gitproxy.New(reg, gitproxy.Options{Transport: h.forge.Client().Transport})
	if err != nil {
		t.Fatalf("gitproxy.New: %v", err)
	}
	installed.Store(http.Handler(px))
}

// --- the forge ---------------------------------------------------------------

// serveForge is the fake forge: basic auth, then git-http-backend as CGI.
//
// net/http/cgi cannot be used here — it refuses a chunked request body, and the
// proxy deliberately sends one because neither the client's Content-Length nor
// its Content-Encoding still describes the bytes it forwards. A real forge
// behind nginx or Apache handles chunked fine, so the CGI plumbing is done by
// hand rather than by weakening what the proxy sends.
func (h *harness) serveForge(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok || user != forgeUser || pass != forgePAT {
		w.Header().Set("WWW-Authenticate", `Basic realm="forge"`)
		http.Error(w, "forge: missing or wrong credential", http.StatusUnauthorized)
		return
	}

	env := []string{
		"GATEWAY_INTERFACE=CGI/1.1",
		"SERVER_PROTOCOL=HTTP/1.1",
		"SERVER_SOFTWARE=cloop-test-forge",
		"REQUEST_METHOD=" + r.Method,
		"QUERY_STRING=" + r.URL.RawQuery,
		"PATH_INFO=" + r.URL.Path,
		"REMOTE_ADDR=" + r.RemoteAddr,
		"REMOTE_USER=" + user,
		"GIT_PROJECT_ROOT=" + h.projectRoot,
		"GIT_HTTP_EXPORT_ALL=1",
		"HOME=" + h.forgeHome,
		"PATH=" + os.Getenv("PATH"),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"LC_ALL=C",
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		env = append(env, "CONTENT_TYPE="+ct)
	}
	if r.ContentLength > 0 {
		env = append(env, "CONTENT_LENGTH="+strconv.FormatInt(r.ContentLength, 10))
	}
	// Without CONTENT_LENGTH git-http-backend reads stdin to EOF, which is what
	// a chunked body gives it.
	if v := r.Header.Get("Content-Encoding"); v != "" {
		env = append(env, "HTTP_CONTENT_ENCODING="+v)
	}
	// git-http-backend reads the protocol version from GIT_PROTOCOL, not from
	// the header, so protocol v2 only reaches it if it is mapped explicitly.
	if v := r.Header.Get("Git-Protocol"); v != "" {
		env = append(env, "GIT_PROTOCOL="+v)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(r.Context(), h.backend)
	cmd.Env = env
	cmd.Dir = h.projectRoot
	cmd.Stdin = r.Body
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	// git-http-backend reports its own failures as a CGI response with a Status
	// header, so parse first and only fall back to 500 if there is no parsable
	// response at all.
	br := bufio.NewReader(bytes.NewReader(stdout.Bytes()))
	header, err := textproto.NewReader(br).ReadMIMEHeader()
	if err != nil {
		http.Error(w, fmt.Sprintf("forge: git-http-backend produced no CGI response (%v): %s",
			runErr, stderr.String()), http.StatusInternalServerError)
		return
	}

	status := http.StatusOK
	if s := header.Get("Status"); s != "" {
		if code, err := strconv.Atoi(strings.Fields(s)[0]); err == nil {
			status = code
		}
		header.Del("Status")
	}
	for k, vs := range header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(status)
	_, _ = io.Copy(w, br)
}

// --- clock and events --------------------------------------------------------

func (h *harness) now() time.Time { return time.Unix(0, h.clock.Load()) }

// advance moves the registry's clock forward without sleeping.
func (h *harness) advance(d time.Duration) { h.clock.Add(int64(d)) }

func (h *harness) record(e gitproxy.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, e)
}

// eventsOf returns every recorded event of one kind.
func (h *harness) eventsOf(kind gitproxy.EventKind) []gitproxy.Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []gitproxy.Event
	for _, e := range h.events {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// eventLog renders the whole trail for a failure message.
func (h *harness) eventLog() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var b strings.Builder
	for _, e := range h.events {
		b.WriteString("\n\t" + e.String())
	}
	return b.String()
}

// --- git driver --------------------------------------------------------------

// clientEnv is the environment every client-side git runs in.
//
// It is closed rather than inherited: a ~/.gitconfig with a credential helper,
// an insteadOf rewrite or a proxy would decide the outcome of these tests
// instead of the policy under test. GIT_SSL_NO_VERIFY is the one concession,
// and it is unavoidable with httptest's self-signed certificates.
func (h *harness) clientEnv() []string {
	return []string{
		"HOME=" + h.clientHome,
		"XDG_CONFIG_HOME=" + filepath.Join(h.clientHome, ".config"),
		"PATH=" + os.Getenv("PATH"),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/nonexistent",
		"SSH_ASKPASS=/nonexistent",
		"GIT_SSL_NO_VERIFY=true",
		"LC_ALL=C",
	}
}

// identity supplies a committer without touching any config file.
func identity() []string {
	return []string{"-c", "user.email=cloop@example.invalid", "-c", "user.name=cloop test"}
}

// git runs one git command and returns its combined output.
func (h *harness) git(t *testing.T, dir string, extraEnv []string, args ...string) (string, error) {
	t.Helper()
	if dir == "" {
		dir = h.scratch
	}
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, h.gitBin, args...)
	cmd.Dir = dir
	cmd.Env = append(h.clientEnv(), extraEnv...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func (h *harness) mustGit(t *testing.T, dir string, extraEnv []string, args ...string) string {
	t.Helper()
	out, err := h.git(t, dir, extraEnv, args...)
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// --- sessions ----------------------------------------------------------------

// mint creates a session for the fixture repository under pol.
func (h *harness) mint(t *testing.T, pol gitproxy.Policy, ttl time.Duration) *gitproxy.Minted {
	t.Helper()
	m, err := h.reg.Mint(gitproxy.MintRequest{
		Upstream:   h.upstream,
		Credential: gitproxy.Credential{Username: forgeUser, Password: forgePAT},
		Policy:     pol,
		TTL:        ttl,
		ProjectID:  "proj-e2e",
		TaskID:     "task-1",
		ExecutorID: "exec-1",
		Actor:      "e2e",
	})
	if err != nil {
		t.Fatalf("minting a session: %v", err)
	}
	if m.RepoURL != h.proxySrv.URL+"/"+forgeOwner+"/"+forgeName {
		t.Fatalf("session repo URL = %q, want it under the proxy", m.RepoURL)
	}
	if strings.Contains(m.RepoURL, forgePAT) || strings.Contains(m.Token, forgePAT) {
		t.Fatal("the forge PAT leaked into what the sandbox is handed")
	}
	return m
}

// credEnv delivers the session credential the way production does.
//
// This mirrors executor.GitCredentialEnv exactly: a URL-scoped http.extraHeader
// through GIT_CONFIG_COUNT, so nothing is written to disk and nothing appears
// in argv, plus an empty credential.helper so no helper can answer a challenge
// with authority the session never granted.
func (h *harness) credEnv(m *gitproxy.Minted) []string {
	c := m.Credential()
	base := h.proxySrv.URL + "/"
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password))
	return []string{
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=http." + base + ".extraHeader",
		"GIT_CONFIG_VALUE_0=Authorization: " + auth,
		"GIT_CONFIG_KEY_1=credential.helper",
		"GIT_CONFIG_VALUE_1=",
	}
}

// clone clones the session's repository through the proxy into a new directory.
func (h *harness) clone(t *testing.T, m *gitproxy.Minted) (dir, out string, err error) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "work")
	out, err = h.git(t, "", h.credEnv(m), "clone", m.RepoURL, dir)
	return dir, out, err
}

// commit writes a file and commits it, returning the new commit's object name.
func (h *harness) commit(t *testing.T, dir, name, body string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	h.mustGit(t, dir, nil, "add", name)
	h.mustGit(t, dir, nil, append(identity(), "commit", "--no-gpg-sign", "-m", "work: "+name)...)
	return strings.TrimSpace(h.mustGit(t, dir, nil, "rev-parse", "HEAD"))
}

// upstreamSHA reads a ref straight out of the bare repository. This is the only
// assertion that means anything about whether the boundary held.
func (h *harness) upstreamSHA(t *testing.T, ref string) (string, bool) {
	t.Helper()
	out, err := h.git(t, "", nil, "--git-dir="+h.bare, "rev-parse", "--verify", "--quiet", ref)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(out), true
}

// --- tests -------------------------------------------------------------------

// TestPushToAllowedBranchSucceeds is the control. Without it, every refusal
// below could be a broken harness rather than an enforced policy.
func TestPushToAllowedBranchSucceeds(t *testing.T) {
	h := newHarness(t)

	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	m := h.mint(t, pol, 0)

	dir, out, err := h.clone(t, m)
	if err != nil {
		t.Fatalf("cloning through the proxy failed: %v\n%s", err, out)
	}
	sha := h.commit(t, dir, "work.txt", "written inside the sandbox\n")

	pushOut, err := h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/cloop/task-1")
	if err != nil {
		t.Fatalf("push to an allowed branch failed: %v\n%s", err, pushOut)
	}

	got, ok := h.upstreamSHA(t, "refs/heads/cloop/task-1")
	if !ok {
		t.Fatalf("refs/heads/cloop/task-1 does not exist upstream after a successful push\npush output:\n%s", pushOut)
	}
	if got != sha {
		t.Fatalf("upstream refs/heads/cloop/task-1 = %s, want the pushed commit %s", got, sha)
	}

	// The push went through the proxy's credential, not the sandbox's: the
	// forge would have answered 401 otherwise. Check the sandbox never saw it.
	if strings.Contains(pushOut, forgePAT) || strings.Contains(out, forgePAT) {
		t.Error("the forge PAT appeared in output the sandbox can read")
	}
	cfg, err := os.ReadFile(filepath.Join(dir, ".git", "config"))
	if err != nil {
		t.Fatalf("reading the clone's config: %v", err)
	}
	if strings.Contains(string(cfg), forgePAT) || strings.Contains(string(cfg), h.forge.URL) {
		t.Errorf("the clone's config names the forge or its credential:\n%s", cfg)
	}

	allowed := h.eventsOf(gitproxy.EventPushAllowed)
	if len(allowed) != 1 {
		t.Fatalf("got %d push_allowed events, want 1%s", len(allowed), h.eventLog())
	}
	if len(allowed[0].Refs) != 1 || allowed[0].Refs[0] != "refs/heads/cloop/task-1" {
		t.Errorf("push_allowed refs = %v, want [refs/heads/cloop/task-1]", allowed[0].Refs)
	}
	if denied := h.eventsOf(gitproxy.EventPushDenied); len(denied) != 0 {
		t.Errorf("got %d push_denied events on the happy path%s", len(denied), h.eventLog())
	}
}

// TestPushToProtectedBranchIsRefused is the property the package exists for.
func TestPushToProtectedBranchIsRefused(t *testing.T) {
	h := newHarness(t)

	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	m := h.mint(t, pol, 0)

	before, ok := h.upstreamSHA(t, "refs/heads/main")
	if !ok {
		t.Fatal("the fixture has no refs/heads/main to protect")
	}

	dir, out, err := h.clone(t, m)
	if err != nil {
		t.Fatalf("cloning through the proxy failed: %v\n%s", err, out)
	}
	local := h.commit(t, dir, "sneaky.txt", "this must not reach main\n")
	if local == before {
		t.Fatal("the sandbox commit is the seeded commit; the push would be a no-op")
	}

	// A plain fast-forward of main. git is perfectly willing; the proxy is not.
	pushOut, err := h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/main")
	if err == nil {
		t.Fatalf("push to refs/heads/main succeeded; the allowlist is not a boundary\n%s", pushOut)
	}

	after, ok := h.upstreamSHA(t, "refs/heads/main")
	if !ok {
		t.Fatalf("refs/heads/main vanished upstream\n%s", pushOut)
	}
	if after != before {
		t.Fatalf("upstream refs/heads/main moved from %s to %s despite the refusal\n%s", before, after, pushOut)
	}

	// The refusal must be legible as a policy refusal, not as a transport
	// failure: a sandbox that cannot tell the difference retries forever.
	if !strings.Contains(pushOut, "allowlist") {
		t.Errorf("push output does not explain the refusal:\n%s", pushOut)
	}

	denied := h.eventsOf(gitproxy.EventPushDenied)
	if len(denied) != 1 {
		t.Fatalf("got %d push_denied events, want 1%s", len(denied), h.eventLog())
	}
	e := denied[0]
	if len(e.Refs) != 1 || e.Refs[0] != "refs/heads/main" {
		t.Errorf("push_denied refs = %v, want [refs/heads/main]", e.Refs)
	}
	if e.SessionID != m.Session.ID || e.RepoPath != forgeOwner+"/"+forgeName || e.TaskID != "task-1" {
		t.Errorf("push_denied is not attributable: %s", e)
	}
	if !strings.Contains(e.Detail, "refs/heads/main") {
		t.Errorf("push_denied detail does not name the ref: %q", e.Detail)
	}
	if allowed := h.eventsOf(gitproxy.EventPushAllowed); len(allowed) != 0 {
		t.Errorf("got %d push_allowed events for a refused push%s", len(allowed), h.eventLog())
	}

	// The control for the control. Everything above is consistent with a forge
	// that refuses main for its own reasons, or a harness that cannot push it
	// at all. Widen the allowlist, replay the identical push, and it lands — so
	// what stopped it the first time was Policy.Decide and nothing else.
	t.Run("a widened allowlist lets the identical push through", func(t *testing.T) {
		wide := gitproxy.Policy{
			AllowedRefs: []string{"refs/heads/main", gitproxy.DefaultAllowedRef},
			AllowCreate: true,
			AllowUpdate: true,
			AllowFetch:  true,
		}
		m2 := h.mint(t, wide, 0)
		out, err := h.git(t, dir, h.credEnv(m2), "push", "origin", "HEAD:refs/heads/main")
		if err != nil {
			t.Fatalf("push to refs/heads/main failed even with main in the allowlist: %v\n%s", err, out)
		}
		got, ok := h.upstreamSHA(t, "refs/heads/main")
		if !ok || got != local {
			t.Fatalf("upstream refs/heads/main = %q (exists=%v), want the pushed commit %s\n%s",
				got, ok, local, out)
		}
	})
}

// TestDeleteOfAllowedRefIsRefused covers the second dimension of the policy: a
// ref inside the allowlist is still not a ref this session may remove.
func TestDeleteOfAllowedRefIsRefused(t *testing.T) {
	h := newHarness(t)

	// A branch the session's allowlist admits by name.
	const doomed = "refs/heads/cloop/doomed"
	h.mustGit(t, "", nil, "--git-dir="+h.bare, "update-ref", doomed, "refs/heads/main")
	before, ok := h.upstreamSHA(t, doomed)
	if !ok {
		t.Fatalf("could not seed %s", doomed)
	}

	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	if pol.AllowDelete {
		t.Fatal("WriteBackPolicy permits deletes; this test asserts the opposite")
	}
	m := h.mint(t, pol, 0)
	if !m.Session.Policy.AllowsRef(doomed) {
		t.Fatalf("%s is outside the allowlist %v; this test would prove nothing",
			doomed, m.Session.Policy.AllowedRefs)
	}

	dir, out, err := h.clone(t, m)
	if err != nil {
		t.Fatalf("cloning through the proxy failed: %v\n%s", err, out)
	}

	pushOut, err := h.git(t, dir, h.credEnv(m), "push", "origin", ":"+doomed)
	if err == nil {
		t.Fatalf("deleting %s succeeded; AllowDelete=false was not enforced\n%s", doomed, pushOut)
	}

	after, ok := h.upstreamSHA(t, doomed)
	if !ok {
		t.Fatalf("%s was deleted upstream despite the refusal\n%s", doomed, pushOut)
	}
	if after != before {
		t.Fatalf("upstream %s moved from %s to %s\n%s", doomed, before, after, pushOut)
	}
	if !strings.Contains(pushOut, "may not delete refs") {
		t.Errorf("push output does not explain the refusal:\n%s", pushOut)
	}

	denied := h.eventsOf(gitproxy.EventPushDenied)
	if len(denied) != 1 {
		t.Fatalf("got %d push_denied events, want 1%s", len(denied), h.eventLog())
	}
	if len(denied[0].Refs) != 1 || denied[0].Refs[0] != doomed {
		t.Errorf("push_denied refs = %v, want [%s]", denied[0].Refs, doomed)
	}
}

// TestFetchRequiresAllowFetch checks the read half is gated too. A session that
// may only push back a tree it was handed has no business reading the history.
func TestFetchRequiresAllowFetch(t *testing.T) {
	h := newHarness(t)

	pol := gitproxy.WriteBackPolicy()
	if pol.AllowFetch {
		t.Fatal("WriteBackPolicy permits fetch; this test asserts the opposite")
	}
	m := h.mint(t, pol, 0)

	dir, out, err := h.clone(t, m)
	if err == nil {
		t.Fatalf("cloning succeeded without AllowFetch\n%s", out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, ".git")); statErr == nil {
		t.Errorf("a repository was created despite the refused clone\n%s", out)
	}

	rejected := h.eventsOf(gitproxy.EventRejected)
	if len(rejected) == 0 {
		t.Fatalf("a refused fetch left no audit row%s", h.eventLog())
	}
	var sawFetchRefusal bool
	for _, e := range rejected {
		if e.SessionID == m.Session.ID && strings.Contains(e.Detail, "may not fetch") {
			sawFetchRefusal = true
		}
	}
	if !sawFetchRefusal {
		t.Errorf("no rejected event names the fetch refusal%s", h.eventLog())
	}

	// The same session may still push: the two authorities are independent, and
	// a test that only proved "nothing works" would prove nothing.
	local := filepath.Join(t.TempDir(), "detached")
	h.mustGit(t, "", nil, "init", local)
	h.mustGit(t, local, nil, "symbolic-ref", "HEAD", "refs/heads/work")
	sha := h.commit(t, local, "handed.txt", "a tree the sandbox was handed\n")
	pushOut, err := h.git(t, local, h.credEnv(m), "push", m.RepoURL, "HEAD:refs/heads/cloop/task-1")
	if err != nil {
		t.Fatalf("push failed for a session that may push but not fetch: %v\n%s", err, pushOut)
	}
	if got, ok := h.upstreamSHA(t, "refs/heads/cloop/task-1"); !ok || got != sha {
		t.Fatalf("upstream refs/heads/cloop/task-1 = %q (exists=%v), want %s", got, ok, sha)
	}
}

// TestExpiredSessionIsRefused checks the TTL is enforced on every request, not
// only at mint time. A token that outlived its session is the failure mode the
// whole ephemeral-credential design exists to bound.
func TestExpiredSessionIsRefused(t *testing.T) {
	h := newHarness(t)

	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	const ttl = time.Minute
	m := h.mint(t, pol, ttl)

	// Still inside the TTL: everything works, so the refusal below is about
	// expiry and not about a broken session.
	dir, out, err := h.clone(t, m)
	if err != nil {
		t.Fatalf("cloning inside the TTL failed: %v\n%s", err, out)
	}
	sha := h.commit(t, dir, "late.txt", "pushed after the session died\n")

	h.advance(ttl + time.Second)
	if !m.Session.Expired(h.now()) {
		t.Fatal("the session is not expired after advancing past its TTL")
	}

	pushOut, err := h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/cloop/task-1")
	if err == nil {
		t.Fatalf("push with an expired session succeeded\n%s", pushOut)
	}
	if _, ok := h.upstreamSHA(t, "refs/heads/cloop/task-1"); ok {
		t.Fatalf("the expired session created refs/heads/cloop/task-1 (%s)\n%s", sha, pushOut)
	}

	rejected := h.eventsOf(gitproxy.EventRejected)
	if len(rejected) == 0 {
		t.Fatalf("an expired session's request left no audit row%s", h.eventLog())
	}
	var sawExpiry bool
	for _, e := range rejected {
		if strings.Contains(e.Detail, "expired") {
			sawExpiry = true
		}
	}
	if !sawExpiry {
		t.Errorf("no rejected event names the expiry%s", h.eventLog())
	}
	if allowed := h.eventsOf(gitproxy.EventPushAllowed); len(allowed) != 0 {
		t.Errorf("an expired session authorised a push%s", h.eventLog())
	}
}
