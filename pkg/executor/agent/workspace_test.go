package agent

// Workspace provisioning tests, against a real git server.
//
// These run the actual `git` binary against an httptest server that shells out
// to `git http-backend`, so the fetch is a genuine smart-HTTP transaction:
// info/refs, upload-pack, a packfile, a checkout. That matters more here than
// anywhere else in this package, because the property under test is not "the
// right arguments were assembled" but "the credential reached the remote as an
// Authorization header and reached nothing else at all". A mocked transport
// could not tell the difference between a header that was set and one that was
// merely built.
//
// The server is TLS because executor.Workspace refuses a non-https clone URL —
// a brokered token delivered over cleartext is a published token. git is
// pointed at the test server's own certificate through GIT_SSL_CAINFO, which is
// one of the transport variables provisioning inherits from the device.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/fs"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// testToken is long enough to be redacted (executor.RedactSecrets ignores
// anything under 8 bytes, since a short string would corrupt ordinary output)
// and distinctive enough that finding it anywhere is unambiguous.
const testToken = "ghp_test_0123456789abcdefghijklmnopqrstuvwxyz"

// testCredential is the material the fake server demands.
func testCredential() executor.GitCredential {
	return executor.GitCredential{
		Username:   "x-access-token",
		Password:   testToken,
		LeaseID:    "lease_test",
		GrantID:    "grant_test",
		SecretName: "github-ci",
	}
}

// gitServer is a real git remote over TLS, with the requests it received.
type gitServer struct {
	srv    *httptest.Server
	repo   string
	caFile string

	mu       sync.Mutex
	requests []recordedRequest
}

type recordedRequest struct {
	path string
	auth string
}

// requireGit skips a test on a machine with no usable git.
func requireGit(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the workspace tests drive a POSIX git installation")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed; workspace provisioning cannot be exercised")
	}
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Skipf("git --exec-path failed: %v", err)
	}
	backend := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skipf("git-http-backend is not installed at %s; cannot serve a real remote", backend)
	}
	return backend
}

// git runs a git command with a closed-enough environment that the developer's
// own ~/.gitconfig cannot change the fixture.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=cloop test",
		"GIT_AUTHOR_EMAIL=test@example.invalid",
		"GIT_COMMITTER_NAME=cloop test",
		"GIT_COMMITTER_EMAIL=test@example.invalid",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s in %s: %v: %s", strings.Join(args, " "), dir, err, out)
	}
	return string(out)
}

// makeBareRepo builds a bare repository on branch main containing files.
func makeBareRepo(t *testing.T, bare string, files map[string]string) {
	t.Helper()
	work := filepath.Join(t.TempDir(), "seed")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatalf("mkdir seed: %v", err)
	}
	git(t, work, "init", "--quiet", "--initial-branch=main")
	for name, body := range files {
		path := filepath.Join(work, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	git(t, work, "add", "-A")
	git(t, work, "commit", "--quiet", "-m", "initial")
	git(t, filepath.Dir(bare), "clone", "--quiet", "--bare", work, bare)
}

// startGitServer serves a repository over TLS, demanding wantAuth on every
// request when it is non-empty.
func startGitServer(t *testing.T, wantAuth string, files map[string]string) *gitServer {
	t.Helper()
	backend := requireGit(t)

	root := t.TempDir()
	makeBareRepo(t, filepath.Join(root, "repo.git"), files)

	gs := &gitServer{}
	handler := &cgi.Handler{
		Path: backend,
		Env: []string{
			"GIT_PROJECT_ROOT=" + root,
			// The fixture repositories have no git-daemon-export-ok marker, and
			// adding one would test the fixture rather than the client.
			"GIT_HTTP_EXPORT_ALL=1",
		},
	}
	gs.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		gs.mu.Lock()
		gs.requests = append(gs.requests, recordedRequest{path: r.URL.Path, auth: auth})
		gs.mu.Unlock()

		if wantAuth != "" && auth != wantAuth {
			// A real forge answers an unauthenticated or wrongly-authenticated
			// fetch with a challenge. git, with prompting disabled by
			// executor.GitBaseEnv, turns that into a hard failure rather than
			// hanging on a terminal nobody will answer.
			w.Header().Set("WWW-Authenticate", `Basic realm="cloop-test"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(gs.srv.Close)

	// Hand git the server's own self-signed certificate as its CA bundle. This
	// is the whole reason provisioning inherits the device's TLS variables: a
	// device that reaches its forge through a private CA is the ordinary case,
	// not an exotic one.
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: gs.srv.Certificate().Raw})
	gs.caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(gs.caFile, caPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	t.Setenv("GIT_SSL_CAINFO", gs.caFile)

	gs.repo = gs.srv.URL + "/repo.git"
	return gs
}

// authorizations returns the Authorization header of every request received.
func (g *gitServer) authorizations() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]string, 0, len(g.requests))
	for _, r := range g.requests {
		out = append(out, r.auth)
	}
	return out
}

// collector accumulates provisioning output the way the agent's log buffer
// would.
type collector struct {
	mu   sync.Mutex
	text strings.Builder
}

func (c *collector) emit(s string) {
	c.mu.Lock()
	c.text.WriteString(s)
	c.mu.Unlock()
}

func (c *collector) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.text.String()
}

// tokenLeaks reports every file under dir whose bytes contain any of secrets.
func tokenLeaks(t *testing.T, dir string, secrets []string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil //nolint:nilerr // an unreadable entry cannot hold a leak we could act on
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		for _, s := range secrets {
			if strings.Contains(string(body), s) {
				found = append(found, path)
				return nil
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return found
}

// gitWorkspace is the spec-side description of the fake server's repository.
func gitWorkspace(gs *gitServer, ref string) executor.Workspace {
	return executor.Workspace{
		Kind:            executor.WorkspaceGit,
		Repo:            gs.repo,
		Ref:             ref,
		Depth:           1,
		CredentialGrant: "github-ci",
	}
}

// TestProvisionWorkspaceClonesAuthenticatedRepo is the headline assertion: a
// private repository ends up in the working directory, and it got there by
// presenting the brokered credential as an Authorization header.
func TestProvisionWorkspaceClonesAuthenticatedRepo(t *testing.T) {
	cred := testCredential()
	gs := startGitServer(t, cred.AuthorizationHeader(), map[string]string{
		"README.md":    "hello from the workspace\n",
		"src/main.go":  "package main\n",
		"nested/a/b.c": "int main(void){}\n",
	})

	dir := t.TempDir()
	var out collector
	if err := provisionWorkspace(context.Background(), dir, gitWorkspace(gs, "main"), cred, out.emit); err != nil {
		t.Fatalf("provisionWorkspace: %v\noutput:\n%s", err, out.String())
	}

	body, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil {
		t.Fatalf("the provisioned tree should contain the repository's files: %v", err)
	}
	if got := string(body); got != "hello from the workspace\n" {
		t.Errorf("README.md = %q, want the repository's content", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "nested", "a", "b.c")); err != nil {
		t.Errorf("nested files should be checked out too: %v", err)
	}

	// The credential must have been presented, and presented as the header the
	// GitCredential encodes — not as userinfo in the URL, and not via a helper.
	var sawHeader bool
	for _, auth := range gs.authorizations() {
		if auth == cred.AuthorizationHeader() {
			sawHeader = true
		}
	}
	if !sawHeader {
		t.Fatalf("the fetch never presented the brokered Authorization header; saw %q",
			gs.authorizations())
	}

	// And it must be nowhere else. Output first: this text is streamed to the
	// hub's live log and persisted as a run artifact.
	for _, secret := range cred.Secrets() {
		if strings.Contains(out.String(), secret) {
			t.Errorf("provisioning output contains the credential:\n%s", out.String())
		}
	}
	// Then the filesystem: a token in .git/config would outlive the lease by
	// however long the workdir survives, and the harness runs as a party that
	// can read it.
	if leaks := tokenLeaks(t, dir, cred.Secrets()); len(leaks) > 0 {
		t.Errorf("the credential was written to %v; it must never touch disk", leaks)
	}
}

// TestProvisionWorkspaceFetchesDefaultBranch covers the empty-ref path, where
// the checkout target is the remote's choice rather than the caller's.
func TestProvisionWorkspaceFetchesDefaultBranch(t *testing.T) {
	cred := testCredential()
	gs := startGitServer(t, cred.AuthorizationHeader(), map[string]string{"README.md": "default branch\n"})

	dir := t.TempDir()
	var out collector
	ws := gitWorkspace(gs, "")
	if err := provisionWorkspace(context.Background(), dir, ws, cred, out.emit); err != nil {
		t.Fatalf("provisionWorkspace: %v\noutput:\n%s", err, out.String())
	}
	body, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil || string(body) != "default branch\n" {
		t.Fatalf("the default branch should have been checked out: %v (%q)", err, body)
	}
}

// TestProvisionWorkspaceRefusesUnauthenticatedFetch is the negative half of the
// credential path: without the header the server refuses, and provisioning
// fails instead of leaving an empty directory that looks provisioned.
func TestProvisionWorkspaceRefusesUnauthenticatedFetch(t *testing.T) {
	gs := startGitServer(t, testCredential().AuthorizationHeader(), map[string]string{"README.md": "private\n"})

	dir := t.TempDir()
	var out collector
	err := provisionWorkspace(context.Background(), dir, gitWorkspace(gs, "main"), executor.GitCredential{}, out.emit)
	if err == nil {
		t.Fatal("a fetch the server rejected must fail provisioning, not produce an empty tree")
	}
	if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
		t.Errorf("error should wrap ErrWorkspaceUnavailable, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "README.md")); statErr == nil {
		t.Error("nothing should have been checked out")
	}
	// The partial repository is cleaned up: leaving one behind would make the
	// next attempt take the reuse path over a tree in an unknown state.
	if _, statErr := os.Stat(filepath.Join(dir, ".git")); statErr == nil {
		t.Error("the partial repository should have been removed after the failure")
	}
}

// TestProvisionWorkspaceRedactsRejectedCredential is the redaction assertion,
// and it uses a credential the server rejects because that is the path where
// git is most likely to quote the material back: a 401 makes it report what it
// tried.
func TestProvisionWorkspaceRedactsRejectedCredential(t *testing.T) {
	wrong := executor.GitCredential{Username: "x-access-token", Password: testToken}
	gs := startGitServer(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("someone:else")),
		map[string]string{"README.md": "private\n"})

	dir := t.TempDir()
	var out collector
	err := provisionWorkspace(context.Background(), dir, gitWorkspace(gs, "main"), wrong, out.emit)
	if err == nil {
		t.Fatal("a rejected credential must fail the provisioning")
	}
	for _, secret := range wrong.Secrets() {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error leaks the credential: %v", err)
		}
		if strings.Contains(out.String(), secret) {
			t.Errorf("the streamed output leaks the credential:\n%s", out.String())
		}
	}
	// The server did see the header, so the redaction is not passing by virtue
	// of the credential never having been used.
	var presented bool
	for _, auth := range gs.authorizations() {
		if auth == wrong.AuthorizationHeader() {
			presented = true
		}
	}
	if !presented {
		t.Fatalf("the fetch should have presented the (wrong) credential; saw %q", gs.authorizations())
	}
}

// TestProvisionWorkspaceReusesExistingCheckout pins the rule that keeps work
// from being destroyed: a directory that already holds this repository is
// fetched into, never re-initialised.
func TestProvisionWorkspaceReusesExistingCheckout(t *testing.T) {
	cred := testCredential()
	gs := startGitServer(t, cred.AuthorizationHeader(), map[string]string{"README.md": "first\n"})

	dir := t.TempDir()
	ws := gitWorkspace(gs, "main")
	var first collector
	if err := provisionWorkspace(context.Background(), dir, ws, cred, first.emit); err != nil {
		t.Fatalf("first provision: %v\n%s", err, first.String())
	}

	// Uncommitted work in the checkout. This is the thing a re-clone would
	// destroy, and the reason the second pass must be a fetch.
	scratch := filepath.Join(dir, "UNCOMMITTED.txt")
	if err := os.WriteFile(scratch, []byte("hours of work\n"), 0o644); err != nil {
		t.Fatalf("write scratch file: %v", err)
	}

	var second collector
	if err := provisionWorkspace(context.Background(), dir, ws, cred, second.emit); err != nil {
		t.Fatalf("second provision: %v\n%s", err, second.String())
	}
	if _, err := os.Stat(scratch); err != nil {
		t.Errorf("re-provisioning discarded uncommitted work: %v", err)
	}
	if !strings.Contains(second.String(), "reusing the existing checkout") {
		t.Errorf("the second pass should say it is reusing the checkout; got:\n%s", second.String())
	}
	if strings.Contains(second.String(), "workspace: init:") {
		t.Errorf("the second pass must not re-initialise the repository; got:\n%s", second.String())
	}
}

// TestProvisionWorkspaceRefusesMismatchedRemote covers the other half of that
// rule: a directory holding a *different* repository is an error naming both,
// not a silent choice between them.
func TestProvisionWorkspaceRefusesMismatchedRemote(t *testing.T) {
	cred := testCredential()
	gs := startGitServer(t, cred.AuthorizationHeader(), map[string]string{"README.md": "wanted\n"})

	dir := t.TempDir()
	// A checkout of something else, with work in it.
	git(t, dir, "init", "--quiet", "--initial-branch=main", ".")
	git(t, dir, "remote", "add", "origin", "https://example.invalid/someone/other.git")
	if err := os.WriteFile(filepath.Join(dir, "KEEP.txt"), []byte("do not lose me\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	var out collector
	err := provisionWorkspace(context.Background(), dir, gitWorkspace(gs, "main"), cred, out.emit)
	if err == nil {
		t.Fatal("provisioning over a different repository must be refused")
	}
	if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
		t.Errorf("error should wrap ErrWorkspaceUnavailable, got %v", err)
	}
	// Both URLs, because the operator's question is "which one is wrong".
	for _, want := range []string{"other.git", gs.repo} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should name %q; got %v", want, err)
		}
	}
	if _, statErr := os.Stat(filepath.Join(dir, "KEEP.txt")); statErr != nil {
		t.Errorf("a refused provisioning must not touch the existing tree: %v", statErr)
	}
}

// TestProvisionWorkspaceEnforcesSizeLimit checks that the project's disk budget
// is enforced rather than advertised. This is the one driver whose disk does not
// belong to the operator who wrote the spec, so a limit nobody applies is not a
// limit.
func TestProvisionWorkspaceEnforcesSizeLimit(t *testing.T) {
	cred := testCredential()
	// Incompressible bytes, so the packfile really is this big on the wire and
	// on disk.
	blob := make([]byte, 3<<20)
	if _, err := rand.Read(blob); err != nil {
		t.Fatalf("rand: %v", err)
	}
	gs := startGitServer(t, cred.AuthorizationHeader(), map[string]string{
		"README.md": "big\n",
		"blob.bin":  string(blob),
	})

	dir := t.TempDir()
	ws := gitWorkspace(gs, "main")
	ws.SizeLimitMB = 1

	var out collector
	err := provisionWorkspace(context.Background(), dir, ws, cred, out.emit)
	if err == nil {
		t.Fatal("a tree over the workload's disk limit must be refused")
	}
	if !strings.Contains(err.Error(), "1 MB") {
		t.Errorf("the refusal should name the limit; got %v", err)
	}
	// Removed, not left behind: the point of the limit is the device's disk.
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("read dir: %v", readErr)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the oversized tree should have been removed; %v is still there", names)
	}
}

// TestProvisionWorkspaceNeedsGit is the "clear error naming the device" case.
func TestProvisionWorkspaceNeedsGit(t *testing.T) {
	// An empty PATH is the closest a test can get to a device with no git,
	// short of moving the binary.
	t.Setenv("PATH", "")
	ws := executor.Workspace{Kind: executor.WorkspaceGit, Repo: "https://example.com/o/r.git", Ref: "main"}

	err := provisionWorkspace(context.Background(), t.TempDir(), ws, executor.GitCredential{}, nil)
	if err == nil {
		t.Fatal("provisioning without git must fail")
	}
	if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
		t.Errorf("error should wrap ErrWorkspaceUnavailable, got %v", err)
	}
	if !strings.Contains(err.Error(), "this device") || !strings.Contains(err.Error(), "git") {
		t.Errorf("the error should name the device and the missing binary; got %v", err)
	}
}

// TestProvisionWorkspaceRefusesExpiredCredential: a lease that has already
// lapsed produces an opaque 401 halfway through a transfer, so it is caught
// before the fetch starts and reported as what it is.
func TestProvisionWorkspaceRefusesExpiredCredential(t *testing.T) {
	requireGit(t)
	cred := testCredential()
	cred.ExpiresAt = time.Now().Add(-time.Minute)
	ws := executor.Workspace{Kind: executor.WorkspaceGit, Repo: "https://example.com/o/r.git", Ref: "main"}

	err := provisionWorkspace(context.Background(), t.TempDir(), ws, cred, nil)
	if err == nil {
		t.Fatal("an expired credential must not begin a fetch")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("the error should say the credential expired; got %v", err)
	}
	for _, secret := range cred.Secrets() {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error leaks the credential: %v", err)
		}
	}
}

// TestProvisionWorkspaceCancellationStopsTheFetch checks that the context is
// honoured, which is what makes a stop during a long clone possible at all.
func TestProvisionWorkspaceCancellationStopsTheFetch(t *testing.T) {
	cred := testCredential()
	gs := startGitServer(t, cred.AuthorizationHeader(), map[string]string{"README.md": "x\n"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := provisionWorkspace(ctx, t.TempDir(), gitWorkspace(gs, "main"), cred, nil)
	if err == nil {
		t.Fatal("a cancelled context must abort provisioning")
	}
	if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
		t.Errorf("error should wrap ErrWorkspaceUnavailable, got %v", err)
	}
}

// TestSameRemoteComparison pins the normalisation, which decides whether an
// existing checkout is fetched into or refused.
func TestSameRemoteComparison(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"https://example.com/o/r.git", "https://example.com/o/r.git", true},
		{"https://example.com/o/r", "https://example.com/o/r.git", true},
		{"https://example.com/o/r.git/", "https://example.com/o/r", true},
		{"https://example.com/o/r", "https://example.com/o/other", false},
		{"", "https://example.com/o/r", false},
		{"https://example.com/o/r", "", false},
		// Case is not folded: two GitHub paths differing only in case are two
		// different repositories as far as this device may assume.
		{"https://example.com/O/R", "https://example.com/o/r", false},
	}
	for _, tc := range cases {
		if got := gitprovision.SameRemote(tc.a, tc.b); got != tc.want {
			t.Errorf("SameRemote(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Agent wiring
// ---------------------------------------------------------------------------

// TestAgentProvisionsWorkspaceBeforeLaunchingHarness is the wiring assertion:
// the harness must see the code, which is only true if provisioning happens
// between resolveWorkDir and the launch.
func TestAgentProvisionsWorkspaceBeforeLaunchingHarness(t *testing.T) {
	cred := testCredential()
	gs := startGitServer(t, cred.AuthorizationHeader(), map[string]string{"README.md": "cloned-by-the-agent\n"})

	dir := t.TempDir()
	a, conns := newScriptedAgent(t, filepath.Join(dir, "agent.json"), filepath.Join(dir, "work"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	cp := <-conns
	hello := cp.handshake(t, "agent-1", nil, "clac1.a.b.c")
	if !hello.Capabilities.WorkspaceProvisioning {
		t.Error("a device with git on PATH should advertise that it can provision a workspace")
	}

	start, err := remote.NewFrame(remote.TypeStart, "req-1", "h1", remote.StartPayload{
		HandleID: "h1",
		Spec: executor.Spec{
			WorkDir:   "cloned-project",
			Argv:      []string{"/bin/sh", "-c", "cat README.md"},
			Workspace: gitWorkspace(gs, "main"),
		},
		WorkspaceCredential: &remote.WorkspaceCredential{
			Username: cred.Username,
			Password: cred.Password,
		},
	})
	if err != nil {
		t.Fatalf("build start: %v", err)
	}
	cp.write(start)

	// Frames are collected rather than filtered, because the ordering is part
	// of the assertion: provisioning output has to reach the hub *before* the
	// start is confirmed, or an operator watching a long clone sees a run that
	// has not started yet and no explanation for the delay.
	var (
		log        strings.Builder
		logBefore  string
		startedGot bool
	)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		f, readErr := cp.read(time.Until(deadline))
		if readErr != nil {
			break
		}
		switch f.Type {
		case remote.TypeLogChunk:
			if chunk, decodeErr := remote.DecodeLogChunk(f); decodeErr == nil {
				log.WriteString(chunk.Text)
			}
		case remote.TypeStarted:
			payload, decodeErr := remote.DecodeStarted(f)
			if decodeErr != nil {
				t.Fatalf("DecodeStarted: %v", decodeErr)
			}
			if payload.Error != "" {
				t.Fatalf("the agent refused a workload it should have provisioned: %s", payload.Error)
			}
			startedGot = true
			logBefore = log.String()
		}
		if startedGot && strings.Contains(log.String(), "cloned-by-the-agent") {
			break
		}
	}
	if !startedGot {
		t.Fatalf("the agent never confirmed the start; log was:\n%s", log.String())
	}
	if !strings.Contains(log.String(), "cloned-by-the-agent") {
		t.Fatalf("the harness should have run against the cloned tree; log was:\n%s", log.String())
	}
	if !strings.Contains(logBefore, "workspace: provisioning") {
		t.Errorf("provisioning output should reach the run's log before the start is confirmed; got:\n%s",
			logBefore)
	}
	// And the token stayed on the wire and in one child process's environment.
	for _, secret := range cred.Secrets() {
		if strings.Contains(log.String(), secret) {
			t.Errorf("the credential reached the run log:\n%s", log.String())
		}
	}
	if leaks := tokenLeaks(t, filepath.Join(dir, "work"), cred.Secrets()); len(leaks) > 0 {
		t.Errorf("the credential was written to %v", leaks)
	}
}

// TestAgentRefusesBindWorkspace: "bind" asserts the executor already holds the
// tree because it shares the control plane's filesystem. A remote agent shares
// nothing, so honouring it would start the harness in an empty directory —
// exactly the failure the workspace contract exists to remove.
func TestAgentRefusesBindWorkspace(t *testing.T) {
	dir := t.TempDir()
	a, conns := newScriptedAgent(t, filepath.Join(dir, "agent.json"), filepath.Join(dir, "work"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	cp := <-conns
	cp.handshake(t, "agent-1", nil, "clac1.a.b.c")

	start, err := remote.NewFrame(remote.TypeStart, "req-1", "h1", remote.StartPayload{
		HandleID: "h1",
		Spec: executor.Spec{
			WorkDir:   "bound-project",
			Argv:      []string{"/bin/sh", "-c", "echo should not run"},
			Workspace: executor.Workspace{Kind: executor.WorkspaceBind},
		},
	})
	if err != nil {
		t.Fatalf("build start: %v", err)
	}
	cp.write(start)

	started := cp.readUntil(remote.TypeStarted, 10*time.Second)
	payload, err := remote.DecodeStarted(started)
	if err != nil {
		t.Fatalf("DecodeStarted: %v", err)
	}
	if payload.Error == "" {
		t.Fatal("a bind workspace must be refused by a remote agent")
	}
	if !strings.Contains(payload.Error, "shares no filesystem") {
		t.Errorf("the refusal should explain why; got %q", payload.Error)
	}
}

// TestSignalDuringProvisioningCancelsTheFetch checks the one window in which a
// workload exists but no process does. Without this a stop issued during a
// twenty-minute clone would be answered with "unknown handle" and the fetch
// would run to completion regardless.
func TestSignalDuringProvisioningCancelsTheFetch(t *testing.T) {
	wl := &workload{handleID: "h1", buf: newRetainBuffer(1024)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if wl.cancelProvisioning() {
		t.Error("a workload with nothing in flight has no fetch to cancel")
	}
	wl.setProvisionCancel(cancel)
	if !wl.cancelProvisioning() {
		t.Fatal("an in-flight fetch should be cancellable")
	}
	if ctx.Err() == nil {
		t.Error("cancelling should have cancelled the provisioning context")
	}
	// Single-shot: two concurrent stops must not both claim the cancellation.
	if wl.cancelProvisioning() {
		t.Error("a second cancel must report that there was nothing left to cancel")
	}
}

// TestProvisionedWorkspaceBecomesBind pins the handoff to the inner driver.
//
// After this device has fetched, the tree really is at WorkDir on the machine
// that is about to run — which is what "bind" asserts. Passing the git
// workspace down unchanged would ask a host-filesystem driver to clone over a
// checkout it does not own, and it refuses; "none" must survive untouched,
// because an intentionally empty tree is not a tree that arrived.
func TestProvisionedWorkspaceBecomesBind(t *testing.T) {
	git := executor.Workspace{
		Kind:            executor.WorkspaceGit,
		Repo:            "https://example.com/o/r.git",
		Ref:             "main",
		Depth:           1,
		CredentialGrant: "github-ci",
		SizeLimitMB:     512,
	}
	got := provisionedWorkspace(git)
	if got.Kind != executor.WorkspaceBind {
		t.Errorf("Kind = %q, want bind after the fetch", got.Kind)
	}
	if got.SizeLimitMB != 512 {
		t.Errorf("SizeLimitMB = %d, want the budget carried across", got.SizeLimitMB)
	}
	if err := got.Validate(); err != nil {
		// A bind workspace still carrying a Repo is refused by Validate, which
		// is what makes "rewrite" mean rewrite rather than "overwrite one field".
		t.Errorf("the rewritten workspace must be valid: %v", err)
	}

	for _, w := range []executor.Workspace{
		{},
		{Kind: executor.WorkspaceBind},
		{Kind: executor.WorkspaceNone},
	} {
		if got := provisionedWorkspace(w); got != w {
			t.Errorf("provisionedWorkspace(%+v) = %+v, want it untouched", w, got)
		}
	}
}

// TestWorkspaceTreeSizeBoundsItsWalk keeps the measurement from becoming a way
// for a remote repository to occupy the device.
func TestWorkspaceTreeSizeBoundsItsWalk(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("12345"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	size, entries, err := gitprovision.TreeSize(dir)
	if err != nil {
		t.Fatalf("TreeSize: %v", err)
	}
	if size != 5 {
		t.Errorf("size = %d, want 5", size)
	}
	if entries < 2 {
		t.Errorf("entries = %d, want the directory and its file", entries)
	}
	if gitprovision.MaxWalkEntries <= 0 {
		t.Fatal("the walk must be bounded")
	}
}

// TestEnforceWorkspaceSizeIgnoresUnsetLimit: 0 means the executor's own
// default, not "refuse everything".
func TestEnforceWorkspaceSizeIgnoresUnsetLimit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), make([]byte, 4096), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := gitprovision.EnforceSizeLimit(dir, executor.Workspace{Kind: executor.WorkspaceGit}); err != nil {
		t.Errorf("an unset size limit must not refuse a tree: %v", err)
	}
}
