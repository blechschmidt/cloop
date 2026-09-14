// Package gitforge stands up a real, hermetic git remote for tests.
//
// # Why this exists rather than a mock
//
// pkg/executor/gitprovision and pkg/executor/gitwriteback are the two halves of
// one circuit: a leased credential reaches a sandbox through the first, and the
// commits the sandbox produced travel back through the second. Neither half can
// be proven against a fake. The claims they make — the token is scoped to one
// origin, the environment handed to git is closed, a refusal happens before any
// byte reaches the remote — are claims about what the *git binary* does with the
// environment those packages build. A mock that returned canned output would
// agree with any of them.
//
// So the remote here is a real bare repository served by real git-http-backend
// over real TLS, and every assertion about it is an assertion about a
// repository rather than about a recorded call. It is hermetic all the same:
// the listener is on loopback, the certificate is minted by httptest, and
// nothing outside the test's temporary directories is read or written.
//
// # Why TLS and not plain HTTP
//
// executor.Workspace refuses a repo URL that is not https, because a brokered
// token on cleartext http is a published token. A test forge on http would
// therefore be testing a configuration production cannot express. TLS also
// makes the transport allowlist observable: the only way a client can trust
// this forge's certificate is GIT_SSL_CAINFO, which is on gitprovision's
// allowlist, while GIT_SSL_NO_VERIFY — the shortcut — is deliberately not. A
// fetch that succeeds here is therefore evidence that the allowlist works, and
// one that fails without CAINFO is evidence that the shortcut really is absent.
//
// # Why it lives under internal/
//
// It imports "testing", so it must never be reachable from a shipped binary.
// internal/ enforces that, and scopes it to the executor tree where both
// callers live.
package gitforge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/redact"
)

// DefaultBranch is the branch a seeded repository puts its first commit on. It
// is named explicitly everywhere rather than inherited from the git version's
// default, which has changed.
const DefaultBranch = "main"

// gitTimeout bounds one fixture git invocation. A hung clone should name itself
// rather than wait for the package-level test timeout.
const gitTimeout = 2 * time.Minute

// --- locating the tools ------------------------------------------------------

// Tools are the binaries a forge needs.
type Tools struct {
	// Git is the client and fixture binary.
	Git string
	// Backend is git-http-backend, which serves the smart-HTTP protocol as CGI.
	Backend string
}

// RequireGit locates git and git-http-backend, or ends the test.
//
// The interesting decision is what "or ends the test" means, and it is not
// always a skip. A skipped test is reported as a pass by every summary anyone
// actually reads, so a suite that skips itself into silence is worse than one
// that was never written: it occupies the place where coverage is supposed to
// be. These tests are the only executable proof that a leased credential does
// not leak, which makes them precisely the ones that must not disappear
// quietly.
//
// So the rule is conditional on whether the environment is one where git is
// guaranteed. In CI it is: this repository cannot be checked out without git,
// so a runner that cannot find it is misconfigured and the suite says so with a
// failure. On a developer machine — where git-http-backend genuinely may not be
// installed, since several distributions package it separately — the skip
// stands, and it names the package to install rather than leaving the reader to
// guess.
//
// CLOOP_REQUIRE_GIT_E2E=1 forces the failing behaviour anywhere, so an operator
// debugging a suspiciously green run can prove the tests really ran.
func RequireGit(tb testing.TB) Tools {
	tb.Helper()

	git, err := exec.LookPath("git")
	if err != nil {
		unavailable(tb, "no git binary on PATH",
			"install git; these tests drive a real git client because the guarantees "+
				"under test are guarantees about what git does with the environment "+
				"these packages build")
		return Tools{}
	}

	// git-http-backend lives in git's exec-path, which is distribution-specific
	// (/usr/lib/git-core on Debian, /usr/libexec/git-core on Fedora and macOS),
	// so ask git where it keeps its helpers before guessing.
	var candidates []string
	if out, err := exec.Command(git, "--exec-path").Output(); err == nil {
		if p := strings.TrimSpace(string(out)); p != "" {
			candidates = append(candidates, filepath.Join(p, "git-http-backend"))
		}
	}
	candidates = append(candidates,
		"/usr/lib/git-core/git-http-backend",
		"/usr/libexec/git-core/git-http-backend",
	)
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() && st.Mode().Perm()&0o111 != 0 {
			return Tools{Git: git, Backend: c}
		}
	}
	unavailable(tb,
		"git-http-backend not found (looked in "+strings.Join(candidates, ", ")+")",
		"install the package that ships git-http-backend (git-core on Debian and "+
			"Ubuntu, git-core on Fedora); without a git server these tests cannot "+
			"observe what the client sends")
	return Tools{}
}

// unavailable ends the test for a missing tool: loudly where the tool is
// guaranteed, with a remedy where it is not. See RequireGit.
func unavailable(tb testing.TB, what, remedy string) {
	tb.Helper()
	if requireTools() {
		tb.Fatalf("%s.\n"+
			"This is a hard failure rather than a skip because the environment says the "+
			"tool must be here (CI or CLOOP_REQUIRE_GIT_E2E is set), and these are the "+
			"only tests that execute the credential path end to end — skipping them "+
			"would report green for a boundary nobody exercised.\n"+
			"Remedy: %s.", what, remedy)
		return
	}
	tb.Skipf("%s; skipping the end-to-end credential tests.\n"+
		"Remedy: %s.\n"+
		"Set CLOOP_REQUIRE_GIT_E2E=1 to turn this skip into a failure.", what, remedy)
}

// requireTools reports whether a missing tool must fail rather than skip.
func requireTools() bool {
	if v := strings.TrimSpace(os.Getenv("CLOOP_REQUIRE_GIT_E2E")); v != "" && v != "0" {
		return true
	}
	// GitHub Actions, GitLab CI, CircleCI and Travis all set CI.
	return strings.TrimSpace(os.Getenv("CI")) != ""
}

// --- the forge ---------------------------------------------------------------

// Request is one HTTP request the forge received.
//
// Authorization is recorded verbatim, which is what lets a test assert the
// negative that matters most: that a host the grant does not cover never saw
// the header at all.
type Request struct {
	Method        string
	Path          string
	Authorization string
	User          string
	Password      string
	Authorized    bool
}

// Options configure a forge.
type Options struct {
	// User and Password are the basic credential the forge demands. When
	// Password is empty the forge serves anonymously, which is how a test
	// distinguishes "the client sent no credential" from "the credential was
	// wrong".
	User, Password string
	// Intercept, when non-nil, runs for every request after it is recorded and
	// before it is authenticated. Returning true means it wrote the response
	// itself and git must not be invoked — used to model a redirect, a hang, or
	// a forge that is down.
	Intercept func(w http.ResponseWriter, r *http.Request) bool
}

// Forge is a bare-repository host served over TLS.
type Forge struct {
	tools Tools
	srv   *httptest.Server
	opt   Options

	root   string // GIT_PROJECT_ROOT
	home   string // $HOME for server-side git
	caFile string // PEM a client must trust to reach this forge

	mu       sync.Mutex
	requests []Request
}

// Start brings up a forge and registers its shutdown with tb.
func Start(tb testing.TB, opt Options) *Forge {
	tb.Helper()
	f := &Forge{
		tools: RequireGit(tb),
		opt:   opt,
		root:  tb.TempDir(),
		home:  tb.TempDir(),
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	tb.Cleanup(f.srv.Close)

	// The certificate has to reach the client as a file, because the only
	// channel gitprovision leaves open for it is GIT_SSL_CAINFO — a path. That
	// is the point: a client that trusts this forge did so through the
	// allowlist, not around it.
	f.caFile = filepath.Join(tb.TempDir(), "forge-ca.pem")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}
	if err := os.WriteFile(f.caFile, pem.EncodeToMemory(block), 0o600); err != nil {
		tb.Fatalf("writing the forge CA to %s: %v", f.caFile, err)
	}
	return f
}

// URL is the forge's base URL, https on loopback.
func (f *Forge) URL() string { return f.srv.URL }

// CAFile is the path to the PEM a client must trust.
func (f *Forge) CAFile() string { return f.caFile }

// Trust points the process environment at this forge's CA for the duration of
// the test, which is the one host setting gitprovision's allowlist forwards.
func (f *Forge) Trust(tb testing.TB) {
	tb.Helper()
	tb.Setenv("GIT_SSL_CAINFO", f.caFile)
}

// RepoURL is the https clone URL for a repository on this forge.
func (f *Forge) RepoURL(owner, name string) string {
	return f.srv.URL + "/" + owner + "/" + name + ".git"
}

// Path is the bare repository's directory, for fixture work that must not go
// through the path under test.
func (f *Forge) Path(owner, name string) string {
	return filepath.Join(f.root, owner, name+".git")
}

// Create makes a bare repository and seeds it with one commit on DefaultBranch,
// returning that commit's SHA.
//
// The seed travels over the filesystem rather than over HTTP: fixture setup
// must not depend on the path under test, or a broken fetch would show up as a
// broken fixture.
func (f *Forge) Create(tb testing.TB, owner, name string) string {
	tb.Helper()
	bare := f.Path(owner, name)
	if err := os.MkdirAll(filepath.Dir(bare), 0o755); err != nil {
		tb.Fatalf("creating the forge owner directory: %v", err)
	}
	f.git(tb, "", "init", "--bare", bare)
	f.git(tb, "", "--git-dir="+bare, "symbolic-ref", "HEAD", "refs/heads/"+DefaultBranch)
	// git-http-backend offers receive-pack only when http.receivepack says so,
	// so a refused push is refused by the code under test rather than by the
	// forge declining to offer the service at all.
	f.git(tb, "", "--git-dir="+bare, "config", "http.receivepack", "true")
	f.git(tb, "", "--git-dir="+bare, "config", "http.uploadpack", "true")

	seed := tb.TempDir()
	f.git(tb, "", "init", "-b", DefaultBranch, seed)
	writeFile(tb, filepath.Join(seed, "README.md"), "seed\n")
	f.git(tb, seed, "add", "--all", "--", ".")
	f.git(tb, seed, "commit", "--no-gpg-sign", "-m", "seed")
	f.git(tb, seed, "push", bare, "HEAD:refs/heads/"+DefaultBranch)
	return f.SHA(tb, owner, name, DefaultBranch)
}

// AddFile commits one file onto a branch of an existing repository and returns
// the new tip.
func (f *Forge) AddFile(tb testing.TB, owner, name, branch, path, content, msg string) string {
	tb.Helper()
	bare := f.Path(owner, name)
	work := tb.TempDir()
	f.git(tb, "", "clone", "--branch", branch, bare, work)
	full := filepath.Join(work, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		tb.Fatalf("creating %s: %v", filepath.Dir(full), err)
	}
	writeFile(tb, full, content)
	f.git(tb, work, "add", "--all", "--", ".")
	f.git(tb, work, "commit", "--no-gpg-sign", "-m", msg)
	f.git(tb, work, "push", bare, "HEAD:refs/heads/"+branch)
	return f.SHA(tb, owner, name, branch)
}

// SHA resolves a branch on the forge, returning "" when the ref does not exist.
// The empty string is the useful answer for "the push was refused": a test can
// assert the ref was never created without special-casing an error.
func (f *Forge) SHA(tb testing.TB, owner, name, branch string) string {
	tb.Helper()
	out, err := f.tryGit(tb, "", "--git-dir="+f.Path(owner, name),
		"rev-parse", "--verify", "--quiet", "refs/heads/"+branch)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// Requests returns every request the forge has received, oldest first.
func (f *Forge) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.requests...)
}

// Count is how many requests the forge has received. Zero is the assertion that
// matters for every refusal that is supposed to happen before the network.
func (f *Forge) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// Log renders the request trail for a failure message.
func (f *Forge) Log() string {
	var b strings.Builder
	for _, r := range f.Requests() {
		fmt.Fprintf(&b, "\n\t%s %s auth=%q authorized=%v", r.Method, r.Path, r.Authorization, r.Authorized)
	}
	if b.Len() == 0 {
		return " (no requests)"
	}
	return b.String()
}

// serve records the request, then runs git-http-backend as CGI behind basic
// auth.
//
// net/http/cgi is not used because it refuses a chunked request body, which a
// real git client sends. A real forge behind nginx handles chunked fine, so the
// plumbing is done by hand rather than by constraining what the client may do.
func (f *Forge) serve(w http.ResponseWriter, r *http.Request) {
	user, pass, hasBasic := r.BasicAuth()
	rec := Request{
		Method:        r.Method,
		Path:          r.URL.Path,
		Authorization: r.Header.Get("Authorization"),
		User:          user,
		Password:      pass,
	}

	if f.opt.Password != "" {
		// subtle.ConstantTimeCompare rather than ==: this file is scanned by
		// tests/security's timing gate like any other non-test source, and a
		// fixture that models the wrong habit is a fixture people copy.
		okUser := subtle.ConstantTimeCompare([]byte(user), []byte(f.opt.User)) == 1
		okPass := subtle.ConstantTimeCompare([]byte(pass), []byte(f.opt.Password)) == 1
		rec.Authorized = hasBasic && okUser && okPass
	} else {
		rec.Authorized = true
	}

	f.mu.Lock()
	f.requests = append(f.requests, rec)
	f.mu.Unlock()

	if f.opt.Intercept != nil && f.opt.Intercept(w, r) {
		return
	}
	if !rec.Authorized {
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
		"GIT_PROJECT_ROOT=" + f.root,
		"GIT_HTTP_EXPORT_ALL=1",
		"HOME=" + f.home,
		"PATH=" + os.Getenv("PATH"),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"LC_ALL=C",
	}
	if v := r.Header.Get("Content-Type"); v != "" {
		env = append(env, "CONTENT_TYPE="+v)
	}
	if r.ContentLength > 0 {
		env = append(env, "CONTENT_LENGTH="+strconv.FormatInt(r.ContentLength, 10))
	}
	if v := r.Header.Get("Content-Encoding"); v != "" {
		env = append(env, "HTTP_CONTENT_ENCODING="+v)
	}
	// git-http-backend reads the protocol version from GIT_PROTOCOL, not from
	// the header, so protocol v2 only reaches it if it is mapped explicitly.
	if v := r.Header.Get("Git-Protocol"); v != "" {
		env = append(env, "GIT_PROTOCOL="+v)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(r.Context(), f.tools.Backend)
	cmd.Env = env
	cmd.Dir = f.root
	cmd.Stdin = r.Body
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	// git-http-backend reports its own failures as a CGI response with a Status
	// header, so parse first and fall back to 500 only when there is no
	// parsable response at all.
	br := bufio.NewReader(bytes.NewReader(stdout.Bytes()))
	header, err := textproto.NewReader(br).ReadMIMEHeader()
	if err != nil {
		http.Error(w, fmt.Sprintf("forge: git-http-backend produced no CGI response (%v): %s",
			runErr, stderr.String()), http.StatusInternalServerError)
		return
	}
	status := http.StatusOK
	if s := header.Get("Status"); s != "" {
		if fields := strings.Fields(s); len(fields) > 0 {
			if code, err := strconv.Atoi(fields[0]); err == nil {
				status = code
			}
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

// --- fixture git -------------------------------------------------------------

// FixtureEnv is the environment every fixture git command runs in.
//
// It is closed for the same reason the code under test closes its own: a
// developer's ~/.gitconfig holding a credential helper, an insteadOf rewrite or
// a commit.gpgsign would otherwise decide the outcome of a test about
// something else. home isolates anything that still reaches for it.
func FixtureEnv(home string) []string {
	return []string{
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"PATH=" + os.Getenv("PATH"),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/nonexistent",
		"SSH_ASKPASS=/nonexistent",
		"GIT_AUTHOR_NAME=fixture",
		"GIT_AUTHOR_EMAIL=fixture@example.invalid",
		"GIT_COMMITTER_NAME=fixture",
		"GIT_COMMITTER_EMAIL=fixture@example.invalid",
		"LC_ALL=C",
	}
}

// Git runs one fixture git command in dir and fails the test if it errors.
func (f *Forge) Git(tb testing.TB, dir string, args ...string) string {
	tb.Helper()
	return f.git(tb, dir, args...)
}

func (f *Forge) git(tb testing.TB, dir string, args ...string) string {
	tb.Helper()
	out, err := f.tryGit(tb, dir, args...)
	if err != nil {
		tb.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (f *Forge) tryGit(tb testing.TB, dir string, args ...string) (string, error) {
	tb.Helper()
	if dir == "" {
		dir = f.root
	}
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, f.tools.Git, args...)
	cmd.Dir = dir
	cmd.Env = FixtureEnv(f.home)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// Git runs a fixture git command outside any forge, for tests that only need a
// local repository. home is the isolated HOME to run it under.
func Git(tb testing.TB, tools Tools, home, dir string, args ...string) string {
	tb.Helper()
	out, err := TryGit(tb, tools, home, dir, args...)
	if err != nil {
		tb.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// TryGit is Git without the assertion, for commands expected to fail.
func TryGit(tb testing.TB, tools Tools, home, dir string, args ...string) (string, error) {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, tools.Git, args...)
	cmd.Dir = dir
	cmd.Env = FixtureEnv(home)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func writeFile(tb testing.TB, path, content string) {
	tb.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		tb.Fatalf("writing %s: %v", path, err)
	}
}

// WriteFile creates a file under dir, making parent directories as needed.
func WriteFile(tb testing.TB, dir, rel, content string) string {
	tb.Helper()
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		tb.Fatalf("creating %s: %v", filepath.Dir(full), err)
	}
	writeFile(tb, full, content)
	return full
}

// --- leak assertions ---------------------------------------------------------
//
// These live beside the forge because both halves of the credential circuit
// assert exactly the same thing about exactly the same values, and an assertion
// that is copied is an assertion that eventually differs. They are phrased
// against pkg/redact rather than against strings.Contains so that a test agrees
// with the production redactor about what counts as a match — including its
// short-value guard, which is the reason a hand-rolled check would disagree.

// NoSecretIn fails tb when text contains any value in set.
//
// what names the channel — "the returned error", "the emitted log" — because
// the first question on a failure is which surface leaked, not what the value
// was. The value itself is never printed; a test that leaked the credential
// into the test log would have reproduced the bug it was written to catch.
func NoSecretIn(tb testing.TB, set *redact.Set, what, text string) {
	tb.Helper()
	if set == nil {
		tb.Fatalf("NoSecretIn(%s): the redact.Set is empty, so this assertion proves nothing "+
			"— the test's credential is probably shorter than redact.MinLen", what)
	}
	if set.Contains(text) {
		tb.Errorf("%s contains leased credential material.\n"+
			"Redacted form of what leaked:\n%s", what, set.String(text))
	}
}

// NoSecretUnder walks root and fails tb for any file whose name or contents
// contain a value in set.
//
// This is the assertion that a credential never reached the disk, and it is
// deliberately blunt: it does not know whether the leak would be an askpass
// script, a credential-helper file, a .git/config entry or a stray temporary,
// and it does not need to. Anything a future change writes lands in one of
// these files or it does not exist.
//
// It returns the number of files scanned so a caller can refuse a vacuous pass:
// an assertion over an empty tree succeeds for the wrong reason.
func NoSecretUnder(tb testing.TB, set *redact.Set, root string) int {
	tb.Helper()
	if set == nil {
		tb.Fatalf("NoSecretUnder(%s): the redact.Set is empty, so this assertion proves nothing", root)
		return 0
	}
	scanned := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// A file removed while we walked is not a finding.
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if set.Contains(d.Name()) {
			tb.Errorf("the file name %s under %s contains leased credential material", p, root)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		scanned++
		b, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if set.Contains(string(b)) {
			tb.Errorf("%s contains leased credential material; a credential reached the disk", p)
		}
		return nil
	})
	if err != nil {
		tb.Fatalf("walking %s: %v", root, err)
	}
	return scanned
}
