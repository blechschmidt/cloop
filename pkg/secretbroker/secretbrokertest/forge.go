package secretbrokertest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
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
)

// Forge is a git smart-HTTP server behind TLS that stands in for github.com: it
// serves bare repositories through git-http-backend and admits a request only
// when its basic-auth password is a token the fake GitHub would honour now and
// that token is scoped to the repository addressed.
//
// That second half is the point. A forge that accepted any password would let
// a test pass whether or not a token was ever refreshed; this one refuses the
// first token the moment the fake clock passes its hour.
type Forge struct {
	// URL is the server's https base, e.g. https://127.0.0.1:40123. Empty for
	// a forge from NewForgeHandler, which its caller serves.
	URL string
	// Addr is the listener's host:port, likewise.
	Addr string
	// Root holds the bare repositories, <owner>/<name>.git.
	Root string

	gh      *GitHub
	git     string
	backend string
	home    string
	srv     *httptest.Server

	mu       sync.Mutex
	accepted int
	refused  int
}

// GitTools finds git and git-http-backend, or skips the test.
func GitTools(t testing.TB) (gitBin, backend string) {
	t.Helper()
	gitBin, backend, err := FindGitTools()
	if err != nil {
		t.Skip(err.Error())
	}
	return gitBin, backend
}

// FindGitTools is GitTools for a caller that is not a test: the forge served
// from a container in a cluster (Task 20385), which has no test to skip.
func FindGitTools() (gitBin, backend string, err error) {
	gitBin, err = exec.LookPath("git")
	if err != nil {
		return "", "", fmt.Errorf("no git binary on PATH; the forge drives a real git")
	}
	var candidates []string
	if out, err := exec.Command(gitBin, "--exec-path").Output(); err == nil {
		candidates = append(candidates, filepath.Join(strings.TrimSpace(string(out)), "git-http-backend"))
	}
	candidates = append(candidates, "/usr/lib/git-core/git-http-backend", "/usr/libexec/git-core/git-http-backend")
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() && st.Mode().Perm()&0o111 != 0 {
			return gitBin, c, nil
		}
	}
	return "", "", fmt.Errorf("git-http-backend not found (looked in %s)", strings.Join(candidates, ", "))
}

// ForgeConfig describes a forge served by something other than a test: the
// stand-alone server tests/kube runs inside a cluster, answering as
// github.com (Task 20385).
type ForgeConfig struct {
	// GitHub decides which tokens the forge honours, for which repositories.
	GitHub *GitHub
	// Root holds the bare repositories, <owner>/<name>.git. Created if missing.
	Root string
	// Home is HOME for the forge's own git commands. Created if missing.
	Home string
	// Repos ("owner/name") are each seeded with one commit on main, unless
	// they already exist under Root.
	Repos []string
}

// NewForgeHandler prepares a forge without starting a server: its tools found
// and its repositories seeded. The Forge is an http.Handler; the caller serves
// it over TLS on a listener of its own, and URL and Addr stay empty.
func NewForgeHandler(cfg ForgeConfig) (*Forge, error) {
	if cfg.GitHub == nil {
		return nil, fmt.Errorf("forge: no GitHub to authorise requests against")
	}
	if strings.TrimSpace(cfg.Root) == "" || strings.TrimSpace(cfg.Home) == "" {
		return nil, fmt.Errorf("forge: Root and Home are required")
	}
	gitBin, backend, err := FindGitTools()
	if err != nil {
		return nil, err
	}
	for _, dir := range []string{cfg.Root, cfg.Home} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("forge: %w", err)
		}
	}
	f := &Forge{gh: cfg.GitHub, git: gitBin, backend: backend, Root: cfg.Root, home: cfg.Home}
	for _, repo := range cfg.Repos {
		if err := f.initRepo(repo); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// ServeHTTP authenticates a request against the fake GitHub and answers it
// with git-http-backend.
func (f *Forge) ServeHTTP(w http.ResponseWriter, r *http.Request) { f.serve(w, r) }

// NewForge starts a forge serving repos ("owner/name"), each seeded with one
// commit on main.
func NewForge(t testing.TB, gh *GitHub, repos ...string) *Forge {
	t.Helper()
	return NewForgeOn(t, "127.0.0.1:0", gh, repos...)
}

// NewForgeOn is NewForge listening on addr — an address a container on the
// docker bridge can reach, for instance.
func NewForgeOn(t testing.TB, addr string, gh *GitHub, repos ...string) *Forge {
	t.Helper()
	return newForge(t, addr, gh, nil, repos...)
}

// NewForgeWithCert is NewForgeOn serving cert — one issued for github.com by
// a test CA, so a hub in another process, trusting that CA and reaching the
// forge through a ConnectProxy, takes it for GitHub (Task 20383).
func NewForgeWithCert(t testing.TB, addr string, gh *GitHub, cert tls.Certificate, repos ...string) *Forge {
	t.Helper()
	return newForge(t, addr, gh, &cert, repos...)
}

func newForge(t testing.TB, addr string, gh *GitHub, cert *tls.Certificate, repos ...string) *Forge {
	t.Helper()
	GitTools(t) // a machine without git skips, rather than fails
	f, err := NewForgeHandler(ForgeConfig{GitHub: gh, Root: t.TempDir(), Home: t.TempDir(), Repos: repos})
	if err != nil {
		t.Fatalf("%v", err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("forge listen on %s: %v", addr, err)
	}
	f.srv = httptest.NewUnstartedServer(f)
	_ = f.srv.Listener.Close()
	f.srv.Listener = ln
	if cert != nil {
		f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
	}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.URL = f.srv.URL
	f.Addr = ln.Addr().String()
	return f
}

// Counts reports how many requests the forge admitted and refused.
func (f *Forge) Counts() (accepted, refused int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.accepted, f.refused
}

// Transport trusts the forge's self-signed certificate.
func (f *Forge) Transport() http.RoundTripper { return f.srv.Client().Transport }

// RepoURL is the forge's own URL for repo.
func (f *Forge) RepoURL(repo string) string { return f.URL + "/" + repo + ".git" }

// Ref returns the commit ref points at in repo, or "" when it does not exist.
func (f *Forge) Ref(t testing.TB, repo, ref string) string {
	t.Helper()
	out, err := f.gitCmd("", "--git-dir="+f.bare(repo), "rev-parse", "--verify", "--quiet", ref)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func (f *Forge) bare(repo string) string { return filepath.Join(f.Root, repo+".git") }

func (f *Forge) initRepo(repo string) error {
	bare := f.bare(repo)
	if _, err := os.Stat(filepath.Join(bare, "HEAD")); err == nil {
		return nil // already there: a forge restarted over its own volume
	}
	if err := os.MkdirAll(filepath.Dir(bare), 0o755); err != nil {
		return fmt.Errorf("forge: %w", err)
	}
	seed, err := os.MkdirTemp(f.home, "seed-")
	if err != nil {
		return fmt.Errorf("forge: %w", err)
	}
	defer os.RemoveAll(seed)
	must := func(dir string, args ...string) error {
		if out, err := f.gitCmd(dir, args...); err != nil {
			return fmt.Errorf("forge: git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return nil
	}
	for _, step := range []struct {
		dir  string
		args []string
	}{
		{"", []string{"init", "--bare", bare}},
		{"", []string{"--git-dir=" + bare, "symbolic-ref", "HEAD", "refs/heads/main"}},
		{"", []string{"--git-dir=" + bare, "config", "http.receivepack", "true"}},
		{"", []string{"init", seed}},
		{seed, []string{"symbolic-ref", "HEAD", "refs/heads/main"}},
	} {
		if err := must(step.dir, step.args...); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(seed, "README.md"), []byte("seed\n"), 0o644); err != nil {
		return fmt.Errorf("forge: %w", err)
	}
	for _, args := range [][]string{
		{"add", "README.md"},
		{"-c", "user.email=forge@example.invalid", "-c", "user.name=forge", "commit", "--no-gpg-sign", "-m", "seed"},
		{"push", bare, "HEAD:refs/heads/main"},
	} {
		if err := must(seed, args...); err != nil {
			return err
		}
	}
	return nil
}

func (f *Forge) gitCmd(dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, f.git, args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"HOME=" + f.home, "PATH=" + os.Getenv("PATH"), "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1", "LC_ALL=C",
	}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err
}

// serve authenticates against the fake GitHub, then runs git-http-backend as
// CGI. net/http/cgi is not used because it refuses a chunked request body,
// which is what a git proxy forwards.
func (f *Forge) serve(w http.ResponseWriter, r *http.Request) {
	repo, ok := repoOf(r.URL.Path)
	_, pass, hasAuth := r.BasicAuth()
	if !ok || !hasAuth || !f.gh.CoversRepo(pass, repo) {
		f.mu.Lock()
		f.refused++
		f.mu.Unlock()
		w.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
		http.Error(w, "fake github: bad credentials", http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	f.accepted++
	f.mu.Unlock()

	env := []string{
		"GATEWAY_INTERFACE=CGI/1.1", "SERVER_PROTOCOL=HTTP/1.1", "REQUEST_METHOD=" + r.Method,
		"QUERY_STRING=" + r.URL.RawQuery, "PATH_INFO=" + r.URL.Path, "REMOTE_ADDR=" + r.RemoteAddr,
		"REMOTE_USER=x-access-token", "GIT_PROJECT_ROOT=" + f.Root, "GIT_HTTP_EXPORT_ALL=1",
		"HOME=" + f.home, "PATH=" + os.Getenv("PATH"), "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1", "LC_ALL=C",
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		env = append(env, "CONTENT_TYPE="+ct)
	}
	if r.ContentLength > 0 {
		env = append(env, "CONTENT_LENGTH="+strconv.FormatInt(r.ContentLength, 10))
	}
	if v := r.Header.Get("Content-Encoding"); v != "" {
		env = append(env, "HTTP_CONTENT_ENCODING="+v)
	}
	if v := r.Header.Get("Git-Protocol"); v != "" {
		env = append(env, "GIT_PROTOCOL="+v)
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(r.Context(), f.backend)
	cmd.Env = env
	cmd.Dir = f.Root
	cmd.Stdin = r.Body
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	br := bufio.NewReader(bytes.NewReader(stdout.Bytes()))
	header, err := textproto.NewReader(br).ReadMIMEHeader()
	if err != nil {
		http.Error(w, fmt.Sprintf("fake github: git-http-backend produced no CGI response (%v): %s",
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

// repoOf extracts "owner/name" from a smart-HTTP path.
func repoOf(p string) (string, bool) {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) < 3 {
		return "", false
	}
	return parts[0] + "/" + strings.TrimSuffix(parts[1], ".git"), true
}

// ---------------------------------------------------------------------------
// CONNECT proxy
// ---------------------------------------------------------------------------

// ConnectProxy is an HTTP proxy that answers CONNECT to github.com:443 — and
// nothing else — by tunnelling to a forge. A workload given
// HTTPS_PROXY=http://<Addr> then clones https://github.com/<repo> exactly as
// it would in production, and its lease's credential helper, which answers for
// github.com only, answers.
type ConnectProxy struct {
	// Addr is the proxy's listen address.
	Addr string

	target string
	ln     net.Listener
	mu     sync.Mutex
	hosts  []string
	wg     sync.WaitGroup
}

// NewConnectProxy listens on listen and tunnels github.com:443 to target.
func NewConnectProxy(t testing.TB, listen, target string) *ConnectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatalf("connect proxy listen on %s: %v", listen, err)
	}
	p := &ConnectProxy{Addr: ln.Addr().String(), target: target, ln: ln}
	srv := &http.Server{Handler: http.HandlerFunc(p.serve), ReadHeaderTimeout: 10 * time.Second}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		p.wg.Wait()
	})
	return p
}

// Hosts lists the CONNECT targets asked for.
func (p *ConnectProxy) Hosts() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.hosts...)
}

func (p *ConnectProxy) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.hosts = append(p.hosts, r.Host)
	p.mu.Unlock()
	if r.Method != http.MethodConnect || r.Host != "github.com:443" {
		http.Error(w, "this proxy tunnels github.com:443 only", http.StatusForbidden)
		return
	}
	up, err := net.DialTimeout("tcp", p.target, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = up.Close()
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		_ = up.Close()
		return
	}
	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	done := make(chan struct{}, 2)
	go func() {
		if n := buf.Reader.Buffered(); n > 0 {
			pending, _ := buf.Reader.Peek(n)
			_, _ = up.Write(pending)
		}
		_, _ = io.Copy(up, conn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, up)
		done <- struct{}{}
	}()
	<-done
	_ = conn.Close()
	_ = up.Close()
	<-done
}
