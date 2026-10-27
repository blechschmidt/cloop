package upgrade_test

// The scratch deployment a rehearsal runs in: one hub directory served by
// members of two builds, a load balancer in front of them, the fakes their
// credentials are spent against, and an enrolled device.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"github.com/blechschmidt/cloop/pkg/provenance"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/version"
)

// token protects every hub: the static token the test's API calls carry.
const token = "upgrade-rehearsal-token-0123456789"

// secretKey configures every hub's secret broker, the same way everywhere: an
// inherited key would make the run's lease depend on who runs the test.
const secretKey = "upgrade-rehearsal-secret-key"

// The people the identity provider signs in: an administrator by email, and
// an operator by a group a role mapping names. The hub denies everyone else,
// and quotas count the operator — never an administrator.
const (
	adminEmail    = "admin@example.com"
	operatorEmail = "dev@example.com"
	operatorGroup = "engineers"
)

// builds name the two sides of the rehearsal in logs and member names.
const (
	buildRelease = "release"
	buildMain    = "main"
)

// world is one scratch deployment.
type world struct {
	t    *testing.T
	ctx  context.Context
	root string

	rel      release // the release rehearsed from
	mainBin  string  // the build under test
	mainInfo binInfo

	relDir, mainDir, deviceBin string
	home, cloopHome            string
	hubDir, proj, proj2        string
	gitconfig                  string

	// hubEnv is added to every member's environment: the routes and trust
	// that reach the fakes.
	hubEnv []string

	idp *ssohubtest.IdP
	lb  *httpLB

	mu      sync.Mutex
	procs   []*proc
	members []*member
	agent   *proc
}

// proc is one process the world started, in a process group of its own.
type proc struct {
	name   string
	cmd    *exec.Cmd
	exited chan struct{}
	log    string
}

// member is one `cloop ui` serving the hub directory.
type member struct {
	*proc
	build string // buildRelease or buildMain
	bin   string
	port  int
	id    string // the member id, from /api/cluster
}

func (m *member) url() string { return fmt.Sprintf("http://127.0.0.1:%d", m.port) }

func (m *member) String() string { return fmt.Sprintf("%s member :%d", m.build, m.port) }

// newWorld obtains both builds and lays out the scratch tree.
func newWorld(t *testing.T) *world {
	t.Helper()
	requireRehearsal(t)
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skipf("the rehearsal runs cloop's linux-amd64 release, and this is %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	root, err := os.MkdirTemp("", "cloop-upgrade-")
	if err != nil {
		t.Fatal(err)
	}
	// Hubs key a run by its project's resolved path; compare against the same.
	if resolved, rerr := filepath.EvalSymlinks(root); rerr == nil {
		root = resolved
	}
	w := &world{t: t, ctx: ctx, root: root}
	t.Cleanup(w.cleanup)
	w.relDir = filepath.Join(root, "bin-release")
	w.mainDir = filepath.Join(root, "bin-main")
	w.deviceBin = filepath.Join(root, "device-bin")
	w.home = filepath.Join(root, "home")
	w.cloopHome = filepath.Join(root, "home", ".cloop")
	w.hubDir = filepath.Join(root, "hub")
	w.proj = filepath.Join(root, "proj")
	w.proj2 = filepath.Join(root, "proj2")
	for _, d := range []string{w.relDir, w.mainDir, w.deviceBin, w.home, w.hubDir, w.proj, w.proj2} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	w.gitconfig = filepath.Join(w.home, ".gitconfig")
	writeFile(t, w.gitconfig, "[user]\n\tname = Rehearsal\n\temail = rehearsal@example.com\n"+
		"[init]\n\tdefaultBranch = main\n[safe]\n\tdirectory = *\n", 0o644)

	w.provisionMain()
	w.provisionRelease()
	t.Logf("rehearsing %s (protocol %d, schema %d, sequence %d) → %s (protocol %d, schema %d, sequence %d)",
		w.rel.tag, w.rel.info.Protocol, w.rel.info.Schema, w.rel.info.Sequence,
		w.mainInfo.Version, w.mainInfo.Protocol, w.mainInfo.Schema, w.mainInfo.Sequence)
	if w.mainInfo.Schema < w.rel.info.Schema {
		t.Fatalf("the build under test embeds schema %d, behind %s's %d: it is older than the release",
			w.mainInfo.Schema, w.rel.tag, w.rel.info.Schema)
	}
	return w
}

// provisionMain builds the binary under test, or links the prebuilt one.
// A build of this checkout is stamped as the :8888 deploy stamps its build —
// dev+g<short>, the commit and its place on main — so the members compare
// builds the way a deployed hub does.
func (w *world) provisionMain() {
	t := w.t
	w.mainBin = filepath.Join(w.mainDir, "cloop")
	if prebuilt := strings.TrimSpace(os.Getenv(mainBinEnv)); prebuilt != "" {
		abs, err := filepath.Abs(prebuilt)
		if err == nil {
			_, err = os.Stat(abs)
		}
		if err != nil {
			t.Fatalf("%s=%s: %v", mainBinEnv, prebuilt, err)
		}
		if err := os.Symlink(abs, w.mainBin); err != nil {
			t.Fatal(err)
		}
	} else {
		ldflags := ""
		if stamp := deployStamp(); stamp != "" {
			ldflags = stamp
		} else {
			t.Logf("this checkout's place on main is unknown (no git, or a shallow clone): the build under test is unstamped")
		}
		ctx, cancel := context.WithTimeout(w.ctx, 8*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags", ldflags, "-o", w.mainBin, ".")
		cmd.Dir = repoRoot()
		cmd.Env = append(append(os.Environ(), goEnv...), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build the binary under test: %v\n%s", err, out)
		}
	}
	info, err := readBinInfo(w.mainBin)
	if err != nil {
		t.Fatal(err)
	}
	w.mainInfo = info
}

// deployStamp is the -ldflags the :8888 deploy builds with, or "" when this
// checkout's first-parent position cannot be counted.
func deployStamp() string {
	root := repoRoot()
	git := func(args ...string) string {
		out, err := exec.Command("git", append([]string{"-C", root}, args...)...).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	if git("rev-parse", "--is-shallow-repository") != "false" {
		return ""
	}
	commit, seq, short := git("rev-parse", "HEAD"), git("rev-list", "--count", "--first-parent", "HEAD"),
		git("rev-parse", "--short", "HEAD")
	if commit == "" || seq == "" || short == "" {
		return ""
	}
	const pkg = "github.com/blechschmidt/cloop/pkg/version"
	return fmt.Sprintf("-X %s.Version=dev+g%s -X %s.Sequence=%s -X %s.Commit=%s", pkg, short, pkg, seq, pkg, commit)
}

// provisionRelease fetches and verifies the release to rehearse from.
func (w *world) provisionRelease() {
	t := w.t
	plan, err := planFrom(os.Getenv(fromEnv), ownReleaseTag(w.mainInfo), version.PublishedReleases(),
		func() (string, error) { return githubReleases().latestTag(w.ctx) })
	if err != nil {
		w.skipOrFail("decide which release to rehearse from", err)
	}
	if plan.tag == w.mainInfo.Version {
		t.Fatalf("asked to rehearse from %s to itself (%s)", plan.tag, plan.why)
	}
	verifier := &provenance.Verifier{Binary: os.Getenv(cosignEnv)}
	rel, err := obtainRelease(w.ctx, githubReleases(), cacheRoot(), plan.tag, w.relDir, verifier, t.Logf)
	if err != nil {
		w.skipOrFail("obtain release "+plan.tag, err)
	}
	from := "downloaded"
	if rel.cached {
		from = "cached"
	}
	issuer, identity := verifier.TrustRoot()
	t.Logf("release %s (%s): %s, signature verified against %s (issuer %s)", rel.tag, plan.why, from, identity, issuer)
	w.rel = rel
}

// skipOrFail skips for a host that could not be reached and fails for
// anything else.
func (w *world) skipOrFail(what string, err error) {
	w.t.Helper()
	if isNoNetwork(err) {
		w.t.Skipf("no network: cannot %s: %v", what, err)
	}
	w.t.Fatalf("%s: %v", what, err)
}

func isNoNetwork(err error) bool {
	for e := err; e != nil; {
		if e == errNoNetwork {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			break
		}
		e = u.Unwrap()
	}
	return false
}

// ── environments ─────────────────────────────────────────────────────────────

// inherited is the test's environment without anything that would make a
// spawned process behave differently from one on a fresh runner: cloop's own
// settings (the agent inherits CLOOP_SECRET_KEY from the service it runs
// under), Claude, Copilot and GitHub credentials, proxies and trust roots.
func inherited() []string {
	var out []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		upper := strings.ToUpper(name)
		switch {
		case strings.HasPrefix(upper, "CLOOP_"), strings.HasPrefix(upper, "CLAUDE"),
			strings.HasPrefix(upper, "ANTHROPIC_"), strings.HasPrefix(upper, "COPILOT_"),
			strings.HasPrefix(upper, "GIT_"), strings.HasPrefix(upper, "SSL_CERT_"),
			strings.HasSuffix(upper, "_PROXY"), upper == "GITHUB_TOKEN", upper == "GH_TOKEN",
			upper == "KUBECONFIG", upper == "PATH", upper == "HOME":
			continue
		}
		out = append(out, kv)
	}
	return out
}

// baseEnv is what every process of the world gets, binDir first on PATH.
func (w *world) baseEnv(binDir, home string) []string {
	return append(inherited(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"HOME="+home,
		"NO_COLOR=1",
		"TERM=dumb",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+w.gitconfig,
		"GIT_TERMINAL_PROMPT=0",
	)
}

// hubSideEnv is the environment of the members and of the CLI run against
// the hub's directories.
func (w *world) hubSideEnv(binDir string) []string {
	return append(w.baseEnv(binDir, w.home),
		"CLOOP_HOME="+w.cloopHome,
		"CLOOP_UI_TOKEN="+token,
		"CLOOP_SECRET_KEY="+secretKey,
	)
}

// binFor is the binary of a build.
func (w *world) binFor(build string) string {
	if build == buildMain {
		return w.mainBin
	}
	return w.rel.bin
}

// cli runs a cloop subcommand of build in dir to completion and returns what
// it printed; a failure fails the test.
func (w *world) cli(build, dir string, args ...string) string {
	w.t.Helper()
	out, err := w.cliErr(build, dir, nil, args...)
	if err != nil {
		w.t.Fatalf("%s cloop %s in %s: %v\n%s", build, strings.Join(args, " "), dir, err, out)
	}
	return out
}

// cliErr is cli returning the error, with extra environment.
func (w *world) cliErr(build, dir string, extra []string, args ...string) (string, error) {
	bin := w.binFor(build)
	ctx, cancel := context.WithTimeout(w.ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = append(w.hubSideEnv(filepath.Dir(bin)), extra...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ── processes ────────────────────────────────────────────────────────────────

// spawn starts a long-running process in a process group of its own, logging
// to a file under the scratch tree.
func (w *world) spawn(name, dir string, env []string, bin string, args ...string) *proc {
	w.t.Helper()
	logPath := filepath.Join(w.root, name+".log")
	logf, err := os.Create(logPath)
	if err != nil {
		w.t.Fatal(err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = logf.Close()
		w.t.Fatalf("start %s: %v", name, err)
	}
	p := &proc{name: name, cmd: cmd, exited: make(chan struct{}), log: logPath}
	go func() {
		_ = cmd.Wait()
		_ = logf.Close()
		close(p.exited)
	}()
	w.mu.Lock()
	w.procs = append(w.procs, p)
	w.mu.Unlock()
	return p
}

// signal sends sig to the process's group.
func (p *proc) signal(sig syscall.Signal) {
	if p != nil && p.cmd.Process != nil {
		_ = syscall.Kill(-p.cmd.Process.Pid, sig)
	}
}

func (p *proc) running() bool {
	select {
	case <-p.exited:
		return false
	default:
		return true
	}
}

// startMember starts a `cloop ui` of build in the hub directory, on loopback.
// Its git proxy and Kubernetes monitor listen on ports of its own, named in
// its instance overlay; the shared configuration advertises the load
// balancers in front of all of them.
func (w *world) startMember(build string, overlay func(port int) string) *member {
	w.t.Helper()
	port := freePort(w.t)
	if overlay != nil {
		writeFile(w.t, filepath.Join(w.hubDir, ".cloop", fmt.Sprintf("config.ui-%d.yaml", port)), overlay(port), 0o600)
	}
	bin := w.binFor(build)
	env := append(w.hubSideEnv(filepath.Dir(bin)), w.hubEnv...)
	p := w.spawn(fmt.Sprintf("%s-member-%d", build, port), w.hubDir, env, bin,
		"ui", "--port", strconv.Itoa(port), "--listen", "127.0.0.1", "--no-browser",
		"--projects", w.proj, "--projects", w.proj2)
	m := &member{proc: p, build: build, bin: bin, port: port}
	w.mu.Lock()
	w.members = append(w.members, m)
	w.mu.Unlock()
	w.eventually(m.String()+" to answer /healthz", 90*time.Second, func() bool {
		if !p.running() {
			w.t.Fatalf("%s exited while starting:\n%s", m, tailFile(p.log, 40))
		}
		resp, err := http.Get(m.url() + "/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	return m
}

// stopMember stops a member as an orchestrator replacing it does, and waits
// for it to exit.
func (w *world) stopMember(m *member) {
	w.t.Helper()
	m.signal(syscall.SIGTERM)
	select {
	case <-m.exited:
	case <-time.After(90 * time.Second):
		w.t.Fatalf("%s did not exit within 90s of SIGTERM:\n%s", m, tailFile(m.log, 40))
	}
	if code := m.cmd.ProcessState.ExitCode(); code != 0 {
		w.t.Errorf("%s exited %d on SIGTERM:\n%s", m, code, tailFile(m.log, 40))
	}
	if w.lb != nil {
		w.lb.remove(m.url())
	}
}

func (w *world) cleanup() {
	w.mu.Lock()
	procs := append([]*proc(nil), w.procs...)
	w.mu.Unlock()
	for _, p := range procs {
		p.signal(syscall.SIGKILL)
	}
	// The device's workloads run in process groups of their own, under the
	// agent: found by their working directory, never by a pattern on the
	// command line, which would match the shell that looks.
	for _, pid := range pidsUnder(filepath.Join(w.root, "device")) {
		if pgid, err := syscall.Getpgid(pid); err == nil && pgid > 1 {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		}
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	for _, p := range procs {
		select {
		case <-p.exited:
		case <-time.After(10 * time.Second):
		}
	}
	if w.lb != nil {
		w.lb.close()
	}
	if w.t.Failed() {
		for _, p := range procs {
			w.t.Logf("── %s (tail) ──\n%s", p.name, tailFile(p.log, 60))
		}
	}
	if os.Getenv(keepEnv) != "" {
		w.t.Logf("%s set: leaving %s", keepEnv, w.root)
		return
	}
	if err := os.RemoveAll(w.root); err != nil {
		w.t.Logf("remove %s: %v", w.root, err)
	}
}

// pidsUnder lists the processes whose working directory is dir or below it.
func pidsUnder(dir string) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		cwd, err := os.Readlink(filepath.Join("/proc", e.Name(), "cwd"))
		if err == nil && (cwd == dir || strings.HasPrefix(cwd, dir+string(os.PathSeparator))) {
			out = append(out, pid)
		}
	}
	return out
}

// ── the load balancers ───────────────────────────────────────────────────────

// httpLB is round-robin over the members, skipping for a few seconds one that
// failed to answer — what any health-checking load balancer does, and all a
// cluster needs from one: no stickiness. Members join and leave it as the
// rehearsal starts and stops them.
type httpLB struct {
	srv  *http.Server
	port int
	next atomic.Uint64

	mu       sync.Mutex
	backends []*backend
}

type backend struct {
	base string
	rp   *httputil.ReverseProxy
	mu   sync.Mutex
	down time.Time
}

func startHTTPLB(t *testing.T) *httpLB {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lb := &httpLB{port: ln.Addr().(*net.TCPAddr).Port}
	lb.srv = &http.Server{Handler: http.HandlerFunc(lb.serve), ReadHeaderTimeout: 30 * time.Second}
	go func() { _ = lb.srv.Serve(ln) }()
	return lb
}

func (lb *httpLB) url() string { return fmt.Sprintf("http://127.0.0.1:%d", lb.port) }

func (lb *httpLB) add(base string) {
	u, _ := url.Parse(base)
	be := &backend{base: base, rp: httputil.NewSingleHostReverseProxy(u)}
	be.rp.FlushInterval = -1
	be.rp.ErrorHandler = func(rw http.ResponseWriter, _ *http.Request, _ error) {
		be.mu.Lock()
		be.down = time.Now().Add(3 * time.Second)
		be.mu.Unlock()
		rw.WriteHeader(http.StatusBadGateway)
	}
	lb.mu.Lock()
	lb.backends = append(lb.backends, be)
	lb.mu.Unlock()
}

func (lb *httpLB) remove(base string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for i, be := range lb.backends {
		if be.base == base {
			lb.backends = append(lb.backends[:i], lb.backends[i+1:]...)
			return
		}
	}
}

func (lb *httpLB) serve(rw http.ResponseWriter, r *http.Request) {
	lb.mu.Lock()
	backends := append([]*backend(nil), lb.backends...)
	lb.mu.Unlock()
	for i := 0; i < len(backends); i++ {
		be := backends[int(lb.next.Add(1))%len(backends)]
		be.mu.Lock()
		down := time.Now().Before(be.down)
		be.mu.Unlock()
		if !down {
			be.rp.ServeHTTP(rw, r)
			return
		}
	}
	rw.WriteHeader(http.StatusServiceUnavailable)
}

func (lb *httpLB) close() { _ = lb.srv.Close() }

// tcpLB passes TLS through to the members' git proxies or Kubernetes
// monitors, round-robin over the ones that accept a connection: the address a
// workload is given stays valid while the members behind it come and go, and
// a member that does not hold a session forwards it to the one that does.
type tcpLB struct {
	ln   net.Listener
	next atomic.Uint64

	mu       sync.Mutex
	backends []string
}

func startTCPLB(t *testing.T) *tcpLB {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lb := &tcpLB{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go lb.pipe(c)
		}
	}()
	return lb
}

func (lb *tcpLB) port() int { return lb.ln.Addr().(*net.TCPAddr).Port }

func (lb *tcpLB) add(addr string) {
	lb.mu.Lock()
	lb.backends = append(lb.backends, addr)
	lb.mu.Unlock()
}

func (lb *tcpLB) pipe(c net.Conn) {
	defer c.Close()
	lb.mu.Lock()
	backends := append([]string(nil), lb.backends...)
	lb.mu.Unlock()
	for i := 0; i < len(backends); i++ {
		addr := backends[int(lb.next.Add(1))%len(backends)]
		up, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			continue
		}
		defer up.Close()
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(up, c); closeWrite(up); done <- struct{}{} }()
		go func() { _, _ = io.Copy(c, up); closeWrite(c); done <- struct{}{} }()
		<-done
		<-done
		return
	}
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

// ── HTTP ─────────────────────────────────────────────────────────────────────

// response is one answer from a member or the load balancer.
type response struct {
	status   int
	body     []byte
	servedBy string
}

func (r response) String() string {
	return fmt.Sprintf("%d %s", r.status, strings.TrimSpace(string(r.body)))
}

func (r response) decode(t *testing.T, out any) {
	t.Helper()
	if err := json.Unmarshal(r.body, out); err != nil {
		t.Fatalf("decode %s: %v", r, err)
	}
}

// api calls base with the static token.
func (w *world) api(base, method, path string, body any) response {
	w.t.Helper()
	return w.do(nil, base, method, path, body, "Bearer "+token)
}

// do sends one request: with client (nil: a plain one) and authorization
// (empty: none — the browser's cookie, or nothing).
func (w *world) do(client *http.Client, base, method, path string, body any, authorization string) response {
	w.t.Helper()
	var rd io.Reader
	if body != nil {
		blob, err := json.Marshal(body)
		if err != nil {
			w.t.Fatal(err)
		}
		rd = bytes.NewReader(blob)
	}
	req, err := http.NewRequestWithContext(w.ctx, method, base+path, rd)
	if err != nil {
		w.t.Fatal(err)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// The origin the members serve the dashboard at, which a browser sends
	// on every unsafe request.
	if w.lb != nil {
		req.Header.Set("Origin", w.lb.url())
	}
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return response{status: 0, body: []byte(err.Error())}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return response{status: resp.StatusCode, body: data, servedBy: resp.Header.Get("X-Cloop-Served-By")}
}

// signIn completes a browser sign-in at base through the identity provider,
// as email in groups, and returns the browser. Cookies are per host, not per
// port, so the session it holds is presented to every member.
func (w *world) signIn(base, email string, groups ...string) *http.Client {
	w.t.Helper()
	w.idp.SetIdentity(email, groups...)
	jar, err := cookiejar.New(nil)
	if err != nil {
		w.t.Fatal(err)
	}
	c := &http.Client{Jar: jar, Timeout: time.Minute}
	req, err := http.NewRequestWithContext(w.ctx, http.MethodGet, base+"/", nil)
	if err != nil {
		w.t.Fatal(err)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp, err := c.Do(req)
	if err != nil {
		w.t.Fatalf("sign in at %s: %v", base, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/" {
		w.t.Fatalf("sign in at %s ended at %s with %d", base, resp.Request.URL, resp.StatusCode)
	}
	return c
}

// sessionCookie is the session the browser holds for the members' host.
func sessionCookie(t *testing.T, browser *http.Client, base string) string {
	t.Helper()
	u, _ := url.Parse(base)
	var names []string
	for _, c := range browser.Jar.Cookies(u) {
		if strings.Contains(strings.ToLower(c.Name), "session") {
			return c.Value
		}
		names = append(names, c.Name)
	}
	t.Fatalf("the browser holds no session cookie for %s (cookies: %v)", base, names)
	return ""
}

// ── cluster status ───────────────────────────────────────────────────────────

type clusterStatus struct {
	Self    string `json:"self"`
	Leader  string `json:"leader"`
	Members []struct {
		ID           string `json:"id"`
		AdvertiseURL string `json:"advertise_url"`
		Alive        bool   `json:"alive"`
		Version      string `json:"version"`
	} `json:"members"`
	Owners []struct {
		Kind   string `json:"kind"`
		Key    string `json:"key"`
		Member string `json:"member"`
		Alive  bool   `json:"alive"`
	} `json:"owners"`
}

func (s clusterStatus) live() int {
	n := 0
	for _, m := range s.Members {
		if m.Alive {
			n++
		}
	}
	return n
}

func (s clusterStatus) alive(id string) bool {
	for _, m := range s.Members {
		if m.ID == id {
			return m.Alive
		}
	}
	return false
}

func (s clusterStatus) owner(kind, key string) string {
	for _, o := range s.Owners {
		if o.Kind == kind && o.Key == key {
			return o.Member
		}
	}
	return ""
}

func (s clusterStatus) memberAt(port int) string {
	suffix := fmt.Sprintf(":%d", port)
	for _, m := range s.Members {
		if strings.HasSuffix(m.AdvertiseURL, suffix) {
			return m.ID
		}
	}
	return ""
}

// waitCluster polls /api/cluster at base until cond holds.
func (w *world) waitCluster(base, what string, cond func(clusterStatus) bool) clusterStatus {
	w.t.Helper()
	var last clusterStatus
	w.eventually(what, 90*time.Second, func() bool {
		r := w.api(base, http.MethodGet, "/api/cluster", nil)
		if r.status != http.StatusOK {
			return false
		}
		var st clusterStatus
		if json.Unmarshal(r.body, &st) != nil {
			return false
		}
		last = st
		return cond(st)
	})
	return last
}

// identify records each member's id.
func (w *world) identify(st clusterStatus, members ...*member) {
	w.t.Helper()
	for _, m := range members {
		if m.id = st.memberAt(m.port); m.id == "" {
			w.t.Fatalf("no member of the cluster advertises %s's port: %+v", m, st.Members)
		}
	}
}

// memberByID is the member whose id is id, or nil.
func (w *world) memberByID(id string) *member {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, m := range w.members {
		if m.id == id {
			return m
		}
	}
	return nil
}

// ── databases ────────────────────────────────────────────────────────────────

// dbPath is the state database of a directory.
func dbPath(dir string) string { return filepath.Join(dir, ".cloop", "state.db") }

// query runs one read-only query and returns every row as strings.
func (w *world) query(dir, q string, args ...any) [][]string {
	w.t.Helper()
	rows, err := w.tryQuery(dir, q, args...)
	if err != nil {
		w.t.Fatalf("query %q on %s: %v", q, dir, err)
	}
	return rows
}

// tryQuery is query for a wait condition: an error is "not yet".
func (w *world) tryQuery(dir, q string, args ...any) ([][]string, error) {
	conn, err := statedb.OpenConn(dbPath(dir), statedb.ReadOnly)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return scanAll(conn.QueryContext(w.ctx, q, args...))
}

// exec writes to dir's database through the connection policy, as the newer
// build or an operator would.
func (w *world) exec(dir string, stmts ...string) {
	w.t.Helper()
	conn, err := statedb.OpenConn(dbPath(dir), statedb.ReadWrite)
	if err != nil {
		w.t.Fatalf("open %s: %v", dbPath(dir), err)
	}
	defer conn.Close()
	for _, s := range stmts {
		if _, err := conn.ExecContext(w.ctx, s); err != nil {
			w.t.Fatalf("%s on %s: %v", s, dbPath(dir), err)
		}
	}
}

func scanAll(rows *sql.Rows, err error) ([][]string, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out [][]string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make([]string, len(cols))
		for i, v := range vals {
			row[i] = sqlString(v)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// sqlString renders a column's value; NULL and a blob are told apart from
// any string.
func sqlString(v any) string {
	switch x := v.(type) {
	case nil:
		return "\x00NULL"
	case []byte:
		return "\x00blob:" + fmt.Sprintf("%x", x)
	case string:
		return x
	default:
		return fmt.Sprint(x)
	}
}

// ── utilities ────────────────────────────────────────────────────────────────

// eventually polls cond until it holds, failing with what it waited for.
func (w *world) eventually(what string, limit time.Duration, cond func() bool) {
	w.t.Helper()
	deadline := time.Now().Add(limit)
	for !cond() {
		if time.Now().After(deadline) {
			w.t.Fatalf("timed out after %s waiting for %s", limit, what)
		}
		select {
		case <-w.ctx.Done():
			w.t.Fatalf("cancelled while waiting for %s", what)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func writeFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, body string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(body); err != nil {
		t.Fatal(err)
	}
}

func readFile(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

func tailFile(path string, n int) string { return tail(readFile(path), n) }

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
