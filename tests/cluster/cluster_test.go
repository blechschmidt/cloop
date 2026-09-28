// Package cluster_test runs a hub cluster for real: three `cloop ui`
// processes serving one control plane behind a load balancer, an edge agent
// enrolled through it, and a run that must survive the process streaming it
// being killed (Task 20354).
//
// The in-process tests in pkg/ui and pkg/hubcluster prove the mechanisms one
// at a time — ownership, the bus, forwarding, adoption. What only real
// processes can prove is the composition: that an agent reconnecting through
// a load balancer after its hub died lands on a survivor that recognises its
// run instead of killing it; that the survivor streams and settles it and
// merges its result; that Stop pressed anywhere reaches the one process that
// can deliver it. Two hubs in one test binary share the executor registry and
// the agent hub, which is exactly the part that could not be tested there.
//
// # What runs
//
// The harness is a stub `claude` on PATH that prints a tick a second until a
// release file appears — deterministic, no credentials, and slow enough to
// kill a hub in the middle of. It logs each start, so the test can tell a run
// that was adopted from one that was quietly started over. Every wait polls a
// named condition under a deadline and fails naming it. Everything listens on
// loopback, and every process is killed with its process group when the test
// ends.
//
// Opt in with CLOOP_CLUSTER_E2E=1 (it builds the binary and spawns processes);
// CLOOP_CLUSTER_BIN points it at a prebuilt one, CLOOP_CLUSTER_KEEP=1 leaves
// the scratch tree behind for inspection.
package cluster_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	_ "modernc.org/sqlite"
	"nhooyr.io/websocket"

	"github.com/blechschmidt/cloop/internal/hometest"
)

const (
	enableEnv = "CLOOP_CLUSTER_E2E"
	binEnv    = "CLOOP_CLUSTER_BIN"
	keepEnv   = "CLOOP_CLUSTER_KEEP"
	token     = "cluster-e2e-token"
)

func TestMain(m *testing.M) {
	// Read before Isolate moves HOME: Go's build and module caches default to
	// directories under it, and building cloop against empty ones is a cold
	// compile that also needs the network.
	goEnv = captureGoEnv()
	os.Exit(hometest.Isolate(m))
}

// goEnv carries GOCACHE, GOMODCACHE and GOPATH into the build of cloop.
var goEnv []string

func captureGoEnv() []string {
	names := []string{"GOCACHE", "GOMODCACHE", "GOPATH"}
	out, err := exec.Command("go", append([]string{"env"}, names...)...).Output()
	if err != nil {
		return nil
	}
	var env []string
	for i, v := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if i < len(names) && v != "" {
			env = append(env, names[i]+"="+v)
		}
	}
	return env
}

// world is one scratch deployment.
type world struct {
	t       *testing.T
	root    string
	bin     string
	binDir  string // the stub claude and the cloop under test, first on PATH
	home    string
	cloopH  string
	hubDir  string
	projDir string
	release string
	hubs    []*hub
	lb      *loadBalancer
	procs   []*exec.Cmd
	mu      sync.Mutex
}

type hub struct {
	port   int
	cmd    *exec.Cmd
	exited chan struct{}
	log    string
	id     string // member id, learned from /api/cluster
}

func (h *hub) url() string { return fmt.Sprintf("http://127.0.0.1:%d", h.port) }

func TestHubClusterEndToEnd(t *testing.T) {
	if os.Getenv(enableEnv) == "" {
		t.Skipf("%s is not set; this builds cloop and runs a cluster of hub processes", enableEnv)
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required for the stub harness")
	}
	w := newWorld(t)
	w.initProjects()
	for i := 0; i < 3; i++ {
		w.startHub()
	}
	w.startLoadBalancer()

	// ── 1. Membership ──────────────────────────────────────────────────────
	st := w.waitCluster("three live members and a leader", func(s clusterStatus) bool {
		return s.live() == 3 && s.Leader != ""
	})
	for _, h := range w.hubs {
		h.id = w.memberFor(st, h.port)
	}
	t.Logf("members: %s %s %s, leader %s", short(w.hubs[0].id), short(w.hubs[1].id), short(w.hubs[2].id), short(st.Leader))

	// ── 2. An agent enrolled and connected through the load balancer ───────
	agentID := w.enrollAndStartAgent()
	st = w.waitCluster("the agent's socket to be recorded", func(s clusterStatus) bool {
		return s.owner("agent", agentID) != ""
	})
	holder := w.hubByID(st.owner("agent", agentID))
	t.Logf("agent %s connected via hub %d", agentID, holder.port)

	projIdx := w.projectIndex()
	w.bindProject(projIdx, agentID)

	// ── 3. A run started on a member that does not hold the agent ──────────
	starter, watcher := w.otherTwo(holder)
	resp := w.post(starter, fmt.Sprintf("/api/run?project_idx=%d", projIdx))
	if resp.status != http.StatusOK {
		t.Fatalf("POST /api/run on hub %d = %d: %s", starter.port, resp.status, resp.body)
	}
	if resp.servedBy != holder.id {
		t.Fatalf("the run was dispatched by %s, want %s — only the member holding the agent's "+
			"socket can reach it", short(resp.servedBy), short(holder.id))
	}

	// ── 4. Its output reaches a dashboard on the third member ──────────────
	ws := w.openStream(watcher, projIdx)
	// The run's own banner, not the harness's output: the claudecode provider
	// hands text-mode output over when the harness exits.
	ws.waitFor(t, 0, "live output relayed from the run's member", func(typ, data string) bool {
		return typ == "step_output" && strings.Contains(data, "Write hello.txt")
	})

	// ── 5. A second start anywhere is refused ──────────────────────────────
	if r := w.post(watcher, fmt.Sprintf("/api/run?project_idx=%d", projIdx)); r.status != http.StatusConflict {
		t.Fatalf("a second start on hub %d = %d, want 409: %s", watcher.port, r.status, r.body)
	}

	// ── 6. The member streaming the run dies ───────────────────────────────
	w.kill(holder, syscall.SIGKILL)
	st = w.waitClusterVia(watcher, "the run to be adopted by a surviving member", func(s clusterStatus) bool {
		o := s.owner("run", w.projDir)
		return o != "" && o != holder.id && s.alive(o) && s.owner("agent", agentID) == o
	})
	adopter := w.hubByID(st.owner("run", w.projDir))
	t.Logf("run adopted by hub %d after hub %d was killed", adopter.port, holder.port)
	w.waitClusterVia(watcher, "a surviving leader", func(s clusterStatus) bool {
		return s.Leader != "" && s.Leader != holder.id && s.alive(s.Leader)
	})

	// ── 7. It finishes, and its result is merged into the hub's project ────
	// Frames from here on: the membership change may already have told the
	// watcher the dead member's run stopped, and that is not the end we want.
	mark := ws.mark()
	if err := os.WriteFile(w.release, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	w.waitTaskStatus(1, "done")
	w.waitProjectStatus("complete")
	if n := w.stubStarts(); n != 1 {
		t.Fatalf("the harness was started %d times for one task: the run was started over, not adopted", n)
	}
	w.waitCluster("the finished run's owner row to be released", func(s clusterStatus) bool {
		return s.owner("run", w.projDir) == ""
	})
	ws.waitFor(t, mark, "the run's end, relayed", func(typ, data string) bool {
		return typ == "run_state" && strings.Contains(data, `"running":false`)
	})
	ws.close()

	// ── 8. Stop pressed on a member that is not streaming the run ──────────
	if err := os.Remove(w.release); err != nil {
		t.Fatal(err)
	}
	w.addTask("Write world.txt")
	starts := w.stubStarts()
	var survivors []*hub
	for _, h := range w.hubs {
		if h != holder {
			survivors = append(survivors, h)
		}
	}
	if r := w.post(survivors[0], fmt.Sprintf("/api/run?project_idx=%d", projIdx)); r.status != http.StatusOK {
		t.Fatalf("second run on hub %d = %d: %s", survivors[0].port, r.status, r.body)
	}
	w.waitStubStarts(starts + 1)
	st = w.waitClusterVia(survivors[0], "the second run to be owned", func(s clusterStatus) bool {
		return s.owner("run", w.projDir) != ""
	})
	runOwner := st.owner("run", w.projDir)
	stopper := survivors[0]
	if stopper.id == runOwner {
		stopper = survivors[1]
	}
	r := w.post(stopper, fmt.Sprintf("/api/stop?project_idx=%d", projIdx))
	if r.status != http.StatusOK || !strings.Contains(r.body, `"ok":true`) {
		t.Fatalf("Stop on hub %d = %d: %s", stopper.port, r.status, r.body)
	}
	if r.servedBy != runOwner {
		t.Fatalf("Stop was answered by %s, want the run's member %s", short(r.servedBy), short(runOwner))
	}
	w.waitProjectStatus("paused")
	w.waitCluster("the stopped run's owner row to be released", func(s clusterStatus) bool {
		return s.owner("run", w.projDir) == ""
	})
	if got, err := w.queryProject(`SELECT status FROM plan_tasks WHERE id = 2`); err != nil || got == "done" {
		t.Fatalf("task 2 is %q (%v) after Stop; a stopped run must not complete it", got, err)
	}

	// ── 9. A rolling update: the member streaming a run is shut down ───────
	// SIGTERM is what an orchestrator sends a replica it is replacing. The
	// member hands over what it owns on the way out, so the last one standing
	// picks the run up without waiting out a failure-detection timeout.
	starts = w.stubStarts()
	if r := w.post(stopper, fmt.Sprintf("/api/run?project_idx=%d", projIdx)); r.status != http.StatusOK {
		t.Fatalf("resumed run on hub %d = %d: %s", stopper.port, r.status, r.body)
	}
	w.waitStubStarts(starts + 1)
	st = w.waitClusterVia(stopper, "the resumed run to be owned", func(s clusterStatus) bool {
		return s.owner("run", w.projDir) != ""
	})
	leaving := w.hubByID(st.owner("run", w.projDir))
	staying := survivors[0]
	if staying == leaving {
		staying = survivors[1]
	}
	w.kill(leaving, syscall.SIGTERM)
	w.waitExit(leaving)
	w.waitClusterVia(staying, "the run to be handed to the last member", func(s clusterStatus) bool {
		return s.owner("run", w.projDir) == staying.id && s.owner("agent", agentID) == staying.id
	})
	t.Logf("run handed from hub %d to hub %d on shutdown", leaving.port, staying.port)
	if err := os.WriteFile(w.release, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	w.waitTaskStatus(2, "done")
	w.waitProjectStatus("complete")
	if n := w.stubStarts() - starts; n != 1 {
		t.Fatalf("the harness was started %d times for the resumed run: it was started over, not handed over", n)
	}
	// Whichever member led at the start, the one left standing leads now.
	w.waitClusterVia(staying, "the last member to lead", func(s clusterStatus) bool {
		return s.Leader == staying.id
	})
}

// ── world setup ─────────────────────────────────────────────────────────────

func newWorld(t *testing.T) *world {
	t.Helper()
	root, err := os.MkdirTemp("", "cloop-cluster-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	// Hubs key a run by its project's resolved path; compare against the same.
	if resolved, rerr := filepath.EvalSymlinks(root); rerr == nil {
		root = resolved
	}
	w := &world{t: t, root: root}
	t.Cleanup(w.cleanup)
	w.binDir = filepath.Join(root, "bin")
	w.home = filepath.Join(root, "home")
	w.cloopH = filepath.Join(root, "cloophome")
	w.hubDir = filepath.Join(root, "hub")
	w.projDir = filepath.Join(root, "proj")
	w.release = filepath.Join(root, "release")
	for _, d := range []string{w.binDir, w.home, w.cloopH, w.hubDir, w.projDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Named cloop and on PATH: the agent runs a task by starting `cloop`.
	w.bin = filepath.Join(w.binDir, "cloop")
	w.provisionBinary()
	stub := `#!/bin/bash
cat >/dev/null
echo "$$ $*" >> "` + filepath.Join(root, "claude.log") + `"
echo "stub claude working"
for i in $(seq 1 900); do
  [ -f "` + w.release + `" ] && break
  echo "tick $i"
  sleep 1
done
echo "all done"
echo "TASK_DONE"
`
	if err := os.WriteFile(filepath.Join(w.binDir, "claude"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) provisionBinary() {
	t := w.t
	if prebuilt := os.Getenv(binEnv); prebuilt != "" {
		abs, err := filepath.Abs(prebuilt)
		if err == nil {
			_, err = os.Stat(abs)
		}
		if err != nil {
			t.Fatalf("%s=%s: %v", binEnv, prebuilt, err)
		}
		if err := os.Symlink(abs, w.bin); err != nil {
			t.Fatal(err)
		}
		return
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test source")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", w.bin, ".")
	cmd.Dir = filepath.Join(filepath.Dir(file), "..", "..")
	cmd.Env = append(os.Environ(), goEnv...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build cloop: %v\n%s", err, out)
	}
}

// env is the hubs' environment: one home, one token, the stub first on PATH.
func (w *world) env() []string {
	return []string{
		"HOME=" + w.home,
		"CLOOP_HOME=" + w.cloopH,
		"PATH=" + w.binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"CLOOP_UI_TOKEN=" + token,
		"NO_COLOR=1",
	}
}

// run executes a cloop subcommand to completion in dir.
func (w *world) run(dir string, args ...string) {
	w.t.Helper()
	cmd := exec.Command(w.bin, args...)
	cmd.Dir = dir
	cmd.Env = w.env()
	if out, err := cmd.CombinedOutput(); err != nil {
		w.t.Fatalf("cloop %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func (w *world) initProjects() {
	w.run(w.hubDir, "init", "--provider", "mock", "--skip-clarify", "hub cluster control plane")
	w.run(w.projDir, "init", "--provider", "claudecode", "--skip-clarify", "hub cluster e2e project")
	w.addTask("Write hello.txt")
}

func (w *world) addTask(title string) {
	w.run(w.projDir, "task", "add", title, "--no-ai", "--auto")
}

// spawn starts a long-running process in its own group, logging to logPath.
// The returned channel closes when it exits.
func (w *world) spawn(dir, logPath string, env []string, args ...string) (*exec.Cmd, chan struct{}) {
	w.t.Helper()
	logf, err := os.Create(logPath)
	if err != nil {
		w.t.Fatal(err)
	}
	cmd := exec.Command(w.bin, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		w.t.Fatalf("start cloop %s: %v", strings.Join(args, " "), err)
	}
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		_ = logf.Close()
		close(exited)
	}()
	w.mu.Lock()
	w.procs = append(w.procs, cmd)
	w.mu.Unlock()
	return cmd, exited
}

func (w *world) startHub() *hub {
	w.t.Helper()
	port := freePort(w.t)
	h := &hub{port: port, log: filepath.Join(w.root, fmt.Sprintf("hub-%d.log", port))}
	h.cmd, h.exited = w.spawn(w.hubDir, h.log, w.env(), "ui", "--port", fmt.Sprint(port), "--no-browser", "--projects", w.projDir)
	w.hubs = append(w.hubs, h)
	w.waitHTTP(h.url() + "/healthz")
	return h
}

func (w *world) kill(h *hub, sig syscall.Signal) {
	if h.cmd != nil && h.cmd.Process != nil {
		_ = syscall.Kill(-h.cmd.Process.Pid, sig)
	}
}

// waitExit waits for a hub told to shut down to finish doing so.
func (w *world) waitExit(h *hub) {
	w.t.Helper()
	select {
	case <-h.exited:
	case <-time.After(45 * time.Second):
		w.t.Fatalf("hub %d did not exit within 45s of SIGTERM", h.port)
	}
}

func (w *world) cleanup() {
	w.mu.Lock()
	procs := append([]*exec.Cmd(nil), w.procs...)
	w.mu.Unlock()
	for _, p := range procs {
		if p.Process != nil {
			_ = syscall.Kill(-p.Process.Pid, syscall.SIGKILL)
		}
	}
	if w.lb != nil {
		w.lb.close()
	}
	if w.t.Failed() {
		for _, h := range w.hubs {
			if data, err := os.ReadFile(h.log); err == nil {
				w.t.Logf("── hub %d log (tail) ──\n%s", h.port, tail(string(data), 40))
			}
		}
		if data, err := os.ReadFile(filepath.Join(w.root, "agent.log")); err == nil {
			w.t.Logf("── agent log (tail) ──\n%s", tail(string(data), 20))
		}
	}
	if os.Getenv(keepEnv) != "" {
		w.t.Logf("%s set: leaving %s", keepEnv, w.root)
		return
	}
	_ = os.RemoveAll(w.root)
}

// ── the load balancer ───────────────────────────────────────────────────────

// loadBalancer is round-robin over the hubs, skipping for a few seconds a
// backend that failed to answer — the behaviour of any health-checking load
// balancer, and all a cluster needs from one: no stickiness.
type loadBalancer struct {
	srv  *http.Server
	port int
}

func (w *world) startLoadBalancer() {
	type backend struct {
		rp   *httputil.ReverseProxy
		mu   sync.Mutex
		down time.Time
	}
	var backends []*backend
	for _, h := range w.hubs {
		u, _ := url.Parse(h.url())
		be := &backend{rp: httputil.NewSingleHostReverseProxy(u)}
		be.rp.FlushInterval = -1
		be.rp.ErrorHandler = func(rw http.ResponseWriter, _ *http.Request, _ error) {
			be.mu.Lock()
			be.down = time.Now().Add(3 * time.Second)
			be.mu.Unlock()
			rw.WriteHeader(http.StatusBadGateway)
		}
		backends = append(backends, be)
	}
	var next atomic.Uint64
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		w.t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		for i := 0; i < len(backends); i++ {
			be := backends[int(next.Add(1))%len(backends)]
			be.mu.Lock()
			down := time.Now().Before(be.down)
			be.mu.Unlock()
			if !down {
				be.rp.ServeHTTP(rw, r)
				return
			}
		}
		rw.WriteHeader(http.StatusServiceUnavailable)
	})}
	go func() { _ = srv.Serve(ln) }()
	w.lb = &loadBalancer{srv: srv, port: ln.Addr().(*net.TCPAddr).Port}
}

func (lb *loadBalancer) close() { _ = lb.srv.Close() }

func (lb *loadBalancer) url() string { return fmt.Sprintf("http://127.0.0.1:%d", lb.port) }

// ── the agent ───────────────────────────────────────────────────────────────

func (w *world) enrollAndStartAgent() string {
	w.t.Helper()
	bundle := filepath.Join(w.root, "bundle")
	server := fmt.Sprintf("ws://127.0.0.1:%d/api/executors/connect", w.lb.port)
	w.run(w.hubDir, "executor", "enroll", "--name", "edge-e2e", "--server", server, "--bundle-file", bundle)
	agentHome := filepath.Join(w.root, "agenthome")
	work := filepath.Join(w.root, "agentwork")
	for _, d := range []string{agentHome, work} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			w.t.Fatal(err)
		}
	}
	env := []string{
		"HOME=" + agentHome,
		"PATH=" + w.binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"NO_COLOR=1",
	}
	_, _ = w.spawn(w.root, filepath.Join(w.root, "agent.log"), env,
		"executor", "agent", "--token-file", bundle,
		"--credential", filepath.Join(agentHome, "agent.json"), "--workdir-root", work)
	var id string
	w.eventually("the agent to enroll", 30*time.Second, func() bool {
		data, _ := os.ReadFile(filepath.Join(w.root, "agent.log"))
		for _, line := range strings.Split(string(data), "\n") {
			if i := strings.Index(line, "enrolled as "); i >= 0 {
				rest := line[i+len("enrolled as "):]
				if j := strings.IndexAny(rest, "; "); j > 0 {
					id = rest[:j]
					return true
				}
			}
		}
		return false
	})
	return id
}

// ── HTTP helpers ────────────────────────────────────────────────────────────

type response struct {
	status   int
	body     string
	servedBy string
}

func (w *world) do(method, base, path string, body []byte) response {
	w.t.Helper()
	req, err := http.NewRequest(method, base+path, bytes.NewReader(body))
	if err != nil {
		w.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return response{status: 0, body: err.Error()}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, body: string(data), servedBy: resp.Header.Get("X-Cloop-Served-By")}
}

func (w *world) post(h *hub, path string) response { return w.do(http.MethodPost, h.url(), path, nil) }

func (w *world) waitHTTP(u string) {
	w.eventually("the hub at "+u+" to answer", 30*time.Second, func() bool {
		resp, err := http.Get(u)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
}

func (w *world) projectIndex() int {
	w.t.Helper()
	r := w.do(http.MethodGet, w.lb.url(), "/api/projects", nil)
	var out struct {
		Projects []struct {
			Path string `json:"path"`
		} `json:"projects"`
	}
	if err := json.Unmarshal([]byte(r.body), &out); err != nil {
		w.t.Fatalf("GET /api/projects: %v (%s)", err, r.body)
	}
	for i, p := range out.Projects {
		if p.Path == w.projDir {
			return i
		}
	}
	w.t.Fatalf("project %s not listed: %s", w.projDir, r.body)
	return -1
}

func (w *world) bindProject(idx int, executorID string) {
	w.t.Helper()
	body, _ := json.Marshal(map[string]string{"executor_id": executorID})
	r := w.do(http.MethodPost, w.lb.url(), fmt.Sprintf("/api/projects/%d/executor", idx), body)
	if r.status != http.StatusOK {
		w.t.Fatalf("bind project: %d %s", r.status, r.body)
	}
}

// ── cluster status ──────────────────────────────────────────────────────────

type clusterStatus struct {
	Self    string `json:"self"`
	Leader  string `json:"leader"`
	Members []struct {
		ID           string `json:"id"`
		AdvertiseURL string `json:"advertise_url"`
		Alive        bool   `json:"alive"`
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

func (w *world) status(base string) (clusterStatus, bool) {
	r := w.do(http.MethodGet, base, "/api/cluster", nil)
	if r.status != http.StatusOK {
		return clusterStatus{}, false
	}
	var st clusterStatus
	if json.Unmarshal([]byte(r.body), &st) != nil {
		return clusterStatus{}, false
	}
	return st, true
}

func (w *world) waitCluster(what string, cond func(clusterStatus) bool) clusterStatus {
	return w.waitStatusAt(w.lb.url(), what, cond)
}

func (w *world) waitClusterVia(h *hub, what string, cond func(clusterStatus) bool) clusterStatus {
	return w.waitStatusAt(h.url(), what, cond)
}

func (w *world) waitStatusAt(base, what string, cond func(clusterStatus) bool) clusterStatus {
	w.t.Helper()
	var last clusterStatus
	w.eventually(what, 45*time.Second, func() bool {
		st, ok := w.status(base)
		if !ok {
			return false
		}
		last = st
		return cond(st)
	})
	return last
}

func (w *world) memberFor(st clusterStatus, port int) string {
	w.t.Helper()
	suffix := fmt.Sprintf(":%d", port)
	for _, m := range st.Members {
		if strings.HasSuffix(m.AdvertiseURL, suffix) {
			return m.ID
		}
	}
	w.t.Fatalf("no member advertises port %d", port)
	return ""
}

func (w *world) hubByID(id string) *hub {
	w.t.Helper()
	for _, h := range w.hubs {
		if h.id == id {
			return h
		}
	}
	w.t.Fatalf("no hub is member %s", id)
	return nil
}

func (w *world) otherTwo(h *hub) (*hub, *hub) {
	var out []*hub
	for _, o := range w.hubs {
		if o != h {
			out = append(out, o)
		}
	}
	return out[0], out[1]
}

// ── project state ───────────────────────────────────────────────────────────

func (w *world) queryProject(query string, args ...any) (string, error) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(w.projDir, ".cloop", "state.db")+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return "", err
	}
	defer db.Close()
	var v string
	err = db.QueryRow(query, args...).Scan(&v)
	return v, err
}

func (w *world) waitTaskStatus(id int, want string) {
	w.t.Helper()
	w.eventually(fmt.Sprintf("task %d to be %s in the hub's copy of the project", id, want), 60*time.Second, func() bool {
		got, err := w.queryProject(`SELECT status FROM plan_tasks WHERE id = ?`, id)
		return err == nil && got == want
	})
}

func (w *world) waitProjectStatus(want string) {
	w.t.Helper()
	w.eventually("the project to be "+want, 60*time.Second, func() bool {
		got, err := w.queryProject(`SELECT value FROM metadata WHERE key = 'status'`)
		return err == nil && got == want
	})
}

// stubStarts counts the stub harness's invocations so far.
func (w *world) stubStarts() int {
	data, _ := os.ReadFile(filepath.Join(w.root, "claude.log"))
	return strings.Count(string(data), "\n")
}

// waitStubStarts waits until the stub harness has started n times: a run that
// has reached the harness is one Stop has something to interrupt.
func (w *world) waitStubStarts(n int) {
	w.t.Helper()
	w.eventually(fmt.Sprintf("the harness to have been started %d time(s)", n), 60*time.Second, func() bool {
		return w.stubStarts() >= n
	})
}

// ── dashboard stream ────────────────────────────────────────────────────────

type stream struct {
	conn   *websocket.Conn
	cancel context.CancelFunc
	mu     sync.Mutex
	frames []frame
}

type frame struct{ typ, data string }

func (w *world) openStream(h *hub, idx int) *stream {
	w.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	u := fmt.Sprintf("ws://127.0.0.1:%d/api/ws?project_idx=%d", h.port, idx)
	conn, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
	})
	if err != nil {
		cancel()
		w.t.Fatalf("dial %s: %v", u, err)
	}
	conn.SetReadLimit(-1)
	s := &stream{conn: conn, cancel: cancel}
	go func() {
		for {
			_, msg, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var m struct {
				Type string          `json:"type"`
				Data json.RawMessage `json:"data"`
			}
			if json.Unmarshal(msg, &m) != nil {
				continue
			}
			s.mu.Lock()
			s.frames = append(s.frames, frame{m.Type, string(m.Data)})
			s.mu.Unlock()
		}
	}()
	return s
}

// mark returns a position in the stream; waitFor(mark, …) ignores what
// arrived before it.
func (s *stream) mark() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.frames)
}

func (s *stream) waitFor(t *testing.T, from int, what string, match func(typ, data string) bool) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		for _, f := range s.frames[from:] {
			if match(f.typ, f.data) {
				s.mu.Unlock()
				return
			}
		}
		s.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
	}
	s.mu.Lock()
	seen := map[string]int{}
	for _, f := range s.frames[from:] {
		seen[f.typ]++
	}
	s.mu.Unlock()
	t.Fatalf("timed out waiting for %s (frames received by type: %v)", what, seen)
}

func (s *stream) close() {
	_ = s.conn.Close(websocket.StatusNormalClosure, "")
	s.cancel()
}

// ── utilities ───────────────────────────────────────────────────────────────

func (w *world) eventually(what string, limit time.Duration, cond func() bool) {
	w.t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	w.t.Fatalf("timed out after %s waiting for %s", limit, what)
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

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
