package e2e_test

// A device run survives its hub restarting (Task 20382).
//
// :8888 restarts every night, and off schedule, while runs on the sgx device
// can be in flight. Before this test nothing proved what happens to such a run:
// pkg/ui's tests and tests/cluster cover a run adopted by a *surviving* hub
// member, not one hub process stopped and started again in the same
// directory, which is what a systemd restart is. If that path breaks, the
// device finishes its task, the hub never merges the result, and the task stays
// pending and runs again — the Task 20339 symptom.
//
// So this runs it for real, on loopback: a token-protected hub with its own
// HOME and CLOOP_HOME, a real `cloop executor agent` in host mode whose work
// root the hub cannot see (so the run is carried out as a seed), and a stand-in
// `claude` that blocks on a FIFO until the test lets it finish. The hub is
// stopped while the workload is blocked — SIGTERM, as systemd stops it, and
// again with SIGKILL — and a new hub process is started in the same directory
// on the same port. The agent reconnects to it on its own. Then the harness is
// released, and the test checks what an operator would:
//
//   - the task is done in the hub's state.db, and the harness ran once;
//   - the device's project result was merged exactly once: one journal row, one
//     cost row, one entry in the global spend ledger;
//   - the run's secret lease was taken over by the new process — the same
//     lease, recorded as its own, listed by it, a takeover row on its trail —
//     and released once, by that process, when the run ended; nothing swept it
//     off the device on the way;
//   - the run's executor session was watched to its end and says "finished";
//   - no executor handle, run owner row, open session or lease record is left.
//
// The feature variant does the same to a feature's run. With a clean worktree
// the commits it returns after the restart land on cloop/feature/<slug> by
// fast-forward; with a worktree an operator dirtied while the hub was down they
// are kept on cloop/returned/… and the feature's Meta.Return says so.
//
// Each scenario takes about three seconds and needs only bash and git, so the
// tests run in CI's Build and Test job with the rest of tests/e2e.
// CLOOP_RESTART_E2E_LOGS=1 prints the hub and agent logs even when they pass.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/blechschmidt/cloop/pkg/feature"
)

// restartToken protects the test hub: `cloop ui` binds every interface.
const restartToken = "e2e-hub-restart-token"

// restartStub stands in for Claude Code. It records that it started, then
// blocks on the scene's FIFO until the test writes a line to it — bounded, so
// a test that dies early does not leave it waiting forever. Inside a git
// checkout (a feature's) it commits a file, as a harness told to commit to its
// branch would. The FIFO is opened read-write so the open never blocks and a
// writer can tell a reader is waiting.
const restartStub = `#!/bin/bash
prompt=$(cat)
echo "$$ $(pwd)" >> "@LOG@"
exec 3<>"@FIFO@"
if ! read -r -t 600 -u 3 line; then
  echo "stub claude: never released" >&2
  exit 1
fi
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  n=$(date +%s)-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
  echo "work $n" > "work-$n.txt"
  git add -A
  git commit -qm "stub claude: work $n" || { echo "stub claude: nothing was committed" >&2; exit 1; }
fi
echo "stub claude: finished after the release"
echo TASK_DONE
`

// restartScene is one hub directory, one project, one device.
type restartScene struct {
	t      *testing.T
	bin    string
	root   string
	env    []string
	hubDir string
	proj   string
	home   string
	port   int
	base   string
	fifo   string
	stub   string // the stub's start log

	// hubEnv is added to the hub process's environment alone: the routes
	// and trust a variant gives the hub to reach its fake upstreams.
	hubEnv []string

	mu       sync.Mutex
	hub      *exec.Cmd
	hubDone  chan struct{}
	hubLogs  []*strings.Builder
	agent    *exec.Cmd
	agentLog *strings.Builder

	executorID string
}

// restartOptions vary the scene for a variant.
type restartOptions struct {
	// gitRepo makes the project a git checkout.
	gitRepo bool
	// executors is YAML appended under the hub's executors: section.
	executors string
	// stub replaces restartStub; vars are its further @NAME@ substitutions.
	stub string
	vars map[string]string
	// hubEnv is the hub's own extra environment.
	hubEnv []string
}

func newRestartScene(t *testing.T, gitRepo bool) *restartScene {
	t.Helper()
	return newRestartSceneWith(t, restartOptions{gitRepo: gitRepo})
}

func newRestartSceneWith(t *testing.T, opt restartOptions) *restartScene {
	t.Helper()
	gitRepo := opt.gitRepo
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required for the stand-in harness")
	}
	if gitRepo {
		if _, err := exec.LookPath("git"); err != nil {
			t.Skip("git not installed")
		}
	}
	root := t.TempDir()
	// The hub keys a run by its project's resolved path.
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	s := &restartScene{
		t: t, bin: binaryPath(t), root: root, hubEnv: opt.hubEnv,
		hubDir: filepath.Join(root, "hub"),
		proj:   filepath.Join(root, "proj"),
		home:   filepath.Join(root, "home"),
		fifo:   filepath.Join(root, "release.fifo"),
		stub:   filepath.Join(root, "claude.log"),
	}
	// Registered after TempDir, so it runs before the directory is removed:
	// nothing the scene started may still be writing into it.
	t.Cleanup(s.teardown)
	for _, d := range []string{s.hubDir, s.proj, s.home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(s.fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	gitconfig := filepath.Join(s.home, ".gitconfig")
	writeTestFile(t, gitconfig, "[user]\n\tname = E2E\n\temail = e2e@example.com\n[init]\n\tdefaultBranch = main\n"+
		"[safe]\n\tdirectory = *\n")
	s.env = append(withoutCloopEnv(os.Environ()),
		"HOME="+s.home,
		"CLOOP_HOME="+filepath.Join(s.home, ".cloop"),
		"CLOOP_UI_TOKEN="+restartToken,
		// The broker is configured on purpose, the same way everywhere: an
		// inherited key would make the run's lease depend on who runs the test.
		"CLOOP_SECRET_KEY=e2e-hub-restart",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+gitconfig,
		"GIT_TERMINAL_PROMPT=0",
		"NO_COLOR=1",
	)

	if gitRepo {
		s.git(s.proj, "init", "-q", "-b", "main")
		writeTestFile(t, filepath.Join(s.proj, "README.md"), "the project\n")
		s.git(s.proj, "add", "README.md")
		s.git(s.proj, "commit", "-qm", "first")
	}
	s.cloop(s.proj, "init", "--provider", "claudecode", "--skip-clarify", "Survive a hub restart")
	if gitRepo {
		s.git(s.proj, "add", "-A")
		s.git(s.proj, "commit", "-qm", "cloop init")
	}
	s.cloop(s.hubDir, "init", "--provider", "mock", "--skip-clarify", "hub")
	grantHarnessCredential(t, s.cloop, s.hubDir, s.proj)
	// Strict: the hub never runs a harness on its own host.
	f, err := os.OpenFile(filepath.Join(s.hubDir, ".cloop", "config.yaml"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\nexecutors:\n    allow_host_process: false\n" + opt.executors); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	script := restartStub
	if opt.stub != "" {
		script = opt.stub
	}
	pairs := []string{"@LOG@", s.stub, "@FIFO@", s.fifo}
	for k, v := range opt.vars {
		pairs = append(pairs, "@"+k+"@", v)
	}
	stub := strings.NewReplacer(pairs...).Replace(script)
	devBin := filepath.Join(root, "device-bin")
	writeTestFile(t, filepath.Join(devBin, "claude"), stub)
	if err := os.Chmod(filepath.Join(devBin, "claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(s.bin, filepath.Join(devBin, "cloop")); err != nil {
		t.Fatal(err)
	}
	s.port = freePort(t)
	s.base = fmt.Sprintf("http://127.0.0.1:%d", s.port)
	return s
}

// startHub starts a hub process in the scene's directory, on the scene's port
// — the one the agent's credential names, so it finds the new process itself.
func (s *restartScene) startHub() {
	s.t.Helper()
	cmd := exec.Command(s.bin, "ui", "--port", strconv.Itoa(s.port), "--no-browser", "--projects", s.proj)
	cmd.Dir = s.hubDir
	cmd.Env = append(append([]string(nil), s.env...), s.hubEnv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	log := &strings.Builder{}
	w := &syncWriter{w: log}
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	s.mu.Lock()
	s.hub, s.hubDone = cmd, done
	s.hubLogs = append(s.hubLogs, log)
	s.mu.Unlock()
	s.waitFor("the hub to answer", 60*time.Second, func() bool {
		resp, err := http.Get(s.base + "/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
}

// stopHub signals the hub's process group and waits for it to exit.
func (s *restartScene) stopHub(sig syscall.Signal) {
	s.t.Helper()
	s.mu.Lock()
	cmd, done := s.hub, s.hubDone
	s.mu.Unlock()
	_ = syscall.Kill(-cmd.Process.Pid, sig)
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		s.t.Fatalf("the hub did not exit within 60s of %v", sig)
	}
}

// startAgent enrolls a device and runs its agent in host mode, with the
// stand-in claude and the cloop under test first on its PATH.
func (s *restartScene) startAgent() {
	s.t.Helper()
	server := strings.Replace(s.base, "http://", "ws://", 1) + "/api/executors/connect"
	bundle := filepath.Join(s.root, "enroll.bundle")
	s.cloop(s.hubDir, "executor", "enroll", "--name", "edge-restart", "--server", server, "--bundle-file", bundle)
	cmd := exec.Command(s.bin, "executor", "agent",
		"--token-file", bundle,
		"--credential", filepath.Join(s.root, "agent.json"),
		"--workdir-root", filepath.Join(s.root, "device"))
	cmd.Env = append(withPath(s.env, filepath.Join(s.root, "device-bin")), "HOME="+filepath.Join(s.root, "device-home"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	s.agentLog = &strings.Builder{}
	w := &syncWriter{w: s.agentLog}
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	s.mu.Lock()
	s.agent = cmd
	s.mu.Unlock()
	s.executorID = s.waitAgentOnline()
}

// waitAgentOnline waits for the device to be connected to the current hub.
func (s *restartScene) waitAgentOnline() string {
	s.t.Helper()
	var id string
	s.waitFor("the agent to be connected", 60*time.Second, func() bool {
		code, body := s.call("GET", "/api/executors", nil)
		if code != http.StatusOK {
			return false
		}
		raw, _ := body["executors"].([]any)
		for _, r := range raw {
			m, _ := r.(map[string]any)
			if m["name"] == "edge-restart" && m["status"] == "online" {
				id = fmt.Sprint(m["id"])
				return true
			}
		}
		return false
	})
	return id
}

// teardown releases the harness and kills everything the scene started, by
// process group, before the scratch directory goes.
func (s *restartScene) teardown() {
	s.releaseHarness(false)
	s.mu.Lock()
	cmds := []*exec.Cmd{s.agent, s.hub}
	s.mu.Unlock()
	for _, c := range cmds {
		if c != nil && c.Process != nil {
			_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		}
	}
	// The workloads run in process groups of their own, under the agent.
	for _, pid := range s.stubPIDs() {
		if pgid, err := syscall.Getpgid(pid); err == nil && pgid > 1 {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		}
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	for _, p := range s.workloadPIDs() {
		_ = syscall.Kill(p, syscall.SIGKILL)
	}
	if s.t.Failed() || os.Getenv("CLOOP_RESTART_E2E_LOGS") != "" {
		s.mu.Lock()
		for i, l := range s.hubLogs {
			s.t.Logf("hub log, process %d:\n%s", i+1, tail(l.String(), 8000))
		}
		if s.agentLog != nil {
			s.t.Logf("agent log:\n%s", tail(s.agentLog.String(), 6000))
		}
		s.mu.Unlock()
	}
}

// workloadPIDs finds processes still running in the scene's device directory:
// the `cloop run` a workload is. Matched by working directory, never by a
// command-line pattern, which would also match the shell that looks.
func (s *restartScene) workloadPIDs() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	device := filepath.Join(s.root, "device")
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		cwd, err := os.Readlink(filepath.Join("/proc", e.Name(), "cwd"))
		if err == nil && (cwd == device || strings.HasPrefix(cwd, device+string(os.PathSeparator))) {
			out = append(out, pid)
		}
	}
	return out
}

func (s *restartScene) stubPIDs() []int {
	data, _ := os.ReadFile(s.stub)
	var out []int
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			if pid, err := strconv.Atoi(f[0]); err == nil && pid > 1 {
				out = append(out, pid)
			}
		}
	}
	return out
}

// stubStarts counts how often the harness has been started.
func (s *restartScene) stubStarts() int { return len(s.stubPIDs()) }

// releaseHarness lets one blocked harness finish. With wait, it fails the
// test if none is blocked within the deadline.
func (s *restartScene) releaseHarness(wait bool) {
	deadline := time.Now().Add(30 * time.Second)
	for {
		f, err := os.OpenFile(s.fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_, _ = f.Write([]byte("go\n"))
			_ = f.Close()
			return
		}
		if !wait || time.Now().After(deadline) {
			if wait {
				s.t.Fatalf("no harness was waiting to be released: %v", err)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (s *restartScene) git(dir string, args ...string) string {
	s.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = s.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		s.t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (s *restartScene) cloop(dir string, args ...string) string {
	s.t.Helper()
	cmd := exec.Command(s.bin, args...)
	cmd.Dir = dir
	cmd.Env = s.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		s.t.Fatalf("cloop %v in %s: %v\n%s", args, dir, err, out)
	}
	return string(out)
}

func (s *restartScene) call(method, path string, body any) (int, map[string]any) {
	s.t.Helper()
	var rd *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	} else {
		rd = strings.NewReader("")
	}
	req, err := http.NewRequest(method, s.base+path, rd)
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+restartToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 2 * time.Minute}).Do(req)
	if err != nil {
		return 0, map[string]any{"error": err.Error()}
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (s *restartScene) waitFor(what string, timeout time.Duration, cond func() bool) {
	s.t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			s.t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// projectIdx is path's index in the hub's project list, or -1.
func (s *restartScene) projectIdx(path string) int {
	s.t.Helper()
	_, body := s.call("GET", "/api/projects", nil)
	raw, _ := body["projects"].([]any)
	for i, r := range raw {
		if m, ok := r.(map[string]any); ok && m["path"] == path {
			return i
		}
	}
	return -1
}

func (s *restartScene) bind() {
	s.t.Helper()
	idx := s.projectIdx(s.proj)
	code, body := s.call("POST", fmt.Sprintf("/api/projects/%d/executor", idx), map[string]any{"executor_id": s.executorID})
	if code != http.StatusOK {
		s.t.Fatalf("bind the project to %s = %d %v", s.executorID, code, body)
	}
}

// ── reading the databases ────────────────────────────────────────────────────

// query runs one read-only query against the state database under dir and
// returns every row, each column rendered as a string.
func (s *restartScene) query(dir, q string, args ...any) [][]string {
	s.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, ".cloop", "state.db")+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		s.t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(q, args...)
	if err != nil {
		s.t.Fatalf("query %q on %s: %v", q, dir, err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out [][]string
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			s.t.Fatal(err)
		}
		row := make([]string, len(cols))
		for i, v := range vals {
			row[i] = v.String
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		s.t.Fatal(err)
	}
	return out
}

// tryQuery is query for a wait condition: an error is "not yet".
func (s *restartScene) tryQuery(dir, q string, args ...any) ([][]string, error) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, ".cloop", "state.db")+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]string
	cols, _ := rows.Columns()
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make([]string, len(cols))
		for i, v := range vals {
			row[i] = v.String
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (s *restartScene) taskStatus(dir string, id int) string {
	rows, err := s.tryQuery(dir, `SELECT status FROM plan_tasks WHERE id = ?`, id)
	if err != nil || len(rows) == 0 {
		return ""
	}
	return rows[0][0]
}

// runOwner returns the member holding the run claim on dir, and its meta.
func (s *restartScene) runOwner(dir string) (member string, meta map[string]any) {
	rows, err := s.tryQuery(s.hubDir, `SELECT instance_id, meta FROM hub_owners WHERE kind = 'run' AND key = ?`, dir)
	if err != nil || len(rows) == 0 {
		return "", nil
	}
	_ = json.Unmarshal([]byte(rows[0][1]), &meta)
	return rows[0][0], meta
}

// leftovers lists the control-plane rows a finished run must not leave behind.
func (s *restartScene) leftovers() []string {
	var out []string
	for _, r := range s.query(s.hubDir, `SELECT kind, key, instance_id FROM hub_owners WHERE kind = 'run'`) {
		out = append(out, "run owner row "+strings.Join(r, " "))
	}
	for _, r := range s.query(s.hubDir, `SELECT handle_id, executor_id, driver FROM executor_handles`) {
		out = append(out, "executor handle "+strings.Join(r, " "))
	}
	for _, r := range s.query(s.hubDir, `SELECT id, handle_id, state FROM executor_sessions WHERE state = 'running'`) {
		out = append(out, "open executor session "+strings.Join(r, " "))
	}
	return out
}

// auditRows returns the control plane's audit rows of one type for one lease,
// as (row id, payload), oldest first.
func (s *restartScene) auditRows(eventType, leaseID string) []auditRow {
	var out []auditRow
	for _, r := range s.query(s.hubDir, `SELECT id, payload FROM audit_events WHERE event_type = ? ORDER BY id`, eventType) {
		var p map[string]any
		_ = json.Unmarshal([]byte(r[1]), &p)
		if leaseID == "" || p["lease_id"] == leaseID {
			id, _ := strconv.Atoi(r[0])
			out = append(out, auditRow{id: id, payload: p})
		}
	}
	return out
}

type auditRow struct {
	id      int
	payload map[string]any
}

// leaseRecord returns the holder of a lease's durable record, or "" when it
// has none.
func (s *restartScene) leaseHolder(leaseID string) string {
	rows, err := s.tryQuery(s.hubDir, `SELECT holder FROM secret_leases WHERE lease_id = ?`, leaseID)
	if err != nil || len(rows) == 0 {
		return ""
	}
	return rows[0][0]
}

// listedLeases returns the ids of the leases the running hub lists, as the
// Secrets panel reads them.
func (s *restartScene) listedLeases() []string {
	code, body := s.call("GET", "/api/leases", nil)
	if code != http.StatusOK {
		s.t.Fatalf("GET /api/leases = %d %v", code, body)
	}
	raw, _ := body["leases"].([]any)
	var ids []string
	for _, r := range raw {
		if m, ok := r.(map[string]any); ok {
			ids = append(ids, fmt.Sprint(m["id"]))
		}
	}
	return ids
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// globalLedgerEntries counts the hub's global spend ledger entries for dir.
func (s *restartScene) globalLedgerEntries(dir string) int {
	data, err := os.ReadFile(filepath.Join(s.home, ".config", "cloop", "costs.jsonl"))
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		var e struct {
			ProjectPath string `json:"project_path"`
		}
		if json.Unmarshal([]byte(line), &e) == nil && e.ProjectPath == dir {
			n++
		}
	}
	return n
}

// ── the scenario ─────────────────────────────────────────────────────────────

// restarted is what restartMidRun learned about the run it restarted under.
type restarted struct {
	lease     string // the run's secret lease
	handle    string // the run's workload on the device
	oldMember string // the hub process that dispatched it
	newMember string // the one that took it over
	takeover  int    // audit row id of the lease's takeover
}

func TestE2EDeviceRunSurvivesHubRestart(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL} {
		sig := sig
		t.Run(sig.String(), func(t *testing.T) {
			s := newRestartScene(t, false)
			s.cloop(s.proj, "task", "add", "Write the report", "--no-ai", "--auto")
			s.startHub()
			s.startAgent()
			s.bind()
			r := s.restartMidRun(sig, s.proj, nil, func() {
				idx := s.projectIdx(s.proj)
				if code, body := s.call("POST", fmt.Sprintf("/api/run?project_idx=%d", idx), nil); code != http.StatusOK {
					t.Fatalf("start the run = %d %v", code, body)
				}
			})
			s.waitFor("task 1 to be done in the hub's copy", 90*time.Second, func() bool {
				return s.taskStatus(s.proj, 1) == "done"
			})
			s.assertSettled(s.proj, 1, r)
		})
	}
}

// restartMidRun starts a run with start, waits until its harness is blocked on
// the device, stops the hub with sig, calls whileDown (if any) while no hub
// process is running, starts a new hub process in the same directory, waits
// for it to take the run over — the run, its lease — and releases the harness.
func (s *restartScene) restartMidRun(sig syscall.Signal, dir string, whileDown func(), start func()) restarted {
	t := s.t
	before := s.stubStarts()
	start()
	s.waitFor("the harness to be running on the device", 90*time.Second, func() bool {
		return s.stubStarts() > before
	})
	var r restarted
	var meta map[string]any
	r.oldMember, meta = s.runOwner(dir)
	if r.oldMember == "" {
		t.Fatal("the running run has no owner row")
	}
	if meta["seeded"] != true || meta["provenance"] == nil {
		t.Fatalf("the run was not carried out as a seed (owner meta %v)", meta)
	}
	r.handle = fmt.Sprint(meta["handle"])
	leases, _ := meta["leases"].([]any)
	if len(leases) != 1 {
		t.Fatalf("the run's owner row names %d leases, want its one: %v", len(leases), meta)
	}
	r.lease = fmt.Sprint(leases[0])
	if got := s.leaseHolder(r.lease); got != r.oldMember {
		t.Fatalf("lease %s is recorded as held by %q, want the dispatching process %s", r.lease, got, r.oldMember)
	}
	if !contains(s.listedLeases(), r.lease) {
		t.Fatalf("the hub does not list the run's lease %s", r.lease)
	}
	t.Logf("run %s on %s, owner %s, lease %s; stopping the hub with %v", r.handle, s.executorID, r.oldMember, r.lease, sig)

	s.stopHub(sig)
	if whileDown != nil {
		whileDown()
	}
	s.startHub()
	s.waitAgentOnline()
	s.waitFor("the restarted hub to take the run over", 60*time.Second, func() bool {
		m, _ := s.runOwner(dir)
		return m != "" && m != r.oldMember
	})
	r.newMember, meta = s.runOwner(dir)
	t.Logf("run adopted by %s", r.newMember)

	// The lease came with it: the same lease, recorded as the new process's,
	// listed by it, and the takeover on the lease's own trail.
	s.waitFor("the restarted hub to hold the run's lease", 30*time.Second, func() bool {
		return s.leaseHolder(r.lease) == r.newMember
	})
	if !contains(s.listedLeases(), r.lease) {
		t.Errorf("the restarted hub does not list the run's lease %s, which it holds", r.lease)
	}
	if got, _ := meta["leases"].([]any); len(got) != 1 || fmt.Sprint(got[0]) != r.lease {
		t.Errorf("the adopted run's owner row names leases %v, want [%s]", meta["leases"], r.lease)
	}
	for _, row := range s.auditRows("secret.renew", r.lease) {
		if row.payload["decision"] == "allow" && strings.Contains(fmt.Sprint(row.payload["reason"]), "taken over") {
			r.takeover = row.id
		}
	}
	if r.takeover == 0 {
		t.Errorf("the lease's trail has no takeover row: %v", s.auditRows("secret.renew", r.lease))
	}

	s.releaseHarness(true)
	return r
}

// assertSettled checks everything the run must have left — and not left —
// once it is over.
func (s *restartScene) assertSettled(dir string, task int, r restarted) {
	t := s.t
	s.waitFor("the run's control-plane rows to be cleared", 60*time.Second, func() bool {
		return len(s.leftovers()) == 0
	})
	if n := s.stubStarts(); n != 1 {
		t.Errorf("the harness was started %d times for one task: the run was started over, not taken over", n)
	}

	// The device's result, merged once: one journal row, one cost row, one
	// entry in the global spend ledger.
	results := s.query(dir, `SELECT message FROM events WHERE type = 'project_result'`)
	if len(results) != 1 {
		t.Errorf("project_result journal rows = %d, want exactly 1: %v", len(results), results)
	} else if want := fmt.Sprintf("#%d done", task); !strings.Contains(results[0][0], want) {
		t.Errorf("the project_result row does not record task %d done: %s", task, results[0][0])
	}
	costs := s.query(dir, `SELECT task_id, identity FROM costs WHERE task_id = ?`, task)
	if len(costs) != 1 {
		t.Errorf("cost rows for task %d = %d, want exactly 1: %v", task, len(costs), costs)
	}
	if n := s.globalLedgerEntries(dir); n != 1 {
		t.Errorf("global spend ledger entries for %s = %d, want exactly 1", dir, n)
	}

	// The lease ended with the run, released once by the process holding it.
	s.waitFor("the run's lease to be released", 30*time.Second, func() bool {
		return len(s.auditRows("secret.release", r.lease)) > 0
	})
	releases := s.auditRows("secret.release", r.lease)
	if len(releases) != 1 {
		t.Errorf("lease %s was released %d times, want once", r.lease, len(releases))
	} else if releases[0].id < r.takeover {
		t.Errorf("lease %s was released before the restarted hub took it over", r.lease)
	}
	if h := s.leaseHolder(r.lease); h != "" {
		t.Errorf("lease %s still has a durable record, held by %s", r.lease, h)
	}
	if contains(s.listedLeases(), r.lease) {
		t.Errorf("the hub still lists lease %s after its run ended", r.lease)
	}
	if rows := s.query(s.hubDir, `SELECT lease_id FROM secret_leases`); len(rows) != 0 {
		t.Errorf("lease records left behind: %v", rows)
	}
	for _, row := range s.auditRows("lease.revoke_sent", r.lease) {
		t.Errorf("lease %s was swept from the device although its holder kept it alive: %v", r.lease, row.payload)
	}

	// The run's executor session was watched to its end by the process that
	// adopted it, and records how the run really ended.
	sessions := s.query(s.hubDir, `SELECT state FROM executor_sessions WHERE handle_id = ?`, r.handle)
	if len(sessions) != 1 || sessions[0][0] != "finished" {
		t.Errorf("the run's executor sessions = %v, want one, finished", sessions)
	}
}

// newFeature creates a feature through the API — on the hub, since the
// project's executor isolates from it — and returns its directory.
func (s *restartScene) newFeature(name string, tasks ...string) string {
	s.t.Helper()
	idx := s.projectIdx(s.proj)
	code, body := s.call("POST", fmt.Sprintf("/api/projects/%d/features", idx),
		map[string]any{"name": name, "description": "Build " + name, "tasks": tasks})
	if code != http.StatusOK {
		s.t.Fatalf("create feature %q = %d %v", name, code, body)
	}
	dir := feature.Path(s.proj, fmt.Sprint(body["slug"]))
	if !feature.IsFeature(dir) {
		s.t.Fatalf("the hub created no feature at %s", dir)
	}
	return dir
}

// TestE2EFeatureRunSurvivesHubRestart: a feature's run on the device, its hub
// restarted mid-run. With a clean worktree the commits the run returns land on
// the feature's branch by fast-forward; with one an operator dirtied while the
// hub was down they are kept on cloop/returned/… and the feature says so.
func TestE2EFeatureRunSurvivesHubRestart(t *testing.T) {
	for _, tc := range []struct {
		sig   syscall.Signal
		dirty bool
	}{
		{syscall.SIGTERM, false},
		{syscall.SIGKILL, true},
	} {
		tc := tc
		t.Run(tc.sig.String(), func(t *testing.T) {
			s := newRestartScene(t, true)
			s.startHub()
			s.startAgent()
			s.bind()
			fdir := s.newFeature("Widget", "Write the widget")
			branch := feature.BranchName("widget")
			before := s.git(s.proj, "rev-parse", "refs/heads/"+branch)
			started := time.Now()
			notes := filepath.Join(fdir, "local-notes.txt")
			var whileDown func()
			if tc.dirty {
				whileDown = func() { writeTestFile(t, notes, "uncommitted, on the hub\n") }
			}
			r := s.restartMidRun(tc.sig, fdir, whileDown, func() {
				idx := s.projectIdx(fdir)
				if code, body := s.call("POST", fmt.Sprintf("/api/projects/%d/run", idx), map[string]any{}); code != http.StatusOK {
					t.Fatalf("start the feature's run = %d %v", code, body)
				}
			})
			var ret *feature.Return
			s.waitFor("the feature's returned work to be landed", 90*time.Second, func() bool {
				m, err := feature.LoadMeta(fdir)
				if err != nil || m.Return == nil || m.Return.At.Before(started) {
					return false
				}
				ret = m.Return
				return true
			})
			t.Logf("feature return: %s — %s", ret.Outcome, ret.Message)
			tip := s.git(s.proj, "rev-parse", "refs/heads/"+branch)
			if !tc.dirty {
				if ret.Outcome != "fast_forwarded" {
					t.Fatalf("the run's work was not applied to a clean worktree: %+v", ret)
				}
				if tip == before || tip != ret.Commit {
					t.Fatalf("%s is at %s (was %s), the run returned %s", branch, tip, before, ret.Commit)
				}
				if log := s.git(s.proj, "log", "--format=%s", before+".."+tip); !strings.Contains(log, "stub claude: work") {
					t.Errorf("the harness's commit is not on %s:\n%s", branch, log)
				}
			} else {
				if ret.Outcome != "conflict" || ret.KeptOn == "" || !strings.HasPrefix(ret.KeptOn, "cloop/returned/") {
					t.Fatalf("a run returning to a worktree dirtied while the hub was down = %+v, want its work kept", ret)
				}
				if tip != before {
					t.Errorf("%s moved to %s although its worktree was dirty", branch, tip)
				}
				if got := s.git(s.proj, "rev-parse", "refs/heads/"+ret.KeptOn); got != ret.Commit {
					t.Errorf("the kept branch %s is at %s, want %s", ret.KeptOn, got, ret.Commit)
				}
				if log := s.git(s.proj, "log", "--format=%s", before+".."+ret.KeptOn); !strings.Contains(log, "stub claude: work") {
					t.Errorf("the kept branch does not carry the harness's commit:\n%s", log)
				}
				if b := readTestFile(t, notes); string(b) != "uncommitted, on the hub\n" {
					t.Errorf("the hub-side change was lost: %q", b)
				}
			}
			s.waitFor("the feature's task to be done in the hub's copy", 60*time.Second, func() bool {
				return s.taskStatus(fdir, 1) == "done"
			})
			s.assertSettled(fdir, 1, r)
		})
	}
}
