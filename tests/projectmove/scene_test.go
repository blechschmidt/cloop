package projectmove_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// hubToken protects the test's hub: it listens on loopback only, and every
// call carries the token anyway.
const hubToken = "e2e-projectmove-hub-token"

// holdMarker in a task's title makes the stand-in harness hold that task
// until the move stops the run, as long as .cloop/e2e-hold exists where it
// runs.
const holdMarker = "HOLD-UNTIL-MOVED"

// stubClaude stands in for Claude Code. It reads the prompt, finds the task it
// was given, and:
//
//   - for a task whose title carries holdMarker, while .cloop/e2e-hold exists
//     in its working directory, says so in .cloop/e2e-holding and waits —
//     until the move's quiesce stops the run, which kills it;
//   - otherwise writes ran-<id>.txt into the working tree, files a report as
//     the task's attachment, and ends the turn with TASK_DONE.
//
// POSIX sh only: the container round trip runs it under Alpine's busybox.
const stubClaude = `#!/bin/sh
prompt=$(cat)
current=$(printf '%s\n' "$prompt" | sed -n '/^\*\*Task [0-9]/{p;q;}')
id=$(printf '%s\n' "$current" | sed -n 's/^\*\*Task \([0-9][0-9]*\):.*/\1/p')
[ -n "$id" ] || id=unknown
case "$current" in
*` + holdMarker + `*)
  if [ -e .cloop/e2e-hold ]; then
    echo "$$ $id" > .cloop/e2e-holding
    while [ -e .cloop/e2e-hold ]; do sleep 1; done
  fi ;;
esac
printf 'task %s ran in %s\n' "$id" "$(pwd)" > "ran-$id.txt"
if [ -n "$CLOOP_TASK_ATTACHMENTS" ]; then
  mkdir -p "$CLOOP_TASK_ATTACHMENTS" &&
    printf 'report of task %s\n' "$id" > "$CLOOP_TASK_ATTACHMENTS/report-$id.txt"
fi
echo "Wrote ran-$id.txt."
echo TASK_DONE
`

// lockedBuffer collects a process's output.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// gitForge serves bare repositories under root over HTTPS on loopback,
// through git's own smart HTTP backend: the project's origin, which a device
// fetches before each run.
type gitForge struct {
	root   string
	srv    *httptest.Server
	caFile string
}

func newGitForge(t *testing.T, dir string) *gitForge {
	t.Helper()
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	f := &gitForge{root: filepath.Join(dir, "forge")}
	if err := os.MkdirAll(f.root, 0o755); err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewUnstartedServer(&cgi.Handler{
		Path: gitBin,
		Args: []string{"http-backend"},
		Env: []string{
			"GIT_PROJECT_ROOT=" + f.root,
			"GIT_HTTP_EXPORT_ALL=1",
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
		},
		InheritEnv: []string{"PATH"},
	})
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.caFile = filepath.Join(dir, "forge-ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	if err := os.WriteFile(f.caFile, block, 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

// repo creates a bare repository at path under the forge and returns its
// directory and https URL. The path has three segments on purpose: a
// repository that is not owner/name needs no grant to be fetched, and this
// origin is public.
func (f *gitForge) repo(t *testing.T, env []string, path string) (string, string) {
	t.Helper()
	dir := filepath.Join(f.root, filepath.FromSlash(path))
	cmd := exec.Command("git", "init", "-q", "--bare", "-b", "main", dir)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}
	return dir, f.srv.URL + "/" + path
}

// scene is a hub, its project, and the executors the project moves between.
type scene struct {
	t      *testing.T
	bin    string
	root   string
	env    []string
	hubDir string
	proj   string
	port   int
	base   string
	forge  *gitForge
	bare   string
	origin string

	hub    *exec.Cmd
	hubLog *lockedBuffer
	// hubLogs keeps the logs of hub processes that ended, for a failure.
	hubLogs []string

	agent      *exec.Cmd
	agentLog   *lockedBuffer
	deviceRoot string
	deviceBin  string
	deviceID   string

	containerID string
}

// sceneOptions shape a scene.
type sceneOptions struct {
	// hubConfig is appended to the hub's .cloop/config.yaml.
	hubConfig string
	// deviceCloop, when set, writes the script the device's PATH runs as
	// cloop, given the scene's directory and the cloop under test; otherwise
	// the device runs the cloop under test itself.
	deviceCloop func(root, bin string) string
}

func newScene(t *testing.T, opts sceneOptions) *scene {
	t.Helper()
	root, err := os.MkdirTemp("", "cloop-projectmove-*")
	if err != nil {
		t.Fatal(err)
	}
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	s := &scene{t: t, bin: cloopBinary(t), root: root,
		hubDir: filepath.Join(root, "hub"), proj: filepath.Join(root, "proj"),
		deviceRoot: filepath.Join(root, "device"), hubLog: &lockedBuffer{}}
	t.Cleanup(func() {
		s.stopAll()
		if t.Failed() {
			for i, l := range s.hubLogs {
				t.Logf("log of hub process %d:\n%s", i+1, tail(l, 12000))
			}
			if s.hubLog != nil {
				t.Logf("hub log:\n%s", tail(s.hubLog.String(), 16000))
			}
			if s.agentLog != nil {
				t.Logf("agent log:\n%s", tail(s.agentLog.String(), 12000))
			}
		}
		if os.Getenv("CLOOP_PROJECTMOVE_KEEP") == "1" {
			t.Logf("kept the scene at %s", root)
			return
		}
		_ = os.RemoveAll(root)
	})

	home := filepath.Join(root, "home")
	hubBin := filepath.Join(root, "hub-bin")
	for _, d := range []string{home, hubBin, s.hubDir, s.proj, s.deviceRoot} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	gitconfig := filepath.Join(home, ".gitconfig")
	writeFile(t, gitconfig, "[user]\n\tname = E2E\n\temail = e2e@example.com\n[init]\n\tdefaultBranch = main\n"+
		"[safe]\n\tdirectory = *\n")
	writeExec(t, filepath.Join(hubBin, "claude"), stubClaude)
	s.env = append(withoutCloopEnv(os.Environ()),
		"HOME="+home,
		"CLOOP_HOME="+filepath.Join(home, ".cloop"),
		"CLOOP_UI_TOKEN="+hubToken,
		// The secret broker, on purpose and the same way everywhere: the
		// harness credential the sandboxed runs need is a grant.
		"CLOOP_SECRET_KEY=e2e-projectmove",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+gitconfig,
		"GIT_TERMINAL_PROMPT=0",
		"NO_COLOR=1",
	)
	s.env = withPath(s.env, hubBin)

	// The device: its PATH runs the cloop under test (or the given script)
	// and the stand-in claude.
	s.deviceBin = filepath.Join(root, "device-bin")
	if err := os.MkdirAll(s.deviceBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if opts.deviceCloop != nil {
		writeExec(t, filepath.Join(s.deviceBin, "cloop"), opts.deviceCloop(root, s.bin))
	} else if err := os.Symlink(s.bin, filepath.Join(s.deviceBin, "cloop")); err != nil {
		t.Fatal(err)
	}
	writeExec(t, filepath.Join(s.deviceBin, "claude"), stubClaude)

	// The origin, on a forge the device reaches over TLS.
	s.forge = newGitForge(t, root)
	s.bare, s.origin = s.forge.repo(t, s.env, "srv/acme/app.git")

	s.cloop(s.hubDir, "init", "--provider", "mock", "--skip-clarify", "hub")
	if opts.hubConfig != "" {
		appendFile(t, filepath.Join(s.hubDir, ".cloop", "config.yaml"), "\n"+opts.hubConfig)
	}
	return s
}

// initProject makes the project: a repository whose main is on the origin,
// with a text, a binary and an executable file, and a cloop project of it
// with the harness credential its sandboxed runs need granted.
func (s *scene) initProject() {
	t := s.t
	s.git(s.proj, "init", "-q", "-b", "main")
	writeFile(t, filepath.Join(s.proj, "README.md"), "# app\n\nThe project a move carries.\n")
	writeFile(t, filepath.Join(s.proj, "src", "main.go"), "package main\n\nfunc main() {}\n")
	writeFile(t, filepath.Join(s.proj, "src", "util.go"), "package main\n\nfunc util() int { return 1 }\n")
	writeFile(t, filepath.Join(s.proj, "docs", "old-name.md"), "a page that is renamed later\n")
	writeBytes(t, filepath.Join(s.proj, "assets", "logo.bin"), binaryBlob(1, 4096))
	writeExec(t, filepath.Join(s.proj, "scripts", "build.sh"), "#!/bin/sh\necho build\n")
	s.git(s.proj, "add", "-A")
	s.git(s.proj, "commit", "-qm", "first")
	s.git(s.proj, "remote", "add", "origin", s.origin)
	s.git(s.proj, "push", "-q", s.bare, "main:refs/heads/main")
	s.git(s.proj, "update-ref", "refs/remotes/origin/main", "refs/heads/main")
	s.cloop(s.proj, "init", "--provider", "claudecode", "--skip-clarify", "Keep everything through every move")

	// The Claude credential a sandboxed claudecode run needs (the stand-in
	// ignores it), made of parts so no literal has a token's shape.
	token := "sk-" + "ant-oat01-" + strings.Repeat("e2eMover", 4) + "Qx7_Lm2-Pz9"
	s.cloop(s.hubDir, "secret", "mint", "e2e-claude-credential", "--kind", "env",
		"--value", `{"CLAUDE_CODE_OAUTH_TOKEN":"`+token+`"}`)
	s.cloop(s.hubDir, "secret", "grant", "e2e-claude-credential", "--to", "project:"+s.proj,
		"--env-keys", "CLAUDE_CODE_OAUTH_TOKEN", "--ttl", "4h")
}

// startHub starts a hub process on the scene's port, the first time on a
// fresh one.
func (s *scene) startHub() {
	s.t.Helper()
	if s.port == 0 {
		s.port = freePort(s.t)
		s.base = fmt.Sprintf("http://127.0.0.1:%d", s.port)
	}
	if s.hub != nil {
		s.hubLogs = append(s.hubLogs, s.hubLog.String())
	}
	s.hubLog = &lockedBuffer{}
	cmd := exec.Command(s.bin, "ui", "--listen", "127.0.0.1", "--port", strconv.Itoa(s.port), "--no-browser",
		"--projects", s.proj)
	cmd.Dir, cmd.Env = s.hubDir, s.env
	s.hub = s.spawn(cmd, s.hubLog)
	s.waitFor("the hub to answer", 60*time.Second, func() bool {
		code, _, _ := s.call("GET", "/api/executors", nil)
		return code == http.StatusOK
	})
}

// killHub kills the hub process outright, as a crash or an OOM kill would.
func (s *scene) killHub() {
	s.t.Helper()
	if s.hub == nil || s.hub.Process == nil {
		return
	}
	_ = syscall.Kill(-s.hub.Process.Pid, syscall.SIGKILL)
	_, _ = s.hub.Process.Wait()
}

// startAgent enrols a device and starts its agent: a second process speaking
// the agent protocol to the hub over a WebSocket. It returns the executor id.
func (s *scene) startAgent() string {
	s.t.Helper()
	bundle := filepath.Join(s.root, "enroll.bundle")
	s.cloop(s.hubDir, "executor", "enroll", "--name", "edge-mover", "--server",
		strings.Replace(s.base, "http://", "ws://", 1)+"/api/executors/connect", "--bundle-file", bundle)
	cmd := exec.Command(s.bin, "executor", "agent", "--token-file", bundle,
		"--credential", filepath.Join(s.root, "agent.json"), "--workdir-root", s.deviceRoot,
		"--max-concurrent", "2")
	cmd.Env = append(withPath(s.env, s.deviceBin),
		"HOME="+filepath.Join(s.root, "device-home"),
		// The device trusts the forge's certificate, as a device trusts an
		// operator's private CA.
		"GIT_SSL_CAINFO="+s.forge.caFile)
	s.agentLog = &lockedBuffer{}
	s.agent = s.spawn(cmd, s.agentLog)
	s.waitFor("the agent to connect", 60*time.Second, func() bool {
		_, body, _ := s.call("GET", "/api/executors", nil)
		for _, e := range list(body, "executors") {
			if e["name"] == "edge-mover" && e["status"] == "online" {
				s.deviceID = fmt.Sprint(e["id"])
				return true
			}
		}
		return false
	})
	return s.deviceID
}

// sandboxUID owns the project while it runs in a container, when the test
// runs as root: the container executor never runs a workload as root.
const sandboxUID = 1000

// ownProject hands the project's directory to sandboxUID before a container
// runs in it, as an operator does, when the test runs as root. Everything the
// test, the hub and the runs on the hub's host wrote since — as root — is
// handed over again, the hub's databases' journals included.
func (s *scene) ownProject() {
	s.t.Helper()
	if os.Geteuid() != 0 {
		return
	}
	err := filepath.WalkDir(s.proj, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, sandboxUID, sandboxUID)
	})
	if err != nil {
		s.t.Fatal(err)
	}
}

// containerExecutor is the id of the hub's container executor.
func (s *scene) containerExecutor() string {
	s.t.Helper()
	_, body, _ := s.call("GET", "/api/executors", nil)
	for _, e := range list(body, "executors") {
		if e["kind"] == "container" {
			s.containerID = fmt.Sprint(e["id"])
		}
	}
	if s.containerID == "" {
		s.t.Fatalf("no container executor is registered: %v", body)
	}
	return s.containerID
}

func (s *scene) spawn(cmd *exec.Cmd, log *lockedBuffer) *exec.Cmd {
	s.t.Helper()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	return cmd
}

func (s *scene) stopAll() {
	for _, c := range []*exec.Cmd{s.agent, s.hub} {
		if c == nil || c.Process == nil {
			continue
		}
		_ = syscall.Kill(-c.Process.Pid, syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _, _ = c.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
			<-done
		}
	}
	// Only what this scene made: containers of its project.
	if out, err := exec.Command("docker", "ps", "-aq", "--filter", "label=cloop.project="+s.proj).Output(); err == nil {
		for _, id := range strings.Fields(string(out)) {
			_ = exec.Command("docker", "rm", "-f", id).Run()
		}
	}
}

func (s *scene) cloop(dir string, args ...string) string {
	s.t.Helper()
	cmd := exec.Command(s.bin, args...)
	cmd.Dir, cmd.Env = dir, s.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		s.t.Fatalf("cloop %v in %s: %v\n%s", args, dir, err, out)
	}
	return string(out)
}

func (s *scene) git(dir string, args ...string) string {
	s.t.Helper()
	out, err := s.gitErr(dir, args...)
	if err != nil {
		s.t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
	return out
}

func (s *scene) gitErr(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir, cmd.Env = dir, s.env
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// call sends one request to the hub with its token.
func (s *scene) call(method, path string, body any) (int, map[string]any, string) {
	s.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, s.base+path, rd)
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+hubToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 3 * time.Minute}).Do(req)
	if err != nil {
		return 0, nil, err.Error()
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, string(raw)
}

// mustCall is call that fails the test on any status but want.
func (s *scene) mustCall(want int, method, path string, body any) map[string]any {
	s.t.Helper()
	code, out, raw := s.call(method, path, body)
	if code != want {
		s.t.Fatalf("%s %s = HTTP %d, want %d: %s", method, path, code, want, raw)
	}
	return out
}

func (s *scene) waitFor(what string, timeout time.Duration, cond func() bool) {
	s.t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			s.t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// idx is the project's index on the hub.
func (s *scene) idx() int {
	s.t.Helper()
	_, body, _ := s.call("GET", "/api/projects", nil)
	for i, p := range list(body, "projects") {
		if p["path"] == s.proj {
			return i
		}
	}
	s.t.Fatalf("the hub does not serve %s", s.proj)
	return -1
}

// task is one task as the hub's state reports it.
type task struct {
	ID     int    `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
}

// tasks reads the project's plan from the hub.
func (s *scene) tasks() []task {
	s.t.Helper()
	code, _, raw := s.call("GET", fmt.Sprintf("/api/state?project_idx=%d", s.idx()), nil)
	if code != http.StatusOK {
		s.t.Fatalf("read the project's state = HTTP %d: %s", code, raw)
	}
	var st struct {
		Plan struct {
			Tasks []task `json:"tasks"`
		} `json:"plan"`
	}
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		s.t.Fatalf("read the project's state: %v", err)
	}
	return st.Plan.Tasks
}

func (s *scene) taskStatus(id int) string {
	for _, tk := range s.tasks() {
		if tk.ID == id {
			return tk.Status
		}
	}
	return ""
}

// addTask adds a task through the hub and returns its id.
func (s *scene) addTask(title string) int {
	s.t.Helper()
	before := map[int]bool{}
	for _, tk := range s.tasks() {
		before[tk.ID] = true
	}
	code, body, raw := s.call("POST", fmt.Sprintf("/api/tasks?project_idx=%d", s.idx()),
		map[string]any{"title": title, "description": title})
	if code != http.StatusOK && code != http.StatusCreated {
		s.t.Fatalf("add task %q = HTTP %d: %s", title, code, raw)
	}
	_ = body
	for _, tk := range s.tasks() {
		if !before[tk.ID] && tk.Title == title {
			return tk.ID
		}
	}
	s.t.Fatalf("the hub did not add task %q", title)
	return 0
}

// run starts the project's run where it is bound.
func (s *scene) run() {
	s.t.Helper()
	s.mustCall(http.StatusOK, "POST", fmt.Sprintf("/api/projects/%d/run", s.idx()), map[string]any{})
}

// runTo starts the project's run and waits for task id to be done.
func (s *scene) runTo(id int, where string) {
	s.t.Helper()
	s.run()
	s.waitFor(fmt.Sprintf("task %d to be done on %s", id, where), 4*time.Minute, func() bool {
		switch st := s.taskStatus(id); st {
		case "done":
			return true
		case "failed", "skipped", "timed_out":
			s.t.Fatalf("task %d ended %s on %s", id, st, where)
		}
		return false
	})
	s.waitIdle()
}

// waitIdle waits for the project's run to end.
func (s *scene) waitIdle() {
	s.t.Helper()
	s.waitFor("the project's run to end", 2*time.Minute, func() bool {
		_, body, _ := s.call("GET", "/api/projects", nil)
		for _, p := range list(body, "projects") {
			if p["path"] == s.proj {
				st := fmt.Sprint(p["status"])
				return st != "running" && st != "evolving" && st != "starting"
			}
		}
		return false
	})
}

// attachments lists a task's attachments: name → SHA-256 of the bytes the
// hub serves for it.
func (s *scene) attachments(id int) map[string]string {
	s.t.Helper()
	body := s.mustCall(http.StatusOK, "GET", fmt.Sprintf("/api/tasks/%d/attachments?project_idx=%d", id, s.idx()), nil)
	out := map[string]string{}
	for _, a := range list(body, "attachments") {
		path := fmt.Sprintf("/api/tasks/%d/attachments/%v?project_idx=%d", id, a["id"], s.idx())
		req, _ := http.NewRequest("GET", s.base+path, nil)
		req.Header.Set("Authorization", "Bearer "+hubToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			s.t.Fatalf("download attachment %v: %v", a["name"], err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			s.t.Fatalf("download attachment %v = HTTP %d: %s", a["name"], resp.StatusCode, b)
		}
		sum := sha256.Sum256(b)
		out[fmt.Sprint(a["name"])] = hex.EncodeToString(sum[:])
	}
	return out
}

// deviceCopy is the project's working copy on the device.
func (s *scene) deviceCopy() string {
	return filepath.Join(s.deviceRoot, executor.DeviceWorkDir(s.proj))
}

// ─── moves ──────────────────────────────────────────────────────────────────

// startMove starts a move through the hub's route and returns its id.
func (s *scene) startMove(target string) string {
	s.t.Helper()
	body := s.mustCall(http.StatusAccepted, "POST", fmt.Sprintf("/api/projects/%d/move", s.idx()),
		map[string]any{"target": target})
	return fmt.Sprint(body["move"].(map[string]any)["id"])
}

// moveView reads one move and the plan for cleaning up after it.
func (s *scene) moveView(id string) (map[string]any, map[string]any) {
	s.t.Helper()
	body := s.mustCall(http.StatusOK, "GET", fmt.Sprintf("/api/projects/%d/move/%s", s.idx(), id), nil)
	m, _ := body["move"].(map[string]any)
	c, _ := body["cleanup"].(map[string]any)
	return m, c
}

// waitMove waits for a move to end and returns it.
func (s *scene) waitMove(id string, timeout time.Duration) map[string]any {
	s.t.Helper()
	var m map[string]any
	s.waitFor("move "+id+" to end", timeout, func() bool {
		code, body, _ := s.call("GET", fmt.Sprintf("/api/projects/%d/move/%s", s.idx(), id), nil)
		if code != http.StatusOK {
			return false
		}
		m, _ = body["move"].(map[string]any)
		switch m["phase"] {
		case "done", "failed", "rolled_back":
			return true
		}
		return false
	})
	return m
}

// requireDone fails the test unless m ended done with nothing mismatched.
func (s *scene) requireDone(m map[string]any) {
	s.t.Helper()
	if m["phase"] != "done" {
		s.t.Fatalf("move %v ended %v at %v: %v", m["id"], m["phase"], m["failed_phase"], m["error"])
	}
	v, _ := dig(m, "detail", "verify").(map[string]any)
	if v == nil {
		s.t.Fatalf("move %v is done with no verification: %v", m["id"], m["detail"])
	}
	if mm, _ := v["mismatches"].([]any); len(mm) > 0 {
		s.t.Fatalf("move %v is done with mismatches: %v", m["id"], mm)
	}
}

// cleanup confirms a move's cleanup through the hub's route.
func (s *scene) cleanup(id string) map[string]any {
	s.t.Helper()
	return s.mustCall(http.StatusOK, "POST", fmt.Sprintf("/api/projects/%d/move/%s/cleanup", s.idx(), id),
		map[string]any{"confirm": true})
}

// ─── working copies ─────────────────────────────────────────────────────────

// workingCopy is what a snapshot of a project's working copy records: what a
// move promises to carry, read by the test with git and a walk of its own.
type workingCopy struct {
	// Files are the working tree's files outside .git and .cloop that git
	// does not ignore, by path: a digest of the bytes and the mode, a link's
	// target, or "missing" for a file the index has and the disk does not.
	Files map[string]string
	// Index is `git ls-files --stage`: every staged mode, blob and path.
	Index string
	// Head is the branch HEAD is on, or "detached <commit>".
	Head string
	// Refs are every branch and tag and what it points at.
	Refs map[string]string
	// Extras are the .cloop files a move delivers, by path under .cloop.
	Extras map[string]string
}

// deliveredExtras are the .cloop paths a move delivers (pkg/projectmove's
// delivered set): what a snapshot reads of .cloop.
var deliveredExtras = []string{"artifacts", "tasks", "attachments/outbox", "checkpoints", "sandbox.yaml", "requirements.yaml"}

// snapshot reads dir's working copy.
func (s *scene) snapshot(dir string) workingCopy {
	s.t.Helper()
	w := workingCopy{Files: map[string]string{}, Refs: map[string]string{}, Extras: map[string]string{}}
	listed := s.git(dir, "-c", "core.quotepath=off", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	for _, p := range strings.Split(listed, "\x00") {
		if p == "" || p == ".cloop" || strings.HasPrefix(p, ".cloop/") {
			continue
		}
		w.Files[p] = describePath(filepath.Join(dir, filepath.FromSlash(p)))
	}
	w.Index = s.git(dir, "ls-files", "--stage")
	if b, err := s.gitErr(dir, "symbolic-ref", "-q", "HEAD"); err == nil {
		w.Head = b
	} else {
		w.Head = "detached " + s.git(dir, "rev-parse", "HEAD")
	}
	for _, line := range strings.Split(s.git(dir, "for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags"), "\n") {
		if name, obj, ok := strings.Cut(line, " "); ok {
			w.Refs[name] = obj
		}
	}
	for _, rel := range deliveredExtras {
		base := filepath.Join(dir, ".cloop", filepath.FromSlash(rel))
		_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			r, _ := filepath.Rel(filepath.Join(dir, ".cloop"), p)
			w.Extras[filepath.ToSlash(r)] = describePath(p)
			return nil
		})
	}
	return w
}

// describePath is a path's content as a snapshot records it.
func describePath(p string) string {
	info, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return "missing"
	}
	if err != nil {
		return "unreadable: " + err.Error()
	}
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		target, _ := os.Readlink(p)
		return "link " + target
	case info.IsDir():
		return "directory"
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "unreadable: " + err.Error()
	}
	sum := sha256.Sum256(b)
	mode := "file"
	if info.Mode()&0o111 != 0 {
		mode = "exec"
	}
	return mode + " " + hex.EncodeToString(sum[:])
}

// compareCopies reports how got differs from want; refs only got holds are
// left out, since a target's repository may hold the move's own, and so are
// the .cloop files skip names.
func compareCopies(want, got workingCopy, skip func(path string) bool) []string {
	var out []string
	diffMaps := func(what string, a, b map[string]string, skip func(string) bool) {
		keys := map[string]bool{}
		for k := range a {
			keys[k] = true
		}
		for k := range b {
			keys[k] = true
		}
		var sorted []string
		for k := range keys {
			if skip == nil || !skip(k) {
				sorted = append(sorted, k)
			}
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			if a[k] != b[k] {
				out = append(out, fmt.Sprintf("%s %s: want %q, got %q", what, k, orNone(a[k]), orNone(b[k])))
			}
		}
	}
	diffMaps("file", want.Files, got.Files, nil)
	diffMaps(".cloop file", want.Extras, got.Extras, skip)
	if want.Index != got.Index {
		out = append(out, fmt.Sprintf("the index differs:\nwant:\n%s\ngot:\n%s", want.Index, got.Index))
	}
	if want.Head != got.Head {
		out = append(out, fmt.Sprintf("HEAD: want %s, got %s", want.Head, got.Head))
	}
	for name, obj := range want.Refs {
		if got.Refs[name] != obj {
			out = append(out, fmt.Sprintf("ref %s: want %s, got %s", name, obj, orNone(got.Refs[name])))
		}
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// ─── small helpers ──────────────────────────────────────────────────────────

func list(body map[string]any, key string) []map[string]any {
	raw, _ := body[key].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// dig follows keys through nested JSON objects.
func dig(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	writeBytes(t, path, []byte(body))
}

func writeBytes(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeExec(t *testing.T, path, body string) {
	t.Helper()
	writeFile(t, path, body)
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// binaryBlob is n bytes no text tool would take for text: every byte value,
// NULs included, in an order seeded by seed.
func binaryBlob(seed byte, n int) []byte {
	b := make([]byte, n)
	x := uint32(seed)*2654435761 + 1
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = byte(x)
	}
	return b
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// withoutCloopEnv drops every variable cloop reads from the environment:
// a hub's child inherits its key, and the test must not depend on who runs it.
func withoutCloopEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if !strings.HasPrefix(kv, "CLOOP_") {
			out = append(out, kv)
		}
	}
	return out
}

// withPath puts dir first on env's PATH.
func withPath(env []string, dir string) []string {
	out := make([]string, 0, len(env)+1)
	path := os.Getenv("PATH")
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			path = strings.TrimPrefix(kv, "PATH=")
			continue
		}
		out = append(out, kv)
	}
	return append(out, "PATH="+dir+string(os.PathListSeparator)+path)
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// buildImage builds the container round trip's sandbox image: git, the static
// cloop under test and the stand-in claude, on the base CI pulls for the
// flagship circuit.
func buildImage(t *testing.T, bin string) string {
	t.Helper()
	dir := t.TempDir()
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	writeBytes(t, filepath.Join(dir, "cloop"), data)
	writeFile(t, filepath.Join(dir, "claude"), stubClaude)
	writeFile(t, filepath.Join(dir, "Dockerfile"), "FROM "+imageBase+"\n"+
		"RUN apk add --no-cache git\n"+
		"COPY cloop /usr/local/bin/cloop\n"+
		"COPY claude /usr/local/bin/claude\n"+
		"RUN chmod 0755 /usr/local/bin/cloop /usr/local/bin/claude\n")
	sum := sha256.Sum256(append(data, []byte(stubClaude)...))
	tag := "cloop-projectmove-e2e:" + hex.EncodeToString(sum[:6])
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "build", "-q", "-t", tag, dir).CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", tag).Run() })
	return tag
}

// imageBase is the sandbox image's base, pinned by digest: the flagship
// circuit's (tests/flagship), so CI pulls it once.
const imageBase = "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
