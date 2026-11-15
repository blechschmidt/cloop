package e2e_test

// A project moved off a remote device (Task 20495), end to end over the real
// protocol: a token-protected hub on loopback and an executor agent, both the
// cloop under test, both started with every inherited CLOOP_* variable
// dropped. The device's working copy — a branch no remote has, uncommitted
// and untracked work, a run's output under .cloop, its configuration, a link
// planted beside the output — is captured by the agent over the capture
// frames and rebuilt in the hub's own directory for the project, where the
// project runs next. A second project, whose working copy holds a value one
// of its grants delivers, is refused at the capture and stays where it was.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

const moveToken = "e2e-project-move-token"

// moveScene is a hub with two projects and one device.
type moveScene struct {
	t      *testing.T
	bin    string
	root   string
	env    []string
	hubDir string
	base   string
	device string
	hubLog *strings.Builder
	agLog  *strings.Builder
	procs  []*exec.Cmd
}

func (s *moveScene) run(dir string, args ...string) string {
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

func (s *moveScene) git(dir string, args ...string) string {
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

func (s *moveScene) start(cmd *exec.Cmd, log *strings.Builder) {
	s.t.Helper()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	w := &syncWriter{w: log}
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	s.procs = append(s.procs, cmd)
}

func (s *moveScene) stop() {
	for _, c := range s.procs {
		if c.Process != nil {
			_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
			_, _ = c.Process.Wait()
		}
	}
	if s.t.Failed() {
		s.t.Logf("hub log:\n%s", tail(s.hubLog.String(), 10000))
		s.t.Logf("agent log:\n%s", tail(s.agLog.String(), 6000))
	}
}

func (s *moveScene) call(method, path string, body any) (int, map[string]any, string) {
	s.t.Helper()
	var rd io.Reader = strings.NewReader("")
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, s.base+path, rd)
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+moveToken)
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

func (s *moveScene) waitFor(what string, timeout time.Duration, cond func() bool) {
	s.t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			s.t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func (s *moveScene) projectIdx(path string) int {
	s.t.Helper()
	_, body, _ := s.call("GET", "/api/projects", nil)
	raw, _ := body["projects"].([]any)
	for i, r := range raw {
		if m, ok := r.(map[string]any); ok && m["path"] == path {
			return i
		}
	}
	s.t.Fatalf("the hub does not serve %s", path)
	return -1
}

// workingCopy leaves a working copy on the device for project, as runs there
// would, and returns its directory.
func (s *moveScene) workingCopy(project string) string {
	s.t.Helper()
	wc := filepath.Join(s.device, executor.DeviceWorkDir(project))
	if err := os.MkdirAll(wc, 0o755); err != nil {
		s.t.Fatal(err)
	}
	s.git(wc, "init", "-q", "-b", "main")
	writeTestFile(s.t, filepath.Join(wc, "README.md"), "made on the device\n")
	s.git(wc, "add", "-A")
	s.git(wc, "commit", "-qm", "first, on the device")
	s.git(wc, "checkout", "-qb", "topic")
	writeTestFile(s.t, filepath.Join(wc, "topic.go"), "package topic\n")
	s.git(wc, "add", "-A")
	s.git(wc, "commit", "-qm", "a commit no remote holds")
	writeTestFile(s.t, filepath.Join(wc, "README.md"), "made on the device, edited since\n")
	writeTestFile(s.t, filepath.Join(wc, "notes", "draft.md"), "untracked draft\n")
	writeTestFile(s.t, filepath.Join(wc, ".cloop", "artifacts", "9_output.txt"), "task nine's output\n")
	writeTestFile(s.t, filepath.Join(wc, ".cloop", "config.yaml"), "provider: mock\n# the device's own\n")
	if err := os.Symlink("/etc/passwd", filepath.Join(wc, ".cloop", "artifacts", "passwd")); err != nil {
		s.t.Fatal(err)
	}
	return wc
}

// moveAndWait starts a move of project to target and waits for it to end.
func (s *moveScene) moveAndWait(project, target string) map[string]any {
	s.t.Helper()
	idx := s.projectIdx(project)
	code, body, raw := s.call("POST", fmt.Sprintf("/api/projects/%d/move", idx), map[string]any{"target": target})
	if code != http.StatusAccepted {
		s.t.Fatalf("start the move = HTTP %d: %s", code, raw)
	}
	id := fmt.Sprint(body["move"].(map[string]any)["id"])
	var move map[string]any
	s.waitFor("the move to end", 3*time.Minute, func() bool {
		_, b, _ := s.call("GET", fmt.Sprintf("/api/projects/%d/moves", idx), nil)
		list, _ := b["moves"].([]any)
		for _, m := range list {
			mm, _ := m.(map[string]any)
			if mm["id"] == id {
				switch mm["phase"] {
				case "done", "failed", "rolled_back":
					move = mm
					return true
				}
			}
		}
		return false
	})
	return move
}

func TestE2EMoveCapturesADevicesWorkingCopy(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	home := filepath.Join(root, "home")
	gitconfig := filepath.Join(home, ".gitconfig")
	writeTestFile(t, gitconfig, "[user]\n\tname = E2E\n\temail = e2e@example.com\n[init]\n\tdefaultBranch = main\n"+
		"[safe]\n\tdirectory = *\n")
	s := &moveScene{t: t, bin: binaryPath(t), root: root, hubDir: filepath.Join(root, "hub"),
		device: filepath.Join(root, "device"), hubLog: &strings.Builder{}, agLog: &strings.Builder{},
		env: append(withoutCloopEnv(os.Environ()),
			"HOME="+home,
			"CLOOP_HOME="+filepath.Join(home, ".cloop"),
			"CLOOP_UI_TOKEN="+moveToken,
			// The broker on purpose, the same way everywhere: an inherited
			// key would make the scan depend on who runs the test.
			"CLOOP_SECRET_KEY=e2e-project-move",
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL="+gitconfig,
			"GIT_TERMINAL_PROMPT=0",
			"NO_COLOR=1",
		)}
	t.Cleanup(s.stop)
	clean, tainted := filepath.Join(root, "proj-clean"), filepath.Join(root, "proj-tainted")
	for _, d := range []string{s.hubDir, clean, tainted} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s.run(s.hubDir, "init", "--provider", "mock", "--skip-clarify", "hub")
	s.run(clean, "init", "--provider", "mock", "--skip-clarify", "Move off the device")
	s.run(tainted, "init", "--provider", "mock", "--skip-clarify", "Carry nothing granted")
	// A value the tainted project's runs are given, which a run wrote into
	// its tree.
	value := "e2e-move-deploy-key-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	s.run(s.hubDir, "secret", "mint", "e2e-move-deploy", "--kind", "env", "--value", `{"DEPLOY_KEY":"`+value+`"}`)
	s.run(s.hubDir, "secret", "grant", "e2e-move-deploy", "--to", "project:"+tainted, "--env-keys", "DEPLOY_KEY", "--ttl", "2h")

	port := freePort(t)
	s.base = fmt.Sprintf("http://127.0.0.1:%d", port)
	hub := exec.Command(s.bin, "ui", "--listen", "127.0.0.1", "--port", strconv.Itoa(port), "--no-browser",
		"--projects", clean, "--projects", tainted)
	hub.Dir, hub.Env = s.hubDir, s.env
	s.start(hub, s.hubLog)
	s.waitFor("the hub to answer", 60*time.Second, func() bool {
		code, _, _ := s.call("GET", "/api/executors", nil)
		return code == http.StatusOK
	})
	// Token-protected: nothing answers without the token.
	if resp, err := http.Get(s.base + "/api/executors"); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("the hub answered an unauthenticated request with %d", resp.StatusCode)
		}
	}

	bundle := filepath.Join(root, "enroll.bundle")
	s.run(s.hubDir, "executor", "enroll", "--name", "edge-move", "--server",
		strings.Replace(s.base, "http://", "ws://", 1)+"/api/executors/connect", "--bundle-file", bundle)
	agent := exec.Command(s.bin, "executor", "agent", "--token-file", bundle,
		"--credential", filepath.Join(root, "agent.json"), "--workdir-root", s.device)
	agent.Env = append(append([]string(nil), s.env...), "HOME="+filepath.Join(root, "device-home"))
	s.start(agent, s.agLog)
	var deviceID string
	s.waitFor("the agent to connect", 60*time.Second, func() bool {
		_, body, _ := s.call("GET", "/api/executors", nil)
		raw, _ := body["executors"].([]any)
		for _, r := range raw {
			m, _ := r.(map[string]any)
			if m["name"] == "edge-move" && m["status"] == "online" {
				deviceID = fmt.Sprint(m["id"])
				return true
			}
		}
		return false
	})
	for _, p := range []string{clean, tainted} {
		code, _, raw := s.call("POST", fmt.Sprintf("/api/projects/%d/executor", s.projectIdx(p)), map[string]any{"executor_id": deviceID})
		if code != http.StatusOK {
			t.Fatalf("bind %s to the device = %d: %s", p, code, raw)
		}
	}
	wc := s.workingCopy(clean)
	taintedWC := s.workingCopy(tainted)
	writeTestFile(t, filepath.Join(taintedWC, "deploy.env"), "DEPLOY_KEY="+value+"\n")
	deviceStatus := s.git(wc, "status", "--porcelain=v2", "--", ".", ":(exclude).cloop")

	// The preflight reads the device's working copy over the protocol.
	code, body, raw := s.call("GET", fmt.Sprintf("/api/projects/%d/move/preflight?target=local", s.projectIdx(clean)), nil)
	if code != http.StatusOK {
		t.Fatalf("preflight = HTTP %d: %s", code, raw)
	}
	if blocked, _ := body["blocked"].(bool); blocked {
		t.Fatalf("the preflight blocks the move:\n%s", raw)
	}
	for _, want := range []string{"1 changed and 1 untracked", "3 commit(s)", "source's own"} {
		if !strings.Contains(raw, want) {
			t.Errorf("the preflight does not say %q:\n%s", want, raw)
		}
	}

	move := s.moveAndWait(clean, "local")
	if move["phase"] != "done" {
		t.Fatalf("the move ended %v at %v: %v", move["phase"], move["failed_phase"], move["error"])
	}
	capture := move["detail"].(map[string]any)["capture"].(map[string]any)
	if capture["delivery"] != "hub_tree" || capture["from"] != "device "+deviceID {
		t.Errorf("capture: delivery %v from %v", capture["delivery"], capture["from"])
	}
	if scan, _ := capture["scan"].(map[string]any); scan["result"] != "clean" {
		t.Errorf("scan = %v", capture["scan"])
	}
	// The hub's directory now holds the device's working copy, exactly.
	if got := s.git(clean, "status", "--porcelain=v2", "--", ".", ":(exclude).cloop"); got != deviceStatus {
		t.Errorf("status on the hub:\n%s\nwant the device's:\n%s", got, deviceStatus)
	}
	if got := s.git(clean, "rev-parse", "--abbrev-ref", "HEAD"); got != "topic" {
		t.Errorf("HEAD on the hub = %s, want topic", got)
	}
	if got, want := s.git(clean, "rev-parse", "refs/heads/topic"), s.git(wc, "rev-parse", "refs/heads/topic"); got != want {
		t.Errorf("topic on the hub = %s, the device's = %s", got, want)
	}
	if b, err := os.ReadFile(filepath.Join(clean, "notes", "draft.md")); err != nil || string(b) != "untracked draft\n" {
		t.Errorf("the untracked draft: %q %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(clean, ".cloop", "artifacts", "9_output.txt")); err != nil || string(b) != "task nine's output\n" {
		t.Errorf("the run's output: %q %v", b, err)
	}
	if _, err := os.Lstat(filepath.Join(clean, ".cloop", "artifacts", "passwd")); err == nil {
		t.Error("the planted link travelled")
	}
	if b, _ := os.ReadFile(filepath.Join(clean, ".cloop", "config.yaml")); strings.Contains(string(b), "the device's own") {
		t.Error("the device's configuration replaced the hub's")
	}
	// And the device keeps its copy as it was.
	if got := s.git(wc, "status", "--porcelain=v2", "--", ".", ":(exclude).cloop"); got != deviceStatus {
		t.Errorf("the device's copy changed:\n%s", got)
	}

	// The tainted project's capture carries a granted value: refused at the
	// capture, nothing switched, the value named nowhere.
	move = s.moveAndWait(tainted, "local")
	if move["phase"] != "failed" || move["failed_phase"] != "capture" {
		t.Fatalf("the tainted move ended %v at %v: %v", move["phase"], move["failed_phase"], move["error"])
	}
	msg := fmt.Sprint(move["error"])
	if !strings.Contains(msg, "e2e-move-deploy") || strings.Contains(msg, value) {
		t.Errorf("the refusal must name the secret and not the value: %s", msg)
	}
	for _, name := range []string{".git", "README.md", "deploy.env"} {
		if _, err := os.Lstat(filepath.Join(tainted, name)); err == nil {
			t.Errorf("the tainted project's hub directory was seeded: it holds %s", name)
		}
	}
	_, projects, _ := s.call("GET", "/api/projects", nil)
	if strings.Contains(fmt.Sprint(projects), value) {
		t.Error("the hub's project list carries the value")
	}
	if strings.Contains(s.hubLog.String(), value) {
		t.Error("the hub logged the value")
	}
}
