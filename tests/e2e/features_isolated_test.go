package e2e_test

// Features on executors that isolate from the hub's filesystem (Task 20367),
// end to end: a real hub in strict no-host-execution mode, a real executor — a
// remote agent over a loopback WebSocket, or the container executor driving
// Docker — and a real `cloop run` on the far side with a stand-in `claude` that
// commits on whatever branch its checkout is on, exactly as a harness told to
// commit to its feature's branch would.
//
// Each test checks what the task promised:
//
//   - the harness's commit lands on cloop/feature/<slug> in the hub's
//     repository, and in the feature's worktree;
//   - the parent's branch, its .git/config and its hooks are untouched, and
//     hooks planted in the parent repository never ran — not when the hub
//     created the feature, shipped it, or landed its work;
//   - a hub-side worktree with uncommitted changes yields a conflict, with the
//     work kept on a branch of its own, instead of lost work in either
//     direction;
//   - a returned bundle over executors.feature_bundle_mb is refused, and the
//     refusal says so.
//
// The remote-agent test runs wherever git does. The container test needs Docker
// and builds a small sandbox image, so it is opt-in: CLOOP_FEATURE_CONTAINER_E2E=1
// (CI's flagship job sets it).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// stubClaude stands in for Claude Code. It commits whatever it writes, on the
// branch its checkout is on. A prompt mentioning BIG-OUTPUT makes it write 2 MB
// of incompressible data, for the bundle cap.
//
// Each run's file names carry a random part: busybox date (the container
// image's) has no %N, and a fast runner starts two runs within one second —
// the second then wrote the first one's file again, had nothing to commit,
// and returned no work for the dirty-worktree check to be about.
const stubClaude = `#!/bin/sh
prompt=$(cat)
n=$(date +%s)-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
case "$prompt" in
*BIG-OUTPUT*) head -c 2097152 /dev/urandom > "big-$n.bin" ;;
esac
echo "work $n" > "work-$n.txt"
# Evidence from inside the sandbox, carried out in the commit: whether this
# tree's .git is a repository of its own or a pointer into the hub's.
{ [ -d .git ] && echo "git-dir: directory" || echo "git-dir: other"
  echo "common-dir: $(git rev-parse --git-common-dir)"; } > "evidence-$n.txt"
git add -A
git commit -qm "stub claude: work $n" || { echo "stub claude: nothing was committed" >&2; exit 1; }
echo "Done: committed work-$n.txt."
echo TASK_DONE
`

// featureScene is a hub, a project with a feature, and the means to drive them.
type featureScene struct {
	t      *testing.T
	bin    string
	root   string
	env    []string
	proj   string
	hubDir string
	base   string
	marker string
	forge  *fakeForge
	origin string

	hub    *exec.Cmd
	hubLog *strings.Builder
	extra  []*exec.Cmd

	// What the parent looked like before the feature ran.
	mainSHA string
	config  []byte
	hooks   string
}

// newFeatureScene prepares the project and the hub's directory. hubConfig is
// appended to the hub's .cloop/config.yaml.
func newFeatureScene(t *testing.T, bin, hubConfig string) *featureScene {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	gitconfig := filepath.Join(home, ".gitconfig")
	// safe.directory for the test's own git: the container test hands the
	// project to an unprivileged uid, as an operator would.
	writeTestFile(t, gitconfig, "[user]\n\tname = E2E\n\temail = e2e@example.com\n[init]\n\tdefaultBranch = main\n"+
		"[safe]\n\tdirectory = *\n")
	s := &featureScene{
		t: t, bin: bin, root: root,
		proj:   filepath.Join(root, "proj"),
		hubDir: filepath.Join(root, "hub"),
		marker: filepath.Join(root, "hook-ran"),
		env: append(withoutCloopEnv(os.Environ()),
			"HOME="+home,
			"CLOOP_HOME="+filepath.Join(home, ".cloop"),
			// The hub's secret broker, configured on purpose and the same way
			// everywhere. With it, the parent's github.com origin — which
			// only the hub can follow, through insteadOf, to the bare origin
			// below — has no grant, so no run is told to fetch it and each
			// ships the branch whole. Inherited, it made the test depend on
			// the caller's environment: a hub's child process carries a key,
			// a CI runner does not, and there the run after the pull request
			// was sent to clone github.com.
			"CLOOP_SECRET_KEY=e2e-features-isolated",
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL="+gitconfig,
			"GIT_TERMINAL_PROMPT=0",
			"NO_COLOR=1",
		),
	}

	// The project: a repository that exists only here, a cloop project of it,
	// and hooks that would announce themselves if anything ran them.
	if err := os.MkdirAll(s.proj, 0o755); err != nil {
		t.Fatal(err)
	}
	s.git(s.proj, "init", "-q", "-b", "main")
	writeTestFile(t, filepath.Join(s.proj, "README.md"), "the project\n")
	s.git(s.proj, "add", "README.md")
	s.git(s.proj, "commit", "-qm", "first")
	s.cloop(s.proj, "init", "--provider", "claudecode", "--skip-clarify", "Parent goal")
	s.git(s.proj, "add", "-A")
	s.git(s.proj, "commit", "-qm", "cloop init")
	// An origin on "GitHub" that pushes to a local bare repository, so the
	// pull request flow has somewhere real to push. Its remote-tracking ref is
	// dropped again: with it, the base would count as on the upstream and a
	// device would be told to clone github.com.
	s.origin = filepath.Join(root, "origin.git")
	s.git(root, "init", "-q", "--bare", s.origin)
	s.git(s.proj, "remote", "add", "origin", "https://github.com/acme/app.git")
	s.git(s.proj, "config", "url."+s.origin+".insteadOf", "https://github.com/acme/app.git")
	s.git(s.proj, "push", "-q", "origin", "main")
	s.git(s.proj, "update-ref", "-d", "refs/remotes/origin/main")
	for _, h := range []string{"post-checkout", "post-merge", "post-commit", "pre-commit",
		"reference-transaction", "post-rewrite", "pre-push"} {
		path := filepath.Join(s.proj, ".git", "hooks", h)
		writeTestFile(t, path, "#!/bin/sh\necho "+h+" >> "+s.marker+"\n")
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.MkdirAll(s.hubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	s.cloop(s.hubDir, "init", "--provider", "mock", "--skip-clarify", "hub")
	// The forge the pull request is opened on, and the hub's own token for
	// it: a hub without sign-in hands that to a feature it publishes itself.
	s.forge = &fakeForge{token: "e2e-forge-token", prs: map[int]map[string]any{}, next: 70}
	api := httptest.NewServer(s.forge)
	t.Cleanup(api.Close)
	s.env = append(s.env, "CLOOP_GITHUB_API_URL="+api.URL)
	f, err := os.OpenFile(filepath.Join(s.hubDir, ".cloop", "config.yaml"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\n" + hubConfig + "github:\n    token: " + s.forge.token + "\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	t.Cleanup(s.stop)
	return s
}

// start runs the hub on a fresh port.
func (s *featureScene) start() {
	s.t.Helper()
	port := freePort(s.t)
	s.base = fmt.Sprintf("http://127.0.0.1:%d", port)
	s.hub = exec.Command(s.bin, "ui", "--port", fmt.Sprint(port), "--no-browser", "--projects", s.proj)
	s.hub.Dir = s.hubDir
	s.hub.Env = s.env
	s.hub.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	s.hubLog = &strings.Builder{}
	w := &syncWriter{w: s.hubLog}
	s.hub.Stdout, s.hub.Stderr = w, w
	if err := s.hub.Start(); err != nil {
		s.t.Fatal(err)
	}
	s.waitFor("the hub to answer", 30*time.Second, func() bool {
		resp, err := http.Get(s.base + "/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
}

// background starts a helper process (an agent) the scene stops with the hub.
func (s *featureScene) background(cmd *exec.Cmd, log *strings.Builder) {
	s.t.Helper()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	w := &syncWriter{w: log}
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	s.extra = append(s.extra, cmd)
}

func (s *featureScene) stop() {
	for _, c := range append(s.extra, s.hub) {
		if c == nil || c.Process == nil {
			continue
		}
		_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		_, _ = c.Process.Wait()
	}
	if s.t.Failed() && s.hubLog != nil {
		s.t.Logf("hub log:\n%s", tail(s.hubLog.String(), 12000))
	}
}

func (s *featureScene) git(dir string, args ...string) string {
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

func (s *featureScene) cloop(dir string, args ...string) string {
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

func (s *featureScene) call(method, path string, body any) (int, map[string]any) {
	s.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, s.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (s *featureScene) waitFor(what string, timeout time.Duration, cond func() bool) {
	s.t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			s.t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// projectIdx is path's index in the hub's project list, or -1.
func (s *featureScene) projectIdx(path string) int {
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

// bind pins the project to an executor through the dashboard's own route.
func (s *featureScene) bind(executorID string) {
	s.t.Helper()
	idx := s.projectIdx(s.proj)
	code, body := s.call("POST", fmt.Sprintf("/api/projects/%d/executor", idx), map[string]any{"executor_id": executorID})
	if code != http.StatusOK {
		s.t.Fatalf("bind the project to %s = %d %v", executorID, code, body)
	}
}

// newFeature creates a feature through the API — on the hub, since the
// project's executor isolates from it — and returns its directory.
func (s *featureScene) newFeature(name string, tasks ...string) string {
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

// snapshotParent records the parent's branch, configuration and hooks.
func (s *featureScene) snapshotParent() {
	s.t.Helper()
	s.mainSHA = s.git(s.proj, "rev-parse", "refs/heads/main")
	s.config = readTestFile(s.t, filepath.Join(s.proj, ".git", "config"))
	s.hooks = hookDigest(s.t, filepath.Join(s.proj, ".git", "hooks"))
}

func (s *featureScene) assertParentUntouched() {
	s.t.Helper()
	if got := s.git(s.proj, "rev-parse", "refs/heads/main"); got != s.mainSHA {
		s.t.Errorf("the parent's main moved from %s to %s", s.mainSHA, got)
	}
	if got := readTestFile(s.t, filepath.Join(s.proj, ".git", "config")); string(got) != string(s.config) {
		s.t.Errorf("the parent's .git/config changed:\n%s", got)
	}
	if got := hookDigest(s.t, filepath.Join(s.proj, ".git", "hooks")); got != s.hooks {
		s.t.Errorf("the parent's .git/hooks changed")
	}
	if b, err := os.ReadFile(s.marker); err == nil {
		s.t.Errorf("a hook in the parent repository ran: %s", b)
	}
}

// addTask adds a task to the feature through the hub.
func (s *featureScene) addTask(featureDir, title string) {
	s.t.Helper()
	idx := s.projectIdx(featureDir)
	code, body := s.call("POST", fmt.Sprintf("/api/tasks?project_idx=%d", idx),
		map[string]any{"title": title, "description": title})
	if code != http.StatusOK && code != http.StatusCreated {
		s.t.Fatalf("add task %q = %d %v", title, code, body)
	}
}

// runFeature starts the feature's run and waits for its work to be landed:
// the feature's record gains a Return newer than the start.
func (s *featureScene) runFeature(featureDir string) *feature.Return {
	s.t.Helper()
	var previous time.Time
	if m, err := feature.LoadMeta(featureDir); err == nil && m.Return != nil {
		previous = m.Return.At
	}
	idx := s.projectIdx(featureDir)
	code, body := s.call("POST", fmt.Sprintf("/api/projects/%d/run", idx), map[string]any{})
	if code != http.StatusOK {
		s.t.Fatalf("start the feature's run = %d %v", code, body)
	}
	var ret *feature.Return
	s.waitFor("the feature's run to end and its work to be landed", 4*time.Minute, func() bool {
		m, err := feature.LoadMeta(featureDir)
		if err != nil || m.Return == nil || !m.Return.At.After(previous) {
			return false
		}
		ret = m.Return
		return true
	})
	s.t.Logf("run of %s: %s — %s", filepath.Base(featureDir), ret.Outcome, ret.Message)
	return ret
}

func (s *featureScene) tasks(featureDir string) []*pm.Task {
	s.t.Helper()
	st, err := state.LoadLite(featureDir)
	if err != nil || st.Plan == nil {
		s.t.Fatalf("read the feature's plan: %v", err)
	}
	return st.Plan.Tasks
}

// exercise is the scenario both tests run once their executor is bound.
func (s *featureScene) exercise() {
	t := s.t
	fdir := s.newFeature("Widget", "Write the widget")
	branch := feature.BranchName("widget")
	s.snapshotParent()
	before := s.git(s.proj, "rev-parse", "refs/heads/"+branch)

	// 1. The harness's commit lands on the feature's branch.
	ret := s.runFeature(fdir)
	if ret.Outcome != "fast_forwarded" {
		t.Fatalf("the first run's work was not applied: %+v", ret)
	}
	tip := s.git(s.proj, "rev-parse", "refs/heads/"+branch)
	if tip == before || tip != ret.Commit {
		t.Fatalf("the feature's branch is at %s (was %s), the run returned %s", tip, before, ret.Commit)
	}
	if !strings.Contains(s.git(s.proj, "log", "--format=%s", before+".."+tip), "stub claude: work") {
		t.Errorf("the harness's own commit is not on %s:\n%s", branch, s.git(s.proj, "log", "--oneline", before+".."+tip))
	}
	files := s.git(fdir, "-c", "core.hooksPath=/dev/null", "ls-files")
	if !strings.Contains(files, "work-") {
		t.Errorf("the feature's worktree does not have the harness's file:\n%s", files)
	}
	// What the sandbox saw: a standalone repository, not a worktree pointer
	// into the hub's — and not the parent's .git mounted in.
	for _, name := range strings.Split(s.git(s.proj, "diff-tree", "--no-commit-id", "--name-only", "-r", tip), "\n") {
		if strings.HasPrefix(name, "evidence-") {
			ev := s.git(s.proj, "show", tip+":"+name)
			if !strings.Contains(ev, "git-dir: directory") || !strings.Contains(ev, "common-dir: .git") {
				t.Errorf("the sandbox's checkout was not a standalone repository:\n%s", ev)
			}
		}
	}
	for _, task := range s.tasks(fdir) {
		if task.Status != pm.TaskDone {
			t.Errorf("task %d %q is %s on the hub after the run, want done", task.ID, task.Title, task.Status)
		}
	}
	s.assertParentUntouched()

	// 1b. The pull request flow works from the written-back branch: the hub
	// pushes it from its own repository and opens the request.
	pidx := s.projectIdx(s.proj)
	code, body := s.call("POST", fmt.Sprintf("/api/projects/%d/features/widget/pr", pidx), map[string]any{"title": "Widget"})
	if code != http.StatusOK {
		t.Fatalf("open the feature's pull request = %d %v", code, body)
	}
	pr := s.forge.byHead(branch)
	if pr == nil || pr["base"].(map[string]any)["ref"] != "main" {
		t.Fatalf("the forge has no pull request from %s into main: %v", branch, s.forge.prs)
	}
	if got := s.git(s.origin, "rev-parse", "refs/heads/"+branch); got != tip {
		t.Errorf("the pushed branch is at %s, want the written-back %s", got, tip)
	}
	if m, err := feature.LoadMeta(fdir); err != nil || m.PR == nil || m.PR.HeadSHA != tip {
		t.Errorf("the feature does not record its pull request at %s: %+v, %v", tip, m, err)
	}
	if got := s.git(s.origin, "rev-parse", "refs/heads/main"); got != s.mainSHA {
		t.Errorf("publishing the feature moved the upstream's main to %s", got)
	}

	// 2. A dirty worktree on the hub: the work is kept, not applied, and the
	// local change survives.
	s.addTask(fdir, "Polish the widget")
	writeTestFile(t, filepath.Join(fdir, "local-notes.txt"), "uncommitted, on the hub\n")
	ret = s.runFeature(fdir)
	if ret.Outcome != "conflict" || ret.KeptOn == "" || !strings.Contains(ret.Message, "uncommitted") {
		t.Fatalf("a run returning to a dirty worktree = %+v, want a conflict", ret)
	}
	if got := s.git(s.proj, "rev-parse", "refs/heads/"+branch); got != tip {
		t.Errorf("the feature's branch moved to %s although its worktree was dirty", got)
	}
	if b := readTestFile(t, filepath.Join(fdir, "local-notes.txt")); string(b) != "uncommitted, on the hub\n" {
		t.Errorf("the hub-side change was lost: %q", b)
	}
	if got := s.git(s.proj, "rev-parse", "refs/heads/"+ret.KeptOn); got != ret.Commit {
		t.Errorf("the kept branch %s is at %s, want %s", ret.KeptOn, got, ret.Commit)
	}
	if !strings.Contains(s.git(s.proj, "log", "--format=%s", tip+".."+ret.KeptOn), "stub claude: work") {
		t.Errorf("the kept branch does not carry the run's commit")
	}
	if err := os.Remove(filepath.Join(fdir, "local-notes.txt")); err != nil {
		t.Fatal(err)
	}
	s.assertParentUntouched()

	// 3. A returned bundle over executors.feature_bundle_mb is refused, and
	// says so; nothing moves.
	s.addTask(fdir, "Produce BIG-OUTPUT")
	ret = s.runFeature(fdir)
	if ret.Outcome != "failed" || !strings.Contains(ret.Message, "over") || !strings.Contains(ret.Message, "limit") {
		t.Fatalf("an oversized write-back = %+v, want a refusal naming the limit", ret)
	}
	if !strings.Contains(ret.Message, "executors.feature_bundle_mb") {
		t.Errorf("the refusal does not say which setting the limit comes from: %s", ret.Message)
	}
	if got := s.git(s.proj, "rev-parse", "refs/heads/"+branch); got != tip {
		t.Errorf("an oversized write-back moved the feature's branch to %s", got)
	}
	s.assertParentUntouched()
}

// TestE2EFeatureRunsOnARemoteAgent: the feature runs on an executor agent
// connected over a loopback WebSocket, with the hub in strict mode.
func TestE2EFeatureRunsOnARemoteAgent(t *testing.T) {
	bin := binaryPath(t)
	s := newFeatureScene(t, bin, "executors:\n    allow_host_process: false\n    feature_bundle_mb: 1\n")

	// The device: the cloop under test and the stand-in claude on its PATH.
	devBin := filepath.Join(s.root, "device-bin")
	if err := os.MkdirAll(devBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bin, filepath.Join(devBin, "cloop")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(devBin, "claude"), stubClaude)
	if err := os.Chmod(filepath.Join(devBin, "claude"), 0o755); err != nil {
		t.Fatal(err)
	}

	s.start()
	server := strings.Replace(s.base, "http://", "ws://", 1) + "/api/executors/connect"
	bundle := filepath.Join(s.root, "enroll.bundle")
	s.cloop(s.hubDir, "executor", "enroll", "--name", "edge-e2e", "--server", server, "--bundle-file", bundle)

	agent := exec.Command(bin, "executor", "agent",
		"--token-file", bundle,
		"--credential", filepath.Join(s.root, "agent.json"),
		"--workdir-root", filepath.Join(s.root, "device"),
		"--max-concurrent", "2")
	agent.Env = append(withPath(s.env, devBin), "HOME="+filepath.Join(s.root, "device-home"))
	var agentLog strings.Builder
	s.background(agent, &agentLog)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("agent log:\n%s", tail(agentLog.String(), 8000))
		}
	})

	var executorID string
	s.waitFor("the agent to connect", 60*time.Second, func() bool {
		_, body := s.call("GET", "/api/executors", nil)
		raw, _ := body["executors"].([]any)
		for _, r := range raw {
			m, _ := r.(map[string]any)
			if m["name"] == "edge-e2e" && m["status"] == "online" {
				executorID = fmt.Sprint(m["id"])
				return true
			}
		}
		return false
	})
	s.bind(executorID)
	s.exercise()
}

// TestE2EFeatureRunsInAContainer: the feature runs in a container on the
// hub's host, through the container executor, with the hub in strict mode.
func TestE2EFeatureRunsInAContainer(t *testing.T) {
	if os.Getenv("CLOOP_FEATURE_CONTAINER_E2E") != "1" {
		t.Skip("set CLOOP_FEATURE_CONTAINER_E2E=1 to run the container feature circuit (needs docker)")
	}
	if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		t.Skipf("docker is not usable: %v %s", err, out)
	}
	image := buildFeatureImage(t)
	staged := stagedFeatureDirs(t)
	s := newFeatureScene(t, binaryPath(t), fmt.Sprintf("executors:\n    allow_host_process: false\n"+
		"    feature_bundle_mb: 1\n    container:\n        enabled: true\n        runtime: docker\n"+
		"        image: %s\n        network: none\n", image))
	if os.Getuid() == 0 {
		// The sandbox runs as the project's owner, and never as root.
		if err := chownTree(s.proj, 1000, 1000); err != nil {
			t.Fatal(err)
		}
	}
	s.start()
	_, body := s.call("GET", "/api/executors", nil)
	raw, _ := body["executors"].([]any)
	var executorID string
	for _, r := range raw {
		if m, _ := r.(map[string]any); m["kind"] == "container" {
			executorID = fmt.Sprint(m["id"])
		}
	}
	if executorID == "" {
		t.Fatalf("no container executor is registered: %v", body)
	}
	s.bind(executorID)
	s.exercise()
	// Each run's staged tree and output went once the hub had collected them.
	if now := stagedFeatureDirs(t); len(now) > len(staged) {
		t.Errorf("staged feature directories were left behind: %v", now)
	}
	if out, _ := exec.Command("docker", "ps", "-aq", "--filter", "label=cloop.managed=true",
		"--filter", "label=cloop.project="+filepath.Join(s.proj, ".cloop", "features", "widget")).Output(); strings.TrimSpace(string(out)) != "" {
		t.Errorf("feature containers were left behind: %s", out)
	}
}

// buildFeatureImage builds the sandbox image for the container test: git, a
// static build of the cloop under test, and the stand-in claude.
func buildFeatureImage(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := os.Getenv("CLOOP_FLAGSHIP_BIN")
	if bin == "" {
		_, thisFile, _, _ := runtime.Caller(0)
		repo := filepath.Join(filepath.Dir(thisFile), "..", "..")
		bin = filepath.Join(dir, "cloop-static")
		build := exec.Command("go", "build", "-o", bin, ".")
		build.Dir = repo
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build a static cloop: %v\n%s", err, out)
		}
	}
	data := readTestFile(t, bin)
	if err := os.WriteFile(filepath.Join(dir, "cloop"), data, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, "claude"), stubClaude)
	writeTestFile(t, filepath.Join(dir, "Dockerfile"), "FROM "+featureImageBase+"\n"+
		"RUN apk add --no-cache git\n"+
		"COPY cloop /usr/local/bin/cloop\n"+
		"COPY claude /usr/local/bin/claude\n"+
		"RUN chmod 0755 /usr/local/bin/cloop /usr/local/bin/claude\n")
	sum := sha256.Sum256(append(data, []byte(stubClaude)...))
	tag := "cloop-feature-e2e:" + hex.EncodeToString(sum[:6])
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "build", "-q", "-t", tag, dir).CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", tag).Run() })
	return tag
}

// featureImageBase is the sandbox image's base, pinned by digest like the
// flagship circuit's (tests/flagship) and the same one, so CI pulls it once.
const featureImageBase = "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

// stagedFeatureDirs lists the container driver's staging directories.
func stagedFeatureDirs(t *testing.T) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(os.TempDir(), "cloop-feature-*"))
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, p := range m {
		if info, err := os.Lstat(p); err == nil && info.IsDir() {
			dirs = append(dirs, p)
		}
	}
	return dirs
}

// withoutCloopEnv drops every variable cloop reads from env.
func withoutCloopEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if !strings.HasPrefix(kv, "CLOOP_") {
			out = append(out, kv)
		}
	}
	return out
}

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

func chownTree(root string, uid, gid int) error {
	return filepath.Walk(root, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(path, uid, gid)
	})
}

func hookDigest(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		h.Write([]byte(n))
		h.Write(readTestFile(t, filepath.Join(dir, n)))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
