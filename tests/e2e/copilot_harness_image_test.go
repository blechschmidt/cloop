package e2e_test

// A copilot project in the flagship isolation path (Task 20450): a strict hub,
// its container executor running the harness image's copilot variant, and a
// feature of a copilot project run in it — the real GitHub Copilot CLI from
// the image, driven by `cloop run`, against a model of the test's own (the
// CLI's bring-your-own-key mode with COPILOT_OFFLINE, so no GitHub account or
// Copilot seat is involved). The task goes through TASK_DONE, and its work
// comes back through the write-back: the file the agent wrote is committed on
// the feature's branch in the hub's repository.
//
// It runs the image CI builds — the job that builds the harness-copilot target
// names it in CLOOP_COPILOT_HARNESS_IMAGE — and skips without one:
//
//	docker build --target harness-copilot -t cloop-harness-copilot:dev .
//	go build -o cloop . && CLOOP_COPILOT_HARNESS_IMAGE=cloop-harness-copilot:dev \
//	  go test ./tests/e2e/ -run TestE2ECopilotFeatureRunsInTheHarnessImage -v

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// copilotWork is what the stub model has the agent do: write a file with the
// bash tool, in the sandbox's checkout, and show it.
const copilotWork = "printf 'written by copilot in the sandbox\\n' > copilot-hello.txt && cat copilot-hello.txt"

// copilotStub is an OpenAI-compatible chat-completions endpoint answering as
// an agent: the bash tool call above first, then a signed-off answer once the
// tool's result is in the conversation. It records who asked and what.
type copilotStub struct {
	url string

	mu       sync.Mutex
	requests []copilotStubRequest
}

type copilotStubRequest struct {
	from    string   // the client's address
	tools   []string // the tools it offered the model
	toolOut string   // the tool result it carried back, if any
}

func newCopilotStub(t *testing.T, host string) *copilotStub {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("cannot listen on the docker bridge's gateway %s: %v", host, err)
	}
	stub := &copilotStub{url: "http://" + ln.Addr().String() + "/v1"}
	srv := &http.Server{Handler: stub, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return stub
}

func (m *copilotStub) seen() []copilotStubRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]copilotStubRequest(nil), m.requests...)
}

func (m *copilotStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/chat/completions") {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content any    `json:"content"`
		} `json:"messages"`
		Tools []struct {
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		} `json:"tools"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	seen := copilotStubRequest{from: r.RemoteAddr}
	for _, tool := range req.Tools {
		seen.tools = append(seen.tools, tool.Function.Name)
	}
	for _, msg := range req.Messages {
		if msg.Role == "tool" {
			seen.toolOut = fmt.Sprint(msg.Content)
		}
	}
	m.mu.Lock()
	m.requests = append(m.requests, seen)
	m.mu.Unlock()

	w.Header().Set("Content-Type", "text/event-stream")
	event := func(v map[string]any) {
		v["id"], v["object"], v["created"], v["model"] = "stub-1", "chat.completion.chunk", time.Now().Unix(), req.Model
		b, _ := json.Marshal(v)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	if seen.toolOut == "" {
		args, _ := json.Marshal(map[string]string{"command": copilotWork, "description": "write the file", "mode": "sync"})
		event(map[string]any{"choices": []any{map[string]any{"index": 0,
			"delta": map[string]any{"role": "assistant", "content": "Writing the file."}}}})
		event(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]any{
			"tool_calls": []any{map[string]any{"index": 0, "id": "call_1", "type": "function",
				"function": map[string]any{"name": "bash", "arguments": string(args)}}}}}}})
		event(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]any{},
			"finish_reason": "tool_calls"}}, "usage": map[string]any{"prompt_tokens": 900, "completion_tokens": 30, "total_tokens": 930}})
	} else {
		event(map[string]any{"choices": []any{map[string]any{"index": 0,
			"delta": map[string]any{"role": "assistant", "content": "Wrote copilot-hello.txt.\nTASK_DONE"}}}})
		event(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]any{},
			"finish_reason": "stop"}}, "usage": map[string]any{"prompt_tokens": 1000, "completion_tokens": 12, "total_tokens": 1012}})
	}
	_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
}

// TestE2ECopilotFeatureRunsInTheHarnessImage is the proof.
func TestE2ECopilotFeatureRunsInTheHarnessImage(t *testing.T) {
	image := os.Getenv("CLOOP_COPILOT_HARNESS_IMAGE")
	if image == "" {
		t.Skip("set CLOOP_COPILOT_HARNESS_IMAGE to a harness-copilot image to run a copilot task in it (needs docker)")
	}
	if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		t.Skipf("docker is not usable: %v %s", err, out)
	}
	labels, err := exec.Command("docker", "image", "inspect", "--format",
		`{{index .Config.Labels "org.cloop.harnesses"}}`, image).Output()
	if err != nil {
		t.Fatalf("%s is not in docker's local store: %v", image, err)
	}
	if !strings.Contains(","+strings.TrimSpace(string(labels))+",", ",copilot,") {
		t.Fatalf("%s says it carries %q, which has no copilot", image, labels)
	}

	// The model, where a container on the default bridge reaches the host: the
	// bridge's gateway. Never every interface — this host may be reachable from
	// the Internet.
	out, err := exec.Command("docker", "network", "inspect", "bridge",
		"--format", "{{(index .IPAM.Config 0).Gateway}}").Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		t.Skipf("no default docker bridge to serve the model on: %v", err)
	}
	gateway := strings.TrimSpace(string(out))
	stub := newCopilotStub(t, gateway)

	grant := func(t *testing.T, run func(dir string, args ...string) string, hubDir, project string) {
		t.Helper()
		// A provider of the project's own (bring your own key), offline: the
		// credential the hub's preflight accepts for copilot besides a
		// COPILOT_GITHUB_TOKEN, and the one that needs no Copilot seat.
		payload, err := json.Marshal(map[string]string{
			"COPILOT_PROVIDER_BASE_URL": stub.url,
			"COPILOT_PROVIDER_API_KEY":  "e2e-stub-key",
			"COPILOT_OFFLINE":           "true",
		})
		if err != nil {
			t.Fatal(err)
		}
		run(hubDir, "secret", "mint", "e2e-copilot-credential", "--kind", "env", "--value", string(payload))
		run(hubDir, "secret", "grant", "e2e-copilot-credential", "--to", "project:"+project,
			"--env-keys", "COPILOT_PROVIDER_BASE_URL,COPILOT_PROVIDER_API_KEY,COPILOT_OFFLINE", "--ttl", "2h")
	}
	s := newFeatureSceneFor(t, binaryPath(t), fmt.Sprintf("executors:\n    allow_host_process: false\n"+
		"    container:\n        enabled: true\n        runtime: docker\n"+
		"        image: %s\n        network: bridge\n", image), "copilot", grant)
	// A provider of one's own needs the model named (the CLI refuses BYOK
	// without one). Committed, because a feature's worktree takes the
	// configuration the parent's branch carries.
	s.cloop(s.proj, "config", "set", "copilot.model", "e2e-stub-model")
	s.git(s.proj, "-c", "core.hooksPath=/dev/null", "commit", "-qam", "copilot model")
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

	fdir := s.newFeature("Greeting", "Write copilot-hello.txt")
	branch := feature.BranchName("greeting")
	s.snapshotParent()
	before := s.git(s.proj, "rev-parse", "refs/heads/"+branch)
	ret := s.runFeature(fdir)

	// 1. The task signed off: TASK_DONE, read by `cloop run` in the sandbox,
	// recorded on the hub through the project result.
	for _, task := range s.tasks(fdir) {
		if task.Status != pm.TaskDone {
			t.Errorf("task %d %q is %s on the hub after the run, want done", task.ID, task.Title, task.Status)
		}
	}
	// 2. The write-back: the file the agent wrote is committed on the
	// feature's branch in the hub's repository.
	if ret.Outcome != "fast_forwarded" {
		t.Fatalf("the run's work was not applied: %+v", ret)
	}
	tip := s.git(s.proj, "rev-parse", "refs/heads/"+branch)
	if tip == before || tip != ret.Commit {
		t.Fatalf("the feature's branch is at %s (was %s), the run returned %s", tip, before, ret.Commit)
	}
	if got := s.git(s.proj, "show", tip+":copilot-hello.txt"); got != "written by copilot in the sandbox" {
		t.Errorf("copilot-hello.txt on %s = %q", branch, got)
	}
	if files := s.git(fdir, "-c", "core.hooksPath=/dev/null", "ls-files"); !strings.Contains(files, "copilot-hello.txt") {
		t.Errorf("the feature's worktree does not have the agent's file:\n%s", files)
	}
	s.assertParentUntouched()

	// 3. It was the Copilot CLI, in the sandbox: the model was offered the
	// CLI's own tools, the bash tool's result came back to it — the file's
	// contents, so the command ran — and every request came from a container
	// on the bridge, not from the hub's host.
	reqs := stub.seen()
	if len(reqs) < 2 {
		t.Fatalf("the model was asked %d times, want the tool turn and the answer", len(reqs))
	}
	var offeredBash, sawResult bool
	for _, r := range reqs {
		for _, name := range r.tools {
			offeredBash = offeredBash || name == "bash"
		}
		sawResult = sawResult || strings.Contains(r.toolOut, "written by copilot in the sandbox")
		host, _, _ := net.SplitHostPort(r.from)
		if host == gateway || net.ParseIP(host).IsLoopback() {
			t.Errorf("a model request came from %s, the hub's own host, not a sandbox", r.from)
		}
	}
	if !offeredBash || !sawResult {
		t.Errorf("the model was not driven by the Copilot CLI's tool loop: %+v", reqs)
	}

	// Nothing of the run is left behind.
	if out, _ := exec.Command("docker", "ps", "-aq", "--filter", "label=cloop.managed=true",
		"--filter", "label=cloop.project="+filepath.Join(s.proj, ".cloop", "features", "greeting")).Output(); strings.TrimSpace(string(out)) != "" {
		t.Errorf("feature containers were left behind: %s", out)
	}
}

// TestE2ECopilotProjectIsRefusedByTheDefaultImage is the other half: the same
// copilot project on a container executor running the default harness image,
// whose label says it carries claude, cloop and git. The hub refuses the run
// before any container exists — 409, naming the image and the copilot variant
// that carries it — instead of starting a sandbox in which `copilot` is not
// found once the run has its credentials. It runs where CI built the default
// image too, named in CLOOP_HARNESS_IMAGE.
func TestE2ECopilotProjectIsRefusedByTheDefaultImage(t *testing.T) {
	image := os.Getenv("CLOOP_HARNESS_IMAGE")
	if image == "" {
		t.Skip("set CLOOP_HARNESS_IMAGE to a harness image without copilot to run this (needs docker)")
	}
	if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		t.Skipf("docker is not usable: %v %s", err, out)
	}
	labels, err := exec.Command("docker", "image", "inspect", "--format",
		`{{index .Config.Labels "org.cloop.harnesses"}}`, image).Output()
	if err != nil {
		t.Fatalf("%s is not in docker's local store: %v", image, err)
	}
	carries := strings.TrimSpace(string(labels))
	if carries == "" || strings.Contains(","+carries+",", ",copilot,") {
		t.Fatalf("%s says it carries %q; this test needs an image labelled without copilot", image, carries)
	}

	grant := func(t *testing.T, run func(dir string, args ...string) string, hubDir, project string) {
		t.Helper()
		payload, _ := json.Marshal(map[string]string{"COPILOT_PROVIDER_BASE_URL": "http://127.0.0.1:9/v1",
			"COPILOT_PROVIDER_API_KEY": "e2e-stub-key"})
		run(hubDir, "secret", "mint", "e2e-copilot-credential", "--kind", "env", "--value", string(payload))
		run(hubDir, "secret", "grant", "e2e-copilot-credential", "--to", "project:"+project,
			"--env-keys", "COPILOT_PROVIDER_BASE_URL,COPILOT_PROVIDER_API_KEY", "--ttl", "2h")
	}
	s := newFeatureSceneFor(t, binaryPath(t), fmt.Sprintf("executors:\n    allow_host_process: false\n"+
		"    container:\n        enabled: true\n        runtime: docker\n"+
		"        image: %s\n        network: none\n", image), "copilot", grant)
	if os.Getuid() == 0 {
		if err := chownTree(s.proj, 1000, 1000); err != nil {
			t.Fatal(err)
		}
	}
	s.start()
	_, body := s.call("GET", "/api/executors", nil)
	raw, _ := body["executors"].([]any)
	for _, r := range raw {
		if m, _ := r.(map[string]any); m["kind"] == "container" {
			s.bind(fmt.Sprint(m["id"]))
		}
	}
	fdir := s.newFeature("Greeting", "Write copilot-hello.txt")

	code, body := s.call("POST", fmt.Sprintf("/api/projects/%d/run", s.projectIdx(fdir)), map[string]any{})
	if code != http.StatusConflict || body["code"] != "sandbox_image_lacks_harness" {
		t.Fatalf("starting a copilot run in %s = %d %v, want 409 sandbox_image_lacks_harness", image, code, body)
	}
	msg, _ := body["error"].(string)
	remedy, _ := body["remediation"].(string)
	for _, want := range []string{image, "copilot", strings.ReplaceAll(carries, ",", ", ")} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal should mention %q: %s", want, msg)
		}
	}
	if !strings.Contains(remedy, "cloop-harness-copilot") {
		t.Errorf("the remedy should name the copilot variant: %s", remedy)
	}
	if out, _ := exec.Command("docker", "ps", "-aq", "--filter", "label=cloop.managed=true",
		"--filter", "label=cloop.project="+filepath.Join(s.proj, ".cloop", "features", "greeting")).Output(); strings.TrimSpace(string(out)) != "" {
		t.Errorf("a container was started for a run the hub refused: %s", out)
	}
	for _, task := range s.tasks(fdir) {
		if task.Status != pm.TaskPending {
			t.Errorf("task %d is %s after a refused start, want it still pending", task.ID, task.Status)
		}
	}
}
