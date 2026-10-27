package copilot

// These tests run the real GitHub Copilot CLI, against a model server of their
// own: the CLI's bring-your-own-provider mode (COPILOT_PROVIDER_BASE_URL) with
// COPILOT_OFFLINE set, so no GitHub account, network or Copilot seat is
// involved, while every flag, the prompt on stdin, the tool loop, the session
// store and the usage report are the CLI's own. They are what the flags in
// provider.go were checked with, and they skip where no CLI is installed: set
// CLOOP_COPILOT_CLI to its path, or put `copilot` on PATH.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/cloop/pkg/copilotauth"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// realCLI puts the installed Copilot CLI first on PATH and confines its state
// to the test, or skips.
func realCLI(t *testing.T) {
	t.Helper()
	path := os.Getenv("CLOOP_COPILOT_CLI")
	if path == "" {
		p, err := exec.LookPath(Binary)
		if err != nil {
			t.Skip("no GitHub Copilot CLI installed; set CLOOP_COPILOT_CLI to its path to run these tests")
		}
		path = p
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "GitHub Copilot CLI") {
		t.Skipf("%s is not the GitHub Copilot CLI (%v): %.200s", path, err, out)
	}
	link := filepath.Join(t.TempDir(), Binary)
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(link)+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("COPILOT_HOME", t.TempDir())
	for _, k := range []string{EnvGitHubToken, "GH_TOKEN", "GITHUB_TOKEN", "COPILOT_MODEL"} {
		t.Setenv(k, "")
	}
	resetFlags(t)
}

// modelServer is an OpenAI-compatible chat-completions endpoint that answers
// as an agent would: one shell command first, when it has one to give, then a
// signed-off answer. It records what each request offered and asked for.
type modelServer struct {
	command string // the shell command the first turn asks to run, if any
	status  int    // when set, every request is refused with it

	mu   sync.Mutex
	seen []modelRequest
}

type modelRequest struct {
	Model    string
	Effort   string
	Tools    []string
	Messages int
	ToolOut  string // the result of the command, once it has run
	Auth     string // the Authorization header: the key the CLI signed in with
}

func (m *modelServer) start(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	t.Setenv("COPILOT_OFFLINE", "true")
	t.Setenv(EnvProviderBaseURL, srv.URL+"/v1")
	t.Setenv("COPILOT_PROVIDER_API_KEY", "stub-key")
}

func (m *modelServer) requests() []modelRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.seen)
}

func (m *modelServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/chat/completions") {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Model           string `json:"model"`
		Stream          bool   `json:"stream"`
		ReasoningEffort string `json:"reasoning_effort"`
		Messages        []struct {
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
	seen := modelRequest{Model: req.Model, Effort: req.ReasoningEffort, Messages: len(req.Messages),
		Auth: r.Header.Get("Authorization")}
	for _, tool := range req.Tools {
		seen.Tools = append(seen.Tools, tool.Function.Name)
	}
	for _, msg := range req.Messages {
		if msg.Role == "tool" {
			seen.ToolOut = fmt.Sprint(msg.Content)
		}
	}
	m.mu.Lock()
	m.seen = append(m.seen, seen)
	m.mu.Unlock()

	if m.status != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(m.status)
		_, _ = fmt.Fprintf(w, `{"error":{"message":"refused by the stub","code":"%d"}}`, m.status)
		return
	}
	chunk := map[string]any{"id": "c1", "object": "chat.completion.chunk", "model": req.Model}
	var deltas []map[string]any
	finish := "stop"
	if m.command != "" && seen.ToolOut == "" && slices.Contains(seen.Tools, "bash") {
		args, _ := json.Marshal(map[string]any{"command": m.command, "description": "run the step", "mode": "sync"})
		deltas = append(deltas, map[string]any{"role": "assistant", "content": "Running the step."},
			map[string]any{"tool_calls": []map[string]any{{"index": 0, "id": "call_1", "type": "function",
				"function": map[string]any{"name": "bash", "arguments": string(args)}}}})
		finish = "tool_calls"
	} else {
		deltas = append(deltas, map[string]any{"role": "assistant", "content": "Did the step"},
			map[string]any{"content": ".\nTASK_DONE"})
	}
	usage := map[string]int{"prompt_tokens": 120, "completion_tokens": 7, "total_tokens": 127}
	if !req.Stream {
		var text strings.Builder
		for _, d := range deltas {
			if c, ok := d["content"].(string); ok {
				text.WriteString(c)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "c1", "object": "chat.completion", "model": req.Model,
			"choices": []any{map[string]any{"index": 0, "finish_reason": finish,
				"message": map[string]any{"role": "assistant", "content": text.String()}}},
			"usage": usage})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	send := func(v map[string]any) {
		data, _ := json.Marshal(v)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	for _, d := range deltas {
		c := maps(chunk)
		c["choices"] = []any{map[string]any{"index": 0, "delta": d}}
		send(c)
	}
	c := maps(chunk)
	c["choices"] = []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": finish}}
	c["usage"] = usage
	send(c)
	_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
}

func maps(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+2)
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestRealCLIRunsATaskInItsWorkDir(t *testing.T) {
	realCLI(t)
	stub := &modelServer{command: "echo proof > proof.txt && echo wrote-it"}
	stub.start(t)
	work := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	res, err := New().Complete(ctx, "Write the proof file.", provider.Options{
		WorkDir: work, Model: "stub-model", Effort: "high",
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !strings.HasSuffix(res.Output, "TASK_DONE") {
		t.Errorf("Output = %q; the agent's sign-off must be its last line", res.Output)
	}
	if data, err := os.ReadFile(filepath.Join(work, "proof.txt")); err != nil || strings.TrimSpace(string(data)) != "proof" {
		t.Errorf("the agent's command did not run in the work dir: %q, %v", data, err)
	}
	if uuid.Validate(res.SessionID) != nil {
		t.Errorf("SessionID = %q; the conversation must be resumable", res.SessionID)
	}
	if res.InputTokens == 0 || res.OutputTokens == 0 || res.Model != "stub-model" {
		t.Errorf("usage: %d in, %d out, model %q; the CLI's report must be read", res.InputTokens, res.OutputTokens, res.Model)
	}
	reqs := stub.requests()
	if len(reqs) < 2 {
		t.Fatalf("the model was asked %d times, want a tool turn and an answer", len(reqs))
	}
	first := reqs[0]
	if first.Model != "stub-model" || first.Effort != "high" {
		t.Errorf("the model was asked as %q at effort %q", first.Model, first.Effort)
	}
	for _, tool := range []string{"bash", "edit", "create", "view"} {
		if !slices.Contains(first.Tools, tool) {
			t.Errorf("a working call must offer %q; offered %v", tool, first.Tools)
		}
	}
	if !strings.Contains(reqs[len(reqs)-1].ToolOut, "wrote-it") {
		t.Errorf("the command's output did not reach the model: %q", reqs[len(reqs)-1].ToolOut)
	}

	// The same conversation, continued: the model sees what came before.
	more, err := New().Complete(ctx, "Carry on.", provider.Options{
		WorkDir: work, Model: "stub-model", ResumeSession: res.SessionID,
	})
	if err != nil {
		t.Fatalf("resumed Complete: %v", err)
	}
	if more.SessionID != res.SessionID {
		t.Errorf("the resumed call reports session %q, want %q", more.SessionID, res.SessionID)
	}
	all := stub.requests()
	if last := all[len(all)-1]; last.Messages <= first.Messages+2 {
		t.Errorf("the resumed turn carried %d messages, the first %d: the conversation was not continued",
			last.Messages, first.Messages)
	}
}

func TestRealCLIReadOnlyOffersReadingToolsOnly(t *testing.T) {
	realCLI(t)
	stub := &modelServer{}
	stub.start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := New().Complete(ctx, "Review.", provider.Options{
		WorkDir: t.TempDir(), Model: "stub-model", ReadOnly: true,
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	reqs := stub.requests()
	if len(reqs) == 0 {
		t.Fatal("the model was never asked")
	}
	got := slices.Sorted(slices.Values(reqs[0].Tools))
	if !slices.Equal(got, []string{"glob", "grep", "view"}) {
		t.Errorf("a read-only call offered %v, want only view, grep and glob", got)
	}
}

func TestRealCLIRefusedCredentialIsAnAuthFailure(t *testing.T) {
	realCLI(t)
	stub := &modelServer{status: http.StatusUnauthorized}
	stub.start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	_, err := New().Complete(ctx, "x", provider.Options{WorkDir: t.TempDir(), Model: "stub-model"})
	if !errors.Is(err, ErrAuthFailure) {
		t.Fatalf("err = %v, want ErrAuthFailure", err)
	}
}

func TestRealCLIWithNoCredentialIsAnAuthFailure(t *testing.T) {
	realCLI(t)
	t.Setenv("COPILOT_OFFLINE", "")
	t.Setenv(EnvProviderBaseURL, "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	_, err := New().Complete(ctx, "x", provider.Options{WorkDir: t.TempDir()})
	if !errors.Is(err, ErrAuthFailure) {
		t.Fatalf("err = %v, want ErrAuthFailure", err)
	}
}

// A run acting for a person on a hub with single sign-on (Task 20449), with the
// real CLI: it signs in with the provider the person's lease delivered — the
// stub's key — keeps its session and logs in their home rather than the one the
// hub's environment names, and its shell sees none of the hub's GitHub tokens,
// hosts or Copilot settings.
func TestRealCLIPinnedToAPersonRunsAsThemOnly(t *testing.T) {
	realCLI(t)
	stub := &modelServer{command: "env | sort"}
	stub.start(t)
	hubHome := os.Getenv("COPILOT_HOME") // the hub user's own, as realCLI set it
	person := t.TempDir()
	for k, v := range map[string]string{
		copilotauth.EnvHome: person,
		"GH_TOKEN":          "host-gh-token",
		"GITHUB_TOKEN":      "host-github-token",
		"GH_HOST":           "ghe.example.com",
		"COPILOT_API_URL":   "http://127.0.0.1:1/collector",
		"COPILOT_MODEL":     "host-model",
	} {
		t.Setenv(k, v)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	res, err := New().Complete(ctx, "Run the step.", provider.Options{WorkDir: t.TempDir(), Model: "stub-model"})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !strings.HasSuffix(res.Output, "TASK_DONE") {
		t.Errorf("Output = %q", res.Output)
	}
	reqs := stub.requests()
	if len(reqs) < 2 {
		t.Fatalf("the model was asked %d times, want a tool turn and an answer", len(reqs))
	}
	for _, r := range reqs {
		if r.Auth != "Bearer stub-key" {
			t.Errorf("the CLI signed in to the model with %q, want the person's own key", r.Auth)
		}
	}
	// Lines, not the whole dump, in a failure: the shell's environment is
	// this test process's, whatever that holds.
	shell := strings.Split(reqs[len(reqs)-1].ToolOut, "\n")
	if !slices.Contains(shell, "COPILOT_HOME="+person) {
		t.Errorf("the agent's shell does not run in the person's home %s", person)
	}
	for _, leak := range []string{"host-gh-token", "host-github-token", "ghe.example.com", "127.0.0.1:1", "host-model",
		hubHome} {
		for _, line := range shell {
			if strings.Contains(line, leak) {
				t.Errorf("the agent's shell sees %q: %s", leak, line)
			}
		}
	}
	entries, err := os.ReadDir(person)
	if err != nil || len(entries) == 0 {
		t.Errorf("the CLI kept nothing in the person's home (%v)", err)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".copilot")); !os.IsNotExist(err) {
		t.Errorf("the CLI wrote into the hub user's ~/.copilot (%v)", err)
	}
	if hub, _ := os.ReadDir(hubHome); len(hub) != 0 {
		var names []string
		for _, e := range hub {
			names = append(names, e.Name())
		}
		t.Errorf("the CLI wrote into the hub's own home: %v", names)
	}
}
