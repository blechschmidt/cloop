package ui

// The dashboard's model calls — the Split preview, dictation's Revise, the
// blocker analysis and the plan assistant — run on the project's executor, not
// in the hub (Task 20442). Driven through the real handlers, with a stand-in
// for the cloop binary the hub dispatches: it records how it was run and
// answers the subcommand it was asked for from a script, framed the way
// pkg/clijson frames it. What the real subcommands do with a model is tested in
// cmd (hub_model_calls_test.go), against the real chain.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/blocker"
	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/provider/claudecode"
	"github.com/blechschmidt/cloop/pkg/state"
)

// modelStub is the stand-in for the cloop binary. Each run writes its
// arguments, NUL-separated, to model-call.args in its working directory — the
// project's, on the host executor — and then answers `cloop <a> <b> …` from
// the scripted reply for "<a>-<b>": a shell fragment named <a>-<b>.sh is
// sourced, otherwise the file <a>-<b> is printed and <a>-<b>.exit, if there
// is one, is the exit status. No reply prints nothing.
type modelStub struct {
	exe     string
	replies string
}

func newModelStub(t *testing.T) *modelStub {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stub is a POSIX shell script")
	}
	dir := t.TempDir()
	replies := filepath.Join(dir, "replies")
	if err := os.Mkdir(replies, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "cloop-model-stub")
	script := "#!/bin/sh\n" +
		"printf '%s\\0' \"$@\" > model-call.args\n" +
		"r=" + shellQuote(replies) + "/\"$1-$2\"\n" +
		"if [ -f \"$r.sh\" ]; then . \"$r.sh\"; exit $?; fi\n" +
		"[ -f \"$r\" ] && cat \"$r\"\n" +
		"[ -f \"$r.exit\" ] && exit \"$(cat \"$r.exit\")\"\n" +
		"exit 0\n"
	if err := os.WriteFile(exe, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return &modelStub{exe: exe, replies: replies}
}

// answer scripts what `cloop <sub…>` prints and how it exits.
func (m *modelStub) answer(t *testing.T, sub, stdout string, exit int) {
	t.Helper()
	path := filepath.Join(m.replies, sub)
	if err := os.WriteFile(path, []byte(stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(path + ".exit")
	if exit != 0 {
		if err := os.WriteFile(path+".exit", []byte(fmt.Sprint(exit)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// script makes `cloop <sub…>` run sh, in the project directory.
func (m *modelStub) script(t *testing.T, sub, sh string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(m.replies, sub+".sh"), []byte(sh), 0o600); err != nil {
		t.Fatal(err)
	}
}

// framed is v as the subcommand prints it.
func framed(t *testing.T, v any) string {
	t.Helper()
	var b strings.Builder
	if err := clijson.Emit(&b, v); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// stubArgs is what the stand-in was last run with in dir, or nil if it never
// ran there.
func stubArgs(t *testing.T, dir string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "model-call.args"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// modelCallHub serves dir with stub as its cloop binary.
func modelCallHub(t *testing.T, dir string, stub *modelStub) *httptest.Server {
	t.Helper()
	srv := New(dir, 0, "")
	srv.SelfExe = stub.exe
	srv.RPS, srv.Burst = 1e6, 1e6
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func modelCallTasks() []*pm.Task {
	return []*pm.Task{
		{ID: 1, Title: "Migrate the database", Description: "Move every table to the new schema.",
			Status: pm.TaskPending, Priority: 1},
		{ID: 2, Title: "Ship it", Status: pm.TaskPending, Priority: 2, DependsOn: []int{1}},
	}
}

// ── the Split preview ───────────────────────────────────────────────────────

func TestSplitPreview_IsAskedOfTheProjectsExecutor(t *testing.T) {
	dir := setupProjectDir(t, "split on the executor", modelCallTasks())
	stub := newModelStub(t)
	stub.answer(t, "task-decompose", "warning: a diagnostic on the shared stream\n"+framed(t, map[string]any{
		"parent_id": 99, "parent_title": "what the executor thinks",
		"subtasks": []map[string]any{
			{"title": "Write the migration", "description": "One file per table.", "role": "backend", "estimated_minutes": 40},
			{"title": "  ", "description": "untitled: dropped"},
			{"title": "Verify the row counts", "role": "astronaut", "estimated_minutes": -5},
		},
	}), 0)
	ts := modelCallHub(t, dir, stub)

	code, body := rawJSON(t, ts, http.MethodPost, "/api/tasks/1/decompose", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("decompose = %d: %v", code, body)
	}
	want := []string{"task", "decompose", "1", "--dry-run", "--json", "--timeout", "4m0s"}
	if got := stubArgs(t, dir); !reflect.DeepEqual(got, want) {
		t.Errorf("the executor was asked for %q, want %q", got, want)
	}
	// The parent is the hub's task, whatever the executor named.
	if body["parent_id"] != float64(1) || body["parent_title"] != "Migrate the database" {
		t.Errorf("parent %v %v, want the hub's task 1", body["parent_id"], body["parent_title"])
	}
	subs, _ := body["subtasks"].([]any)
	if len(subs) != 2 {
		t.Fatalf("subtasks %v: the untitled one must be dropped and the rest kept", subs)
	}
	second, _ := subs[1].(map[string]any)
	if second["role"] != nil || second["estimated_minutes"] != nil {
		t.Errorf("an unknown role and a negative estimate reached the dialog: %v", second)
	}
}

func TestSplitPreview_AModelFailureIsABadGateway(t *testing.T) {
	dir := setupProjectDir(t, "split fails", modelCallTasks())
	stub := newModelStub(t)
	stub.answer(t, "task-decompose", framed(t, map[string]string{"error": "decompose: provider error: model is down"}), 1)
	ts := modelCallHub(t, dir, stub)

	code, body := rawJSON(t, ts, http.MethodPost, "/api/tasks/1/decompose", map[string]any{})
	if code != http.StatusBadGateway || !strings.Contains(fmt.Sprint(body["error"]), "model is down") {
		t.Fatalf("a failed model call = %d %v, want 502 with the provider's reason", code, body)
	}
	// An executor whose cloop printed no result at all is a bad gateway too,
	// not a hub fault.
	stub.answer(t, "task-decompose", "Error: unknown flag: --json\n", 1)
	code, body = rawJSON(t, ts, http.MethodPost, "/api/tasks/1/decompose", map[string]any{})
	if msg := fmt.Sprint(body["error"]); code != http.StatusBadGateway || !strings.Contains(msg, "unknown flag") ||
		!strings.Contains(msg, "older than this hub") {
		t.Fatalf("no result = %d %v, want 502 quoting what the command printed and naming the old cloop", code, body)
	}
}

// ── the blocker analysis ────────────────────────────────────────────────────

func blockerReport() map[string]any {
	return map[string]any{"task_id": 1, "task_title": "x", "root_cause": "a failed dependency",
		"actions": []string{"retry it", "split it", "ask"}, "recommendation": "reassign"}
}

func TestBlocker_GetOnlyDetects(t *testing.T) {
	dir := setupProjectDir(t, "blocker detection", modelCallTasks())
	stub := newModelStub(t)
	stub.answer(t, "task-ai-blocker", framed(t, blockerReport()), 0)
	ts := modelCallHub(t, dir, stub)

	code, body := rawJSON(t, ts, http.MethodGet, "/api/tasks/1/blocker", nil)
	if code != http.StatusOK || body["task_id"] != float64(1) || body["root_cause"] != nil {
		t.Fatalf("GET = %d %v, want the detection only", code, body)
	}
	code, body = rawJSON(t, ts, http.MethodGet, "/api/tasks/1/blocker?analyze=true&apply=true", nil)
	if code != http.StatusMethodNotAllowed || !strings.Contains(fmt.Sprint(body["error"]), "POST") {
		t.Fatalf("GET ?analyze=true = %d %v, want 405 naming POST", code, body)
	}
	if args := stubArgs(t, dir); args != nil {
		t.Fatalf("a GET dispatched %q", args)
	}
}

func TestBlocker_PostAnalysesOnTheExecutorAndApplies(t *testing.T) {
	dir := setupProjectDir(t, "blocker analysis", modelCallTasks())
	stub := newModelStub(t)
	stub.answer(t, "task-ai-blocker", framed(t, blockerReport()), 0)
	ts := modelCallHub(t, dir, stub)

	code, body := rawJSON(t, ts, http.MethodPost, "/api/tasks/2/blocker", map[string]any{"apply": true})
	if code != http.StatusOK {
		t.Fatalf("POST = %d %v", code, body)
	}
	want := []string{"task", "ai-blocker", "2", "--json", "--timeout", "3m0s"}
	if got := stubArgs(t, dir); !reflect.DeepEqual(got, want) {
		t.Errorf("the executor was asked for %q, want %q", got, want)
	}
	if body["task_id"] != float64(2) || body["task_title"] != "Ship it" || body["recommendation"] != "reassign" {
		t.Errorf("report %v: want the hub's task and the model's recommendation", body)
	}
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	var note string
	for _, a := range ps.Plan.TaskByID(2).Annotations {
		note += a.Text
	}
	if !strings.Contains(note, "Recommendation: REASSIGN. Root cause: a failed dependency") {
		t.Errorf("apply did not annotate the task: %q", note)
	}

	stub.answer(t, "task-ai-blocker", framed(t, map[string]string{"error": "blocker analysis failed: 401"}), 1)
	code, body = rawJSON(t, ts, http.MethodPost, "/api/tasks/2/blocker", nil)
	if code != http.StatusBadGateway || !strings.Contains(fmt.Sprint(body["error"]), "analysis error: blocker analysis failed: 401") {
		t.Fatalf("a failed analysis = %d %v, want 502", code, body)
	}
}

// TestBlocker_AViewerCannotStartTheAnalysis: the analysis used to hang off the
// GET a viewer may make, so anyone with read could have a model call made —
// on the hub's host. It is task.mutate now; detection stays a read.
func TestBlocker_AViewerCannotStartTheAnalysis(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	resolver, err := authz.New(authz.Config{Bindings: []authz.Binding{
		{Claim: authz.ClaimGroup, Value: "watchers", Role: authz.RoleViewer},
		{Claim: authz.ClaimGroup, Value: "engineers", Role: authz.RoleOperator},
	}})
	if err != nil {
		t.Fatal(err)
	}
	srv.Authz = resolver
	srv.RPS, srv.Burst = 1e6, 1e6
	stub := newModelStub(t)
	stub.answer(t, "task-ai-blocker", framed(t, blockerReport()), 0)
	srv.SelfExe = stub.exe
	ps, err := state.Load(srv.WorkDir)
	if err != nil {
		t.Fatal(err)
	}
	ps.Plan = &pm.Plan{Goal: ps.Goal, Tasks: modelCallTasks()}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}

	as := func(sub, email, group string) *http.Client {
		idp.sub, idp.email, idp.groups = sub, email, []string{group}
		c := jarClient(t)
		login(t, c, ts)
		return c
	}
	viewer := as("sub-wanda", "wanda@corp.example", "watchers")
	operator := as("sub-olive", "olive@corp.example", "engineers")
	call := func(c *http.Client, method string) int {
		t.Helper()
		var body *strings.Reader
		if method == http.MethodPost {
			body = strings.NewReader("{}")
		} else {
			body = strings.NewReader("")
		}
		req, err := http.NewRequest(method, ts.URL+"/api/tasks/1/blocker", body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := call(viewer, http.MethodGet); code != http.StatusOK {
		t.Errorf("a viewer's detection = %d, want 200", code)
	}
	if code := call(viewer, http.MethodPost); code != http.StatusForbidden {
		t.Errorf("a viewer's analysis = %d, want 403", code)
	}
	if args := stubArgs(t, srv.WorkDir); args != nil {
		t.Fatalf("a viewer's request made a model call: %q", args)
	}
	if code := call(operator, http.MethodPost); code != http.StatusOK {
		t.Errorf("an operator's analysis = %d, want 200", code)
	}
	if args := stubArgs(t, srv.WorkDir); len(args) < 2 || args[1] != "ai-blocker" {
		t.Errorf("the operator's analysis was not dispatched: %q", args)
	}
}

// ── the plan assistant ──────────────────────────────────────────────────────

type chatEvent struct{ name, data string }

// planChat posts to the plan assistant and reads its answer: the status, the
// content type, and the events, passing each to seen as it arrives.
func planChat(t *testing.T, ts *httptest.Server, body any, seen func(chatEvent)) (int, string, []chatEvent) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/chat/plan", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/chat/plan: %v", err)
	}
	defer resp.Body.Close()
	var events []chatEvent
	r := bufio.NewReader(resp.Body)
	var cur chatEvent
	for {
		line, err := r.ReadString('\n')
		line = strings.TrimRight(line, "\n")
		switch {
		case strings.HasPrefix(line, "event: "):
			cur.name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			cur.data = strings.TrimPrefix(line, "data: ")
			events = append(events, cur)
			if seen != nil {
				seen(cur)
			}
			cur = chatEvent{}
		}
		if err != nil {
			break
		}
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), events
}

func tokens(t *testing.T, events []chatEvent) (toks []string, last string) {
	t.Helper()
	for _, e := range events {
		last = e.name
		if e.name != "token" {
			continue
		}
		var d struct{ Token string }
		if err := json.Unmarshal([]byte(e.data), &d); err != nil {
			t.Fatalf("token event %q: %v", e.data, err)
		}
		toks = append(toks, d.Token)
	}
	return toks, last
}

// TestPlanChat_RelaysTheAnswerAsTheExecutorDeliversIt: a token is on the
// dashboard while the model is still answering. The stand-in holds its second
// token until the test has read the first, so a hub that waited for the end
// would never get there.
func TestPlanChat_RelaysTheAnswerAsTheExecutorDeliversIt(t *testing.T) {
	dir := setupProjectDir(t, "plan chat", modelCallTasks())
	stub := newModelStub(t)
	stub.script(t, "plan-chat", "echo 'warning: noise on the stream'\n"+
		"printf '%s\\n' '"+clijson.ChunkMarker+`{"token":"Task 1 "}'`+"\n"+
		"i=0; while [ ! -e release ] && [ $i -lt 1500 ]; do sleep 0.02; i=$((i+1)); done\n"+
		"printf 'half a line, then '; printf '%s\\n' '"+clijson.ChunkMarker+`{"token":"comes first."}'`+"\n"+
		"cat <<'EOF'\n"+framed(t, map[string]string{"answer": "Task 1 comes first."})+"EOF\n")
	ts := modelCallHub(t, dir, stub)

	var once sync.Once
	code, ctype, events := planChat(t, ts, map[string]any{
		"message": "What is next?",
		"history": []map[string]string{{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}},
	}, func(e chatEvent) {
		if e.name == "token" {
			once.Do(func() { _ = os.WriteFile(filepath.Join(dir, "release"), nil, 0o600) })
		}
	})
	if code != http.StatusOK || !strings.HasPrefix(ctype, "text/event-stream") {
		t.Fatalf("plan chat = %d %s", code, ctype)
	}
	toks, last := tokens(t, events)
	if !reflect.DeepEqual(toks, []string{"Task 1 ", "comes first."}) || last != "done" {
		t.Fatalf("events %v: want the two streamed tokens, nothing twice, then done", events)
	}
	args := stubArgs(t, dir)
	want := []string{"plan", "chat", "--message=What is next?",
		`--history=[{"role":"user","content":"hi"},{"role":"assistant","content":"hello"}]`,
		"--timeout", "2m0s", "--json"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("the executor was asked for %q, want %q", args, want)
	}
}

func TestPlanChat_AnAnswerThatWasNotStreamedArrivesWhole(t *testing.T) {
	dir := setupProjectDir(t, "plan chat whole", modelCallTasks())
	stub := newModelStub(t)
	stub.answer(t, "plan-chat", framed(t, map[string]string{"answer": "All at once."}), 0)
	ts := modelCallHub(t, dir, stub)

	_, _, events := planChat(t, ts, map[string]any{"message": "Summarise"}, nil)
	if toks, last := tokens(t, events); !reflect.DeepEqual(toks, []string{"All at once."}) || last != "done" {
		t.Fatalf("events %v, want the whole answer as one token, then done", events)
	}
}

func TestPlanChat_AModelFailureIsAnErrorEvent(t *testing.T) {
	dir := setupProjectDir(t, "plan chat fails", modelCallTasks())
	stub := newModelStub(t)
	stub.answer(t, "plan-chat", framed(t, map[string]string{"error": "claude CLI error: 401"}), 1)
	ts := modelCallHub(t, dir, stub)

	_, _, events := planChat(t, ts, map[string]any{"message": "Summarise"}, nil)
	if len(events) != 1 || events[0].name != "error" || !strings.Contains(events[0].data, "claude CLI error: 401") {
		t.Fatalf("events %v, want one error event with the provider's reason", events)
	}
}

func TestPlanChat_BoundsWhatTravelsAsArguments(t *testing.T) {
	dir := setupProjectDir(t, "plan chat bounds", modelCallTasks())
	stub := newModelStub(t)
	stub.answer(t, "plan-chat", framed(t, map[string]string{"answer": "ok"}), 0)
	ts := modelCallHub(t, dir, stub)

	code, body := rawJSON(t, ts, http.MethodPost, "/api/chat/plan",
		map[string]any{"message": strings.Repeat("x", maxPlanChatMessageBytes+1)})
	if code != http.StatusBadRequest {
		t.Fatalf("an oversized question = %d %v, want 400", code, body)
	}
	long := strings.Repeat("y", planChatHistoryBytes/2)
	planChat(t, ts, map[string]any{"message": "ok?", "history": []map[string]string{
		{"role": "user", "content": "oldest " + long}, {"role": "assistant", "content": "older " + long},
		{"role": "user", "content": "latest"},
	}}, nil)
	var history string
	for _, a := range stubArgs(t, dir) {
		if h, ok := strings.CutPrefix(a, "--history="); ok {
			history = h
		}
	}
	if strings.Contains(history, "oldest") || !strings.Contains(history, "older") || !strings.Contains(history, "latest") {
		t.Errorf("history sent: %.80q…, want the latest turns that fit and not the oldest", history)
	}
}

// ── where the model calls run ───────────────────────────────────────────────

// sandboxStub is an executor that isolates from the hub, records each
// workload, and answers it as a sandbox running cloop would, from answer.
type sandboxStub struct {
	*harnessExec
	answer func(argv []string) string

	mu      sync.Mutex
	byID    map[string]executor.Spec
	started []executor.Spec
}

func newSandboxStub(id string, answer func([]string) string) *sandboxStub {
	return &sandboxStub{harnessExec: newHarnessExec(id, executor.KindContainer, executor.IsolationContainer),
		answer: answer, byID: map[string]executor.Spec{}}
}

func (e *sandboxStub) Start(_ context.Context, spec executor.Spec) (executor.Handle, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.started = append(e.started, spec)
	id := fmt.Sprintf("%s-%d", e.id, len(e.started))
	e.byID[id] = spec
	return executor.Handle{ID: id, ExecutorID: e.id, StartedAt: time.Now()}, nil
}

func (e *sandboxStub) Stream(_ context.Context, id string) (<-chan executor.LogLine, error) {
	e.mu.Lock()
	spec, ok := e.byID[id]
	e.mu.Unlock()
	if !ok {
		return nil, executor.ErrHandleNotFound
	}
	ch := make(chan executor.LogLine, 1)
	ch <- executor.LogLine{Text: e.answer(spec.Argv)}
	close(ch)
	return ch, nil
}

func (e *sandboxStub) argvs() [][]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out [][]string
	for _, s := range e.started {
		out = append(out, s.Argv)
	}
	return out
}

// hostClaude puts a `claude` first on PATH that records where it ran and for
// whom, and returns the file it records into.
func hostClaude(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "claude-ran.log")
	script := "#!/bin/sh\necho \"$PWD|${CLAUDE_CONFIG_DIR-}|${CLAUDE_CODE_OAUTH_TOKEN-<unset>}|$*\" >> " +
		shellQuote(log) + "\ncat >/dev/null\necho 'an answer from the hub host'\n"
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// registerClaudeCode registers claudecode as cmd/providers.go does in the
// binary, for the length of the test: pkg/ui's tests register no real
// provider, so a provider built in the hub would otherwise fail to build
// rather than run. Afterwards the name builds nothing again.
func registerClaudeCode(t *testing.T) {
	t.Helper()
	provider.Register(claudecode.ProviderName, func(provider.ProviderConfig) (provider.Provider, error) {
		return claudecode.New(), nil
	})
	t.Cleanup(func() {
		provider.Register(claudecode.ProviderName, func(provider.ProviderConfig) (provider.Provider, error) {
			return nil, fmt.Errorf("provider %q is not registered in this test binary", claudecode.ProviderName)
		})
	})
}

// modelCallRequests are the four, with what each dispatches.
var modelCallRequests = []struct {
	name, method, path string
	body               any
	sub                string // "<a>-<b>" of the subcommand
}{
	{"split preview", http.MethodPost, "/api/tasks/1/decompose", map[string]any{}, "task-decompose"},
	{"revise", http.MethodPost, "/api/tasks/1/revise",
		map[string]any{"instruction": "and mention the indexes", "description": "Move every table."}, "task-revise"},
	{"blocker analysis", http.MethodPost, "/api/tasks/1/blocker", map[string]any{}, "task-ai-blocker"},
	{"plan chat", http.MethodPost, "/api/chat/plan", map[string]any{"message": "What next?"}, "plan-chat"},
}

// sandboxAnswer is what a sandbox running cloop answers each of the four.
func sandboxAnswer(t *testing.T) func([]string) string {
	answers := map[string]string{
		"task-decompose":  framed(t, map[string]any{"subtasks": []map[string]any{{"title": "a"}, {"title": "b"}}}),
		"task-revise":     framed(t, map[string]any{"description": "Move every table, and the indexes."}),
		"task-ai-blocker": framed(t, blockerReport()),
		"plan-chat":       framed(t, map[string]any{"answer": "Task 1."}),
	}
	return func(argv []string) string {
		if len(argv) < 3 {
			return ""
		}
		return answers[argv[1]+"-"+argv[2]]
	}
}

// TestModelCallsNeverRunOnTheHubUnderStrictMode is the headline of Task 20442.
// Task 20441 proved it for Split: with host execution off, claudecode
// registered and a stand-in `claude` first on PATH, the preview answered 200
// and the stand-in had run in the project directory with the hub's
// environment. Now none of the four runs anything on the hub: with nowhere
// isolating to go each is refused, naming the setting, and bound to a sandbox
// each is dispatched there.
func TestModelCallsNeverRunOnTheHubUnderStrictMode(t *testing.T) {
	// The hub's own project, so the grants below are in the control plane
	// the hub reads.
	f := newHarnessFixture(t)
	claudeLog := hostClaude(t)
	registerClaudeCode(t)
	dir := f.dir
	if ps, err := state.Init(dir, "strict model calls", 0); err != nil {
		t.Fatal(err)
	} else {
		ps.Plan = &pm.Plan{Goal: ps.Goal, Tasks: modelCallTasks()}
		if err := ps.Save(); err != nil {
			t.Fatal(err)
		}
	}
	setProvider(t, dir, claudecode.ProviderName)
	stub := newModelStub(t)
	ts := modelCallHub(t, dir, stub)
	enterStrictMode(t)

	ranOnTheHub := func(t *testing.T) {
		t.Helper()
		if raw, err := os.ReadFile(claudeLog); err == nil {
			t.Fatalf("claude ran on the hub's host: %s", raw)
		}
		if args := stubArgs(t, dir); args != nil {
			t.Fatalf("cloop ran on the hub's host: %q", args)
		}
	}

	if len(executor.IsolatedIDs()) == 0 {
		for _, c := range modelCallRequests {
			code, body := rawJSON(t, ts, c.method, c.path, c.body)
			if code != http.StatusConflict || !strings.Contains(fmt.Sprint(body["error"]), "allow_host_process") {
				t.Errorf("%s with nowhere isolating to run = %d %v, want 409 naming allow_host_process", c.name, code, body)
			}
		}
		ranOnTheHub(t)
	}

	box := newSandboxStub("model-call-box", sandboxAnswer(t))
	registerStub(t, box)
	if err := executor.Bind(dir, box.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	// A sandbox with no Claude login is refused before anything starts, with
	// the code the dashboard opens the credential dialog on.
	for _, c := range modelCallRequests {
		code, body := rawJSON(t, ts, c.method, c.path, c.body)
		if code != http.StatusConflict || body["code"] != codeHarnessCredentialMissing {
			t.Errorf("%s on a sandbox with no Claude login = %d %v, want 409 %s", c.name, code, body, codeHarnessCredentialMissing)
		}
	}
	if n := len(box.argvs()); n != 0 {
		t.Fatalf("refused calls started %d workload(s)", n)
	}

	f.grant(t, f.env(t, "team-claude", map[string]string{envClaudeOAuthToken: fakeAnthropicToken("oat01", "teamtok")}, ""),
		"project:"+dir, time.Hour)
	for _, c := range modelCallRequests {
		code, body := rawJSON(t, ts, c.method, c.path, c.body)
		if code != http.StatusOK {
			t.Errorf("%s on a granted sandbox = %d %v, want 200", c.name, code, body)
		}
	}
	var subs []string
	for _, argv := range box.argvs() {
		subs = append(subs, argv[1]+"-"+argv[2])
	}
	want := []string{"task-decompose", "task-revise", "task-ai-blocker", "plan-chat"}
	if !reflect.DeepEqual(subs, want) {
		t.Errorf("the sandbox was asked for %v, want %v", subs, want)
	}
	ranOnTheHub(t)
}

// TestInlineReplaysStayOffTheHubForAProjectInASandbox: the provider-call and
// task replays still call a provider inside the hub, to compare its answers,
// so they are refused for a project whose runs are kept off the hub's host —
// on a hub that allows host execution too, where strict mode does not refuse
// them.
func TestInlineReplaysStayOffTheHubForAProjectInASandbox(t *testing.T) {
	claudeLog := hostClaude(t)
	registerClaudeCode(t)
	restoreHostPolicy(t)
	dir := statedbtest.Dir(t)
	if ps, err := state.Init(dir, "inline replays", 0); err != nil {
		t.Fatal(err)
	} else {
		ps.Plan = &pm.Plan{Goal: ps.Goal, Tasks: modelCallTasks()}
		if err := ps.Save(); err != nil {
			t.Fatal(err)
		}
	}
	ts := modelCallHub(t, dir, newModelStub(t))
	box := newSandboxStub("inline-replay-box", sandboxAnswer(t))
	registerStub(t, box)
	if err := executor.Bind(dir, box.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	for path, body := range map[string]any{
		"/api/provider-calls/1/replay": map[string]any{"prompt": "hello"},
		"/api/replay-runs":             map[string]any{"task_id": 1, "provider": claudecode.ProviderName},
	} {
		code, out := rawJSON(t, ts, http.MethodPost, path, body)
		if code != http.StatusConflict || out["code"] != "inline_call_isolated" {
			t.Errorf("POST %s for a project in a sandbox = %d %v, want 409 inline_call_isolated", path, code, out)
		}
	}
	if raw, err := os.ReadFile(claudeLog); err == nil {
		t.Fatalf("claude ran on the hub's host: %s", raw)
	}
}

// TestWhatAnExecutorSendsBackIsBounded: an analysis or a proposal comes from
// whatever cloop the executor runs — an old one, a device's — so the hub keeps
// only what it would have accepted from its own: one of the three
// recommendations, a few actions, and text of a task's size.
func TestWhatAnExecutorSendsBackIsBounded(t *testing.T) {
	long := strings.Repeat("é", maxBlockerTextRunes+10)
	r := blocker.BlockerReport{RootCause: "  " + long, Recommendation: "Format the disk",
		Actions: []string{"a", " ", "b", "c", "d", "e", "f"}}
	if !checkBlockerReport(&r) {
		t.Fatal("a report with a cause and actions was refused")
	}
	if r.Recommendation != "retry" || len([]rune(r.RootCause)) != maxBlockerTextRunes ||
		!reflect.DeepEqual(r.Actions, []string{"a", "b", "c", "d", "e"}) {
		t.Errorf("kept %q, %d runes of cause, actions %q", r.Recommendation, len([]rune(r.RootCause)), r.Actions)
	}
	if empty := (blocker.BlockerReport{RootCause: " ", Actions: []string{""}}); checkBlockerReport(&empty) {
		t.Error("a report with nothing in it was accepted")
	}

	subs := cleanDecomposeProposal([]decomposeSubtaskWire{
		{Title: strings.Repeat("t", maxProposedTitleRunes+1), Description: strings.Repeat("d", pm.MaxReviseDescriptionRunes+1)},
	})
	if len(subs) != 1 || len(subs[0].Title) != maxProposedTitleRunes || len(subs[0].Description) != pm.MaxReviseDescriptionRunes {
		t.Errorf("an oversized proposal reached the dialog: %d-rune title, %d-rune description",
			len(subs[0].Title), len(subs[0].Description))
	}
	var many []decomposeSubtaskWire
	for i := 0; i < decomposeMaxSubtasks+5; i++ {
		many = append(many, decomposeSubtaskWire{Title: fmt.Sprint("step ", i)})
	}
	if n := len(cleanDecomposeProposal(many)); n != decomposeMaxSubtasks {
		t.Errorf("%d sub-tasks reached the dialog, want at most %d", n, decomposeMaxSubtasks)
	}
}

// TestModelCallsGoToTheMemberHoldingTheDevice: in a hub cluster an edge
// agent's connection is held by one member, and only that member can send it
// work. The four model calls are dispatched like a run, so a request that lands
// on another member is forwarded there — the plan assistant's stream too.
func TestModelCallsGoToTheMemberHoldingTheDevice(t *testing.T) {
	dir, a, b := clusterPair(t)
	if ps, err := state.Load(dir); err != nil {
		t.Fatal(err)
	} else {
		ps.Plan = &pm.Plan{Goal: ps.Goal, Tasks: modelCallTasks()}
		if err := ps.Save(); err != nil {
			t.Fatal(err)
		}
	}
	dev := remoteExec("model-call-device-"+strings.ReplaceAll(filepath.Base(dir), ".", "-"), executor.KindRemoteAgent)
	registerStub(t, dev)
	if err := executor.Bind(dir, dev.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })
	// The device's socket is held by A.
	if err := a.node.Assert(ownerAgent, dev.ID(), nil); err != nil {
		t.Fatal(err)
	}

	for _, c := range modelCallRequests {
		raw, err := json.Marshal(c.body)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(c.method, b.ts.URL+c.path, strings.NewReader(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s on B: %v", c.name, err)
		}
		resp.Body.Close()
		if got := resp.Header.Get(hubcluster.HeaderServedBy); got != a.node.ID() {
			t.Errorf("%s sent to B was served by %q (HTTP %d), want A, which holds the device", c.name, got, resp.StatusCode)
		}
	}
}
