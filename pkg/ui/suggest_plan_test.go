package ui

// Planning a request from the suggestions panel (Task 20342), driven through
// the real handlers with a stub standing in for `cloop suggest --json`. The
// stub records the arguments it was given, so these tests pin what the hub
// asks the executor for as well as what it does with the answer.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// loginPlan is what the stub's model "answers": four tasks, one with a
// forward reference the hub must drop (2 → 3).
const loginPlan = `{"summary":"OAuth login in four steps","suggestions":[` +
	`{"id":1,"title":"Add provider config","description":"d1","category":"feature","effort":"l","depends_on":[]},` +
	`{"id":2,"title":"Callback handler","description":"d2","category":"security","effort":"xs","depends_on":[1,3]},` +
	`{"id":3,"title":"Login button","description":"d3","category":"ux","effort":"s","depends_on":[1]},` +
	`{"id":4,"title":"Document login","description":"d4","category":"docs","effort":"m","depends_on":[2,3]}]}`

// writePlanStub writes the stand-in for `cloop suggest --json`. It records its
// arguments NUL-separated in its working directory's suggest.args — so a
// request containing a newline is still seen as the one argument it was —
// waits while a file named hold exists there, and then prints body framed
// the way pkg/clijson frames it. The summary is prefixed with the directory's
// name, so a test can tell which project an answer was generated for.
func writePlanStub(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub uses a POSIX shell")
	}
	path := filepath.Join(t.TempDir(), "cloop-suggest-stub")
	script := "#!/bin/sh\n" +
		"printf '%s\\0' \"$@\" > suggest.args\n" +
		"while [ -e hold ]; do sleep 0.02; done\n" +
		"echo '<<<cloop-json:begin>>>'\n" +
		"sed \"s|\\\"summary\\\":\\\"|\\\"summary\\\":\\\"$(basename \"$PWD\"): |\" <<'CLOOP_STUB_STDOUT'\n" + body + "\nCLOOP_STUB_STDOUT\n" +
		"echo '<<<cloop-json:end>>>'\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("writing stub: %v", err)
	}
	return path
}

// newPlanServer serves dir (index 0) and extra (1, 2, ...) with the stub as
// its cloop binary.
func newPlanServer(t *testing.T, stub, dir string, extra ...string) *httptest.Server {
	t.Helper()
	srv := New(dir, 0, "")
	srv.Projects = extra
	srv.SelfExe = stub
	// These tests poll the job's status; under -race a job takes long enough
	// for that to exhaust the default per-IP budget, which is not under test.
	srv.RPS, srv.Burst = 1e6, 1e6
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// generate starts a job and waits for it to finish, returning its status.
func generate(t *testing.T, ts *httptest.Server, query string, body map[string]interface{}) map[string]interface{} {
	t.Helper()
	code, resp := rawJSON(t, ts, http.MethodPost, "/api/suggest/generate"+query, body)
	if code != http.StatusOK {
		t.Fatalf("generate %v returned HTTP %d: %v", body, code, resp)
	}
	return waitSuggest(t, ts, query)
}

func waitSuggest(t *testing.T, ts *httptest.Server, query string) map[string]interface{} {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		st := apiGET(t, ts, "/api/suggest/status"+query)
		if done, _ := st["done"].(bool); done {
			if msg, _ := st["error"].(string); msg != "" {
				t.Fatalf("suggest job failed: %s", msg)
			}
			return st
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("suggest job did not finish within 30s")
	return nil
}

// recordedArgs is what the stub was run with in dir, minus the program name.
func recordedArgs(t *testing.T, dir string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "suggest.args"))
	if err != nil {
		t.Fatalf("the stub recorded no arguments: %v", err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
}

func stepDeps(st map[string]interface{}) map[string][]int {
	out := map[string][]int{}
	list, _ := st["suggestions"].([]interface{})
	for _, it := range list {
		m, _ := it.(map[string]interface{})
		title, _ := m["title"].(string)
		var deps []int
		if raw, ok := m["depends_on"].([]interface{}); ok {
			for _, d := range raw {
				deps = append(deps, int(d.(float64)))
			}
		}
		out[title] = deps
	}
	return out
}

func genOf(t *testing.T, st map[string]interface{}) int {
	t.Helper()
	g, _ := st["gen"].(float64)
	if g <= 0 {
		t.Fatalf("status carries no generation: %v", st)
	}
	return int(g)
}

// The request travels as a single argument joined to its flag, and the count
// is only sent when there is one — an absent --count is how a plan is left to
// size itself.
func TestSuggestPlan_WhatTheHubAsksTheCommandFor(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newPlanServer(t, writePlanStub(t, loginPlan), dir)

	cases := []struct {
		name string
		body map[string]interface{}
		want []string
	}{
		{"a plan of unset length sends no count",
			map[string]interface{}{"input": "  --yes\nplan the login flow  "},
			[]string{"suggest", "--json", "--input=--yes\nplan the login flow"}},
		{"a plan of set length",
			map[string]interface{}{"input": "plan it", "count": 3},
			[]string{"suggest", "--json", "--input=plan it", "--count", "3"}},
		{"a plan is capped at twenty tasks",
			map[string]interface{}{"input": "plan it", "count": 99},
			[]string{"suggest", "--json", "--input=plan it", "--count", "20"}},
		{"a brainstorm defaults to five ideas",
			map[string]interface{}{},
			[]string{"suggest", "--json", "--count", "5"}},
		{"a blank input is a brainstorm",
			map[string]interface{}{"input": " \n ", "count": 2},
			[]string{"suggest", "--json", "--count", "2"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			generate(t, ts, "", c.body)
			if got := recordedArgs(t, dir); !reflect.DeepEqual(got, c.want) {
				t.Errorf("the command ran with %q, want %q", got, c.want)
			}
		})
	}
}

// What the panel is sent: the plan, re-checked by the hub rather than
// trusted, and marked as a plan by the request it answers.
func TestSuggestPlan_StatusCarriesTheCheckedPlan(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newPlanServer(t, writePlanStub(t, loginPlan), dir)

	st := generate(t, ts, "", map[string]interface{}{"input": "Add OAuth login"})
	if st["request"] != "Add OAuth login" {
		t.Errorf("request = %v; it is what tells the panel these are a plan's tasks", st["request"])
	}
	genOf(t, st)
	want := map[string][]int{
		"Add provider config": nil,
		"Callback handler":    {1}, // the forward reference to 3 is dropped
		"Login button":        {1},
		"Document login":      {2, 3},
	}
	if got := stepDeps(st); !reflect.DeepEqual(got, want) {
		t.Errorf("plan = %v, want %v", got, want)
	}

	// A device's cloop may not honour --count; the hub holds the plan to it.
	st = generate(t, ts, "", map[string]interface{}{"input": "Add OAuth login", "count": 2})
	if n := len(stepDeps(st)); n != 2 {
		t.Errorf("asked for 2 tasks and the panel was sent %d", n)
	}

	// And a brainstorm is not a plan, whatever the answer claimed.
	st = generate(t, ts, "", map[string]interface{}{"count": 5})
	if st["request"] != "" {
		t.Errorf("a brainstorm's status names a request: %v", st["request"])
	}
	for title, deps := range stepDeps(st) {
		if len(deps) != 0 {
			t.Errorf("brainstormed idea %q carries dependencies %v", title, deps)
		}
	}
}

func loadTasks(t *testing.T, dir string) map[string]*pm.Task {
	t.Helper()
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	out := map[string]*pm.Task{}
	if ps.Plan == nil {
		return out
	}
	for _, tk := range ps.Plan.Tasks {
		out[tk.Title] = tk
	}
	return out
}

// "Add all": the plan lands at the end of the queue, in order, with its
// dependencies translated to task IDs.
func TestSuggestPlan_AddAllQueuesThePlanInOrder(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, []*pm.Task{
		{ID: 1, Title: "already done", Status: pm.TaskDone, Priority: 1},
		{ID: 2, Title: "already queued", Status: pm.TaskPending, Priority: 2},
	})
	ts := newPlanServer(t, writePlanStub(t, loginPlan), dir)
	gen := genOf(t, generate(t, ts, "", map[string]interface{}{"input": "Add OAuth login"}))

	code, resp := rawJSON(t, ts, http.MethodPost, "/api/suggest/add",
		map[string]interface{}{"gen": gen, "ids": []int{4, 3, 2, 1}})
	if code != http.StatusOK {
		t.Fatalf("add all returned HTTP %d: %v", code, resp)
	}
	if added, _ := resp["added"].([]interface{}); len(added) != 4 {
		t.Fatalf("added %v, want 4 tasks", resp["added"])
	}

	tasks := loadTasks(t, dir)
	wantDeps := map[string][]int{
		"Add provider config": nil,
		"Callback handler":    {3},
		"Login button":        {3},
		"Document login":      {4, 5},
	}
	for title, deps := range wantDeps {
		tk := tasks[title]
		if tk == nil {
			t.Fatalf("task %q was not added", title)
		}
		if !reflect.DeepEqual(append([]int(nil), tk.DependsOn...), deps) {
			t.Errorf("%q depends on %v, want %v", title, tk.DependsOn, deps)
		}
	}

	ps, _ := state.Load(dir)
	var order []string
	for _, tk := range pm.SortByExecutionOrder(ps.Plan.Tasks) {
		if tk.Status == pm.TaskPending {
			order = append(order, tk.Title)
		}
	}
	want := []string{"already queued", "Add provider config", "Callback handler", "Login button", "Document login"}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("run queue = %v, want %v — behind existing work, in plan order", order, want)
	}

	if st := apiGET(t, ts, "/api/suggest/status"); len(stepDeps(st)) != 0 {
		t.Errorf("added tasks are still offered for review: %v", st["suggestions"])
	}
}

// One card at a time, out of order, skipping one: every task still ends up
// waiting for what the plan put before it, and nothing is added twice.
func TestSuggestPlan_AddingStepsOneByOneKeepsThePlan(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, []*pm.Task{
		{ID: 1, Title: "already queued", Status: pm.TaskPending, Priority: 1},
	})
	ts := newPlanServer(t, writePlanStub(t, loginPlan), dir)
	gen := genOf(t, generate(t, ts, "", map[string]interface{}{"input": "Add OAuth login"}))

	add := func(ids ...int) map[string]interface{} {
		t.Helper()
		code, resp := rawJSON(t, ts, http.MethodPost, "/api/suggest/add", map[string]interface{}{"gen": gen, "ids": ids})
		if code != http.StatusOK {
			t.Fatalf("add %v returned HTTP %d: %v", ids, code, resp)
		}
		return resp
	}

	add(4) // "Document login" first, before anything it needs → #2
	add(1) // "Add provider config" → #3; docs now waits for it through the missing 2 and 3
	// 2 ("Callback handler") is skipped; 3 ("Login button") → #4, after config.
	add(3)

	tasks := loadTasks(t, dir)
	if got := tasks["Login button"].DependsOn; !reflect.DeepEqual(got, []int{3}) {
		t.Errorf("Login button depends on %v, want [3]", got)
	}
	if got := tasks["Document login"].DependsOn; !reflect.DeepEqual(got, []int{3, 4}) {
		t.Errorf("Document login depends on %v, want [3 4] — config through the skipped "+
			"callback, and the button, both gained after it was added", got)
	}

	if again := add(3); len(again["added"].([]interface{})) != 0 {
		t.Errorf("accepting a task twice added it twice: %v", again["added"])
	}
	if n := len(loadTasks(t, dir)); n != 4 {
		t.Errorf("plan has %d tasks, want 4", n)
	}
	if left := stepDeps(apiGET(t, ts, "/api/suggest/status")); len(left) != 1 || left["Callback handler"] == nil {
		t.Errorf("still offered for review: %v, want only the skipped Callback handler", left)
	}
}

// An accept aimed at a generation that has been replaced is refused, rather
// than landing on whatever the new generation numbered the same.
func TestSuggestAdd_RefusesAReplacedGeneration(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newPlanServer(t, writePlanStub(t, loginPlan), dir)
	old := genOf(t, generate(t, ts, "", map[string]interface{}{"input": "Add OAuth login"}))
	generate(t, ts, "", map[string]interface{}{"count": 4})

	code, _ := rawJSON(t, ts, http.MethodPost, "/api/suggest/add", map[string]interface{}{"gen": old, "ids": []int{1}})
	if code != http.StatusConflict {
		t.Errorf("accepting from a replaced generation returned HTTP %d, want 409", code)
	}
	if n := len(loadTasks(t, dir)); n != 0 {
		t.Errorf("a refused accept still added %d tasks", n)
	}
}

// The older request shape — the proposals themselves — keeps working: one that
// matches the current generation is accepted like its ID (and so leaves the
// review list), anything else is added as an independent idea.
func TestSuggestAdd_ServesTheOlderRequestShape(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newPlanServer(t, writePlanStub(t, loginPlan), dir)
	generate(t, ts, "", map[string]interface{}{"input": "Add OAuth login"})

	code, resp := rawJSON(t, ts, http.MethodPost, "/api/suggest/add", map[string]interface{}{
		"suggestions": []map[string]interface{}{
			{"id": 1, "title": "Add provider config"},
			{"id": 1, "title": "Not from this plan", "effort": "xs"},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("legacy add returned HTTP %d: %v", code, resp)
	}
	tasks := loadTasks(t, dir)
	if tasks["Add provider config"] == nil || tasks["Not from this plan"] == nil {
		t.Fatalf("legacy add did not add both: %v", tasks)
	}
	if p := tasks["Not from this plan"].Priority; p != 3 {
		t.Errorf("a loose idea's priority = %d, want the effort mapping's 3", p)
	}
	left := stepDeps(apiGET(t, ts, "/api/suggest/status"))
	if _, still := left["Add provider config"]; still {
		t.Error("an accepted proposal is still offered for review")
	}
}

// Each project has its own job: one project's generation neither blocks
// another's nor shows up in its status.
func TestSuggestJobsArePerProject(t *testing.T) {
	a := setupProjectDir(t, cloopGoal, nil)
	b := setupProjectDir(t, sysmonGoal, nil)
	ts := newPlanServer(t, writePlanStub(t, loginPlan), a, b)

	hold := filepath.Join(a, "hold")
	if err := os.WriteFile(hold, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, resp := rawJSON(t, ts, http.MethodPost, "/api/suggest/generate",
		map[string]interface{}{"input": "project A's confidential roadmap"})
	if code != http.StatusOK {
		t.Fatalf("generate in A returned HTTP %d: %v", code, resp)
	}

	idle := apiGET(t, ts, "/api/suggest/status?project_idx=1")
	if idle["running"] == true || idle["done"] == true || idle["request"] != "" {
		t.Errorf("project B reports project A's job: %v", idle)
	}

	stB := generate(t, ts, "?project_idx=1", map[string]interface{}{"input": "B's own plan"})
	if stB["request"] != "B's own plan" {
		t.Errorf("B's status names request %v", stB["request"])
	}
	if sum, _ := stB["summary"].(string); !strings.HasPrefix(sum, filepath.Base(b)+":") {
		t.Errorf("B was shown a summary generated in another project: %q", sum)
	}

	if st := apiGET(t, ts, "/api/suggest/status"); st["running"] != true {
		t.Errorf("A's job should still be running while held: %v", st)
	}
	if err := os.Remove(hold); err != nil {
		t.Fatal(err)
	}
	stA := waitSuggest(t, ts, "")
	if stA["request"] != "project A's confidential roadmap" {
		t.Errorf("A's status names request %v", stA["request"])
	}
	if st := apiGET(t, ts, "/api/suggest/status?project_idx=1"); st["request"] != "B's own plan" {
		t.Errorf("A finishing changed B's status: %v", st["request"])
	}
}

func TestSuggestGenerate_ValidatesTheInput(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newPlanServer(t, writePlanStub(t, loginPlan), dir)

	for name, body := range map[string]interface{}{
		"over-long": map[string]interface{}{"input": strings.Repeat("x", 8001)},
		"NUL":       map[string]interface{}{"input": "plan\x00this"},
		"not JSON":  "{",
	} {
		t.Run(name, func(t *testing.T) {
			var code int
			if s, ok := body.(string); ok {
				resp, err := http.Post(ts.URL+"/api/suggest/generate", "application/json", strings.NewReader(s))
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				code = resp.StatusCode
			} else {
				code, _ = rawJSON(t, ts, http.MethodPost, "/api/suggest/generate", body)
			}
			if code != http.StatusBadRequest {
				t.Errorf("HTTP %d, want 400", code)
			}
		})
	}
	if st := apiGET(t, ts, "/api/suggest/status"); st["running"] == true || st["done"] == true {
		t.Errorf("a refused request started a job: %v", st)
	}

	// An empty body is still the defaults, as it always was.
	resp, err := http.Post(ts.URL+"/api/suggest/generate", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("an empty body returned HTTP %d", resp.StatusCode)
	}
	waitSuggest(t, ts, "")
	if got := recordedArgs(t, dir); !reflect.DeepEqual(got, []string{"suggest", "--json", "--count", "5"}) {
		t.Errorf("an empty body ran %q", got)
	}
}
