package e2e_test

// `cloop suggest --input` on the real binary with the offline mock provider
// (Task 20342): the plan it hands the dashboard, and the tasks it adds when
// run interactively.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// planResponses scripts the mock: the plan prompt is recognised by its REQUEST
// section, anything else gets a brainstorm. Task 2's reference to task 3 is a
// forward edge the command must drop.
const planResponses = `rules:
  - substring: "## REQUEST"
    response: |
      Here is the plan.
      {"summary":"OAuth login in four steps","suggestions":[
       {"id":1,"title":"Add provider config","description":"Add OAuth client settings.","category":"feature","effort":"l","depends_on":[]},
       {"id":2,"title":"Callback handler","description":"Handle the redirect.","category":"security","effort":"xs","depends_on":[1,3]},
       {"id":3,"title":"Login button","description":"Add the button.","category":"ux","effort":"s","depends_on":[1]},
       {"id":4,"title":"Document login","description":"Write docs.","category":"docs","effort":"m","depends_on":[2,3]}]}
default: |
  {"summary":"two ideas","suggestions":[{"id":1,"title":"Dark mode","category":"ux","effort":"s"},{"id":2,"title":"Rate limits","category":"security","effort":"m"}]}
`

func newPlanProject(t *testing.T) string {
	t.Helper()
	dir := newWorkDir(t)
	mustRun(t, dir, "init", "Plan requests")
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "mock_responses.yaml"), []byte(planResponses), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

type e2eSuggestion struct {
	ID        int    `json:"id"`
	Title     string `json:"title"`
	DependsOn []int  `json:"depends_on"`
}

type e2eSuggestResult struct {
	Summary     string          `json:"summary"`
	Request     string          `json:"request"`
	Suggestions []e2eSuggestion `json:"suggestions"`
}

// suggestJSON runs `cloop suggest --json` and reads the framed payload.
func suggestJSON(t *testing.T, dir string, args ...string) e2eSuggestResult {
	t.Helper()
	out := mustRun(t, dir, append([]string{"suggest", "--provider", "mock", "--json"}, args...)...)
	const begin, end = "<<<cloop-json:begin>>>", "<<<cloop-json:end>>>"
	i, j := strings.Index(out, begin), strings.Index(out, end)
	if i < 0 || j < i {
		t.Fatalf("no framed payload in:\n%s", out)
	}
	var r e2eSuggestResult
	if err := json.Unmarshal([]byte(out[i+len(begin):j]), &r); err != nil {
		t.Fatalf("payload is not JSON: %v\n%s", err, out)
	}
	return r
}

func TestE2ESuggestPlansARequest(t *testing.T) {
	dir := newPlanProject(t)

	r := suggestJSON(t, dir, "--input", "Add OAuth login")
	if r.Request != "Add OAuth login" {
		t.Errorf("request = %q; it is what marks the payload as a plan", r.Request)
	}
	got := map[string][]int{}
	for _, s := range r.Suggestions {
		got[s.Title] = s.DependsOn
	}
	want := map[string][]int{
		"Add provider config": nil,
		"Callback handler":    {1},
		"Login button":        {1},
		"Document login":      {2, 3},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("plan = %v, want %v", got, want)
	}

	if r := suggestJSON(t, dir, "--input", "Add OAuth login", "--count", "2"); len(r.Suggestions) != 2 {
		t.Errorf("--count 2 produced %d tasks", len(r.Suggestions))
	}
	if r := suggestJSON(t, dir); r.Request != "" || len(r.Suggestions) != 2 {
		t.Errorf("without --input it must still brainstorm: %+v", r)
	}
}

func TestE2ESuggestRejectsABadCount(t *testing.T) {
	dir := newPlanProject(t)
	for reason, args := range map[string][]string{
		"a plan has at most 20 tasks": {"--input", "x", "--count", "21"},
		"must not be negative":        {"--count", "-1"},
	} {
		out, err := run(t, dir, append([]string{"suggest", "--provider", "mock", "--json"}, args...)...)
		if err == nil {
			t.Errorf("suggest %v succeeded:\n%s", args, out)
		}
		assertContains(t, out, reason)
	}
}

// Accepting interactively, with one task rejected: the rest land as tasks in
// plan order, and the task that needed the rejected one waits for what the
// rejected one needed instead.
func TestE2ESuggestAddsAcceptedPlanTasks(t *testing.T) {
	dir := newPlanProject(t)

	cmd := exec.Command(binaryPath(t), "suggest", "--provider", "mock", "--input", "Add OAuth login")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb")
	cmd.Stdin = strings.NewReader("y\nn\ny\ny\n") // reject the callback handler
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("interactive suggest failed: %v\n%s", err, out)
	}
	assertContains(t, string(out), "Added 3 task(s)")

	var tasks []struct {
		ID        int    `json:"id"`
		Title     string `json:"title"`
		Priority  int    `json:"priority"`
		DependsOn []int  `json:"depends_on"`
	}
	list := mustRun(t, dir, "task", "list", "--json")
	if err := json.Unmarshal([]byte(list), &tasks); err != nil {
		t.Fatalf("task list --json: %v\n%s", err, list)
	}
	type row struct {
		Title string
		Deps  []int
	}
	var got []row
	for _, tk := range tasks {
		got = append(got, row{tk.Title, tk.DependsOn})
	}
	want := []row{
		{"Add provider config", nil},
		{"Login button", []int{1}},
		{"Document login", []int{1, 2}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tasks = %+v, want %+v", got, want)
	}
	for i := 1; i < len(tasks); i++ {
		if tasks[i].Priority <= tasks[i-1].Priority {
			t.Errorf("priorities %d then %d: the plan must queue in order", tasks[i-1].Priority, tasks[i].Priority)
		}
	}
}
