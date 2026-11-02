package cmd

// `cloop requirements plan`, and `suggest` and `task decompose` with the
// requirements in view (Task 20463), run as a person runs them and as the hub
// dispatches them, with the deterministic mock provider standing in for the
// model. Each scripted answer is matched on words only the requirement status
// puts in the prompt, so a test passing is the prompt carrying it.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/suggest"
)

// gapPlanAnswer is the model's plan: a should gap, a task repeating what open
// task #1 implements, a must gap that needs the first task — linking a draft
// and a deprecated requirement besides — and one linking only the draft.
const gapPlanAnswer = `{"summary":"Close the spec's gaps","suggestions":[
{"id":1,"title":"Paginate exports","description":"Page the export API.","category":"feature","effort":"m","depends_on":[],"requirements":[2],"kind":"implement"},
{"id":2,"title":"Expire sessions sooner","description":"Shorter sessions.","category":"security","effort":"s","depends_on":[],"requirements":[4]},
{"id":3,"title":"Restore the config exit code","description":"Make a bad config exit 2.","category":"dx","effort":"s","depends_on":[1],"requirements":["R-1",5,6]},
{"id":4,"title":"Drafted work","description":"Do what the draft says.","category":"feature","effort":"s","depends_on":[],"requirements":[5]}]}`

// writeMockRules scripts the mock provider: each rule answers prompts that
// contain its substring, first match first; anything else gets fallback.
func writeMockRules(t *testing.T, dir, fallback string, rules ...[2]string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("rules:\n")
	for _, r := range rules {
		b.WriteString("  - substring: " + strconvQuote(r[0]) + "\n    response: |\n")
		for _, line := range strings.Split(r[1], "\n") {
			b.WriteString("      " + line + "\n")
		}
	}
	b.WriteString("default: " + strconvQuote(fallback) + "\n")
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "mock_responses.yaml"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// gapProject is helperProject's — task #1 pending — with R-1 a must
// requirement found unfulfilled, R-2 a should one never checked, R-3 a must one
// with no test that holds by a person's word, R-4 a must one task #1
// implements, R-5 a must draft and R-6 a deprecated must one.
func gapProject(t *testing.T, exe string) string {
	t.Helper()
	dir := helperProject(t, "mock")
	mustRun(t, exe, dir, "requirements", "add", "Config errors exit 2", "--priority", "must", "--test", "false")
	mustRun(t, exe, dir, "requirements", "add", "Exports are paginated", "--priority", "should", "--test", "true")
	mustRun(t, exe, dir, "requirements", "add", "The audit log is signed", "--priority", "must")
	mustRun(t, exe, dir, "requirements", "add", "Sessions expire", "--priority", "must", "--test", "true")
	mustRun(t, exe, dir, "requirements", "add", "A must draft", "--priority", "must", "--status", "draft")
	mustRun(t, exe, dir, "requirements", "add", "A deprecated must", "--priority", "must", "--status", "deprecated")
	mustRun(t, exe, dir, "requirements", "verdict", "1", "unfulfilled", "--note", "exits 1")
	mustRun(t, exe, dir, "requirements", "verdict", "3", "fulfilled", "--note", "checked by hand")
	mustRun(t, exe, dir, "task", "edit", "1", "--requirement", "4")
	return dir
}

func TestRequirementsPlanByHand(t *testing.T) {
	exe := cliSelfExe(t)
	dir := gapProject(t, exe)
	writeMockRules(t, dir, "I will not answer that.", [2]string{"- R-1 [must] Config errors exit 2 — unfulfilled", gapPlanAnswer})

	out := mustRun(t, exe, dir, "requirements", "plan", "--dry-run")
	for _, want := range []string{"Planning 3 open requirement gap(s)",
		`Note: Left out "Expire sessions sooner": R-4 is already implemented by open task #1.`,
		`Note: Added "Add a test for R-3: The audit log is signed": the must requirement R-3 had no task.`,
		"Closes: R-1 [must]", "Closes: R-3 [must] — only adds a test", "Closes no requirement's gap.", "(dry-run) Nothing was added."} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	if ps, _ := state.LoadLite(dir); len(ps.Plan.Tasks) != 1 {
		t.Fatalf("a dry run added %d tasks", len(ps.Plan.Tasks)-1)
	}

	mustRun(t, exe, dir, "requirements", "plan", "--yes")
	ps, err := state.LoadLite(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, task := range ps.Plan.Tasks[1:] {
		got = append(got, fmt.Sprintf("#%d P%d %s %v %v %v", task.ID, task.Priority, task.Title, task.Requirements, task.Tags, task.DependsOn))
	}
	want := []string{
		// The should task the must one needs runs first, as a must task.
		"#2 P1 Paginate exports [2] [requirement] []",
		"#3 P1 Restore the config exit code [1] [requirement] [2]",
		"#4 P1 Add a test for R-3: The audit log is signed [3] [requirement test-only] []",
		"#5 P3 Drafted work [] [] []",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("added\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, task := range ps.Plan.Tasks {
		for _, id := range task.Requirements {
			if id == 5 || id == 6 {
				t.Errorf("task #%d links the draft or the deprecated requirement: %v", task.ID, task.Requirements)
			}
		}
	}

	// Every gap now has an open task: nothing more to plan, and the model is
	// not asked.
	writeMockRules(t, dir, "I will not answer that.")
	out = mustRun(t, exe, dir, "requirements", "plan")
	if !strings.Contains(out, "Nothing to plan") || !strings.Contains(out, "An open task implements: R-1, R-3, R-4, R-2.") {
		t.Errorf("a second plan:\n%s", out)
	}
}

// As the hub dispatches it: the hub's summary, a framed plan, nothing added.
func TestRequirementsPlanAsTheHubDispatchesIt(t *testing.T) {
	exe := cliSelfExe(t)
	dir := gapProject(t, exe)
	// R-9 exists only in the hub's summary: what the plan is made against is
	// what the hub sent.
	hub := `{"requirements":[{"id":9,"title":"Hub only","priority":"must","tested":true,"gaps":["unlinked","unchecked"],"action":"implement"}]}`
	writeMockRules(t, dir, "I will not answer that.", [2]string{"- R-9 [must] Hub only",
		`{"summary":"s","suggestions":[{"id":1,"title":"Build it","description":"d","requirements":[9,1]}]}`})
	out, err := runHelper(t, exe, dir, "requirements", "plan", "--json", "--requirements="+hub)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var res suggest.Result
	if err := clijson.Unmarshal(out, &res); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if res.Request != suggest.RequirementsRequest || len(res.Suggestions) != 1 ||
		fmt.Sprint([]int(res.Suggestions[0].Requirements)) != "[9]" || res.Suggestions[0].Kind != "implement" {
		t.Errorf("the plan %+v", res)
	}
	if ps, _ := state.LoadLite(dir); len(ps.Plan.Tasks) != 1 {
		t.Error("a plan for the hub added tasks")
	}
	// The hub's summary is for a plan the hub reads, never one added here.
	if out, err := runHelper(t, exe, dir, "requirements", "plan", "--yes", "--requirements="+hub); err == nil ||
		!strings.Contains(string(out), "--requirements is the hub's") {
		t.Errorf("--requirements without --json: %v\n%s", err, out)
	}
	// A summary that does not read is refused, framed.
	out, err = runHelper(t, exe, dir, "requirements", "plan", "--json", "--requirements=[1]")
	if err == nil || !strings.Contains(string(out), "the requirement status") {
		t.Errorf("a bad summary: %v\n%s", err, out)
	}
	if _, perr := clijson.Extract(out); perr != nil {
		t.Errorf("the refusal was not framed: %s", out)
	}
}

// A brainstorm with must gaps open closes them before any new feature, and
// links what it closes.
func TestSuggestClosesTheMustGapsFirst(t *testing.T) {
	exe := cliSelfExe(t)
	dir := gapProject(t, exe)
	writeMockRules(t, dir, "I will not answer that.", [2]string{"open must gaps (R-1, R-3)", `{"summary":"ideas","suggestions":[` +
		`{"id":1,"title":"Dark mode","description":"d","category":"ux","effort":"s"},` +
		`{"id":2,"title":"Sign the audit log","description":"d","category":"security","effort":"m","requirements":[3,5]}]}`})
	out, err := runHelper(t, exe, dir, "suggest", "--json", "--count", "2")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var res suggest.Result
	if err := clijson.Unmarshal(out, &res); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var got []string
	for _, s := range res.Suggestions {
		got = append(got, fmt.Sprintf("%s %v %s P%d", s.Title, []int(s.Requirements), s.Kind, s.Priority))
	}
	want := []string{"Sign the audit log [3]  P1", "Restore R-1: Config errors exit 2 [1] fix P1", "Dark mode []  P3"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("ideas\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A split of a task that implements requirements keeps them on the sub-tasks
// that make them hold.
func TestDecomposePreviewNamesWhatEachSubTaskCovers(t *testing.T) {
	exe := cliSelfExe(t)
	dir := gapProject(t, exe)
	writeMockRules(t, dir, "[]", [2]string{"- R-4 [must] Sessions expire", `[` +
		`{"title":"Add expiry","description":"d","requirements":[4,2]},` +
		`{"title":"Migrate","description":"d"},{"title":"Document","description":"d","requirements":["R-4"]}]`})
	out, err := runHelper(t, exe, dir, "task", "decompose", "1", "--dry-run", "--json")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var preview struct {
		SubTasks []struct {
			Title        string `json:"title"`
			Requirements []int  `json:"requirements"`
		} `json:"subtasks"`
	}
	if err := clijson.Unmarshal(out, &preview); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	raw, _ := json.Marshal(preview.SubTasks)
	if string(raw) != `[{"title":"Add expiry","requirements":[4]},{"title":"Migrate","requirements":null},{"title":"Document","requirements":[4]}]` {
		t.Errorf("sub-tasks %s", raw)
	}
}
