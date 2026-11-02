package orchestrator

// Auto-evolve with the requirements in view (Task 20463), against the
// deterministic mock provider: its answers are scripted in the project's
// .cloop/mock_responses.yaml and matched on the prompt's own words, so a rule
// that only matches when the prompt carries the requirement status summary is
// what proves the round was shown it.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	mockprovider "github.com/blechschmidt/cloop/pkg/provider/mock"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// evolveAnswer is the round's tasks: a feature, a should gap, one repeating
// what open task #3 implements, one linking only a draft and a deprecated
// requirement, and one naming R-1 in its title only.
const evolveAnswer = `{"tasks":[
{"id":1,"title":"Dark mode","description":"A dark theme.","priority":1},
{"id":2,"title":"Paginate exports","description":"Page them.","priority":1,"requirements":[2]},
{"id":3,"title":"Session tweak","description":"Expire sooner.","priority":1,"requirements":["R-5"]},
{"id":4,"title":"Draft thing","description":"Do the draft.","priority":2,"requirements":[6,7]},
{"id":5,"title":"Restore R-1: config errors exit 2","description":"Fix the exit code.","priority":3}
]}`

// requirementsEvolveProject is a finished plan with requirements: R-1 a must
// one that fails, R-2 a should one nothing shows to hold, R-3 a must one that
// holds by a person's word and has no test, R-4 a could one that holds, R-5 a
// must one task #3 implements — pending behind a failed task, so the plan is
// finished all the same — and R-6 a must draft, R-7 a deprecated must one.
func requirementsEvolveProject(t *testing.T) string {
	t.Helper()
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.AutoEvolve = true
	s.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{
		{ID: 1, Title: "Done already", Priority: 1, Status: pm.TaskDone, Result: "Implemented it."},
		{ID: 2, Title: "Broke", Priority: 1, Status: pm.TaskFailed},
		{ID: 3, Title: "Expire sessions", Priority: 1, Status: pm.TaskPending, DependsOn: []int{2}, Requirements: []int{5}},
	}}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.AsProject()
	tested := []requirements.Test{{Command: "true"}}
	for _, r := range []requirements.Requirement{
		{Title: "Config errors exit 2", Priority: requirements.PriorityMust, Tests: tested},
		{Title: "Exports are paginated", Priority: requirements.PriorityShould, Tests: tested},
		{Title: "The audit log is signed", Priority: requirements.PriorityMust},
		{Title: "Logs rotate", Priority: requirements.PriorityCould, Tests: tested},
		{Title: "Sessions expire", Priority: requirements.PriorityMust, Tests: tested},
		{Title: "A must draft", Priority: requirements.PriorityMust, Status: requirements.StatusDraft},
		{Title: "A deprecated must", Priority: requirements.PriorityMust, Status: requirements.StatusDeprecated},
	} {
		if _, err := db.AddRequirement(r, "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	for id, v := range map[int]string{1: requirements.VerdictUnfulfilled, 3: requirements.VerdictFulfilled, 4: requirements.VerdictFulfilled} {
		if _, err := db.RecordRequirementVerdict(id, v, "", "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// scriptMock writes the mock provider's rules: the round's answer only for a
// prompt that carries the requirement status, and a dedup verdict — Dark mode
// repeats existing work — only for a prompt that shows the links.
func scriptMock(t *testing.T, dir, evolve string) {
	t.Helper()
	yaml := "rules:\n" +
		"  - substring: \"- R-1 [must] Config errors exit 2\"\n    response: |\n" + indent(evolve) +
		"  - substring: \"(implements R-1)\"\n    response: '{\"novel\":[1,2,3],\"reason\":\"Dark mode repeats #1\"}'\n" +
		"default: '{\"tasks\":[]}'\n"
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "mock_responses.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
}

func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		b.WriteString("      " + line + "\n")
	}
	return b.String()
}

func TestEvolveRoundClosesTheMustGapsFirstAndLinksWhatItAdds(t *testing.T) {
	dir := requirementsEvolveProject(t)
	scriptMock(t, dir, evolveAnswer)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, mockprovider.New(""))
	n, err := o.evolvePM(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, err := state.LoadLite(dir)
	if err != nil {
		t.Fatal(err)
	}
	var added []string
	for _, task := range got.Plan.Tasks[3:] {
		added = append(added, fmt.Sprintf("#%d P%d %s %v %v", task.ID, task.Priority, task.Title, task.Requirements, task.Tags))
	}
	want := []string{
		"#4 P1 Restore R-1: config errors exit 2 [1] [requirement]",
		"#5 P1 Add a test for R-3: The audit log is signed [3] [requirement test-only]",
		"#6 P2 Paginate exports [2] [requirement]",
		"#7 P3 Draft thing [] []", // its links named a draft and a deprecated requirement
	}
	if n != len(want) || strings.Join(added, "\n") != strings.Join(want, "\n") {
		t.Errorf("the round added %d:\n%s\nwant\n%s", n, strings.Join(added, "\n"), strings.Join(want, "\n"))
	}
	// "Session tweak" links only R-5, which open task #3 implements; Dark
	// mode the semantic dedup found repeated, shown the links.
	for _, task := range got.Plan.Tasks {
		if task.Title == "Session tweak" || task.Title == "Dark mode" {
			t.Errorf("%q was added", task.Title)
		}
	}
	// The test task is told how its test is named, and runs as a test task.
	if task := got.Plan.TaskByID(5); task.Role != pm.RoleTesting || !strings.Contains(task.Description, "shell command") {
		t.Errorf("the test task: %+v", task)
	}
	// Run order: must work first, then should, then the rest.
	ready := got.Plan.ReadyTasks()
	var order []int
	for _, task := range ready {
		order = append(order, task.ID)
	}
	if fmt.Sprint(order) != "[4 5 6 7]" {
		t.Errorf("run order %v", order)
	}
}

// With a must gap open the round closes it whatever the model answered:
// nothing at all here.
func TestEvolveRoundWithNothingProposedStillClosesTheMustGaps(t *testing.T) {
	dir := requirementsEvolveProject(t)
	scriptMock(t, dir, `{"tasks":[]}`)
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, mockprovider.New(""))
	n, err := o.evolvePM(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := state.LoadLite(dir)
	var titles []string
	for _, task := range got.Plan.Tasks[3:] {
		titles = append(titles, task.Title)
	}
	if n != 2 || strings.Join(titles, "|") != "Restore R-1: Config errors exit 2|Add a test for R-3: The audit log is signed" {
		t.Errorf("added %d: %v", n, titles)
	}

	// Once those finish, nothing is open that a task closes: the next round
	// adds nothing by template — it cannot loop on a requirement.
	ps, _ := state.Load(dir)
	done := time.Now()
	for _, task := range ps.Plan.Tasks[3:] {
		task.Status, task.CompletedAt = pm.TaskDone, &done
	}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	o = newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, mockprovider.New(""))
	if n, err := o.evolvePM(context.Background()); err != nil || n != 0 {
		t.Errorf("the next round added %d (%v)", n, err)
	}
}

// A project without approved requirements evolves as it always did: the
// model's tasks, unlinked, and nothing added by template.
func TestEvolveRoundWithoutRequirementsIsUnchanged(t *testing.T) {
	dir := evolveProject(t)
	answer := `{"tasks":[{"id":1,"title":"Dark mode","priority":1,"requirements":[1]}]}`
	yaml := "rules:\n  - substring: \"AUTO-EVOLVE\"\n    response: |\n" + indent(answer) +
		"  - substring: \"task deduplication assistant\"\n    response: '{\"novel\":[0]}'\n"
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "mock_responses.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, mockprovider.New(""))
	if n, err := o.evolvePM(context.Background()); err != nil || n != 1 {
		t.Fatalf("added %d (%v)", n, err)
	}
	got, _ := state.LoadLite(dir)
	if task := got.Plan.TaskByID(2); task == nil || task.Requirements != nil || task.Priority != 1 {
		t.Errorf("the task: %+v", task)
	}
}
