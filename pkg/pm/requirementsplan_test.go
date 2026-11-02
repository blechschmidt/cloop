package pm

// Tasks proposed with the requirements in view (Task 20463).

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/requirements"
)

// reqPlanSummary: R-1 must and failing, R-2 should with nothing known, R-3 a
// must that lacks only a test, R-4 could and changed since it held, R-5 one
// an open task (#7) implements; R-6 a must draft and R-7 a must deprecated
// requirement, which have no standing.
func reqPlanSummary(t *testing.T) requirements.StatusSummary {
	t.Helper()
	at := func(h int) time.Time { return time.Date(2026, 10, 1, h, 0, 0, 0, time.UTC) }
	tested := []requirements.Test{{Command: "true"}}
	reqs := []requirements.Requirement{
		{ID: 1, Title: "Config errors exit 2", Priority: requirements.PriorityMust, Tests: tested, UpdatedAt: at(0)},
		{ID: 2, Title: "Exports are paginated", Priority: requirements.PriorityShould, Tests: tested, UpdatedAt: at(0)},
		{ID: 3, Title: "The audit log is signed", Priority: requirements.PriorityMust, UpdatedAt: at(0)},
		{ID: 4, Title: "Logs rotate daily", Priority: requirements.PriorityCould, Tests: tested, UpdatedAt: at(5)},
		{ID: 5, Title: "Sessions expire", Priority: requirements.PriorityMust, Tests: tested, UpdatedAt: at(0)},
		{ID: 6, Title: "A must draft", Priority: requirements.PriorityMust, Status: requirements.StatusDraft},
		{ID: 7, Title: "A deprecated must", Priority: requirements.PriorityMust, Status: requirements.StatusDeprecated},
	}
	last := map[int]requirements.LastCheck{
		1: {Verdict: requirements.VerdictUnfulfilled, Fingerprint: reqs[0].Fingerprint(), CheckedAt: at(2), Summary: "exit 1"},
		3: {Verdict: requirements.VerdictFulfilled, Fingerprint: reqs[2].Fingerprint(), CheckedAt: at(2)},
		4: {Verdict: requirements.VerdictFulfilled, Fingerprint: "earlier", CheckedAt: at(2)},
		5: {Verdict: requirements.VerdictUnfulfilled, Fingerprint: reqs[4].Fingerprint(), CheckedAt: at(2)},
	}
	plan := &Plan{Tasks: []*Task{{ID: 7, Title: "Expire sessions", Status: TaskPending, Requirements: []int{5}}}}
	return requirements.Summarize(requirements.Standings(reqs, last), TaskViews(plan))
}

func TestLinkProposedTasksKeepsOnlyApprovedRequirements(t *testing.T) {
	sum := reqPlanSummary(t)
	tasks := []*Task{
		{Title: "Fix the exit code", Requirements: []int{1, 6, 7, 99}},
		{Title: "Restore R-3: sign the audit log"},
		{Title: "Add a test for the signed audit log", Description: "Test it.", Requirements: []int{3}},
		{Title: "Dark mode"},
	}
	LinkProposedTasks(tasks, sum)
	if got := fmt.Sprint(tasks[0].Requirements); got != "[1]" {
		t.Errorf("links %s: a draft's, a deprecated requirement's and a made-up id stay", got)
	}
	if got := fmt.Sprint(tasks[1].Requirements); got != "[3]" {
		t.Errorf("a task that names R-3 in its title links %s", got)
	}
	// What a task the model proposed does is the model's to say: linking a
	// requirement that lacks a test does not make it a test task.
	if !hasTag(tasks[2], TagRequirement) || hasTag(tasks[2], TagTestOnly) || tasks[2].Role == RoleTesting ||
		strings.Contains(tasks[2].Description, "shell command") {
		t.Errorf("the model's task linking R-3: %+v", tasks[2])
	}
	if !hasTag(tasks[0], TagRequirement) || hasTag(tasks[0], TagTestOnly) {
		t.Errorf("a fix task's tags %v", tasks[0].Tags)
	}
	if len(tasks[3].Requirements) != 0 || len(tasks[3].Tags) != 0 {
		t.Errorf("a feature task got %v %v", tasks[3].Requirements, tasks[3].Tags)
	}
}

func hasTag(t *Task, tag string) bool {
	for _, x := range t.Tags {
		if x == tag {
			return true
		}
	}
	return false
}

func TestDedupByRequirementsDropsWhatAnOpenTaskImplements(t *testing.T) {
	sum := reqPlanSummary(t)
	cands := []*Task{
		{Title: "Make sessions expire", Requirements: []int{5}},
		{Title: "Sessions and exports", Requirements: []int{5, 2}},
		{Title: "Dark mode"},
	}
	kept, dropped := DedupByRequirements(cands, sum)
	if len(kept) != 2 || kept[0].Title != "Sessions and exports" || kept[1].Title != "Dark mode" {
		t.Errorf("kept %v", kept)
	}
	if len(dropped) != 1 || !strings.Contains(dropped[0].Reason(), `"Make sessions expire" links R-5, which open task #7 already implements`) {
		t.Errorf("dropped %+v", dropped)
	}
}

func TestCloseMustGapsAddsATaskForEachMustGapLeftOpen(t *testing.T) {
	sum := reqPlanSummary(t)
	tasks := CloseMustGaps([]*Task{{ID: 50, Title: "Fix exit codes", Requirements: []int{1}}}, sum)
	if len(tasks) != 2 {
		t.Fatalf("tasks %d, want the model's and one for R-3", len(tasks))
	}
	got := tasks[1]
	if got.Title != "Add a test for R-3: The audit log is signed" || fmt.Sprint(got.Requirements) != "[3]" ||
		!hasTag(got, TagTestOnly) || got.Status != TaskPending {
		t.Errorf("the task for R-3: %+v", got)
	}
	// Nothing for the draft or the deprecated must requirement, nor for R-5,
	// which an open task implements.
	for _, task := range tasks {
		for _, id := range task.Requirements {
			if id == 5 || id == 6 || id == 7 {
				t.Errorf("a task for R-%d: %+v", id, task)
			}
		}
	}
}

func TestOrderByRequirementsRunsGapWorkFirst(t *testing.T) {
	sum := reqPlanSummary(t)
	tasks := []*Task{
		{ID: 50, Title: "Dark mode", Priority: 1},
		{ID: 51, Title: "Rotate logs", Priority: 1, Requirements: []int{4}},
		{ID: 52, Title: "Paginate exports", Priority: 3, Requirements: []int{2}},
		{ID: 53, Title: "Fix exit codes", Priority: 2, Requirements: []int{1}, DependsOn: []int{54}},
		{ID: 54, Title: "Refactor the config loader", Priority: 5},
		{ID: 55, Title: "Polish", Priority: 2, DependsOn: []int{9}},
	}
	out := OrderByRequirements(tasks, sum, 100)
	var got []string
	for _, task := range out {
		got = append(got, fmt.Sprintf("%d:%s:P%d:%v", task.ID, task.Title, task.Priority, task.DependsOn))
	}
	want := []string{
		"100:Refactor the config loader:P1:[]", // what the must task needs runs as a must task
		"101:Fix exit codes:P1:[100]",
		"102:Paginate exports:P2:[]",
		"103:Rotate logs:P4:[]",
		"104:Dark mode:P5:[]", // behind every gap task
		"105:Polish:P5:[9]",   // a dependency outside the batch is kept
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("ordered\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A dependency on a task of the batch that was dropped names nothing: it
// must not land on the task that takes the dropped one's number.
func TestOrderByRequirementsDropsDependenciesOnDroppedTasks(t *testing.T) {
	sum := reqPlanSummary(t)
	// The plan's last task is #10; the model proposed #11 and #12 after it,
	// and the dedup dropped #11.
	tasks := []*Task{{ID: 12, Title: "Restore R-1", Requirements: []int{1}, DependsOn: []int{11, 10, 12}}}
	out := OrderByRequirements(tasks, sum, 11)
	if out[0].ID != 11 || fmt.Sprint(out[0].DependsOn) != "[10]" {
		t.Errorf("task %d depends on %v, want 11 on [10]", out[0].ID, out[0].DependsOn)
	}
}

func TestEvolveTasksCarryTheirLinksAndThePromptTheSpec(t *testing.T) {
	sum := reqPlanSummary(t)
	plan := &Plan{Tasks: []*Task{{ID: 7, Title: "Expire sessions", Status: TaskPending, Requirements: []int{5}}}}
	prompt := EvolveDiscoverPrompt("goal", "", plan, 2, false, sum)
	for _, want := range []string{"## REQUIREMENTS — WHERE THE PROJECT'S SPEC STANDS", "- R-1 [must] Config errors exit 2",
		"open must gaps (R-1, R-3)", `"requirements":[]`} {
		if !strings.Contains(prompt, want) {
			t.Errorf("the evolve prompt lacks %q", want)
		}
	}
	if strings.Contains(prompt, "A must draft") || strings.Contains(prompt, "A deprecated must") {
		t.Error("the evolve prompt names a draft or a deprecated requirement")
	}
	if p := EvolveDiscoverPrompt("goal", "", plan, 2, false, requirements.StatusSummary{}); strings.Contains(p, "REQUIREMENTS") ||
		strings.Contains(p, `"requirements"`) {
		t.Error("a project without requirements is asked about them")
	}

	tasks, err := ParseEvolveTasks("goal", `{"tasks":[{"id":1,"title":"Fix","requirements":["R-1",3,"x"]},{"id":2,"title":"New"}]}`, plan)
	if err != nil || len(tasks) != 2 || fmt.Sprint(tasks[0].Requirements) != "[1 3]" || tasks[1].Requirements != nil {
		t.Errorf("parsed %v %v", tasks, err)
	}
	// Every other planner's tasks link nothing until a caller checks them.
	p, err := ParseTaskPlan("goal", `{"tasks":[{"id":1,"title":"Fix","requirements":[1]}]}`)
	if err != nil || p.Tasks[0].Requirements != nil {
		t.Errorf("ParseTaskPlan kept a link no caller checked: %v %v", p.Tasks[0].Requirements, err)
	}
}

func TestDedupPromptSaysWhichRequirementsATaskImplements(t *testing.T) {
	existing := []*Task{
		{ID: 7, Title: "Expire sessions", Status: TaskPending, Requirements: []int{5}},
		{ID: 8, Title: "Old work", Status: TaskDone},
	}
	p := dedupPrompt(existing, []*Task{{Title: "Expire them sooner", Requirements: []int{5}}})
	for _, want := range []string{"- [7] Expire sessions:  (implements R-5; open)", "- [8] Old work: \n",
		"- [0] Expire them sooner:  (implements R-5)", "OPEN existing task implementing the same requirement"} {
		if !strings.Contains(p, want) {
			t.Errorf("the dedup prompt lacks %q:\n%s", want, p)
		}
	}
	if p := dedupPrompt(existing[1:], []*Task{{Title: "x"}}); strings.Contains(p, "implements R-") || strings.Contains(p, "OPEN existing") {
		t.Error("a plan without links is told about them")
	}
}
