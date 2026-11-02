package requirements

// The rules every planner holds its proposals to once it knows where the
// requirements stand (Task 20463).

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestLooseRefsReadWhatAModelWrites(t *testing.T) {
	var task struct {
		Requirements LooseRefs `json:"requirements"`
	}
	for in, want := range map[string]string{
		`{"requirements":[3,"R-5","#7","r-9","x","R-0",-2,1.5,{"id":4}]}`: "[3 5 7 9]",
		`{"requirements":"R-3"}`: "[]",
		`{"requirements":null}`:  "[]",
		`{}`:                     "[]",
	} {
		task.Requirements = nil
		if err := json.Unmarshal([]byte(in), &task); err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got := fmt.Sprint([]int(task.Requirements)); got != want {
			t.Errorf("%s read as %s, want %s", in, got, want)
		}
	}
	many := make([]int, 2*MaxTaskLinks)
	for i := range many {
		many[i] = i + 1
	}
	raw, _ := json.Marshal(map[string]any{"requirements": many})
	_ = json.Unmarshal(raw, &task)
	if len(task.Requirements) != MaxTaskLinks {
		t.Errorf("read %d links, want at most %d", len(task.Requirements), MaxTaskLinks)
	}
}

func TestMentionedRefs(t *testing.T) {
	if got := MentionedRefs("Restore R-3: and R-12, again R-3; not XR-4 or R-0 or R-"); fmt.Sprint(got) != "[3 12]" {
		t.Errorf("MentionedRefs = %v", got)
	}
}

func planningSummary() StatusSummary {
	reqs, last := standingProject()
	return Summarize(Standings(reqs, last), []TaskView{{ID: 20, Status: "in_progress", Requirements: []int{5}}})
}

func TestKeepLinksNeverLinksADraftOrADeprecatedRequirement(t *testing.T) {
	sum := planningSummary()
	if got := sum.KeepLinks([]int{6, 7, 99, 3, 1, 3, 5}, false); fmt.Sprint(got) != "[1 3 5]" {
		t.Errorf("KeepLinks = %v, want the approved ones only, sorted, once each", got)
	}
	// R-5 holds and an open task implements it: not a gap.
	if got := sum.KeepLinks([]int{1, 5, 3}, true); fmt.Sprint(got) != "[1 3]" {
		t.Errorf("KeepLinks(targets only) = %v", got)
	}
}

func TestKindAndRankFollowFromTheLinks(t *testing.T) {
	sum := planningSummary()
	for _, c := range []struct {
		ids  []int
		kind string
		rank int
	}{
		{[]int{3}, ActionTest, 0},         // a must requirement that lacks only a test
		{[]int{3, 1}, ActionFix, 0},       // the strongest action wins
		{[]int{4}, ActionVerify, 2},       // could
		{[]int{2, 4}, ActionImplement, 1}, // should and could: should
		{[]int{5}, "", NoRank},            // holds, and an open task has it
		{nil, "", NoRank},
	} {
		if k := sum.KindFor(c.ids); k != c.kind {
			t.Errorf("KindFor(%v) = %q, want %q", c.ids, k, c.kind)
		}
		if r := sum.RankFor(c.ids); r != c.rank {
			t.Errorf("RankFor(%v) = %d, want %d", c.ids, r, c.rank)
		}
	}
	if p := sum.PriorityFor([]int{2, 4}); p != PriorityShould {
		t.Errorf("PriorityFor = %q", p)
	}
	if TaskPriority(PriorityMust) != 1 || TaskPriority(PriorityShould) != 2 || TaskPriority(PriorityCould) != 4 || TaskPriority("") != 2 {
		t.Error("TaskPriority changed")
	}
}

func TestCoveringTasksAndUncoveredMusts(t *testing.T) {
	sum := planningSummary()
	if got := sum.CoveringTasks([]int{5}); fmt.Sprint(got) != "[20]" {
		t.Errorf("CoveringTasks([5]) = %v", got)
	}
	if got := sum.CoveringTasks([]int{5, 1}); got != nil {
		t.Errorf("a proposal that closes R-1 as well repeats nothing: %v", got)
	}
	if got := sum.CoveringTasks(nil); got != nil {
		t.Errorf("CoveringTasks(nil) = %v", got)
	}
	open := sum.UncoveredMusts([]int{1}, []int{2})
	var keys []string
	for _, st := range open {
		keys = append(keys, st.Key())
	}
	if fmt.Sprint(keys) != "[R-3 R-8]" {
		t.Errorf("uncovered musts %v", keys)
	}
}

func TestPlanOrderPutsMustWorkFirstAfterWhatItNeeds(t *testing.T) {
	// 0: a feature, 1: could, 2: must that needs 3, 3: should, 4: must.
	ranks := []int{NoRank, 2, 0, 1, 0}
	deps := [][]int{nil, nil, {3}, nil, nil}
	order, eff := PlanOrder(ranks, deps)
	if fmt.Sprint(order) != "[3 2 4 1 0]" {
		t.Errorf("order %v, want [3 2 4 1 0]: the should task the must one needs runs as a must one", order)
	}
	if fmt.Sprint(eff) != "[4 2 0 0 0]" {
		t.Errorf("effective ranks %v", eff)
	}
	// A cycle still orders every proposal once.
	order, _ = PlanOrder([]int{1, 0}, [][]int{{1}, {0}})
	if len(order) != 2 || order[0] == order[1] {
		t.Errorf("a cycle ordered as %v", order)
	}
}

func TestGapTaskSaysWhatClosesTheGap(t *testing.T) {
	for _, c := range []struct {
		st          Standing
		title, desc string
	}{
		{Standing{ID: 3, Title: "Exit 2", Action: ActionFix, Verdict: VerdictUnfulfilled, Summary: "exit 1", Tested: true},
			"Restore R-3: Exit 2", "Its last check (unfulfilled): exit 1"},
		{Standing{ID: 4, Title: "Signed", Action: ActionTest}, "Add a test for R-4: Signed", "Write an automated test"},
		{Standing{ID: 5, Title: "Paged", Action: ActionVerify, Tested: true}, "Verify R-5: Paged", "Run its tests against the current code"},
		{Standing{ID: 6, Title: "Logged", Action: ActionImplement}, "Implement R-6: Logged", "write an automated test"},
	} {
		title, desc := GapTask(c.st)
		if title != c.title || !strings.Contains(desc, c.desc) {
			t.Errorf("GapTask(%s) = %q, %q", c.st.Action, title, desc)
		}
	}
}

func TestPlanPromptListsOnlyTheOpenGaps(t *testing.T) {
	sum := planningSummary()
	p := PlanPrompt("Ship it", "Go only", "cmd/", "- [pending] Task 20: x (implements R-5)", sum, 4)
	for _, want := range []string{"## PROJECT GOAL\nShip it", "## OPEN TASKS", "in at most 4 tasks",
		"- R-1 [must] Fails", "Close the must gaps first", `"kind"`, `"requirements":[3]`} {
		if !strings.Contains(p, want) {
			t.Errorf("the plan prompt lacks %q", want)
		}
	}
	if strings.Contains(p, "A draft") || strings.Contains(p, "Deprecated") {
		t.Errorf("the plan prompt names a draft or a deprecated requirement:\n%s", p)
	}
}

func TestGapRulesAskForTheMustGapsFirst(t *testing.T) {
	if (StatusSummary{}).GapRules() != "" {
		t.Error("a project without requirements is given rules")
	}
	r := planningSummary().GapRules()
	if !strings.Contains(r, "open must gaps (R-1, R-3, R-8). Your first tasks must close them") {
		t.Errorf("the rules:\n%s", r)
	}
}

func TestParseProposedTasks(t *testing.T) {
	answer := "Here is what I would do.\n\n```tasks\n[{\"title\": \"Restore exit codes\", \"requirements\": [\"R-1\", 3]}," +
		"{\"title\": \"\"}, {\"title\": \"Dark mode\", \"requirements\": []}]\n```\n"
	clean, tasks := ParseProposedTasks(answer)
	if clean != "Here is what I would do." {
		t.Errorf("clean %q", clean)
	}
	if len(tasks) != 2 || tasks[0].Title != "Restore exit codes" || fmt.Sprint([]int(tasks[0].Requirements)) != "[1 3]" ||
		tasks[1].Title != "Dark mode" {
		t.Errorf("tasks %+v", tasks)
	}
	// Only the last block counts; one that does not read stays in the text.
	if clean, tasks := ParseProposedTasks("a\n```tasks\nnot json\n```"); len(tasks) != 0 || !strings.Contains(clean, "not json") {
		t.Errorf("an unreadable block: %q %v", clean, tasks)
	}
	if clean, tasks := ParseProposedTasks("no block"); clean != "no block" || tasks != nil {
		t.Errorf("no block: %q %v", clean, tasks)
	}
}

func TestNothingToPlanSaysWhatEachWaitsFor(t *testing.T) {
	if got := NothingToPlan(StatusSummary{}); !strings.Contains(got, "no approved requirements") {
		t.Errorf("empty: %q", got)
	}
	reqs, last := standingProject()
	sum := Summarize(Standings(reqs, last), []TaskView{
		{ID: 10, Status: "pending", Requirements: []int{1, 3, 8}},
		{ID: 11, Status: "done", CompletedAt: at(6), Requirements: []int{2, 4}},
	})
	got := NothingToPlan(sum)
	for _, want := range []string{"An open task implements: R-1, R-3, R-8.", "Waiting for a check (cloop requirements check, or Check all): R-2, R-4."} {
		if !strings.Contains(got, want) {
			t.Errorf("NothingToPlan lacks %q: %s", want, got)
		}
	}
}
