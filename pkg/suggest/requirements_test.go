package suggest

// A generation held to the project's requirements (Task 20463).

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
)

// gapSummary: R-1 must and failing, R-2 should and never checked, R-3 a must
// that lacks only a test, R-4 could and changed since it held, R-5 a must one
// an open task (#7) implements; R-6 a must draft and R-7 a must deprecated
// requirement.
func gapSummary() requirements.StatusSummary {
	at := func(h int) time.Time { return time.Date(2026, 10, 1, h, 0, 0, 0, time.UTC) }
	tested := []requirements.Test{{Command: "true"}}
	reqs := []requirements.Requirement{
		{ID: 1, Title: "Config errors exit 2", Priority: requirements.PriorityMust, Tests: tested},
		{ID: 2, Title: "Exports are paginated", Priority: requirements.PriorityShould, Tests: tested},
		{ID: 3, Title: "The audit log is signed", Priority: requirements.PriorityMust},
		{ID: 4, Title: "Logs rotate daily", Priority: requirements.PriorityCould, Tests: tested},
		{ID: 5, Title: "Sessions expire", Priority: requirements.PriorityMust, Tests: tested},
		{ID: 6, Title: "A must draft", Priority: requirements.PriorityMust, Status: requirements.StatusDraft},
		{ID: 7, Title: "A deprecated must", Priority: requirements.PriorityMust, Status: requirements.StatusDeprecated},
	}
	last := map[int]requirements.LastCheck{
		1: {Verdict: requirements.VerdictUnfulfilled, Fingerprint: reqs[0].Fingerprint(), CheckedAt: at(2)},
		3: {Verdict: requirements.VerdictFulfilled, Fingerprint: reqs[2].Fingerprint(), CheckedAt: at(2)},
		4: {Verdict: requirements.VerdictFulfilled, Fingerprint: "earlier", CheckedAt: at(2)},
	}
	plan := &pm.Plan{Tasks: []*pm.Task{{ID: 7, Title: "Expire sessions", Status: pm.TaskPending, Requirements: []int{5}}}}
	return requirements.Summarize(requirements.Standings(reqs, last), pm.TaskViews(plan))
}

func titles(r *Result) []string {
	var out []string
	for _, s := range r.Suggestions {
		out = append(out, fmt.Sprintf("%d:%s:%v:%s:P%d:%v", s.ID, s.Title, []int(s.Requirements), s.Kind, s.Priority, s.DependsOn))
	}
	return out
}

// A plan from the requirements: links only to open gaps, a test task for the
// gap that lacks only a test, a task for the must gap the model left open,
// must work first — each after what it needs — and nothing that repeats an
// open task.
func TestApplyRequirementsForGaps(t *testing.T) {
	r := &Result{Request: RequirementsRequest, Suggestions: []*Suggestion{
		{ID: 1, Title: "Rotate logs", Requirements: requirements.LooseRefs{4, 6}},
		{ID: 2, Title: "Paginate exports", Requirements: requirements.LooseRefs{2, 7}, DependsOn: []int{1}},
		{ID: 3, Title: "Make sessions expire", Requirements: requirements.LooseRefs{5}},
		{ID: 4, Title: "Restore R-1: config errors"},
	}}
	NormalizePlan(r, 0)
	ApplyRequirements(r, gapSummary(), ForGaps, 0)
	want := []string{
		"1:Restore R-1: config errors:[1]:fix:P1:[]",
		"2:Add a test for R-3: The audit log is signed:[3]:test:P1:[]",
		"3:Rotate logs:[4]:verify:P2:[]", // a should task waits for it: it runs as a should task
		"4:Paginate exports:[2]:implement:P2:[3]",
	}
	if got := titles(r); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the plan\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(r.Suggestions[1].Description, "shell command") {
		t.Errorf("the test task does not say how its test is named: %q", r.Suggestions[1].Description)
	}
	notes := strings.Join(r.Notes, "\n")
	for _, want := range []string{`Left out "Make sessions expire": R-5 is already implemented by open task #7.`,
		`Added "Add a test for R-3: The audit log is signed": the must requirement R-3 had no task.`} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
	if open := Uncovered(r, gapSummary()); len(open) != 0 {
		t.Errorf("must gaps left open: %v", open)
	}

	// Held again — as the hub holds what an executor sent — nothing changes.
	before := strings.Join(titles(r), "\n")
	ApplyRequirements(r, gapSummary(), ForGaps, 0)
	if after := strings.Join(titles(r), "\n"); after != before {
		t.Errorf("held twice:\n%s\nonce:\n%s", after, before)
	}

	// A limit bounds the tasks added for must gaps too.
	r = &Result{Request: RequirementsRequest, Suggestions: []*Suggestion{{ID: 1, Title: "Paginate", Requirements: requirements.LooseRefs{2}}}}
	ApplyRequirements(r, gapSummary(), ForGaps, 2)
	if len(r.Suggestions) != 2 || len(Uncovered(r, gapSummary())) != 1 {
		t.Errorf("with a limit of 2: %v", titles(r))
	}
}

// A brainstorm with must gaps open closes them before any new feature.
func TestApplyRequirementsForIdeas(t *testing.T) {
	r := &Result{Suggestions: []*Suggestion{
		{ID: 1, Title: "Dark mode", Effort: EffortS},
		{ID: 2, Title: "Sign the audit log", Effort: EffortM, Requirements: requirements.LooseRefs{3}},
		{ID: 3, Title: "Session expiry tweak", Requirements: requirements.LooseRefs{5}},
	}}
	NormalizeIdeas(r, 0)
	ApplyRequirements(r, gapSummary(), ForIdeas, 0)
	// An idea that links a requirement lacking a test is not taken to write
	// nothing but the test: only a task by template, or a plan's, is.
	want := []string{
		"1:Sign the audit log:[3]::P1:[]",
		"2:Restore R-1: Config errors exit 2:[1]:fix:P1:[]",
		"3:Dark mode:[]::P3:[]",
	}
	if got := titles(r); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the ideas\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A task by template is numbered past every suggestion kept: a dropped one
// leaves a gap, and a kept one may still depend on the number above it.
func TestApplyRequirementsNumbersATemplateAfterEveryKeptTask(t *testing.T) {
	r := &Result{Request: RequirementsRequest, Suggestions: []*Suggestion{
		{ID: 1, Title: "Sessions", Requirements: requirements.LooseRefs{5}},
		{ID: 2, Title: "Sessions again", Requirements: requirements.LooseRefs{5}},
		{ID: 3, Title: "Paginate", Requirements: requirements.LooseRefs{2}},
		{ID: 4, Title: "Restore R-1", Requirements: requirements.LooseRefs{1}},
		{ID: 5, Title: "After the restore", Requirements: requirements.LooseRefs{2}, DependsOn: []int{4}},
	}}
	NormalizePlan(r, 0)
	ApplyRequirements(r, gapSummary(), ForGaps, 0)
	var after []int
	byTitle := map[string]*Suggestion{}
	for _, s := range r.Suggestions {
		byTitle[s.Title] = s
	}
	restore, then := byTitle["Restore R-1"], byTitle["After the restore"]
	if restore == nil || then == nil {
		t.Fatalf("the plan %v", titles(r))
	}
	after = then.DependsOn
	if fmt.Sprint(after) != fmt.Sprint([]int{restore.ID}) {
		t.Errorf("%q depends on %v, want the restore's %d:\n%s", then.Title, after, restore.ID, strings.Join(titles(r), "\n"))
	}
}

// A request's plan keeps its order and its tasks; only its links are held.
func TestApplyRequirementsForARequest(t *testing.T) {
	r := &Result{Request: "add OAuth", Suggestions: []*Suggestion{
		{ID: 1, Title: "Config", Requirements: requirements.LooseRefs{6, 7, 1}},
		{ID: 2, Title: "Callback", Requirements: requirements.LooseRefs{5}, DependsOn: []int{1}},
	}}
	NormalizePlan(r, 0)
	ApplyRequirements(r, gapSummary(), ForRequest, 0)
	want := []string{"1:Config:[1]:fix:P0:[]", "2:Callback:[5]::P0:[1]"}
	if got := titles(r); strings.Join(got, "\n") != strings.Join(want, "\n") || len(r.Notes) != 0 {
		t.Errorf("the plan\n%s\nwant\n%s\nnotes %v", strings.Join(got, "\n"), strings.Join(want, "\n"), r.Notes)
	}

	// Without approved requirements nothing is linked, whatever the model says.
	r = &Result{Suggestions: []*Suggestion{{ID: 1, Title: "x", Requirements: requirements.LooseRefs{1}, Kind: "fix", Priority: 1}}}
	ApplyRequirements(r, requirements.StatusSummary{}, ForIdeas, 0)
	if s := r.Suggestions[0]; s.Requirements != nil || s.Kind != "" || s.Priority != 0 {
		t.Errorf("a project without requirements kept %+v", s)
	}
}

func TestLedgerAddsTasksLinkedToWhatTheyClose(t *testing.T) {
	r := &Result{Request: RequirementsRequest, Suggestions: []*Suggestion{
		{ID: 1, Title: "Sign the audit log", Requirements: requirements.LooseRefs{3}},
		{ID: 2, Title: "Paginate exports", Requirements: requirements.LooseRefs{2}, DependsOn: []int{1}},
		{ID: 3, Title: "Tidy up"},
	}}
	NormalizePlan(r, 0)
	ApplyRequirements(r, gapSummary(), ForGaps, 0)
	plan := &pm.Plan{Tasks: []*pm.Task{{ID: 7, Title: "Expire sessions", Status: pm.TaskPending, Priority: 3, Requirements: []int{5}}}}
	l := NewLedger(r)
	added := l.Apply(plan, r.Suggestions)
	var got []string
	for _, t := range added {
		got = append(got, fmt.Sprintf("#%d %s P%d %v %v %s %v", t.ID, t.Title, t.Priority, t.Requirements, t.Tags, t.Role, t.DependsOn))
	}
	want := []string{
		"#8 Sign the audit log P1 [3] [requirement test-only] testing []",
		"#9 Restore R-1: Config errors exit 2 P1 [1] [requirement]  []",
		"#10 Paginate exports P2 [2] [requirement]  [8]",
		"#11 Tidy up P4 [] []  []", // the queue's tail
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("added\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if fmt.Sprint(l.Added()) != "[1 2 3 4]" {
		t.Errorf("Added = %v", l.Added())
	}
}
