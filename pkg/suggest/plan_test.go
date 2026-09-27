package suggest

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/provider"
)

func TestBuildPlanPrompt_CarriesTheRequestAndTheCount(t *testing.T) {
	prompt := BuildPlanPrompt("Build a CLI", "Go only", "cmd/", "fix: x", "mem", "- [done] Task 1: setup",
		"Add OAuth login with GitHub and Google", 4)

	for _, want := range []string{
		"## REQUEST\nAdd OAuth login with GitHub and Google",
		"Break the request into exactly 4 tasks.",
		"PROJECT GOAL", "Build a CLI",
		"CONSTRAINTS", "Go only",
		"EXISTING TASKS", "Task 1: setup",
		`"depends_on":[1]`,
		"EARLIER tasks",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("plan prompt is missing %q", want)
		}
	}
}

// Leaving the count unset is the point of the feature: the plan is as long as
// the request needs. The prompt must say so, and must not smuggle a number in.
func TestBuildPlanPrompt_UnsetCountLeavesTheLengthToTheRequest(t *testing.T) {
	prompt := BuildPlanPrompt("goal", "", "", "", "", "", "Rename the config key", 0)

	if strings.Contains(prompt, "exactly") {
		t.Errorf("a plan of variable length must not ask for an exact count:\n%s", prompt)
	}
	for _, want := range []string{"as many tasks as it genuinely needs", "a small request may be a single task", "more than 20"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("plan prompt is missing %q", want)
		}
	}
	if strings.Contains(prompt, "CONSTRAINTS") || strings.Contains(prompt, "EXISTING TASKS") {
		t.Error("empty sections should be omitted")
	}
}

func TestCleanRequest(t *testing.T) {
	if got, err := CleanRequest("  plan this \n"); err != nil || got != "plan this" {
		t.Errorf("CleanRequest trims: got %q, %v", got, err)
	}
	if got, err := CleanRequest("   "); err != nil || got != "" {
		t.Errorf("a blank request is no request: got %q, %v", got, err)
	}
	if _, err := CleanRequest("a\x00b"); err == nil {
		t.Error("a NUL cannot travel in argv and must be refused")
	}
	if _, err := CleanRequest(strings.Repeat("é", MaxRequestRunes)); err != nil {
		t.Errorf("the limit counts characters, not bytes: %v", err)
	}
	if _, err := CleanRequest(strings.Repeat("x", MaxRequestRunes+1)); err == nil {
		t.Error("an over-long request must be refused")
	}
}

func ids(r *Result) []int {
	out := make([]int, len(r.Suggestions))
	for i, s := range r.Suggestions {
		out[i] = s.ID
	}
	return out
}

func TestNormalizePlan_RenumbersAndRemapsDependencies(t *testing.T) {
	// The model numbered from 10 and one task has no title.
	r := &Result{Suggestions: []*Suggestion{
		{ID: 10, Title: "schema"},
		{ID: 11, Title: "  "},
		{ID: 12, Title: "api", DependsOn: []int{10, 11}},
		{ID: 13, Title: "ui", DependsOn: []int{12, 10, 12}},
	}}
	NormalizePlan(r, 0)

	if got := ids(r); !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Fatalf("ids = %v, want [1 2 3]", got)
	}
	want := [][]int{nil, {1}, {1, 2}}
	for i, s := range r.Suggestions {
		if !reflect.DeepEqual(s.DependsOn, want[i]) {
			t.Errorf("task %d depends on %v, want %v — renumbered, the dropped task gone, duplicates collapsed", s.ID, s.DependsOn, want[i])
		}
	}
}

// Every edge must point backwards, whatever the model wrote, or accepting the
// plan could deadlock the queue.
func TestNormalizePlan_KeepsOnlyBackwardEdges(t *testing.T) {
	r := &Result{Suggestions: []*Suggestion{
		{ID: 1, Title: "a", DependsOn: []int{2}},    // forward
		{ID: 2, Title: "b", DependsOn: []int{2, 1}}, // self
		{ID: 3, Title: "c", DependsOn: []int{99}},   // unknown
	}}
	NormalizePlan(r, 0)

	want := [][]int{nil, {1}, nil}
	for i, s := range r.Suggestions {
		if !reflect.DeepEqual(s.DependsOn, want[i]) {
			t.Errorf("task %d depends on %v, want %v", s.ID, s.DependsOn, want[i])
		}
	}
}

func TestNormalizePlan_AmbiguousIDsResolveToNothing(t *testing.T) {
	r := &Result{Suggestions: []*Suggestion{
		{ID: 1, Title: "a"},
		{ID: 1, Title: "b"},
		{ID: 2, Title: "c", DependsOn: []int{1}},
	}}
	NormalizePlan(r, 0)
	if deps := r.Suggestions[2].DependsOn; len(deps) != 0 {
		t.Errorf("an ID two tasks share names neither, got depends_on %v", deps)
	}
	if got := ids(r); !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Errorf("ids = %v, want [1 2 3]", got)
	}
}

func TestNormalizePlan_Limits(t *testing.T) {
	mk := func(n int) *Result {
		r := &Result{}
		for i := 1; i <= n; i++ {
			r.Suggestions = append(r.Suggestions, &Suggestion{ID: i, Title: "t", DependsOn: []int{i - 1}})
		}
		return r
	}
	r := mk(6)
	NormalizePlan(r, 4)
	if len(r.Suggestions) != 4 {
		t.Errorf("asked for 4 tasks, kept %d", len(r.Suggestions))
	}
	r = mk(MaxCount + 5)
	NormalizePlan(r, 0)
	if len(r.Suggestions) != MaxCount {
		t.Errorf("a plan of unset length kept %d tasks, want the cap of %d", len(r.Suggestions), MaxCount)
	}
}

func TestNormalizePlan_IsIdempotent(t *testing.T) {
	r := &Result{Suggestions: []*Suggestion{
		{ID: 3, Title: "a"}, {ID: 5, Title: "b", DependsOn: []int{3}}, {ID: 9, Title: "c", DependsOn: []int{5, 3}},
	}}
	NormalizePlan(r, 0)
	var once [][]int
	for _, s := range r.Suggestions {
		once = append(once, append([]int(nil), s.DependsOn...))
	}
	NormalizePlan(r, 0)
	for i, s := range r.Suggestions {
		if s.ID != i+1 || !reflect.DeepEqual(append([]int(nil), s.DependsOn...), once[i]) {
			t.Errorf("second pass changed task %d: %v", i+1, s.DependsOn)
		}
	}
}

func TestNormalizeIdeas(t *testing.T) {
	r := &Result{Suggestions: []*Suggestion{
		{ID: 4, Title: "a", DependsOn: []int{1}}, {ID: 4, Title: ""}, {ID: 4, Title: "b"}, {Title: "c"},
	}}
	NormalizeIdeas(r, 2)
	if got := ids(r); !reflect.DeepEqual(got, []int{1, 2}) {
		t.Fatalf("ids = %v, want [1 2]: numbered, untitled dropped, capped at 2", got)
	}
	if r.Suggestions[0].DependsOn != nil {
		t.Error("ideas are independent; dependencies must be dropped")
	}
}

// scripted is a provider that returns one canned answer and records the prompt.
type scripted struct {
	out    string
	prompt string
}

func (s *scripted) Name() string         { return "scripted" }
func (s *scripted) DefaultModel() string { return "" }
func (s *scripted) Complete(_ context.Context, prompt string, _ provider.Options) (*provider.Result, error) {
	s.prompt = prompt
	return &provider.Result{Output: s.out}, nil
}

func TestGeneratePlan_NormalizesAndMarksTheResultAsAPlan(t *testing.T) {
	p := &scripted{out: "Here is the plan:\n```json\n" +
		`{"summary":"login","suggestions":[` +
		`{"id":1,"title":"Add provider config","category":"feature","effort":"s","depends_on":[]},` +
		`{"id":2,"title":"Callback handler","category":"feature","effort":"m","depends_on":[1,3]},` +
		`{"id":3,"title":"Login button","category":"ux","effort":"xs","depends_on":[2]}]}` + "\n```"}
	prompt := BuildPlanPrompt("goal", "", "", "", "", "", "Add OAuth login", 0)

	r, err := GeneratePlan(context.Background(), p, prompt, provider.Options{}, "Add OAuth login", 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Request != "Add OAuth login" {
		t.Errorf("Request = %q; it is what marks the result as a plan", r.Request)
	}
	if !reflect.DeepEqual(r.Suggestions[1].DependsOn, []int{1}) {
		t.Errorf("task 2 depends on %v; its forward reference to 3 must be dropped", r.Suggestions[1].DependsOn)
	}
	if !reflect.DeepEqual(r.Suggestions[2].DependsOn, []int{2}) {
		t.Errorf("task 3 depends on %v, want [2]", r.Suggestions[2].DependsOn)
	}
	if p.prompt != prompt {
		t.Error("the prompt given is the prompt sent")
	}
}
