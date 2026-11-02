package requirements

// Where each approved requirement stands against the plan, and what closes
// its gap (Task 20463).

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func at(h int) time.Time { return t0.Add(time.Duration(h) * time.Hour) }

// standingProject is one approved requirement for each row of the decision
// table, with a draft and a deprecated one beside them.
func standingProject() ([]Requirement, map[int]LastCheck) {
	tested := []Test{{Command: "true"}}
	reqs := []Requirement{
		{ID: 1, Title: "Fails", Priority: PriorityMust, Tests: tested, UpdatedAt: at(0)},
		{ID: 2, Title: "Never checked, no task", Priority: PriorityShould, Tests: tested, UpdatedAt: at(0)},
		{ID: 3, Title: "Holds by the model's word", Priority: PriorityMust, UpdatedAt: at(0)},
		{ID: 4, Title: "Changed since it held", Priority: PriorityCould, Tests: tested, UpdatedAt: at(5)},
		{ID: 5, Title: "Holds", Tests: tested, UpdatedAt: at(0)},
		{ID: 6, Title: "A draft", Status: StatusDraft, Priority: PriorityMust, UpdatedAt: at(0)},
		{ID: 7, Title: "Deprecated", Status: StatusDeprecated, Priority: PriorityMust, UpdatedAt: at(0)},
		{ID: 8, Title: "Untested, nothing known", Priority: PriorityMust, UpdatedAt: at(0)},
	}
	fp := map[int]string{}
	for _, r := range reqs {
		fp[r.ID] = r.Fingerprint()
	}
	last := map[int]LastCheck{
		1: {Verdict: VerdictUnfulfilled, Summary: "test \"true\" failed (exit 1)", Fingerprint: fp[1], CheckedAt: at(2)},
		3: {Verdict: VerdictFulfilled, Fingerprint: fp[3], CheckedAt: at(2)},
		4: {Verdict: VerdictFulfilled, Fingerprint: "an earlier definition", CheckedAt: at(2)},
		5: {Verdict: VerdictFulfilled, Fingerprint: fp[5], CheckedAt: at(10)},
		6: {Verdict: VerdictUnfulfilled, Fingerprint: fp[6], CheckedAt: at(2)},
		7: {Verdict: VerdictUnfulfilled, Fingerprint: fp[7], CheckedAt: at(2)},
	}
	return reqs, last
}

func actions(sum StatusSummary) map[int]string {
	out := map[int]string{}
	for _, st := range sum.Requirements {
		out[st.ID] = st.Action
	}
	return out
}

func TestStandingsLeaveOutDraftsAndDeprecatedRequirements(t *testing.T) {
	reqs, last := standingProject()
	st := Standings(reqs, last)
	var ids []int
	for _, s := range st {
		ids = append(ids, s.ID)
	}
	// Must first, then should, could and none; by id within each.
	if fmt.Sprint(ids) != "[1 3 8 2 4 5]" {
		t.Errorf("standings %v, want [1 3 8 2 4 5]: approved only, most important first", ids)
	}
	sum := Summarize(st, nil)
	for _, id := range []int{6, 7} {
		if _, ok := sum.Lookup(id); ok {
			t.Errorf("R-%d has a standing", id)
		}
	}
	if s, _ := sum.Lookup(4); !s.Earlier || s.Verdict != VerdictFulfilled {
		t.Errorf("a verdict about an earlier definition: %+v", s)
	}
}

func TestAssessDecidesWhatClosesEachGap(t *testing.T) {
	reqs, last := standingProject()
	st := Standings(reqs, last)

	sum := Summarize(st, nil)
	want := map[int]string{1: ActionFix, 2: ActionImplement, 3: ActionTest, 4: ActionVerify, 5: ActionNone, 8: ActionImplement}
	if got := actions(sum); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("with no tasks: %v, want %v", got, want)
	}
	if got := fmt.Sprint(sum.Requirements[0].Gaps); got != "[unfulfilled unlinked]" {
		t.Errorf("R-1's gaps %s", got)
	}
	if s, _ := sum.Lookup(8); fmt.Sprint(s.Gaps) != "[untested unlinked unchecked]" {
		t.Errorf("R-8's gaps %v", s.Gaps)
	}

	// An open task covers what it links; work finished since a verdict waits
	// for a check; a test written since waits for a person; a failed attempt
	// waits for a person.
	tasks := []TaskView{
		{ID: 10, Status: "pending", Requirements: []int{1}},
		{ID: 11, Status: "done", CompletedAt: at(6), Requirements: []int{2}},
		{ID: 12, Status: "done", CompletedAt: at(3), Requirements: []int{3}},
		{ID: 13, Status: "failed", CompletedAt: at(7), Requirements: []int{4}},
		{ID: 14, Status: "done", CompletedAt: at(1), Requirements: []int{8}},
	}
	sum = Summarize(st, tasks)
	want = map[int]string{1: ActionCovered, 2: ActionCheck, 3: ActionAttachTest, 4: ActionStuck, 5: ActionNone, 8: ActionAttachTest}
	if got := actions(sum); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("with tasks: %v, want %v", got, want)
	}
	if s, _ := sum.Lookup(1); fmt.Sprint(s.Open) != "[10]" {
		t.Errorf("R-1's open tasks %v", s.Open)
	}
	if s, _ := sum.Lookup(4); fmt.Sprint(s.Failed) != "[13]" {
		t.Errorf("R-4's failed tasks %v", s.Failed)
	}
	// R-5 held at hour 10; nothing finished after it.
	if s, _ := sum.Lookup(5); slices.Contains(s.Gaps, GapStale) {
		t.Errorf("R-5 is stale with no task finished since its check: %v", s.Gaps)
	}
	if fmt.Sprint(len(sum.Targets())) != "0" {
		t.Errorf("targets %+v", sum.Targets())
	}
}

func TestAssessWorkBeforeTheVerdictDoesNotCount(t *testing.T) {
	reqs, last := standingProject()
	// R-1 was worked on at hour 1 and checked unfulfilled at hour 2: it broke
	// again, and needs a fix — not a check.
	sum := Summarize(Standings(reqs, last), []TaskView{{ID: 9, Status: "done", CompletedAt: at(1), Requirements: []int{1}}})
	if s, _ := sum.Lookup(1); s.Action != ActionFix || fmt.Sprint(s.Done) != "[9]" {
		t.Errorf("R-1: %+v", s)
	}
	// A task finished after R-5's check makes it stale: a check would say,
	// not a task.
	sum = Summarize(Standings(reqs, last), []TaskView{{ID: 9, Status: "done", CompletedAt: at(11)}})
	if s, _ := sum.Lookup(5); s.Action != ActionCheck || !slices.Contains(s.Gaps, GapStale) {
		t.Errorf("R-5 after a later task: %+v", s)
	}
}

// Every way a task can stop being open is an attempt, and none makes its
// requirement a target again on its own: that is what keeps auto-evolve from
// adding the same task round after round.
func TestAssessAttemptsStopPlanningUntilSomethingNewIsKnown(t *testing.T) {
	reqs, last := standingProject()
	for _, c := range []struct {
		name   string
		task   TaskView
		id     int
		action string
	}{
		{"a fix marked done by hand, with no completion time", TaskView{ID: 9, Status: "done", Requirements: []int{1}}, 1, ActionStuck},
		{"an implementation marked done by hand", TaskView{ID: 9, Status: "done", Requirements: []int{2}}, 2, ActionCheck},
		{"a test written, marked done by hand", TaskView{ID: 9, Status: "done", Requirements: []int{3}}, 3, ActionAttachTest},
		{"a template the tag filter skipped", TaskView{ID: 9, Status: "skipped", CompletedAt: at(3), Requirements: []int{1}}, 1, ActionStuck},
		{"a skipped task with no time", TaskView{ID: 9, Status: "skipped", Requirements: []int{8}}, 8, ActionStuck},
		{"a timed-out fix", TaskView{ID: 9, Status: "timed_out", CompletedAt: at(3), Requirements: []int{1}}, 1, ActionStuck},
	} {
		sum := Summarize(Standings(reqs, last), []TaskView{c.task})
		if st, _ := sum.Lookup(c.id); st.Action != c.action {
			t.Errorf("%s: R-%d is %q, want %q", c.name, c.id, st.Action, c.action)
		}
	}

	// The requirements gate checks every must requirement at every task: a
	// failure confirmed by a later check stays one a person looks at.
	failedFix := TaskView{ID: 9, Status: "failed", CompletedAt: at(3), Requirements: []int{1}}
	later := map[int]LastCheck{}
	for id, c := range last {
		later[id] = c
	}
	c := later[1]
	c.CheckedAt = at(4)
	later[1] = c
	if st, _ := Summarize(Standings(reqs, later), []TaskView{failedFix}).Lookup(1); st.Action != ActionStuck {
		t.Errorf("a failed fix, checked failing again since: %q, want stuck", st.Action)
	}
	// Found to hold after the failed attempt and failing again: a new
	// regression, a target again.
	c.HeldAt, c.CheckedAt = at(5), at(6)
	later[1] = c
	if st, _ := Summarize(Standings(reqs, later), []TaskView{failedFix}).Lookup(1); st.Action != ActionFix {
		t.Errorf("a regression after a failed fix and a pass: %q, want fix", st.Action)
	}
	// Changed after the failed attempt: a target again.
	changed := slices.Clone(reqs)
	changed[0].UpdatedAt = at(4)
	if st, _ := Summarize(Standings(changed, last), []TaskView{failedFix}).Lookup(1); st.Action != ActionFix {
		t.Errorf("changed since the failed fix: %q, want fix", st.Action)
	}
}

func TestMustGapsAreMustTargets(t *testing.T) {
	reqs, last := standingProject()
	sum := Summarize(Standings(reqs, last), nil)
	var keys []string
	for _, st := range sum.MustGaps() {
		keys = append(keys, st.Key())
	}
	// R-6 is a must draft and R-7 a must deprecated requirement: neither.
	if fmt.Sprint(keys) != "[R-1 R-3 R-8]" {
		t.Errorf("must gaps %v", keys)
	}
}

func TestStatusSummaryTravelsBoundedAndReadsBack(t *testing.T) {
	reqs, last := standingProject()
	sum := Summarize(Standings(reqs, last), []TaskView{{ID: 10, Status: "pending", Requirements: []int{5}}})
	raw, err := sum.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseStatusSummary(raw)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(actions(back)) != fmt.Sprint(actions(sum)) || back.Omitted != 0 {
		t.Errorf("read back %+v", back)
	}

	// Too many to fit: the least pressing go, counted.
	var many []Requirement
	for i := 1; i <= 600; i++ {
		many = append(many, Requirement{ID: i, Title: strings.Repeat("x", 280) + fmt.Sprint(i), Tests: []Test{{Command: "true"}}})
	}
	big := Summarize(Standings(many, nil), nil)
	raw, err = big.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > MaxStatusBytes {
		t.Fatalf("encoded %d bytes", len(raw))
	}
	back, err = ParseStatusSummary(raw)
	if err != nil {
		t.Fatal(err)
	}
	if back.Omitted == 0 || len(back.Requirements)+back.Omitted != 600 {
		t.Errorf("kept %d, omitted %d of 600", len(back.Requirements), back.Omitted)
	}

	// A newer hub's fields, gaps and actions are passed over.
	if s, err := ParseStatusSummary([]byte(`{"requirements":[{"id":3,"title":"t","gaps":["untested","new-gap"],` +
		`"action":"new-action","colour":"red"}],"later":1}`)); err != nil || s.Requirements[0].Action != ActionNone ||
		fmt.Sprint(s.Requirements[0].Gaps) != "[untested]" {
		t.Errorf("a newer hub's summary: %+v, %v", s, err)
	}
	// So are a priority and a verdict it does not know: as none.
	if s, err := ParseStatusSummary([]byte(`{"requirements":[{"id":1,"title":"t","priority":"urgent","verdict":"maybe",` +
		`"checked_at":"2026-10-01T00:00:00Z"}]}`)); err != nil || s.Requirements[0].Priority != "" ||
		s.Requirements[0].Verdict != "" || !s.Requirements[0].CheckedAt.IsZero() {
		t.Errorf("a newer hub's priority and verdict: %+v, %v", s, err)
	}
	for _, bad := range []string{
		`{"requirements":[{"id":0,"title":"t"}]}`,
		`{"requirements":[{"id":1,"title":""}]}`,
		`{"requirements":[{"id":1,"title":"a\nb"}]}`,
		`{"requirements":[{"id":1,"title":"t"},{"id":1,"title":"u"}]}`,
		`{"requirements":[{"id":1,"title":"t","open_tasks":[-1]}]}`,
		`[1,2]`,
	} {
		if _, err := ParseStatusSummary([]byte(bad)); !errors.Is(err, ErrInvalid) {
			t.Errorf("ParseStatusSummary(%s) = %v, want an ErrInvalid", bad, err)
		}
	}
}

// On a device the run's own checks are laid over what the seed carried, and
// everything else is the seed's.
func TestMergeStandingsTakesOnlyNewerChecks(t *testing.T) {
	facts := []Standing{
		{ID: 1, Title: "One", Priority: PriorityMust, Tested: true, ChangedAt: at(0), Verdict: VerdictUnfulfilled, CheckedAt: at(2)},
		{ID: 2, Title: "Two", Tested: true, ChangedAt: at(0), Verdict: VerdictFulfilled, CheckedAt: at(5)},
	}
	local := []Standing{
		// Seeded copies are written when the seed lands: their change time
		// says nothing.
		{ID: 1, Title: "One", Priority: PriorityMust, Tested: true, ChangedAt: at(9), Verdict: VerdictFulfilled, CheckedAt: at(8)},
		{ID: 2, Title: "Two", Tested: true, ChangedAt: at(9), Verdict: VerdictUnfulfilled, CheckedAt: at(4)},
		{ID: 3, Title: "Only here", ChangedAt: at(9)},
	}
	got, unknown := MergeStandings(facts, local)
	// R-3 is one the seed left out: its copy here says nothing of where it
	// stands, so it is not planned for.
	if len(got) != 2 || unknown != 1 || got[0].Verdict != VerdictFulfilled || !got[0].ChangedAt.Equal(at(0)) ||
		got[1].ID != 2 || got[1].Verdict != VerdictFulfilled {
		t.Errorf("merged %+v, %d unknown", got, unknown)
	}
}

func TestSectionSaysWhereTheSpecStands(t *testing.T) {
	reqs, last := standingProject()
	sum := Summarize(Standings(reqs, last), []TaskView{
		{ID: 10, Status: "pending", Requirements: []int{5}},
		{ID: 11, Status: "done", CompletedAt: at(6), Requirements: []int{2}},
	})
	s := sum.Section()
	for _, want := range []string{
		"## REQUIREMENTS — WHERE THE PROJECT'S SPEC STANDS",
		"6 approved: 2 fulfilled, 1 unfulfilled, 2 never checked, 3 stale, 2 without a test, 4 implemented by no task.",
		"- R-1 [must] Fails — unfulfilled (test \"true\" failed (exit 1)); tasks finished since its last check; " +
			"no task implements it. To close it: a task that restores it.",
		"- R-3 [must] Holds by the model's word — tasks finished since its last check; no test; no task implements it; " +
			"it holds by the model's or a person's word. To close it: a task that only adds its test: it is believed to hold.",
		"- R-4 [could] Changed since it held — changed since it was last checked",
		"Being worked on — an open task implements it; plan nothing more for these: R-5 (#10).",
		"Waiting for a check, not a task",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the section lacks %q:\n%s", want, s)
		}
	}
	for _, never := range []string{"A draft", "Deprecated", "R-6", "R-7"} {
		if strings.Contains(s, never) {
			t.Errorf("the section names %q:\n%s", never, s)
		}
	}
	if (StatusSummary{}).Section() != "" {
		t.Error("a project without approved requirements gets a section")
	}
}

func TestFactsCarryNothingThePlanAdds(t *testing.T) {
	reqs, last := standingProject()
	sum := Summarize(Standings(reqs, last), []TaskView{{ID: 10, Status: "pending", Requirements: []int{1}}})
	raw, _ := json.Marshal(sum.Facts())
	for _, key := range []string{`"action"`, `"gaps"`, `"open_tasks"`} {
		if strings.Contains(string(raw), key) {
			t.Errorf("the facts carry %s: %s", key, raw)
		}
	}
}
