package projectseed

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Task 20357: a run on a device reviews its tasks there, and the verdict — why
// a task whose agent said TASK_DONE failed, what was pushed — has to come back
// with the outcome, bounded and redacted like the rest of it.
func TestMergeCarriesTheReviewBack(t *testing.T) {
	now := time.Now().UTC()
	review := &pm.TaskReview{
		Verdict: pm.ReviewChangesRequested, Mode: pm.ReviewModeBlock, Blocked: true, Model: "claude-opus-5-5",
		Rounds: 1, Summary: "Leaks ghs_SECRETTOKEN into the log.", ReviewedAt: now,
		Findings:  []pm.ReviewFinding{{Severity: "blocker", Title: "token ghs_SECRETTOKEN printed"}},
		Published: []pm.ReviewPublish{{Repo: ".", Remote: "origin", Ref: "refs/heads/main", Outcome: pm.PublishWithheld}},
	}
	st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{{ID: 1, Title: "a", Status: pm.TaskPending}}}}
	tc := TaskChange{
		Before: &pm.Task{ID: 1, Title: "a", Status: pm.TaskPending},
		After: &pm.Task{ID: 1, Title: "a", Status: pm.TaskFailed, FailureDiagnosis: "blocked",
			StartedAt: ptrTime(now.Add(-time.Minute)), CompletedAt: ptrTime(now), Review: review},
	}
	scrub := func(s string) string { return strings.ReplaceAll(s, "ghs_SECRETTOKEN", "[REDACTED]") }
	Merge(st, &Result{Format: 1, Tasks: []TaskChange{tc}}, Provenance{}, scrub, now)

	got := st.Plan.TaskByID(1).Review
	if got == nil || got.Verdict != pm.ReviewChangesRequested || !got.Blocked || len(got.Published) != 1 {
		t.Fatalf("review did not come back: %+v", got)
	}
	if strings.Contains(got.Summary, "ghs_") || strings.Contains(got.Findings[0].Title, "ghs_") {
		t.Errorf("the lease's secret survived the merge: %+v", got)
	}
	if review.Summary == got.Summary {
		t.Error("the merge redacted the run's own record in place instead of a copy")
	}
}

func TestSanitizeReviewDropsUnknownVerdicts(t *testing.T) {
	id := func(s string) string { return s }
	if sanitizeReview(&pm.TaskReview{Verdict: "lgtm"}, id) != nil {
		t.Error("a verdict this build does not know was kept")
	}
	r := sanitizeReview(&pm.TaskReview{Verdict: pm.ReviewApproved, Rounds: 1e6, Model: strings.Repeat("m", 500),
		Summary: strings.Repeat("s", 10000)}, id)
	if r == nil || r.Rounds != 100 || len(r.Model) > 140 || len(r.Summary) > 2100 {
		t.Errorf("unbounded review kept: rounds %d, model %d, summary %d", r.Rounds, len(r.Model), len(r.Summary))
	}
}

// A device whose cloop predates the gate ignores it. Its result cannot be
// made reviewed after the fact, but it must not read as if it had been.
func TestMergeFlagsATaskAnOldDeviceRanUnreviewed(t *testing.T) {
	now := time.Now().UTC()
	st := &state.ProjectState{
		ReviewGate: &pm.ReviewGate{Enabled: true},
		Plan: &pm.Plan{Tasks: []*pm.Task{
			{ID: 1, Title: "a", Status: pm.TaskPending},
			{ID: 2, Title: "b", Status: pm.TaskPending},
		}},
	}
	done := func(id int, title string, review *pm.TaskReview) TaskChange {
		return TaskChange{
			Before: &pm.Task{ID: id, Title: title, Status: pm.TaskPending},
			After: &pm.Task{ID: id, Title: title, Status: pm.TaskDone, StartedAt: ptrTime(now.Add(-time.Minute)),
				CompletedAt: ptrTime(now), Review: review},
		}
	}
	rep, _ := Merge(st, &Result{Format: 1, Tasks: []TaskChange{
		done(1, "a", nil),
		done(2, "b", &pm.TaskReview{Verdict: pm.ReviewApproved, Mode: pm.ReviewModeFix}),
	}}, Provenance{}, nil, now)
	if len(rep.Unreviewed) != 1 || rep.Unreviewed[0] != 1 {
		t.Fatalf("unreviewed = %v, want [1]", rep.Unreviewed)
	}
	if !strings.Contains(rep.Summary(), "came back done without a review") {
		t.Errorf("the journal does not say so: %s", rep.Summary())
	}
	found := false
	for _, a := range st.Plan.TaskByID(1).Annotations {
		found = found || strings.Contains(a.Text, "predates the review gate")
	}
	if !found {
		t.Error("the unreviewed task carries no note")
	}

	// With the gate off nothing is flagged.
	st2 := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{{ID: 1, Title: "a", Status: pm.TaskPending}}}}
	if rep, _ := Merge(st2, &Result{Format: 1, Tasks: []TaskChange{done(1, "a", nil)}}, Provenance{}, nil, now); len(rep.Unreviewed) != 0 {
		t.Errorf("flagged with the gate off: %v", rep.Unreviewed)
	}
}
