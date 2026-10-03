package statedb

import (
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// Task 20357. The review record is a new plan_tasks column, and an older hub
// sharing the control plane must keep opening the database.
func TestTaskReviewMigrationIsAdditive(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	for _, m := range migrations {
		if m.Version != 53 {
			continue
		}
		if got := classifyMigration(string(m.SQL)); got != CompatAdditive {
			t.Fatalf("0053_task_review classified %q, want %q", got, CompatAdditive)
		}
		return
	}
	t.Fatal("migration 53 is not in the embedded set")
}

func TestTaskReview_SurvivesASaveRoundTrip(t *testing.T) {
	db := openTestDB(t)
	at := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	review := &pm.TaskReview{
		Verdict: pm.ReviewChangesRequested, Mode: pm.ReviewModeFix, Blocked: true,
		Provider: "anthropic", Model: "claude-opus-5-5", Rounds: 3, FixRounds: 2,
		Summary:    "Still broken.",
		Findings:   []pm.ReviewFinding{{Severity: "blocker", File: "a.go", Line: 4, Title: "panic"}},
		Repos:      []pm.ReviewedRepo{{Path: ".", Base: "aaa", Head: "bbb", Files: 2, Commits: 1}},
		Published:  []pm.ReviewPublish{{Repo: ".", Remote: "origin", Ref: "refs/heads/main", Outcome: pm.PublishWithheld}},
		ReviewedAt: at,
	}
	plan := &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "reviewed", Status: pm.TaskFailed, Review: review},
		{ID: 2, Title: "not reviewed", Status: pm.TaskPending},
	}}
	if err := db.SaveState(&State{Goal: "g", PMMode: true, Plan: plan}); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := db.LoadState()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	r := got.Plan.TaskByID(1).Review
	if r == nil || r.Verdict != pm.ReviewChangesRequested || !r.Blocked || r.FixRounds != 2 ||
		len(r.Findings) != 1 || r.Findings[0].Line != 4 || len(r.Published) != 1 || !r.ReviewedAt.Equal(at) {
		t.Fatalf("review came back as %+v", r)
	}
	if got.Plan.TaskByID(2).Review != nil {
		t.Error("an unreviewed task came back with a review")
	}
	one, err := db.LoadTask(1)
	if err != nil || one.Review == nil || one.Review.Model != "claude-opus-5-5" {
		t.Fatalf("LoadTask review = %+v, %v", one, err)
	}
}

func TestDecodeReviewToleratesJunk(t *testing.T) {
	for _, raw := range []string{"", "null", "{", `{"mode":"fix"}`} {
		if decodeReview(raw) != nil {
			t.Errorf("decodeReview(%q) produced a record", raw)
		}
	}
}

// The gate's settings are written on their own, so the dashboard changing them
// cannot write a stale copy of the tasks over a run's.
func TestSaveReviewGateTouchesNothingElse(t *testing.T) {
	db := openTestDB(t)
	plan := &pm.Plan{Goal: "g", Tasks: []*pm.Task{{ID: 1, Title: "t", Status: pm.TaskInProgress}}}
	if err := db.SaveState(&State{Goal: "g", PMMode: true, Plan: plan}); err != nil {
		t.Fatal(err)
	}
	gate := &pm.ReviewGate{Enabled: true, Provider: "openai", Model: "gpt-5", Mode: pm.ReviewModeBlock}
	if err := db.SaveReviewGate(gate); err != nil {
		t.Fatal(err)
	}
	got, err := db.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if got.ReviewGate == nil || *got.ReviewGate != *gate {
		t.Fatalf("gate = %+v", got.ReviewGate)
	}
	if got.Plan.TaskByID(1).Status != pm.TaskInProgress || got.Goal != "g" {
		t.Error("saving the gate changed the project")
	}

	// A full save from a copy that never saw the gate leaves it alone.
	if err := db.SaveState(&State{Goal: "g2", PMMode: true, Plan: plan}); err != nil {
		t.Fatal(err)
	}
	got, _ = db.LoadState()
	if got.ReviewGate == nil || !got.ReviewGate.Enabled {
		t.Error("a save without the gate switched it off")
	}
	// Switching it off is an explicit write.
	if err := db.SaveReviewGate(&pm.ReviewGate{Provider: "openai"}); err != nil {
		t.Fatal(err)
	}
	got, _ = db.LoadState()
	if got.ReviewGate == nil || got.ReviewGate.Enabled || got.ReviewGate.Provider != "openai" {
		t.Errorf("disabled gate = %+v", got.ReviewGate)
	}
}

// "Done means committed" is written on its own too (Task 20370), and a save
// from a copy that never saw it leaves it alone.
func TestSaveCommitPolicyTouchesNothingElse(t *testing.T) {
	db := openTestDB(t)
	plan := &pm.Plan{Goal: "g", Tasks: []*pm.Task{{ID: 1, Title: "t", Status: pm.TaskInProgress}}}
	if err := db.SaveState(&State{Goal: "g", PMMode: true, Plan: plan}); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveCommitPolicy(&pm.CommitPolicy{Enabled: true, Pushed: true}); err != nil {
		t.Fatal(err)
	}
	got, err := db.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if !got.CommitPolicy.RequiresPush() || got.Plan.TaskByID(1).Status != pm.TaskInProgress || got.Goal != "g" {
		t.Fatalf("after saving the policy: %+v, task %s", got.CommitPolicy, got.Plan.TaskByID(1).Status)
	}
	if err := db.SaveState(&State{Goal: "g2", PMMode: true, Plan: plan}); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.LoadStateLite(); !got.CommitPolicy.RequiresPush() {
		t.Error("a save without the policy switched it off")
	}
	if err := db.SaveCommitPolicy(&pm.CommitPolicy{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.LoadState(); got.CommitPolicy == nil || got.CommitPolicy.Active() {
		t.Errorf("disabled policy = %+v", got.CommitPolicy)
	}
}
