package projectseed

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/state"
)

// TestRunningRunReportsItsPlan is the defect this file exists for (Task
// 50): a run on an executor that cannot read the hub's database plans in
// its own copy of the project, and until it reported the plan while it ran,
// the hub's copy — the one the dashboard renders — had nothing in it.
//
// The project that motivated it was started in pm mode with a goal and no
// tasks: the run planned twelve of them on the device and worked through them
// for twenty minutes, while the dashboard showed an empty project, and when
// the executor stopped answering the plan was lost with it.
func TestRunningRunReportsItsPlan(t *testing.T) {
	isolateHome(t)
	const secret = "ghp_s3cretTokenValue0123456789"
	scrub := redact.New(secret).String

	// The hub's copy at dispatch: a goal, and not one task.
	hub := hubProject(t, &state.ProjectState{
		Goal:        "Build an attested enclave and a client for it",
		Provider:    "claudecode",
		Status:      "initialized",
		CurrentStep: 2,
		Plan:        &pm.Plan{Goal: "Build an attested enclave and a client for it"},
	})
	seed := seedFromHub(t, hub)

	started := time.Now().Add(-3 * time.Minute).UTC()
	finished := time.Now().Add(-time.Minute).UTC()
	dev := onDevice(t, seed, func(dir string, st *state.ProjectState) {
		// `cloop run` plans, finishes the first task and starts the second —
		// and is still running: nothing here is an outcome.
		st.Plan.Tasks = append(st.Plan.Tasks,
			&pm.Task{ID: 1, Title: "Pin down the enclave protocol", Description: "read the blueprint",
				Priority: 1, Role: "review", Status: pm.TaskDone, Result: "documented; pushed with " + secret,
				StartedAt: &started, CompletedAt: &finished, ActualMinutes: 2},
			&pm.Task{ID: 2, Title: "Set up the Cargo workspace", Priority: 2, Role: "backend",
				Status: pm.TaskInProgress, StartedAt: &finished, DependsOn: []int{1}},
			&pm.Task{ID: 3, Title: "Implement the attested key exchange", Priority: 3, DependsOn: []int{2}},
		)
		st.AddStep(state.StepResult{Task: "Pin down the enclave protocol", Output: "a transcript", Time: finished})
		st.TotalInputTokens += 400
		st.TotalOutputTokens += 90
		st.Status = "running"
		if err := st.Save(); err != nil {
			t.Fatalf("device save: %v", err)
		}
		state.LogEvent(dir, state.EventRow{Timestamp: finished, Type: state.EventTaskDone, TaskID: 1,
			TaskTitle: "Pin down the enclave protocol", Step: 3, Message: "Task #1 done"})
		if err := cost.AppendLedger(dir, cost.LedgerEntry{Timestamp: finished, TaskID: 1,
			Provider: "claudecode", Model: "claude-opus-5", InputTokens: 400, OutputTokens: 90,
			EstimatedUSD: 12}); err != nil {
			t.Fatalf("device cost: %v", err)
		}
	})

	data, err := HarvestProgress(dev, seed, scrub)
	if err != nil {
		t.Fatalf("HarvestProgress: %v", err)
	}
	doc, err := DecodeResult(data)
	if err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	if !doc.Interim {
		t.Error("a progress report must say it is one, or the hub would take it for the run's outcome")
	}
	if len(doc.Tasks) != 3 {
		t.Fatalf("progress report carries %d tasks, want the 3 the run planned", len(doc.Tasks))
	}
	// Everything a report deliberately leaves to the run's own outcome: it is
	// made every few seconds, from a database the harness is still writing.
	switch {
	case len(doc.Steps) != 0:
		t.Errorf("progress report carries %d steps; a report is the plan only", len(doc.Steps))
	case len(doc.Events) != 0:
		t.Errorf("progress report carries %d journal events; a report is the plan only", len(doc.Events))
	case len(doc.Costs) != 0:
		t.Errorf("progress report carries %d cost rows; a report is the plan only", len(doc.Costs))
	case len(doc.Attachments) != 0:
		t.Errorf("progress report carries %d attachments; a report is the plan only", len(doc.Attachments))
	case doc.Status != "":
		t.Errorf("progress report claims the project status %q; the run has not ended", doc.Status)
	}

	// The hub folds it into its own copy — which is what the dashboard
	// renders, and what a lost run leaves behind.
	prov := Provenance{ExecutorID: "sgx-1", ExecutorKind: "remote", Isolation: "remote",
		RunID: "run_1", Identity: "sub:cli:root"}
	rep, err := Apply(hub, doc, prov, scrub)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(rep.Added) != 3 {
		t.Fatalf("merge added %v, want the 3 tasks the run planned", rep.Added)
	}
	st, err := state.LoadLite(hub)
	if err != nil {
		t.Fatalf("reload the hub's copy: %v", err)
	}
	if got := len(st.Plan.Tasks); got != 3 {
		t.Fatalf("the hub's plan holds %d tasks, want 3", got)
	}
	one := st.Plan.TaskByID(1)
	if one == nil || one.Status != pm.TaskDone {
		t.Fatalf("task #1 on the hub: %+v, want it done", one)
	}
	if strings.Contains(one.Result, secret) {
		t.Error("the leased credential reached the hub's plan unredacted")
	}
	if one.ExecutorID != "sgx-1" || one.Isolation != "remote" {
		t.Errorf("task #1 is attributed to %q/%q, want the executor the hub dispatched to",
			one.ExecutorID, one.Isolation)
	}
	if two := st.Plan.TaskByID(2); two == nil || two.Status != pm.TaskInProgress {
		t.Fatalf("task #2 on the hub: %+v, want it in progress", two)
	}
	if three := st.Plan.TaskByID(3); three == nil || three.Status != pm.TaskPending {
		t.Fatalf("task #3 on the hub: %+v, want it pending", three)
	}
	// The run is still going, so nothing about it is settled: the project's
	// status is whoever settles the run's to write, not a report's.
	if st.Status != "initialized" {
		t.Errorf("the project's status became %q from a progress report; only the run's end settles it", st.Status)
	}
	if st.StepCount != 0 {
		t.Errorf("the hub recorded %d steps from a progress report", st.StepCount)
	}
	if !strings.Contains(rep.Summary(), "last reported") {
		t.Errorf("the journal row does not say the plan came from a report while running: %q", rep.Summary())
	}
}

// TestProgressReportCannotCompleteTheProject holds the line the status rule
// exists for: a device that reports "complete" in a progress report — out of
// order, out of date, or lying — must not finish the project on the hub. Only
// the run's outcome, merged when the run ends, can.
func TestProgressReportCannotCompleteTheProject(t *testing.T) {
	isolateHome(t)
	hub := hubProject(t, &state.ProjectState{
		Goal:   "Keep going",
		Status: "running",
		Plan: &pm.Plan{Goal: "Keep going", Tasks: []*pm.Task{
			{ID: 1, Title: "The only task", Priority: 1, Status: pm.TaskPending},
		}},
	})
	st, err := state.LoadLite(hub)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	rep, _ := Merge(st, &Result{Format: ResultFormat, Interim: true, Status: "complete"},
		Provenance{ExecutorID: "sgx-1"}, nil, time.Now())
	if st.Status != "running" {
		t.Errorf("a progress report set the project's status to %q", st.Status)
	}
	if rep.StatusTo != "" {
		t.Errorf("a progress report reported a status change to %q", rep.StatusTo)
	}
}
