package statedb

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// Task 20362. A run that stops because a full save failed records why with
// this, so it must change the status and nothing else: what the run could not
// store stays as the last successful save left it.
func TestSaveRunStatusTouchesNothingElse(t *testing.T) {
	db := openTestDB(t)
	plan := &pm.Plan{Goal: "g", Tasks: []*pm.Task{{ID: 1, Title: "t", Status: pm.TaskInProgress}}}
	if err := db.SaveState(&State{Goal: "g", Status: "running", PMMode: true, Plan: plan, CurrentStep: 3}); err != nil {
		t.Fatal(err)
	}

	reason := pausereason.New(pausereason.CodeStateNotPersisted,
		"could not save task #1's completion (status done): database or disk is full")
	at := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	if err := db.SaveRunStatus("paused", &reason, at); err != nil {
		t.Fatalf("SaveRunStatus: %v", err)
	}

	got, err := db.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "paused" || got.PauseReason == nil || *got.PauseReason != reason {
		t.Fatalf("status = %q, reason = %+v", got.Status, got.PauseReason)
	}
	if !got.UpdatedAt.Equal(at) {
		t.Errorf("updated_at = %v, want %v", got.UpdatedAt, at)
	}
	if got.Goal != "g" || got.CurrentStep != 3 || got.Plan.TaskByID(1).Status != pm.TaskInProgress {
		t.Errorf("the status write changed the project: goal=%q step=%d task=%q",
			got.Goal, got.CurrentStep, got.Plan.TaskByID(1).Status)
	}

	// The audit trail records it as the state save it is, with only what it
	// changed: a goal or counters it never read would be zeroes that look
	// like facts.
	rows, _, err := db.ListAuditEvents(AuditFilter{EventType: "state.save", Order: "desc", Limit: 1})
	if err != nil || len(rows) != 1 {
		t.Fatalf("state.save audit rows = %v, %v", rows, err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(rows[0].Payload), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["status"] != "paused" || payload["pause_code"] != string(pausereason.CodeStateNotPersisted) {
		t.Errorf("audit payload = %v", payload)
	}
	if _, ok := payload["goal"]; ok {
		t.Errorf("the status-only audit row claims a goal it never read: %v", payload)
	}

	// A status other than paused carries no reason, as with a full save.
	if err := db.SaveRunStatus("running", &reason, at); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.LoadState(); got.PauseReason != nil {
		t.Errorf("a running status kept the pause reason %+v", got.PauseReason)
	}
}
