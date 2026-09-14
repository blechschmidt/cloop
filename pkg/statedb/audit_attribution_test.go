package statedb

// The audit trail has to carry executor attribution (Task 20244).
//
// It does so structurally rather than by naming the fields: auditTaskUpsert
// marshals the whole pm.Task, so a new field lands in the payload for free.
// "For free" is exactly why it needs a test — nothing in the emitter mentions
// these fields, so nothing there would break if they stopped arriving, and the
// payload also passes through redaction on its way out. An attribution that is
// silently redacted or dropped leaves the trail answering the
// no-host-execution question with a confident blank.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

func TestAuditPayloadCarriesExecutorAttribution(t *testing.T) {
	db := newAuditDB(t)

	st := &State{
		Goal:    "attribution reaches the trail",
		WorkDir: t.TempDir(),
		Status:  "running",
		Plan: &pm.Plan{Goal: "attribution", Version: 1, Tasks: []*pm.Task{{
			ID: 1, Title: "ran on the host", Status: pm.TaskInProgress,
			ExecutorID: "local", ExecutorKind: "localprocess", Isolation: "none",
		}}},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := db.SaveState(st); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	rows, _, err := db.ListAuditEvents(AuditFilter{EntityType: "task"})
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	var payload map[string]any
	found := false
	for _, r := range rows {
		if r.EventType != "task.upsert" {
			continue
		}
		if err := json.Unmarshal([]byte(r.Payload), &payload); err != nil {
			t.Fatalf("decode audit payload %q: %v", r.Payload, err)
		}
		found = true
		break
	}
	if !found {
		t.Fatal("no task.upsert audit row for a newly attributed task")
	}

	for field, want := range map[string]string{
		"executor_id":   "local",
		"executor_kind": "localprocess",
		"isolation":     "none",
	} {
		got, ok := payload[field]
		if !ok {
			t.Errorf("audit payload has no %q — the trail cannot answer "+
				"'what ran on the host' for this task", field)
			continue
		}
		if got != want {
			t.Errorf("audit payload %q = %v, want %q (a redacted or rewritten "+
				"value is as unusable here as a missing one)", field, got, want)
		}
	}
}

// TestAuditReEmitsOnReplacement: the emitter only writes a row when a task's
// payload changes, so attribution has to be part of what "changed" means.
// Moving a task from one executor to another with everything else identical
// must produce a new row — otherwise a re-placement is invisible in the trail.
func TestAuditReEmitsWhenAttributionChanges(t *testing.T) {
	db := newAuditDB(t)

	task := &pm.Task{
		ID: 1, Title: "same task", Description: "unchanged", Status: pm.TaskInProgress,
		ExecutorID: "docker-1", ExecutorKind: "container", Isolation: "container",
	}
	st := &State{
		Goal:      "re-placement",
		WorkDir:   t.TempDir(),
		Status:    "running",
		Plan:      &pm.Plan{Goal: "re-placement", Version: 1, Tasks: []*pm.Task{task}},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := db.SaveState(st); err != nil {
		t.Fatalf("first save: %v", err)
	}
	baseline := countAudit(t, db, "task.upsert")

	// A save that changes nothing must stay silent — the amplification
	// property Task 20218 established, re-checked here so the assertion below
	// is about attribution rather than about every save emitting.
	if err := db.SaveState(st); err != nil {
		t.Fatalf("no-op save: %v", err)
	}
	if got := countAudit(t, db, "task.upsert"); got != baseline {
		t.Fatalf("a no-op save emitted %d extra rows", got-baseline)
	}

	// Now move it to the host, changing nothing else.
	task.ExecutorID = "local"
	task.ExecutorKind = "localprocess"
	task.Isolation = "none"
	if err := db.SaveState(st); err != nil {
		t.Fatalf("re-placed save: %v", err)
	}
	if got := countAudit(t, db, "task.upsert"); got != baseline+1 {
		t.Errorf("moving a task from a container to the host emitted %d rows, want 1 — "+
			"a re-placement that leaves no audit row is a host execution nobody can find",
			got-baseline)
	}
}
