package statedb

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// TestAbortRoundTrip guards the persistence half of Task 20224.
//
// The finding is worth nothing if it dies with the process that made it. Worse,
// a clearance that does not survive means the sweep rediscovers the refusal on
// every iteration and reopens work that was verified as finished — so both the
// classification and the verdict have to come back intact.
func TestAbortRoundTrip(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	summary := "You've hit your limit · resets 2:50pm (UTC)"
	cleared := &pm.TaskAbort{
		Class:              "quota_exceeded",
		Reason:             "organisation monthly usage limit reached",
		Evidence:           "You've hit your org's monthly usage limit",
		DetectedAt:         time.Now().UTC().Truncate(time.Second),
		SummaryFingerprint: pm.FingerprintSummary("You've hit your org's monthly usage limit"),
	}
	cleared.Clear("triage", "re-landed by Task 20103 (pkg/apierror)")

	tasks := []*pm.Task{
		{ID: 194, Title: "watch-deps", Status: pm.TaskPending, Result: summary, Abort: &pm.TaskAbort{
			Class:              "usage_limit",
			Reason:             "subscription limit reached",
			Evidence:           summary,
			DetectedAt:         time.Now().UTC().Truncate(time.Second),
			SummaryFingerprint: pm.FingerprintSummary(summary),
		}},
		{ID: 20103, Title: "structured errors", Status: pm.TaskDone, Abort: cleared},
		// A task that never carried a record must read back nil, not an
		// empty struct — the UI keys its badge off the field's presence.
		{ID: 20224, Title: "the fix", Status: pm.TaskDone},
	}
	st := &State{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: tasks}}
	if err := db.SaveState(st); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	reloaded, err := db.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	loaded := reloaded.Plan.Tasks
	if len(loaded) != 3 {
		t.Fatalf("loaded %d tasks, want 3", len(loaded))
	}

	got := loaded[0].Abort
	if got == nil {
		t.Fatal("task 194 lost its abort record across a save/load")
	}
	if got.Class != "usage_limit" || got.Reason == "" || got.Evidence != summary {
		t.Errorf("task 194 record lost detail: %+v", got)
	}
	if got.SummaryFingerprint != pm.FingerprintSummary(summary) {
		t.Errorf("task 194 lost the digest binding it to its summary: %+v", got)
	}
	if got.Blocks() != true {
		t.Error("task 194's uncleared record must still block")
	}

	back := loaded[1].Abort
	if back == nil {
		t.Fatal("task 20103 lost its cleared record; the sweep would reopen finished work")
	}
	if !back.Cleared || back.ClearedBy != "triage" || back.ClearedNote == "" || back.ClearedAt == nil {
		t.Errorf("clearance did not survive: %+v", back)
	}
	if back.Blocks() {
		t.Error("a cleared record must not block completion after a reload")
	}

	if loaded[2].Abort != nil {
		t.Errorf("a task with no record must read back nil, got %+v", loaded[2].Abort)
	}

	// Single-task load takes a different query; it must agree.
	one, err := db.LoadTask(194)
	if err != nil {
		t.Fatalf("LoadTask: %v", err)
	}
	if one.Abort == nil || one.Abort.Class != "usage_limit" {
		t.Errorf("LoadTask lost the record: %+v", one.Abort)
	}

	// Clearing the field must actually clear it, not leave the old JSON.
	tasks[0].Abort = nil
	if err := db.SaveState(st); err != nil {
		t.Fatalf("SaveState (cleared): %v", err)
	}
	again, err := db.LoadTask(194)
	if err != nil {
		t.Fatalf("LoadTask (cleared): %v", err)
	}
	if again.Abort != nil {
		t.Errorf("discarded record came back: %+v", again.Abort)
	}
}

func TestDecodeAbortTolerance(t *testing.T) {
	// A malformed or classless value must degrade to "no record" rather than
	// failing the load — refusing to open a project because one diagnostic
	// blob is corrupt trades a cosmetic loss for a total one.
	for _, raw := range []string{"", "null", "{", "not json", `{"reason":"x"}`, `[]`} {
		if got := decodeAbort(raw); got != nil {
			t.Errorf("decodeAbort(%q) = %+v, want nil", raw, got)
		}
	}
	if got := decodeAbort(`{"class":"usage_limit","reason":"r"}`); got == nil || got.Class != "usage_limit" {
		t.Errorf("decodeAbort dropped a valid record: %+v", got)
	}
	if encodeAbort(nil) != "" {
		t.Error("a nil record must encode to the empty string, not \"null\"")
	}
}
