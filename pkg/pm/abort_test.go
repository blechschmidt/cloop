package pm

import (
	"encoding/json"
	"testing"
	"time"
)

func doneWithAbort(id int, a *TaskAbort) *Task {
	return &Task{ID: id, Title: "t", Status: TaskDone, Abort: a}
}

func usageLimitRecord(summary string) *TaskAbort {
	return &TaskAbort{
		Class:              "usage_limit",
		Reason:             "subscription limit reached",
		Evidence:           summary,
		DetectedAt:         time.Now().UTC(),
		SummaryFingerprint: FingerprintSummary(summary),
	}
}

// TestIsComplete_UnverifiedAbortBlocks is the data-model half of Task 20224.
// A plan whose every task is marked done is not finished if one of those tasks
// never ran — answering otherwise is what let auto-evolve plan new work on top
// of features nobody had written.
func TestIsComplete_UnverifiedAbortBlocks(t *testing.T) {
	summary := "You've hit your limit · resets 2:50pm (UTC)"
	p := &Plan{Goal: "g", Tasks: []*Task{
		{ID: 1, Title: "real work", Status: TaskDone},
		doneWithAbort(2, usageLimitRecord(summary)),
	}}

	if p.IsComplete() {
		t.Error("IsComplete() = true although task 2's whole summary is a usage limit")
	}
	if got := len(p.UnverifiedAborts()); got != 1 {
		t.Errorf("UnverifiedAborts() returned %d tasks, want 1", got)
	}

	// Clearing it — the verdict that the work exists despite the summary —
	// unblocks completion but keeps the entry on the books.
	p.Tasks[1].Abort.Clear("triage", "re-landed by Task 20214")
	if !p.IsComplete() {
		t.Error("IsComplete() = false after the finding was cleared")
	}
	if got := len(p.UnverifiedAborts()); got != 0 {
		t.Errorf("UnverifiedAborts() returned %d tasks after clearance, want 0", got)
	}
	if got := len(p.AbortedOutcomes()); got != 1 {
		t.Errorf("AbortedOutcomes() returned %d tasks, want 1: a cleared entry is still a bad ledger entry", got)
	}
}

// TestIsComplete_AbortOnNonDoneTaskDoesNotBlock: once a task is reopened it is
// pending, and the ordinary pending rule is what keeps the plan open. The
// record stays attached as history and must not double-count.
func TestIsComplete_AbortOnNonDoneTaskDoesNotBlock(t *testing.T) {
	rec := usageLimitRecord("You've hit your limit")
	p := &Plan{Goal: "g", Tasks: []*Task{
		{ID: 1, Status: TaskSkipped, Abort: rec},
	}}
	if !p.IsComplete() {
		t.Error("a skipped task carrying an old abort record must not block completion")
	}
	if got := len(p.UnverifiedAborts()); got != 0 {
		t.Errorf("UnverifiedAborts() = %d, want 0: only done tasks are findings", got)
	}
}

func TestTaskAbort_BlocksNilSafe(t *testing.T) {
	var nilRec *TaskAbort
	if nilRec.Blocks() {
		t.Error("a nil record must not block — most tasks have none")
	}
	nilRec.Clear("x", "y") // must not panic
	if (&TaskAbort{}).Blocks() != true {
		t.Error("an uncleared record must block")
	}
}

func TestAbortAppliesTo(t *testing.T) {
	summary := "You've hit your weekly limit · resets Aug 28, 10pm (UTC)"
	rec := usageLimitRecord(summary)

	if !AbortAppliesTo(rec, summary) {
		t.Error("record does not match the summary it was derived from")
	}
	// Trailing whitespace is the same summary.
	if !AbortAppliesTo(rec, "\n  "+summary+"\t\n") {
		t.Error("digest is sensitive to surrounding whitespace")
	}
	// A re-run that produced real work must invalidate the record, clearance
	// and all — otherwise a stale verdict could mask a fresh refusal.
	if AbortAppliesTo(rec, "Implemented the feature.\nTASK_DONE") {
		t.Error("record still claims to describe a summary that has changed")
	}
	if AbortAppliesTo(nil, summary) {
		t.Error("nil record must not apply to anything")
	}
	if AbortAppliesTo(&TaskAbort{Class: "usage_limit"}, summary) {
		t.Error("a record with no digest must not be treated as matching")
	}
}

// TestTaskAbort_JSONRoundTrip pins the wire shape the Web UI reads.
func TestTaskAbort_JSONRoundTrip(t *testing.T) {
	rec := usageLimitRecord("You've hit your limit")
	rec.Clear("triage", "re-landed by Task 20214")

	raw, err := json.Marshal(&Task{ID: 7, Status: TaskDone, Abort: rec})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Task
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Abort == nil {
		t.Fatal("abort record lost across JSON")
	}
	if back.Abort.Class != "usage_limit" || back.Abort.Evidence == "" {
		t.Errorf("record lost detail: %+v", back.Abort)
	}
	if !back.Abort.Cleared || back.Abort.ClearedNote == "" || back.Abort.ClearedAt == nil {
		t.Errorf("clearance lost across JSON: %+v", back.Abort)
	}

	// A task with no record must not grow an empty one in the payload —
	// the field is read by the UI to decide whether to show a badge.
	plain, err := json.Marshal(&Task{ID: 8, Status: TaskDone})
	if err != nil {
		t.Fatalf("marshal plain: %v", err)
	}
	var plainBack map[string]any
	if err := json.Unmarshal(plain, &plainBack); err != nil {
		t.Fatalf("unmarshal plain: %v", err)
	}
	if _, present := plainBack["abort"]; present {
		t.Error("abort key emitted for a task that has no record")
	}
}
