package cmd

import (
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/orchestrator"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// The summaries below are verbatim from cloop's own ledger — the tasks this
// command exists to find. See pkg/orchestrator/abort_test.go for the full
// corpus and the classifier that recognises it.
const (
	ledgerUsageLimit = "You've hit your limit · resets 2:50pm (UTC)"
	ledgerOrgQuota   = "You've hit your org's monthly usage limit"
	ledgerWeekly     = "You've hit your weekly limit · resets Aug 28, 10pm (UTC)"
	ledgerHarness    = "--dangerously-skip-permissions cannot be used with root/sudo privileges for security reasons"
)

func corruptedPlan() *pm.Plan {
	return &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 193, Title: "cloop task tdd", Status: pm.TaskDone, Result: ledgerUsageLimit},
			{ID: 20015, Title: "Web UI rate limits", Status: pm.TaskDone, Result: ledgerHarness},
			{ID: 20103, Title: "Structured error type", Status: pm.TaskDone, Result: ledgerOrgQuota},
			{ID: 20198, Title: "Hub control-plane metrics", Status: pm.TaskDone, Result: ledgerWeekly},
			// Real work — must never be flagged.
			{ID: 20199, Title: "Sealing-key DR", Status: pm.TaskDone, Result: "Implemented envelope encryption and added tests. TASK_DONE"},
			// A task that legitimately discusses limits.
			{ID: 20200, Title: "Rate limit the API", Status: pm.TaskDone,
				Result: "Added per-IP token-bucket limiting; 429 responses now carry Retry-After. All tests pass."},
			// Already visible as not-complete: not this command's business.
			{ID: 20201, Title: "Provenance", Status: pm.TaskFailed, Result: ledgerUsageLimit},
			{ID: 20202, Title: "Pending work", Status: pm.TaskPending},
		},
	}
}

func TestAuditPlanLedger_FindsOnlyCorruptedDoneTasks(t *testing.T) {
	findings := auditPlanLedger(corruptedPlan())

	want := map[int]orchestrator.AbortClass{
		193:   orchestrator.AbortUsageLimit,
		20015: orchestrator.AbortHarnessRefusal,
		20103: orchestrator.AbortQuotaExceeded,
		20198: orchestrator.AbortUsageLimit,
	}
	if len(findings) != len(want) {
		t.Fatalf("found %d task(s), want %d: %+v", len(findings), len(want), findings)
	}
	for _, f := range findings {
		wantClass, ok := want[f.TaskID]
		if !ok {
			t.Errorf("task #%d should not have been flagged (%s)", f.TaskID, f.Reason)
			continue
		}
		if f.Class != wantClass {
			t.Errorf("task #%d class = %q, want %q", f.TaskID, f.Class, wantClass)
		}
		if f.Evidence == "" {
			t.Errorf("task #%d has no evidence quoted — the report would not say what was seen", f.TaskID)
		}
	}
}

// TestAuditPlanLedger_EmptySummaryIsNotTheSignature guards the trap this
// command walked into on its first run against the real ledger: replaying the
// live classifier verbatim flagged 22 additional done tasks whose stored
// summary was simply empty. Live, an empty response is an abort. Stored, it
// only means no summary was recorded — true of plenty of tasks that genuinely
// shipped. --reopen would have thrown that work back on the queue.
func TestAuditPlanLedger_EmptySummaryIsNotTheSignature(t *testing.T) {
	plan := &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 174, Title: "Race detector CI pass", Status: pm.TaskDone, Result: ""},
			{ID: 20043, Title: "Convert projects into isolated tenants", Status: pm.TaskDone, Result: "   \n\t "},
		},
	}
	if findings := auditPlanLedger(plan); len(findings) != 0 {
		t.Errorf("an absent summary is not evidence of a refusal; flagged %+v", findings)
	}
}

func TestReopenLedgerTasks_ResetsToPending(t *testing.T) {
	dir := t.TempDir()
	s, err := state.Init(dir, "goal", 0)
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	s.PMMode = true
	s.Plan = corruptedPlan()
	// Give the corrupted tasks a completion stamp, as the bug did.
	stamp := time.Now()
	for _, task := range s.Plan.Tasks {
		if task.Status == pm.TaskDone {
			task.CompletedAt = &stamp
			task.ActualMinutes = 7
		}
	}
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	findings := auditPlanLedger(s.Plan)
	reopened := reopenLedgerTasks(dir, s, findings)
	if len(reopened) != 4 {
		t.Fatalf("reopened %d task(s), want 4: %v", len(reopened), reopened)
	}

	reloaded, err := state.Load(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	byID := map[int]*pm.Task{}
	for _, task := range reloaded.Plan.Tasks {
		byID[task.ID] = task
	}

	for _, id := range []int{193, 20015, 20103, 20198} {
		task := byID[id]
		if task == nil {
			t.Fatalf("task #%d vanished", id)
		}
		if task.Status != pm.TaskPending {
			t.Errorf("task #%d status = %q, want pending", id, task.Status)
		}
		if task.CompletedAt != nil {
			t.Errorf("task #%d still carries a completion timestamp", id)
		}
		if task.ActualMinutes != 0 {
			t.Errorf("task #%d still claims %d minutes of work", id, task.ActualMinutes)
		}
		found := false
		for _, ann := range task.Annotations {
			if ann.Author == "cloop" && len(ann.Text) > 0 {
				found = true
			}
		}
		if !found {
			t.Errorf("task #%d has no annotation explaining why it was reopened", id)
		}
	}

	// Genuine work must be untouched.
	if got := byID[20199].Status; got != pm.TaskDone {
		t.Errorf("task #20199 (real work) status = %q, want done", got)
	}
	if byID[20199].CompletedAt == nil {
		t.Error("task #20199 (real work) lost its completion timestamp")
	}
	if got := byID[20201].Status; got != pm.TaskFailed {
		t.Errorf("task #20201 was already failed; audit must leave it alone, got %q", got)
	}

	// Re-running finds nothing: the audit is idempotent.
	if again := auditPlanLedger(reloaded.Plan); len(again) != 0 {
		t.Errorf("second audit still reports %d task(s): %+v", len(again), again)
	}
}
