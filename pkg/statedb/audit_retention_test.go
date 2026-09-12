package statedb

// Tests for the two halves of Task 20218: that a save no longer amplifies into
// one audit row per task, and that a pruned chain still verifies.
//
// The amplification test is the one that would have caught the original bug.
// It is written as a ratio rather than an exact count so it keeps failing for
// the right reason if the payload or the emitter changes: what matters is that
// N saves of an M-task plan cost O(changed), not O(N×M).

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// planWith builds a deterministic M-task plan.
func planWith(m int) *pm.Plan {
	p := &pm.Plan{Goal: "amplification", Version: 1}
	for i := 1; i <= m; i++ {
		p.Tasks = append(p.Tasks, &pm.Task{
			ID:          i,
			Title:       fmt.Sprintf("task %d", i),
			Description: "unchanged across saves",
			Priority:    5,
			Status:      pm.TaskPending,
		})
	}
	return p
}

func countAudit(t *testing.T, db *DB, eventType string) int {
	t.Helper()
	var n int
	q := `SELECT COUNT(*) FROM audit_events`
	args := []any{}
	if eventType != "" {
		q += ` WHERE event_type = ?`
		args = append(args, eventType)
	}
	if err := db.conn.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return n
}

// TestSaveStateEmitsOChangedNotONTimesM is the regression test for the
// measured bug: 417 tasks × one save per finished step produced 1,093,055
// task.upsert rows, 99.7% of the audit table.
func TestSaveStateEmitsOChangedNotONTimesM(t *testing.T) {
	const (
		tasks = 40
		saves = 25
	)
	db := newAuditDB(t)

	st := &State{
		Goal:      "amplification",
		WorkDir:   t.TempDir(),
		Status:    "running",
		Plan:      planWith(tasks),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	// First save establishes the baseline: every task is new to the trail, so
	// one row each. That is a real mutation, and it happens exactly once.
	if err := db.SaveState(st); err != nil {
		t.Fatalf("initial save: %v", err)
	}
	baseline := countAudit(t, db, "task.upsert")
	if baseline != tasks {
		t.Fatalf("baseline emitted %d task.upsert rows, want %d (one per new task)", baseline, tasks)
	}

	// Now save repeatedly without changing a single task. The old emitter
	// produced tasks×saves rows here; the fixed one must produce none.
	for i := 0; i < saves; i++ {
		st.CurrentStep = i + 1
		st.UpdatedAt = time.Now().UTC()
		if err := db.SaveState(st); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	afterNoOps := countAudit(t, db, "task.upsert")
	if afterNoOps != baseline {
		t.Errorf("%d no-op saves of a %d-task plan emitted %d extra task.upsert rows, want 0 "+
			"(old behaviour would have been %d)",
			saves, tasks, afterNoOps-baseline, saves*tasks)
	}

	// Change exactly one task and save. Exactly one row must appear.
	st.Plan.Tasks[3].Status = pm.TaskDone
	if err := db.SaveState(st); err != nil {
		t.Fatalf("save after change: %v", err)
	}
	if got := countAudit(t, db, "task.upsert"); got != baseline+1 {
		t.Errorf("one changed task emitted %d rows, want 1", got-baseline)
	}

	// Removing a task must be recorded once, as a delete.
	st.Plan.Tasks = st.Plan.Tasks[:tasks-1]
	if err := db.SaveState(st); err != nil {
		t.Fatalf("save after removal: %v", err)
	}
	if got := countAudit(t, db, "task.delete"); got != 1 {
		t.Errorf("removing one task emitted %d task.delete rows, want 1", got)
	}

	// The whole point is that the trail stayed small and still verifies.
	rep, err := db.VerifyAuditChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("chain broken at id %d: %s", rep.BreakAtID, rep.Reason)
	}
	// The whole table must be O(tasks + saves), not O(tasks × saves). The
	// per-save term is the plan-level `state.save` row, which is one per save
	// by design and is not amplification — on the measured hub it accounted
	// for 3,137 rows against task.upsert's 1,093,055.
	const totalBound = tasks + saves + 10
	if rep.Total > totalBound {
		t.Errorf("audit table holds %d rows after %d saves of a %d-task plan (bound %d); "+
			"O(N×M) would be ~%d", rep.Total, saves+3, tasks, totalBound, (saves+3)*tasks)
	}
}

// TestUpsertTaskKeepsFingerprintInStepWithSaveState guards the interaction
// that would silently drop a real change: a single-task write leaving a stale
// fingerprint that the next SaveState matches against.
func TestUpsertTaskKeepsFingerprintInStepWithSaveState(t *testing.T) {
	db := newAuditDB(t)
	plan := planWith(3)
	st := &State{Goal: "g", WorkDir: t.TempDir(), Plan: plan}
	if err := db.SaveState(st); err != nil {
		t.Fatalf("save: %v", err)
	}
	before := countAudit(t, db, "task.upsert")

	// Mutate through the single-task path.
	plan.Tasks[0].Title = "changed via UpsertTask"
	if err := db.UpsertTask(plan.Tasks[0]); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if got := countAudit(t, db, "task.upsert"); got != before+1 {
		t.Fatalf("UpsertTask emitted %d rows, want 1", got-before)
	}

	// A SaveState carrying the same content must now be a no-op: the
	// fingerprint UpsertTask wrote already describes it.
	if err := db.SaveState(st); err != nil {
		t.Fatalf("save after upsert: %v", err)
	}
	if got := countAudit(t, db, "task.upsert"); got != before+1 {
		t.Errorf("SaveState re-emitted %d rows for content UpsertTask already recorded", got-(before+1))
	}

	// And a genuine change after that must still be caught — the dangerous
	// direction of a stale fingerprint.
	plan.Tasks[0].Title = "changed again"
	if err := db.SaveState(st); err != nil {
		t.Fatalf("save after second change: %v", err)
	}
	if got := countAudit(t, db, "task.upsert"); got != before+2 {
		t.Errorf("a real change after UpsertTask emitted %d rows, want 1", got-(before+1))
	}
}

// TestDeletedTaskDropsFingerprint covers id reuse: cloop reassigns task ids,
// and a fingerprint outliving its task would make an unrelated new task look
// unchanged.
func TestDeletedTaskDropsFingerprint(t *testing.T) {
	db := newAuditDB(t)
	original := &pm.Task{ID: 7, Title: "original", Status: pm.TaskPending}
	if err := db.UpsertTask(original); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := db.DeleteTask(7); err != nil {
		t.Fatalf("delete: %v", err)
	}
	var n int
	if err := db.conn.QueryRow(
		`SELECT COUNT(*) FROM audit_task_fingerprints WHERE task_id = 7`).Scan(&n); err != nil {
		t.Fatalf("count fingerprints: %v", err)
	}
	if n != 0 {
		t.Fatalf("fingerprint survived DeleteTask")
	}

	// A different task claiming id 7 must be audited as new.
	before := countAudit(t, db, "task.upsert")
	reused := &pm.Task{ID: 7, Title: "a completely different task", Status: pm.TaskPending}
	st := &State{Goal: "g", WorkDir: t.TempDir(), Plan: &pm.Plan{Tasks: []*pm.Task{reused}}}
	if err := db.SaveState(st); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := countAudit(t, db, "task.upsert"); got != before+1 {
		t.Errorf("a task reusing id 7 emitted %d rows, want 1", got-before)
	}
}

// ── retention ──────────────────────────────────────────────────────────────

// seedChain appends n rows and returns them.
func seedChain(t *testing.T, db *DB, n int) []AuditEvent {
	t.Helper()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	out := make([]AuditEvent, 0, n)
	for i := 0; i < n; i++ {
		ev := AuditEvent{
			Timestamp:  base.Add(time.Duration(i) * time.Hour),
			Actor:      "tester",
			EventType:  "task.upsert",
			EntityType: "task",
			EntityID:   fmt.Sprintf("%d", i),
			Payload:    fmt.Sprintf(`{"i":%d}`, i),
		}
		if err := db.AppendAuditEvent(&ev); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		out = append(out, ev)
	}
	return out
}

// prunePrefix is the statedb-level half of a prune, with a fake seal. The
// end-to-end sealing path is tested in pkg/auditretention.
func prunePrefix(t *testing.T, db *DB, through int64, cutoff time.Time) AuditAnchor {
	t.Helper()
	cand, err := db.PlanAuditPrune(cutoff)
	if err != nil {
		t.Fatalf("plan prune: %v", err)
	}
	if cand.ThroughID != through {
		t.Fatalf("cutoff resolved to id %d, want %d", cand.ThroughID, through)
	}
	a, err := db.PruneAuditPrefix(AuditAnchor{
		Cutoff:          cutoff,
		Actor:           "tester",
		PrunedFirstID:   cand.FirstID,
		PrunedThroughID: cand.ThroughID,
		BoundaryHash:    cand.BoundaryHash,
		ExportPath:      "/tmp/seal.jsonl",
		ExportFormat:    "jsonl",
		ExportSHA256:    "deadbeef",
	})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	return a
}

func TestVerifyWalksAcrossATruncation(t *testing.T) {
	db := newAuditDB(t)
	rows := seedChain(t, db, 20)

	// Without an anchor, deleting a prefix must look like tampering — this is
	// the behaviour the anchor exists to make unnecessary, and it has to keep
	// working for undeclared deletions.
	dbBad := newAuditDB(t)
	seedChain(t, dbBad, 20)
	if _, err := dbBad.conn.Exec(`DELETE FROM audit_events WHERE id <= 5`); err != nil {
		t.Fatalf("raw delete: %v", err)
	}
	if rep, err := dbBad.VerifyAuditChain(); err != nil {
		t.Fatalf("verify: %v", err)
	} else if rep.OK {
		t.Fatal("an unanchored truncation verified clean; tamper detection is broken")
	}

	// With an anchor, the same shape of truncation verifies.
	cutoff := rows[5].Timestamp.Add(time.Minute) // rows 0..5 → ids 1..6
	anchor := prunePrefix(t, db, 6, cutoff)

	if anchor.RetainedFromID != 7 {
		t.Errorf("anchor pinned retained_from_id=%d, want 7", anchor.RetainedFromID)
	}
	if anchor.BoundaryHash != rows[5].RowHash {
		t.Errorf("anchor boundary hash does not match the last pruned row")
	}
	if anchor.PrunedCount != 6 {
		t.Errorf("anchor recorded %d pruned rows, want 6", anchor.PrunedCount)
	}

	rep, err := db.VerifyAuditChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("pruned chain failed to verify at id %d: %s", rep.BreakAtID, rep.Reason)
	}
	if !rep.Anchored || rep.VerifiedFromID != 7 {
		t.Errorf("report did not describe the anchor: anchored=%v from=%d", rep.Anchored, rep.VerifiedFromID)
	}
	if rep.Total != 14 {
		t.Errorf("verified %d rows, want 14", rep.Total)
	}
}

// TestAnchorDoesNotExcuseASecondTruncation is the reason retained_from_id is
// pinned rather than inferred. A prune must not become cover for deleting a
// few more rows just after the boundary.
func TestAnchorDoesNotExcuseASecondTruncation(t *testing.T) {
	db := newAuditDB(t)
	rows := seedChain(t, db, 20)
	prunePrefix(t, db, 6, rows[5].Timestamp.Add(time.Minute))

	if _, err := db.conn.Exec(`DELETE FROM audit_events WHERE id IN (7,8)`); err != nil {
		t.Fatalf("raw delete: %v", err)
	}
	rep, err := db.VerifyAuditChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.OK {
		t.Fatal("rows deleted just after an anchor verified clean")
	}
	if rep.BreakAtID != 9 {
		t.Errorf("break reported at id %d, want 9", rep.BreakAtID)
	}
}

// TestChainResumesAfterAFullPrune covers the case that would silently fork the
// chain: pruning everything, then appending. Restarting at id 1 / genesis
// would produce a table that verifies on its own while contradicting the
// anchor.
func TestChainResumesAfterAFullPrune(t *testing.T) {
	db := newAuditDB(t)
	rows := seedChain(t, db, 10)
	anchor := prunePrefix(t, db, 10, rows[9].Timestamp.Add(time.Minute))

	if anchor.RetainedFromID != 0 {
		t.Fatalf("expected an emptied table, got retained_from_id=%d", anchor.RetainedFromID)
	}
	if n := countAudit(t, db, ""); n != 0 {
		t.Fatalf("table not empty after full prune: %d rows", n)
	}
	// An empty but anchored table is a valid state.
	if rep, err := db.VerifyAuditChain(); err != nil || !rep.OK {
		t.Fatalf("empty anchored chain failed to verify: %v %+v", err, rep)
	}

	next := AuditEvent{Actor: "tester", EventType: "config.set", EntityType: "config"}
	if err := db.AppendAuditEvent(&next); err != nil {
		t.Fatalf("append after full prune: %v", err)
	}
	if next.ID != 11 {
		t.Errorf("resumed at id %d, want 11 (restarting at 1 forks the chain)", next.ID)
	}
	if next.PrevHash != anchor.BoundaryHash {
		t.Errorf("resumed row does not link to the anchor boundary")
	}
	if rep, err := db.VerifyAuditChain(); err != nil || !rep.OK {
		t.Fatalf("chain after resume failed to verify: %v %+v", err, rep)
	}
}

func TestPruneRefusesWithoutASeal(t *testing.T) {
	db := newAuditDB(t)
	rows := seedChain(t, db, 5)
	cand, err := db.PlanAuditPrune(rows[2].Timestamp.Add(time.Minute))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	_, err = db.PruneAuditPrefix(AuditAnchor{
		PrunedThroughID: cand.ThroughID,
		BoundaryHash:    cand.BoundaryHash,
		// No ExportPath / ExportSHA256.
	})
	if err == nil {
		t.Fatal("PruneAuditPrefix deleted rows with no export digest")
	}
	if n := countAudit(t, db, ""); n != 5 {
		t.Errorf("rows were removed despite the refusal: %d remain of 5", n)
	}
}

// TestPruneRefusesWhenTheBoundaryChanged guards the seal-then-delete window:
// if the row the seal ended on is not the row still in the table, the delete
// would destroy a divergence instead of reporting it.
func TestPruneRefusesWhenTheBoundaryChanged(t *testing.T) {
	db := newAuditDB(t)
	rows := seedChain(t, db, 5)
	_, err := db.PruneAuditPrefix(AuditAnchor{
		PrunedThroughID: 3,
		BoundaryHash:    "0000000000000000000000000000000000000000000000000000000000000001",
		ExportPath:      "/tmp/x.jsonl",
		ExportSHA256:    "abc",
	})
	if err == nil {
		t.Fatal("prune accepted a boundary hash that does not match the stored row")
	}
	if n := countAudit(t, db, ""); n != len(rows) {
		t.Errorf("rows removed despite the mismatch: %d remain of %d", n, len(rows))
	}
}

func TestPlanAuditPruneOnAnEmptyRange(t *testing.T) {
	db := newAuditDB(t)
	seedChain(t, db, 3)
	cand, err := db.PlanAuditPrune(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if cand.Count != 0 || cand.ThroughID != 0 {
		t.Errorf("a cutoff older than every row selected %d rows through id %d", cand.Count, cand.ThroughID)
	}
}

// TestBatchAppendMatchesSequentialChaining pins the equivalence the bulk path
// depends on: chaining N rows in one transaction must produce exactly the
// hashes N single appends would.
func TestBatchAppendMatchesSequentialChaining(t *testing.T) {
	mk := func(i int) *AuditEvent {
		return &AuditEvent{
			Timestamp:  time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			Actor:      "tester",
			EventType:  "task.upsert",
			EntityType: "task",
			EntityID:   fmt.Sprintf("%d", i),
			Payload:    fmt.Sprintf(`{"i":%d}`, i),
		}
	}

	seq, err := Open(filepath.Join(t.TempDir(), "seq.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer seq.Close()
	var seqHashes []string
	for i := 0; i < 8; i++ {
		ev := mk(i)
		if err := seq.AppendAuditEvent(ev); err != nil {
			t.Fatalf("append: %v", err)
		}
		seqHashes = append(seqHashes, ev.RowHash)
	}

	batchDB, err := Open(filepath.Join(t.TempDir(), "batch.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer batchDB.Close()
	var batch []*AuditEvent
	for i := 0; i < 8; i++ {
		batch = append(batch, mk(i))
	}
	if err := batchDB.AppendAuditEvents(batch); err != nil {
		t.Fatalf("batch append: %v", err)
	}
	for i, ev := range batch {
		if ev.RowHash != seqHashes[i] {
			t.Fatalf("row %d: batch hash %s != sequential hash %s", i, short(ev.RowHash), short(seqHashes[i]))
		}
		if ev.ID != int64(i+1) {
			t.Errorf("row %d got id %d", i, ev.ID)
		}
	}
	if rep, err := batchDB.VerifyAuditChain(); err != nil || !rep.OK {
		t.Fatalf("batch-written chain failed to verify: %v %+v", err, rep)
	}
}
