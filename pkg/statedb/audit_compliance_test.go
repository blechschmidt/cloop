package statedb

// The compliance test (Task 20282).
//
// The claim under test is a specific sentence, and it is worth stating exactly
// because the whole design follows from it:
//
//	An auditor with audit_events and nothing else can answer "which executor ran
//	task 63, under which secret leases, and how did it end?"
//
// "And nothing else" is the part a normal test would quietly cheat on. A test
// that seeds the trail, then reconstructs, then compares against the task
// record would pass just as happily if the reconstruction were reading
// plan_tasks the whole time — the two agree, so nothing distinguishes a
// self-sufficient trail from a convenient join.
//
// So this test destroys the alternatives. It DROPs plan_tasks and task_runs
// before reconstructing, which means every table the answer could have come
// from other than audit_events is physically absent. If ReconstructTask ever
// grows a join to the plan, this test fails with a SQL error naming the table,
// and it fails immediately rather than a release later.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// complianceFixture runs one task through the real lifecycle machinery — the
// same SaveState path production uses — and returns the run id the dispatch was
// filed under.
//
// Nothing here writes an audit row by hand. The rows under test have to be the
// ones the system actually emits, or the test proves only that the test can
// write rows.
func complianceFixture(t *testing.T, db *DB, taskID int) (runID, projectDir string) {
	t.Helper()

	projectDir = t.TempDir()
	runID = "run_0123456789abcdef0123456789abcdef"
	leaseID := "lease-7f3c"

	task := &pm.Task{
		ID:       taskID,
		Title:    "Provision the staging cluster",
		Status:   pm.TaskPending,
		Priority: 1,
	}
	st := &State{Goal: "ship it", WorkDir: projectDir, Plan: &pm.Plan{Tasks: []*pm.Task{task}}}
	if err := db.SaveState(st); err != nil {
		t.Fatalf("seed pending: %v", err)
	}

	// The hub leases credentials to the run before the workload exists. This is
	// the row the run id has to reach, and it is filed under entity_type
	// 'secret' — nothing about it mentions a task.
	AuditSecretDecision(db, SecretAuditInput{
		Actor:     "alice@example.com",
		EventType: "secret.lease",
		EntityID:  "gh-deploy-key",
		Timestamp: time.Now().UTC(),
		Payload: map[string]any{
			"decision":    "allow",
			"lease_id":    leaseID,
			"run_id":      runID,
			"executor_id": "edge-pi4",
			"project_id":  projectDir,
			"kind":        "github_pat",
		},
	})

	// The orchestrator's dispatch row, with the placement facts the hub left in
	// the provenance record.
	AuditTaskDispatch(db, TaskDispatchInput{
		TaskID:       taskID,
		TaskTitle:    task.Title,
		ProjectPath:  projectDir,
		RunID:        runID,
		ExecutorID:   "edge-pi4",
		ExecutorKind: "remote",
		Isolation:    "remote",
		PinnedImage:  "ghcr.io/acme/harness@sha256:" + strings.Repeat("a", 64),
		SpecHash:     strings.Repeat("b", 64),
		LeaseIDs:     []string{leaseID},
		Actor:        "alice@example.com",
	})

	// Now the task actually executes and finishes. Both transitions go through
	// SaveState, which is what the terminal emission hangs off.
	started := time.Now().UTC().Add(-90 * time.Second)
	task.Status = pm.TaskInProgress
	task.StartedAt = &started
	task.RunID = runID
	task.ExecutorID, task.ExecutorKind, task.Isolation = "edge-pi4", "remote", "remote"
	if err := db.SaveState(st); err != nil {
		t.Fatalf("save in_progress: %v", err)
	}

	completed := started.Add(90 * time.Second)
	task.Status = pm.TaskFailed
	task.CompletedAt = &completed
	task.Result = "terraform apply exited 1: quota exceeded in eu-west-1"
	if err := db.SaveState(st); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	return runID, projectDir
}

// dropTaskTables removes every table the answer could come from other than
// audit_events.
//
// DROP rather than a flag or a mock: a flag would be something the production
// path could be written to ignore, whereas a dropped table makes the wrong
// implementation impossible rather than merely discouraged.
func dropTaskTables(t *testing.T, db *DB) {
	t.Helper()
	for _, table := range []string{"plan_tasks", "task_runs", "audit_task_fingerprints"} {
		if _, err := db.conn.Exec(`DROP TABLE IF EXISTS ` + table); err != nil {
			t.Fatalf("drop %s: %v", table, err)
		}
	}
	// Prove the drop took, so a future schema change that renames a table
	// cannot turn this test into a no-op that always passes.
	var n int
	if err := db.conn.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('plan_tasks','task_runs')`,
	).Scan(&n); err != nil {
		t.Fatalf("verify drop: %v", err)
	}
	if n != 0 {
		t.Fatalf("plan_tasks/task_runs still present after DROP (%d); this test would be vacuous", n)
	}
}

// TestAuditTrailAnswersTheComplianceQuestionWithoutTheTasksTable is the point
// of Task 20282.
func TestAuditTrailAnswersTheComplianceQuestionWithoutTheTasksTable(t *testing.T) {
	db := newAuditDB(t)
	const taskID = 63
	runID, projectDir := complianceFixture(t, db, taskID)

	dropTaskTables(t, db)

	story, err := db.ReconstructTask(taskID)
	if err != nil {
		t.Fatalf("ReconstructTask with the tasks table absent: %v\n\n"+
			"This is the failure the test exists to catch: the reconstruction "+
			"reached for a table an auditor would not have.", err)
	}

	// "which executor ran task 63"
	if len(story.Runs) != 1 {
		t.Fatalf("got %d executions, want 1 — the trail cannot say how many times the task ran", len(story.Runs))
	}
	run := story.Runs[0]
	if run.RunID != runID {
		t.Errorf("run id = %q, want %q", run.RunID, runID)
	}
	if run.ExecutorID != "edge-pi4" {
		t.Errorf("executor = %q, want edge-pi4 — the trail cannot say where the task ran", run.ExecutorID)
	}
	if run.ExecutorKind != "remote" || run.Isolation != "remote" {
		t.Errorf("kind/isolation = %q/%q, want remote/remote", run.ExecutorKind, run.Isolation)
	}
	if run.RanOnHost() {
		t.Error("a remote execution was reported as having run on the host")
	}
	if !strings.Contains(run.PinnedImage, "@sha256:") {
		t.Errorf("pinned image = %q, want a digest — reproducibility is unprovable without it", run.PinnedImage)
	}
	if run.SpecHash == "" {
		t.Error("the trail records no sandbox spec hash, so the environment cannot be pinned to a spec")
	}

	// "under which secret leases"
	if len(run.LeaseIDs) != 1 || run.LeaseIDs[0] != "lease-7f3c" {
		t.Errorf("lease ids = %v, want [lease-7f3c]", run.LeaseIDs)
	}
	// The authoritative half: the broker's own row, found only because it
	// carries the same run id. A task-scoped query would never have reached it.
	if len(run.LeaseEvents) == 0 {
		t.Fatal("no broker lease rows were correlated to this run — the run-id join is not working, " +
			"which is the whole mechanism that makes credentials attributable to an execution")
	}
	if got := run.LeaseEvents[0].EventType; got != "secret.lease" {
		t.Errorf("correlated lease row type = %q, want secret.lease", got)
	}

	// "and how did it end"
	if run.Outcome != string(pm.TaskFailed) {
		t.Errorf("outcome = %q, want failed", run.Outcome)
	}
	if run.DurationMS <= 0 {
		t.Error("no duration recorded — 'how long did it run' is part of how it ended")
	}
	if !strings.Contains(run.Reason, "quota exceeded") {
		t.Errorf("reason = %q, want it to carry the exit reason", run.Reason)
	}
	if run.Finished == nil {
		t.Fatal("no terminal row")
	}

	// The title travels in the payload, so the story is readable without the
	// plan that named it.
	if !strings.Contains(story.Title, "staging cluster") {
		t.Errorf("title = %q, want the trail to carry it", story.Title)
	}
	_ = projectDir
}

// TestTaskFinishIsEmittedOnEveryExitPath covers the exit paths that do not go
// through the orchestrator's ordinary signal handling.
//
// These are the ones a hand-written emitter forgets: a kill, a timeout, a
// provider abort that resets the task to pending, and a crash recovery that
// requeues it. Each is expressed the way its real code path expresses it — as a
// status write — because that is the only thing they have in common and the
// reason detection lives at the write.
func TestTaskFinishIsEmittedOnEveryExitPath(t *testing.T) {
	cases := []struct {
		name     string
		terminal pm.TaskStatus
		// wantReason is a substring the recorded exit reason must contain, or
		// "" when any reason will do.
		wantReason string
	}{
		{"signalled done", pm.TaskDone, ""},
		{"signalled failure", pm.TaskFailed, ""},
		{"skipped", pm.TaskSkipped, ""},
		{"timeout", pm.TaskTimedOut, "time budget"},
		// The abort and crash-recovery paths both land a task back on pending.
		// Without a terminal row here, an execution that burned an hour and
		// held a credential would leave the trail looking like a task that
		// simply had not started yet.
		{"provider abort / crash requeue", pm.TaskPending, "without a recorded outcome"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newAuditDB(t)
			dir := t.TempDir()
			task := &pm.Task{ID: 7, Title: "t", Status: pm.TaskPending}
			st := &State{Goal: "g", WorkDir: dir, Plan: &pm.Plan{Tasks: []*pm.Task{task}}}
			if err := db.SaveState(st); err != nil {
				t.Fatalf("seed: %v", err)
			}

			started := time.Now().UTC().Add(-time.Minute)
			task.Status = pm.TaskInProgress
			task.StartedAt = &started
			task.RunID = "run_exit_path"
			if err := db.SaveState(st); err != nil {
				t.Fatalf("start: %v", err)
			}

			completed := started.Add(time.Minute)
			task.Status = tc.terminal
			if tc.terminal != pm.TaskPending {
				task.CompletedAt = &completed
			}
			if err := db.SaveState(st); err != nil {
				t.Fatalf("finish: %v", err)
			}

			rows, _, err := db.ListAuditEvents(AuditFilter{
				EntityType: "task", EntityID: "7", EventType: "task.finish", Order: "asc",
			})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("got %d task.finish rows, want exactly 1 — %q left no terminal record", len(rows), tc.terminal)
			}
			payload := decodeAuditPayload(rows[0].Payload)
			if got := payloadString(payload, "outcome"); got != string(tc.terminal) {
				t.Errorf("outcome = %q, want %q", got, tc.terminal)
			}
			if got := payloadString(payload, "run_id"); got != "run_exit_path" {
				t.Errorf("run_id = %q, want run_exit_path — the terminal row does not join to its execution", got)
			}
			if tc.wantReason != "" {
				if got := payloadString(payload, "reason"); !strings.Contains(got, tc.wantReason) {
					t.Errorf("reason = %q, want it to contain %q", got, tc.wantReason)
				}
			}
		})
	}
}

// TestLifecycleRowsAreNotEmittedForUnrelatedSaves guards the cost side.
//
// auditPlanTasks once emitted a row per task per save and produced 1.09M rows,
// 99.7% of the hub's audit table. A lifecycle emitter that fired on every save
// would reintroduce exactly that, so "no edge, no row" is a correctness
// property rather than an optimisation.
func TestLifecycleRowsAreNotEmittedForUnrelatedSaves(t *testing.T) {
	db := newAuditDB(t)
	dir := t.TempDir()
	task := &pm.Task{ID: 1, Title: "t", Status: pm.TaskPending}
	st := &State{Goal: "g", WorkDir: dir, Plan: &pm.Plan{Tasks: []*pm.Task{task}}}
	if err := db.SaveState(st); err != nil {
		t.Fatalf("seed: %v", err)
	}

	for i := 0; i < 20; i++ {
		task.Description = fmt.Sprintf("edited %d", i)
		if err := db.SaveState(st); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}

	for _, evType := range []string{"task.dispatch", "task.finish"} {
		rows, _, err := db.ListAuditEvents(AuditFilter{EventType: evType})
		if err != nil {
			t.Fatalf("list %s: %v", evType, err)
		}
		if len(rows) != 0 {
			t.Errorf("%d %s rows from saves that never crossed the execution boundary, want 0", len(rows), evType)
		}
	}
}

// TestOneDispatchRowPerPlacement pins the division of labour between the
// orchestrator's emitter and the state store's.
//
// The store detects the dispatch edge — it must, or the terminal edge could
// never fire — but writes no row for it. If it ever did, the simplest audit
// query there is ("how many times did task 63 run") would return two for an
// orchestrator-run task and one for anything else, which is a worse answer than
// either number on its own.
func TestOneDispatchRowPerPlacement(t *testing.T) {
	db := newAuditDB(t)
	const taskID = 63
	complianceFixture(t, db, taskID)

	rows, _, err := db.ListAuditEvents(AuditFilter{
		EntityType: "task", EntityID: "63", EventType: "task.dispatch",
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d task.dispatch rows for one placement, want exactly 1 — "+
			"counting executions from the trail would be wrong by a factor of %d", len(rows), len(rows))
	}
	// And the surviving row must be the full-fidelity one, not a thin summary.
	p := decodeAuditPayload(rows[0].Payload)
	for _, key := range []string{"pinned_image", "spec_sha256", "lease_ids", "executor_id"} {
		if _, ok := p[key]; !ok {
			t.Errorf("dispatch row is missing %q — the placement facts did not survive: %s", key, rows[0].Payload)
		}
	}
}

// TestReRunProducesDistinctExecutions is the reason a task id is not a key.
//
// Task 63 running twice with different credentials is precisely the case a
// task-id join gets wrong: it unions both sets and reports that the task held
// all of them, at every moment.
func TestReRunProducesDistinctExecutions(t *testing.T) {
	db := newAuditDB(t)
	dir := t.TempDir()
	task := &pm.Task{ID: 63, Title: "t", Status: pm.TaskPending}
	st := &State{Goal: "g", WorkDir: dir, Plan: &pm.Plan{Tasks: []*pm.Task{task}}}
	if err := db.SaveState(st); err != nil {
		t.Fatalf("seed: %v", err)
	}

	runs := []struct{ runID, leaseID, executor string }{
		{"run_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "lease-first", "edge-pi4"},
		{"run_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "lease-second", "k8s-prod"},
	}
	for _, r := range runs {
		AuditSecretDecision(db, SecretAuditInput{
			Actor: "ops", EventType: "secret.lease", EntityID: "sec",
			Timestamp: time.Now().UTC(),
			Payload:   map[string]any{"lease_id": r.leaseID, "run_id": r.runID},
		})
		AuditTaskDispatch(db, TaskDispatchInput{
			TaskID: 63, ProjectPath: dir, RunID: r.runID,
			ExecutorID: r.executor, ExecutorKind: "remote", Isolation: "remote",
			LeaseIDs: []string{r.leaseID}, Actor: "ops",
		})

		started := time.Now().UTC()
		task.Status = pm.TaskInProgress
		task.StartedAt = &started
		task.RunID = r.runID
		if err := db.SaveState(st); err != nil {
			t.Fatalf("start %s: %v", r.runID, err)
		}
		done := started.Add(time.Second)
		task.Status = pm.TaskFailed
		task.CompletedAt = &done
		if err := db.SaveState(st); err != nil {
			t.Fatalf("finish %s: %v", r.runID, err)
		}
		task.Status = pm.TaskPending
	}

	dropTaskTables(t, db)
	story, err := db.ReconstructTask(63)
	if err != nil {
		t.Fatalf("ReconstructTask: %v", err)
	}
	if len(story.Runs) != 2 {
		t.Fatalf("got %d executions, want 2 — re-runs are being collapsed", len(story.Runs))
	}
	for i, want := range runs {
		got := story.Runs[i]
		if got.RunID != want.runID {
			t.Errorf("run %d id = %q, want %q", i, got.RunID, want.runID)
		}
		if got.ExecutorID != want.executor {
			t.Errorf("run %d executor = %q, want %q", i, got.ExecutorID, want.executor)
		}
		// The decisive assertion: each execution holds only its own credential.
		if len(got.LeaseIDs) != 1 || got.LeaseIDs[0] != want.leaseID {
			t.Errorf("run %d leases = %v, want exactly [%s] — credentials are leaking across executions",
				i, got.LeaseIDs, want.leaseID)
		}
		for _, ev := range got.LeaseEvents {
			p := decodeAuditPayload(ev.Payload)
			if id := payloadString(p, "lease_id"); id != want.leaseID {
				t.Errorf("run %d correlated a broker row for %q, want only %q", i, id, want.leaseID)
			}
		}
	}
}

// TestEditsAfterARunDoNotInventAnExecution guards a trap the run id created for
// itself.
//
// pm.Task now has a RunID field, so the marshalled task inside every
// task.upsert payload mentions a run. A reconstruction that treated "row
// mentions a run" as "row is evidence of a run" would report a fresh execution
// every time somebody retitled the task months later — and, worse, one with no
// executor and no outcome, which reads as a run the trail failed to record.
func TestEditsAfterARunDoNotInventAnExecution(t *testing.T) {
	db := newAuditDB(t)
	const taskID = 63
	_, _ = complianceFixture(t, db, taskID)

	// Reload so the edits below carry the persisted RunID, exactly as a later
	// UI or CLI edit would.
	st, err := db.LoadState()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(st.Plan.Tasks) != 1 {
		t.Fatalf("got %d tasks", len(st.Plan.Tasks))
	}
	if st.Plan.Tasks[0].RunID == "" {
		t.Fatal("RunID did not survive the round trip — the terminal row for a " +
			"crash-recovered task could not name the run that spent its leases")
	}
	for i := 0; i < 3; i++ {
		st.Plan.Tasks[0].Description = fmt.Sprintf("retitled %d", i)
		if err := db.SaveState(st); err != nil {
			t.Fatalf("edit %d: %v", i, err)
		}
	}

	dropTaskTables(t, db)
	story, err := db.ReconstructTask(taskID)
	if err != nil {
		t.Fatalf("ReconstructTask: %v", err)
	}
	if len(story.Runs) != 1 {
		t.Fatalf("got %d executions after 3 unrelated edits, want 1", len(story.Runs))
	}
	if story.Runs[0].ExecutorID == "" || story.Runs[0].Outcome == "" {
		t.Errorf("the surviving execution lost its facts: %+v", story.Runs[0])
	}
}

// TestRunCorrelationIsExactNotSubstring guards the join itself.
//
// The scan that finds a run's rows uses a payload LIKE, and two things make a
// LIKE the wrong final answer: '_' is a single-character wildcard and a run id
// contains one, and a substring match hits any row that merely quotes the id
// somewhere. Either would attach another run's credentials to this execution —
// the precise failure the run id was introduced to prevent.
func TestRunCorrelationIsExactNotSubstring(t *testing.T) {
	db := newAuditDB(t)
	dir := t.TempDir()
	const runID = "run_abcdef0123456789abcdef0123456789"

	// A decoy whose run id differs from runID only at the '_' position. Under
	// LIKE, "run_..." matches this; under an exact compare it does not.
	decoy := "runXabcdef0123456789abcdef0123456789"
	AuditSecretDecision(db, SecretAuditInput{
		Actor: "ops", EventType: "secret.lease", EntityID: "other",
		Timestamp: time.Now().UTC(),
		Payload:   map[string]any{"lease_id": "lease-DECOY", "run_id": decoy},
	})
	// A second decoy: the right id, but quoted inside an unrelated free-text
	// field rather than being this row's run.
	AuditSecretDecision(db, SecretAuditInput{
		Actor: "ops", EventType: "secret.lease", EntityID: "mention",
		Timestamp: time.Now().UTC(),
		Payload:   map[string]any{"lease_id": "lease-MENTION", "reason": "superseded by " + runID},
	})
	// The genuine row.
	AuditSecretDecision(db, SecretAuditInput{
		Actor: "ops", EventType: "secret.lease", EntityID: "real",
		Timestamp: time.Now().UTC(),
		Payload:   map[string]any{"lease_id": "lease-REAL", "run_id": runID},
	})

	AuditTaskDispatch(db, TaskDispatchInput{
		TaskID: 9, ProjectPath: dir, RunID: runID,
		ExecutorID: "edge", ExecutorKind: "remote", Isolation: "remote",
		LeaseIDs: []string{"lease-REAL"}, Actor: "ops",
	})

	story, err := db.ReconstructTask(9)
	if err != nil {
		t.Fatalf("ReconstructTask: %v", err)
	}
	if len(story.Runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(story.Runs))
	}
	got := story.Runs[0].LeaseEvents
	if len(got) != 1 {
		var ids []string
		for _, ev := range got {
			ids = append(ids, payloadString(decodeAuditPayload(ev.Payload), "lease_id"))
		}
		t.Fatalf("correlated %d lease rows %v, want exactly 1 (lease-REAL) — "+
			"credentials from another execution are being attributed to this one", len(got), ids)
	}
	if id := payloadString(decodeAuditPayload(got[0].Payload), "lease_id"); id != "lease-REAL" {
		t.Errorf("correlated %q, want lease-REAL", id)
	}
}

// TestManualStatusFlipNamesTheHuman covers the gap the task description called
// out by name: "a task killed by hand leaves no audit row naming who killed
// it".
func TestManualStatusFlipNamesTheHuman(t *testing.T) {
	db := newAuditDB(t)
	AuditTaskStatus(db, 63, "in_progress", "failed", "alice@example.com")

	rows, _, err := db.ListAuditEvents(AuditFilter{EventType: "task.status", EntityType: "task", EntityID: "63"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d task.status rows, want 1", len(rows))
	}
	if rows[0].Actor != "alice@example.com" {
		t.Errorf("actor = %q, want the human who made the change", rows[0].Actor)
	}
	p := decodeAuditPayload(rows[0].Payload)
	if payloadString(p, "old_status") != "in_progress" || payloadString(p, "new_status") != "failed" {
		t.Errorf("payload does not record the transition: %s", rows[0].Payload)
	}
}
