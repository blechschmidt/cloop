package statedb

// Benchmarks for the two statedb paths whose cost scales with something the
// operator does not control: the length of the audit trail, and the number of
// tasks in a plan.
//
// Both are on the hub's hot path. SaveState runs on every plan mutation and
// re-diffs the whole task set; the audit trail is appended to by that same
// call and is never shorter tomorrow than it is today. Neither had a number
// attached to it, which meant a change that made either quadratic would first
// be noticed as a CI timeout.
//
// These deliberately do not assert a latency bound. On a shared runner the
// variance between two runs of the same commit is larger than most regressions
// worth catching, so a threshold here would flake far more often than it would
// fire correctly. What they provide is a number in the CI log, comparable
// across commits, and a compile-time guarantee that these call sites still
// exist in the shape the benchmark expects.

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// openBenchDB opens a fresh SQLite state database under a temp directory.
//
// Separate from openTestDB only because that one takes *testing.T; the body is
// the same. b.TempDir is cleaned up by the framework.
func openBenchDB(b *testing.B) *DB {
	b.Helper()
	db, err := Open(filepath.Join(b.TempDir(), "state.db"))
	if err != nil {
		b.Fatalf("open: %v", err)
	}
	b.Cleanup(func() { _ = db.Close() })
	return db
}

// benchPlan builds a plan of n tasks with realistically-sized descriptions.
//
// The field population matters. A plan of n empty structs measures SQLite's
// row overhead and nothing else; real tasks carry a paragraph of description,
// a result, tags and dependencies, and it is the marshalling and diffing of
// those that SaveState spends its time on.
func benchPlan(n int) *pm.Plan {
	tasks := make([]*pm.Task, 0, n)
	now := time.Now().UTC()
	for i := 1; i <= n; i++ {
		t := &pm.Task{
			ID:          i,
			Title:       fmt.Sprintf("Task %d: instrument the control plane and hold the line on wall clock", i),
			Description: fmt.Sprintf("Task %d exists to give the benchmark a body of text to marshal. Real task descriptions run to a paragraph, carrying acceptance criteria and a pointer at the file that has to change, and the cost of persisting a plan is dominated by this field rather than by the row count.", i),
			Priority:    (i % 3) + 1,
			Status:      pm.TaskPending,
			Tags:        []string{"bench", fmt.Sprintf("group-%d", i%7)},
		}
		// A realistic plan is mostly finished work: completed tasks carry a
		// Result, which is the largest column in the table and the one a
		// load has to materialize for every row.
		if i%3 != 0 {
			t.Status = pm.TaskDone
			t.Result = fmt.Sprintf("Completed task %d. The summary an agent writes back is long enough to matter in aggregate — a few hundred bytes per row, several hundred rows, re-read on every load of the plan.", i)
			started := now.Add(-time.Duration(i) * time.Minute)
			done := started.Add(3 * time.Minute)
			t.StartedAt = &started
			t.CompletedAt = &done
			t.ActualMinutes = 3
		}
		if i > 1 && i%5 == 0 {
			t.DependsOn = []int{i - 1}
		}
		tasks = append(tasks, t)
	}
	return &pm.Plan{Goal: "benchmark the hub control plane", Tasks: tasks}
}

func benchState(n int) *State {
	return &State{
		Goal:   "benchmark the hub control plane",
		Status: "running",
		PMMode: true,
		Plan:   benchPlan(n),
		Model:  "claude-opus-4-8",
	}
}

// ── plan persistence ────────────────────────────────────────────────────────

// BenchmarkSaveState measures the write that every plan mutation performs.
//
// Sized at 200/400/800 because that is the range real cloop projects live in —
// this repository's own plan passed 400 tasks during Task 20195, where the
// cost of saving it was what made adding a task take seconds. The three sizes
// are the point: a linear path roughly doubles between them, and a quadratic
// one quadruples, which is visible in the CI log without any threshold.
func BenchmarkSaveState(b *testing.B) {
	for _, n := range []int{200, 400, 800} {
		b.Run(fmt.Sprintf("tasks=%d", n), func(b *testing.B) {
			db := openBenchDB(b)
			st := benchState(n)
			// Save once outside the timed loop so the measurement is of the
			// steady-state update path — insert-on-empty is a different and
			// much rarer operation than the re-save this is standing in for.
			if err := db.SaveState(st); err != nil {
				b.Fatalf("seed SaveState: %v", err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Mutate one task per iteration. A save of a byte-identical
				// plan is the one case the fingerprint diff can short-circuit
				// entirely, so measuring that would flatter the path that
				// actually runs.
				st.Plan.Tasks[i%n].Result = fmt.Sprintf("iteration %d", i)
				if err := db.SaveState(st); err != nil {
					b.Fatalf("SaveState: %v", err)
				}
			}
		})
	}
}

// BenchmarkLoadStateLite measures the read behind /api/state and every
// dashboard render. Lite, because that is the variant the hub uses: it skips
// the step rows, so what remains is dominated by the plan.
func BenchmarkLoadStateLite(b *testing.B) {
	for _, n := range []int{200, 400, 800} {
		b.Run(fmt.Sprintf("tasks=%d", n), func(b *testing.B) {
			db := openBenchDB(b)
			if err := db.SaveState(benchState(n)); err != nil {
				b.Fatalf("seed SaveState: %v", err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				got, err := db.LoadStateLite()
				if err != nil {
					b.Fatalf("LoadStateLite: %v", err)
				}
				if got.Plan == nil || len(got.Plan.Tasks) != n {
					b.Fatalf("loaded %v tasks, want %d", got.Plan, n)
				}
			}
		})
	}
}

// ── audit trail ─────────────────────────────────────────────────────────────

// seedTrail appends n events, using the batch path so that seeding a long
// trail does not dominate the benchmark's own setup time.
func seedTrail(b *testing.B, db *DB, n int) {
	b.Helper()
	const batch = 500
	for start := 0; start < n; start += batch {
		size := batch
		if start+size > n {
			size = n - start
		}
		evs := make([]*AuditEvent, size)
		for i := range evs {
			evs[i] = &AuditEvent{
				Actor:      "alice@example.com",
				EventType:  "task.upsert",
				EntityType: "task",
				EntityID:   fmt.Sprintf("%d", start+i),
				Payload:    `{"status":"done","priority":2}`,
			}
		}
		if err := db.AppendAuditEvents(evs); err != nil {
			b.Fatalf("seed AppendAuditEvents: %v", err)
		}
	}
}

// BenchmarkAppendAuditEvent measures a single-event append onto a trail that
// already has 10k rows behind it.
//
// The depth is the whole point. Appending chains against the current tip, so
// if reading that tip ever degrades from an indexed lookup into a scan, this
// number grows with the trail while a benchmark against an empty database
// would stay flat and report nothing.
func BenchmarkAppendAuditEvent(b *testing.B) {
	db := openBenchDB(b)
	seedTrail(b, db, 10000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev := &AuditEvent{
			Actor:      "alice@example.com",
			EventType:  "secret.grant",
			EntityType: "lease",
			EntityID:   fmt.Sprintf("lease-%d", i),
			Payload:    `{"kind":"github_pat","ttl":"15m"}`,
		}
		if err := db.AppendAuditEvent(ev); err != nil {
			b.Fatalf("AppendAuditEvent: %v", err)
		}
	}
}

// BenchmarkAppendAuditEvents measures the batch path that SaveState uses to
// emit a whole plan's worth of task events in one transaction.
//
// Task 20218 replaced per-row appends with this after the per-row version was
// found to cost one transaction per task on every save. Comparing this against
// BenchmarkAppendAuditEvent×100 is what keeps that decision honest.
func BenchmarkAppendAuditEvents(b *testing.B) {
	db := openBenchDB(b)
	seedTrail(b, db, 10000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evs := make([]*AuditEvent, 100)
		for j := range evs {
			evs[j] = &AuditEvent{
				Actor:      "alice@example.com",
				EventType:  "task.upsert",
				EntityType: "task",
				EntityID:   fmt.Sprintf("%d-%d", i, j),
				Payload:    `{"status":"in_progress"}`,
			}
		}
		if err := db.AppendAuditEvents(evs); err != nil {
			b.Fatalf("AppendAuditEvents: %v", err)
		}
	}
}

// BenchmarkVerifyAuditChain measures a full chain walk, which is unavoidably
// O(trail) — it re-hashes every row.
//
// That makes it the one audit operation whose cost an operator will actually
// feel, and the reason retention exists at all (Task 20218). Sizing it at 1k
// through 50k brackets the range where "verify the trail" goes from an
// instant CLI call to something worth a progress bar; the per-row cost should
// stay flat across all four, and a jump means the walk has picked up a
// per-row query it did not have before.
func BenchmarkVerifyAuditChain(b *testing.B) {
	for _, n := range []int{1000, 10000, 50000} {
		b.Run(fmt.Sprintf("events=%d", n), func(b *testing.B) {
			db := openBenchDB(b)
			seedTrail(b, db, n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rep, err := db.VerifyAuditChain()
				if err != nil {
					b.Fatalf("VerifyAuditChain: %v", err)
				}
				// Assert the walk actually happened. A verification that
				// silently checked zero rows would otherwise benchmark as
				// extremely fast, which is the most misleading result this
				// file could produce.
				if !rep.OK || rep.Total < n {
					b.Fatalf("chain verify checked %d rows (ok=%v), want >= %d", rep.Total, rep.OK, n)
				}
			}
		})
	}
}
