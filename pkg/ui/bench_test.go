package ui

// Benchmarks for the hub's control-plane hot paths: the two per-mutation ones —
// turning a project state into the bytes that go on the wire, and fanning those
// bytes out to every subscribed tab — and the per-tick project sweep, which
// costs the same whether or not any mutation happens at all.
//
// The first two matter together. Every plan mutation marshals once and then
// fans out once per connected client, so the cost of a single task edit on a
// multi-tenant hub is (snapshot cost) + (subscribers × handoff cost). Neither
// term had a number attached to it. The first scales with plan size, the
// second with tenancy, and both are inputs nobody sets deliberately.
//
// The sweep is the floor underneath them: it runs on a two-second timer
// regardless, so its cost is what a hub pays for merely having tenants.
//
// Fanout is measured at 1, 10 and 100 subscribers because the interesting
// question is not the absolute number but whether it stays linear: the send is
// non-blocking by construction (sendOrLag), so 100 subscribers should cost
// about 100× one, and anything worse means something started blocking while
// hubMu is held — which on this path stalls every other broadcast on the hub.
//
// No latency assertion: see the note in pkg/statedb/bench_test.go.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// benchProjectDir initialises a real project directory carrying n tasks.
//
// On disk rather than in memory because marshalStateForWire reads
// config.yaml for the per-project step timeout (Task 20147), and a benchmark
// against a synthetic in-memory state would skip that read — measuring
// something the hub never actually does.
func benchProjectDir(b *testing.B, n int) string {
	b.Helper()
	dir := b.TempDir()
	ps, err := state.Init(dir, "benchmark the hub control plane", 0)
	if err != nil {
		b.Fatalf("state.Init: %v", err)
	}
	tasks := make([]*pm.Task, 0, n)
	now := time.Now().UTC()
	for i := 1; i <= n; i++ {
		t := &pm.Task{
			ID:          i,
			Title:       fmt.Sprintf("Task %d: instrument the control plane and hold the line on wall clock", i),
			Description: fmt.Sprintf("Task %d exists to give the benchmark a body of text to marshal. Real task descriptions run to a paragraph, carrying acceptance criteria and a pointer at the file that has to change.", i),
			Priority:    (i % 3) + 1,
			Status:      pm.TaskPending,
			Tags:        []string{"bench", fmt.Sprintf("group-%d", i%7)},
		}
		if i%3 != 0 {
			t.Status = pm.TaskDone
			t.Result = fmt.Sprintf("Completed task %d. The summary an agent writes back is long enough to matter in aggregate — a few hundred bytes per row, several hundred rows, re-marshalled on every broadcast.", i)
			started := now.Add(-time.Duration(i) * time.Minute)
			done := started.Add(3 * time.Minute)
			t.StartedAt = &started
			t.CompletedAt = &done
		}
		tasks = append(tasks, t)
	}
	ps.PMMode = true
	ps.Plan = &pm.Plan{Goal: ps.Goal, Tasks: tasks}
	if err := ps.Save(); err != nil {
		b.Fatalf("state.Save: %v", err)
	}
	return dir
}

// ── wire snapshot ───────────────────────────────────────────────────────────

// BenchmarkMarshalStateForWire measures the full-state frame.
//
// This runs on every /api/state request and behind every full task_update
// broadcast, and its cost is entirely in the plan: the function clones the
// state, drops Steps, marshals, and splices two fields onto the end. The
// sizes bracket where real projects sit — this repository's own plan passed
// 400 tasks — so a super-linear result between them is the signal.
func BenchmarkMarshalStateForWire(b *testing.B) {
	for _, n := range []int{50, 200, 800} {
		b.Run(fmt.Sprintf("tasks=%d", n), func(b *testing.B) {
			dir := benchProjectDir(b, n)
			ps, err := state.LoadLite(dir)
			if err != nil {
				b.Fatalf("LoadLite: %v", err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				raw, err := marshalStateForWire(ps)
				if err != nil {
					b.Fatalf("marshalStateForWire: %v", err)
				}
				// Guard against the frame silently collapsing to something
				// trivial — a tiny payload would benchmark beautifully and
				// mean the wire had stopped carrying the plan.
				if len(raw) < n {
					b.Fatalf("wire frame is %d bytes for %d tasks — suspiciously small", len(raw), n)
				}
			}
		})
	}
}

// BenchmarkComputeStateDiff measures the incremental path that replaced
// full-state broadcasts (Task 20134), in its steady-state form: one task
// changed against a cached baseline.
//
// This is the comparison that justifies the diff machinery existing. Against
// BenchmarkMarshalStateForWire at the same task count it should be
// dramatically cheaper; if it ever is not, the cache is missing and every
// mutation is shipping a full plan to every tab.
func BenchmarkComputeStateDiff(b *testing.B) {
	for _, n := range []int{50, 200, 800} {
		b.Run(fmt.Sprintf("tasks=%d", n), func(b *testing.B) {
			dir := benchProjectDir(b, n)
			prev, err := state.LoadLite(dir)
			if err != nil {
				b.Fatalf("LoadLite: %v", err)
			}
			curr, err := state.LoadLite(dir)
			if err != nil {
				b.Fatalf("LoadLite: %v", err)
			}
			curr.Plan.Tasks[n/2].Status = pm.TaskInProgress
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				diff := computeStateDiff(prev, curr)
				if !diff.HasChanges {
					b.Fatal("diff reports no changes against a mutated state")
				}
			}
		})
	}
}

// ── fanout ──────────────────────────────────────────────────────────────────

// attachDrainedClients registers n hub clients on workDir, each with a
// goroutine consuming its channel, and returns a stop function.
//
// The drain is what makes the measurement honest. hubClient.ch is bounded at
// hubClientBufferSize (64); without a consumer the buffer fills after 64
// iterations and every subsequent send takes sendOrLag's cheap resync branch
// instead of the send branch. The benchmark would then report the cost of
// giving up on a slow client rather than the cost of delivering to a live
// one, and would get faster the more it was doing wrong.
func attachDrainedClients(b *testing.B, srv *Server, workDir string, n int) (stop func()) {
	b.Helper()
	done := make(chan struct{})
	clients := make([]*hubClient, 0, n)
	for i := 0; i < n; i++ {
		hc := &hubClient{
			ch:     make(chan wsMessage, hubClientBufferSize),
			resync: make(chan struct{}, 1),
			id:     fmt.Sprintf("bench-%d", i),
			name:   fmt.Sprintf("Bench Client %d", i),
			color:  "#58a6ff",
		}
		clients = append(clients, hc)
		go func(hc *hubClient) {
			for {
				select {
				case <-hc.ch:
				case <-done:
					return
				}
			}
		}(hc)
	}
	srv.hubMu.Lock()
	if srv.hubClients[workDir] == nil {
		srv.hubClients[workDir] = make(map[*hubClient]struct{})
	}
	for _, hc := range clients {
		srv.hubClients[workDir][hc] = struct{}{}
	}
	srv.hubMu.Unlock()

	return func() {
		close(done)
		srv.hubMu.Lock()
		for _, hc := range clients {
			delete(srv.hubClients[workDir], hc)
		}
		srv.hubMu.Unlock()
	}
}

// BenchmarkBroadcastToProject measures WebSocket fanout at 1, 10 and 100
// subscribers — one tab, a small team, and a hub with a hundred tabs open on
// one busy project.
//
// hubMu is held across the whole iteration, so this is also a measurement of
// how long every *other* broadcast on the hub is blocked while this one runs.
func BenchmarkBroadcastToProject(b *testing.B) {
	for _, subs := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("subscribers=%d", subs), func(b *testing.B) {
			// A real project directory, not a bare temp dir: New calls
			// bootstrapExecutors, which opens the control-plane database and
			// logs a warning per call when there isn't one. That warning is
			// harmless but it interleaves with the benchmark output.
			workDir := benchProjectDir(b, 0)
			srv := New(workDir, 0, "")
			stop := attachDrainedClients(b, srv, workDir, subs)
			defer stop()

			raw, err := json.Marshal(map[string]any{"id": 42, "status": "in_progress"})
			if err != nil {
				b.Fatalf("marshal: %v", err)
			}
			msg := wsMessage{Type: "task_update", Data: raw}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				srv.broadcastToProject(workDir, msg)
			}
		})
	}
}

// BenchmarkBroadcastStateDiff measures the whole per-mutation path end to end:
// cache swap, diff, marshal, fan out.
//
// This is the number that corresponds to a real event — a task changing status
// while N tabs watch — and the one that would move if either half regressed.
// Holding subscribers at 1, 10 and 100 over the same 400-task plan separates
// the per-mutation cost from the per-subscriber cost.
func BenchmarkBroadcastStateDiff(b *testing.B) {
	const tasks = 400
	for _, subs := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("subscribers=%d", subs), func(b *testing.B) {
			dir := benchProjectDir(b, tasks)
			srv := New(dir, 0, "")
			stop := attachDrainedClients(b, srv, dir, subs)
			defer stop()

			ps, err := state.LoadLite(dir)
			if err != nil {
				b.Fatalf("LoadLite: %v", err)
			}
			// Seed the cache so the timed iterations measure the incremental
			// path. Without this the first call ships a full-state diff,
			// which is the documented fallback but not the common case.
			srv.ensureDiffCache().swap(dir, ps)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Alternate the mutated task's status so every iteration
				// produces a real delta; a no-change diff returns early and
				// would measure nothing.
				if i%2 == 0 {
					ps.Plan.Tasks[i%tasks].Status = pm.TaskInProgress
				} else {
					ps.Plan.Tasks[i%tasks].Status = pm.TaskDone
				}
				srv.broadcastStateDiff(dir, ps)
			}
		})
	}
}

// ── the per-tick project sweep ──────────────────────────────────────────────

// benchSweepServer builds a hub with n registered projects, each a real
// project directory carrying a small plan.
//
// Real directories because the sweep's cost is almost entirely syscalls and
// per-project I/O — stat the state files, walk /proc, and on any change reload
// every project's status from its database. A synthetic registry pointing at
// paths that do not exist would short-circuit all of it and measure nothing.
//
// The projects are wired in through the --projects flag rather than the
// on-disk registry so the benchmark does not depend on (or write to) the
// user's ~/.cloop/projects.json.
func benchSweepServer(b *testing.B, n int) (*Server, []string) {
	b.Helper()
	root := b.TempDir()
	paths := make([]string, 0, n)
	for i := 0; i < n; i++ {
		dir := filepath.Join(root, fmt.Sprintf("project-%04d", i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			b.Fatalf("mkdir: %v", err)
		}
		// Skip the migration run per project: at 500 projects that dominates
		// setup and none of it is what we are measuring.
		statedbtest.SeedDir(b, dir)
		ps, err := state.Init(dir, fmt.Sprintf("tenant %d", i), 0)
		if err != nil {
			b.Fatalf("state.Init: %v", err)
		}
		ps.PMMode = true
		ps.Plan = &pm.Plan{Goal: ps.Goal, Tasks: []*pm.Task{
			{ID: 1, Title: "A task the sweep has to count", Status: pm.TaskDone},
			{ID: 2, Title: "Another one", Status: pm.TaskPending},
		}}
		if err := ps.Save(); err != nil {
			b.Fatalf("state.Save: %v", err)
		}
		paths = append(paths, dir)
	}
	// WorkDir is one of the tenants rather than a separate directory, so the
	// project count is exactly n.
	srv := New(paths[0], 0, "")
	srv.Projects = append([]string(nil), paths[1:]...)
	return srv, paths
}

// BenchmarkWatchProjectsTick measures one iteration of the hub's project sweep
// at 10, 100 and 500 registered projects.
//
// This is the hub's floor cost: it runs every two seconds whether or not
// anybody is connected and whether or not any project is doing anything, so it
// is the price of merely having tenants. It was the one control-plane hot path
// the Task 20227 benchmarks left uncovered — those measure what a *mutation*
// costs, and this measures what idling costs.
//
// Two shapes, because they exercise very different amounts of work:
//
//   - idle: no project's state file has changed since the last tick. This is
//     the overwhelmingly common case on a hosted hub and should be close to
//     free per project.
//   - one-changed: exactly one project wrote to its state file, which is what
//     a single active tenant looks like. It is worth measuring separately
//     because a change in *any* project reloads the status of *every* project.
//
// Growth across the project counts is the signal, not the absolute numbers:
// the sweep is inherently O(projects), so what matters is the constant on that
// term and whether the one-changed shape stays close to the idle one.
func BenchmarkWatchProjectsTick(b *testing.B) {
	for _, n := range []int{10, 100, 500} {
		srv, paths := benchSweepServer(b, n)

		b.Run(fmt.Sprintf("projects=%d/idle", n), func(b *testing.B) {
			sw := newProjectSweep()
			// Prime lastMod so the timed iterations see no change; the first
			// tick against a fresh sweep reports every project as changed.
			srv.sweepProjectsTick(sw, time.Now())

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				srv.sweepProjectsTick(sw, time.Now())
			}
		})

		b.Run(fmt.Sprintf("projects=%d/dormant", n), func(b *testing.B) {
			// Every project last written long enough ago to qualify for the
			// stat backoff — a hosted hub whose tenants are between sessions,
			// which is the shape the deferral exists for. The idle case above
			// deliberately does not qualify (its projects were written during
			// setup), so the difference between the two is what the deferral
			// is worth.
			old := time.Now().Add(-24 * time.Hour)
			for _, dir := range paths {
				for _, f := range stateFilesFor(dir) {
					_ = os.Chtimes(f, old, old)
				}
			}
			sw := newProjectSweep()
			srv.sweepProjectsTick(sw, time.Now())

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				srv.sweepProjectsTick(sw, time.Now())
			}
		})

		b.Run(fmt.Sprintf("projects=%d/one-changed", n), func(b *testing.B) {
			sw := newProjectSweep()
			srv.sweepProjectsTick(sw, time.Now())

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Drop one project's remembered timestamp instead of touching
				// the file: it drives the identical code path without adding
				// the write to the measurement.
				b.StopTimer()
				delete(sw.lastMod, paths[i%len(paths)])
				b.StartTimer()
				srv.sweepProjectsTick(sw, time.Now())
			}
		})
	}
}

// stateFilesFor lists the files stateModTime stats for a project, so a
// benchmark can backdate them.
func stateFilesFor(dir string) []string {
	db := state.StateDBPath(dir)
	return []string{db, db + "-wal", state.StatePath(dir)}
}

// ── the Event History page ──────────────────────────────────────────────────

// benchJournalDir builds a project whose journal holds the given numbers of
// steps and events, interleaved in time the way a run writes them. Step
// outputs follow this hub's own journal: most a few hundred bytes, one in
// fifty several kilobytes.
//
// Written in one transaction through a raw handle: through AppendStep, fifty
// thousand rows would be fifty thousand transactions, and the setup would be
// most of the benchmark's run time.
func benchJournalDir(b *testing.B, steps, events int) string {
	b.Helper()
	dir := statedbtest.Dir(b)
	if _, err := state.Init(dir, "benchmark the event history", 0); err != nil {
		b.Fatalf("state.Init: %v", err)
	}
	conn, err := statedb.OpenConn(state.StateDBPath(dir), statedb.ReadWrite)
	if err != nil {
		b.Fatalf("open: %v", err)
	}
	defer conn.Close()
	tx, err := conn.Begin()
	if err != nil {
		b.Fatal(err)
	}
	stepStmt, err := tx.Prepare(`INSERT INTO steps(step, task, output, exit_code, duration, time) VALUES(?,?,?,0,'2m10s',?)`)
	if err != nil {
		b.Fatal(err)
	}
	eventStmt, err := tx.Prepare(`INSERT INTO events(timestamp, type, task_id, task_title, step, message, details) VALUES(?,?,?,?,-1,?,?)`)
	if err != nil {
		b.Fatal(err)
	}
	short := strings.Repeat("A task's summary of what it changed and why. ", 10)
	long := strings.Repeat("A long transcript tail, the kind a failing build leaves. ", 300)
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	perEvent := steps / max(events, 1)
	for i, e := 0, 0; i < steps; i++ {
		at = at.Add(97 * time.Second)
		out := short
		if i%50 == 0 {
			out = long
		}
		if _, err := stepStmt.Exec(i, fmt.Sprintf("Task %d: work", i/3), out, at.Format(time.RFC3339Nano)); err != nil {
			b.Fatal(err)
		}
		if e < events && i%perEvent == 0 {
			e++
			if _, err := eventStmt.Exec(at.Add(time.Second).Format(time.RFC3339Nano), "task_done", i/3, "work",
				fmt.Sprintf("Task #%d completed in 2m10s", i/3), `{"attempt":1}`); err != nil {
				b.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	return dir
}

// BenchmarkEventHistoryPage measures GET /api/event-history at two journal
// sizes ten times apart — 5,000 steps and 500 events, and 50,000 and 5,000,
// ten times this hub's own — for the three reads the dashboard makes: the
// newest page, a page halfway down the history, and the rows written since a
// cursor (what a reconnect or a gap reads; the hub's own push reads the same).
//
// The sizes are the point (Task 20384). The handler used to load the whole
// project, every step's output included, and every event, then sort them all
// to return fifty rows, so its cost grew with the journal: 38 ms a page at the
// smaller size and 244 ms, with 155 MB allocated, at the larger. Now each read
// is an index seek and a LIMIT per table — about 3 ms at either size, most of
// it opening the database — so the two sizes should cost the same; a read
// that grows tenfold between them has stopped using the index (see
// TestHistory_PagesSeekTheIndex).
func BenchmarkEventHistoryPage(b *testing.B) {
	for _, size := range []struct{ steps, events int }{{5000, 500}, {50000, 5000}} {
		dir := benchJournalDir(b, size.steps, size.events)
		srv := New(dir, 0, "")
		get := func(b *testing.B, query string) historyResponse {
			rec := httptest.NewRecorder()
			srv.handleEventHistory(rec, httptest.NewRequest(http.MethodGet, "/api/event-history?"+query, nil))
			if rec.Code != http.StatusOK {
				b.Fatalf("GET ?%s: HTTP %d: %s", query, rec.Code, rec.Body)
			}
			var resp struct {
				Entries []json.RawMessage `json:"entries"`
				Bottom  []float64         `json:"bottom"`
				Top     []int64           `json:"top"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				b.Fatal(err)
			}
			if len(resp.Entries) == 0 {
				b.Fatalf("GET ?%s returned no entries", query)
			}
			return historyResponse{Entries: make([]historyEntry, len(resp.Entries)), Bottom: wirePlace(resp.Bottom), Top: wireCursor(resp.Top)}
		}
		// Halfway down: the bottom of the page at the middle of the journal.
		middle := get(b, fmt.Sprintf("offset=%d&limit=50", (size.steps+size.events)/2))
		top := get(b, "limit=50").Top
		reads := []struct{ name, query string }{
			{"newest", "limit=50"},
			{"halfway", "limit=50&before=" + url.QueryEscape(fmt.Sprintf("%v,%d,%d", middle.Bottom.Day, b2i(middle.Bottom.Event), middle.Bottom.Key))},
			{"since", fmt.Sprintf("limit=500&after=%d,%d", top.Step-3, top.Event-1)},
		}
		for _, r := range reads {
			b.Run(fmt.Sprintf("steps=%d,events=%d/%s", size.steps, size.events, r.name), func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					get(b, r.query)
				}
			})
		}
	}
}

func wirePlace(v []float64) *historyPlace {
	if len(v) != 3 {
		return nil
	}
	return &historyPlace{Day: v[0], Event: v[1] == 1, Key: int64(v[2])}
}

func wireCursor(v []int64) *historyCursor {
	if len(v) != 2 {
		return nil
	}
	return &historyCursor{Step: v[0], Event: v[1]}
}

func b2i(v bool) int {
	if v {
		return 1
	}
	return 0
}
