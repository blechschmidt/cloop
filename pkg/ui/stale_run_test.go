package ui

// Tests for the automatic half of stale-run detection (Task 20209): a project
// whose persisted status still claims to be running after the run behind it
// died. Before this, only a human pressing Stop cleared that.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// runningProject builds an initialised project whose persisted status says
// "running" with no process anywhere behind it — what a run leaves when it is
// killed rather than stopped.
func runningProject(t *testing.T, status string) string {
	t.Helper()
	dir := t.TempDir()
	seedMigratedDB(t, dir)
	st, err := state.Init(dir, "ship the thing", 0)
	if err != nil {
		t.Fatalf("init project: %v", err)
	}
	st.Status = status
	if err := st.SaveDirect(); err != nil {
		t.Fatalf("save project: %v", err)
	}
	return dir
}

// waitFor polls cond until it holds, failing the test with what it was waiting
// for if it never does. Used instead of a sleep so the timing assertions do not
// encode the watcher's tick interval.
func waitFor(t *testing.T, limit time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", limit, what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func projectStatus(t *testing.T, dir string) string {
	t.Helper()
	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("reload state: %v", err)
	}
	return st.Status
}

// TestReconcileDeadRunClearsStaleStatus is the headline behaviour: nobody
// pressed anything, and the project stops claiming to be running.
func TestReconcileDeadRunClearsStaleStatus(t *testing.T) {
	for _, status := range []string{"running", "evolving"} {
		t.Run(status, func(t *testing.T) {
			dir := runningProject(t, status)
			srv := &Server{WorkDir: dir}

			srv.reconcileDeadRun(dir, runVerdict{})

			if got := projectStatus(t, dir); got != "paused" {
				t.Errorf("status = %q, want %q — a dead run's status was not reconciled", got, "paused")
			}
		})
	}
}

// TestReconcileDeadRunLeavesTerminalStatusAlone: a run that ended cleanly wrote
// its own terminal status, and reconciliation must not rewrite it. This is what
// keeps the sweep silent for every healthy project on every tick.
func TestReconcileDeadRunLeavesTerminalStatusAlone(t *testing.T) {
	for _, status := range []string{"complete", "failed", "paused", "initialized"} {
		t.Run(status, func(t *testing.T) {
			dir := runningProject(t, status)
			srv := &Server{WorkDir: dir}

			srv.reconcileDeadRun(dir, runVerdict{})

			if got := projectStatus(t, dir); got != status {
				t.Errorf("status = %q, want %q — a settled project was rewritten", got, status)
			}
		})
	}
}

// TestReconcileDeadRunSkipsLiveProject is the safety property for the status
// half: a project something is still executing keeps its running status.
func TestReconcileDeadRunSkipsLiveProject(t *testing.T) {
	dir := runningProject(t, "running")
	srv := &Server{WorkDir: dir}
	srv.liveLogSetRunning(dir, true)

	srv.reconcileDeadRun(dir, runVerdict{})

	if got := projectStatus(t, dir); got != "running" {
		t.Errorf("status = %q, want %q — a live project was paused underneath its run", got, "running")
	}
}

// TestReconcileDeadRunRecordsWhyItStopped: the status flip alone would leave an
// operator with a project that quietly stopped. The journal is where the reason
// lives, and for the case this task names it has to say so in words.
func TestReconcileDeadRunRecordsWhyItStopped(t *testing.T) {
	dir := runningProject(t, "running")
	srv := &Server{WorkDir: dir}

	srv.reconcileDeadRun(dir, runVerdict{
		Detail: "it was killed by a signal that cloop did not send",
		OOM:    true,
	})

	events, _, err := state.ListEvents(dir, 0, 50)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	var msg string
	for _, e := range events {
		if e.Type == state.EventSessionFailed {
			msg = e.Message
		}
	}
	if msg == "" {
		t.Fatal("no session-failed event recorded — the project stopped with no explanation in its timeline")
	}
	for _, want := range []string{"killed by a signal", "paused", "memory"} {
		if !strings.Contains(msg, want) {
			t.Errorf("event message does not mention %q: %s", want, msg)
		}
	}
}

// TestReconcileDeadRunIsSilentWithoutAStaleStatus: no status to clear and no
// task to repair means no event, or every idle project would log one per tick.
func TestReconcileDeadRunIsSilentWithoutAStaleStatus(t *testing.T) {
	dir := runningProject(t, "complete")
	srv := &Server{WorkDir: dir}

	srv.reconcileDeadRun(dir, runVerdict{})

	events, _, err := state.ListEvents(dir, 0, 50)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	for _, e := range events {
		if e.Type == state.EventSessionFailed {
			t.Fatalf("a settled project logged a failure event: %s", e.Message)
		}
	}
}

// TestReconcileDeadRunReportsWhatItCleared covers the Stop button's contract:
// it needs to distinguish "we tidied up stale state" from "there was nothing
// here at all", and must not claim the former twice.
func TestReconcileDeadRunReportsWhatItCleared(t *testing.T) {
	dir := runningProject(t, "running")
	srv := &Server{WorkDir: dir}

	if !srv.reconcileDeadRun(dir, runVerdict{}) {
		t.Fatal("reconcileDeadRun = false on a stale project, want true")
	}
	if got := projectStatus(t, dir); got != "paused" {
		t.Errorf("status = %q, want %q", got, "paused")
	}
	if srv.reconcileDeadRun(dir, runVerdict{}) {
		t.Error("reconcileDeadRun = true on a second pass, want false — it re-reported a clear it did not make")
	}
}

// TestCachedRunningClaims covers the gate the watcher sweep runs on every tick.
// It has to select exactly the statuses a killed run can leave behind: too
// narrow and the sweep never fires, too wide and it pays a full state load per
// project per tick for projects that are plainly idle.
func TestCachedRunningClaims(t *testing.T) {
	srv := &Server{}
	srv.projStatuses = []multiui.ProjectStatus{
		{Path: "/a", Status: "running"},
		{Path: "/b", Status: "evolving"},
		{Path: "/c", Status: "complete"},
		{Path: "/d", Status: "paused"},
		{Path: "/e", Status: ""},
	}

	claims := srv.cachedRunningClaims()
	for _, want := range []string{"/a", "/b"} {
		if _, ok := claims[want]; !ok {
			t.Errorf("%s claims to be running but was not selected — the sweep would never look at it", want)
		}
	}
	for _, unwanted := range []string{"/c", "/d", "/e"} {
		if _, ok := claims[unwanted]; ok {
			t.Errorf("%s is idle but was selected for stale detection", unwanted)
		}
	}
}

// TestStateModTimeSeesAWALOnlyCommit is the regression test for why a stale
// project needed a manual refresh to reveal itself at all.
//
// Both watchers detect change by statting the project's state file. The
// database runs in WAL mode, so a commit lands in state.db-wal and reaches
// state.db only when something checkpoints — and nothing does while another
// connection is open, which on a hub is most of the time. Statting state.db
// alone therefore reported a project as unchanged straight through a run, so
// no update was ever pushed and the browser kept whatever it had until the
// user reloaded the page.
func TestStateModTimeSeesAWALOnlyCommit(t *testing.T) {
	dir := runningProject(t, "initialized")
	dbPath := state.StateDBPath(dir)

	// Hold a connection open for the whole test: this is what stops the
	// writer's close from checkpointing, and it is the ordinary condition on
	// a hub rather than a contrived one.
	reader, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	defer reader.Close()

	before, ok := stateModTime(dir)
	if !ok {
		t.Fatal("stateModTime found no state files for an initialised project")
	}
	dbBefore := mustModTime(t, dbPath)

	// Sleep past filesystem timestamp granularity so an unchanged mtime is
	// evidence of nothing happening rather than of the clock not moving.
	time.Sleep(20 * time.Millisecond)
	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	st.Status = "running"
	if err := st.SaveDirect(); err != nil {
		t.Fatalf("save state: %v", err)
	}

	after, ok := stateModTime(dir)
	if !ok {
		t.Fatal("stateModTime found no state files after a write")
	}
	if !after.After(before) {
		t.Errorf("stateModTime did not advance across a commit (%s → %s) — "+
			"the watchers would report this project as unchanged", before, after)
	}
	if dbAfter := mustModTime(t, dbPath); dbAfter.After(dbBefore) {
		t.Skip("this platform checkpointed state.db despite an open reader, " +
			"so the WAL-only case this test exists for did not arise")
	}
}

func mustModTime(t *testing.T, path string) time.Time {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.ModTime()
}

// TestWatcherReconcilesWithoutBeingAsked is the task in one test: a project
// goes stale while the hub is watching it, and the hub fixes it on its own.
//
// The status is made stale *after* the watcher starts, so the startup sweep
// cannot be what repairs it — this exercises the per-tick sweep, which is the
// path that did not exist before. Nothing here presses Stop, which is what a
// human previously had to do to get the same result.
func TestWatcherReconcilesWithoutBeingAsked(t *testing.T) {
	dir := runningProject(t, "initialized")
	srv := New(dir, 0, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.watchProjects(ctx)
	}()

	// Wait until the watcher is inside its loop before stranding anything.
	// watchProjects sweeps once on entry, and a status written before that
	// sweep would be repaired by it — leaving the per-tick path this test
	// exists for untested. The first broadcast run state is the observable
	// that only happens on a tick, so it is what proves the sweep is behind us.
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("abs %s: %v", dir, err)
	}
	waitFor(t, 30*time.Second, "the watcher to complete a tick", func() bool {
		_, known := srv.wasRunning(abs)
		return known
	})

	// Now strand it, the way a killed run does: the status claims a run is in
	// flight and there is no process anywhere behind it.
	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	st.Status = "running"
	if err := st.SaveDirect(); err != nil {
		t.Fatalf("save state: %v", err)
	}

	waitFor(t, 30*time.Second, "the watcher to notice the run was gone", func() bool {
		return projectStatus(t, dir) == "paused"
	})

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Error("watchProjects did not return after its context was cancelled")
	}
}

// ------------------------------------------------------------ liveness

// stubExecutor is an executor.Executor that reports one fixed status. It stands
// in for a driver so the liveness rules can be tested without a real workload,
// whose exit would be a timing race rather than a fact.
type stubExecutor struct {
	status executor.Status
	err    error
}

func (s *stubExecutor) ID() string                          { return "stub" }
func (s *stubExecutor) Kind() string                        { return "stub" }
func (s *stubExecutor) Capabilities() executor.Capabilities { return executor.Capabilities{} }
func (s *stubExecutor) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, nil
}
func (s *stubExecutor) Signal(context.Context, string, executor.Signal) error { return nil }
func (s *stubExecutor) Status(context.Context, string) (executor.Status, error) {
	return s.status, s.err
}
func (s *stubExecutor) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	ch := make(chan executor.LogLine)
	close(ch)
	return ch, nil
}
func (s *stubExecutor) HealthCheck(context.Context) error { return nil }

// TestProjectExecutingPrefersTheDriverOverTheStream is the wedge this task had
// to close. The live-log flag says the hub is still streaming a run; the driver
// says that run is over. The stream can stay open long after the workload dies
// — anything that inherited its stdout holds the pipe — so believing the flag
// pins the project in "running" with nothing to clear it.
func TestProjectExecutingPrefersTheDriverOverTheStream(t *testing.T) {
	dir := t.TempDir()
	srv := &Server{WorkDir: dir}
	srv.liveLogSetRunning(dir, true)
	srv.trackRun(dir, &stubExecutor{status: executor.Status{State: executor.StateKilled}}, "h1")

	if srv.projectExecuting(dir) {
		t.Error("projectExecuting = true for a workload the driver calls killed — " +
			"an orphan holding the output pipe would pin this project as running forever")
	}
}

// TestProjectExecutingTrustsARunningHandle is the same rule in the other
// direction: an isolated executor's workload has no local process to find, so
// the driver saying "running" is the only thing standing between it and a
// repair that would reset its tasks.
func TestProjectExecutingTrustsARunningHandle(t *testing.T) {
	dir := t.TempDir()
	srv := &Server{WorkDir: dir}
	srv.trackRun(dir, &stubExecutor{status: executor.Status{State: executor.StateRunning}}, "h1")

	if !srv.projectExecuting(dir) {
		t.Error("projectExecuting = false for a workload the driver calls running")
	}
}

// TestProjectExecutingFailsClosedOnAnUnreachableDriver: a remote executor that
// cannot be reached must not be read as an executor with nothing running.
func TestProjectExecutingFailsClosedOnAnUnreachableDriver(t *testing.T) {
	dir := t.TempDir()
	srv := &Server{WorkDir: dir}
	srv.trackRun(dir, &stubExecutor{err: executor.ErrHandleNotFound}, "h1")

	if !srv.projectExecuting(dir) {
		t.Error("projectExecuting = false when the driver could not be asked — " +
			"an unreachable executor must not license a repair")
	}
}

// TestUntrackRunReleasesTheHandle: the map is bounded by runs in flight, and a
// settled run must fall back to the other liveness signals rather than pinning
// its last known status.
func TestUntrackRunReleasesTheHandle(t *testing.T) {
	dir := t.TempDir()
	srv := &Server{WorkDir: dir}
	srv.trackRun(dir, &stubExecutor{status: executor.Status{State: executor.StateRunning}}, "h1")
	srv.untrackRun(dir)

	if _, ok := srv.trackedRun(dir); ok {
		t.Fatal("handle still tracked after untrackRun")
	}
	if srv.projectExecuting(dir) {
		t.Error("projectExecuting = true for a project with no process, no handle and no stream")
	}
}

// ------------------------------------------------------------ attribution

// TestWorkloadVerdict pins how each way of dying is reported, and in particular
// that an OOM kill is told apart from a stop cloop asked for. The two are the
// same signal; the only thing separating them is whether a requester left a
// reason behind.
func TestWorkloadVerdict(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   executor.Status
		wantOOM  bool
		contains string
	}{
		{
			name:     "unrequested SIGKILL is read as an OOM",
			status:   executor.Status{State: executor.StateKilled, Error: "signal: killed"},
			wantOOM:  true,
			contains: "out-of-memory",
		},
		{
			name:     "a container reports the same event as exit 137",
			status:   executor.Status{State: executor.StateExited, ExitCode: 137},
			wantOOM:  true,
			contains: "out-of-memory",
		},
		{
			name:     "a kill cloop requested keeps its own reason",
			status:   executor.Status{State: executor.StateKilled, Error: "stopped by request"},
			wantOOM:  false,
			contains: "stopped by request",
		},
		{
			name:     "a deadline kill keeps its own reason",
			status:   executor.Status{State: executor.StateKilled, Error: "deadline exceeded"},
			wantOOM:  false,
			contains: "deadline exceeded",
		},
		{
			name:     "a non-zero exit is reported verbatim",
			status:   executor.Status{State: executor.StateExited, ExitCode: 2},
			wantOOM:  false,
			contains: "status 2",
		},
		{
			name:     "a driver-side failure names itself",
			status:   executor.Status{State: executor.StateFailed, Error: "node went away"},
			wantOOM:  false,
			contains: "node went away",
		},
		{
			name:     "a clean exit that wrote no outcome says exactly that",
			status:   executor.Status{State: executor.StateExited},
			wantOOM:  false,
			contains: "without recording an outcome",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := workloadVerdict(&stubExecutor{status: tc.status}, "h1")
			if got.OOM != tc.wantOOM {
				t.Errorf("OOM = %v, want %v (detail: %s)", got.OOM, tc.wantOOM, got.Detail)
			}
			if !strings.Contains(got.Detail, tc.contains) {
				t.Errorf("detail = %q, want it to mention %q", got.Detail, tc.contains)
			}
		})
	}
}

// TestWorkloadVerdictWithoutADriver: the watcher and the startup sweep have no
// handle to ask, and must not invent a cause they cannot know.
func TestWorkloadVerdictWithoutADriver(t *testing.T) {
	if got := workloadVerdict(nil, ""); got.Detail != "" || got.OOM {
		t.Errorf("verdict = %+v, want the zero value when there is no handle to ask", got)
	}
	got := workloadVerdict(&stubExecutor{err: executor.ErrHandleNotFound}, "h1")
	if got.OOM {
		t.Errorf("verdict claims an OOM from a driver that answered nothing: %+v", got)
	}
	if !strings.Contains(got.Detail, "could not say") {
		t.Errorf("detail = %q, want it to admit the executor could not be asked", got.Detail)
	}
}
