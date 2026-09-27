package ui

// A run on an executor that does not share this filesystem works on a copy of
// the project and brings its state back only when it ends. Until then the
// hub's own state.db still says how the previous run finished (Task 20349).

import (
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/state"
)

func TestStateReportsASeededRunInFlightAsRunning(t *testing.T) {
	dir := setupProjectDir(t, "seeded status", nil)
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	ps.Status = "complete"
	if err := ps.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	srv := New(dir, 0, "")
	ts := newTestServerFor(t, srv)
	if got := apiGET(t, ts, "/api/state")["status"]; got != "complete" {
		t.Fatalf("before any run, status = %v, want the recorded complete", got)
	}

	// The dispatch as handleRun records it for a device that was sent the
	// project: seeded, tracked, and streaming.
	ex := stubExec{id: "edge-seeded", caps: executor.Capabilities{}}
	rememberSeededDispatch(ex, "h-seeded-1", projectseed.Provenance{ExecutorID: ex.id})
	t.Cleanup(func() { takeSeededDispatch(ex, "h-seeded-1") })
	srv.trackRun(dir, ex, "h-seeded-1")
	srv.liveLogStartRun(dir)

	if got := apiGET(t, ts, "/api/state")["status"]; got != "running" {
		t.Fatalf("with a seeded run in flight, status = %v, want running — the device is working "+
			"through the project while the hub's copy still says how the last run ended", got)
	}
	// The record itself is untouched: the overlay is a view, not a write.
	back, err := state.LoadLite(dir)
	if err != nil {
		t.Fatalf("LoadLite: %v", err)
	}
	if back.Status != "complete" {
		t.Fatalf("the project's recorded status became %q; the overlay must not be saved", back.Status)
	}

	// The run ends: the flag drops and the recorded status speaks again.
	srv.liveLogSetRunning(dir, false)
	srv.untrackRun(dir)
	if got := apiGET(t, ts, "/api/state")["status"]; got != "complete" {
		t.Fatalf("after the run settled, status = %v, want complete", got)
	}
}

// TestStateLeavesALocalRunsStatusAlone: a run on this filesystem writes its own
// status, and overriding it would misreport one that is already pausing.
func TestStateLeavesALocalRunsStatusAlone(t *testing.T) {
	dir := setupProjectDir(t, "local status", nil)
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	ps.Status = "complete"
	if err := ps.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	srv := New(dir, 0, "")
	ts := newTestServerFor(t, srv)
	ex := stubExec{id: "local-host", caps: executor.Capabilities{}}
	srv.trackRun(dir, ex, "h-local-1") // tracked and live, but never seeded
	srv.liveLogStartRun(dir)
	t.Cleanup(func() { srv.untrackRun(dir) })

	if got := apiGET(t, ts, "/api/state")["status"]; got != "complete" {
		t.Fatalf("a local run's status = %v, want the one it recorded", got)
	}
}

// newTestServerFor serves an already-built Server, for a test that has to reach
// into it (tracked runs, the live flag) while it answers requests.
func newTestServerFor(t *testing.T, srv *Server) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}
