package ui

// Regression tests for Task 20153: pressing Stop on a project whose run
// process died without writing a terminal status (SIGKILL, OOM, host
// reboot) used to answer "no running cloop process found" forever while the
// persisted status stayed "running" — so the UI kept rendering a Stop
// button that could never succeed. Stop must instead reconcile the stale
// status so the project recovers to a runnable state.
//
// The tests run against temp project directories, so the /proc walk in
// multiui.CloopRunPIDsInDir deterministically finds no live run for them.

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/state"
)

// setStatus persists the given lifecycle status for the project at dir,
// simulating a run that died before writing a terminal status.
func setStatus(t *testing.T, dir, status string) {
	t.Helper()
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load(%s): %v", dir, err)
	}
	ps.Status = status
	if err := ps.SaveDirect(); err != nil {
		t.Fatalf("SaveDirect(%s): %v", dir, err)
	}
}

// loadStatus reads the persisted lifecycle status for the project at dir.
func loadStatus(t *testing.T, dir string) string {
	t.Helper()
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load(%s): %v", dir, err)
	}
	return ps.Status
}

// TestStopReconcilesStaleRunningState covers the exact user-visible bug:
// status says "running", no process exists, Stop must clear the stale
// status (→ "paused") and report success instead of an error.
func TestStopReconcilesStaleRunningState(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	setStatus(t, dir, "running")

	ts := newTestServer(t, dir, nil)
	out := apiPOST(t, ts, "/api/stop", map[string]interface{}{})

	if ok, _ := out["ok"].(bool); !ok {
		t.Fatalf("POST /api/stop with stale running state: ok=false, want true (message=%v)", out["message"])
	}
	msg, _ := out["message"].(string)
	if !strings.Contains(msg, "stale") {
		t.Errorf("message = %q, want mention of stale status", msg)
	}
	if got := loadStatus(t, dir); got != "paused" {
		t.Errorf("status after stop = %q, want %q", got, "paused")
	}
}

// TestStopReconcilesStaleEvolvingState verifies the evolve-phase status is
// treated the same as "running".
func TestStopReconcilesStaleEvolvingState(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	setStatus(t, dir, "evolving")

	ts := newTestServer(t, dir, nil)
	out := apiPOST(t, ts, "/api/stop", map[string]interface{}{})

	if ok, _ := out["ok"].(bool); !ok {
		t.Fatalf("POST /api/stop with stale evolving state: ok=false, want true (message=%v)", out["message"])
	}
	if got := loadStatus(t, dir); got != "paused" {
		t.Errorf("status after stop = %q, want %q", got, "paused")
	}
}

// TestStopWithoutRunOrStaleState keeps the honest failure mode: nothing is
// running and the state does not claim otherwise, so Stop reports ok=false
// and must not touch the persisted status.
func TestStopWithoutRunOrStaleState(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)

	ts := newTestServer(t, dir, nil)
	out := apiPOST(t, ts, "/api/stop", map[string]interface{}{})

	if ok, _ := out["ok"].(bool); ok {
		t.Fatalf("POST /api/stop with idle project: ok=true, want false")
	}
	if got := loadStatus(t, dir); got != "initialized" {
		t.Errorf("status after stop = %q, want untouched %q", got, "initialized")
	}
}

// TestStopScopedToRequestedProject verifies /api/stop honours ?project_idx=N:
// reconciling the secondary project's stale state must not modify the
// primary project's status.
func TestStopScopedToRequestedProject(t *testing.T) {
	primary := setupProjectDir(t, cloopGoal, nil)
	secondary := setupProjectDir(t, sysmonGoal, nil)
	setStatus(t, primary, "running")
	setStatus(t, secondary, "running")

	ts := newTestServer(t, primary, []string{secondary})
	out := apiPOST(t, ts, "/api/stop?project_idx=1", map[string]interface{}{})

	if ok, _ := out["ok"].(bool); !ok {
		t.Fatalf("POST /api/stop?project_idx=1: ok=false, want true (message=%v)", out["message"])
	}
	if got := loadStatus(t, secondary); got != "paused" {
		t.Errorf("secondary status = %q, want %q", got, "paused")
	}
	if got := loadStatus(t, primary); got != "running" {
		t.Errorf("primary status = %q, want untouched %q", got, "running")
	}
}

// TestProjectStopReconcilesStaleState verifies the project-card Stop path
// (/api/projects/{idx}/stop) self-heals stale state the same way.
func TestProjectStopReconcilesStaleState(t *testing.T) {
	primary := setupProjectDir(t, cloopGoal, nil)
	secondary := setupProjectDir(t, sysmonGoal, nil)
	setStatus(t, secondary, "running")

	ts := newTestServer(t, primary, []string{secondary})
	out := apiPOST(t, ts, "/api/projects/1/stop", map[string]interface{}{})

	if ok, _ := out["ok"].(bool); !ok {
		t.Fatalf("POST /api/projects/1/stop with stale state: ok=false, want true (message=%v)", out["message"])
	}
	if got := loadStatus(t, secondary); got != "paused" {
		t.Errorf("secondary status = %q, want %q", got, "paused")
	}
}
