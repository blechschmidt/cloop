package ui

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// stalledProject builds an initialised project whose task 63 is in_progress
// with a finished live artifact behind it — a run that died after its agent
// reported success but before the outcome was persisted.
func stalledProject(t *testing.T) (dir string, taskID int) {
	t.Helper()
	dir = t.TempDir()

	st, err := state.Init(dir, "ship the thing", 0)
	if err != nil {
		t.Fatalf("init project: %v", err)
	}
	started := time.Now().Add(-time.Hour)
	st.Plan = &pm.Plan{
		Goal: "ship the thing",
		Tasks: []*pm.Task{{
			ID:        63,
			Title:     "Analyze and fix the streaming performance",
			Status:    pm.TaskInProgress,
			StartedAt: &started,
		}},
	}
	if err := st.SaveDirect(); err != nil {
		t.Fatalf("save project: %v", err)
	}

	live := artifact.LiveArtifactPath(dir, 63)
	if err := os.MkdirAll(filepath.Dir(live), 0o755); err != nil {
		t.Fatalf("mkdir artifacts: %v", err)
	}
	if err := os.WriteFile(live, []byte("Shipped it.\n\nTASK_DONE\n"), 0o644); err != nil {
		t.Fatalf("write live artifact: %v", err)
	}
	finished := started.Add(30 * time.Minute)
	if err := os.Chtimes(live, finished, finished); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	return dir, 63
}

// TestReconcileStaleTasksAdoptsAndPersists is the end-to-end check that the hub
// repairs a stranded task rather than leaving it rendering as running forever.
func TestReconcileStaleTasksAdoptsAndPersists(t *testing.T) {
	dir, taskID := stalledProject(t)
	srv := &Server{WorkDir: dir}

	srv.reconcileDeadRun(dir, runVerdict{})

	reloaded, err := state.Load(dir)
	if err != nil {
		t.Fatalf("reload state: %v", err)
	}
	var found *pm.Task
	for _, task := range reloaded.Plan.Tasks {
		if task.ID == taskID {
			found = task
		}
	}
	if found == nil {
		t.Fatalf("task %d vanished from the plan", taskID)
	}
	if found.Status != pm.TaskDone {
		t.Errorf("status = %q, want %q — the finished outcome was not adopted", found.Status, pm.TaskDone)
	}
	if found.CompletedAt == nil {
		t.Error("CompletedAt not persisted")
	}
}

// TestReconcileStaleTasksSkipsLiveProject is the safety property: reconciliation
// must never reach into a project something is still executing, or it would
// reset a task out from under the process running it.
func TestReconcileStaleTasksSkipsLiveProject(t *testing.T) {
	dir, taskID := stalledProject(t)

	// Register a live-log stream for this project, which is one of the two
	// signals projectExecuting consults.
	srv := &Server{WorkDir: dir}
	srv.liveLogSetRunning(dir, true)

	srv.reconcileDeadRun(dir, runVerdict{})

	reloaded, err := state.Load(dir)
	if err != nil {
		t.Fatalf("reload state: %v", err)
	}
	for _, task := range reloaded.Plan.Tasks {
		if task.ID == taskID && task.Status != pm.TaskInProgress {
			t.Errorf("status = %q, want %q — a live project must not be reconciled",
				task.Status, pm.TaskInProgress)
		}
	}
}

// TestReconcileStaleTasksRefusesRelocatedState guards the footgun that
// ProjectState.WorkDir is persisted and Load only fills it when empty: a
// project directory that was copied, moved or restored comes back pointing at
// its old home, and SaveDirect follows that pointer instead of the path it was
// read from. Without the guard, reconciling the copy judged it by the copy's
// artifacts and wrote the verdict into the original project's database — which
// is exactly what happened while validating this fix by hand.
func TestReconcileStaleTasksRefusesRelocatedState(t *testing.T) {
	origin, taskID := stalledProject(t)

	// Relocate: a byte-for-byte copy, whose stored WorkDir still names origin.
	moved := t.TempDir()
	out, err := exec.Command("cp", "-a", filepath.Join(origin, ".cloop"), filepath.Join(moved, ".cloop")).CombinedOutput()
	if err != nil {
		t.Fatalf("copy project: %v (%s)", err, out)
	}

	srv := &Server{WorkDir: moved}
	srv.reconcileDeadRun(moved, runVerdict{})

	// The original must be untouched: reconciling the copy must not reach
	// across into a project it was never asked about.
	originState, err := state.Load(origin)
	if err != nil {
		t.Fatalf("reload origin: %v", err)
	}
	for _, task := range originState.Plan.Tasks {
		if task.ID == taskID && task.Status != pm.TaskInProgress {
			t.Errorf("origin task status = %q, want %q — reconciling a relocated copy wrote into the original",
				task.Status, pm.TaskInProgress)
		}
	}
}

// TestSameDir covers the path comparison the relocation guard rests on.
func TestSameDir(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, a, b string
		want       bool
	}{
		{"identical", dir, dir, true},
		{"empty stored workdir is backfilled by Load", "", dir, true},
		{"trailing slash is the same dir", dir + "/", dir, true},
		{"different dirs", dir, filepath.Join(dir, "sub"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameDir(tc.a, tc.b); got != tc.want {
				t.Errorf("sameDir(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestReconcileStaleTasksIsIdempotent: the startup sweep and the per-tick edge
// can both fire for the same project, and a second pass must be a no-op rather
// than re-annotating or re-timestamping settled work.
func TestReconcileStaleTasksIsIdempotent(t *testing.T) {
	dir, taskID := stalledProject(t)
	srv := &Server{WorkDir: dir}

	srv.reconcileDeadRun(dir, runVerdict{})
	first, err := state.Load(dir)
	if err != nil {
		t.Fatalf("reload after first pass: %v", err)
	}

	srv.reconcileDeadRun(dir, runVerdict{})
	second, err := state.Load(dir)
	if err != nil {
		t.Fatalf("reload after second pass: %v", err)
	}

	find := func(ps *state.ProjectState) *pm.Task {
		for _, task := range ps.Plan.Tasks {
			if task.ID == taskID {
				return task
			}
		}
		return nil
	}
	a, b := find(first), find(second)
	if a == nil || b == nil {
		t.Fatal("task missing after reconciliation")
	}
	if len(a.Annotations) != len(b.Annotations) {
		t.Errorf("annotations grew from %d to %d on a second pass", len(a.Annotations), len(b.Annotations))
	}
	if b.Status != pm.TaskDone {
		t.Errorf("status = %q after second pass, want %q", b.Status, pm.TaskDone)
	}
}
