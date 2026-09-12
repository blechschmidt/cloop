package eventlog

// Replay is the consumer that made Task 20218's amplification fix delicate.
//
// pkg/statedb/audit.go keeps actor='system' task.upsert rows rather than
// moving them to the `events` table precisely because Replay rebuilds the task
// tree from their payloads. These tests pin both halves of that reasoning:
// that skipping *no-op* upserts leaves the rebuild identical (a write that
// changes nothing contributes nothing to replay either), and that once
// retention has pruned the early history Replay says so instead of quietly
// producing a partial database.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditretention"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// buildProject writes a project whose plan is saved many times but changes
// rarely — the shape that used to produce O(saves × tasks) audit rows.
func buildProject(t *testing.T) (workDir string, wantTasks []*pm.Task) {
	t.Helper()
	workDir = t.TempDir()
	statedb.SetAuditEnabled(true)
	if err := os.MkdirAll(filepath.Join(workDir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}

	db, err := statedb.Open(filepath.Join(workDir, ".cloop", "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	plan := &pm.Plan{Goal: "replay fidelity", Version: 1}
	for i := 1; i <= 6; i++ {
		plan.Tasks = append(plan.Tasks, &pm.Task{
			ID: i, Title: "task " + string(rune('A'+i-1)),
			Description: "initial", Priority: 5, Status: pm.TaskPending,
		})
	}
	st := &statedb.State{
		Goal: "replay fidelity", WorkDir: workDir, Status: "running", Plan: plan,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := db.SaveState(st); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Many saves, few changes: tasks 2 and 5 progress, the rest never move.
	for i := 0; i < 15; i++ {
		switch i {
		case 4:
			plan.Tasks[1].Status = pm.TaskInProgress
		case 8:
			plan.Tasks[1].Status = pm.TaskDone
			plan.Tasks[1].Result = "finished"
		case 11:
			plan.Tasks[4].Status = pm.TaskFailed
		}
		st.CurrentStep = i + 1
		if err := db.SaveState(st); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	return workDir, plan.Tasks
}

func TestReplayReconstructsDespiteSkippedNoOpUpserts(t *testing.T) {
	workDir, want := buildProject(t)

	dest := filepath.Join(t.TempDir(), "rebuilt.db")
	rep, err := Replay(context.Background(), workDir, dest, ReplayOptions{})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if rep.BreakAtID != 0 {
		t.Fatalf("replay broke at id %d: %s", rep.BreakAtID, rep.BreakReason)
	}

	statedb.SetAuditEnabled(true)
	got, err := statedb.Open(dest)
	if err != nil {
		t.Fatalf("open rebuilt: %v", err)
	}
	defer got.Close()

	rebuilt, err := got.LoadState()
	if err != nil {
		t.Fatalf("load rebuilt: %v", err)
	}
	if rebuilt.Plan == nil || len(rebuilt.Plan.Tasks) != len(want) {
		t.Fatalf("rebuilt plan has %v tasks, want %d", tasksLen(rebuilt), len(want))
	}
	byID := map[int]*pm.Task{}
	for _, tk := range rebuilt.Plan.Tasks {
		byID[tk.ID] = tk
	}
	for _, w := range want {
		g, ok := byID[w.ID]
		if !ok {
			t.Errorf("task %d missing from the rebuild", w.ID)
			continue
		}
		if g.Status != w.Status || g.Title != w.Title || g.Result != w.Result {
			t.Errorf("task %d rebuilt as {%s %q %q}, want {%s %q %q}",
				w.ID, g.Status, g.Title, g.Result, w.Status, w.Title, w.Result)
		}
	}
}

func tasksLen(s *statedb.State) int {
	if s == nil || s.Plan == nil {
		return 0
	}
	return len(s.Plan.Tasks)
}

func TestReplayRefusesAPrunedTrailUnlessAsked(t *testing.T) {
	workDir, _ := buildProject(t)

	// Prune everything older than "now", which on this fixture is all of it.
	statedb.SetAuditEnabled(true)
	db, err := statedb.Open(filepath.Join(workDir, ".cloop", "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	archive := t.TempDir()
	pr, err := auditretention.Prune(db, auditretention.Options{
		Before:    time.Now().UTC().Add(time.Hour),
		ExportDir: archive,
		Actor:     "tester",
	})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if !pr.Pruned {
		t.Fatal("fixture produced nothing to prune")
	}
	db.Close()

	dest := filepath.Join(t.TempDir(), "rebuilt.db")
	_, err = Replay(context.Background(), workDir, dest, ReplayOptions{})
	if err == nil {
		t.Fatal("replay of a pruned trail succeeded silently; the rebuild would be partial")
	}
	if !strings.Contains(err.Error(), "pruned by retention") {
		t.Errorf("error did not explain the truncation: %v", err)
	}
	if !strings.Contains(err.Error(), pr.ExportPath) {
		t.Errorf("error did not name the archive holding the missing events: %v", err)
	}
	if _, statErr := os.Stat(dest); statErr == nil {
		t.Error("a destination database was created despite the refusal")
	}

	// Opting in must work and must mark the report.
	rep, err := Replay(context.Background(), workDir, dest, ReplayOptions{AllowTruncated: true})
	if err != nil {
		t.Fatalf("replay --allow-truncated: %v", err)
	}
	if !rep.Truncated || rep.ArchivePath != pr.ExportPath {
		t.Errorf("report did not record the truncation: %+v", rep)
	}
}
