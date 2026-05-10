package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRequestTaskKill_RoundTripThroughDisk(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir, "goal", 100); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := RequestTaskKill(dir, 5, "done", "ui"); err != nil {
		t.Fatalf("RequestTaskKill: %v", err)
	}
	rows, err := PendingKills(dir)
	if err != nil {
		t.Fatalf("PendingKills: %v", err)
	}
	if len(rows) != 1 || rows[0].TaskID != 5 || rows[0].TargetStatus != "done" {
		t.Fatalf("rows = %+v", rows)
	}

	r, ok, err := LookupTaskKill(dir, 5)
	if err != nil || !ok || r.TaskID != 5 {
		t.Errorf("LookupTaskKill = (%+v, %v, %v)", r, ok, err)
	}

	if err := ClearTaskKill(dir, 5); err != nil {
		t.Fatalf("ClearTaskKill: %v", err)
	}
	rows, _ = PendingKills(dir)
	if len(rows) != 0 {
		t.Errorf("rows after clear = %+v", rows)
	}
}

func TestRequestTaskKill_NoDB_NoOp(t *testing.T) {
	// Project never initialized — RequestTaskKill must return nil rather than
	// erroring or creating files. The orchestrator may not be running yet, in
	// which case there's nothing to cancel.
	dir := t.TempDir()
	if err := RequestTaskKill(dir, 1, "done", "ui"); err != nil {
		t.Errorf("RequestTaskKill on uninitialized dir = %v; want nil", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".cloop", "state.db")); err == nil {
		t.Error("RequestTaskKill created a state.db on uninitialized project; should be no-op")
	}
}

func TestRequestTaskKill_RejectsZeroOrEmpty(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir, "g", 0); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := RequestTaskKill("", 1, "done", "ui"); err != nil {
		t.Errorf("RequestTaskKill empty workDir = %v; want nil (silent no-op)", err)
	}
	if err := RequestTaskKill(dir, 0, "done", "ui"); err != nil {
		t.Errorf("RequestTaskKill task_id=0 = %v; want nil (silent no-op)", err)
	}
	rows, _ := PendingKills(dir)
	if len(rows) != 0 {
		t.Errorf("rows after rejected calls = %+v; want empty", rows)
	}
}
