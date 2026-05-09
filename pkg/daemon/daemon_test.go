package daemon

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestSave_RoundTrip verifies a basic save → load cycle works.
func TestSave_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := &State{
		PID:       4242,
		StartedAt: time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC),
		Status:    "idle",
		Interval:  "5m",
		Provider:  "anthropic",
	}
	if err := s.Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got == nil {
		t.Fatal("Load returned nil")
	}
	if got.PID != 4242 || got.Status != "idle" || got.Provider != "anthropic" {
		t.Fatalf("unexpected loaded state: %+v", got)
	}
}

// TestSave_AtomicNoTornFile verifies that concurrent saves never produce a
// torn (unparseable) daemon.json. Before the atomic-write + per-path lock
// fix, two goroutines racing on os.WriteFile could interleave content and
// Load() would fail with "corrupt daemon state". After the fix, Load() must
// always succeed regardless of how many writers race.
func TestSave_AtomicNoTornFile(t *testing.T) {
	dir := t.TempDir()
	const writers = 16
	const itersPerWriter = 40

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < itersPerWriter; i++ {
				s := &State{
					PID:                 id*1000 + i,
					Status:              "running",
					Interval:            "5m",
					RunCount:            i,
					TotalTasksCompleted: i * 2,
					LastError:           "",
				}
				if err := s.Save(dir); err != nil {
					t.Errorf("writer %d save: %v", id, err)
					return
				}
			}
		}(w)
	}

	// Concurrently load while writers race; every Load must succeed because
	// either the old or the new fully-written file is visible — never a half
	// file. (json.Unmarshal of a torn file would surface as a load error.)
	done := make(chan struct{})
	var loadErr error
	go func() {
		defer close(done)
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := Load(dir); err != nil {
				loadErr = err
				return
			}
		}
	}()
	wg.Wait()
	<-done
	if loadErr != nil {
		t.Fatalf("Load saw a torn write: %v", loadErr)
	}

	// Final state must be parseable.
	if _, err := Load(dir); err != nil {
		t.Fatalf("final Load: %v", err)
	}
}

// TestSave_NoStaleTmpFiles verifies atomic-write cleans up its tmp file under
// happy-path conditions (the rename consumes it; no leftover .tmp on disk).
func TestSave_NoStaleTmpFiles(t *testing.T) {
	dir := t.TempDir()
	s := &State{PID: 1, Status: "idle"}
	for i := 0; i < 5; i++ {
		if err := s.Save(dir); err != nil {
			t.Fatalf("save: %v", err)
		}
	}
	cloopDir := filepath.Join(dir, ".cloop")
	entries, err := os.ReadDir(cloopDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if filepath.Ext(name) == ".tmp" || (len(name) > 4 && name[:1] == "." && name != ".") {
			// Allow the canonical files; flag anything that looks like a leftover tmp.
			if name == "daemon.json" {
				continue
			}
			t.Fatalf("unexpected leftover file in .cloop/: %s", name)
		}
	}
}

// TestWritePID_Atomic verifies WritePID is safe under concurrent calls and
// produces a parseable PID file.
func TestWritePID_Atomic(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(pid int) {
			defer wg.Done()
			if err := WritePID(dir, pid); err != nil {
				t.Errorf("WritePID(%d): %v", pid, err)
			}
		}(1000 + i)
	}
	wg.Wait()
	got := ReadPID(dir)
	if got < 1000 || got >= 1020 {
		t.Fatalf("ReadPID returned %d, expected one of 1000..1019", got)
	}
}
