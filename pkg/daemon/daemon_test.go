package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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

// TestStop_NoDaemonRunning verifies Stop returns a clear error when there's
// nothing to stop (no PID file or stale PID).
func TestStop_NoDaemonRunning(t *testing.T) {
	dir := t.TempDir()
	err := Stop(dir)
	if err == nil {
		t.Fatal("Stop on empty workdir: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not running") {
		t.Errorf("Stop error should mention 'not running'; got %v", err)
	}
}

// TestStop_BlocksUntilWorkerExits is the load-bearing regression test: Stop
// must not return before the daemon worker has cleaned up (removed its PID
// file, fsynced final state, etc.). Otherwise a `daemon stop && daemon start`
// pair can race and spawn two workers.
//
// We simulate a worker by spawning `sleep`, writing its PID, and verifying
// that Stop returns ~immediately after the process is gone (sleep exits on
// SIGTERM ~instantly). A reaper goroutine calls Wait() so the child doesn't
// linger as a zombie that Signal(0) would still see as "alive" — in
// production the daemon worker is detached and reaped by init, so the same
// concern doesn't apply there.
func TestStop_BlocksUntilWorkerExits(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep not available")
	}
	dir := t.TempDir()

	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawning sleep: %v", err)
	}
	waited := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(waited)
	}()
	defer func() {
		_ = cmd.Process.Kill()
		<-waited
	}()

	if err := WritePID(dir, cmd.Process.Pid); err != nil {
		t.Fatalf("WritePID: %v", err)
	}

	// Stop should send SIGTERM, see the process die, and return cleanly.
	start := time.Now()
	if err := Stop(dir); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	elapsed := time.Since(start)

	// sleep dies promptly on SIGTERM; we should observe that within a
	// poll-interval or two. Anything close to the production grace timeout
	// would mean Stop wasn't actually polling for exit.
	if elapsed > 2*time.Second {
		t.Errorf("Stop took %s — should have returned shortly after SIGTERM-induced exit", elapsed)
	}

	<-waited
	// Process must really be gone.
	if err := cmd.Process.Signal(syscall.Signal(0)); err == nil {
		t.Error("sleep process is still alive after Stop returned")
	}
}

// TestStopWithTimeout_EscalatesToSIGKILL covers the wedged-worker path: if
// the daemon ignores SIGTERM (here, a subprocess that traps it), Stop must
// escalate to SIGKILL within the grace window so a stuck daemon can always be
// replaced. The PID file must be removed in that case since the killed
// worker can't run its own cleanup.
func TestStopWithTimeout_EscalatesToSIGKILL(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	dir := t.TempDir()

	// Trap SIGTERM and keep sleeping; only SIGKILL will reap this.
	script := `trap '' TERM; while true; do sleep 1; done`
	cmd := exec.Command("sh", "-c", script)
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawning trap script: %v", err)
	}
	waited := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(waited)
	}()
	defer func() {
		_ = cmd.Process.Kill()
		<-waited
	}()

	if err := WritePID(dir, cmd.Process.Pid); err != nil {
		t.Fatalf("WritePID: %v", err)
	}

	// Use a short grace so the test isn't slow.
	start := time.Now()
	err := StopWithTimeout(dir, 300*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("StopWithTimeout: expected escalation error, got nil")
	}
	if !strings.Contains(err.Error(), "force-killed") && !strings.Contains(err.Error(), "did not exit") {
		t.Errorf("expected force-kill diagnostic; got %v", err)
	}
	if elapsed < 250*time.Millisecond {
		t.Errorf("StopWithTimeout returned in %s — should have waited the full grace period before SIGKILL", elapsed)
	}

	// Wait for SIGKILL to actually reap the process before asserting.
	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		t.Error("trap subprocess is still alive after force-kill path")
	}

	// PID file must be cleaned up since the killed worker couldn't.
	if _, statErr := os.Stat(PIDPath(dir)); statErr == nil {
		t.Error("PID file should be removed after SIGKILL escalation")
	} else if !os.IsNotExist(statErr) {
		t.Errorf("unexpected stat error: %v", statErr)
	}
}
