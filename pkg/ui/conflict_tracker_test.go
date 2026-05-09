package ui

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestConflictTracker_DetectsActiveConflict pins the core contract: two
// different clients editing the same field within conflictWindow should be
// flagged as a conflict.
func TestConflictTracker_DetectsActiveConflict(t *testing.T) {
	s := New(t.TempDir(), 0, "")
	const wd = "/tmp/proj"

	if got := s.checkAndRecordEdit(wd, "alice", 1, []string{"title"}); got {
		t.Fatalf("first edit reported conflict; want false")
	}
	if got := s.checkAndRecordEdit(wd, "bob", 1, []string{"title"}); !got {
		t.Fatalf("second edit by different client within window reported no conflict; want true")
	}
}

// TestConflictTracker_SameClientNoConflict confirms self-edits are never
// flagged — only cross-client races count.
func TestConflictTracker_SameClientNoConflict(t *testing.T) {
	s := New(t.TempDir(), 0, "")
	const wd = "/tmp/proj"

	s.checkAndRecordEdit(wd, "alice", 1, []string{"title"})
	if got := s.checkAndRecordEdit(wd, "alice", 1, []string{"title"}); got {
		t.Fatalf("repeat edit from same client flagged as conflict; want false")
	}
}

// TestConflictTracker_StaleEntryDoesNotConflict verifies the
// time-based sweep: an entry older than conflictWindow no longer triggers a
// conflict, and is removed from the tracker.
func TestConflictTracker_StaleEntryDoesNotConflict(t *testing.T) {
	s := New(t.TempDir(), 0, "")
	const wd = "/tmp/proj"
	const key = "1:title"

	s.checkAndRecordEdit(wd, "alice", 1, []string{"title"})

	s.conflictMu.Lock()
	if s.conflictTracker[wd][key] == nil {
		s.conflictMu.Unlock()
		t.Fatalf("entry not recorded")
	}
	s.conflictTracker[wd][key].editedAt = time.Now().Add(-2 * conflictWindow)
	s.conflictMu.Unlock()

	if got := s.checkAndRecordEdit(wd, "bob", 1, []string{"title"}); got {
		t.Fatalf("stale entry triggered conflict; want false")
	}
}

// TestConflictTracker_SweepRemovesStaleEntries is the load-bearing memory test:
// a workDir that stops being edited must not retain its entries forever. The
// global per-call sweep should drop stale projects entirely.
func TestConflictTracker_SweepRemovesStaleEntries(t *testing.T) {
	s := New(t.TempDir(), 0, "")
	const idle = "/tmp/idle-proj"
	const active = "/tmp/active-proj"

	for i := 0; i < 100; i++ {
		s.checkAndRecordEdit(idle, "alice", i, []string{"title"})
	}

	s.conflictMu.Lock()
	if got := len(s.conflictTracker[idle]); got != 100 {
		s.conflictMu.Unlock()
		t.Fatalf("setup: idle project has %d entries; want 100", got)
	}
	for _, e := range s.conflictTracker[idle] {
		e.editedAt = time.Now().Add(-2 * conflictWindow)
	}
	s.conflictMu.Unlock()

	s.checkAndRecordEdit(active, "bob", 1, []string{"title"})

	s.conflictMu.Lock()
	defer s.conflictMu.Unlock()
	if _, present := s.conflictTracker[idle]; present {
		t.Fatalf("idle project still in tracker; want swept")
	}
	if got := len(s.conflictTracker[active]); got == 0 {
		t.Fatalf("active project unexpectedly empty")
	}
}

// TestConflictTracker_HardCapEnforced guarantees the defense-in-depth ceiling:
// if the time-based sweep is bypassed (e.g., wall-clock skew makes everything
// look fresh), the inner map still cannot grow without limit.
func TestConflictTracker_HardCapEnforced(t *testing.T) {
	s := New(t.TempDir(), 0, "")
	const wd = "/tmp/proj"

	for i := 0; i < maxConflictEntriesPerWorkDir+512; i++ {
		s.checkAndRecordEdit(wd, "alice", i, []string{"title"})
	}

	s.conflictMu.Lock()
	got := len(s.conflictTracker[wd])
	s.conflictMu.Unlock()

	if got > maxConflictEntriesPerWorkDir {
		t.Fatalf("tracker size = %d, exceeds hard cap %d", got, maxConflictEntriesPerWorkDir)
	}
}

// TestConflictTracker_PerWorkDirIsolated confirms entries in one project don't
// bleed into another: a recent edit on workDir A must not satisfy a conflict
// query against workDir B.
func TestConflictTracker_PerWorkDirIsolated(t *testing.T) {
	s := New(t.TempDir(), 0, "")
	s.checkAndRecordEdit("/tmp/a", "alice", 1, []string{"title"})
	if got := s.checkAndRecordEdit("/tmp/b", "bob", 1, []string{"title"}); got {
		t.Fatalf("cross-workDir conflict reported; want false")
	}
}

// TestConflictTracker_ConcurrentSafe runs many writers in parallel under
// -race to catch any locking regressions in the sweep loop.
func TestConflictTracker_ConcurrentSafe(t *testing.T) {
	s := New(t.TempDir(), 0, "")
	const writers = 8
	const iters = 200

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			wd := fmt.Sprintf("/tmp/proj-%d", w%3)
			client := fmt.Sprintf("client-%d", w)
			for i := 0; i < iters; i++ {
				s.checkAndRecordEdit(wd, client, i, []string{"title", "desc"})
			}
		}(w)
	}
	wg.Wait()

	s.conflictMu.Lock()
	defer s.conflictMu.Unlock()
	for wd, m := range s.conflictTracker {
		if len(m) > maxConflictEntriesPerWorkDir {
			t.Fatalf("workDir %s tracker size %d exceeds cap", wd, len(m))
		}
	}
}
