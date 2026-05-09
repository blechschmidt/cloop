package learning

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestSaveMemory_FirstWriteCreatesHeader(t *testing.T) {
	dir := t.TempDir()
	if err := SaveMemory(dir, "first session distilled output"); err != nil {
		t.Fatalf("save: %v", err)
	}
	got := LoadMemory(dir)
	if !strings.Contains(got, "# cloop Project Memory") {
		t.Errorf("expected header, got: %q", got)
	}
	if !strings.Contains(got, "first session distilled output") {
		t.Errorf("expected summary in memory: %q", got)
	}
}

func TestSaveMemory_AppendsAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	if err := SaveMemory(dir, "session A"); err != nil {
		t.Fatalf("save A: %v", err)
	}
	if err := SaveMemory(dir, "session B"); err != nil {
		t.Fatalf("save B: %v", err)
	}
	got := LoadMemory(dir)
	if !strings.Contains(got, "session A") {
		t.Errorf("missing session A: %q", got)
	}
	if !strings.Contains(got, "session B") {
		t.Errorf("missing session B: %q", got)
	}
	// session A should appear before session B in the file.
	if strings.Index(got, "session A") > strings.Index(got, "session B") {
		t.Error("expected session A to appear before session B")
	}
}

func TestSaveMemory_EmptyIsNoop(t *testing.T) {
	dir := t.TempDir()
	if err := SaveMemory(dir, "   \n\t  "); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := LoadMemory(dir); got != "" {
		t.Errorf("expected empty memory, got: %q", got)
	}
}

// TestSaveMemory_ConcurrentAppends_NoLostUpdates verifies that under heavy
// concurrent SaveMemory pressure, every session's contribution is preserved.
// Without the saveMu lock + atomic write, the read-modify-write pattern in
// SaveMemory races and the second writer silently drops the first writer's
// session. With the fix, all 32 sessions are visible afterward.
func TestSaveMemory_ConcurrentAppends_NoLostUpdates(t *testing.T) {
	dir := t.TempDir()

	const N = 32
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			summary := fmt.Sprintf("UNIQUE_MARKER_%03d", i)
			if err := SaveMemory(dir, summary); err != nil {
				t.Errorf("save %d: %v", i, err)
			}
		}()
	}
	wg.Wait()

	got := LoadMemory(dir)
	for i := 0; i < N; i++ {
		marker := fmt.Sprintf("UNIQUE_MARKER_%03d", i)
		if !strings.Contains(got, marker) {
			t.Errorf("lost session: %s missing from accumulated memory", marker)
		}
	}
}

// TestSaveMemory_ConcurrentReaderNeverSeesPartialFile spins a writer and
// reader. The reader must never observe a 0-byte file or a file missing its
// header. Atomic rename guarantees readers see only complete files.
func TestSaveMemory_ConcurrentReaderNeverSeesPartialFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".cloop", "memory.md")

	// Seed.
	if err := SaveMemory(dir, "seed"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const iterations = 150
	var stop atomic.Bool
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			big := strings.Repeat("DATA_", 256)
			if err := SaveMemory(dir, big); err != nil {
				t.Errorf("save: %v", err)
				return
			}
		}
	}()

	// Reader runs a fixed number of iterations and signals stop on exit so the
	// unbounded writer goroutine terminates and wg.Wait returns. Without this,
	// the writer loops forever and the test deadlocks at wg.Wait.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stop.Store(true)
		for i := 0; i < iterations; i++ {
			data, err := os.ReadFile(path)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					t.Errorf("reader saw missing file mid-write")
					return
				}
				continue
			}
			if len(data) == 0 {
				t.Errorf("reader saw 0-byte file")
				return
			}
			if !strings.HasPrefix(string(data), "# cloop Project Memory") {
				t.Errorf("reader saw file without header (len=%d): %q",
					len(data), string(data[:min(80, len(data))]))
				return
			}
		}
	}()

	wg.Wait()
}

// TestSaveMemory_NoLeftoverTmpFiles ensures the atomic write does not leave
// orphaned .tmp files behind on success.
func TestSaveMemory_NoLeftoverTmpFiles(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		if err := SaveMemory(dir, fmt.Sprintf("session %d", i)); err != nil {
			t.Fatalf("save: %v", err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, ".cloop"))
	if err != nil {
		t.Fatalf("read .cloop: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("leftover tmp file: %s", e.Name())
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestLoadMemory_OversizeFileReturnsEmpty verifies that a memory.md exceeding
// memoryFileMaxBytes is NOT injected into prompts (LoadMemory returns ""),
// preventing an unbounded blob from blowing every task's token budget.
func TestLoadMemory_OversizeFileReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".cloop", "memory.md")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Write a payload larger than the cap.
	payload := strings.Repeat("X", int(memoryFileMaxBytes)+1024)
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := LoadMemory(dir); got != "" {
		t.Errorf("expected empty memory for oversize file, got %d bytes", len(got))
	}
}

// TestSaveMemory_OversizeFileSelfHeals verifies that when memory.md is over
// the cap, the next SaveMemory drops the bloated content and recreates a
// healthy file with the new session — so the system recovers automatically
// instead of amplifying the bloat by reading + appending + rewriting.
func TestSaveMemory_OversizeFileSelfHeals(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".cloop", "memory.md")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Pre-populate with a payload over the cap, with a unique marker we can
	// later assert was dropped.
	bloated := "## OLD_BLOATED_SESSION\n" + strings.Repeat("X", int(memoryFileMaxBytes)+1024)
	if err := os.WriteFile(path, []byte(bloated), 0o644); err != nil {
		t.Fatalf("write bloated: %v", err)
	}

	if err := SaveMemory(dir, "fresh session after bloat"); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if int64(len(got)) >= memoryFileMaxBytes {
		t.Errorf("expected file to shrink under cap after self-heal, got %d bytes", len(got))
	}
	if strings.Contains(string(got), "OLD_BLOATED_SESSION") {
		t.Error("expected old bloated content to be dropped")
	}
	if !strings.Contains(string(got), "fresh session after bloat") {
		t.Error("expected new session to be present in healed file")
	}
	if !strings.Contains(string(got), "# cloop Project Memory") {
		t.Error("expected header to be re-emitted in healed file")
	}
}
