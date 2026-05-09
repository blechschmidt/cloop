package memory

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// TestSave_NoLeftoverTmpFiles verifies the atomic-write path does not leak
// .tmp files into .cloop/ on success. This catches anyone reverting Save() to
// a direct os.WriteFile or breaking the cleanup defer in writeAtomic.
func TestSave_NoLeftoverTmpFiles(t *testing.T) {
	dir := tempDir(t)
	m := &Memory{NextID: 1}
	m.Add("learning A", "ai", "goal", nil)

	for i := 0; i < 5; i++ {
		if err := m.Save(dir); err != nil {
			t.Fatalf("save iter %d: %v", i, err)
		}
	}

	cloopDir := filepath.Join(dir, ".cloop")
	entries, err := os.ReadDir(cloopDir)
	if err != nil {
		t.Fatalf("read .cloop: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("leftover tmp file after Save: %s", e.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(cloopDir, "memory.json")); err != nil {
		t.Errorf("expected memory.json to exist: %v", err)
	}
}

// TestSave_ConcurrentReaderNeverSeesEmptyOrPartialFile spins up a hot writer
// and a hot reader. The reader must NEVER see a 0-byte file, a missing file
// after the first successful save, or a partial JSON document. This is the
// regression test for the os.WriteFile → atomic-write fix.
func TestSave_ConcurrentReaderNeverSeesEmptyOrPartialFile(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, ".cloop", "memory.json")

	// Seed with a valid file.
	m := &Memory{NextID: 1}
	for i := 0; i < 50; i++ {
		m.Add(strings.Repeat("x", 200), "ai", "goal", nil)
	}
	if err := m.Save(dir); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	const iterations = 200
	var stop atomic.Bool
	var wg sync.WaitGroup

	// Writer goroutine — keeps mutating and saving.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			m.Add("entry-"+strings.Repeat("y", 100), "ai", "goal", nil)
			if err := m.Save(dir); err != nil {
				t.Errorf("save: %v", err)
				return
			}
		}
	}()

	// Reader goroutine — keeps reading and decoding the JSON. Must always
	// see either the seed file or a later valid file. The previous
	// non-atomic os.WriteFile would let it observe a truncated/empty blob.
	// The reader signals stop on exit so the writer terminates and wg.Wait
	// returns; otherwise the writer would loop forever and deadlock the test.
	var observedBad atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stop.Store(true)
		for i := 0; i < iterations; i++ {
			data, err := os.ReadFile(path)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					observedBad.Add(1)
					t.Errorf("reader saw missing file mid-write")
					return
				}
				continue
			}
			if len(data) == 0 {
				observedBad.Add(1)
				t.Errorf("reader saw 0-byte file")
				return
			}
			var got Memory
			if err := json.Unmarshal(data, &got); err != nil {
				observedBad.Add(1)
				t.Errorf("reader saw partial/invalid JSON: %v (len=%d)", err, len(data))
				return
			}
		}
	}()

	wg.Wait()

	if observedBad.Load() > 0 {
		t.Fatalf("reader observed %d bad states (expected 0)", observedBad.Load())
	}
}

// TestSave_RoundTripPreservesPermissions ensures the atomic write path keeps
// the 0644 mode (no escalation, no degradation).
func TestSave_RoundTripPreservesPermissions(t *testing.T) {
	dir := tempDir(t)
	m := &Memory{NextID: 1}
	m.Add("entry", "ai", "g", nil)
	if err := m.Save(dir); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, ".cloop", "memory.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Errorf("expected mode 0644, got %o", got)
	}
}
