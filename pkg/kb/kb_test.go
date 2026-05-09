package kb_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/kb"
)

func TestAddAndLoad(t *testing.T) {
	dir := t.TempDir()

	e1, err := kb.Add(dir, "first", "alpha", []string{"x"})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if e1.ID != 1 {
		t.Fatalf("expected id 1, got %d", e1.ID)
	}

	e2, err := kb.Add(dir, "second", "beta", nil)
	if err != nil {
		t.Fatalf("add 2: %v", err)
	}
	if e2.ID != 2 {
		t.Fatalf("expected id 2, got %d", e2.ID)
	}

	loaded, err := kb.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(loaded.Entries))
	}
}

func TestRemove(t *testing.T) {
	dir := t.TempDir()
	e, _ := kb.Add(dir, "doomed", "x", nil)
	if err := kb.Remove(dir, e.ID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	loaded, _ := kb.Load(dir)
	if len(loaded.Entries) != 0 {
		t.Fatalf("expected empty after remove, got %d", len(loaded.Entries))
	}
	if err := kb.Remove(dir, 999); err == nil {
		t.Fatalf("expected error removing missing entry")
	}
}

// TestAdd_ConcurrentNoLostUpdates exercises the lost-update fix:
// before kbMu was added, two goroutines each running Load → assign next id →
// Save would race — both reading the same nextID and one of the two appended
// entries would be silently dropped on the second goroutine's overwrite.
//
// With the fix, all N concurrent Add calls must result in N distinct entries
// in the file, with N distinct IDs.
func TestAdd_ConcurrentNoLostUpdates(t *testing.T) {
	dir := t.TempDir()

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			if _, err := kb.Add(dir, fmt.Sprintf("title-%d", i), "body", nil); err != nil {
				t.Errorf("add %d: %v", i, err)
			}
		}()
	}
	wg.Wait()

	loaded, err := kb.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded.Entries) != goroutines {
		t.Fatalf("expected %d entries, got %d (lost-update race?)", goroutines, len(loaded.Entries))
	}
	seen := make(map[int]bool, goroutines)
	for _, e := range loaded.Entries {
		if seen[e.ID] {
			t.Fatalf("duplicate id %d (lost-update race assigned same nextID twice)", e.ID)
		}
		seen[e.ID] = true
	}
}

// TestAdd_ReaderNeverSeesTornJSON spawns a writer that adds entries in a tight
// loop and a reader that calls Load() in parallel. With os.WriteFile (the old
// path) Load could race the truncate-then-write and see an empty/partial file
// and return a parse error. The atomic-rename Save must always present a
// complete document to readers.
func TestAdd_ReaderNeverSeesTornJSON(t *testing.T) {
	dir := t.TempDir()
	// Seed so the reader has a non-empty file from the start.
	if _, err := kb.Add(dir, "seed", "seed body", nil); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const iterations = 100
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if _, err := kb.Add(dir, fmt.Sprintf("t-%d", i), "x", nil); err != nil {
				t.Errorf("add: %v", err)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if _, err := kb.Load(dir); err != nil {
				t.Errorf("reader saw torn JSON: %v", err)
				return
			}
		}
	}()
	wg.Wait()
}

// TestSave_NoStaleTmpFiles confirms the writeAtomic cleanup defer fires —
// repeated saves should never accumulate ".tmp" staging files in .cloop/.
func TestSave_NoStaleTmpFiles(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 10; i++ {
		if _, err := kb.Add(dir, fmt.Sprintf("e-%d", i), "x", nil); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, ".cloop"))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if matched, _ := filepath.Match(".kb.json.*.tmp", e.Name()); matched {
			t.Errorf("leftover staging file: %s", e.Name())
		}
	}
}

// TestSave_FileIsValidJSON sanity-checks the format the atomic write produces.
func TestSave_FileIsValidJSON(t *testing.T) {
	dir := t.TempDir()
	if _, err := kb.Add(dir, "t", "body", []string{"a", "b"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, ".cloop", "kb.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, data)
	}
}
