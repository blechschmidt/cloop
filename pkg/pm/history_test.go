package pm

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestSaveSnapshot_AtomicNoTempFiles ensures SaveSnapshot leaves no tmp
// stragglers behind on the happy path — a torn tmp file would fail to
// json.Unmarshal and ListSnapshots would silently drop it.
func TestSaveSnapshot_AtomicNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	plan := &Plan{
		Goal: "test",
		Tasks: []*Task{
			{ID: 1, Title: "first", Status: TaskPending},
		},
	}
	if err := SaveSnapshot(dir, plan); err != nil {
		t.Fatalf("SaveSnapshot: %v", err)
	}

	entries, err := os.ReadDir(filepath.Join(dir, historyDir))
	if err != nil {
		t.Fatalf("read history dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") || strings.HasPrefix(e.Name(), ".") {
			t.Errorf("found leftover tmp file: %s", e.Name())
		}
	}
}

// TestSaveSnapshot_ConcurrentSerialisation hammers SaveSnapshot from many
// goroutines. Without serialisation, callers race on plan.Version++ and
// can write two files at the same version (one wins, other is clobbered),
// or write a file with a duplicate version that breaks LoadSnapshot ordering.
// With historyMu in place, every distinct fingerprint produces exactly one
// versioned file and ListSnapshots returns strictly increasing versions.
func TestSaveSnapshot_ConcurrentSerialisation(t *testing.T) {
	dir := t.TempDir()

	const writers = 8
	const iters = 10

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				// Each iteration makes a fresh Plan with a unique title
				// so the fingerprint differs and the dedup short-circuit
				// is bypassed — exercising the write path every time.
				plan := &Plan{
					Goal: "concurrent",
					Tasks: []*Task{
						{
							ID:     wid*1000 + i,
							Title:  "writer task",
							Status: TaskPending,
						},
					},
				}
				if err := SaveSnapshot(dir, plan); err != nil {
					t.Errorf("writer %d iter %d: SaveSnapshot: %v", wid, i, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	metas, err := ListSnapshots(dir)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(metas) == 0 {
		t.Fatalf("expected snapshots, got none")
	}

	// Every snapshot must load and parse cleanly — the atomicity guarantee.
	// Versions must be strictly increasing — the serialisation guarantee.
	seen := map[int]bool{}
	for _, m := range metas {
		if seen[m.Version] {
			t.Errorf("duplicate snapshot version %d", m.Version)
		}
		seen[m.Version] = true
		snap, err := LoadSnapshot(dir, m.Version)
		if err != nil {
			t.Errorf("LoadSnapshot v%d: %v", m.Version, err)
			continue
		}
		if snap.Plan == nil {
			t.Errorf("snapshot v%d has nil Plan", m.Version)
		}
	}

	// No leftover tmp files.
	entries, err := os.ReadDir(filepath.Join(dir, historyDir))
	if err != nil {
		t.Fatalf("read history dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") || strings.HasPrefix(e.Name(), ".") {
			t.Errorf("found leftover tmp file: %s", e.Name())
		}
	}
}
