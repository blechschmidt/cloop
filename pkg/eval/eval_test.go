package eval

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSave_AtomicNoTempFiles verifies that save() leaves no .tmp stragglers in
// the evals dir on success — the rename must clean up the staging file.
func TestSave_AtomicNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	r := &EvalResult{
		TaskID:      1,
		TaskTitle:   "first",
		Weighted:    7.5,
		EvaluatedAt: time.Now().UTC(),
	}
	if err := save(dir, r); err != nil {
		t.Fatalf("save: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, ".cloop", "evals"))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("leftover tmp file after save: %s", e.Name())
		}
	}
}

// TestSave_OverwriteIsAtomic verifies that save() called twice on the same
// task ID replaces the file cleanly — the second result is what Load returns,
// and there are no tmp stragglers afterwards.
func TestSave_OverwriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	first := &EvalResult{TaskID: 1, TaskTitle: "first", Weighted: 1.0, EvaluatedAt: time.Now().UTC()}
	if err := save(dir, first); err != nil {
		t.Fatalf("save first: %v", err)
	}
	second := &EvalResult{TaskID: 1, TaskTitle: "second", Weighted: 9.5, EvaluatedAt: time.Now().UTC()}
	if err := save(dir, second); err != nil {
		t.Fatalf("save second: %v", err)
	}
	got, err := Load(dir, 1)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got == nil || got.TaskTitle != "second" || got.Weighted != 9.5 {
		t.Fatalf("expected second result, got %+v", got)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, ".cloop", "evals"))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("leftover tmp file after overwrite: %s", e.Name())
		}
	}
}

// TestSave_ConcurrentNoCorruption hammers save() with many goroutines on
// distinct task IDs. Each saved file must be valid JSON when read back, and
// no .tmp stragglers may remain. Run under -race to catch shared-state bugs.
func TestSave_ConcurrentNoCorruption(t *testing.T) {
	dir := t.TempDir()
	const writers = 8
	const iters = 25

	var wg sync.WaitGroup
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				r := &EvalResult{
					TaskID:      w*1000 + i,
					TaskTitle:   "concurrent",
					Weighted:    float64(i),
					EvaluatedAt: time.Now().UTC(),
				}
				if err := save(dir, r); err != nil {
					t.Errorf("save w=%d i=%d: %v", w, i, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	entries, err := os.ReadDir(filepath.Join(dir, ".cloop", "evals"))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("leftover tmp file after concurrent saves: %s", e.Name())
		}
		data, err := os.ReadFile(filepath.Join(dir, ".cloop", "evals", e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var r EvalResult
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatalf("parse %s: %v (data=%q)", e.Name(), err, data)
		}
	}
}
