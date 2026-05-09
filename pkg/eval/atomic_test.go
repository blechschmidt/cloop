package eval

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// TestSave_AtomicNoStaleTmpFiles verifies that the writeAtomic cleanup defer
// fires — repeated saves must not accumulate sibling .tmp files in the eval
// directory. A leftover indicates the temp-file lifecycle regressed (e.g. a
// revert to os.WriteFile that drops the staging step entirely).
func TestSave_AtomicNoStaleTmpFiles(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 10; i++ {
		r := &EvalResult{
			TaskID:      i + 1,
			TaskTitle:   "t",
			Scores:      []Score{{Value: 5}},
			Weighted:    5.0,
			EvaluatedAt: time.Now(),
		}
		if err := save(dir, r); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, ".cloop", "evals"))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if matched, _ := filepath.Match(".eval.json.*.tmp", e.Name()); matched {
			t.Errorf("leftover staging file: %s", e.Name())
		}
	}
}

// TestSave_ReaderNeverSeesTornJSON spawns a writer that saves the same task ID
// in a tight loop and a reader that calls Load in parallel. With a non-atomic
// os.WriteFile the reader could observe a truncate-then-write race and decode
// an empty/partial file. The atomic-rename save must always present a
// complete JSON document to readers.
func TestSave_ReaderNeverSeesTornJSON(t *testing.T) {
	dir := t.TempDir()
	const taskID = 42
	seed := &EvalResult{
		TaskID:      taskID,
		TaskTitle:   "seed",
		Scores:      []Score{{Value: 7}},
		Weighted:    7.0,
		EvaluatedAt: time.Now(),
	}
	if err := save(dir, seed); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	const iterations = 100
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			r := &EvalResult{
				TaskID:      taskID,
				TaskTitle:   "t",
				Scores:      []Score{{Value: 5}},
				Weighted:    5.0,
				EvaluatedAt: time.Now(),
			}
			if err := save(dir, r); err != nil {
				t.Errorf("save %d: %v", i, err)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			r, err := Load(dir, taskID)
			if err != nil {
				t.Errorf("reader saw torn JSON at iter %d: %v", i, err)
				return
			}
			if r == nil {
				t.Errorf("reader got nil result at iter %d", i)
				return
			}
		}
	}()

	wg.Wait()
}

// TestLoad_QuarantinesCorruptFile verifies that a hand-edited or torn-write
// eval result is renamed aside (preserved as a .corrupt-* sibling) and Load
// returns (nil, nil) so callers like `cloop eval show` and the auto-promote
// heuristic can proceed instead of bailing on the whole project.
func TestLoad_QuarantinesCorruptFile(t *testing.T) {
	dir := t.TempDir()
	const taskID = 7
	if err := os.MkdirAll(filepath.Join(dir, ".cloop", "evals"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := evalPath(dir, taskID)
	if err := os.WriteFile(path, []byte("{not valid json"), 0o644); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}

	r, err := Load(dir, taskID)
	if err != nil {
		t.Fatalf("Load returned error instead of recovering: %v", err)
	}
	if r != nil {
		t.Fatalf("expected nil result for quarantined file, got %+v", r)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("original corrupt file should have been renamed away (stat err: %v)", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	prefix := filepath.Base(path) + ".corrupt-"
	found := false
	for _, e := range entries {
		if len(e.Name()) > len(prefix) && e.Name()[:len(prefix)] == prefix {
			found = true
			break
		}
	}
	if !found {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("expected a %s* sibling preserving the bad bytes; entries=%v", prefix, names)
	}
}

// TestSave_FileIsValidJSON sanity-checks the format the atomic write produces.
func TestSave_FileIsValidJSON(t *testing.T) {
	dir := t.TempDir()
	task := &pm.Task{ID: 1, Title: "t"}
	r := &EvalResult{
		TaskID:      task.ID,
		TaskTitle:   task.Title,
		Scores:      []Score{{Value: 8, Rationale: "good"}},
		Weighted:    8.0,
		EvaluatedAt: time.Now(),
	}
	if err := save(dir, r); err != nil {
		t.Fatalf("save: %v", err)
	}
	data, err := os.ReadFile(evalPath(dir, r.TaskID))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, data)
	}
}
