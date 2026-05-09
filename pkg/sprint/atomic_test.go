package sprint_test

// Regression tests for the atomic-write + serialised-write fix in sprint.go.
//
// .cloop/sprints.json holds the project's planned sprints (names, goals,
// task assignments, dates). Save() rewrites the entire file as a unit. A
// torn write (crash, ENOSPC, two `cloop sprint plan` runs racing) would
// truncate the JSON and `cloop sprint list/show/burndown` would all fail
// to parse on the next read — the sprint structure would be silently lost.
//
// Pinned invariants:
//  1. Save leaves no leftover .tmp files.
//  2. A reader running in parallel with a writer never sees a 0-byte file.
//  3. N concurrent Save() callers all complete cleanly and the final file
//     loads as one of the inputs (not garbled mid-marshal output).
//  4. Persisted file is 0o600 (sprint plans are project-internal).

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/cloop/pkg/sprint"
)

// TestSave_NoLeftoverTmpFiles asserts the atomic write path renames its
// staging tmp files instead of leaking them next to sprints.json.
func TestSave_NoLeftoverTmpFiles(t *testing.T) {
	work := t.TempDir()

	sf := &sprint.SprintFile{
		Sprints: []*sprint.Sprint{
			{ID: 1, Name: "Sprint 1", Goal: "Foundations", TaskIDs: []int{1, 2}},
		},
	}

	for i := 0; i < 8; i++ {
		if err := sprint.Save(work, sf); err != nil {
			t.Fatalf("save iter %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(filepath.Join(work, ".cloop"))
	if err != nil {
		t.Fatalf("read .cloop: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("leftover tmp file after Save: %s", e.Name())
		}
	}
}

// TestSave_ConcurrentReaderNeverSeesPartial pits a hot Save writer against a
// hot reader. Without the atomic rename the reader would see a 0-byte
// sprints.json in the os.WriteFile→write-syscall window.
func TestSave_ConcurrentReaderNeverSeesPartial(t *testing.T) {
	work := t.TempDir()
	path := filepath.Join(work, ".cloop", "sprints.json")

	// Build a payload large enough to widen the torn-write window.
	bigGoal := strings.Repeat("g", 2048)
	sf := &sprint.SprintFile{
		Sprints: []*sprint.Sprint{
			{ID: 1, Name: "S1", Goal: bigGoal, TaskIDs: []int{1, 2, 3, 4, 5, 6, 7, 8}},
			{ID: 2, Name: "S2", Goal: bigGoal, TaskIDs: []int{9, 10, 11, 12}},
		},
	}
	if err := sprint.Save(work, sf); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const iterations = 200
	var stop atomic.Bool
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			sf.Sprints[0].Goal = strings.Repeat("g", 2048+(i%512))
			if err := sprint.Save(work, sf); err != nil {
				t.Errorf("save: %v", err)
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stop.Store(true)
		for i := 0; i < iterations; i++ {
			data, err := os.ReadFile(path)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					t.Errorf("reader saw missing sprints.json mid-write")
					return
				}
				continue
			}
			if len(data) == 0 {
				t.Errorf("reader saw 0-byte sprints.json")
				return
			}
			// Don't strictly Unmarshal here — Load handles the schema and is
			// the canonical entry point. We just need to know readers never
			// observe a truncated file.
			if data[0] != '{' {
				t.Errorf("reader saw torn-write content (no leading '{'): len=%d head=%q", len(data), string(data[:min(len(data), 32)]))
				return
			}
		}
	}()

	wg.Wait()

	// And after the writer finishes, the file must Load cleanly.
	if _, err := sprint.Load(work); err != nil {
		t.Fatalf("post-race Load: %v", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestSave_ConcurrentWritersAllSucceed fires N goroutines into Save with
// distinct payloads. The serialisation guarantee is per-call atomicity (one
// Save's MarshalIndent buffer doesn't tear into another's write); the final
// file must load cleanly regardless of which writer landed last.
func TestSave_ConcurrentWritersAllSucceed(t *testing.T) {
	work := t.TempDir()

	const writers = 16
	const iters = 25
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				sf := &sprint.SprintFile{
					Sprints: []*sprint.Sprint{
						{ID: w, Name: "Sprint", Goal: "g", TaskIDs: []int{w, i}},
					},
				}
				if err := sprint.Save(work, sf); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("save: %v", err)
	}

	got, err := sprint.Load(work)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got.Sprints) != 1 {
		t.Fatalf("expected exactly 1 sprint (last writer wins), got %d", len(got.Sprints))
	}
}

// TestSave_PermissionsAre0600 keeps the file owner-only readable.
func TestSave_PermissionsAre0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission semantics not enforced on Windows")
	}
	work := t.TempDir()

	if err := sprint.Save(work, &sprint.SprintFile{}); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(filepath.Join(work, ".cloop", "sprints.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("expected mode 0600, got %o", got)
	}
}

// TestLoad_CorruptFileQuarantined ensures a malformed sprints.json no longer
// hard-errors every `cloop sprint *` subcommand. Before the fix, one bad save
// would propagate `sprint: parse sprints.json: ...` to list/show/burndown and
// to PlanCommit (which Loads then mutates), leaving the user unable to
// recover without manually deleting the file. After the fix Load quarantines
// the corrupt bytes aside and returns an empty SprintFile so a fresh plan can
// be created.
func TestLoad_CorruptFileQuarantined(t *testing.T) {
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(work, ".cloop", "sprints.json")
	// Truncated mid-array — exactly the shape a torn pre-atomicfile write
	// would have produced.
	if err := os.WriteFile(path, []byte(`{"sprints":[{"id":1,"name":"S1"`), 0o600); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	sf, err := sprint.Load(work)
	if err != nil {
		t.Fatalf("Load on corrupt file should not return an error, got: %v", err)
	}
	if sf == nil {
		t.Fatalf("Load on corrupt file should return a non-nil empty SprintFile")
	}
	if len(sf.Sprints) != 0 {
		t.Errorf("expected empty sprint list on corrupt file, got %d sprints", len(sf.Sprints))
	}

	// Original path freed up; corrupt bytes preserved under .corrupt-* sibling.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected corrupt %s to be moved aside, stat err = %v", path, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	found := false
	for _, e := range entries {
		if strings.Contains(e.Name(), ".corrupt-") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a .corrupt-* sibling preserving the bad bytes, dir contents: %v", entries)
	}
}

// TestLoad_ZeroByteSprintsFile is the post-crash zero-byte case for sprints.
// json.Unmarshal of "" fails with `unexpected end of JSON input`; previously
// this poisoned every sprint command until the user nuked the file. Now Load
// recovers transparently.
func TestLoad_ZeroByteSprintsFile(t *testing.T) {
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(work, ".cloop", "sprints.json")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("seed empty: %v", err)
	}

	sf, err := sprint.Load(work)
	if err != nil {
		t.Fatalf("Load on zero-byte file should not return an error, got: %v", err)
	}
	if sf == nil || len(sf.Sprints) != 0 {
		t.Errorf("expected empty SprintFile, got %+v", sf)
	}
}
