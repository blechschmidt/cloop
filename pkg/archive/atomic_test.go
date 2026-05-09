package archive_test

// Regression tests for the atomic-write + corrupt-file quarantine fix in
// pkg/archive. .cloop/archive.json holds tasks that were moved out of the
// active plan; pkg/search/search.go walks the archive when scoring matches
// and `cloop task unarchive` reads it to restore tasks. A torn write
// previously could leave a 0-byte file (the old tmp+rename hand-roll
// skipped fsync of both the data file and the parent directory inode).
// LoadMapping → json.Unmarshal would then fail on every search/unarchive
// invocation until the user manually deleted the file — losing the entire
// archive history in the process.
//
// Pinned invariants:
//  1. Save leaves no leftover .tmp files in .cloop/.
//  2. A reader running in parallel with a writer never sees a 0-byte file.
//  3. Load on a corrupt JSON file quarantines the bad bytes aside and
//     returns nil (instead of erroring).
//  4. Load on a zero-byte file (post-crash leftover) returns nil cleanly.
//  5. Persisted file is 0o600 (archive may include task descriptions and
//     results that the user expects to stay project-internal).

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
	"time"

	"github.com/blechschmidt/cloop/pkg/archive"
	"github.com/blechschmidt/cloop/pkg/pm"
)

func TestSave_NoLeftoverTmpFiles(t *testing.T) {
	work := t.TempDir()

	tasks := []archive.ArchivedTask{
		{Task: pm.Task{ID: 1, Title: "first archived"}, ArchivedAt: time.Now()},
	}

	for i := 0; i < 8; i++ {
		if err := archive.Save(work, tasks); err != nil {
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

func TestSave_ConcurrentReaderNeverSeesPartial(t *testing.T) {
	work := t.TempDir()
	path := filepath.Join(work, ".cloop", "archive.json")

	// Build a payload large enough to widen the torn-write window. Each
	// task carries a 2KiB description so MarshalIndent produces tens of
	// kilobytes — much wider than a single write() syscall on most fs.
	bigDesc := strings.Repeat("d", 2048)
	tasks := make([]archive.ArchivedTask, 32)
	for i := range tasks {
		tasks[i] = archive.ArchivedTask{
			Task:       pm.Task{ID: i, Title: "t", Description: bigDesc},
			ArchivedAt: time.Now(),
		}
	}
	if err := archive.Save(work, tasks); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const iterations = 200
	var stop atomic.Bool
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			tasks[0].Task.Description = strings.Repeat("d", 2048+(i%512))
			if err := archive.Save(work, tasks); err != nil {
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
					t.Errorf("reader saw missing archive.json mid-write")
					return
				}
				continue
			}
			if len(data) == 0 {
				t.Errorf("reader saw 0-byte archive.json")
				return
			}
			if data[0] != '[' {
				t.Errorf("reader saw torn-write content (no leading '['): len=%d head=%q",
					len(data), string(data[:minInt(len(data), 32)]))
				return
			}
		}
	}()

	wg.Wait()

	if _, err := archive.Load(work); err != nil {
		t.Fatalf("post-race Load: %v", err)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestSave_PermissionsAre0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission semantics not enforced on Windows")
	}
	work := t.TempDir()

	if err := archive.Save(work, []archive.ArchivedTask{}); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(filepath.Join(work, ".cloop", "archive.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("expected mode 0600, got %o", got)
	}
}

// TestLoad_CorruptFileQuarantined ensures a malformed archive.json no longer
// hard-errors `cloop task unarchive` and the search-path code in
// pkg/search/search.go (which calls archive.Load on every search). Before
// the fix one bad save would propagate `parsing archive: ...` to every
// caller and the user couldn't recover without manually deleting the file
// — which silently destroys the archive history. After the fix Load
// quarantines the corrupt bytes aside and returns nil so search and
// unarchive can continue (search returns no archive matches; unarchive
// reports "task not found in archive" rather than failing outright).
func TestLoad_CorruptFileQuarantined(t *testing.T) {
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(work, ".cloop", "archive.json")
	// Truncated mid-array — the shape a torn pre-atomicfile write would
	// have produced.
	if err := os.WriteFile(path, []byte(`[{"task":{"id":1,"title":"truncated"`), 0o600); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	tasks, err := archive.Load(work)
	if err != nil {
		t.Fatalf("Load on corrupt file should not return an error, got: %v", err)
	}
	if len(tasks) != 0 {
		t.Errorf("expected empty archive on corrupt file, got %d tasks", len(tasks))
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

// TestLoad_ZeroByteFile is the post-crash zero-byte case for archive.json.
// json.Unmarshal of "" fails with `unexpected end of JSON input`; previously
// this poisoned `cloop task archive`/`unarchive` until the user nuked the
// file. Now Load recovers transparently.
func TestLoad_ZeroByteFile(t *testing.T) {
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(work, ".cloop", "archive.json")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("seed empty: %v", err)
	}

	tasks, err := archive.Load(work)
	if err != nil {
		t.Fatalf("Load on zero-byte file should not return an error, got: %v", err)
	}
	if len(tasks) != 0 {
		t.Errorf("expected empty archive, got %d tasks", len(tasks))
	}
}

// TestSave_RoundTrip pins that ArchivedTask survives a Save→Load cycle.
// Catches regressions in the JSON tagging on ArchivedTask fields.
func TestSave_RoundTrip(t *testing.T) {
	work := t.TempDir()

	now := time.Now().UTC().Truncate(time.Second)
	want := []archive.ArchivedTask{
		{Task: pm.Task{ID: 1, Title: "first", Status: pm.TaskDone}, ArchivedAt: now},
		{Task: pm.Task{ID: 2, Title: "second", Status: pm.TaskSkipped}, ArchivedAt: now},
	}
	if err := archive.Save(work, want); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := archive.Load(work)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 archived tasks, got %d", len(got))
	}
	if got[0].Task.Title != "first" || got[1].Task.Title != "second" {
		t.Errorf("titles mismatch: got %q, %q", got[0].Task.Title, got[1].Task.Title)
	}
	if got[0].Task.Status != pm.TaskDone || got[1].Task.Status != pm.TaskSkipped {
		t.Errorf("statuses mismatch: got %q, %q", got[0].Task.Status, got[1].Task.Status)
	}
	if !got[0].ArchivedAt.Equal(now) {
		t.Errorf("ArchivedAt mismatch: got %v want %v", got[0].ArchivedAt, now)
	}
}
