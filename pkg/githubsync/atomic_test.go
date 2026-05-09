package githubsync_test

// Regression tests for the atomic-write + corrupt-file quarantine fix in
// pkg/githubsync. .cloop/github-sync.json holds the bidirectional task↔issue
// mapping; a torn write previously could leave a 0-byte file. The next
// LoadMapping would then propagate `parsing .cloop/github-sync.json: ...` to
// every `cloop sync github push|pull`. Worse — once a user removed the bad
// file, every previously-synced task would look "unlinked" and the next push
// would create duplicate GitHub issues for already-synced work.
//
// Pinned invariants:
//  1. Save leaves no leftover .tmp files in .cloop/.
//  2. A reader running in parallel with a writer never sees a 0-byte file.
//  3. LoadMapping on a corrupt JSON file quarantines the bad bytes aside and
//     returns an empty mapping (instead of erroring).
//  4. LoadMapping on a zero-byte file (post-crash leftover) returns an empty
//     mapping (instead of erroring).

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

	"github.com/blechschmidt/cloop/pkg/githubsync"
)

func TestSave_NoLeftoverTmpFiles(t *testing.T) {
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	m := &githubsync.Mapping{
		TaskToIssue: map[int]int{1: 101, 2: 202},
		IssueToTask: map[int]int{101: 1, 202: 2},
	}

	for i := 0; i < 8; i++ {
		if err := m.Save(work); err != nil {
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
	if err := os.MkdirAll(filepath.Join(work, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(work, ".cloop", "github-sync.json")

	// Build a payload large enough to widen the torn-write window.
	m := &githubsync.Mapping{
		TaskToIssue: make(map[int]int, 256),
		IssueToTask: make(map[int]int, 256),
	}
	for i := 0; i < 256; i++ {
		m.TaskToIssue[i] = i + 10000
		m.IssueToTask[i+10000] = i
	}
	if err := m.Save(work); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const iterations = 200
	var stop atomic.Bool
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			m.TaskToIssue[i+1000000] = i + 2000000
			if err := m.Save(work); err != nil {
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
					t.Errorf("reader saw missing github-sync.json mid-write")
					return
				}
				continue
			}
			if len(data) == 0 {
				t.Errorf("reader saw 0-byte github-sync.json")
				return
			}
			if data[0] != '{' {
				t.Errorf("reader saw torn-write content (no leading '{'): len=%d head=%q",
					len(data), string(data[:minInt(len(data), 32)]))
				return
			}
		}
	}()

	wg.Wait()

	if _, err := githubsync.LoadMapping(work); err != nil {
		t.Fatalf("post-race LoadMapping: %v", err)
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
	if err := os.MkdirAll(filepath.Join(work, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	m := &githubsync.Mapping{TaskToIssue: map[int]int{}, IssueToTask: map[int]int{}}
	if err := m.Save(work); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(filepath.Join(work, ".cloop", "github-sync.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("expected mode 0600, got %o", got)
	}
}

// TestLoadMapping_CorruptFileQuarantined ensures a malformed github-sync.json
// no longer hard-errors `cloop sync github push|pull`. Before the fix one bad
// save would propagate `parsing .cloop/github-sync.json: ...` to both push
// and pull and the user couldn't recover without manually deleting the file
// (which would orphan every previously-linked issue and spawn duplicates on
// the next push). After the fix LoadMapping quarantines the corrupt bytes
// aside and returns an empty mapping so the next push reconciles via the
// legacy Task.GitHubIssue field.
func TestLoadMapping_CorruptFileQuarantined(t *testing.T) {
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(work, ".cloop", "github-sync.json")
	// Truncated mid-object — exactly the shape a torn pre-atomicfile write
	// would have produced.
	if err := os.WriteFile(path, []byte(`{"task_to_issue":{"1":101,`), 0o600); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	m, err := githubsync.LoadMapping(work)
	if err != nil {
		t.Fatalf("LoadMapping on corrupt file should not return an error, got: %v", err)
	}
	if m == nil {
		t.Fatalf("LoadMapping on corrupt file should return a non-nil empty Mapping")
	}
	if len(m.TaskToIssue) != 0 || len(m.IssueToTask) != 0 {
		t.Errorf("expected empty mapping on corrupt file, got TaskToIssue=%v IssueToTask=%v",
			m.TaskToIssue, m.IssueToTask)
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

// TestLoadMapping_ZeroByteFile is the post-crash zero-byte case — a torn
// pre-atomicfile write that left the file truncated to 0 bytes. json.Unmarshal
// of "" fails with `unexpected end of JSON input`; previously this poisoned
// every github sync subcommand until the user manually nuked the file. Now
// LoadMapping recovers transparently.
func TestLoadMapping_ZeroByteFile(t *testing.T) {
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(work, ".cloop", "github-sync.json")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("seed empty: %v", err)
	}

	m, err := githubsync.LoadMapping(work)
	if err != nil {
		t.Fatalf("LoadMapping on zero-byte file should not return an error, got: %v", err)
	}
	if m == nil || len(m.TaskToIssue) != 0 || len(m.IssueToTask) != 0 {
		t.Errorf("expected empty Mapping, got %+v", m)
	}
}

// TestSave_RoundTrip pins that the mapping survives a Save→LoadMapping cycle,
// catching regressions in field tagging or in atomicfile's marshal path.
func TestSave_RoundTrip(t *testing.T) {
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	want := &githubsync.Mapping{
		TaskToIssue: map[int]int{1: 101, 2: 202, 3: 303},
		IssueToTask: map[int]int{101: 1, 202: 2, 303: 3},
	}
	if err := want.Save(work); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := githubsync.LoadMapping(work)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got.TaskToIssue) != 3 || got.TaskToIssue[2] != 202 {
		t.Errorf("TaskToIssue mismatch after round-trip: got %+v", got.TaskToIssue)
	}
	// LoadMapping rebuilds IssueToTask from TaskToIssue as the canonical source,
	// so this should match without us serialising it.
	if got.IssueToTask[202] != 2 {
		t.Errorf("IssueToTask not reconstructed: got %+v", got.IssueToTask)
	}
}
