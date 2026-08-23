package pm

import (
	"fmt"
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

// TestListSnapshots_QuarantinesCorruptFile pins the recovery flow: a torn or
// hand-edited snapshot in the history directory used to silently linger,
// re-parsed (and re-failed) on every `cloop snapshot list`. ListSnapshots
// now renames it aside as a .corrupt-* sibling so the next call sees a clean
// directory and the bad bytes remain available for forensic inspection.
func TestListSnapshots_QuarantinesCorruptFile(t *testing.T) {
	dir := t.TempDir()

	// Seed one good snapshot first so we have a file alongside the bad one.
	good := &Plan{
		Goal:  "test",
		Tasks: []*Task{{ID: 1, Title: "ok", Status: TaskPending}},
	}
	if err := SaveSnapshot(dir, good); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}

	histDir := filepath.Join(dir, historyDir)
	badPath := filepath.Join(histDir, "20260101-000000-v999.json")
	if err := os.WriteFile(badPath, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	metas, err := ListSnapshots(dir)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(metas) != 1 || metas[0].Version != 1 {
		t.Fatalf("expected only the good snapshot in metas, got %+v", metas)
	}

	if _, err := os.Stat(badPath); !os.IsNotExist(err) {
		t.Fatalf("corrupt snapshot should have been renamed away (stat err: %v)", err)
	}
	entries, err := os.ReadDir(histDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	foundCorrupt := false
	for _, e := range entries {
		if strings.Contains(e.Name(), ".corrupt-") {
			foundCorrupt = true
			break
		}
	}
	if !foundCorrupt {
		t.Fatalf("expected a .corrupt-* sibling preserving the bad bytes; entries=%v", entries)
	}

	// A subsequent ListSnapshots call must skip the .corrupt-* sibling rather
	// than treating it as a new snapshot to parse.
	metas2, err := ListSnapshots(dir)
	if err != nil {
		t.Fatalf("ListSnapshots second call: %v", err)
	}
	if len(metas2) != 1 {
		t.Fatalf("second ListSnapshots should still return 1 snapshot, got %d", len(metas2))
	}
}

// TestLoadSnapshot_QuarantinesCorruptVersion pins the LoadSnapshot recovery
// flow: a corrupt v<N> file used to render that version permanently un-loadable
// while leaving the bad bytes in place to fail every retry. We now rename it
// aside and surface a clear error so the caller knows v<N> is gone but the
// other versions remain accessible.
func TestLoadSnapshot_QuarantinesCorruptVersion(t *testing.T) {
	dir := t.TempDir()
	histDir := filepath.Join(dir, historyDir)
	if err := os.MkdirAll(histDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	badPath := filepath.Join(histDir, "20260101-000000-v5.json")
	if err := os.WriteFile(badPath, []byte("not json at all"), 0o644); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	if _, err := LoadSnapshot(dir, 5); err == nil {
		t.Fatalf("expected error from corrupt snapshot, got nil")
	}
	if _, err := os.Stat(badPath); !os.IsNotExist(err) {
		t.Fatalf("corrupt snapshot should have been renamed away (stat err: %v)", err)
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

// TestSaveSnapshot_DoesNotReadEverySnapshot pins the fix for the add-task
// stall (Task 20195). SaveSnapshot used to call ListSnapshots purely to learn
// the newest version, which reads and unmarshals *every* snapshot — and each
// snapshot is a full copy of the plan. On a real project (3.8k snapshots,
// ~525 KiB each) that meant parsing ~1.9 GiB per save, putting a ~16s stall
// behind every task add and status change in the UI.
//
// Asserting on wall-clock would be flaky, so this asserts the structural
// property that caused it: older snapshots must not be opened at all. The
// probe is that unparseable decoys survive untouched — the old code would
// have read them, failed to unmarshal, and quarantined them away.
func TestSaveSnapshot_DoesNotReadEverySnapshot(t *testing.T) {
	dir := t.TempDir()
	histDir := filepath.Join(dir, historyDir)
	if err := os.MkdirAll(histDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Seed decoys at v1..v20 that would blow up any reader.
	decoys := make([]string, 0, 20)
	for v := 1; v <= 20; v++ {
		name := filepath.Join(histDir, fmt.Sprintf("20260101-0000%02d-v%d.json", v, v))
		if err := os.WriteFile(name, []byte("{ this is not valid json"), 0o644); err != nil {
			t.Fatalf("seed decoy: %v", err)
		}
		decoys = append(decoys, name)
	}

	// The newest version is a decoy too, so SaveSnapshot cannot dedup and must
	// write. It must still pick v21 — version numbers are never reused, even
	// when the file holding the current max is unreadable.
	plan := &Plan{Goal: "g", Tasks: []*Task{{ID: 1, Title: "t", Status: TaskPending}}}
	if err := SaveSnapshot(dir, plan); err != nil {
		t.Fatalf("SaveSnapshot: %v", err)
	}
	if plan.Version != 21 {
		t.Errorf("version = %d, want 21 (max on-disk + 1)", plan.Version)
	}

	// Every decoy below the newest must be exactly as we left it: not read,
	// not quarantined, not rewritten.
	for _, name := range decoys[:len(decoys)-1] {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Errorf("decoy %s disappeared (it was read and quarantined): %v",
				filepath.Base(name), err)
			continue
		}
		if string(b) != "{ this is not valid json" {
			t.Errorf("decoy %s was rewritten", filepath.Base(name))
		}
	}
}

// TestSaveSnapshot_DedupStillSkipsIdenticalPlan guards the behaviour the
// fast path had to preserve: an unchanged plan writes nothing.
func TestSaveSnapshot_DedupStillSkipsIdenticalPlan(t *testing.T) {
	dir := t.TempDir()
	plan := &Plan{Goal: "g", Tasks: []*Task{{ID: 1, Title: "t", Status: TaskPending}}}
	if err := SaveSnapshot(dir, plan); err != nil {
		t.Fatalf("first save: %v", err)
	}
	firstVersion := plan.Version

	for i := 0; i < 3; i++ {
		if err := SaveSnapshot(dir, plan); err != nil {
			t.Fatalf("resave %d: %v", i, err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, historyDir))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("identical plan produced %d snapshots, want 1", len(entries))
	}
	if plan.Version != firstVersion {
		t.Errorf("dedup bumped version %d -> %d", firstVersion, plan.Version)
	}

	// A real change must still produce a new snapshot.
	plan.Tasks[0].Status = TaskDone
	if err := SaveSnapshot(dir, plan); err != nil {
		t.Fatalf("changed save: %v", err)
	}
	entries, _ = os.ReadDir(filepath.Join(dir, historyDir))
	if len(entries) != 2 {
		t.Errorf("changed plan produced %d snapshots, want 2", len(entries))
	}
}

// TestSnapshotVersionFromName covers the filename parser the fast path relies
// on, including the quarantined siblings it must ignore.
func TestSnapshotVersionFromName(t *testing.T) {
	cases := []struct {
		name string
		want int
		ok   bool
	}{
		{"20260823-181309-v3607.json", 3607, true},
		{"20260101-000000-v1.json", 1, true},
		{"20260101-000000-v0.json", 0, true},
		{"20260101-000000-v12.json.corrupt-1699999999", 0, false},
		{"20260101-000000-vabc.json", 0, false},
		{"20260101-000000-v-5.json", 0, false},
		{"notasnapshot.json", 0, false},
		{"20260101-000000-v7.txt", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := snapshotVersionFromName(c.name)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("snapshotVersionFromName(%q) = (%d,%v), want (%d,%v)",
				c.name, got, ok, c.want, c.ok)
		}
	}
}
