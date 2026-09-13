package pm

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// snapshotCount counts well-formed snapshot files in a project's history.
func snapshotCount(t *testing.T, workDir string) int {
	t.Helper()
	entries, err := os.ReadDir(historyPath(workDir))
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("read plan-history: %v", err)
	}
	n := 0
	for _, e := range entries {
		if _, ok := snapshotVersionFromName(e.Name()); ok {
			n++
		}
	}
	return n
}

// withRetention sets the write-time keep-count for one test and restores the
// previous value afterwards. The setting is process-global, so tests that
// change it must not leak into their neighbours.
func withRetention(t *testing.T, keep int) {
	t.Helper()
	prev := SnapshotRetention()
	SetSnapshotRetention(keep)
	t.Cleanup(func() { SetSnapshotRetention(prev) })
}

// saveN writes n distinct snapshots. Each differs from the last so
// SaveSnapshot's deduplication does not swallow it.
func saveN(t *testing.T, workDir string, n int) *Plan {
	t.Helper()
	plan := &Plan{Goal: "retention", Tasks: []*Task{}}
	for i := 0; i < n; i++ {
		plan.Tasks = append(plan.Tasks, &Task{
			ID:     i + 1,
			Title:  fmt.Sprintf("task %d", i+1),
			Status: TaskPending,
		})
		if err := SaveSnapshot(workDir, plan); err != nil {
			t.Fatalf("SaveSnapshot %d: %v", i, err)
		}
	}
	return plan
}

// TestSaveSnapshot_SelfPrunes is the spec-required regression test for
// Task 20229: plan history must not outrun the janitor between passes, so
// SaveSnapshot bounds the directory in the same call that grew it.
func TestSaveSnapshot_SelfPrunes(t *testing.T) {
	withRetention(t, 5)
	dir := t.TempDir()

	saveN(t, dir, 40)

	if got := snapshotCount(t, dir); got != 5 {
		t.Fatalf("plan-history holds %d snapshots, want the keep-count of 5", got)
	}
}

// TestSaveSnapshot_KeepsNewest proves the prune keeps the newest versions, not
// an arbitrary five: a retention policy that discarded the latest snapshot
// would break rollback and diff while still looking bounded.
func TestSaveSnapshot_KeepsNewest(t *testing.T) {
	withRetention(t, 3)
	dir := t.TempDir()

	plan := saveN(t, dir, 20)
	newest := plan.Version

	metas, err := ListSnapshots(dir)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(metas) != 3 {
		t.Fatalf("got %d snapshots, want 3", len(metas))
	}
	// ListSnapshots sorts ascending by version.
	got := []int{metas[0].Version, metas[1].Version, metas[2].Version}
	want := []int{newest - 2, newest - 1, newest}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("surviving versions %v, want %v", got, want)
		}
	}
	// The newest must still load — the file kept is a real snapshot, not a
	// truncated remnant.
	if _, err := LoadSnapshot(dir, newest); err != nil {
		t.Fatalf("newest snapshot v%d does not load: %v", newest, err)
	}
}

// TestSaveSnapshot_RetentionDisabled confirms the opt-out really keeps
// everything. Zero must mean "retention off", never "keep zero".
func TestSaveSnapshot_RetentionDisabled(t *testing.T) {
	withRetention(t, 0)
	dir := t.TempDir()

	saveN(t, dir, 12)

	if got := snapshotCount(t, dir); got != 12 {
		t.Fatalf("retention disabled kept %d snapshots, want all 12", got)
	}
}

// TestPruneSnapshots_ZeroKeepIsNoOp guards the same invariant at the function
// an operator's config reaches: a keep-count that failed to parse arrives here
// as zero, and zero must not empty the directory.
func TestPruneSnapshots_ZeroKeepIsNoOp(t *testing.T) {
	withRetention(t, 0)
	dir := t.TempDir()
	saveN(t, dir, 6)

	st, err := PruneSnapshots(dir, 0, false)
	if err != nil {
		t.Fatalf("PruneSnapshots: %v", err)
	}
	if st.Deleted != 0 {
		t.Fatalf("keep=0 deleted %d snapshots; it must be a no-op", st.Deleted)
	}
	if got := snapshotCount(t, dir); got != 6 {
		t.Fatalf("keep=0 left %d snapshots, want 6", got)
	}
}

// TestPruneSnapshots_DryRun reports without deleting.
func TestPruneSnapshots_DryRun(t *testing.T) {
	withRetention(t, 0) // let saveN build a backlog first
	dir := t.TempDir()
	saveN(t, dir, 10)

	st, err := PruneSnapshots(dir, 4, true)
	if err != nil {
		t.Fatalf("PruneSnapshots: %v", err)
	}
	if st.Deleted != 6 {
		t.Fatalf("dry run reported %d deletions, want 6", st.Deleted)
	}
	if st.BytesFreed <= 0 {
		t.Fatalf("dry run reported %d bytes freed, want a positive estimate", st.BytesFreed)
	}
	if got := snapshotCount(t, dir); got != 10 {
		t.Fatalf("dry run removed files: %d remain, want 10", got)
	}
}

// TestPruneSnapshots_LeavesQuarantinedFiles proves retention does not reclaim
// the `.corrupt-<unix>` siblings LoadSnapshot writes. They are evidence that
// something produced a bad snapshot; a janitor that deleted them would erase
// the only trace of the bug.
func TestPruneSnapshots_LeavesQuarantinedFiles(t *testing.T) {
	withRetention(t, 0)
	dir := t.TempDir()
	saveN(t, dir, 8)

	quarantined := filepath.Join(historyPath(dir), "20260101-000000-v1.json.corrupt-1700000000")
	if err := os.WriteFile(quarantined, []byte("{ truncated"), 0o644); err != nil {
		t.Fatalf("write quarantine fixture: %v", err)
	}

	if _, err := PruneSnapshots(dir, 2, false); err != nil {
		t.Fatalf("PruneSnapshots: %v", err)
	}
	if _, err := os.Stat(quarantined); err != nil {
		t.Fatalf("quarantined snapshot was reclaimed: %v", err)
	}
	if got := snapshotCount(t, dir); got != 2 {
		t.Fatalf("got %d snapshots, want 2", got)
	}
}

// TestSaveSnapshot_PerProjectResolverWins is the regression test for the hub's
// multi-tenant case. One process writes plan history for many projects, so a
// single process-wide keep-count would apply the control plane's policy to
// every tenant — pruning the history of a project whose own config said to
// keep it, which is silent data loss against explicit configuration.
func TestSaveSnapshot_PerProjectResolverWins(t *testing.T) {
	withRetention(t, 3) // the process-wide value: deliberately restrictive

	keepEverything := t.TempDir()
	bounded := t.TempDir()

	SetSnapshotRetentionResolver(func(workDir string) int {
		if workDir == keepEverything {
			return 0 // this tenant opted out
		}
		return 5
	})
	t.Cleanup(func() { SetSnapshotRetentionResolver(nil) })

	saveN(t, keepEverything, 15)
	saveN(t, bounded, 15)

	if got := snapshotCount(t, keepEverything); got != 15 {
		t.Errorf("opted-out project kept %d snapshots, want all 15", got)
	}
	if got := snapshotCount(t, bounded); got != 5 {
		t.Errorf("bounded project kept %d snapshots, want the resolver's 5", got)
	}
}

// TestSaveSnapshot_FallsBackToProcessValue: with no resolver installed — every
// CLI invocation — the process-wide keep-count still governs.
func TestSaveSnapshot_FallsBackToProcessValue(t *testing.T) {
	withRetention(t, 4)
	SetSnapshotRetentionResolver(nil)

	dir := t.TempDir()
	saveN(t, dir, 12)

	if got := snapshotCount(t, dir); got != 4 {
		t.Fatalf("kept %d snapshots, want the process-wide 4", got)
	}
}
