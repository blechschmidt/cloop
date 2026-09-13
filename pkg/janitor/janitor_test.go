package janitor

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/diskusage"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ─── fixtures ────────────────────────────────────────────────────────────────

// newProject creates a .cloop directory and returns the project root.
func newProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}
	return dir
}

// writeSnapshots writes n plan snapshots with write-time retention disabled,
// so the test controls exactly how large a backlog the janitor inherits. This
// models the real situation Task 20229 has to clean up: a project whose
// history was written before anything bounded it.
func writeSnapshots(t *testing.T, workDir string, n int) {
	t.Helper()
	prev := pm.SnapshotRetention()
	pm.SetSnapshotRetention(0)
	t.Cleanup(func() { pm.SetSnapshotRetention(prev) })

	plan := &pm.Plan{Goal: "janitor fixture"}
	for i := 0; i < n; i++ {
		plan.Tasks = append(plan.Tasks, &pm.Task{ID: i + 1, Title: fmt.Sprintf("t%d", i), Status: pm.TaskPending})
		if err := pm.SaveSnapshot(workDir, plan); err != nil {
			t.Fatalf("SaveSnapshot %d: %v", i, err)
		}
	}
}

// writeSeal creates one archive file with the given size and modification
// time, named the way auditretention.Prune names its output.
func writeSeal(t *testing.T, dir string, first, through int, age time.Duration, sizeKB int) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir audit-archive: %v", err)
	}
	ts := time.Now().Add(-age).UTC().Format("20060102T150405Z")
	name := fmt.Sprintf("audit-%d-%d-%s.jsonl.gz", first, through, ts)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(strings.Repeat("s", sizeKB*1024)), 0o600); err != nil {
		t.Fatalf("write seal: %v", err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatalf("chtimes seal: %v", err)
	}
	return path
}

func countFiles(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("read %s: %v", dir, err)
	}
	return len(entries)
}

// fillAndDelete builds a state.db with a large freelist: insert many rows,
// delete them all, checkpoint the WAL. That is exactly the shape the live hub
// was in — 2.3 GB on disk, 87% of it free pages.
func fillAndDelete(t *testing.T, workDir string, rows, payloadKB int) string {
	t.Helper()
	dbPath := filepath.Join(workDir, ".cloop", "state.db")
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	payload := strings.Repeat("x", payloadKB*1024)
	for i := 0; i < rows; i++ {
		if err := db.AppendStep(statedb.StepRow{
			Step: i, Task: "fill", Output: payload, Duration: "0s", Time: time.Now(),
		}); err != nil {
			t.Fatalf("AppendStep %d: %v", i, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rawExec(t, dbPath, `DELETE FROM steps`)
	rawExec(t, dbPath, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return dbPath
}

// newSmallDB builds a state.db with a negligible freelist.
func newSmallDB(t *testing.T, workDir string) string {
	t.Helper()
	dbPath := filepath.Join(workDir, ".cloop", "state.db")
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return dbPath
}

func rawExec(t *testing.T, dbPath, query string) {
	t.Helper()
	conn, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer conn.Close() //nolint:errcheck
	conn.SetMaxOpenConns(1)
	if _, err := conn.Exec(query); err != nil {
		t.Fatalf("Exec %q: %v", query, err)
	}
}

func mustSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Size()
}

// withFreeSpace pins what the janitor believes is free on disk, so the VACUUM
// tests describe a disk rather than inheriting the one the suite happens to
// run on. The machine this was written on was at 100%, which is precisely the
// condition these tests need to be able to assert both sides of.
func withFreeSpace(t *testing.T, bytes int64) {
	t.Helper()
	prev := freeBytes
	freeBytes = func(string) (int64, error) { return bytes, nil }
	t.Cleanup(func() { freeBytes = prev })
}

// plentyOfSpace is more headroom than any fixture in this file needs.
const plentyOfSpace = int64(1) << 40 // 1 TiB

// ─── spec-required: a pass bounds each directory ─────────────────────────────

// TestRunOnce_BoundsEachDirectory is the spec-required regression test: one
// janitor pass must leave every directory it governs within its configured
// limit, starting from a project that looks like the one Task 20229 measured —
// history far past the keep-count and an archive far past its size cap.
func TestRunOnce_BoundsEachDirectory(t *testing.T) {
	dir := newProject(t)
	writeSnapshots(t, dir, 60)

	arch := archiveDir(dir)
	for i := 0; i < 8; i++ {
		// Newest last: seal 0 is the oldest.
		writeSeal(t, arch, i*100, i*100+99, time.Duration(8-i)*24*time.Hour, 256)
	}
	newSmallDB(t, dir)

	before := countFiles(t, filepath.Join(dir, ".cloop", "plan-history"))
	if before != 60 {
		t.Fatalf("fixture wrote %d snapshots, want 60", before)
	}

	rep, err := RunOnce(Options{
		WorkDir: dir,
		Policy: Policy{
			Enabled:         true,
			KeepSnapshots:   10,
			ArchiveMaxBytes: 1 << 20, // 1 MiB; the fixture holds 2 MiB
		},
	})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if errs := rep.Errs(); len(errs) > 0 {
		t.Fatalf("pass reported errors: %v", errs)
	}

	// plan-history is bounded by the keep-count.
	if got := countFiles(t, filepath.Join(dir, ".cloop", "plan-history")); got != 10 {
		t.Errorf("plan-history holds %d snapshots after the pass, want 10", got)
	}
	if rep.PlanHistory.Deleted != 50 {
		t.Errorf("reported %d snapshots deleted, want 50", rep.PlanHistory.Deleted)
	}

	// audit-archive is bounded by the size cap.
	usage, err := diskusage.MeasureFiles(dir)
	if err != nil {
		t.Fatalf("MeasureFiles: %v", err)
	}
	if got := usage.Bytes("audit-archive"); got > 1<<20 {
		t.Errorf("audit-archive is %d bytes after the pass, want <= 1 MiB", got)
	}
	if rep.Archive.Deleted == 0 {
		t.Error("no seals were pruned, but the archive started at twice its cap")
	}
	if rep.BytesFreed() <= 0 {
		t.Error("pass reported nothing reclaimed")
	}
}

// TestRunOnce_IsIdempotent proves a second pass over an already-bounded
// project does no further damage — the janitor runs unattended on a daily
// timer, so a pass that kept eating into history would empty it within weeks.
func TestRunOnce_IsIdempotent(t *testing.T) {
	dir := newProject(t)
	writeSnapshots(t, dir, 30)
	newSmallDB(t, dir)

	pol := Policy{Enabled: true, KeepSnapshots: 10}
	if _, err := RunOnce(Options{WorkDir: dir, Policy: pol}); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	second, err := RunOnce(Options{WorkDir: dir, Policy: pol})
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if second.PlanHistory.Deleted != 0 {
		t.Errorf("second pass deleted %d more snapshots; the first pass should have been sufficient", second.PlanHistory.Deleted)
	}
	if got := countFiles(t, filepath.Join(dir, ".cloop", "plan-history")); got != 10 {
		t.Errorf("plan-history holds %d snapshots, want a stable 10", got)
	}
}

// TestRunOnce_DryRunChangesNothing guards the preview path an operator uses
// before enabling retention on a hub holding real history.
func TestRunOnce_DryRunChangesNothing(t *testing.T) {
	dir := newProject(t)
	writeSnapshots(t, dir, 25)
	arch := archiveDir(dir)
	for i := 0; i < 4; i++ {
		writeSeal(t, arch, i*10, i*10+9, time.Duration(4-i)*24*time.Hour, 128)
	}

	rep, err := RunOnce(Options{
		WorkDir: dir,
		DryRun:  true,
		Policy:  Policy{Enabled: true, KeepSnapshots: 5, ArchiveMaxBytes: 64 << 10},
	})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if rep.PlanHistory.Deleted != 20 {
		t.Errorf("dry run reported %d snapshot deletions, want 20", rep.PlanHistory.Deleted)
	}
	if got := countFiles(t, filepath.Join(dir, ".cloop", "plan-history")); got != 25 {
		t.Errorf("dry run deleted snapshots: %d remain, want 25", got)
	}
	if got := countFiles(t, arch); got != 4 {
		t.Errorf("dry run deleted seals: %d remain, want 4", got)
	}
	if rep.After != nil {
		t.Error("dry run reported an After measurement; nothing changed, so there is nothing to re-measure")
	}
}

// ─── spec-required: VACUUM is skipped below the threshold ────────────────────

// TestMaybeVacuum_SkippedBelowThreshold is the spec-required regression test
// for the conditional VACUUM. Rewriting a multi-gigabyte file is expensive
// enough that doing it unconditionally would be its own defect, so the
// decision is driven by the free-page ratio and must refuse below it.
func TestMaybeVacuum_SkippedBelowThreshold(t *testing.T) {
	withFreeSpace(t, plentyOfSpace)
	dir := newProject(t)
	// maybeVacuum stats the database before deciding; an empty file is enough
	// for the threshold arithmetic, which reads its inputs from the Usage.
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "state.db"), nil, 0o600); err != nil {
		t.Fatalf("write db placeholder: %v", err)
	}
	pol := Policy{VacuumFreeRatio: 0.30, VacuumMinFreeBytes: 1 << 20}

	cases := []struct {
		name        string
		dbBytes     int64
		reclaimable int64
		wantSkip    bool
		wantReason  string
	}{
		{
			name:    "just below the ratio",
			dbBytes: 1000 << 20, reclaimable: 299 << 20,
			wantSkip: true, wantReason: "below the 30% threshold",
		},
		{
			name:    "far below the ratio",
			dbBytes: 1000 << 20, reclaimable: 10 << 20,
			wantSkip: true, wantReason: "below the 30% threshold",
		},
		{
			name:    "over the ratio but under the absolute floor",
			dbBytes: 2 << 20, reclaimable: 900 << 10,
			wantSkip: true, wantReason: "floor",
		},
		{
			name:    "at the ratio and over the floor",
			dbBytes: 1000 << 20, reclaimable: 300 << 20,
			wantSkip: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := &diskusage.Usage{
				DBBytes:          tc.dbBytes,
				ReclaimableBytes: tc.reclaimable,
				FreeRatio:        float64(tc.reclaimable) / float64(tc.dbBytes),
			}
			// DryRun keeps the decision pure: the threshold is evaluated, but
			// no database is rewritten. A crossed threshold surfaces as a
			// non-zero BytesFreed estimate.
			res := maybeVacuum(Options{WorkDir: dir, DryRun: true}, pol.normalise(), u)

			if tc.wantSkip {
				if res.Ran {
					t.Fatalf("vacuum ran below the threshold (reason %q)", res.Reason)
				}
				if res.BytesFreed != 0 {
					t.Errorf("skipped vacuum still claimed %d bytes", res.BytesFreed)
				}
				if !strings.Contains(res.Reason, tc.wantReason) {
					t.Errorf("reason %q does not mention %q", res.Reason, tc.wantReason)
				}
				return
			}
			if res.BytesFreed != tc.reclaimable {
				t.Errorf("threshold crossed but estimate is %d, want %d", res.BytesFreed, tc.reclaimable)
			}
			if !strings.Contains(res.Reason, "dry run") {
				t.Errorf("reason %q does not describe the dry run", res.Reason)
			}
		})
	}
}

// TestMaybeVacuum_DisabledByRatio confirms the documented "never vacuum"
// escape hatch: a ratio of 1 or more cannot be crossed.
func TestMaybeVacuum_DisabledByRatio(t *testing.T) {
	withFreeSpace(t, plentyOfSpace)
	dir := newProject(t)
	u := &diskusage.Usage{DBBytes: 100 << 20, ReclaimableBytes: 99 << 20, FreeRatio: 0.99}
	res := maybeVacuum(Options{WorkDir: dir}, Policy{VacuumFreeRatio: 1}.normalise(), u)
	if res.Ran || res.Skipped {
		t.Fatalf("vacuum was considered despite being disabled: %+v", res)
	}
	if !strings.Contains(res.Reason, "disabled") {
		t.Errorf("reason %q does not say the step is disabled", res.Reason)
	}
}

// TestRunOnce_SkipsVacuumOnHealthyDB is the end-to-end counterpart: a real
// database with no meaningful freelist must come through a pass untouched.
func TestRunOnce_SkipsVacuumOnHealthyDB(t *testing.T) {
	withFreeSpace(t, plentyOfSpace)
	dir := newProject(t)
	dbPath := newSmallDB(t, dir)
	sizeBefore := mustSize(t, dbPath)

	rep, err := RunOnce(Options{WorkDir: dir, Policy: Policy{Enabled: true, KeepSnapshots: 10}})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if rep.Vacuum.Ran {
		t.Fatalf("vacuumed a healthy database: %s", rep.Vacuum.Reason)
	}
	if !rep.Vacuum.Skipped {
		t.Errorf("vacuum was neither run nor skipped: %+v", rep.Vacuum)
	}
	if got := mustSize(t, dbPath); got != sizeBefore {
		t.Errorf("database size changed from %d to %d without a vacuum", sizeBefore, got)
	}
}

// TestRunOnce_VacuumsWastefulDB is the positive case: once the freelist is
// large enough, a pass really does return the pages to the filesystem.
func TestRunOnce_VacuumsWastefulDB(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and vacuums a multi-megabyte database")
	}
	withFreeSpace(t, plentyOfSpace)
	dir := newProject(t)
	dbPath := fillAndDelete(t, dir, 2000, 1)
	sizeBefore := mustSize(t, dbPath)

	rep, err := RunOnce(Options{
		WorkDir: dir,
		// A low floor so the fixture need not be gigabytes to be realistic.
		Policy: Policy{Enabled: true, KeepSnapshots: 10, VacuumFreeRatio: 0.30, VacuumMinFreeBytes: 1 << 20},
	})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !rep.Vacuum.Ran {
		t.Fatalf("vacuum did not run on a mostly-free database: %s (err %v)", rep.Vacuum.Reason, rep.Vacuum.Err)
	}
	sizeAfter := mustSize(t, dbPath)
	if sizeAfter >= sizeBefore {
		t.Fatalf("database did not shrink: %d → %d", sizeBefore, sizeAfter)
	}
	if rep.Vacuum.BytesFreed <= 0 {
		t.Errorf("vacuum reported %d bytes freed", rep.Vacuum.BytesFreed)
	}
}

// ─── archive retention ───────────────────────────────────────────────────────

// TestPruneArchive_AgeLimit deletes by age and keeps what is inside the window.
func TestPruneArchive_AgeLimit(t *testing.T) {
	dir := newProject(t)
	arch := archiveDir(dir)
	writeSeal(t, arch, 0, 99, 40*24*time.Hour, 16)    // stale
	writeSeal(t, arch, 100, 199, 35*24*time.Hour, 16) // stale
	writeSeal(t, arch, 200, 299, 5*24*time.Hour, 16)  // fresh
	writeSeal(t, arch, 300, 399, 1*24*time.Hour, 16)  // newest

	res := pruneArchive(arch, Policy{ArchiveMaxAgeDays: 30}, time.Now(), false)
	if res.Err != nil {
		t.Fatalf("pruneArchive: %v", res.Err)
	}
	if res.Deleted != 2 {
		t.Fatalf("deleted %d seals, want 2", res.Deleted)
	}
	if got := countFiles(t, arch); got != 2 {
		t.Fatalf("%d seals remain, want 2", got)
	}
}

// TestPruneArchive_NeverDeletesNewest is the safety floor. A size cap smaller
// than a single seal must not empty the directory: these files are the only
// remaining copy of the audit rows they hold.
func TestPruneArchive_NeverDeletesNewest(t *testing.T) {
	dir := newProject(t)
	arch := archiveDir(dir)
	writeSeal(t, arch, 0, 99, 10*24*time.Hour, 64)
	newest := writeSeal(t, arch, 100, 199, 1*time.Hour, 64)

	// Both a size cap of one byte and an age limit of one day would, taken
	// literally, delete everything.
	res := pruneArchive(arch, Policy{ArchiveMaxBytes: 1, ArchiveMaxAgeDays: 1}, time.Now(), false)
	if res.Err != nil {
		t.Fatalf("pruneArchive: %v", res.Err)
	}
	if _, err := os.Stat(newest); err != nil {
		t.Fatalf("newest seal was deleted: %v", err)
	}
	if got := countFiles(t, arch); got != 1 {
		t.Fatalf("%d seals remain, want exactly the newest", got)
	}
}

// TestPruneArchive_IgnoresForeignFiles proves the janitor only reclaims files
// it recognises as its own output. An operator's notes, or a seal copied in
// from another host under a different name, are not ours to delete.
func TestPruneArchive_IgnoresForeignFiles(t *testing.T) {
	dir := newProject(t)
	arch := archiveDir(dir)
	writeSeal(t, arch, 0, 99, 90*24*time.Hour, 32)
	writeSeal(t, arch, 100, 199, 1*time.Hour, 32)

	foreign := filepath.Join(arch, "README.txt")
	if err := os.WriteFile(foreign, []byte("shipped to cold storage 2026-01-01"), 0o600); err != nil {
		t.Fatalf("write foreign file: %v", err)
	}

	res := pruneArchive(arch, Policy{ArchiveMaxAgeDays: 30}, time.Now(), false)
	if res.Err != nil {
		t.Fatalf("pruneArchive: %v", res.Err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign file was deleted: %v", err)
	}
}

// TestPruneArchive_DisabledByDefault documents the deliberate default: with no
// limits set, seals are kept. They are the only copy of rows already removed
// from the database, so unattended deletion has to be opted into.
func TestPruneArchive_DisabledByDefault(t *testing.T) {
	dir := newProject(t)
	arch := archiveDir(dir)
	for i := 0; i < 5; i++ {
		writeSeal(t, arch, i*10, i*10+9, time.Duration(400-i)*24*time.Hour, 64)
	}

	res := pruneArchive(arch, DefaultPolicy(), time.Now(), false)
	if res.Ran {
		t.Errorf("archive retention ran with no limits configured")
	}
	if res.Deleted != 0 {
		t.Fatalf("deleted %d seals with retention disabled", res.Deleted)
	}
	if got := countFiles(t, arch); got != 5 {
		t.Fatalf("%d seals remain, want all 5", got)
	}
}

// ─── policy plumbing ─────────────────────────────────────────────────────────

// TestPolicyFromConfig_DefaultsWhenUnset proves an existing config.yaml that
// predates this feature gets the working policy rather than a disabled one.
func TestPolicyFromConfig_DefaultsWhenUnset(t *testing.T) {
	pol := PolicyFromConfig(&config.Config{})
	want := DefaultPolicy()
	if !pol.Enabled {
		t.Error("janitor disabled for a config with no retention section")
	}
	if pol.KeepSnapshots != want.KeepSnapshots {
		t.Errorf("KeepSnapshots = %d, want %d", pol.KeepSnapshots, want.KeepSnapshots)
	}
	if pol.VacuumFreeRatio != want.VacuumFreeRatio {
		t.Errorf("VacuumFreeRatio = %v, want %v", pol.VacuumFreeRatio, want.VacuumFreeRatio)
	}
	if pol.ArchiveMaxBytes != 0 || pol.ArchiveMaxAgeDays != 0 {
		t.Errorf("archive retention defaulted on: %+v", pol)
	}
}

// TestPolicyFromConfig_ExplicitOptOut proves `enabled: false` is honoured and
// distinguishable from an absent key.
func TestPolicyFromConfig_ExplicitOptOut(t *testing.T) {
	off := false
	pol := PolicyFromConfig(&config.Config{Retention: config.RetentionConfig{Enabled: &off}})
	if pol.Enabled {
		t.Fatal("retention.enabled=false did not disable the janitor")
	}
}

// TestPolicyFromConfig_Overrides checks the megabyte-to-byte conversions.
func TestPolicyFromConfig_Overrides(t *testing.T) {
	pol := PolicyFromConfig(&config.Config{Retention: config.RetentionConfig{
		IntervalHours:     6,
		KeepSnapshots:     7,
		ArchiveMaxMB:      512,
		ArchiveMaxAgeDays: 90,
		VacuumFreeRatio:   0.5,
		VacuumMinFreeMB:   128,
	}})
	if pol.Interval != 6*time.Hour {
		t.Errorf("Interval = %v, want 6h", pol.Interval)
	}
	if pol.KeepSnapshots != 7 {
		t.Errorf("KeepSnapshots = %d, want 7", pol.KeepSnapshots)
	}
	if pol.ArchiveMaxBytes != 512<<20 {
		t.Errorf("ArchiveMaxBytes = %d, want %d", pol.ArchiveMaxBytes, 512<<20)
	}
	if pol.ArchiveMaxAgeDays != 90 {
		t.Errorf("ArchiveMaxAgeDays = %d, want 90", pol.ArchiveMaxAgeDays)
	}
	if pol.VacuumFreeRatio != 0.5 {
		t.Errorf("VacuumFreeRatio = %v, want 0.5", pol.VacuumFreeRatio)
	}
	if pol.VacuumMinFreeBytes != 128<<20 {
		t.Errorf("VacuumMinFreeBytes = %d, want %d", pol.VacuumMinFreeBytes, 128<<20)
	}
}

// TestRunOnce_RequiresWorkDir guards the one input that cannot be defaulted.
func TestRunOnce_RequiresWorkDir(t *testing.T) {
	if _, err := RunOnce(Options{}); err == nil {
		t.Fatal("RunOnce accepted an empty work dir")
	}
}

// TestMaybeVacuum_SkippedWhenDiskIsFull covers the case the machine this was
// written on was already in: 100% full, zero bytes available.
//
// VACUUM is not a pure reclaim — SQLite rebuilds the database into a temporary
// copy and writes it back through the journal, so it needs free space before
// it returns any. Attempting it on a full disk is how the operation meant to
// save an operator becomes the one that finishes the job.
func TestMaybeVacuum_SkippedWhenDiskIsFull(t *testing.T) {
	dir := newProject(t)
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "state.db"), nil, 0o600); err != nil {
		t.Fatalf("write db placeholder: %v", err)
	}

	// A database whose freelist says "vacuum" on a disk with nothing left —
	// so only the headroom check can stop it.
	withFreeSpace(t, 0)
	u := &diskusage.Usage{
		DBBytes:          2300 << 20,
		ReclaimableBytes: 2000 << 20,
		FreeRatio:        2000.0 / 2300.0,
	}
	res := maybeVacuum(Options{WorkDir: dir}, DefaultPolicy().normalise(), u)

	if res.Ran {
		t.Fatal("vacuumed a database far larger than the free space available")
	}
	if !res.Skipped {
		t.Fatalf("vacuum was neither run nor skipped: %+v", res)
	}
	if !strings.Contains(res.Reason, "free") {
		t.Errorf("reason %q does not explain that the disk lacks room", res.Reason)
	}
}

// TestVacuumHeadroom_ScalesWithLiveDataNotFileSize is the property that keeps
// the check from being self-defeating. A mostly-empty 2.3 GB database holds
// 300 MB of real data; requiring twice the *file* size would refuse to reclaim
// exactly the databases that most need it.
func TestVacuumHeadroom_ScalesWithLiveDataNotFileSize(t *testing.T) {
	wasteful := &diskusage.Usage{DBBytes: 2300 << 20, ReclaimableBytes: 2000 << 20}
	dense := &diskusage.Usage{DBBytes: 2300 << 20, ReclaimableBytes: 0}

	if wasteful.VacuumHeadroom() >= dense.VacuumHeadroom() {
		t.Fatalf("a mostly-free database demands %d bytes of headroom, no less than a full one's %d",
			wasteful.VacuumHeadroom(), dense.VacuumHeadroom())
	}
	// 300 MB live → ~664 MB, comfortably under the 2.3 GB file size.
	if got := wasteful.VacuumHeadroom(); got >= wasteful.DBBytes {
		t.Errorf("headroom %d exceeds the file size %d; the check would never pass", got, wasteful.DBBytes)
	}
}

// TestMaybeVacuum_RefusesLargeInProcessRewrite is the regression test for the
// defect that would have taken the live hub down.
//
// The control-plane database is where the hub's own lease lives, so a VACUUM
// that outlasts the lease TTL starves the heartbeat; the hub then concludes a
// peer took the fence and stands down. Because the pass runs 30s after
// startup, that is a restart loop, not a one-off. A pass running inside a hub
// (InstanceID set) must therefore decline a rewrite it cannot finish in time.
func TestMaybeVacuum_RefusesLargeInProcessRewrite(t *testing.T) {
	dir := newProject(t)
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "state.db"), nil, 0o600); err != nil {
		t.Fatalf("write db placeholder: %v", err)
	}
	withFreeSpace(t, plentyOfSpace)

	// 12 GiB live inside a 20 GiB file: the ratio says vacuum, and only the
	// in-process ceiling can stop it.
	const gib = int64(1) << 30
	u := &diskusage.Usage{DBBytes: 20 * gib, ReclaimableBytes: 8 * gib, FreeRatio: 0.4}
	pol := DefaultPolicy().normalise()

	inHub := maybeVacuum(Options{WorkDir: dir, InstanceID: "hub-1", DryRun: true}, pol, u)
	if inHub.Ran || !inHub.Skipped {
		t.Fatalf("in-hub pass did not decline a rewrite larger than the lease TTL allows: %+v", inHub)
	}
	if !strings.Contains(inHub.Reason, "in-process limit") {
		t.Errorf("reason %q does not name the in-process limit", inHub.Reason)
	}
	if !strings.Contains(inHub.Reason, "hub stopped") {
		t.Errorf("reason %q does not tell the operator how to do it anyway", inHub.Reason)
	}

	// The CLI has no heartbeat to lose, so the same database is fair game.
	offline := maybeVacuum(Options{WorkDir: dir, DryRun: true}, pol, u)
	if offline.BytesFreed != u.ReclaimableBytes {
		t.Errorf("offline pass declined too: %+v", offline)
	}
}

// TestMaybeVacuum_AllowsSmallInProcessRewrite is the other half: the ceiling
// must not be so cautious that it never vacuums. It is measured against live
// data, not file size, precisely so a mostly-empty database still qualifies.
func TestMaybeVacuum_AllowsSmallInProcessRewrite(t *testing.T) {
	dir := newProject(t)
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "state.db"), nil, 0o600); err != nil {
		t.Fatalf("write db placeholder: %v", err)
	}
	withFreeSpace(t, plentyOfSpace)

	// The shape of this repository's own control plane: a 2.3 GB file holding
	// under 300 MB of live data. Gating on file size would refuse it; gating
	// on live data — which is what VACUUM actually copies — does not.
	u := &diskusage.Usage{DBBytes: 2300 << 20, ReclaimableBytes: 2000 << 20, FreeRatio: 2000.0 / 2300.0}
	res := maybeVacuum(Options{WorkDir: dir, InstanceID: "hub-1", DryRun: true}, DefaultPolicy().normalise(), u)

	if res.BytesFreed != u.ReclaimableBytes {
		t.Fatalf("declined a 300 MB rewrite inside a 2.3 GB file: %+v", res)
	}
}

// TestPolicyFromConfig_FollowsAuditExportDir: seals move when an operator sets
// audit.export_dir, and retention has to follow them. Bounding the default
// path while the configured one grows is a silent no-op that also makes
// `cloop hub doctor` report a limit that is doing nothing.
func TestPolicyFromConfig_FollowsAuditExportDir(t *testing.T) {
	pol := PolicyFromConfig(&config.Config{
		Audit: config.AuditConfig{ExportDir: "/srv/audit"},
	})
	if pol.ArchiveDir != "/srv/audit" {
		t.Fatalf("ArchiveDir = %q, want the configured export dir", pol.ArchiveDir)
	}
	if got := resolveArchiveDir("/proj", pol); got != "/srv/audit" {
		t.Errorf("resolveArchiveDir = %q, want /srv/audit", got)
	}
	// Unset still means the default beneath .cloop.
	def := PolicyFromConfig(&config.Config{})
	if got := resolveArchiveDir("/proj", def); got != filepath.Join("/proj", ".cloop", "audit-archive") {
		t.Errorf("default resolveArchiveDir = %q", got)
	}
}

// TestRunOnce_RefusesProjectWithoutCloop stops a pass manufacturing a .cloop
// directory in every path the hub has ever been pointed at just to hold its
// run stamp.
func TestRunOnce_RefusesProjectWithoutCloop(t *testing.T) {
	dir := t.TempDir() // no .cloop
	if _, err := RunOnce(Options{WorkDir: dir, Policy: DefaultPolicy()}); err == nil {
		t.Fatal("RunOnce accepted a directory with no .cloop")
	}
	if _, err := os.Stat(filepath.Join(dir, ".cloop")); err == nil {
		t.Error("RunOnce created a .cloop directory in a project that had none")
	}
}
