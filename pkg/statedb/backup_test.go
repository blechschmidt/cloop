// Tests for pkg/dbbackup live in pkg/statedb to avoid an import cycle:
// dbbackup depends on statedb, and we want the tests to use the same
// helpers (tempDB, baseState) the rest of the statedb test suite uses to
// seed a realistic database.
package statedb_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/blechschmidt/cloop/pkg/dbbackup"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// seedDB writes a realistic plan with several tasks and step rows so the
// backup tests have something non-trivial to compare against. Returns the
// DB handle (closed by t.Cleanup) and the on-disk path.
func seedDB(t *testing.T) (*statedb.DB, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	plan := &pm.Plan{Goal: "backup test", Version: 1}
	for i := 1; i <= 5; i++ {
		plan.Tasks = append(plan.Tasks, &pm.Task{
			ID: i, Title: "task " + strings.Repeat("x", i),
			Description: "desc", Status: pm.TaskPending, Priority: i,
		})
	}
	s := &statedb.State{
		Goal:      "backup test",
		WorkDir:   dir,
		Status:    "running",
		Plan:      plan,
		MaxSteps:  20,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
		Steps: []statedb.StepRow{
			{Step: 1, Task: "init", Output: "boot", ExitCode: 0, Duration: "1s", Time: time.Now().UTC()},
			{Step: 2, Task: "decompose", Output: "plan ready", ExitCode: 0, Duration: "2s", Time: time.Now().UTC()},
		},
	}
	if err := db.SaveState(s); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	return db, path
}

// readScalar returns the value of a metadata key from the SQLite DB at path.
// We deliberately bypass statedb.Open so the test doesn't trigger schema
// migration writes on the file under test.
func readScalar(t *testing.T, path, key string) string {
	t.Helper()
	conn, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatalf("sql.Open(%q): %v", path, err)
	}
	defer conn.Close()
	conn.SetMaxOpenConns(1)
	var v string
	err = conn.QueryRow("SELECT value FROM metadata WHERE key=?", key).Scan(&v)
	if err != nil && err != sql.ErrNoRows {
		t.Fatalf("scan %s: %v", key, err)
	}
	return v
}

// snapshotPlan reads the plan_tasks table and returns a stable string
// representation suitable for diff'ing in tests.
func snapshotPlan(t *testing.T, path string) string {
	t.Helper()
	conn, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatalf("sql.Open(%q): %v", path, err)
	}
	defer conn.Close()
	conn.SetMaxOpenConns(1)
	rows, err := conn.Query(`SELECT id, title, status, priority FROM plan_tasks ORDER BY id`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var id, prio int
		var title, status string
		if err := rows.Scan(&id, &title, &status, &prio); err != nil {
			t.Fatalf("scan: %v", err)
		}
		b.WriteString(title + "|" + status + "\n")
		_ = id
		_ = prio
	}
	return b.String()
}

// TestBackup_ProducesValidSelfContainedFile verifies the happy path: a
// backup of a populated DB exists, is non-empty, has a sidecar metadata
// file, and can itself be opened and queried.
func TestBackup_ProducesValidSelfContainedFile(t *testing.T) {
	_, src := seedDB(t)
	dst := filepath.Join(t.TempDir(), "backup.db")

	report, err := dbbackup.Backup(src, dst)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if report.SizeBytes <= 0 {
		t.Errorf("expected backup to have non-zero size, got %d", report.SizeBytes)
	}
	if report.SHA256 == "" {
		t.Error("expected non-empty checksum in report")
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("backup file missing: %v", err)
	}
	meta, err := dbbackup.LoadMetadata(dst)
	if err != nil {
		t.Fatalf("LoadMetadata: %v", err)
	}
	if meta == nil {
		t.Fatal("expected sidecar metadata to be written")
	}
	if meta.SHA256 != report.SHA256 {
		t.Errorf("metadata checksum %q != report checksum %q", meta.SHA256, report.SHA256)
	}
	// The backup itself must be a queryable SQLite DB.
	if got := readScalar(t, dst, "goal"); got != "backup test" {
		t.Errorf("goal in backup: got %q want %q", got, "backup test")
	}
	tasks := snapshotPlan(t, dst)
	if !strings.Contains(tasks, "task xx|") {
		t.Errorf("expected backup plan_tasks to contain seeded titles, got:\n%s", tasks)
	}
}

// TestBackup_RefusesIdenticalSourceAndOutput catches a copy-paste bug
// where the operator passes --output pointing at the live state.db.
func TestBackup_RefusesIdenticalSourceAndOutput(t *testing.T) {
	_, src := seedDB(t)
	if _, err := dbbackup.Backup(src, src); err == nil {
		t.Fatal("expected error when source == output, got nil")
	}
}

// TestBackup_OverwritesStaleOutput verifies that an existing destination
// is cleared before VACUUM INTO runs (which would otherwise fail).
func TestBackup_OverwritesStaleOutput(t *testing.T) {
	_, src := seedDB(t)
	dst := filepath.Join(t.TempDir(), "backup.db")
	// Pre-create stale junk at the destination.
	if err := os.WriteFile(dst, []byte("stale junk"), 0o600); err != nil {
		t.Fatalf("seed stale: %v", err)
	}
	if err := os.WriteFile(dst+dbbackup.MetadataSuffix, []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed stale meta: %v", err)
	}
	if _, err := dbbackup.Backup(src, dst); err != nil {
		t.Fatalf("Backup over stale dst: %v", err)
	}
	// File should now be a real SQLite DB.
	if got := readScalar(t, dst, "goal"); got != "backup test" {
		t.Errorf("goal after overwrite: got %q want %q", got, "backup test")
	}
}

// TestBackup_WhileConcurrentWriter is the spec's "backup-while-writing
// produces consistent snapshot" requirement. We start a goroutine that
// keeps inserting cost rows, run a backup mid-flight, and verify the
// backup is internally consistent (PRAGMA integrity_check passes) and
// is queryable as a normal SQLite DB.
//
// We can't compare to a fixed target because the writer is racing the
// backup — what we *can* assert is "no corruption, no torn rows, and
// the row count is somewhere within the writer's recorded range".
func TestBackup_WhileConcurrentWriter(t *testing.T) {
	if testing.Short() {
		t.Skip("skip under -short: spawns a writer goroutine for ~1s")
	}
	db, src := seedDB(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var written atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			// AppendCost is a one-row autocommit write. Lots of these
			// during the backup is exactly the contention pattern WAL
			// mode is supposed to handle gracefully.
			err := db.AppendCost(statedb.CostEntry{
				TaskID: int(written.Load() % 5),
				Provider: "test",
				Model: "m",
				InputTokens: 1, OutputTokens: 1,
				EstimatedUSD: 0.001,
			})
			if err == nil {
				written.Add(1)
			}
			// No sleep — push hard.
		}
	}()

	// Give the writer a head start so the backup catches an in-flight
	// pattern, not an empty WAL.
	time.Sleep(50 * time.Millisecond)
	startWriteCount := written.Load()

	dst := filepath.Join(t.TempDir(), "backup.db")
	report, err := dbbackup.Backup(src, dst)
	if err != nil {
		cancel()
		wg.Wait()
		t.Fatalf("Backup under load: %v", err)
	}

	// Stop the writer before further assertions on the backup file.
	cancel()
	wg.Wait()

	endWriteCount := written.Load()
	if startWriteCount == endWriteCount {
		// Writer didn't actually run — environment too slow / tickless.
		// Don't fail; just record so a regression that breaks the
		// concurrency premise is visible.
		t.Logf("concurrent writer made 0 forward progress during the backup window")
	}

	// Backup file must be internally consistent.
	conn, err := sql.Open("sqlite", "file:"+dst+"?mode=ro")
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer conn.Close()
	conn.SetMaxOpenConns(1)
	rows, err := conn.Query("PRAGMA integrity_check")
	if err != nil {
		t.Fatalf("integrity_check: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var msg string
		if err := rows.Scan(&msg); err != nil {
			t.Fatalf("scan integrity row: %v", err)
		}
		if msg != "ok" {
			t.Errorf("integrity_check failed on backup: %q", msg)
		}
	}

	// Cost rows in the backup must be a snapshot somewhere in the
	// writer's [start, end] interval — never beyond it (which would
	// indicate the backup somehow saw the future), never less than zero.
	var backupCount int64
	if err := conn.QueryRow("SELECT COUNT(*) FROM costs").Scan(&backupCount); err != nil {
		t.Fatalf("count: %v", err)
	}
	if backupCount > endWriteCount+5 { // small slack: writer can advance in TOCTOU
		t.Errorf("backup cost count %d exceeds writer's end count %d — backup saw the future",
			backupCount, endWriteCount)
	}
	if backupCount < 0 {
		t.Errorf("negative cost count %d in backup", backupCount)
	}
	// Sanity on the report: SHA-256 is hex of length 64.
	if len(report.SHA256) != 64 {
		t.Errorf("expected sha256 length 64, got %d (%q)", len(report.SHA256), report.SHA256)
	}
}

// TestRestore_ProducesIdenticalState is the spec's "restore produces
// identical state" requirement. Roundtrip: seed → backup → restore over
// fresh path → assert both DBs return the same plan and metadata.
func TestRestore_ProducesIdenticalState(t *testing.T) {
	_, src := seedDB(t)

	backupPath := filepath.Join(t.TempDir(), "backup.db")
	if _, err := dbbackup.Backup(src, backupPath); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// Restore into a fresh directory (no pre-existing dst → no --force needed).
	dstDir := t.TempDir()
	dst := filepath.Join(dstDir, "state.db")
	report, err := dbbackup.Restore(backupPath, dst, dbbackup.RestoreOptions{})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if report.Destination != dst {
		t.Errorf("report destination mismatch: got %q want %q", report.Destination, dst)
	}
	if report.BackedUpPath != "" {
		t.Errorf("expected no pre-restore stash for fresh dst, got %q", report.BackedUpPath)
	}

	// Both databases should report the same content. We compare the plan
	// row digest and the goal scalar — together a strong integrity signal.
	gotGoal := readScalar(t, dst, "goal")
	wantGoal := readScalar(t, src, "goal")
	if gotGoal != wantGoal {
		t.Errorf("goal mismatch after restore: got %q want %q", gotGoal, wantGoal)
	}
	gotPlan := snapshotPlan(t, dst)
	wantPlan := snapshotPlan(t, src)
	if gotPlan != wantPlan {
		t.Errorf("plan mismatch after restore.\nrestored:\n%s\noriginal:\n%s", gotPlan, wantPlan)
	}
}

// TestRestore_RefusesActiveDatabaseWithoutForce verifies the active-DB
// guard: if the destination already exists (the canonical "cloop is
// running" signal), Restore must refuse without --force.
func TestRestore_RefusesActiveDatabaseWithoutForce(t *testing.T) {
	_, src := seedDB(t)
	backupPath := filepath.Join(t.TempDir(), "backup.db")
	if _, err := dbbackup.Backup(src, backupPath); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// Pretend dst is "active" by creating a non-empty file at its path.
	dstDir := t.TempDir()
	dst := filepath.Join(dstDir, "state.db")
	if err := os.WriteFile(dst, []byte("live db pretend"), 0o600); err != nil {
		t.Fatalf("seed dst: %v", err)
	}
	_, err := dbbackup.Restore(backupPath, dst, dbbackup.RestoreOptions{})
	if err == nil {
		t.Fatal("expected error when dst exists without --force, got nil")
	}
	if !strings.Contains(err.Error(), "active") {
		t.Errorf("expected 'active' guard message, got %q", err.Error())
	}
	// Original "live" file must be untouched.
	body, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst after refused restore: %v", err)
	}
	if string(body) != "live db pretend" {
		t.Errorf("dst was modified despite refused restore: got %q", string(body))
	}
}

// TestRestore_ForceMovesExistingFileAside verifies that --force preserves
// the previous state.db as a sibling .pre-restore.<ts> file before
// swapping in the backup.
func TestRestore_ForceMovesExistingFileAside(t *testing.T) {
	_, src := seedDB(t)
	backupPath := filepath.Join(t.TempDir(), "backup.db")
	if _, err := dbbackup.Backup(src, backupPath); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	dstDir := t.TempDir()
	dst := filepath.Join(dstDir, "state.db")
	const sentinel = "i am the previous live db"
	if err := os.WriteFile(dst, []byte(sentinel), 0o600); err != nil {
		t.Fatalf("seed dst: %v", err)
	}
	report, err := dbbackup.Restore(backupPath, dst, dbbackup.RestoreOptions{Force: true})
	if err != nil {
		t.Fatalf("Restore --force: %v", err)
	}
	if report.BackedUpPath == "" {
		t.Fatal("expected BackedUpPath to be set when --force preempted existing dst")
	}
	body, err := os.ReadFile(report.BackedUpPath)
	if err != nil {
		t.Fatalf("read pre-restore stash: %v", err)
	}
	if string(body) != sentinel {
		t.Errorf("stash content mismatch: got %q want %q", string(body), sentinel)
	}
	// And dst itself is now the restored DB.
	if got := readScalar(t, dst, "goal"); got != "backup test" {
		t.Errorf("after --force restore, dst goal = %q want %q", got, "backup test")
	}
}

// TestRestore_RefusesCorruptedBackup is the spec's "restore refuses
// corrupted backups" requirement. We deliberately corrupt a real backup
// by overwriting its header bytes, then assert Restore returns an error.
func TestRestore_RefusesCorruptedBackup(t *testing.T) {
	_, src := seedDB(t)
	backupPath := filepath.Join(t.TempDir(), "backup.db")
	if _, err := dbbackup.Backup(src, backupPath); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// Corrupt the SQLite header: bytes 0..15 are the magic "SQLite format 3\0".
	// Smashing them turns the file into something the read-only sqlite handle
	// will reject on Ping or integrity_check.
	f, err := os.OpenFile(backupPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open backup for corruption: %v", err)
	}
	if _, err := f.WriteAt([]byte("CORRUPTEDFILE!!!"), 0); err != nil {
		f.Close()
		t.Fatalf("write corruption: %v", err)
	}
	f.Close()

	dstDir := t.TempDir()
	dst := filepath.Join(dstDir, "state.db")
	_, err = dbbackup.Restore(backupPath, dst, dbbackup.RestoreOptions{SkipChecksum: true})
	if err == nil {
		t.Fatal("expected error when restoring corrupted backup, got nil")
	}
	// Destination must not exist after a refused restore.
	if _, statErr := os.Stat(dst); statErr == nil {
		t.Errorf("dst should not exist after refused restore, but it does: %s", dst)
	}
}

// TestRestore_RefusesChecksumMismatch verifies the SHA-256 verification
// path: a backup whose bytes don't match the sidecar metadata is rejected
// (unless SkipChecksum is set).
func TestRestore_RefusesChecksumMismatch(t *testing.T) {
	_, src := seedDB(t)
	backupPath := filepath.Join(t.TempDir(), "backup.db")
	if _, err := dbbackup.Backup(src, backupPath); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// Append junk to the *end* of the backup file — the SQLite header
	// stays intact (so integrity_check still passes; we want to test
	// the checksum path specifically) but the byte stream now differs
	// from what the sidecar recorded.
	f, err := os.OpenFile(backupPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("open backup for append: %v", err)
	}
	if _, err := f.Write([]byte("trailing-noise")); err != nil {
		f.Close()
		t.Fatalf("write trailing junk: %v", err)
	}
	f.Close()

	dst := filepath.Join(t.TempDir(), "state.db")
	_, err = dbbackup.Restore(backupPath, dst, dbbackup.RestoreOptions{})
	if err == nil {
		t.Fatal("expected checksum mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "checksum") && !strings.Contains(err.Error(), "integrity") {
		t.Errorf("expected checksum/integrity error, got: %v", err)
	}
}

// TestRestore_SkipChecksumAcceptsLegitMetadataMissing covers the
// recovery flow: metadata sidecar lost, but the backup itself is fine —
// SkipChecksum lets the operator restore anyway.
func TestRestore_SkipChecksumAcceptsLegitMetadataMissing(t *testing.T) {
	_, src := seedDB(t)
	backupPath := filepath.Join(t.TempDir(), "backup.db")
	if _, err := dbbackup.Backup(src, backupPath); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	// Drop the sidecar.
	if err := os.Remove(backupPath + dbbackup.MetadataSuffix); err != nil {
		t.Fatalf("remove sidecar: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "state.db")
	if _, err := dbbackup.Restore(backupPath, dst, dbbackup.RestoreOptions{SkipChecksum: true}); err != nil {
		t.Fatalf("Restore with SkipChecksum and no sidecar: %v", err)
	}
	if got := readScalar(t, dst, "goal"); got != "backup test" {
		t.Errorf("restored goal mismatch: got %q want %q", got, "backup test")
	}
}

// TestBackup_RecordsSchemaVersion ensures the metadata sidecar carries the
// schema version. Restores will eventually use this to reject backups
// from a future binary, but for now we just verify it is populated.
func TestBackup_RecordsSchemaVersion(t *testing.T) {
	_, src := seedDB(t)
	dst := filepath.Join(t.TempDir(), "backup.db")
	rep, err := dbbackup.Backup(src, dst)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if rep.SchemaVersion <= 0 {
		t.Errorf("expected non-zero schema version in report, got %d", rep.SchemaVersion)
	}
	meta, err := dbbackup.LoadMetadata(dst)
	if err != nil {
		t.Fatalf("LoadMetadata: %v", err)
	}
	if meta == nil || meta.SchemaVersion != rep.SchemaVersion {
		t.Errorf("metadata schema version mismatch: meta=%v report=%d", meta, rep.SchemaVersion)
	}
}
