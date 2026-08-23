package ui

// Tests for the startup reconciliation of orphaned credential directories
// (Task 20193).
//
// The scenario every one of these simulates is the same, and it is the common
// one rather than an exotic one: a hub writes a lease's plaintext into
// /dev/shm, and the process dies before the goroutine that would have wiped it
// runs. A deploy, an OOM kill, a panic, `systemctl restart`. The next hub used
// to come up with an empty in-memory registry and no way to find — let alone
// destroy — the credentials its predecessor had left behind.
//
// "Crash" here means exactly what it means in production: the row exists, the
// directory exists, and nothing in this process knows about either.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/securewipe"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const sweptCanary = "ghp_swept_canary_must_not_survive"

// crashedLease leaves behind exactly what a hub killed mid-lease leaves: a
// populated credential directory and the durable row that records it. It
// returns the directory.
func crashedLease(t *testing.T, controlPlaneDir string, expiresAt time.Time) string {
	t.Helper()

	// Under the test's own TempDir rather than /dev/shm: the sweep acts on
	// whatever path the row names, and a test that wrote into the real
	// /dev/shm could collide with the live hub running on this host.
	dir := filepath.Join(t.TempDir(), securewipe.LeaseDirPrefix+"crashed")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir lease dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(sweptCanary), 0o600); err != nil {
		t.Fatalf("write credential: %v", err)
	}

	db, err := statedb.Open(state.DBPath(controlPlaneDir))
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	defer db.Close()
	if err := db.PutSecretLeaseDir(statedb.SecretLeaseDirRow{
		Dir:         dir,
		LeaseID:     "lease_crashed",
		ExecutorID:  "local",
		ProjectPath: controlPlaneDir,
		ExpiresAt:   expiresAt,
	}); err != nil {
		t.Fatalf("record lease dir: %v", err)
	}
	return dir
}

func recordedLeaseDirs(t *testing.T, controlPlaneDir string) []statedb.SecretLeaseDirRow {
	t.Helper()
	db, err := statedb.Open(state.DBPath(controlPlaneDir))
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	defer db.Close()
	rows, err := db.ListSecretLeaseDirs()
	if err != nil {
		t.Fatalf("list lease dirs: %v", err)
	}
	return rows
}

// TestStartupSweepWipesCrashOrphanedLeaseDir is the core regression test.
//
// Before the sweep existed, nothing outlived the process that materialised a
// lease: wipeLeaseOnExit was a bare `go` statement, and the TTL janitor swept
// an in-memory map that a restart emptied. /dev/shm is a tmpfs and clears on
// reboot, but a hub *process* restart clears nothing — and that is the case
// that actually happens.
func TestStartupSweepWipesCrashOrphanedLeaseDir(t *testing.T) {
	dir := setupProjectDir(t, "lease sweep", nil)
	orphan := crashedLease(t, dir, time.Now().Add(-time.Hour))

	// Precondition, so a broken fixture cannot make this test pass vacuously.
	if body, err := os.ReadFile(filepath.Join(orphan, "token")); err != nil ||
		!strings.Contains(string(body), sweptCanary) {
		t.Fatalf("fixture did not leave a credential on disk: %v", err)
	}

	res := sweepOrphanedLeaseDirs(dir)

	if res.Wiped != 1 {
		t.Errorf("Wiped = %d, want 1 (rows=%d vanished=%d errors=%v)",
			res.Wiped, res.Rows, res.Vanished, res.Errors)
	}
	if len(res.Errors) != 0 {
		t.Errorf("unexpected sweep errors: %v", res.Errors)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Errorf("the orphaned credential directory survived a hub restart: %v\n"+
			"a plaintext PAT or kubeconfig left in /dev/shm has nothing to collect it", err)
	}
	if rows := recordedLeaseDirs(t, dir); len(rows) != 0 {
		t.Errorf("the record should be cleared once the directory is gone; %d row(s) left", len(rows))
	}
}

// TestStartupSweepLeavesUnrecordedDirectoriesAlone is the multi-hub guard, and
// it is why the sweep reconciles against a table instead of globbing
// /dev/shm/cloop-lease-*.
//
// Two hubs can share a host — this very box runs a service on :8888 and a
// second instance on :8080. A blind prefix sweep at startup would destroy the
// other hub's live credentials in the middle of its tasks, turning a leak into
// an outage. A directory this hub has no row for is somebody else's.
func TestStartupSweepLeavesUnrecordedDirectoriesAlone(t *testing.T) {
	dir := setupProjectDir(t, "lease sweep foreign", nil)

	foreign := filepath.Join(t.TempDir(), securewipe.LeaseDirPrefix+"other-hub")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	token := filepath.Join(foreign, "token")
	if err := os.WriteFile(token, []byte("another hub's live credential"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	res := sweepOrphanedLeaseDirs(dir)

	if res.Wiped != 0 {
		t.Errorf("Wiped = %d, want 0: nothing here belongs to this hub", res.Wiped)
	}
	if _, err := os.Stat(token); err != nil {
		t.Errorf("the sweep destroyed a credential directory it has no record of: %v\n"+
			"that is another hub's live lease, and wiping it breaks a running task", err)
	}
}

// TestStartupSweepSkipsLeasesHeldByThisProcess covers calling the sweep on a
// running hub. At startup the live set is empty by construction, but the guard
// has to hold if the sweep is ever invoked again — from a maintenance command,
// from a test — or it would pull a credential out from under a running task.
func TestStartupSweepSkipsLeasesHeldByThisProcess(t *testing.T) {
	dir := setupProjectDir(t, "lease sweep live", nil)
	held := crashedLease(t, dir, time.Now().Add(time.Hour))

	// Registered directly: add() requires a real *secretbroker.Lease, and what
	// the sweep consults is only the dir field.
	liveLeases.mu.Lock()
	liveLeases.active["lease_crashed"] = &secretLease{dir: held}
	liveLeases.mu.Unlock()
	t.Cleanup(func() { liveLeases.remove("lease_crashed") })

	res := sweepOrphanedLeaseDirs(dir)

	if res.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", res.Skipped)
	}
	if _, err := os.Stat(held); err != nil {
		t.Errorf("the sweep wiped a lease this process is still holding: %v", err)
	}
	if rows := recordedLeaseDirs(t, dir); len(rows) != 1 {
		t.Errorf("a skipped lease must keep its row; got %d", len(rows))
	}
}

// TestStartupSweepClearsRecordsWhoseDirectoryNeverAppeared covers the window
// the write-ahead ordering deliberately creates: the row goes in before the
// mkdir, so a crash in between leaves a row pointing at nothing. The end state
// the sweep wants is already true, and it must say so rather than erroring.
func TestStartupSweepClearsRecordsWhoseDirectoryNeverAppeared(t *testing.T) {
	dir := setupProjectDir(t, "lease sweep phantom", nil)

	phantom := filepath.Join(t.TempDir(), securewipe.LeaseDirPrefix+"never-created")
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	if err := db.PutSecretLeaseDir(statedb.SecretLeaseDirRow{Dir: phantom, LeaseID: "lease_phantom"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	_ = db.Close()

	res := sweepOrphanedLeaseDirs(dir)

	if res.Vanished != 1 || res.Wiped != 0 || len(res.Errors) != 0 {
		t.Errorf("vanished=%d wiped=%d errors=%v, want vanished=1",
			res.Vanished, res.Wiped, res.Errors)
	}
	if rows := recordedLeaseDirs(t, dir); len(rows) != 0 {
		t.Errorf("a row with no directory should be cleared; %d left", len(rows))
	}
}

// TestStartupSweepKeepsTheRecordWhenTheWipeFails is the "stop swallowing wipe
// errors" contract at the hub level.
//
// The row is the only handle anything has on the directory. Dropping it because
// the wipe failed would turn a recoverable orphan into a permanent one — the
// next startup would be blind to a credential that is demonstrably still there.
func TestStartupSweepKeepsTheRecordWhenTheWipeFails(t *testing.T) {
	dir := setupProjectDir(t, "lease sweep stuck", nil)
	orphan := crashedLease(t, dir, time.Time{})
	// The confined wipe refuses to recurse, which is a deterministic and
	// root-safe way to make destruction genuinely fail.
	if err := os.Mkdir(filepath.Join(orphan, "nested"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	res := sweepOrphanedLeaseDirs(dir)

	if len(res.Errors) != 1 {
		t.Fatalf("a failed wipe was not reported: %+v", res)
	}
	if res.Wiped != 0 {
		t.Errorf("Wiped = %d, want 0: nothing was destroyed", res.Wiped)
	}
	if rows := recordedLeaseDirs(t, dir); len(rows) != 1 {
		t.Errorf("the record must survive a failed wipe so the next startup retries; got %d rows", len(rows))
	}
}

// TestStartupSweepIsSafeWithoutADatabase keeps a fresh install booting. A hub
// that has never run has nothing to reconcile, and failing startup over it
// would take the control plane down for a credential that does not exist.
func TestStartupSweepIsSafeWithoutADatabase(t *testing.T) {
	if res := sweepOrphanedLeaseDirs(t.TempDir()); res.Rows != 0 || len(res.Errors) != 0 {
		t.Errorf("sweep on a bare directory did something: %+v", res)
	}
	if res := sweepOrphanedLeaseDirs(""); res.Rows != 0 {
		t.Errorf("sweep with no control plane did something: %+v", res)
	}
}
