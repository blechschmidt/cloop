package ui

// secrets_sweep.go collects the credential directories a previous incarnation
// of this hub left behind (Task 20193).
//
// # The gap this closes
//
// Three things wipe a lease's plaintext, and before this file all three lived
// and died with the process that created it:
//
//   - wipeLeaseOnExit, an unguarded `go` in dispatchExecutor, watching one
//     workload's output stream;
//   - the TTL janitor, which sweeps liveLeases — a package-level map;
//   - an operator's explicit revoke, which also goes through liveLeases.
//
// All three are in-memory. A hub killed between Materialize and the wipe — a
// deploy, an OOM kill, a panic, a `systemctl restart` — came back up with
// liveLeases empty and /dev/shm still holding plaintext GitHub PATs and
// kubeconfigs, with nothing left that could attribute them, let alone remove
// them. /dev/shm is a tmpfs and clears on reboot, which is the case that does
// not happen; a process restart clears nothing, which is the case that does.
//
// # Why this is not "rm -rf /dev/shm/cloop-lease-*"
//
// Because two hubs can share a host. This box runs one right now: a service on
// :8888 and a second instance on :8080. A blind prefix sweep at startup would
// destroy the live credentials of the other hub in the middle of its tasks,
// turning a leak into an outage. Ownership has to be decidable, and the
// secret_lease_dirs row is what decides it: this hub wipes a directory when its
// own control-plane database says it created it, and leaves anything else
// alone. A directory with no row is somebody else's business.
//
// The cost of that choice is honest: a directory whose row was lost — a
// database restored from a backup, a `.cloop` moved out from under a running
// hub — is not swept, because nothing can prove it was ours. Reporting the
// count of unattributable directories is the compensation, so an operator can
// see there is something to look at rather than being told the sweep was clean.

import (
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/securewipe"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// leaseSweepResult is what one reconciliation pass did, for the log line and
// for the tests.
type leaseSweepResult struct {
	// Rows is how many recorded directories were examined.
	Rows int
	// Wiped counts directories that existed and were destroyed.
	Wiped int
	// Vanished counts rows whose directory was already gone — the ordinary
	// outcome for a crash between the intent row and the mkdir, and for a
	// tmpfs that cleared on reboot.
	Vanished int
	// Skipped counts directories still held by a live lease in this process.
	// Zero at startup by construction; non-zero only if the sweep is ever
	// called on a running hub.
	Skipped int
	// Errors are wipes that failed. Each one is a credential still on disk.
	Errors []string
}

// sweepOrphanedLeaseDirs destroys credential directories recorded by a previous
// run of this hub and clears their rows.
//
// Called once at startup, before anything can dispatch. It is safe to call on a
// running hub — a directory belonging to a lease in liveLeases is skipped — but
// startup is the moment it matters, because that is when every row is an
// orphan.
//
// Best-effort by design: a hub that cannot open its database must still start.
// Failing to boot because a wipe failed would take the control plane down over
// a credential that is already exposed, which helps nobody.
func sweepOrphanedLeaseDirs(controlPlaneDir string) leaseSweepResult {
	var result leaseSweepResult
	if controlPlaneDir == "" {
		return result
	}
	dbPath := state.DBPath(controlPlaneDir)
	if _, err := os.Stat(dbPath); err != nil {
		// No database means no hub has ever run here, so there is nothing this
		// hub could have orphaned.
		return result
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: lease sweep: open state database: %v\n", err)
		return result
	}
	defer db.Close()

	rows, err := db.ListSecretLeaseDirs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: lease sweep: list recorded lease directories: %v\n", err)
		return result
	}
	result.Rows = len(rows)
	if len(rows) == 0 {
		return result
	}

	// Directories still held here must not be touched. At startup this set is
	// empty; the check exists so that calling the sweep again later — from a
	// maintenance command, from a test — cannot pull a credential out from
	// under a running task.
	held := make(map[string]struct{})
	for _, sl := range liveLeases.snapshot() {
		if sl != nil && sl.dir != "" {
			held[sl.dir] = struct{}{}
		}
	}

	for _, row := range rows {
		if _, live := held[row.Dir]; live {
			result.Skipped++
			continue
		}
		existed := dirExists(row.Dir)
		if err := securewipe.Dir(row.Dir); err != nil {
			// Keep the row. It is the only handle anything has on this
			// directory, and dropping it because the wipe failed would make
			// the next startup blind to a credential that is still there.
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", row.Dir, err))
			fmt.Fprintf(os.Stderr,
				"ui: lease sweep: FAILED to wipe orphaned credential directory %s (lease %s); "+
					"the plaintext is still on this host: %v\n", row.Dir, row.LeaseID, err)
			continue
		}
		if existed {
			result.Wiped++
		} else {
			result.Vanished++
		}
		if err := db.DeleteSecretLeaseDir(row.Dir); err != nil {
			fmt.Fprintf(os.Stderr, "ui: lease sweep: clear record for %s: %v\n", row.Dir, err)
		}
	}

	reportLeaseSweep(db, controlPlaneDir, result, rows)
	return result
}

// dirExists reports whether a lease directory is actually on disk, so the sweep
// can tell a real orphan from a row whose directory was never created.
//
// The distinction is worth the extra stat: "wiped 3 orphaned credential
// directories" and "cleared 3 stale records" describe very different incidents,
// and an operator reading the startup log needs to know which one happened.
func dirExists(dir string) bool {
	info, err := os.Stat(dir)
	return err == nil && info.IsDir()
}

// reportLeaseSweep logs and audits a non-trivial sweep.
//
// A clean startup says nothing — the overwhelmingly common case should not add
// noise to every boot — but anything actually destroyed is both logged and
// written to the audit trail, because "this hub found credentials a previous
// run left on disk" is a security event an operator may have to account for
// long after the log has rotated.
func reportLeaseSweep(db *statedb.DB, controlPlaneDir string, res leaseSweepResult, rows []statedb.SecretLeaseDirRow) {
	if res.Wiped == 0 && res.Vanished == 0 && len(res.Errors) == 0 {
		return
	}

	now := time.Now().UTC()
	var expired int
	for _, row := range rows {
		if !row.ExpiresAt.IsZero() && now.After(row.ExpiresAt) {
			expired++
		}
	}

	fmt.Fprintf(os.Stderr,
		"ui: lease sweep: reconciled %d recorded credential director(ies) from a previous run "+
			"— %d wiped, %d already gone, %d still held, %d failed (%d had lapsed TTLs)\n",
		res.Rows, res.Wiped, res.Vanished, res.Skipped, len(res.Errors), expired)

	// The payload names counts and, on failure, the directory that still holds
	// plaintext. No lease contents and no environment: this trail records that
	// credentials were found and destroyed, never what they were.
	payload := map[string]any{
		"rows":     res.Rows,
		"wiped":    res.Wiped,
		"vanished": res.Vanished,
		"skipped":  res.Skipped,
		"failed":   len(res.Errors),
		"expired":  expired,
	}
	if len(res.Errors) > 0 {
		payload["errors"] = res.Errors
	}

	// Best-effort, like every other emitter: the credentials are already
	// destroyed by the time this runs, and failing startup because the journal
	// is unavailable would trade a recorded cleanup for no cleanup at all.
	statedb.AuditSecretDecision(db, statedb.SecretAuditInput{
		Actor:     "system",
		EventType: "secret.lease.sweep",
		EntityID:  controlPlaneDir,
		Payload:   payload,
	})
}
