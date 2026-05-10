// Manual abort requests (Task 20140).
//
// Thin wrapper around statedb.RequestKill / PendingKills / ClearKill so the
// UI server (which already imports pkg/state) can request task aborts
// without taking a separate statedb dependency.

package state

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// KillRequest is re-exported from statedb so callers don't have to import
// the lower layer just to read the requestor / target_status.
type KillRequest = statedb.KillRequest

// RequestTaskKill records a manual-abort request for taskID. The orchestrator's
// fast-tick poller picks this up and fires the task's registered cancel; once
// the worker exits, target_status is re-applied so the operator's choice
// wins over the worker's "canceled → failed" handling.
//
// Returns nil on success or when the project DB does not exist (a kill request
// against a project with no orchestrator running is benign — there's nothing
// to cancel).
func RequestTaskKill(workDir string, taskID int, targetStatus, requestedBy string) error {
	if workDir == "" || taskID <= 0 {
		return nil
	}
	dir := ActiveDir(workDir)
	dbPath := effectiveDBPath(dir)
	if _, err := os.Stat(filepath.Dir(dbPath)); err != nil {
		return nil
	}
	if _, err := os.Stat(dbPath); err != nil {
		return nil
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return fmt.Errorf("kill request open: %w", err)
	}
	defer db.Close()
	return db.RequestKill(statedb.KillRequest{
		TaskID:       taskID,
		TargetStatus: targetStatus,
		RequestedBy:  requestedBy,
	})
}

// PendingKills returns all currently-pending abort requests for the project.
// Returns (nil, nil) when the project has no DB yet.
func PendingKills(workDir string) ([]KillRequest, error) {
	if workDir == "" {
		return nil, nil
	}
	dir := ActiveDir(workDir)
	dbPath := effectiveDBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return db.PendingKills()
}

// LookupTaskKill returns the pending kill row for taskID. Used by the
// orchestrator after a worker exits to recover the operator's chosen
// target_status.
func LookupTaskKill(workDir string, taskID int) (KillRequest, bool, error) {
	if workDir == "" || taskID <= 0 {
		return KillRequest{}, false, nil
	}
	dir := ActiveDir(workDir)
	dbPath := effectiveDBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return KillRequest{}, false, nil
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return KillRequest{}, false, err
	}
	defer db.Close()
	return db.LookupKill(taskID)
}

// ClearTaskKill removes the kill row for taskID. Idempotent.
func ClearTaskKill(workDir string, taskID int) error {
	if workDir == "" || taskID <= 0 {
		return nil
	}
	dir := ActiveDir(workDir)
	dbPath := effectiveDBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.ClearKill(taskID)
}
