package state

// quarantine.go is the explicit reset's half of the node-killer quarantine
// (Task 20391): the one path that lets a suspected node killer run again.
//
// A task two or more distinct executors went down under is marked by the
// hub's failover and fails. Nothing automatic brings it back: --retry-failed
// skips it and the orchestrator's gate holds it even if something sets it
// pending. What does is a person resetting it on purpose — `cloop task reset`,
// `cloop task bulk reset`, the dashboard's status control — and each of those
// calls ReleaseQuarantine, which removes the mark and the losses behind it,
// and records who released it.

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ReleaseQuarantine clears a task's quarantine mark and the node losses
// recorded against it, as part of an explicit reset to pending. actor is who
// reset it and via names the path ("cli", "ui", "bulk").
//
// It returns the mark it released, or nil when the task carried none — in
// which case the task's losses, if it had any, are still cleared: a reset is
// a fresh start, and a loss left over from before it would quarantine the
// task on the next unrelated node failure. A project with no database has
// nothing to release.
func ReleaseQuarantine(workDir string, taskID int, actor, via string) (*pm.TaskQuarantine, error) {
	if workDir == "" || taskID <= 0 {
		return nil, nil
	}
	dbPath := effectiveDBPath(ActiveDir(workDir))
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("release task %d: %w", taskID, err)
	}
	defer db.Close()
	db.AsProject()

	mark, err := db.TaskQuarantine(taskID)
	if err != nil {
		return nil, fmt.Errorf("release task %d: %w", taskID, err)
	}
	if _, err := db.ClearTaskQuarantine(taskID); err != nil {
		return nil, fmt.Errorf("release task %d: %w", taskID, err)
	}
	if mark == nil {
		return nil, nil
	}

	statedb.AuditTaskQuarantineRelease(db, taskID, *mark, actor, via)
	row := statedb.EventRow{
		Type:    statedb.EventFailover,
		TaskID:  taskID,
		Step:    statedb.NoStep,
		Message: fmt.Sprintf("quarantine released by an explicit reset (%s): the task may run again", via),
	}
	if err := db.RecordEvent(row); err != nil {
		fmt.Fprintf(os.Stderr, "[events] record %s: %v\n", row.Type, err)
	}
	return mark, nil
}
