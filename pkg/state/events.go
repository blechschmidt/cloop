// Event journal helpers (Task 20118).
//
// Wraps statedb.RecordEvent / ListEvents in a workdir-resolving API so callers
// don't need to manage statedb handles directly. RecordEvent is best-effort:
// failures are logged to stderr but never returned, matching the orchestrator's
// invariant that observability code paths must not fail user work.

package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// EventRow is re-exported for callers that don't want to import statedb
// directly (the orchestrator uses pkg/state already).
type EventRow = statedb.EventRow

// EventType is re-exported for the same reason.
type EventType = statedb.EventType

// Re-exported event-type constants. Keep this list in sync with
// pkg/statedb/events.go.
const (
	EventSessionStarted    = statedb.EventSessionStarted
	EventSessionPaused     = statedb.EventSessionPaused
	EventSessionFailed     = statedb.EventSessionFailed
	EventPlanComplete      = statedb.EventPlanComplete
	EventTaskStarted       = statedb.EventTaskStarted
	EventTaskDone          = statedb.EventTaskDone
	EventTaskFailed        = statedb.EventTaskFailed
	EventTaskSkipped       = statedb.EventTaskSkipped
	EventTaskHeal          = statedb.EventTaskHeal
	EventTaskKilled        = statedb.EventTaskKilled
	EventTaskAdded         = statedb.EventTaskAdded
	EventTaskAddedExternal = statedb.EventTaskAddedExternal
	EventTaskDeleted       = statedb.EventTaskDeleted
	EventTaskStatusChange  = statedb.EventTaskStatusChange
	EventEvolveRoundStart  = statedb.EventEvolveRoundStart
	EventEvolveDiscovered  = statedb.EventEvolveDiscovered
	EventEvolveNoOp        = statedb.EventEvolveNoOp
)

// LogEvent appends one row to the project's event journal. Best-effort: any
// persistence error is reported to stderr and otherwise swallowed so that
// observability never blocks the orchestrator's work.
//
// Pass workDir as the project root (or a session dir); it is resolved through
// the same effectiveDBPath the rest of the package uses. The Timestamp field
// of row will be set to time.Now() if zero.
func LogEvent(workDir string, row EventRow) {
	if workDir == "" {
		return
	}
	dir := ActiveDir(workDir)
	dbPath := effectiveDBPath(dir)
	// Don't auto-create the .cloop dir from observability code — if no project
	// exists, just drop the event.
	if _, err := os.Stat(filepath.Dir(dbPath)); err != nil {
		return
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[events] open %s: %v\n", dbPath, err)
		return
	}
	defer db.Close()
	if row.Timestamp.IsZero() {
		row.Timestamp = time.Now()
	}
	if row.Step == 0 {
		// Treat zero as "no associated step" rather than step #0 by default;
		// the orchestrator passes an explicit step value for step-bound events.
		row.Step = -1
	}
	if err := db.RecordEvent(row); err != nil {
		fmt.Fprintf(os.Stderr, "[events] record %s: %v\n", row.Type, err)
	}
}

// LogEventDetails serialises v as the row's Details JSON before recording. v
// may be nil (no details). Marshal failures fall back to recording without
// details rather than dropping the event entirely.
func LogEventDetails(workDir string, row EventRow, v any) {
	if v != nil {
		if b, err := json.Marshal(v); err == nil {
			row.Details = string(b)
		}
	}
	LogEvent(workDir, row)
}

// ListEvents returns up to limit events starting at offset, latest-first,
// along with the total event count. Returns (nil, 0, nil) for projects that
// don't have a state.db yet.
func ListEvents(workDir string, offset, limit int) ([]EventRow, int, error) {
	if workDir == "" {
		return nil, 0, nil
	}
	dir := ActiveDir(workDir)
	dbPath := effectiveDBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, 0, nil
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, 0, err
	}
	defer db.Close()
	return db.ListEvents(offset, limit)
}
