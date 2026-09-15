package cmd

// Audit emission for manual task status flips made from the CLI (Task 20282).
//
// The orchestrator's task.dispatch and task.finish rows describe executions,
// and an execution cannot say who ended it. `cloop task done 63` is a human
// overriding a recorded outcome, and before this the audit trail had no row for
// it at all: the status simply differed between one task.upsert and the next,
// attributed to "system", indistinguishable from the orchestrator writing the
// same value.
//
// The UI's equivalent lives in pkg/ui/audit_api.go and emits through the same
// statedb.AuditTaskStatus, so a reviewer filtering event_type='task.status'
// sees flips from both surfaces in one series rather than having to know which
// tool was used.

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// auditManualTaskStatus records one operator-initiated status change.
//
// Best-effort, matching every emitter in pkg/statedb: the status has already
// been saved by the time this runs, and a wedged or read-only audit log must
// not turn a successful command into a failed one. The warning goes to stderr
// so it cannot corrupt the stdout of a command being parsed by a script.
func auditManualTaskStatus(workDir string, taskID int, oldStatus, newStatus pm.TaskStatus) {
	if oldStatus == newStatus {
		return
	}
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[audit] record task %d status change: %v\n", taskID, err)
		return
	}
	defer db.Close()
	statedb.AuditTaskStatus(db, taskID, string(oldStatus), string(newStatus), operatorActor())
}
