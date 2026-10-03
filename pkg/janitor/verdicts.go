package janitor

// verdicts.go bounds the orchestrator's verdict sidecars (Task 20365).
//
// The orchestrator writes .cloop/artifacts/<id>_verdict.json before each
// outcome write, so that a run that dies before the write is recovered as it
// decided rather than as its agent claimed. One file per task that ever ran:
// small, but nothing else would ever remove them. A sidecar is read only to
// recover a task left in progress, so once its task is in any other state — or
// gone from the plan — it is redundant, and this step removes it after
// VerdictMaxAge. The age keeps the pass away from a run that is writing one
// now, and leaves a recent decision on disk for whoever is looking into it.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/taskrecover"
)

// VerdictMaxAge is how long a verdict sidecar whose task is no longer in
// progress is kept.
const VerdictMaxAge = 7 * 24 * time.Hour

// pruneVerdicts removes the verdict sidecars recovery can no longer need.
//
// Which tasks are in progress comes from the database, never from a guess: a
// database that cannot be read prunes nothing, because the sidecars of tasks
// a dead run left in progress are exactly the ones recovery needs.
func pruneVerdicts(opts Options) StepResult {
	dbPath := filepath.Join(opts.WorkDir, ".cloop", "state.db")
	if _, err := os.Stat(dbPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return StepResult{Reason: "no state.db"}
		}
		return StepResult{Err: fmt.Errorf("janitor: stat state.db: %w", err)}
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return StepResult{Err: fmt.Errorf("janitor: open state.db to prune task verdicts: %w", err)}
	}
	statuses, err := db.TaskStatuses()
	_ = db.Close() //nolint:errcheck // a read-only use; nothing to flush
	if err != nil {
		return StepResult{Err: fmt.Errorf("janitor: read task statuses to prune task verdicts: %w", err)}
	}

	res, err := taskrecover.PruneVerdicts(opts.WorkDir,
		func(id int) bool { return statuses[id] == pm.TaskInProgress },
		opts.now().Add(-VerdictMaxAge), opts.DryRun)
	out := StepResult{
		Ran:        true,
		Deleted:    res.Deleted,
		BytesFreed: res.Bytes,
		Reason: fmt.Sprintf("kept %d; a verdict is removed %s after its task leaves in-progress",
			res.Kept, humanDays(VerdictMaxAge)),
	}
	if err != nil {
		out.Err = fmt.Errorf("janitor: prune task verdicts: %w", err)
	}
	return out
}

func humanDays(d time.Duration) string {
	if n := int(d / (24 * time.Hour)); n > 0 && d%(24*time.Hour) == 0 {
		if n == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", n)
	}
	return d.String()
}
