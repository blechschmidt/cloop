package janitor

// The write-ahead log: the last step of a pass (Task 20392).
//
// Every step before this one writes through state.db-wal. A row prune of a
// busy table rewrites every page it touches, and a VACUUM writes the whole
// database through the log, so a pass that ended without this step would
// leave behind a log as large as the work it just did — and SQLite never
// shrinks the file on its own. The connection policy's journal_size_limit
// trims it the next time one of this build's connections starts the log over;
// this step does not wait for that, and covers a database whose writers
// predate the limit.

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/blechschmidt/cloop/pkg/diskusage"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// truncateWAL resets the database's write-ahead log once the pass's own
// writes are in it.
//
// It runs whether or not a run is busy or other hub processes serve the
// database, unlike the VACUUM: the checkpoint waits at most
// statedb.WALCheckpointBusyTimeout for anything, so the longest it can hold a
// writer up is a fraction of a second, and a reader is never waited out. A
// checkpoint that finds a reader still using the log reports busy, which is
// recorded as a skipped step — the hub retries on its next check, and the
// next pass does anyway.
func truncateWAL(opts Options) StepResult {
	dbPath := filepath.Join(opts.WorkDir, ".cloop", "state.db")
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return StepResult{Reason: "no state.db"}
		}
		return StepResult{Err: fmt.Errorf("janitor: stat state.db: %w", err)}
	}
	size, err := statedb.WALSize(dbPath)
	if err != nil {
		return StepResult{Err: fmt.Errorf("janitor: %w", err)}
	}
	if size == 0 {
		return StepResult{Ran: true, Reason: "no write-ahead log to truncate"}
	}
	if opts.DryRun {
		return StepResult{
			Skipped:    true,
			BytesFreed: size,
			Reason:     "dry run: would truncate the " + diskusage.HumanBytes(size) + " write-ahead log",
		}
	}

	cp, err := statedb.CheckpointWAL(dbPath, statedb.WALCheckpointBusyTimeout)
	if err != nil {
		return StepResult{Err: fmt.Errorf("janitor: truncate the write-ahead log: %w", err)}
	}
	return walStep(cp)
}

// walStep renders a TRUNCATE checkpoint's outcome as a step result.
func walStep(cp statedb.WALCheckpoint) StepResult {
	switch {
	case cp.Busy:
		return StepResult{
			Skipped: true,
			Reason: fmt.Sprintf("busy: another connection was still using the %s log after %s; it is retried",
				diskusage.HumanBytes(cp.BytesBefore), statedb.WALCheckpointBusyTimeout),
		}
	case !cp.Truncated():
		return StepResult{Reason: "the database is not in WAL mode"}
	}
	return StepResult{
		Ran:        true,
		BytesFreed: cp.BytesFreed(),
		Reason: fmt.Sprintf("truncated the write-ahead log, %s → %s",
			diskusage.HumanBytes(cp.BytesBefore), diskusage.HumanBytes(cp.BytesAfter)),
	}
}
