package ui

// statedb_wal.go: the leader keeps the control plane's write-ahead log
// bounded (Task 20392).
//
// The connection policy's journal_size_limit trims the log whenever one of
// this build's connections starts it over, which on a hub that writes every
// few seconds is soon. It does nothing while the connections starting it over
// are older builds — this deployment's database is shared with a long-lived
// `cloop run` and an older dashboard — and nothing while a burst has left the
// log large and nobody writes. So the leader looks every minute, as part of
// its retention duty, and truncates the log while it is past the limit. One
// member doing that is enough: it is one file, and every member checkpointing
// it would only multiply the moments writers wait.

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/diskusage"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// walCheckInterval is how often the leader looks at the control plane's
// write-ahead log. Looking is a stat; a checkpoint runs only while the log is
// past statedb.JournalSizeLimitBytes, and holds writers up for at most
// statedb.WALCheckpointBusyTimeout when it does.
const walCheckInterval = time.Minute

// walLogEvery is how many consecutive busy or failed attempts pass between
// two log lines about them: the first says the log is held, and one an hour
// after that says it still is, rather than one a minute.
const walLogEvery = 60

// walCheckState is the leader's record of its attempts, across checks.
type walCheckState struct {
	mu     sync.Mutex
	busy   int // consecutive attempts that found the log in use
	failed int // consecutive attempts that could not check at all
}

// walCheckOutcome is one look at the control plane's log.
type walCheckOutcome struct {
	// Size is the log's size when the check looked at it.
	Size int64
	// Attempted reports that it was past the limit and a checkpoint ran;
	// Checkpoint is what that checkpoint reported.
	Attempted  bool
	Checkpoint statedb.WALCheckpoint
	// Err is a check that could not run: the log could not be measured, or
	// the checkpoint failed for a reason other than another connection.
	Err error
	// BusyStreak counts the consecutive attempts that found the log in use,
	// this one included; zero once one gets through.
	BusyStreak int
}

// checkControlPlaneWAL truncates the control plane's write-ahead log if it is
// larger than statedb.JournalSizeLimitBytes, and records how that went.
//
// A busy checkpoint — a reader still using the log, or a writer holding the
// lock past the checkpoint's short timeout — changes nothing and is not a
// fault. It is recorded, logged the first time and hourly after that, and the
// next check tries again.
func (s *Server) checkControlPlaneWAL() (out walCheckOutcome) {
	defer recoverGoroutine("checkControlPlaneWAL")
	if s == nil || s.WorkDir == "" {
		return out
	}
	dbPath := state.DBPath(s.WorkDir)
	if _, err := os.Stat(dbPath); err != nil {
		return out // nothing persisted yet, so no log
	}
	size, err := statedb.WALSize(dbPath)
	if err != nil {
		out.Err = err
		s.recordWALCheck(&out)
		return out
	}
	out.Size = size
	if size > statedb.JournalSizeLimitBytes {
		out.Attempted = true
		out.Checkpoint, out.Err = statedb.CheckpointWAL(dbPath, statedb.WALCheckpointBusyTimeout)
	}
	s.recordWALCheck(&out)
	return out
}

// recordWALCheck folds one outcome into the leader's record and logs what an
// operator needs to know: a truncation, a log held past the limit, a check
// that could not run.
func (s *Server) recordWALCheck(out *walCheckOutcome) {
	st := &s.walCheck
	st.mu.Lock()
	defer st.mu.Unlock()

	switch {
	case out.Err != nil:
		st.failed++
		if st.failed == 1 || st.failed%walLogEvery == 0 {
			s.logRetention(s.WorkDir, fmt.Sprintf("write-ahead log check failed (%d in a row): %v", st.failed, out.Err))
		}
		return
	case out.Attempted && out.Checkpoint.Busy:
		st.failed = 0
		st.busy++
		out.BusyStreak = st.busy
		if st.busy == 1 || st.busy%walLogEvery == 0 {
			s.logRetention(s.WorkDir, fmt.Sprintf(
				"write-ahead log is %s, over the %s limit, and another connection was still using it after %s "+
					"(%d attempt(s) so far); retrying every %.0f s",
				diskusage.HumanBytes(out.Size), diskusage.HumanBytes(statedb.JournalSizeLimitBytes),
				statedb.WALCheckpointBusyTimeout, st.busy, walCheckInterval.Seconds()))
		}
		return
	}

	held := st.busy
	st.busy, st.failed = 0, 0
	switch {
	case out.Attempted && out.Checkpoint.Truncated():
		msg := fmt.Sprintf("truncated the write-ahead log, %s → %s",
			diskusage.HumanBytes(out.Checkpoint.BytesBefore), diskusage.HumanBytes(out.Checkpoint.BytesAfter))
		if held > 0 {
			msg += fmt.Sprintf(", after %d busy attempt(s)", held)
		}
		s.logRetentionResult(s.WorkDir, msg)
	case held > 0:
		// Back under the limit without this check's help: a writer under the
		// connection policy started the log over and trimmed it.
		s.logRetentionResult(s.WorkDir, fmt.Sprintf("write-ahead log is back under the %s limit (%s), after %d busy attempt(s)",
			diskusage.HumanBytes(statedb.JournalSizeLimitBytes), diskusage.HumanBytes(out.Size), held))
	}
}
