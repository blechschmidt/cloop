// Package eventlog wraps the audit log for forensic and compliance use cases
// (Task 20119): tail (with optional follow), filter, replay into a fresh
// database, and verify the SHA-256 hash chain.
//
// The append-only `audit_events` table itself lives in pkg/statedb so that
// mutation hot-paths (UpsertTask, AppendStep, SetConfigBlob, SaveState) can
// emit rows without an import cycle. This package supplies the workdir-aware
// API and operator-facing workflows on top.
//
// The audit log is best-effort by design: a stuck DB cannot block user work.
// `cloop events verify` is the explicit check that the chain is intact;
// detected breaks tell operators the journal lost or had rows tampered with.
package eventlog

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// AuditEvent re-exports statedb.AuditEvent so callers don't need to import
// both packages.
type AuditEvent = statedb.AuditEvent

// AuditFilter re-exports statedb.AuditFilter.
type AuditFilter = statedb.AuditFilter

// VerifyReport re-exports statedb.AuditVerifyReport.
type VerifyReport = statedb.AuditVerifyReport

// ErrNoProject is returned when the resolved workdir has no SQLite state DB
// yet — usually because cloop init has not been run.
var ErrNoProject = errors.New("eventlog: no .cloop/state.db found at workdir")

// Open opens a handle to the audit log at the resolved state.db path. The
// caller must Close.
func Open(workDir string) (*Log, error) {
	if workDir == "" {
		return nil, fmt.Errorf("eventlog: empty workdir")
	}
	dbPath := state.DBPath(workDir)
	if _, err := os.Stat(dbPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoProject
		}
		return nil, fmt.Errorf("eventlog: stat %s: %w", dbPath, err)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("eventlog: open %s: %w", dbPath, err)
	}
	return &Log{db: db, dbPath: dbPath}, nil
}

// Log is a handle to an audit log. Concurrency: safe for use by multiple
// goroutines as long as Close is only called once.
type Log struct {
	db     *statedb.DB
	dbPath string
}

// DB returns the underlying *statedb.DB. Exposed so callers that already need
// other statedb operations against the same database don't open a second
// connection.
func (l *Log) DB() *statedb.DB { return l.db }

// Path returns the on-disk path of the SQLite database.
func (l *Log) Path() string { return l.dbPath }

// Close releases the underlying connection.
func (l *Log) Close() error {
	if l == nil || l.db == nil {
		return nil
	}
	return l.db.Close()
}

// Append records one event. Caller-supplied actor/event_type/etc. flow
// through to the row; the package fills timestamp + hash chain.
func (l *Log) Append(ev *AuditEvent) error {
	return l.db.AppendAuditEvent(ev)
}

// List returns events matching the filter and the unfiltered total count.
func (l *Log) List(f AuditFilter) ([]AuditEvent, int, error) {
	return l.db.ListAuditEvents(f)
}

// Verify recomputes the SHA-256 chain from the genesis row to head. Returns
// (report, nil) for a clean verification, including reports where OK=false:
// the inner Reason describes the break. The error return is reserved for
// driver/IO failures.
func (l *Log) Verify() (VerifyReport, error) {
	return l.db.VerifyAuditChain()
}

// MaxID returns the largest id currently in the audit log; 0 when empty.
func (l *Log) MaxID() (int64, error) {
	return l.db.MaxAuditID()
}

// DistinctActors returns the sorted list of actor values seen in the log.
// Used by the Web UI's filter dropdown.
func (l *Log) DistinctActors() ([]string, error) {
	return l.db.AuditDistinctActors()
}

// DistinctEntityTypes returns the sorted list of entity types seen.
func (l *Log) DistinctEntityTypes() ([]string, error) {
	return l.db.AuditDistinctEntityTypes()
}

// TailOptions controls Tail behaviour.
type TailOptions struct {
	FromID  int64         // start streaming events with id >= FromID (1 = beginning)
	Follow  bool          // when true, keep polling for new events; when false, return at head
	Poll    time.Duration // follow-mode polling interval (default 500ms)
	Filter  AuditFilter   // additional filtering (Order/Limit/Offset/FromID are overridden)
	BatchSize int         // events per query (default 200, capped at 5000)
}

// Tail streams events to out in id-ascending order. When Follow is false the
// function returns once it has caught up to MaxID at the time of the call.
// When Follow is true the function only returns on context cancellation.
//
// The channel out is closed before Tail returns (success or error). The
// caller may pass an unbuffered channel; Tail respects ctx during sends.
func (l *Log) Tail(ctx context.Context, opts TailOptions, out chan<- AuditEvent) error {
	defer close(out)

	if opts.Poll <= 0 {
		opts.Poll = 500 * time.Millisecond
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 200
	} else if opts.BatchSize > 5000 {
		opts.BatchSize = 5000
	}

	cursor := opts.FromID
	if cursor < 1 {
		cursor = 1
	}

	for {
		f := opts.Filter
		f.FromID = cursor
		f.Order = "asc"
		f.Limit = opts.BatchSize
		f.Offset = 0

		rows, _, err := l.db.ListAuditEvents(f)
		if err != nil {
			return fmt.Errorf("eventlog tail: %w", err)
		}
		for _, ev := range rows {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case out <- ev:
			}
			if ev.ID >= cursor {
				cursor = ev.ID + 1
			}
		}
		// If we got a full batch, immediately query again to drain the backlog
		// before returning or sleeping. This is what gives the operator
		// "instant cat-ish" semantics on cold start.
		if len(rows) == opts.BatchSize {
			continue
		}

		if !opts.Follow {
			return nil
		}

		// Sleep, then loop. Honour ctx during the wait so SIGINT returns
		// promptly without an extra round-trip to the database.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(opts.Poll):
		}
	}
}
