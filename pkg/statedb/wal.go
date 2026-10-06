package statedb

// wal.go: keeping the write-ahead log bounded (Task 20392).
//
// A database in WAL mode appends every write to state.db-wal and copies it
// back into the database at a checkpoint. Once a checkpoint has copied every
// frame, the next write starts the log again from its beginning — but the
// file keeps its size. Nothing in SQLite shrinks it unless journal_size_limit
// is set or a TRUNCATE checkpoint runs, so a WAL stays at the high-water mark
// of its largest burst for as long as the database is open. On a hub that is
// forever: on 2026-10-06 the control plane's log was 339,949,472 bytes beside
// a 409 MB database, on a disk 98% full whose nightly deploy skips below 2 GB.
//
// Two things bound it now. The connection policy sets journal_size_limit on
// every read-write handle (JournalSizeLimitBytes), so whichever of this
// build's connections restarts the log trims it as that write commits. That
// covers a database this build writes; it does not cover one whose writers
// predate the limit — the hub shares its database with a long-lived run and an
// older dashboard — or one nobody is writing to. CheckpointWAL covers those:
// the hub's leader runs it after a retention pass and whenever it finds the
// log past the limit.
//
// # Why the checkpoint has a busy timeout of its own
//
// A TRUNCATE checkpoint, like FULL and RESTART, first takes the database's
// write lock and then, holding it, waits for every reader whose snapshot still
// needs frames in the log. SQLite documents it: "This mode blocks new database
// writers while it is pending." Under the policy's 5 s busy timeout one long
// read would hold every writer up for 5 s — twice over, since the checkpoint
// waits once to copy the log back and once more to reset it — and a writer's
// own busy timeout is the same 5 s, so the hub's heartbeat and a run's state
// write would fail with "database is locked". With WALCheckpointBusyTimeout
// the checkpoint gives up within a fraction of a second instead, SQLite
// reports it busy, the log stays as it was, and the next attempt tries again.
// A reader is never blocked or waited out: the checkpoint simply cannot reset
// the log past a snapshot that still reads from it.
//
// Waiting is not the only time the write lock is held: a TRUNCATE checkpoint
// also copies back, under that lock, every frame no checkpoint has copied yet.
// Usually that is a handful, since SQLite checkpoints every 1000 pages on its
// own. Behind a reader that held the log for a while it is everything written
// since — on a copy of the hub's database, 150 MB that took 300 ms to copy
// back. So a PASSIVE checkpoint goes first: it copies what it can without the
// write lock, never making a writer wait, and leaves the TRUNCATE only what
// was written in between.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// WALCheckpointBusyTimeout is how long a TRUNCATE checkpoint waits for another
// connection before reporting busy — and so roughly the longest a writer can
// be held up behind one, which SQLite makes wait while the checkpoint holds
// the write lock. A quarter of a second outlasts the reads and writes cloop
// makes, and is a twentieth of the 5 s every writer waits before giving up.
const WALCheckpointBusyTimeout = 250 * time.Millisecond

// WALPath returns the path of the write-ahead log beside dbPath.
func WALPath(dbPath string) string { return dbPath + "-wal" }

// WALSize reports the size of the write-ahead log beside dbPath. A log that
// does not exist is zero bytes, not an error: the last connection to close a
// WAL database deletes it.
func WALSize(dbPath string) (int64, error) {
	fi, err := os.Stat(WALPath(dbPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("statedb: measure the write-ahead log: %w", err)
	}
	return fi.Size(), nil
}

// WALCheckpoint is the outcome of one TRUNCATE checkpoint.
type WALCheckpoint struct {
	// Busy reports that the checkpoint could not finish within its busy
	// timeout: another connection held the write lock, or a reader's snapshot
	// still needed frames in the log. Not an error. What could be copied back
	// was, and the log keeps its size until an attempt finds it free.
	Busy bool `json:"busy"`
	// LogFrames and CheckpointedFrames are SQLite's counts after the attempt:
	// the frames in the log, and how many of them are in the database file.
	// Both are zero once the log is truncated; on a busy attempt they say how
	// far it got. -1 means the database is not in WAL mode at all.
	LogFrames          int `json:"log_frames"`
	CheckpointedFrames int `json:"checkpointed_frames"`
	// BytesBefore and BytesAfter are the log file's size either side. A writer
	// may start the log again the moment the checkpoint finishes, so
	// BytesAfter can be a few pages rather than zero.
	BytesBefore int64 `json:"bytes_before"`
	BytesAfter  int64 `json:"bytes_after"`
	// Duration is how long the TRUNCATE checkpoint ran: an upper bound on how
	// long it held the write lock. The PASSIVE one before it, which takes no
	// such lock, is not counted.
	Duration time.Duration `json:"duration"`
}

// Truncated reports whether the checkpoint reset the log.
func (c WALCheckpoint) Truncated() bool { return !c.Busy && c.LogFrames >= 0 }

// BytesFreed is how much the log shrank by.
func (c WALCheckpoint) BytesFreed() int64 {
	if c.BytesBefore > c.BytesAfter {
		return c.BytesBefore - c.BytesAfter
	}
	return 0
}

// CheckpointWAL runs PRAGMA wal_checkpoint(TRUNCATE) on the database at dbPath,
// through a connection of its own whose busy timeout is busy, or
// WALCheckpointBusyTimeout when busy is zero or less.
//
// It never creates a database: one that does not exist is an error wrapping
// os.ErrNotExist. Nothing about the schema is read, so it migrates nothing and
// works on a database of any version.
//
// A busy checkpoint is a result, not an error; see WALCheckpoint.Busy.
func CheckpointWAL(dbPath string, busy time.Duration) (WALCheckpoint, error) {
	var res WALCheckpoint
	if _, err := os.Stat(dbPath); err != nil {
		return res, fmt.Errorf("statedb: checkpoint %s: %w", dbPath, err)
	}
	before, err := WALSize(dbPath)
	if err != nil {
		return res, err
	}

	conn, err := OpenConn(dbPath, ReadWrite)
	if err != nil {
		return res, err
	}
	defer conn.Close() //nolint:errcheck // nothing was written through this handle but the checkpoint
	ctx := context.Background()
	c, err := conn.Conn(ctx)
	if err != nil {
		return res, fmt.Errorf("statedb: checkpoint %s: %w", dbPath, classifyDriverErr(err))
	}
	defer c.Close() //nolint:errcheck // returns the connection to a pool closed just after

	res, err = checkpointTruncate(ctx, c, busy)
	res.BytesBefore = before
	if err != nil {
		return res, fmt.Errorf("statedb: checkpoint %s: %w", dbPath, err)
	}
	if res.BytesAfter, err = WALSize(dbPath); err != nil {
		return res, err
	}
	return res, nil
}

// checkpointTruncate runs the TRUNCATE checkpoint on c with busy as its busy
// timeout, and puts the policy's timeout back afterwards: c may be a pooled
// connection that other statements go on to use.
func checkpointTruncate(ctx context.Context, c *sql.Conn, busy time.Duration) (WALCheckpoint, error) {
	var res WALCheckpoint
	if busy <= 0 {
		busy = WALCheckpointBusyTimeout
	}
	ms := busy.Milliseconds()
	if ms < 1 {
		ms = 1
	}
	if _, err := c.ExecContext(ctx, "PRAGMA busy_timeout = "+strconv.FormatInt(ms, 10)); err != nil {
		return res, fmt.Errorf("set the checkpoint's busy_timeout: %w", classifyDriverErr(err))
	}
	defer func() {
		if _, err := c.ExecContext(context.Background(), "PRAGMA busy_timeout = "+strconv.Itoa(BusyTimeoutMillis)); err != nil {
			// A connection left with the checkpoint's timeout would give up
			// on the next writer it meets after a quarter of a second. Have
			// the pool discard it rather than hand it out again.
			_ = c.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()

	// The copy, without the write lock: see the file comment.
	if _, err := c.ExecContext(ctx, `PRAGMA wal_checkpoint(PASSIVE)`); err != nil {
		return res, fmt.Errorf("wal_checkpoint(PASSIVE): %w", classifyDriverErr(err))
	}
	start := time.Now()
	var busyFlag int
	err := c.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busyFlag, &res.LogFrames, &res.CheckpointedFrames)
	res.Duration = time.Since(start)
	if err != nil {
		return res, fmt.Errorf("wal_checkpoint(TRUNCATE): %w", classifyDriverErr(err))
	}
	res.Busy = busyFlag != 0
	return res, nil
}
