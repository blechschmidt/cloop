package statedb

// connpolicy.go: how every connection to a cloop SQLite file is opened (Task
// 20374).
//
// statedb's own handles have opened under one policy since Task 20349, and each
// part of it closed a failure seen on a live hub (connString tells the story):
// busy_timeout before any other statement, so not even the WAL pragma can fail
// on a lock it could have waited out; foreign keys on; and transactions that
// take the write lock at BEGIN, so a read-then-write transaction waits on the
// busy handler instead of failing with SQLITE_BUSY_SNAPSHOT, which no busy
// handler retries.
//
// Eight other packages opened the same files with a bare sql.Open and had none
// of it. Several issued `PRAGMA busy_timeout` with Exec after opening, which
// looks equivalent and is not: the pragma is connection-scoped, so it reached
// the one connection that ran it and no other. database/sql replaces pooled
// connections — after a driver error, at a lifetime limit — and the
// replacement started with a busy_timeout of zero: taskqueue's MarkDone then
// failed instantly with "database is locked" against a writer it would
// otherwise have waited a few milliseconds for. A setting carried in the data
// source name is applied by the driver to every connection it opens, before the
// connection is handed out, which is the only place a connection-scoped pragma
// actually holds.
//
// So the policy lives here, once. tests/arch rejects a sql.Open anywhere else
// in production code, so the next package to open a cloop database inherits the
// policy instead of rediscovering why it exists.

import (
	"database/sql"
	"fmt"
	"net/url"
	"strconv"
)

// Access is what a handle opened under the connection policy may do.
type Access int

const (
	// ReadWrite handles read and write. Their transactions take the write
	// lock at BEGIN (BEGIN IMMEDIATE): every transaction cloop opens reads
	// before it writes, and a deferred one fails with SQLITE_BUSY_SNAPSHOT —
	// no busy handler, no retry — whenever another handle commits between its
	// read and its write. In WAL mode an immediate transaction blocks no
	// reader.
	ReadWrite Access = iota
	// ReadOnly handles cannot write, enforced by SQLite rather than by the
	// caller's good behaviour: the file is opened mode=ro. A diagnostic, a
	// backup check or a liveness probe that looks at a hub's live database
	// can neither change it nor, when the file does not exist, create an
	// empty one in its place.
	ReadOnly
)

// String names the access mode for messages.
func (a Access) String() string {
	if a == ReadOnly {
		return "read-only"
	}
	return "read-write"
}

// BusyTimeoutMillis is how long any connection under the policy waits on
// another connection's lock before returning SQLITE_BUSY.
const BusyTimeoutMillis = 5000

// JournalSizeLimitBytes is the size a read-write connection under the policy
// trims the write-ahead log back to when it restarts it (Task 20392).
//
// SQLite rewrites a WAL from its start once a checkpoint has copied every
// frame back into the database, but it never shrinks the file: the log stays
// at the high-water mark of the largest burst written between two checkpoints
// — a bulk delete, a VACUUM, which writes the whole database through it — for
// as long as the database is open. On 2026-10-06 the hub's own log was 340 MB
// beside a 409 MB database on a disk 98% full, in use, and never coming back.
// With journal_size_limit set, the connection whose write restarts the log
// truncates the file to this size when that write commits, or to the size
// of the write if that is larger. Nothing else changes: the limit is not a
// cap on how large the log may grow, and checkpoints run as before.
//
// 64 MiB is several times the log a busy hub needs between two automatic
// checkpoints (1000 pages, 4 MiB), so the trim costs a steady-state hub
// nothing, and small enough that a burst no longer leaves a meaningful share
// of a small disk behind.
const JournalSizeLimitBytes int64 = 64 << 20

// DSN returns the data source name a handle with the given access opens path
// with.
//
// The name is a file: URI, so that the path is escaped rather than parsed: the
// driver cuts a bare path at its first '?', so a project directory with a
// question mark in its name would open some other file, and mode=ro only means
// something to SQLite inside a URI.
func DSN(path string, access Access) string {
	return policyDSN(path, access)
}

// policyDSN is DSN with further pragmas a caller adds to the policy's own —
// statedb.Open's synchronous=NORMAL, which is only safe because Open also puts
// the file in WAL mode.
func policyDSN(path string, access Access, extraPragmas ...string) string {
	pragmas := []string{
		// The driver issues busy_timeout before every other pragma whatever
		// the order here; it is listed first so the reader does not have to
		// know that.
		"busy_timeout(" + strconv.Itoa(BusyTimeoutMillis) + ")",
		"foreign_keys(1)",
	}
	if access != ReadOnly {
		// Whichever connection restarts the log trims it (Task 20392). A
		// read-only handle never writes the log, so it never restarts it.
		pragmas = append(pragmas, "journal_size_limit("+strconv.FormatInt(JournalSizeLimitBytes, 10)+")")
	}
	pragmas = append(pragmas, extraPragmas...)
	q := url.Values{"_pragma": pragmas}
	switch access {
	case ReadOnly:
		q.Set("mode", "ro")
	default:
		q.Set("_txlock", "immediate")
	}
	return "file:" + url.PathEscape(path) + "?" + q.Encode()
}

// OpenConn opens path under the connection policy and checks that the first
// connection can be established, so a missing file or a bad path is reported
// here rather than by whichever query happens to run first.
//
// The pool holds one connection. Within a process that serialises every
// statement on the handle, which is what all of cloop's callers want; the
// policy does not depend on it, because the driver applies the policy to every
// connection it opens, so a caller that needs more may raise the limit.
//
// A ReadOnly open of a file that does not exist fails rather than creating it.
func OpenConn(path string, access Access) (*sql.DB, error) {
	conn, err := sql.Open("sqlite", DSN(path, access))
	if err != nil {
		return nil, fmt.Errorf("statedb: open %s (%s): %w", path, access, classifyDriverErr(err))
	}
	conn.SetMaxOpenConns(1)
	if err := conn.Ping(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("statedb: open %s (%s): %w", path, access, classifyDriverErr(err))
	}
	return conn, nil
}
