// Package dbverify runs SQLite integrity checks against the cloop state database.
//
// It exposes a Verify() function used by both the `cloop db verify` CLI command
// and `cloop doctor` so that silent on-disk corruption (after a crash, a disk
// error, or a partial write) is surfaced before it manifests as a confusing
// runtime failure deeper in the stack.
//
// The package opens its own *sql.DB handle (not statedb.Open) and runs only
// PRAGMA integrity_check / quick_check / foreign_key_check. We avoid
// statedb.Open here because:
//
//   - statedb.Open executes the CREATE TABLE schema, which would mutate a
//     freshly-corrupted database during a read-only diagnostic.
//   - statedb.Open enables WAL mode, which writes -wal/-shm sidecar files
//     even on a verify-only path.
//
// A directly-opened, read-only handle keeps verification truly side-effect-free.
package dbverify

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGo
)

// Report summarises the result of an integrity verification run.
type Report struct {
	// DBPath is the path of the database that was checked.
	DBPath string

	// QuickCheck is true if PRAGMA quick_check was used instead of
	// the slower-but-more-thorough PRAGMA integrity_check.
	QuickCheck bool

	// IntegrityIssues holds the rows returned by integrity_check / quick_check.
	// A clean database returns a single row containing the literal string "ok"
	// — Verify normalises that into an empty slice so callers can simply
	// check len(IntegrityIssues) == 0.
	IntegrityIssues []string

	// ForeignKeyViolations holds rows returned by PRAGMA foreign_key_check.
	// Each row identifies a child row that does not satisfy its FK constraint.
	ForeignKeyViolations []ForeignKeyViolation
}

// ForeignKeyViolation describes one row returned by PRAGMA foreign_key_check.
//
// Columns (per https://www.sqlite.org/pragma.html#pragma_foreign_key_check):
//
//	table   — name of the child table
//	rowid   — rowid of the offending row in the child table (NULL for views)
//	parent  — name of the parent table the FK should reference
//	fkid    — index of the failed FK constraint within the child table
type ForeignKeyViolation struct {
	Table  string
	RowID  sql.NullInt64
	Parent string
	FKID   int
}

// OK reports whether the report contains zero issues.
func (r *Report) OK() bool {
	return len(r.IntegrityIssues) == 0 && len(r.ForeignKeyViolations) == 0
}

// Verify runs PRAGMA integrity_check (or quick_check when quick is true) and
// PRAGMA foreign_key_check against the SQLite database at dbPath.
//
// Returns a populated *Report describing any issues found. A nil error with
// report.OK() == true means the database is structurally sound. Any error
// returned indicates Verify itself could not run (file missing, driver
// failure, etc.) — distinct from "ran successfully but found corruption".
func Verify(dbPath string, quick bool) (*Report, error) {
	if dbPath == "" {
		return nil, errors.New("dbverify: empty database path")
	}
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("dbverify: database not found: %s", dbPath)
		}
		return nil, fmt.Errorf("dbverify: stat %s: %w", dbPath, err)
	}

	// Open read-only with immutable=0 so we can still see live updates if the
	// DB is being written to by another process (e.g. a running cloop ui), but
	// our handle itself never writes.
	dsn := fmt.Sprintf("file:%s?mode=ro", url.PathEscape(dbPath))
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("dbverify: open %s: %w", dbPath, err)
	}
	defer conn.Close()
	conn.SetMaxOpenConns(1)

	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("dbverify: ping %s: %w", dbPath, err)
	}

	rep := &Report{DBPath: dbPath, QuickCheck: quick}

	pragma := "integrity_check"
	if quick {
		pragma = "quick_check"
	}
	issues, err := runIntegrityCheck(conn, pragma)
	if err != nil {
		return nil, fmt.Errorf("dbverify: %s: %w", pragma, err)
	}
	rep.IntegrityIssues = issues

	violations, err := runForeignKeyCheck(conn)
	if err != nil {
		return nil, fmt.Errorf("dbverify: foreign_key_check: %w", err)
	}
	rep.ForeignKeyViolations = violations

	return rep, nil
}

// runIntegrityCheck executes PRAGMA integrity_check or PRAGMA quick_check and
// returns the issue rows. A clean database returns exactly one row with the
// string "ok", which we filter out so the caller sees an empty slice.
func runIntegrityCheck(conn *sql.DB, pragma string) ([]string, error) {
	rows, err := conn.Query("PRAGMA " + pragma)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var issues []string
	for rows.Next() {
		var msg string
		if err := rows.Scan(&msg); err != nil {
			return nil, err
		}
		if msg == "ok" {
			continue
		}
		issues = append(issues, msg)
	}
	return issues, rows.Err()
}

// runForeignKeyCheck executes PRAGMA foreign_key_check and returns each
// reported violation. Empty result set means every row satisfies its FKs.
func runForeignKeyCheck(conn *sql.DB) ([]ForeignKeyViolation, error) {
	rows, err := conn.Query("PRAGMA foreign_key_check")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ForeignKeyViolation
	for rows.Next() {
		var v ForeignKeyViolation
		if err := rows.Scan(&v.Table, &v.RowID, &v.Parent, &v.FKID); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
