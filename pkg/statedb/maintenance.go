// Maintenance helpers for the SQLite state database (Task 20107).
//
// VACUUM reclaims space from rows previously deleted (cloop deletes step rows
// on `cloop compact`, prunes archived tasks, etc.). ANALYZE refreshes the
// query planner's statistics so growing tables continue to use sensible
// indexes. Both operations run as autocommit statements and acquire d.mu so
// no other goroutine in this process can interleave with them; cross-process
// contention is bounded by busy_timeout=5000.
//
// Persistence: every successful VACUUM/ANALYZE run is appended to the
// `maintenance_log` table by AppendMaintenanceLog so:
//   - cloop db maintain --auto can compare current page_count against the
//     last vacuum's page_count_after to decide whether to skip,
//   - cloop doctor can surface "last maintenance: 3d ago, freed 4.2 MB",
//   - operators have a forensic trail when investigating disk-usage spikes.
package statedb

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SizeStats captures the physical size of the SQLite database at a point in
// time. Bytes is derived as PageCount * PageSize for convenience; FreelistPages
// counts free pages that VACUUM would reclaim.
type SizeStats struct {
	PageCount     int64
	PageSize      int64
	FreelistPages int64
	Bytes         int64
}

// FreelistBytes returns the bytes currently allocated to the freelist —
// roughly the upper bound on what VACUUM can reclaim.
func (s SizeStats) FreelistBytes() int64 {
	return s.FreelistPages * s.PageSize
}

// SizeStats reads PRAGMA page_count, page_size, and freelist_count.
//
// Connection-scoped pragmas — modernc.org/sqlite returns one row per query.
// We hold d.mu so the three reads stay consistent against concurrent writers
// in this process; concurrent writers in *other* processes can still extend
// the file between the page_count and freelist_count reads, but the resulting
// values remain individually valid (worst case: a slightly stale Bytes total).
func (d *DB) SizeStats() (SizeStats, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var s SizeStats
	if err := d.conn.QueryRow(`PRAGMA page_count`).Scan(&s.PageCount); err != nil {
		return s, fmt.Errorf("statedb: read page_count: %w", classifyDriverErr(err))
	}
	if err := d.conn.QueryRow(`PRAGMA page_size`).Scan(&s.PageSize); err != nil {
		return s, fmt.Errorf("statedb: read page_size: %w", classifyDriverErr(err))
	}
	if err := d.conn.QueryRow(`PRAGMA freelist_count`).Scan(&s.FreelistPages); err != nil {
		return s, fmt.Errorf("statedb: read freelist_count: %w", classifyDriverErr(err))
	}
	s.Bytes = s.PageCount * s.PageSize
	return s, nil
}

// Vacuum runs a full VACUUM on the database. Cannot be inside a transaction;
// the autocommit code path in modernc.org/sqlite handles this correctly. WAL
// mode is preserved across the VACUUM (SQLite re-applies the journal_mode
// pragma internally).
func (d *DB) Vacuum() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`VACUUM`); err != nil {
		return fmt.Errorf("statedb: VACUUM: %w", classifyDriverErr(err))
	}
	return nil
}

// Analyze runs ANALYZE to refresh the query planner's per-index statistics.
// Cheap on small databases; on large ones it scales roughly with total row
// count across all indexes.
func (d *DB) Analyze() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`ANALYZE`); err != nil {
		return fmt.Errorf("statedb: ANALYZE: %w", classifyDriverErr(err))
	}
	return nil
}

// WALCheckpointTruncate flushes the WAL into the main database file and
// truncates the WAL to zero bytes. Used as the first step of a hot backup
// (Task 20115) so VACUUM INTO produces a snapshot that includes every
// committed transaction up to the moment of the backup, not just whatever
// had previously been folded into the main file.
//
// PRAGMA wal_checkpoint returns three columns: busy (0 if checkpoint
// completed without contention), log_size (frames in the WAL before the
// checkpoint), and checkpointed (frames moved to the main DB). The string
// returned summarises those values for logging; a non-zero busy column is
// not an error per se — under heavy concurrent load the checkpoint can
// only flush as many frames as it could acquire — but it is reported so an
// operator can decide whether to retry.
func (d *DB) WALCheckpointTruncate() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var busy, logSize, checkpointed int
	row := d.conn.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`)
	if err := row.Scan(&busy, &logSize, &checkpointed); err != nil {
		return "", fmt.Errorf("statedb: wal_checkpoint(TRUNCATE): %w", classifyDriverErr(err))
	}
	if busy != 0 {
		return fmt.Sprintf("PARTIAL (busy=%d log_frames=%d checkpointed=%d)", busy, logSize, checkpointed), nil
	}
	return fmt.Sprintf("TRUNCATE log_frames=%d checkpointed=%d", logSize, checkpointed), nil
}

// VacuumInto produces a transactionally-consistent copy of the database at
// outPath using SQLite's `VACUUM INTO 'path'` statement. The output is a
// single self-contained file (no WAL/SHM sidecars) and is the recommended
// hot-backup primitive when the C-level Online Backup API is not available.
//
// outPath must not already exist — VACUUM INTO refuses to overwrite. The
// caller is responsible for clearing any stale destination first.
//
// The path is interpolated into a SQL string literal because VACUUM INTO
// does not accept bound parameters. Single quotes in the path are escaped
// by doubling, matching SQLite's quoting rules.
func (d *DB) VacuumInto(outPath string) error {
	if outPath == "" {
		return fmt.Errorf("statedb: VACUUM INTO: empty output path")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	escaped := strings.ReplaceAll(outPath, "'", "''")
	stmt := fmt.Sprintf(`VACUUM INTO '%s'`, escaped)
	if _, err := d.conn.Exec(stmt); err != nil {
		return fmt.Errorf("statedb: VACUUM INTO %q: %w", outPath, classifyDriverErr(err))
	}
	return nil
}

// MaintenanceLogEntry mirrors one row of the maintenance_log table.
//
// ID is auto-assigned by SQLite on insert. Operation is one of "vacuum",
// "analyze", or "vacuum+analyze" (we record the combined run as a single row).
// Note carries free-form context — typically the auto-mode reasoning string.
type MaintenanceLogEntry struct {
	ID              int64
	Operation       string
	StartedAt       time.Time
	CompletedAt     time.Time
	PageCountBefore int64
	PageCountAfter  int64
	PageSize        int64
	BytesBefore     int64
	BytesAfter      int64
	Note            string
}

// BytesFreed returns BytesBefore - BytesAfter (zero when the file did not
// shrink, e.g. because freelist was already empty).
func (e MaintenanceLogEntry) BytesFreed() int64 {
	if e.BytesBefore <= e.BytesAfter {
		return 0
	}
	return e.BytesBefore - e.BytesAfter
}

// AppendMaintenanceLog inserts a maintenance_log row. Returns the new row id.
// StartedAt / CompletedAt default to time.Now().UTC() when zero so callers
// don't have to fill them in for ad-hoc records.
func (d *DB) AppendMaintenanceLog(e MaintenanceLogEntry) (int64, error) {
	now := time.Now().UTC()
	if e.StartedAt.IsZero() {
		e.StartedAt = now
	}
	if e.CompletedAt.IsZero() {
		e.CompletedAt = now
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	res, err := d.conn.Exec(`
		INSERT INTO maintenance_log(operation, started_at, completed_at,
			page_count_before, page_count_after, page_size,
			bytes_before, bytes_after, note)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		e.Operation,
		e.StartedAt.UTC().Format(time.RFC3339Nano),
		e.CompletedAt.UTC().Format(time.RFC3339Nano),
		e.PageCountBefore, e.PageCountAfter, e.PageSize,
		e.BytesBefore, e.BytesAfter, e.Note,
	)
	if err != nil {
		return 0, fmt.Errorf("statedb: append maintenance_log: %w", classifyDriverErr(err))
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("statedb: append maintenance_log: %w", classifyDriverErr(err))
	}
	return id, nil
}

// LastMaintenanceLog returns the most recent maintenance_log row. Returns
// (nil, nil) when no maintenance has been recorded yet — callers should treat
// that as "schedule a maintenance run on first invocation".
func (d *DB) LastMaintenanceLog() (*MaintenanceLogEntry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	row := d.conn.QueryRow(`
		SELECT id, operation, started_at, completed_at,
			page_count_before, page_count_after, page_size,
			bytes_before, bytes_after, note
		FROM maintenance_log
		ORDER BY id DESC LIMIT 1`)

	var (
		e                       MaintenanceLogEntry
		startedAt, completedAt  string
	)
	err := row.Scan(&e.ID, &e.Operation, &startedAt, &completedAt,
		&e.PageCountBefore, &e.PageCountAfter, &e.PageSize,
		&e.BytesBefore, &e.BytesAfter, &e.Note)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("statedb: read last maintenance_log: %w", classifyDriverErr(err))
	}
	e.StartedAt, _ = time.Parse(time.RFC3339Nano, startedAt)
	e.CompletedAt, _ = time.Parse(time.RFC3339Nano, completedAt)
	return &e, nil
}
