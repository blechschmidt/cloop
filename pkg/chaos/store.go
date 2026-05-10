package chaos

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGo
)

// Run is one row of the chaos_runs table — a single fault injection together
// with the observed outcome.
type Run struct {
	ID                 int64
	FaultType          FaultType
	Probability        float64
	StartedAt          time.Time
	StoppedAt          time.Time
	DurationMS         int64
	Outcome            Outcome
	OutcomeDetail      string
	ObservedErrors     int
	ObservedRetries    int
	ObservedRecoveries int
	Note               string
}

// Store is a thin SQLite-backed log of chaos injections. Uses its own *sql.DB
// rather than statedb.DB so chaos can run even when statedb itself is the
// subject of the fault (for sqlite-busy testing).
//
// All operations honour a brief busy_timeout so a fault holder doesn't
// accidentally wedge the chaos store while testing sqlite-busy contention.
type Store struct {
	db     *sql.DB
	dbPath string
}

// OpenStore opens (and migrates as needed) the chaos_runs table inside the
// project state database. Reuses .cloop/state.db so chaos runs travel with
// the rest of project history; the table itself is provisioned by migration
// 0004_chaos_runs.sql.
//
// Closes any opened resources on failure so callers don't have to reach for
// a deferred Close on the error path.
func OpenStore(dbPath string) (*Store, error) {
	if dbPath == "" {
		return nil, errors.New("chaos: empty db path")
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(2000)&_pragma=journal_mode(WAL)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("chaos: open store %s: %w", dbPath, err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("chaos: ping store %s: %w", dbPath, err)
	}
	// Idempotent table creation; migration 0004 covers the "fresh project"
	// path but creating here keeps unit tests using a bare sqlite file
	// self-sufficient and makes the package usable without statedb.
	if _, err := db.Exec(chaosRunsDDL); err != nil {
		db.Close()
		return nil, fmt.Errorf("chaos: provision chaos_runs: %w", err)
	}
	return &Store{db: db, dbPath: dbPath}, nil
}

// Close releases the underlying connection. Idempotent.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// chaosRunsDDL mirrors the migration body so callers can OpenStore against
// arbitrary sqlite files (e.g. an isolated test DB) without depending on the
// migration framework.
const chaosRunsDDL = `
CREATE TABLE IF NOT EXISTS chaos_runs (
	id                  INTEGER PRIMARY KEY AUTOINCREMENT,
	fault_type          TEXT    NOT NULL DEFAULT '',
	probability         REAL    NOT NULL DEFAULT 1.0,
	started_at          TEXT    NOT NULL DEFAULT '',
	stopped_at          TEXT    NOT NULL DEFAULT '',
	duration_ms         INTEGER NOT NULL DEFAULT 0,
	outcome             TEXT    NOT NULL DEFAULT 'unknown',
	outcome_detail      TEXT    NOT NULL DEFAULT '',
	observed_errors     INTEGER NOT NULL DEFAULT 0,
	observed_retries    INTEGER NOT NULL DEFAULT 0,
	observed_recoveries INTEGER NOT NULL DEFAULT 0,
	note                TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS chaos_runs_started_at ON chaos_runs(started_at);
CREATE INDEX IF NOT EXISTS chaos_runs_fault_type ON chaos_runs(fault_type);
`

// Insert appends a new row and returns the assigned ID. Use Update later to
// stamp the outcome once the fault window closes.
func (s *Store) Insert(r Run) (int64, error) {
	if r.StartedAt.IsZero() {
		r.StartedAt = time.Now()
	}
	if r.Outcome == "" {
		r.Outcome = OutcomeUnknown
	}
	res, err := s.db.Exec(
		`INSERT INTO chaos_runs(
			fault_type, probability, started_at, stopped_at, duration_ms,
			outcome, outcome_detail, observed_errors, observed_retries,
			observed_recoveries, note
		) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		string(r.FaultType),
		r.Probability,
		r.StartedAt.UTC().Format(time.RFC3339Nano),
		nullableTime(r.StoppedAt),
		r.DurationMS,
		string(r.Outcome),
		r.OutcomeDetail,
		r.ObservedErrors,
		r.ObservedRetries,
		r.ObservedRecoveries,
		r.Note,
	)
	if err != nil {
		return 0, fmt.Errorf("chaos: insert run: %w", err)
	}
	return res.LastInsertId()
}

// Update finalises a run by writing the stopped_at, duration, and outcome
// fields. Other columns are left untouched so concurrent observers can keep
// incrementing the counters without racing the finaliser.
func (s *Store) Update(r Run) error {
	if r.ID == 0 {
		return errors.New("chaos: update run: zero id")
	}
	_, err := s.db.Exec(
		`UPDATE chaos_runs SET
			stopped_at = ?, duration_ms = ?, outcome = ?,
			outcome_detail = ?, observed_errors = ?, observed_retries = ?,
			observed_recoveries = ?, note = ?
		 WHERE id = ?`,
		nullableTime(r.StoppedAt),
		r.DurationMS,
		string(r.Outcome),
		r.OutcomeDetail,
		r.ObservedErrors,
		r.ObservedRetries,
		r.ObservedRecoveries,
		r.Note,
		r.ID,
	)
	if err != nil {
		return fmt.Errorf("chaos: update run %d: %w", r.ID, err)
	}
	return nil
}

// List returns up to limit rows starting at offset, newest first. Pass 0/0
// for "all rows".
func (s *Store) List(offset, limit int) ([]Run, error) {
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.Query(
		`SELECT id, fault_type, probability, started_at, stopped_at,
			duration_ms, outcome, outcome_detail, observed_errors,
			observed_retries, observed_recoveries, note
		 FROM chaos_runs
		 ORDER BY id DESC
		 LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("chaos: list: %w", err)
	}
	defer rows.Close()

	var out []Run
	for rows.Next() {
		var r Run
		var ftype, outcome, started, stopped string
		if err := rows.Scan(
			&r.ID, &ftype, &r.Probability,
			&started, &stopped, &r.DurationMS,
			&outcome, &r.OutcomeDetail,
			&r.ObservedErrors, &r.ObservedRetries, &r.ObservedRecoveries,
			&r.Note,
		); err != nil {
			return nil, fmt.Errorf("chaos: scan: %w", err)
		}
		r.FaultType = FaultType(ftype)
		r.Outcome = Outcome(outcome)
		if t, perr := time.Parse(time.RFC3339Nano, started); perr == nil {
			r.StartedAt = t
		}
		if stopped != "" {
			if t, perr := time.Parse(time.RFC3339Nano, stopped); perr == nil {
				r.StoppedAt = t
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
