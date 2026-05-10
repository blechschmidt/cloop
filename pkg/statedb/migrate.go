// Schema migration framework for statedb.
//
// Replaces the prior "execute the entire CREATE TABLE IF NOT EXISTS blob on
// every Open" approach with versioned, append-only .sql files embedded into
// the binary. Each migration runs inside its own transaction and records
// itself in schema_migrations on success; a crash mid-migration rolls back
// cleanly so the next Open re-attempts from the failed version.
//
// Lifecycle:
//
//	Open() ──► applyPragmas() ──► Migrate() ──► return *DB
//
// Adding a new migration:
//
//  1. Create pkg/statedb/migrations/NNNN_<slug>.sql where NNNN is the next
//     unused 4-digit version (e.g. 0002_add_pinned.sql).
//  2. Write idempotent-friendly DDL. Single-statement migrations are safest
//     because the modernc.org/sqlite driver does not natively support
//     executing multiple statements with the binding parameter API; the
//     migration runner therefore splits on `;` boundaries before exec.
//  3. NEVER edit a shipped migration file. Roll forward with another file.
//
// Existing databases (pre-framework) are detected at boot: if all the 0001
// tables already exist but schema_migrations is empty, version 1 is recorded
// as the baseline rather than re-applied. This makes the rollout safe for
// databases written by older binaries.
package statedb

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// migration represents a single .sql file embedded into the binary.
type migration struct {
	Version int    // numeric prefix, e.g. 1 for 0001_init.sql
	Name    string // raw filename, used in error messages and the report
	SQL     string // file contents, executed inside a transaction
}

// loadMigrations parses every embedded migration file and returns them
// sorted by version ascending. Returned errors indicate a packaging bug
// (malformed filename, duplicate version) and should fail the build during
// tests, never at runtime.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("statedb: read embedded migrations: %w", err)
	}
	var out []migration
	seen := make(map[int]string)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		v, err := parseVersion(e.Name())
		if err != nil {
			return nil, fmt.Errorf("statedb: migration %q: %w", e.Name(), err)
		}
		if prev, ok := seen[v]; ok {
			return nil, fmt.Errorf("statedb: duplicate migration version %d (%s and %s)", v, prev, e.Name())
		}
		seen[v] = e.Name()
		body, err := fs.ReadFile(migrationFS, "migrations/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("statedb: read migration %s: %w", e.Name(), err)
		}
		out = append(out, migration{Version: v, Name: e.Name(), SQL: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	if len(out) == 0 {
		return nil, fmt.Errorf("statedb: no migrations embedded — build is missing migrations/*.sql")
	}
	// Versions must form a dense, gap-free sequence starting at 1. A gap
	// almost certainly means a developer forgot to commit a file or chose
	// a non-monotonic version number.
	for i, m := range out {
		want := i + 1
		if m.Version != want {
			return nil, fmt.Errorf("statedb: migration sequence broken at index %d: expected version %d, got %d (%s)", i, want, m.Version, m.Name)
		}
	}
	return out, nil
}

// parseVersion extracts the leading numeric prefix from a migration filename.
// Accepts "0001_init.sql", "12_foo.sql", etc. The underscore is required.
func parseVersion(name string) (int, error) {
	base := strings.TrimSuffix(name, ".sql")
	idx := strings.IndexRune(base, '_')
	if idx <= 0 {
		return 0, fmt.Errorf("expected NNNN_<slug>.sql, got %q", name)
	}
	v, err := strconv.Atoi(base[:idx])
	if err != nil {
		return 0, fmt.Errorf("non-numeric version prefix in %q: %w", name, err)
	}
	if v < 1 {
		return 0, fmt.Errorf("migration version must be >= 1, got %d in %q", v, name)
	}
	return v, nil
}

// MigrationReport summarises the outcome of a Migrate call.
type MigrationReport struct {
	StartVersion   int      // version recorded before this run (0 = brand new DB)
	EndVersion     int      // highest version applied (or already present)
	Applied        []int    // versions newly applied during this run
	BaselineApplied bool    // true when an existing pre-framework DB was adopted at v1
}

// Migrate brings db up to the latest embedded schema version. Safe to call
// repeatedly: a fully migrated database is a no-op. Each pending migration
// runs inside a transaction together with the schema_migrations row insert,
// so an interrupted run leaves the database at the previous version.
//
// Errors are wrapped with ErrSchemaMismatch so callers can use errors.Is to
// distinguish migration failures from generic SQLite errors.
func Migrate(db *sql.DB) (*MigrationReport, error) {
	migrations, err := loadMigrations()
	if err != nil {
		return nil, wrap(ErrSchemaMismatch, err)
	}

	if err := ensureMigrationsTable(db); err != nil {
		return nil, wrap(ErrSchemaMismatch, err)
	}

	current, err := currentVersion(db)
	if err != nil {
		return nil, wrap(ErrSchemaMismatch, err)
	}

	report := &MigrationReport{StartVersion: current}

	// Adopt pre-framework databases: when schema_migrations is empty but the
	// 0001 tables already exist, mark v1 as applied without re-running it.
	if current == 0 {
		baseline, err := detectBaseline(db)
		if err != nil {
			return nil, wrap(ErrSchemaMismatch, err)
		}
		if baseline {
			if err := recordVersion(db, 1, "baseline (pre-framework adoption)"); err != nil {
				return nil, wrap(ErrSchemaMismatch, err)
			}
			report.BaselineApplied = true
			current = 1
			report.StartVersion = 0
		}
	}

	for _, m := range migrations {
		if m.Version <= current {
			continue
		}
		if err := applyOne(db, m); err != nil {
			return report, wrap(ErrSchemaMismatch, fmt.Errorf("apply migration %s: %w", m.Name, err))
		}
		report.Applied = append(report.Applied, m.Version)
		current = m.Version
	}
	report.EndVersion = current
	return report, nil
}

// ensureMigrationsTable creates the schema_migrations bookkeeping table.
// Idempotent.
func ensureMigrationsTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TEXT    NOT NULL,
			name       TEXT    NOT NULL DEFAULT ''
		)`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	return nil
}

// currentVersion returns the highest version recorded in schema_migrations,
// or 0 if the table is empty.
func currentVersion(db *sql.DB) (int, error) {
	var v sql.NullInt64
	err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("read schema_migrations: %w", err)
	}
	if !v.Valid {
		return 0, nil
	}
	return int(v.Int64), nil
}

// detectBaseline returns true when the database was created by an older
// binary that ran the inline schema directly (so the user-facing tables
// exist but schema_migrations was just freshly created and is empty).
//
// Heuristic: if the metadata table exists, this is an existing cloop
// database — adopt it at version 1 rather than re-running 0001.
func detectBaseline(db *sql.DB) (bool, error) {
	var name string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='metadata' LIMIT 1`).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect sqlite_master: %w", err)
	}
	return name == "metadata", nil
}

// recordVersion inserts a row into schema_migrations. Used both by
// applyOne (within its tx) and by the baseline-adoption path.
func recordVersion(db *sql.DB, version int, name string) error {
	_, err := db.Exec(
		`INSERT INTO schema_migrations(version, applied_at, name) VALUES (?, ?, ?)`,
		version, time.Now().UTC().Format(time.RFC3339Nano), name,
	)
	if err != nil {
		return fmt.Errorf("record migration %d: %w", version, err)
	}
	return nil
}

// applyOne runs a single migration inside a transaction. The schema_migrations
// row is inserted in the same tx, so a failure rolls back both the schema
// changes and the version bookkeeping — the next run re-attempts cleanly.
//
// Migration files may contain multiple statements separated by `;`; we split
// and execute them sequentially because the modernc.org/sqlite driver's Exec
// only honours the first statement in a multi-statement string when prepared
// statements are involved. Splitting also gives clearer error messages
// (which statement failed).
func applyOne(db *sql.DB, m migration) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck — ignored if Commit succeeds

	stmts := splitStatements(m.SQL)
	for i, stmt := range stmts {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("statement %d: %w\n--- SQL ---\n%s", i+1, err, stmt)
		}
	}

	if _, err := tx.Exec(
		`INSERT INTO schema_migrations(version, applied_at, name) VALUES (?, ?, ?)`,
		m.Version, time.Now().UTC().Format(time.RFC3339Nano), m.Name,
	); err != nil {
		return fmt.Errorf("record schema_migrations: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// splitStatements splits a SQL script on `;` boundaries while respecting
// '...'-quoted strings and "..."-quoted identifiers, and stripping `--`
// line comments. It also drops empty statements (consecutive semicolons,
// or a trailing semicolon at EOF). This is sufficient for the migration
// dialect we use (no triggers, no BEGIN/END blocks); revisit if those are
// ever introduced.
func splitStatements(sql string) []string {
	var (
		out     []string
		current strings.Builder
		inSingle bool
		inDouble bool
	)
	flush := func() {
		s := strings.TrimSpace(current.String())
		if s != "" {
			out = append(out, s)
		}
		current.Reset()
	}
	// Strip line comments line-by-line first.
	var stripped strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		// Find -- outside of strings. Conservatively, since migrations don't
		// embed -- inside string literals, a simple scan is enough.
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		stripped.WriteString(line)
		stripped.WriteByte('\n')
	}
	src := stripped.String()
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			current.WriteByte(c)
		case c == '"' && !inSingle:
			inDouble = !inDouble
			current.WriteByte(c)
		case c == ';' && !inSingle && !inDouble:
			flush()
		default:
			current.WriteByte(c)
		}
	}
	flush()
	return out
}

// CurrentSchemaVersion returns the highest migration version recorded in
// the database. Useful for diagnostic commands (cloop db verify, cloop
// migrate status). Acquires the DB mutex like other read helpers in this
// package.
func (d *DB) CurrentSchemaVersion() (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return currentVersion(d.conn)
}
