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
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	StartVersion    int   // version recorded before this run (0 = brand new DB)
	EndVersion      int   // highest version applied (or already present)
	Applied         []int // versions newly applied during this run
	BaselineApplied bool  // true when an existing pre-framework DB was adopted at v1

	// Divergent names a version this database recorded under a different
	// migration file than this binary embeds. See checkNames.
	Divergent []VersionDivergence
}

// VersionDivergence is one version whose recorded name is not the name this
// binary embeds for it.
type VersionDivergence struct {
	Version  int
	Recorded string
	Embedded string
}

// MigrateOptions configures MigrateWithOptions.
type MigrateOptions struct {
	// Target stops after the migration numbered Target. Zero means
	// LatestVersion — every embedded migration.
	Target int

	// AllowSchemaDowngrade suppresses the refusal to open a database whose
	// schema is ahead of this binary's. See schema_guard.go; the operator-
	// facing spelling is the CLOOP_ALLOW_SCHEMA_DOWNGRADE environment
	// variable, which Migrate and MigrateTo read on the caller's behalf.
	AllowSchemaDowngrade bool
}

// Migrate brings db up to the latest embedded schema version. Safe to call
// repeatedly: a fully migrated database is a no-op. Each pending migration
// runs inside a transaction together with the schema_migrations row insert,
// so an interrupted run leaves the database at the previous version.
//
// Errors are wrapped with ErrSchemaMismatch so callers can use errors.Is to
// distinguish migration failures from generic SQLite errors. A database ahead
// of this binary additionally carries ErrSchemaTooNew.
func Migrate(db *sql.DB) (*MigrationReport, error) {
	return MigrateTo(db, LatestVersion)
}

// LatestVersion is the sentinel MigrateTo accepts to mean "every embedded
// migration". Any real schema version is far below it.
const LatestVersion = 1 << 30

// MigrateTo is Migrate, stopping after the migration numbered target. It exists
// so that a test can construct the schema some earlier release actually shipped
// and then let Open() migrate it forward, which is the only way to exercise a
// migration against the database it will really meet.
//
// The alternative — migrate fully, then hand-undo one migration's DDL and
// delete its schema_migrations row — does not work, and the way it fails is
// worth recording. currentVersion is MAX(version), so forgetting migration N
// forgets everything after it too, and they all re-run. That is harmless while
// every later migration is CREATE ... IF NOT EXISTS, and stops being harmless
// the moment one of them is an ALTER TABLE ADD COLUMN, which SQLite has no
// idempotent spelling for. It then fails with "duplicate column name" inside
// whichever unrelated test did the rewinding.
//
// Note that target bounds how far *forward* this call migrates and has no
// bearing on the version-skew refusal, which always compares the database
// against the highest migration the binary embeds.
func MigrateTo(db *sql.DB, target int) (*MigrationReport, error) {
	return MigrateWithOptions(db, MigrateOptions{
		Target:               target,
		AllowSchemaDowngrade: AllowSchemaDowngradeFromEnv(),
	})
}

// MigrateWithOptions is Migrate with the opt-out under the caller's control
// rather than the environment's. `cloop hub doctor` uses it to inspect a
// database the hub itself would refuse — diagnosing a skew is the one job that
// must still work when the skew is present.
func MigrateWithOptions(db *sql.DB, opts MigrateOptions) (*MigrationReport, error) {
	target := opts.Target
	if target <= 0 {
		target = LatestVersion
	}

	migrations, err := loadMigrations()
	if err != nil {
		return nil, wrap(ErrSchemaMismatch, err)
	}
	latest := migrations[len(migrations)-1].Version

	if err := ensureMigrationsTable(db); err != nil {
		return nil, wrap(ErrSchemaMismatch, err)
	}

	current, err := currentVersion(db)
	if err != nil {
		return nil, wrap(ErrSchemaMismatch, err)
	}

	// The direction the loop below cannot see. Checked before anything is
	// written, so a refusal leaves the database untouched — including the
	// provenance column added immediately after.
	if err := checkNotFromFuture(db, current, latest, opts.AllowSchemaDowngrade); err != nil {
		return nil, err
	}

	if err := ensureMigrationsProvenance(db); err != nil {
		return nil, wrap(ErrSchemaMismatch, err)
	}

	// Classify what is already recorded, so a database migrated by a build that
	// predates this mechanism still gives a future older binary something to
	// reason about. Fatal like the schema_migrations maintenance above it: this
	// runs after the skew check, so anything failing here is the bookkeeping
	// table itself being unwritable, which the next statement would hit anyway.
	if err := backfillCompat(db, migrations); err != nil {
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
			if err := recordVersion(db, 1, "baseline (pre-framework adoption)", classifyMigration(migrations[0].SQL)); err != nil {
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
		if m.Version > target {
			break
		}
		if err := applyOne(db, m); err != nil {
			return report, wrap(ErrSchemaMismatch, fmt.Errorf("apply migration %s: %w", m.Name, err))
		}
		report.Applied = append(report.Applied, m.Version)
		current = m.Version
	}
	report.EndVersion = current

	// Asked after applying, because the answer is only interesting for versions
	// that were already there — a migration this run applied recorded its own
	// name a moment ago.
	div, err := checkNames(db, migrations)
	if err != nil {
		// Not fatal: this is diagnosis, and a database that will not answer a
		// SELECT on its own bookkeeping table has a bigger problem that the
		// next statement will surface with a better message.
		return report, nil
	}
	report.Divergent = div
	for _, d := range div {
		if divergenceAlreadyWarned(d) {
			continue
		}
		fmt.Fprintf(os.Stderr,
			"warning: schema version %d was applied from %q, but this build embeds %q for that "+
				"version — so %q has been SKIPPED and its effects are absent from this database. "+
				"Two migrations were numbered the same; renumber the later one and re-apply it by "+
				"hand.\n", d.Version, d.Recorded, d.Embedded, d.Embedded)
	}
	return report, nil
}

// divergenceWarned records which divergences this process has already
// reported, so repeated Opens do not repeat the warning.
//
// A single command opens statedb more than once — the control plane and the
// project store are separate handles over the same file — and an unconditional
// Fprintf makes one genuine problem look like several. The report returned to
// the caller is unaffected: this suppresses the duplicate console line, not the
// finding. Same reason and same shape as warnIfConfigTooOpen in pkg/config.
var (
	divergenceWarnedMu sync.Mutex
	divergenceWarned   = map[string]struct{}{}
)

// divergenceAlreadyWarned reports whether d has been printed, recording it if
// not. Keyed by all three fields rather than the version alone: a database that
// diverges at one version and is then repaired to diverge differently is a new
// finding, not the one already shown.
func divergenceAlreadyWarned(d VersionDivergence) bool {
	key := fmt.Sprintf("%d\x00%s\x00%s", d.Version, d.Recorded, d.Embedded)
	divergenceWarnedMu.Lock()
	defer divergenceWarnedMu.Unlock()
	if _, ok := divergenceWarned[key]; ok {
		return true
	}
	divergenceWarned[key] = struct{}{}
	return false
}

// checkNames reports versions whose recorded migration name is not the one this
// binary embeds.
//
// # Why this is worth a check at all
//
// The apply loop skips any migration whose version is already recorded, and it
// compares nothing else. That is correct for the case it was written for — a
// database that is simply up to date — and silently wrong for the one this
// function exists to name: two different migration files numbered the same.
//
// It happens whenever two changes are developed in parallel, because the next
// free number is obvious and the same for both, and the sequence check that
// enforces contiguity only sees one tree at a time. Whichever file lands second
// is then, against any database the first one already touched, applied never
// and reported nowhere. The column it was supposed to add does not exist, the
// code that selects it fails at runtime, and the schema version says the
// database is current.
//
// # Why it warns rather than refuses
//
// Refusing would be the stronger guarantee and the wrong trade. A hub whose
// control plane carries an overtaken version number is a *deployment* that
// works — the overtaken migration's effects are missing, not corrupt — and
// turning that into a refusal to open the database converts a fixable
// divergence into an outage for every tenant on it. The warning names both
// files and the remedy, which is what an operator needs and what nothing
// previously said.
func checkNames(db *sql.DB, migrations []migration) ([]VersionDivergence, error) {
	rows, err := db.Query(`SELECT version, name FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	embedded := make(map[int]string, len(migrations))
	for _, m := range migrations {
		embedded[m.Version] = m.Name
	}

	var out []VersionDivergence
	for rows.Next() {
		var (
			version int
			name    string
		)
		if err := rows.Scan(&version, &name); err != nil {
			return nil, err
		}
		want, ok := embedded[version]
		// A name this binary has no migration for is a database from a newer
		// build, which the skew guard has already decided about; and the v1
		// baseline row is recorded under a name no file has.
		if !ok || name == "" || name == want {
			continue
		}
		if version == 1 && strings.HasPrefix(name, "baseline") {
			continue
		}
		out = append(out, VersionDivergence{Version: version, Recorded: name, Embedded: want})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// ensureMigrationsTable creates the schema_migrations bookkeeping table.
// Idempotent.
//
// This table is the framework's own bookkeeping, so it is maintained here in Go
// rather than by a migration file: a migration cannot be recorded until the
// table that records it exists, and resolving that circularity in SQL is worse
// than the two idempotent statements it saves.
func ensureMigrationsTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version     INTEGER PRIMARY KEY,
			applied_at  TEXT    NOT NULL,
			name        TEXT    NOT NULL DEFAULT '',
			applied_by  TEXT    NOT NULL DEFAULT '',
			compat      TEXT    NOT NULL DEFAULT ''
		)`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	return nil
}

// ensureMigrationsProvenance adds applied_by and compat to a schema_migrations
// table created before those columns existed.
//
// Rows already there keep an empty applied_by, which reads as "an unidentified
// build" — accurate, since nothing recorded it. Guarded by a column check
// because SQLite has no ADD COLUMN IF NOT EXISTS and the alternative is
// swallowing a "duplicate column name" error, which would also swallow real
// ones.
//
// These columns are maintained here rather than by a numbered migration for the
// same reason the table itself is: they describe the migration bookkeeping, and
// a migration cannot depend on the bookkeeping it is about to be recorded in.
func ensureMigrationsProvenance(db *sql.DB) error {
	for _, col := range []string{"applied_by", "compat"} {
		has, err := hasColumn(db, "schema_migrations", col)
		if err != nil {
			return err
		}
		if has {
			continue
		}
		if _, err := db.Exec(
			`ALTER TABLE schema_migrations ADD COLUMN ` + col + ` TEXT NOT NULL DEFAULT ''`,
		); err != nil {
			return fmt.Errorf("add schema_migrations.%s: %w", col, err)
		}
	}
	return nil
}

// backfillCompat classifies already-recorded migrations that this binary also
// embeds but that were applied before compat was recorded.
//
// Without it the mechanism would only ever help databases migrated by a build
// that already had this code, which on any existing deployment means "no
// database for as long as the schema does not move". A binary that embeds
// migration N holds its SQL and can classify it exactly as the build that
// applied it would have, so the verdict is reconstructed rather than guessed.
//
// Only empty values are written. A recorded verdict is never revised: two
// builds must not disagree about a migration, and if they somehow do, the
// stricter reading is the one already in the database.
func backfillCompat(db *sql.DB, migrations []migration) error {
	rows, err := db.Query(`SELECT version FROM schema_migrations WHERE compat = ''`)
	if err != nil {
		return fmt.Errorf("read unclassified migrations: %w", err)
	}
	defer rows.Close()

	pending := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return fmt.Errorf("scan unclassified migration: %w", err)
		}
		pending[v] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read unclassified migrations: %w", err)
	}

	for _, m := range migrations {
		if !pending[m.Version] {
			continue
		}
		if _, err := db.Exec(
			`UPDATE schema_migrations SET compat = ? WHERE version = ? AND compat = ''`,
			string(classifyMigration(m.SQL)), m.Version,
		); err != nil {
			return fmt.Errorf("classify migration %d: %w", m.Version, err)
		}
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
//
// applied_by is this build's identifier, which is what lets a later binary's
// refusal name the build that moved the schema past it rather than only the
// version number it landed on. compat is this build's reading of whether the
// migration is tolerable to binaries older than itself — see schema_compat.go.
func recordVersion(db *sql.DB, version int, name string, compat MigrationCompat) error {
	_, err := db.Exec(
		`INSERT INTO schema_migrations(version, applied_at, name, applied_by, compat) VALUES (?, ?, ?, ?, ?)`,
		version, time.Now().UTC().Format(time.RFC3339Nano), name, binaryVersion(), string(compat),
	)
	if err != nil {
		// A concurrent process may have recorded the same baseline version
		// first (two first-opens racing); that's success, not failure.
		if isUniqueConstraintErr(err) {
			return nil
		}
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

	// Concurrent first-open protection: another process may have applied this
	// migration between our currentVersion read and this transaction. Check
	// inside the tx and treat "already recorded" as success (the deferred
	// rollback discards our no-op transaction).
	var one int
	checkErr := tx.QueryRow(`SELECT 1 FROM schema_migrations WHERE version = ?`, m.Version).Scan(&one)
	if checkErr == nil {
		return nil
	}
	if !errors.Is(checkErr, sql.ErrNoRows) {
		return fmt.Errorf("check schema_migrations: %w", checkErr)
	}

	stmts := splitStatements(m.SQL)
	for i, stmt := range stmts {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("statement %d: %w\n--- SQL ---\n%s", i+1, err, stmt)
		}
	}

	if _, err := tx.Exec(
		`INSERT INTO schema_migrations(version, applied_at, name, applied_by, compat) VALUES (?, ?, ?, ?, ?)`,
		m.Version, time.Now().UTC().Format(time.RFC3339Nano), m.Name, binaryVersion(),
		string(classifyMigration(m.SQL)),
	); err != nil {
		// A unique-constraint failure means a concurrent process won the race
		// and recorded this version first — already applied, not an error.
		if isUniqueConstraintErr(err) {
			return nil
		}
		return fmt.Errorf("record schema_migrations: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// isUniqueConstraintErr reports whether err is a SQLite unique/primary-key
// constraint violation. String matching is unavoidable — modernc.org/sqlite
// does not expose stable error-code constants (see classifyDriverErr).
func isUniqueConstraintErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "unique constraint")
}

// splitStatements splits a SQL script on `;` boundaries while respecting
// '...'-quoted strings and "..."-quoted identifiers, and stripping `--`
// line comments. It also drops empty statements (consecutive semicolons,
// or a trailing semicolon at EOF). This is sufficient for the migration
// dialect we use (no triggers, no BEGIN/END blocks); revisit if those are
// ever introduced.
func splitStatements(sql string) []string {
	var (
		out      []string
		current  strings.Builder
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

// LatestSchemaVersion returns the highest migration version this *binary*
// carries, which is what a database will be at once Migrate has run.
//
// It exists so a diagnostic can compare the two numbers. On its own,
// CurrentSchemaVersion answers "what has been applied" and cannot distinguish a
// fully-migrated database from one an older binary left behind — and the second
// is the interesting case, because a hub rolled back to a previous image runs
// against a schema from the future and fails on whichever column it does not
// know about.
func LatestSchemaVersion() (int, error) {
	migrations, err := loadMigrations()
	if err != nil {
		return 0, err
	}
	// loadMigrations returns them sorted by version, and errors rather than
	// returning an empty slice.
	return migrations[len(migrations)-1].Version, nil
}
