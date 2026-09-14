package statedb

// Version-skew guard for the migration framework (Task 20226).
//
// migrate.go answers "which migrations are still pending" by skipping every
// embedded migration at or below the version already recorded. That question
// only has a safe answer in one direction. A database migrated to v30 by a new
// hub, then opened by an older binary that embeds through v29, has nothing
// pending — so the loop applies nothing, Migrate returns a successful report,
// and the old code proceeds to read and write tables whose shape it does not
// know. The failure surfaces later, as a "no such column" from whichever
// handler happened to touch the new schema first, or as silent data loss when
// an INSERT omits a column the newer binary requires.
//
// Rolling a binary back is a realistic operator action — docs/operations/
// runbook.md documents the procedure, and asserted this refusal as fact long
// before anything enforced it — so the skew is worth detecting at the one
// moment the process can still decline cleanly: before Open returns a handle.
//
// Three pieces make the refusal useful rather than merely correct:
//
//	It names both versions and the build that moved the schema. "Schema
//	mismatch" sends an operator to the wrong place; "this database is at 30,
//	this binary carries 29, and cloop v0.4.0 applied 30 an hour ago" names the
//	image to roll forward to.
//
//	It is a distinct sentinel. ErrSchemaMismatch also covers corruption and
//	partial migrations, which need different handling — this one is fixed by
//	changing which binary is running, not by touching the database.
//
//	It has an opt-out. Not every version bump changes a table an older binary
//	reads, and an operator who has checked the diff should not be forced to
//	restore a backup to get back to a known-good build. CLOOP_ALLOW_SCHEMA_
//	DOWNGRADE=1 says "I have checked"; `cloop hub doctor` then reports that the
//	guard is off, so the exemption cannot be forgotten in place.
//
// That opt-out was, for a while, the only relief — and being manual, it was no
// relief at all on a deployment whose "operator" is a nightly timer. Task 20254
// made the common case answer itself: schema_compat.go has the applying binary
// record whether each migration is tolerable to older builds, and the check
// below reads those verdicts instead of comparing version numbers alone. A
// database that only gained new tables is no longer refused; everything else,
// including anything unclassified, is refused exactly as before.

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// EnvAllowSchemaDowngrade names the operator opt-out. Set it to 1/true/yes/on
// to open a database whose schema is ahead of this binary's.
//
// An environment variable rather than a config key on purpose: the check runs
// inside statedb.Open, which is reached from CLI commands, the orchestrator and
// the hub alike, several of them before any config file has been read. A knob
// that cannot be set in every context where the guard fires is not an opt-out.
const EnvAllowSchemaDowngrade = "CLOOP_ALLOW_SCHEMA_DOWNGRADE"

// AllowSchemaDowngradeFromEnv reports whether the operator opt-out is set.
//
// Exported so `cloop hub doctor` can tell an operator the guard is disabled.
// A safety check that can be switched off silently gets switched off and left
// that way, so the off state is itself a finding.
func AllowSchemaDowngradeFromEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvAllowSchemaDowngrade))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// binaryVersionV holds the build identifier stamped into schema_migrations.
// atomic because Open — and therefore Migrate — is called concurrently from
// several goroutines in the hub, while SetBinaryVersion is called once at
// process start.
var binaryVersionV atomic.Value // string

// SetBinaryVersion records which build this process is, for stamping into
// schema_migrations when it applies a migration. Call it once during process
// initialisation; cmd does so with the ldflags-injected version.
//
// It lives here rather than being read from pkg/cmd because pkg/statedb sits
// below the CLI in the import graph and must not depend on it.
func SetBinaryVersion(v string) { binaryVersionV.Store(strings.TrimSpace(v)) }

// binaryVersion returns what SetBinaryVersion recorded, or "" when nothing did
// (tests, and any embedder that never called it). Empty is rendered as "an
// unidentified build" rather than guessed at.
func binaryVersion() string {
	s, _ := binaryVersionV.Load().(string)
	return s
}

// SchemaStamp is one schema_migrations row: which version was applied, when,
// and by which build.
//
// AppliedBy is "" for rows written before this provenance existed, and for
// rows written by a process that never called SetBinaryVersion. Absence is not
// an error — it just means the refusal message cannot name a build.
type SchemaStamp struct {
	Version   int       `json:"version"`
	Name      string    `json:"name,omitempty"`
	AppliedAt time.Time `json:"applied_at,omitempty"`
	AppliedBy string    `json:"applied_by,omitempty"`
	// Compat is the applying build's reading of whether this migration is
	// tolerable to older binaries. Empty for rows written before that was
	// recorded, which reads as "not known to be safe".
	Compat MigrationCompat `json:"compat,omitempty"`
}

// SchemaTooNewError is the detail behind ErrSchemaTooNew: the two versions that
// disagree, plus whatever the database records about the build that moved it
// forward.
//
// It satisfies errors.Is for both ErrSchemaTooNew and ErrSchemaMismatch. The
// second is deliberate: every existing caller that already treats a schema
// mismatch as fatal (HTTPStatus maps it to 500, classifyDriverErr declines to
// re-wrap it) keeps working unchanged, while callers that care about this
// specific cause can ask for it by name.
type SchemaTooNewError struct {
	// DBVersion is the highest version recorded in schema_migrations.
	DBVersion int
	// BinaryVersion is the highest migration embedded in this binary.
	BinaryVersion int
	// Stamp describes the schema_migrations row for DBVersion, when one could
	// be read. A zero Stamp means the row was unreadable, not that it is
	// absent — either way the message simply omits the provenance.
	Stamp SchemaStamp
	// Blocking lists the migrations ahead of this binary that it cannot
	// tolerate: the ones recorded as breaking, plus any it could not classify.
	// Migrations recorded as additive are absent, because they did not
	// contribute to the refusal.
	Blocking []SchemaStamp
}

func (e *SchemaTooNewError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: database is at schema version %d but this binary carries %d",
		ErrSchemaTooNew.Error(), e.DBVersion, e.BinaryVersion)
	if p := e.provenance(); p != "" {
		b.WriteString(" (" + p + ")")
	}
	b.WriteString("; this build does not know the tables and columns the newer one added, " +
		"so opening the database would corrupt it or fail later with a confusing SQL error.")
	if blocked := e.blockers(); blocked != "" {
		b.WriteString(" Incompatible: " + blocked + ".")
	}
	b.WriteString(" Roll forward to the newer cloop, or restore a backup taken before the upgrade " +
		"(see `cloop db restore`). If the schemas are known-compatible, set " +
		EnvAllowSchemaDowngrade + "=1 to open it anyway.")
	return b.String()
}

// blockers names the migrations that actually caused the refusal, so an
// operator looking at a 12-version gap is not left to diff all twelve.
func (e *SchemaTooNewError) blockers() string {
	var parts []string
	for _, s := range e.Blocking {
		switch {
		case s.Name != "" && s.Compat == CompatBreaking:
			parts = append(parts, s.Name)
		case s.Name != "":
			parts = append(parts, s.Name+" (unclassified)")
		default:
			parts = append(parts, fmt.Sprintf("v%d (unrecorded)", s.Version))
		}
	}
	return strings.Join(parts, ", ")
}

// provenance renders the "applied by …" clause, or "" when the database
// records nothing useful about who moved it forward.
func (e *SchemaTooNewError) provenance() string {
	var parts []string
	switch {
	case e.Stamp.AppliedBy != "":
		parts = append(parts, "applied by cloop "+e.Stamp.AppliedBy)
	case e.Stamp.Name != "" || !e.Stamp.AppliedAt.IsZero():
		parts = append(parts, "applied by an unidentified build")
	}
	if e.Stamp.Name != "" {
		parts = append(parts, "as "+e.Stamp.Name)
	}
	if !e.Stamp.AppliedAt.IsZero() {
		parts = append(parts, "at "+e.Stamp.AppliedAt.UTC().Format(time.RFC3339))
	}
	return strings.Join(parts, " ")
}

// Is makes both sentinels match. See the type comment for why ErrSchemaMismatch
// is included.
func (e *SchemaTooNewError) Is(target error) bool {
	return target == ErrSchemaTooNew || target == ErrSchemaMismatch
}

// checkNotFromFuture refuses a database migrated past this binary's highest
// embedded migration.
//
// Called after currentVersion and before any migration is applied, so a
// refusing process leaves the database exactly as it found it. It deliberately
// runs before the provenance column is added: writing to a database we are
// about to declare unreadable would undercut the guarantee the refusal makes.
func checkNotFromFuture(db *sql.DB, current, latest int, allow bool) error {
	if current <= latest || allow {
		return nil
	}

	// Ahead — but not necessarily in a way that matters. Ask what the missing
	// migrations actually did before refusing. See schema_compat.go; anything
	// unrecorded or unrecognised reads as breaking, so this can only relax the
	// refusal for migrations a build positively classified as additive.
	blocking, cErr := breakingVersionsAhead(db, latest, current)
	if cErr == nil && len(blocking) == 0 {
		return nil
	}

	err := &SchemaTooNewError{DBVersion: current, BinaryVersion: latest, Blocking: blocking}
	// Best-effort: a database we cannot introspect still gets refused, just
	// without the provenance clause.
	if stamp, sErr := readSchemaStamp(db, current); sErr == nil {
		err.Stamp = stamp
	}
	return err
}

// breakingVersionsAhead returns the versions in (latest, current] that this
// binary cannot tolerate, in ascending order.
//
// A version with no row of its own is reported as blocking: currentVersion is
// a MAX, so a gap means the database knows something happened that it cannot
// describe, and that is not a basis for relaxing a safety check.
func breakingVersionsAhead(db *sql.DB, latest, current int) ([]SchemaStamp, error) {
	has, err := hasColumn(db, "schema_migrations", "compat")
	if err != nil {
		return nil, err
	}
	if !has {
		// Written by a build with no notion of compatibility. Everything ahead
		// is unknown, therefore everything ahead blocks.
		return unknownRange(latest, current), nil
	}

	rows, err := db.Query(
		`SELECT version, name, compat FROM schema_migrations
		  WHERE version > ? AND version <= ? ORDER BY version`, latest, current)
	if err != nil {
		return nil, fmt.Errorf("read migration compatibility: %w", err)
	}
	defer rows.Close()

	seen := make(map[int]bool)
	var blocking []SchemaStamp
	for rows.Next() {
		var (
			st     SchemaStamp
			compat string
		)
		if err := rows.Scan(&st.Version, &st.Name, &compat); err != nil {
			return nil, fmt.Errorf("scan migration compatibility: %w", err)
		}
		seen[st.Version] = true
		st.Compat = MigrationCompat(compat)
		if !st.Compat.Tolerable() {
			blocking = append(blocking, st)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read migration compatibility: %w", err)
	}

	// Any version in the range without a row at all.
	for v := latest + 1; v <= current; v++ {
		if !seen[v] {
			blocking = append(blocking, SchemaStamp{Version: v})
		}
	}
	sort.Slice(blocking, func(i, j int) bool { return blocking[i].Version < blocking[j].Version })
	return blocking, nil
}

// unknownRange describes every version in (latest, current] as unclassified.
func unknownRange(latest, current int) []SchemaStamp {
	var out []SchemaStamp
	for v := latest + 1; v <= current; v++ {
		out = append(out, SchemaStamp{Version: v})
	}
	return out
}

// readSchemaStamp returns the schema_migrations row for version.
//
// Tolerates the applied_by column being absent: the row may predate the
// provenance, or have been written by a binary too old to record it.
func readSchemaStamp(db *sql.DB, version int) (SchemaStamp, error) {
	cols := "name, applied_at, ''"
	if has, err := hasColumn(db, "schema_migrations", "applied_by"); err != nil {
		return SchemaStamp{}, err
	} else if has {
		cols = "name, applied_at, applied_by"
	}

	out := SchemaStamp{Version: version}
	var appliedAt string
	err := db.QueryRow(
		`SELECT `+cols+` FROM schema_migrations WHERE version = ?`, version,
	).Scan(&out.Name, &appliedAt, &out.AppliedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return SchemaStamp{}, fmt.Errorf("no schema_migrations row for version %d", version)
	}
	if err != nil {
		return SchemaStamp{}, fmt.Errorf("read schema_migrations row %d: %w", version, err)
	}
	out.AppliedAt = parseStampTime(appliedAt)
	return out, nil
}

// parseStampTime reads an applied_at value, returning the zero time when it is
// absent or in a shape we do not recognise.
//
// Rows this package writes are RFC3339Nano. The lenient fallbacks cover rows
// written by hand or by an older tool — a timestamp we cannot parse must not
// cost the operator the rest of the refusal message.
func parseStampTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// hasColumn reports whether table has a column of that name.
func hasColumn(db *sql.DB, table, column string) (bool, error) {
	// table is a package constant at every call site, never user input, so
	// the interpolation below cannot be influenced from outside.
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, fmt.Errorf("inspect %s columns: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid        int
			name, typ  string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultVal, &pk); err != nil {
			return false, fmt.Errorf("scan %s columns: %w", table, err)
		}
		if strings.EqualFold(name, column) {
			return true, rows.Err()
		}
	}
	return false, rows.Err()
}

// SchemaStamp returns provenance for the highest version recorded in this
// database: which migration last moved the schema, when, and by which build.
//
// Returns a zero SchemaStamp and no error when the database has no recorded
// migrations at all — a brand-new file, which is not a fault.
func (d *DB) SchemaStamp() (SchemaStamp, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	v, err := currentVersion(d.conn)
	if err != nil {
		return SchemaStamp{}, err
	}
	if v == 0 {
		return SchemaStamp{}, nil
	}
	return readSchemaStamp(d.conn, v)
}
