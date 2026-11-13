package statedb

// Recovering a migration that a reused version number caused the apply loop to
// skip (Task 48).
//
// checkNames finds the problem and says so. What it then tells the operator to
// do — "renumber the later one and re-apply it by hand" — is advice for the
// developer who owns the tree, and it is unusable by the person actually
// holding the database: the losing number is already recorded, renaming it
// would overwrite the record of what really ran, and "by hand" means writing
// the skipped file's DDL out against a live control plane. On this deployment
// that was twenty-four databases carrying the same two skipped migrations,
// each of them a table the current binary expects and will not find.
//
// So a divergence is now repaired rather than only named. The apply loop
// cannot do it, because it is keyed on the version number and that number is
// taken; this is keyed on the migration's *name*, which is what a reused
// number makes ambiguous in the first place.
//
// # What makes it safe
//
//   - It only ever runs for a migration this database never applied. Nothing
//     that already ran is re-run.
//   - The whole file goes in one transaction, so a repair that cannot finish
//     leaves the database exactly as it was.
//   - A plain ALTER TABLE ... ADD COLUMN is executed through the idempotent
//     path in addcolumn.go, which adopts a column already present when it is
//     the column the migration declares and refuses when it is not. That is
//     the one statement likely to meet its own effects here: the sibling
//     migration that took the number is often a near-twin that added the same
//     column under a different file name.
//   - A repair that fails is not fatal. The database stays open and the
//     warning is printed, which is exactly the behaviour that existed before
//     this file — see the "Why it warns rather than refuses" note on
//     checkNames. Repair can only improve on that outcome, never worsen it.
//
// # What it records
//
// The recorded name in schema_migrations is left alone, because it is true:
// version 48 really was applied from 0048_egress_firewall_rules.sql on these
// databases. Rewriting it to the name this binary embeds would destroy the
// only evidence of what happened. The repair is recorded beside it instead, in
// schema_migration_repairs, keyed by the embedded file name — so the two facts
// ("this number was taken by that file" and "this file ran anyway") are both
// kept, and a repaired divergence stops warning because it is no longer a
// missing migration.

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"
)

// ensureRepairsTable creates the bookkeeping for recovered migrations.
// Idempotent.
//
// Maintained here in Go rather than by a numbered migration for the same
// reason schema_migrations itself is: it describes the migration bookkeeping,
// and the database that most needs it is by definition one whose numbering
// cannot be trusted to carry a new file.
func ensureRepairsTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migration_repairs (
			name        TEXT PRIMARY KEY,
			version     INTEGER NOT NULL,
			displaced   TEXT    NOT NULL DEFAULT '',
			repaired_at TEXT    NOT NULL DEFAULT '',
			repaired_by TEXT    NOT NULL DEFAULT ''
		)`)
	if err != nil {
		return fmt.Errorf("create schema_migration_repairs: %w", err)
	}
	return nil
}

// repairedMigrations returns the embedded file names already recovered here.
func repairedMigrations(db *sql.DB) (map[string]struct{}, error) {
	rows, err := db.Query(`SELECT name FROM schema_migration_repairs`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migration_repairs: %w", err)
	}
	defer rows.Close()

	out := map[string]struct{}{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan schema_migration_repairs: %w", err)
		}
		out[name] = struct{}{}
	}
	return out, rows.Err()
}

// recoverDivergent repairs what it can of div and returns the divergences that
// are still missing from the database, together with the ones this call
// recovered. A divergence recovered by an earlier call is in neither: it is
// not a finding any more.
//
// Errors are deliberately swallowed into the first return value. Every failure
// mode here — an unwritable bookkeeping table, a column whose shape does not
// match, a statement SQLite rejects — leaves the caller with the divergence it
// already had, which is the state this function was added to improve on and is
// never worse than it.
func recoverDivergent(db *sql.DB, migrations []migration, div []VersionDivergence) (remaining, recovered []VersionDivergence) {
	if len(div) == 0 {
		return nil, nil
	}
	if err := ensureRepairsTable(db); err != nil {
		return div, nil
	}
	done, err := repairedMigrations(db)
	if err != nil {
		return div, nil
	}

	byVersion := make(map[int]migration, len(migrations))
	for _, m := range migrations {
		byVersion[m.Version] = m
	}

	for _, d := range div {
		if _, ok := done[d.Embedded]; ok {
			continue // recovered by an earlier open; nothing is missing
		}
		m, ok := byVersion[d.Version]
		if !ok || m.Name != d.Embedded {
			// checkNames read d.Embedded out of this same slice, so this
			// cannot happen; if it somehow does, say so rather than repair
			// something the finding does not describe.
			remaining = append(remaining, d)
			continue
		}
		if err := recoverSkipped(db, m, d.Recorded); err != nil {
			reportRepairFailure(d, err)
			remaining = append(remaining, d)
			continue
		}
		recovered = append(recovered, d)
	}
	return remaining, recovered
}

// recoverSkipped applies m to a database that never ran it because another
// file had already recorded its version number, and records the repair.
//
// Mirrors applyOne — one transaction over the whole file, the same statement
// splitting, the same tolerance for a concurrent process winning the race —
// with two differences it cannot share: the guard is the repair row rather
// than the version row, and a plain ADD COLUMN is run through the idempotent
// path because the file name that took this number is frequently a sibling
// that added the same column.
func recoverSkipped(db *sql.DB, m migration, displaced string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // ignored if Commit succeeds

	var one int
	switch err := tx.QueryRow(
		`SELECT 1 FROM schema_migration_repairs WHERE name = ?`, m.Name).Scan(&one); {
	case err == nil:
		return nil // another process repaired it between the read and here
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("check schema_migration_repairs: %w", err)
	}

	for i, stmt := range splitStatements(m.SQL) {
		add, ok := parseAddColumnIfNotExists(stmt)
		if !ok {
			add, ok = parseAddColumn(stmt)
		}
		if ok {
			if err := add.apply(tx); err != nil {
				return fmt.Errorf("statement %d: %w\n--- SQL ---\n%s", i+1, err, stmt)
			}
			continue
		}
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("statement %d: %w\n--- SQL ---\n%s", i+1, err, stmt)
		}
	}

	if _, err := tx.Exec(
		`INSERT INTO schema_migration_repairs(name, version, displaced, repaired_at, repaired_by)
		 VALUES (?, ?, ?, ?, ?)`,
		m.Name, m.Version, displaced, time.Now().UTC().Format(time.RFC3339Nano), binaryVersion(),
	); err != nil {
		if isUniqueConstraintErr(err) {
			return nil
		}
		return fmt.Errorf("record schema_migration_repairs: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// reportRepairFailure prints why a divergence could not be repaired, once per
// process, so the warning that follows it is not the whole story.
//
// Deduplicated on the same key and for the same reason as the warning itself:
// a single command opens statedb more than once, and one problem should read
// as one problem.
func reportRepairFailure(d VersionDivergence, err error) {
	if divergenceAlreadyWarned(VersionDivergence{
		Version:  d.Version,
		Recorded: "repair-failed:" + d.Recorded,
		Embedded: d.Embedded,
	}) {
		return
	}
	fmt.Fprintf(os.Stderr,
		"warning: could not re-apply the skipped migration %q: %v\n", d.Embedded, err)
}
