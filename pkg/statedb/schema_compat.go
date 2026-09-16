package statedb

// Backward-compatibility classification for migrations (Task 20254).
//
// schema_guard.go refuses to open a database whose schema is ahead of this
// binary. That refusal is right in principle and was, in practice, too blunt:
// it compares version numbers and nothing else, so *any* newer migration makes
// the database unopenable even when the newer migration only added a table the
// older binary has never heard of and will never touch.
//
// The cost of that bluntness was a real outage. On 2026-09-14 a development
// build applied 0034_telemetry.sql — one CREATE TABLE and two CREATE INDEX,
// touching nothing that existed before — to every registered project's
// state.db at 08:44. The hub deployed at 04:43 embedded 33 migrations, so from
// 08:44 until the next nightly rebuild it refused all 18 databases and served
// a dashboard on which every project had no goal, no tasks and no steps. The
// guard's own doc comment already conceded the gap ("Not every version bump
// changes a table an older binary reads") and left it to an operator to set
// CLOOP_ALLOW_SCHEMA_DOWNGRADE. A nightly timer is not an operator, and an
// exemption that must be set by hand during the outage it prevents is not one.
//
// So the guard needs to ask a better question than "how far ahead is this
// database": it needs to ask "does anything it gained since my build actually
// affect me". Only the binary that *applies* a migration can see its SQL, so
// that binary classifies it at apply time and records the verdict in
// schema_migrations.compat. A later, older binary reads the verdicts for the
// versions it is missing and proceeds only when every one of them is additive.
//
// Two properties make this safe to rely on:
//
//	The classification is derived from the SQL, never declared. A `-- compat:
//	additive` comment in the migration file would be one forgotten line away
//	from a corrupted database, and the forgetting would be invisible until an
//	old binary opened it.
//
//	Unknown means breaking. A row written before this column existed, a row
//	written by a build without this code, a version with no row at all, and a
//	statement this file does not recognise all come out as "not known to be
//	safe" and are refused exactly as they are today. The mechanism can only
//	ever relax the guard for a migration some binary positively classified.

import (
	"strings"
)

// MigrationCompat says whether a migration can be tolerated by a binary that
// predates it.
type MigrationCompat string

const (
	// CompatUnknown is the zero value: nothing classified this migration, so
	// nothing may assume it is safe. Treated exactly like CompatBreaking.
	CompatUnknown MigrationCompat = ""

	// CompatAdditive means the migration only introduced objects that did not
	// exist before — new tables, new non-unique indexes, new views. An older
	// binary cannot read or write them because it does not know their names,
	// and their presence changes nothing about the statements it does issue.
	CompatAdditive MigrationCompat = "additive"

	// CompatBreaking means the migration changed something that was already
	// there, or did something this classifier does not understand. Either way
	// an older binary must not open the database.
	CompatBreaking MigrationCompat = "breaking"
)

// Tolerable reports whether a binary that does not embed this migration may
// still open a database that has it.
func (c MigrationCompat) Tolerable() bool { return c == CompatAdditive }

// classifyMigration decides whether a migration is additive for binaries that
// predate it.
//
// Conservative by construction: a statement has to be recognised as adding
// something an older binary cannot see to keep the migration additive, and
// anything else — DROP, INSERT, UPDATE, DELETE, PRAGMA, or a CREATE this
// function cannot parse — makes the whole migration breaking. Being wrong in
// the additive direction hands an old binary a database it will corrupt; being
// wrong in the breaking direction costs a refusal that was already today's
// behaviour.
//
// ALTER is not a blanket refusal: additiveAlter admits ADD COLUMN in the one
// shape an older binary cannot notice — nullable or defaulted, with no UNIQUE,
// PRIMARY KEY, REFERENCES or CHECK — because such a binary enumerates its
// columns explicitly and so neither selects nor inserts the new one. Every
// other ALTER, including RENAME and DROP COLUMN, is breaking.
func classifyMigration(sqlText string) MigrationCompat {
	stmts := splitStatements(sqlText)
	if len(stmts) == 0 {
		// A migration that does nothing cannot break anything, but it also
		// should not exist. Refuse to bless it.
		return CompatBreaking
	}

	// Objects this migration itself creates. A constraint or trigger attached
	// to one of them is invisible to an older binary — it has no statements
	// that touch a table it does not know — whereas the same constraint on a
	// pre-existing table can reject a write that used to succeed.
	created := make(map[string]bool)

	for _, stmt := range stmts {
		if !additiveStatement(stmt, created) {
			return CompatBreaking
		}
	}
	return CompatAdditive
}

// additiveStatement reports whether one statement only adds a new object,
// recording any table it creates into created.
func additiveStatement(stmt string, created map[string]bool) bool {
	f := strings.Fields(stmt)
	if len(f) < 2 {
		return false
	}
	if strings.EqualFold(f[0], "ALTER") {
		return additiveAlter(f, created)
	}
	if !strings.EqualFold(f[0], "CREATE") {
		return false
	}

	// Skip the modifiers SQLite allows between CREATE and the object kind.
	// UNIQUE is remembered rather than skipped: it is the one modifier that
	// turns an otherwise-invisible index into a constraint on existing rows.
	i := 1
	unique := false
	for i < len(f) && isCreateModifier(f[i]) {
		if strings.EqualFold(f[i], "UNIQUE") {
			unique = true
		} else {
			// TEMP/TEMPORARY: the object vanishes with the connection, so it
			// cannot be what an older binary trips over — but it also has no
			// business in a migration. Decline to classify it as safe.
			return false
		}
		i++
	}
	if i >= len(f) {
		return false
	}

	kind := strings.ToUpper(f[i])
	rest := skipIfNotExists(f[i+1:])
	if len(rest) == 0 {
		return false
	}

	switch kind {
	case "TABLE":
		created[identifier(rest[0])] = true
		return true

	case "VIEW":
		// A view is a named SELECT. Nothing an older binary issues can name it.
		return true

	case "INDEX":
		if !unique {
			// A plain index changes only the query planner's options.
			return true
		}
		// A unique index is a new rule the old binary's INSERTs must satisfy,
		// so it is safe only on a table that binary cannot write to at all.
		return onlyTouchesNewTable(rest, created)

	case "TRIGGER":
		// A trigger can rewrite or reject writes to the table it watches.
		return onlyTouchesNewTable(rest, created)
	}
	return false
}

// additiveAlter reports whether an ALTER TABLE only appends a column that an
// older binary cannot see and cannot trip over.
//
// Adding a column is the one ALTER that can be safe, and it is the shape every
// migration that extends an existing table takes — so classifying the whole
// family as breaking would either blank the older hub sharing this control
// plane, or push authors toward rebuilding tables, which is genuinely
// destructive. It is admitted under three conditions, each of which is the
// reason an older binary is unaffected:
//
//	The statement is ADD COLUMN. RENAME and DROP change or remove something
//	that binary already reads; there is no version of those that is safe.
//
//	The column has a DEFAULT, or is nullable. An older binary's INSERTs name
//	their columns explicitly and will never name this one, so the row it writes
//	must be acceptable without it. A NOT NULL column with no default makes
//	every one of those INSERTs fail — and SQLite rejects the ALTER itself, so
//	this also refuses to bless a migration that cannot apply.
//
//	The column carries no constraint: not UNIQUE, not PRIMARY KEY, no
//	REFERENCES, no CHECK. Each of those is a new rule an older binary's writes
//	would have to satisfy without knowing it exists — a foreign key in
//	particular can reject a row whose default does not resolve in the parent.
//
// What makes the first condition sufficient rather than merely necessary is
// that nothing in this package issues `SELECT *`: every read names its columns,
// so an appended one is invisible to a binary compiled before it. A reader that
// did select everything and scan into a fixed struct would break on the extra
// value, and that is the assumption to re-check if this is ever relaxed
// further.
//
// An ALTER against a table the same migration created is additive whatever it
// says: an older binary has no statements that name a table it has never heard
// of.
func additiveAlter(f []string, created map[string]bool) bool {
	if len(f) < 5 || !strings.EqualFold(f[1], "TABLE") {
		return false
	}
	table := identifier(f[2])

	// "ADD COLUMN x" or the "COLUMN"-less "ADD x" SQLite also accepts.
	rest := f[3:]
	if !strings.EqualFold(rest[0], "ADD") {
		return false
	}
	rest = rest[1:]
	if len(rest) > 0 && strings.EqualFold(rest[0], "COLUMN") {
		rest = rest[1:]
	}
	if len(rest) < 2 {
		// A bare name with no type is a form this function did not anticipate.
		return false
	}

	if created[table] {
		return true
	}

	// Scan the column definition for anything that is a rule rather than a
	// value. Checked over the whole remainder, not just the tokens this
	// function understands, so an unanticipated keyword cannot slip past by
	// sitting somewhere the parser does not look.
	hasDefault := false
	notNull := false
	for i, tok := range rest[1:] {
		switch strings.ToUpper(strings.Trim(tok, "\"`[]';,()")) {
		case "UNIQUE", "PRIMARY", "REFERENCES", "CHECK", "COLLATE", "GENERATED", "AS":
			return false
		case "DEFAULT":
			// A DEFAULT must actually have a value after it.
			if i+2 > len(rest)-1 {
				return false
			}
			hasDefault = true
		case "NULL":
			// Distinguish "NOT NULL" from a bare "NULL"; the NOT is the token
			// before it.
			if i > 0 && strings.EqualFold(rest[i], "NOT") {
				notNull = true
			}
		}
	}
	if notNull && !hasDefault {
		return false
	}
	return true
}

// isCreateModifier reports whether tok is one of the words SQLite allows
// between CREATE and the kind of object being created.
func isCreateModifier(tok string) bool {
	return strings.EqualFold(tok, "UNIQUE") ||
		strings.EqualFold(tok, "TEMP") ||
		strings.EqualFold(tok, "TEMPORARY")
}

// skipIfNotExists drops a leading "IF NOT EXISTS" so the object name is first.
func skipIfNotExists(f []string) []string {
	if len(f) >= 3 && strings.EqualFold(f[0], "IF") &&
		strings.EqualFold(f[1], "NOT") && strings.EqualFold(f[2], "EXISTS") {
		return f[3:]
	}
	return f
}

// onlyTouchesNewTable reports whether the ON clause of an index or trigger
// names a table this same migration created.
//
// Requiring an explicit ON is deliberate: a form without one is a form this
// function did not anticipate, and the answer to that is "breaking".
func onlyTouchesNewTable(f []string, created map[string]bool) bool {
	for i := 0; i+1 < len(f); i++ {
		if strings.EqualFold(f[i], "ON") {
			return created[identifier(f[i+1])]
		}
	}
	return false
}

// identifier normalises a table or index name for comparison: quoting stripped,
// any trailing "(" or column list cut off, case folded.
//
// SQLite identifiers are case-insensitive for ASCII, which is all these
// migrations use.
func identifier(tok string) string {
	if i := strings.IndexByte(tok, '('); i > 0 {
		tok = tok[:i]
	}
	tok = strings.Trim(tok, "\"`[]';,")
	// A schema-qualified name ("main.tasks") is keyed by its final component;
	// migrations here never qualify, and treating the two spellings as one
	// errs toward recognising a table as new rather than away from it.
	if i := strings.LastIndex(tok, "."); i >= 0 {
		tok = tok[i+1:]
	}
	return strings.ToLower(tok)
}
