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
// versions it is missing and proceeds only when it can tolerate every one of
// them: additive, or — for a build from Task 20388 on — additive-columns.
//
// Two properties make this safe to rely on:
//
//	The classification is derived from the SQL, never declared. A `-- compat:
//	additive` comment in the migration file would be one forgotten line away
//	from a corrupted database, and the forgetting would be invisible until an
//	old binary opened it. The one exception runs the other way and is closed:
//	migrations shipped before a verdict existed keep the verdict they were
//	recorded with (see migrationVerdict), so no new file can claim it.
//
//	Unknown means breaking. A row written before this column existed, a row
//	written by a build without this code, a version with no row at all, a
//	verdict this build has never heard of, and a statement this file does not
//	recognise all come out as "not known to be safe" and are refused exactly as
//	they are today. The mechanism can only ever relax the guard for a migration
//	some binary positively classified — and it is what lets a stricter verdict
//	be introduced at all: a build that predates it reads it as unknown, and
//	refuses.
//
// # Additive for reads is not additive for writes
//
// An appended column was reasoned to be invisible to an older binary because
// that binary names its columns: it neither selects nor inserts the new one.
// That covers its reads and its INSERTs, and not a write that replaces a row.
// Until Task 20388 three writers did: SaveState emptied plan_tasks and
// inserted the plan again, PutCIExchange wrote INSERT OR REPLACE, and
// ReplaceQuotaGauges deleted the gauge rows and inserted them again. Every
// such write resets each column its binary does not know, so a binary one
// migration behind erased that migration's column on its first save — on this
// deployment, a run built before 0054 erased 0054's thirteen task columns on
// every save it made.
//
// Those writers now update the rows they keep in place, in the columns they
// know, and delete only the rows that go; tests/arch/rowreplace_test.go keeps
// any writer from replacing rows again. But the builds already shipped still
// replace, and will for as long as they run. So an ADD COLUMN on a table they
// rewrite (rewrittenTables) is CompatAdditiveColumns, not CompatAdditive:
// tolerable to this build and every later one, unknown — therefore refused —
// to every build before. A refusal is better than a silent erasure.

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
	// exist before — new tables, new non-unique indexes, new views, and
	// columns appended to tables no shipped build rewrites. An older binary
	// cannot read or write them because it does not know their names, and
	// their presence changes nothing about the statements it does issue.
	CompatAdditive MigrationCompat = "additive"

	// CompatAdditiveColumns is CompatAdditive for a migration that also
	// appends a column to one of rewrittenTables. A build from Task 20388 on
	// writes those tables row by row, in the columns it knows, so the new
	// column survives it and it tolerates the migration. A build before that
	// replaces their rows on every write and would erase the column; it has
	// never heard of this verdict, reads it as unknown, and refuses the
	// database instead.
	CompatAdditiveColumns MigrationCompat = "additive-columns"

	// CompatBreaking means the migration changed something that was already
	// there, or did something this classifier does not understand. Either way
	// an older binary must not open the database.
	CompatBreaking MigrationCompat = "breaking"
)

// Tolerable reports whether a binary that does not embed this migration may
// still open a database that has it.
//
// Every build from Task 20254 to Task 20387 answered this with c ==
// CompatAdditive, which is what makes CompatAdditiveColumns a refusal for
// them.
func (c MigrationCompat) Tolerable() bool {
	return c == CompatAdditive || c == CompatAdditiveColumns
}

// rewrittenTables are the tables that builds before Task 20388 write by
// replacing whole rows, each with the writer that does it. Such a build resets
// every column it does not know on each of those writes, so a column appended
// to one of these tables survives only the builds that came after it — which
// is what CompatAdditiveColumns records.
//
// The list describes binaries already shipped, so it never shrinks. It found
// its entries by running tests/arch/rowreplace_test.go's analysis over every
// commit that changed a SQL write, and it grows only if a later build ships a
// new row replacement on purpose: that gate refuses one unless it is
// allowlisted, and an allowlisted one belongs here as well.
var rewrittenTables = map[string]string{
	"plan_tasks": "SaveState deleted every row and inserted the plan again, on every save " +
		"(every build from Task 107)",
	"quota_counters": "ReplaceQuotaGauges deleted every gauge row and inserted the gauges again " +
		"(from Task 20182)",
	"ci_exchanges": "PutCIExchange let a conflicting id replace the stored row " +
		"(from Task 20278)",
}

// firstColumnsVerdict is the first migration CompatAdditiveColumns can be
// recorded for.
//
// Migrations 0001–0059 shipped before the verdict existed, and every database
// that holds one of them already records what its applying build said — for
// each one that appends to plan_tasks (0018, 0025, 0029, 0032, 0042, 0053,
// 0054), additive. Those records are left as they are: re-recording them
// stricter would make the builds now writing those databases refuse them,
// among them the long-lived run that drives this project. This build records
// the same verdicts on a database it creates, so that no two databases
// disagree about one shipped migration. The builds that predate one of those
// migrations go on erasing its columns wherever they write until they are
// replaced; the verdict protects the next column, not the ones already added.
const firstColumnsVerdict = 60

// migrationVerdict is the verdict this build records for m: classifyMigration's
// reading of its SQL, except that a migration shipped before
// CompatAdditiveColumns existed keeps the verdict it shipped with.
func migrationVerdict(m migration) MigrationCompat {
	v := classifyMigration(m.SQL)
	if v == CompatAdditiveColumns && m.Version < firstColumnsVerdict {
		return CompatAdditive
	}
	return v
}

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
// ALTER is not a blanket refusal: alterVerdict admits ADD COLUMN in the one
// shape an older binary cannot notice — nullable or defaulted, with no UNIQUE,
// PRIMARY KEY, REFERENCES or CHECK — because such a binary names its columns
// explicitly, so it neither selects the new one nor writes a row without it.
// That holds only for a binary that also updates rows rather than replacing
// them, which builds before Task 20388 did not for rewrittenTables: appending
// to one of those makes the migration CompatAdditiveColumns. Every other
// ALTER, including RENAME and DROP COLUMN, is breaking.
//
// The verdict of a migration is the strictest of its statements' verdicts.
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

	verdict := CompatAdditive
	for _, stmt := range stmts {
		switch statementVerdict(stmt, created) {
		case CompatAdditive:
		case CompatAdditiveColumns:
			verdict = CompatAdditiveColumns
		default:
			return CompatBreaking
		}
	}
	return verdict
}

// statementVerdict classifies one statement, recording any table it creates
// into created.
func statementVerdict(stmt string, created map[string]bool) MigrationCompat {
	f := strings.Fields(stmt)
	if len(f) < 2 {
		return CompatBreaking
	}
	if strings.EqualFold(f[0], "ALTER") {
		return alterVerdict(f, created)
	}
	if additiveCreate(f, created) {
		return CompatAdditive
	}
	return CompatBreaking
}

// additiveCreate reports whether a CREATE statement only adds a new object,
// recording any table it creates into created.
func additiveCreate(f []string, created map[string]bool) bool {
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

// alterVerdict classifies an ALTER TABLE: additive when it only appends a
// column that an older binary cannot see and cannot trip over, additive-columns
// when that column lands on a table builds before Task 20388 rewrite, breaking
// otherwise.
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
// Naming its columns keeps an older binary's reads and INSERTs off the new
// column; it does not keep a write that replaces the row off it. Since Task
// 20388 no writer does that (tests/arch/rowreplace_test.go), but the builds
// before it replaced the rows of rewrittenTables on every write, so an append
// to one of those is CompatAdditiveColumns: the one verdict those builds
// cannot read.
//
// An ALTER against a table the same migration created is additive whatever it
// says: an older binary has no statements that name a table it has never heard
// of. rewrittenTables are the exception, since no migration can create one
// anew: every database has had them since long before.
func alterVerdict(f []string, created map[string]bool) MigrationCompat {
	if len(f) < 5 || !strings.EqualFold(f[1], "TABLE") {
		return CompatBreaking
	}
	table := identifier(f[2])

	// "ADD COLUMN x" or the "COLUMN"-less "ADD x" SQLite also accepts.
	rest := f[3:]
	if !strings.EqualFold(rest[0], "ADD") {
		return CompatBreaking
	}
	rest = rest[1:]
	if len(rest) > 0 && strings.EqualFold(rest[0], "COLUMN") {
		rest = rest[1:]
	}
	// The runner's idempotent form (addcolumn.go). It adds the same column as
	// the plain statement or nothing at all, so it classifies the same way.
	rest = skipIfNotExists(rest)
	if len(rest) < 2 {
		// A bare name with no type is a form this function did not anticipate.
		return CompatBreaking
	}

	// A table this migration created — unless it is one of rewrittenTables,
	// which every database has had since long before this migration: a
	// CREATE TABLE IF NOT EXISTS of one of those created nothing.
	_, rewritten := rewrittenTables[table]
	if created[table] && !rewritten {
		return CompatAdditive
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
			return CompatBreaking
		case "DEFAULT":
			// A DEFAULT must actually have a value after it.
			if i+2 > len(rest)-1 {
				return CompatBreaking
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
		return CompatBreaking
	}
	if rewritten {
		return CompatAdditiveColumns
	}
	return CompatAdditive
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
