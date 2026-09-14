package statedb

// The verdict on every shipped migration, pinned (Task 20254).
//
// schema_compat.go decides whether a migration is tolerable to an older binary,
// and schema_guard.go refuses a database carrying one that is not. Both are
// tested. What neither of them does — and what this file adds — is tell the
// person *writing* the next migration which side of that line they landed on.
//
// That gap is the first link in the chain that caused the outage. On
// 2026-09-14 a development build applied a migration to every registered
// project's state.db at 08:44; the hub deployed at 04:43 could not open a
// single one of them and served a dashboard on which 26 projects had no goal,
// no tasks and no steps until the next nightly rebuild. Every later link in
// that chain has since been fixed: the classifier lets an additive migration
// through, the deploy script parses /api/projects and rolls back a build that
// resolves none of them, and the dashboard now says "could not be loaded"
// instead of rendering an empty project. The first link was still unguarded.
// A migration that classifies as breaking passes CI in silence, and the cost
// lands hours later on a deployment whose only operator is a timer.
//
// The check is deliberately asymmetric, because the risk is:
//
//	Additive costs nothing. It is the overwhelmingly common shape — 34 of the
//	37 migrations shipped so far — and requires no bookkeeping here at all. A
//	test that made authors register every migration would be edited on
//	autopilot, and a list nobody reads protects nobody.
//
//	Breaking must be acknowledged by name, with a reason. Not forbidden:
//	sometimes the schema genuinely has to change under an existing table, and
//	this file is not the place to litigate that. But it must be a decision
//	somebody made and wrote down, rather than one discovered from a blank
//	dashboard, because the cost is paid by a running deployment and is invisible
//	until it is hours old.
//
// The list is also checked in the other direction: an entry whose migration no
// longer classifies as breaking is itself a failure. Otherwise the improvement
// that reclassified it — additiveAlter, which turned nine of these from
// breaking to additive — would leave stale entries behind, and a list that
// drifts is one an author stops trusting enough to read.

import (
	"fmt"
	"sort"
	"testing"
)

// breakingMigrations names every shipped migration that an older binary cannot
// tolerate, and why.
//
// Adding an entry means accepting that from the moment this migration is
// applied, every hub built before it refuses the databases it touched, until
// each of those hubs is rebuilt. On this project's own deployment that window
// is up to a day. Prefer a shape the classifier recognises as additive: a new
// table, a new plain index, a new view, or an appended column that is nullable
// or has a DEFAULT and carries no constraint.
var breakingMigrations = map[int]string{
	1: "the baseline schema itself: every table an older binary reads is " +
		"created here, so there is no older binary for it to be compatible with.",
	9: "DROPs the stuck-task tables (Task 20151). Removing an object a prior " +
		"build still queries is breaking by definition.",
	19: "rewrites existing secret rows into envelope-encrypted form (Task 20181). " +
		"An older build would read the new wrapping as ciphertext it cannot open.",
}

// unacknowledgedBreaking returns the names of migrations that classify as
// breaking without an entry in ack.
//
// Split out from the test so the gate can be exercised against synthetic input.
// A check that has only ever been run against a passing corpus has not been
// shown to fail, and this one exists precisely for the day something does.
func unacknowledgedBreaking(migrations []migration, ack map[int]string) []string {
	var out []string
	for _, m := range migrations {
		if classifyMigration(m.SQL) != CompatBreaking {
			continue
		}
		if _, ok := ack[m.Version]; ok {
			continue
		}
		out = append(out, m.Name)
	}
	sort.Strings(out)
	return out
}

// TestEveryBreakingMigrationIsAcknowledged fails when a migration classifies as
// breaking without an entry above.
//
// This is the test that would have made the outage a code-review conversation
// instead of a morning of blank dashboards.
func TestEveryBreakingMigrationIsAcknowledged(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}

	for _, name := range unacknowledgedBreaking(migrations, breakingMigrations) {
		t.Errorf("%s classifies as %q and is not acknowledged in breakingMigrations.\n"+
			"\n"+
			"Every hub built before this migration will refuse every database it is\n"+
			"applied to, serving projects with no goal, no tasks and no steps until\n"+
			"that hub is rebuilt — up to a day on the nightly deployment.\n"+
			"\n"+
			"Either reshape it so an older binary cannot trip over it (a new table, a\n"+
			"new plain index, a new view, or an appended column that is nullable or\n"+
			"DEFAULTed and carries no UNIQUE/PRIMARY KEY/REFERENCES/CHECK), or add it\n"+
			"to breakingMigrations in this file with the reason it has to be this way.",
			name, CompatBreaking)
	}
}

// TestAcknowledgementGateActuallyFires proves the gate above can fail.
//
// The synthetic migrations are held in memory and never written to
// pkg/statedb/migrations/: a stray .sql file there is picked up by go:embed,
// and on 2026-08-22 an untracked one was applied to every registered project's
// database by an unrelated build. Verifying a safety check must not risk the
// thing the check protects.
func TestAcknowledgementGateActuallyFires(t *testing.T) {
	const dropsATable = "DROP TABLE tasks;"
	const addsATable = "CREATE TABLE IF NOT EXISTS widgets (id TEXT PRIMARY KEY);"

	synthetic := []migration{
		{Version: 900, Name: "0900_drops_a_table.sql", SQL: dropsATable},
		{Version: 901, Name: "0901_adds_a_table.sql", SQL: addsATable},
	}

	// Sanity: the corpus is what the test thinks it is. Otherwise a classifier
	// change could make both migrations additive and this test would "pass" by
	// asserting nothing.
	if got := classifyMigration(dropsATable); got != CompatBreaking {
		t.Fatalf("a DROP TABLE must classify as breaking, got %q", got)
	}
	if got := classifyMigration(addsATable); got != CompatAdditive {
		t.Fatalf("a CREATE TABLE must classify as additive, got %q", got)
	}

	// Unacknowledged: the breaking one is reported, the additive one is not.
	got := unacknowledgedBreaking(synthetic, map[int]string{})
	if len(got) != 1 || got[0] != "0900_drops_a_table.sql" {
		t.Errorf("gate did not flag the unacknowledged breaking migration: got %v, "+
			"want [0900_drops_a_table.sql]", got)
	}

	// Acknowledged: nothing is reported, so the list genuinely suppresses.
	if got := unacknowledgedBreaking(synthetic, map[int]string{900: "deliberate"}); len(got) != 0 {
		t.Errorf("an acknowledged migration must not be reported, got %v", got)
	}
}

// TestNoStaleBreakingAcknowledgement fails when an acknowledged migration is no
// longer breaking, or names a version that does not exist.
//
// Keeps the list above honest. additiveAlter reclassified nine migrations that
// had been recorded as breaking; without this, their entries would have
// survived as folklore about a problem that no longer exists.
func TestNoStaleBreakingAcknowledgement(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	byVersion := make(map[int]migration, len(migrations))
	for _, m := range migrations {
		byVersion[m.Version] = m
	}

	versions := make([]int, 0, len(breakingMigrations))
	for v := range breakingMigrations {
		versions = append(versions, v)
	}
	sort.Ints(versions)

	for _, v := range versions {
		m, ok := byVersion[v]
		if !ok {
			t.Errorf("breakingMigrations lists version %d, which no migration has; "+
				"remove the entry", v)
			continue
		}
		if got := classifyMigration(m.SQL); got != CompatBreaking {
			t.Errorf("%s is acknowledged as breaking but now classifies as %q; "+
				"remove its entry from breakingMigrations", m.Name, got)
		}
		if breakingMigrations[v] == "" {
			t.Errorf("%s is acknowledged as breaking with no reason given", m.Name)
		}
	}
}

// TestShippedMigrationsAreOverwhelminglyAdditive is the summary the other two
// tests cannot give: a single number an author can watch move.
//
// It asserts the weak, durable property — that the additive path is the normal
// one — rather than an exact count, which would fail on every new migration
// and teach people to update it without reading it.
func TestShippedMigrationsAreOverwhelminglyAdditive(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("no embedded migrations")
	}

	var additive []string
	var breaking []string
	for _, m := range migrations {
		if classifyMigration(m.SQL) == CompatAdditive {
			additive = append(additive, m.Name)
		} else {
			breaking = append(breaking, fmt.Sprintf("%s (%s)", m.Name, reasonFor(m.Version)))
		}
	}

	t.Logf("%d migrations: %d additive, %d breaking", len(migrations), len(additive), len(breaking))
	for _, b := range breaking {
		t.Logf("  breaking: %s", b)
	}

	// A hub is only safe across a deploy gap if the *typical* migration is
	// additive. If that stops being true the guard has become a formality and
	// the deployment is back to depending on the nightly rebuild.
	if len(additive)*2 <= len(migrations) {
		t.Errorf("only %d of %d migrations are additive; an older hub sharing this "+
			"control plane is refused more often than not", len(additive), len(migrations))
	}
}

func reasonFor(version int) string {
	if r, ok := breakingMigrations[version]; ok {
		return r
	}
	return "UNACKNOWLEDGED"
}
