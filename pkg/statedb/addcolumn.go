package statedb

// An idempotent ADD COLUMN for migration files (Task 20361).
//
// SQLite has no ADD COLUMN IF NOT EXISTS, so a migration that adds a column a
// database already has fails with "duplicate column name" — inside the
// migration's transaction, which means the database never moves past that
// version and nothing that opens it starts. Databases do arrive with columns
// no migration of this package created:
//
//   - `cloop migrate` (pkg/migrate, Task 187) adds plan_tasks.assignee,
//     external_url and links to every project it upgrades, with no
//     schema_migrations row to say so. The hub's own control plane carries
//     them.
//   - Development builds run from a dirty tree have applied migrations whose
//     files never landed, under version numbers main later used for something
//     else (see checkNames). Their columns stay behind.
//
// So the runner accepts one statement SQLite itself does not:
//
//	ALTER TABLE <table> ADD [COLUMN] IF NOT EXISTS <column> <declaration>
//
// and executes it as a plain ADD COLUMN when the column is missing. When the
// column is already there it is adopted only if it is the column the
// migration declares — same type, same nullability, same default, as SQLite
// itself reports them — and the migration fails otherwise, naming both shapes.
// A column of another shape is not this migration's column: adopting it would
// trade a loud failure at deploy for a quiet one in every load afterwards (a
// nullable column scans NULL into a Go string and fails each read; a different
// default is what an older binary's INSERTs write).

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"
)

// addColumnIfNotExistsRE matches the statement form the runner interprets.
// Identifiers are bare: the migrations here never quote them, and accepting
// only what the regexp can see whole keeps them safe to interpolate.
var addColumnIfNotExistsRE = regexp.MustCompile(
	`(?is)^ALTER\s+TABLE\s+([A-Za-z_][A-Za-z0-9_]*)\s+ADD\s+(?:COLUMN\s+)?IF\s+NOT\s+EXISTS\s+([A-Za-z_][A-Za-z0-9_]*)\s+(\S.*)$`)

// addColumnIfNotExists is one parsed ALTER TABLE ... ADD COLUMN IF NOT EXISTS.
type addColumnIfNotExists struct {
	table, column, declaration string
}

// parseAddColumnIfNotExists recognises the runner's idempotent ADD COLUMN.
// Any other statement, including a plain ADD COLUMN, is not one.
func parseAddColumnIfNotExists(stmt string) (addColumnIfNotExists, bool) {
	m := addColumnIfNotExistsRE.FindStringSubmatch(strings.TrimSpace(stmt))
	if m == nil {
		return addColumnIfNotExists{}, false
	}
	return addColumnIfNotExists{table: m[1], column: m[2], declaration: strings.TrimSpace(m[3])}, true
}

// apply adds the column, or verifies that the one already there matches.
func (a addColumnIfNotExists) apply(tx *sql.Tx) error {
	have, found, err := columnShape(tx, "main", a.table, a.column)
	if err != nil {
		return err
	}
	if !found {
		// No such table makes this fail with SQLite's own message, which is the
		// right one: the migration is wrong, not the database.
		_, err := tx.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", a.table, a.column, a.declaration))
		return err
	}
	want, err := a.declaredShape(tx)
	if err != nil {
		return err
	}
	if !have.sameAs(want) {
		return fmt.Errorf("%s.%s already exists as %s, but this migration declares it %s: "+
			"something other than a cloop migration created it. Check what the column holds, "+
			"then drop it (ALTER TABLE %s DROP COLUMN %s) or rebuild it to match, and start "+
			"cloop again", a.table, a.column, have, want, a.table, a.column)
	}
	return nil
}

// declaredShape is the shape SQLite gives the column this statement declares,
// learned by declaring it on a scratch table. Asking SQLite rather than parsing
// the declaration here means the comparison sees exactly what an ALTER would
// have produced, whatever spelling the migration used.
func (a addColumnIfNotExists) declaredShape(tx *sql.Tx) (columnInfo, error) {
	const probe = "cloop_add_column_probe"
	if _, err := tx.Exec(fmt.Sprintf("CREATE TEMP TABLE %s (%s %s)", probe, a.column, a.declaration)); err != nil {
		return columnInfo{}, fmt.Errorf("check the declaration of %s.%s: %w", a.table, a.column, err)
	}
	shape, found, err := columnShape(tx, "temp", probe, a.column)
	if _, dropErr := tx.Exec("DROP TABLE temp." + probe); dropErr != nil && err == nil {
		err = dropErr
	}
	if err != nil {
		return columnInfo{}, err
	}
	if !found {
		return columnInfo{}, fmt.Errorf("check the declaration of %s.%s: the scratch table has no such column", a.table, a.column)
	}
	return shape, nil
}

// columnInfo is a column as PRAGMA table_info reports it.
type columnInfo struct {
	Type    string
	NotNull bool
	Default sql.NullString
	PK      bool
}

// sameAs compares two columns the way it matters to the code reading them.
// SQLite type names are case-insensitive; a default is compared as written,
// because that text is what fills the column in a row that does not name it.
func (c columnInfo) sameAs(o columnInfo) bool {
	return strings.EqualFold(strings.Join(strings.Fields(c.Type), " "), strings.Join(strings.Fields(o.Type), " ")) &&
		c.NotNull == o.NotNull && c.Default == o.Default && c.PK == o.PK
}

func (c columnInfo) String() string {
	var b strings.Builder
	b.WriteString(c.Type)
	if c.Type == "" {
		b.WriteString("(untyped)")
	}
	if c.NotNull {
		b.WriteString(" NOT NULL")
	} else {
		b.WriteString(" NULL")
	}
	if c.Default.Valid {
		b.WriteString(" DEFAULT " + c.Default.String)
	}
	if c.PK {
		b.WriteString(" PRIMARY KEY")
	}
	return b.String()
}

// columnShape reports column's shape in schema.table, and whether it exists.
// schema and table come from the migration file or are constants here, never
// from input, and table has passed addColumnIfNotExistsRE.
func columnShape(tx *sql.Tx, schema, table, column string) (columnInfo, bool, error) {
	rows, err := tx.Query(fmt.Sprintf("PRAGMA %s.table_info(%s)", schema, table))
	if err != nil {
		return columnInfo{}, false, fmt.Errorf("inspect %s columns: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid     int
			name    string
			c       columnInfo
			notNull int
			pk      int
		)
		if err := rows.Scan(&cid, &name, &c.Type, &notNull, &c.Default, &pk); err != nil {
			return columnInfo{}, false, fmt.Errorf("scan %s columns: %w", table, err)
		}
		if strings.EqualFold(name, column) {
			c.NotNull, c.PK = notNull != 0, pk != 0
			return c, true, rows.Err()
		}
	}
	return columnInfo{}, false, rows.Err()
}
