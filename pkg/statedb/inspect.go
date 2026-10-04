package statedb

// inspect.go: what statedb's own bookkeeping says about a database file, read
// without migrating it (Task 20374).
//
// `cloop migrate` used to decide whether a project needed it from a version
// number of its own, kept in metadata.schema_version — a key statedb never
// writes, so every project created by a current binary read as out of date and
// every interactive command said so. Whether a database is statedb's, and what
// Open would do with it, is statedb's to say, by the same rules Open applies.

import (
	"database/sql"
	"errors"
	"fmt"
)

// SchemaState is what a database file is, in statedb's terms.
type SchemaState struct {
	// Version is the highest migration schema_migrations records; zero when
	// the table is missing or empty. Open migrates it to LatestSchemaVersion.
	Version int
	// PreFramework reports a database Open would adopt as its baseline instead
	// of building from scratch: cloop's metadata table, and no migration
	// recorded — the rule detectBaseline applies.
	PreFramework bool
	// HoldsProject reports a project in the database: a metadata row, the
	// test HasProjectState applies. Opening a database creates the file and
	// every table in it, so the file existing says nothing.
	HoldsProject bool
}

// InspectSchema reports what the database at path is, through a read-only
// handle: asking neither migrates it nor, when it does not exist, creates it.
func InspectSchema(path string) (SchemaState, error) {
	conn, err := OpenConn(path, ReadOnly)
	if err != nil {
		return SchemaState{}, err
	}
	defer conn.Close()

	hasMetadata, err := tableExists(conn, "metadata")
	if err != nil {
		return SchemaState{}, err
	}
	hasMigrations, err := tableExists(conn, "schema_migrations")
	if err != nil {
		return SchemaState{}, err
	}

	var st SchemaState
	if hasMigrations {
		if st.Version, err = currentVersion(conn); err != nil {
			return SchemaState{}, fmt.Errorf("statedb: inspect %s: %w", path, err)
		}
	}
	if hasMetadata {
		var one int
		switch err := conn.QueryRow(`SELECT 1 FROM metadata LIMIT 1`).Scan(&one); {
		case err == nil:
			st.HoldsProject = true
		case !errors.Is(err, sql.ErrNoRows):
			return SchemaState{}, fmt.Errorf("statedb: inspect %s: %w", path, classifyDriverErr(err))
		}
	}
	st.PreFramework = st.Version == 0 && hasMetadata
	return st, nil
}

// tableExists reports whether the database behind conn has a table named name.
func tableExists(conn *sql.DB, name string) (bool, error) {
	var n int
	if err := conn.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name,
	).Scan(&n); err != nil {
		return false, fmt.Errorf("statedb: inspect sqlite_master: %w", classifyDriverErr(err))
	}
	return n > 0, nil
}
