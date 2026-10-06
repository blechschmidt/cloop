package statedbtest

// A column from a newer build (Task 20388).
//
// A migration that appends a nullable or defaulted column is recorded
// additive, so a binary that predates it keeps opening the database: a hub
// cluster member mid-way through a rolling update, a long-lived run, a
// rolled-back image. That is only safe if such a binary leaves the column
// alone on every write it makes, and three of statedb's writers did not — they
// replaced whole rows, resetting every column they did not name. These helpers
// stand in for the newer build, so a test outside pkg/statedb can write
// through its own path and check what is left of the column.

import (
	"fmt"
	"testing"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// FutureColumn is the column a newer build added. No build of this tree knows
// it, so no statement this tree issues names it.
const FutureColumn = "from_a_newer_build"

// AddFutureColumn appends FutureColumn to table in the database at dbPath, in
// the shape a migration recorded additive takes, and sets it in every row
// already there to value, an SQL expression over the row — `'kept by ' || id`.
func AddFutureColumn(tb testing.TB, dbPath, table, value string) {
	tb.Helper()
	exec(tb, dbPath,
		`ALTER TABLE `+table+` ADD COLUMN `+FutureColumn+` TEXT NOT NULL DEFAULT ''`,
		`UPDATE `+table+` SET `+FutureColumn+` = `+value)
}

// SetFutureValue sets FutureColumn to value, an SQL expression, in the rows of
// table that where selects.
func SetFutureValue(tb testing.TB, dbPath, table, value, where string) {
	tb.Helper()
	exec(tb, dbPath, `UPDATE `+table+` SET `+FutureColumn+` = `+value+` WHERE `+where)
}

// FutureValues reads FutureColumn from every row of table, keyed by key, an
// SQL expression naming the row: `id`, or `identity || '/' || resource`.
func FutureValues(tb testing.TB, dbPath, table, key string) map[string]string {
	tb.Helper()
	conn, err := statedb.OpenConn(dbPath, statedb.ReadOnly)
	if err != nil {
		tb.Fatalf("open %s: %v", dbPath, err)
	}
	defer conn.Close()
	rows, err := conn.Query(`SELECT CAST(` + key + ` AS TEXT), ` + FutureColumn + ` FROM ` + table)
	if err != nil {
		tb.Fatalf("read %s.%s: %v", table, FutureColumn, err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			tb.Fatalf("scan %s.%s: %v", table, FutureColumn, err)
		}
		out[k] = v
	}
	if err := rows.Err(); err != nil {
		tb.Fatalf("read %s.%s: %v", table, FutureColumn, err)
	}
	return out
}

// WantFutureValues fails tb unless table's rows are exactly want: the same
// keys, each holding the value given. after names the write being checked.
func WantFutureValues(tb testing.TB, dbPath, table, key, after string, want map[string]string) {
	tb.Helper()
	got := FutureValues(tb, dbPath, table, key)
	for k, v := range want {
		g, ok := got[k]
		switch {
		case !ok:
			tb.Errorf("after %s: %s row %s is gone, want it kept", after, table, k)
		case g != v:
			tb.Errorf("after %s: %s row %s holds %s = %q, want %q — a write by a binary that "+
				"does not know the column reset it", after, table, k, FutureColumn, g, v)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			tb.Errorf("after %s: %s row %s is still there, want it deleted", after, table, k)
		}
	}
}

func exec(tb testing.TB, dbPath string, stmts ...string) {
	tb.Helper()
	conn, err := statedb.OpenConn(dbPath, statedb.ReadWrite)
	if err != nil {
		tb.Fatalf("open %s: %v", dbPath, err)
	}
	defer conn.Close()
	for _, s := range stmts {
		if _, err := conn.Exec(s); err != nil {
			tb.Fatalf("%s: %v", s, fmt.Errorf("%s: %w", dbPath, err))
		}
	}
}
