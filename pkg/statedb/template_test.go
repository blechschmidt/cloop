package statedb

// This package's own state.db template (Task 20372).
//
// Every other package gets a migrated database from internal/statedbtest, and
// so do this package's external (statedb_test) files. Its in-package tests
// cannot: statedbtest imports statedb, and a package's in-package tests may not
// import anything that imports the package. So the binding is repeated here on
// the same generic mechanism, internal/dbtemplate, and keyed on the
// migrations this binary embeds rather than on files read from disk.
//
// Most tests in this package need a database and are not about how one comes
// to exist; they take openFresh. The tests that are about exactly that —
// migrate_test.go, schema_compat_test.go, schema_guard_test.go,
// taskfields_migration_test.go, busy_test.go and pragmas_internal_test.go —
// build theirs from scratch and must keep doing so: a copied file would skip
// the migrations, the adoption of an older schema, and the first-open races
// they exist to exercise.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/internal/dbtemplate"
)

var (
	freshTemplateOnce sync.Once
	freshTemplateV    *dbtemplate.Template
)

func freshTemplate() *dbtemplate.Template {
	freshTemplateOnce.Do(func() {
		key := "unavailable"
		if ms, err := loadMigrations(); err == nil {
			h := sha256.New()
			for _, m := range ms {
				fmt.Fprintf(h, "%s\x00%d\x00", m.Name, len(m.SQL))
				h.Write([]byte(m.SQL))
			}
			key = hex.EncodeToString(h.Sum(nil))[:16]
		}
		freshTemplateV = dbtemplate.New("state.db", key, buildFreshTemplate, verifyFreshTemplate)
	})
	return freshTemplateV
}

func buildFreshTemplate(path string) error {
	db, err := Open(path)
	if err != nil {
		return err
	}
	return db.Close()
}

// verifyFreshTemplate holds the template to the embedded migrations: one
// schema_migrations row per file, in order, under that file's name.
func verifyFreshTemplate(path string) error {
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	rows, err := conn.Query(`SELECT version, name FROM schema_migrations ORDER BY version`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	i := 0
	for rows.Next() {
		var (
			v    int
			name string
		)
		if err := rows.Scan(&v, &name); err != nil {
			return err
		}
		if i >= len(ms) || v != ms[i].Version || name != ms[i].Name {
			return fmt.Errorf("schema_migrations row %d is version %d %q, which is not migration %d of the %d embedded",
				i+1, v, name, i+1, len(ms))
		}
		i++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if i != len(ms) {
		return fmt.Errorf("the template records %d migrations; the binary embeds %d", i, len(ms))
	}
	return nil
}

// freshPath returns the path of a fully migrated, empty database in a new
// temporary directory, copied from the template rather than migrated.
func freshPath(tb testing.TB) string {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "state.db")
	freshTemplate().Seed(tb, path)
	return path
}

// freshDir is freshPath's directory: a new temporary directory whose state.db
// is already migrated.
func freshDir(tb testing.TB) string {
	tb.Helper()
	return filepath.Dir(freshPath(tb))
}

// openFresh opens a fully migrated, empty database at a new temporary path and
// closes it when the test ends.
func openFresh(tb testing.TB) *DB {
	tb.Helper()
	db, err := Open(freshPath(tb))
	if err != nil {
		tb.Fatalf("opening a seeded database: %v", err)
	}
	tb.Cleanup(func() { _ = db.Close() })
	return db
}

// The in-package template must be what Open builds from scratch, exactly as
// internal/statedbtest's is; see TestSeededDatabaseIsWhatAFreshOpenBuilds
// there for why this is asserted rather than inferred.
func TestFreshTemplateIsWhatOpenBuilds(t *testing.T) {
	fresh := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	dump := func(path string) []string {
		conn, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		rows, err := conn.Query(`
			SELECT type || ' ' || name || ' ' || tbl_name || ' ' || COALESCE(sql, '') FROM sqlite_master
			UNION ALL
			SELECT 'migration ' || version || ' ' || name || ' ' || applied_by || ' ' || compat FROM schema_migrations
			ORDER BY 1`)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	want, got := dump(fresh), dump(freshPath(t))
	if len(want) != len(got) {
		t.Fatalf("a fresh database has %d schema entries, a seeded one %d", len(want), len(got))
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("first difference between a fresh and a seeded database:\nfresh:  %s\nseeded: %s", want[i], got[i])
		}
	}
}
