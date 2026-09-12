package dbbackup

// Backup must survive the version-skew guard (Task 20226).
//
// statedb refuses to open a database migrated past the binary's own schema,
// which is right for anything that reads or writes rows — an older build does
// not know the columns a newer one added. Backup is the exception, and the
// exception is load-bearing: the documented way out of a bad rollback
// (docs/operations/runbook.md) begins with having a backup, and the moment an
// operator discovers they need one is precisely the moment a rolled-back hub is
// refusing to start.
//
// This test exists so the explicit opt-out in Backup is not later "tidied" back
// to statedb.Open, which would pass every other test in the tree.

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"

	_ "modernc.org/sqlite"
)

func TestBackupWorksOnASchemaNewerThanThisBinary(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "state.db")

	db, err := statedb.Open(src)
	if err != nil {
		t.Fatalf("seed Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("seed Close: %v", err)
	}

	// Stamp a version above anything this binary embeds: what a database
	// looks like after a newer cloop migrated it and the image was rolled back.
	latest, err := statedb.LatestSchemaVersion()
	if err != nil {
		t.Fatalf("LatestSchemaVersion: %v", err)
	}
	future := latest + 1
	raw, err := sql.Open("sqlite", src)
	if err != nil {
		t.Fatalf("open sqlite directly: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO schema_migrations(version, applied_at, name, applied_by) VALUES (?, ?, ?, ?)`,
		future, time.Now().UTC().Format(time.RFC3339Nano), "9999_future.sql", "v9.9.9",
	); err != nil {
		t.Fatalf("stamp future version: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	// The premise: an ordinary open is refused. Without this the test could
	// pass because the guard never fired at all.
	if _, err := statedb.Open(src); err == nil {
		t.Fatal("statedb.Open accepted a future schema; this test no longer proves anything")
	}

	out := filepath.Join(dir, "backup.db")
	meta, err := Backup(src, out)
	if err != nil {
		t.Fatalf("Backup on a future schema: %v", err)
	}
	if meta.SchemaVersion != future {
		t.Errorf("metadata schema_version = %d, want %d", meta.SchemaVersion, future)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("backup file missing: %v", err)
	}

	// The sidecar must describe the database that was actually copied, since
	// that is what a later restore checks itself against.
	rawMeta, err := os.ReadFile(out + MetadataSuffix)
	if err != nil {
		t.Fatalf("read metadata sidecar: %v", err)
	}
	var decoded struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(rawMeta, &decoded); err != nil {
		t.Fatalf("metadata sidecar does not decode: %v", err)
	}
	if decoded.SchemaVersion != future {
		t.Errorf("sidecar schema_version = %d, want %d", decoded.SchemaVersion, future)
	}
}
