package statedb_test

// The connection policy every cloop SQLite handle opens under (Task 20374).

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// The defect the policy exists for: a connection-scoped pragma issued with Exec
// reaches the connection that ran it and no other, so a pool that opens a
// second connection hands out one with no busy timeout. Settings carried in the
// DSN reach every connection, which this checks on three held at once.
func TestConnPolicyReachesEveryPooledConnection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	conn, err := statedb.OpenConn(path, statedb.ReadWrite)
	if err != nil {
		t.Fatalf("OpenConn: %v", err)
	}
	defer conn.Close()
	conn.SetMaxOpenConns(3)

	ctx := context.Background()
	var held []*sql.Conn
	for i := 0; i < 3; i++ {
		c, err := conn.Conn(ctx)
		if err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		held = append(held, c)
	}
	for i, c := range held {
		var busy, fk int
		var limit int64
		if err := c.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busy); err != nil {
			t.Fatalf("connection %d busy_timeout: %v", i, err)
		}
		if err := c.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil {
			t.Fatalf("connection %d foreign_keys: %v", i, err)
		}
		if err := c.QueryRowContext(ctx, `PRAGMA journal_size_limit`).Scan(&limit); err != nil {
			t.Fatalf("connection %d journal_size_limit: %v", i, err)
		}
		if busy != statedb.BusyTimeoutMillis || fk != 1 || limit != statedb.JournalSizeLimitBytes {
			t.Errorf("connection %d: busy_timeout=%d foreign_keys=%d journal_size_limit=%d, want %d, 1 and %d",
				i, busy, fk, limit, statedb.BusyTimeoutMillis, statedb.JournalSizeLimitBytes)
		}
		_ = c.Close()
	}
}

// A writer's transaction holds the write lock from BEGIN, so a second writer
// that wants the lock meanwhile finds it taken — rather than the first finding
// out at its first write, when a deferred transaction can no longer wait.
func TestConnPolicyWriterTakesTheWriteLockAtBegin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	writer, err := statedb.OpenConn(path, statedb.ReadWrite)
	if err != nil {
		t.Fatalf("OpenConn: %v", err)
	}
	defer writer.Close()
	if _, err := writer.Exec(`CREATE TABLE t (n INTEGER)`); err != nil {
		t.Fatal(err)
	}

	tx, err := writer.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// A bare connection with no busy timeout: it reports the lock at once
	// instead of waiting for it.
	probe, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if _, err := probe.Exec(`BEGIN IMMEDIATE`); err == nil {
		_, _ = probe.Exec(`ROLLBACK`)
		t.Fatal("a second writer took the write lock while a policy transaction was open; " +
			"the policy's BEGIN did not take it")
	} else if !strings.Contains(strings.ToLower(err.Error()), "locked") &&
		!strings.Contains(strings.ToLower(err.Error()), "busy") {
		t.Fatalf("BEGIN IMMEDIATE beside an open transaction: %v, want a busy error", err)
	}
}

func TestConnPolicyReaderNeitherWritesNorCreates(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "absent.db")
	if conn, err := statedb.OpenConn(missing, statedb.ReadOnly); err == nil {
		conn.Close()
		t.Fatal("a read-only open of a missing file succeeded")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a read-only open created %s (stat: %v)", missing, err)
	}

	path := filepath.Join(dir, "state.db")
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	reader, err := statedb.OpenConn(path, statedb.ReadOnly)
	if err != nil {
		t.Fatalf("read-only open: %v", err)
	}
	defer reader.Close()
	var n int
	if err := reader.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil || n == 0 {
		t.Fatalf("read through the read-only handle: n=%d err=%v", n, err)
	}
	if _, err := reader.Exec(`CREATE TABLE written_by_a_reader (n INTEGER)`); err == nil {
		t.Fatal("a read-only handle wrote to the database")
	}
}

// The DSN is a URI, so the path is escaped: a bare path is cut at its first '?'
// by the driver and would open a different file.
func TestConnPolicyOpensPathsWithURISyntaxInThem(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "odd ?name #1 50%")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	writer, err := statedb.OpenConn(path, statedb.ReadWrite)
	if err != nil {
		t.Fatalf("OpenConn: %v", err)
	}
	if _, err := writer.Exec(`CREATE TABLE t (n INTEGER)`); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the database was not created at %s: %v", path, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(dir))
	if len(entries) != 1 {
		t.Fatalf("the open created files outside %s: %v", dir, entries)
	}
	reader, err := statedb.OpenConn(path, statedb.ReadOnly)
	if err != nil {
		t.Fatalf("read-only open: %v", err)
	}
	defer reader.Close()
	if _, err := reader.Exec(`SELECT n FROM t`); err != nil {
		t.Fatalf("the reader did not open the writer's file: %v", err)
	}
}

// PeekHubCluster answers from a control plane it may neither migrate nor be
// refused by: here one whose schema is ahead of this binary, which Open would
// refuse outright.
func TestPeekHubClusterReadsWithoutMigrating(t *testing.T) {
	db, path := clusterDB(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := db.JoinHubMember(statedb.HubMemberRow{InstanceID: "m1", Hostname: "h", PID: 42}); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.ClaimHubOwner(statedb.HubOwnerRow{
		Kind: "run", Key: "/srv/p", InstanceID: "m1", Meta: `{"dispatching":true}`, ClaimedAt: now,
	}, statedb.HubOwnerRow{}); err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	if ok, err := db.ClaimHubOwner(statedb.HubOwnerRow{
		Kind: "agent", Key: "ex1", InstanceID: "m1", ClaimedAt: now,
	}, statedb.HubOwnerRow{}); err != nil || !ok {
		t.Fatalf("claim agent: %v %v", ok, err)
	}
	db.Close()

	latest, err := statedb.LatestSchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO schema_migrations(version, applied_at, name) VALUES (?, ?, ?)`,
		latest+1, now.Format(time.RFC3339Nano), "9999_from_the_future.sql"); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	if reopened, err := statedb.Open(path); err == nil {
		reopened.Close()
		t.Fatal("Open accepted a schema from the future; this test no longer shows what it should")
	}

	members, owners, err := statedb.PeekHubCluster(path, "run")
	if err != nil {
		t.Fatalf("PeekHubCluster: %v", err)
	}
	if len(members) != 1 || members[0].InstanceID != "m1" || members[0].PID != 42 {
		t.Errorf("members = %+v, want m1 (pid 42)", members)
	}
	if len(owners) != 1 || owners[0].Key != "/srv/p" || owners[0].Meta != `{"dispatching":true}` ||
		!owners[0].ClaimedAt.Equal(now) {
		t.Errorf("owners = %+v, want the one run claim, as written", owners)
	}
}

func TestPeekHubClusterOnAControlPlaneWithoutClusterTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	members, owners, err := statedb.PeekHubCluster(path, "")
	if err != nil || members != nil || owners != nil {
		t.Fatalf("PeekHubCluster = %v, %v, %v; want nothing and no error", members, owners, err)
	}
	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var n int
	if err := check.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'schema_migrations'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("looking migrated the database (schema_migrations present: %d, %v)", n, err)
	}

	missing := filepath.Join(t.TempDir(), "state.db")
	if _, _, err := statedb.PeekHubCluster(missing, ""); err == nil {
		t.Fatal("PeekHubCluster on a missing file returned no error")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("PeekHubCluster created %s", missing)
	}
}
