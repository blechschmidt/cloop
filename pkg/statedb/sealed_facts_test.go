package statedb

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// sealedFactsDB is a migrated database holding sealed rows of every set under
// a mix of keys, the legacy construction included.
func sealedFactsDB(t *testing.T) (string, *DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	at := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	for _, k := range []KEKRow{
		{ID: "kek_old", Salt: "aa", State: "active", CheckValue: []byte{1}, CreatedAt: formatTimeRFC(at)},
		{ID: "kek_new", Salt: "bb", State: "primary", CheckValue: []byte{2}, CreatedAt: formatTimeRFC(at.Add(time.Hour))},
		{ID: "kek_gone", Salt: "", State: "retired", CreatedAt: formatTimeRFC(at.Add(-time.Hour))},
	} {
		if err := db.PutKEK(k); err != nil {
			t.Fatal(err)
		}
	}
	secret := func(id, key string) {
		if err := db.PutBrokerSecret(BrokerSecretRow{
			ID: id, Kind: "env", Name: id, Payload: []byte("ciphertext-" + id), KeyID: key,
			WrappedDEK: []byte("dek"), MetadataJSON: "{}", CreatedAt: formatTimeRFC(at),
		}); err != nil {
			t.Fatal(err)
		}
	}
	secret("s1", "kek_new")
	secret("s2", "kek_new")
	secret("s3", "kek_old")
	secret("s4", "legacy")
	session := func(id, key string, sealed []byte) {
		if err := db.PutSession(SessionRow{
			ID: id, Subject: id, Issuer: "https://idp", IssuedAt: at, LastSeen: at, ExpiresAt: at.Add(time.Hour),
			RefreshSealed: sealed, RefreshKeyID: key, RefreshWrappedDEK: []byte("dek"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	session("sess1", "kek_new", []byte("refresh"))
	session("sess2", "kek_old", nil) // holds nothing sealed: not counted
	if _, err := db.InsertHubTLS(HubTLSRow{
		ID: "ca", Kind: "ca", Serial: "01", CertPEM: "pem", KeyID: "kek_new", WrappedDEK: []byte("dek"),
		KeySealed: []byte("key"), NotBefore: at, NotAfter: at.Add(time.Hour), IssuedAt: at,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetBrokerMeta("secretbroker.salt", "00112233"); err != nil {
		t.Fatal(err)
	}
	return path, db
}

func readFacts(t *testing.T, path string) SealedFacts {
	t.Helper()
	conn, err := OpenConn(path, ReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	f, err := ReadSealedFacts(conn, "secretbroker.salt")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// ReadSealedFacts reads a backup it must not migrate; its counts must be the
// ones the live store's own counters give, set by set, or a restore preflight
// would judge a backup on different numbers than rotation and retirement do.
func TestSealedFactsMatchTheStoresOwnCounts(t *testing.T) {
	path, db := sealedFactsDB(t)
	facts := readFacts(t, path)

	for set, count := range map[string]func() (map[string]int, error){
		"secrets":  db.CountBrokerSecretsByKey,
		"sessions": db.CountSessionsByKey,
		"hub_tls":  db.CountHubTLSByKey,
	} {
		want, err := count()
		if err != nil {
			t.Fatal(err)
		}
		if got := facts.Rows[set]; fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: facts %v, store %v", set, got, want)
		}
	}
	if len(facts.Sets()) != len(sealedPopulations) {
		t.Errorf("sets %v; every sealed population must be read", facts.Sets())
	}
	if got := facts.ByKey(); got["kek_new"] != 4 || got["kek_old"] != 1 || got[LegacyKeyID] != 1 {
		t.Errorf("by key %v", got)
	}
	if len(facts.KEKs) != 3 {
		t.Errorf("%d keys read", len(facts.KEKs))
	}
	if facts.LegacySalt != "00112233" || string(facts.LegacySample) != "ciphertext-s4" {
		t.Errorf("legacy salt %q sample %q", facts.LegacySalt, facts.LegacySample)
	}
}

// A backup taken before a sealed set existed, or before its key column did,
// reads as the migration adding it would leave it — not as an error.
func TestSealedFactsOfAnOlderSchema(t *testing.T) {
	path, db := sealedFactsDB(t)
	_ = db.Close()
	raw, err := OpenConn(path, ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`DROP TABLE hub_tls`,
		`ALTER TABLE sessions DROP COLUMN refresh_sealed`,
		`DROP INDEX IF EXISTS idx_broker_secrets_key`,
		`ALTER TABLE broker_secrets DROP COLUMN key_id`,
		`DROP TABLE broker_keks`,
	} {
		if _, err := raw.Exec(stmt); err != nil {
			t.Logf("%s: %v", stmt, err)
		}
	}
	_ = raw.Close()

	facts := readFacts(t, path)
	if len(facts.KEKs) != 0 {
		t.Errorf("keys %v", facts.KEKs)
	}
	if _, ok := facts.Rows["hub_tls"]; ok {
		t.Error("a missing table has rows")
	}
	if _, ok := facts.Rows["sessions"]; ok {
		t.Error("a set without its sealed column has rows")
	}
	if got := facts.Rows["secrets"]; got[LegacyKeyID] != 4 || len(got) != 1 {
		t.Errorf("secrets without a key column must all read as legacy: %v", got)
	}
}

func TestReadAuditHeadMatchesTheHandles(t *testing.T) {
	path, db := sealedFactsDB(t)
	for i := 0; i < 3; i++ {
		if err := db.AppendAuditEvent(&AuditEvent{Actor: "t", EventType: "task.upsert", EntityType: "task", Payload: "{}"}); err != nil {
			t.Fatal(err)
		}
	}
	want, err := db.AuditHead()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := OpenConn(path, ReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	got, err := ReadAuditHead(conn)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastID != want.LastID || got.LastRowHash != want.LastRowHash || got.Rows != want.Rows ||
		!got.LastTimestamp.Equal(want.LastTimestamp) || got.FirstID != want.FirstID {
		t.Fatalf("read %+v, handle %+v", got, want)
	}

	// A database from before the audit tables is an empty chain.
	empty := filepath.Join(t.TempDir(), "old.db")
	old, err := OpenConn(empty, ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatal(err)
	}
	if h, err := ReadAuditHead(old); err != nil || h.LastID != 0 {
		t.Fatalf("%+v %v", h, err)
	}
	_ = old.Close()
}

// AbandonKEKs retires referenced keys — what RetireKEK refuses — and only
// the ones named.
func TestAbandonKEKsRetiresReferencedKeys(t *testing.T) {
	_, db := sealedFactsDB(t)
	if err := db.RetireKEK("kek_old", time.Now()); err == nil {
		t.Fatal("premise: RetireKEK refuses a referenced key")
	}
	done, err := db.AbandonKEKs([]string{"kek_old", "kek_new", "kek_gone", "kek_missing"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(done) != "[kek_old kek_new]" {
		t.Fatalf("retired %v", done)
	}
	keks, err := db.ListKEKs()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keks {
		if k.State != "retired" || k.Salt != "" || k.CheckValue != nil {
			t.Errorf("%s: %+v", k.ID, k)
		}
	}
	// The rows stay: what they held is lost, not erased.
	if n, _ := db.CountBrokerSecretsByKey(); n["kek_old"] != 1 {
		t.Errorf("rows %v", n)
	}
}
