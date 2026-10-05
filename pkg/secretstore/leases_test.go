package secretstore_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// holderBroker is newBroker for a hub process that keeps lease records.
func holderBroker(t *testing.T, db *statedb.DB, holder string) *secretbroker.Broker {
	t.Helper()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	cipher, err := secretbroker.NewCipherWithKey(testKey())
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	b, err := secretbroker.New(store,
		secretbroker.WithCipher(cipher),
		secretbroker.WithAuditor(secretstore.NewAuditor(db)),
		secretbroker.WithLeaseRecords(holder))
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	return b
}

// TestLeaseSurvivesItsProcess is Task 20382 through a real database: a lease
// issued by one hub process is taken over by the next, opened afresh over the
// same file, with its requester intact — and the row it travelled in holds no
// credential.
func TestLeaseSurvivesItsProcess(t *testing.T) {
	db, path := openTestDB(t)
	a := holderBroker(t, db, "hub_a")
	ctx := context.Background()
	if _, err := a.Mint(ctx, secretbroker.MintRequest{
		Name: "claude", Kind: secretbroker.KindEnv,
		Payload: []byte(`{"CLAUDE_CODE_OAUTH_TOKEN":"` + testEnvVal + `"}`), Actor: "test",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := a.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: "claude", Subject: mustSubject(t, "project:/srv/app"),
		Constraints: secretbroker.Constraints{EnvKeys: []string{"CLAUDE_CODE_OAUTH_TOKEN"}},
		TTL:         2 * time.Hour, Actor: "test",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	req := secretbroker.Requester{
		ExecutorID: "edge-01", ProjectID: "/srv/app", RunID: "run_restart",
		Labels:   map[string]string{"site": "lab"},
		Withhold: map[string]string{"grant_other": "another user's personal credential"},
	}
	lease, err := a.LeaseFor(ctx, req, "ui")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	row, err := db.GetSecretLease(lease.ID)
	if err != nil {
		t.Fatalf("the lease has no row: %v", err)
	}
	if strings.Contains(row.Record, testEnvVal) {
		t.Fatalf("the lease record carries the credential: %s", row.Record)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// The next process: a new handle, a new broker, the same file.
	db2, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	b := holderBroker(t, db2, "hub_b")
	rec, err := b.LeaseRecordFor(lease.ID)
	if err != nil {
		t.Fatalf("LeaseRecordFor: %v", err)
	}
	if rec.Holder != "hub_a" || rec.Requester.RunID != "run_restart" || rec.Requester.Labels["site"] != "lab" ||
		rec.Requester.Withhold["grant_other"] == "" || rec.Actor != "ui" || len(rec.GrantIDs) != 1 ||
		len(rec.Kinds) != 1 || rec.Kinds[0] != secretbroker.KindEnv || !rec.ExpiresAt.Equal(lease.ExpiresAt) {
		t.Fatalf("record after the restart = %+v", rec)
	}
	taken, err := b.Restore(ctx, lease.ID)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if taken.ID != lease.ID || taken.RunID != "run_restart" {
		t.Fatalf("taken over = %+v", taken)
	}
	if _, err := b.Extend(ctx, lease.ID); err != nil {
		t.Fatalf("the new holder's Extend: %v", err)
	}
	b.Release(lease.ID)
	if recs, err := b.LeaseRecords(); err != nil || len(recs) != 0 {
		t.Fatalf("records after the release = %+v, %v", recs, err)
	}
}
