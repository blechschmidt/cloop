package secretstore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
)

// TestRelabeledLeaseIsRecordedForTheProcessThatAdoptsIt (Task 20432): a lease
// relabeled because its executor's recorded labels changed carries the new
// labels in its row, so the process taking the run over judges its grants by
// them — and only the process holding the record may rewrite it.
func TestRelabeledLeaseIsRecordedForTheProcessThatAdoptsIt(t *testing.T) {
	db, _ := openTestDB(t)
	a := holderBroker(t, db, "hub_a")
	ctx := context.Background()
	if _, err := a.Mint(ctx, secretbroker.MintRequest{
		Name: "eu-only", Kind: secretbroker.KindEnv,
		Payload: []byte(`{"EU_TOKEN":"` + testEnvVal + `"}`), Actor: "test",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := a.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: "eu-only", Subject: mustSubject(t, "label:region=eu"),
		Constraints: secretbroker.Constraints{EnvKeys: []string{"EU_TOKEN"}}, TTL: time.Hour, Actor: "test",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	req := secretbroker.NewRequester(secretbroker.RecordedExecutor{ID: "edge-01", Labels: map[string]string{"region": "eu"}},
		secretbroker.RequestScope{ProjectID: "/srv/app", RunID: "run_relabel"})
	lease, err := a.LeaseFor(ctx, req, "ui")
	if err != nil || lease.Empty() {
		t.Fatalf("lease = %v, %v; want the label grant", lease, err)
	}

	if changed, err := a.RelabelLease(lease.ID, map[string]string{"region": "us"}); !changed || err != nil {
		t.Fatalf("RelabelLease = %v, %v", changed, err)
	}
	b := holderBroker(t, db, "hub_b")
	rec, err := b.LeaseRecordFor(lease.ID)
	if err != nil {
		t.Fatalf("LeaseRecordFor: %v", err)
	}
	if !secretbroker.SameLabels(rec.Requester.Labels, map[string]string{"region": "us"}) ||
		rec.Requester.RunID != "run_relabel" || rec.Requester.ExecutorID != "edge-01" || len(rec.GrantIDs) != 1 {
		t.Fatalf("record after the relabel = %+v", rec)
	}

	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	if wrote, err := store.SetLeaseLabels(lease.ID, "hub_b", map[string]string{"region": "eu"}); wrote || err != nil {
		t.Errorf("a process not holding the record rewrote it: %v, %v", wrote, err)
	}
	// The process taking it over judges the label grant by the recorded
	// labels: the lease's only grant no longer stands, so the lease is
	// refused, which the hub answers by taking it back whole.
	if _, err := b.Restore(ctx, lease.ID); !errors.Is(err, secretbroker.ErrInvalidGrant) {
		t.Errorf("restoring a lease whose only grant its recorded labels no longer match = %v; want it refused", err)
	}
}
