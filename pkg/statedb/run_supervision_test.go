package statedb

import (
	"errors"
	"testing"
	"time"
)

// TestLeaseRevocationsOutliveTheirHolder covers the record a lease revocation
// leaves (Task 20419): a revocation made while nobody held the lease is still
// there for the member that reaches its workload, a second revocation re-opens
// it without weakening a kill, and only an enforced one is ever pruned.
func TestLeaseRevocationsOutliveTheirHolder(t *testing.T) {
	db := openTestDB(t)
	at := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	if err := db.PutLeaseRevocation(LeaseRevocationRow{
		LeaseID: "lease_a", Action: "kill", Reason: "incident 42", Actor: "alice",
		ExecutorID: "ctr", ProjectID: "/p", Holder: "hub_dead", RevokedAt: at,
	}); err != nil {
		t.Fatalf("PutLeaseRevocation: %v", err)
	}
	if err := db.PutLeaseRevocation(LeaseRevocationRow{
		LeaseID: "lease_a", GrantID: "grant_2", Reason: "one grant", Actor: "bob", RevokedAt: at,
	}); err != nil {
		t.Fatalf("PutLeaseRevocation(grant): %v", err)
	}
	revs, err := db.LeaseRevocations("lease_a")
	if err != nil || len(revs) != 2 {
		t.Fatalf("LeaseRevocations = %+v, %v; want two", revs, err)
	}
	whole := revs[0]
	if whole.GrantID != "" || whole.Action != "kill" || whole.Holder != "hub_dead" || !whole.RevokedAt.Equal(at) ||
		!whole.Pending() || revs[1].GrantID != "grant_2" || revs[1].Action != "scrub" {
		t.Fatalf("revocations = %+v", revs)
	}

	if ok, err := db.MarkLeaseRevocationEnforced("lease_a", "", "hub_b", "taken back on adoption", at.Add(time.Minute)); err != nil || !ok {
		t.Fatalf("MarkLeaseRevocationEnforced = %v, %v", ok, err)
	}
	if ok, _ := db.MarkLeaseRevocationEnforced("lease_a", "", "hub_c", "again", at.Add(2*time.Minute)); ok {
		t.Fatal("a revocation already enforced was enforced a second time")
	}
	if err := db.NoteLeaseRevocation("lease_a", "", "overwritten"); err != nil {
		t.Fatal(err)
	}
	pending, err := db.ListLeaseRevocations(true)
	if err != nil || len(pending) != 1 || pending[0].GrantID != "grant_2" {
		t.Fatalf("pending = %+v, %v; want only the grant's", pending, err)
	}
	revs, _ = db.LeaseRevocations("lease_a")
	if revs[0].EnforcedBy != "hub_b" || revs[0].Detail != "taken back on adoption" {
		t.Fatalf("the enforced revocation was changed by a later note: %+v", revs[0])
	}

	// Revoked again, with a gentler action: re-opened, still a kill, first
	// time kept, latest reason.
	if err := db.PutLeaseRevocation(LeaseRevocationRow{
		LeaseID: "lease_a", Action: "scrub", Reason: "still compromised", Actor: "carol", RevokedAt: at.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	revs, _ = db.LeaseRevocations("lease_a")
	if !revs[0].Pending() || revs[0].Action != "kill" || revs[0].Reason != "still compromised" ||
		revs[0].Actor != "carol" || !revs[0].RevokedAt.Equal(at) || revs[0].Holder != "hub_dead" {
		t.Fatalf("re-revoked = %+v", revs[0])
	}

	// Only enforced rows are pruned.
	if _, err := db.MarkLeaseRevocationEnforced("lease_a", "", "hub_b", "", at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n, err := db.PruneLeaseRevocations(at.Add(48 * time.Hour)); err != nil || n != 1 {
		t.Fatalf("PruneLeaseRevocations = %d, %v; want the enforced one", n, err)
	}
	revs, _ = db.LeaseRevocations("lease_a")
	if len(revs) != 1 || revs[0].GrantID != "grant_2" {
		t.Fatalf("after the prune = %+v, want the pending grant revocation kept", revs)
	}
	if err := db.PutLeaseRevocation(LeaseRevocationRow{}); err == nil {
		t.Fatal("a revocation with no lease was recorded")
	}
}

// TestDispatchIntentsTrackAWorkloadUntilItsRunIsRecorded covers the intent a
// dispatch writes before its workload exists (Task 20419).
func TestDispatchIntentsTrackAWorkloadUntilItsRunIsRecorded(t *testing.T) {
	db := openTestDB(t)
	if err := db.PutDispatchIntent(DispatchIntentRow{
		RunID: "run_1", InstanceID: "hub_a", ExecutorID: "ctr", Driver: "container",
		ProjectPath: "/p", LeaseIDs: []string{"lease_a", "lease_b"},
	}); err != nil {
		t.Fatalf("PutDispatchIntent: %v", err)
	}
	got, err := db.GetDispatchIntent("run_1")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != DispatchIntentDispatching || got.HandleID != "" || len(got.LeaseIDs) != 2 ||
		got.LeaseIDs[1] != "lease_b" || got.CreatedAt.IsZero() {
		t.Fatalf("intent = %+v", got)
	}
	if ok, err := db.MarkDispatchStarted("run_1", "c-123", []string{"egress_1"}); err != nil || !ok {
		t.Fatalf("MarkDispatchStarted = %v, %v", ok, err)
	}
	if ok, _ := db.MarkDispatchStarted("run_missing", "c-9", nil); ok {
		t.Fatal("an intent nobody wrote was completed")
	}
	if err := db.NoteDispatchIntent("run_1", "could not stop it yet"); err != nil {
		t.Fatal(err)
	}
	all, err := db.ListDispatchIntents()
	if err != nil || len(all) != 1 || all[0].HandleID != "c-123" || all[0].State != DispatchIntentStarted ||
		len(all[0].EgressIDs) != 1 || all[0].Detail != "could not stop it yet" {
		t.Fatalf("intents = %+v, %v", all, err)
	}
	if ok, err := db.DeleteDispatchIntentForHandle("ctr", "c-123"); err != nil || !ok {
		t.Fatalf("DeleteDispatchIntentForHandle = %v, %v", ok, err)
	}
	if _, err := db.GetDispatchIntent("run_1"); !errors.Is(err, ErrDispatchIntentNotFound) {
		t.Fatalf("after the run was recorded: %v, want not found", err)
	}
	if err := db.DeleteDispatchIntent("run_1"); err != nil {
		t.Fatalf("deleting an intent twice: %v", err)
	}
	if err := db.PutDispatchIntent(DispatchIntentRow{}); err == nil {
		t.Fatal("an intent with no run id was recorded")
	}
}

// TestClaimingAHandleRowIsACompareAndSwap: of two hub processes adopting one
// workload row, only one records itself as its owner (Task 20419), and the
// claim leaves the row's other extras alone.
func TestClaimingAHandleRowIsACompareAndSwap(t *testing.T) {
	db := openTestDB(t)
	if err := db.PutExecutorHandle(ExecutorHandleRow{
		HandleID: "c-1", ExecutorID: "ctr", Driver: "container", ExternalID: "cloop-p-1",
		MetaJSON: MarshalHandleMeta(map[string]string{"hub_instance": "hub_dead", "runtime": "docker"}),
	}); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.ClaimExecutorHandleMeta("c-1", "hub_instance", "hub_dead", "hub_b"); err != nil || !ok {
		t.Fatalf("the first claim = %v, %v", ok, err)
	}
	if ok, err := db.ClaimExecutorHandleMeta("c-1", "hub_instance", "hub_dead", "hub_c"); err != nil || ok {
		t.Fatalf("a second claim from the same reading = %v, %v; want refused", ok, err)
	}
	if ok, _ := db.ClaimExecutorHandleMeta("c-1", "hub_instance", "hub_dead", "hub_b"); !ok {
		t.Error("the owner's own repeated claim was refused")
	}
	row, err := db.GetExecutorHandle("c-1")
	if err != nil {
		t.Fatal(err)
	}
	meta := UnmarshalHandleMeta(row.MetaJSON)
	if meta["hub_instance"] != "hub_b" || meta["runtime"] != "docker" {
		t.Fatalf("meta after the claim = %v", meta)
	}
	if ok, err := db.ClaimExecutorHandleMeta("c-missing", "hub_instance", "", "hub_b"); err != nil || ok {
		t.Fatalf("claiming a row that is gone = %v, %v", ok, err)
	}
	// A row written before clustering carries no owner: claimed from "".
	if err := db.PutExecutorHandle(ExecutorHandleRow{HandleID: "c-2", ExecutorID: "ctr", ExternalID: "n"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.ClaimExecutorHandleMeta("c-2", "hub_instance", "", "hub_b"); err != nil || !ok {
		t.Fatalf("claiming an unowned row = %v, %v", ok, err)
	}
}
