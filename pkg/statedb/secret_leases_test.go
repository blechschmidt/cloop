package statedb

import (
	"errors"
	"testing"
	"time"
)

// TestSecretLeasesHandOverOnlyFromTheHolder covers the rows a lease outlives
// its hub process with (Task 20382): every write after the insert names the
// holder it expects, so a process that lost a lease — to the process that
// adopted its run — can neither extend nor delete it, and two processes racing
// to take one over cannot both win.
func TestSecretLeasesHandOverOnlyFromTheHolder(t *testing.T) {
	db := openTestDB(t)
	issued := time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)
	row := SecretLeaseRow{
		LeaseID: "lease_a", Holder: "hub_old", ExecutorID: "dev1", ProjectID: "/p", RunID: "run_1",
		Record: `{"grant_ids":["grant_1"]}`, IssuedAt: issued, ExpiresAt: issued.Add(15 * time.Minute),
	}
	if err := db.PutSecretLease(row); err != nil {
		t.Fatalf("PutSecretLease: %v", err)
	}
	got, err := db.GetSecretLease("lease_a")
	if err != nil {
		t.Fatalf("GetSecretLease: %v", err)
	}
	if got.Holder != "hub_old" || got.ExecutorID != "dev1" || got.ProjectID != "/p" || got.RunID != "run_1" ||
		got.Record != row.Record || !got.IssuedAt.Equal(row.IssuedAt) || !got.ExpiresAt.Equal(row.ExpiresAt) {
		t.Fatalf("round trip = %+v, want %+v", got, row)
	}

	later := issued.Add(25 * time.Minute)
	if ok, err := db.ExtendSecretLease("lease_a", "hub_old", later); err != nil || !ok {
		t.Fatalf("the holder's extension = %v, %v", ok, err)
	}
	if ok, err := db.ExtendSecretLease("lease_a", "hub_other", later.Add(time.Hour)); err != nil || ok {
		t.Fatalf("a non-holder's extension = %v, %v; want refused", ok, err)
	}

	// Two processes adopt the run; one gets the lease.
	if ok, err := db.TakeSecretLease("lease_a", "hub_old", "hub_new"); err != nil || !ok {
		t.Fatalf("first takeover = %v, %v", ok, err)
	}
	if ok, err := db.TakeSecretLease("lease_a", "hub_old", "hub_late"); err != nil || ok {
		t.Fatalf("second takeover from the same holder = %v, %v; want refused", ok, err)
	}
	got, _ = db.GetSecretLease("lease_a")
	if got.Holder != "hub_new" || !got.ExpiresAt.Equal(later) {
		t.Fatalf("after the takeover = %+v", got)
	}

	// The process that lost it cannot extend or delete it any more.
	if ok, _ := db.ExtendSecretLease("lease_a", "hub_old", later.Add(time.Hour)); ok {
		t.Fatal("the previous holder extended a lease it lost")
	}
	if ok, _ := db.DeleteSecretLease("lease_a", "hub_old"); ok {
		t.Fatal("the previous holder deleted a lease it lost")
	}
	if rows, err := db.ListSecretLeases(); err != nil || len(rows) != 1 {
		t.Fatalf("ListSecretLeases = %v, %v", rows, err)
	}
	if ok, err := db.DeleteSecretLease("lease_a", "hub_new"); err != nil || !ok {
		t.Fatalf("the holder's delete = %v, %v", ok, err)
	}
	if ok, err := db.DeleteSecretLease("lease_a", "hub_new"); err != nil || ok {
		t.Fatalf("a second delete = %v, %v; want a quiet no-op", ok, err)
	}
	if _, err := db.GetSecretLease("lease_a"); !errors.Is(err, ErrSecretLeaseNotFound) {
		t.Fatalf("GetSecretLease after delete = %v, want ErrSecretLeaseNotFound", err)
	}
	if err := db.PutSecretLease(SecretLeaseRow{Holder: "x"}); err == nil {
		t.Fatal("a lease without an id was recorded")
	}
}
