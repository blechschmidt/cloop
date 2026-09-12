package statedb_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// The concurrency contract of hub_instances is a compare-and-swap, and these
// tests exercise it as one: every case is "what the caller observed" versus
// "what the row actually is now". That is the only property the fence rests on
// — if a CAS can succeed against a row that changed, two hubs can both believe
// they hold the lease, and every higher-level guarantee in pkg/hublease is
// void.

func hubLeaseDB(t *testing.T) *statedb.DB {
	t.Helper()
	db, err := statedb.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func mustAcquire(t *testing.T, db *statedb.DB, instance string, expect statedb.HubLeaseRow) statedb.HubLeaseRow {
	t.Helper()
	row := statedb.HubLeaseRow{
		Scope:      statedb.HubScope,
		InstanceID: instance,
		Hostname:   "host-a",
		PID:        4242,
		BootID:     "boot-1",
	}
	ok, err := db.AcquireHubLease(row, expect)
	if err != nil {
		t.Fatalf("AcquireHubLease(%s): %v", instance, err)
	}
	if !ok {
		t.Fatalf("AcquireHubLease(%s) = false, want the lease to be taken", instance)
	}
	got, err := db.GetHubLease(statedb.HubScope)
	if err != nil {
		t.Fatalf("GetHubLease: %v", err)
	}
	return got
}

func TestGetHubLease_AbsentIsASentinel(t *testing.T) {
	db := hubLeaseDB(t)

	_, err := db.GetHubLease(statedb.HubScope)
	if !errors.Is(err, statedb.ErrHubLeaseNotFound) {
		t.Fatalf("GetHubLease on a fresh db = %v, want ErrHubLeaseNotFound", err)
	}
}

func TestAcquireHubLease_FirstTakeSucceeds(t *testing.T) {
	db := hubLeaseDB(t)

	row := mustAcquire(t, db, "hub_a", statedb.HubLeaseRow{})

	if row.InstanceID != "hub_a" {
		t.Errorf("InstanceID = %q, want hub_a", row.InstanceID)
	}
	if !row.Held() {
		t.Error("Held() = false, want true for a freshly taken lease")
	}
	if row.HeartbeatAt.IsZero() {
		t.Error("HeartbeatAt is zero — the acquiring write must also be the first beat, " +
			"or the lease reads as infinitely stale the moment it is written")
	}
	if row.Hostname != "host-a" || row.PID != 4242 || row.BootID != "boot-1" {
		t.Errorf("identity not round-tripped: %+v", row)
	}
}

func TestAcquireHubLease_SecondTakeIsRefusedWhileHeld(t *testing.T) {
	db := hubLeaseDB(t)
	mustAcquire(t, db, "hub_a", statedb.HubLeaseRow{})

	// hub_b saw no row (it raced hub_a's insert) and tries anyway.
	ok, err := db.AcquireHubLease(
		statedb.HubLeaseRow{Scope: statedb.HubScope, InstanceID: "hub_b"},
		statedb.HubLeaseRow{})
	if err != nil {
		t.Fatalf("AcquireHubLease: %v", err)
	}
	if ok {
		t.Fatal("a second acquire against a held lease succeeded — the fence does not fence")
	}

	after, err := db.GetHubLease(statedb.HubScope)
	if err != nil {
		t.Fatalf("GetHubLease: %v", err)
	}
	if after.InstanceID != "hub_a" {
		t.Errorf("holder = %q after a refused acquire, want hub_a to be untouched", after.InstanceID)
	}
}

func TestAcquireHubLease_StaleObservationLoses(t *testing.T) {
	db := hubLeaseDB(t)
	observed := mustAcquire(t, db, "hub_a", statedb.HubLeaseRow{})

	// hub_b read the row and judged it takeable. Before it writes, hub_a
	// heartbeats — which is exactly the race the CAS exists to lose.
	ok, err := db.RenewHubLease(statedb.HubScope, "hub_a", time.Now().UTC().Add(time.Second))
	if err != nil || !ok {
		t.Fatalf("RenewHubLease: ok=%v err=%v", ok, err)
	}

	ok, err = db.AcquireHubLease(
		statedb.HubLeaseRow{Scope: statedb.HubScope, InstanceID: "hub_b"}, observed)
	if err != nil {
		t.Fatalf("AcquireHubLease: %v", err)
	}
	if ok {
		t.Fatal("acquire succeeded against a row that changed after it was observed — " +
			"a holder that renews mid-takeover would be silently evicted")
	}
}

func TestAcquireHubLease_TakesOverAnObservedRow(t *testing.T) {
	db := hubLeaseDB(t)
	observed := mustAcquire(t, db, "hub_a", statedb.HubLeaseRow{})

	// hub_b observed the row and nothing changed since, so the takeover lands.
	row := mustAcquire(t, db, "hub_b", observed)

	if row.InstanceID != "hub_b" {
		t.Errorf("holder = %q after takeover, want hub_b", row.InstanceID)
	}
	if !row.ReleasedAt.IsZero() {
		t.Error("released_at survived a takeover — the new holder would read as released")
	}
}

func TestRenewHubLease_FencedOnInstanceID(t *testing.T) {
	db := hubLeaseDB(t)
	observed := mustAcquire(t, db, "hub_a", statedb.HubLeaseRow{})
	mustAcquire(t, db, "hub_b", observed)

	// hub_a was taken over while it was paused. Its next beat must report the
	// loss rather than stamping its heartbeat onto hub_b's row: this is the
	// signal that makes a paused hub stand down instead of running on as a
	// second control plane.
	ok, err := db.RenewHubLease(statedb.HubScope, "hub_a", time.Now().UTC())
	if err != nil {
		t.Fatalf("RenewHubLease: %v", err)
	}
	if ok {
		t.Fatal("a superseded instance renewed the lease — fencing is not enforced")
	}

	after, _ := db.GetHubLease(statedb.HubScope)
	if after.InstanceID != "hub_b" {
		t.Errorf("holder = %q, want hub_b to still hold it", after.InstanceID)
	}
}

func TestReleaseHubLease_CannotFreeASuccessorsClaim(t *testing.T) {
	db := hubLeaseDB(t)
	observed := mustAcquire(t, db, "hub_a", statedb.HubLeaseRow{})
	mustAcquire(t, db, "hub_b", observed)

	// hub_a's deferred Release runs late, after it already lost the lease.
	ok, err := db.ReleaseHubLease(statedb.HubScope, "hub_a", time.Now().UTC())
	if err != nil {
		t.Fatalf("ReleaseHubLease: %v", err)
	}
	if ok {
		t.Fatal("a superseded instance released the lease — a late defer would " +
			"unlock the control plane while its successor was serving")
	}

	after, _ := db.GetHubLease(statedb.HubScope)
	if !after.Held() {
		t.Error("lease reads as free after a stale release; hub_b still holds it")
	}
}

func TestReleaseHubLease_KeepsTheRowForForensics(t *testing.T) {
	db := hubLeaseDB(t)
	mustAcquire(t, db, "hub_a", statedb.HubLeaseRow{})

	ok, err := db.ReleaseHubLease(statedb.HubScope, "hub_a", time.Now().UTC())
	if err != nil || !ok {
		t.Fatalf("ReleaseHubLease: ok=%v err=%v", ok, err)
	}

	row, err := db.GetHubLease(statedb.HubScope)
	if err != nil {
		t.Fatalf("GetHubLease after release: %v", err)
	}
	if row.InstanceID != "hub_a" {
		t.Errorf("InstanceID = %q, want the last holder to remain visible", row.InstanceID)
	}
	if row.ReleasedAt.IsZero() {
		t.Error("ReleasedAt is zero after a release")
	}
	if row.Held() {
		t.Error("Held() = true after release")
	}
}

func TestReleaseHubLease_IsIdempotent(t *testing.T) {
	db := hubLeaseDB(t)
	mustAcquire(t, db, "hub_a", statedb.HubLeaseRow{})

	if ok, err := db.ReleaseHubLease(statedb.HubScope, "hub_a", time.Now().UTC()); err != nil || !ok {
		t.Fatalf("first release: ok=%v err=%v", ok, err)
	}
	// Server.Shutdown and the command's deferred Release can both fire; the
	// second must be a quiet no-op rather than an error on a clean exit path.
	ok, err := db.ReleaseHubLease(statedb.HubScope, "hub_a", time.Now().UTC())
	if err != nil {
		t.Fatalf("second release: %v", err)
	}
	if ok {
		t.Error("second release reported a change; releasing twice should do nothing")
	}
}

func TestClearHubLease_RefusesWhenTheHeartbeatMoved(t *testing.T) {
	db := hubLeaseDB(t)
	observed := mustAcquire(t, db, "hub_a", statedb.HubLeaseRow{})

	// The operator's staleness check passed, then the holder came back.
	if ok, err := db.RenewHubLease(statedb.HubScope, "hub_a", time.Now().UTC().Add(time.Minute)); err != nil || !ok {
		t.Fatalf("RenewHubLease: ok=%v err=%v", ok, err)
	}

	ok, err := db.ClearHubLease(statedb.HubScope, observed, time.Now().UTC())
	if err != nil {
		t.Fatalf("ClearHubLease: %v", err)
	}
	if ok {
		t.Fatal("cleared a lease that was renewed after the staleness check — " +
			"the operator gate would be advisory rather than enforced")
	}
	if row, _ := db.GetHubLease(statedb.HubScope); !row.Held() {
		t.Error("lease was released despite the refused clear")
	}
}

func TestClearHubLease_SucceedsOnTheObservedRow(t *testing.T) {
	db := hubLeaseDB(t)
	observed := mustAcquire(t, db, "hub_a", statedb.HubLeaseRow{})

	ok, err := db.ClearHubLease(statedb.HubScope, observed, time.Now().UTC())
	if err != nil || !ok {
		t.Fatalf("ClearHubLease: ok=%v err=%v", ok, err)
	}
	row, _ := db.GetHubLease(statedb.HubScope)
	if row.Held() {
		t.Error("lease still held after a successful clear")
	}
}

func TestHubLease_RejectsAnEmptyInstanceID(t *testing.T) {
	db := hubLeaseDB(t)

	// An empty instance id would make every fenced write match every row,
	// turning renewal and release into unconditional statements.
	if _, err := db.AcquireHubLease(statedb.HubLeaseRow{Scope: statedb.HubScope}, statedb.HubLeaseRow{}); err == nil {
		t.Error("AcquireHubLease accepted an empty instance id")
	}
	if _, err := db.RenewHubLease(statedb.HubScope, "", time.Now()); err == nil {
		t.Error("RenewHubLease accepted an empty instance id")
	}
	if _, err := db.ReleaseHubLease(statedb.HubScope, "", time.Now()); err == nil {
		t.Error("ReleaseHubLease accepted an empty instance id")
	}
	if _, err := db.ClearHubLease(statedb.HubScope, statedb.HubLeaseRow{}, time.Now()); err == nil {
		t.Error("ClearHubLease accepted an empty observed instance id")
	}
}

// Timestamps round-trip through RFC3339 TEXT, and the CAS compares them as
// strings. A whole-second instant renders without a fractional part, so if the
// format ever changed to something lossy the CAS would start matching rows it
// should not — this pins both the round trip and the exact-equality behaviour
// the fence depends on.
func TestHubLease_TimestampsRoundTripExactly(t *testing.T) {
	db := hubLeaseDB(t)

	for _, at := range []time.Time{
		time.Date(2026, 9, 12, 17, 23, 15, 0, time.UTC),           // whole second
		time.Date(2026, 9, 12, 17, 23, 15, 500_000_000, time.UTC), // half second
		time.Date(2026, 9, 12, 17, 23, 15, 1, time.UTC),           // one nanosecond
	} {
		row := statedb.HubLeaseRow{
			Scope: statedb.HubScope, InstanceID: "hub_a",
			AcquiredAt: at, HeartbeatAt: at,
		}
		prev, err := db.GetHubLease(statedb.HubScope)
		if errors.Is(err, statedb.ErrHubLeaseNotFound) {
			prev = statedb.HubLeaseRow{}
		} else if err != nil {
			t.Fatalf("GetHubLease: %v", err)
		}
		if ok, err := db.AcquireHubLease(row, prev); err != nil || !ok {
			t.Fatalf("AcquireHubLease(%s): ok=%v err=%v", at, ok, err)
		}
		got, err := db.GetHubLease(statedb.HubScope)
		if err != nil {
			t.Fatalf("GetHubLease: %v", err)
		}
		if !got.HeartbeatAt.Equal(at) {
			t.Errorf("HeartbeatAt round trip = %v, want %v", got.HeartbeatAt, at)
		}
	}
}
