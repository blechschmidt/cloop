package statedb

import (
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/autoupdate"
)

func openAutoUpdateDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// An unconfigured fleet reads as "off", not as an error. "Nobody has set this"
// and "automatic upgrades are disabled" are the same operational state, and the
// overwhelmingly common one — putting an error path in front of it would mean
// every caller handling a condition that is not a problem.
func TestAutoUpdatePolicyDefaultsToDisabled(t *testing.T) {
	got, err := AutoUpdatePolicyFor(openAutoUpdateDB(t))
	if err != nil {
		t.Fatalf("reading an unset policy returned an error: %v", err)
	}
	if got.Policy.Enabled {
		t.Fatal("an unconfigured fleet reports automatic upgrades as enabled")
	}
}

func TestAutoUpdatePolicyRoundTrips(t *testing.T) {
	db := openAutoUpdateDB(t)
	want := autoupdate.Policy{Enabled: true, TargetVersion: "v1.4.0", MaxInFlight: 3}
	if err := SetAutoUpdatePolicy(db, want, "alice@example.com"); err != nil {
		t.Fatalf("set: %v", err)
	}

	got, err := AutoUpdatePolicyFor(db)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Policy != want {
		t.Fatalf("round trip changed the policy: got %+v want %+v", got.Policy, want)
	}
	if got.SetBy != "alice@example.com" {
		t.Fatalf("provenance lost: SetBy=%q", got.SetBy)
	}
	if got.SetAt.IsZero() {
		t.Fatal("SetAt was not recorded; the audit trail cannot say when the fleet was opened up")
	}
}

// The single-row CHECK is what stops the table drifting into holding two
// policies that disagree, so a second write must replace rather than add.
func TestSetAutoUpdatePolicyReplaces(t *testing.T) {
	db := openAutoUpdateDB(t)
	if err := SetAutoUpdatePolicy(db,
		autoupdate.Policy{Enabled: true, TargetVersion: "v1.0.0"}, "alice"); err != nil {
		t.Fatalf("first set: %v", err)
	}
	if err := SetAutoUpdatePolicy(db,
		autoupdate.Policy{Enabled: false, TargetVersion: "v2.0.0"}, "bob"); err != nil {
		t.Fatalf("second set: %v", err)
	}

	got, err := AutoUpdatePolicyFor(db)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Policy.Enabled || got.Policy.TargetVersion != "v2.0.0" || got.SetBy != "bob" {
		t.Fatalf("the second write did not replace the first: %+v (by %s)", got.Policy, got.SetBy)
	}

	var rows int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM autoupdate_policy`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Fatalf("autoupdate_policy holds %d rows, want exactly 1", rows)
	}
}

// A negative budget would reach Plan as MaxInFlight<=0 and resolve to the
// default, silently ignoring what the admin typed. Rejecting it at the boundary
// keeps the stored value and the applied value the same thing.
func TestSetAutoUpdatePolicyRejectsNegativeBudget(t *testing.T) {
	err := SetAutoUpdatePolicy(openAutoUpdateDB(t),
		autoupdate.Policy{Enabled: true, MaxInFlight: -1}, "alice")
	if err == nil {
		t.Fatal("a negative max_in_flight was accepted")
	}
}
