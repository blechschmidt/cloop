package executor

// Unit tests for the lease→handle index, and specifically for the one rule in
// it that is a security decision rather than bookkeeping: what an *unrecorded*
// binding on a rehydrated handle means (Task 20231).
//
// The rule lives here, in the shared type, rather than in each driver, because
// four copies of "an adopted handle with no recorded bindings holds nothing"
// would eventually become three copies of that and one that got it right — and
// the wrong answer is silent. It does not fail a build, it does not log; it
// turns a revocation that reached nothing into a report that says revoked.
//
// The end-to-end proof that a revocation survives a restart is in
// tests/security/revocation_test.go, against a real driver running a real
// process. What is pinned here is the vocabulary those tests depend on.

import (
	"errors"
	"strings"
	"testing"
)

func revocableBinding(leaseID, grantID string) SecretBinding {
	return SecretBinding{
		LeaseID:    leaseID,
		GrantID:    grantID,
		SecretName: "github-ci",
		Kind:       "github_pat",
		EnvKeys:    []string{"GITHUB_TOKEN"},
	}
}

// TestLeaseIndexAdoptRestoresRecordedBindings is the positive half: a record
// that says what it held is believed, and the handle becomes reachable by a
// revocation exactly as a freshly started one is.
func TestLeaseIndexAdoptRestoresRecordedBindings(t *testing.T) {
	li := NewLeaseIndex()
	li.Adopt(HandleRecord{
		HandleID:        "h1",
		Secrets:         []SecretBinding{revocableBinding("lease_a", "grant_a")},
		SecretsRecorded: true,
	})

	if !li.Holds("lease_a") {
		t.Fatal("an adopted handle with recorded bindings is not reported as holding its lease")
	}
	if got := li.Leases(); len(got) != 1 || got[0] != "lease_a" {
		t.Errorf("Leases() = %v, want [lease_a]", got)
	}
	if err := li.UnresolvedError(); err != nil {
		t.Errorf("a fully rebuilt index reports doubt it does not have: %v", err)
	}

	held := li.Handles(RevokeRequest{LeaseID: "lease_a"})
	if len(held["h1"]) != 1 {
		t.Fatalf("Handles did not return the adopted handle's bindings: %+v", held)
	}
	// A grant-scoped revocation must still narrow correctly after adoption —
	// the binding has to survive the round trip whole, not just its lease id.
	if narrowed := li.Handles(RevokeRequest{LeaseID: "lease_a", GrantID: "grant_b"}); len(narrowed) != 0 {
		t.Errorf("a revocation scoped to another grant matched the adopted handle: %+v", narrowed)
	}
}

// TestLeaseIndexAdoptOfAnEmptyRecordHoldsNothing keeps the cautious path from
// swallowing the ordinary one.
//
// A workload that genuinely held no leases is the common case, and a record
// saying so is an answer. If it were treated as doubt, every restart would put
// every executor into permanent failure and the distinction would be worthless.
func TestLeaseIndexAdoptOfAnEmptyRecordHoldsNothing(t *testing.T) {
	li := NewLeaseIndex()
	li.Adopt(HandleRecord{HandleID: "h1", SecretsRecorded: true})

	if li.Holds("lease_a") {
		t.Error("a handle recorded as holding nothing is reported as a holder")
	}
	if err := li.UnresolvedError(); err != nil {
		t.Errorf("a record that authoritatively says `no leases` produced doubt: %v", err)
	}
}

// TestLeaseIndexAdoptOfAnUnrecordedRecordIsDoubtNotAbsence is the rule this
// file exists for.
//
// nil bindings and unrecorded bindings are the same empty slice, and reading
// the second as the first is how a revocation misses a holder. Holds must
// answer true — for *any* lease, since nothing here can say which — so the
// executor is asked rather than skipped, and UnresolvedError must be able to
// name the handle so the driver's report is actionable.
func TestLeaseIndexAdoptOfAnUnrecordedRecordIsDoubtNotAbsence(t *testing.T) {
	li := NewLeaseIndex()
	li.Adopt(HandleRecord{HandleID: "h-legacy"})

	if !li.Holds("lease_a") {
		t.Fatal("a handle whose bindings could not be rebuilt answered Holds false.\n" +
			"  The revocation fan-out skips a non-holder, so the executor is never asked and\n" +
			"  the fleet aggregate reads `revoked` for a credential nobody checked.")
	}
	if !li.Holds("some-entirely-other-lease") {
		t.Error("the doubt must not be scoped to one lease: nothing records which lease an " +
			"unrecorded handle held, so every lease is in question")
	}

	// Leases() is the exception and deliberately so: there is no honest way to
	// name a lease nobody wrote down.
	if got := li.Leases(); len(got) != 0 {
		t.Errorf("Leases() invented %v for a handle with no recorded bindings", got)
	}

	err := li.UnresolvedError()
	if err == nil {
		t.Fatal("UnresolvedError returned nil for an unresolved handle")
	}
	if !errors.Is(err, ErrBindingsUnresolved) {
		t.Errorf("the error does not match the sentinel callers filter on: %v", err)
	}
	for _, want := range []string{"h-legacy", "rotate it at the source"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the diagnostic must contain %q so an operator can act on it; got %q", want, err)
		}
	}
}

// TestLeaseIndexDoubtClearsWhenTheWorkloadEnds bounds the blast radius.
//
// One pre-upgrade row must not poison every revocation on an executor for the
// life of the process. The doubt is about a specific running workload, so it
// ends when that workload does — which is the same Release call the driver
// already makes on every terminal transition.
func TestLeaseIndexDoubtClearsWhenTheWorkloadEnds(t *testing.T) {
	li := NewLeaseIndex()
	li.Adopt(HandleRecord{HandleID: "h-legacy"})
	li.Adopt(HandleRecord{
		HandleID:        "h-known",
		Secrets:         []SecretBinding{revocableBinding("lease_a", "")},
		SecretsRecorded: true,
	})

	li.Release("h-legacy")
	if err := li.UnresolvedError(); err != nil {
		t.Errorf("the doubt outlived the workload it described: %v", err)
	}
	// Releasing the unresolved handle must not have taken the real binding
	// with it — that would be the opposite failure, an executor forgetting a
	// lease it is genuinely holding.
	if !li.Holds("lease_a") {
		t.Error("releasing an unresolved handle dropped an unrelated handle's binding")
	}
	if li.Holds("lease_b") {
		t.Error("Holds still reports doubt after the unresolved handle was released")
	}
}

// TestLeaseIndexBindResolvesDoubt covers the ordering a driver can produce:
// adopt marks a handle unresolved, and a later Bind for the same handle is the
// authoritative answer arriving. The cautious state must not be sticky.
func TestLeaseIndexBindResolvesDoubt(t *testing.T) {
	li := NewLeaseIndex()
	li.MarkUnresolved("h1", "")
	li.Bind("h1", []SecretBinding{revocableBinding("lease_a", "")})

	if err := li.UnresolvedError(); err != nil {
		t.Errorf("Bind did not clear the doubt it answered: %v", err)
	}
	if !li.Holds("lease_a") {
		t.Error("Bind after MarkUnresolved did not record the binding")
	}

	// The subtle case: a Bind that records *nothing* still answered the
	// question. Leaving the mark standing because the slice came back empty
	// would make every later revocation on this executor report a failure
	// about a workload whose bindings are in fact known.
	li.MarkUnresolved("h2", "")
	li.Bind("h2", []SecretBinding{{LeaseID: "lease_b"}}) // names a lease, delivered nothing
	if err := li.UnresolvedError(); err != nil {
		t.Errorf("a Bind carrying no revocable material left the handle in doubt: %v", err)
	}
}

// TestLeaseIndexNilIsSafe pins the degraded path.
//
// This type sits on the revocation path of four drivers, and a driver
// constructed without one (an embedder, a test double) must not take the hub
// down with a nil dereference in the middle of an incident. Tracking nothing
// is the honest answer for an index that does not exist: such a driver never
// bound anything either.
func TestLeaseIndexNilIsSafe(t *testing.T) {
	var li *LeaseIndex
	li.Bind("h1", []SecretBinding{revocableBinding("lease_a", "")})
	li.Adopt(HandleRecord{HandleID: "h1"})
	li.MarkUnresolved("h1", "")
	li.Release("h1")

	if li.Holds("lease_a") {
		t.Error("a nil index claims to hold a lease")
	}
	if got := li.Leases(); got != nil {
		t.Errorf("Leases() on a nil index = %v, want nil", got)
	}
	if got := li.Handles(RevokeRequest{LeaseID: "lease_a"}); got != nil {
		t.Errorf("Handles() on a nil index = %v, want nil", got)
	}
	if err := li.UnresolvedError(); err != nil {
		t.Errorf("UnresolvedError() on a nil index = %v, want nil", err)
	}
}
