package ui

// The lease keepalive (Task 20349). A run's lease is issued for fifteen
// minutes; before the keepalive nothing renewed it, so the lease janitor swept
// every run's credentials a quarter of an hour in — files scrubbed on the
// device, git proxy sessions closed, App tokens destroyed at GitHub — however
// long the run still had to go.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// keepaliveClock is a settable time source shared by the broker and the test.
type keepaliveClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *keepaliveClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *keepaliveClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// keepaliveLease issues a real lease — a statedb-backed store, a real grant —
// from a broker whose clock the test drives, and registers it with the hub the
// way acquireSecretLease does, minus the goroutine: the test calls keepAlive
// itself, at the moments it chooses.
func keepaliveLease(t *testing.T, executorID string) (*secretLease, *secretbroker.Broker, *keepaliveClock) {
	t.Helper()
	dir := seedPATGrant(t, executorID, "ghp_keepalive0123456789abcdefghijkl")
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("secretstore.New: %v", err)
	}
	clock := &keepaliveClock{now: time.Now().UTC()}
	broker, err := secretbroker.New(store,
		secretbroker.WithAuditor(secretstore.NewAuditor(db)),
		secretbroker.WithClock(clock.Now))
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}
	lease, err := broker.LeaseFor(context.Background(), secretbroker.Requester{
		ExecutorID: executorID, ProjectID: "/srv/proj", RunID: "run_keepalive",
	}, "ui")
	if err != nil {
		t.Fatalf("LeaseFor: %v", err)
	}
	if len(lease.Materials) != 1 {
		t.Fatalf("lease carries %d materials, want the seeded grant", len(lease.Materials))
	}
	sl := &secretLease{broker: broker, lease: lease, expiry: lease.ExpiresAt}
	liveLeases.add(sl)
	t.Cleanup(func() { liveLeases.remove(lease.ID) })
	return sl, broker, clock
}

// TestLeaseKeepaliveOutlivesTheIssuedTTL is the regression: a run past its
// lease's issued deadline keeps its credential, because the janitor reads the
// extended deadline.
func TestLeaseKeepaliveOutlivesTheIssuedTTL(t *testing.T) {
	sl, _, clock := keepaliveLease(t, "edge-keepalive")
	issued := sl.lease.ExpiresAt

	// Eleven minutes in, inside the margin: the keepalive extends.
	clock.advance(11 * time.Minute)
	if !sl.keepAlive(context.Background(), clock.Now()) {
		t.Fatal("the keepalive stopped on a healthy lease")
	}
	if want := clock.Now().Add(secretbroker.DefaultMaxLeaseTTL); !sl.ExpiresAt().Equal(want) {
		t.Fatalf("lease deadline = %s, want one lease period from now (%s)", sl.ExpiresAt(), want)
	}

	// Past the issued deadline, the janitor leaves it alone.
	s := &Server{}
	if swept := s.sweepExpiredLeases(issued.Add(time.Minute)); len(swept) != 0 {
		t.Fatalf("the janitor swept an extended lease at its issued deadline: %+v", swept)
	}
	if !leaseIsRegistered(sl.lease.ID) {
		t.Fatal("the extended lease is no longer registered on the hub")
	}
	// The panel reports the deadline that actually binds.
	if got := sl.TTL(issued.Add(time.Minute)); got <= 0 {
		t.Errorf("remaining TTL after the issued deadline = %s, want the extension's", got)
	}
}

// TestLeaseKeepaliveStopsOnARevokedGrant: the extension re-checks the grant,
// so a revocation still lands within one lease period — the lease lapses on
// its current deadline and the janitor takes it back.
func TestLeaseKeepaliveStopsOnARevokedGrant(t *testing.T) {
	sl, broker, clock := keepaliveLease(t, "edge-revoked")
	grants, err := broker.ListGrants(secretbroker.GrantFilter{ActiveOnly: true})
	if err != nil || len(grants) != 1 {
		t.Fatalf("ListGrants = %d grants, %v; want the seeded one", len(grants), err)
	}
	if err := broker.Revoke(context.Background(), grants[0].ID, "operator"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	deadline := sl.ExpiresAt()

	clock.advance(11 * time.Minute)
	if sl.keepAlive(context.Background(), clock.Now()) {
		t.Fatal("the keepalive kept running although the lease's grant was revoked")
	}
	if !sl.ExpiresAt().Equal(deadline) {
		t.Fatalf("a refused extension moved the deadline from %s to %s", deadline, sl.ExpiresAt())
	}
	s := &Server{}
	swept := s.sweepExpiredLeases(deadline.Add(time.Second))
	if len(swept) != 1 || swept[0].LeaseID != sl.lease.ID {
		t.Fatalf("the janitor swept %+v at the unextended deadline, want the revoked lease", swept)
	}
}

// TestLeaseKeepaliveSkipsAFinishedWorkload: the liveness check wins over the
// deadline. A workload the executor reports finished is not extended.
func TestLeaseKeepaliveSkipsAFinishedWorkload(t *testing.T) {
	sl, _, clock := keepaliveLease(t, "edge-finished")
	asked := 0
	sl.setLiveness(func(context.Context) bool {
		asked++
		return false
	})
	deadline := sl.ExpiresAt()

	clock.advance(11 * time.Minute)
	if sl.keepAlive(context.Background(), clock.Now()) {
		t.Fatal("the keepalive kept running for a finished workload")
	}
	if asked != 1 {
		t.Errorf("liveness asked %d times, want once", asked)
	}
	if !sl.ExpiresAt().Equal(deadline) {
		t.Errorf("a finished workload's lease was extended to %s", sl.ExpiresAt())
	}
}

// TestLeaseKeepaliveWaitsForTheMargin: far from its deadline the lease is left
// alone — no broker call, no audit row, and certainly no liveness round trip
// to an edge device every minute.
func TestLeaseKeepaliveWaitsForTheMargin(t *testing.T) {
	sl, _, clock := keepaliveLease(t, "edge-early")
	sl.setLiveness(func(context.Context) bool {
		t.Error("liveness was asked although the deadline is outside the margin")
		return true
	})
	deadline := sl.ExpiresAt()

	clock.advance(time.Minute)
	if !sl.keepAlive(context.Background(), clock.Now()) {
		t.Fatal("the keepalive stopped far from the deadline")
	}
	if !sl.ExpiresAt().Equal(deadline) {
		t.Errorf("the lease was extended to %s while %s remained", sl.ExpiresAt(), deadline.Sub(clock.Now()))
	}
}

// TestAcquiredLeaseIsKeptAliveUntilClosed: every lease acquireSecretLease issues
// carries its keepalive, and Close stops it before releasing anything.
func TestAcquiredLeaseIsKeptAliveUntilClosed(t *testing.T) {
	dir := seedPATGrant(t, "sandbox-keepalive", "ghp_keepaliveacquire0123456789abcd")
	ex := stubExec{id: "sandbox-keepalive", caps: executor.Capabilities{
		SupportsSecretFiles: true, SecretFilesFromHostPath: false,
	}}
	lease := acquireSecretLease(dir, "/srv/proj", ex, "run_keepalive_acquire")
	if lease == nil {
		t.Fatal("no lease was issued, so this test would be vacuous")
	}
	if lease.stopKeepalive == nil {
		lease.Close()
		t.Fatal("acquireSecretLease issued a lease with no keepalive; it would lapse fifteen minutes into its run")
	}

	closed := make(chan struct{})
	go func() {
		lease.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return: stopping the keepalive hung")
	}
	lease.Close() // idempotent
	if leaseIsRegistered(lease.lease.ID) {
		t.Error("a closed lease is still registered on the hub")
	}
}
