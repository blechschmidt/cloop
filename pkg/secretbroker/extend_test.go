package secretbroker

// extend_test.go covers Broker.Extend (Task 20349): the in-place renewal the
// hub's dispatch path uses to keep a running workload's lease alive past
// DefaultMaxLeaseTTL without re-issuing material the sandbox cannot receive.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestExtendKeepsTheLeaseAndItsMaterial: the whole point of Extend over Renew.
// Same ID, same token, a later deadline — and an audited decision.
func TestExtendKeepsTheLeaseAndItsMaterial(t *testing.T) {
	b, _, auditor, clock := newTestBroker(t)
	ctx := context.Background()

	s := mintGitHub(t, b, "tok", "ghp_extendabletoken")
	grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"org/*"}}, 24*time.Hour)

	lease, err := b.Lease(ctx, "e1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	issuedDeadline := lease.ExpiresAt

	clock.advance(10 * time.Minute)
	deadline, err := b.Extend(ctx, lease.ID)
	if err != nil {
		t.Fatalf("extend: %v", err)
	}
	if want := clock.Now().Add(DefaultMaxLeaseTTL); !deadline.Equal(want) {
		t.Errorf("extended deadline = %s, want one lease period from now (%s)", deadline, want)
	}
	if !deadline.After(issuedDeadline) {
		t.Errorf("extension did not move the deadline: %s, issued %s", deadline, issuedDeadline)
	}

	// Past the original deadline the lease is still the broker's.
	clock.advance(10 * time.Minute)
	expired, live := b.SweepExpired()
	if n := expired[KindGitHubPAT]; n != 0 {
		t.Errorf("the sweep dropped %d extended lease(s) at their original deadline", n)
	}
	if n := live[KindGitHubPAT]; n != 1 {
		t.Errorf("live leases after the original deadline = %d, want the extended one", n)
	}
	// And it can be extended again, so a run of any length stays covered.
	if _, err := b.Extend(ctx, lease.ID); err != nil {
		t.Fatalf("second extension: %v", err)
	}

	var allowed []Event
	for _, ev := range auditor.byAction(ActionRenew) {
		if ev.LeaseID == lease.ID && ev.Decision == DecisionAllow {
			allowed = append(allowed, ev)
		}
	}
	if len(allowed) != 2 {
		t.Fatalf("got %d allowed secret.renew rows for the lease, want one per extension: %+v",
			len(allowed), auditor.byAction(ActionRenew))
	}
	if !strings.Contains(allowed[0].Reason, "extended in place") || allowed[0].ExpiresAt.IsZero() {
		t.Errorf("extension row = %+v; it should say it extended in place and name the new deadline", allowed[0])
	}
	for _, ev := range auditor.all() {
		if strings.Contains(ev.Reason, "ghp_extendabletoken") {
			t.Fatalf("an audit row carries the token: %+v", ev)
		}
	}
}

// TestExtendRefusesARevokedGrant is the property the short TTL exists for. An
// extension that ignored revocation would turn a fifteen-minute window into
// "until the run ends", however long that is.
func TestExtendRefusesARevokedGrant(t *testing.T) {
	b, _, auditor, clock := newTestBroker(t)
	ctx := context.Background()

	s := mintGitHub(t, b, "tok", "ghp_revokedmidrun")
	g := grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"*"}}, 24*time.Hour)
	lease, err := b.Lease(ctx, "e1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}

	if err := b.Revoke(ctx, g.ID, "operator"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	clock.advance(5 * time.Minute)
	if _, err := b.Extend(ctx, lease.ID); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("extend after revocation: err = %v, want ErrGrantRevoked", err)
	}

	// Refused, the lease keeps its original deadline and lapses on schedule.
	clock.advance(DefaultMaxLeaseTTL)
	expired, _ := b.SweepExpired()
	if expired[KindGitHubPAT] != 1 {
		t.Errorf("the refused lease did not lapse at its original deadline: expired = %v", expired)
	}

	var denied bool
	for _, ev := range auditor.byAction(ActionRenew) {
		if ev.LeaseID == lease.ID && ev.Decision == DecisionDeny && ev.GrantID == g.ID {
			denied = true
		}
	}
	if !denied {
		t.Error("the refused extension produced no audited denial naming the revoked grant")
	}
}

// TestExtendIsClampedToTheGrant: a lease may never outlive the authority it was
// issued under, extended or not.
func TestExtendIsClampedToTheGrant(t *testing.T) {
	b, _, _, clock := newTestBroker(t)
	ctx := context.Background()

	s := mintGitHub(t, b, "tok", "ghp_shortgrant")
	g := grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"*"}}, 20*time.Minute)
	lease, err := b.Lease(ctx, "e1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}

	clock.advance(10 * time.Minute)
	deadline, err := b.Extend(ctx, lease.ID)
	if err != nil {
		t.Fatalf("extend: %v", err)
	}
	if !deadline.Equal(g.ExpiresAt) {
		t.Errorf("extended to %s, past the grant's own expiry %s", deadline, g.ExpiresAt)
	}
}

// TestExtendRefusesALapsedLease: once the janitor may be taking material back,
// the hub must not resurrect the lease under it.
func TestExtendRefusesALapsedLease(t *testing.T) {
	b, _, _, clock := newTestBroker(t)
	ctx := context.Background()

	s := mintGitHub(t, b, "tok", "ghp_lapsedlease")
	grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"*"}}, 24*time.Hour)
	lease, err := b.Lease(ctx, "e1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	clock.advance(DefaultMaxLeaseTTL + time.Second)
	if _, err := b.Extend(ctx, lease.ID); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("extending a lapsed lease: err = %v, want ErrLeaseExpired", err)
	}
}

// TestExtendAfterReleaseFails: a released lease is gone, and extending it must
// not bring its record back.
func TestExtendAfterReleaseFails(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	ctx := context.Background()

	s := mintGitHub(t, b, "tok", "ghp_releasedlease")
	grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"*"}}, 24*time.Hour)
	lease, err := b.Lease(ctx, "e1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	b.Release(lease.ID)
	if _, err := b.Extend(ctx, lease.ID); !errors.Is(err, ErrLeaseNotFound) {
		t.Fatalf("extending a released lease: err = %v, want ErrLeaseNotFound", err)
	}
	if _, live := b.SweepExpired(); len(live) != 0 {
		t.Errorf("a failed extension resurrected the released lease: live = %v", live)
	}
}

// TestExtendLeavesAnAppTokenAlone: an App token in a sandbox cannot be swapped
// for a fresh one, so extending must neither mint a new token nor destroy the
// one the workload holds — which is exactly what Renew does, and why the
// dispatch path cannot use Renew.
func TestExtendLeavesAnAppTokenAlone(t *testing.T) {
	gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "org/tool"})
	b, gh, _ := appBroker(t, []string{"org/tool"}, nil, gh)

	lease := leaseOnce(t, b)
	token := tokenFrom(t, lease)

	if _, err := b.Extend(context.Background(), lease.ID); err != nil {
		t.Fatalf("extend: %v", err)
	}
	if gh.wasRevoked(token) {
		t.Fatal("extending the lease destroyed the token the workload holds")
	}
	if live := gh.liveTokens(); len(live) != 1 || live[0] != token {
		t.Errorf("live tokens = %v, want only the one the lease was issued with", live)
	}

	// Release still destroys it: extension does not orphan the token record.
	b.Release(lease.ID)
	if !gh.wasRevoked(token) {
		t.Error("releasing an extended lease left its installation token live at GitHub")
	}
}
