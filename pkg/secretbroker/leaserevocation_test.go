package secretbroker

// leaserevocation_test.go covers the durable lease revocations (Task 20419): a
// revocation recorded while no hub process held the lease binds whoever takes
// it over, and one its holder never heard of stops the holder keeping it alive.

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"
)

// ── memStore's LeaseRevocationStore half ─────────────────────────────────────

var _ LeaseRevocationStore = (*memStore)(nil)

func (m *memStore) PutLeaseRevocation(r LeaseRevocation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := [2]string{r.LeaseID, r.GrantID}
	if prev, ok := m.revocations[key]; ok {
		r.RevokedAt = prev.RevokedAt
		if prev.Action == "kill" {
			r.Action = "kill"
		}
	}
	r.EnforcedAt, r.EnforcedBy, r.Detail = time.Time{}, "", ""
	m.revocations[key] = r
	return nil
}

func (m *memStore) LeaseRevocations(leaseID string) ([]LeaseRevocation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revocationErr != nil {
		return nil, m.revocationErr
	}
	var out []LeaseRevocation
	for k, r := range m.revocations {
		if k[0] == leaseID {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GrantID < out[j].GrantID })
	return out, nil
}

func (m *memStore) ListLeaseRevocations(pendingOnly bool) ([]LeaseRevocation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revocationErr != nil {
		return nil, m.revocationErr
	}
	var out []LeaseRevocation
	for _, r := range m.revocations {
		if !pendingOnly || r.Pending() {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memStore) SettleLeaseRevocation(leaseID, grantID, by, detail string, at time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := [2]string{leaseID, grantID}
	r, ok := m.revocations[key]
	if !ok || !r.Pending() {
		return false, nil
	}
	r.EnforcedAt, r.EnforcedBy, r.Detail = at, by, detail
	m.revocations[key] = r
	return true, nil
}

func (m *memStore) NoteLeaseRevocation(leaseID, grantID, detail string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := [2]string{leaseID, grantID}
	if r, ok := m.revocations[key]; ok && r.Pending() {
		r.Detail = detail
		m.revocations[key] = r
	}
	return nil
}

// ── tests ────────────────────────────────────────────────────────────────────

// issueTwoGrantLease leases two env credentials to one project from hub_a.
func issueTwoGrantLease(t *testing.T) (*memStore, *fakeClock, *Broker, *Lease, []Grant) {
	t.Helper()
	setup, store, _, clock := newTestBroker(t)
	s1 := mintEnv(t, setup, "claude", `{"CLAUDE_CODE_OAUTH_TOKEN":"sk-very-secret-value-0101"}`)
	s2 := mintEnv(t, setup, "npm", `{"NPM_TOKEN":"npm-very-secret-value-0102"}`)
	g1 := grantTo(t, setup, s1.ID, "project:/srv/app", Constraints{EnvKeys: []string{"CLAUDE_CODE_OAUTH_TOKEN"}}, 2*time.Hour)
	g2 := grantTo(t, setup, s2.ID, "project:/srv/app", Constraints{EnvKeys: []string{"NPM_TOKEN"}}, 2*time.Hour)
	a, _ := holderBroker(t, store, clock, "hub_a")
	lease, err := a.LeaseFor(context.Background(), Requester{ExecutorID: "ctr", ProjectID: "/srv/app"}, "ui")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	return store, clock, a, lease, []Grant{g1, g2}
}

// TestARevokedLeaseIsNeverTakenOver is the incident responder's revocation
// surviving the death of the holder that would have enforced it: recorded
// from any process, it stops the process adopting the run from taking the
// lease over — the refusal carries the revocation, so the adopter can take the
// material back as the operator asked — and the record stays where it was.
func TestARevokedLeaseIsNeverTakenOver(t *testing.T) {
	ctx := context.Background()
	store, clock, _, lease, _ := issueTwoGrantLease(t)

	survivor, _ := holderBroker(t, store, clock, "hub_b")
	rev, recorded, err := survivor.RecordLeaseRevocation(LeaseRevocation{
		LeaseID: lease.ID, Action: "kill", Reason: "token leaked in a log", Actor: "alice@example.com",
	})
	if err != nil || !recorded {
		t.Fatalf("RecordLeaseRevocation = %v, %v", recorded, err)
	}
	if rev.Holder != "hub_a" || rev.ExecutorID != "ctr" || rev.ProjectID != "/srv/app" || rev.RevokedAt.IsZero() {
		t.Fatalf("the recorded revocation does not say whose lease it was: %+v", rev)
	}

	adopter, audit := holderBroker(t, store, clock, "hub_c")
	_, err = adopter.Restore(ctx, lease.ID)
	if !errors.Is(err, ErrLeaseRevoked) {
		t.Fatalf("Restore of a revoked lease = %v, want ErrLeaseRevoked", err)
	}
	got, ok := RevocationOf(err)
	if !ok || got.Action != "kill" || got.Actor != "alice@example.com" || got.Reason != "token leaked in a log" {
		t.Fatalf("the refusal carries %+v (%v), want the revocation", got, ok)
	}
	if !strings.Contains(err.Error(), "alice@example.com") || !strings.Contains(err.Error(), "token leaked") {
		t.Errorf("the refusal does not say who revoked it or why: %v", err)
	}
	if rec, _ := store.leaseRecord(lease.ID); rec.Holder != "hub_a" {
		t.Fatalf("a refused takeover moved the record to %q", rec.Holder)
	}
	if len(eventsFor(audit, ActionRenew, lease.ID, DecisionDeny)) != 1 {
		t.Error("the refusal was not audited")
	}

	pending, err := adopter.PendingLeaseRevocations()
	if err != nil || len(pending) != 1 || pending[0].LeaseID != lease.ID {
		t.Fatalf("pending = %+v, %v", pending, err)
	}
	if ok, err := adopter.SettleLeaseRevocation(lease.ID, "", "hub_c", "taken back on adoption"); err != nil || !ok {
		t.Fatalf("SettleLeaseRevocation = %v, %v", ok, err)
	}
	if pending, _ := adopter.PendingLeaseRevocations(); len(pending) != 0 {
		t.Fatalf("still pending after it was settled: %+v", pending)
	}
	// Settled is not forgotten: the lease is still refused.
	if _, err := adopter.Restore(ctx, lease.ID); !errors.Is(err, ErrLeaseRevoked) {
		t.Fatalf("Restore after the revocation was settled = %v", err)
	}
}

// TestARevokedLeaseIsNotKeptAlive is the holder the revocation's fan-out did
// not reach: it stops extending the lease, so the lease lapses on schedule
// even if nothing else ever tells it.
func TestARevokedLeaseIsNotKeptAlive(t *testing.T) {
	ctx := context.Background()
	store, clock, holder, lease, _ := issueTwoGrantLease(t)
	elsewhere, _ := holderBroker(t, store, clock, "hub_b")
	if _, _, err := elsewhere.RecordLeaseRevocation(LeaseRevocation{LeaseID: lease.ID, Actor: "bob"}); err != nil {
		t.Fatal(err)
	}
	clock.advance(DefaultMaxLeaseTTL - time.Minute)
	if _, err := holder.Extend(ctx, lease.ID); !errors.Is(err, ErrLeaseRevoked) {
		t.Fatalf("the holder extended a revoked lease: Extend = %v", err)
	}
}

// TestARevokedGrantOfALeaseIsWithdrawnOnTakeover: a revocation naming one grant
// of a lease withdraws that grant — on takeover, from the holder's own
// keepalive, and in the janitor's list — and the lease keeps the other. A lease
// of that one grant is refused whole.
func TestARevokedGrantOfALeaseIsWithdrawnOnTakeover(t *testing.T) {
	ctx := context.Background()
	store, clock, holder, lease, grants := issueTwoGrantLease(t)
	if _, _, err := holder.RecordLeaseRevocation(LeaseRevocation{LeaseID: lease.ID, GrantID: grants[0].ID, Actor: "carol"}); err != nil {
		t.Fatal(err)
	}
	withdrawn := holder.WithdrawnGrants(lease.ID)
	if len(withdrawn) != 1 || withdrawn[0].GrantID != grants[0].ID || !strings.Contains(withdrawn[0].Reason, "carol") {
		t.Fatalf("WithdrawnGrants = %+v, want the revoked grant", withdrawn)
	}
	clock.advance(DefaultMaxLeaseTTL - time.Minute)
	if _, err := holder.Extend(ctx, lease.ID); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("Extend with a revoked grant = %v, want ErrGrantRevoked", err)
	}

	adopter, _ := holderBroker(t, store, clock, "hub_c")
	taken, err := adopter.Restore(ctx, lease.ID)
	if err != nil {
		t.Fatalf("Restore = %v, want the lease with one grant withdrawn", err)
	}
	if len(taken.Withdrawn) != 1 || taken.Withdrawn[0].GrantID != grants[0].ID {
		t.Fatalf("Withdrawn = %+v, want the revoked grant", taken.Withdrawn)
	}

	// The same revocation on a lease of that grant alone takes the lease.
	setup, store2, _, clock2 := newTestBroker(t)
	s := mintEnv(t, setup, "solo", `{"SOLO_TOKEN":"solo-very-secret-value-0103"}`)
	g := grantTo(t, setup, s.ID, "project:/srv/solo", Constraints{EnvKeys: []string{"SOLO_TOKEN"}}, 2*time.Hour)
	a, _ := holderBroker(t, store2, clock2, "hub_a")
	solo, err := a.LeaseFor(ctx, Requester{ExecutorID: "ctr", ProjectID: "/srv/solo"}, "ui")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.RecordLeaseRevocation(LeaseRevocation{LeaseID: solo.ID, GrantID: g.ID}); err != nil {
		t.Fatal(err)
	}
	b, _ := holderBroker(t, store2, clock2, "hub_b")
	if _, err := b.Restore(ctx, solo.ID); !errors.Is(err, ErrLeaseRevoked) {
		t.Fatalf("Restore of a one-grant lease whose grant was revoked = %v, want ErrLeaseRevoked", err)
	}
}

// TestATakeoverWaitsForARevocationItCannotRead: whether a lease was revoked
// has to be known before it is handed on. A store that cannot say makes the
// takeover fail for now — not succeed, and not be refused for good.
func TestATakeoverWaitsForARevocationItCannotRead(t *testing.T) {
	ctx := context.Background()
	store, clock, _, lease, _ := issueTwoGrantLease(t)
	store.revocationErr = errors.New("database is locked")
	adopter, _ := holderBroker(t, store, clock, "hub_c")
	_, err := adopter.Restore(ctx, lease.ID)
	if err == nil || errors.Is(err, ErrLeaseRevoked) || errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("Restore with unreadable revocations = %v, want a transient failure", err)
	}
	if rec, _ := store.leaseRecord(lease.ID); rec.Holder != "hub_a" {
		t.Fatalf("the lease was taken over on a guess: holder %q", rec.Holder)
	}
	store.revocationErr = nil
	if _, err := adopter.Restore(ctx, lease.ID); err != nil {
		t.Fatalf("Restore once the store answers = %v", err)
	}
}
