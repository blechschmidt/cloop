package secretbroker

// grantrevoke_test.go covers revoking a grant held by live leases (Task 20403):
// the announcement the hub cascades from, a lease giving up one grant and
// keeping the others, a superseded grant whose lease stands on its successor,
// and a lease taken over after one of its grants was revoked.

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── memStore's halves of the new store extensions ───────────────────────────

var (
	_ SupersedingRevoker = (*memStore)(nil)
	_ LeaseGrantStore    = (*memStore)(nil)
)

func (m *memStore) RevokeGrantSuperseded(id string, at time.Time, successorID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	if !ok {
		return wrapf(ErrGrantNotFound, "%s", id)
	}
	if !g.RevokedAt.IsZero() {
		return nil
	}
	g.RevokedAt, g.RevokedCause, g.SupersededBy = at.UTC(), RevokedSuperseded, successorID
	m.grants[id] = g
	return nil
}

func (m *memStore) SetLeaseGrants(id, holder string, grantIDs []string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.leases[id]
	if !ok || r.Holder != holder {
		return false, nil
	}
	r.GrantIDs = append([]string(nil), grantIDs...)
	m.leases[id] = r
	return true, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

// revocationRecorder collects the announcements for the grants a test made, so
// tests running beside it in the package cannot be mistaken for its own.
type revocationRecorder struct {
	mu     sync.Mutex
	grants map[string]bool
	got    []GrantRevocation
}

func recordRevocations(t *testing.T, grantIDs ...string) *revocationRecorder {
	t.Helper()
	r := &revocationRecorder{grants: map[string]bool{}}
	for _, id := range grantIDs {
		r.grants[id] = true
	}
	cancel := OnGrantRevoked(func(_ context.Context, rev GrantRevocation) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.grants[rev.GrantID] {
			r.got = append(r.got, rev)
		}
	})
	t.Cleanup(cancel)
	return r
}

func (r *revocationRecorder) all() []GrantRevocation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]GrantRevocation(nil), r.got...)
}

// twoGrantHeldLease issues a lease, through a broker keeping records as hub_a,
// carrying two grants of /srv/app.
func twoGrantHeldLease(t *testing.T) (setup *Broker, store *memStore, clock *fakeClock, a *Broker, g1, g2 Grant, lease *Lease) {
	t.Helper()
	setup, store, _, clock = newTestBroker(t)
	s1 := mintEnv(t, setup, "deploy", `{"DEPLOY_TOKEN":"deploy-canary-0001"}`)
	s2 := mintEnv(t, setup, "metrics", `{"METRICS_TOKEN":"metrics-canary-0002"}`)
	g1 = grantTo(t, setup, s1.ID, "project:/srv/app", Constraints{EnvKeys: []string{"DEPLOY_TOKEN"}}, 2*time.Hour)
	g2 = grantTo(t, setup, s2.ID, "project:/srv/app", Constraints{EnvKeys: []string{"METRICS_TOKEN"}}, 2*time.Hour)
	a, _ = holderBroker(t, store, clock, "hub_a")
	var err error
	lease, err = a.LeaseFor(context.Background(), Requester{ExecutorID: "dev1", ProjectID: "/srv/app"}, "ui")
	if err != nil {
		t.Fatalf("LeaseFor: %v", err)
	}
	if len(lease.Materials) != 2 {
		t.Fatalf("lease carries %d materials, want both grants", len(lease.Materials))
	}
	return setup, store, clock, a, g1, g2, lease
}

func withdrawnIDs(ws []WithdrawnGrant) []string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.GrantID)
	}
	return out
}

// ── tests ────────────────────────────────────────────────────────────────────

// TestRevocationIsAnnouncedOnceAndOnlyWhenItRevokes: the hub cascades from the
// announcement, so it must fire for every way a grant is revoked — by itself,
// with its secret — and never for a revocation that changed nothing, or an
// already-revoked grant would cascade again on every retry.
func TestRevocationIsAnnouncedOnceAndOnlyWhenItRevokes(t *testing.T) {
	ctx := context.Background()
	b, _, _, _ := newTestBroker(t)
	s := mintEnv(t, b, "deploy", `{"DEPLOY_TOKEN":"deploy-canary-0003"}`)
	g := grantTo(t, b, s.ID, "project:/srv/app", Constraints{}, time.Hour)
	other := mintEnv(t, b, "doomed", `{"X":"doomed-canary-0004"}`)
	d1 := grantTo(t, b, other.ID, "project:/srv/app", Constraints{}, time.Hour)
	d2 := grantTo(t, b, other.ID, "project:/srv/web", Constraints{}, time.Hour)
	rec := recordRevocations(t, g.ID, d1.ID, d2.ID)

	rev, revoked, err := b.RevokeGrant(ctx, RevokeGrantRequest{GrantID: g.ID, Actor: "operator", Reason: "rotated"})
	if err != nil || !revoked {
		t.Fatalf("RevokeGrant = %v, %v; want revoked", revoked, err)
	}
	if rev.GrantID != g.ID || rev.SecretName != "deploy" || rev.Actor != "operator" || rev.At.IsZero() {
		t.Errorf("revocation = %+v; it must name the grant, its secret, the actor and when", rev)
	}
	if got := rec.all(); len(got) != 1 || got[0].GrantID != g.ID {
		t.Fatalf("announcements = %+v, want exactly one for %s", got, g.ID)
	}

	_, revoked, err = b.RevokeGrant(ctx, RevokeGrantRequest{GrantID: g.ID, Actor: "operator"})
	if err != nil || revoked {
		t.Fatalf("second RevokeGrant = %v, %v; want success that revoked nothing", revoked, err)
	}
	if err := b.Revoke(ctx, g.ID, "operator"); err != nil {
		t.Fatalf("Revoke of a revoked grant: %v", err)
	}
	if got := rec.all(); len(got) != 1 {
		t.Fatalf("a repeat revocation was announced again: %+v", got)
	}

	if err := b.DeleteSecret(ctx, other.ID, "operator"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	causes := map[string]RevocationCause{}
	for _, r := range rec.all()[1:] {
		causes[r.GrantID] = r.Cause
	}
	if len(causes) != 2 || causes[d1.ID] != RevokedSecretDeleted || causes[d2.ID] != RevokedSecretDeleted {
		t.Errorf("deleting the secret announced %v; want both its grants, as revoked with it", causes)
	}
}

// TestAPanickingSubscriberDoesNotStopTheRevocation: a subscriber is the hub's
// cascade, and a bug in it must not leave the grant unrevoked or the other
// subscribers unaware.
func TestAPanickingSubscriberDoesNotStopTheRevocation(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	s := mintEnv(t, b, "deploy", `{"DEPLOY_TOKEN":"deploy-canary-0005"}`)
	g := grantTo(t, b, s.ID, "project:/srv/app", Constraints{}, time.Hour)
	cancel := OnGrantRevoked(func(_ context.Context, rev GrantRevocation) {
		if rev.GrantID == g.ID {
			panic("subscriber bug")
		}
	})
	defer cancel()
	rec := recordRevocations(t, g.ID)
	if err := b.Revoke(context.Background(), g.ID, "operator"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(rec.all()) != 1 {
		t.Error("the subscriber after a panicking one was not told")
	}
	if got, _ := b.store.GetGrant(g.ID); got.RevokedAt.IsZero() {
		t.Error("the grant is not revoked")
	}
}

// TestALeaseGivesUpOneGrantAndKeepsTheOthers: revoking one grant of a lease
// must end that grant's part of it — the keepalive stops being able to extend
// a lease that still carries it — and, once the grant is dropped, leave the
// lease alive on the grants nobody revoked, durably.
func TestALeaseGivesUpOneGrantAndKeepsTheOthers(t *testing.T) {
	ctx := context.Background()
	setup, store, _, a, g1, g2, lease := twoGrantHeldLease(t)

	if err := setup.Revoke(ctx, g1.ID, "operator"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := a.Extend(ctx, lease.ID); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("Extend while carrying the revoked grant = %v, want ErrGrantRevoked", err)
	}
	if got := withdrawnIDs(a.WithdrawnGrants(lease.ID)); !reflect.DeepEqual(got, []string{g1.ID}) {
		t.Fatalf("WithdrawnGrants = %v, want [%s]", got, g1.ID)
	}
	if got := a.HeldOn(lease.ID, g1.ID); !reflect.DeepEqual(got, []string{g1.ID}) {
		t.Errorf("HeldOn(%s) = %v", g1.ID, got)
	}

	left, err := a.DropLeaseGrant(ctx, lease.ID, g1.ID, "grant revoked by operator")
	if err != nil || left != 1 {
		t.Fatalf("DropLeaseGrant = %d, %v; want one grant left", left, err)
	}
	if _, err := a.Extend(ctx, lease.ID); err != nil {
		t.Fatalf("Extend on the grant nobody revoked: %v", err)
	}
	if got := a.WithdrawnGrants(lease.ID); len(got) != 0 {
		t.Errorf("WithdrawnGrants after the drop = %+v", got)
	}
	if rec, _ := store.leaseRecord(lease.ID); !reflect.DeepEqual(rec.GrantIDs, []string{g2.ID}) {
		t.Errorf("record grants = %v, want [%s]: a process taking the lease over would carry the revoked one",
			rec.GrantIDs, g2.ID)
	}
	if left, err := a.DropLeaseGrant(ctx, lease.ID, g1.ID, ""); err != nil || left != 1 {
		t.Errorf("dropping it again = %d, %v; want the same lease, unchanged", left, err)
	}
}

// TestASupersededGrantsLeaseStandsOnItsSuccessor is the trap the task names:
// supersession is not revocation. An edit revokes the old grant only after
// minting the successor, and the successor still authorises the run — so the
// running lease must keep extending, standing on it, until the successor itself
// is revoked, when the old grant's material is withdrawn like any other.
func TestASupersededGrantsLeaseStandsOnItsSuccessor(t *testing.T) {
	ctx := context.Background()
	setup, store, clock := func() (*Broker, *memStore, *fakeClock) { b, s, _, c := newTestBroker(t); return b, s, c }()
	sec := mintEnv(t, setup, "claude", `{"CLAUDE_CODE_OAUTH_TOKEN":"sk-claude-canary-0006"}`)
	old := grantTo(t, setup, sec.ID, "project:/srv/app", Constraints{EnvKeys: []string{"CLAUDE_CODE_OAUTH_TOKEN"}}, time.Hour)
	a, _ := holderBroker(t, store, clock, "hub_a")
	lease, err := a.LeaseFor(ctx, Requester{ExecutorID: "dev1", ProjectID: "/srv/app"}, "ui")
	if err != nil {
		t.Fatalf("LeaseFor: %v", err)
	}
	next := grantTo(t, setup, sec.ID, "project:/srv/app", Constraints{EnvKeys: []string{"CLAUDE_CODE_OAUTH_TOKEN"}}, 6*time.Hour)
	rec := recordRevocations(t, old.ID)

	rev, revoked, err := setup.Supersede(ctx, old.ID, next.ID, "operator")
	if err != nil || !revoked {
		t.Fatalf("Supersede = %v, %v", revoked, err)
	}
	if !rev.Superseded() || rev.SupersededBy != next.ID {
		t.Errorf("revocation = %+v; want it announced as superseded by %s", rev, next.ID)
	}
	if got := rec.all(); len(got) != 1 || !got[0].Superseded() {
		t.Errorf("announcements = %+v", got)
	}
	if g, _ := store.GetGrant(old.ID); g.RevokedCause != RevokedSuperseded || g.SupersededBy != next.ID {
		t.Fatalf("stored grant = cause %q successor %q; the successor must be recorded on it", g.RevokedCause, g.SupersededBy)
	}

	// A lease no longer includes it…
	fresh, err := setup.LeaseFor(ctx, Requester{ExecutorID: "dev2", ProjectID: "/srv/app"}, "ui")
	if err != nil || len(fresh.Materials) != 1 || fresh.Materials[0].GrantID != next.ID {
		t.Fatalf("a new lease = %+v, %v; want only the successor", fresh, err)
	}
	// …but the running one stands on the successor, and its keepalive carries
	// it past the old grant's own end.
	for elapsed := time.Duration(0); elapsed < 70*time.Minute; elapsed += 10 * time.Minute {
		clock.advance(10 * time.Minute)
		deadline, err := a.Extend(ctx, lease.ID)
		if err != nil {
			t.Fatalf("Extend %s after the supersession: %v", elapsed+10*time.Minute, err)
		}
		if !deadline.After(clock.Now()) {
			t.Fatalf("extended to %v, not past now", deadline)
		}
	}
	if got := a.WithdrawnGrants(lease.ID); len(got) != 0 {
		t.Fatalf("a superseded grant with a live successor is reported withdrawn: %+v", got)
	}
	if got := a.HeldOn(lease.ID, next.ID); !reflect.DeepEqual(got, []string{old.ID}) {
		t.Errorf("HeldOn(successor) = %v, want the superseded grant standing on it", got)
	}

	// The successor revoked in its turn: now the old grant's material goes.
	if err := setup.Revoke(ctx, next.ID, "operator"); err != nil {
		t.Fatalf("Revoke successor: %v", err)
	}
	if _, err := a.Extend(ctx, lease.ID); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("Extend after the successor was revoked = %v, want ErrGrantRevoked", err)
	}
	got := a.WithdrawnGrants(lease.ID)
	if len(got) != 1 || got[0].GrantID != old.ID || !strings.Contains(got[0].Reason, next.ID) {
		t.Errorf("WithdrawnGrants = %+v; want the superseded grant, naming the revoked successor", got)
	}
}

// TestSupersedeRefusesASuccessorThatCannotStandForIt: a successor that is not
// live, or reaches another subject, would make a supersession a way to keep a
// lease alive on authority it does not have.
func TestSupersedeRefusesASuccessorThatCannotStandForIt(t *testing.T) {
	ctx := context.Background()
	b, _, _, _ := newTestBroker(t)
	sec := mintEnv(t, b, "claude", `{"K":"supersede-canary-0007"}`)
	old := grantTo(t, b, sec.ID, "project:/srv/app", Constraints{}, time.Hour)
	elsewhere := grantTo(t, b, sec.ID, "project:/srv/other", Constraints{}, time.Hour)
	dead := grantTo(t, b, sec.ID, "project:/srv/app", Constraints{}, time.Hour)
	if err := b.Revoke(ctx, dead.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	for name, successor := range map[string]string{"another subject": elsewhere.ID, "revoked": dead.ID, "itself": old.ID} {
		if _, _, err := b.Supersede(ctx, old.ID, successor, "operator"); err == nil {
			t.Errorf("superseding by %s was accepted", name)
		}
	}
	if g, _ := b.store.GetGrant(old.ID); !g.RevokedAt.IsZero() {
		t.Error("a refused supersession revoked the grant anyway")
	}
}

// TestRestoreWithdrawsOnlyTheRevokedGrant: a member adopting a run must see a
// grant revoked while nobody held its lease and take it back (Task 20403), and
// keep the grants nobody revoked rather than refuse the whole lease.
func TestRestoreWithdrawsOnlyTheRevokedGrant(t *testing.T) {
	ctx := context.Background()
	setup, store, clock, _, g1, g2, lease := twoGrantHeldLease(t)
	if err := setup.Revoke(ctx, g1.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	b, _ := holderBroker(t, store, clock, "hub_b")
	taken, err := b.Restore(ctx, lease.ID)
	if err != nil {
		t.Fatalf("Restore of a lease with one live grant: %v", err)
	}
	if got := withdrawnIDs(taken.Withdrawn); !reflect.DeepEqual(got, []string{g1.ID}) {
		t.Fatalf("Withdrawn = %v, want [%s]", got, g1.ID)
	}
	if _, err := b.DropLeaseGrant(ctx, lease.ID, g1.ID, "revoked while nobody held it"); err != nil {
		t.Fatalf("DropLeaseGrant: %v", err)
	}
	if _, err := b.Extend(ctx, lease.ID); err != nil {
		t.Fatalf("Extend on the grant nobody revoked: %v", err)
	}

	// Every grant revoked: nothing is left to take over.
	setup2, store2, clock2, _, h1, h2, lease2 := twoGrantHeldLease(t)
	for _, id := range []string{h1.ID, h2.ID} {
		if err := setup2.Revoke(ctx, id, "operator"); err != nil {
			t.Fatal(err)
		}
	}
	c, _ := holderBroker(t, store2, clock2, "hub_b")
	if _, err := c.Restore(ctx, lease2.ID); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("Restore with every grant revoked = %v, want ErrGrantRevoked", err)
	}
	_ = g2
}

// TestASupersededAppGrantsTokenIsHeldToItsSuccessor: an edit that narrowed a
// project's GitHub App assignment — fewer repositories, read instead of write —
// supersedes the grant a running lease carries. The run keeps working, and its
// token is re-minted at once at the old scope held to the successor: never
// wider than either.
func TestASupersededAppGrantsTokenIsHeldToItsSuccessor(t *testing.T) {
	f := newRefreshFixture(t, []string{"org/tool", "org/service"}, []string{"contents:write"},
		InstallationRepo{ID: 1, FullName: "org/tool"},
		InstallationRepo{ID: 2, FullName: "org/service"},
	)
	ctx := context.Background()
	lease := f.lease(t)
	first := tokenFrom(t, lease)
	next, err := f.b.Grant(ctx, GrantRequest{
		SecretRef: f.secret.ID, Subject: f.grant.Subject, TTL: 24 * time.Hour, Actor: "test",
		Constraints: Constraints{Repos: []string{"org/tool"}, Permissions: []string{"contents:read"}},
	})
	if err != nil {
		t.Fatalf("Grant successor: %v", err)
	}
	if _, _, err := f.b.Supersede(ctx, f.grant.ID, next.ID, "operator"); err != nil {
		t.Fatalf("Supersede: %v", err)
	}
	if !f.isLive(first) {
		t.Fatal("superseding the grant destroyed the running workload's token")
	}
	if !f.b.AppTokensDue(lease.ID) {
		t.Fatal("the token of a superseded grant is not due for re-minting at the successor's terms")
	}
	fr, err := f.b.RefreshLeaseFiles(ctx, lease)
	if err != nil || fr == nil || len(fr.Files) != 1 {
		t.Fatalf("RefreshLeaseFiles = %+v, %v; want the token re-minted", fr, err)
	}
	defer fr.Close()
	creates := f.scopedCreates()
	last := creates[len(creates)-1]
	if !reflect.DeepEqual(last.RepositoryIDs, []int64{1}) {
		t.Errorf("re-minted for repositories %v, want only org/tool (1)", last.RepositoryIDs)
	}
	if !reflect.DeepEqual(last.Permissions, map[string]string{"contents": "read"}) {
		t.Errorf("re-minted with permissions %v, want contents:read", last.Permissions)
	}
	fr.Delivered(false)
	if f.b.AppTokensDue(lease.ID) {
		t.Error("the slot is still due after its token was held to the successor and delivered")
	}
}
