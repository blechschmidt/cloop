package secretbroker

// leaserecord_test.go covers the durable lease records (Task 20382): a lease
// outlives the hub process that issued it, the process that adopts its run
// takes it over, and the process that lost it can neither extend nor end it.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// ── memStore's LeaseStore half ───────────────────────────────────────────────

var _ LeaseStore = (*memStore)(nil)

func (m *memStore) PutLease(r LeaseRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.leases[r.ID] = r
	return nil
}

func (m *memStore) GetLease(id string) (LeaseRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.leases[id]
	if !ok {
		return LeaseRecord{}, wrapf(ErrLeaseNotFound, "%s", id)
	}
	return r, nil
}

func (m *memStore) ListLeases() ([]LeaseRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]LeaseRecord, 0, len(m.leases))
	for _, r := range m.leases {
		out = append(out, r)
	}
	return out, nil
}

func (m *memStore) ExtendLease(id, holder string, expiresAt time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.leases[id]
	if !ok || r.Holder != holder {
		return false, nil
	}
	r.ExpiresAt = expiresAt
	m.leases[id] = r
	return true, nil
}

func (m *memStore) TakeLease(id, from, holder string) (bool, error) {
	if m.beforeTake != nil {
		hook := m.beforeTake
		m.beforeTake = nil
		hook()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.leases[id]
	if !ok || r.Holder != from {
		return false, nil
	}
	r.Holder = holder
	m.leases[id] = r
	return true, nil
}

func (m *memStore) DeleteLease(id, holder string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.leases[id]
	if !ok || r.Holder != holder {
		return false, nil
	}
	delete(m.leases, id)
	return true, nil
}

func (m *memStore) leaseRecord(id string) (LeaseRecord, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.leases[id]
	return r, ok
}

// ── helpers ──────────────────────────────────────────────────────────────────

// holderBroker is a second broker over the same store and clock: another hub
// process sharing the control plane.
func holderBroker(t *testing.T, store *memStore, clock *fakeClock, holder string) (*Broker, *recordingAuditor) {
	t.Helper()
	cipher, err := NewCipherWithKey(testKey)
	if err != nil {
		t.Fatal(err)
	}
	auditor := &recordingAuditor{}
	b, err := New(store, WithCipher(cipher), WithAuditor(auditor), WithClock(clock.Now), WithLeaseRecords(holder))
	if err != nil {
		t.Fatal(err)
	}
	return b, auditor
}

func eventsFor(a *recordingAuditor, action Action, leaseID string, decision Decision) []Event {
	var out []Event
	for _, ev := range a.byAction(action) {
		if ev.LeaseID == leaseID && ev.Decision == decision {
			out = append(out, ev)
		}
	}
	return out
}

// ── tests ────────────────────────────────────────────────────────────────────

// TestLeasesAreRecordedForTheirHolder: a broker that keeps records writes one
// per lease that carries something, under its holder, with what a successor
// needs to take it over — and nothing that is a credential.
func TestLeasesAreRecordedForTheirHolder(t *testing.T) {
	setup, store, _, clock := newTestBroker(t)
	s := mintEnv(t, setup, "claude", `{"CLAUDE_CODE_OAUTH_TOKEN":"sk-very-secret-value-0001"}`)
	g := grantTo(t, setup, s.ID, "project:/srv/app", Constraints{EnvKeys: []string{"CLAUDE_CODE_OAUTH_TOKEN"}}, 2*time.Hour)

	a, _ := holderBroker(t, store, clock, "hub_a")
	lease, err := a.LeaseFor(context.Background(), Requester{ExecutorID: "dev1", ProjectID: "/srv/app", RunID: "run_1"}, "ui")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	rec, ok := store.leaseRecord(lease.ID)
	if !ok {
		t.Fatal("the lease was not recorded")
	}
	if rec.Holder != "hub_a" || rec.Requester.ExecutorID != "dev1" || rec.Requester.ProjectID != "/srv/app" ||
		rec.Requester.RunID != "run_1" || rec.Actor != "ui" || !rec.ExpiresAt.Equal(lease.ExpiresAt) ||
		len(rec.GrantIDs) != 1 || rec.GrantIDs[0] != g.ID || len(rec.Kinds) != 1 || rec.Kinds[0] != KindEnv {
		t.Fatalf("record = %+v", rec)
	}

	// A lease carrying nothing is released by its caller at once: no record.
	empty, err := a.LeaseFor(context.Background(), Requester{ExecutorID: "dev1", ProjectID: "/srv/other"}, "ui")
	if err != nil {
		t.Fatalf("empty lease: %v", err)
	}
	if _, ok := store.leaseRecord(empty.ID); ok {
		t.Error("an empty lease was recorded")
	}
	// Nor does a broker that names no holder keep any.
	plain, err := setup.LeaseFor(context.Background(), Requester{ExecutorID: "dev1", ProjectID: "/srv/app"}, "cli")
	if err != nil {
		t.Fatalf("plain lease: %v", err)
	}
	if _, ok := store.leaseRecord(plain.ID); ok {
		t.Error("a broker without WithLeaseRecords recorded its lease")
	}
}

// TestALeaseIsTakenOverWithItsRun is the restart: the process that issued the
// lease is gone, the one that adopted its run takes it over, keeps it alive and
// ends it. The one that lost it — were it still alive — can do neither.
func TestALeaseIsTakenOverWithItsRun(t *testing.T) {
	setup, store, _, clock := newTestBroker(t)
	s := mintEnv(t, setup, "claude", `{"CLAUDE_CODE_OAUTH_TOKEN":"sk-very-secret-value-0002"}`)
	grantTo(t, setup, s.ID, "project:/srv/app", Constraints{EnvKeys: []string{"CLAUDE_CODE_OAUTH_TOKEN"}}, 2*time.Hour)
	ctx := context.Background()

	a, auditA := holderBroker(t, store, clock, "hub_a")
	lease, err := a.LeaseFor(ctx, Requester{ExecutorID: "dev1", ProjectID: "/srv/app", RunID: "run_1"}, "ui")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}

	clock.advance(3 * time.Minute)
	b, auditB := holderBroker(t, store, clock, "hub_b")
	taken, err := b.Restore(ctx, lease.ID)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if taken.ID != lease.ID || !taken.ExpiresAt.Equal(lease.ExpiresAt) || taken.RunID != "run_1" ||
		taken.ExecutorID != "dev1" || taken.ProjectID != "/srv/app" {
		t.Fatalf("taken-over lease = %+v, want %s as issued", taken, lease.ID)
	}
	if len(taken.Materials) != 1 || taken.Materials[0].SecretName != "claude" || taken.Materials[0].Kind != KindEnv {
		t.Fatalf("taken-over materials = %+v", taken.Materials)
	}
	for _, m := range taken.Materials {
		if len(m.Env) != 0 || len(m.Files) != 0 {
			t.Fatalf("a taken-over lease carries material: %+v", m)
		}
	}
	if rec, _ := store.leaseRecord(lease.ID); rec.Holder != "hub_b" {
		t.Fatalf("record holder after the takeover = %q", rec.Holder)
	}
	if rows := eventsFor(auditB, ActionRenew, lease.ID, DecisionAllow); len(rows) != 1 ||
		!strings.Contains(rows[0].Reason, "taken over") || !strings.Contains(rows[0].Reason, "hub_a") ||
		rows[0].RunID != "run_1" {
		t.Fatalf("takeover rows = %+v", rows)
	}
	if b.HeldElsewhere(lease.ID) || !a.HeldElsewhere(lease.ID) {
		t.Fatal("HeldElsewhere does not follow the record")
	}

	// The process that lost it may neither keep it alive...
	clock.advance(8 * time.Minute)
	if _, err := a.Extend(ctx, lease.ID); !errors.Is(err, ErrLeaseMoved) {
		t.Fatalf("the previous holder's Extend = %v, want ErrLeaseMoved", err)
	}
	if rows := eventsFor(auditA, ActionRenew, lease.ID, DecisionDeny); len(rows) != 1 {
		t.Fatalf("the refused extension was not audited: %+v", auditA.byAction(ActionRenew))
	}
	// ... nor end it: its release is the new holder's to make.
	a.Release(lease.ID)
	if rows := eventsFor(auditA, ActionRelease, lease.ID, DecisionAllow); len(rows) != 0 {
		t.Fatalf("the previous holder released a lease it lost: %+v", rows)
	}
	if rec, ok := store.leaseRecord(lease.ID); !ok || rec.Holder != "hub_b" {
		t.Fatalf("the previous holder's release touched the record: %+v %v", rec, ok)
	}

	// The new holder keeps it alive, record and all...
	deadline, err := b.Extend(ctx, lease.ID)
	if err != nil {
		t.Fatalf("the new holder's Extend: %v", err)
	}
	if !deadline.After(lease.ExpiresAt) {
		t.Fatalf("extended deadline %s is not past the issued %s", deadline, lease.ExpiresAt)
	}
	if rec, _ := store.leaseRecord(lease.ID); !rec.ExpiresAt.Equal(deadline) {
		t.Fatalf("record deadline = %s, want %s", rec.ExpiresAt, deadline)
	}
	// ... and ends it.
	b.Release(lease.ID)
	if _, ok := store.leaseRecord(lease.ID); ok {
		t.Fatal("the record survived its holder's release")
	}
	if rows := eventsFor(auditB, ActionRelease, lease.ID, DecisionAllow); len(rows) != 1 {
		t.Fatalf("release rows = %+v", rows)
	}
	for _, ev := range append(auditA.all(), auditB.all()...) {
		if strings.Contains(ev.Reason, "sk-very-secret") {
			t.Fatalf("an audit row carries the credential: %+v", ev)
		}
	}
}

// TestRestoreRefusesWhatExtendWould: taking a lease over extends its life past
// the process that issued it, so nothing its grants no longer allow survives
// the handover — and of two processes racing for it, one gets it.
func TestRestoreRefusesWhatExtendWould(t *testing.T) {
	ctx := context.Background()
	issue := func(t *testing.T) (*memStore, *fakeClock, *Broker, Grant, *Lease) {
		setup, store, _, clock := newTestBroker(t)
		s := mintEnv(t, setup, "claude", `{"CLAUDE_CODE_OAUTH_TOKEN":"sk-very-secret-value-0003"}`)
		g := grantTo(t, setup, s.ID, "project:/srv/app", Constraints{EnvKeys: []string{"CLAUDE_CODE_OAUTH_TOKEN"}}, 2*time.Hour)
		a, _ := holderBroker(t, store, clock, "hub_a")
		lease, err := a.LeaseFor(ctx, Requester{ExecutorID: "dev1", ProjectID: "/srv/app"}, "ui")
		if err != nil {
			t.Fatalf("lease: %v", err)
		}
		return store, clock, setup, g, lease
	}

	t.Run("lapsed while nobody held it", func(t *testing.T) {
		store, clock, _, _, lease := issue(t)
		clock.advance(DefaultMaxLeaseTTL + time.Second)
		b, audit := holderBroker(t, store, clock, "hub_b")
		if _, err := b.Restore(ctx, lease.ID); !errors.Is(err, ErrLeaseExpired) {
			t.Fatalf("Restore = %v, want ErrLeaseExpired", err)
		}
		if rec, _ := store.leaseRecord(lease.ID); rec.Holder != "hub_a" {
			t.Fatalf("a refused takeover moved the record to %q", rec.Holder)
		}
		if len(eventsFor(audit, ActionRenew, lease.ID, DecisionDeny)) != 1 {
			t.Fatal("the refusal was not audited")
		}
	})
	t.Run("grant revoked meanwhile", func(t *testing.T) {
		store, clock, setup, g, lease := issue(t)
		if err := setup.Revoke(ctx, g.ID, "operator"); err != nil {
			t.Fatal(err)
		}
		b, _ := holderBroker(t, store, clock, "hub_b")
		if _, err := b.Restore(ctx, lease.ID); !errors.Is(err, ErrGrantRevoked) {
			t.Fatalf("Restore = %v, want ErrGrantRevoked", err)
		}
	})
	t.Run("no record", func(t *testing.T) {
		store, clock, _, _, _ := issue(t)
		b, _ := holderBroker(t, store, clock, "hub_b")
		if _, err := b.Restore(ctx, "lease_unknown"); !errors.Is(err, ErrLeaseNotFound) {
			t.Fatalf("Restore = %v, want ErrLeaseNotFound", err)
		}
	})
	t.Run("another process took it over first", func(t *testing.T) {
		store, clock, _, _, lease := issue(t)
		b, _ := holderBroker(t, store, clock, "hub_b")
		c, _ := holderBroker(t, store, clock, "hub_c")
		store.beforeTake = func() {
			if _, err := c.Restore(ctx, lease.ID); err != nil {
				t.Errorf("the winning takeover: %v", err)
			}
		}
		if _, err := b.Restore(ctx, lease.ID); !errors.Is(err, ErrLeaseMoved) {
			t.Fatalf("the losing takeover = %v, want ErrLeaseMoved", err)
		}
		if rec, _ := store.leaseRecord(lease.ID); rec.Holder != "hub_c" {
			t.Fatalf("record holder = %q, want the winner", rec.Holder)
		}
		if _, err := b.Extend(ctx, lease.ID); !errors.Is(err, ErrLeaseNotFound) {
			t.Fatalf("the loser holds the lease after all: Extend = %v", err)
		}
	})
}

// TestRetireRecordEndsALeaseNobodyHolds: the sweep's half — a lease whose run
// ended while no hub held it, or that lapsed, is released on the record of the
// process that last held it, and only if nobody took it over meanwhile.
func TestRetireRecordEndsALeaseNobodyHolds(t *testing.T) {
	setup, store, _, clock := newTestBroker(t)
	s := mintEnv(t, setup, "claude", `{"CLAUDE_CODE_OAUTH_TOKEN":"sk-very-secret-value-0004"}`)
	grantTo(t, setup, s.ID, "project:/srv/app", Constraints{EnvKeys: []string{"CLAUDE_CODE_OAUTH_TOKEN"}}, 2*time.Hour)
	a, _ := holderBroker(t, store, clock, "hub_a")
	lease, err := a.LeaseFor(context.Background(), Requester{ExecutorID: "dev1", ProjectID: "/srv/app", RunID: "run_9"}, "ui")
	if err != nil {
		t.Fatal(err)
	}
	sweeper, audit := holderBroker(t, store, clock, "hub_leader")
	rec, err := sweeper.LeaseRecordFor(lease.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Taken over between the read and the retirement: left alone.
	stale := rec
	stale.Holder = "hub_gone"
	if ok, err := sweeper.RetireRecord(stale, "lapsed"); err != nil || ok {
		t.Fatalf("RetireRecord of a record held by someone else = %v, %v", ok, err)
	}
	if ok, err := sweeper.RetireRecord(rec, "its run ended while no hub process held the lease"); err != nil || !ok {
		t.Fatalf("RetireRecord = %v, %v", ok, err)
	}
	if _, ok := store.leaseRecord(lease.ID); ok {
		t.Fatal("the record survived its retirement")
	}
	rows := eventsFor(audit, ActionRelease, lease.ID, DecisionAllow)
	if len(rows) != 1 || rows[0].RunID != "run_9" || !strings.Contains(rows[0].Reason, "no hub process held") {
		t.Fatalf("release rows = %+v", rows)
	}
}

// TestRedactionValuesAreWhatTheLeaseDelivered: the process that took a lease
// over scrubs its workload's output with the credentials the lease carries —
// the env keys its grant delivers, not the ones it withholds.
func TestRedactionValuesAreWhatTheLeaseDelivered(t *testing.T) {
	setup, store, _, clock := newTestBroker(t)
	env := mintEnv(t, setup, "claude", `{"CLAUDE_CODE_OAUTH_TOKEN":"sk-delivered-value-0005","OTHER_KEY":"withheld-by-the-grant-0005"}`)
	grantTo(t, setup, env.ID, "project:/srv/app", Constraints{EnvKeys: []string{"CLAUDE_CODE_OAUTH_TOKEN"}}, 2*time.Hour)
	pat := mintGitHub(t, setup, "pat", "ghp_takenoverpat0123456789")
	grantTo(t, setup, pat.ID, "project:/srv/app", Constraints{Repos: []string{"org/*"}}, 2*time.Hour)

	a, _ := holderBroker(t, store, clock, "hub_a")
	lease, err := a.LeaseFor(context.Background(), Requester{ExecutorID: "dev1", ProjectID: "/srv/app"}, "ui")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := holderBroker(t, store, clock, "hub_b")
	if got := b.RedactionValues(lease.ID); got != nil {
		t.Fatalf("a broker that does not hold the lease returned %v", got)
	}
	if _, err := b.Restore(context.Background(), lease.ID); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(b.RedactionValues(lease.ID), "\n")
	for _, want := range []string{"sk-delivered-value-0005", "ghp_takenoverpat0123456789"} {
		if !strings.Contains(got, want) {
			t.Errorf("redaction values lack %q: %q", want, got)
		}
	}
	if strings.Contains(got, "withheld-by-the-grant-0005") {
		t.Errorf("redaction values include a key the grant does not deliver: %q", got)
	}
}
