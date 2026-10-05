package egressbroker

// Tests for a session that outlives the hub process that redeemed it (Task
// 20383): recorded without its token, renewed and checkpointed as it goes,
// restored by another broker over the same grants with the same credential and
// its counters, so its quota still binds — and never restored once its grant
// was revoked or expired.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// memSessionStore is a SessionStore that remembers what it was told.
type memSessionStore struct {
	mu          sync.Mutex
	records     map[string]SessionRecord
	extended    map[string]time.Time
	checkpoints map[string][]SessionCounters
	closed      map[string]string
}

func newMemSessionStore() *memSessionStore {
	return &memSessionStore{records: map[string]SessionRecord{}, extended: map[string]time.Time{},
		checkpoints: map[string][]SessionCounters{}, closed: map[string]string{}}
}

func (m *memSessionStore) SaveSession(rec SessionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[rec.ID] = rec
	return nil
}

func (m *memSessionStore) ExtendSession(id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.extended[id] = at
	return nil
}

func (m *memSessionStore) CheckpointSession(id string, c SessionCounters) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkpoints[id] = append(m.checkpoints[id], c)
	rec := m.records[id]
	rec.Counters = c
	m.records[id] = rec
	return nil
}

func (m *memSessionStore) CloseSession(id, reason string, _ time.Time, c SessionCounters) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed[id] = reason
	rec := m.records[id]
	rec.Counters = c
	m.records[id] = rec
	return nil
}

func (m *memSessionStore) record(t *testing.T, id string) SessionRecord {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[id]
	if !ok {
		t.Fatalf("no record of %s", id)
	}
	return rec
}

// twoBrokers builds two brokers over one grant store — a hub process and the
// one that replaces it — each recording sessions in store.
func twoBrokers(t *testing.T, now *time.Time, store *memSessionStore, opts ...Option) (first, second *Broker, audit *recordingAuditor) {
	t.Helper()
	grants := NewMemStore()
	audit = &recordingAuditor{}
	build := func() *Broker {
		all := append([]Option{
			WithAuditor(audit),
			WithEndpoint("127.0.0.1:8899"),
			WithClock(func() time.Time { return *now }),
			WithSessionStore(store),
		}, opts...)
		b, err := New(grants, all...)
		if err != nil {
			t.Fatalf("new broker: %v", err)
		}
		return b
	}
	return build(), build(), audit
}

func redeemDurable(t *testing.T, b *Broker) *Redemption {
	t.Helper()
	red, err := b.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/app", Labels: map[string]string{"site": "lab"}},
		RunID:     "run-1",
		TaskID:    "run-1",
		Actor:     "alice",
		Durable:   true,
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	return red
}

func TestDurableEgressSessionIsRecordedWithoutItsToken(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	store := newMemSessionStore()
	b, _, _ := twoBrokers(t, &now, store, WithMaxSessionTTL(10*time.Minute))
	g := mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: time.Hour,
		MaxBytesDown: 4096})
	red := redeemDurable(t, b)
	if !red.Session.Durable() {
		t.Fatal("a durable redemption was not recorded")
	}
	rec := store.record(t, red.Session.ID)
	sum := sha256.Sum256([]byte(red.Token))
	if rec.TokenSHA256 != hex.EncodeToString(sum[:]) || rec.GrantID != g.ID || rec.Grant.ID != g.ID ||
		rec.Grant.MaxBytesDown != 4096 || rec.RunID != "run-1" || rec.Labels["site"] != "lab" ||
		!rec.ExpiresAt.Equal(red.Session.ExpiresAt()) {
		t.Fatalf("record = %+v", rec)
	}
	raw, _ := json.Marshal(rec)
	if strings.Contains(string(raw), red.Token) || strings.Contains(string(raw), red.ProxyURL) {
		t.Fatalf("the record carries the proxy credential: %s", raw)
	}

	// A renewal moves the recorded deadline.
	now = now.Add(8 * time.Minute)
	got, err := b.ExtendSession(context.Background(), red.Session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if at := store.extended[red.Session.ID]; !at.Equal(got) {
		t.Fatalf("recorded deadline %s, want %s", at, got)
	}

	// A checkpoint writes the counters when they moved, and only then.
	_ = red.Session.addDown(100)
	b.CheckpointSession(red.Session.ID)
	b.CheckpointSession(red.Session.ID)
	if cps := store.checkpoints[red.Session.ID]; len(cps) != 1 || cps[0].BytesDown != 100 {
		t.Fatalf("checkpoints = %+v, want one at 100 bytes down", cps)
	}

	b.CloseSession(red.Session.ID, "run ended")
	if store.closed[red.Session.ID] != "run ended" {
		t.Fatalf("close recorded as %q", store.closed[red.Session.ID])
	}

	// Not asked to be durable: not recorded.
	plain, err := b.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/app"}})
	if err != nil {
		t.Fatal(err)
	}
	if plain.Session.Durable() {
		t.Fatal("a session that did not ask to be durable was recorded")
	}
}

// TestRestoredEgressSessionKeepsCountingAgainstItsQuota is item 7 of the task:
// the counters checkpointed into the record come back with the session, so a
// sandbox cannot reset its quota by outliving a hub process.
func TestRestoredEgressSessionKeepsCountingAgainstItsQuota(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	store := newMemSessionStore()
	first, second, audit := twoBrokers(t, &now, store)
	mustGrant(t, first, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: time.Hour,
		MaxBytesDown: 1000})
	red := redeemDurable(t, first)

	// The first process moves 990 bytes and checkpoints, then dies.
	if err := red.Session.addDown(990); err != nil {
		t.Fatal(err)
	}
	first.CheckpointSession(red.Session.ID)

	now = now.Add(time.Minute)
	sess, err := second.RestoreSession(context.Background(), RestoreRequest{
		Record: store.record(t, red.Session.ID), From: "hub_old",
	})
	if err != nil {
		t.Fatalf("RestoreSession: %v", err)
	}
	if got, err := second.Authenticate(red.Session.ID, red.Token); err != nil || got != sess {
		t.Fatalf("the original token on the second broker = %v, %v", got, err)
	}
	if sess.BytesDown() != 990 || sess.Grant.MaxBytesDown != 1000 {
		t.Fatalf("restored counters %d of quota %d", sess.BytesDown(), sess.Grant.MaxBytesDown)
	}
	if !sess.ExpiresAt().Equal(red.Session.ExpiresAt()) || !sess.Durable() {
		t.Fatalf("restored deadline %s, durable %v", sess.ExpiresAt(), sess.Durable())
	}
	// Twenty more bytes cross the quota the first process had nearly spent.
	if err := sess.addDown(20); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("crossing the quota after the restore = %v, want ErrQuotaExceeded", err)
	}
	if err := sess.checkLive(now); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("a spent session after the restore = %v", err)
	}
	ev, ok := findEvent(audit.all(), secretbroker.ActionEgressRestore, secretbroker.DecisionAllow)
	if !ok || ev.LeaseID != red.Session.ID || ev.RunID != "run-1" || !strings.Contains(ev.Reason, "hub_old") {
		t.Fatalf("restore row = %+v\n%s", ev, renderEvents(audit.all()))
	}
}

// TestEgressRestoreRefusesARevokedOrLapsedSession: what was revoked or expired
// while no process held the session stays ended.
func TestEgressRestoreRefusesARevokedOrLapsedSession(t *testing.T) {
	t.Run("revoked grant", func(t *testing.T) {
		now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
		store := newMemSessionStore()
		first, second, audit := twoBrokers(t, &now, store)
		g := mustGrant(t, first, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: time.Hour})
		red := redeemDurable(t, first)
		rec := store.record(t, red.Session.ID)
		// Revoked through the other broker, which does not hold the session —
		// as a revocation made while the first process was down would be.
		if err := second.Revoke(context.Background(), g.ID, "admin"); err != nil {
			t.Fatal(err)
		}
		if _, err := second.RestoreSession(context.Background(), RestoreRequest{Record: rec}); !errors.Is(err, ErrGrantRevoked) {
			t.Fatalf("restore of a revoked grant's session = %v", err)
		}
		if second.Session(red.Session.ID) != nil {
			t.Fatal("a refused restore left the session live")
		}
		if _, ok := findEvent(audit.all(), secretbroker.ActionEgressRestore, secretbroker.DecisionDeny); !ok {
			t.Fatalf("no denied restore row:\n%s", renderEvents(audit.all()))
		}
	})
	t.Run("lapsed session", func(t *testing.T) {
		now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
		store := newMemSessionStore()
		first, second, _ := twoBrokers(t, &now, store, WithMaxSessionTTL(10*time.Minute))
		mustGrant(t, first, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: time.Hour})
		red := redeemDurable(t, first)
		now = now.Add(11 * time.Minute)
		if _, err := second.RestoreSession(context.Background(), RestoreRequest{
			Record: store.record(t, red.Session.ID)}); !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("restore of a lapsed session = %v", err)
		}
	})
	t.Run("expired grant", func(t *testing.T) {
		now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
		store := newMemSessionStore()
		first, second, _ := twoBrokers(t, &now, store)
		mustGrant(t, first, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: 5 * time.Minute})
		red := redeemDurable(t, first)
		now = now.Add(6 * time.Minute)
		if _, err := second.RestoreSession(context.Background(), RestoreRequest{
			Record: store.record(t, red.Session.ID)}); !errors.Is(err, ErrGrantExpired) {
			t.Fatalf("restore under an expired grant = %v", err)
		}
	})
	t.Run("already live", func(t *testing.T) {
		now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
		store := newMemSessionStore()
		first, _, _ := twoBrokers(t, &now, store)
		mustGrant(t, first, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: time.Hour})
		red := redeemDurable(t, first)
		if _, err := first.RestoreSession(context.Background(), RestoreRequest{
			Record: store.record(t, red.Session.ID)}); !errors.Is(err, ErrSessionExists) {
			t.Fatalf("restore over a live session = %v", err)
		}
	})
	t.Run("grant no longer matches the requester", func(t *testing.T) {
		now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
		store := newMemSessionStore()
		first, second, _ := twoBrokers(t, &now, store)
		mustGrant(t, first, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: time.Hour})
		red := redeemDurable(t, first)
		rec := store.record(t, red.Session.ID)
		rec.ProjectID = "/srv/other"
		if _, err := second.RestoreSession(context.Background(), RestoreRequest{Record: rec}); !errors.Is(err, ErrNoGrant) {
			t.Fatalf("restore for another requester = %v", err)
		}
	})
}

// TestSuspendSessionLeavesItRestorable: a hub stopping gracefully suspends a
// durable session — no close row, record open, counters checkpointed.
func TestSuspendSessionLeavesItRestorable(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	store := newMemSessionStore()
	first, second, audit := twoBrokers(t, &now, store)
	mustGrant(t, first, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: time.Hour})
	red := redeemDurable(t, first)
	_ = red.Session.addUp(42)

	if !first.SuspendSession(red.Session.ID, "the hub is shutting down") {
		t.Fatal("suspend did not find the session")
	}
	if first.Session(red.Session.ID) != nil || !red.Session.Closed() {
		t.Fatal("a suspended session is still served")
	}
	if _, closed := store.closed[red.Session.ID]; closed {
		t.Fatal("suspending recorded the session closed")
	}
	if n := countEvents(audit.all(), secretbroker.ActionEgressClose); n != 0 {
		t.Fatalf("suspending wrote %d close rows", n)
	}
	rec := store.record(t, red.Session.ID)
	if rec.Counters.BytesUp != 42 {
		t.Fatalf("suspend did not checkpoint the counters: %+v", rec.Counters)
	}
	if _, err := second.RestoreSession(context.Background(), RestoreRequest{Record: rec}); err != nil {
		t.Fatalf("a suspended session could not be restored: %v", err)
	}
}

// flakyGrants is a grant store whose reads can be made to fail, as a busy or
// unreachable database does.
type flakyGrants struct {
	Store
	fail atomic.Bool
}

func (f *flakyGrants) GetGrant(id string) (Grant, error) {
	if f.fail.Load() {
		return Grant{}, errors.New("database is locked")
	}
	return f.Store.GetGrant(id)
}

// brokerOver builds a broker over grants recording sessions in store, with
// options of its own — a hub process configured differently from the one it
// replaces.
func brokerOver(t *testing.T, grants Store, now *time.Time, store *memSessionStore, audit secretbroker.Auditor, opts ...Option) *Broker {
	t.Helper()
	b, err := New(grants, append([]Option{WithAuditor(audit), WithEndpoint("127.0.0.1:8899"),
		WithClock(func() time.Time { return *now }), WithSessionStore(store)}, opts...)...)
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	return b
}

// TestEgressRestoreHoldsTheRecordToTodaysLimits: a restored session is never
// wider than what the restoring hub would redeem now — a quota default lowered
// meanwhile applies, a deadline is held to the session ceiling from now — and
// a grant store that cannot be read ends nothing.
func TestEgressRestoreHoldsTheRecordToTodaysLimits(t *testing.T) {
	t.Run("default quota", func(t *testing.T) {
		now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
		store, grants, audit := newMemSessionStore(), NewMemStore(), &recordingAuditor{}
		first := brokerOver(t, grants, &now, store, audit, WithDefaultQuotas(0, 10_000))
		mustGrant(t, first, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: time.Hour})
		red := redeemDurable(t, first)
		rec := store.record(t, red.Session.ID)

		lowered := brokerOver(t, grants, &now, store, audit, WithDefaultQuotas(0, 1_000))
		sess, err := lowered.RestoreSession(context.Background(), RestoreRequest{Record: rec})
		if err != nil {
			t.Fatal(err)
		}
		if sess.Grant.MaxBytesDown != 1_000 {
			t.Fatalf("restored under a lowered default with a %d-byte quota, want 1000", sess.Grant.MaxBytesDown)
		}
		lowered.SuspendSession(sess.ID, "next")

		raised := brokerOver(t, grants, &now, store, audit, WithDefaultQuotas(0, 50_000))
		sess, err = raised.RestoreSession(context.Background(), RestoreRequest{Record: rec})
		if err != nil {
			t.Fatal(err)
		}
		if sess.Grant.MaxBytesDown != 10_000 {
			t.Fatalf("restored under a raised default with a %d-byte quota, want the 10000 it was redeemed with",
				sess.Grant.MaxBytesDown)
		}
	})
	t.Run("deadline beyond the ceiling", func(t *testing.T) {
		now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
		store := newMemSessionStore()
		first, second, _ := twoBrokers(t, &now, store, WithMaxSessionTTL(10*time.Minute))
		mustGrant(t, first, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: 24 * time.Hour})
		red := redeemDurable(t, first)
		rec := store.record(t, red.Session.ID)
		rec.ExpiresAt = now.Add(20 * time.Hour) // as a record edited underneath the broker
		sess, err := second.RestoreSession(context.Background(), RestoreRequest{Record: rec})
		if err != nil {
			t.Fatal(err)
		}
		if want := now.Add(10 * time.Minute); !sess.ExpiresAt().Equal(want) {
			t.Fatalf("restored until %s, want the ceiling from now, %s", sess.ExpiresAt(), want)
		}
	})
	t.Run("store unreadable", func(t *testing.T) {
		now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
		store, audit := newMemSessionStore(), &recordingAuditor{}
		grants := &flakyGrants{Store: NewMemStore()}
		first := brokerOver(t, grants, &now, store, audit)
		mustGrant(t, first, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: time.Hour})
		red := redeemDurable(t, first)
		rec := store.record(t, red.Session.ID)

		second := brokerOver(t, grants, &now, store, audit)
		grants.fail.Store(true)
		if _, err := second.RestoreSession(context.Background(), RestoreRequest{Record: rec}); !errors.Is(err, ErrStoreUnavailable) {
			t.Fatalf("restore with the grant store unreadable = %v, want ErrStoreUnavailable", err)
		}
		if _, ok := findEvent(audit.all(), secretbroker.ActionEgressRestore, secretbroker.DecisionDeny); ok {
			t.Fatalf("a read error was recorded as a refusal:\n%s", renderEvents(audit.all()))
		}
		store.mu.Lock()
		_, closed := store.closed[red.Session.ID]
		store.mu.Unlock()
		if closed || second.Session(red.Session.ID) != nil {
			t.Fatal("a read error ended or served the session")
		}
		grants.fail.Store(false)
		if _, err := second.RestoreSession(context.Background(), RestoreRequest{Record: rec}); err != nil {
			t.Fatalf("the retry once the store answers = %v", err)
		}
	})
}
