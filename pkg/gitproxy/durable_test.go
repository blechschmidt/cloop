package gitproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// memSessionStore is a SessionStore that remembers what it was told.
type memSessionStore struct {
	mu      sync.Mutex
	records map[string]SessionRecord
	closed  map[string]string
	saveErr error
}

func newMemSessionStore() *memSessionStore {
	return &memSessionStore{records: map[string]SessionRecord{}, closed: map[string]string{}}
}

func (m *memSessionStore) SaveSession(rec SessionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	m.records[rec.ID] = rec
	return nil
}

func (m *memSessionStore) CloseSession(id, reason string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed[id] = reason
	return nil
}

func (m *memSessionStore) record(t *testing.T, id string) SessionRecord {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[id]
	if !ok {
		t.Fatalf("no record of session %s", id)
	}
	return rec
}

func (m *memSessionStore) closeReason(id string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.closed[id]
	return r, ok
}

// durableMint mints a scoped, durable session standing on lease_1.
func durableMint(t *testing.T, reg *Registry) *Minted {
	t.Helper()
	pol := WriteBackPolicy()
	pol.AllowFetch = true
	pol.RestrictRefs = []string{"refs/heads/cloop/feature-*"}
	m, err := reg.Mint(MintRequest{
		Upstream:     "https://github.com",
		RepoPatterns: []string{"acme/*"},
		Credential:   Credential{Username: "x-access-token", Password: "ghp_the-upstream-pat", GrantID: "grant_1", LeaseID: "lease_1"},
		Policy:       pol,
		TTL:          time.Hour,
		ProjectID:    "/srv/proj",
		ExecutorID:   "edge-1",
		Actor:        "alice",
		RunID:        "run_7",
		Durable:      true,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return m
}

// TestDurableSessionIsRecordedWithoutItsCredentials: the record carries the
// token's hash and the scope, and neither the token nor the upstream PAT.
func TestDurableSessionIsRecordedWithoutItsCredentials(t *testing.T) {
	reg := newTestRegistry(t, time.Now())
	store := newMemSessionStore()
	reg.Store = store
	m := durableMint(t, reg)
	if !m.Session.Durable() {
		t.Fatal("a durable mint with a store was not recorded")
	}
	rec := store.record(t, m.Session.ID)
	sum := sha256.Sum256([]byte(m.Token))
	if rec.TokenSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("recorded hash %q is not the token's SHA-256", rec.TokenSHA256)
	}
	if rec.LeaseID != "lease_1" || rec.GrantID != "grant_1" || rec.RunID != "run_7" || rec.Actor != "alice" ||
		strings.Join(rec.RepoPatterns, ",") != "acme/*" || rec.Upstream != "https://github.com" ||
		!rec.ExpiresAt.Equal(m.Session.ExpiresAt) {
		t.Fatalf("record = %+v", rec)
	}
	raw, _ := json.Marshal(rec)
	for _, secret := range []string{m.Token, "ghp_the-upstream-pat"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("the record carries a credential: %s", raw)
		}
	}

	// Its end is recorded once, with the reason.
	reg.Close(m.Session.ID, "lease released")
	if reason, ok := store.closeReason(m.Session.ID); !ok || reason != "lease released" {
		t.Fatalf("close recorded as %q, %v", reason, ok)
	}

	// A session minted without Durable is not recorded, nor is its end.
	plain := mintOne(t, reg, MintRequest{})
	if plain.Session.Durable() {
		t.Fatal("a session that did not ask to be durable was recorded")
	}
	reg.Close(plain.Session.ID, "done")
	if _, ok := store.closeReason(plain.Session.ID); ok {
		t.Fatal("the end of an unrecorded session was written to the store")
	}
}

// TestDurableSessionServesWhenItsRecordCannotBeWritten: a store that fails
// costs the session its survival, not its use, and the minted row says so.
func TestDurableSessionServesWhenItsRecordCannotBeWritten(t *testing.T) {
	reg := newTestRegistry(t, time.Now())
	store := newMemSessionStore()
	store.saveErr = errors.New("database is locked")
	reg.Store = store
	var minted []Event
	reg.OnEvent = func(e Event) {
		if e.Kind == EventSessionMinted {
			minted = append(minted, e)
		}
	}
	m := durableMint(t, reg)
	if m.Session.Durable() {
		t.Fatal("a session whose record failed is reported durable")
	}
	if _, err := reg.Authenticate(m.Session.ID, m.Token); err != nil {
		t.Fatalf("the session does not work: %v", err)
	}
	if len(minted) != 1 || !strings.Contains(minted[0].Detail, "not recorded durably") {
		t.Fatalf("minted rows = %+v", minted)
	}
}

// TestRestoreBringsBackTheSameSession is the property the task is about: a
// second registry — a restarted hub — restores the session from its record,
// and the workload's token, minted by the first, authenticates there.
func TestRestoreBringsBackTheSameSession(t *testing.T) {
	now := time.Now()
	first := newTestRegistry(t, now)
	store := newMemSessionStore()
	first.Store = store
	m := durableMint(t, first)
	rec := store.record(t, m.Session.ID)

	second := newTestRegistry(t, now.Add(10*time.Minute))
	second.Store = store
	var restored []Event
	second.OnEvent = func(e Event) {
		if e.Kind == EventSessionRestored {
			restored = append(restored, e)
		}
	}
	s, err := second.Restore(RestoreRequest{
		Record:     rec,
		Credential: Credential{Username: "x-access-token", Password: "ghp_rederived"},
		From:       "hub_old",
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	got, err := second.Authenticate(m.Session.ID, m.Token)
	if err != nil || got != s {
		t.Fatalf("the original token on the restarted registry = %v, %v", got, err)
	}
	if _, err := second.Authenticate(m.Session.ID, m.Token+"x"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("a wrong token = %v", err)
	}
	if !s.ExpiresAt.Equal(m.Session.ExpiresAt) || !s.Scoped() || !s.AllowsRepo("acme/tool") || s.AllowsRepo("evil/tool") {
		t.Fatalf("restored scope or expiry differs: %+v", s)
	}
	if !s.Policy.AllowsRef("refs/heads/cloop/feature-x") || s.Policy.AllowsRef("refs/heads/cloop/other") ||
		s.Policy.AllowsRef("refs/heads/main") {
		t.Fatalf("restored ref policy differs: %s", s.Policy.RefSummary())
	}
	if s.LeaseID != "lease_1" || s.GrantID != "grant_1" || s.RunID != "run_7" || !s.Durable() {
		t.Fatalf("restored labels = %+v", s)
	}
	if cred, release, err := second.credentialFor(context.Background(), s); err != nil || cred.Password != "ghp_rederived" ||
		cred.LeaseID != "lease_1" || cred.GrantID != "grant_1" {
		t.Fatalf("restored upstream credential = %+v, %v", cred, err)
	} else {
		release()
	}
	if len(restored) != 1 || !strings.Contains(restored[0].Detail, "hub_old") || restored[0].SessionID != s.ID {
		t.Fatalf("restored rows = %+v", restored)
	}

	// Its end is recorded like a minted one's.
	second.CloseForLease("lease_1", "lease released")
	if reason, ok := store.closeReason(s.ID); !ok || reason != "lease released" {
		t.Fatalf("restored session's close = %q, %v", reason, ok)
	}
}

// TestRestoreRefusesWhatMintWouldRefuse: a record read back from a database
// is checked as strictly as a new session.
func TestRestoreRefusesWhatMintWouldRefuse(t *testing.T) {
	now := time.Now()
	reg := newTestRegistry(t, now)
	store := newMemSessionStore()
	reg.Store = store
	m := durableMint(t, reg)
	good := store.record(t, m.Session.ID)

	other := newTestRegistry(t, now)
	cases := []struct {
		name   string
		mutate func(*SessionRecord)
		want   error
	}{
		{"lapsed", func(r *SessionRecord) { r.ExpiresAt = now.Add(-time.Second) }, ErrSessionLapsed},
		{"hash not sha256", func(r *SessionRecord) { r.TokenSHA256 = "abcd" }, nil},
		{"no policy", func(r *SessionRecord) { r.Policy = Policy{} }, nil},
		{"credentials in upstream", func(r *SessionRecord) { r.Upstream = "https://user:pw@github.com" }, nil},
		{"scoped upstream with a path", func(r *SessionRecord) { r.Upstream = "https://github.com/acme" }, nil},
		{"policy that permits nothing", func(r *SessionRecord) {
			r.Policy = Policy{AllowedRefs: []string{"refs/heads/x"}}
		}, nil},
		{"pinned repo disagreeing with its upstream", func(r *SessionRecord) {
			r.RepoPatterns, r.Upstream, r.RepoPath = nil, "https://github.com/acme/tool.git", "evil/tool"
		}, nil},
		{"empty id", func(r *SessionRecord) { r.ID = "" }, nil},
		{"deadline beyond any mint", func(r *SessionRecord) { r.ExpiresAt = r.IssuedAt.Add(MaxSessionTTL + time.Minute) }, nil},
		{"issued in the future", func(r *SessionRecord) {
			r.IssuedAt, r.ExpiresAt = now.Add(10*time.Hour), now.Add(20*time.Hour)
		}, nil},
		{"no issue time", func(r *SessionRecord) { r.IssuedAt = time.Time{} }, nil},
	}
	for _, tc := range cases {
		rec := good
		rec.RepoPatterns = append([]string(nil), good.RepoPatterns...)
		tc.mutate(&rec)
		_, err := other.Restore(RestoreRequest{Record: rec, Credential: Credential{Password: "p"}})
		if err == nil {
			t.Errorf("%s: restored", tc.name)
			continue
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}

	// Restoring over a live session is refused rather than replacing it.
	if _, err := reg.Restore(RestoreRequest{Record: good, Credential: Credential{Password: "p"}}); !errors.Is(err, ErrSessionExists) {
		t.Fatalf("restore over the live session = %v", err)
	}
	// And a refresher needs the credential's expiry, as on Mint.
	_, err := other.Restore(RestoreRequest{Record: good, Credential: Credential{Password: "p"},
		Refresh: func(context.Context, string) (Refreshed, error) { return Refreshed{}, nil }})
	if err == nil {
		t.Fatal("a refresher without an expiry was restored")
	}
}

// TestSuspendLeavesTheRecordOpen: a hub stopping gracefully, or handing a
// lease to the process that adopted its run, stops serving the session but
// leaves it to be restored — no close recorded, no OnEnd.
func TestSuspendLeavesTheRecordOpen(t *testing.T) {
	reg := newTestRegistry(t, time.Now())
	store := newMemSessionStore()
	reg.Store = store
	ended := false
	m := durableMint(t, reg)
	reg.mu.Lock()
	m.Session.onEnd = func() { ended = true }
	reg.mu.Unlock()
	other := durableMint(t, reg)
	// Not recorded, so nothing could restore it: closed, not suspended.
	unrecorded := mintOne(t, reg, MintRequest{Credential: Credential{Password: "p", LeaseID: "lease_1"}})

	ids := reg.SuspendForLease("lease_1", "the hub is shutting down")
	if len(ids) != 2 || !slices.Contains(ids, m.Session.ID) || !slices.Contains(ids, other.Session.ID) {
		t.Fatalf("suspended %v of lease_1, want the two recorded sessions", ids)
	}
	if reg.Known(m.Session.ID) || reg.Known(other.Session.ID) || reg.Known(unrecorded.Session.ID) {
		t.Fatal("a session of the lease is still served")
	}
	if reason := unrecorded.Session.CloseReason(); reason != "the hub is shutting down" {
		t.Fatalf("the unrecorded session ended with %q, want it closed with the reason", reason)
	}
	if _, ok := store.closeReason(m.Session.ID); ok {
		t.Fatal("suspending recorded the session as closed")
	}
	if ended {
		t.Fatal("suspending ran the session's OnEnd")
	}
	if !m.Session.Closed() || !strings.HasPrefix(m.Session.CloseReason(), "suspended") {
		t.Fatalf("suspended session reason = %q", m.Session.CloseReason())
	}
	if reg.Suspend(m.Session.ID, "again") {
		t.Fatal("a second suspend found the session")
	}
}

// TestCloseForLeaseClosesOnlyThatLease's sessions.
func TestCloseForLeaseClosesOnlyThatLease(t *testing.T) {
	reg := newTestRegistry(t, time.Now())
	a := durableMint(t, reg)
	b := mintOne(t, reg, MintRequest{Credential: Credential{Password: "p", LeaseID: "lease_2"}})
	if n := reg.CloseForLease("lease_1", "lease released"); n != 1 {
		t.Fatalf("closed %d", n)
	}
	if reg.Known(a.Session.ID) || !reg.Known(b.Session.ID) {
		t.Fatal("CloseForLease closed the wrong sessions")
	}
	if n := reg.CloseForLease("", "x"); n != 0 {
		t.Fatalf("an empty lease id closed %d sessions", n)
	}
}

// TestCloseForGrantClosesOnlyThatGrantsSessions (Task 20403): one grant of a
// lease revoked must end the sessions its credential feeds and leave the
// sessions of the lease's other grants serving.
func TestCloseForGrantClosesOnlyThatGrantsSessions(t *testing.T) {
	reg := newTestRegistry(t, time.Now())
	revoked := mintOne(t, reg, MintRequest{Credential: Credential{Password: "p", LeaseID: "lease_1", GrantID: "grant_a"}})
	other := mintOne(t, reg, MintRequest{Credential: Credential{Password: "q", LeaseID: "lease_1", GrantID: "grant_b"}})
	elsewhere := mintOne(t, reg, MintRequest{Credential: Credential{Password: "r", LeaseID: "lease_2", GrantID: "grant_a"}})
	if n := reg.CloseForGrant("lease_1", "grant_a", "grant revoked"); n != 1 {
		t.Fatalf("closed %d sessions, want 1", n)
	}
	if reg.Known(revoked.Session.ID) {
		t.Error("the revoked grant's session is still serving")
	}
	if !reg.Known(other.Session.ID) || !reg.Known(elsewhere.Session.ID) {
		t.Error("CloseForGrant closed a session of another grant or another lease")
	}
	if n := reg.CloseForGrant("lease_1", "", "x"); n != 0 {
		t.Fatalf("an empty grant id closed %d sessions", n)
	}
}

// TestReapRecordsTheExpiry of a durable session.
func TestReapRecordsTheExpiry(t *testing.T) {
	now := time.Now()
	var mu sync.Mutex
	reg := newTestRegistry(t, now)
	setClock(reg, &now, &mu)
	store := newMemSessionStore()
	reg.Store = store
	m := durableMint(t, reg)
	mu.Lock()
	now = now.Add(2 * time.Hour)
	mu.Unlock()
	if n := reg.ReapExpired(); n != 1 {
		t.Fatalf("reaped %d", n)
	}
	if reason, ok := store.closeReason(m.Session.ID); !ok || reason != "expired" {
		t.Fatalf("reap recorded %q, %v", reason, ok)
	}
}
