package gitproxy

// Renew (Task 20422): a workspace's session outlives session_minutes while
// its run does, and the renewal survives a restore.

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestRenewMovesTheDeadlineAndRecordsIt: a renewal moves the deadline to the
// TTL from now — the session then authenticates past where it would have
// lapsed — records it, and says so on the trail; one that would not move it
// forward changes nothing.
func TestRenewMovesTheDeadlineAndRecordsIt(t *testing.T) {
	var mu sync.Mutex
	t0 := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	now := t0
	reg := newTestRegistry(t, t0)
	setClock(reg, &now, &mu)
	store := newMemSessionStore()
	reg.Store = store
	var events []Event
	reg.OnEvent = func(e Event) { events = append(events, e) }
	m := durableMint(t, reg)
	id := m.Session.ID

	mu.Lock()
	now = t0.Add(55 * time.Minute)
	mu.Unlock()
	got, err := reg.Renew(id, time.Hour)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	want := t0.Add(55*time.Minute + time.Hour)
	if !got.Equal(want) || !m.Session.ExpiresAt().Equal(want) || !m.Session.RenewedAt().Equal(t0.Add(55*time.Minute)) {
		t.Fatalf("renewed to %s (session %s, renewed at %s), want %s", got, m.Session.ExpiresAt(), m.Session.RenewedAt(), want)
	}
	rec := store.record(t, id)
	if !rec.ExpiresAt.Equal(want) || !rec.RenewedAt.Equal(t0.Add(55*time.Minute)) {
		t.Fatalf("the record was not renewed: %+v", rec)
	}
	last := events[len(events)-1]
	if last.Kind != EventSessionRenewed || last.SessionID != id || !strings.Contains(last.Detail, want.Format(time.RFC3339)) {
		t.Fatalf("the renewal was reported as %+v", last)
	}

	// Past the first deadline, it still authenticates.
	mu.Lock()
	now = t0.Add(90 * time.Minute)
	mu.Unlock()
	if _, err := reg.Authenticate(id, m.Token); err != nil {
		t.Fatalf("the renewed session past its first deadline: %v", err)
	}

	// A renewal that would not move it forward leaves it, and says nothing.
	n := len(events)
	if got, err := reg.Renew(id, time.Minute); err != nil || !got.Equal(want) || len(events) != n {
		t.Fatalf("a shorter renewal = %s, %v (events %d → %d); want the deadline unchanged and nothing reported",
			got, err, n, len(events))
	}
}

// TestARenewalTheRecordMissedSaysSo: a renewal the store could not record
// still renews — a busy database must not cut a live run's write-back short —
// and its trail row says the process that adopts the run restores the session
// only until the deadline the record still holds.
func TestARenewalTheRecordMissedSaysSo(t *testing.T) {
	var mu sync.Mutex
	t0 := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	now := t0
	reg := newTestRegistry(t, t0)
	setClock(reg, &now, &mu)
	store := newMemSessionStore()
	reg.Store = store
	var events []Event
	reg.OnEvent = func(e Event) { events = append(events, e) }
	m := durableMint(t, reg)
	first := m.Session.ExpiresAt()

	store.mu.Lock()
	store.renewErr = errors.New("database is locked")
	store.mu.Unlock()
	mu.Lock()
	now = first.Add(-2 * time.Minute)
	mu.Unlock()
	got, err := reg.Renew(m.Session.ID, time.Hour)
	if err != nil || !got.After(first) {
		t.Fatalf("Renew = %s, %v; want it renewed past %s regardless", got, err, first)
	}
	last := events[len(events)-1]
	if last.Kind != EventSessionRenewed || !strings.Contains(last.Detail, "not recorded durably") ||
		!strings.Contains(last.Detail, "database is locked") || !strings.Contains(last.Detail, first.UTC().Format(time.RFC3339)) {
		t.Fatalf("the unrecorded renewal was reported as %q", last.Detail)
	}
	if rec := store.record(t, m.Session.ID); !rec.ExpiresAt.Equal(first) {
		t.Fatalf("the record moved to %s", rec.ExpiresAt)
	}
}

// TestRenewRefusesWhatIsOver: a lapsed session stays lapsed, a closed one
// stays closed, and no renewal is longer than any mint.
func TestRenewRefusesWhatIsOver(t *testing.T) {
	var mu sync.Mutex
	t0 := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	now := t0
	reg := newTestRegistry(t, t0)
	setClock(reg, &now, &mu)
	m := durableMint(t, reg)

	if _, err := reg.Renew(m.Session.ID, MaxSessionTTL+time.Minute); err == nil {
		t.Fatal("a renewal past MaxSessionTTL was accepted")
	}
	mu.Lock()
	now = t0.Add(time.Hour)
	mu.Unlock()
	if _, err := reg.Renew(m.Session.ID, time.Hour); !errors.Is(err, ErrSessionLapsed) {
		t.Fatalf("renewing a lapsed session: %v, want ErrSessionLapsed", err)
	}

	other := durableMint(t, reg)
	reg.Close(other.Session.ID, "run finished")
	if _, err := reg.Renew(other.Session.ID, time.Hour); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("renewing a closed session: %v, want ErrSessionNotFound", err)
	}
}

// TestRestoreBoundsARenewedSessionFromItsRenewal: a session renewed past its
// first period is restored to its renewed deadline — bounded from the
// renewal, not the issue — while a record claiming a deadline neither a mint
// nor a renewal could have written, or a renewal still to come, is refused.
func TestRestoreBoundsARenewedSessionFromItsRenewal(t *testing.T) {
	now := time.Date(2026, 10, 12, 21, 0, 0, 0, time.UTC)
	reg := newTestRegistry(t, now)
	m := durableMint(t, newTestRegistry(t, now.Add(-13*time.Hour)))
	rec := m.Session.record()
	rec.IssuedAt = now.Add(-13 * time.Hour)
	rec.RenewedAt = now.Add(-10 * time.Minute)
	rec.ExpiresAt = now.Add(50 * time.Minute)

	if err := reg.CheckRestore(rec); err != nil {
		t.Fatalf("a renewed session's record: %v", err)
	}
	restored, err := reg.Restore(RestoreRequest{Record: rec, Credential: Credential{Password: "ghp_rederived"}})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !restored.ExpiresAt().Equal(rec.ExpiresAt) || !restored.RenewedAt().Equal(rec.RenewedAt) {
		t.Fatalf("restored until %s, renewed at %s", restored.ExpiresAt(), restored.RenewedAt())
	}
	if _, err := reg.Authenticate(rec.ID, m.Token); err != nil {
		t.Fatalf("the restored renewed session: %v", err)
	}

	for name, bad := range map[string]func(r *SessionRecord){
		"never renewed, past its first period": func(r *SessionRecord) { r.RenewedAt = time.Time{} },
		"renewed beyond any TTL":               func(r *SessionRecord) { r.ExpiresAt = now.Add(MaxSessionTTL + time.Hour) },
		// A renewal no hub has made yet counts from now.
		"renewed in the future": func(r *SessionRecord) {
			r.RenewedAt = now.Add(2 * time.Hour)
			r.ExpiresAt = now.Add(MaxSessionTTL + time.Hour)
		},
	} {
		r := rec
		r.ID = rec.ID + "x"
		bad(&r)
		if err := newTestRegistry(t, now).CheckRestore(r); err == nil {
			t.Errorf("%s: the record was accepted", name)
		}
	}
}
