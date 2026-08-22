package sessionstore

// Durability and encryption-at-rest tests for the SQLite session store
// (Task 20176).
//
// pkg/oidcauth's lifecycle tests cover the policy against an in-memory store.
// These cover what only a real database can show: that a session outlives the
// process, that the refresh token is not readable in the file, and that a hub
// with no encryption key degrades by dropping the token rather than writing it
// in the clear.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// newTestStore opens a store on a fresh database in dir. Reopening the same
// dir models a hub restart.
func newTestStore(t *testing.T, dir string) (*Store, *statedb.DB) {
	t.Helper()
	db, err := statedb.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(db)
	if err != nil {
		t.Fatalf("sessionstore.New: %v", err)
	}
	return s, db
}

func sampleRecord(id string, now time.Time) oidcauth.SessionRecord {
	return oidcauth.SessionRecord{
		ID: id,
		Identity: oidcauth.Identity{
			Sub:    "user-123",
			Email:  "alice@example.com",
			Name:   "Alice Dev",
			Groups: []string{"engineering", "cloop-admins"},
			Roles:  []string{"operator"},
		},
		IP:           "203.0.113.9",
		UserAgent:    "Mozilla/5.0 Chrome/128",
		IssuedAt:     now,
		LastSeen:     now,
		ExpiresAt:    now.Add(24 * time.Hour),
		RefreshToken: "super-secret-refresh-token-value",
	}
}

// TestSessionSurvivesProcessRestart is the durability guarantee: a row written
// by one handle is readable, intact, by a handle opened fresh over the same
// file — including the claims RBAC resolves against, which must not be
// re-derived after a restart.
func TestSessionSurvivesProcessRestart(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, "test-passphrase")
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Millisecond)

	first, db1 := newTestStore(t, dir)
	if err := first.Put(sampleRecord("hash-abc", now)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := db1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// "Restart": new handle, new store, same file.
	second, _ := newTestStore(t, dir)
	got, err := second.Get("hash-abc")
	if err != nil {
		t.Fatalf("Get after restart: %v", err)
	}
	if got.Identity.Sub != "user-123" || got.Identity.Email != "alice@example.com" {
		t.Fatalf("identity = %+v, want it preserved verbatim", got.Identity)
	}
	if len(got.Identity.Groups) != 2 || got.Identity.Groups[0] != "engineering" {
		t.Fatalf("groups = %v, want them preserved — RBAC resolves against these", got.Identity.Groups)
	}
	if len(got.Identity.Roles) != 1 || got.Identity.Roles[0] != "operator" {
		t.Fatalf("roles = %v, want [operator]", got.Identity.Roles)
	}
	if got.IP != "203.0.113.9" || got.UserAgent == "" {
		t.Fatalf("request metadata lost: ip=%q ua=%q", got.IP, got.UserAgent)
	}
	if !got.ExpiresAt.Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("expires_at = %s, want %s — the ceiling must not move across a restart",
			got.ExpiresAt, now.Add(24*time.Hour))
	}
	if got.RefreshToken != "super-secret-refresh-token-value" {
		t.Fatalf("refresh token did not round-trip: %q", got.RefreshToken)
	}
}

// TestRefreshTokenIsEncryptedAtRest greps the raw database file for the
// plaintext. This is the assertion that would have caught "we meant to seal it
// and forgot", which no round-trip test can.
func TestRefreshTokenIsEncryptedAtRest(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, "test-passphrase")
	dir := t.TempDir()
	const plaintext = "super-secret-refresh-token-value"

	store, db := newTestStore(t, dir)
	if !store.Available() {
		t.Fatal("with a key set, the store must be able to seal refresh tokens")
	}
	if err := store.Put(sampleRecord("hash-abc", time.Now())); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Checkpoint WAL into the main file so the scan below sees the row.
	if err := db.Vacuum(); err != nil {
		t.Fatalf("Vacuum: %v", err)
	}

	for _, name := range []string{"state.db", "state.db-wal"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue // -wal may not exist after a vacuum
		}
		if bytes.Contains(raw, []byte(plaintext)) {
			t.Fatalf("%s contains the refresh token in plaintext — a stolen database file "+
				"would yield live credentials", name)
		}
	}

	// The sealed column really does hold something, i.e. the test above is not
	// passing because nothing was written.
	row, err := db.GetSession("hash-abc")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if len(row.RefreshSealed) == 0 {
		t.Fatal("refresh_sealed is empty — nothing was stored, so the plaintext scan proved nothing")
	}
	if bytes.Contains(row.RefreshSealed, []byte(plaintext)) {
		t.Fatal("the sealed column contains the plaintext")
	}
}

// TestNoKeyDropsRefreshToken pins the degraded mode: without an encryption key
// the store keeps working and simply does not retain the token. Writing it in
// the clear instead would be the tempting shortcut and is the one outcome that
// must not happen.
func TestNoKeyDropsRefreshToken(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, "")
	dir := t.TempDir()

	store, db := newTestStore(t, dir)
	if store.Available() {
		t.Fatal("with no key configured the store must report that it cannot seal")
	}
	if err := store.Put(sampleRecord("hash-abc", time.Now())); err != nil {
		t.Fatalf("Put must still succeed without a key: %v", err)
	}
	row, err := db.GetSession("hash-abc")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if len(row.RefreshSealed) != 0 {
		t.Fatalf("refresh_sealed holds %d bytes with no key — it must be dropped, never stored in the clear",
			len(row.RefreshSealed))
	}
	// The session itself is fully usable; only the IdP-revocation channel is lost.
	got, err := store.Get("hash-abc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Identity.Sub != "user-123" {
		t.Fatal("the session must remain usable without an encryption key")
	}
	if got.RefreshToken != "" {
		t.Fatalf("refresh token = %q, want empty", got.RefreshToken)
	}
}

// TestWrongKeyDoesNotBreakAuthentication covers a rotated CLOOP_SECRET_KEY:
// existing sessions must keep authenticating, losing only their ability to be
// revalidated. Treating an undecryptable token as a provider refusal would
// sign the whole fleet out on a key rotation.
func TestWrongKeyDoesNotBreakAuthentication(t *testing.T) {
	dir := t.TempDir()

	t.Setenv(secretbroker.EnvPassphraseKey, "original-passphrase")
	first, db := newTestStore(t, dir)
	if err := first.Put(sampleRecord("hash-abc", time.Now())); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Same database, different passphrase — the salt is persisted, so this
	// derives a different key.
	t.Setenv(secretbroker.EnvPassphraseKey, "rotated-passphrase")
	rotated, err := New(db)
	if err != nil {
		t.Fatalf("New after rotation: %v", err)
	}
	got, err := rotated.Get("hash-abc")
	if err != nil {
		t.Fatalf("Get after key rotation must succeed, got %v", err)
	}
	if got.Identity.Sub != "user-123" {
		t.Fatal("a key rotation must not invalidate existing sessions")
	}
	if got.RefreshToken != "" {
		t.Fatalf("refresh token = %q, want empty — an undecryptable token is 'absent', not 'refused'",
			got.RefreshToken)
	}
}

// TestDeleteExpiredHonoursBothClocks checks the sweep selects on expires_at and
// last_seen independently, and returns what it removed so each can be audited.
func TestDeleteExpiredHonoursBothClocks(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, "test-passphrase")
	store, _ := newTestStore(t, t.TempDir())
	now := time.Now().UTC()

	live := sampleRecord("live", now)

	past := sampleRecord("past-ceiling", now)
	past.ExpiresAt = now.Add(-time.Minute)

	idle := sampleRecord("idle", now)
	idle.LastSeen = now.Add(-9 * time.Hour)

	for _, rec := range []oidcauth.SessionRecord{live, past, idle} {
		if err := store.Put(rec); err != nil {
			t.Fatalf("Put %s: %v", rec.ID, err)
		}
	}

	gone, err := store.DeleteExpired(now, now.Add(-8*time.Hour))
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if len(gone) != 2 {
		t.Fatalf("DeleteExpired removed %d rows, want 2 (one per clock)", len(gone))
	}
	ids := map[string]bool{}
	for _, rec := range gone {
		ids[rec.ID] = true
		if rec.Identity.Sub == "" {
			t.Error("returned rows must carry the identity so the sweep can audit them")
		}
	}
	if !ids["past-ceiling"] || !ids["idle"] {
		t.Fatalf("removed %v, want past-ceiling and idle", ids)
	}
	if _, err := store.Get("live"); err != nil {
		t.Fatalf("the live session must survive the sweep: %v", err)
	}
}

// TestTouchIsMonotonic pins the conditional UPDATE. Two processes sharing the
// database can call Touch out of order; the later timestamp must win, or a
// session could be aged into an early idle expiry by a stale writer.
func TestTouchIsMonotonic(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, "test-passphrase")
	store, _ := newTestStore(t, t.TempDir())
	now := time.Now().UTC()

	if err := store.Put(sampleRecord("hash-abc", now)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	ahead := now.Add(10 * time.Minute)
	if err := store.Touch("hash-abc", ahead); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	// A stale writer with an older timestamp must not win.
	if err := store.Touch("hash-abc", now.Add(time.Minute)); err != nil {
		t.Fatalf("Touch (stale): %v", err)
	}
	got, err := store.Get("hash-abc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.LastSeen.Equal(ahead) {
		t.Fatalf("last_seen = %s, want %s — a stale Touch moved the idle clock backwards",
			got.LastSeen, ahead)
	}
}

// TestDeleteBySubjectSparesKeepID covers logout-everywhere: every session for
// the subject goes except the caller's, and nobody else's is touched.
func TestDeleteBySubjectSparesKeepID(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, "test-passphrase")
	store, _ := newTestStore(t, t.TempDir())
	now := time.Now().UTC()

	for _, id := range []string{"mine", "other-1", "other-2"} {
		if err := store.Put(sampleRecord(id, now)); err != nil {
			t.Fatalf("Put %s: %v", id, err)
		}
	}
	bob := sampleRecord("bob", now)
	bob.Identity.Sub = "user-999"
	if err := store.Put(bob); err != nil {
		t.Fatalf("Put bob: %v", err)
	}

	gone, err := store.DeleteBySubject("user-123", "mine")
	if err != nil {
		t.Fatalf("DeleteBySubject: %v", err)
	}
	if len(gone) != 2 {
		t.Fatalf("removed %d, want 2", len(gone))
	}
	if _, err := store.Get("mine"); err != nil {
		t.Fatalf("the caller's own session must be spared: %v", err)
	}
	if _, err := store.Get("bob"); err != nil {
		t.Fatalf("another subject's session must not be touched: %v", err)
	}
}

// TestDueForRefreshOrdersAndBounds checks the revalidation selection: only
// sessions holding a token, oldest check first, capped at the batch size so a
// hub cannot burst its whole population at the IdP in one tick.
func TestDueForRefreshOrdersAndBounds(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, "test-passphrase")
	store, _ := newTestStore(t, t.TempDir())
	now := time.Now().UTC()

	// Never checked — must come first.
	fresh := sampleRecord("never-checked", now)
	if err := store.Put(fresh); err != nil {
		t.Fatal(err)
	}
	// Checked a while ago.
	old := sampleRecord("checked-old", now)
	old.RefreshCheckedAt = now.Add(-time.Hour)
	if err := store.Put(old); err != nil {
		t.Fatal(err)
	}
	// Checked just now — not due.
	recent := sampleRecord("checked-recent", now)
	recent.RefreshCheckedAt = now
	if err := store.Put(recent); err != nil {
		t.Fatal(err)
	}
	// No token to redeem — never selected.
	none := sampleRecord("no-token", now)
	none.RefreshToken = ""
	if err := store.Put(none); err != nil {
		t.Fatal(err)
	}

	due, err := store.DueForRefresh(now.Add(-15*time.Minute), 10)
	if err != nil {
		t.Fatalf("DueForRefresh: %v", err)
	}
	if len(due) != 2 {
		t.Fatalf("due = %d sessions, want 2", len(due))
	}
	if due[0].ID != "never-checked" {
		t.Fatalf("due[0] = %q, want never-checked first", due[0].ID)
	}
	for _, rec := range due {
		if rec.RefreshToken == "" {
			t.Errorf("session %q has no token to redeem and must not be selected", rec.ID)
		}
	}

	// The batch cap is enforced.
	capped, err := store.DueForRefresh(now.Add(-15*time.Minute), 1)
	if err != nil {
		t.Fatalf("DueForRefresh (capped): %v", err)
	}
	if len(capped) != 1 {
		t.Fatalf("capped batch returned %d, want 1", len(capped))
	}
}

// TestGetMissingReturnsSentinel pins the error translation: oidcauth branches
// on its own sentinel, so a storage-layer error leaking through would make an
// unknown cookie look like a database fault.
func TestGetMissingReturnsSentinel(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, "test-passphrase")
	store, _ := newTestStore(t, t.TempDir())
	if _, err := store.Get("nope"); err != oidcauth.ErrSessionNotFound {
		t.Fatalf("Get(missing) = %v, want oidcauth.ErrSessionNotFound", err)
	}
}

// TestStoreSatisfiesInterface is a compile-time assertion with a runtime home:
// the adapter must stay assignable to what oidcauth expects.
func TestStoreSatisfiesInterface(t *testing.T) {
	var _ oidcauth.SessionStore = (*Store)(nil)
}
