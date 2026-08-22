package statedb

// Storage-level tests for the sealing-key registry (Task 20181).
//
// These sit below pkg/secretbroker: they check the properties the SQL is
// solely responsible for, where a Go-side check would be a race or a lie.

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openKeysDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func putTestKEK(t *testing.T, db *DB, id, state string) {
	t.Helper()
	if err := db.PutKEK(KEKRow{
		ID: id, Salt: "aa", State: state, CheckValue: []byte("cv"),
		CreatedAt: "2026-01-01T00:00:00Z", CreatedBy: "test",
	}); err != nil {
		t.Fatalf("put kek %s: %v", id, err)
	}
}

// TestOnlyOnePrimaryKEKCanExist. The invariant is enforced by a partial unique
// index rather than by application code, because two processes promoting
// concurrently is exactly the case application code cannot cover: both would
// read "there is one primary", both would demote it, and both would promote
// their own.
func TestOnlyOnePrimaryKEKCanExist(t *testing.T) {
	db := openKeysDB(t)
	putTestKEK(t, db, "kek_a", "active")
	putTestKEK(t, db, "kek_b", "active")

	if err := db.PromoteKEK("kek_a", time.Now()); err != nil {
		t.Fatalf("promote a: %v", err)
	}
	if err := db.PromoteKEK("kek_b", time.Now()); err != nil {
		t.Fatalf("promote b: %v", err)
	}

	primaries := 0
	keks, err := db.ListKEKs()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, k := range keks {
		if k.State == "primary" {
			primaries++
		}
	}
	if primaries != 1 {
		t.Fatalf("%d primaries after two promotions, want 1", primaries)
	}
	row, ok, err := db.PrimaryKEK()
	if err != nil || !ok {
		t.Fatalf("PrimaryKEK: %v ok=%v", err, ok)
	}
	if row.ID != "kek_b" {
		t.Errorf("primary = %s, want kek_b", row.ID)
	}
}

// TestRetirementIsTerminal. A crypto-shred that an ordinary upsert can undo is
// not a shred — it is a flag, and the whole point of blanking the salt is that
// the guarantee should survive code that does not know about it.
func TestRetirementIsTerminal(t *testing.T) {
	db := openKeysDB(t)
	putTestKEK(t, db, "kek_doomed", "active")

	if err := db.RetireKEK("kek_doomed", time.Now()); err != nil {
		t.Fatalf("retire: %v", err)
	}

	// The obvious resurrection: write the record again with a live salt.
	if err := db.PutKEK(KEKRow{
		ID: "kek_doomed", Salt: "bb", State: "active", CheckValue: []byte("cv"),
	}); err != nil {
		t.Fatalf("put: %v", err)
	}

	keks, _ := db.ListKEKs()
	for _, k := range keks {
		if k.ID != "kek_doomed" {
			continue
		}
		if k.Salt != "" {
			t.Errorf("a retired key's salt was restored by an upsert: %q", k.Salt)
		}
		if k.State != "retired" {
			t.Errorf("a retired key's state was restored to %q", k.State)
		}
	}
	// And it cannot be promoted back into service.
	if err := db.PromoteKEK("kek_doomed", time.Now()); !errors.Is(err, ErrKEKNotFound) {
		t.Errorf("promoting a retired key: err = %v, want ErrKEKNotFound", err)
	}
}

// TestRetirementRefusesWhileEitherPopulationReferencesTheKey exercises both
// arms of the reference check, including the sessions arm's "only rows that
// actually hold sealed material count" filter — without it, a logged-out
// session that never had a refresh token would block retirement forever.
func TestRetirementRefusesWhileEitherPopulationReferencesTheKey(t *testing.T) {
	db := openKeysDB(t)
	putTestKEK(t, db, "kek_held", "active")
	putTestKEK(t, db, "kek_primary", "active")
	if err := db.PromoteKEK("kek_primary", time.Now()); err != nil {
		t.Fatalf("promote: %v", err)
	}

	if err := db.PutBrokerSecret(BrokerSecretRow{
		ID: "sec_1", Kind: "env", Name: "held", Payload: []byte("ct"),
		KeyID: "kek_held", WrappedDEK: []byte("wrapped"),
	}); err != nil {
		t.Fatalf("put secret: %v", err)
	}
	if err := db.RetireKEK("kek_held", time.Now()); !errors.Is(err, ErrKEKInUse) {
		t.Fatalf("with a secret referencing it: err = %v, want ErrKEKInUse", err)
	}

	if err := db.DeleteBrokerSecret("sec_1"); err != nil {
		t.Fatalf("delete secret: %v", err)
	}
	if err := db.PutSession(SessionRow{
		ID: "sess_1", Subject: "u", IssuedAt: time.Now(), LastSeen: time.Now(),
		RefreshSealed: []byte("ct"), RefreshKeyID: "kek_held",
		RefreshWrappedDEK: []byte("wrapped"),
	}); err != nil {
		t.Fatalf("put session: %v", err)
	}
	if err := db.RetireKEK("kek_held", time.Now()); !errors.Is(err, ErrKEKInUse) {
		t.Fatalf("with a session referencing it: err = %v, want ErrKEKInUse", err)
	}

	// Clearing the token also clears the key id, so the row stops blocking.
	if err := db.UpdateSessionRefresh("sess_1", "", nil, nil, time.Now()); err != nil {
		t.Fatalf("clear refresh: %v", err)
	}
	if err := db.RetireKEK("kek_held", time.Now()); err != nil {
		t.Fatalf("retire after clearing: %v", err)
	}
	if err := db.RetireKEK("kek_primary", time.Now()); !errors.Is(err, ErrKEKInUse) {
		t.Errorf("retiring the primary: err = %v, want ErrKEKInUse", err)
	}
}

// TestSealedCompareAndSwapComparesBytes. SQLite's `payload = ?` on a BLOB is
// the entire concurrency guarantee of rotation, so it is checked directly
// rather than inferred from the layer above — including with embedded NULs and
// high bytes, which is what ciphertext looks like.
func TestSealedCompareAndSwapComparesBytes(t *testing.T) {
	db := openKeysDB(t)
	original := []byte{0x00, 0xff, 'a', 0x00, 0x7f, 0xc3, 0xa9}
	if err := db.PutBrokerSecret(BrokerSecretRow{
		ID: "sec_cas", Kind: "env", Name: "cas", Payload: original,
		KeyID: "kek_old", WrappedDEK: []byte("w1"),
	}); err != nil {
		t.Fatalf("put: %v", err)
	}

	next := SealedRow{KeyID: "kek_new", WrappedDEK: []byte("w2"), Ciphertext: original}

	// One byte off must not match.
	wrong := append([]byte(nil), original...)
	wrong[3] ^= 0x01
	ok, err := db.ReplaceBrokerSecretSealed("sec_cas",
		SealedRow{KeyID: "kek_old", Ciphertext: wrong}, next)
	if err != nil {
		t.Fatalf("cas (wrong bytes): %v", err)
	}
	if ok {
		t.Fatal("the swap matched a different ciphertext")
	}

	// The right key with the wrong ciphertext must not match either — this is
	// the lost-update case, and matching on key id alone is the bug.
	ok, _ = db.ReplaceBrokerSecretSealed("sec_cas",
		SealedRow{KeyID: "kek_old", Ciphertext: []byte("totally different")}, next)
	if ok {
		t.Fatal("the swap matched on key id alone")
	}

	// An empty expectation binds as NULL and would silently match nothing;
	// that has to be an error rather than a "skipped" row.
	if _, err := db.ReplaceBrokerSecretSealed("sec_cas",
		SealedRow{KeyID: "kek_old"}, next); err == nil {
		t.Error("an empty compare-and-swap expectation was accepted")
	}

	// The exact bytes swap.
	ok, err = db.ReplaceBrokerSecretSealed("sec_cas",
		SealedRow{KeyID: "kek_old", Ciphertext: original}, next)
	if err != nil {
		t.Fatalf("cas: %v", err)
	}
	if !ok {
		t.Fatal("the swap did not match the exact ciphertext it was given")
	}
	row, err := db.GetBrokerSecret("sec_cas")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if row.KeyID != "kek_new" || string(row.WrappedDEK) != "w2" {
		t.Errorf("row after swap = %+v", row)
	}
}
