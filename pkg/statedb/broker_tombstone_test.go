package statedb

// Deleting a broker secret destroys its sealed bytes, and leaves a tombstone
// that names what it was (Task 20400).

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// sealedLike returns n random bytes: the shape of a ciphertext, and a pattern
// no other row in the file could reproduce by accident.
func sealedLike(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// fileHolds reports whether the database file or its WAL contains needle.
func fileHolds(t *testing.T, dbPath string, needle []byte) bool {
	t.Helper()
	for _, p := range []string{dbPath, dbPath + "-wal"} {
		raw, err := os.ReadFile(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			t.Fatal(err)
		}
		if bytes.Contains(raw, needle) {
			return true
		}
	}
	return false
}

// TestDeleteBrokerSecretOverwritesTheSealedBytes is the property a plain DELETE
// does not have. SQLite unlinks a deleted row and leaves its bytes in the page
// until the space is reused, so a copy of state.db taken after an offboarding
// would still hold the departed user's ciphertext and wrapped data key —
// sealed under a key the hub still has. Both a payload that fits in its page
// and one long enough to spill into overflow pages are checked: the second is
// where an unlinked chain would otherwise sit, intact, on the freelist.
func TestDeleteBrokerSecretOverwritesTheSealedBytes(t *testing.T) {
	for _, size := range []int{600, 20000} {
		path := freshPath(t)
		db, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		payload := sealedLike(t, size)
		wrapped := sealedLike(t, 60)
		if err := db.PutBrokerSecret(BrokerSecretRow{
			ID: "sec_departed", Kind: "github_pat", Name: "alice-pat", Payload: payload,
			KeyID: "kek_1", WrappedDEK: wrapped, Owner: "alice@example.com",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.WALCheckpointTruncate(); err != nil {
			t.Fatal(err)
		}
		if !fileHolds(t, path, payload[:32]) {
			t.Fatalf("size %d: the fixture never reached the file, so the assertion below would prove nothing", size)
		}

		if err := db.DeleteBrokerSecretTombstoned("sec_departed", BrokerSecretTombstoneRow{
			Name: "alice-pat", Kind: "github_pat", Owner: "alice@example.com",
			DeletedAt: "2026-10-10T07:00:00Z", DeletedBy: "admin@example.com", Cause: "offboarded",
			Reason: "left the company",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.WALCheckpointTruncate(); err != nil {
			t.Fatal(err)
		}
		for _, probe := range [][]byte{payload[:32], payload[size-32:], wrapped[:32]} {
			if fileHolds(t, path, probe) {
				t.Fatalf("size %d: sealed bytes of a deleted secret are still in %s", size, path)
			}
		}
		if _, err := db.GetBrokerSecret("sec_departed"); !errors.Is(err, ErrBrokerSecretNotFound) {
			t.Fatalf("size %d: the row survived its deletion: %v", size, err)
		}
	}
}

// TestDeleteBrokerSecretTombstonedRemembersWhatItWas: the tombstone is written
// in the same transaction as the delete and round-trips every field.
func TestDeleteBrokerSecretTombstonedRemembersWhatItWas(t *testing.T) {
	db := openFresh(t)
	if err := db.PutBrokerSecret(BrokerSecretRow{
		ID: "sec_1", Kind: "kubeconfig", Name: "alice-kube", Payload: []byte("ct"), Owner: "alice@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	want := BrokerSecretTombstoneRow{
		SecretID: "sec_1", Name: "alice-kube", Kind: "kubeconfig", Owner: "alice@example.com",
		DeletedAt: "2026-10-10T07:00:00Z", DeletedBy: "admin@example.com", Cause: "offboarded",
		Reason: "left the company",
	}
	if err := db.DeleteBrokerSecretTombstoned("sec_1", want); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetBrokerSecretTombstone("sec_1")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("tombstone = %+v, want %+v", got, want)
	}

	// Deleting what does not exist records nothing.
	if err := db.DeleteBrokerSecretTombstoned("sec_missing", want); !errors.Is(err, ErrBrokerSecretNotFound) {
		t.Fatalf("delete missing: %v, want ErrBrokerSecretNotFound", err)
	}
	if _, err := db.GetBrokerSecretTombstone("sec_missing"); !errors.Is(err, ErrBrokerSecretNotFound) {
		t.Fatalf("a failed delete left a tombstone: %v", err)
	}
	// A plain delete still works, and records nothing.
	if err := db.PutBrokerSecret(BrokerSecretRow{ID: "sec_2", Kind: "env", Name: "x", Payload: []byte("ct")}); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteBrokerSecret("sec_2"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetBrokerSecretTombstone("sec_2"); !errors.Is(err, ErrBrokerSecretNotFound) {
		t.Fatalf("a plain delete wrote a tombstone: %v", err)
	}
}

// TestTombstoneMigrationIsAdditive pins 0062's compat class: a hub one build
// behind must keep opening the control plane once this build has migrated it
// (see schema_compat.go — a breaking class blanks the older hub's dashboard).
func TestTombstoneMigrationIsAdditive(t *testing.T) {
	embedded, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range embedded {
		if !strings.Contains(m.Name, "broker_secret_tombstones") {
			continue
		}
		if got := migrationVerdict(m); got != CompatAdditive {
			t.Fatalf("%s classifies as %q, want additive", m.Name, got)
		}
		return
	}
	t.Fatal("migration 0062_broker_secret_tombstones not found")
}

// TestRevokeBrokerGrantWithCauseKeepsTheFirstCause: the cause is written by the
// revocation that stamps the grant, and a later revocation changes neither it
// nor the time.
func TestRevokeBrokerGrantWithCauseKeepsTheFirstCause(t *testing.T) {
	db := openFresh(t)
	if err := db.PutBrokerGrant(BrokerGrantRow{ID: "grant_1", SecretID: "sec_1", SubjectType: "project",
		SubjectValue: "/srv/app", CreatedAt: "2026-10-10T07:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	first := time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)
	if err := db.RevokeBrokerGrantWithCause("grant_1", first, "owner_offboarded"); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeBrokerGrantWithCause("grant_1", first.Add(time.Hour), "secret_deleted"); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetBrokerGrant("grant_1")
	if err != nil {
		t.Fatal(err)
	}
	if got.RevokedCause != "owner_offboarded" || got.RevokedAt != first.Format(time.RFC3339Nano) {
		t.Fatalf("grant = %+v, want the first revocation's cause and time", got)
	}
	// An upsert of the row by a writer that knows the column keeps it too.
	if err := db.PutBrokerGrant(got); err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListBrokerGrants()
	if err != nil || len(rows) != 1 || rows[0].RevokedCause != "owner_offboarded" {
		t.Fatalf("listed %+v (%v)", rows, err)
	}
}
