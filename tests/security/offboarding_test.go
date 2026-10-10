package security

// Guarantee: offboarding leaves none of the departed person's personal secrets
// behind, and destroys their sealed material rather than unlinking it
// (Task 20400).
//
// Before this, `cloop hub user offboard` and the dashboard's offboarding ended
// every session, token and membership the person held and left every personal
// secret they had stored — a GitHub PAT, a kubeconfig — sealed in
// broker_secrets indefinitely, with the grants over it still live. The hub had
// severed the person and kept their credentials.
//
// It lives here as well as in pkg/offboard because the property spans three
// packages that each hold a piece of it: pkg/offboard resolves who the person
// is, pkg/secretbroker decides what is theirs and destroys it, and pkg/statedb
// scrubs the bytes. Each is tested at home; "no row of theirs survives, and the
// ciphertext is not in the file" is the conjunction, and is asserted against
// the real database, read back the way an attacker holding a copy of state.db
// would read it.

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/offboard"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestOffboardingLeavesNoPersonalSecretOfTheDepartedOwner offboards alice, who
// keeps one secret under her email and one under her subject — the spelling a
// secret minted while the IdP withheld her email carries — and asserts that no
// broker_secrets row is left with her as owner, that bob's personal secret and
// the shared one are untouched, and that her ciphertext is gone from the file.
func TestOffboardingLeavesNoPersonalSecretOfTheDepartedOwner(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, "security-suite-offboarding-passphrase")
	path := statedbtest.Path(t)
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mint := func(name, owner, token string) secretbroker.Secret {
		t.Helper()
		s, err := broker.Mint(ctx, secretbroker.MintRequest{Name: name, Kind: secretbroker.KindGitHubPAT,
			Payload: []byte(token), Actor: "seed", Owner: owner, Personal: owner != ""})
		if err != nil {
			t.Fatalf("mint %s: %v", name, err)
		}
		return s
	}
	aliceMail := mint("alice-pat", aliceID, alicePATCanary)
	aliceSub := mint("alice-sub-pat", "sub:u-alice", "ghp_ALICESUBJECTCANARY0123456789abcd")
	bobs := mint("bob-pat", bobID, "ghp_BOBPERSONALCANARY0123456789abcdef")
	shared := mint("fleet-deploy-pat", "", sharedCanary)
	if _, err := broker.Grant(ctx, secretbroker.GrantRequest{SecretRef: aliceMail.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: "/srv/shared"},
		Constraints: secretbroker.Constraints{Repos: []string{"corp/app"}}, TTL: time.Hour,
		Actor: aliceID, Viewer: secretbroker.Viewer{Identity: aliceID}}); err != nil {
		t.Fatal(err)
	}

	// The session is what ties alice's email to her subject.
	now := time.Now().UTC()
	if err := db.PutSession(statedb.SessionRow{ID: "s-alice", Subject: "u-alice", Email: aliceID,
		OwnerKey: aliceID, IssuedAt: now, LastSeen: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	// What an attacker with a later copy of state.db would search for.
	var sealed [][]byte
	for _, s := range []secretbroker.Secret{aliceMail, aliceSub} {
		row, err := db.GetBrokerSecret(s.ID)
		if err != nil {
			t.Fatal(err)
		}
		sealed = append(sealed, row.Payload, row.WrappedDEK)
	}
	if _, err := db.WALCheckpointTruncate(); err != nil {
		t.Fatal(err)
	}
	for _, b := range sealed {
		if len(b) < 16 || !dbFileHolds(t, path, b[:16]) {
			t.Fatal("alice's sealed material never reached the file — the check below would pass vacuously")
		}
	}

	secrets, err := offboard.StoreSecrets(db)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := offboard.Run(offboard.Options{DB: db, Identity: aliceID, Reason: "left the company, HR-882",
		Actor: rootID, Via: "test", Secrets: secrets})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("offboarding reported failures: %+v", rep.Failures)
	}

	rows, err := db.ListBrokerSecrets()
	if err != nil {
		t.Fatal(err)
	}
	departed := map[string]bool{aliceID: true, "sub:u-alice": true}
	present := map[string]bool{}
	for _, row := range rows {
		if departed[secretbroker.NormalizeOwner(row.Owner)] {
			t.Errorf("broker_secrets still holds %s (%s) owned by the departed %s", row.Name, row.ID, row.Owner)
		}
		present[row.ID] = true
	}
	if !present[bobs.ID] || !present[shared.ID] {
		t.Errorf("offboarding alice destroyed someone else's secret: bob's present=%v, shared present=%v",
			present[bobs.ID], present[shared.ID])
	}

	// No checkpoint here: the offboarding asks for one itself, because until
	// the zeroed pages are folded back into the database file a copy of
	// state.db taken without its -wal still holds the old ones.
	for _, b := range sealed {
		if dbFileHolds(t, path, b[:16]) {
			t.Error("a departed user's ciphertext or wrapped data key is still in state.db after offboarding")
		}
	}
	if raw, err := os.ReadFile(path); err == nil {
		for _, b := range sealed {
			if bytes.Contains(raw, b[:16]) {
				t.Error("the database file itself, read without its WAL, still holds a departed user's sealed bytes")
			}
		}
	}
}

// dbFileHolds reports whether the database file or its WAL contains needle.
func dbFileHolds(t *testing.T, path string, needle []byte) bool {
	t.Helper()
	for _, p := range []string{path, path + "-wal"} {
		raw, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
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
