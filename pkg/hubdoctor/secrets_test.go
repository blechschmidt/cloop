package hubdoctor

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestSealingKeyIsAskedOfTheHubsKeyring: a key's strength says nothing about
// whether it is the key the secrets were sealed under. The keyring the broker
// opens before every lease does, read-only — and with the key unset, a hub
// whose registry already records a sealing key is not "not yet keyed"; it
// cannot open what it sealed (Task 20387).
func TestSealingKeyIsAskedOfTheHubsKeyring(t *testing.T) {
	dir := t.TempDir()
	seedBranchGrants(t, dir) // mints a secret under "hubdoctor-branch-grants"

	t.Setenv("CLOOP_SECRET_KEY", "Zq4pV9mW2xT7rL0yH3nB8kD5sF1gJ6cA-uE_oI4tR7w")
	got := findingsFor(t, dir, hubCfg(), Options{Offline: true})
	wantSeverity(t, only(t, got, "secret_key.entropy"), SeverityPass)
	f := only(t, got, "secret_key.matches")
	wantSeverity(t, f, SeverityFail)
	if !strings.Contains(f.Message, "refuses every lease") {
		t.Errorf("want the broker's consequence, got %q", f.Message)
	}

	t.Setenv("CLOOP_SECRET_KEY", "hubdoctor-branch-grants")
	got = findingsFor(t, dir, hubCfg(), Options{Offline: true})
	wantSeverity(t, only(t, got, "secret_key.matches"), SeverityPass)

	t.Setenv("CLOOP_SECRET_KEY", "")
	got = findingsFor(t, dir, hubCfg(), Options{Offline: true})
	wantSeverity(t, only(t, got, "secret_key.present"), SeverityFail)
}

// TestARecordedKeyIsNotASealedSecret: the hub records a sealing key whenever
// it starts with one set — an OIDC hub's session store does, and so does every
// broker it builds — sealed secret or not. With the key unset, that is a hub
// not yet able to seal, a warning, not one that cannot open what it sealed.
func TestARecordedKeyIsNotASealedSecret(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CLOOP_SECRET_KEY", "hubdoctor-recorded-key")
	db, err := statedb.Open(mustInitStateDB(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secretbroker.New(store); err != nil { // records the first key
		t.Fatal(err)
	}
	if keks, err := store.ListKEKs(); err != nil || len(keks) == 0 {
		t.Fatalf("premise: constructing a broker records a key (%d, %v)", len(keks), err)
	}
	_ = db.Close()

	t.Setenv("CLOOP_SECRET_KEY", "")
	got := findingsFor(t, dir, hubCfg(), Options{Offline: true})
	wantSeverity(t, only(t, got, "secret_key.present"), SeverityWarn)
}

// TestDoctorNeverMintsASealingKey: the keyring is opened read-only, so a
// doctor run on a hub that has recorded no sealing key yet leaves it with
// none. A diagnostic that minted the first key would choose the key the hub's
// secrets are then sealed under — from whatever environment the operator
// happened to run the doctor in (Task 20387).
func TestDoctorNeverMintsASealingKey(t *testing.T) {
	dir := t.TempDir()
	dbPath := mustInitStateDB(t, dir)
	t.Setenv("CLOOP_SECRET_KEY", "Zq4pV9mW2xT7rL0yH3nB8kD5sF1gJ6cA-uE_oI4tR7w")

	got := findingsFor(t, dir, hubCfg(), Options{Offline: true})
	f := only(t, got, "secret_key.matches")
	wantSeverity(t, f, SeverityPass)
	if !strings.Contains(f.Message, "no sealing key is recorded yet") {
		t.Errorf("want the empty registry named, got %q", f.Message)
	}

	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	keks, err := store.ListKEKs()
	if err != nil {
		t.Fatal(err)
	}
	if len(keks) != 0 {
		t.Fatalf("the doctor recorded %d sealing key(s); it may only read the registry", len(keks))
	}
}
