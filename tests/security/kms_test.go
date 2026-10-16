package security

// Guarantee 12 on the KMS path (Task 20433): a key-encryption key held by an
// external key-management service never reaches disk or a log in the clear.
//
// With secrets.kms configured the KEK is random — crypto/rand, like a data
// key — and the record keeps only the KMS's ciphertext of it. The keyring
// unwraps it into memory and nowhere else. So the witness that makes data keys
// visible to TestPlaintextDataKeysNeverReachDiskOrLogs makes KEKs visible too:
// every 32-byte draw that is not a stored (decoy) salt is a data key, a KEK,
// or one of the fake plugin's own keys, and none of them may appear on any
// surface, in any encoding. The path is exercised end to end over the real
// KMS v2 protocol: minting under the KMS, sealing secrets and a session
// refresh token, rotating onto new KMS-held keys, following a rotation of the
// KMS key, retiring a key, and every failure an operator reads when the KMS
// stops answering.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/kms/kmstest"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/sessionstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestPlaintextKMSKeysNeverReachDiskOrLogs is the guarantee.
func TestPlaintextKMSKeysNeverReachDiskOrLogs(t *testing.T) {
	witness := installDEKWitness(t)
	t.Cleanup(secretbroker.ForgetOpenedKeys)
	plugin := kmstest.StartPlugin(t)
	prov, err := kms.Open(config.KMSConfig{Provider: config.KMSProviderKMSv2, Timeout: "2s",
		KMSv2: config.KMSv2Config{Endpoint: plugin.Endpoint()}})
	if err != nil {
		t.Fatal(err)
	}
	defer prov.Close()
	root := secretbroker.KMSRoot(prov)

	dir := statedbtest.Dir(t)
	if _, err := state.Init(dir, "kms key material conformance", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	dbPath := state.DBPath(dir)
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := secretbroker.OpenKeyring(store, secretbroker.WithKeyringRootSet(root, secretbroker.Root{}),
		secretbroker.WithKeyringActor("conformance"))
	if err != nil {
		t.Fatalf("open keyring: %v", err)
	}
	b, err := secretbroker.New(store, secretbroker.WithKeyring(kr), secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessionstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	sessions.WithKeyring(kr)
	rot, err := secretbroker.NewRotator(kr, store, sessions)
	if err != nil {
		t.Fatal(err)
	}
	rot.WithHistory(store)
	ctx := context.Background()

	payloads := map[string]string{
		"pat": "ghp_kmsconformance0123456789abcdef",
		"env": "DEPLOY_TOKEN=kmsconformance-env-value",
	}
	kinds := map[string]secretbroker.Kind{"pat": secretbroker.KindGitHubPAT, "env": secretbroker.KindEnv}
	for name, payload := range payloads {
		if _, err := b.Mint(ctx, secretbroker.MintRequest{Name: name, Kind: kinds[name], Payload: []byte(payload),
			Actor: "conformance"}); err != nil {
			t.Fatalf("mint %s: %v", name, err)
		}
	}
	if err := sessions.Put(oidcauth.SessionRecord{
		ID: "sess_kms_conformance", Identity: oidcauth.Identity{Sub: "user", Email: "u@example.com"},
		IssuedAt: time.Now(), LastSeen: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		RefreshToken: "rt_kmsconformance_refresh_token",
	}); err != nil {
		t.Fatalf("put session: %v", err)
	}

	// Rotate twice: two more KMS-held KEKs, every data key unwrapped and
	// rewrapped under each.
	first := kr.PrimaryID()
	var reports []any
	for i := 0; i < 2; i++ {
		rep, err := rot.Rotate(ctx, secretbroker.RotateOptions{NewKey: true, Actor: "conformance"})
		if err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
		reports = append(reports, rep)
	}
	// Follow a rotation of the KMS key, and retire the first KEK.
	plugin.Rotate()
	rewrap, err := kr.RewrapKMS(ctx)
	if err != nil || rewrap.Rewrapped == 0 {
		t.Fatalf("rewrap: %+v, %v", rewrap, err)
	}
	reports = append(reports, rewrap)
	if err := rot.RetireKey(first); err != nil {
		t.Fatalf("retire %s: %v", first, err)
	}

	// Every failure an operator reads when the KMS stops answering.
	plugin.Stop()
	secretbroker.ForgetOpenedKeys()
	var failures []string
	if _, err := secretbroker.OpenKeyring(store, secretbroker.WithKeyringRootSet(root, secretbroker.Root{})); err != nil {
		failures = append(failures, err.Error())
	}
	ro, err := secretbroker.OpenKeyring(store, secretbroker.WithKeyringRootSet(root, secretbroker.Root{}),
		secretbroker.WithoutKeyCreation())
	if err != nil {
		t.Fatalf("read-only open with the KMS down: %v", err)
	}
	for id, why := range ro.UnderivableReasons() {
		failures = append(failures, id+" "+why)
	}
	for _, s := range mustSecrets(t, store) {
		if _, err := ro.OpenEnvelope(secretAAD(s.ID), s.Envelope()); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) < 3 {
		t.Fatalf("only %d failure messages with the KMS down — the scan of error paths is too thin", len(failures))
	}

	// ── isolate the keys ────────────────────────────────────────────────
	keks, err := db.ListKEKs()
	if err != nil {
		t.Fatal(err)
	}
	salts := map[string]bool{}
	live := 0
	for _, k := range keks {
		if k.Salt != "" {
			salts[strings.ToLower(k.Salt)] = true
		}
		if k.State == secretbroker.KEKStateRetired {
			if len(k.KMSCiphertext) != 0 {
				t.Errorf("retired key %s keeps its KMS ciphertext", k.ID)
			}
			continue
		}
		live++
		// The positive control: the record does hold the wrapped key.
		if k.Wrap != secretbroker.WrapKMS || len(k.KMSCiphertext) == 0 || k.KMSKeyID == "" {
			t.Errorf("live key %s is not held by the KMS: %+v", k.ID, k)
		}
	}
	if live != 2 {
		t.Fatalf("%d live keys, want 2", live)
	}
	var keys [][]byte
	for _, chunk := range witness.sized(32) {
		if !salts[strings.ToLower(hexString(chunk))] {
			keys = append(keys, chunk)
		}
	}
	// Vacuity guard: three KEKs, a data key per secret and for the session.
	if minimum := 3 + len(payloads) + 1; len(keys) < minimum {
		t.Fatalf("the witness captured %d candidate keys, expected at least %d — the scan would be vacuous",
			len(keys), minimum)
	}

	// ── the surfaces ────────────────────────────────────────────────────
	surfaces := map[string]string{
		"audit trail":        dumpTrail(t, dir),
		"key list JSON":      mustJSON(t, kr.Keys()),
		"rotation reports":   mustJSON(t, reports),
		"rotation status":    mustJSON(t, mustStatus(t, rot)),
		"kek rows (%#v)":     fmt.Sprintf("%#v", keks),
		"secrets (%#v)":      goSyntax(t, mustSecrets(t, store)),
		"sessions (%#v)":     fmt.Sprintf("%#v", mustSessionRows(t, db)),
		"failure messages":   strings.Join(failures, "\n"),
		"metrics exposition": hubmetrics.Default.Gather(),
	}
	for name, body := range surfaces {
		assertNoDEK(t, name, body, keys)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, rerr := os.ReadFile(dbPath + suffix)
		if rerr != nil {
			continue
		}
		assertNoDEKBytes(t, filepath.Base(dbPath+suffix), data, keys)
	}
}

// TestADatabaseAndKeyFileDoNotOpenAKMSHeldStore is what moving onto a KMS is
// for: a copy of the database and of CLOOP_SECRET_KEY, taken after the store
// moved, opens nothing without the KMS — the passphrase derives no key from a
// KMS-held record, and no root but the KMS is tried in its place.
func TestADatabaseAndKeyFileDoNotOpenAKMSHeldStore(t *testing.T) {
	t.Cleanup(secretbroker.ForgetOpenedKeys)
	const passphrase = "the-hub's-own-root-key-0123456789abcdefghijk"
	plugin := kmstest.StartPlugin(t)
	prov, err := kms.Open(config.KMSConfig{Provider: config.KMSProviderKMSv2,
		KMSv2: config.KMSv2Config{Endpoint: plugin.Endpoint()}})
	if err != nil {
		t.Fatal(err)
	}
	defer prov.Close()
	db := statedbtest.Open(t)
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := secretbroker.OpenKeyring(store, secretbroker.WithKeyringRootSet(secretbroker.KMSRoot(prov), secretbroker.Root{}))
	if err != nil {
		t.Fatal(err)
	}
	b, err := secretbroker.New(store, secretbroker.WithKeyring(kr))
	if err != nil {
		t.Fatal(err)
	}
	sec, err := b.Mint(context.Background(), secretbroker.MintRequest{Name: "copied", Kind: secretbroker.KindEnv,
		Payload: []byte("COPIED=the-value-a-copy-must-not-open"), Actor: "conformance"})
	if err != nil {
		t.Fatal(err)
	}

	// The attacker's process: the database, the key file, no KMS.
	secretbroker.ForgetOpenedKeys()
	if _, err := secretbroker.OpenKeyring(store, secretbroker.WithKeyringPassphrase(passphrase)); err == nil {
		t.Fatal("the key file opened a keyring over a KMS-held store")
	}
	ro, err := secretbroker.OpenKeyring(store, secretbroker.WithKeyringPassphrase(passphrase), secretbroker.WithoutKeyCreation())
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetSecret(sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := ro.OpenEnvelope(secretAAD(sec.ID), stored.Envelope()); err == nil {
		t.Fatalf("the key file opened a KMS-held secret: %q", pt)
	}
	rows, err := db.ListKEKs()
	if err != nil {
		t.Fatal(err)
	}
	var recs []secretbroker.KEKRecord
	for _, r := range rows {
		recs = append(recs, secretstore.KEKFromRow(r))
	}
	for _, c := range secretbroker.CheckKeys(secretbroker.PassphraseRoots(passphrase), recs) {
		if c.Opens {
			t.Fatalf("the passphrase derives %s", c.ID)
		}
	}
}
