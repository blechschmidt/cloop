package secretbroker

// Changing the root, CLOOP_SECRET_KEY itself (Task 20425), against the
// in-memory registry: a keyring holding a current and a previous root, the
// startup rule that every live key derives from one of them, minting from the
// current root only, and RetirePrevious. The SQLite questions — attribution
// written back, a change under concurrent load across secrets, sessions and
// the hub CA — are in pkg/secretstore/rootchange_test.go.

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/rootkey"
)

const (
	oldRoot = "the-old-root-key-0123456789abcdefghijklmnop"
	newRoot = "the-new-root-key-qrstuvwxyz9876543210ABCDEF"
)

// sealedUnderOld is a registry whose every key derives from oldRoot, holding
// n secrets.
func sealedUnderOld(t *testing.T, n int) (*memKeyStore, map[string]string) {
	t.Helper()
	store := newMemKeyStore()
	kr, err := OpenKeyring(store, WithKeyringPassphrase(oldRoot))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kr.AddKey("test"); err != nil { // two keys of the old root
		t.Fatal(err)
	}
	b, err := New(store, WithKeyring(kr))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for _, id := range mintTestSecrets(t, b, n) {
		sec, _ := store.GetSecret(id)
		plain, err := kr.OpenEnvelope(AADFor(SetSecrets, id), sec.Envelope())
		if err != nil {
			t.Fatal(err)
		}
		want[id] = string(plain)
	}
	return store, want
}

// openAll opens every secret in want with kr.
func openAll(t *testing.T, kr *Keyring, store *memKeyStore, want map[string]string) {
	t.Helper()
	for id, plain := range want {
		sec, err := store.GetSecret(id)
		if err != nil {
			t.Fatal(err)
		}
		got, err := kr.OpenEnvelope(AADFor(SetSecrets, id), sec.Envelope())
		if err != nil {
			t.Fatalf("open %s: %v", id, err)
		}
		if string(got) != plain {
			t.Fatalf("%s opened to %q, want %q", id, got, plain)
		}
	}
}

// The rolling restart: a member given the new key as current and the old one
// as previous starts, opens everything the old root sealed, and leaves the
// registry exactly as it found it — nothing is minted until the retire step,
// so a member not restarted yet keeps sealing under the same primary.
func TestANewRootBesideThePreviousOpensEverythingAndChangesNothing(t *testing.T) {
	store, want := sealedUnderOld(t, 4)
	before, _ := store.ListKEKs()

	kr, err := OpenKeyring(store, WithKeyringRoots(newRoot, oldRoot))
	if err != nil {
		t.Fatalf("open with the new root beside the old: %v", err)
	}
	openAll(t, kr, store, want)
	after, _ := store.ListKEKs()
	if len(after) != len(before) {
		t.Fatalf("opening minted: %d keys, was %d", len(after), len(before))
	}
	if !kr.HasPrevious() || kr.PrimaryFromCurrent() {
		t.Errorf("HasPrevious=%v PrimaryFromCurrent=%v, want a change in progress", kr.HasPrevious(), kr.PrimaryFromCurrent())
	}
	for _, k := range kr.Keys() {
		if k.DerivedBy != RootPrevious {
			t.Errorf("key %s derived by %q, want the previous root", k.ID, k.DerivedBy)
		}
	}
	if got := kr.PreviousRootKeys(); len(got) != len(before) {
		t.Errorf("PreviousRootKeys = %v, want all %d", got, len(before))
	}

	// A member still on the old root alone opens what the new one sealed in
	// the meantime: the primary is the registry's, and it is the old root's.
	b, _ := New(store, WithKeyring(kr))
	sec, err := b.Mint(context.Background(), MintRequest{Name: "during", Kind: KindEnv,
		Payload: []byte("DURING=1"), Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	old, err := OpenKeyring(store, WithKeyringPassphrase(oldRoot))
	if err != nil {
		t.Fatalf("a member still on the old root no longer starts: %v", err)
	}
	stored, _ := store.GetSecret(sec.ID)
	if got, err := old.OpenEnvelope(AADFor(SetSecrets, sec.ID), stored.Envelope()); err != nil || string(got) != "DURING=1" {
		t.Errorf("the old member opens a secret sealed during the change: %q, %v", got, err)
	}
}

// The startup rule, generalised: every live key derives from a configured
// root. A new key without the previous one, or with the wrong previous one,
// refuses rather than forking the registry — the generalisation of
// TestWrongPassphraseRefusesRatherThanForkingTheRegistry.
func TestEveryLiveKeyMustDeriveFromAConfiguredRoot(t *testing.T) {
	store, _ := sealedUnderOld(t, 1)
	before, _ := store.ListKEKs()
	for name, opt := range map[string]KeyringOption{
		"the new key alone":                WithKeyringPassphrase(newRoot),
		"the new key and a wrong previous": WithKeyringRoots(newRoot, "a-mistyped-previous-key-0123456789"),
		"a mistyped new key alone":         WithKeyringPassphrase(newRoot + "x"),
	} {
		_, err := OpenKeyring(store, opt)
		if !errors.Is(err, ErrKeyUnavailable) {
			t.Errorf("%s: err = %v, want ErrKeyUnavailable", name, err)
		}
	}
	after, _ := store.ListKEKs()
	if len(after) != len(before) {
		t.Fatal("a refused open minted a key")
	}

	// Read-only, the same registry is reported on rather than refused: that
	// is what `cloop hub key list` is for.
	kr, err := OpenKeyring(store, WithKeyringPassphrase(newRoot), WithoutKeyCreation())
	if err != nil {
		t.Fatalf("read-only open: %v", err)
	}
	if got := kr.Underivable(); len(got) != len(before) {
		t.Errorf("Underivable = %v, want every key", got)
	}
	if _, err := kr.SealFor("x", []byte("y")); err == nil {
		t.Error("a keyring that derives none of the registry sealed something")
	}
}

// The current root mints; the previous one only opens. A key added during a
// change, and the first key of a fresh registry, both derive from the
// current root and record its fingerprint.
func TestOnlyTheCurrentRootMints(t *testing.T) {
	newFP, _ := rootkey.Fingerprint(newRoot)

	fresh := newMemKeyStore()
	kr, err := OpenKeyring(fresh, WithKeyringRoots(newRoot, oldRoot))
	if err != nil {
		t.Fatal(err)
	}
	if !kr.PrimaryFromCurrent() {
		t.Error("a fresh registry's first key does not derive from the current root")
	}

	store, _ := sealedUnderOld(t, 1)
	kr, err = OpenKeyring(store, WithKeyringRoots(newRoot, oldRoot))
	if err != nil {
		t.Fatal(err)
	}
	info, err := kr.AddKey("test")
	if err != nil {
		t.Fatal(err)
	}
	if info.Root != newFP || info.DerivedBy != RootCurrent || !kr.PrimaryFromCurrent() {
		t.Errorf("added %+v, want a primary of the current root %s", info, newFP)
	}
	// The registry says so too, for the next process.
	keks, _ := store.ListKEKs()
	for _, k := range keks {
		if k.ID == info.ID && k.Root != newFP {
			t.Errorf("stored root %q, want %s", k.Root, newFP)
		}
	}
	// And the new root alone now refuses: the old root's keys are still live.
	if _, err := OpenKeyring(store, WithKeyringPassphrase(newRoot)); !errors.Is(err, ErrKeyUnavailable) {
		t.Errorf("the new root alone, with old keys live: %v", err)
	}
}

// The whole procedure: retire the previous root, then restart without it.
func TestRetirePreviousMovesEverythingAndShredsTheOldRoot(t *testing.T) {
	store, want := sealedUnderOld(t, 5)
	oldKeys, _ := store.ListKEKs()

	kr, err := OpenKeyring(store, WithKeyringRoots(newRoot, oldRoot))
	if err != nil {
		t.Fatal(err)
	}
	rot, _ := NewRotator(kr, store)
	rot.WithBatch(2)

	dry, err := rot.RetirePrevious(context.Background(), RetirePreviousOptions{DryRun: true})
	if err != nil || dry.Rotation.Rewrapped != 5 || len(dry.Keys) != len(oldKeys) {
		t.Fatalf("dry run: %+v, %v", dry, err)
	}
	if after, _ := store.ListKEKs(); len(after) != len(oldKeys) {
		t.Fatal("a dry run minted a key")
	}

	rep, err := rot.RetirePrevious(context.Background(), RetirePreviousOptions{Actor: "test"})
	if err != nil {
		t.Fatalf("retire previous: %v (%+v)", err, rep)
	}
	if !rep.Complete || rep.Minted == "" || rep.Rotation.Rewrapped != 5 || len(rep.Keys) != len(oldKeys) {
		t.Fatalf("report %+v", rep)
	}
	keks, _ := store.ListKEKs()
	for _, k := range keks {
		retired := k.State == KEKStateRetired
		if k.ID == rep.Minted {
			if retired || k.State != KEKStatePrimary {
				t.Errorf("the minted key is %s", k.State)
			}
			continue
		}
		if !retired || k.Salt != "" {
			t.Errorf("old key %s is %s with a salt left", k.ID, k.State)
		}
	}

	// Restart without the previous root: everything opens.
	kr2, err := OpenKeyring(store, WithKeyringPassphrase(newRoot))
	if err != nil {
		t.Fatalf("restart without the previous root: %v", err)
	}
	openAll(t, kr2, store, want)
	// And the old root alone opens nothing — it refuses to start.
	if _, err := OpenKeyring(store, WithKeyringPassphrase(oldRoot)); !errors.Is(err, ErrKeyUnavailable) {
		t.Errorf("the old root after retirement: %v", err)
	}
	// Running it again finds nothing to do and mints nothing.
	again, err := rot.RetirePrevious(context.Background(), RetirePreviousOptions{})
	if err != nil || again.Minted != "" || again.Rotation.Rewrapped != 0 || len(again.Keys) != 0 {
		t.Errorf("a second run: %+v, %v", again, err)
	}
}

// Interrupted mid-way, it retires nothing — the rows still under the old root
// would be lost — and the next run finishes without minting again.
func TestRetirePreviousIsResumableAndRetiresNothingUnfinished(t *testing.T) {
	store, want := sealedUnderOld(t, 6)
	kr, err := OpenKeyring(store, WithKeyringRoots(newRoot, oldRoot))
	if err != nil {
		t.Fatal(err)
	}
	rot, _ := NewRotator(kr, store)
	rot.WithBatch(2)

	ctx, cancel := context.WithCancel(context.Background())
	swaps := 0
	store.onReplace = func(string, Envelope) {
		if swaps++; swaps == 3 {
			cancel()
		}
	}
	rep, err := rot.RetirePrevious(ctx, RetirePreviousOptions{})
	if err == nil || len(rep.Keys) != 0 {
		t.Fatalf("an interrupted run: %+v, %v", rep, err)
	}
	minted := rep.Minted
	if minted == "" {
		t.Fatal("the interrupted run did not mint")
	}
	for _, k := range kr.PreviousRootKeys() {
		if store.keks[k].State == KEKStateRetired {
			t.Fatalf("%s retired before every row moved", k)
		}
	}
	openAll(t, kr, store, want)

	store.onReplace = nil
	rep, err = rot.RetirePrevious(context.Background(), RetirePreviousOptions{})
	if err != nil || !rep.Complete || rep.Minted != "" {
		t.Fatalf("the resumed run: %+v, %v", rep, err)
	}
	if kr.PrimaryID() != minted {
		t.Errorf("primary %s, want the key the first run minted, %s", kr.PrimaryID(), minted)
	}
	kr2, err := OpenKeyring(store, WithKeyringPassphrase(newRoot))
	if err != nil {
		t.Fatal(err)
	}
	openAll(t, kr2, store, want)
}

func TestRetirePreviousNeedsAPreviousRoot(t *testing.T) {
	store, _ := sealedUnderOld(t, 1)
	kr, _ := OpenKeyring(store, WithKeyringPassphrase(oldRoot))
	rot, _ := NewRotator(kr, store)
	if _, err := rot.RetirePrevious(context.Background(), RetirePreviousOptions{}); !errors.Is(err, ErrNoPreviousRoot) {
		t.Errorf("err = %v, want ErrNoPreviousRoot", err)
	}
}

// A member that kept serving on the old root alone when the change was
// finished — the retire step's member check is what prevents it, but a member
// can still start in the window — loses nothing: its seals and its reads of
// rewrapped rows fail, loudly, naming the key, and nothing it holds is
// overwritten.
func TestAMemberStillOnTheOldRootFailsLoudlyAfterTheChange(t *testing.T) {
	store, want := sealedUnderOld(t, 2)
	stale, err := OpenKeyring(store, WithKeyringPassphrase(oldRoot))
	if err != nil {
		t.Fatal(err)
	}
	kr, _ := OpenKeyring(store, WithKeyringRoots(newRoot, oldRoot))
	rot, _ := NewRotator(kr, store)
	if _, err := rot.RetirePrevious(context.Background(), RetirePreviousOptions{}); err != nil {
		t.Fatal(err)
	}

	if _, err := stale.SealFor(AADFor(SetSecrets, "x"), []byte("y")); !errors.Is(err, ErrKeyUnavailable) {
		t.Errorf("the stale member sealed: %v", err)
	}
	stale.lastReload = time.Time{} // let the read re-read the registry at once
	for id := range want {
		sec, _ := store.GetSecret(id)
		if _, err := stale.OpenEnvelope(AADFor(SetSecrets, id), sec.Envelope()); !errors.Is(err, ErrKeyUnavailable) {
			t.Errorf("the stale member reading %s: %v, want ErrKeyUnavailable", id, err)
		}
	}
	kr2, _ := OpenKeyring(store, WithKeyringPassphrase(newRoot))
	openAll(t, kr2, store, want)
}

// Pre-envelope rows sealed under the previous root open, and move, too.
func TestLegacyRowsOfThePreviousRootOpenAndMove(t *testing.T) {
	store := newMemKeyStore()
	salt := bytes.Repeat([]byte{7}, saltSize)
	if err := store.SetMeta(metaKeySalt, encodeHex(salt)); err != nil {
		t.Fatal(err)
	}
	sealed, err := (&Cipher{key: deriveKey(oldRoot, salt)}).Seal([]byte("LEGACY=1"))
	if err != nil {
		t.Fatal(err)
	}
	row := Secret{ID: "sec_legacy_old", Kind: KindEnv, Name: "legacy", Sealed: sealed, KeyID: LegacyKeyID, CreatedAt: time.Now()}
	if err := store.PutSecret(row); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKeyring(store, WithKeyringPassphrase(oldRoot)); err != nil {
		t.Fatal(err)
	}

	kr, err := OpenKeyring(store, WithKeyringRoots(newRoot, oldRoot))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := kr.OpenEnvelope(AADFor(SetSecrets, row.ID), row.Envelope()); err != nil || string(got) != "LEGACY=1" {
		t.Fatalf("legacy row under the previous root: %q, %v", got, err)
	}
	rot, _ := NewRotator(kr, store)
	if _, err := rot.RetirePrevious(context.Background(), RetirePreviousOptions{}); err != nil {
		t.Fatal(err)
	}
	kr2, err := OpenKeyring(store, WithKeyringPassphrase(newRoot))
	if err != nil {
		t.Fatal(err)
	}
	moved, _ := store.GetSecret(row.ID)
	if moved.Envelope().IsLegacy() {
		t.Fatal("the legacy row did not move")
	}
	if got, err := kr2.OpenEnvelope(AADFor(SetSecrets, row.ID), moved.Envelope()); err != nil || string(got) != "LEGACY=1" {
		t.Errorf("the moved row under the new root alone: %q, %v", got, err)
	}
}

// A keyring opened per request does not derive its keys per request: the
// cache answers every open after the first, for the current root and the
// previous alike — and retiring a key wipes what the process derived of it.
func TestDerivedKeysAreCachedForTheProcess(t *testing.T) {
	store, _ := sealedUnderOld(t, 1)
	if _, err := OpenKeyring(store, WithKeyringRoots(newRoot, oldRoot)); err != nil {
		t.Fatal(err)
	}
	before := kekDerivations.Load()
	for i := 0; i < 5; i++ {
		kr, err := OpenKeyring(store, WithKeyringRoots(newRoot, oldRoot))
		if err != nil {
			t.Fatal(err)
		}
		_ = kr.Keys()
	}
	if n := kekDerivations.Load() - before; n != 0 {
		t.Errorf("five opens derived %d keys, want 0", n)
	}

	kr, _ := OpenKeyring(store, WithKeyringPassphrase(oldRoot))
	victim, err := kr.AddKey("test")
	if err != nil {
		t.Fatal(err)
	}
	keep := victim.ID
	if _, err := kr.AddKey("test"); err != nil {
		t.Fatal(err)
	}
	if err := kr.RetireKey(keep); err != nil {
		t.Fatal(err)
	}
	kekCache.Lock()
	ids := append([]string(nil), kekCache.byKEK[keep]...)
	kekCache.Unlock()
	if len(ids) != 0 {
		sort.Strings(ids)
		t.Errorf("the retired key is still cached: %v", ids)
	}
}
