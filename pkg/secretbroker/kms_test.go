package secretbroker

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/hubmetrics"
)

// fakeKMS is a KMS in memory: AES-GCM under a key it holds, which can be made
// unreachable or refusing. pkg/kms tests the real protocols; this tests the
// keyring's handling of what any KMS answers.
type fakeKMS struct {
	name string

	mu        sync.Mutex
	aead      cipher.AEAD
	keyID     string
	down      bool
	noDecrypt bool
	encrypts  int
	decrypts  int
}

func newFakeKMS(t *testing.T, name string) *fakeKMS {
	t.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return &fakeKMS{name: name, aead: aead, keyID: "v1"}
}

func (f *fakeKMS) Name() string { return f.name }

func (f *fakeKMS) Encrypt(_ context.Context, pt []byte) (KMSCiphertext, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.encrypts++
	if f.down {
		return KMSCiphertext{}, fmt.Errorf("%w: connection refused", ErrKMSUnavailable)
	}
	nonce := make([]byte, f.aead.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)
	return KMSCiphertext{KeyID: f.keyID, Ciphertext: f.aead.Seal(nonce, nonce, pt, []byte(f.keyID))}, nil
}

func (f *fakeKMS) Decrypt(_ context.Context, c KMSCiphertext) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decrypts++
	switch {
	case f.down:
		return nil, fmt.Errorf("%w: connection refused", ErrKMSUnavailable)
	case f.noDecrypt:
		return nil, errors.New("permission denied: decrypt")
	}
	n := f.aead.NonceSize()
	if len(c.Ciphertext) < n {
		return nil, errors.New("short")
	}
	return f.aead.Open(nil, c.Ciphertext[:n], c.Ciphertext[n:], []byte(c.KeyID))
}

func (f *fakeKMS) set(fn func(*fakeKMS)) {
	f.mu.Lock()
	fn(f)
	f.mu.Unlock()
}

// A KMS-held record carries a decoy salt, so a build from before KMS roots —
// reading the record as a derived key — derives nothing from it and refuses,
// instead of reading an empty salt as a retired key and minting a passphrase
// key over the KMS's primary.
func TestAKMSHeldKeyIsUnderivableToAnOlderBuild(t *testing.T) {
	t.Cleanup(ForgetOpenedKeys)
	k := newFakeKMS(t, "kms:test")
	store := newMemKeyStore()
	kr, err := OpenKeyring(store, WithKeyringRootSet(KMSRoot(k), Root{}))
	if err != nil {
		t.Fatal(err)
	}
	recs, _ := store.ListKEKs()
	if len(recs) != 1 || recs[0].Wrap != WrapKMS || recs[0].Retired() || len(recs[0].Salt) != 2*saltSize {
		t.Fatalf("record = %+v", recs)
	}
	if kr.PrimaryID() != recs[0].ID {
		t.Fatal("the KMS key is not primary")
	}

	// An older build's view of the row: no wrap, no KMS fields.
	old := newMemKeyStore()
	rec := recs[0]
	rec.Wrap, rec.KMSKeyID, rec.KMSCiphertext, rec.KMSAnnotations, rec.Root = "", "", nil, nil, ""
	_ = old.PutKEK(rec)
	_, err = OpenKeyring(old, WithKeyringPassphrase(testPassphrase))
	if err == nil || !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("an older build's open: %v", err)
	}
	if got, _ := old.ListKEKs(); len(got) != 1 {
		t.Fatalf("an older build minted beside the KMS key: %d keys", len(got))
	}
}

// A new key is proven to unwrap before anything is recorded: an identity
// allowed to encrypt and not decrypt mints nothing, rather than a primary no
// one can open.
func TestMintProvesTheKMSUnwrapsBeforeRecording(t *testing.T) {
	t.Cleanup(ForgetOpenedKeys)
	k := newFakeKMS(t, "kms:encrypt-only")
	k.set(func(f *fakeKMS) { f.noDecrypt = true })
	store := newMemKeyStore()
	_, err := OpenKeyring(store, WithKeyringRootSet(KMSRoot(k), Root{}))
	if err == nil || !strings.Contains(err.Error(), "would not unwrap it again") {
		t.Fatalf("an encrypt-only identity: %v", err)
	}
	if recs, _ := store.ListKEKs(); len(recs) != 0 {
		t.Fatalf("recorded %d keys it could not unwrap", len(recs))
	}
}

// A read-only open with the KMS down reports which keys do not open and why,
// and a read of a row under one fails as an unreachable KMS, counted as such.
func TestUnreachableKMSIsReportedAndCounted(t *testing.T) {
	t.Cleanup(ForgetOpenedKeys)
	k := newFakeKMS(t, "kms:flaky")
	store := newMemKeyStore()
	kr, err := OpenKeyring(store, WithKeyringRootSet(KMSRoot(k), Root{}))
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(store, WithKeyring(kr))
	if err != nil {
		t.Fatal(err)
	}
	ids := mintTestSecrets(t, b, 1)
	keyID := kr.PrimaryID()

	ForgetOpenedKeys()
	k.set(func(f *fakeKMS) { f.down = true })
	ro, err := OpenKeyring(store, WithKeyringRootSet(KMSRoot(k), Root{}), WithoutKeyCreation())
	if err != nil {
		t.Fatalf("a read-only open is answered, not refused: %v", err)
	}
	if bad := ro.Underivable(); len(bad) != 1 || bad[0] != keyID {
		t.Fatalf("underivable = %v", bad)
	}
	if why := ro.UnderivableReasons()[keyID]; !strings.Contains(why, "connection refused") || !strings.Contains(why, "kms:flaky") {
		t.Fatalf("reason = %q", why)
	}
	if !errors.Is(ro.UnderivableErr(keyID), ErrKMSUnavailable) {
		t.Fatalf("the reason is not an unreachable KMS: %v", ro.UnderivableErr(keyID))
	}
	s, _ := store.GetSecret(ids[0])
	_, err = ro.OpenEnvelope(AADFor(SetSecrets, s.ID), s.Envelope())
	if !errors.Is(err, ErrKMSUnavailable) {
		t.Fatalf("a read under an unreachable KMS: %v", err)
	}
	if !strings.Contains(hubmetrics.Default.Gather(), `cloop_secret_unseal_failures_total{reason="kms_unavailable"}`) {
		t.Fatal("the failed read is not counted kms_unavailable")
	}
}

// Retiring a KMS-held key drops it from the process along with its record's
// ciphertext: nothing in memory, or in the record, gives it back.
func TestRetiringAKMSHeldKeyForgetsIt(t *testing.T) {
	t.Cleanup(ForgetOpenedKeys)
	k := newFakeKMS(t, "kms:retire")
	store := newMemKeyStore()
	kr, err := OpenKeyring(store, WithKeyringRootSet(KMSRoot(k), Root{}))
	if err != nil {
		t.Fatal(err)
	}
	old := kr.PrimaryID()
	if _, err := kr.AddKey("test"); err != nil {
		t.Fatal(err)
	}
	if err := kr.RetireKey(old); err != nil {
		t.Fatal(err)
	}
	kr.mu.RLock()
	rec, held := kr.records[old], kr.keks[old] != nil
	kr.mu.RUnlock()
	if held || len(rec.KMSCiphertext) != 0 || len(rec.CheckValue) != 0 || !rec.Retired() {
		t.Fatalf("after retirement: held=%v record=%+v", held, rec)
	}
	kekCache.Lock()
	cached := len(kekCache.byKEK[old])
	kekCache.Unlock()
	if cached != 0 {
		t.Fatal("the retired key is still in the process's key cache")
	}
}

// The KMS is asked once per key per process: every later keyring in the
// process opens from memory.
func TestKMSHeldKeysAreHeldInMemory(t *testing.T) {
	t.Cleanup(ForgetOpenedKeys)
	k := newFakeKMS(t, "kms:cache")
	store := newMemKeyStore()
	if _, err := OpenKeyring(store, WithKeyringRootSet(KMSRoot(k), Root{})); err != nil {
		t.Fatal(err)
	}
	ForgetOpenedKeys()
	k.set(func(f *fakeKMS) { f.decrypts = 0 })
	for i := 0; i < 5; i++ {
		if _, err := OpenKeyring(store, WithKeyringRootSet(KMSRoot(k), Root{})); err != nil {
			t.Fatal(err)
		}
	}
	k.mu.Lock()
	n := k.decrypts
	k.mu.Unlock()
	if n != 1 {
		t.Fatalf("five opens asked the KMS %d times", n)
	}
}
