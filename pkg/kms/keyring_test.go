package kms_test

// The keyring against a KMS over the real protocol and a real state database
// (Task 20433): what is minted, what opens, what refuses — and that nothing
// ever falls back to a passphrase in a KMS's place.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/kms/kmstest"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const testPassphrase = "kms-keyring-test-passphrase-0123456789abcdef"

// member is one hub process's view of a shared store: its own database
// handle, its own KMS client, the same file and the same plugin.
type member struct {
	db    *statedb.DB
	store *secretstore.Store
}

func newMember(t *testing.T, path string) member {
	t.Helper()
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	return member{db: db, store: store}
}

func (m member) keyring(t *testing.T, current, previous secretbroker.Root, extra ...secretbroker.KeyringOption) (*secretbroker.Keyring, error) {
	t.Helper()
	opts := append([]secretbroker.KeyringOption{secretbroker.WithKeyringRootSet(current, previous),
		secretbroker.WithKeyringActor("test")}, extra...)
	return secretbroker.OpenKeyring(m.store, opts...)
}

func (m member) mustKeyring(t *testing.T, current, previous secretbroker.Root) *secretbroker.Keyring {
	t.Helper()
	kr, err := m.keyring(t, current, previous)
	if err != nil {
		t.Fatalf("open keyring: %v", err)
	}
	return kr
}

func (m member) broker(t *testing.T, kr *secretbroker.Keyring) *secretbroker.Broker {
	t.Helper()
	b, err := secretbroker.New(m.store, secretbroker.WithKeyring(kr))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mint(t *testing.T, b *secretbroker.Broker, name, value string) string {
	t.Helper()
	s, err := b.Mint(context.Background(), secretbroker.MintRequest{
		Name: name, Kind: secretbroker.KindEnv, Payload: []byte("V=" + value), Actor: "test"})
	if err != nil {
		t.Fatalf("mint %s: %v", name, err)
	}
	return s.ID
}

// opens reads every secret through kr and checks its payload.
func opens(t *testing.T, m member, kr *secretbroker.Keyring, want map[string]string) {
	t.Helper()
	for id, value := range want {
		s, err := m.store.GetSecret(id)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := kr.OpenEnvelope(secretbroker.AADFor(secretbroker.SetSecrets, id), s.Envelope())
		if err != nil {
			t.Fatalf("open %s: %v", id, err)
		}
		if string(pt) != "V="+value {
			t.Fatalf("secret %s = %q", id, pt)
		}
	}
}

func pluginRoot(t *testing.T, p *kmstest.Plugin, name, timeout string) secretbroker.Root {
	t.Helper()
	cfg := pluginConfig(p, timeout)
	cfg.Name = name
	prov, err := kms.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = prov.Close() })
	return secretbroker.KMSRoot(prov)
}

func kekRows(t *testing.T, m member) []statedb.KEKRow {
	t.Helper()
	rows, err := m.db.ListKEKs()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// Minted under a KMS, a key is random and held only as the plugin's
// ciphertext; a fresh process unwraps it through the plugin and every secret
// opens. A passphrase — even the hub's own — derives nothing from the record.
func TestKeyringRoundTripThroughThePlugin(t *testing.T) {
	p := kmstest.StartPlugin(t)
	m := newMember(t, statedbtest.Path(t))
	root := pluginRoot(t, p, "", "")
	kr := m.mustKeyring(t, root, secretbroker.Root{})
	want := map[string]string{}
	b := m.broker(t, kr)
	for i := 0; i < 3; i++ {
		want[mint(t, b, fmt.Sprintf("s%d", i), fmt.Sprintf("value-%d", i))] = fmt.Sprintf("value-%d", i)
	}

	rows := kekRows(t, m)
	if len(rows) != 1 {
		t.Fatalf("%d keys, want 1", len(rows))
	}
	rec := rows[0]
	if rec.Wrap != secretbroker.WrapKMS || rec.KMSKeyID != "key-1" || len(rec.KMSCiphertext) == 0 ||
		rec.Root != root.KMS.Name() || rec.State != secretbroker.KEKStatePrimary {
		t.Fatalf("record = %+v", rec)
	}
	if !strings.Contains(rec.KMSAnnotations, kmstest.AnnotationKey) {
		t.Fatalf("annotations not stored: %q", rec.KMSAnnotations)
	}
	if p.Calls("Encrypt") != 1 || p.Calls("Decrypt") != 1 {
		// One wrap, and the unwrap that proves it before anything is recorded.
		t.Fatalf("mint made %d encrypts and %d decrypts, want 1 and 1", p.Calls("Encrypt"), p.Calls("Decrypt"))
	}

	// A new process: nothing cached, so the key comes from the plugin.
	secretbroker.ForgetOpenedKeys()
	before := p.Calls("Decrypt")
	kr2 := m.mustKeyring(t, root, secretbroker.Root{})
	opens(t, m, kr2, want)
	if p.Calls("Decrypt") != before+1 {
		t.Fatalf("reopening made %d unwraps, want 1", p.Calls("Decrypt")-before)
	}
	// And a second keyring in that process asks the plugin nothing.
	kr3 := m.mustKeyring(t, root, secretbroker.Root{})
	opens(t, m, kr3, want)
	if p.Calls("Decrypt") != before+1 {
		t.Fatal("an opened key was not held in memory: the plugin was asked again")
	}

	// The hub's passphrase derives nothing from a KMS-held record — the
	// decoy salt is not a salt — so the database and the key file together
	// are not enough.
	recs := []secretbroker.KEKRecord{secretstore.KEKFromRow(rec)}
	for _, c := range secretbroker.CheckKeys([]secretbroker.Root{secretbroker.PassphraseRoot(testPassphrase)}, recs) {
		if c.Opens {
			t.Fatal("a passphrase opened a KMS-held key")
		}
		if c.KMS != root.KMS.Name() || !strings.Contains(c.Why, "no KMS was checked") {
			t.Fatalf("check = %+v", c)
		}
	}
	derived := rec
	derived.Wrap, derived.KMSCiphertext, derived.KMSKeyID = "", nil, ""
	if _, err := secretbroker.OpenKeyring(newMemKeyStore(derived), secretbroker.WithKeyringPassphrase(testPassphrase)); err == nil {
		t.Fatal("an older build reading the record as a derived key opened it with the passphrase")
	}
}

// With the plugin down a fresh process refuses to open the store, naming the
// key and the KMS — and a passphrase configured beside it changes nothing: the
// key is not derived, and nothing is minted in its place.
func TestKeyringRefusesWhenThePluginIsUnavailable(t *testing.T) {
	p := kmstest.StartPlugin(t)
	m := newMember(t, statedbtest.Path(t))
	root := pluginRoot(t, p, "", "1s")
	kr := m.mustKeyring(t, root, secretbroker.Root{})
	mint(t, m.broker(t, kr), "s", "v")
	keyID := kr.PrimaryID()

	p.Stop()
	secretbroker.ForgetOpenedKeys()
	for _, previous := range []secretbroker.Root{{}, secretbroker.PassphraseRoot(testPassphrase)} {
		_, err := m.keyring(t, root, previous)
		if err == nil {
			t.Fatal("the store opened with its KMS down")
		}
		if !errors.Is(err, secretbroker.ErrKMSUnavailable) || !errors.Is(err, secretbroker.ErrKeyUnavailable) {
			t.Fatalf("not an unreachable KMS: %v", err)
		}
		for _, part := range []string{keyID, root.KMS.Name(), "refusing to mint"} {
			if !strings.Contains(err.Error(), part) {
				t.Fatalf("refusal does not say %q: %v", part, err)
			}
		}
	}
	if rows := kekRows(t, m); len(rows) != 1 || rows[0].ID != keyID || rows[0].State != secretbroker.KEKStatePrimary {
		t.Fatalf("the registry changed while the KMS was down: %+v", rows)
	}

	// A fresh store whose current root is the KMS mints nothing from the
	// passphrase while the KMS is down: it fails.
	fresh := newMember(t, statedbtest.Path(t))
	if _, err := fresh.keyring(t, root, secretbroker.PassphraseRoot(testPassphrase)); err == nil ||
		!errors.Is(err, secretbroker.ErrKMSUnavailable) {
		t.Fatalf("a fresh store with its KMS down: %v", err)
	}
	if rows := kekRows(t, fresh); len(rows) != 0 {
		t.Fatalf("a key was minted with the KMS down: %+v", rows)
	}

	// Back up, the same store opens again.
	if err := p.Restart(); err != nil {
		t.Fatal(err)
	}
	secretbroker.ForgetOpenedKeys()
	m.mustKeyring(t, root, secretbroker.Root{})
}

// Another plugin's key does not open the store: the refusal is a refusal, not
// an outage, and says the KMS did not unwrap the key.
func TestKeyringRefusesAnotherPluginsKey(t *testing.T) {
	a := kmstest.StartPlugin(t)
	b := kmstest.StartPlugin(t)
	m := newMember(t, statedbtest.Path(t))
	kr := m.mustKeyring(t, pluginRoot(t, a, "kms-prod", ""), secretbroker.Root{})
	mint(t, m.broker(t, kr), "s", "v")

	secretbroker.ForgetOpenedKeys()
	_, err := m.keyring(t, pluginRoot(t, b, "kms-prod", ""), secretbroker.Root{})
	if err == nil {
		t.Fatal("another plugin's key opened the store")
	}
	if errors.Is(err, secretbroker.ErrKMSUnavailable) || !errors.Is(err, secretbroker.ErrKeyUnavailable) {
		t.Fatalf("a wrong key reads as an outage: %v", err)
	}
	if !strings.Contains(err.Error(), "did not unwrap") {
		t.Fatalf("refusal does not say the KMS refused: %v", err)
	}
}

// A plugin slower than the timeout is an unreachable KMS, found out within
// the timeout; one inside it is fine.
func TestKeyringWithASlowPlugin(t *testing.T) {
	p := kmstest.StartPlugin(t)
	m := newMember(t, statedbtest.Path(t))
	root := pluginRoot(t, p, "", "300ms")
	kr := m.mustKeyring(t, root, secretbroker.Root{})
	want := map[string]string{mint(t, m.broker(t, kr), "s", "v"): "v"}

	p.SetDelay(100 * time.Millisecond)
	secretbroker.ForgetOpenedKeys()
	opens(t, m, m.mustKeyring(t, root, secretbroker.Root{}), want)

	p.SetDelay(3 * time.Second)
	secretbroker.ForgetOpenedKeys()
	start := time.Now()
	_, err := m.keyring(t, root, secretbroker.Root{})
	if err == nil || !errors.Is(err, secretbroker.ErrKMSUnavailable) {
		t.Fatalf("a plugin past its timeout: %v", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("refusing took %s with a 300ms timeout", took)
	}
	// A failure is remembered briefly, so reads during an outage do not each
	// wait out the timeout again.
	start = time.Now()
	if _, err := m.keyring(t, root, secretbroker.Root{}); err == nil {
		t.Fatal("opened while the plugin is still slow")
	}
	if took := time.Since(start); took > 150*time.Millisecond {
		t.Fatalf("a second open during the outage took %s", took)
	}
}

// Members opening one store at once — each its own process in all but the
// key cache — all open it, share their unwraps, read each other's writes, and
// leave one primary.
func TestConcurrentMembersOpenOneStore(t *testing.T) {
	p := kmstest.StartPlugin(t)
	path := statedbtest.Path(t)
	first := newMember(t, path)
	kr := first.mustKeyring(t, pluginRoot(t, p, "", ""), secretbroker.Root{})
	want := map[string]string{}
	for i := 0; i < 5; i++ {
		v := fmt.Sprintf("seed-%d", i)
		want[mint(t, first.broker(t, kr), "seed"+fmt.Sprint(i), v)] = v
	}

	const members = 8
	ms := make([]member, members)
	roots := make([]secretbroker.Root, members)
	for i := range ms {
		ms[i] = newMember(t, path)
		roots[i] = pluginRoot(t, p, "", "")
	}
	secretbroker.ForgetOpenedKeys()
	before := p.Calls("Decrypt")

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		errs    []error
		written = map[string]string{}
	)
	start := make(chan struct{})
	for i := 0; i < members; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			kr, err := ms[i].keyring(t, roots[i], secretbroker.Root{})
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("member %d: %w", i, err))
				mu.Unlock()
				return
			}
			b, err := secretbroker.New(ms[i].store, secretbroker.WithKeyring(kr))
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}
			v := fmt.Sprintf("member-%d", i)
			s, err := b.Mint(context.Background(), secretbroker.MintRequest{
				Name: fmt.Sprintf("m%d", i), Kind: secretbroker.KindEnv, Payload: []byte("V=" + v), Actor: "test"})
			mu.Lock()
			if err != nil {
				errs = append(errs, err)
			} else {
				written[s.ID] = v
			}
			mu.Unlock()
		}(i)
	}
	close(start)
	wg.Wait()
	for _, err := range errs {
		t.Error(err)
	}
	if n := p.Calls("Decrypt") - before; n > 2 {
		t.Errorf("%d members opening at once made %d unwraps of one key; they should share one", members, n)
	}
	for id, v := range written {
		want[id] = v
	}
	for i := range ms {
		kr, err := ms[i].keyring(t, roots[i], secretbroker.Root{})
		if err != nil {
			t.Fatalf("member %d reopening: %v", i, err)
		}
		opens(t, ms[i], kr, want)
	}
	primaries := 0
	for _, r := range kekRows(t, first) {
		if r.State == secretbroker.KEKStatePrimary {
			primaries++
		}
	}
	if primaries != 1 {
		t.Fatalf("%d primaries after concurrent opens", primaries)
	}
}

// A first open racing on an empty store may mint more than one key, as it may
// with a passphrase; exactly one is primary and every one opens.
func TestConcurrentFirstOpensLeaveOnePrimary(t *testing.T) {
	p := kmstest.StartPlugin(t)
	path := statedbtest.Path(t)
	const members = 6
	var wg sync.WaitGroup
	errs := make(chan error, members)
	for i := 0; i < members; i++ {
		m := newMember(t, path)
		root := pluginRoot(t, p, "", "")
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.keyring(t, root, secretbroker.Root{}); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	m := newMember(t, path)
	secretbroker.ForgetOpenedKeys()
	kr := m.mustKeyring(t, pluginRoot(t, p, "", ""), secretbroker.Root{})
	primaries := 0
	for _, k := range kr.Keys() {
		if !k.Openable {
			t.Errorf("key %s does not open", k.ID)
		}
		if k.Primary {
			primaries++
		}
	}
	if primaries != 1 {
		t.Fatalf("%d primaries", primaries)
	}
}

// A rotation of the plugin's key is followed by rewrapping each key in place:
// one row per key changes, no sealed row does, and the store opens through the
// new key version. Two members rewrapping at once do not both write.
func TestRewrapFollowsAKMSKeyRotation(t *testing.T) {
	p := kmstest.StartPlugin(t)
	path := statedbtest.Path(t)
	m := newMember(t, path)
	root := pluginRoot(t, p, "", "")
	kr := m.mustKeyring(t, root, secretbroker.Root{})
	want := map[string]string{mint(t, m.broker(t, kr), "s", "v"): "v"}
	var id string
	for k := range want {
		id = k
	}
	sealedBefore, _ := m.store.GetSecret(id)

	newKey := p.Rotate()
	if stale := kr.StaleKMSKeys(newKey); len(stale) != 1 || stale[0] != kr.PrimaryID() {
		t.Fatalf("stale keys = %v", stale)
	}

	other := newMember(t, path)
	otherKR := other.mustKeyring(t, pluginRoot(t, p, "", ""), secretbroker.Root{})
	var (
		wg   sync.WaitGroup
		reps [2]secretbroker.KMSRewrapReport
		errs [2]error
	)
	for i, k := range []*secretbroker.Keyring{kr, otherKR} {
		wg.Add(1)
		go func(i int, k *secretbroker.Keyring) {
			defer wg.Done()
			reps[i], errs[i] = k.RewrapKMS(context.Background())
		}(i, k)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("rewrap: %v / %v", errs[0], errs[1])
	}
	if got := reps[0].Rewrapped + reps[1].Rewrapped; got != 1 {
		t.Fatalf("%d rewraps of one key by two members (reports %+v, %+v)", got, reps[0], reps[1])
	}
	rows := kekRows(t, m)
	if len(rows) != 1 || rows[0].KMSKeyID != newKey {
		t.Fatalf("after rewrap the key is wrapped by %q, want %q", rows[0].KMSKeyID, newKey)
	}
	sealedAfter, _ := m.store.GetSecret(id)
	if !bytes.Equal(sealedBefore.WrappedDEK, sealedAfter.WrappedDEK) ||
		!bytes.Equal(sealedBefore.Sealed, sealedAfter.Sealed) || sealedBefore.KeyID != sealedAfter.KeyID {
		t.Fatal("a rewrap of the KMS wrapping changed a sealed row")
	}
	secretbroker.ForgetOpenedKeys()
	fresh := m.mustKeyring(t, root, secretbroker.Root{})
	opens(t, m, fresh, want)
	if stale := fresh.StaleKMSKeys(newKey); len(stale) != 0 {
		t.Fatalf("still stale after the rewrap: %v", stale)
	}
}

// Moving a store from CLOOP_SECRET_KEY onto a KMS and back is a change of root:
// members on the old configuration and on the new open everything throughout,
// the retire step moves every row and shreds the old root's keys, and after it
// the old root alone refuses.
func TestMoveOntoAKMSAndBack(t *testing.T) {
	p := kmstest.StartPlugin(t)
	path := statedbtest.Path(t)
	m := newMember(t, path)
	pass := secretbroker.PassphraseRoot(testPassphrase)
	kmsRoot := pluginRoot(t, p, "", "")

	// Before: a passphrase hub.
	old := m.mustKeyring(t, pass, secretbroker.Root{})
	want := map[string]string{}
	for i := 0; i < 4; i++ {
		v := fmt.Sprintf("before-%d", i)
		want[mint(t, m.broker(t, old), "b"+fmt.Sprint(i), v)] = v
	}
	passKey := old.PrimaryID()

	// Rolling restart onto secrets.kms with previous_root: passphrase. The
	// primary stays the passphrase key, so a member not yet restarted and
	// one restarted seal under one key and read each other.
	moving := m.mustKeyring(t, kmsRoot, pass)
	if moving.PrimaryID() != passKey || moving.PrimaryFromCurrent() {
		t.Fatal("a member restarted onto the KMS minted, or changed the primary, before the retire step")
	}
	if p.Calls("Encrypt") != 0 {
		t.Fatal("the KMS was asked to wrap anything before the retire step")
	}
	want[mint(t, m.broker(t, moving), "during-new", "n")] = "n"
	want[mint(t, m.broker(t, old), "during-old", "o")] = "o"
	opens(t, m, old, want)
	opens(t, m, moving, want)

	// The retire step.
	rot, err := secretbroker.NewRotator(moving, m.store)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := rot.RetirePrevious(context.Background(), secretbroker.RetirePreviousOptions{Actor: "test"})
	if err != nil || !rep.Complete || rep.Minted == "" || len(rep.Keys) != 1 || rep.Keys[0] != passKey {
		t.Fatalf("retire previous: %+v, %v", rep, err)
	}
	for _, r := range kekRows(t, m) {
		switch r.ID {
		case passKey:
			if r.State != secretbroker.KEKStateRetired || r.Salt != "" || len(r.CheckValue) != 0 {
				t.Fatalf("the passphrase key was not shredded: %+v", r)
			}
		case rep.Minted:
			if r.Wrap != secretbroker.WrapKMS || r.State != secretbroker.KEKStatePrimary {
				t.Fatalf("the minted key is not the KMS primary: %+v", r)
			}
		}
	}
	secretbroker.ForgetOpenedKeys()
	opens(t, m, m.mustKeyring(t, kmsRoot, secretbroker.Root{}), want)
	if _, err := m.keyring(t, pass, secretbroker.Root{}); err == nil {
		t.Fatal("the passphrase alone still opens the store after it moved onto the KMS")
	}

	// And back: CLOOP_SECRET_KEY current, the KMS as secrets.kms_previous.
	kmsKey := rep.Minted
	back := m.mustKeyring(t, pass, kmsRoot)
	rot, err = secretbroker.NewRotator(back, m.store)
	if err != nil {
		t.Fatal(err)
	}
	rep, err = rot.RetirePrevious(context.Background(), secretbroker.RetirePreviousOptions{Actor: "test"})
	if err != nil || !rep.Complete || len(rep.Keys) != 1 || rep.Keys[0] != kmsKey {
		t.Fatalf("retire the KMS: %+v, %v", rep, err)
	}
	for _, r := range kekRows(t, m) {
		if r.ID == kmsKey && (r.State != secretbroker.KEKStateRetired || len(r.KMSCiphertext) != 0) {
			t.Fatalf("the KMS key's ciphertext survived its retirement: %+v", r)
		}
	}
	secretbroker.ForgetOpenedKeys()
	opens(t, m, m.mustKeyring(t, pass, secretbroker.Root{}), want)
}

// newMemKeyStore is a one-record registry, standing in for how an older build
// reads a KMS-held row.
func newMemKeyStore(rec statedb.KEKRow) *memKeys {
	return &memKeys{rec: secretstore.KEKFromRow(rec)}
}

type memKeys struct{ rec secretbroker.KEKRecord }

func (m *memKeys) PutKEK(k secretbroker.KEKRecord) error { return errors.New("read-only") }
func (m *memKeys) ListKEKs() ([]secretbroker.KEKRecord, error) {
	return []secretbroker.KEKRecord{m.rec}, nil
}
func (m *memKeys) PrimaryKEK() (secretbroker.KEKRecord, bool, error) { return m.rec, true, nil }
func (m *memKeys) PromoteKEK(string, time.Time) error                { return errors.New("read-only") }
func (m *memKeys) RetireKEK(string, time.Time) error                 { return errors.New("read-only") }
