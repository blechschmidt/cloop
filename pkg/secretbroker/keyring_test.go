package secretbroker

// Unit tests for envelope encryption and the key registry (Task 20181).
//
// These run against an in-memory registry, which is right for the questions
// they ask: does a rewrap preserve plaintext, does associated data actually
// bind a row, does a retired key fail loudly. The SQLite-level questions —
// compare-and-swap under concurrent writers, the one-time legacy upgrade,
// interruption and resume against a real file — are in
// pkg/secretstore/rotation_test.go, because they are only meaningful against
// a database that can genuinely race.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// in-memory key registry
// ---------------------------------------------------------------------------

// memKeyStore adds a KEK registry, rotation history, and a SealedSet view to
// memStore, so a test double exercises exactly the interfaces a real hub
// implements.
type memKeyStore struct {
	*memStore

	kmu       sync.Mutex
	keks      map[string]KEKRecord
	rotations []RotationRecord

	// refuseRetire mimics the SQL-side refusal without needing SQL.
	refuseRetire map[string]bool

	// primaryErr makes PrimaryKEK fail, standing in for a locked database.
	primaryErr error
	// onReplace fires after every successful ReplaceSealed, so a test can
	// simulate another writer racing the rotator on the same row. It receives
	// the envelope the row held beforehand.
	onReplace func(id string, previous Envelope)
}

func newMemKeyStore() *memKeyStore {
	return &memKeyStore{
		memStore:     newMemStore(),
		keks:         map[string]KEKRecord{},
		refuseRetire: map[string]bool{},
	}
}

func (m *memKeyStore) PutKEK(k KEKRecord) error {
	m.kmu.Lock()
	defer m.kmu.Unlock()
	m.keks[k.ID] = k
	return nil
}

func (m *memKeyStore) ListKEKs() ([]KEKRecord, error) {
	m.kmu.Lock()
	defer m.kmu.Unlock()
	out := make([]KEKRecord, 0, len(m.keks))
	for _, k := range m.keks {
		out = append(out, k)
	}
	return out, nil
}

func (m *memKeyStore) PrimaryKEK() (KEKRecord, bool, error) {
	m.kmu.Lock()
	defer m.kmu.Unlock()
	if m.primaryErr != nil {
		return KEKRecord{}, false, m.primaryErr
	}
	for _, rec := range m.keks {
		if rec.State == KEKStatePrimary {
			return rec, true, nil
		}
	}
	return KEKRecord{}, false, nil
}

func (m *memKeyStore) PromoteKEK(id string, _ time.Time) error {
	m.kmu.Lock()
	defer m.kmu.Unlock()
	if _, ok := m.keks[id]; !ok {
		return fmt.Errorf("%w: %s", ErrKeyUnknown, id)
	}
	for kid, rec := range m.keks {
		if rec.State == KEKStatePrimary && kid != id {
			rec.State = KEKStateActive
			m.keks[kid] = rec
		}
	}
	rec := m.keks[id]
	rec.State = KEKStatePrimary
	m.keks[id] = rec
	return nil
}

func (m *memKeyStore) RetireKEK(id string, at time.Time) error {
	// The reference check the SQL implementation does inside its transaction.
	counts, err := m.CountSealedByKey()
	if err != nil {
		return err
	}
	m.kmu.Lock()
	defer m.kmu.Unlock()
	if counts[id] > 0 || m.refuseRetire[id] {
		return fmt.Errorf("%w: %s", ErrKeyInUse, id)
	}
	rec, ok := m.keks[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrKeyUnknown, id)
	}
	if rec.State == KEKStatePrimary {
		return fmt.Errorf("%w: %s is primary", ErrKeyInUse, id)
	}
	rec.State = KEKStateRetired
	rec.Salt = ""
	rec.CheckValue = nil
	rec.RetiredAt = at
	m.keks[id] = rec
	return nil
}

func (m *memKeyStore) PutRotation(r RotationRecord) error {
	m.kmu.Lock()
	defer m.kmu.Unlock()
	for i, existing := range m.rotations {
		if existing.ID == r.ID {
			m.rotations[i] = r
			return nil
		}
	}
	m.rotations = append(m.rotations, r)
	return nil
}

func (m *memKeyStore) ListRotations(limit int) ([]RotationRecord, error) {
	m.kmu.Lock()
	defer m.kmu.Unlock()
	out := append([]RotationRecord(nil), m.rotations...)
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

func (m *memKeyStore) SealedSetName() string { return "secrets" }

func (m *memKeyStore) CountSealedByKey() (map[string]int, error) {
	secrets, err := m.ListSecrets()
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, s := range secrets {
		id := s.KeyID
		if id == "" {
			id = LegacyKeyID
		}
		out[id]++
	}
	return out, nil
}

func (m *memKeyStore) ListSealedNotUnder(keyID string, limit int) ([]SealedRow, error) {
	secrets, err := m.ListSecrets()
	if err != nil {
		return nil, err
	}
	var out []SealedRow
	for _, s := range secrets {
		if s.KeyID == keyID {
			continue
		}
		out = append(out, SealedRow{ID: s.ID, AAD: AADFor(SetSecrets, s.ID), Env: s.Envelope()})
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *memKeyStore) ReplaceSealed(id string, expect, next Envelope) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.secrets[id]
	if !ok {
		return false, nil
	}
	// Compare-and-swap on the exact ciphertext, as SQLite does.
	if s.KeyID != expect.KeyID || !bytes.Equal(s.Sealed, expect.Ciphertext) {
		return false, nil
	}
	m.secrets[id] = s.WithEnvelope(next)
	hook := m.onReplace
	m.mu.Unlock()
	if hook != nil {
		hook(id, expect)
	}
	m.mu.Lock()
	return true, nil
}

var (
	_ KeyStore      = (*memKeyStore)(nil)
	_ RotationStore = (*memKeyStore)(nil)
	_ SealedSet     = (*memKeyStore)(nil)
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const testPassphrase = "correct horse battery staple"

func newTestKeyring(t *testing.T, store *memKeyStore) *Keyring {
	t.Helper()
	kr, err := OpenKeyring(store, WithKeyringPassphrase(testPassphrase))
	if err != nil {
		t.Fatalf("open keyring: %v", err)
	}
	return kr
}

func mintTestSecrets(t *testing.T, b *Broker, n int) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		s, err := b.Mint(context.Background(), MintRequest{
			Name:    fmt.Sprintf("secret-%02d", i),
			Kind:    KindEnv,
			Payload: []byte(fmt.Sprintf("TOKEN_%02d=value-%02d", i, i)),
			Actor:   "test",
		})
		if err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
		ids = append(ids, s.ID)
	}
	return ids
}

// ---------------------------------------------------------------------------
// envelope shape
// ---------------------------------------------------------------------------

// TestMintProducesEnvelopeNotDirectCiphertext is the check that the feature is
// switched on at all. Everything else here would still pass against the old
// single-key construction if secrets were quietly still sealed directly.
func TestMintProducesEnvelopeNotDirectCiphertext(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)
	b, err := New(store, WithKeyring(kr))
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}

	id := mintTestSecrets(t, b, 1)[0]
	sec, err := store.GetSecret(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if sec.KeyID != kr.PrimaryID() {
		t.Errorf("secret key id = %q, want the primary %q", sec.KeyID, kr.PrimaryID())
	}
	if len(sec.WrappedDEK) == 0 {
		t.Error("secret has no wrapped DEK — it was sealed with the legacy construction")
	}
	if sec.Envelope().IsLegacy() {
		t.Error("envelope reports itself legacy")
	}
}

// TestEveryRowGetsADistinctDataKey. Reusing one DEK across rows would give
// back exactly what envelope encryption is for: one compromise, one blast
// radius. Distinct wrapped DEKs are the observable consequence.
func TestEveryRowGetsADistinctDataKey(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)
	b, _ := New(store, WithKeyring(kr))

	seen := map[string]bool{}
	for _, id := range mintTestSecrets(t, b, 8) {
		sec, err := store.GetSecret(id)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		k := string(sec.WrappedDEK)
		if seen[k] {
			t.Fatalf("wrapped DEK repeated across rows — data keys are not per-row")
		}
		seen[k] = true
	}
}

// TestEnvelopeIsBoundToItsRow covers the substitution attack the associated
// data exists to stop: an attacker with write access to the database moving a
// secret they control into a row that trusted grants point at.
func TestEnvelopeIsBoundToItsRow(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)

	victim, err := kr.SealFor("sec_victim", []byte("the-real-production-token"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// The whole envelope moves — both halves, exactly as a cut-and-paste
	// attacker would do it.
	if _, err := kr.OpenEnvelope("sec_attacker", victim); err == nil {
		t.Fatal("an envelope opened under a different row id — associated data is not bound")
	}
	// And it still opens under its own row, so the binding is not simply
	// breaking decryption.
	plain, err := kr.OpenEnvelope("sec_victim", victim)
	if err != nil {
		t.Fatalf("open under its own id: %v", err)
	}
	if string(plain) != "the-real-production-token" {
		t.Errorf("plaintext = %q", plain)
	}
}

// TestWrappedDEKCannotBeSwappedBetweenRows is the same attack at the other
// layer: keep the victim's ciphertext, substitute a DEK the attacker wrapped.
func TestWrappedDEKCannotBeSwappedBetweenRows(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)

	victim, _ := kr.SealFor("sec_victim", []byte("production"))
	attacker, _ := kr.SealFor("sec_attacker", []byte("attacker"))

	frankenstein := Envelope{
		KeyID:      victim.KeyID,
		WrappedDEK: attacker.WrappedDEK,
		Ciphertext: victim.Ciphertext,
	}
	if _, err := kr.OpenEnvelope("sec_victim", frankenstein); err == nil {
		t.Fatal("a foreign wrapped DEK was accepted for this row")
	}
}

// ---------------------------------------------------------------------------
// rotation
// ---------------------------------------------------------------------------

func TestRotationRewrapsWithoutChangingCiphertext(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)
	b, _ := New(store, WithKeyring(kr))

	ids := mintTestSecrets(t, b, 5)
	before := map[string]Secret{}
	for _, id := range ids {
		s, _ := store.GetSecret(id)
		before[id] = s
	}
	oldKey := kr.PrimaryID()

	rot, err := NewRotator(kr, store)
	if err != nil {
		t.Fatalf("rotator: %v", err)
	}
	report, err := rot.Rotate(context.Background(), RotateOptions{NewKey: true, Actor: "test"})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !report.Complete || report.Rewrapped != len(ids) {
		t.Fatalf("report = %+v, want complete with %d rewrapped", report, len(ids))
	}
	if report.TargetKeyID == oldKey {
		t.Fatal("rotation did not mint a new key")
	}

	for _, id := range ids {
		after, _ := store.GetSecret(id)
		if after.KeyID != report.TargetKeyID {
			t.Errorf("%s key id = %q, want %q", id, after.KeyID, report.TargetKeyID)
		}
		// This is the property that makes rotation cheap and safe: the
		// payload was never decrypted, so its bytes are untouched.
		if !bytes.Equal(after.Sealed, before[id].Sealed) {
			t.Errorf("%s payload ciphertext changed during rotation", id)
		}
		if bytes.Equal(after.WrappedDEK, before[id].WrappedDEK) {
			t.Errorf("%s wrapped DEK unchanged — it was not rewrapped", id)
		}
	}
}

func TestSecretsStillOpenAfterSeveralRotations(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)
	b, _ := New(store, WithKeyring(kr))

	const payload = "ghp_rotationsurvivor0123456789"
	sec, err := b.Mint(context.Background(), MintRequest{
		Name: "survivor", Kind: KindGitHubPAT, Payload: []byte(payload), Actor: "test",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	rot, _ := NewRotator(kr, store)
	for i := 0; i < 3; i++ {
		if _, err := rot.Rotate(context.Background(), RotateOptions{NewKey: true}); err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
	}

	stored, _ := store.GetSecret(sec.ID)
	plain, err := kr.OpenEnvelope(AADFor(SetSecrets, stored.ID), stored.Envelope())
	if err != nil {
		t.Fatalf("open after rotations: %v", err)
	}
	if string(plain) != payload {
		t.Errorf("plaintext = %q, want %q", plain, payload)
	}
}

// TestRotationIsIdempotent — the property resumability rests on. Running a
// finished rotation again must move nothing, or "re-run to continue" would be
// advice that churns the whole registry every time.
func TestRotationIsIdempotent(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)
	b, _ := New(store, WithKeyring(kr))
	mintTestSecrets(t, b, 4)

	rot, _ := NewRotator(kr, store)
	if _, err := rot.Rotate(context.Background(), RotateOptions{NewKey: true}); err != nil {
		t.Fatalf("first rotation: %v", err)
	}
	second, err := rot.Rotate(context.Background(), RotateOptions{NewKey: false})
	if err != nil {
		t.Fatalf("second rotation: %v", err)
	}
	if second.Rewrapped != 0 || second.Failed != 0 {
		t.Errorf("re-running a finished rotation moved %d row(s): %+v", second.Rewrapped, second)
	}
	if !second.Complete {
		t.Error("re-run reported incomplete")
	}
}

// TestInterruptedRotationResumesToCompletion is the crash-safety case: cancel
// mid-run, then run again and expect every row to arrive.
func TestInterruptedRotationResumesToCompletion(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)
	b, _ := New(store, WithKeyring(kr))
	ids := mintTestSecrets(t, b, 20)

	rot, _ := NewRotator(kr, store)
	rot.WithBatch(4).WithHistory(store)

	// Cancel after the first batch, which is the realistic shape of an
	// interruption: some rows moved, some did not, and the process is gone.
	ctx, cancel := context.WithCancel(context.Background())
	rot.WithProgress(func(RotationRecord) { cancel() })

	first, err := rot.Rotate(ctx, RotateOptions{NewKey: true, Actor: "test"})
	if err == nil {
		t.Fatal("expected the cancelled rotation to report an error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled rotation error = %v, want context.Canceled", err)
	}
	if first.Complete {
		t.Fatal("an interrupted rotation reported itself complete")
	}
	target := first.TargetKeyID

	// Every row is still readable: rotation retires nothing, so the old key
	// is intact and a half-rotated registry is a working one.
	for _, id := range ids {
		s, _ := store.GetSecret(id)
		if _, oerr := kr.OpenEnvelope(AADFor(SetSecrets, s.ID), s.Envelope()); oerr != nil {
			t.Fatalf("row %s unreadable after interruption: %v", id, oerr)
		}
	}

	rot.WithProgress(nil)
	second, err := rot.Rotate(context.Background(), RotateOptions{NewKey: false, Actor: "test"})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if !second.Complete {
		t.Fatalf("resumed rotation incomplete: %+v", second)
	}
	if second.TargetKeyID != target {
		t.Errorf("resume targeted %q, want the interrupted run's %q", second.TargetKeyID, target)
	}
	if first.Rewrapped+second.Rewrapped != len(ids) {
		t.Errorf("rewrapped %d + %d, want %d in total",
			first.Rewrapped, second.Rewrapped, len(ids))
	}
	for _, id := range ids {
		s, _ := store.GetSecret(id)
		if s.KeyID != target {
			t.Errorf("%s still under %q after resume", id, s.KeyID)
		}
	}

	// The history records the interruption rather than reporting success.
	recs, _ := store.ListRotations(10)
	if len(recs) == 0 {
		t.Fatal("no rotation history recorded")
	}
	var sawInterrupted bool
	for _, r := range recs {
		if r.State == RotationInterrupted {
			sawInterrupted = true
		}
	}
	if !sawInterrupted {
		t.Error("no rotation record marked interrupted")
	}
}

// TestRotationUnderConcurrentReadWriteLoad. The rotator must never revert a
// concurrent write and never make a row unreadable, even momentarily.
func TestRotationUnderConcurrentReadWriteLoad(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)
	b, _ := New(store, WithKeyring(kr))
	ids := mintTestSecrets(t, b, 30)

	var (
		wg       sync.WaitGroup
		stop     = make(chan struct{})
		readErrs = make(chan error, 64)
	)

	// Readers: every row must stay openable for the whole rotation. This is
	// the "online" in online rotation — if it ever fails, a lease would have
	// failed for a real workload.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, id := range ids {
					s, gerr := store.GetSecret(id)
					if gerr != nil {
						continue
					}
					if _, oerr := kr.OpenEnvelope(AADFor(SetSecrets, s.ID), s.Envelope()); oerr != nil {
						select {
						case readErrs <- fmt.Errorf("%s: %w", id, oerr):
						default:
						}
						return
					}
				}
			}
		}()
	}

	// A writer re-sealing rows underneath the rotation, which is what an
	// operator re-minting a credential looks like from here.
	rewritten := map[string]string{}
	var rwmu sync.Mutex
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i, id := range ids {
			if i%3 != 0 {
				continue
			}
			select {
			case <-stop:
				return
			default:
			}
			fresh := fmt.Sprintf("REWRITTEN_%s", id)
			env, serr := kr.SealFor(AADFor(SetSecrets, id), []byte(fresh))
			if serr != nil {
				continue
			}
			s, gerr := store.GetSecret(id)
			if gerr != nil {
				continue
			}
			if err := store.PutSecret(s.WithEnvelope(env)); err == nil {
				rwmu.Lock()
				rewritten[id] = fresh
				rwmu.Unlock()
			}
		}
	}()

	rot, _ := NewRotator(kr, store)
	rot.WithBatch(3)
	if _, err := rot.Rotate(context.Background(), RotateOptions{NewKey: true}); err != nil {
		t.Fatalf("rotate under load: %v", err)
	}
	// A second pass mops up rows the writer touched mid-flight, exactly as
	// `cloop hub key rotate --continue` would.
	report, err := rot.Rotate(context.Background(), RotateOptions{NewKey: false})
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if !report.Complete {
		t.Fatalf("rotation under load did not converge: %+v", report)
	}

	close(stop)
	wg.Wait()
	close(readErrs)
	for err := range readErrs {
		t.Errorf("a row became unreadable during rotation: %v", err)
	}

	target := kr.PrimaryID()
	for _, id := range ids {
		s, _ := store.GetSecret(id)
		if s.KeyID != target {
			t.Errorf("%s left under %q", id, s.KeyID)
		}
		plain, oerr := kr.OpenEnvelope(AADFor(SetSecrets, s.ID), s.Envelope())
		if oerr != nil {
			t.Errorf("%s unreadable after rotation: %v", id, oerr)
			continue
		}
		// The lost-update check: a value written during the rotation must
		// still be the value that is there afterwards.
		rwmu.Lock()
		want, wasRewritten := rewritten[id]
		rwmu.Unlock()
		if wasRewritten && string(plain) != want {
			t.Errorf("%s: rotation reverted a concurrent write (got %q, want %q)", id, plain, want)
		}
	}
}

// ---------------------------------------------------------------------------
// retirement
// ---------------------------------------------------------------------------

func TestRetireRefusesWhileRowsReferenceTheKey(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)
	b, _ := New(store, WithKeyring(kr))
	mintTestSecrets(t, b, 3)

	old := kr.PrimaryID()
	rot, _ := NewRotator(kr, store)
	if _, err := rot.Rotate(context.Background(), RotateOptions{NewKey: true}); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// The new primary is holding every row, so retiring it must be refused.
	if err := rot.RetireKey(kr.PrimaryID()); !errors.Is(err, ErrKeyInUse) {
		t.Fatalf("retiring the in-use primary: err = %v, want ErrKeyInUse", err)
	}
	// The drained old key may go.
	if err := rot.RetireKey(old); err != nil {
		t.Fatalf("retiring the drained key: %v", err)
	}
}

// TestReadsFailLoudlyOnceAKEKIsRetired. The setup is deliberately hostile —
// a row is put back under the retired key, which is what a partial backup
// restore looks like. The read must not merely fail; it must say the key was
// retired, because that is the difference between "fix your passphrase" and
// "this credential is gone, re-mint it".
func TestReadsFailLoudlyOnceAKEKIsRetired(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)
	b, _ := New(store, WithKeyring(kr))

	sec, err := b.Mint(context.Background(), MintRequest{
		Name: "doomed", Kind: KindEnv, Payload: []byte("K=v"), Actor: "test",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	stranded, _ := store.GetSecret(sec.ID)
	doomedKey := stranded.KeyID

	rot, _ := NewRotator(kr, store)
	if _, err := rot.Rotate(context.Background(), RotateOptions{NewKey: true}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := rot.RetireKey(doomedKey); err != nil {
		t.Fatalf("retire: %v", err)
	}

	// Restore the pre-rotation row: sealed under a key whose salt is gone.
	if err := store.PutSecret(stranded); err != nil {
		t.Fatalf("restore stranded row: %v", err)
	}

	_, err = kr.OpenEnvelope(AADFor(SetSecrets, stranded.ID), stranded.Envelope())
	if err == nil {
		t.Fatal("a row sealed under a retired key opened — the salt was not destroyed")
	}
	if !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("err = %v, want ErrKeyRetired", err)
	}
	if !strings.Contains(err.Error(), doomedKey) {
		t.Errorf("error does not name the retired key: %v", err)
	}

	// And through the broker, where an operator would actually meet it: the
	// specific cause survives the wrapping, so `errors.Is` at any layer can
	// distinguish a shredded key from a corrupt payload.
	if _, merr := b.materialFor(stranded, Grant{ID: "g", SecretID: stranded.ID}); merr == nil {
		t.Fatal("materialFor succeeded against a retired key")
	} else if !errors.Is(merr, ErrKeyRetired) || !errors.Is(merr, ErrSealFailed) {
		t.Errorf("materialFor err = %v; want both ErrKeyRetired and ErrSealFailed", merr)
	}

	// A retired key cannot be rewrapped away either — rotation reports it as
	// stuck rather than looping on it forever.
	report, rerr := rot.Rotate(context.Background(), RotateOptions{NewKey: false})
	if rerr == nil {
		t.Fatal("rotation over an unrecoverable row reported success")
	}
	if !errors.Is(rerr, ErrRotationFailed) || report.Failed != 1 {
		t.Errorf("report = %+v, err = %v; want one failed row and ErrRotationFailed", report, rerr)
	}
}

// ---------------------------------------------------------------------------
// registry safety
// ---------------------------------------------------------------------------

// TestWrongPassphraseRefusesRatherThanForkingTheRegistry.
//
// The dangerous version of this code mints a fresh primary whenever it cannot
// find a usable one — which, on a typo'd passphrase, silently demotes the real
// key, starts sealing new secrets under a key the operator does not know
// exists, and reports itself healthy. Every symptom appears later, somewhere
// else.
func TestWrongPassphraseRefusesRatherThanForkingTheRegistry(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)
	original := kr.PrimaryID()

	_, err := OpenKeyring(store, WithKeyringPassphrase("a different passphrase"))
	if err == nil {
		t.Fatal("opening with the wrong passphrase succeeded")
	}
	if !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("err = %v, want ErrKeyUnavailable", err)
	}

	keks, _ := store.ListKEKs()
	if len(keks) != 1 {
		t.Fatalf("registry grew to %d keys — it forked", len(keks))
	}
	if keks[0].ID != original || keks[0].State != KEKStatePrimary {
		t.Errorf("primary changed: %+v, want %s still primary", keks[0], original)
	}
}

// TestReadOnlyKeyringDoesNotMint keeps `cloop hub key list` from fabricating
// the registry it reports on.
func TestReadOnlyKeyringDoesNotMint(t *testing.T) {
	store := newMemKeyStore()
	kr, err := OpenKeyring(store,
		WithKeyringPassphrase(testPassphrase), WithoutKeyCreation())
	if err != nil {
		t.Fatalf("open read-only: %v", err)
	}
	if kr.PrimaryID() != "" {
		t.Errorf("read-only open produced a primary key %q", kr.PrimaryID())
	}
	if keks, _ := store.ListKEKs(); len(keks) != 0 {
		t.Errorf("read-only open wrote %d key(s)", len(keks))
	}
	// And it cannot seal, so nothing downstream mistakes it for a live one.
	if _, err := kr.SealFor("x", []byte("y")); err == nil {
		t.Error("a keyring with no primary sealed something")
	}
}

// TestKeysNeverReportTwoPrimaries guards the display invariant a promotion
// could break in memory even while the database is correct.
func TestKeysNeverReportTwoPrimaries(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)
	if _, err := kr.AddKey("test"); err != nil {
		t.Fatalf("add key: %v", err)
	}
	primaries := 0
	for _, k := range kr.Keys() {
		if k.Primary {
			primaries++
		}
		if k.State == KEKStatePrimary && !k.Primary {
			t.Errorf("key %s claims state=primary but is not the primary", k.ID)
		}
	}
	if primaries != 1 {
		t.Errorf("Keys() reported %d primaries, want exactly 1", primaries)
	}
}

// ---------------------------------------------------------------------------
// legacy interop
// ---------------------------------------------------------------------------

// TestLegacyRowsRemainReadableAndUpgradeOnRotation is the migration promise:
// nothing breaks on upgrade, and the first rotation converts pre-envelope rows
// into envelope form.
func TestLegacyRowsRemainReadableAndUpgradeOnRotation(t *testing.T) {
	store := newMemKeyStore()

	// A row as the old construction wrote it: ciphertext directly under the
	// passphrase-derived key, no wrapped DEK.
	salt := make([]byte, saltSize)
	for i := range salt {
		salt[i] = byte(i)
	}
	if err := store.SetMeta(metaKeySalt, encodeHex(salt)); err != nil {
		t.Fatalf("seed salt: %v", err)
	}
	legacyCipher := &Cipher{key: deriveKey(testPassphrase, salt)}
	const legacyPayload = "LEGACY_TOKEN=abc123"
	sealed, err := legacyCipher.Seal([]byte(legacyPayload))
	if err != nil {
		t.Fatalf("legacy seal: %v", err)
	}
	legacyRow := Secret{
		ID: "sec_legacy", Kind: KindEnv, Name: "legacy",
		Sealed: sealed, KeyID: LegacyKeyID, CreatedAt: time.Now(),
	}
	if err := store.PutSecret(legacyRow); err != nil {
		t.Fatalf("put legacy: %v", err)
	}

	kr := newTestKeyring(t, store)
	if !kr.HasLegacy() {
		t.Fatal("keyring did not pick up the legacy salt")
	}
	plain, err := kr.OpenEnvelope(AADFor(SetSecrets, legacyRow.ID), legacyRow.Envelope())
	if err != nil {
		t.Fatalf("open legacy row: %v", err)
	}
	if string(plain) != legacyPayload {
		t.Errorf("legacy plaintext = %q", plain)
	}

	rot, _ := NewRotator(kr, store)
	report, err := rot.Rotate(context.Background(), RotateOptions{NewKey: false})
	if err != nil {
		t.Fatalf("upgrade rotation: %v", err)
	}
	if report.Rewrapped != 1 {
		t.Fatalf("upgraded %d rows, want 1: %+v", report.Rewrapped, report)
	}

	upgraded, _ := store.GetSecret(legacyRow.ID)
	if upgraded.Envelope().IsLegacy() {
		t.Error("row is still legacy after rotation")
	}
	if len(upgraded.WrappedDEK) == 0 {
		t.Error("upgraded row has no wrapped DEK")
	}
	// The upgrade re-encrypts (a legacy row has no DEK to rewrap), so the
	// ciphertext must change while the plaintext must not.
	if bytes.Equal(upgraded.Sealed, legacyRow.Sealed) {
		t.Error("legacy ciphertext was carried over verbatim into the envelope")
	}
	got, err := kr.OpenEnvelope(AADFor(SetSecrets, upgraded.ID), upgraded.Envelope())
	if err != nil {
		t.Fatalf("open upgraded row: %v", err)
	}
	if string(got) != legacyPayload {
		t.Errorf("plaintext after upgrade = %q, want %q", got, legacyPayload)
	}
}

// TestStatusReportsWhatIsSealedUnderWhat backs `cloop hub key status`, which
// is the only thing an operator has to decide whether retirement is safe.
func TestStatusReportsWhatIsSealedUnderWhat(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)
	b, _ := New(store, WithKeyring(kr))
	mintTestSecrets(t, b, 3)

	rot, _ := NewRotator(kr, store)
	rot.WithHistory(store)

	st, err := rot.Status(5)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.Unrotated != 0 {
		t.Errorf("fresh registry reports %d unrotated rows", st.Unrotated)
	}
	if len(st.Usage) != 1 || st.Usage[0].KeyID != kr.PrimaryID() || st.Usage[0].Total != 3 {
		t.Fatalf("usage = %+v, want 3 rows under the primary", st.Usage)
	}
	if st.Usage[0].BySet["secrets"] != 3 {
		t.Errorf("per-set breakdown = %+v", st.Usage[0].BySet)
	}

	if _, err := kr.AddKey("test"); err != nil {
		t.Fatalf("add key: %v", err)
	}
	st, _ = rot.Status(5)
	if st.Unrotated != 3 {
		t.Errorf("after promoting a new key, unrotated = %d, want 3", st.Unrotated)
	}
}

// TestKeyringAdoptsKeysMintedByAnotherProcess is the staleness case that
// matters operationally: `cloop hub key rotate` runs in a shell while the hub
// is serving, so every long-lived Keyring in the hub process is holding a key
// set that no longer describes the database. Without the self-healing re-read,
// reads of rotated rows would fail in the serving process until it restarted —
// silently, because a session store treats a failed unseal as "no token".
func TestKeyringAdoptsKeysMintedByAnotherProcess(t *testing.T) {
	store := newMemKeyStore()

	// The long-lived reader, opened before anything rotates.
	serving := newTestKeyring(t, store)

	// A separate keyring over the same registry, standing in for the CLI.
	cli := newTestKeyring(t, store)
	b, _ := New(store, WithKeyring(cli))
	sec, err := b.Mint(context.Background(), MintRequest{
		Name: "adopted", Kind: KindEnv, Payload: []byte("ADOPTED=1"), Actor: "cli",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	rot, _ := NewRotator(cli, store)
	report, err := rot.Rotate(context.Background(), RotateOptions{NewKey: true, Actor: "cli"})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if report.TargetKeyID == serving.PrimaryID() {
		t.Fatal("the CLI rotation did not mint a key the serving keyring lacks")
	}

	// The serving keyring has never heard of the new KEK. It must find it
	// rather than report the row unreadable.
	stored, _ := store.GetSecret(sec.ID)
	plain, err := serving.OpenEnvelope(AADFor(SetSecrets, stored.ID), stored.Envelope())
	if err != nil {
		t.Fatalf("serving keyring could not open a row rotated by another process: %v", err)
	}
	if string(plain) != "ADOPTED=1" {
		t.Errorf("plaintext = %q", plain)
	}
	if serving.PrimaryID() != report.TargetKeyID {
		t.Errorf("after adopting, primary = %q, want %q", serving.PrimaryID(), report.TargetKeyID)
	}
}

// TestReloadDropsRetiredKeys: a key retired by another process must stop
// opening rows here too, or retirement would be a property of one process
// rather than of the deployment.
func TestReloadDropsRetiredKeys(t *testing.T) {
	store := newMemKeyStore()
	serving := newTestKeyring(t, store)
	b, _ := New(store, WithKeyring(serving))
	sec, err := b.Mint(context.Background(), MintRequest{
		Name: "retired-elsewhere", Kind: KindEnv, Payload: []byte("R=1"), Actor: "test",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	stranded, _ := store.GetSecret(sec.ID)
	doomed := stranded.KeyID

	rot, _ := NewRotator(serving, store)
	if _, err := rot.Rotate(context.Background(), RotateOptions{NewKey: true}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := rot.RetireKey(doomed); err != nil {
		t.Fatalf("retire: %v", err)
	}
	// Put the pre-rotation row back and force a registry re-read.
	if err := store.PutSecret(stranded); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if err := serving.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, err := serving.OpenEnvelope(AADFor(SetSecrets, stranded.ID), stranded.Envelope()); !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("err = %v, want ErrKeyRetired after reload", err)
	}
}

// ---------------------------------------------------------------------------
// regressions found by adversarial review
// ---------------------------------------------------------------------------

// TestSealNeverUsesAStalePrimary.
//
// The dangerous version caches the primary at open and never checks again. A
// hub process would then keep sealing new material under the key a rotation
// had just moved away from — so a rotation could never reach zero unrotated
// rows while the hub ran, and an operator who retired the old key on the
// database's word ("nothing references it") would have the hub write a fresh
// credential under a salt that had just been destroyed. Unrecoverable, with no
// error anywhere.
func TestSealNeverUsesAStalePrimary(t *testing.T) {
	store := newMemKeyStore()
	serving := newTestKeyring(t, store) // opened before the rotation
	cli := newTestKeyring(t, store)     // stands in for `cloop hub key rotate`

	promoted, err := cli.AddKey("cli")
	if err != nil {
		t.Fatalf("add key: %v", err)
	}
	if serving.PrimaryID() == promoted.ID {
		t.Fatal("the serving keyring already knew the new key — the test proves nothing")
	}

	env, err := serving.SealFor(AADFor(SetSecrets, "sec_after_rotation"), []byte("NEW=1"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if env.KeyID != promoted.ID {
		t.Fatalf("sealed under %q, want the current primary %q", env.KeyID, promoted.ID)
	}
	if serving.PrimaryID() != promoted.ID {
		t.Errorf("keyring did not adopt the new primary: %q", serving.PrimaryID())
	}
}

// TestSealFailsClosedWhenTheRegistryCannotBeRead: if we cannot prove the cached
// primary is still current, sealing under it is the exact failure above.
func TestSealFailsClosedWhenTheRegistryCannotBeRead(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)

	store.primaryErr = errors.New("database is locked")
	if _, err := kr.SealFor(AADFor(SetSecrets, "sec_x"), []byte("X=1")); err == nil {
		t.Fatal("sealed while unable to confirm the primary key")
	}
}

// TestEnvelopesDoNotCrossSealedSets.
//
// Row ids are chosen by whoever writes the row, so binding to the id alone lets
// an attacker with database write access insert a *session* whose id equals a
// secret's id, copy the secret's envelope into the refresh-token columns, and
// have the hub POST the kubeconfig to the identity provider as a refresh token
// — an exfiltration channel out of the sealed store to an external host.
func TestEnvelopesDoNotCrossSealedSets(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)

	const rowID = "shared_id"
	env, err := kr.SealFor(AADFor(SetSecrets, rowID), []byte("kubeconfig-contents"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := kr.OpenEnvelope(AADFor(SetSessions, rowID), env); err == nil {
		t.Fatal("a secret's envelope opened as a session's — the sets are not namespaced")
	}
	if _, err := kr.OpenEnvelope(AADFor(SetSecrets, rowID), env); err != nil {
		t.Fatalf("the envelope no longer opens in its own set: %v", err)
	}
}

// TestDryRunCountsEveryRowNotOneBatch. Walking the listings under-reports by
// exactly the batch size, because a dry run writes nothing and every round
// therefore returns the same first `batch` rows.
func TestDryRunCountsEveryRowNotOneBatch(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)
	b, _ := New(store, WithKeyring(kr))

	const n = 17
	mintTestSecrets(t, b, n)

	rot, _ := NewRotator(kr, store)
	rot.WithBatch(4)

	report, err := rot.Rotate(context.Background(), RotateOptions{NewKey: true, DryRun: true})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if report.Rewrapped != n {
		t.Errorf("dry run reported %d rows, want %d", report.Rewrapped, n)
	}
	// And it wrote nothing: no key minted, no row moved.
	if keks, _ := store.ListKEKs(); len(keks) != 1 {
		t.Errorf("dry run minted a key: registry has %d", len(keks))
	}
	counts, _ := store.CountSealedByKey()
	if counts[kr.PrimaryID()] != n {
		t.Errorf("dry run moved rows: %v", counts)
	}
}

// TestReadOnlyOpenDoesNotPromote. A diagnostic must not repair the registry it
// is diagnosing — `cloop hub key list` reporting a promotion it just performed
// is a lie about the state of the hub.
func TestReadOnlyOpenDoesNotPromote(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)
	id := kr.PrimaryID()

	// Demote it behind the keyring's back — a hand-edited or partially
	// restored registry.
	store.kmu.Lock()
	rec := store.keks[id]
	rec.State = KEKStateActive
	store.keks[id] = rec
	store.kmu.Unlock()

	if _, err := OpenKeyring(store,
		WithKeyringPassphrase(testPassphrase), WithoutKeyCreation()); err != nil {
		t.Fatalf("read-only open: %v", err)
	}
	store.kmu.Lock()
	got := store.keks[id].State
	store.kmu.Unlock()
	if got == KEKStatePrimary {
		t.Error("a read-only open promoted a key")
	}
}

// TestKEKWithoutACheckValueIsNotDerivable. Accepting one would let an attacker
// with database write access NULL every check_value and walk straight past the
// "refuse to start on the wrong passphrase" rule.
func TestKEKWithoutACheckValueIsNotDerivable(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)
	id := kr.PrimaryID()

	store.kmu.Lock()
	rec := store.keks[id]
	rec.CheckValue = nil
	store.keks[id] = rec
	store.kmu.Unlock()

	_, err := OpenKeyring(store, WithKeyringPassphrase("a completely different passphrase"))
	if err == nil {
		t.Fatal("opened with a wrong passphrase against a check-value-less key")
	}
	if !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("err = %v, want ErrKeyUnavailable", err)
	}
}

// TestConcurrentRotationsDoNotLivelock. Two rotators each rewrapping onto their
// own target would otherwise CAS-fight forever, because a lost swap counts as
// progress and the listing never empties.
func TestConcurrentRotationsDoNotLivelock(t *testing.T) {
	store := newMemKeyStore()
	kr := newTestKeyring(t, store)
	b, _ := New(store, WithKeyring(kr))
	mintTestSecrets(t, b, 6)

	rot, _ := NewRotator(kr, store)
	rot.WithBatch(2)

	// A second rotator, pulling every row straight back onto the old key the
	// instant this one moves it. Without a bound the listing never empties,
	// every round rewraps rows that are immediately undone, and neither
	// process ever finishes.
	store.onReplace = func(id string, previous Envelope) {
		sec, err := store.GetSecret(id)
		if err != nil {
			return
		}
		_ = store.PutSecret(sec.WithEnvelope(previous))
	}

	type outcome struct {
		report RotationReport
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		rep, err := rot.Rotate(context.Background(), RotateOptions{NewKey: true})
		done <- outcome{rep, err}
	}()
	select {
	case got := <-done:
		if got.err == nil {
			t.Fatal("a rotation that converged on nothing reported success")
		}
		if !errors.Is(got.err, ErrRotationFailed) {
			t.Errorf("err = %v, want ErrRotationFailed", got.err)
		}
		if got.report.Complete {
			t.Error("report claims complete")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("rotation did not terminate — the barren-round bound is missing")
	}
}
