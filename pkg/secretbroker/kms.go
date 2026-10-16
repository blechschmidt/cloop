package secretbroker

// Key-encryption keys held by an external key-management service (Task 20433).
//
// A KEK derived from CLOOP_SECRET_KEY and a stored salt has one weakness the
// envelope cannot fix: the database and the key file together open everything,
// offline, for as long as anybody keeps the copy — a backup, a volume snapshot,
// a Pod's mounted Secret. A KEK held by a KMS is random instead. Its record
// keeps the KMS's ciphertext of it and the KMS key id that made it, never the
// key, and the hub asks the KMS to unwrap it into memory when it opens the
// store. Copying the database and the key file then gets an attacker the
// ciphertext and nothing to open it with: unwrapping is a call to the KMS,
// which logs it and whose owner can take the hub's access away.
//
// # What a KMS root is to the keyring
//
// A root, in the sense keyring.go uses the word, is whatever a key-encryption
// key comes from. A passphrase root derives a KEK from a salt; a KMS root
// unwraps one. Everything else is shared: a KMS root can be the current root,
// which mints, or the previous one, which only opens, so moving a store from
// CLOOP_SECRET_KEY onto a KMS — or back, or from one KMS to another — is the
// change of root Task 20425 built, finished by `cloop hub key rotate
// --retire-previous` with every cluster member able to open the store
// throughout.
//
// Which root opens a key is still decided by opening it. For a KMS key that
// means the KMS unwraps it and the result passes the key's check value, the
// same check a derived key passes; the record's root column only names the KMS
// for messages and listings.
//
// # The unwrapped key lives in memory only
//
// The plaintext KEK goes from the KMS's response into this process's key
// cache (keycache.go) and nowhere else: not into the record, not into an
// error, not into a log line. Retiring the key wipes it from the cache, and
// destroys the ciphertext in the record, so a retired key cannot be unwrapped
// again by anybody, with or without the KMS.
//
// # An older binary sees a key it cannot open
//
// A KMS-held record carries a decoy salt: random bytes no passphrase derives
// the key from. A build from before this file finds a live key whose check
// value no root it holds can open — and refuses to start, or to seal, naming
// the key and the KMS recorded as its root. Without the decoy it would see an
// empty salt, read that as a retired key, and mint a passphrase key over the
// KMS's primary: the fork, and the downgrade, the keyring exists to prevent.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// WrapKMS marks a KEK record held wrapped by a KMS. A record with an empty
// Wrap derives from a passphrase root and its salt.
const WrapKMS = "kms"

// kmsKEKSize is the length of a KMS-held KEK: AES-256, the same as a derived
// one. A KMS that unwraps to anything else unwrapped something that is not one
// of these keys.
const kmsKEKSize = 32

// kmsCallTimeout bounds a KMS call when the KMS sets no deadline of its own.
// pkg/kms applies the configured timeout to every call; this is the backstop
// for a KMS implementation that does not.
const kmsCallTimeout = time.Minute

// KMS is an external key-management service a key-encryption key can be held
// wrapped by. pkg/kms implements it for a Kubernetes KMS v2 plugin and for
// Vault or OpenBao Transit.
type KMS interface {
	// Name is what the registry records as the root of a key this KMS wraps,
	// and what a hub cluster member advertises: stable for one KMS key across
	// its versions, and distinct from every passphrase fingerprint (it holds
	// a colon).
	Name() string
	// Encrypt wraps plaintext under the KMS's current key.
	Encrypt(ctx context.Context, plaintext []byte) (KMSCiphertext, error)
	// Decrypt unwraps what Encrypt returned. The caller owns the result.
	Decrypt(ctx context.Context, c KMSCiphertext) ([]byte, error)
}

// KMSKeyReporter is the optional part of a KMS that reports the key it
// currently encrypts under, so a rotation of the KMS key can be noticed and the
// keys it wraps rewrapped (RewrapKMS).
type KMSKeyReporter interface {
	CurrentKeyID(ctx context.Context) (string, error)
}

// KMSCiphertext is a key as a KMS wrapped it: everything Decrypt needs back.
type KMSCiphertext struct {
	// KeyID names the KMS key, and for most KMSs its version, that wrapped it.
	KeyID string
	// Ciphertext is the KMS's output. Opaque.
	Ciphertext []byte
	// Annotations are metadata a KMS v2 plugin returns with a ciphertext and
	// must be given back to decrypt it. Not secret by the protocol's rules.
	Annotations map[string][]byte
}

// Root is one root a keyring opens with: a passphrase its keys derive from, or
// a KMS that holds them wrapped. Exactly one of the two is set; the zero Root
// is no root.
type Root struct {
	Passphrase string
	KMS        KMS
}

// PassphraseRoot is a root that derives keys from p.
func PassphraseRoot(p string) Root { return Root{Passphrase: p} }

// KMSRoot is a root that holds keys wrapped by k.
func KMSRoot(k KMS) Root { return Root{KMS: k} }

// IsZero reports whether r is no root.
func (r Root) IsZero() bool { return r.Passphrase == "" && r.KMS == nil }

// IsKMS reports whether r is a KMS root.
func (r Root) IsKMS() bool { return r.KMS != nil }

// opens reports whether r is the kind of root that can open rec: a KMS root
// opens only KMS-held records, a passphrase root only derived ones.
func (r Root) opens(rec KEKRecord) bool {
	if rec.Wrap == WrapKMS {
		return r.KMS != nil
	}
	return r.Passphrase != ""
}

// PassphraseRoots wraps passphrases as roots, current first, skipping empty
// ones — for callers that held the roots as strings before KMS roots existed.
func PassphraseRoots(ps ...string) []Root {
	out := make([]Root, 0, len(ps))
	for _, p := range ps {
		if p != "" {
			out = append(out, PassphraseRoot(p))
		}
	}
	return out
}

// ErrKMSUnavailable is wrapped by every failure to reach, or be answered by, a
// KMS a key is held by — never by a KMS that answered and refused. It wraps
// ErrKeyUnavailable as well, so code that treats an unopenable key as such
// does not need to know there is a KMS behind it.
var ErrKMSUnavailable = fmt.Errorf("%w: the key-management service cannot be reached", ErrKeyUnavailable)

// kmsUnwrap opens rec with the KMS root k: asks the KMS to unwrap the key, and
// checks what came back against the record's check value, exactly as a derived
// key is checked. Every failure wipes what it was given.
func kmsUnwrap(ctx context.Context, k KMS, rec KEKRecord) ([]byte, error) {
	if err := kmsOpenable(rec); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, kmsCallTimeout)
		defer cancel()
	}
	key, err := k.Decrypt(ctx, KMSCiphertext{
		KeyID:       rec.KMSKeyID,
		Ciphertext:  append([]byte(nil), rec.KMSCiphertext...),
		Annotations: copyAnnotations(rec.KMSAnnotations),
	})
	if err != nil {
		// The KMS's own error says why — unreachable, denied, a key it does
		// not hold — and carries no key material: the KMS was never given the
		// plaintext, and the ciphertext is not in it.
		if errors.Is(err, ErrKMSUnavailable) {
			return nil, fmt.Errorf("%w: sealing key %s: %v", ErrKMSUnavailable, rec.ID, kmsErrText(err))
		}
		return nil, fmt.Errorf("%w: sealing key %s: the KMS %s did not unwrap it: %v", ErrKeyUnavailable,
			rec.ID, k.Name(), kmsErrText(err))
	}
	if len(key) != kmsKEKSize {
		zero(key)
		return nil, fmt.Errorf("%w: sealing key %s: the KMS %s unwrapped it to %d bytes, not a %d-byte key",
			ErrKeyUnavailable, rec.ID, k.Name(), len(key), kmsKEKSize)
	}
	got, err := openWith(key, kekCheckAAD(rec.ID), rec.CheckValue)
	if err != nil {
		zero(key)
		// A KMS that answered with a key that fails the check holds another
		// key under the same ciphertext's name — or is not the KMS this key
		// was wrapped by. Either way this root does not open it.
		return nil, fmt.Errorf("%w: sealing key %s: what the KMS %s unwrapped fails the key's check value",
			ErrKeyUnavailable, rec.ID, k.Name())
	}
	defer zero(got)
	if subtle.ConstantTimeCompare(got, []byte(kekCheckPlaintext)) != 1 {
		zero(key)
		return nil, fmt.Errorf("%w: sealing key %s failed its check value", ErrSealFailed, rec.ID)
	}
	return key, nil
}

// kmsOpenable checks what a KMS-held record must carry before a KMS is asked
// about it.
func kmsOpenable(rec KEKRecord) error {
	if rec.Wrap != WrapKMS {
		return fmt.Errorf("%w: sealing key %s is not held by a KMS", ErrKeyUnavailable, rec.ID)
	}
	if len(rec.KMSCiphertext) == 0 {
		return fmt.Errorf("%w: sealing key %s is held by a KMS and has no ciphertext", ErrSealFailed, rec.ID)
	}
	if len(rec.CheckValue) == 0 {
		// The same rule a derived key is held to (derivable): without a check
		// value nothing proves what a KMS unwrapped is this key.
		return fmt.Errorf("%w: sealing key %s has no check value", ErrSealFailed, rec.ID)
	}
	return nil
}

// kmsMint makes a new KEK held by k: random, wrapped by the KMS, and proven to
// unwrap again before anything is recorded — a KMS identity allowed to encrypt
// and not to decrypt would otherwise mint a primary nobody can open, and every
// secret sealed under it would be lost. The record carries a decoy salt (see
// the file comment). The caller persists it.
func kmsMint(ctx context.Context, k KMS, id, actor string, now time.Time) (KEKRecord, []byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, kmsCallTimeout)
		defer cancel()
	}
	key := make([]byte, kmsKEKSize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return KEKRecord{}, nil, fmt.Errorf("secretbroker: generate a key-encryption key: %w", err)
	}
	fail := func(err error) (KEKRecord, []byte, error) {
		zero(key)
		return KEKRecord{}, nil, err
	}
	wrapped, err := k.Encrypt(ctx, key)
	if err != nil {
		return fail(kmsCallErr(k, "wrap a new sealing key", err))
	}
	if len(wrapped.Ciphertext) == 0 {
		return fail(fmt.Errorf("%w: the KMS %s returned no ciphertext for a new sealing key", ErrSealFailed, k.Name()))
	}
	back, err := k.Decrypt(ctx, wrapped)
	if err != nil {
		return fail(fmt.Errorf("%w: the KMS %s wrapped a new sealing key and would not unwrap it again (%v) — "+
			"its identity needs decrypt as well as encrypt; nothing was recorded", ErrSealFailed, k.Name(), kmsErrText(err)))
	}
	same := subtle.ConstantTimeCompare(back, key) == 1
	zero(back)
	if !same {
		return fail(fmt.Errorf("%w: the KMS %s unwrapped a new sealing key to something else; nothing was recorded",
			ErrSealFailed, k.Name()))
	}
	decoy := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, decoy); err != nil {
		return fail(fmt.Errorf("secretbroker: generate key salt: %w", err))
	}
	check, err := sealWith(key, kekCheckAAD(id), []byte(kekCheckPlaintext))
	if err != nil {
		return fail(err)
	}
	return KEKRecord{
		ID:             id,
		Salt:           encodeHex(decoy),
		State:          KEKStateActive,
		CheckValue:     check,
		CreatedAt:      now,
		CreatedBy:      actor,
		Root:           k.Name(),
		Wrap:           WrapKMS,
		KMSKeyID:       wrapped.KeyID,
		KMSCiphertext:  wrapped.Ciphertext,
		KMSAnnotations: copyAnnotations(wrapped.Annotations),
	}, key, nil
}

// kmsCallErr wraps a failed KMS call, keeping ErrKMSUnavailable when the KMS
// could not be reached.
func kmsCallErr(k KMS, what string, err error) error {
	if errors.Is(err, ErrKMSUnavailable) {
		return fmt.Errorf("%w: %s: %v", ErrKMSUnavailable, what, kmsErrText(err))
	}
	return fmt.Errorf("%w: the KMS %s could not %s: %v", ErrSealFailed, k.Name(), what, kmsErrText(err))
}

// kmsErrText is a KMS error as a message part, without the sentinel prefixes
// the wrapping already says.
func kmsErrText(err error) string {
	s := err.Error()
	for _, p := range []string{ErrKMSUnavailable.Error() + ": ", ErrKeyUnavailable.Error() + ": "} {
		s = strings.TrimPrefix(s, p)
	}
	return RedactString(s)
}

func copyAnnotations(m map[string][]byte) map[string][]byte {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string][]byte, len(m))
	for k, v := range m {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Rewrapping onto the KMS's current key
// ---------------------------------------------------------------------------

// KEKRewrapper is the optional part of a KeyStore that replaces a KMS-held
// key's wrapping in place (RewrapKMS). A store without it cannot follow a KMS
// key's rotation, and RewrapKMS says so.
type KEKRewrapper interface {
	// RewrapKEK replaces the KMS fields and root of the key id if, and only
	// if, the record still holds the ciphertext expect — a compare-and-swap,
	// so two members rewrapping at once cannot leave a ciphertext neither
	// verified. It reports whether the swap happened.
	RewrapKEK(id string, expect []byte, next KEKRecord) (bool, error)
}

// KMSRewrap is one key RewrapKMS moved, or tried to.
type KMSRewrap struct {
	ID      string `json:"id"`
	FromKey string `json:"from_kms_key"`
	ToKey   string `json:"to_kms_key,omitempty"`
	// Skipped: another process changed the record first.
	Skipped bool   `json:"skipped,omitempty"`
	Error   string `json:"error,omitempty"`
}

// KMSRewrapReport is the outcome of RewrapKMS.
type KMSRewrapReport struct {
	// KMS is the current root's name; CurrentKey the key it reported.
	KMS        string      `json:"kms"`
	CurrentKey string      `json:"current_kms_key"`
	Keys       []KMSRewrap `json:"keys,omitempty"`
	// Rewrapped counts the keys moved; Failed those that could not be.
	Rewrapped int `json:"rewrapped"`
	Failed    int `json:"failed"`
}

// StaleKMSKeys returns the live keys the current KMS root opens whose recorded
// KMS key is not current, given the KMS's current key — what RewrapKMS would
// move. Every live key is opened first, so the answer does not depend on which
// have been read.
func (k *Keyring) StaleKMSKeys(current string) []string {
	if len(k.roots) == 0 || !k.roots[0].IsKMS() || current == "" {
		return nil
	}
	var out []string
	for _, id := range k.liveIDs() {
		if key, _, _ := k.lookup(id); key == nil {
			continue
		}
		k.mu.RLock()
		rec, idx := k.records[id], k.rootOf[id]
		k.mu.RUnlock()
		if idx == 0 && rec.Wrap == WrapKMS && rec.KMSKeyID != current {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// KMSHeldKeys counts the live keys the current KMS root holds: none before a
// move onto it has minted one.
func (k *Keyring) KMSHeldKeys() int {
	if len(k.roots) == 0 || !k.roots[0].IsKMS() {
		return 0
	}
	name := k.roots[0].KMS.Name()
	k.mu.RLock()
	defer k.mu.RUnlock()
	n := 0
	for _, rec := range k.records {
		if !rec.Retired() && rec.Wrap == WrapKMS && rec.Root == name {
			n++
		}
	}
	return n
}

// RewrapKMS follows a rotation of the KMS key: every live key the current KMS
// root opens whose recorded KMS key id differs from the one the KMS now
// encrypts under is wrapped again — the key itself, held in memory, encrypted
// once more, proven to unwrap, and swapped into its record under
// compare-and-swap. Nothing sealed under the key changes, so this touches one
// row per key, not one per secret; afterwards the KMS's old key version holds
// nothing of this hub's and can be disabled.
//
// Safe to run on every member at once: a swap that loses the race is counted
// as skipped and the winner's ciphertext stands, verified by the winner.
func (k *Keyring) RewrapKMS(ctx context.Context) (KMSRewrapReport, error) {
	var rep KMSRewrapReport
	if len(k.roots) == 0 || !k.roots[0].IsKMS() {
		return rep, fmt.Errorf("%w: the current root is not a KMS; there is no KMS key to follow", ErrInvalidSecret)
	}
	kms := k.roots[0].KMS
	rep.KMS = kms.Name()
	reporter, ok := kms.(KMSKeyReporter)
	if !ok {
		return rep, fmt.Errorf("%w: the KMS %s does not report its current key", ErrInvalidSecret, kms.Name())
	}
	rw, ok := k.store.(KEKRewrapper)
	if !ok {
		return rep, fmt.Errorf("%w: this key store cannot rewrap a key in place", ErrInvalidSecret)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, err := reporter.CurrentKeyID(ctx)
	if err != nil {
		return rep, kmsCallErr(kms, "report its current key", err)
	}
	if current == "" {
		return rep, fmt.Errorf("%w: the KMS %s reported no current key", ErrSealFailed, kms.Name())
	}
	rep.CurrentKey = current
	if err := k.Reload(); err != nil {
		return rep, err
	}
	var firstErr error
	for _, id := range k.StaleKMSKeys(current) {
		key, rec, _ := k.lookup(id)
		r := KMSRewrap{ID: id, FromKey: rec.KMSKeyID}
		if key == nil {
			continue
		}
		next, err := k.rewrapOne(ctx, kms, rec, key)
		switch {
		case err != nil:
			r.Error = err.Error()
			rep.Failed++
			if firstErr == nil {
				firstErr = err
			}
		default:
			swapped, serr := rw.RewrapKEK(id, rec.KMSCiphertext, next)
			switch {
			case serr != nil:
				r.Error = serr.Error()
				rep.Failed++
				if firstErr == nil {
					firstErr = serr
				}
			case !swapped:
				r.Skipped = true
			default:
				r.ToKey = next.KMSKeyID
				rep.Rewrapped++
				k.mu.Lock()
				k.records[id] = next
				k.mu.Unlock()
				rememberKEK(k.roots[0], next, key)
			}
		}
		rep.Keys = append(rep.Keys, r)
	}
	if firstErr != nil {
		return rep, fmt.Errorf("%w: %d key(s) could not be rewrapped onto the KMS key %s: %v", ErrRotationFailed,
			rep.Failed, current, firstErr)
	}
	return rep, nil
}

// rewrapOne wraps key again under the KMS's current key and proves the result
// unwraps to it. It returns the record as it should be stored.
func (k *Keyring) rewrapOne(ctx context.Context, kms KMS, rec KEKRecord, key []byte) (KEKRecord, error) {
	cctx, cancel := context.WithTimeout(ctx, kmsCallTimeout)
	defer cancel()
	wrapped, err := kms.Encrypt(cctx, key)
	if err != nil {
		return KEKRecord{}, kmsCallErr(kms, "rewrap sealing key "+rec.ID, err)
	}
	if len(wrapped.Ciphertext) == 0 {
		return KEKRecord{}, fmt.Errorf("%w: the KMS %s returned no ciphertext rewrapping %s", ErrSealFailed, kms.Name(), rec.ID)
	}
	back, err := kms.Decrypt(cctx, wrapped)
	if err != nil {
		return KEKRecord{}, fmt.Errorf("%w: the KMS %s rewrapped %s and would not unwrap it again: %v", ErrSealFailed,
			kms.Name(), rec.ID, kmsErrText(err))
	}
	same := subtle.ConstantTimeCompare(back, key) == 1
	zero(back)
	if !same {
		return KEKRecord{}, fmt.Errorf("%w: the KMS %s rewrapped %s to something that unwraps to another key",
			ErrSealFailed, kms.Name(), rec.ID)
	}
	next := rec
	next.Root = kms.Name()
	next.KMSKeyID = wrapped.KeyID
	next.KMSCiphertext = wrapped.Ciphertext
	next.KMSAnnotations = copyAnnotations(wrapped.Annotations)
	return next, nil
}
