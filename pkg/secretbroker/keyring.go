package secretbroker

// Envelope encryption and the key registry it needs (Task 20181).
//
// The construction this replaces sealed every payload directly under one key
// derived from CLOOP_SECRET_KEY. That is fine cryptographically and fatal
// operationally: the key is welded to the ciphertext, so rotating it means
// re-encrypting every payload, which means holding every plaintext, which the
// old code could only do by asking an operator to re-mint each credential at
// its source. The runbook said as much, in a box, as a caveat.
//
// Here a payload is sealed under a per-row DEK, and only the DEK is sealed
// under the passphrase-derived KEK. Rotation touches 60 bytes per row and
// never touches a payload, so it can run online against a serving hub. The
// two layers have different jobs and different lifetimes, which is the whole
// idea:
//
//	DEK   random per row, never reused, never persisted in plaintext, never
//	      leaves this file's stack frames.
//	KEK   derived from the passphrase and a per-KEK salt, identified by an ID
//	      stored next to every ciphertext, and rotatable because nothing but
//	      DEKs is sealed under it.
//
// Several KEKs may be openable at once. That is not an accident of the schema
// — it is the property that makes rotation online rather than a maintenance
// window: rows move to the new KEK one at a time while reads keep succeeding
// against whichever KEK each row still names.
//
// # Associated data
//
// Both layers bind their ciphertext to the row it belongs to, via GCM
// associated data. Without it, an attacker with write access to the database
// (a compromised backup restore, a replica with the wrong permissions) could
// move a (wrapped_dek, payload) pair from one row to another: replace the
// wrapped DEK and ciphertext of "prod-deploy-pat" with those of a secret they
// minted themselves, and the broker would happily unseal it, validate it, and
// hand their token to every workload holding a grant on the production name.
// Every check upstream passes, because the substitution happened underneath
// them. Binding the wrap to (purpose, key ID, row ID) and the payload to
// (purpose, row ID) turns that into an authentication failure.
//
// The payload's AAD deliberately excludes the key ID. If it did not, rotation
// would have to re-encrypt payloads, and the cheapness of rewrapping is the
// reason online rotation is possible at all.

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// LegacyKeyID names material sealed by the pre-envelope construction:
	// ciphertext directly under the passphrase-derived key, with no wrapped
	// DEK. Migration 0019 stamps it onto every pre-existing row so "sealed
	// the old way" is an explicit state rather than an inference from an
	// empty column.
	LegacyKeyID = "legacy"

	// KEK lifecycle states. Exactly one KEK is primary (new material is
	// sealed under it); any number may be active (openable, still referenced
	// by rows); retired KEKs have had their salt destroyed and can no longer
	// be derived at all.
	KEKStatePrimary = "primary"
	KEKStateActive  = "active"
	KEKStateRetired = "retired"

	// dekSize is the per-row data-encryption key length (AES-256).
	dekSize = 32

	// kekCheckPlaintext is sealed under each KEK at creation and re-opened at
	// load. It answers "does the passphrase in this process's environment
	// derive this KEK?" without decrypting a single credential, so
	// `cloop hub key list` can report openability up front instead of an
	// operator discovering it one failed lease at a time.
	//
	// It is not a passphrase oracle an attacker did not already have: any
	// wrapped DEK in the database serves the same purpose, since GCM
	// authenticates. The check value only saves cloop from having to read a
	// secret in order to answer a question about a key.
	kekCheckPlaintext = "cloop-kek-check-v1"

	// AAD domain separators. Distinct prefixes stop a wrapped DEK from ever
	// being accepted where a payload is expected, and vice versa, and stop the
	// key check value from being accepted as either.
	aadDEKPrefix     = "cloop-dek-v1"
	aadPayloadPrefix = "cloop-payload-v1"
	aadCheckPrefix   = "cloop-kek-check-v1"
)

// Sealed-set names. They are part of every envelope's associated data, so they
// are a wire format: changing one makes existing rows in that set unopenable.
//
// Namespacing by set is not cosmetic. Without it, an attacker with database
// write access could copy a secret's (wrapped_dek, payload) into a sessions row
// whose id equals that secret's id, and the hub would authenticate it happily
// and then POST the kubeconfig to the identity provider as if it were a refresh
// token — an exfiltration channel out of the sealed store to an external host.
// Row ids alone cannot prevent that, because they are chosen by whoever writes
// the row.
const (
	SetSecrets  = "secrets"
	SetSessions = "sessions"
)

// AADFor builds the associated data for one row of one sealed set. Every seal,
// open, and rewrap of that row must use the identical value.
func AADFor(set, rowID string) string { return set + "\x00" + rowID }

// KEKRecord is one key-encryption key as stored. It never contains key
// material: `Salt` plus the passphrase derives the key, and the salt alone is
// useless.
type KEKRecord struct {
	ID    string
	Salt  string // hex-encoded KDF salt; emptied on retirement
	State string // primary | active | retired
	// CheckValue is kekCheckPlaintext sealed under this KEK.
	CheckValue []byte
	CreatedAt  time.Time
	CreatedBy  string
	RetiredAt  time.Time
}

// Retired reports whether the KEK has been shredded.
func (k KEKRecord) Retired() bool { return k.State == KEKStateRetired || k.Salt == "" }

// KeyStore is the persistence a Keyring needs on top of the broker's Store.
//
// It is separate from Store on purpose. Store has several in-memory
// implementations in tests whose value is that they are twenty lines long;
// folding key management into it would force every one of them to grow a KEK
// registry to keep compiling, for no gain. A store that implements both gets
// envelope encryption and rotation; a store that implements only Store keeps
// the single-key behaviour, which is exactly right for a test double.
type KeyStore interface {
	// PutKEK inserts or replaces a KEK record.
	PutKEK(k KEKRecord) error
	// ListKEKs returns every KEK, including retired ones — retired rows are
	// kept so `cloop hub key list` can still explain what a row referencing
	// a dead key is referencing.
	ListKEKs() ([]KEKRecord, error)
	// PrimaryKEK returns the current primary, if there is one. It exists
	// separately from ListKEKs because it is on the seal path: every seal
	// re-reads it, so it must be a single indexed lookup rather than a scan.
	PrimaryKEK() (KEKRecord, bool, error)
	// PromoteKEK makes id the sole primary, demoting any incumbent, in one
	// transaction. Atomicity matters: two hubs promoting concurrently must
	// not both succeed and leave rows sealed under a key neither considers
	// current.
	PromoteKEK(id string, at time.Time) error
	// RetireKEK marks a KEK retired and destroys its salt. It must refuse
	// while any sealed row still references the key.
	RetireKEK(id string, at time.Time) error
}

// Keyring holds every derivable KEK and performs envelope seal/open.
//
// Safe for concurrent use: leases and session reads both go through it from
// many goroutines, and a rotation mutates the primary underneath them.
type Keyring struct {
	mu sync.RWMutex

	store KeyStore
	// keks maps key ID to derived key material for every KEK the current
	// passphrase can actually open. A KEK whose check value fails is
	// recorded in `records` but absent here, so reads against it fail with a
	// specific error instead of a GCM tag mismatch.
	keks    map[string][]byte
	records map[string]KEKRecord
	primary string

	// legacy opens pre-envelope rows. Nil on a hub that never had any.
	legacy *Cipher

	// passphrase is remembered only when supplied explicitly, so a keyring
	// built with WithKeyringPassphrase can still mint keys without the
	// process environment. Empty means "read CLOOP_SECRET_KEY at use time".
	passphrase string

	// lastReload throttles the self-healing registry re-read on the
	// unknown-key path. Without it, a genuinely unknown key id — a row from
	// another hub's database, say — would turn every read of that row into a
	// registry query, which is a cheap way to make a corrupt row look like a
	// database performance problem.
	lastReload time.Time

	clock func() time.Time
}

// reloadInterval bounds how often an unknown key id triggers a registry
// re-read.
const reloadInterval = time.Second

// KeyringOption configures a Keyring.
type KeyringOption func(*keyringConfig)

type keyringConfig struct {
	passphrase string
	clock      func() time.Time
	actor      string
	create     bool
}

// WithKeyringPassphrase overrides CLOOP_SECRET_KEY. Tests use it; so does any
// caller that sources the passphrase from somewhere other than the process
// environment.
func WithKeyringPassphrase(p string) KeyringOption {
	return func(c *keyringConfig) { c.passphrase = p }
}

// WithKeyringClock overrides the time source.
func WithKeyringClock(fn func() time.Time) KeyringOption {
	return func(c *keyringConfig) {
		if fn != nil {
			c.clock = fn
		}
	}
}

// WithKeyringActor records who caused a KEK to be created.
func WithKeyringActor(a string) KeyringOption {
	return func(c *keyringConfig) { c.actor = a }
}

// WithoutKeyCreation opens the keyring read-only with respect to the
// registry: if no primary KEK exists, OpenKeyring fails rather than minting
// one.
//
// Read-only diagnostics (`cloop hub key list` against someone else's hub, a
// health check) should not have the side effect of creating key material, and
// a diagnostic that silently mints a KEK would report a healthy registry it
// had just fabricated.
func WithoutKeyCreation() KeyringOption {
	return func(c *keyringConfig) { c.create = false }
}

// OpenKeyring loads the KEK registry, derives every KEK the passphrase can
// open, and ensures a primary exists.
//
// Derivation is deliberately eager. It costs ~60ms per KEK at 200 000 KDF
// rounds, once, at startup — versus paying it on the first lease of the day,
// inside somebody's run, per key. Eager also means an unusable passphrase is
// a startup failure rather than an intermittent one.
func OpenKeyring(store KeyStore, opts ...KeyringOption) (*Keyring, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: nil key store", ErrInvalidSecret)
	}
	cfg := keyringConfig{clock: time.Now, create: true}
	cfg.passphrase = os.Getenv(EnvPassphraseKey)
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.passphrase == "" {
		return nil, fmt.Errorf("%w: set it to seal and open secret payloads", ErrNoKey)
	}

	kr := &Keyring{
		store:      store,
		keks:       make(map[string][]byte),
		records:    make(map[string]KEKRecord),
		passphrase: cfg.passphrase,
		clock:      cfg.clock,
	}

	// The legacy cipher is loaded, never created. A hub that has never sealed
	// anything the old way has no legacy salt, and inventing one would leave
	// a second live key in the registry that nothing seals under and nobody
	// rotates.
	if meta, ok := store.(metaStore); ok {
		if c, err := loadLegacyCipher(meta, cfg.passphrase); err == nil {
			kr.legacy = c
		}
	}

	records, err := store.ListKEKs()
	if err != nil {
		return nil, fmt.Errorf("secretbroker: list sealing keys: %w", err)
	}
	// Deriving the primary is enough to answer "is this passphrase right?",
	// because every KEK is stretched from the same passphrase. So the primary
	// is derived eagerly and the rest lazily, on the first read that names
	// them. The difference is not academic: a hub that has rotated ten times
	// without retiring would otherwise pay ten KDF passes on every construction
	// of a broker, and pkg/ui builds one per request.
	for _, rec := range records {
		kr.records[rec.ID] = rec
	}
	for _, rec := range records {
		if rec.Retired() || rec.State != KEKStatePrimary {
			continue
		}
		if key, derr := deriveKEK(cfg.passphrase, rec); derr == nil {
			kr.keks[rec.ID] = key
			kr.primary = rec.ID
		}
		break
	}
	if kr.primary != "" {
		return kr, nil
	}

	// No usable primary. Now the whole registry has to be derived, because the
	// decision below depends on whether *any* live key resists this passphrase.
	var undecipherable []string
	for _, rec := range records {
		if rec.Retired() {
			continue
		}
		key, derr := deriveKEK(cfg.passphrase, rec)
		if derr != nil {
			// Recorded, live, and not derivable from this passphrase. Keep the
			// record so reads can name the key precisely, and remember it: the
			// bootstrap rule below turns on whether any such key exists.
			undecipherable = append(undecipherable, rec.ID)
			continue
		}
		kr.keks[rec.ID] = key
	}

	// Everything below is the "no usable primary" path, and getting its rule
	// wrong is worse than any bug in the cryptography.
	//
	// The naive rule — "no usable primary, so mint one" — is a trap. Start a
	// hub with a typo in CLOOP_SECRET_KEY and it would mint a *second*
	// registry, demote the real primary, and report itself healthy; new
	// secrets would be sealed under a key the operator does not know exists,
	// and `cloop hub key list` would show two primaries. The failure would be
	// discovered later, by a lease against the original key failing, long
	// after the fork.
	//
	// So minting is permitted only when there is genuinely nothing to fork
	// from. A live key that cannot be derived means the passphrase is wrong,
	// and the only safe response is to refuse to start.
	switch {
	case len(undecipherable) > 0:
		sort.Strings(undecipherable)
		return nil, fmt.Errorf("%w: %d live sealing key(s) (%s) cannot be derived from the current %s; "+
			"refusing to mint a new key, which would fork the registry and leave existing secrets unreadable",
			ErrKeyUnavailable, len(undecipherable), strings.Join(undecipherable, ", "), EnvPassphraseKey)

	case !cfg.create:
		// A read-only caller. Not an error, and — importantly — not a write
		// either: `cloop hub key list` on a fresh or half-repaired registry
		// must report what it finds, not promote a key and then report the
		// registry it has just modified. A keyring with no primary refuses to
		// seal, so nothing downstream mistakes this for a live one.
		return kr, nil

	case len(kr.keks) > 0:
		// Usable keys exist but none is flagged primary — a hand-edited or
		// partially restored registry. Promoting the newest usable key repairs
		// it without creating key material, which is strictly safer than
		// minting: nothing new to keep track of, and no row is orphaned.
		newest := newestKeyID(kr.records, kr.keks)
		if err := store.PromoteKEK(newest, kr.now()); err != nil {
			return nil, fmt.Errorf("secretbroker: adopt sealing key %s as primary: %w", newest, err)
		}
		kr.markPrimary(newest)
		return kr, nil

	default:
		rec, key, cerr := kr.mintKEK(cfg.passphrase, cfg.actor)
		if cerr != nil {
			return nil, cerr
		}
		kr.records[rec.ID] = rec
		kr.keks[rec.ID] = key
		kr.markPrimary(rec.ID)
		return kr, nil
	}
}

// markPrimary points the keyring at id and demotes the incumbent in the
// in-memory records, so Keys() cannot report two primaries after a promotion.
func (k *Keyring) markPrimary(id string) {
	if prev, ok := k.records[k.primary]; ok && prev.ID != id && prev.State == KEKStatePrimary {
		prev.State = KEKStateActive
		k.records[prev.ID] = prev
	}
	if rec, ok := k.records[id]; ok {
		rec.State = KEKStatePrimary
		k.records[id] = rec
	}
	k.primary = id
}

// newestKeyID picks the most recently created derivable key, breaking ties by
// ID so the choice is deterministic across hubs adopting the same registry.
func newestKeyID(records map[string]KEKRecord, usable map[string][]byte) string {
	best := ""
	for id := range usable {
		rec := records[id]
		cur, ok := records[best]
		if !ok || rec.CreatedAt.After(cur.CreatedAt) ||
			(rec.CreatedAt.Equal(cur.CreatedAt) && id < best) {
			best = id
		}
	}
	return best
}

// metaStore is the slice of Store the legacy cipher needs. Declared here so
// KeyStore implementations that are not full Stores still work.
type metaStore interface {
	Meta(key string) (string, bool, error)
}

// mintKEK creates, seals a check value for, and persists a new KEK, then
// promotes it to primary.
func (k *Keyring) mintKEK(passphrase, actor string) (KEKRecord, []byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return KEKRecord{}, nil, fmt.Errorf("secretbroker: generate key salt: %w", err)
	}
	id, err := newID(kekIDPrefix)
	if err != nil {
		return KEKRecord{}, nil, err
	}
	key := deriveKey(passphrase, salt)

	check, err := sealWith(key, kekCheckAAD(id), []byte(kekCheckPlaintext))
	if err != nil {
		return KEKRecord{}, nil, err
	}
	rec := KEKRecord{
		ID:         id,
		Salt:       encodeHex(salt),
		State:      KEKStateActive,
		CheckValue: check,
		CreatedAt:  k.now(),
		CreatedBy:  actor,
	}
	if err := k.store.PutKEK(rec); err != nil {
		return KEKRecord{}, nil, fmt.Errorf("secretbroker: persist sealing key: %w", err)
	}
	if err := k.store.PromoteKEK(rec.ID, k.now()); err != nil {
		return KEKRecord{}, nil, fmt.Errorf("secretbroker: promote sealing key: %w", err)
	}
	rec.State = KEKStatePrimary
	return rec, key, nil
}

const kekIDPrefix = "kek"

func (k *Keyring) now() time.Time { return k.clock().UTC() }

// PrimaryID returns the key ID new material is sealed under.
func (k *Keyring) PrimaryID() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.primary
}

// KeyInfo is a KEK as reported to an operator. It carries no key material and
// is safe to render in a CLI table or an API response.
type KeyInfo struct {
	ID        string    `json:"id"`
	State     string    `json:"state"`
	Primary   bool      `json:"primary"`
	Openable  bool      `json:"openable"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
	RetiredAt time.Time `json:"retired_at,omitempty"`
}

// Keys returns every known KEK, primary first, then newest.
func (k *Keyring) Keys() []KeyInfo {
	k.mu.RLock()
	ids := make([]string, 0, len(k.records))
	for id := range k.records {
		ids = append(ids, id)
	}
	primary := k.primary
	k.mu.RUnlock()

	out := make([]KeyInfo, 0, len(ids))
	for _, id := range ids {
		rec := k.records[id]
		// Force derivation rather than reporting the cache: with lazy
		// derivation, "openable" would otherwise mean "happens to have been
		// read already", which is the opposite of the question an operator is
		// asking before they retire something.
		key, _, _ := k.lookup(id)
		out = append(out, KeyInfo{
			ID:        id,
			State:     rec.State,
			Primary:   id == primary,
			Openable:  key != nil,
			CreatedAt: rec.CreatedAt,
			CreatedBy: rec.CreatedBy,
			RetiredAt: rec.RetiredAt,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Primary != out[j].Primary {
			return out[i].Primary
		}
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// HasLegacy reports whether pre-envelope material can still be opened on this
// hub. False with legacy rows present means those rows are unreadable, which
// `cloop hub key status` reports rather than leaving to be discovered.
func (k *Keyring) HasLegacy() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.legacy != nil
}

// ---------------------------------------------------------------------------
// Seal / Open
// ---------------------------------------------------------------------------

// currentPrimary re-reads the registry's primary and adopts it if this process
// has fallen behind.
//
// Every seal goes through here, and that is deliberate rather than
// conservative. A hub process caches its primary at startup; a `cloop hub key
// rotate` run in a shell promotes a new one. Without this read, the serving hub
// would keep sealing new material under the *old* key — so a rotation could
// never reach zero unrotated rows while the hub ran, and worse, an operator who
// then retired the old key (the database says nothing references it, because
// rotation moved everything) would have the hub write a fresh credential under
// a key whose salt had just been destroyed. That credential would be
// unrecoverable, with no error anywhere.
//
// One indexed SELECT per seal is a small price for closing that. Seals are
// operator actions and session writes, not a hot path.
//
// It fails closed: a registry that cannot be read means we cannot prove the
// cached primary is still current, and sealing under an unverified key is
// exactly the failure above.
func (k *Keyring) currentPrimary() (string, []byte, error) {
	rec, ok, err := k.store.PrimaryKEK()
	if err != nil {
		return "", nil, fmt.Errorf("%w: cannot confirm the current sealing key: %v", ErrSealFailed, err)
	}
	if !ok || rec.Retired() {
		return "", nil, fmt.Errorf("%w: no usable primary sealing key", ErrSealFailed)
	}

	k.mu.RLock()
	cached := k.keks[rec.ID]
	k.mu.RUnlock()
	if cached != nil {
		if k.PrimaryID() != rec.ID {
			k.mu.Lock()
			k.records[rec.ID] = rec
			k.markPrimary(rec.ID)
			k.mu.Unlock()
		}
		return rec.ID, cached, nil
	}

	// A key minted by another process. Deriving it costs one KDF pass, once.
	pass := k.effectivePassphrase()
	if pass == "" {
		return "", nil, fmt.Errorf("%w: cannot derive the current sealing key", ErrNoKey)
	}
	key, derr := deriveKEK(pass, rec)
	if derr != nil {
		return "", nil, derr
	}
	k.mu.Lock()
	k.records[rec.ID] = rec
	k.keks[rec.ID] = key
	k.markPrimary(rec.ID)
	k.mu.Unlock()
	return rec.ID, key, nil
}

func (k *Keyring) effectivePassphrase() string {
	k.mu.RLock()
	pass := k.passphrase
	k.mu.RUnlock()
	if pass == "" {
		pass = os.Getenv(EnvPassphraseKey)
	}
	return pass
}

// SealFor seals plaintext under a fresh DEK wrapped by the primary KEK.
//
// aad identifies the row this envelope belongs to — build it with AADFor so it
// carries the sealed set as well as the row id. The identical value must be
// supplied to OpenEnvelope; a mismatch is an authentication failure, which is
// how a row-swap attack surfaces.
func (k *Keyring) SealFor(aad string, plaintext []byte) (Envelope, error) {
	primary, kek, err := k.currentPrimary()
	if err != nil {
		return Envelope{}, err
	}

	dek := make([]byte, dekSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return Envelope{}, fmt.Errorf("secretbroker: generate data key: %w", err)
	}
	// The DEK exists only for the length of this function. Nothing writes it
	// anywhere, and it is wiped before returning even on the error paths.
	defer zero(dek)

	wrapped, err := sealWith(kek, dekAAD(primary, aad), dek)
	if err != nil {
		return Envelope{}, err
	}
	ct, err := sealWith(dek, payloadAAD(aad), plaintext)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{KeyID: primary, WrappedDEK: wrapped, Ciphertext: ct}, nil
}

// OpenEnvelope unwraps the DEK and decrypts the payload.
//
// The error cases are deliberately distinguishable, because they call for
// completely different operator responses: a retired key means the material
// is gone and the credential must be re-minted; an underivable key means the
// passphrase is wrong and the material is probably fine; a tag failure means
// tampering or corruption. Collapsing all three into "decryption failed"
// turns a five-minute diagnosis into an afternoon.
func (k *Keyring) OpenEnvelope(aad string, env Envelope) ([]byte, error) {
	if env.IsLegacy() {
		k.mu.RLock()
		legacy := k.legacy
		k.mu.RUnlock()
		if legacy == nil {
			return nil, fmt.Errorf("%w: no legacy sealing key on this hub", ErrKeyUnavailable)
		}
		return legacy.Unseal(env.Ciphertext)
	}

	kek, rec, known := k.lookup(env.KeyID)
	if kek == nil && !known {
		// Another process may have minted this key since we loaded — a
		// `cloop hub key rotate` run against a hub that is still serving is
		// exactly that. Re-reading the registry here is what keeps a rotation
		// from silently breaking reads in every long-lived process until it
		// restarts.
		if k.reloadThrottled() {
			kek, rec, known = k.lookup(env.KeyID)
		}
	}

	if kek == nil {
		switch {
		case known && rec.Retired():
			return nil, fmt.Errorf("%w: sealing key %s was retired at %s; this material cannot be recovered",
				ErrKeyRetired, env.KeyID, formatOrUnknown(rec.RetiredAt))
		case known:
			return nil, fmt.Errorf("%w: sealing key %s exists but cannot be derived from the current %s",
				ErrKeyUnavailable, env.KeyID, EnvPassphraseKey)
		default:
			return nil, fmt.Errorf("%w: no sealing key %s in this hub's registry", ErrKeyUnknown, env.KeyID)
		}
	}

	dek, err := openWith(kek, dekAAD(env.KeyID, aad), env.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("%w: unwrap data key for %s", ErrSealFailed, SafeRef(aad))
	}
	defer zero(dek)

	return openWith(dek, payloadAAD(aad), env.Ciphertext)
}

// Rewrap moves an envelope onto the primary KEK without decrypting its
// payload.
//
// This is the operation rotation is made of, and the reason it is cheap: the
// payload ciphertext is returned byte-identical, so a rotation over a hundred
// megabytes of kubeconfigs still only encrypts a hundred DEKs. It also means
// a rotation never materialises a credential, so a rotation running on a
// serving hub does not widen the plaintext exposure window at all.
func (k *Keyring) Rewrap(aad string, env Envelope) (Envelope, error) {
	// Fresh, for the same reason SealFor is: a rewrap writes material under
	// the target key, and writing it under a key that is no longer primary
	// would leave a row a concurrent retirement believes is unreferenced.
	primary, target, err := k.currentPrimary()
	if err != nil {
		return Envelope{}, err
	}
	if env.KeyID == primary && len(env.WrappedDEK) > 0 {
		return env, nil
	}

	// A legacy row has no DEK to rewrap: its payload is sealed directly under
	// the old key, so the upgrade genuinely has to re-encrypt it. This is the
	// one place plaintext is handled during rotation, it happens once per row
	// in the history of the hub, and the buffer is wiped immediately.
	if env.IsLegacy() {
		plain, err := k.OpenEnvelope(aad, env)
		if err != nil {
			return Envelope{}, err
		}
		defer zero(plain)
		return k.SealFor(aad, plain)
	}

	source, rec, known := k.lookup(env.KeyID)
	if source == nil && !known && k.reloadThrottled() {
		source, rec, known = k.lookup(env.KeyID)
	}
	if source == nil {
		if known && rec.Retired() {
			return Envelope{}, fmt.Errorf("%w: sealing key %s was retired", ErrKeyRetired, env.KeyID)
		}
		return Envelope{}, fmt.Errorf("%w: sealing key %s is not available", ErrKeyUnavailable, env.KeyID)
	}

	dek, err := openWith(source, dekAAD(env.KeyID, aad), env.WrappedDEK)
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: unwrap data key for %s", ErrSealFailed, SafeRef(aad))
	}
	defer zero(dek)

	wrapped, err := sealWith(target, dekAAD(primary, aad), dek)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{KeyID: primary, WrappedDEK: wrapped, Ciphertext: env.Ciphertext}, nil
}

// ---------------------------------------------------------------------------
// Registry mutation
// ---------------------------------------------------------------------------

// AddKey mints a new KEK, promotes it to primary, and returns it. Existing
// material stays readable under its old KEK — that overlap is what lets a
// rotation run while the hub serves traffic.
func (k *Keyring) AddKey(actor string) (KeyInfo, error) {
	k.mu.RLock()
	pass := k.passphrase
	k.mu.RUnlock()
	if pass == "" {
		pass = os.Getenv(EnvPassphraseKey)
	}
	if pass == "" {
		return KeyInfo{}, fmt.Errorf("%w: cannot derive a new sealing key", ErrNoKey)
	}

	rec, key, err := k.mintKEK(pass, actor)
	if err != nil {
		return KeyInfo{}, err
	}

	k.mu.Lock()
	k.records[rec.ID] = rec
	k.keks[rec.ID] = key
	k.markPrimary(rec.ID)
	k.mu.Unlock()

	return KeyInfo{
		ID: rec.ID, State: KEKStatePrimary, Primary: true, Openable: true,
		CreatedAt: rec.CreatedAt, CreatedBy: rec.CreatedBy,
	}, nil
}

// RetireKey destroys a KEK's salt, making it permanently underivable.
//
// The store refuses while any row still references the key, so this is safe
// to call optimistically; the refusal is the second step the design requires,
// and it is enforced in SQL rather than by a check here that a concurrent
// write could race past.
func (k *Keyring) RetireKey(id string) error {
	k.mu.RLock()
	primary := k.primary
	_, known := k.records[id]
	k.mu.RUnlock()

	if id == LegacyKeyID {
		return fmt.Errorf("%w: the legacy key is retired by rotating its rows away, not directly", ErrKeyInUse)
	}
	if !known {
		return fmt.Errorf("%w: no sealing key %s", ErrKeyUnknown, id)
	}
	if id == primary {
		return fmt.Errorf("%w: %s is the primary key; rotate onto a new key first", ErrKeyInUse, id)
	}
	at := k.now()
	if err := k.store.RetireKEK(id, at); err != nil {
		return err
	}

	k.mu.Lock()
	if key, ok := k.keks[id]; ok {
		zero(key)
		delete(k.keks, id)
	}
	if rec, ok := k.records[id]; ok {
		rec.State = KEKStateRetired
		rec.Salt = ""
		rec.RetiredAt = at
		k.records[id] = rec
	}
	k.mu.Unlock()
	return nil
}

// lookup returns the derived key, the record, and whether the id is known,
// deriving the key on first use.
//
// Lazy derivation is what keeps a hub that has rotated several times from
// paying a KDF pass per key on every keyring construction. It is safe because
// deriving verifies against the key check value: a key that does not belong to
// this passphrase comes back nil here exactly as it would have from an eager
// pass.
func (k *Keyring) lookup(id string) ([]byte, KEKRecord, bool) {
	k.mu.RLock()
	key, has := k.keks[id]
	rec, known := k.records[id]
	k.mu.RUnlock()
	if has || !known || rec.Retired() {
		return key, rec, known
	}

	pass := k.effectivePassphrase()
	if pass == "" {
		return nil, rec, known
	}
	derived, err := deriveKEK(pass, rec)
	if err != nil {
		return nil, rec, known
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	// Another goroutine may have derived it while we were not holding the
	// lock; keep the first one so callers holding a []byte keep a live slice.
	if existing, ok := k.keks[id]; ok {
		zero(derived)
		return existing, k.records[id], true
	}
	k.keks[id] = derived
	return derived, k.records[id], true
}

// reloadThrottled re-reads the registry at most once per reloadInterval and
// reports whether a read actually happened.
func (k *Keyring) reloadThrottled() bool {
	k.mu.Lock()
	now := k.clock().UTC()
	if !k.lastReload.IsZero() && now.Sub(k.lastReload) < reloadInterval {
		k.mu.Unlock()
		return false
	}
	k.lastReload = now
	pass := k.passphrase
	k.mu.Unlock()

	if pass == "" {
		pass = os.Getenv(EnvPassphraseKey)
	}
	if pass == "" {
		return false
	}
	return k.reload(pass) == nil
}

// Reload re-reads the KEK registry, adopting keys another process minted and
// dropping ones it retired.
//
// It never mints and never demotes to nothing: a registry that has become
// unreadable leaves the in-memory state exactly as it was, because a hub that
// is currently serving reads is better off with a stale key set than with an
// empty one.
func (k *Keyring) Reload() error {
	k.mu.RLock()
	pass := k.passphrase
	k.mu.RUnlock()
	if pass == "" {
		pass = os.Getenv(EnvPassphraseKey)
	}
	if pass == "" {
		return fmt.Errorf("%w: cannot re-derive sealing keys", ErrNoKey)
	}
	return k.reload(pass)
}

func (k *Keyring) reload(passphrase string) error {
	records, err := k.store.ListKEKs()
	if err != nil {
		return fmt.Errorf("secretbroker: reload sealing keys: %w", err)
	}

	// Derive outside the lock: each derivation is 200 000 SHA-256 rounds, and
	// holding the write lock across them would stall every concurrent read of
	// an already-known key for no reason.
	fresh := map[string][]byte{}
	for _, rec := range records {
		if rec.Retired() {
			continue
		}
		if key, _, ok := k.lookup(rec.ID); ok && key != nil {
			continue
		}
		if key, derr := deriveKEK(passphrase, rec); derr == nil {
			fresh[rec.ID] = key
		}
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	seen := make(map[string]bool, len(records))
	for _, rec := range records {
		seen[rec.ID] = true
		k.records[rec.ID] = rec
		if rec.Retired() {
			if old, ok := k.keks[rec.ID]; ok {
				zero(old)
				delete(k.keks, rec.ID)
			}
			continue
		}
		if key, ok := fresh[rec.ID]; ok {
			k.keks[rec.ID] = key
		}
		if rec.State == KEKStatePrimary && k.keks[rec.ID] != nil {
			k.primary = rec.ID
		}
	}
	// A record that vanished from the registry cannot be trusted to keep
	// opening rows: dropping it turns a deleted key into ErrKeyUnknown rather
	// than a read that succeeds against a key the operator believes is gone.
	for id := range k.records {
		if !seen[id] {
			if old, ok := k.keks[id]; ok {
				zero(old)
				delete(k.keks, id)
			}
			delete(k.records, id)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Derivation and primitives
// ---------------------------------------------------------------------------

// deriveKEK derives a KEK from the passphrase and verifies it against the
// record's check value.
//
// Verification is what separates "this key is not for this passphrase" from
// "this ciphertext is corrupt" at load time rather than at lease time.
func deriveKEK(passphrase string, rec KEKRecord) ([]byte, error) {
	salt, err := decodeHex(rec.Salt)
	if err != nil || len(salt) != saltSize {
		return nil, fmt.Errorf("%w: sealing key %s has a corrupt salt", ErrSealFailed, rec.ID)
	}
	if len(rec.CheckValue) == 0 {
		// A live KEK with no check value cannot be verified, and accepting it
		// would hand an attacker with database write access a way past the
		// "refuse to start on the wrong passphrase" rule: NULL every
		// check_value and every key becomes trivially "derivable", so the hub
		// boots on a garbage passphrase and seals new material under a key
		// nothing can open. mintKEK always writes one, so an absent one is a
		// tampered or corrupt row either way.
		return nil, fmt.Errorf("%w: sealing key %s has no check value", ErrSealFailed, rec.ID)
	}
	key := deriveKey(passphrase, salt)
	got, err := openWith(key, kekCheckAAD(rec.ID), rec.CheckValue)
	if err != nil {
		zero(key)
		return nil, fmt.Errorf("%w: sealing key %s does not match the current %s",
			ErrKeyUnavailable, rec.ID, EnvPassphraseKey)
	}
	defer zero(got)
	if subtle.ConstantTimeCompare(got, []byte(kekCheckPlaintext)) != 1 {
		zero(key)
		return nil, fmt.Errorf("%w: sealing key %s failed its check value", ErrSealFailed, rec.ID)
	}
	return key, nil
}

// loadLegacyCipher builds the pre-envelope cipher if the store still holds
// the old salt. It never creates one.
func loadLegacyCipher(store metaStore, passphrase string) (*Cipher, error) {
	v, ok, err := store.Meta(metaKeySalt)
	if err != nil || !ok || v == "" {
		return nil, fmt.Errorf("%w: no legacy salt", ErrKeyUnknown)
	}
	salt, derr := decodeHex(v)
	if derr != nil || len(salt) != saltSize {
		return nil, fmt.Errorf("%w: legacy salt is corrupt", ErrSealFailed)
	}
	return &Cipher{key: deriveKey(passphrase, salt)}, nil
}

func dekAAD(keyID, aad string) []byte {
	return []byte(aadDEKPrefix + "\x00" + keyID + "\x00" + aad)
}

func payloadAAD(aad string) []byte {
	return []byte(aadPayloadPrefix + "\x00" + aad)
}

// kekCheckAAD has its own prefix rather than reusing the DEK prefix with a
// "check" component. With a shared prefix the separation would rest entirely on
// no key id ever being the literal string "check" — true today because ids come
// from newID, and not a property worth depending on.
func kekCheckAAD(keyID string) []byte {
	return []byte(aadCheckPrefix + "\x00" + keyID)
}

func formatOrUnknown(t time.Time) string {
	if t.IsZero() {
		return "an unrecorded time"
	}
	return t.UTC().Format(time.RFC3339)
}

// normaliseKeyID trims and lowercases a user-supplied key reference.
func normaliseKeyID(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
