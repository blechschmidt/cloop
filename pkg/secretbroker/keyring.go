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
//
// # Roots (Task 20425)
//
// Every KEK is derived from a root secret, CLOOP_SECRET_KEY, so rotating KEKs
// bounds the life of a key and not of the secret every key comes from. A
// keyring therefore holds up to two roots, resolved by pkg/rootkey: the
// current one, which mints and opens, and during a change of root the previous
// one, which only opens. Nothing is ever minted from the previous root, and no
// key of it is promoted while a key of the current one is there to choose.
//
// Changing the root is then online. Every member restarts with the new key as
// current and the old as previous; `cloop hub key rotate --retire-previous`
// mints a key from the new root, rewraps every sealed row onto it with the
// same compare-and-swap rotation always used, and retires every key of the old
// root. Until that step the registry's primary stays the key it was, so a
// member restarted with the new root and one not yet restarted seal under the
// same key and read each other's writes, and the change can be backed out by
// restarting with the old configuration. After it, a process holding only the
// old root refuses to start.
//
// The rule that refuses it is the one that stops a mistyped key forking the
// registry, generalised: every live KEK must derive from a configured root. A
// key that none derives means a key is wrong, or this process was not given
// the root new material is sealed under — and minting a fresh primary in
// either case would leave the existing secrets unreadable by whoever then
// starts with the right one.
//
// Which root derives a key is decided by deriving it: the check value says,
// and the root column of broker_keks only records the answer (by fingerprint,
// for `cloop hub key list` and the doctor). A key minted before the column
// existed is attributed once, by the first process whose root derives it.

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/rootkey"
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
	// SetHubTLS holds the private keys of the hub's own CA and of the
	// certificates it issues its credential monitors (pkg/hubca, Task 20409).
	SetHubTLS = "hub_tls"
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
	// Root is the fingerprint of the root secret the key derives from
	// (pkg/rootkey); "" for a key nobody has attributed yet. A record, not an
	// authority: which root opens a key is decided by deriving it.
	Root string
}

// Which configured root derives a key, as KeyInfo reports it.
const (
	RootCurrent  = "current"
	RootPrevious = "previous"
)

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

// KeyAttributor is the optional part of a KeyStore that records which root a
// key derives from (Task 20425). A store without it — the in-memory test
// doubles — still opens, mints and rotates; its old keys stay unattributed.
type KeyAttributor interface {
	// AttributeKEK records root for a key no one has attributed yet, and
	// reports whether it did. A recorded root is never rewritten.
	AttributeKEK(id, root string) (bool, error)
}

// Keyring holds every derivable KEK and performs envelope seal/open.
//
// Safe for concurrent use: leases and session reads both go through it from
// many goroutines, and a rotation mutates the primary underneath them.
type Keyring struct {
	mu sync.RWMutex

	store KeyStore
	// keks maps key ID to derived key material for every KEK a configured
	// root can actually open. A KEK whose check value fails is recorded in
	// `records` but absent here, so reads against it fail with a specific
	// error instead of a GCM tag mismatch.
	keks    map[string][]byte
	records map[string]KEKRecord
	// rootOf records which root derived each key in keks: an index into
	// roots, so 0 is the current root and 1 the previous.
	rootOf  map[string]int
	primary string

	// roots are what keys derive from, current first. Fixed for the life of
	// the keyring: a hub resolves its roots once (pkg/rootkey.Pin), and a
	// keyring that changed roots under work in flight would answer the same
	// question two ways.
	roots []string

	// legacySalt is the pre-envelope construction's store-wide salt; nil on a
	// hub that never had one. Its cipher is derived per root, on first use,
	// into legacy.
	legacySalt []byte
	legacy     map[int]*Cipher

	// underivable names the live keys no configured root derives. A keyring
	// opened to serve refuses to exist with any (see OpenKeyring); a
	// read-only one reports them, which is what `cloop hub key list` is for.
	underivable []string

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
	roots      []string
	rootsGiven bool
	clock      func() time.Time
	actor      string
	create     bool
}

// WithKeyringPassphrase gives the keyring one root, p, instead of resolving
// the hub's (pkg/rootkey). Tests use it; so does any caller that holds the key
// some other way — a backup's preflight, an escrow being checked.
func WithKeyringPassphrase(p string) KeyringOption {
	return func(c *keyringConfig) { c.roots, c.rootsGiven = []string{p}, true }
}

// WithKeyringRoots gives the keyring a current root and a previous one ("" for
// none) instead of resolving them.
func WithKeyringRoots(current, previous string) KeyringOption {
	return func(c *keyringConfig) {
		c.roots, c.rootsGiven = []string{current}, true
		if previous != "" {
			c.roots = append(c.roots, previous)
		}
	}
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

// OpenKeyring loads the KEK registry, derives every live KEK from the roots it
// was given — by default the hub's, resolved through pkg/rootkey — and ensures a
// primary exists.
//
// Derivation is eager, and goes through a cache that lives as long as the
// process (keycache.go). A derivation costs ~60ms at 200 000 KDF rounds, and
// pkg/ui opens a keyring for every request that touches a secret, so without
// the cache a hub that has rotated a few times would pay a few hundred
// milliseconds a request; with it, a key is derived once per process. Eager
// also means an unusable key is an open failure rather than an intermittent
// one: the rule below is checked against every live key, not the first.
func OpenKeyring(store KeyStore, opts ...KeyringOption) (*Keyring, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: nil key store", ErrInvalidSecret)
	}
	cfg := keyringConfig{clock: time.Now, create: true}
	for _, opt := range opts {
		opt(&cfg)
	}
	if !cfg.rootsGiven {
		roots, err := rootkey.Resolve()
		if err != nil {
			// A source that is configured and wrong is never "no key": the
			// operator meant to give the hub one, and carrying on without
			// would degrade quietly into sealing nothing.
			return nil, fmt.Errorf("%w: %v", ErrRootConfig, err)
		}
		cfg.roots = roots.Values()
	}
	if len(cfg.roots) == 0 || cfg.roots[0] == "" {
		return nil, fmt.Errorf("%w: set it to seal and open secret payloads", ErrNoKey)
	}
	if len(cfg.roots) > 1 && subtle.ConstantTimeCompare([]byte(cfg.roots[0]), []byte(cfg.roots[1])) == 1 {
		cfg.roots = cfg.roots[:1]
	}

	kr := &Keyring{
		store:   store,
		keks:    make(map[string][]byte),
		records: make(map[string]KEKRecord),
		rootOf:  make(map[string]int),
		legacy:  make(map[int]*Cipher),
		roots:   append([]string(nil), cfg.roots...),
		clock:   cfg.clock,
	}

	// The legacy salt is loaded, never created. A hub that has never sealed
	// anything the old way has no legacy salt, and inventing one would leave
	// a second live key in the registry that nothing seals under and nobody
	// rotates.
	if meta, ok := store.(metaStore); ok {
		kr.legacySalt = loadLegacySalt(meta)
	}

	records, err := store.ListKEKs()
	if err != nil {
		return nil, fmt.Errorf("secretbroker: list sealing keys: %w", err)
	}
	for _, rec := range records {
		kr.records[rec.ID] = rec
	}

	// Every live key must derive from a configured root (Task 20425).
	var undecipherable []string
	for _, rec := range records {
		if rec.Retired() {
			continue
		}
		key, idx, derr := kr.deriveAny(rec)
		if derr != nil {
			// Recorded, live, and derived by no root this process holds.
			// Keep the record so reads can name the key precisely, and
			// remember it: the rule below turns on whether any such key exists.
			undecipherable = append(undecipherable, rec.ID)
			continue
		}
		kr.keks[rec.ID] = key
		kr.rootOf[rec.ID] = idx
		if rec.State == KEKStatePrimary {
			kr.primary = rec.ID
		}
	}
	sort.Strings(undecipherable)

	// Getting this rule wrong is worse than any bug in the cryptography.
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
	// from, and a process that cannot derive every live key does not serve at
	// all: a live key no root derives means a key is wrong, or this member was
	// not given the root new material is sealed under, and the only safe
	// response to either is to refuse to start — before a seal under the
	// wrong primary, not after.
	if len(undecipherable) > 0 {
		if cfg.create {
			return nil, kr.refusal(undecipherable)
		}
		// A read-only caller — `cloop hub key list`, the doctor — is asking
		// precisely which keys open, and is answered rather than refused. It
		// never seals: see the !cfg.create case below.
		kr.underivable = undecipherable
	}

	if cfg.create {
		kr.attribute()
	}

	switch {
	case kr.primary != "":
		return kr, nil

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
		newest := newestKeyID(kr.records, kr.keks, kr.rootOf)
		if err := store.PromoteKEK(newest, kr.now()); err != nil {
			return nil, fmt.Errorf("secretbroker: adopt sealing key %s as primary: %w", newest, err)
		}
		kr.markPrimary(newest)
		return kr, nil

	default:
		rec, key, cerr := kr.mintKEK(cfg.actor)
		if cerr != nil {
			return nil, cerr
		}
		kr.records[rec.ID] = rec
		kr.keks[rec.ID] = key
		kr.rootOf[rec.ID] = 0
		kr.markPrimary(rec.ID)
		return kr, nil
	}
}

// refusal is the error a serving keyring is refused with when live keys derive
// from no configured root. It names the roots the registry records for them
// and the ones this process holds, by fingerprint, so "the key is wrong" and
// "this member was not given the new root" read differently.
func (k *Keyring) refusal(ids []string) error {
	named := make([]string, 0, len(ids))
	for _, id := range ids {
		if fp := k.records[id].Root; fp != "" {
			named = append(named, id+" (root "+fp+")")
		} else {
			named = append(named, id)
		}
	}
	return fmt.Errorf("%w: %d live sealing key(s) — %s — derive from no root this process holds (%s); "+
		"refusing to mint a new key, which would fork the registry and leave existing secrets unreadable",
		ErrKeyUnavailable, len(ids), strings.Join(named, ", "), k.describeRoots())
}

// describeRoots names the configured roots for a message: by variable and
// fingerprint, never by value.
func (k *Keyring) describeRoots() string {
	names := []string{rootkey.EnvKey, rootkey.EnvPrevious}
	parts := make([]string, 0, len(k.roots))
	for i, r := range k.roots {
		fp, err := rootkey.Fingerprint(r)
		if err != nil {
			fp = "unknown"
		}
		parts = append(parts, fmt.Sprintf("%s %s", names[i], fp))
	}
	return strings.Join(parts, ", ")
}

// deriveAny derives rec from the first configured root that opens it, and says
// which. The current root is tried first; no key derives from both, since each
// is salted on its own and the previous root may not equal the current.
func (k *Keyring) deriveAny(rec KEKRecord) ([]byte, int, error) {
	var lastErr error
	for i, root := range k.roots {
		key, err := cachedDeriveKEK(root, rec)
		if err == nil {
			return key, i, nil
		}
		lastErr = err
		if !errors.Is(err, ErrKeyUnavailable) {
			break // a corrupt record: no root does better
		}
	}
	return nil, -1, lastErr
}

// attribute records, once, which root each unattributed live key derives from
// (Task 20425). Keys minted before broker_keks.root existed have none; the
// first process holding the root that derives them writes it back. Best
// effort, on purpose: the derivation is the authority on which root opens a
// key, so a failed write costs nothing but a retry by the next opener.
func (k *Keyring) attribute() {
	ks, ok := k.store.(KeyAttributor)
	if !ok {
		return
	}
	k.mu.RLock()
	pending := map[string]int{}
	for id, rec := range k.records {
		if idx, derived := k.rootOf[id]; derived && rec.Root == "" && !rec.Retired() {
			pending[id] = idx
		}
	}
	k.mu.RUnlock()
	for id, idx := range pending {
		fp, err := rootkey.Fingerprint(k.roots[idx])
		if err != nil {
			continue
		}
		if done, err := ks.AttributeKEK(id, fp); err != nil || !done {
			continue
		}
		k.mu.Lock()
		if rec, ok := k.records[id]; ok {
			rec.Root = fp
			k.records[id] = rec
		}
		k.mu.Unlock()
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
// ID so the choice is deterministic across hubs adopting the same registry. A
// key of the current root beats any key of the previous one: adopting a key is
// choosing what seals next, and the previous root only opens.
func newestKeyID(records map[string]KEKRecord, usable map[string][]byte, rootOf map[string]int) string {
	best := ""
	for id := range usable {
		rec := records[id]
		cur, ok := records[best]
		switch {
		case !ok:
			best = id
		case rootOf[id] != rootOf[best]:
			if rootOf[id] < rootOf[best] {
				best = id
			}
		case rec.CreatedAt.After(cur.CreatedAt) || (rec.CreatedAt.Equal(cur.CreatedAt) && id < best):
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

// mintKEK creates, seals a check value for, and persists a new KEK derived
// from the current root, then promotes it to primary. The previous root never
// mints: it is there to open what it sealed until that has been rewrapped.
func (k *Keyring) mintKEK(actor string) (KEKRecord, []byte, error) {
	root := k.roots[0]
	fingerprint, err := rootkey.Fingerprint(root)
	if err != nil {
		return KEKRecord{}, nil, fmt.Errorf("secretbroker: name the root of a new sealing key: %w", err)
	}
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return KEKRecord{}, nil, fmt.Errorf("secretbroker: generate key salt: %w", err)
	}
	id, err := newID(kekIDPrefix)
	if err != nil {
		return KEKRecord{}, nil, err
	}
	key := deriveKey(root, salt)

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
		Root:       fingerprint,
	}
	if err := k.store.PutKEK(rec); err != nil {
		return KEKRecord{}, nil, fmt.Errorf("secretbroker: persist sealing key: %w", err)
	}
	if err := k.store.PromoteKEK(rec.ID, k.now()); err != nil {
		return KEKRecord{}, nil, fmt.Errorf("secretbroker: promote sealing key: %w", err)
	}
	// Every other keyring this process opens finds it derived already.
	rememberKEK(root, rec, key)
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
	// Root is the fingerprint the registry records for the root the key
	// derives from; "" when nobody has attributed it.
	Root string `json:"root,omitempty"`
	// DerivedBy says which of this process's roots derives it, RootCurrent
	// or RootPrevious; "" when neither does.
	DerivedBy string `json:"derived_by,omitempty"`
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
		// Force derivation rather than reporting the cache: with lazy
		// derivation, "openable" would otherwise mean "happens to have been
		// read already", which is the opposite of the question an operator is
		// asking before they retire something.
		key, _, _ := k.lookup(id)
		k.mu.RLock()
		rec := k.records[id]
		idx, derived := k.rootOf[id]
		k.mu.RUnlock()
		info := KeyInfo{
			ID:        id,
			State:     rec.State,
			Primary:   id == primary,
			Openable:  key != nil,
			CreatedAt: rec.CreatedAt,
			CreatedBy: rec.CreatedBy,
			RetiredAt: rec.RetiredAt,
			Root:      rec.Root,
		}
		if key != nil && derived {
			info.DerivedBy = rootSlot(idx)
		}
		out = append(out, info)
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
func (k *Keyring) HasLegacy() bool { return k.legacySalt != nil }

// rootSlot names a root by its index in roots.
func rootSlot(idx int) string {
	if idx == 0 {
		return RootCurrent
	}
	return RootPrevious
}

// HasPrevious reports whether this keyring holds a previous root: a change of
// root is in progress on this process.
func (k *Keyring) HasPrevious() bool { return len(k.roots) > 1 }

// PrimaryFromCurrent reports whether the primary derives from the current
// root. False during a change of root until `cloop hub key rotate
// --retire-previous` has minted a key of the new one, and on a keyring with no
// primary.
func (k *Keyring) PrimaryFromCurrent() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	idx, ok := k.rootOf[k.primary]
	return k.primary != "" && ok && idx == 0
}

// PreviousRootKeys returns the live keys the previous root derives, sorted:
// what retiring the previous root retires. Every live key is derived first, so
// the answer does not depend on which ones happen to have been read.
func (k *Keyring) PreviousRootKeys() []string {
	if !k.HasPrevious() {
		return nil
	}
	k.mu.RLock()
	ids := make([]string, 0, len(k.records))
	for id, rec := range k.records {
		if !rec.Retired() {
			ids = append(ids, id)
		}
	}
	k.mu.RUnlock()
	var out []string
	for _, id := range ids {
		if key, _, _ := k.lookup(id); key == nil {
			continue
		}
		k.mu.RLock()
		idx := k.rootOf[id]
		k.mu.RUnlock()
		if idx == 1 {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// Underivable names the live keys no configured root derives. Only a
// read-only keyring can have any (WithoutKeyCreation); one opened to serve is
// refused instead.
func (k *Keyring) Underivable() []string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return append([]string(nil), k.underivable...)
}

// RootFingerprints names the roots this keyring derives from; previous is ""
// when there is none. Each costs a key derivation the first time in a process.
func (k *Keyring) RootFingerprints() (current, previous string, err error) {
	if current, err = rootkey.Fingerprint(k.roots[0]); err != nil {
		return "", "", err
	}
	if k.HasPrevious() {
		if previous, err = rootkey.Fingerprint(k.roots[1]); err != nil {
			return "", "", err
		}
	}
	return current, previous, nil
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

	// A key minted by another process. Deriving it costs one KDF pass, once
	// per process.
	key, idx, derr := k.deriveAny(rec)
	if derr != nil {
		// The member was not given the root new material is now sealed
		// under — started before a change of root reached it, or with the
		// wrong key. Sealing anything else instead would leave material its
		// peers cannot open, so it seals nothing, loudly.
		return "", nil, fmt.Errorf("%w: the primary sealing key %s%s derives from no root this process holds "+
			"(%s): restart this hub member with the key every other member runs on", ErrKeyUnavailable,
			rec.ID, recordedRoot(rec), k.describeRoots())
	}
	k.mu.Lock()
	k.records[rec.ID] = rec
	k.keks[rec.ID] = key
	k.rootOf[rec.ID] = idx
	k.markPrimary(rec.ID)
	k.mu.Unlock()
	return rec.ID, key, nil
}

// recordedRoot is " (root <fingerprint>)" for a key whose root is recorded.
func recordedRoot(rec KEKRecord) string {
	if rec.Root == "" {
		return ""
	}
	return " (root " + rec.Root + ")"
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
		if k.legacySalt == nil {
			hubmetrics.UnsealFailures.Inc("key_unavailable")
			return nil, fmt.Errorf("%w: no legacy sealing key on this hub", ErrKeyUnavailable)
		}
		// Either root may have sealed it: the pre-envelope construction has
		// no check value to say which, and GCM refuses the wrong one.
		var err error
		for i := range k.roots {
			var out []byte
			if out, err = k.legacyCipher(i).Unseal(env.Ciphertext); err == nil {
				return out, nil
			}
		}
		hubmetrics.UnsealFailures.Inc("seal_failed")
		return nil, err
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
		// The reason label mirrors the sentinel, and the sentinels are
		// distinguishable for the reason given above: the three call for
		// completely different operator responses, so an alert that fires
		// on a rate of "unseal failures" is only actionable if the operator
		// can see which kind without opening the logs.
		switch {
		case known && rec.Retired():
			hubmetrics.UnsealFailures.Inc("key_retired")
			return nil, fmt.Errorf("%w: sealing key %s was retired at %s; this material cannot be recovered",
				ErrKeyRetired, env.KeyID, formatOrUnknown(rec.RetiredAt))
		case known:
			hubmetrics.UnsealFailures.Inc("key_unavailable")
			return nil, fmt.Errorf("%w: sealing key %s%s exists but derives from no root this process holds (%s)",
				ErrKeyUnavailable, env.KeyID, recordedRoot(rec), k.describeRoots())
		default:
			hubmetrics.UnsealFailures.Inc("key_unknown")
			return nil, fmt.Errorf("%w: no sealing key %s in this hub's registry", ErrKeyUnknown, env.KeyID)
		}
	}

	dek, err := openWith(kek, dekAAD(env.KeyID, aad), env.WrappedDEK)
	if err != nil {
		hubmetrics.UnsealFailures.Inc("seal_failed")
		return nil, fmt.Errorf("%w: unwrap data key for %s", ErrSealFailed, SafeRef(aad))
	}
	defer zero(dek)

	plaintext, err := openWith(dek, payloadAAD(aad), env.Ciphertext)
	if err != nil {
		hubmetrics.UnsealFailures.Inc("seal_failed")
	}
	return plaintext, err
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
	rec, key, err := k.mintKEK(actor)
	if err != nil {
		return KeyInfo{}, err
	}

	k.mu.Lock()
	k.records[rec.ID] = rec
	k.keks[rec.ID] = key
	k.rootOf[rec.ID] = 0
	k.markPrimary(rec.ID)
	k.mu.Unlock()

	return KeyInfo{
		ID: rec.ID, State: KEKStatePrimary, Primary: true, Openable: true,
		CreatedAt: rec.CreatedAt, CreatedBy: rec.CreatedBy, Root: rec.Root, DerivedBy: RootCurrent,
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
	// The salt is gone from the registry; the copies this process derived
	// go with it, or retirement would shred everything but the memory of
	// the process that did it.
	forgetKEK(id)

	k.mu.Lock()
	if key, ok := k.keks[id]; ok {
		zero(key)
		delete(k.keks, id)
	}
	delete(k.rootOf, id)
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

	derived, idx, err := k.deriveAny(rec)
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
	k.rootOf[id] = idx
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
	k.mu.Unlock()
	return k.reload() == nil
}

// Reload re-reads the KEK registry, adopting keys another process minted and
// dropping ones it retired.
//
// It never mints and never demotes to nothing: a registry that has become
// unreadable leaves the in-memory state exactly as it was, because a hub that
// is currently serving reads is better off with a stale key set than with an
// empty one.
func (k *Keyring) Reload() error { return k.reload() }

func (k *Keyring) reload() error {
	records, err := k.store.ListKEKs()
	if err != nil {
		return fmt.Errorf("secretbroker: reload sealing keys: %w", err)
	}

	// Derive outside the lock: each derivation is 200 000 SHA-256 rounds, and
	// holding the write lock across them would stall every concurrent read of
	// an already-known key for no reason.
	fresh := map[string][]byte{}
	freshRoot := map[string]int{}
	for _, rec := range records {
		if rec.Retired() {
			// Retired elsewhere: what this process derived of it goes too.
			forgetKEK(rec.ID)
			continue
		}
		if key, _, ok := k.lookup(rec.ID); ok && key != nil {
			continue
		}
		if key, idx, derr := k.deriveAny(rec); derr == nil {
			fresh[rec.ID] = key
			freshRoot[rec.ID] = idx
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
			delete(k.rootOf, rec.ID)
			continue
		}
		if key, ok := fresh[rec.ID]; ok {
			k.keks[rec.ID] = key
			k.rootOf[rec.ID] = freshRoot[rec.ID]
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
			delete(k.rootOf, id)
			delete(k.records, id)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Derivation and primitives
// ---------------------------------------------------------------------------

// deriveKEK derives a KEK from a root and verifies it against the record's
// check value. Callers go through cachedDeriveKEK (keycache.go).
//
// Verification is what separates "this key is not for this root" from "this
// ciphertext is corrupt" at load time rather than at lease time.
func deriveKEK(passphrase string, rec KEKRecord) ([]byte, error) {
	salt, err := derivable(rec)
	if err != nil {
		return nil, err
	}
	key := deriveKey(passphrase, salt)
	got, err := openWith(key, kekCheckAAD(rec.ID), rec.CheckValue)
	if err != nil {
		zero(key)
		return nil, fmt.Errorf("%w: sealing key %s does not derive from this root", ErrKeyUnavailable, rec.ID)
	}
	defer zero(got)
	if subtle.ConstantTimeCompare(got, []byte(kekCheckPlaintext)) != 1 {
		zero(key)
		return nil, fmt.Errorf("%w: sealing key %s failed its check value", ErrSealFailed, rec.ID)
	}
	return key, nil
}

// derivable checks what a record must carry before any root is tried against
// it, and returns its salt.
func derivable(rec KEKRecord) ([]byte, error) {
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
	return salt, nil
}

// loadLegacySalt reads the pre-envelope construction's salt if the store still
// holds it; nil when it does not, or when it is corrupt.
func loadLegacySalt(store metaStore) []byte {
	v, ok, err := store.Meta(metaKeySalt)
	if err != nil || !ok || v == "" {
		return nil
	}
	salt, derr := decodeHex(v)
	if derr != nil || len(salt) != saltSize {
		return nil
	}
	return salt
}

// legacyCipher is the pre-envelope cipher of root i, derived on first use.
func (k *Keyring) legacyCipher(i int) *Cipher {
	k.mu.RLock()
	c := k.legacy[i]
	k.mu.RUnlock()
	if c != nil {
		return c
	}
	c = &Cipher{key: cachedLegacyKey(k.roots[i], k.legacySalt)}
	k.mu.Lock()
	defer k.mu.Unlock()
	if existing := k.legacy[i]; existing != nil {
		return existing
	}
	k.legacy[i] = c
	return c
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
