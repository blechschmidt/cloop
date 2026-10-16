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
//
// # KMS roots (Task 20433)
//
// A root may also be a key-management service: a KEK of a KMS root is random,
// and its record keeps the KMS's ciphertext of it instead of a salt. Opening
// it is asking the KMS to unwrap it, checked against the same check value.
// Everything above holds for it unchanged — current and previous, the rule a
// keyring opens by, the change of root — which is how a store moves onto a KMS
// and off one; kms.go has what is particular to it.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
// useless; a KMS-held key's ciphertext opens only through the KMS (kms.go).
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
	// (pkg/rootkey), or the name of the KMS holding it; "" for a derived key
	// nobody has attributed yet. A record, not an authority: which root opens
	// a key is decided by opening it.
	Root string

	// Wrap says how the key is held: "" — derived from a passphrase root and
	// Salt, which is then a real salt; WrapKMS — random, held wrapped by the
	// KMS Root names, with a decoy Salt no passphrase derives it from.
	Wrap string
	// KMSKeyID, KMSCiphertext and KMSAnnotations are a KMS-held key's
	// wrapping, as the KMS returned it (Task 20433). Retirement destroys the
	// ciphertext along with the salt.
	KMSKeyID       string
	KMSCiphertext  []byte
	KMSAnnotations map[string][]byte
}

// Which configured root derives a key, as KeyInfo reports it.
const (
	RootCurrent  = "current"
	RootPrevious = "previous"
)

// Retired reports whether the KEK has been shredded.
func (k KEKRecord) Retired() bool {
	return k.State == KEKStateRetired || k.Salt == "" || (k.Wrap == WrapKMS && len(k.KMSCiphertext) == 0)
}

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
	// rootOf records which root opened each key in keks: an index into
	// roots, so 0 is the current root and 1 the previous.
	rootOf  map[string]int
	primary string

	// roots are what keys derive from or are unwrapped by, current first.
	// Fixed for the life of the keyring: a hub resolves its roots once
	// (pkg/rootkey.Pin, PinRoots), and a keyring that changed roots under work
	// in flight would answer the same question two ways.
	roots []Root

	// ctx bounds the KMS calls opening a key makes (WithKeyringContext).
	ctx context.Context

	// legacySalt is the pre-envelope construction's store-wide salt; nil on a
	// hub that never had one. Its cipher is derived per root, on first use,
	// into legacy.
	legacySalt []byte
	legacy     map[int]*Cipher

	// underivable names the live keys no configured root opens, and
	// underivableWhy what opening each said. A keyring opened to serve refuses
	// to exist with any (see OpenKeyring); a read-only one reports them, which
	// is what `cloop hub key list` is for.
	underivable    []string
	underivableWhy map[string]error

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
	roots      []Root
	rootsGiven bool
	clock      func() time.Time
	actor      string
	create     bool
	ctx        context.Context
}

// WithKeyringPassphrase gives the keyring one root, p, instead of resolving
// the hub's (pkg/rootkey). Tests use it; so does any caller that holds the key
// some other way — a backup's preflight, an escrow being checked.
func WithKeyringPassphrase(p string) KeyringOption {
	return func(c *keyringConfig) { c.roots, c.rootsGiven = []Root{PassphraseRoot(p)}, true }
}

// WithKeyringRoots gives the keyring a current passphrase root and a previous
// one ("" for none) instead of resolving them.
func WithKeyringRoots(current, previous string) KeyringOption {
	return func(c *keyringConfig) {
		c.roots, c.rootsGiven = []Root{PassphraseRoot(current)}, true
		if previous != "" {
			c.roots = append(c.roots, PassphraseRoot(previous))
		}
	}
}

// WithKeyringRootSet gives the keyring a current root and a previous one (the
// zero Root for none), either of which may be a KMS (Task 20433).
func WithKeyringRootSet(current, previous Root) KeyringOption {
	return func(c *keyringConfig) {
		c.roots, c.rootsGiven = []Root{current}, true
		if !previous.IsZero() {
			c.roots = append(c.roots, previous)
		}
	}
}

// WithKeyringContext bounds the KMS calls opening the keyring makes. Without
// it they are bounded by each KMS's own timeout.
func WithKeyringContext(ctx context.Context) KeyringOption {
	return func(c *keyringConfig) {
		if ctx != nil {
			c.ctx = ctx
		}
	}
}

// ---------------------------------------------------------------------------
// The process's roots
// ---------------------------------------------------------------------------

// RootResolver supplies the roots a keyring opens with when it is given none:
// the current root and the previous one (the zero Root for none).
type RootResolver func() (current, previous Root, err error)

type rootSet struct{ current, previous Root }

var (
	pinnedRoots  atomic.Pointer[rootSet]
	rootResolver atomic.Pointer[RootResolver]
)

// PinRoots makes every keyring this process opens without a root option open
// with current and previous, and returns a function that undoes it. `cloop ui`
// pins the roots it resolved at startup — the root key (pkg/rootkey) and the
// KMS of secrets.kms (pkg/kms) — for the reason it pins the root key: its
// cluster peers are told the roots it started with, and a configuration that
// changed under it would change the roots under work in flight.
func PinRoots(current, previous Root) (unpin func()) {
	prev := pinnedRoots.Swap(&rootSet{current: current, previous: previous})
	return func() { pinnedRoots.Store(prev) }
}

// PinnedRoots returns the roots PinRoots pinned, and whether any are: what a
// serving hub's own diagnosis opens its keyring with, rather than resolving
// a KMS client of its own (Task 20434).
func PinnedRoots() (current, previous Root, ok bool) {
	p := pinnedRoots.Load()
	if p == nil {
		return Root{}, Root{}, false
	}
	return p.current, p.previous, true
}

// SetRootResolver installs fn as the source of the roots keyrings open with
// when nothing is pinned, and returns a function that undoes it. A command
// that reads secrets.kms installs one; fn is called on every such open and
// must be cheap after its first call. With none installed, the roots are the
// root key's (rootkey.Resolve).
func SetRootResolver(fn RootResolver) (restore func()) {
	var p *RootResolver
	if fn != nil {
		p = &fn
	}
	prev := rootResolver.Swap(p)
	return func() { rootResolver.Store(prev) }
}

// processRoots resolves the roots a keyring given none opens with.
func processRoots() ([]Root, error) {
	if p := pinnedRoots.Load(); p != nil {
		return rootList(p.current, p.previous), nil
	}
	if fn := rootResolver.Load(); fn != nil {
		cur, prev, err := (*fn)()
		if err != nil {
			return nil, err
		}
		return rootList(cur, prev), nil
	}
	roots, err := rootkey.Resolve()
	if err != nil {
		// A source that is configured and wrong is never "no key": the
		// operator meant to give the hub one, and carrying on without
		// would degrade quietly into sealing nothing.
		return nil, fmt.Errorf("%w: %v", ErrRootConfig, err)
	}
	return PassphraseRoots(roots.Values()...), nil
}

func rootList(current, previous Root) []Root {
	out := []Root{current}
	if !previous.IsZero() {
		out = append(out, previous)
	}
	return out
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
	cfg := keyringConfig{clock: time.Now, create: true, ctx: context.Background()}
	for _, opt := range opts {
		opt(&cfg)
	}
	if !cfg.rootsGiven {
		roots, err := processRoots()
		if err != nil {
			return nil, err
		}
		cfg.roots = roots
	}
	if len(cfg.roots) == 0 || cfg.roots[0].IsZero() {
		return nil, fmt.Errorf("%w: set it, or secrets.kms, to seal and open secret payloads", ErrNoKey)
	}
	if len(cfg.roots) > 1 && sameRoot(cfg.roots[0], cfg.roots[1]) {
		cfg.roots = cfg.roots[:1]
	}

	kr := &Keyring{
		store:   store,
		keks:    make(map[string][]byte),
		records: make(map[string]KEKRecord),
		rootOf:  make(map[string]int),
		legacy:  make(map[int]*Cipher),
		roots:   append([]Root(nil), cfg.roots...),
		ctx:     cfg.ctx,
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

	// Every live key must open with a configured root (Task 20425): derive
	// from a passphrase root, or unwrap through a KMS root (Task 20433).
	var undecipherable []string
	why := map[string]error{}
	for _, rec := range records {
		if rec.Retired() {
			continue
		}
		key, idx, derr := kr.openAny(rec)
		if derr != nil {
			// Recorded, live, and opened by no root this process holds.
			// Keep the record so reads can name the key precisely, and
			// remember it: the rule below turns on whether any such key exists.
			undecipherable = append(undecipherable, rec.ID)
			why[rec.ID] = derr
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
			return nil, kr.refusal(undecipherable, why)
		}
		// A read-only caller — `cloop hub key list`, the doctor — is asking
		// precisely which keys open, and is answered rather than refused. It
		// never seals: see the !cfg.create case below.
		kr.underivable = undecipherable
		kr.underivableWhy = why
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

// refusal is the error a serving keyring is refused with when live keys open
// with no configured root. It names the roots the registry records for them,
// what opening each said — a KMS that cannot be reached reads differently from
// one that refused, and both from a key no root of this kind exists for — and
// the roots this process holds, by fingerprint or KMS name, so "the key is
// wrong" and "this member was not given the new root" read differently.
func (k *Keyring) refusal(ids []string, why map[string]error) error {
	const shown = 8
	named := make([]string, 0, len(ids))
	kmsDown := false
	for i, id := range ids {
		if i == shown {
			named = append(named, fmt.Sprintf("and %d more", len(ids)-shown))
			break
		}
		named = append(named, id+k.reasonFor(id, why[id]))
		kmsDown = kmsDown || errors.Is(why[id], ErrKMSUnavailable)
	}
	sentinel := ErrKeyUnavailable
	if kmsDown {
		// Wraps ErrKeyUnavailable too: callers that test for an unopenable
		// key still see one.
		sentinel = ErrKMSUnavailable
	}
	return fmt.Errorf("%w: %d live sealing key(s) — %s — open with no root this process holds (%s); "+
		"refusing to mint a new key, which would fork the registry and leave existing secrets unreadable",
		sentinel, len(ids), strings.Join(named, ", "), k.describeRoots())
}

// reasonFor is " (root X: what opening it said)" for a key a configured root
// could not open, kept short: the reason of a KMS error can be long.
func (k *Keyring) reasonFor(id string, err error) string {
	return reasonForRec(k.records[id], err)
}

// reasonForRec is reasonFor for a record the caller holds, for paths that do
// not hold the keyring's lock.
func reasonForRec(rec KEKRecord, err error) string {
	id := rec.ID
	var parts []string
	if rec.Root != "" {
		parts = append(parts, "root "+rec.Root)
	}
	if err != nil {
		msg := err.Error()
		for _, p := range []string{ErrKMSUnavailable.Error() + ": ", ErrKeyUnavailable.Error() + ": ",
			"sealing key " + id + ": ", "sealing key " + id + " "} {
			msg = strings.TrimPrefix(msg, p)
		}
		if len(msg) > 240 {
			msg = msg[:240] + "…"
		}
		parts = append(parts, msg)
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ": ") + ")"
}

// describeRoots names the configured roots for a message: a passphrase by
// the setting it came from and its fingerprint, never its value; a KMS by the
// setting and its name.
func (k *Keyring) describeRoots() string {
	parts := make([]string, 0, len(k.roots))
	for i := range k.roots {
		parts = append(parts, k.rootLabel(i))
	}
	return strings.Join(parts, ", ")
}

// rootLabel names root i as an operator configured it.
func (k *Keyring) rootLabel(i int) string {
	r := k.roots[i]
	if r.IsKMS() {
		if i == 0 {
			return "secrets.kms " + r.KMS.Name()
		}
		return "secrets.kms_previous " + r.KMS.Name()
	}
	fp, err := rootkey.Fingerprint(r.Passphrase)
	if err != nil {
		fp = "unknown"
	}
	switch {
	case i == 0:
		return rootkey.EnvKey + " " + fp
	case k.roots[0].IsKMS():
		// Moving onto a KMS: the passphrase being replaced is the hub's
		// CLOOP_SECRET_KEY, named the previous root by secrets.previous_root.
		return rootkey.EnvKey + " " + fp + " (secrets.previous_root)"
	default:
		return rootkey.EnvPrevious + " " + fp
	}
}

// sameRoot reports whether two roots are one: equal passphrases, or KMSs of
// one name.
func sameRoot(a, b Root) bool {
	switch {
	case a.IsKMS() && b.IsKMS():
		return a.KMS.Name() == b.KMS.Name()
	case a.IsKMS() || b.IsKMS():
		return false
	}
	return a.Passphrase != "" && subtle.ConstantTimeCompare([]byte(a.Passphrase), []byte(b.Passphrase)) == 1
}

// openAny opens rec with the first configured root that can, and says which.
// A derived key is tried against the passphrase roots, current first — no key
// derives from both, since each is salted on its own and the previous root may
// not equal the current. A KMS-held key is tried against the KMS roots, the one
// its record names first.
func (k *Keyring) openAny(rec KEKRecord) ([]byte, int, error) {
	var lastErr error
	tried := false
	for _, i := range k.rootOrder(rec) {
		tried = true
		key, err := cachedOpenKEK(k.ctx, k.roots[i], rec)
		if err == nil {
			return key, i, nil
		}
		lastErr = err
		if !errors.Is(err, ErrKeyUnavailable) {
			break // a corrupt record: no root does better
		}
	}
	if !tried {
		return nil, -1, k.noRootFor(rec)
	}
	return nil, -1, lastErr
}

// rootOrder lists the indexes of the roots that could open rec, in the order
// to try them.
func (k *Keyring) rootOrder(rec KEKRecord) []int {
	var named, rest []int
	for i, r := range k.roots {
		if !r.opens(rec) {
			continue
		}
		if r.IsKMS() && r.KMS.Name() == rec.Root {
			named = append(named, i)
			continue
		}
		rest = append(rest, i)
	}
	return append(named, rest...)
}

// noRootFor says why no configured root is even of the kind that opens rec.
func (k *Keyring) noRootFor(rec KEKRecord) error {
	if rec.Wrap == WrapKMS {
		return fmt.Errorf("%w: sealing key %s is held by the KMS %s, and this process has no KMS configured "+
			"to unwrap it (secrets.kms, or secrets.kms_previous while moving off it)", ErrKeyUnavailable, rec.ID,
			orUnnamed(rec.Root))
	}
	return fmt.Errorf("%w: sealing key %s derives from a passphrase root%s, and this process holds none "+
		"(%s, or secrets.previous_root: passphrase while moving onto a KMS)", ErrKeyUnavailable, rec.ID,
		recordedRoot(rec), rootkey.EnvKey)
}

func orUnnamed(s string) string {
	if s == "" {
		return "(unnamed)"
	}
	return s
}

// attribute records, once, which root each unattributed live key derives from
// (Task 20425). Keys minted before broker_keks.root existed have none; the
// first process holding the root that derives them writes it back. Best
// effort, on purpose: the derivation is the authority on which root opens a
// key, so a failed write costs nothing but a retry by the next opener. A
// KMS-held key is named at mint and never needs this.
func (k *Keyring) attribute() {
	ks, ok := k.store.(KeyAttributor)
	if !ok {
		return
	}
	k.mu.RLock()
	pending := map[string]int{}
	for id, rec := range k.records {
		if idx, derived := k.rootOf[id]; derived && rec.Root == "" && !rec.Retired() && rec.Wrap == "" &&
			!k.roots[idx].IsKMS() {
			pending[id] = idx
		}
	}
	k.mu.RUnlock()
	for id, idx := range pending {
		fp, err := rootkey.Fingerprint(k.roots[idx].Passphrase)
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

// mintKEK creates, seals a check value for, and persists a new KEK of the
// current root — derived from its passphrase, or random and wrapped by its KMS
// (kms.go) — then promotes it to primary. The previous root never mints: it is
// there to open what it sealed until that has been rewrapped.
func (k *Keyring) mintKEK(actor string) (KEKRecord, []byte, error) {
	root := k.roots[0]
	id, err := newID(kekIDPrefix)
	if err != nil {
		return KEKRecord{}, nil, err
	}
	var (
		rec KEKRecord
		key []byte
	)
	if root.IsKMS() {
		if rec, key, err = kmsMint(k.ctx, root.KMS, id, actor, k.now()); err != nil {
			return KEKRecord{}, nil, err
		}
	} else {
		fingerprint, err := rootkey.Fingerprint(root.Passphrase)
		if err != nil {
			return KEKRecord{}, nil, fmt.Errorf("secretbroker: name the root of a new sealing key: %w", err)
		}
		salt := make([]byte, saltSize)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return KEKRecord{}, nil, fmt.Errorf("secretbroker: generate key salt: %w", err)
		}
		key = deriveKey(root.Passphrase, salt)
		check, err := sealWith(key, kekCheckAAD(id), []byte(kekCheckPlaintext))
		if err != nil {
			zero(key)
			return KEKRecord{}, nil, err
		}
		rec = KEKRecord{
			ID:         id,
			Salt:       encodeHex(salt),
			State:      KEKStateActive,
			CheckValue: check,
			CreatedAt:  k.now(),
			CreatedBy:  actor,
			Root:       fingerprint,
		}
	}
	if err := k.store.PutKEK(rec); err != nil {
		zero(key)
		return KEKRecord{}, nil, fmt.Errorf("secretbroker: persist sealing key: %w", err)
	}
	if err := k.store.PromoteKEK(rec.ID, k.now()); err != nil {
		zero(key)
		return KEKRecord{}, nil, fmt.Errorf("secretbroker: promote sealing key: %w", err)
	}
	// Every other keyring this process opens finds it opened already.
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
	// derives from, or the name of the KMS holding it; "" when nobody has
	// attributed it.
	Root string `json:"root,omitempty"`
	// DerivedBy says which of this process's roots opens it, RootCurrent
	// or RootPrevious; "" when neither does.
	DerivedBy string `json:"derived_by,omitempty"`
	// Wrap is WrapKMS for a key held by a KMS, and KMSKeyID the KMS key that
	// wraps it (Task 20433). The ciphertext is never reported.
	Wrap     string `json:"wrap,omitempty"`
	KMSKeyID string `json:"kms_key_id,omitempty"`
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
			Wrap:      rec.Wrap,
			KMSKeyID:  rec.KMSKeyID,
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
// hub: the legacy salt is there, and a passphrase root to derive its key from
// — a KMS never sealed anything that way. False with legacy rows present
// means those rows are unreadable, which `cloop hub key status` reports rather
// than leaving to be discovered.
func (k *Keyring) HasLegacy() bool {
	if k.legacySalt == nil {
		return false
	}
	for _, r := range k.roots {
		if !r.IsKMS() && r.Passphrase != "" {
			return true
		}
	}
	return false
}

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

// Underivable names the live keys no configured root opens. Only a read-only
// keyring can have any (WithoutKeyCreation); one opened to serve is refused
// instead.
func (k *Keyring) Underivable() []string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return append([]string(nil), k.underivable...)
}

// UnderivableReasons says, for each key Underivable names, why no configured
// root opened it — a KMS that cannot be reached, one that refused, no root of
// the key's kind — as a message naming the key, never quoting key material.
func (k *Keyring) UnderivableReasons() map[string]string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make(map[string]string, len(k.underivable))
	for _, id := range k.underivable {
		out[id] = strings.TrimPrefix(k.reasonFor(id, k.underivableWhy[id]), " ")
	}
	return out
}

// UnderivableErr is the error opening the key id said, for a key Underivable
// names; nil otherwise.
func (k *Keyring) UnderivableErr(id string) error {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.underivableWhy[id]
}

// RootFingerprints names the roots this keyring opens with: a passphrase root
// by its fingerprint, a KMS root by its name. previous is "" when there is
// none. A fingerprint costs a key derivation the first time in a process.
func (k *Keyring) RootFingerprints() (current, previous string, err error) {
	if current, err = rootName(k.roots[0]); err != nil {
		return "", "", err
	}
	if k.HasPrevious() {
		if previous, err = rootName(k.roots[1]); err != nil {
			return "", "", err
		}
	}
	return current, previous, nil
}

// RootName names r as the registry and a hub cluster member do: the
// fingerprint of a passphrase, or the name of a KMS.
func RootName(r Root) (string, error) { return rootName(r) }

func rootName(r Root) (string, error) {
	if r.IsKMS() {
		return r.KMS.Name(), nil
	}
	return rootkey.Fingerprint(r.Passphrase)
}

// CurrentKMS is the current root's KMS, nil when the current root is a
// passphrase.
func (k *Keyring) CurrentKMS() KMS {
	if len(k.roots) == 0 {
		return nil
	}
	return k.roots[0].KMS
}

// PreviousIsKMS reports whether the previous root is a KMS.
func (k *Keyring) PreviousIsKMS() bool { return k.HasPrevious() && k.roots[1].IsKMS() }

// RootLabels names the configured roots as an operator configured them,
// current first: "CLOOP_SECRET_KEY de46…", "secrets.kms kmsv2:/run/kms.sock".
func (k *Keyring) RootLabels() []string {
	out := make([]string, 0, len(k.roots))
	for i := range k.roots {
		out = append(out, k.rootLabel(i))
	}
	return out
}

// liveIDs lists the ids of every key not retired.
func (k *Keyring) liveIDs() []string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	ids := make([]string, 0, len(k.records))
	for id, rec := range k.records {
		if !rec.Retired() {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
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

	// A key minted by another process. Deriving it costs one KDF pass, and
	// unwrapping it one KMS call, once per process.
	key, idx, derr := k.openAny(rec)
	if derr != nil {
		// The member was not given the root new material is now sealed
		// under — started before a change of root reached it, or with the
		// wrong key — or its KMS cannot be reached. Sealing anything else
		// instead would leave material its peers cannot open, so it seals
		// nothing, loudly.
		sentinel := ErrKeyUnavailable
		if errors.Is(derr, ErrKMSUnavailable) {
			sentinel = ErrKMSUnavailable
		}
		return "", nil, fmt.Errorf("%w: the primary sealing key %s%s opens with no root this process holds "+
			"(%s): restart this hub member with the roots every other member runs on", sentinel,
			rec.ID, reasonForRec(rec, derr), k.describeRoots())
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
		// Either passphrase root may have sealed it: the pre-envelope
		// construction has no check value to say which, and GCM refuses the
		// wrong one. A KMS never sealed anything this way.
		err := fmt.Errorf("%w: no passphrase root to open pre-envelope material with", ErrKeyUnavailable)
		for i, root := range k.roots {
			if root.IsKMS() {
				continue
			}
			var out []byte
			if out, err = k.legacyCipher(i).Unseal(env.Ciphertext); err == nil {
				return out, nil
			}
		}
		hubmetrics.UnsealFailures.Inc("seal_failed")
		return nil, err
	}

	kek, rec, known, openErr := k.lookupErr(env.KeyID)
	if kek == nil && !known {
		// Another process may have minted this key since we loaded — a
		// `cloop hub key rotate` run against a hub that is still serving is
		// exactly that. Re-reading the registry here is what keeps a rotation
		// from silently breaking reads in every long-lived process until it
		// restarts.
		if k.reloadThrottled() {
			kek, rec, known, openErr = k.lookupErr(env.KeyID)
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
		case known && errors.Is(openErr, ErrKMSUnavailable):
			// The key is fine; the KMS holding it does not answer. Nothing
			// opens it until it does — no other root is tried in its place.
			hubmetrics.UnsealFailures.Inc("kms_unavailable")
			return nil, fmt.Errorf("%w: sealing key %s%s (%s)", ErrKMSUnavailable, env.KeyID,
				reasonForRec(rec, openErr), k.describeRoots())
		case known:
			hubmetrics.UnsealFailures.Inc("key_unavailable")
			return nil, fmt.Errorf("%w: sealing key %s%s exists but opens with no root this process holds (%s)",
				ErrKeyUnavailable, env.KeyID, reasonForRec(rec, openErr), k.describeRoots())
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
		Wrap: rec.Wrap, KMSKeyID: rec.KMSKeyID,
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
		rec.CheckValue = nil
		rec.KMSCiphertext = nil
		rec.KMSAnnotations = nil
		rec.RetiredAt = at
		k.records[id] = rec
	}
	k.mu.Unlock()
	return nil
}

// lookup returns the opened key, the record, and whether the id is known,
// opening the key on first use.
//
// Lazy derivation is what keeps a hub that has rotated several times from
// paying a KDF pass per key on every keyring construction. It is safe because
// opening verifies against the key check value: a key that does not belong to
// this root comes back nil here exactly as it would have from an eager pass.
func (k *Keyring) lookup(id string) ([]byte, KEKRecord, bool) {
	key, rec, known, _ := k.lookupErr(id)
	return key, rec, known
}

// lookupErr is lookup, and what opening the key said when it did not open.
func (k *Keyring) lookupErr(id string) ([]byte, KEKRecord, bool, error) {
	k.mu.RLock()
	key, has := k.keks[id]
	rec, known := k.records[id]
	k.mu.RUnlock()
	if has || !known || rec.Retired() {
		return key, rec, known, nil
	}

	opened, idx, err := k.openAny(rec)
	if err != nil {
		return nil, rec, known, err
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	// Another goroutine may have opened it while we were not holding the
	// lock; keep the first one so callers holding a []byte keep a live slice.
	if existing, ok := k.keks[id]; ok {
		zero(opened)
		return existing, k.records[id], true, nil
	}
	k.keks[id] = opened
	k.rootOf[id] = idx
	return opened, k.records[id], true, nil
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
		if key, idx, derr := k.openAny(rec); derr == nil {
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
// check value. Callers go through cachedOpenKEK (keycache.go).
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
	c = &Cipher{key: cachedLegacyKey(k.roots[i].Passphrase, k.legacySalt)}
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
