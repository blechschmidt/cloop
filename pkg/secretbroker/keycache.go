package secretbroker

// Keys opened in this process, kept for the life of the process (Task 20425).
//
// A KEK costs 200 000 SHA-256 rounds to derive — about 60 ms on a small host —
// and pkg/ui opens a keyring for every request that touches a secret: every
// lease, every listing, every session write. A keyring that derived its keys
// itself made each of those requests pay one derivation per live key, and a
// hub in the middle of a change of root holds the keys of two roots. Cached,
// a key is derived once per process, by whichever keyring asks first.
//
// What is cached is the outcome of a derivation for one (root, key record):
// the key, or "this root does not derive this record". Both are deterministic
// in the record's salt and check value, and both are part of the index, so a
// record edited in the database is a different entry rather than a stale hit.
// A record too corrupt to derive at all never reaches the cache.
//
// A key held by a KMS (Task 20433) is cached the same way once the KMS has
// unwrapped it and it has passed its check value: this cache is the "held in
// memory" a KMS-held key's plaintext lives in, and the only place it lives.
// Without it every request would be a KMS call — a latency every request pays,
// and a rate a KMS bills or throttles. A failure to unwrap is not deterministic
// the way a failed derivation is — the KMS may be back in a second — so it is
// remembered only for kmsFailureTTL: long enough that a KMS outage does not
// turn every read into a call that waits out its timeout, short enough that
// the store opens again as soon as the KMS does. Concurrent opens of one key
// share one call.
//
// Entries are indexed by an HMAC under a key this process drew at random
// (rootkey.CacheID), never by the root itself. Retiring a key evicts and
// wipes every entry opened for it: retirement destroys the salt (and a
// KMS-held key's ciphertext) in the registry, and a process that kept a copy
// would have shredded everything but its own memory.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/blechschmidt/cloop/pkg/rootkey"
)

// kekDerivations counts the derivations the cache did not answer, so a test
// can tell a cached key from one derived again.
var kekDerivations atomic.Int64

// kmsUnwraps counts the KMS unwraps the cache did not answer.
var kmsUnwraps atomic.Int64

// kekCacheLimit bounds the cache. A registry holds a handful of live keys and a
// hub two roots, so this is never reached by a working hub; it exists so that
// rows written into the database by someone else cannot grow the hub's memory
// without bound. Past it the cache is emptied and refilled.
const kekCacheLimit = 1024

// kmsFailureTTL is how long a failed unwrap is remembered before the KMS is
// asked again.
const kmsFailureTTL = 5 * time.Second

type kekCacheEntry struct {
	key   []byte // nil: the root does not derive the record
	kekID string
}

type kmsFailure struct {
	err   error
	until time.Time
}

var kekCache = struct {
	sync.Mutex
	entries map[string]kekCacheEntry
	byKEK   map[string][]string // key id -> cache ids, for eviction on retirement
	legacy  map[string][]byte
	failed  map[string]kmsFailure
}{
	entries: map[string]kekCacheEntry{},
	byKEK:   map[string][]string{},
	legacy:  map[string][]byte{},
	failed:  map[string]kmsFailure{},
}

// kmsFlight shares one KMS call among the opens of one key that arrive while
// it is in flight: a hub starting with a few hundred requests queued must not
// send the KMS a few hundred identical unwraps.
var kmsFlight singleflight.Group

// cacheNow is the cache's clock, a variable so a test can step past
// kmsFailureTTL.
var cacheNow = time.Now

func kekCacheID(root Root, rec KEKRecord) string {
	if root.IsKMS() {
		return rootkey.CacheID("secretbroker/kms-kek", root.KMS.Name(), rec.ID, rec.KMSKeyID,
			string(rec.KMSCiphertext), string(rec.CheckValue))
	}
	return rootkey.CacheID("secretbroker/kek", root.Passphrase, rec.ID, rec.Salt, string(rec.CheckValue))
}

// cachedOpenKEK opens rec with root through the cache: derives it from a
// passphrase root, or has a KMS root unwrap it. The caller owns the returned
// slice.
func cachedOpenKEK(ctx context.Context, root Root, rec KEKRecord) ([]byte, error) {
	if !root.opens(rec) {
		if rec.Wrap == WrapKMS {
			return nil, fmt.Errorf("%w: sealing key %s is held by a KMS, not derived from a passphrase", ErrKeyUnavailable, rec.ID)
		}
		return nil, fmt.Errorf("%w: sealing key %s derives from a passphrase, not a KMS", ErrKeyUnavailable, rec.ID)
	}
	if root.IsKMS() {
		return cachedUnwrapKEK(ctx, root, rec)
	}
	return cachedDeriveKEK(root.Passphrase, rec)
}

// cachedDeriveKEK is deriveKEK through the cache.
func cachedDeriveKEK(root string, rec KEKRecord) ([]byte, error) {
	if _, err := derivable(rec); err != nil {
		return nil, err
	}
	id := kekCacheID(PassphraseRoot(root), rec)
	kekCache.Lock()
	e, ok := kekCache.entries[id]
	kekCache.Unlock()
	if ok {
		if e.key == nil {
			return nil, fmt.Errorf("%w: sealing key %s does not derive from this root", ErrKeyUnavailable, rec.ID)
		}
		return append([]byte(nil), e.key...), nil
	}
	kekDerivations.Add(1)
	key, err := deriveKEK(root, rec)
	switch {
	case err == nil:
		rememberKEK(PassphraseRoot(root), rec, key)
	case errors.Is(err, ErrKeyUnavailable):
		remember(id, rec.ID, nil)
	}
	return key, err
}

// cachedUnwrapKEK is kmsUnwrap through the cache.
func cachedUnwrapKEK(ctx context.Context, root Root, rec KEKRecord) ([]byte, error) {
	if err := kmsOpenable(rec); err != nil {
		return nil, err
	}
	id := kekCacheID(root, rec)
	kekCache.Lock()
	e, ok := kekCache.entries[id]
	f, failed := kekCache.failed[id]
	kekCache.Unlock()
	if ok && e.key != nil {
		return append([]byte(nil), e.key...), nil
	}
	if failed && cacheNow().Before(f.until) {
		return nil, f.err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// The call is shared, so no one caller's cancellation may end it — that
	// would fail every other caller and be remembered as the KMS failing. It
	// is bounded by the KMS's own timeout instead.
	callCtx := context.WithoutCancel(ctx)
	for attempt := 0; attempt < 2; attempt++ {
		_, err, _ := kmsFlight.Do(id, func() (any, error) {
			kmsUnwraps.Add(1)
			key, err := kmsUnwrap(callCtx, root.KMS, rec)
			if err != nil {
				kekCache.Lock()
				kekCache.failed[id] = kmsFailure{err: err, until: cacheNow().Add(kmsFailureTTL)}
				kekCache.Unlock()
				return nil, err
			}
			kekCache.Lock()
			delete(kekCache.failed, id)
			kekCache.Unlock()
			// The cache takes the key itself: the only copy that outlives
			// this call is the one retirement wipes.
			remember(id, rec.ID, key)
			return nil, nil
		})
		if err != nil {
			return nil, err
		}
		kekCache.Lock()
		e, ok := kekCache.entries[id]
		var out []byte
		if ok && e.key != nil {
			out = append([]byte(nil), e.key...)
		}
		kekCache.Unlock()
		if out != nil {
			return out, nil
		}
		// Evicted between the call and the read — the cache refilled past
		// its limit. Once more; a second miss is not worth chasing.
	}
	return nil, fmt.Errorf("%w: sealing key %s: the key cache could not hold it", ErrSealFailed, rec.ID)
}

// rememberKEK records key as what root opens for rec — for a key this process
// just minted or rewrapped, so the next keyring does not open it again.
func rememberKEK(root Root, rec KEKRecord, key []byte) {
	remember(kekCacheID(root, rec), rec.ID, append([]byte(nil), key...))
}

func remember(id, kekID string, key []byte) {
	kekCache.Lock()
	defer kekCache.Unlock()
	if _, dup := kekCache.entries[id]; dup {
		zero(key)
		return
	}
	if len(kekCache.entries) >= kekCacheLimit {
		for _, e := range kekCache.entries {
			zero(e.key)
		}
		kekCache.entries = map[string]kekCacheEntry{}
		kekCache.byKEK = map[string][]string{}
	}
	if len(kekCache.failed) >= kekCacheLimit {
		kekCache.failed = map[string]kmsFailure{}
	}
	kekCache.entries[id] = kekCacheEntry{key: key, kekID: kekID}
	kekCache.byKEK[kekID] = append(kekCache.byKEK[kekID], id)
}

// forgetKEK wipes and drops every entry opened for the key kekID.
func forgetKEK(kekID string) {
	kekCache.Lock()
	defer kekCache.Unlock()
	for _, id := range kekCache.byKEK[kekID] {
		if e, ok := kekCache.entries[id]; ok {
			zero(e.key)
			delete(kekCache.entries, id)
		}
	}
	delete(kekCache.byKEK, kekID)
}

// cachedLegacyKey derives the pre-envelope construction's key for root, once
// per process. Its salt is never destroyed, so nothing evicts it but the limit.
// The returned slice is shared and must not be modified.
func cachedLegacyKey(root string, salt []byte) []byte {
	id := rootkey.CacheID("secretbroker/legacy", root, string(salt))
	kekCache.Lock()
	key, ok := kekCache.legacy[id]
	kekCache.Unlock()
	if ok {
		return key
	}
	key = deriveKey(root, salt)
	kekCache.Lock()
	defer kekCache.Unlock()
	if prev, dup := kekCache.legacy[id]; dup {
		return prev
	}
	if len(kekCache.legacy) >= kekCacheLimit {
		kekCache.legacy = map[string][]byte{}
	}
	kekCache.legacy[id] = key
	return key
}

// ForgetOpenedKeys wipes and drops every key this process has derived or
// unwrapped, and every remembered KMS failure, so the next open derives — or
// asks the KMS — afresh, as a new process would. Keyrings already open keep
// the keys they hold.
func ForgetOpenedKeys() {
	kekCache.Lock()
	defer kekCache.Unlock()
	for _, e := range kekCache.entries {
		zero(e.key)
	}
	kekCache.entries = map[string]kekCacheEntry{}
	kekCache.byKEK = map[string][]string{}
	kekCache.failed = map[string]kmsFailure{}
}
