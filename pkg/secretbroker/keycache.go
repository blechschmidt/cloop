package secretbroker

// Keys derived in this process, kept for the life of the process (Task 20425).
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
// Entries are indexed by an HMAC under a key this process drew at random
// (rootkey.CacheID), never by the root itself. Retiring a key evicts and
// wipes every entry derived for it: retirement destroys the salt in the
// registry, and a process that kept a derived copy would have shredded
// everything but its own memory.

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/blechschmidt/cloop/pkg/rootkey"
)

// kekDerivations counts the derivations the cache did not answer, so a test
// can tell a cached key from one derived again.
var kekDerivations atomic.Int64

// kekCacheLimit bounds the cache. A registry holds a handful of live keys and a
// hub two roots, so this is never reached by a working hub; it exists so that
// rows written into the database by someone else cannot grow the hub's memory
// without bound. Past it the cache is emptied and refilled.
const kekCacheLimit = 1024

type kekCacheEntry struct {
	key   []byte // nil: the root does not derive the record
	kekID string
}

var kekCache = struct {
	sync.Mutex
	entries map[string]kekCacheEntry
	byKEK   map[string][]string // key id -> cache ids, for eviction on retirement
	legacy  map[string][]byte
}{
	entries: map[string]kekCacheEntry{},
	byKEK:   map[string][]string{},
	legacy:  map[string][]byte{},
}

func kekCacheID(root string, rec KEKRecord) string {
	return rootkey.CacheID("secretbroker/kek", root, rec.ID, rec.Salt, string(rec.CheckValue))
}

// cachedDeriveKEK is deriveKEK through the cache. The caller owns the returned
// slice.
func cachedDeriveKEK(root string, rec KEKRecord) ([]byte, error) {
	if _, err := derivable(rec); err != nil {
		return nil, err
	}
	id := kekCacheID(root, rec)
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
		rememberKEK(root, rec, key)
	case errors.Is(err, ErrKeyUnavailable):
		remember(id, rec.ID, nil)
	}
	return key, err
}

// rememberKEK records key as what root derives for rec — for a key this process
// just minted, so the next keyring does not derive it again.
func rememberKEK(root string, rec KEKRecord, key []byte) {
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
	kekCache.entries[id] = kekCacheEntry{key: key, kekID: kekID}
	kekCache.byKEK[kekID] = append(kekCache.byKEK[kekID], id)
}

// forgetKEK wipes and drops every entry derived for the key kekID.
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
