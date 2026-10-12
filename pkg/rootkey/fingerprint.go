package rootkey

// The name of a root.
//
// The hub has named CLOOP_SECRET_KEY one way since Task 20404: the fingerprint
// of the audit checkpoint key it derives, stamped on every checkpoint, every
// sealed backup sidecar and every key escrow, and printed by `cloop hub
// doctor`. A key-encryption key records the root it was derived from under the
// same name, and a hub cluster member advertises the roots it holds under it,
// so "the escrow on record holds the root every member runs on" is a
// comparison of three strings that were always computed the same way.
//
// The derivation lives here rather than in pkg/auditcheckpoint because the
// secret broker needs it and pkg/auditcheckpoint depends on the broker (through
// pkg/config). pkg/auditcheckpoint derives its key through DeriveCheckpointKey,
// so the two cannot drift.

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
)

// CheckpointKDFIterations is the PBKDF2-HMAC-SHA256 work factor of the audit
// checkpoint key, and so of every fingerprint: a record carrying one travels
// through log pipelines, and each is a test of a guessed key.
const CheckpointKDFIterations = 600_000

// The labels are a wire format: every checkpoint and escrow ever written names
// its key through them.
const (
	checkpointKeyLabel = "cloop/audit-checkpoint/v1"
	fingerprintLabel   = "cloop/audit-checkpoint/key-fingerprint/v1"
)

// ErrNoKey is returned when there is no value to derive from.
var ErrNoKey = errors.New("rootkey: no key to derive from")

type checkpointEntry struct {
	raw         []byte
	fingerprint string
}

var (
	cacheOnce sync.Once
	// cacheMAC keys the cache. Entries are found by an HMAC of the value under
	// a key this process drew at random, so the cache index is not itself a
	// fast, offline-testable hash of the root.
	cacheMAC []byte

	checkpointMu    sync.Mutex
	checkpointCache = map[string]checkpointEntry{}
)

// CacheID is the process-local index of a value under a purpose label, for the
// derivation caches here and in pkg/secretbroker.
func CacheID(purpose string, parts ...string) string {
	cacheOnce.Do(func() {
		cacheMAC = make([]byte, 32)
		if _, err := rand.Read(cacheMAC); err != nil {
			// crypto/rand does not fail on a supported platform; if it does,
			// a fixed key still indexes correctly, it is only less private.
			cacheMAC = []byte("cloop-rootkey-cache-fallback-key")
		}
	})
	m := hmac.New(sha256.New, cacheMAC)
	m.Write([]byte(purpose))
	for _, p := range parts {
		m.Write([]byte{0})
		m.Write([]byte(strconv.Itoa(len(p))))
		m.Write([]byte{0})
		m.Write([]byte(p))
	}
	return hex.EncodeToString(m.Sum(nil))
}

// DeriveCheckpointKey derives the audit checkpoint key from value at the given
// work factor, and the fingerprint that names value. The result is cached for
// the life of the process: the derivation costs a tenth of a second, and every
// keyring, checkpoint and sidecar check asks for it. The caller owns the
// returned slice.
//
// iterations is a parameter so pkg/auditcheckpoint's tests can lower it for
// themselves; everything else passes CheckpointKDFIterations.
func DeriveCheckpointKey(value string, iterations int) ([]byte, string, error) {
	if value == "" {
		return nil, "", ErrNoKey
	}
	if iterations <= 0 {
		return nil, "", fmt.Errorf("rootkey: %d iterations", iterations)
	}
	id := CacheID("checkpoint", strconv.Itoa(iterations), value)
	checkpointMu.Lock()
	e, ok := checkpointCache[id]
	checkpointMu.Unlock()
	if !ok {
		raw, err := pbkdf2.Key(sha256.New, value, []byte(checkpointKeyLabel), iterations, sha256.Size)
		if err != nil {
			return nil, "", fmt.Errorf("rootkey: derive the checkpoint key: %w", err)
		}
		fp := sha256.Sum256(append([]byte(fingerprintLabel+"\x00"), raw...))
		e = checkpointEntry{raw: raw, fingerprint: hex.EncodeToString(fp[:8])}
		checkpointMu.Lock()
		if prev, dup := checkpointCache[id]; dup {
			e = prev
		} else {
			checkpointCache[id] = e
		}
		checkpointMu.Unlock()
	}
	return append([]byte(nil), e.raw...), e.fingerprint, nil
}

// Fingerprint names value the way every checkpoint, sidecar, escrow, sealing
// key and hub member does: 16 hex characters.
func Fingerprint(value string) (string, error) {
	_, fp, err := DeriveCheckpointKey(value, CheckpointKDFIterations)
	return fp, err
}

// Fingerprints names the configured roots; "" for a slot that is not set.
func (r Roots) Fingerprints() (current, previous string, err error) {
	if r.Current.Set() {
		if current, err = Fingerprint(r.Current.Value); err != nil {
			return "", "", err
		}
	}
	if r.Previous.Set() {
		if previous, err = Fingerprint(r.Previous.Value); err != nil {
			return "", "", err
		}
	}
	return current, previous, nil
}
