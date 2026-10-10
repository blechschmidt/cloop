// Package auditcheckpoint writes the head of every audit chain somewhere the
// database cannot reach, and checks a chain against what was written
// (Task 20404).
//
// # The gap it closes
//
// audit_events is hash-chained, so editing or deleting a row anywhere in the
// middle breaks the chain from that point. Deleting the newest rows does not:
// the survivors are a shorter chain that verifies, and nothing inside the
// database can tell it from a quiet one — an attacker who can delete rows can
// also delete or rewrite anything else the database holds about them. The
// threat model conceded exactly that, and asked operators to remember to cron
// an export.
//
// A checkpoint is the cheap version of that export, taken by the hub itself.
// Every few minutes the cluster leader writes one record per chain: the newest
// row's id and hash, the row count, the latest prune anchor, the time and the
// member that wrote it. The record goes to a file outside .cloop/, fsynced,
// and/or to stderr as one JSON line for a container platform to ship off the
// box. Later, `cloop hub audit verify --checkpoints <file>` asks each recorded
// head whether the chain still holds it, and names what it finds: a tail
// truncated after an id a checkpoint saw, a database restored from a backup
// older than a checkpoint, a row rewritten under one.
//
// # Why the records are sealed
//
// A record anybody could write proves nothing: whoever truncated the chain
// would write a fresh record agreeing with the truncation. So each record is
// MACed under a key derived from CLOOP_SECRET_KEY with a label of its own —
// nothing in state.db can produce it — and stamped with that key's fingerprint,
// so a record sealed under a rotated key reads as "a different key" rather than
// as a forgery. A hub with no CLOOP_SECRET_KEY writes unsigned records, which
// still pin each head against an attacker who cannot write the checkpoint
// file, and `cloop hub doctor` says they are unsigned.
//
// The seal cannot stop records being deleted from the file. That is what
// keeping the file off the box, or shipping the stderr copy, is for; the
// doctor reports a newest checkpoint that has gone stale.
package auditcheckpoint

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Kind marks a checkpoint record, so one can be picked out of a log stream.
const Kind = "cloop.audit.checkpoint"

// Version is the record format.
const Version = 1

// EnvKey is the variable the sealing key is derived from: the same
// CLOOP_SECRET_KEY the secret broker seals credentials under
// (secretbroker.EnvPassphraseKey), so a hub has one root secret, not two.
const EnvKey = "CLOOP_SECRET_KEY"

// Why a record was written.
const (
	// ReasonInterval: the leader's periodic checkpoint for a window.
	ReasonInterval = "interval"
	// ReasonShutdown: the leader shutting down cleanly.
	ReasonShutdown = "shutdown"
)

// Chain roles, as the records name them.
const (
	ChainControlPlane = "control-plane"
	ChainProject      = "project"
)

// Record is one checkpoint: where one chain ended, at one moment.
//
// Time is a string rather than a time.Time so the sealed bytes are exactly the
// bytes on disk; a round trip through a time value is one place for a
// formatting difference to turn a valid seal into a refused one.
type Record struct {
	Kind    string `json:"kind"`
	Version int    `json:"v"`

	// Chain is ChainControlPlane or ChainProject; Path the absolute path of
	// the database, which is how a record is matched to a chain.
	Chain string `json:"chain"`
	Path  string `json:"path"`

	// Reason is ReasonInterval or ReasonShutdown. Window is the interval
	// window an interval record belongs to: the Unix time divided by the
	// interval, so every member numbers windows alike.
	Reason string `json:"reason"`
	Window int64  `json:"window,omitempty"`

	// LastID and LastRowHash are the newest row; Rows how many the table
	// held. All zero for an empty chain.
	LastID      int64  `json:"last_id"`
	LastRowHash string `json:"last_row_hash,omitempty"`
	Rows        int64  `json:"rows"`

	// The newest prune anchor, if the chain was ever pruned.
	AnchorID        int64  `json:"anchor_id,omitempty"`
	AnchorThroughID int64  `json:"anchor_through_id,omitempty"`
	AnchorHash      string `json:"anchor_hash,omitempty"`
	// AnchorVerified says the hub read that anchor's archive itself and found
	// it the intact chain the anchor ends in. Seeing an anchor in the database
	// proves only that one is there — whoever can delete rows can write one —
	// so this, under the seal, is what lets a later verifier accept the
	// prune when the archive has since moved out of reach.
	AnchorVerified bool `json:"anchor_verified,omitempty"`

	// Time is when the head was read (RFC 3339, UTC); Member the hub member
	// that read it.
	Time   string `json:"time"`
	Member string `json:"member,omitempty"`

	// KeyFingerprint names the key Seal was computed under. Both are empty
	// on an unsigned record.
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
	Seal           string `json:"seal,omitempty"`
}

// At parses Time, returning the zero time when it does not parse.
func (r Record) At() time.Time {
	t, err := time.Parse(time.RFC3339Nano, r.Time)
	if err != nil {
		return time.Time{}
	}
	return t
}

// HeadRecord is the unsealed record of head, read at at.
//
// Strings are made valid UTF-8 before they are sealed: JSON replaces invalid
// bytes on the way out, and a seal over bytes the file no longer holds would
// refuse every record of a hub whose path is not UTF-8.
func HeadRecord(head statedb.AuditHead, chain, path, reason string, window int64, member string, at time.Time) Record {
	r := Record{
		Kind:        Kind,
		Version:     Version,
		Chain:       chain,
		Path:        ValidPath(path),
		Reason:      reason,
		Window:      window,
		LastID:      head.LastID,
		LastRowHash: head.LastRowHash,
		Rows:        head.Rows,
		Time:        FormatTime(at),
		Member:      strings.ToValidUTF8(member, "\uFFFD"),
	}
	if a := head.Anchor; a != nil {
		r.AnchorID, r.AnchorThroughID, r.AnchorHash = a.ID, a.PrunedThroughID, a.AnchorHash
	}
	return r
}

// ValidPath is path as a record names it: cleaned, and valid UTF-8.
func ValidPath(path string) string {
	return strings.ToValidUTF8(filepath.Clean(path), "\uFFFD")
}

// Signed reports whether the record carries a seal at all.
func (r Record) Signed() bool { return r.Seal != "" || r.KeyFingerprint != "" }

// FormatTime renders t the way Record.Time holds it.
func FormatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// canonical is what the seal covers: every field but the seal, in a fixed
// order, strings quoted so no field can bleed into the next. JSON is not used
// because its encoding is not unique — a reordered or re-escaped object would
// be the same record with a different seal.
func (r Record) canonical() []byte {
	var b strings.Builder
	b.WriteString("cloop-audit-checkpoint/v1\n")
	str := func(name, v string) {
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(strconv.Quote(v))
		b.WriteByte('\n')
	}
	num := func(name string, v int64) {
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(strconv.FormatInt(v, 10))
		b.WriteByte('\n')
	}
	str("kind", r.Kind)
	num("v", int64(r.Version))
	str("chain", r.Chain)
	str("path", r.Path)
	str("reason", r.Reason)
	num("window", r.Window)
	num("last_id", r.LastID)
	str("last_row_hash", r.LastRowHash)
	num("rows", r.Rows)
	num("anchor_id", r.AnchorID)
	num("anchor_through_id", r.AnchorThroughID)
	str("anchor_hash", r.AnchorHash)
	verified := int64(0)
	if r.AnchorVerified {
		verified = 1
	}
	num("anchor_verified", verified)
	str("time", r.Time)
	str("member", r.Member)
	str("key_fingerprint", r.KeyFingerprint)
	return []byte(b.String())
}

// ── the key ──────────────────────────────────────────────────────────────────

// keyLabel separates this key from every other use of CLOOP_SECRET_KEY: it is
// the PBKDF2 salt, so the derived key is useless for anything else and the
// secret broker's keys are useless for this.
const keyLabel = "cloop/audit-checkpoint/v1"

// fingerprintLabel derives the fingerprint from the key, so the fingerprint
// names the key without being a way to compute it.
const fingerprintLabel = "cloop/audit-checkpoint/key-fingerprint/v1"

// kdfIterations is the PBKDF2-HMAC-SHA256 work factor. Records are meant to
// travel through log pipelines, and each one is a test of a guessed
// passphrase; a key typed by a human must cost real work per guess. Derived
// once per process and cached, so the cost is paid once. A variable so tests
// can lower it.
var kdfIterations = 600_000

// ErrNoKey is returned when there is no CLOOP_SECRET_KEY to derive from.
var ErrNoKey = errors.New("auditcheckpoint: " + EnvKey + " is not set")

// Key seals and checks records.
type Key struct {
	raw         []byte
	fingerprint string
}

// Fingerprint names the key: 16 hex characters, stamped on every record it
// seals.
func (k *Key) Fingerprint() string {
	if k == nil {
		return ""
	}
	return k.fingerprint
}

var keyCache sync.Map // cache id -> *Key

// DeriveKey derives the checkpoint key from passphrase.
func DeriveKey(passphrase string) (*Key, error) {
	if passphrase == "" {
		return nil, ErrNoKey
	}
	iter := kdfIterations
	id := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%s", keyLabel, iter, passphrase)))
	cacheID := hex.EncodeToString(id[:])
	if k, ok := keyCache.Load(cacheID); ok {
		return k.(*Key), nil
	}
	raw, err := pbkdf2.Key(sha256.New, passphrase, []byte(keyLabel), iter, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("auditcheckpoint: derive key: %w", err)
	}
	fp := sha256.Sum256(append([]byte(fingerprintLabel+"\x00"), raw...))
	k := &Key{raw: raw, fingerprint: hex.EncodeToString(fp[:8])}
	actual, _ := keyCache.LoadOrStore(cacheID, k)
	return actual.(*Key), nil
}

// KeyFromEnv derives the key from CLOOP_SECRET_KEY, returning ErrNoKey when it
// is not set.
func KeyFromEnv() (*Key, error) { return DeriveKey(os.Getenv(EnvKey)) }

// seal computes the record's seal under k.
func (k *Key) seal(r Record) []byte {
	m := hmac.New(sha256.New, k.raw)
	m.Write(r.canonical())
	return m.Sum(nil)
}

// Seal stamps r with k's fingerprint and seal. A nil key leaves r unsigned.
func (k *Key) Seal(r *Record) {
	if k == nil || r == nil {
		return
	}
	r.KeyFingerprint = k.fingerprint
	r.Seal = hex.EncodeToString(k.seal(*r))
}

// SealStatus is what a record's seal says about it.
type SealStatus string

const (
	// SealValid: sealed under the key checking it, and the seal verifies.
	SealValid SealStatus = "valid"
	// SealUnsigned: written by a hub with no key.
	SealUnsigned SealStatus = "unsigned"
	// SealUnchecked: sealed, but there is no key here to check it with.
	SealUnchecked SealStatus = "unchecked"
	// SealForeignKey: sealed under a different key than the one checking it
	// — a rotated CLOOP_SECRET_KEY, or another hub's record.
	SealForeignKey SealStatus = "foreign-key"
	// SealBad: claims the checking key and does not verify under it, or is
	// half a seal. Edited or forged; such a record is refused.
	SealBad SealStatus = "bad"
)

// Check reports what r's seal says, checked under k (which may be nil).
func Check(r Record, k *Key) SealStatus {
	switch {
	case r.Seal == "" && r.KeyFingerprint == "":
		return SealUnsigned
	case r.Seal == "" || r.KeyFingerprint == "":
		return SealBad
	case k == nil:
		return SealUnchecked
	case r.KeyFingerprint != k.fingerprint:
		return SealForeignKey
	}
	got, err := hex.DecodeString(r.Seal)
	if err != nil || !hmac.Equal(got, k.seal(r)) {
		return SealBad
	}
	return SealValid
}
