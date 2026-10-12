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
//
// # Restores
//
// Restoring a backup does to a chain what deleting its tail while the hub
// keeps writing does, so `cloop db restore` writes a restore record (Task
// 20410): a record sealed like any other, with a canonical form of its own,
// naming the backup, the head the chain was restored to, the newest checkpoint
// superseded, who and why, and pinning the audit.restored row the restore
// appended. A verifier holding the key accepts it as the explanation for the
// checkpoints sealed before it that saw past the restored head — see
// restore.go — and nothing else does: an unsigned or forged record is refused.
package auditcheckpoint

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/rootkey"
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
	// ReasonRestore: `cloop db restore` put a backup in place of the
	// database; the record carries a Restore (Task 20410).
	ReasonRestore = "restore"
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

	// Restore says what a restore record records; nil on every other record.
	Restore *Restore `json:"restore,omitempty"`

	// KeyFingerprint names the key Seal was computed under. Both are empty
	// on an unsigned record.
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
	Seal           string `json:"seal,omitempty"`
}

// Restore is what a restore record says happened (Task 20410): which backup
// replaced the database, the head its chain was restored to, the newest
// checkpoint that saw history the backup does not hold, and who did it and
// why.
//
// `cloop db restore` writes it after the restore has appended its own
// audit.restored row, so the record's head — Record.LastID and LastRowHash — is
// that row. A chain cut back to the restored head afterwards, or rebuilt from
// it with other rows, disagrees with the record exactly as it would with any
// checkpoint.
//
// Only a record sealed under the key the verifier holds accounts for anything:
// it is what turns "the chain lost the rows these checkpoints saw" from a
// finding into an acknowledged restore, so whoever can write the database or
// the checkpoint file must not be able to write one. The seal is computed under
// the checkpoint key, which nothing in state.db can produce.
type Restore struct {
	// BackupSHA256 is the restored file's digest; BackupTime when the backup
	// was taken, from its sidecar ("" when it had none). Sidecar says what
	// vouched for the file: "sealed" when its sidecar's seal verified under
	// the hub's key, "unchecked" when it was restored with --allow-unsealed,
	// "skipped" with --skip-checksum.
	BackupSHA256 string `json:"backup_sha256"`
	BackupTime   string `json:"backup_time,omitempty"`
	Sidecar      string `json:"sidecar"`

	// RestoredID, RestoredRowHash and RestoredTime are the newest row the
	// backup holds: where the chain was restored to. All zero for a backup
	// whose chain was empty.
	RestoredID      int64  `json:"restored_id"`
	RestoredRowHash string `json:"restored_row_hash,omitempty"`
	RestoredTime    string `json:"restored_time,omitempty"`

	// SupersededID, SupersededRowHash and SupersededTime are the newest
	// checkpoint the restore found that saw an id past RestoredID: the far end
	// of the history the restore gave up, as far as any checkpoint recorded
	// it. Zero when none did.
	SupersededID      int64  `json:"superseded_id,omitempty"`
	SupersededRowHash string `json:"superseded_row_hash,omitempty"`
	SupersededTime    string `json:"superseded_time,omitempty"`

	// Actor restored it, for Reason, which the command requires.
	Actor  string `json:"actor"`
	Reason string `json:"reason"`

	// SecretLoss names the sealing keys the restore went ahead without,
	// under --accept-secret-loss: whatever the backup holds sealed under them
	// can no longer be opened.
	SecretLoss []string `json:"secret_loss,omitempty"`
}

// LostEvents is how many events the superseded checkpoint saw past the
// restored head — the history the restore gave up, as far as a checkpoint saw
// it. Events written after that checkpoint and before the restore are not
// counted: nothing outside the database recorded them.
func (x Restore) LostEvents() int64 {
	if x.SupersededID > x.RestoredID {
		return x.SupersededID - x.RestoredID
	}
	return 0
}

// IsRestore reports whether r claims to be a restore record. A record that
// claims it by its reason without carrying a Restore, or carries one under
// another reason, was not written by `cloop db restore`.
func (r Record) IsRestore() bool { return r.Reason == ReasonRestore || r.Restore != nil }

// RestoreRecord is the unsealed restore record for path's chain, whose head —
// read after the restore appended its audit.restored row — is head.
func RestoreRecord(head statedb.AuditHead, chain, path, member string, at time.Time, x Restore) Record {
	r := HeadRecord(head, chain, path, ReasonRestore, 0, member, at)
	valid := func(s string) string { return strings.ToValidUTF8(s, "\uFFFD") }
	x.Actor, x.Reason, x.Sidecar = valid(x.Actor), valid(x.Reason), valid(x.Sidecar)
	loss := make([]string, len(x.SecretLoss))
	for i, k := range x.SecretLoss {
		loss[i] = valid(k)
	}
	if len(loss) == 0 {
		loss = nil
	}
	x.SecretLoss = loss
	r.Restore = &x
	return r
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
//
// A restore record has a canonical form of its own, with a different first
// line: a seal over a checkpoint can never verify as a restore record's, or the
// other way round, so neither can be made by adding or stripping a Restore.
// Every other record's form is unchanged since version 1.
func (r Record) canonical() []byte {
	var b strings.Builder
	if r.Restore != nil {
		b.WriteString("cloop-audit-restore/v1\n")
	} else {
		b.WriteString("cloop-audit-checkpoint/v1\n")
	}
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
	if x := r.Restore; x != nil {
		str("restore.backup_sha256", x.BackupSHA256)
		str("restore.backup_time", x.BackupTime)
		str("restore.sidecar", x.Sidecar)
		num("restore.restored_id", x.RestoredID)
		str("restore.restored_row_hash", x.RestoredRowHash)
		str("restore.restored_time", x.RestoredTime)
		num("restore.superseded_id", x.SupersededID)
		str("restore.superseded_row_hash", x.SupersededRowHash)
		str("restore.superseded_time", x.SupersededTime)
		str("restore.actor", x.Actor)
		str("restore.reason", x.Reason)
		num("restore.secret_loss", int64(len(x.SecretLoss)))
		for _, k := range x.SecretLoss {
			str("restore.secret_loss.key", k)
		}
	}
	str("key_fingerprint", r.KeyFingerprint)
	return []byte(b.String())
}

// ── the key ──────────────────────────────────────────────────────────────────

// The key is PBKDF2-HMAC-SHA256 over CLOOP_SECRET_KEY under a label of its
// own — so it is useless for anything else and the secret broker's keys are
// useless for this — and its fingerprint is derived from it, so the
// fingerprint names the key without being a way to compute it. pkg/rootkey
// holds the derivation, because the secret broker names its roots by the same
// fingerprint and cannot import this package.

// kdfIterations is the PBKDF2-HMAC-SHA256 work factor. Records are meant to
// travel through log pipelines, and each one is a test of a guessed
// passphrase; a key typed by a human must cost real work per guess. Derived
// once per process and cached, so the cost is paid once. A variable so tests
// can lower it.
var kdfIterations = rootkey.CheckpointKDFIterations

// ErrNoKey is returned when there is no CLOOP_SECRET_KEY to derive from.
var ErrNoKey = errors.New("auditcheckpoint: " + EnvKey + " is not set")

// Key seals and checks records.
type Key struct {
	raw         []byte
	fingerprint string
	// previous checks records sealed under the root being replaced, while a
	// change of root is in progress (Task 20425). It never seals.
	previous *Key
}

// Fingerprint names the key: 16 hex characters, stamped on every record it
// seals.
func (k *Key) Fingerprint() string {
	if k == nil {
		return ""
	}
	return k.fingerprint
}

// DeriveKey derives the checkpoint key from passphrase. pkg/rootkey caches the
// derivation, so the cost is paid once per process.
func DeriveKey(passphrase string) (*Key, error) {
	if passphrase == "" {
		return nil, ErrNoKey
	}
	raw, fp, err := rootkey.DeriveCheckpointKey(passphrase, kdfIterations)
	if err != nil {
		return nil, fmt.Errorf("auditcheckpoint: derive key: %w", err)
	}
	return &Key{raw: raw, fingerprint: fp}, nil
}

// KeyForRoots derives the key from the current root and, when previous is set,
// lets it also check records sealed under the previous root: a hub mid-way
// through a change of root wrote its checkpoints under both, and they all
// still vouch for the chain. Only the current root seals.
func KeyForRoots(current, previous string) (*Key, error) {
	k, err := DeriveKey(current)
	if err != nil || previous == "" {
		return k, err
	}
	p, err := DeriveKey(previous)
	if err != nil {
		return nil, err
	}
	k.previous = p
	return k, nil
}

// KeyFromRoots derives the key from the hub's roots (pkg/rootkey): the file,
// the systemd credential or the environment, current and previous. ErrNoKey
// when no current root is configured; a root source that is configured and
// refused is an error of its own.
func KeyFromRoots() (*Key, error) {
	roots, err := rootkey.Resolve()
	if err != nil {
		return nil, err
	}
	return KeyForRoots(roots.Current.Value, roots.Previous.Value)
}

// PreviousFingerprint names the previous root this key also checks under; ""
// when it checks under the current one only.
func (k *Key) PreviousFingerprint() string {
	if k == nil || k.previous == nil {
		return ""
	}
	return k.previous.fingerprint
}

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
		if k.previous != nil && r.KeyFingerprint == k.previous.fingerprint {
			// Sealed before the root changed: as good as one sealed after, for
			// as long as the previous root is configured to check it.
			return Check(r, k.previous)
		}
		return SealForeignKey
	}
	got, err := hex.DecodeString(r.Seal)
	if err != nil || !hmac.Equal(got, k.seal(r)) {
		return SealBad
	}
	return SealValid
}
