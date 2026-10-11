package dbbackup

// The backup manifest: what a backup depends on, sealed (Task 20410).
//
// The sidecar used to carry a SHA-256 and nothing else that mattered, and
// nothing vouched for the SHA-256 itself: edit a backup, recompute its digest,
// write it into the sidecar, and restore accepted it. It also knew nothing of
// the sealing keys — a restore checked integrity, digest and schema, swapped
// the file in, and only then did the hub refuse to start because
// CLOOP_SECRET_KEY could not derive the backup's KEKs.
//
// So the sidecar now records what a restore needs to know before it swaps
// anything — the KEKs the backup's sealed rows depend on, with how many rows
// each seals, and where its audit chain ends — and the whole sidecar is sealed:
// an HMAC under a key derived from CLOOP_SECRET_KEY with a label of its own,
// the construction the audit checkpoints use. Nothing in a database, and
// nothing an attacker holding only the backup and its sidecar can compute,
// produces that seal. It is stamped with CLOOP_SECRET_KEY's fingerprint — the
// one every checkpoint carries — so a sidecar sealed under another key reads
// as exactly that, rather than as a forgery.

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditcheckpoint"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ManifestVersion is the manifest format this build writes.
const ManifestVersion = 1

// EnvKey is the variable the manifest seal is derived from: the secret
// broker's passphrase, the hub's one root secret.
const EnvKey = auditcheckpoint.EnvKey

// Key states a manifest names beyond the registry's own (primary, active,
// retired): the pre-envelope construction, and a key id rows name that the
// registry does not hold.
const (
	KeyStateLegacy  = "legacy"
	KeyStateUnknown = "unknown"
)

// ManifestKey is one sealing key a backup depends on: in its registry, or
// named by its sealed rows.
type ManifestKey struct {
	ID    string `json:"id"`
	State string `json:"state"`
	// Rows counts the rows sealed under it, by sealed set.
	Rows map[string]int `json:"rows,omitempty"`
}

// Total is how many rows are sealed under the key.
func (k ManifestKey) Total() int {
	n := 0
	for _, c := range k.Rows {
		n += c
	}
	return n
}

// ManifestChain is where a backup's audit chain ends.
type ManifestChain struct {
	LastID          int64  `json:"last_id"`
	LastRowHash     string `json:"last_row_hash,omitempty"`
	LastTime        string `json:"last_time,omitempty"`
	FirstID         int64  `json:"first_id,omitempty"`
	Rows            int64  `json:"rows"`
	AnchorID        int64  `json:"anchor_id,omitempty"`
	AnchorThroughID int64  `json:"anchor_through_id,omitempty"`
	AnchorHash      string `json:"anchor_hash,omitempty"`
}

// manifestKeys is the keys facts depend on: every registry entry, and every
// key id a sealed row names, sorted by id.
func manifestKeys(facts statedb.SealedFacts) []ManifestKey {
	byID := map[string]*ManifestKey{}
	get := func(id, state string) *ManifestKey {
		k := byID[id]
		if k == nil {
			k = &ManifestKey{ID: id, State: state}
			byID[id] = k
		}
		return k
	}
	for _, rec := range facts.KEKs {
		state := rec.State
		if rec.Salt == "" {
			state = "retired"
		}
		get(rec.ID, state)
	}
	for set, counts := range facts.Rows {
		for id, n := range counts {
			state := KeyStateUnknown
			if id == statedb.LegacyKeyID {
				state = KeyStateLegacy
			}
			k := get(id, state)
			if k.Rows == nil {
				k.Rows = map[string]int{}
			}
			k.Rows[set] += n
		}
	}
	out := make([]ManifestKey, 0, len(byID))
	for _, k := range byID {
		out = append(out, *k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// manifestChain is head as the manifest records it.
func manifestChain(head statedb.AuditHead) *ManifestChain {
	c := &ManifestChain{
		LastID:      head.LastID,
		LastRowHash: head.LastRowHash,
		FirstID:     head.FirstID,
		Rows:        head.Rows,
	}
	if !head.LastTimestamp.IsZero() {
		c.LastTime = auditcheckpoint.FormatTime(head.LastTimestamp)
	}
	if a := head.Anchor; a != nil {
		c.AnchorID, c.AnchorThroughID, c.AnchorHash = a.ID, a.PrunedThroughID, a.AnchorHash
	}
	return c
}

// canonical is what the seal covers: every field of the sidecar but the seal,
// in a fixed order, strings quoted so no field bleeds into the next.
func (m *Metadata) canonical() []byte {
	var b strings.Builder
	b.WriteString("cloop-db-backup-manifest/v1\n")
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
	str("source", m.Source)
	str("backup", m.Backup)
	str("created_at", m.CreatedAt.UTC().Format(time.RFC3339Nano))
	num("size_bytes", m.SizeBytes)
	str("sha256", m.SHA256)
	num("duration_ms", m.DurationMS)
	num("schema_version", int64(m.SchemaVersion))
	str("cloop_version", m.CloopVersion)
	num("manifest", int64(m.Manifest))
	num("keys", int64(len(m.Keys)))
	for _, k := range m.Keys {
		str("key.id", k.ID)
		str("key.state", k.State)
		sets := make([]string, 0, len(k.Rows))
		for set := range k.Rows {
			sets = append(sets, set)
		}
		sort.Strings(sets)
		num("key.sets", int64(len(sets)))
		for _, set := range sets {
			str("key.set", set)
			num("key.set.rows", int64(k.Rows[set]))
		}
	}
	if c := m.Chain; c != nil {
		num("chain", 1)
		num("chain.last_id", c.LastID)
		str("chain.last_row_hash", c.LastRowHash)
		str("chain.last_time", c.LastTime)
		num("chain.first_id", c.FirstID)
		num("chain.rows", c.Rows)
		num("chain.anchor_id", c.AnchorID)
		num("chain.anchor_through_id", c.AnchorThroughID)
		str("chain.anchor_hash", c.AnchorHash)
	} else {
		num("chain", 0)
	}
	str("key_fingerprint", m.KeyFingerprint)
	return []byte(b.String())
}

// SealState is what a sidecar's seal says about it.
type SealState string

const (
	// SealValid: sealed under the key checking it, and the seal verifies.
	SealValid SealState = "valid"
	// SealUnsigned: written without a key — by a hub with no
	// CLOOP_SECRET_KEY, or by a build that did not seal sidecars.
	SealUnsigned SealState = "unsigned"
	// SealUnchecked: sealed, and there is no key here to check it with.
	SealUnchecked SealState = "unchecked"
	// SealForeignKey: sealed under another CLOOP_SECRET_KEY than the one
	// checking it.
	SealForeignKey SealState = "foreign-key"
	// SealBad: claims the checking key and does not verify under it, or is
	// half a seal. The sidecar, or the backup with it, was edited.
	SealBad SealState = "bad"
)

// validUTF8 makes every string in m valid UTF-8, in place. The seal covers the
// strings as sealed and the file holds them as JSON wrote them, and JSON
// replaces invalid bytes: one key id or path that is not UTF-8 — a row anybody
// with the database can write — would otherwise turn every later backup's seal
// into a refusal.
func (m *Metadata) validUTF8() {
	v := func(s string) string { return strings.ToValidUTF8(s, "\uFFFD") }
	m.Source, m.Backup, m.SHA256, m.CloopVersion = v(m.Source), v(m.Backup), v(m.SHA256), v(m.CloopVersion)
	for i, k := range m.Keys {
		k.ID, k.State = v(k.ID), v(k.State)
		if len(k.Rows) > 0 {
			rows := make(map[string]int, len(k.Rows))
			for set, n := range k.Rows {
				rows[v(set)] += n
			}
			k.Rows = rows
		}
		m.Keys[i] = k
	}
	if c := m.Chain; c != nil {
		c.LastRowHash, c.LastTime, c.AnchorHash = v(c.LastRowHash), v(c.LastTime), v(c.AnchorHash)
	}
}

// seal stamps m with key's fingerprint and seal; an empty key leaves m
// unsigned. It makes m's strings valid UTF-8 first: see validUTF8.
func (m *Metadata) seal(key string) error {
	m.validUTF8()
	m.KeyFingerprint, m.Seal = "", ""
	if key == "" {
		return nil
	}
	k, err := deriveManifestKey(key)
	if err != nil {
		return err
	}
	m.KeyFingerprint = k.fingerprint
	m.Seal = hex.EncodeToString(k.sum(m.canonical()))
	return nil
}

// Check reports what m's seal says, checked under key ("" when this process
// has none).
func (m *Metadata) Check(key string) SealState {
	switch {
	case m.Seal == "" && m.KeyFingerprint == "":
		return SealUnsigned
	case m.Seal == "" || m.KeyFingerprint == "":
		return SealBad
	case key == "":
		return SealUnchecked
	}
	k, err := deriveManifestKey(key)
	if err != nil {
		return SealUnchecked
	}
	if m.KeyFingerprint != k.fingerprint {
		return SealForeignKey
	}
	got, err := hex.DecodeString(m.Seal)
	if err != nil || !hmac.Equal(got, k.sum(m.canonical())) {
		return SealBad
	}
	return SealValid
}

// ── the key ──────────────────────────────────────────────────────────────────

// manifestKeyLabel is the PBKDF2 salt that makes the manifest key useless for
// anything else, and every other key derived from CLOOP_SECRET_KEY useless for
// this.
const manifestKeyLabel = "cloop/db-backup/manifest/v1"

// manifestKDFIterations is the PBKDF2-HMAC-SHA256 work factor, the checkpoint
// key's: a sidecar travels with the backup, and each one is a test of a guessed
// passphrase. A variable so tests can lower it.
var manifestKDFIterations = 600_000

type manifestKey struct {
	raw []byte
	// fingerprint is CLOOP_SECRET_KEY's — the audit checkpoint key's, the
	// name every record sealed under this key carries — not this key's own.
	fingerprint string
}

func (k *manifestKey) sum(msg []byte) []byte {
	m := hmac.New(sha256.New, k.raw)
	m.Write(msg)
	return m.Sum(nil)
}

var manifestKeyCache sync.Map // cache id -> *manifestKey

func deriveManifestKey(passphrase string) (*manifestKey, error) {
	iter := manifestKDFIterations
	id := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%s", manifestKeyLabel, iter, passphrase)))
	cacheID := hex.EncodeToString(id[:])
	if k, ok := manifestKeyCache.Load(cacheID); ok {
		return k.(*manifestKey), nil
	}
	cp, err := auditcheckpoint.DeriveKey(passphrase)
	if err != nil {
		return nil, err
	}
	raw, err := pbkdf2.Key(sha256.New, passphrase, []byte(manifestKeyLabel), iter, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("dbbackup: derive the manifest key: %w", err)
	}
	k := &manifestKey{raw: raw, fingerprint: cp.Fingerprint()}
	actual, _ := manifestKeyCache.LoadOrStore(cacheID, k)
	return actual.(*manifestKey), nil
}

// KeyFingerprint names passphrase the way every audit checkpoint, escrow and
// sidecar sealed under it does; "" for no key.
func KeyFingerprint(passphrase string) string {
	if passphrase == "" {
		return ""
	}
	k, err := auditcheckpoint.DeriveKey(passphrase)
	if err != nil {
		return ""
	}
	return k.Fingerprint()
}
