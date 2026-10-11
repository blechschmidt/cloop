package dbbackup

// The restore preflight: everything a restore must know before it swaps
// anything (Task 20410).
//
// A restore used to check integrity, digest and schema, swap the file in, and
// leave the rest to the hub — which then refused to start, because the
// CLOOP_SECRET_KEY it was given could not derive the backup's sealing keys. By
// then the old database had been moved aside and the operator was debugging a
// hub that would not start rather than a backup that would not restore. And an
// edited backup with a recomputed SHA-256 in its sidecar restored cleanly.
//
// Inspect reads the backup through a read-only connection and asks every
// question first: can this binary open it, is it the file its sidecar
// describes, is the sidecar the one this hub's key sealed, and does the key the
// restored hub will run with open every sealing key the backup's secrets
// depend on. Each "no" is a Refusal naming the flag that overrides it, if one
// does — and the key check's flag is --accept-secret-loss, deliberately not
// --force: overwriting a live database and abandoning every sealed credential
// are different decisions, and one flag must not make both.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Sentinels a RefusedError wraps, one per kind of refusal.
var (
	ErrIntegrity   = errors.New("dbbackup: the backup fails PRAGMA integrity_check")
	ErrSchemaAhead = errors.New("dbbackup: the backup's schema is newer than this binary")
	ErrNoSidecar   = errors.New("dbbackup: the backup has no sidecar")
	ErrChecksum    = errors.New("dbbackup: checksum mismatch")
	ErrSealBroken  = errors.New("dbbackup: the sidecar's seal does not verify")
	ErrUnsealed    = errors.New("dbbackup: the sidecar's seal cannot be checked")
	ErrSecretLoss  = errors.New("dbbackup: the key cannot open the backup's sealing keys")
)

// Flags that override a refusal, as the CLI spells them.
const (
	OverrideSkipChecksum     = "--skip-checksum"
	OverrideAllowUnsealed    = "--allow-unsealed"
	OverrideAcceptSecretLoss = "--accept-secret-loss"
)

// PreflightOptions are what a backup is checked against.
type PreflightOptions struct {
	// Key is the CLOOP_SECRET_KEY the restored hub will run with.
	Key string
	// SkipChecksum, AllowUnsealed and AcceptSecretLoss are RestoreOptions'.
	SkipChecksum     bool
	AllowUnsealed    bool
	AcceptSecretLoss bool
}

// SidecarState is how the sidecar was found.
type SidecarState string

const (
	// SidecarSealed: present, the digest matches, and its seal verifies
	// under the key.
	SidecarSealed SidecarState = "sealed"
	// SidecarUnchecked: present and the digest matches, but its seal could
	// not be checked here (see the Refusal or note saying why).
	SidecarUnchecked SidecarState = "unchecked"
	// SidecarBroken: present, and either the digest or the seal says the
	// backup or the sidecar was changed.
	SidecarBroken SidecarState = "broken"
	// SidecarMissing: there is none.
	SidecarMissing SidecarState = "missing"
	// SidecarSkipped: not checked, under --skip-checksum.
	SidecarSkipped SidecarState = "skipped"
)

// KeyVerdict is one sealing key the backup depends on, judged against the
// key a restore would run with.
type KeyVerdict struct {
	ManifestKey
	// Opens: the key derives it (passes its check value; for the legacy
	// key, opens a sample of what it sealed).
	Opens bool `json:"opens"`
	// Lost: rows sealed under it would be unreadable after the restore, and
	// it is the key's fault — a restore would make them unreadable.
	Lost bool `json:"lost,omitempty"`
	// Why says why it does not open, when it does not.
	Why string `json:"why,omitempty"`
}

// Refusal is one reason a restore is refused.
type Refusal struct {
	// Err is the sentinel; Message says it to an operator.
	Err     error
	Message string
	// Override is the flag that proceeds anyway; "" when none does.
	Override string
}

// RefusedError is a restore refused before anything was touched.
type RefusedError struct {
	Backup   string
	Refusals []Refusal
}

func (e *RefusedError) Error() string {
	msgs := make([]string, 0, len(e.Refusals))
	for _, r := range e.Refusals {
		m := r.Message
		if r.Override != "" {
			m += " (" + r.Override + " proceeds anyway)"
		}
		msgs = append(msgs, m)
	}
	return fmt.Sprintf("dbbackup: refusing to restore %s: %s", e.Backup, strings.Join(msgs, "; "))
}

// Is matches every sentinel the refusals carry.
func (e *RefusedError) Is(target error) bool {
	for _, r := range e.Refusals {
		if errors.Is(r.Err, target) {
			return true
		}
	}
	return false
}

// Preflight is what a backup is, checked against the key a restore would run
// with.
type Preflight struct {
	Backup    string
	SizeBytes int64
	// SHA256 is the backup file's digest, computed here.
	SHA256 string
	// Meta is the sidecar; nil when there is none.
	Meta    *Metadata
	Sidecar SidecarState
	// Seal is what the sidecar's seal says, when it was checked.
	Seal SealState
	// SchemaVersion is the highest migration the backup records.
	SchemaVersion int
	// Chain is where the backup's audit chain ends.
	Chain statedb.AuditHead
	// Keys are the sealing keys the backup depends on, by id.
	Keys []KeyVerdict
	// KeyFingerprint names the key checked against; "" when there was none.
	KeyFingerprint string

	// Refusals say why the restore is refused; none when it may go ahead.
	Refusals []Refusal
	// Notes are what a restore gives up, or cannot check, without being
	// refused for it.
	Notes []string
}

// Err is the refusal, or nil when the backup may be restored.
func (p *Preflight) Err() error {
	if len(p.Refusals) == 0 {
		return nil
	}
	return &RefusedError{Backup: p.Backup, Refusals: p.Refusals}
}

// LostKeys are the keys whose material a restore gives up.
func (p *Preflight) LostKeys() []KeyVerdict {
	var out []KeyVerdict
	for _, k := range p.Keys {
		if k.Lost {
			out = append(out, k)
		}
	}
	return out
}

func (p *Preflight) refuse(err error, override, format string, args ...any) {
	p.Refusals = append(p.Refusals, Refusal{Err: err, Message: fmt.Sprintf(format, args...), Override: override})
}

func (p *Preflight) note(format string, args ...any) {
	p.Notes = append(p.Notes, fmt.Sprintf(format, args...))
}

// Inspect checks the backup at path against opts without writing anything —
// not to the backup, not to the database it would replace. An error means it
// could not look at all; what it found is in the Preflight, and Err says
// whether a restore may proceed.
func Inspect(path string, opts PreflightOptions) (*Preflight, error) {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	stat, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("dbbackup: backup not found: %s", path)
		}
		return nil, fmt.Errorf("dbbackup: stat backup: %w", err)
	}
	if stat.IsDir() {
		return nil, fmt.Errorf("dbbackup: backup path is a directory: %s", path)
	}
	p := &Preflight{Backup: path, SizeBytes: stat.Size(), KeyFingerprint: KeyFingerprint(opts.Key)}

	if err := validateBackup(path); err != nil {
		// Nothing else can be read reliably from a file that fails this.
		p.refuse(ErrIntegrity, "", "backup invalid: %v", err)
		return p, nil
	}
	if p.SHA256, err = fileSHA256(path); err != nil {
		return nil, fmt.Errorf("dbbackup: checksum: %w", err)
	}
	p.checkSchema(path)
	p.checkSidecar(path, opts)

	facts, head, err := readBackupFacts(path)
	if err != nil {
		return nil, fmt.Errorf("dbbackup: read the backup's keys and audit head: %w", err)
	}
	p.Chain = head
	p.checkKeys(facts, opts)
	return p, nil
}

// checkSchema refuses a backup this binary could not open once restored.
func (p *Preflight) checkSchema(path string) {
	st, err := statedb.InspectSchema(path)
	if err != nil {
		p.note("could not read the backup's schema version: %v", err)
		return
	}
	p.SchemaVersion = st.Version
	latest, err := statedb.LatestSchemaVersion()
	if err != nil || st.Version <= latest {
		return
	}
	if err := statedb.CheckSchemaAhead(path); err != nil {
		if statedb.AllowSchemaDowngradeFromEnv() {
			p.note("the backup's schema is newer than this binary and %s is set: %v",
				statedb.EnvAllowSchemaDowngrade, err)
			return
		}
		p.refuse(ErrSchemaAhead, "", "%v — restore it with the build that wrote it", err)
	}
}

// checkSidecar checks the digest and the seal the sidecar carries.
func (p *Preflight) checkSidecar(path string, opts PreflightOptions) {
	if opts.SkipChecksum {
		p.Sidecar = SidecarSkipped
		p.note("the sidecar was not checked (%s): nothing vouches that this backup was not edited", OverrideSkipChecksum)
		if meta, err := LoadMetadata(path); err == nil {
			p.Meta = meta
		}
		return
	}
	meta, err := LoadMetadata(path)
	if err != nil {
		p.Sidecar = SidecarBroken
		p.refuse(ErrChecksum, OverrideSkipChecksum, "checksum mismatch: the sidecar %s does not read: %v",
			path+MetadataSuffix, err)
		return
	}
	if meta == nil {
		p.Sidecar = SidecarMissing
		p.refuse(ErrNoSidecar, OverrideSkipChecksum, "there is no sidecar (%s): without it nothing says this "+
			"is the file that was backed up", filepath.Base(path)+MetadataSuffix)
		return
	}
	p.Meta = meta
	if meta.SHA256 == "" || !strings.EqualFold(meta.SHA256, p.SHA256) {
		p.Sidecar = SidecarBroken
		p.refuse(ErrChecksum, OverrideSkipChecksum, "checksum mismatch: expected %s, got %s", orNone(meta.SHA256), p.SHA256)
		return
	}

	p.Seal = meta.Check(opts.Key)
	switch p.Seal {
	case SealValid:
		p.Sidecar = SidecarSealed
		return
	case SealBad:
		p.Sidecar = SidecarBroken
		p.refuse(ErrSealBroken, OverrideSkipChecksum, "the sidecar claims key %s and its seal does not verify under it: "+
			"the backup and its SHA-256 were changed after it was written, or the sidecar was",
			orNone(meta.KeyFingerprint))
		return
	}

	p.Sidecar = SidecarUnchecked
	var why string
	switch p.Seal {
	case SealUnsigned:
		why = "the sidecar carries no seal — written before cloop sealed them, or by a hub with no " + EnvKey +
			" — so nothing proves the backup was not edited and its SHA-256 recomputed"
	case SealForeignKey:
		why = fmt.Sprintf("the sidecar is sealed under key %s, and the %s here is %s", meta.KeyFingerprint,
			EnvKey, orNone(p.KeyFingerprint))
	default:
		why = "there is no " + EnvKey + " here to check the sidecar's seal with"
	}
	if opts.AllowUnsealed {
		p.note("%s (%s)", why, OverrideAllowUnsealed)
		return
	}
	p.refuse(ErrUnsealed, OverrideAllowUnsealed, "%s", why)
}

// checkKeys judges every sealing key the backup depends on against the key
// the restored hub will run with — the check secretbroker.OpenKeyring makes
// when the hub starts, made before the swap instead of after it.
func (p *Preflight) checkKeys(facts statedb.SealedFacts, opts PreflightOptions) {
	records := make([]secretbroker.KEKRecord, 0, len(facts.KEKs))
	for _, row := range facts.KEKs {
		records = append(records, secretbroker.KEKRecord{
			ID: row.ID, Salt: row.Salt, State: row.State, CheckValue: row.CheckValue,
		})
	}
	opens := map[string]bool{}
	for _, c := range secretbroker.CheckKeys(opts.Key, records) {
		opens[c.ID] = c.Opens
	}
	// With a primary the key derives, the hub starts and any other live key
	// matters only for what is sealed under it. Without one, OpenKeyring
	// derives the whole registry and refuses to start on any live key it
	// cannot — sealed rows or none — so each of them is lost with the rest.
	primaryOpens := false
	for _, rec := range records {
		if rec.State == secretbroker.KEKStatePrimary && !rec.Retired() && opens[rec.ID] {
			primaryOpens = true
		}
	}

	var lost []string
	for _, mk := range manifestKeys(facts) {
		v := KeyVerdict{ManifestKey: mk}
		rows := mk.Total()
		switch mk.State {
		case KeyStateLegacy:
			switch {
			case facts.LegacySalt == "":
				v.Why = "the pre-envelope salt is not in the backup, so no key opens these rows"
				p.note("%d row(s) are sealed the pre-envelope way and the backup holds no salt for them: "+
					"they were lost before this restore", rows)
			case secretbroker.LegacyKeyOpens(opts.Key, facts.LegacySalt, facts.LegacySample):
				v.Opens = true
			default:
				v.Lost, v.Why = true, "the key does not open what the pre-envelope construction sealed"
			}
		case KeyStateUnknown:
			v.Why = "no key with this id is in the backup's registry"
			p.note("%d row(s) are sealed under %s, which the backup's key registry does not hold: "+
				"they were lost before this restore", rows, mk.ID)
		case secretbroker.KEKStateRetired:
			v.Why = "retired: its salt was destroyed"
			if rows > 0 {
				p.note("%d row(s) are sealed under %s, retired before the backup was taken: "+
					"they were lost before this restore", rows, mk.ID)
			}
		default:
			v.Opens = opens[mk.ID]
			if v.Opens {
				break
			}
			v.Why = "the key does not derive it"
			if opts.Key == "" {
				v.Why = "there is no " + EnvKey + " to derive it from"
			}
			// A live key nothing is sealed under still stops the hub
			// starting when the primary cannot be derived: OpenKeyring will
			// not fork a registry it cannot derive.
			if rows > 0 || mk.State == secretbroker.KEKStatePrimary || !primaryOpens {
				v.Lost = true
			}
		}
		if v.Lost {
			lost = append(lost, describeKey(v))
		}
		p.Keys = append(p.Keys, v)
	}
	sort.Slice(p.Keys, func(i, j int) bool { return p.Keys[i].ID < p.Keys[j].ID })
	if len(lost) == 0 {
		return
	}

	if opts.Key == "" {
		// Not a loss to accept: a variable missing from this shell says
		// nothing about whether the hub's key is lost, and with no key every
		// key would be abandoned — including ones the hub's own key opens.
		p.refuse(ErrSecretLoss, "", "there is no %s here to open the backup's sealing keys %s: load the hub's "+
			"environment, or recover the key from escrow (`cloop hub key escrow import`). If it is lost for good, "+
			"set a new %s and restore with %s", EnvKey, strings.Join(lost, ", "), EnvKey, OverrideAcceptSecretLoss)
		return
	}
	msg := fmt.Sprintf("the %s here (key %s) cannot open the backup's sealing keys %s: every secret, session and "+
		"hub CA key sealed under them would be unreadable, and the hub would refuse to start on them. Restore the "+
		"key they were sealed under (`cloop hub key escrow import`)", EnvKey, orNone(p.KeyFingerprint), strings.Join(lost, ", "))
	if opts.AcceptSecretLoss {
		p.note("%s — proceeding under %s: those keys are retired in the restored database, and the backup file keeps them",
			msg, OverrideAcceptSecretLoss)
		return
	}
	p.refuse(ErrSecretLoss, OverrideAcceptSecretLoss, "%s", msg)
}

// describeKey names a key and what is sealed under it.
func describeKey(v KeyVerdict) string {
	if len(v.Rows) == 0 {
		return v.ID + " (" + v.State + ", nothing sealed)"
	}
	sets := make([]string, 0, len(v.Rows))
	for set := range v.Rows {
		sets = append(sets, set)
	}
	sort.Strings(sets)
	parts := make([]string, 0, len(sets))
	for _, set := range sets {
		parts = append(parts, fmt.Sprintf("%d %s", v.Rows[set], set))
	}
	return v.ID + " (" + strings.Join(parts, ", ") + ")"
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
