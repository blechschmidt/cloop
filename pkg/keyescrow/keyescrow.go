// Package keyescrow wraps the hub's root secret, CLOOP_SECRET_KEY, under a
// passphrase an operator keeps, so that losing .cloop/hub.env stops being the
// end of every sealed credential (Task 20410).
//
// # What it protects, and what it cannot
//
// Every key-encryption key the secret broker seals under is derived from
// CLOOP_SECRET_KEY, so rotating the KEKs as often as you like changes nothing
// about this one value: lose it and every sealed PAT, kubeconfig, App key,
// session refresh token and hub CA key is gone. Until this package the
// bootstrap said so in a comment — "no recovery path and no escrow" — and the
// runbook's restore was a two-part procedure whose second part assumed the
// first had survived.
//
// An escrow file holds the key sealed under a passphrase. It is safe to keep
// where a database backup is not — with the other root credentials, off the
// host — because without the passphrase it is a few dozen bytes of AES-GCM
// ciphertext behind a memory-hard KDF. It is exactly as strong as the
// passphrase and no stronger, which is why one shorter than
// MinPassphraseLength is refused.
//
// # Why argon2id, and not the store's own KDF
//
// The broker stretches CLOOP_SECRET_KEY with 200,000 rounds of SHA-256
// (pkg/secretbroker/cipher.go). That is plenty for 256 bits of crypto/rand,
// which nobody guesses, and far too cheap for something a person chose: a GPU
// tries billions of SHA-256 a second. argon2id makes every guess cost memory as
// well as time, which is what a GPU or an ASIC has least of. The parameters
// are RFC 9106's second recommended option (§4: t=3, p=4, 64 MiB), written into
// the file and bound into the AEAD's associated data, so a file cannot be
// talked into a cheaper derivation than it was made with; and they are bounded
// on read, so a crafted file cannot make a verifier allocate the machine.
//
// # What the hub keeps
//
// Only a Record: the escrow's id, when and by whom, and the key's fingerprint —
// the one `cloop hub doctor` and every audit checkpoint already show for this
// key, so recording it publishes nothing a checkpoint line has not. It is what
// lets the doctor say that the escrow on record no longer holds the key in use.
//
// # Plaintext never touches disk
//
// The key goes from the environment into memory and out as ciphertext. The
// escrow file is written through a temporary holding ciphertext only.
// WriteEnvFile, which puts a recovered key back, writes the one file the key
// lives in anyway, and a temporary that fails on the way there is destroyed
// with pkg/securewipe rather than merely unlinked.
package keyescrow

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/securewipe"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Kind marks an escrow file.
const Kind = "cloop.hub.key-escrow"

// Version is the file format this build writes and reads.
const Version = 1

// The algorithms a version 1 file names.
const (
	KDFArgon2id = "argon2id"
	AEADAESGCM  = "aes-256-gcm"
)

// EnvKey is the variable holding the key an escrow protects: the secret
// broker's passphrase (secretbroker.EnvPassphraseKey), which every audit
// checkpoint and backup manifest seal is derived from as well. It may as well
// come from a key file or a systemd credential (pkg/rootkey); an escrow holds
// the current one, whichever source it was read from.
const EnvKey = rootkey.EnvKey

// MinPassphraseLength is the shortest passphrase an escrow accepts, in
// characters: NIST SP 800-63B rev. 4 asks 15 of a password that is the only
// thing standing between an attacker and what it protects, which is this
// passphrase's whole job.
const MinPassphraseLength = 15

const (
	saltSize  = 16 // RFC 9106 §3.1: 128 bits
	nonceSize = 12
	wrapSize  = 32 // AES-256
	// maxKeySize bounds the key an escrow holds. `cloop hub bootstrap`
	// generates 43 characters; a value past this is not a key.
	maxKeySize = 4096
	// maxFileSize bounds what ReadFile reads. A version 1 file is under 1 KiB.
	maxFileSize = 64 << 10
)

// Sentinels. A wrong passphrase and an altered file are deliberately the same
// error (ErrOpen): AES-GCM cannot tell them apart, and the difference would
// help only whoever is doing the altering.
var (
	ErrNotEscrow      = errors.New("keyescrow: not a cloop key escrow file")
	ErrUnsupported    = errors.New("keyescrow: unsupported escrow format")
	ErrParams         = errors.New("keyescrow: argon2id parameters out of bounds")
	ErrOpen           = errors.New("keyescrow: wrong passphrase, or the file was altered")
	ErrWeakPassphrase = errors.New("keyescrow: passphrase refused")
	ErrNoKey          = errors.New("keyescrow: " + EnvKey + " is not set")
)

// Params are argon2id's work factors.
type Params struct {
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
}

// DefaultParams is RFC 9106's second recommended option: three passes over
// 64 MiB with four lanes, about a tenth of a second on a server core.
var DefaultParams = Params{Time: 3, MemoryKiB: 64 << 10, Threads: 4}

// The bounds a file's parameters must lie within to be opened. The floor is
// OWASP's minimum for argon2id — 19 MiB over two passes, as memory × passes, so
// 46 MiB over one passes as well — which nothing this package writes comes near;
// a file below it was not made here. The ceiling stops a crafted file from
// making whoever opens it allocate more than a gigabyte or spin for long: the
// file is replaced more easily than the passphrase is learned, and verify and
// import derive before they can know the file is not theirs. DefaultParams sit
// well inside both.
const (
	minMemoryKiB = 19 << 10
	minWorkKiB   = 2 * minMemoryKiB
	maxMemoryKiB = 1 << 20
	maxTime      = 10
	maxThreads   = 16
)

func (p Params) validate() error {
	switch {
	case p.Threads < 1 || p.Threads > maxThreads:
		return fmt.Errorf("%w: %d threads (1–%d)", ErrParams, p.Threads, maxThreads)
	case p.Time < 1 || p.Time > maxTime:
		return fmt.Errorf("%w: %d passes (1–%d)", ErrParams, p.Time, maxTime)
	case p.MemoryKiB < minMemoryKiB || p.MemoryKiB > maxMemoryKiB:
		return fmt.Errorf("%w: %d KiB of memory (%d–%d)", ErrParams, p.MemoryKiB, minMemoryKiB, maxMemoryKiB)
	case uint64(p.Time)*uint64(p.MemoryKiB) < minWorkKiB:
		return fmt.Errorf("%w: %d passes over %d KiB is less work than %d over %d",
			ErrParams, p.Time, p.MemoryKiB, 2, minMemoryKiB)
	}
	return nil
}

// String renders the parameters for an operator.
func (p Params) String() string {
	return fmt.Sprintf("argon2id t=%d m=%dMiB p=%d", p.Time, p.MemoryKiB>>10, p.Threads)
}

// File is an escrow file. Every field but Ciphertext is bound into the AEAD's
// associated data, so none can be edited without the passphrase noticing.
type File struct {
	Kind    string `json:"kind"`
	Version int    `json:"v"`
	// ID names this escrow; the hub's Record carries it, so `cloop hub key
	// escrow verify` can say whether a file is the one on record.
	ID        string `json:"escrow_id"`
	CreatedAt string `json:"created_at"`
	CreatedBy string `json:"created_by,omitempty"`
	// Hub is the directory it was exported from, for whoever finds the file.
	Hub string `json:"hub,omitempty"`
	// KeyFingerprint is Fingerprint of the key inside.
	KeyFingerprint string `json:"key_fingerprint"`
	KDF            KDF    `json:"kdf"`
	AEAD           AEAD   `json:"aead"`
	// Ciphertext is the key sealed under the passphrase, base64.
	Ciphertext string `json:"ciphertext"`
}

// KDF names the derivation of the wrapping key from the passphrase.
type KDF struct {
	Alg string `json:"alg"`
	Params
	Salt string `json:"salt"`
}

// AEAD names the cipher the key is sealed with.
type AEAD struct {
	Alg   string `json:"alg"`
	Nonce string `json:"nonce"`
}

// WrapOptions describe an escrow being made.
type WrapOptions struct {
	// Params are the KDF's work factors; zero means DefaultParams.
	Params Params
	// CreatedBy and Hub are recorded in the file, for whoever finds it.
	CreatedBy string
	Hub       string
	// Now is the creation time; zero means time.Now.
	Now time.Time
}

// Wrap seals key under passphrase.
func Wrap(key, passphrase []byte, opts WrapOptions) (*File, error) {
	if len(key) == 0 {
		return nil, ErrNoKey
	}
	if len(key) > maxKeySize {
		return nil, fmt.Errorf("keyescrow: a %d-byte %s is not a key", len(key), EnvKey)
	}
	if err := CheckPassphrase(passphrase); err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(key, passphrase) == 1 {
		return nil, fmt.Errorf("%w: it is %s itself", ErrWeakPassphrase, EnvKey)
	}
	params := opts.Params
	if params == (Params{}) {
		params = DefaultParams
	}
	if err := params.validate(); err != nil {
		return nil, err
	}
	fingerprint, err := Fingerprint(key)
	if err != nil {
		return nil, err
	}
	salt, err := random(saltSize)
	if err != nil {
		return nil, err
	}
	nonce, err := random(nonceSize)
	if err != nil {
		return nil, err
	}
	id, err := random(8)
	if err != nil {
		return nil, err
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	f := &File{
		Kind:           Kind,
		Version:        Version,
		ID:             "esc_" + hex.EncodeToString(id),
		CreatedAt:      formatTime(now),
		CreatedBy:      strings.ToValidUTF8(opts.CreatedBy, "�"),
		Hub:            strings.ToValidUTF8(opts.Hub, "�"),
		KeyFingerprint: fingerprint,
		KDF:            KDF{Alg: KDFArgon2id, Params: params, Salt: b64.EncodeToString(salt)},
		AEAD:           AEAD{Alg: AEADAESGCM, Nonce: b64.EncodeToString(nonce)},
	}
	wrapKey := derive(passphrase, salt, params)
	defer zero(wrapKey)
	gcm, err := newGCM(wrapKey)
	if err != nil {
		return nil, err
	}
	f.Ciphertext = b64.EncodeToString(gcm.Seal(nil, nonce, key, f.aad()))
	return f, nil
}

// Open recovers the key. The caller owns the returned slice and should zero it.
func (f *File) Open(passphrase []byte) ([]byte, error) {
	salt, nonce, ct, err := f.decoded()
	if err != nil {
		return nil, err
	}
	wrapKey := derive(passphrase, salt, f.KDF.Params)
	defer zero(wrapKey)
	gcm, err := newGCM(wrapKey)
	if err != nil {
		return nil, err
	}
	key, err := gcm.Open(nil, nonce, ct, f.aad())
	if err != nil {
		return nil, ErrOpen
	}
	// The fingerprint the file names is authenticated with everything else in
	// the header, and is not recomputed here: it names the key the way the
	// build that wrote the file named keys, and an escrow has to open under
	// every later build, whatever they do to fingerprints.
	return key, nil
}

// decoded validates f and returns its binary parts.
func (f *File) decoded() (salt, nonce, ct []byte, err error) {
	switch {
	case f == nil || f.Kind != Kind:
		return nil, nil, nil, ErrNotEscrow
	case f.Version != Version:
		return nil, nil, nil, fmt.Errorf("%w: version %d (this build reads %d)", ErrUnsupported, f.Version, Version)
	case f.KDF.Alg != KDFArgon2id:
		return nil, nil, nil, fmt.Errorf("%w: key derivation %q", ErrUnsupported, f.KDF.Alg)
	case f.AEAD.Alg != AEADAESGCM:
		return nil, nil, nil, fmt.Errorf("%w: cipher %q", ErrUnsupported, f.AEAD.Alg)
	case f.ID == "" || len(f.KeyFingerprint) != 16:
		return nil, nil, nil, fmt.Errorf("%w: no escrow id or key fingerprint", ErrNotEscrow)
	}
	if _, perr := time.Parse(time.RFC3339Nano, f.CreatedAt); perr != nil {
		return nil, nil, nil, fmt.Errorf("%w: created_at %q", ErrNotEscrow, f.CreatedAt)
	}
	if err := f.KDF.Params.validate(); err != nil {
		return nil, nil, nil, err
	}
	if salt, err = b64.DecodeString(f.KDF.Salt); err != nil || len(salt) < saltSize || len(salt) > 64 {
		return nil, nil, nil, fmt.Errorf("%w: the salt is not %d–64 bytes of base64", ErrNotEscrow, saltSize)
	}
	if nonce, err = b64.DecodeString(f.AEAD.Nonce); err != nil || len(nonce) != nonceSize {
		return nil, nil, nil, fmt.Errorf("%w: the nonce is not %d bytes of base64", ErrNotEscrow, nonceSize)
	}
	// A tag and at least one byte, and no more than the largest key plus a tag.
	if ct, err = b64.DecodeString(f.Ciphertext); err != nil || len(ct) <= 16 || len(ct) > maxKeySize+16 {
		return nil, nil, nil, fmt.Errorf("%w: the ciphertext is not base64 of a sealed key", ErrNotEscrow)
	}
	return salt, nonce, ct, nil
}

// Validate checks f's structure and parameters without the passphrase.
func (f *File) Validate() error {
	_, _, _, err := f.decoded()
	return err
}

// aad is what the AEAD binds the ciphertext to: every field but the
// ciphertext, in a fixed order, strings quoted so no field bleeds into the
// next. JSON is not used because its encoding is not unique.
func (f *File) aad() []byte {
	var b strings.Builder
	b.WriteString("cloop-key-escrow/v1\n")
	str := func(name, v string) {
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(strconv.Quote(v))
		b.WriteByte('\n')
	}
	num := func(name string, v uint64) {
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(strconv.FormatUint(v, 10))
		b.WriteByte('\n')
	}
	str("kind", f.Kind)
	num("v", uint64(f.Version))
	str("escrow_id", f.ID)
	str("created_at", f.CreatedAt)
	str("created_by", f.CreatedBy)
	str("hub", f.Hub)
	str("key_fingerprint", f.KeyFingerprint)
	str("kdf.alg", f.KDF.Alg)
	num("kdf.time", uint64(f.KDF.Time))
	num("kdf.memory_kib", uint64(f.KDF.MemoryKiB))
	num("kdf.threads", uint64(f.KDF.Threads))
	str("kdf.salt", f.KDF.Salt)
	str("aead.alg", f.AEAD.Alg)
	str("aead.nonce", f.AEAD.Nonce)
	return []byte(b.String())
}

// Created parses CreatedAt, returning the zero time when it does not parse.
func (f *File) Created() time.Time {
	t, err := time.Parse(time.RFC3339Nano, f.CreatedAt)
	if err != nil {
		return time.Time{}
	}
	return t
}

// Marshal renders the file as written to disk.
func (f *File) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("keyescrow: encode: %w", err)
	}
	return append(b, '\n'), nil
}

// Parse decodes an escrow file and checks its structure. It needs no
// passphrase, and proves nothing about the ciphertext.
func Parse(data []byte) (*File, error) {
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("%w: %d bytes is not an escrow file", ErrNotEscrow, len(data))
	}
	// Kind and version first, leniently: a newer file carries fields this
	// build does not know, and should be told apart from a broken one.
	var head struct {
		Kind    string `json:"kind"`
		Version int    `json:"v"`
	}
	if err := json.Unmarshal(data, &head); err != nil || head.Kind != Kind {
		return nil, ErrNotEscrow
	}
	if head.Version != Version {
		return nil, fmt.Errorf("%w: version %d (this build reads %d)", ErrUnsupported, head.Version, Version)
	}
	// Then strictly: a field this version does not define was added by hand.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotEscrow, err)
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// ReadFile reads and parses the escrow file at path; "-" reads standard input.
func ReadFile(path string) (*File, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		fh, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("keyescrow: %w", err)
		}
		defer fh.Close()
		r = fh
	}
	data, err := io.ReadAll(io.LimitReader(r, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("keyescrow: read %s: %w", path, err)
	}
	return Parse(data)
}

// CheckDestination reports why path is no place for an escrow file. The file
// exists to survive the loss of the hub's .cloop/ directory — the place
// hub.env, the database and its backups are most likely to be lost together —
// so a destination inside one, followed through symlinks, is refused.
func CheckDestination(path string) error {
	if path == "" {
		return errors.New("keyescrow: no destination")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("keyescrow: %w", err)
	}
	if config.PathInsideCloopDir(abs) {
		return fmt.Errorf("keyescrow: %s is inside a .cloop/ directory, which is what an escrow must outlive: "+
			"write it where you keep root credentials, off this host", path)
	}
	if real, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil && config.PathInsideCloopDir(real) {
		return fmt.Errorf("keyescrow: %s resolves to %s, inside a .cloop/ directory", path, real)
	}
	return nil
}

// WriteFile writes f to path, 0600, through a temporary in the same
// directory, and refuses to replace an existing file unless replace is set:
// an escrow already there may be the only one whose passphrase somebody
// remembers.
func WriteFile(path string, f *File, replace bool) error {
	if err := CheckDestination(path); err != nil {
		return err
	}
	if err := f.Validate(); err != nil {
		return err
	}
	data, err := f.Marshal()
	if err != nil {
		return err
	}
	if !replace {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("keyescrow: %s exists; pass --force to replace it", path)
		}
	}
	return writeAtomically(path, data)
}

// writeAtomically writes data to path, 0600, through a temporary in its
// directory. A temporary that fails is destroyed through pkg/securewipe: for
// an escrow file it holds ciphertext, and for hub.env it holds the key.
func writeAtomically(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("keyescrow: create a temporary in %s: %w", dir, err)
	}
	name := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			if werr := securewipe.File(name); werr != nil {
				err = errors.Join(err, werr)
			}
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("keyescrow: restrict %s: %w", name, err)
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("keyescrow: write %s: %w", name, err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("keyescrow: fsync %s: %w", name, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("keyescrow: close %s: %w", name, err)
	}
	if err = os.Rename(name, path); err != nil {
		return fmt.Errorf("keyescrow: install %s: %w", path, err)
	}
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// CheckPassphrase reports why passphrase is too weak to protect a root key.
// Length is what counts (NIST SP 800-63B rev. 4 drops composition rules); a
// passphrase of one or two repeated characters is refused as well, because it
// is long only on paper.
func CheckPassphrase(passphrase []byte) error {
	if !utf8.Valid(passphrase) {
		return fmt.Errorf("%w: it is not valid UTF-8", ErrWeakPassphrase)
	}
	n := utf8.RuneCount(passphrase)
	if n < MinPassphraseLength {
		return fmt.Errorf("%w: %d characters; an escrow passphrase needs at least %d — "+
			"five or six random words are easier to remember and far stronger", ErrWeakPassphrase, n, MinPassphraseLength)
	}
	distinct := map[rune]bool{}
	for _, r := range string(passphrase) {
		distinct[r] = true
	}
	if len(distinct) < 5 {
		return fmt.Errorf("%w: it uses only %d distinct characters", ErrWeakPassphrase, len(distinct))
	}
	return nil
}

// Fingerprint names key the way the hub already names it wherever an operator
// meets it: the fingerprint of the audit checkpoint key it derives, stamped on
// every checkpoint the hub seals and printed by `cloop hub doctor` and `cloop
// hub audit verify`. One key, one name — and recording it publishes nothing a
// checkpoint line has not, at the cost to a guesser that line already sets: a
// full PBKDF2 pass per try.
func Fingerprint(key []byte) (string, error) {
	fp, err := rootkey.Fingerprint(string(key))
	if err != nil {
		if errors.Is(err, rootkey.ErrNoKey) {
			return "", ErrNoKey
		}
		return "", fmt.Errorf("keyescrow: fingerprint: %w", err)
	}
	return fp, nil
}

// ── what the hub keeps ──────────────────────────────────────────────────────

// recordKey is the hub metadata key the Record lives under.
const recordKey = "key_escrow"

// Record is everything the hub keeps about its escrow. Nothing in it is
// secret, and nothing in it helps open the file.
type Record struct {
	ID             string `json:"escrow_id"`
	KeyFingerprint string `json:"key_fingerprint"`
	CreatedAt      string `json:"created_at"`
	CreatedBy      string `json:"created_by,omitempty"`
	KDF            string `json:"kdf"`
	// RecordedAt and RecordedBy say when the record was last written — by the
	// export, or by a `verify --record` after a restore brought back a
	// database older than the escrow.
	RecordedAt string `json:"recorded_at"`
	RecordedBy string `json:"recorded_by,omitempty"`
}

// Record is what the hub keeps about f.
func (f *File) Record(by string, at time.Time) Record {
	return Record{
		ID:             f.ID,
		KeyFingerprint: f.KeyFingerprint,
		CreatedAt:      f.CreatedAt,
		CreatedBy:      f.CreatedBy,
		KDF:            f.KDF.Params.String(),
		RecordedAt:     formatTime(at),
		RecordedBy:     by,
	}
}

// LoadRecord reads the hub's escrow record from its control plane.
func LoadRecord(db *statedb.DB) (Record, bool, error) {
	raw, ok, err := db.HubMeta(recordKey)
	if err != nil || !ok {
		return Record{}, false, err
	}
	var r Record
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return Record{}, true, fmt.Errorf("keyescrow: the hub's escrow record does not decode: %w", err)
	}
	return r, true, nil
}

// ReadRecord is LoadRecord through a bare connection — one statedb.OpenConn
// opened ReadOnly — so asking which escrow a hub records writes nothing to it.
func ReadRecord(conn *sql.DB) (Record, bool, error) {
	raw, ok, err := statedb.ReadHubMeta(conn, recordKey)
	if err != nil || !ok {
		return Record{}, false, err
	}
	var r Record
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return Record{}, true, fmt.Errorf("keyescrow: the hub's escrow record does not decode: %w", err)
	}
	return r, true, nil
}

// SaveRecord writes the hub's escrow record, replacing any earlier one.
func SaveRecord(db *statedb.DB, r Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("keyescrow: encode record: %w", err)
	}
	return db.SetHubMeta(recordKey, string(b))
}

// Created parses CreatedAt.
func (r Record) Created() time.Time {
	t, err := time.Parse(time.RFC3339Nano, r.CreatedAt)
	if err != nil {
		return time.Time{}
	}
	return t
}

// ── primitives ──────────────────────────────────────────────────────────────

var b64 = base64.StdEncoding

func derive(passphrase, salt []byte, p Params) []byte {
	return argon2.IDKey(passphrase, salt, p.Time, p.MemoryKiB, p.Threads, wrapSize)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("keyescrow: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keyescrow: %w", err)
	}
	return gcm, nil
}

func random(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("keyescrow: read randomness: %w", err)
	}
	return b, nil
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// zero overwrites b. Best effort: Go may have copied it, and the key also
// lives in the process environment as an immutable string.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Zero overwrites a key Open returned.
func Zero(b []byte) { zero(b) }
