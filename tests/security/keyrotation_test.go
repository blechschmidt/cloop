package security

// Guarantee 12: a plaintext data-encryption key never reaches disk or a log
// (Task 20181).
//
// Envelope encryption moves the security of every stored credential onto one
// claim: the per-row DEK exists only inside two functions, for microseconds,
// and is wiped. If a DEK leaks, the row it protects is decryptable by anyone
// holding the database — and unlike a leaked credential, nobody can rotate a
// DEK out from under an attacker who already copied the ciphertext. So this is
// the guarantee that carries the rest of the design.
//
// It is also the one hardest to assert honestly, because a DEK is
// unpredictable random bytes with no canary shape to grep for. The trick used
// here is to make it predictable to the *test* without making it predictable
// to anyone else: crypto/rand.Reader is replaced with a wrapper that still
// returns real entropy but records every chunk it hands out. After the run,
// the 32-byte chunks are exactly the salts and the DEKs; the salts are
// identifiable (they are stored, hex-encoded, in the key registry by design),
// and everything left is a DEK.
//
// Those DEK bytes then become canaries, and the scan is the same one the rest
// of this package uses: raw, hex, and base64, across the database file, the
// write-ahead log, the audit trail, every operator-facing JSON rendering, and
// the Go-syntax formatting of every struct that carries envelope material.
//
// Scope, stated honestly. This asserts that *cloop* does not persist or print
// a DEK. It cannot assert that the kernel never paged one out of the heap, and
// it does not try to; that is a deployment property (swap encryption, memory
// limits) documented in the threat model rather than a code property a test
// can reach.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/sessionstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// dekWitness records every random chunk the package under test asks for.
//
// It wraps the real reader rather than replacing the entropy: a deterministic
// stream would make the test's own ciphertexts predictable and could hide a
// bug that only shows with real nonces.
type dekWitness struct {
	mu     sync.Mutex
	src    io.Reader
	chunks [][]byte
}

func (w *dekWitness) Read(p []byte) (int, error) {
	n, err := io.ReadFull(w.src, p)
	if n > 0 {
		w.mu.Lock()
		cp := make([]byte, n)
		copy(cp, p[:n])
		w.chunks = append(w.chunks, cp)
		w.mu.Unlock()
	}
	return n, err
}

// sized returns every recorded chunk of exactly n bytes.
func (w *dekWitness) sized(n int) [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out [][]byte
	for _, c := range w.chunks {
		if len(c) == n {
			out = append(out, c)
		}
	}
	return out
}

// installDEKWitness swaps crypto/rand.Reader for the duration of the test.
//
// This is a process-global mutation, which is safe here only because Go runs
// a package's non-parallel tests one at a time and this test never calls
// t.Parallel(). If that ever changes, this becomes a flake factory — hence
// the assertion in the caller that the witness saw the expected traffic,
// which fails loudly rather than silently scanning nothing.
func installDEKWitness(t *testing.T) *dekWitness {
	t.Helper()
	w := &dekWitness{src: rand.Reader}
	orig := rand.Reader
	rand.Reader = w
	t.Cleanup(func() { rand.Reader = orig })
	return w
}

// keyRotationFixture is a real hub: SQLite state, a broker, a session store,
// and a rotator over both.
type keyRotationFixture struct {
	workDir string
	dbPath  string
	db      *statedb.DB
	store   *secretstore.Store
	session *sessionstore.Store
	keyring *secretbroker.Keyring
	broker  *secretbroker.Broker
	rotator *secretbroker.Rotator
}

const keyRotationPassphrase = "guarantee-12-passphrase"

func newKeyRotationFixture(t *testing.T) *keyRotationFixture {
	t.Helper()
	dir := t.TempDir()
	if _, err := state.Init(dir, "key rotation conformance", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	dbPath := state.DBPath(dir)
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("secretstore: %v", err)
	}
	kr, err := secretbroker.OpenKeyring(store,
		secretbroker.WithKeyringPassphrase(keyRotationPassphrase),
		secretbroker.WithKeyringActor("conformance"))
	if err != nil {
		t.Fatalf("open keyring: %v", err)
	}
	b, err := secretbroker.New(store,
		secretbroker.WithKeyring(kr),
		secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatalf("broker: %v", err)
	}
	sessions, err := sessionstore.New(db)
	if err != nil {
		t.Fatalf("sessionstore: %v", err)
	}
	sessions.WithKeyring(kr)
	rot, err := secretbroker.NewRotator(kr, store, sessions)
	if err != nil {
		t.Fatalf("rotator: %v", err)
	}
	rot.WithHistory(store)

	return &keyRotationFixture{
		workDir: dir, dbPath: dbPath, db: db, store: store,
		session: sessions, keyring: kr, broker: b, rotator: rot,
	}
}

// TestPlaintextDataKeysNeverReachDiskOrLogs is the guarantee.
func TestPlaintextDataKeysNeverReachDiskOrLogs(t *testing.T) {
	witness := installDEKWitness(t)
	fx := newKeyRotationFixture(t)

	// Exercise every path that mints or handles a DEK: minting secrets of
	// several kinds, sealing a session refresh token, rotating onto a new
	// KEK (which unwraps and rewraps every DEK), and rotating again.
	payloads := map[string]string{
		"pat":   "ghp_dekconformance0123456789abcdef",
		"env":   "DEPLOY_TOKEN=dekconformance-env-value",
		"proxy": "http://user:dekconformance@proxy.internal:3128",
	}
	kinds := map[string]secretbroker.Kind{
		"pat":   secretbroker.KindGitHubPAT,
		"env":   secretbroker.KindEnv,
		"proxy": secretbroker.KindEgressProxy,
	}
	for name, payload := range payloads {
		if _, err := fx.broker.Mint(context.Background(), secretbroker.MintRequest{
			Name: name, Kind: kinds[name], Payload: []byte(payload), Actor: "conformance",
		}); err != nil {
			t.Fatalf("mint %s: %v", name, err)
		}
	}
	if err := fx.session.Put(oidcauth.SessionRecord{
		ID:        "sess_dek_conformance",
		Identity:  oidcauth.Identity{Sub: "user", Email: "u@example.com"},
		IssuedAt:  time.Now(),
		LastSeen:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		// A refresh token is the other long-lived sealed credential, and it
		// shares the registry. If it were sealed some other way, the rotation
		// below would not touch it and this test would say so.
		RefreshToken: "rt_dekconformance_refresh_token",
	}); err != nil {
		t.Fatalf("put session: %v", err)
	}

	var reports []secretbroker.RotationReport
	for i := 0; i < 2; i++ {
		rep, err := fx.rotator.Rotate(context.Background(),
			secretbroker.RotateOptions{NewKey: true, Actor: "conformance"})
		if err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
		reports = append(reports, rep)
	}

	// ── isolate the DEKs ────────────────────────────────────────────────
	//
	// 32-byte draws are salts and DEKs. Salts are stored by design (hex, in
	// broker_keks) so they must be excluded, or this test would "find" one on
	// disk and fail for the wrong reason.
	salts := map[string]bool{}
	keks, err := fx.db.ListKEKs()
	if err != nil {
		t.Fatalf("list keks: %v", err)
	}
	for _, k := range keks {
		if k.Salt != "" {
			salts[strings.ToLower(k.Salt)] = true
		}
	}

	var deks [][]byte
	for _, chunk := range witness.sized(32) {
		if salts[strings.ToLower(hexString(chunk))] {
			continue
		}
		deks = append(deks, chunk)
	}

	// Vacuity guard. If the witness saw nothing — because rand.Reader was not
	// actually consulted, or a refactor moved DEK generation elsewhere — every
	// assertion below would pass while checking nothing at all.
	minimum := len(payloads) + 1 // one per secret, one per session
	if len(deks) < minimum {
		t.Fatalf("witness captured %d candidate data keys, expected at least %d — "+
			"the leak scan would be vacuous", len(deks), minimum)
	}

	// ── the surfaces ────────────────────────────────────────────────────
	surfaces := map[string]string{
		"audit trail":     dumpTrail(t, fx.workDir),
		"key list JSON":   mustJSON(t, fx.keyring.Keys()),
		"rotation report": mustJSON(t, reports),
		"rotation status": mustJSON(t, mustStatus(t, fx.rotator)),
		"secrets (%#v)":   goSyntax(t, mustSecrets(t, fx.store)),
		"kek rows (%#v)":  fmt.Sprintf("%#v", keks),
		"sessions (%#v)":  fmt.Sprintf("%#v", mustSessionRows(t, fx.db)),
	}
	for name, body := range surfaces {
		assertNoDEK(t, name, body, deks)
	}

	// The database file itself, including the write-ahead log, which is where
	// a row lives between commit and checkpoint and is the copy most likely to
	// be overlooked by a scan that only reads state.db.
	if err := fx.db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := fx.dbPath + suffix
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			continue
		}
		assertNoDEKBytes(t, filepath.Base(path), data, deks)
	}
}

// TestWrappedDataKeysOnDiskAreNotThePlaintextOnes is the complement: the
// previous test would also pass if the DEK were never written *because it was
// never used*. This asserts the wrapped form is present, is the right size,
// and is not simply the DEK stored under a different column name.
func TestWrappedDataKeysOnDiskAreNotThePlaintextOnes(t *testing.T) {
	witness := installDEKWitness(t)
	fx := newKeyRotationFixture(t)

	if _, err := fx.broker.Mint(context.Background(), secretbroker.MintRequest{
		Name: "wrapped", Kind: secretbroker.KindEnv,
		Payload: []byte("WRAPPED=1"), Actor: "conformance",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}

	secrets := mustSecrets(t, fx.store)
	if len(secrets) != 1 {
		t.Fatalf("expected one secret, got %d", len(secrets))
	}
	sec := secrets[0]
	if len(sec.WrappedDEK) == 0 {
		t.Fatal("no wrapped DEK on disk — the row was sealed without envelope encryption")
	}
	// nonce(12) + key(32) + tag(16). A wrapped DEK of exactly 32 bytes would
	// mean the key was stored raw.
	if want := 12 + 32 + 16; len(sec.WrappedDEK) != want {
		t.Errorf("wrapped DEK is %d bytes, want %d (nonce+key+tag)", len(sec.WrappedDEK), want)
	}
	for _, dek := range witness.sized(32) {
		if bytes.Contains(sec.WrappedDEK, dek) {
			t.Fatal("the wrapped DEK column contains raw key bytes — it is not encrypted")
		}
	}
}

// TestOpenFailuresDoNotEchoKeyMaterial. An error path is where secrets leak
// in practice, because it is written under pressure and read by everyone: a
// failed unwrap must name the key, not quote its contents.
func TestOpenFailuresDoNotEchoKeyMaterial(t *testing.T) {
	witness := installDEKWitness(t)
	fx := newKeyRotationFixture(t)

	sec, err := fx.broker.Mint(context.Background(), secretbroker.MintRequest{
		Name: "corruptible", Kind: secretbroker.KindEnv,
		Payload: []byte("CORRUPT=1"), Actor: "conformance",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	stored, err := fx.store.GetSecret(sec.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	var msgs []string
	// Every way a caller can arrive at a failed open.
	tampered := stored.Envelope()
	tampered.Ciphertext = append([]byte(nil), tampered.Ciphertext...)
	tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 0xff
	if _, err := fx.keyring.OpenEnvelope(secretAAD(stored.ID), tampered); err != nil {
		msgs = append(msgs, err.Error())
	}
	if _, err := fx.keyring.OpenEnvelope(secretAAD("wrong-row-id"), stored.Envelope()); err != nil {
		msgs = append(msgs, err.Error())
	}
	unknown := stored.Envelope()
	unknown.KeyID = "kek_does_not_exist"
	if _, err := fx.keyring.OpenEnvelope(secretAAD(stored.ID), unknown); err != nil {
		msgs = append(msgs, err.Error())
	}
	// And through Lease, which is where an operator actually meets a failed
	// open: a corrupt row reached at delivery time, not in a unit test.
	subject, serr := secretbroker.ParseSubject("project:/proj")
	if serr != nil {
		t.Fatalf("parse subject: %v", serr)
	}
	if _, gerr := fx.broker.Grant(context.Background(), secretbroker.GrantRequest{
		SecretRef: sec.Name, Subject: subject, TTL: time.Hour, Actor: "conformance",
	}); gerr != nil {
		t.Fatalf("grant: %v", gerr)
	}
	corrupt := stored
	corrupt.Sealed = append([]byte(nil), stored.Sealed...)
	corrupt.Sealed[len(corrupt.Sealed)-1] ^= 0xff
	if perr := fx.store.PutSecret(corrupt); perr != nil {
		t.Fatalf("corrupt row: %v", perr)
	}
	lease, lerr := fx.broker.Lease(context.Background(), "exec-1", "/proj")
	if lerr != nil {
		msgs = append(msgs, lerr.Error())
	}
	// A row that will not open is skipped, not delivered: the lease comes back
	// empty rather than partially materialised. The refusal is recorded in the
	// audit trail, which is where an operator finds it — and which is
	// therefore the surface that has to be scanned.
	if lease != nil && len(lease.Materials) != 0 {
		t.Errorf("a corrupt row was delivered anyway: %d material(s)", len(lease.Materials))
	}
	msgs = append(msgs, dumpTrail(t, fx.workDir))
	if len(msgs) < 3 {
		t.Fatalf("only %d error paths produced a message — the scan is too thin", len(msgs))
	}

	joined := strings.Join(msgs, "\n")
	assertNoDEK(t, "open error messages", joined, witness.sized(32))
	if strings.Contains(joined, "CORRUPT=1") {
		t.Errorf("an error message quoted the plaintext payload:\n%s", joined)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// assertNoDEK scans a rendered surface for any DEK in any encoding it could
// plausibly take on the way into a log or an export.
func assertNoDEK(t *testing.T, surface, body string, deks [][]byte) {
	t.Helper()
	assertNoDEKBytes(t, surface, []byte(body), deks)
}

func assertNoDEKBytes(t *testing.T, surface string, body []byte, deks [][]byte) {
	t.Helper()
	for i, dek := range deks {
		for encoding, form := range encodingsOf(string(dek)) {
			if form == "" {
				continue
			}
			if bytes.Contains(body, []byte(form)) {
				t.Errorf("data key #%d leaked into %s as %s", i, surface, encoding)
			}
		}
		// The raw bytes again, explicitly: encodingsOf works on strings, and a
		// DEK is arbitrary bytes that may not survive a string round-trip
		// intact through every encoder it applies.
		if bytes.Contains(body, dek) {
			t.Errorf("data key #%d leaked into %s as raw bytes", i, surface)
		}
		if bytes.Contains(bytes.ToLower(body), []byte(hexString(dek))) {
			t.Errorf("data key #%d leaked into %s as hex", i, surface)
		}
	}
}

// secretAAD builds the associated data a brokered secret is sealed with.
func secretAAD(id string) string {
	return secretbroker.AADFor(secretbroker.SetSecrets, id)
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0x0f]
	}
	return string(out)
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	blob, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(blob)
}

// goSyntax renders with %#v, which prints unexported-tag-free struct contents
// in full. A field hidden from JSON by `json:"-"` is invisible to a JSON scan
// and printed verbatim here, which is exactly the gap this catches.
func goSyntax(t *testing.T, v any) string {
	t.Helper()
	return fmt.Sprintf("%#v", v)
}

func mustSecrets(t *testing.T, store *secretstore.Store) []secretbroker.Secret {
	t.Helper()
	secrets, err := store.ListSecrets()
	if err != nil {
		t.Fatalf("list secrets: %v", err)
	}
	return secrets
}

func mustStatus(t *testing.T, rot *secretbroker.Rotator) secretbroker.RotationStatus {
	t.Helper()
	st, err := rot.Status(10)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	return st
}

func mustSessionRows(t *testing.T, db *statedb.DB) []statedb.SessionRow {
	t.Helper()
	rows, err := db.ListSessions()
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	return rows
}

// unused import guard: eventlog is used indirectly via dumpTrail, which lives
// in audit_test.go; referencing the type here keeps the dependency explicit
// for a reader of this file.
var _ = eventlog.AuditFilter{}
