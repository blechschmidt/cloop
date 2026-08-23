// SQLite-level tests for envelope encryption and online key rotation
// (Task 20181).
//
// pkg/secretbroker's keyring tests cover the algorithm against an in-memory
// registry. These cover what only a real database can show:
//
//   - migration 0019 stamps pre-existing rows 'legacy' and the first rotation
//     upgrades them in place, against a database genuinely rewound to the
//     previous schema rather than one hand-shaped to look like it;
//   - the compare-and-swap really is atomic in SQL, so a credential re-minted
//     mid-rotation is not silently reverted;
//   - retirement's reference check is enforced by the transaction, not by a
//     Go-side check a concurrent writer can race past;
//   - session refresh tokens rotate alongside secrets, because a rotation that
//     covered only half the sealed material would report success while leaving
//     the other half behind.

package secretstore_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/sessionstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const rotationPassphrase = "rotation-test-passphrase"

// newRotationHarness wires a broker, keyring, and rotator over a real database
// covering both sealed populations.
type rotationHarness struct {
	db      *statedb.DB
	path    string
	store   *secretstore.Store
	keyring *secretbroker.Keyring
	broker  *secretbroker.Broker
	rotator *secretbroker.Rotator
	session *sessionstore.Store
}

func newRotationHarness(t *testing.T) *rotationHarness {
	t.Helper()
	db, path := openTestDB(t)
	return rotationHarnessOn(t, db, path)
}

func rotationHarnessOn(t *testing.T, db *statedb.DB, path string) *rotationHarness {
	t.Helper()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	kr, err := secretbroker.OpenKeyring(store,
		secretbroker.WithKeyringPassphrase(rotationPassphrase),
		secretbroker.WithKeyringActor("test"))
	if err != nil {
		t.Fatalf("open keyring: %v", err)
	}
	b, err := secretbroker.New(store,
		secretbroker.WithKeyring(kr),
		secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	sessions, err := sessionstore.New(db)
	if err != nil {
		t.Fatalf("new session store: %v", err)
	}
	sessions.WithKeyring(kr)
	rot, err := secretbroker.NewRotator(kr, store, sessions)
	if err != nil {
		t.Fatalf("new rotator: %v", err)
	}
	rot.WithHistory(store)
	return &rotationHarness{
		db: db, path: path, store: store, keyring: kr,
		broker: b, rotator: rot, session: sessions,
	}
}

func (h *rotationHarness) mint(t *testing.T, name, payload string) secretbroker.Secret {
	t.Helper()
	s, err := h.broker.Mint(context.Background(), secretbroker.MintRequest{
		Name: name, Kind: secretbroker.KindEnv,
		Payload: []byte(payload), Actor: "test",
	})
	if err != nil {
		t.Fatalf("mint %s: %v", name, err)
	}
	return s
}

func (h *rotationHarness) open(t *testing.T, id string) string {
	t.Helper()
	sec, err := h.store.GetSecret(id)
	if err != nil {
		t.Fatalf("get %s: %v", id, err)
	}
	plain, err := h.keyring.OpenEnvelope(secretbroker.AADFor(secretbroker.SetSecrets, sec.ID), sec.Envelope())
	if err != nil {
		t.Fatalf("open %s: %v", id, err)
	}
	return string(plain)
}

// ---------------------------------------------------------------------------
// migration and legacy upgrade
// ---------------------------------------------------------------------------

// TestMigration0019StampsAndUpgradesPreExistingRows rewinds a real database to
// the pre-envelope schema, writes a row the way the old code did, and lets
// statedb.Open migrate it forward.
//
// Running the real migrations up to 0018 rather than hand-building the old
// schema matters: a hand-built "old" database is a copy of the migration's
// assumptions, so it would agree with a broken migration. This is the schema
// the release before 0019 actually shipped.
func TestMigration0019StampsAndUpgradesPreExistingRows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	// 1. The database as it stood one migration before envelope encryption.
	const preEnvelope = 18
	seedPre0019(t, path, preEnvelope)

	// 2. Seal a payload the way the pre-envelope code did — one key derived
	//    from the passphrase and the store-wide salt, applied directly.
	const legacyPayload = "LEGACY_SECRET=pre-envelope-value"
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i * 7)
	}
	legacySealed := sealLegacy(t, rotationPassphrase, salt, legacyPayload)

	// 3. Write the legacy row in the shape 0018 could hold.
	insertLegacyRow(t, path, salt, legacySealed)

	// 4. Open — 0019 and everything after it apply, once each.
	db2, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("reopen (migrating): %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })

	row, err := db2.GetBrokerSecret("sec_legacy")
	if err != nil {
		t.Fatalf("get migrated row: %v", err)
	}
	if row.KeyID != secretbroker.LegacyKeyID {
		t.Fatalf("migrated row key_id = %q, want %q — the in-place upgrade did not run",
			row.KeyID, secretbroker.LegacyKeyID)
	}
	if len(row.WrappedDEK) != 0 {
		t.Errorf("migrated row has a wrapped DEK; SQL cannot have produced one")
	}

	// 5. The hub opens it as before the upgrade, because the legacy salt is
	//    still there and the keyring loads it.
	h := rotationHarnessOn(t, db2, path)
	if !h.keyring.HasLegacy() {
		t.Fatal("keyring did not adopt the legacy salt")
	}
	if got := h.open(t, "sec_legacy"); got != legacyPayload {
		t.Fatalf("legacy payload = %q, want %q", got, legacyPayload)
	}

	counts, err := h.store.CountSealedByKey()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if counts[secretbroker.LegacyKeyID] != 1 {
		t.Errorf("counts = %v, want one legacy row", counts)
	}

	// 6. Rotation upgrades it into envelope form, once, permanently.
	report, err := h.rotator.Rotate(context.Background(),
		secretbroker.RotateOptions{NewKey: false, Actor: "test"})
	if err != nil {
		t.Fatalf("upgrade rotation: %v", err)
	}
	if !report.Complete || report.Rewrapped != 1 {
		t.Fatalf("report = %+v, want one row upgraded", report)
	}

	upgraded, err := db2.GetBrokerSecret("sec_legacy")
	if err != nil {
		t.Fatalf("get upgraded: %v", err)
	}
	if upgraded.KeyID == secretbroker.LegacyKeyID || len(upgraded.WrappedDEK) == 0 {
		t.Fatalf("row is still legacy after rotation: key_id=%q wrapped=%d bytes",
			upgraded.KeyID, len(upgraded.WrappedDEK))
	}
	if got := h.open(t, "sec_legacy"); got != legacyPayload {
		t.Fatalf("payload after upgrade = %q, want %q", got, legacyPayload)
	}

	counts, _ = h.store.CountSealedByKey()
	if counts[secretbroker.LegacyKeyID] != 0 {
		t.Errorf("legacy rows remain after rotation: %v", counts)
	}
}

// sealLegacy reproduces the pre-envelope construction: AES-256-GCM,
// nonce||ct||tag, one passphrase-derived key, no associated data.
func sealLegacy(t *testing.T, passphrase string, salt []byte, plaintext string) []byte {
	t.Helper()
	c, err := secretbroker.NewLegacyCipher(passphrase, salt)
	if err != nil {
		t.Fatalf("legacy cipher: %v", err)
	}
	sealed, err := c.Seal([]byte(plaintext))
	if err != nil {
		t.Fatalf("legacy seal: %v", err)
	}
	return sealed
}

// seedPre0019 creates a database at exactly schema version `upTo` by running
// the real embedded migrations and stopping, so what 0019 later meets is the
// schema that shipped rather than a reconstruction of it.
//
// It also asserts it actually stopped short of the target being tested. A
// migration numbered <= upTo would make this a no-op that still passes, which
// is the one way this helper could lie.
func seedPre0019(t *testing.T, path string, upTo int) {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer raw.Close()

	report, err := statedb.MigrateTo(raw, upTo)
	if err != nil {
		t.Fatalf("migrate to %d: %v", upTo, err)
	}
	if report.EndVersion != upTo {
		t.Fatalf("seeded database is at version %d, want %d", report.EndVersion, upTo)
	}
	latest, err := statedb.LatestSchemaVersion()
	if err != nil {
		t.Fatalf("latest schema version: %v", err)
	}
	if latest <= upTo {
		t.Fatalf("latest schema version is %d, so stopping at %d tests nothing", latest, upTo)
	}
}

// insertLegacyRow writes a secret in the pre-0019 shape — no key_id, no
// wrapped DEK — plus the store-wide salt the old cipher derived from.
func insertLegacyRow(t *testing.T, path string, salt, legacySealed []byte) {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer raw.Close()

	if _, err := raw.Exec(
		`INSERT INTO broker_secrets(id, kind, name, payload, metadata_json, created_at, created_by)
		 VALUES ('sec_legacy','env','legacy-secret', ?, '{}', '2026-01-01T00:00:00Z','test')`,
		legacySealed); err != nil {
		t.Fatalf("insert legacy secret: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO broker_meta(key, value) VALUES ('secretbroker.salt', ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		hexOf(salt)); err != nil {
		t.Fatalf("insert legacy salt: %v", err)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0x0f]
	}
	return string(out)
}

// ---------------------------------------------------------------------------
// concurrency
// ---------------------------------------------------------------------------

// TestRotationUnderConcurrentDatabaseLoad runs a rotation while other
// goroutines read every secret and re-mint some of them, which is what a
// serving hub does to a rotation in progress.
func TestRotationUnderConcurrentDatabaseLoad(t *testing.T) {
	h := newRotationHarness(t)

	const n = 24
	ids := make([]string, 0, n)
	want := map[string]string{}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("load-%02d", i)
		payload := fmt.Sprintf("VALUE_%02d=original", i)
		s := h.mint(t, name, payload)
		ids = append(ids, s.ID)
		want[s.ID] = payload
	}

	var (
		wg      sync.WaitGroup
		stop    = make(chan struct{})
		errCh   = make(chan error, 32)
		wantMu  sync.Mutex
		readers = 3
	)

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, id := range ids {
					sec, err := h.store.GetSecret(id)
					if err != nil {
						continue
					}
					if _, err := h.keyring.OpenEnvelope(
						secretbroker.AADFor(secretbroker.SetSecrets, sec.ID), sec.Envelope()); err != nil {
						select {
						case errCh <- fmt.Errorf("read %s during rotation: %w", id, err):
						default:
						}
						return
					}
				}
			}
		}()
	}

	// Writers replace the payload of every third row, mid-rotation.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i, id := range ids {
			if i%3 != 0 {
				continue
			}
			fresh := fmt.Sprintf("VALUE_%02d=rewritten", i)
			env, err := h.keyring.SealFor(secretbroker.AADFor(secretbroker.SetSecrets, id), []byte(fresh))
			if err != nil {
				continue
			}
			sec, err := h.store.GetSecret(id)
			if err != nil {
				continue
			}
			if err := h.store.PutSecret(sec.WithEnvelope(env)); err != nil {
				continue
			}
			wantMu.Lock()
			want[id] = fresh
			wantMu.Unlock()
		}
	}()

	h.rotator.WithBatch(4)
	if _, err := h.rotator.Rotate(context.Background(),
		secretbroker.RotateOptions{NewKey: true, Actor: "test"}); err != nil {
		t.Fatalf("rotate under load: %v", err)
	}
	// One mop-up pass, exactly what `--continue` does, to absorb rows the
	// writer replaced while the first pass was running.
	report, err := h.rotator.Rotate(context.Background(),
		secretbroker.RotateOptions{NewKey: false, Actor: "test"})
	if err != nil {
		t.Fatalf("continue pass: %v", err)
	}
	if !report.Complete {
		t.Fatalf("rotation under load did not converge: %+v", report)
	}

	close(stop)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("%v", err)
	}

	target := h.keyring.PrimaryID()
	for _, id := range ids {
		sec, err := h.store.GetSecret(id)
		if err != nil {
			t.Fatalf("final get %s: %v", id, err)
		}
		if sec.KeyID != target {
			t.Errorf("%s left under %q, want %q", id, sec.KeyID, target)
		}
		wantMu.Lock()
		expected := want[id]
		wantMu.Unlock()
		if got := h.open(t, id); got != expected {
			t.Errorf("%s = %q, want %q — rotation reverted a concurrent write", id, got, expected)
		}
	}
}

// TestCompareAndSwapRefusesAStaleRewrap is the lost-update guard in isolation:
// a rotator holding a stale read must not win against a writer that already
// replaced the row.
func TestCompareAndSwapRefusesAStaleRewrap(t *testing.T) {
	h := newRotationHarness(t)
	sec := h.mint(t, "cas", "ORIGINAL=1")

	stale, err := h.store.GetSecret(sec.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	// A concurrent writer replaces the payload after the rotator's read.
	fresh, err := h.keyring.SealFor(secretbroker.AADFor(secretbroker.SetSecrets, sec.ID), []byte("REPLACED=2"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := h.store.PutSecret(stale.WithEnvelope(fresh)); err != nil {
		t.Fatalf("concurrent write: %v", err)
	}

	// The rotator now tries to write back a rewrap of what it read.
	rewrapped, err := h.keyring.Rewrap(secretbroker.AADFor(secretbroker.SetSecrets, sec.ID), stale.Envelope())
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	swapped, err := h.store.ReplaceSealed(sec.ID, stale.Envelope(), rewrapped)
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if swapped {
		t.Fatal("a stale rewrap was accepted — the compare-and-swap does not compare the ciphertext")
	}
	if got := h.open(t, sec.ID); got != "REPLACED=2" {
		t.Errorf("payload = %q, want the concurrent writer's value", got)
	}
}

// ---------------------------------------------------------------------------
// interruption and resume against a real file
// ---------------------------------------------------------------------------

// TestInterruptedRotationSurvivesAProcessRestart closes the database
// mid-rotation and reopens it, which is as close to SIGKILL as a test gets.
func TestInterruptedRotationSurvivesAProcessRestart(t *testing.T) {
	db, path := openTestDB(t)
	h := rotationHarnessOn(t, db, path)

	const n = 15
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		ids = append(ids, h.mint(t, fmt.Sprintf("restart-%02d", i),
			fmt.Sprintf("V%02d=x", i)).ID)
	}

	ctx, cancel := context.WithCancel(context.Background())
	h.rotator.WithBatch(3).WithProgress(func(secretbroker.RotationRecord) { cancel() })
	first, err := h.rotator.Rotate(ctx, secretbroker.RotateOptions{NewKey: true, Actor: "test"})
	if err == nil {
		t.Fatal("expected the interrupted rotation to report an error")
	}
	target := first.TargetKeyID
	if first.Rewrapped == 0 || first.Rewrapped == n {
		t.Fatalf("interruption landed at %d/%d rows — the test needs a partial state", first.Rewrapped, n)
	}

	// Simulate the restart.
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	db2, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	h2 := rotationHarnessOn(t, db2, path)

	// The reopened hub adopts the interrupted rotation's key as primary,
	// because that is what the registry says. Nothing was lost.
	if h2.keyring.PrimaryID() != target {
		t.Fatalf("after restart primary = %q, want %q", h2.keyring.PrimaryID(), target)
	}
	for _, id := range ids {
		if h2.open(t, id) == "" {
			t.Fatalf("%s unreadable after restart", id)
		}
	}

	second, err := h2.rotator.Rotate(context.Background(),
		secretbroker.RotateOptions{NewKey: false, Actor: "test"})
	if err != nil {
		t.Fatalf("resume after restart: %v", err)
	}
	if !second.Complete {
		t.Fatalf("resumed rotation incomplete: %+v", second)
	}
	status, err := h2.rotator.Status(10)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.Unrotated != 0 {
		t.Errorf("status reports %d unrotated rows after a completed resume", status.Unrotated)
	}
	if len(status.Rotations) < 2 {
		t.Errorf("rotation history has %d records, want the interrupted one and the resume",
			len(status.Rotations))
	}
}

// ---------------------------------------------------------------------------
// retirement
// ---------------------------------------------------------------------------

// TestRetirementIsRefusedInSQLNotOnlyInGo bypasses the Go-side pre-check
// entirely and calls the database directly, because that check is advisory and
// the transaction is the actual guarantee.
func TestRetirementIsRefusedInSQLNotOnlyInGo(t *testing.T) {
	h := newRotationHarness(t)
	h.mint(t, "held", "A=1")
	inUse := h.keyring.PrimaryID()

	// Rotate so `inUse` is no longer primary but still holds no rows... then
	// put a row back under it, which is what a partial restore looks like.
	if _, err := h.rotator.Rotate(context.Background(),
		secretbroker.RotateOptions{NewKey: true, Actor: "test"}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	row, err := h.db.GetBrokerSecret(mustSecretID(t, h, "held"))
	if err != nil {
		t.Fatalf("get row: %v", err)
	}
	row.KeyID = inUse
	if err := h.db.PutBrokerSecret(row); err != nil {
		t.Fatalf("strand row: %v", err)
	}

	err = h.db.RetireKEK(inUse, time.Now())
	if !errors.Is(err, statedb.ErrKEKInUse) {
		t.Fatalf("RetireKEK err = %v, want ErrKEKInUse", err)
	}

	// The salt must still be there: a refused retirement that shredded
	// anyway would be the worst of both.
	keks, err := h.db.ListKEKs()
	if err != nil {
		t.Fatalf("list keks: %v", err)
	}
	for _, k := range keks {
		if k.ID == inUse && (k.Salt == "" || k.State == "retired") {
			t.Fatalf("refused retirement still shredded %s: %+v", inUse, k)
		}
	}
}

// TestReadsFailLoudlyAfterRetirementInSQLite is the storage-level half of the
// loud-failure guarantee: the salt is really gone from the file, so a hub
// restarted from that file cannot derive the key however it tries.
func TestReadsFailLoudlyAfterRetirementInSQLite(t *testing.T) {
	db, path := openTestDB(t)
	h := rotationHarnessOn(t, db, path)
	sec := h.mint(t, "doomed", "GONE=1")

	doomed := h.keyring.PrimaryID()
	stranded, err := h.db.GetBrokerSecret(sec.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := h.rotator.Rotate(context.Background(),
		secretbroker.RotateOptions{NewKey: true, Actor: "test"}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := h.rotator.RetireKey(doomed); err != nil {
		t.Fatalf("retire: %v", err)
	}

	// Put the pre-rotation row back and restart, so nothing is cached.
	if err := h.db.PutBrokerSecret(stranded); err != nil {
		t.Fatalf("restore stranded row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	db2, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	h2 := rotationHarnessOn(t, db2, path)

	row, err := h2.store.GetSecret(sec.ID)
	if err != nil {
		t.Fatalf("get after restart: %v", err)
	}
	_, err = h2.keyring.OpenEnvelope(secretbroker.AADFor(secretbroker.SetSecrets, row.ID), row.Envelope())
	if err == nil {
		t.Fatal("a row under a retired key opened after restart")
	}
	if !errors.Is(err, secretbroker.ErrKeyRetired) {
		t.Fatalf("err = %v, want ErrKeyRetired", err)
	}
	if !strings.Contains(err.Error(), doomed) {
		t.Errorf("error must name the retired key, got: %v", err)
	}

	// The salt column is empty on disk, not merely ignored in Go.
	for _, k := range mustListKEKs(t, h2.db) {
		if k.ID == doomed {
			if k.Salt != "" {
				t.Errorf("retired key still has a salt on disk (%d chars)", len(k.Salt))
			}
			if k.State != "retired" {
				t.Errorf("retired key state = %q", k.State)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// sessions
// ---------------------------------------------------------------------------

// TestSessionRefreshTokensRotateAlongsideSecrets. A rotation that covered only
// brokered secrets would report success and leave every refresh token under
// the old key — and retirement would then refuse for a reason nothing in the
// output explained.
func TestSessionRefreshTokensRotateAlongsideSecrets(t *testing.T) {
	h := newRotationHarness(t)
	if !h.session.Available() {
		t.Fatal("session store reports no sealing key")
	}
	h.mint(t, "with-sessions", "A=1")

	const refresh = "rt_session_refresh_canary_0123456789"
	rec := oidcauth.SessionRecord{
		ID:           "sess_rotation_1",
		Identity:     oidcauth.Identity{Sub: "user-1", Email: "u@example.com"},
		IssuedAt:     time.Now(),
		LastSeen:     time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
		RefreshToken: refresh,
	}
	if err := h.session.Put(rec); err != nil {
		t.Fatalf("put session: %v", err)
	}

	before, err := h.session.CountSealedByKey()
	if err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if before[h.keyring.PrimaryID()] != 1 {
		t.Fatalf("session counts = %v, want 1 under the primary", before)
	}

	report, err := h.rotator.Rotate(context.Background(),
		secretbroker.RotateOptions{NewKey: true, Actor: "test"})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !report.Complete {
		t.Fatalf("incomplete: %+v", report)
	}
	var sessionSet *secretbroker.SetReport
	for i := range report.Sets {
		if report.Sets[i].Name == "sessions" {
			sessionSet = &report.Sets[i]
		}
	}
	if sessionSet == nil {
		t.Fatal("rotation report has no sessions set — sessions are not registered for rotation")
	}
	if sessionSet.Rewrapped != 1 {
		t.Errorf("sessions rewrapped = %d, want 1", sessionSet.Rewrapped)
	}

	got, err := h.session.Get(rec.ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if got.RefreshToken != refresh {
		t.Errorf("refresh token after rotation = %q, want %q", got.RefreshToken, refresh)
	}

	after, _ := h.session.CountSealedByKey()
	if after[h.keyring.PrimaryID()] != 1 {
		t.Errorf("session counts after rotation = %v, want 1 under the new primary", after)
	}
}

// TestSessionTokenIsBoundToItsSessionRow: the same substitution attack as for
// secrets, at the session table. Copying an administrator's sealed refresh
// token into your own row must not let the hub present it to the IdP for you.
func TestSessionTokenIsBoundToItsSessionRow(t *testing.T) {
	h := newRotationHarness(t)

	const adminRefresh = "rt_admin_refresh_canary_0123456789"
	admin := oidcauth.SessionRecord{
		ID:       "sess_admin",
		Identity: oidcauth.Identity{Sub: "admin"},
		IssuedAt: time.Now(), LastSeen: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour), RefreshToken: adminRefresh,
	}
	if err := h.session.Put(admin); err != nil {
		t.Fatalf("put admin session: %v", err)
	}
	attacker := oidcauth.SessionRecord{
		ID:       "sess_attacker",
		Identity: oidcauth.Identity{Sub: "attacker"},
		IssuedAt: time.Now(), LastSeen: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := h.session.Put(attacker); err != nil {
		t.Fatalf("put attacker session: %v", err)
	}

	adminRow, err := h.db.GetSession(admin.ID)
	if err != nil {
		t.Fatalf("get admin row: %v", err)
	}
	// Copy the whole sealed envelope across, exactly as a database writer
	// would.
	if err := h.db.UpdateSessionRefresh(attacker.ID, adminRow.RefreshKeyID,
		adminRow.RefreshWrappedDEK, adminRow.RefreshSealed, time.Now()); err != nil {
		t.Fatalf("transplant: %v", err)
	}

	stolen, err := h.session.Get(attacker.ID)
	if err != nil {
		t.Fatalf("get attacker session: %v", err)
	}
	if stolen.RefreshToken != "" {
		t.Fatalf("a transplanted refresh token was decrypted for another session: %q",
			stolen.RefreshToken)
	}
	// The victim's own row is unaffected.
	victim, err := h.session.Get(admin.ID)
	if err != nil {
		t.Fatalf("get admin session: %v", err)
	}
	if victim.RefreshToken != adminRefresh {
		t.Errorf("admin refresh token = %q, want it intact", victim.RefreshToken)
	}
}

// ---------------------------------------------------------------------------
// on-disk shape
// ---------------------------------------------------------------------------

// TestDatabaseFileHoldsNoPlaintextAfterRotation greps the file itself. It is
// crude on purpose: the point is that no refactor of the layers above can
// reintroduce plaintext at rest without this failing.
func TestDatabaseFileHoldsNoPlaintextAfterRotation(t *testing.T) {
	h := newRotationHarness(t)
	const canary = "ghp_ondiskcanary9876543210abcdefgh"
	h.mint(t, "ondisk", canary)

	if _, err := h.rotator.Rotate(context.Background(),
		secretbroker.RotateOptions{NewKey: true, Actor: "test"}); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// Force WAL content into the main file so the scan sees everything.
	if err := h.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, err := os.ReadFile(h.path + suffix)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), canary) {
			t.Errorf("plaintext credential found in %s", filepath.Base(h.path+suffix))
		}
	}
}

// ---------------------------------------------------------------------------

func mustSecretID(t *testing.T, h *rotationHarness, name string) string {
	t.Helper()
	secrets, err := h.store.ListSecrets()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, s := range secrets {
		if s.Name == name {
			return s.ID
		}
	}
	t.Fatalf("no secret named %q", name)
	return ""
}

func mustListKEKs(t *testing.T, db *statedb.DB) []statedb.KEKRow {
	t.Helper()
	keks, err := db.ListKEKs()
	if err != nil {
		t.Fatalf("list keks: %v", err)
	}
	return keks
}

// TestRetirementChecksEverySetThatRotates is the drift gate for the one place
// where the two enumerations of "sealed material" have to agree.
//
// Rotation is driven by the SealedSet interface, so a new sealed population
// rotates for free the moment it is registered. Retirement's reference check is
// hand-written SQL inside the retiring transaction, because it has to be — a
// Go-side check outside the transaction is a race. If someone adds a third
// population and registers it for rotation without adding it to that SQL, then
// `cloop hub key retire` will crypto-shred a key that is still protecting live
// material, and it will do so while printing a confident success message.
//
// The failure is silent and permanent, and no other test would catch it.
func TestRetirementChecksEverySetThatRotates(t *testing.T) {
	h := newRotationHarness(t)

	rotated := map[string]bool{}
	// The sets a production hub registers, assembled the same way
	// cmd/hub_key_cmd.go assembles them.
	for _, set := range []secretbroker.SealedSet{h.store, h.session} {
		rotated[set.SealedSetName()] = true
	}
	checked := map[string]bool{}
	for _, name := range statedb.SealedSetNames() {
		checked[name] = true
	}

	for name := range rotated {
		if !checked[name] {
			t.Errorf("set %q rotates but retirement does not count it — "+
				"add it to sealedPopulations in pkg/statedb/keys.go, or "+
				"`cloop hub key retire` will shred a key it still uses", name)
		}
	}
	for name := range checked {
		if !rotated[name] {
			t.Errorf("retirement counts %q but nothing rotates it — "+
				"either register it as a SealedSet or drop it from sealedPopulations", name)
		}
	}
	if len(checked) == 0 {
		t.Fatal("statedb.SealedSetNames() is empty — the gate is disabled, not passing")
	}
}

// TestSecretEnvelopeCannotBeReadAsASessionToken is the cross-table half of the
// substitution attack, against the real schema.
//
// Binding to the row id alone is not enough, because row ids are chosen by
// whoever writes the row. An attacker with database write access inserts a
// session whose id equals a secret's id, copies the secret's envelope into the
// refresh-token columns, and the hub presents the kubeconfig to the identity
// provider as a refresh token — sealed material leaving the store, over the
// network, to a third party.
func TestSecretEnvelopeCannotBeReadAsASessionToken(t *testing.T) {
	h := newRotationHarness(t)

	const kubeconfig = "apiVersion: v1\nkind: Config\n# canary"
	sec, err := h.broker.Mint(context.Background(), secretbroker.MintRequest{
		Name: "transplant-source", Kind: secretbroker.KindKubeconfig,
		Payload: []byte(kubeconfig), Actor: "test",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	row, err := h.db.GetBrokerSecret(sec.ID)
	if err != nil {
		t.Fatalf("get secret row: %v", err)
	}

	// A session whose id is the secret's id — the attacker's choice.
	if err := h.session.Put(oidcauth.SessionRecord{
		ID:       sec.ID,
		Identity: oidcauth.Identity{Sub: "attacker"},
		IssuedAt: time.Now(), LastSeen: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("put session: %v", err)
	}
	if err := h.db.UpdateSessionRefresh(sec.ID, row.KeyID, row.WrappedDEK, row.Payload, time.Now()); err != nil {
		t.Fatalf("transplant: %v", err)
	}

	got, err := h.session.Get(sec.ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if got.RefreshToken != "" {
		t.Fatalf("a secret's envelope decrypted as a refresh token: %q", got.RefreshToken)
	}
}
