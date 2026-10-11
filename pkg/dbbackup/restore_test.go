package dbbackup_test

// The restore preflight, the sealed manifest and the restore record, against
// a real broker over a real control plane (Task 20410).

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/auditcheckpoint"
	"github.com/blechschmidt/cloop/pkg/dbbackup"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	hubKey   = "dbbackup-test-hub-key-Zq4pV9mW2xT7rL0yH3nB8kD5sF1g"
	otherKey = "dbbackup-test-another-key-0123456789abcdefghijk"
	project  = "/srv/app"
)

// hub is a control plane with one secret granted to a project, sealed under
// hubKey. It returns the hub directory and the secret's id.
func hub(t *testing.T) (string, string) {
	t.Helper()
	// Before anything seals: the ambient environment may carry another key.
	t.Setenv(secretbroker.EnvPassphraseKey, hubKey)
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	b, closeDB := broker(t, dir)
	defer closeDB()
	ctx := context.Background()
	s, err := b.Mint(ctx, secretbroker.MintRequest{Name: "drill-token", Kind: secretbroker.KindEnv,
		Payload: []byte(`{"DRILL_TOKEN":"the-drill-secret-value"}`), Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Grant(ctx, secretbroker.GrantRequest{SecretRef: s.ID,
		Subject: secretbroker.Subject{Type: secretbroker.SubjectProject, Value: project}, Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	return dir, s.ID
}

func dbPath(dir string) string { return filepath.Join(dir, ".cloop", "state.db") }

func broker(t *testing.T, dir string) (*secretbroker.Broker, func()) {
	t.Helper()
	db, err := statedb.Open(dbPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	// The hub's own wiring: every mint, grant and lease is an audit row, so
	// the control plane's chain is the one a real hub writes.
	b, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	return b, func() { _ = db.Close() }
}

// openSecret opens the secret's envelope through the hub's keyring, as a
// lease would, and returns the error it fails with.
func openSecret(t *testing.T, dir, id string) error {
	t.Helper()
	b, closeDB := broker(t, dir)
	defer closeDB()
	db, err := statedb.Open(dbPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.GetSecret(id)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := b.Keyring().OpenEnvelope(secretbroker.AADFor(secretbroker.SetSecrets, s.ID),
		secretbroker.Envelope{KeyID: s.KeyID, WrappedDEK: s.WrappedDEK, Ciphertext: s.Sealed})
	for i := range plain {
		plain[i] = 0
	}
	return err
}

// leaseValue leases the project's secret and returns DRILL_TOKEN, or the
// error the lease failed with.
func leaseValue(t *testing.T, dir string) (string, error) {
	t.Helper()
	b, closeDB := broker(t, dir)
	defer closeDB()
	l, err := b.Lease(context.Background(), "executor-1", project)
	if err != nil {
		return "", err
	}
	defer b.Release(l.ID)
	for _, m := range l.Materials {
		if v, ok := m.Env["DRILL_TOKEN"]; ok {
			return v, nil
		}
	}
	return "", nil
}

func backup(t *testing.T, dir, key string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "state-backup.db")
	if _, err := dbbackup.BackupWithOptions(dbPath(dir), out, dbbackup.BackupOptions{Key: key}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTheSidecarIsASealedManifest(t *testing.T) {
	dir, _ := hub(t)
	out := filepath.Join(t.TempDir(), "b.db")
	rep, err := dbbackup.BackupWithOptions(dbPath(dir), out, dbbackup.BackupOptions{Key: hubKey})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Sealed() || rep.KeyFingerprint != dbbackup.KeyFingerprint(hubKey) {
		t.Fatalf("report %+v", rep)
	}
	meta, err := dbbackup.LoadMetadata(out)
	if err != nil || meta == nil {
		t.Fatal(err)
	}
	var sealedUnder []string
	for _, k := range meta.Keys {
		if k.Rows["secrets"] > 0 {
			sealedUnder = append(sealedUnder, k.ID+"/"+k.State)
		}
	}
	if len(sealedUnder) != 1 || !strings.HasSuffix(sealedUnder[0], "/primary") {
		t.Errorf("the manifest names the key the secret is sealed under as %v", sealedUnder)
	}

	db, err := statedb.Open(dbPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	head, _ := db.AuditHead()
	_ = db.Close()
	if meta.Chain == nil || meta.Chain.LastID != head.LastID || meta.Chain.LastRowHash != head.LastRowHash || head.LastID == 0 {
		t.Errorf("manifest chain %+v, database head %+v", meta.Chain, head)
	}

	for key, want := range map[string]dbbackup.SealState{
		hubKey: dbbackup.SealValid, otherKey: dbbackup.SealForeignKey, "": dbbackup.SealUnchecked,
	} {
		if got := meta.Check(key); got != want {
			t.Errorf("checked under %q: %s, want %s", key, got, want)
		}
	}
	for name, edit := range map[string]func(m *dbbackup.Metadata){
		"sha256":     func(m *dbbackup.Metadata) { m.SHA256 = strings.Repeat("0", 64) },
		"a key's id": func(m *dbbackup.Metadata) { m.Keys[0].ID = "kek_other" },
		"rows":       func(m *dbbackup.Metadata) { m.Keys[0].Rows = map[string]int{"secrets": 99} },
		"chain head": func(m *dbbackup.Metadata) { m.Chain.LastID++ },
		"created":    func(m *dbbackup.Metadata) { m.CreatedAt = m.CreatedAt.Add(time.Hour) },
	} {
		m := *meta
		m.Keys = append([]dbbackup.ManifestKey(nil), meta.Keys...)
		c := *meta.Chain
		m.Chain = &c
		edit(&m)
		if got := m.Check(hubKey); got != dbbackup.SealBad {
			t.Errorf("an edited %s checks as %s", name, got)
		}
	}

	unsealed, err := dbbackup.BackupWithOptions(dbPath(dir), filepath.Join(t.TempDir(), "u.db"), dbbackup.BackupOptions{})
	if err != nil || unsealed.Sealed() {
		t.Fatalf("a keyless backup: %+v %v", unsealed, err)
	}
}

// The drill's first refusal: a restore under a key that cannot derive the
// backup's sealing keys is refused before anything is touched, naming them.
func TestARestoreUnderAnotherKeyIsRefusedBeforeTheSwap(t *testing.T) {
	dir, _ := hub(t)
	b := backup(t, dir, hubKey)

	pre, err := dbbackup.Inspect(b, dbbackup.PreflightOptions{Key: otherKey})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(pre.Err(), dbbackup.ErrSecretLoss) || !errors.Is(pre.Err(), dbbackup.ErrUnsealed) {
		t.Fatalf("refusals %+v", pre.Refusals)
	}
	lost := pre.LostKeys()
	if len(lost) != 1 || !strings.Contains(pre.Err().Error(), lost[0].ID+" (1 secrets)") {
		t.Fatalf("lost %+v; refusal %v", lost, pre.Err())
	}
	for _, r := range pre.Refusals {
		if errors.Is(r.Err, dbbackup.ErrSecretLoss) && r.Override != dbbackup.OverrideAcceptSecretLoss {
			t.Errorf("the key refusal is overridden by %q", r.Override)
		}
	}

	// The live database is left exactly as it was.
	dst := filepath.Join(t.TempDir(), "state.db")
	if err := os.WriteFile(dst, []byte("the live database"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = dbbackup.Restore(b, dst, dbbackup.RestoreOptions{Key: otherKey, Force: true, Reason: "drill"})
	var refused *dbbackup.RefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("Restore: %v", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "the live database" {
		t.Fatal("a refused restore touched the destination")
	}
	if left, _ := filepath.Glob(dst + ".pre-restore.*"); len(left) != 0 {
		t.Fatalf("a refused restore stashed the destination: %v", left)
	}

	// No key at all is refused too — and --accept-secret-loss does not
	// apply: a variable missing from a shell is not a lost key, and with no
	// key every key in the backup would be abandoned.
	pre, err = dbbackup.Inspect(b, dbbackup.PreflightOptions{AllowUnsealed: true, AcceptSecretLoss: true})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(pre.Err(), dbbackup.ErrSecretLoss) || !strings.Contains(pre.Err().Error(), "no CLOOP_SECRET_KEY here") {
		t.Fatalf("without a key: %v", pre.Err())
	}
	for _, r := range pre.Refusals {
		if errors.Is(r.Err, dbbackup.ErrSecretLoss) && r.Override != "" {
			t.Errorf("without a key the loss can be accepted with %s", r.Override)
		}
	}

	// And the right key passes.
	pre, err = dbbackup.Inspect(b, dbbackup.PreflightOptions{Key: hubKey})
	if err != nil || pre.Err() != nil || pre.Sidecar != dbbackup.SidecarSealed {
		t.Fatalf("under its own key: %+v %v", pre, err)
	}
}

// The drill's last refusal: a backup edited after it was taken, its SHA-256
// recomputed into the sidecar, no longer matches the sidecar's seal.
func TestAnEditedBackupWithARecomputedDigestIsRefused(t *testing.T) {
	dir, _ := hub(t)
	b := backup(t, dir, hubKey)

	// Extend the grant to every project, behind the hub's back.
	conn, err := sql.Open("sqlite", b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`UPDATE broker_grants SET subject_type = 'any', subject_value = ''`); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	sum := fileSHA(t, b)
	meta, err := dbbackup.LoadMetadata(b)
	if err != nil {
		t.Fatal(err)
	}
	if meta.SHA256 == sum {
		t.Fatal("premise: the edit changed the file")
	}
	meta.SHA256 = sum
	writeMeta(t, b, meta)

	pre, err := dbbackup.Inspect(b, dbbackup.PreflightOptions{Key: hubKey})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(pre.Err(), dbbackup.ErrSealBroken) || pre.Sidecar != dbbackup.SidecarBroken {
		t.Fatalf("an edited backup with a recomputed digest: %+v", pre.Refusals)
	}

	// Stripping the seal as well does not make it a legacy backup.
	meta.Seal, meta.KeyFingerprint = "", ""
	writeMeta(t, b, meta)
	pre, err = dbbackup.Inspect(b, dbbackup.PreflightOptions{Key: hubKey})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(pre.Err(), dbbackup.ErrUnsealed) {
		t.Fatalf("with the seal stripped: %+v", pre.Refusals)
	}
	for _, r := range pre.Refusals {
		if r.Override != dbbackup.OverrideAllowUnsealed {
			t.Errorf("refusal %+v", r)
		}
	}
}

func TestASidecarIsRequiredUnlessSkipped(t *testing.T) {
	dir, _ := hub(t)
	b := backup(t, dir, hubKey)
	if err := os.Remove(b + dbbackup.MetadataSuffix); err != nil {
		t.Fatal(err)
	}
	pre, err := dbbackup.Inspect(b, dbbackup.PreflightOptions{Key: hubKey})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(pre.Err(), dbbackup.ErrNoSidecar) {
		t.Fatalf("no sidecar: %+v", pre.Refusals)
	}
	pre, err = dbbackup.Inspect(b, dbbackup.PreflightOptions{Key: hubKey, SkipChecksum: true})
	if err != nil || pre.Err() != nil || pre.Sidecar != dbbackup.SidecarSkipped || len(pre.Notes) == 0 {
		t.Fatalf("skipped: %+v %v", pre, err)
	}
}

// --accept-secret-loss restores the backup, and retires the keys the hub's
// key cannot derive, so the hub starts on a fresh one; what they sealed is
// reported lost, by name, and the restore says so in the audit trail.
func TestAcceptingSecretLossLeavesAHubThatStarts(t *testing.T) {
	dir, secretID := hub(t)
	b := backup(t, dir, hubKey)
	cps := filepath.Join(t.TempDir(), "checkpoints.jsonl")

	t.Setenv(secretbroker.EnvPassphraseKey, otherKey)
	rep, err := dbbackup.Restore(b, dbPath(dir), dbbackup.RestoreOptions{
		Key: otherKey, Force: true, AllowUnsealed: true, AcceptSecretLoss: true,
		Reason: "hub.env lost and no escrow", Actor: "cli:test", CheckpointFile: cps,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Recorded.RetiredKeys) != 1 {
		t.Fatalf("retired %v", rep.Recorded.RetiredKeys)
	}

	// The hub's broker starts — a fresh primary under the key it has — and
	// leases without the secret it cannot open, which says why.
	if v, err := leaseValue(t, dir); err != nil || v != "" {
		t.Fatalf("leasing after the loss: %q, %v", v, err)
	}
	if err := openSecret(t, dir, secretID); !errors.Is(err, secretbroker.ErrKeyRetired) {
		t.Fatalf("opening a secret sealed under a retired key: %v", err)
	}
	db, err := statedb.Open(dbPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var payload map[string]any
	row := rep.Recorded.Row
	if row.EventType != string(auditaction.ActionAuditRestored) || json.Unmarshal([]byte(row.Payload), &payload) != nil {
		t.Fatalf("row %+v", row)
	}
	if payload["accepted_loss"] != true || !strings.Contains(row.Payload, rep.Recorded.RetiredKeys[0]) {
		t.Fatalf("payload %s", row.Payload)
	}
	stored, ok, err := db.AuditRowAt(row.ID)
	if err != nil || !ok || stored.RowHash != row.RowHash {
		t.Fatalf("the audit.restored row is not in the restored chain: %+v %v %v", stored, ok, err)
	}
	if rr := rep.Recorded.Record.Restore; rr == nil || len(rr.SecretLoss) != 1 || rr.Sidecar != string(dbbackup.SidecarUnchecked) {
		t.Fatalf("the restore record does not name the loss and the unchecked sidecar: %+v", rep.Recorded.Record)
	}
}

// A rotation leaves the old key active with nothing sealed under it until it
// is retired. Restored under a key that derives neither, the hub would refuse
// to start on the old one — OpenKeyring derives the whole registry when the
// primary is gone — so --accept-secret-loss must give up both.
func TestAcceptingSecretLossGivesUpEveryKeyTheHubWouldStopOn(t *testing.T) {
	dir, _ := hub(t)
	db, err := statedb.Open(dbPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := secretbroker.OpenKeyring(store)
	if err != nil {
		t.Fatal(err)
	}
	rot, err := secretbroker.NewRotator(kr, store)
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := rot.Rotate(context.Background(), secretbroker.RotateOptions{NewKey: true, Actor: "test"}); err != nil || !rep.Complete {
		t.Fatalf("rotate: %+v %v", rep, err)
	}
	_ = db.Close()
	b := backup(t, dir, hubKey)

	pre, err := dbbackup.Inspect(b, dbbackup.PreflightOptions{Key: otherKey, AllowUnsealed: true, AcceptSecretLoss: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(pre.LostKeys()) != 2 {
		t.Fatalf("lost %+v; want both keys, the emptied one too", pre.LostKeys())
	}
	t.Setenv(secretbroker.EnvPassphraseKey, otherKey)
	if _, err := dbbackup.Restore(b, dbPath(dir), dbbackup.RestoreOptions{Key: otherKey, Force: true,
		AllowUnsealed: true, AcceptSecretLoss: true, Reason: "test", Actor: "cli:test"}); err != nil {
		t.Fatal(err)
	}
	db, err = statedb.Open(dbPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err = secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secretbroker.OpenKeyring(store); err != nil {
		t.Fatalf("the restored hub does not start: %v", err)
	}
}

// A database's write-ahead log is part of it. One left beside a missing
// state.db would be replayed into the restored file the first time anything
// opened it — SQLite does not ask whose log it is — so it moves aside with
// the rest, and the restored chain is the backup's.
func TestAStaleLogIsNotReplayedIntoTheRestore(t *testing.T) {
	dir, _ := hub(t)
	b := backup(t, dir, hubKey)
	pre, err := dbbackup.Inspect(b, dbbackup.PreflightOptions{Key: hubKey})
	if err != nil || pre.Err() != nil {
		t.Fatal(err, pre.Err())
	}

	// Another database's log, still holding its frames, beside where the
	// restore will put the file.
	other := filepath.Join(t.TempDir(), "other.db")
	statedbtest.Template().Seed(t, other)
	odb, err := statedb.Open(other)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := odb.AppendAuditEvent(&statedb.AuditEvent{Actor: "other", EventType: "task.upsert", EntityType: "task"}); err != nil {
			t.Fatal(err)
		}
	}
	wal, err := os.ReadFile(other + "-wal")
	if err != nil || len(wal) == 0 {
		t.Fatalf("premise: the other database's log holds frames: %v", err)
	}
	_ = odb.Close()
	if err := os.Remove(dbPath(dir)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath(dir)+"-wal", wal, 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := dbbackup.Restore(b, dbPath(dir), dbbackup.RestoreOptions{Key: hubKey, Force: true, Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Recorded.RestoredHead.LastRowHash != pre.Chain.LastRowHash {
		t.Fatalf("the restored chain is not the backup's: %+v vs %+v", rep.Recorded.RestoredHead, pre.Chain)
	}
	if _, err := os.Stat(rep.BackedUpPath); err != nil || !strings.HasSuffix(rep.BackedUpPath, "-wal") {
		t.Fatalf("the stale log was not kept aside: %q %v", rep.BackedUpPath, err)
	}
}

// A key id that is not valid UTF-8 — any row the database's attacker writes —
// must not turn every later backup's seal into a refusal: the sidecar is
// sealed as it is written.
func TestAManifestOfInvalidUTF8StillVerifies(t *testing.T) {
	dir, _ := hub(t)
	conn, err := sql.Open("sqlite", dbPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`INSERT INTO broker_keks(id, salt, state, created_at)
		VALUES (CAST(X'6b656b5fff' AS TEXT), '', 'retired', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	b := backup(t, dir, hubKey)
	pre, err := dbbackup.Inspect(b, dbbackup.PreflightOptions{Key: hubKey})
	if err != nil {
		t.Fatal(err)
	}
	if pre.Err() != nil || pre.Sidecar != dbbackup.SidecarSealed {
		t.Fatalf("an untouched backup refused: %v (%s)", pre.Err(), pre.Sidecar)
	}
}

// A restore under the right key is recorded where the checkpoints can
// account for it: the audit.restored row, and a restore record sealed to the
// checkpoint file naming exactly the history it gave up.
func TestARestoreIsRecordedForTheCheckpoints(t *testing.T) {
	dir, _ := hub(t)
	cps := filepath.Join(t.TempDir(), "checkpoints.jsonl")
	key, err := auditcheckpoint.DeriveKey(hubKey)
	if err != nil {
		t.Fatal(err)
	}
	writeCheckpoint := func() auditcheckpoint.Record {
		t.Helper()
		time.Sleep(2 * time.Millisecond)
		db, err := statedb.Open(dbPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		head, err := db.AuditHead()
		if err != nil {
			t.Fatal(err)
		}
		rec := auditcheckpoint.HeadRecord(head, auditcheckpoint.ChainControlPlane, dbPath(dir),
			auditcheckpoint.ReasonInterval, 1, "member", time.Now())
		key.Seal(&rec)
		if err := (auditcheckpoint.Sink{File: cps}).Write([]auditcheckpoint.Record{rec}); err != nil {
			t.Fatal(err)
		}
		return rec
	}
	writeCheckpoint()
	b := backup(t, dir, hubKey)
	backedUp := writeCheckpoint()

	// History the backup does not hold, which a checkpoint saw.
	bk, closeDB := broker(t, dir)
	for i := 0; i < 3; i++ {
		if _, err := bk.Mint(context.Background(), secretbroker.MintRequest{Name: "later-" + string(rune('a'+i)),
			Kind: secretbroker.KindEnv, Payload: []byte(`{"X":"y"}`), Actor: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	closeDB()
	lost := writeCheckpoint()
	if lost.LastID <= backedUp.LastID {
		t.Fatal("premise: the history after the backup was checkpointed")
	}

	rep, err := dbbackup.Restore(b, dbPath(dir), dbbackup.RestoreOptions{
		Key: hubKey, Force: true, Reason: "rehearsal", Actor: "cli:test", CheckpointFile: cps,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := rep.Recorded
	if rec.Superseded == nil || rec.Superseded.LastID != lost.LastID {
		t.Fatalf("superseded %+v, want the checkpoint at id %d", rec.Superseded, lost.LastID)
	}
	if rec.RestoredHead.LastID != backedUp.LastID || rec.Row.ID != backedUp.LastID+1 || !rec.Sealed {
		t.Fatalf("recording %+v", rec)
	}
	if v, err := leaseValue(t, dir); err != nil || v != "the-drill-secret-value" {
		t.Fatalf("after the restore the secret leases as %q, %v", v, err)
	}

	parsed, err := auditcheckpoint.ReadFile(cps)
	if err != nil {
		t.Fatal(err)
	}
	db, err := statedb.Open(dbPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	recs := auditcheckpoint.ByPath(parsed.Records)[auditcheckpoint.ValidPath(dbPath(dir))]
	chain, err := auditcheckpoint.VerifyChain(db, dbPath(dir), auditcheckpoint.ChainControlPlane, recs, key)
	if err != nil {
		t.Fatal(err)
	}
	if !chain.OK() || len(chain.Restores) != 1 {
		t.Fatalf("%s — %+v", chain.Finding, chain)
	}
	f := chain.Restores[0]
	if want := lost.LastID - backedUp.LastID; f.LostEvents != want || f.To != lost.Time {
		t.Errorf("lost %d through %s, want %d through %s", f.LostEvents, f.To, want, lost.Time)
	}
	if !strings.Contains(f.Summary(), `by cli:test, reason "rehearsal"`) || !f.Vouched() {
		t.Errorf("summary %q", f.Summary())
	}
	if rec.Record.Restore.Sidecar != string(dbbackup.SidecarSealed) {
		t.Errorf("the record says the sidecar was %q", rec.Record.Restore.Sidecar)
	}
}

func fileSHA(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func writeMeta(t *testing.T, backup string, m *dbbackup.Metadata) {
	t.Helper()
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup+dbbackup.MetadataSuffix, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A restore does not take a database from under a hub still serving it,
// --force or not: the hub would keep writing to the file moved aside.
func TestARestoreUnderAServingHubIsRefused(t *testing.T) {
	dir, _ := hub(t)
	b := backup(t, dir, hubKey)
	lease, err := hublease.Acquire(hublease.Options{DBPath: dbPath(dir)})
	if err != nil {
		t.Fatal(err)
	}
	before := fileSHA(t, dbPath(dir))
	_, err = dbbackup.Restore(b, dbPath(dir), dbbackup.RestoreOptions{Key: hubKey, Force: true, Reason: "test"})
	if !errors.Is(err, dbbackup.ErrHubServing) {
		t.Fatalf("restoring under a serving hub: %v", err)
	}
	if fileSHA(t, dbPath(dir)) != before {
		t.Fatal("the served database was touched")
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := dbbackup.Restore(b, dbPath(dir), dbbackup.RestoreOptions{Key: hubKey, Force: true, Reason: "test"}); err != nil {
		t.Fatalf("once the hub stopped: %v", err)
	}
}
