package cmd

// The disaster-recovery drill, end to end (Task 20410): the procedure the
// runbook asks an operator to rehearse, run against a real control plane,
// a real broker and the real commands.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/auditcheckpoint"
	"github.com/blechschmidt/cloop/pkg/dbbackup"
	"github.com/blechschmidt/cloop/pkg/keyescrow"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	drillHubKey     = "drill-hub-key-Zq4pV9mW2xT7rL0yH3nB8kD5sF1gJ6cA-uE"
	drillFreshKey   = "drill-key-a-fresh-bootstrap-made-0123456789abcd"
	drillPassphrase = "the drill passphrase nobody would guess"
	drillProject    = "/srv/drill-project"
	drillSecret     = "the-drill-secret-value"
)

func TestDisasterRecoveryDrill(t *testing.T) {
	// Before anything seals: this host's environment may carry another key.
	t.Setenv(secretbroker.EnvPassphraseKey, drillHubKey)

	dir := auditDir(t)
	dbPath := state.DBPath(dir)
	offHost := t.TempDir()
	cps := filepath.Join(offHost, "audit-checkpoints.jsonl")
	passFile := filepath.Join(offHost, "escrow-passphrase")
	escrowPath := filepath.Join(offHost, "cloop-hub.escrow")
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"),
		[]byte("audit:\n  checkpoints:\n    file: "+cps+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passFile, []byte(drillPassphrase+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A hub with a secret a project leases, its key escrowed, a checkpoint
	// written, and a backup taken.
	drillMint(t, dir, "drill-token", drillSecret)
	if got := drillLease(t, dir); got != drillSecret {
		t.Fatalf("premise: the secret leases as %q", got)
	}
	var out bytes.Buffer
	if err := runEscrowExport(&out, escrowOptions{Workdir: dir, File: escrowPath, PassphraseFile: passFile,
		Key: drillHubKey, Now: time.Now}); err != nil {
		t.Fatalf("escrow export: %v\n%s", err, out.String())
	}
	drillCheckpoint(t, dir, cps)
	backupPath := filepath.Join(offHost, "state-backup.db")
	bk, err := dbbackup.BackupWithOptions(dbPath, backupPath, dbbackup.BackupOptions{Key: drillHubKey})
	if err != nil || !bk.Sealed() {
		t.Fatalf("backup: %+v %v", bk, err)
	}
	backedUp := drillHead(t, dir)
	var backupKEK string
	for _, k := range bk.Keys {
		if k.Rows["secrets"] > 0 {
			backupKEK = k.ID
		}
	}

	// Life goes on: the sealing key is rotated, more is written, and a
	// checkpoint sees it — history the backup does not hold.
	h, err := openHubKeyring(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.rotator.Rotate(context.Background(), secretbroker.RotateOptions{NewKey: true, Actor: "drill"}); err != nil {
		t.Fatal(err)
	}
	if h.keyring.PrimaryID() == backupKEK {
		t.Fatal("premise: the rotation minted a new key")
	}
	h.close()
	drillMint(t, dir, "after-the-backup", "minted after the backup")
	drillLease(t, dir)
	lost := drillCheckpoint(t, dir, cps)
	if lost.LastID <= backedUp.LastID {
		t.Fatal("premise: a checkpoint saw history after the backup")
	}

	// The disaster: hub.env is gone, and re-bootstrapping gave the host a
	// new key.
	envPath := filepath.Join(dir, ".cloop", hubEnvFile)
	if err := os.WriteFile(envPath, []byte("CLOOP_SECRET_KEY="+drillFreshKey+"\nCLOOP_UI_TOKEN=tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("a restore under another key is refused, and touches nothing", func(t *testing.T) {
		before := drillFileSHA(t, dbPath)
		code, out, _ := drillRestore(t, dir, backupPath, drillFreshKey, "drill", false)
		if code != restoreExitRefused {
			t.Fatalf("exit %d\n%s", code, out)
		}
		for _, want := range []string{"Refused — nothing was changed", backupKEK + " (1 secrets)", "--accept-secret-loss"} {
			if !strings.Contains(out, want) {
				t.Errorf("the refusal does not say %q:\n%s", want, out)
			}
		}
		if drillFileSHA(t, dbPath) != before {
			t.Fatal("a refused restore changed the live database")
		}
	})

	t.Run("the escrow brings the key back", func(t *testing.T) {
		var buf bytes.Buffer
		code := runEscrowImport(&buf, escrowOptions{Workdir: dir, File: escrowPath, PassphraseFile: passFile,
			Force: true, Now: time.Now})
		if code != 0 {
			t.Fatalf("exit %d\n%s", code, buf.String())
		}
		if got := drillEnvKey(t, envPath); got != drillHubKey {
			t.Fatalf("hub.env holds %q", got)
		}
		kept, _ := filepath.Glob(envPath + ".pre-import.*")
		if len(kept) != 1 || drillEnvKey(t, kept[0]) != drillFreshKey {
			t.Fatalf("the key it replaced was not kept aside: %v", kept)
		}
		if !strings.Contains(string(drillRead(t, envPath)), "CLOOP_UI_TOKEN=tok") {
			t.Error("the env file's other lines were lost")
		}
	})

	key := drillEnvKey(t, envPath)
	t.Setenv(secretbroker.EnvPassphraseKey, key)

	t.Run("the restore under the recovered key unseals, and a lease works", func(t *testing.T) {
		code, out, stderr := drillRestore(t, dir, backupPath, key, "drill: hub.env lost", false)
		if code != restoreExitOK {
			t.Fatalf("exit %d\n%s", code, out)
		}
		if got := drillLease(t, dir); got != drillSecret {
			t.Fatalf("after the restore the secret leases as %q", got)
		}
		if !strings.Contains(stderr, `"reason":"restore"`) || !strings.Contains(stderr, auditcheckpoint.Kind) {
			t.Errorf("the restore record's stderr copy: %q", stderr)
		}
		for _, want := range []string{fmt.Sprintf("supersedes:  the checkpoint at %s, which saw id %d", lost.Time, lost.LastID),
			"audit.restored row", "restore record sealed under key"} {
			if !strings.Contains(out, want) {
				t.Errorf("the restore does not say %q:\n%s", want, out)
			}
		}
	})

	restoredRow := backedUp.LastID + 1
	t.Run("the checkpoints acknowledge the restore, with the window it lost", func(t *testing.T) {
		code, out := runVerify(t, hubAuditVerifyOptions{Hub: dir, Project: dir, CheckpointsFile: cps})
		if code != auditExitIntact {
			t.Fatalf("exit %d\n%s", code, out)
		}
		want := fmt.Sprintf("restored (acknowledged): %d events lost between %s and %s, by cli:%s, reason %q",
			lost.LastID-backedUp.LastID, auditcheckpoint.FormatTime(backedUp.LastTimestamp), lost.Time,
			currentUser(), "drill: hub.env lost")
		if !strings.Contains(out, want) {
			t.Fatalf("verify does not report\n  %s\n%s", want, out)
		}
		row := drillRow(t, dir, restoredRow)
		if row.EventType != string(auditaction.ActionAuditRestored) {
			t.Fatalf("row %d is %s, not the restore", restoredRow, row.EventType)
		}
	})

	t.Run("a tail deleted while the hub keeps writing still fails", func(t *testing.T) {
		appendAudit(t, dir, 3, auditaction.ActionExecutorCordon)
		drillCheckpoint(t, dir, cps)
		rawDB(t, dbPath, fmt.Sprintf(`DELETE FROM audit_events WHERE id > %d`, restoredRow+1))
		appendAudit(t, dir, 4, auditaction.ActionExecutorCordon)
		code, out := runVerify(t, hubAuditVerifyOptions{Hub: dir, Project: dir, CheckpointsFile: cps})
		if code != auditExitBroken || !strings.Contains(out, "RESTORED ") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})

	t.Run("a hand-written restore record is refused", func(t *testing.T) {
		head := drillHead(t, dir)
		x := auditcheckpoint.Restore{RestoredID: restoredRow + 1, BackupSHA256: strings.Repeat("ab", 32),
			Actor: "cli:mallory", Reason: "nothing to see"}
		abs, _ := filepath.Abs(dbPath)
		forged := auditcheckpoint.RestoreRecord(head, auditcheckpoint.ChainControlPlane, abs, "m", time.Now(), x)
		if err := (auditcheckpoint.Sink{File: cps}).Write([]auditcheckpoint.Record{forged}); err != nil {
			t.Fatal(err)
		}
		// The chain is already broken by the subtest before; what is being
		// checked is that the hand-written record explains none of it.
		code, out := runVerify(t, hubAuditVerifyOptions{Hub: dir, Project: dir, CheckpointsFile: cps})
		if code != auditExitBroken || !strings.Contains(out, "carries no seal") {
			t.Fatalf("exit %d\n%s", code, out)
		}
		if strings.Contains(out, "by cli:mallory") {
			t.Fatalf("the hand-written record was acknowledged:\n%s", out)
		}

		// Sealed with somebody's key, but not this hub's.
		other, err := auditcheckpoint.DeriveKey("not-the-hubs-key-0123456789abcdef")
		if err != nil {
			t.Fatal(err)
		}
		other.Seal(&forged)
		forged.KeyFingerprint = dbbackup.KeyFingerprint(key) // claims the hub's key
		if err := (auditcheckpoint.Sink{File: cps}).Write([]auditcheckpoint.Record{forged}); err != nil {
			t.Fatal(err)
		}
		code, out = runVerify(t, hubAuditVerifyOptions{Hub: dir, Project: dir, CheckpointsFile: cps})
		if code != auditExitBroken || !strings.Contains(out, "its seal does not verify") || strings.Contains(out, "by cli:mallory") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})

	t.Run("an edited backup with a recomputed SHA-256 is refused", func(t *testing.T) {
		edited := filepath.Join(t.TempDir(), "edited.db")
		if err := os.WriteFile(edited, drillRead(t, backupPath), 0o600); err != nil {
			t.Fatal(err)
		}
		rawDB(t, edited, `UPDATE broker_grants SET subject_type = 'any', subject_value = ''`)
		var meta dbbackup.Metadata
		if err := json.Unmarshal(drillRead(t, backupPath+dbbackup.MetadataSuffix), &meta); err != nil {
			t.Fatal(err)
		}
		meta.SHA256 = drillFileSHA(t, edited)
		b, _ := json.Marshal(meta)
		if err := os.WriteFile(edited+dbbackup.MetadataSuffix, b, 0o600); err != nil {
			t.Fatal(err)
		}
		code, out, _ := drillRestore(t, dir, edited, key, "drill", true)
		if code != restoreExitRefused || !strings.Contains(out, "its seal does not verify under it") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
}

func drillRestore(t *testing.T, dir, backup, key, reason string, check bool) (int, string, string) {
	t.Helper()
	var out, stderr bytes.Buffer
	code := runDBRestore(&out, dbRestoreOptions{Backup: backup, Workdir: dir, Reason: reason, Force: true,
		Check: check, Key: key, Stderr: &stderr})
	return code, out.String(), stderr.String()
}

// drillBroker builds the hub's broker over dir's control plane, auditing as
// the hub does.
func drillBroker(t *testing.T, dir string) (*secretbroker.Broker, func()) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	b, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	return b, func() { _ = db.Close() }
}

func drillMint(t *testing.T, dir, name, value string) {
	t.Helper()
	b, done := drillBroker(t, dir)
	defer done()
	ctx := context.Background()
	s, err := b.Mint(ctx, secretbroker.MintRequest{Name: name, Kind: secretbroker.KindEnv,
		Payload: []byte(fmt.Sprintf(`{"DRILL_TOKEN":%q}`, value)), Actor: "drill"})
	if err != nil {
		t.Fatal(err)
	}
	if name != "drill-token" {
		return // granted elsewhere, so the drill's lease stays one value
	}
	if _, err := b.Grant(ctx, secretbroker.GrantRequest{SecretRef: s.ID, Actor: "drill",
		Subject: secretbroker.Subject{Type: secretbroker.SubjectProject, Value: drillProject}}); err != nil {
		t.Fatal(err)
	}
}

// drillLease leases the project's credentials and returns DRILL_TOKEN.
func drillLease(t *testing.T, dir string) string {
	t.Helper()
	b, done := drillBroker(t, dir)
	defer done()
	l, err := b.Lease(context.Background(), "drill-executor", drillProject)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Release(l.ID)
	for _, m := range l.Materials {
		if v, ok := m.Env["DRILL_TOKEN"]; ok {
			return v
		}
	}
	return ""
}

// drillCheckpoint writes the control plane's head to the checkpoint file the
// way the cluster leader does, under the key in the environment.
func drillCheckpoint(t *testing.T, dir, file string) auditcheckpoint.Record {
	t.Helper()
	key, err := auditcheckpoint.KeyFromRoots()
	if err != nil {
		t.Fatal(err)
	}
	head := drillHead(t, dir)
	abs, _ := filepath.Abs(state.DBPath(dir))
	rec := auditcheckpoint.HeadRecord(head, auditcheckpoint.ChainControlPlane, abs,
		auditcheckpoint.ReasonInterval, time.Now().Unix()/300, "drill-leader", time.Now())
	key.Seal(&rec)
	if err := (auditcheckpoint.Sink{File: file}).Write([]auditcheckpoint.Record{rec}); err != nil {
		t.Fatal(err)
	}
	return rec
}

func drillHead(t *testing.T, dir string) statedb.AuditHead {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	head, err := db.AuditHead()
	if err != nil {
		t.Fatal(err)
	}
	return head
}

func drillRow(t *testing.T, dir string, id int64) statedb.AuditEvent {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	row, ok, err := db.AuditRowAt(id)
	if err != nil || !ok {
		t.Fatalf("row %d: %v %v", id, ok, err)
	}
	return row
}

func drillEnvKey(t *testing.T, path string) string {
	t.Helper()
	for _, line := range strings.Split(string(drillRead(t, path)), "\n") {
		if v, ok := strings.CutPrefix(line, keyescrow.EnvKey+"="); ok {
			return v
		}
	}
	return ""
}

func drillRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func drillFileSHA(t *testing.T, path string) string {
	t.Helper()
	sum := sha256.Sum256(drillRead(t, path))
	return hex.EncodeToString(sum[:])
}

// The same command restores a project's database, and the restore record
// goes to the hub's checkpoint file, where the project chain's checkpoints
// are: verify acknowledges it there exactly as it does the control plane's.
func TestAProjectRestoreIsAcknowledgedToo(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, drillHubKey)
	hub, project := auditDir(t), auditDir(t)
	appendAudit(t, hub, 2, auditaction.ActionExecutorCordon)
	appendAudit(t, project, 4, auditaction.ActionTaskUpsert)
	cps := filepath.Join(t.TempDir(), "audit-checkpoints.jsonl")
	key, err := auditcheckpoint.KeyFromRoots()
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := func(dir, chain string) auditcheckpoint.Record {
		t.Helper()
		abs, _ := filepath.Abs(state.DBPath(dir))
		rec := auditcheckpoint.HeadRecord(drillHead(t, dir), chain, abs, auditcheckpoint.ReasonInterval, 1, "leader", time.Now())
		key.Seal(&rec)
		if err := (auditcheckpoint.Sink{File: cps}).Write([]auditcheckpoint.Record{rec}); err != nil {
			t.Fatal(err)
		}
		return rec
	}
	checkpoint(hub, auditcheckpoint.ChainControlPlane)
	checkpoint(project, auditcheckpoint.ChainProject)
	backupPath := filepath.Join(t.TempDir(), "project.db")
	if _, err := dbbackup.BackupWithOptions(state.DBPath(project), backupPath, dbbackup.BackupOptions{Key: drillHubKey}); err != nil {
		t.Fatal(err)
	}
	appendAudit(t, project, 6, auditaction.ActionTaskUpsert)
	lost := checkpoint(project, auditcheckpoint.ChainProject)

	code, out := runVerify(t, hubAuditVerifyOptions{Hub: hub, Project: project, CheckpointsFile: cps})
	if code != auditExitIntact {
		t.Fatalf("before the restore: exit %d\n%s", code, out)
	}

	var restoreOut, stderr bytes.Buffer
	if code := runDBRestore(&restoreOut, dbRestoreOptions{Backup: backupPath, Workdir: project, Force: true,
		Reason: "project rollback", Key: drillHubKey, CheckpointFile: cps, Stderr: &stderr}); code != restoreExitOK {
		t.Fatalf("restore: exit %d\n%s", code, restoreOut.String())
	}
	code, out = runVerify(t, hubAuditVerifyOptions{Hub: hub, Project: project, CheckpointsFile: cps})
	if code != auditExitIntact {
		t.Fatalf("after the restore: exit %d\n%s", code, out)
	}
	backedUp := drillRow(t, project, 4)
	want := fmt.Sprintf("restored (acknowledged): 6 events lost between %s and %s, by cli:%s, reason %q",
		auditcheckpoint.FormatTime(backedUp.Timestamp), lost.Time, currentUser(), "project rollback")
	if !strings.Contains(out, "RESTORED      project") || !strings.Contains(out, want) {
		t.Fatalf("the project's restore is not acknowledged:\n%s", out)
	}
	if strings.Contains(out, "RESTORED      control-plane") {
		t.Fatalf("the control plane was not restored:\n%s", out)
	}
	parsed, err := auditcheckpoint.ReadFile(cps)
	if err != nil {
		t.Fatal(err)
	}
	last := parsed.Records[len(parsed.Records)-1]
	if !last.IsRestore() || last.Chain != auditcheckpoint.ChainProject {
		t.Fatalf("the restore record names chain %q: %+v", last.Chain, last.Record)
	}
}

func TestEscrowCommandsRefuseWhatCannotRecover(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, drillHubKey)
	dir := auditDir(t)
	drillMint(t, dir, "drill-token", drillSecret) // records the hub's first sealing key
	offHost := t.TempDir()
	passFile := filepath.Join(offHost, "pass")
	if err := os.WriteFile(passFile, []byte(drillPassphrase), 0o600); err != nil {
		t.Fatal(err)
	}
	escrowPath := filepath.Join(offHost, "hub.escrow")
	export := func(key, file string) error {
		return runEscrowExport(&bytes.Buffer{}, escrowOptions{Workdir: dir, File: file, PassphraseFile: passFile,
			Key: key, Now: time.Now})
	}

	if err := export(drillFreshKey, escrowPath); err == nil || !strings.Contains(err.Error(), "does not open this hub's sealing keys") {
		t.Fatalf("escrowing a key that is not the hub's: %v", err)
	}
	if err := export(drillHubKey, filepath.Join(dir, ".cloop", "hub.escrow")); err == nil {
		t.Fatal("an escrow beside the database it is meant to outlive was written")
	}
	if err := export("", escrowPath); err == nil {
		t.Fatal("an escrow of no key was written")
	}
	weak := filepath.Join(offHost, "weak")
	if err := os.WriteFile(weak, []byte("hunter2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runEscrowExport(&bytes.Buffer{}, escrowOptions{Workdir: dir, File: escrowPath, PassphraseFile: weak,
		Key: drillHubKey, Now: time.Now}); !errors.Is(err, keyescrow.ErrWeakPassphrase) {
		t.Fatalf("a weak passphrase: %v", err)
	}
	if _, err := os.Stat(escrowPath); !os.IsNotExist(err) {
		t.Fatal("a refused export left a file")
	}

	if err := export(drillHubKey, escrowPath); err != nil {
		t.Fatal(err)
	}
	wrong := filepath.Join(offHost, "wrong")
	if err := os.WriteFile(wrong, []byte("not the drill passphrase at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := runEscrowVerify(&out, escrowOptions{Workdir: dir, File: escrowPath, PassphraseFile: wrong, Now: time.Now}); code != 1 ||
		!strings.Contains(out.String(), "DOES NOT OPEN") {
		t.Fatalf("a wrong passphrase: exit %d\n%s", code, out.String())
	}

	// A restore of a database older than the escrow loses the record of it;
	// verify --record puts it back, once it has proven the file opens the hub.
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteHubMeta("key_escrow"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	out.Reset()
	if code := runEscrowVerify(&out, escrowOptions{Workdir: dir, File: escrowPath, PassphraseFile: passFile,
		Key: drillHubKey, Record: true, Now: time.Now}); code != 0 {
		t.Fatalf("verify --record: exit %d\n%s", code, out.String())
	}
	for _, want := range []string{"OPENS THE HUB", "IN USE", "NOT ON RECORD", "RECORDED"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("verify does not say %q:\n%s", want, out.String())
		}
	}
	// verify without --record writes nothing to the hub's database — not even
	// a migration — and with it records the escrow and nothing else.
	db, err = statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.WALCheckpointTruncate()
	_ = db.Close()
	before := drillFileSHA(t, state.DBPath(dir))
	out.Reset()
	if code := runEscrowVerify(&out, escrowOptions{Workdir: dir, File: escrowPath, PassphraseFile: passFile,
		Key: drillHubKey, Now: time.Now}); code != 0 {
		t.Fatalf("verify: exit %d\n%s", code, out.String())
	}
	if drillFileSHA(t, state.DBPath(dir)) != before {
		t.Fatal("verify wrote to the hub's database")
	}
	if _, err := os.Stat(state.DBPath(dir) + "-wal"); err == nil {
		if wal := drillRead(t, state.DBPath(dir)+"-wal"); len(wal) > 0 {
			t.Fatal("verify wrote to the hub's log")
		}
	}

	db, err = statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	f, err := keyescrow.ReadFile(escrowPath)
	if err != nil {
		t.Fatal(err)
	}
	if rec, ok, err := keyescrow.LoadRecord(db); err != nil || !ok || rec.ID != f.ID || rec.RecordedBy == "" {
		t.Fatalf("record %+v %v %v", rec, ok, err)
	}
}

// A restore onto a replacement host starts from a directory with no database.
// The commands that put one back must not create one first: the root pre-run
// reconciles executors, which opens the working directory's database and
// creates it when it is missing — after which the restore found a database
// "already there" and asked for --force.
func TestTheRecoveryCommandsCreateNoDatabase(t *testing.T) {
	for _, c := range []*cobra.Command{dbRestoreCmd, hubKeyEscrowImportCmd} {
		t.Run(c.CommandPath(), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Chdir(dir)
			if err := rootCmd.PersistentPreRunE(c, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(state.DBPath(dir)); !os.IsNotExist(err) {
				t.Fatalf("%s's pre-run created %s", c.CommandPath(), state.DBPath(dir))
			}
		})
	}
	// The premise: an ordinary command's pre-run does create it.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if err := rootCmd.PersistentPreRunE(dbBackupCmd, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(state.DBPath(dir)); err != nil {
		t.Skipf("premise no longer holds — the pre-run creates no database for any command (%v)", err)
	}
}

// The restore record goes where the hubs here write their checkpoints: a
// per-instance overlay's file wins over config.yaml's, as it does for the hub
// reading it, and hubs writing different files leave the choice to the
// operator.
func TestTheRestoreRecordGoesWhereTheHubsCheckpointsGo(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, file string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, ".cloop", name),
			[]byte("audit:\n  checkpoints:\n    file: "+file+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("config.yaml", "/var/log/cloop/from-config.jsonl")
	if f, _, note := restoreCheckpointSinks(dir, ""); f != "/var/log/cloop/from-config.jsonl" || note != "" {
		t.Fatalf("config.yaml alone: %q %q", f, note)
	}
	write("config.ui-8081.yaml", "/var/log/cloop/from-overlay.jsonl")
	if f, _, note := restoreCheckpointSinks(dir, ""); f != "/var/log/cloop/from-overlay.jsonl" || note != "" {
		t.Fatalf("an overlay overriding it: %q %q", f, note)
	}
	write("config.ui-8082.yaml", "/var/log/cloop/another.jsonl")
	if f, stderr, note := restoreCheckpointSinks(dir, ""); f != "" || !stderr || !strings.Contains(note, "--checkpoints") {
		t.Fatalf("two hubs, two files: %q %v %q", f, stderr, note)
	}
	if f, _, _ := restoreCheckpointSinks(dir, "/explicit.jsonl"); f != "/explicit.jsonl" {
		t.Fatalf("--checkpoints: %q", f)
	}
}
