package dbbackup_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditcheckpoint"
	"github.com/blechschmidt/cloop/pkg/dbbackup"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// A backup taken before CLOOP_SECRET_KEY was changed holds keys only the old
// root derives, and a sidecar sealed under it (Task 20425). Restored under the
// new root alone it is refused, as before; restored with the old root as the
// previous one — the configuration a change of root runs with — it restores,
// its secret leases, and the checkpoints written on both sides of the change
// account for the history it gave up.
func TestABackupFromBeforeAChangeOfRootRestoresWithThePreviousRootSet(t *testing.T) {
	dir, _ := hub(t) // sealed under hubKey, the old root
	for _, v := range []string{rootkey.EnvKeyFile, rootkey.EnvPreviousFile, rootkey.EnvCredentialsDirectory} {
		t.Setenv(v, "")
	}
	cps := filepath.Join(t.TempDir(), "checkpoints.jsonl")
	checkpoint := func(key *auditcheckpoint.Key) auditcheckpoint.Record {
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
	oldKey, err := auditcheckpoint.DeriveKey(hubKey)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint(oldKey)
	b := backup(t, dir, hubKey)
	backedUp := checkpoint(oldKey)

	// The change of root: the hub runs on otherKey with hubKey beside it,
	// everything moves onto otherKey and the old root's keys are retired.
	t.Setenv(rootkey.EnvKey, otherKey)
	t.Setenv(rootkey.EnvPrevious, hubKey)
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
	if rep, err := rot.RetirePrevious(context.Background(), secretbroker.RetirePreviousOptions{}); err != nil || !rep.Complete {
		t.Fatalf("retire the previous root: %+v, %v", rep, err)
	}
	bk, err := secretbroker.New(store, secretbroker.WithKeyring(kr), secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bk.Mint(context.Background(), secretbroker.MintRequest{Name: "after-the-change", Kind: secretbroker.KindEnv,
		Payload: []byte(`{"X":"y"}`), Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	both, err := auditcheckpoint.KeyForRoots(otherKey, hubKey)
	if err != nil {
		t.Fatal(err)
	}
	lost := checkpoint(both) // sealed under the new root

	// Under the new root alone: refused, exactly as any other key would be.
	pre, err := dbbackup.Inspect(b, dbbackup.PreflightOptions{Key: otherKey})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(pre.Err(), dbbackup.ErrSecretLoss) || !errors.Is(pre.Err(), dbbackup.ErrUnsealed) {
		t.Fatalf("under the new root alone: %v", pre.Err())
	}

	// With the old root as the previous: the sidecar's seal and the keys check.
	pre, err = dbbackup.Inspect(b, dbbackup.PreflightOptions{Key: otherKey, Previous: hubKey})
	if err != nil {
		t.Fatal(err)
	}
	if pre.Err() != nil || pre.Sidecar != dbbackup.SidecarSealed || pre.PreviousKeyFingerprint == "" {
		t.Fatalf("with the previous root: sidecar %s, %v", pre.Sidecar, pre.Err())
	}
	rep, err := dbbackup.Restore(b, dbPath(dir), dbbackup.RestoreOptions{
		Key: otherKey, Previous: hubKey, Force: true, Reason: "before the change", Actor: "cli:test", CheckpointFile: cps,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Recorded.Sealed || rep.Recorded.Record.KeyFingerprint != both.Fingerprint() {
		t.Errorf("the restore record is sealed under %q, want the new root's %s",
			rep.Recorded.Record.KeyFingerprint, both.Fingerprint())
	}
	if rep.Recorded.Superseded == nil || rep.Recorded.Superseded.LastID != lost.LastID {
		t.Errorf("superseded %+v, want the checkpoint sealed under the new root", rep.Recorded.Superseded)
	}
	if v, err := leaseValue(t, dir); err != nil || v != "the-drill-secret-value" {
		t.Fatalf("after the restore the secret leases as %q, %v", v, err)
	}

	parsed, err := auditcheckpoint.ReadFile(cps)
	if err != nil {
		t.Fatal(err)
	}
	vdb, err := statedb.Open(dbPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer vdb.Close()
	recs := auditcheckpoint.ByPath(parsed.Records)[auditcheckpoint.ValidPath(dbPath(dir))]
	chain, err := auditcheckpoint.VerifyChain(vdb, dbPath(dir), auditcheckpoint.ChainControlPlane, recs, both)
	if err != nil {
		t.Fatal(err)
	}
	if !chain.OK() || len(chain.Restores) != 1 || !chain.Restores[0].Vouched() || chain.ForeignKey != 0 {
		t.Fatalf("%s — %+v", chain.Finding, chain)
	}
	if want := lost.LastID - backedUp.LastID; chain.Restores[0].LostEvents != want {
		t.Errorf("lost %d events, want %d", chain.Restores[0].LostEvents, want)
	}
}
