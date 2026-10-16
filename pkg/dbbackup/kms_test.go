package dbbackup_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/dbbackup"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/kms/kmstest"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// A backup of a hub whose sealing keys a KMS holds restores only where that
// KMS answers (Task 20433). The preflight asks the KMS the restored hub will
// run with, says in every case that the backup depends on it, and refuses —
// naming the reason — without it, with it unreachable, or with no root at
// all; with it, the backup restores and its secret leases.
func TestABackupOfAKMSHubRestoresOnlyWithTheKMS(t *testing.T) {
	for _, v := range []string{rootkey.EnvKeyFile, rootkey.EnvPreviousFile, rootkey.EnvCredentialsDirectory,
		rootkey.EnvPrevious} {
		t.Setenv(v, "")
	}
	t.Setenv(secretbroker.EnvPassphraseKey, hubKey)
	p := kmstest.StartPlugin(t)
	prov, err := kms.Open(config.KMSConfig{Provider: config.KMSProviderKMSv2,
		KMSv2: config.KMSv2Config{Endpoint: p.Endpoint()}})
	if err != nil {
		t.Fatal(err)
	}
	defer prov.Close()
	t.Cleanup(secretbroker.ForgetOpenedKeys)
	unpin := secretbroker.PinRoots(secretbroker.KMSRoot(prov), secretbroker.Root{})
	defer unpin()

	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	b, closeDB := broker(t, dir)
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
	closeDB()
	bk := backup(t, dir, hubKey)
	kmsList := []secretbroker.KMS{prov}

	// With the KMS: it opens, and the report says the backup needs it.
	secretbroker.ForgetOpenedKeys()
	pre, err := dbbackup.Inspect(bk, dbbackup.PreflightOptions{Key: hubKey, KMS: kmsList})
	if err != nil {
		t.Fatal(err)
	}
	if err := pre.Err(); err != nil {
		t.Fatalf("refused with the KMS: %v", err)
	}
	held := 0
	for _, k := range pre.Keys {
		if k.KMS != "" {
			held++
			if !k.Opens || k.KMS != prov.Name() {
				t.Fatalf("key verdict = %+v", k)
			}
		}
	}
	if held != 1 {
		t.Fatalf("%d KMS-held keys reported, want 1", held)
	}
	if !strings.Contains(strings.Join(pre.Notes, "\n"), "restores only where that KMS key answers") {
		t.Fatalf("the report does not say the backup needs the KMS: %q", pre.Notes)
	}

	// Without a KMS configured: refused, saying a restore needs one.
	secretbroker.ForgetOpenedKeys()
	pre, _ = dbbackup.Inspect(bk, dbbackup.PreflightOptions{Key: hubKey})
	if err := pre.Err(); !errors.Is(err, dbbackup.ErrSecretLoss) ||
		!strings.Contains(err.Error(), "needs access to it: no KMS is configured here") {
		t.Fatalf("without the KMS: %v", err)
	}

	// With the KMS unreachable: refused, saying the keys may be fine.
	p.Stop()
	secretbroker.ForgetOpenedKeys()
	pre, _ = dbbackup.Inspect(bk, dbbackup.PreflightOptions{Key: hubKey, KMS: kmsList})
	if err := pre.Err(); !errors.Is(err, dbbackup.ErrSecretLoss) || !strings.Contains(err.Error(), "cannot be reached") {
		t.Fatalf("with the KMS down: %v", err)
	}

	// With no root at all: refused, and no flag accepts the loss.
	pre, _ = dbbackup.Inspect(bk, dbbackup.PreflightOptions{AcceptSecretLoss: true})
	var refused *dbbackup.RefusedError
	if err := pre.Err(); !errors.As(err, &refused) || refused.Refusals[len(refused.Refusals)-1].Override != "" {
		t.Fatalf("with no root at all: %v", err)
	}

	// Back up: the restore goes through, and the restored hub leases.
	if err := p.Restart(); err != nil {
		t.Fatal(err)
	}
	secretbroker.ForgetOpenedKeys()
	restored := t.TempDir()
	if _, err := dbbackup.Restore(bk, dbPath(restored), dbbackup.RestoreOptions{
		Key: hubKey, KMS: kmsList, Reason: "drill", Actor: "test"}); err != nil {
		t.Fatalf("restore with the KMS: %v", err)
	}
	if v, err := leaseValue(t, restored); err != nil || v != "the-drill-secret-value" {
		t.Fatalf("the restored hub leases %q, %v", v, err)
	}
}
