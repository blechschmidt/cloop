package cmd

// The CLI over a store whose keys a KMS holds (Task 20433): moving onto a KMS
// with --retire-previous, following a rotation of the KMS key with rewrap, and
// `cloop ui` refusing to start on a KMS it cannot reach.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/kms/kmstest"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// useSecrets makes every keyring this test opens use sc's roots, as
// installKeyringRoots does for a command, and undoes it at the end.
func useSecrets(t *testing.T, sc config.SecretsConfig) {
	t.Helper()
	t.Cleanup(secretbroker.SetRootResolver(kms.Resolver(sc)))
	t.Cleanup(secretbroker.ForgetOpenedKeys)
}

func pluginSecrets(p *kmstest.Plugin) config.SecretsConfig {
	return config.SecretsConfig{KMS: config.KMSConfig{Provider: config.KMSProviderKMSv2, Timeout: "2s",
		KMSv2: config.KMSv2Config{Endpoint: p.Endpoint()}}}
}

// Moving onto a KMS is a change of root the CLI finishes: it waits for every
// member to advertise the KMS as its root, and for the KMS to answer, needs no
// escrow — no escrow opens what a KMS holds — and afterwards the store opens
// through the KMS alone.
func TestMovingOntoAKMSThroughTheCLI(t *testing.T) {
	clearRoots(t)
	t.Setenv(rootkey.EnvKey, rootChangeOld)
	dir := auditDir(t)
	drillMint(t, dir, "drill-token", "the value before the move")

	p := kmstest.StartPlugin(t)
	moving := pluginSecrets(p)
	moving.PreviousRoot = config.PreviousRootPassphrase
	useSecrets(t, moving)
	kmsName := moving.KMS.EffectiveName()
	oldFP, err := rootkey.Fingerprint(rootChangeOld)
	if err != nil {
		t.Fatal(err)
	}

	putMember(t, dir, "m-old", oldFP, "")
	out, err := retirePrevious(t, dir, false)
	if !errors.Is(err, errRootChangeNotReady) || !strings.Contains(out, "runs on root key "+oldFP) {
		t.Fatalf("a member still on the passphrase: %v\n%s", err, out)
	}
	putMember(t, dir, "m-old", kmsName, oldFP)

	p.Stop()
	secretbroker.ForgetOpenedKeys()
	out, err = retirePrevious(t, dir, false)
	if !errors.Is(err, errRootChangeNotReady) || !strings.Contains(out, "does not answer") {
		t.Fatalf("with the KMS down: %v\n%s", err, out)
	}
	if err := p.Restart(); err != nil {
		t.Fatal(err)
	}

	out, err = retirePrevious(t, dir, false)
	if err != nil {
		t.Fatalf("retire previous: %v\n%s", err, out)
	}
	if !strings.Contains(out, "no escrow is needed") || !strings.Contains(out, "secrets.previous_root") {
		t.Errorf("the output does not say what the move means:\n%s", out)
	}

	// The store now opens through the KMS alone, and its secret leases.
	alone := pluginSecrets(p)
	useSecrets(t, alone)
	secretbroker.ForgetOpenedKeys()
	if got := drillLease(t, dir); got != "the value before the move" {
		t.Fatalf("after the move the secret leases %q", got)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.ListKEKs()
	if err != nil {
		t.Fatal(err)
	}
	live := 0
	for _, r := range rows {
		if r.State != secretbroker.KEKStateRetired {
			live++
			if r.Wrap != secretbroker.WrapKMS || r.Root != kmsName {
				t.Fatalf("a live key is not the KMS's: %+v", r)
			}
		}
	}
	if live != 1 {
		t.Fatalf("%d live keys after the move", live)
	}
	auditHas(t, dir, "sealing_key.root_changed")
}

// `cloop hub key rewrap` follows a rotation of the KMS key, records it, and
// leaves nothing stale.
func TestRewrapFollowsTheKMSKey(t *testing.T) {
	clearRoots(t)
	p := kmstest.StartPlugin(t)
	useSecrets(t, pluginSecrets(p))
	dir := auditDir(t)
	drillMint(t, dir, "drill-token", "the value")
	newKey := p.Rotate()

	h, err := openHubKeyring(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if stale := h.keyring.StaleKMSKeys(newKey); len(stale) != 1 {
		t.Fatalf("stale before = %v", stale)
	}
	h.close()

	// Through the command itself, not the root: the root's pre-run reads the
	// working directory's configuration, which is not this test's hub.
	if err := hubKeyRewrapCmd.Flags().Set("workdir", dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hubKeyRewrapCmd.Flags().Set("workdir", "") })
	if err := hubKeyRewrapCmd.RunE(hubKeyRewrapCmd, nil); err != nil {
		t.Fatal(err)
	}
	h, err = openHubKeyring(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	if stale := h.keyring.StaleKMSKeys(newKey); len(stale) != 0 {
		t.Fatalf("stale after = %v", stale)
	}
	for _, k := range h.keyring.Keys() {
		if k.Primary && k.KMSKeyID != newKey {
			t.Fatalf("the primary is wrapped under %q", k.KMSKeyID)
		}
	}
	auditHas(t, dir, "sealing_key.kms_rewrapped")
	if got := drillLease(t, dir); got != "the value" {
		t.Fatalf("after the rewrap the secret leases %q", got)
	}
}

// `cloop ui` reaches its KMS before it serves anything and refuses to start —
// saying which KMS, and why — when it does not answer; and a KMS that answers
// but does not hold the store's keys stops it at the key check.
func TestUIRefusesToStartWithoutItsKMS(t *testing.T) {
	clearRoots(t)
	t.Setenv(rootkey.EnvKey, rootChangeOld)
	p := kmstest.StartPlugin(t)
	cfg := config.Default()
	cfg.Secrets = pluginSecrets(p)
	cfg.Secrets.KMS.StartupTimeout = "0s"
	keys, err := rootkey.Resolve()
	if err != nil {
		t.Fatal(err)
	}

	p.Stop()
	_, err = resolveHubRoots(context.Background(), cfg, keys)
	if err == nil || !strings.Contains(err.Error(), "refusing to open the secret store") ||
		!strings.Contains(err.Error(), p.Socket()) || !errors.Is(err, secretbroker.ErrKMSUnavailable) {
		t.Fatalf("an unreachable KMS at startup: %v", err)
	}

	// A store another plugin's key holds.
	if err := p.Restart(); err != nil {
		t.Fatal(err)
	}
	other := kmstest.StartPlugin(t)
	useSecrets(t, pluginSecrets(other))
	dir := auditDir(t)
	drillMint(t, dir, "drill-token", "v")
	secretbroker.ForgetOpenedKeys()

	roots, err := resolveHubRoots(context.Background(), cfg, keys)
	if err != nil {
		t.Fatalf("a KMS that answers: %v", err)
	}
	defer roots.Close()
	err = checkHubRoots(dir, roots)
	if err == nil || !errors.Is(err, secretbroker.ErrKeyUnavailable) || !strings.Contains(err.Error(), "did not unwrap") {
		t.Fatalf("a store another KMS holds: %v", err)
	}
}

// auditHas fails unless dir's chain records action.
func auditHas(t *testing.T, dir, action string) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	events, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: action})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatalf("the audit trail records no %s", action)
	}
}
