package hubdoctor

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/kms/kmstest"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// kmsHub is a control plane whose sealing key a KMS plugin holds, with one
// secret sealed under it.
func kmsHub(t *testing.T) (string, *kmstest.Plugin, *config.Config) {
	t.Helper()
	t.Setenv("CLOOP_SECRET_KEY", "Zq4pV9mW2xT7rL0yH3nB8kD5sF1gJ6cA-uE_oI4tR7w")
	p := kmstest.StartPlugin(t)
	cfg := hubCfg()
	cfg.Secrets.KMS = config.KMSConfig{Provider: config.KMSProviderKMSv2, Timeout: "1s",
		KMSv2: config.KMSv2Config{Endpoint: p.Endpoint()}}
	dir := t.TempDir()
	db, err := statedb.Open(mustInitStateDB(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	prov, err := kms.Open(cfg.Secrets.KMS)
	if err != nil {
		t.Fatal(err)
	}
	defer prov.Close()
	kr, err := secretbroker.OpenKeyring(store, secretbroker.WithKeyringRootSet(secretbroker.KMSRoot(prov), secretbroker.Root{}))
	if err != nil {
		t.Fatal(err)
	}
	b, err := secretbroker.New(store, secretbroker.WithKeyring(kr))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Mint(context.Background(), secretbroker.MintRequest{Name: "s", Kind: secretbroker.KindEnv,
		Payload: []byte("A=1"), Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secretbroker.ForgetOpenedKeys)
	return dir, p, cfg
}

// secrets.kms: the doctor reaches the KMS the hub would, says how long it
// took, opens the keys it holds through it, and notices a rotation of the KMS
// key still to be followed.
func TestDoctorChecksTheKMS(t *testing.T) {
	dir, p, cfg := kmsHub(t)

	secretbroker.ForgetOpenedKeys()
	got := findingsFor(t, dir, cfg, Options{Offline: true})
	wantSeverity(t, only(t, got, "secrets.kms.config"), SeverityPass)
	reach := only(t, got, "secrets.kms.reachable")
	wantSeverity(t, reach, SeverityPass)
	if !strings.Contains(reach.Message, "key-1") || reach.Details["latency_ms"] == nil {
		t.Errorf("reachable = %q %v", reach.Message, reach.Details)
	}
	wantSeverity(t, only(t, got, "secret_key.matches"), SeverityPass)
	wantSeverity(t, only(t, got, "secrets.kms.rewrap"), SeverityPass)

	p.Rotate()
	secretbroker.ForgetOpenedKeys()
	got = findingsFor(t, dir, cfg, Options{Offline: true})
	rw := only(t, got, "secrets.kms.rewrap")
	wantSeverity(t, rw, SeverityWarn)
	if !strings.Contains(rw.Remediation, "cloop hub key rewrap") {
		t.Errorf("rewrap remediation = %q", rw.Remediation)
	}
}

// A KMS that does not answer fails secrets.kms.reachable with its own reason,
// and the keys it holds fail secret_key.matches: the hub would not start.
func TestDoctorFailsAnUnreachableKMS(t *testing.T) {
	dir, p, cfg := kmsHub(t)
	p.Stop()
	secretbroker.ForgetOpenedKeys()
	got := findingsFor(t, dir, cfg, Options{Offline: true})
	reach := only(t, got, "secrets.kms.reachable")
	wantSeverity(t, reach, SeverityFail)
	if !strings.Contains(reach.Message, "does not answer") || reach.Details["unreachable"] != true {
		t.Errorf("reachable = %q %v", reach.Message, reach.Details)
	}
	m := only(t, got, "secret_key.matches")
	wantSeverity(t, m, SeverityFail)
	if !strings.Contains(m.Message, "cannot be reached") {
		t.Errorf("matches does not say why: %q", m.Message)
	}

	// A hub with no secrets.kms at all, over a store a KMS holds: the keys
	// open with nothing it has, and the finding says what holds them.
	if err := p.Restart(); err != nil {
		t.Fatal(err)
	}
	plain := hubCfg()
	got = findingsFor(t, dir, plain, Options{Offline: true})
	m = only(t, got, "secret_key.matches")
	wantSeverity(t, m, SeverityFail)
	if !strings.Contains(m.Message, "held by the KMS") {
		t.Errorf("matches = %q", m.Message)
	}
	if _, ok := got["secrets.kms.reachable"]; ok {
		t.Error("a hub with no secrets.kms was checked for one")
	}
}

// A section the hub refuses fails secrets.kms.config; a change of root in
// progress warns.
func TestDoctorReportsTheSecretsSection(t *testing.T) {
	dir, _, cfg := kmsHub(t)
	bad := *cfg
	bad.Secrets.PreviousRoot = "vault"
	got := findingsFor(t, dir, &bad, Options{Offline: true})
	wantSeverity(t, only(t, got, "secrets.kms.config"), SeverityFail)

	moving := *cfg
	moving.Secrets.PreviousRoot = config.PreviousRootPassphrase
	got = findingsFor(t, dir, &moving, Options{Offline: true})
	wantSeverity(t, only(t, got, "secrets.kms.previous"), SeverityWarn)
}
