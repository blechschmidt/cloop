package ui

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/kms/kmstest"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// A serving hub follows a rotation of its KMS key (Task 20433): the poll every
// member makes sees the new key, and the leader rewraps the key-encryption
// keys the KMS holds onto it and records sealing_key.kms_rewrapped. A KMS that
// stops answering is remembered as such, and the poll says so.
func TestHubFollowsARotationOfItsKMSKey(t *testing.T) {
	t.Cleanup(secretbroker.ForgetOpenedKeys)
	p := kmstest.StartPlugin(t)
	prov, err := kms.Open(config.KMSConfig{Provider: config.KMSProviderKMSv2, Timeout: "2s",
		KMSv2: config.KMSv2Config{Endpoint: p.Endpoint()}})
	if err != nil {
		t.Fatal(err)
	}
	defer prov.Close()
	t.Cleanup(secretbroker.PinRoots(secretbroker.KMSRoot(prov), secretbroker.Root{}))

	dir := setupProjectDir(t, "kms", nil)
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	b, err := secretbroker.New(store) // the pinned roots: the KMS
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Mint(context.Background(), secretbroker.MintRequest{Name: "s", Kind: secretbroker.KindEnv,
		Payload: []byte("A=1"), Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	srv := New(dir, 0, "")
	srv.SetKMS([]kms.Provider{prov})
	ctx := context.Background()
	if !srv.pollKMS(ctx) {
		t.Fatal("a healthy KMS polled unhealthy")
	}
	if h := srv.KMSHealth()[prov.Name()]; h.Err != "" || h.Status.KeyID != "key-1" {
		t.Fatalf("health = %+v", h)
	}

	newKey := p.Rotate()
	if !srv.pollKMS(ctx) {
		t.Fatal("the poll after a rotation reported unhealthy")
	}
	db, err = statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.ListKEKs()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.State != secretbroker.KEKStateRetired && r.KMSKeyID != newKey {
			t.Fatalf("key %s is still wrapped under %s after the leader's poll", r.ID, r.KMSKeyID)
		}
	}
	events, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: "sealing_key.kms_rewrapped"})
	if err != nil || len(events) != 1 || !strings.Contains(events[0].Payload, newKey) {
		t.Fatalf("audit = %+v, %v", events, err)
	}

	p.Stop()
	if srv.pollKMS(ctx) {
		t.Fatal("a stopped plugin polled healthy")
	}
	if h := srv.KMSHealth()[prov.Name()]; h.Err == "" {
		t.Fatal("the failed poll is not remembered")
	}
}

// The Secrets panel says what is wrong when the store will not open because of
// its KMS, and what to do about it.
func TestSecretsPanelExplainsAKMSFailure(t *testing.T) {
	reason, remedy := brokerUnavailableReason(secretbroker.ErrKMSUnavailable)
	if !strings.Contains(reason, "cannot be reached") || !strings.Contains(remedy, "secrets.kms") {
		t.Fatalf("unreachable: %q / %q", reason, remedy)
	}
	reason, remedy = brokerUnavailableReason(errDenied{})
	if !strings.Contains(reason, "refuses this hub") || !strings.Contains(remedy, "encrypt and decrypt") {
		t.Fatalf("denied: %q / %q", reason, remedy)
	}
}

type errDenied struct{}

func (errDenied) Error() string {
	return "sealing key kek_1: the KMS k refused this hub's identity (decrypt): permission denied"
}
