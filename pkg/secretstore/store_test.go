// Integration tests for the SQLite-backed secret broker.
//
// pkg/secretbroker's own tests use an in-memory store, which is right for
// exercising policy. These cover what only a real database can show: that
// grants and revocations survive a process boundary, that the payload column
// really holds ciphertext, and that broker decisions land in the
// hash-chained audit log.

package secretstore_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	testToken  = "ghp_sqlitecanary0123456789"
	testEnvVal = "envcanary0123456789"
)

// testKey is a fixed AES key so tests skip the 200 000-round KDF.
func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i * 3)
	}
	return k
}

// openTestDB creates a migrated database in a temp directory and returns it
// with its path.
func openTestDB(t *testing.T) (*statedb.DB, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

// newBroker wires a broker over a real database.
func newBroker(t *testing.T, db *statedb.DB) *secretbroker.Broker {
	t.Helper()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	cipher, err := secretbroker.NewCipherWithKey(testKey())
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	b, err := secretbroker.New(store,
		secretbroker.WithCipher(cipher),
		secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	return b
}

func mustSubject(t *testing.T, spec string) secretbroker.Subject {
	t.Helper()
	sub, err := secretbroker.ParseSubject(spec)
	if err != nil {
		t.Fatalf("parse subject %q: %v", spec, err)
	}
	return sub
}

// TestRoundTripThroughSQLite is the end-to-end path: mint, grant, lease, and
// get the credential back out through a real database.
func TestRoundTripThroughSQLite(t *testing.T) {
	db, _ := openTestDB(t)
	b := newBroker(t, db)
	ctx := context.Background()

	s, err := b.Mint(ctx, secretbroker.MintRequest{
		Name: "deploy-pat", Kind: secretbroker.KindGitHubPAT,
		Payload: []byte(testToken), Actor: "test",
		Metadata: map[string]string{"owner": "platform"},
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if _, err := b.Grant(ctx, secretbroker.GrantRequest{
		SecretRef:   "deploy-pat", // resolved by name, as the CLI does
		Subject:     mustSubject(t, "project:/srv/app"),
		Constraints: secretbroker.Constraints{Repos: []string{"org/*"}},
		TTL:         time.Hour,
		Actor:       "test",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	lease, err := b.Lease(ctx, "edge-01", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if len(lease.Materials) != 1 {
		t.Fatalf("got %d materials, want 1", len(lease.Materials))
	}
	m := lease.Materials[0]
	if m.SecretName != "deploy-pat" || m.Kind != secretbroker.KindGitHubPAT {
		t.Errorf("unexpected material: %s/%s", m.SecretName, m.Kind)
	}

	// The token survives the seal/unseal round trip and reaches the token
	// file the credential helper reads.
	var tokenSeen bool
	for _, f := range m.Files {
		if strings.Contains(string(f.Content), testToken) {
			tokenSeen = true
		}
	}
	if !tokenSeen {
		t.Error("token did not survive the round trip into the delivered files")
	}

	// Metadata is non-sensitive and does survive.
	stored, err := b.ListSecrets()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(stored) != 1 || stored[0].Metadata["owner"] != "platform" {
		t.Errorf("metadata did not round trip: %+v", stored)
	}
	if stored[0].ID != s.ID {
		t.Errorf("secret id changed: %s → %s", s.ID, stored[0].ID)
	}
}

// TestPayloadIsCiphertextOnDisk: the whole point of sealing is that a
// database file, a backup, or a replica leaks nothing usable.
func TestPayloadIsCiphertextOnDisk(t *testing.T) {
	db, path := openTestDB(t)
	b := newBroker(t, db)

	if _, err := b.Mint(context.Background(), secretbroker.MintRequest{
		Name: "sealed", Kind: secretbroker.KindGitHubPAT,
		Payload: []byte(testToken), Actor: "test",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	// Close so WAL content is checkpointed into the main file.
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Scan the database and its sidecars: a token sitting in the -wal file
	// is just as exposed as one in the main file.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, err := os.ReadFile(path + suffix)
		if err != nil {
			continue // sidecar may not exist
		}
		if strings.Contains(string(data), testToken) {
			t.Fatalf("plaintext token found in %s", filepath.Base(path+suffix))
		}
	}
}

// TestRevocationSurvivesRestart: revocation must be durable, not a
// process-local flag. A control plane that forgot revocations on restart
// would re-grant access nobody re-authorised.
func TestRevocationSurvivesRestart(t *testing.T) {
	db, path := openTestDB(t)
	b := newBroker(t, db)
	ctx := context.Background()

	if _, err := b.Mint(ctx, secretbroker.MintRequest{
		Name: "tok", Kind: secretbroker.KindGitHubPAT,
		Payload: []byte(testToken), Actor: "test",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	g, err := b.Grant(ctx, secretbroker.GrantRequest{
		SecretRef:   "tok",
		Subject:     mustSubject(t, "project:/srv/app"),
		Constraints: secretbroker.Constraints{Repos: []string{"*"}},
		TTL:         24 * time.Hour,
		Actor:       "test",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := b.Revoke(ctx, g.ID, "test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen: a fresh process, a fresh broker, the same database.
	db2, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	b2 := newBroker(t, db2)

	lease, err := b2.Lease(ctx, "edge-01", "/srv/app")
	if err != nil {
		t.Fatalf("lease after restart: %v", err)
	}
	if len(lease.Materials) != 0 {
		t.Fatalf("revoked grant was leased after restart: %d materials", len(lease.Materials))
	}

	// The row is retained, so "who had access" remains answerable.
	all, err := b2.ListGrants(secretbroker.GrantFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 1 || all[0].RevokedAt.IsZero() {
		t.Errorf("revoked grant should persist with a revocation stamp: %+v", all)
	}
}

// TestGrantConstraintsSurviveRestart: an allowlist that decoded wrongly on
// reload would be an allowlist that stopped constraining.
func TestGrantConstraintsSurviveRestart(t *testing.T) {
	db, path := openTestDB(t)
	b := newBroker(t, db)
	ctx := context.Background()

	if _, err := b.Mint(ctx, secretbroker.MintRequest{
		Name: "kube", Kind: secretbroker.KindKubeconfig,
		Payload: []byte(kubeconfigFixture), Actor: "test",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := b.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: "kube",
		Subject:   mustSubject(t, "label:region=eu,tier=prod"),
		Constraints: secretbroker.Constraints{
			Contexts:   []string{"prod"},
			Namespaces: []string{"team-a"},
		},
		TTL:   time.Hour,
		Actor: "test",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	db2, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	b2 := newBroker(t, db2)

	grants, err := b2.ListGrants(secretbroker.GrantFilter{ActiveOnly: true})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("got %d grants, want 1", len(grants))
	}
	g := grants[0]
	if g.Subject.Type != secretbroker.SubjectLabel {
		t.Fatalf("subject type = %q, want label", g.Subject.Type)
	}
	if g.Subject.Labels["region"] != "eu" || g.Subject.Labels["tier"] != "prod" {
		t.Errorf("label selector did not round trip: %+v", g.Subject.Labels)
	}
	if g.Constraints.AllowsNamespace("kube-system") {
		t.Error("namespace allowlist stopped constraining after reload")
	}
	if !g.Constraints.AllowsNamespace("team-a") {
		t.Error("namespace allowlist lost its allowed entry after reload")
	}

	// And the reloaded grant still leases correctly to a matching subject.
	lease, err := b2.LeaseFor(ctx, secretbroker.Requester{
		ExecutorID: "edge-01",
		ProjectID:  "/srv/app",
		Labels:     map[string]string{"region": "eu", "tier": "prod"},
	}, "test")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if len(lease.Materials) != 1 {
		t.Fatalf("got %d materials, want 1", len(lease.Materials))
	}
	// The staging cluster's credential must not have survived minimization.
	for _, f := range lease.Materials[0].Files {
		if strings.Contains(string(f.Content), "staging-secret-token") {
			t.Error("minimization did not drop the disallowed context's credential")
		}
	}
}

// TestDuplicateNameRejectedByIndex: the unique index is the backstop for two
// processes racing past the broker's own check.
func TestDuplicateNameRejectedByIndex(t *testing.T) {
	db, _ := openTestDB(t)

	first := statedb.BrokerSecretRow{
		ID: "sec_a", Kind: "env", Name: "same", Payload: []byte("x"),
	}
	if err := db.PutBrokerSecret(first); err != nil {
		t.Fatalf("first put: %v", err)
	}
	second := statedb.BrokerSecretRow{
		ID: "sec_b", Kind: "env", Name: "same", Payload: []byte("y"),
	}
	if err := db.PutBrokerSecret(second); err == nil {
		t.Fatal("a second secret with the same name must be rejected by the unique index")
	}
}

// TestAuditRowsRecordDecisions: every brokered operation must be reviewable,
// and none of the rows may contain credential material.
func TestAuditRowsRecordDecisions(t *testing.T) {
	db, _ := openTestDB(t)
	b := newBroker(t, db)
	ctx := context.Background()

	if _, err := b.Mint(ctx, secretbroker.MintRequest{
		Name: "audited", Kind: secretbroker.KindGitHubPAT,
		Payload: []byte(testToken), Actor: "cli:alice",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := b.Mint(ctx, secretbroker.MintRequest{
		Name: "envsec", Kind: secretbroker.KindEnv,
		Payload: []byte(`{"CANARY":"` + testEnvVal + `"}`), Actor: "cli:alice",
	}); err != nil {
		t.Fatalf("mint env: %v", err)
	}
	g, err := b.Grant(ctx, secretbroker.GrantRequest{
		SecretRef:   "audited",
		Subject:     mustSubject(t, "project:/srv/app"),
		Constraints: secretbroker.Constraints{Repos: []string{"org/*"}},
		TTL:         time.Hour,
		Actor:       "cli:alice",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if _, err := b.Lease(ctx, "edge-01", "/srv/app"); err != nil {
		t.Fatalf("lease: %v", err)
	}
	if err := b.Revoke(ctx, g.ID, "cli:alice"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := b.Lease(ctx, "edge-01", "/srv/app"); err != nil {
		t.Fatalf("lease after revoke: %v", err)
	}

	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EntityType: "secret"})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("no secret audit rows recorded")
	}

	seen := map[string]bool{}
	for _, row := range rows {
		seen[row.EventType] = true
		if row.Actor == "" {
			t.Errorf("audit row %d has no actor", row.ID)
		}
		for _, canary := range []string{testToken, testEnvVal} {
			if strings.Contains(row.Payload, canary) {
				t.Errorf("audit row %d (%s) leaked credential material: %s",
					row.ID, row.EventType, row.Payload)
			}
		}
	}
	for _, want := range []string{
		string(secretbroker.ActionMint),
		string(secretbroker.ActionGrant),
		string(secretbroker.ActionLease),
		string(secretbroker.ActionRevoke),
	} {
		if !seen[want] {
			t.Errorf("no audit row for %s (got %v)", want, seen)
		}
	}

	// A denial must be there too, with a reason.
	var denials int
	for _, row := range rows {
		if strings.Contains(row.Payload, `"decision":"deny"`) {
			denials++
			if !strings.Contains(row.Payload, `"reason"`) {
				t.Errorf("denial row %d has no reason: %s", row.ID, row.Payload)
			}
		}
	}
	if denials == 0 {
		t.Error("expected an audited denial after revocation")
	}

	// The audit log is hash-chained; broker writes must not break it.
	report, err := db.VerifyAuditChain()
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if !report.OK {
		t.Errorf("audit chain broken at id %d: %s", report.BreakAtID, report.Reason)
	}
}

// TestSentinelTranslation: callers match against the broker's sentinels, so
// the adapter must translate the storage layer's.
func TestSentinelTranslation(t *testing.T) {
	db, _ := openTestDB(t)
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	if _, err := store.GetSecret("sec_missing"); !errors.Is(err, secretbroker.ErrSecretNotFound) {
		t.Errorf("GetSecret: want ErrSecretNotFound, got %v", err)
	}
	if _, err := store.GetGrant("grant_missing"); !errors.Is(err, secretbroker.ErrGrantNotFound) {
		t.Errorf("GetGrant: want ErrGrantNotFound, got %v", err)
	}
	if err := store.DeleteSecret("sec_missing"); !errors.Is(err, secretbroker.ErrSecretNotFound) {
		t.Errorf("DeleteSecret: want ErrSecretNotFound, got %v", err)
	}
	if err := store.RevokeGrant("grant_missing", time.Now()); !errors.Is(err, secretbroker.ErrGrantNotFound) {
		t.Errorf("RevokeGrant: want ErrGrantNotFound, got %v", err)
	}
}

// TestCorruptGrantRowIsDenied: a row the adapter cannot decode must lose
// access, not keep it. Failing open here would turn a storage bug into a
// credential leak.
func TestCorruptGrantRowIsDenied(t *testing.T) {
	db, _ := openTestDB(t)
	b := newBroker(t, db)

	if _, err := b.Mint(context.Background(), secretbroker.MintRequest{
		Name: "tok", Kind: secretbroker.KindGitHubPAT,
		Payload: []byte(testToken), Actor: "test",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	secrets, _ := b.ListSecrets()

	// Write a grant row directly, bypassing the broker's validation, with a
	// subject type no parser accepts.
	if err := db.PutBrokerGrant(statedb.BrokerGrantRow{
		ID: "grant_corrupt", SecretID: secrets[0].ID,
		SubjectType: "nonsense", SubjectValue: "whatever",
		ConstraintsJSON: `{"repos":["*"]}`,
		CreatedAt:       time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatalf("put corrupt grant: %v", err)
	}

	lease, err := b.Lease(context.Background(), "edge-01", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if len(lease.Materials) != 0 {
		t.Fatalf("an undecodable grant must not deliver credentials, got %d materials",
			len(lease.Materials))
	}
}

// TestMetaRoundTrip covers the KDF salt's storage.
func TestMetaRoundTrip(t *testing.T) {
	db, _ := openTestDB(t)
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	if _, ok, err := store.Meta("absent"); err != nil || ok {
		t.Errorf("absent key: ok=%v err=%v", ok, err)
	}
	if err := store.SetMeta("k", "v1"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if v, ok, err := store.Meta("k"); err != nil || !ok || v != "v1" {
		t.Errorf("get: %q ok=%v err=%v", v, ok, err)
	}
	if err := store.SetMeta("k", "v2"); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	if v, _, _ := store.Meta("k"); v != "v2" {
		t.Errorf("overwrite: got %q, want v2", v)
	}
}

const kubeconfigFixture = `apiVersion: v1
kind: Config
current-context: staging
clusters:
- name: prod-cluster
  cluster:
    server: https://prod.example.com
- name: staging-cluster
  cluster:
    server: https://staging.example.com
contexts:
- name: prod
  context:
    cluster: prod-cluster
    user: prod-user
    namespace: default
- name: staging
  context:
    cluster: staging-cluster
    user: staging-user
    namespace: staging
users:
- name: prod-user
  user:
    token: prod-token-value
- name: staging-user
  user:
    token: staging-secret-token
`
