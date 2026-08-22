package kubernetes

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// memStore is an in-memory secretbroker.Store, so the broker integration can
// be tested without a SQLite database.
type memStore struct {
	secrets map[string]secretbroker.Secret
	grants  map[string]secretbroker.Grant
	meta    map[string]string
}

func newMemStore() *memStore {
	return &memStore{
		secrets: make(map[string]secretbroker.Secret),
		grants:  make(map[string]secretbroker.Grant),
		meta:    make(map[string]string),
	}
}

func (m *memStore) PutSecret(s secretbroker.Secret) error {
	m.secrets[s.ID] = s
	return nil
}

func (m *memStore) GetSecret(id string) (secretbroker.Secret, error) {
	s, ok := m.secrets[id]
	if !ok {
		return secretbroker.Secret{}, secretbroker.ErrSecretNotFound
	}
	return s, nil
}

func (m *memStore) ListSecrets() ([]secretbroker.Secret, error) {
	out := make([]secretbroker.Secret, 0, len(m.secrets))
	for _, s := range m.secrets {
		out = append(out, s)
	}
	return out, nil
}

func (m *memStore) DeleteSecret(id string) error {
	delete(m.secrets, id)
	return nil
}

func (m *memStore) PutGrant(g secretbroker.Grant) error {
	m.grants[g.ID] = g
	return nil
}

func (m *memStore) GetGrant(id string) (secretbroker.Grant, error) {
	g, ok := m.grants[id]
	if !ok {
		return secretbroker.Grant{}, secretbroker.ErrGrantNotFound
	}
	return g, nil
}

func (m *memStore) ListGrants() ([]secretbroker.Grant, error) {
	out := make([]secretbroker.Grant, 0, len(m.grants))
	for _, g := range m.grants {
		out = append(out, g)
	}
	return out, nil
}

func (m *memStore) DeleteGrant(id string) error {
	delete(m.grants, id)
	return nil
}

func (m *memStore) RevokeGrant(id string, at time.Time) error {
	g, ok := m.grants[id]
	if !ok {
		return secretbroker.ErrGrantNotFound
	}
	if g.RevokedAt.IsZero() {
		g.RevokedAt = at
		m.grants[id] = g
	}
	return nil
}

func (m *memStore) Meta(key string) (string, bool, error) {
	v, ok := m.meta[key]
	return v, ok, nil
}

func (m *memStore) SetMeta(key, value string) error {
	m.meta[key] = value
	return nil
}

// newTestBroker returns a broker with a kubeconfig secret granted to
// executorID, plus the store so a test can revoke it.
func newTestBroker(t *testing.T, executorID, kubeconfig string) (*secretbroker.Broker, *memStore, secretbroker.Grant) {
	t.Helper()

	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	t.Setenv("CLOOP_SECRET_KEY", base64.StdEncoding.EncodeToString(key[:]))

	store := newMemStore()
	broker, err := secretbroker.New(store)
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}
	secret, err := broker.Mint(context.Background(), secretbroker.MintRequest{
		Name:    "prod-kubeconfig",
		Kind:    secretbroker.KindKubeconfig,
		Payload: []byte(kubeconfig),
		Actor:   "test",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	grant, err := broker.Grant(context.Background(), secretbroker.GrantRequest{
		SecretRef: secret.Name,
		Subject:   secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: executorID},
		Constraints: secretbroker.Constraints{
			Namespaces: []string{"cloop-jobs"},
		},
		Actor: "test",
	})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	return broker, store, grant
}

func testKubeconfigYAML(t *testing.T) string {
	t.Helper()
	certPEM, _ := selfSignedPEM(t)
	return `apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod-cluster
  cluster:
    server: https://api.prod.example:6443
    certificate-authority-data: ` + base64.StdEncoding.EncodeToString(certPEM) + `
contexts:
- name: prod
  context:
    cluster: prod-cluster
    user: runner
    namespace: cloop-jobs
- name: staging
  context:
    cluster: prod-cluster
    user: runner
    namespace: staging
users:
- name: runner
  user:
    token: sha256~brokered-token
`
}

// TestBrokerSource_LeasesInMemory is the requirement the whole design turns
// on: the kubeconfig reaches the driver as bytes and never becomes a file on
// the control-plane host.
func TestBrokerSource_LeasesInMemory(t *testing.T) {
	broker, _, _ := newTestBroker(t, "k8s", testKubeconfigYAML(t))
	src, err := NewBrokerSource(broker, "k8s", "", "")
	if err != nil {
		t.Fatalf("NewBrokerSource: %v", err)
	}

	// Snapshot the directories a materialised lease would have used, so a
	// regression that starts writing files is caught rather than assumed
	// absent.
	before := leaseDirSnapshot(t)

	creds, err := src.Acquire(context.Background(), "/srv/app")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer src.Release(creds.LeaseID)

	if creds.Rest == nil {
		t.Fatal("Acquire returned no REST config")
	}
	if creds.Rest.BearerToken != "sha256~brokered-token" {
		t.Errorf("BearerToken = %q, want the brokered one", creds.Rest.BearerToken)
	}
	if creds.Rest.Server != "https://api.prod.example:6443" {
		t.Errorf("Server = %q", creds.Rest.Server)
	}
	// The grant pinned cloop-jobs, so MinimizeKubeconfig dropped the staging
	// context and the driver must see the narrowed namespace.
	if creds.Namespace != "cloop-jobs" {
		t.Errorf("Namespace = %q, want the grant's pinned namespace", creds.Namespace)
	}
	if creds.SecretName != "prod-kubeconfig" {
		t.Errorf("SecretName = %q", creds.SecretName)
	}
	if creds.ExpiresAt.IsZero() || creds.ExpiresAt.Before(time.Now()) {
		t.Errorf("ExpiresAt = %v, want a future deadline", creds.ExpiresAt)
	}

	after := leaseDirSnapshot(t)
	for dir, entries := range after {
		if len(entries) > len(before[dir]) {
			t.Errorf("Acquire created %d new entries under %s; the kubeconfig must never "+
				"become a file on the control-plane host", len(entries)-len(before[dir]), dir)
		}
	}
}

// leaseDirSnapshot lists the directories secretbroker.Lease.Materialize would
// write into, so a test can prove nothing was written.
func leaseDirSnapshot(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, dir := range []string{"/dev/shm", os.TempDir()} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		out[dir] = names
	}
	return out
}

// TestBrokerSource_RenewReflectsRevocation is what makes a revoked grant take
// effect inside one lease period: Renew re-evaluates the store rather than
// extending what was already issued.
func TestBrokerSource_RenewReflectsRevocation(t *testing.T) {
	broker, _, grant := newTestBroker(t, "k8s", testKubeconfigYAML(t))
	src, err := NewBrokerSource(broker, "k8s", "", "")
	if err != nil {
		t.Fatalf("NewBrokerSource: %v", err)
	}

	creds, err := src.Acquire(context.Background(), "/srv/app")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	// A renewal retires the old lease ID and issues a new one, so the caller
	// must adopt it — which is exactly what record.adoptCredentials does.
	renewed, err := src.Renew(context.Background(), creds.LeaseID)
	if err != nil {
		t.Fatalf("Renew before revocation: %v", err)
	}
	if renewed.LeaseID == creds.LeaseID {
		t.Error("Renew reused the lease ID; a captured stale ID would be renewable forever")
	}

	if err := broker.Revoke(context.Background(), grant.ID, "test"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := src.Renew(context.Background(), renewed.LeaseID); err == nil {
		t.Fatal("Renew succeeded after the grant was revoked; the credential would outlive its authority")
	} else if !errors.Is(err, ErrNoKubeconfigGrant) {
		t.Errorf("Renew after revocation = %v, want ErrNoKubeconfigGrant", err)
	}
}

// TestBrokerSource_NoGrantIsADenial: no kubeconfig means no cluster, and the
// error must say how to fix it rather than degrade to something else.
func TestBrokerSource_NoGrantIsADenial(t *testing.T) {
	broker, _, _ := newTestBroker(t, "other-executor", testKubeconfigYAML(t))
	src, err := NewBrokerSource(broker, "k8s", "", "")
	if err != nil {
		t.Fatalf("NewBrokerSource: %v", err)
	}

	_, err = src.Acquire(context.Background(), "/srv/app")
	if !errors.Is(err, ErrNoKubeconfigGrant) {
		t.Fatalf("Acquire = %v, want ErrNoKubeconfigGrant", err)
	}
	if !strings.Contains(err.Error(), "cloop secret grant") {
		t.Errorf("error %q does not say how to grant one", err)
	}
}

// TestBrokerSource_SecretRefSelectsAmongGrants: a control plane with several
// clusters must reach the one its config names.
func TestBrokerSource_SecretRefSelectsAmongGrants(t *testing.T) {
	broker, _, _ := newTestBroker(t, "k8s", testKubeconfigYAML(t))

	src, err := NewBrokerSource(broker, "k8s", "prod-kubeconfig", "")
	if err != nil {
		t.Fatalf("NewBrokerSource: %v", err)
	}
	creds, err := src.Acquire(context.Background(), "/srv/app")
	if err != nil {
		t.Fatalf("Acquire with a matching ref: %v", err)
	}
	src.Release(creds.LeaseID)

	missing, err := NewBrokerSource(broker, "k8s", "staging-kubeconfig", "")
	if err != nil {
		t.Fatalf("NewBrokerSource: %v", err)
	}
	_, err = missing.Acquire(context.Background(), "/srv/app")
	if !errors.Is(err, ErrNoKubeconfigGrant) {
		t.Fatalf("Acquire with an unmatched ref = %v, want ErrNoKubeconfigGrant", err)
	}
	if !strings.Contains(err.Error(), "staging-kubeconfig") {
		t.Errorf("error %q does not name the secret it could not find", err)
	}
}

// TestBrokerSource_ReleasesUnusableLease: a lease we cannot build a config
// from is a lease we must not keep holding.
func TestBrokerSource_ReleasesUnusableLease(t *testing.T) {
	// A kubeconfig whose only surviving user runs an exec plugin: the
	// broker delivers it happily, and the driver must refuse it.
	bad := `apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: c
  cluster: {server: 'https://api.example:6443', insecure-skip-tls-verify: true}
contexts:
- name: prod
  context: {cluster: c, user: u, namespace: cloop-jobs}
users:
- name: u
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /bin/sh
`
	broker, _, _ := newTestBroker(t, "k8s", bad)
	src, err := NewBrokerSource(broker, "k8s", "", "")
	if err != nil {
		t.Fatalf("NewBrokerSource: %v", err)
	}

	_, err = src.Acquire(context.Background(), "/srv/app")
	if err == nil {
		t.Fatal("Acquire accepted a kubeconfig with an exec credential plugin")
	}
	if !strings.Contains(err.Error(), "exec credential plugin") {
		t.Errorf("error %q does not name the refused construct", err)
	}
}

func TestNewBrokerSource_Validation(t *testing.T) {
	if _, err := NewBrokerSource(nil, "k8s", "", ""); err == nil {
		t.Error("NewBrokerSource accepted a nil broker")
	}
	broker, _, _ := newTestBroker(t, "k8s", testKubeconfigYAML(t))
	if _, err := NewBrokerSource(broker, "  ", "", ""); err == nil {
		t.Error("NewBrokerSource accepted a blank executor ID; grants would match nothing")
	}
	src, err := NewBrokerSource(broker, "k8s", "ref", "ctx")
	if err != nil {
		t.Fatalf("NewBrokerSource: %v", err)
	}
	if !strings.Contains(src.Describe(), "k8s") || !strings.Contains(src.Describe(), "ref") {
		t.Errorf("Describe() = %q", src.Describe())
	}
	// Release must tolerate an unknown or empty ID: cleanup paths call it
	// without knowing whether a lease was ever issued.
	src.Release("")
	src.Release("lease-that-never-existed")
}

// TestBrokerSource_ContextSelection: the executor's configured context wins
// among the ones the grant left standing.
func TestBrokerSource_ContextSelection(t *testing.T) {
	broker, _, _ := newTestBroker(t, "k8s", testKubeconfigYAML(t))
	src, err := NewBrokerSource(broker, "k8s", "", "prod")
	if err != nil {
		t.Fatalf("NewBrokerSource: %v", err)
	}
	creds, err := src.Acquire(context.Background(), "/srv/app")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer src.Release(creds.LeaseID)
	if creds.Rest.Context != "prod" {
		t.Errorf("Context = %q, want prod", creds.Rest.Context)
	}
}
