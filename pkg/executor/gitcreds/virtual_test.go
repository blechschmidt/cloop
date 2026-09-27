package gitcreds_test

// A virtual executor's workspace is leased as the virtual executor (Task 20349).
//
// Its device's driver runs the dispatch, and the credential source it holds was
// built for the device. The grant chosen before the dispatch, though, is
// matched against the virtual executor — so a grant issued to the virtual
// executor used to be chosen and then missing from the lease, failing the
// dispatch as though no grant existed.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitcreds"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// memStore is the smallest secretbroker.Store that holds what a lease reads.
type memStore struct {
	mu      sync.Mutex
	secrets map[string]secretbroker.Secret
	grants  map[string]secretbroker.Grant
	meta    map[string]string
}

func newMemStore() *memStore {
	return &memStore{
		secrets: map[string]secretbroker.Secret{},
		grants:  map[string]secretbroker.Grant{},
		meta:    map[string]string{},
	}
}

func (m *memStore) PutSecret(s secretbroker.Secret) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[s.ID] = s
	return nil
}

func (m *memStore) GetSecret(id string) (secretbroker.Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.secrets[id]
	if !ok {
		return secretbroker.Secret{}, fmt.Errorf("%w: %s", secretbroker.ErrSecretNotFound, id)
	}
	return s, nil
}

func (m *memStore) ListSecrets() ([]secretbroker.Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]secretbroker.Secret, 0, len(m.secrets))
	for _, s := range m.secrets {
		out = append(out, s)
	}
	return out, nil
}

func (m *memStore) DeleteSecret(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.secrets, id)
	return nil
}

func (m *memStore) PutGrant(g secretbroker.Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.grants[g.ID] = g
	return nil
}

func (m *memStore) GetGrant(id string) (secretbroker.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	if !ok {
		return secretbroker.Grant{}, fmt.Errorf("%w: %s", secretbroker.ErrGrantNotFound, id)
	}
	return g, nil
}

func (m *memStore) ListGrants() ([]secretbroker.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]secretbroker.Grant, 0, len(m.grants))
	for _, g := range m.grants {
		out = append(out, g)
	}
	return out, nil
}

func (m *memStore) RevokeGrant(id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	if !ok {
		return fmt.Errorf("%w: %s", secretbroker.ErrGrantNotFound, id)
	}
	g.RevokedAt = at
	m.grants[id] = g
	return nil
}

func (m *memStore) Meta(key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.meta[key]
	return v, ok, nil
}

func (m *memStore) SetMeta(key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.meta[key] = value
	return nil
}

// brokerWithPAT mints one repository-scoped PAT and grants it to subject.
func brokerWithPAT(t *testing.T, token, subject string) *secretbroker.Broker {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*11 + 3)
	}
	cipher, err := secretbroker.NewCipherWithKey(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	b, err := secretbroker.New(newMemStore(), secretbroker.WithCipher(cipher))
	if err != nil {
		t.Fatalf("broker: %v", err)
	}
	sec, err := b.Mint(context.Background(), secretbroker.MintRequest{
		Name: "acme-pat", Kind: secretbroker.KindGitHubPAT, Payload: []byte(token), Actor: "test",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	sub, err := secretbroker.ParseSubject(subject)
	if err != nil {
		t.Fatalf("subject %q: %v", subject, err)
	}
	if _, err := b.Grant(context.Background(), secretbroker.GrantRequest{
		SecretRef: sec.ID, Subject: sub,
		Constraints: secretbroker.Constraints{Repos: []string{"acme/*"}},
		TTL:         time.Hour, Actor: "test",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	return b
}

func privateWorkspace() executor.Workspace {
	return executor.Workspace{
		Kind:            executor.WorkspaceGit,
		Repo:            "https://github.com/acme/tool.git",
		Ref:             "main",
		CredentialGrant: "acme-pat",
	}
}

// TestVirtualExecutorLeasesItsOwnGrant: the device's source, asked on behalf of
// its virtual executor, leases the grant issued to the virtual executor.
func TestVirtualExecutorLeasesItsOwnGrant(t *testing.T) {
	const token = "ghp_virtualgrant0123456789abcdefghij"
	b := brokerWithPAT(t, token, "executor:virt-1")
	src, err := gitcreds.New(b, "device-1", "ui")
	if err != nil {
		t.Fatalf("gitcreds.New: %v", err)
	}

	ctx := executor.WithRequestingExecutor(context.Background(), "virt-1")
	access, release, err := src.ForWorkspace(ctx, "/srv/app", privateWorkspace())
	defer release()
	if err != nil {
		t.Fatalf("the grant issued to the virtual executor was not leased for its dispatch: %v", err)
	}
	if access.Credential.Password != token {
		t.Fatal("the lease did not carry the virtual executor's grant")
	}
}

// TestVirtualExecutorDoesNotBorrowTheDevicesGrant: the other half of the same
// fix. A grant issued to the device is authority for the device; a dispatch
// for one of its virtual executors — chosen, and refused, against the virtual
// executor — must not quietly lease it anyway.
func TestVirtualExecutorDoesNotBorrowTheDevicesGrant(t *testing.T) {
	b := brokerWithPAT(t, "ghp_devicegrant0123456789abcdefghijk", "executor:device-1")
	src, err := gitcreds.New(b, "device-1", "ui")
	if err != nil {
		t.Fatalf("gitcreds.New: %v", err)
	}

	ctx := executor.WithRequestingExecutor(context.Background(), "virt-1")
	_, release, err := src.ForWorkspace(ctx, "/srv/app", privateWorkspace())
	defer release()
	var grantErr *executor.WorkspaceGrantError
	if !errors.As(err, &grantErr) {
		t.Fatalf("err = %v, want a *WorkspaceGrantError for the virtual executor", err)
	}
	if grantErr.ExecutorID != "virt-1" {
		t.Errorf("the refusal names executor %q; the operator bound the project to virt-1", grantErr.ExecutorID)
	}

	// And the device's own dispatches are unchanged.
	access, release2, err := src.ForWorkspace(context.Background(), "/srv/app", privateWorkspace())
	defer release2()
	if err != nil || access.Credential.Empty() {
		t.Fatalf("the device's own dispatch lost its grant: %v", err)
	}
}
