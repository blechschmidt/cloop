package secretbroker

import (
	"sync"
	"time"
)

// memStore is an in-memory Store for tests.
//
// It exists so the policy tests — which are the ones that matter — run
// without a SQLite file. The one behaviour it must reproduce faithfully is
// RevokeGrant's "do not move an existing revocation timestamp", because the
// revocation tests would otherwise pass against a store that lets a retry
// rewrite when access was withdrawn.
type memStore struct {
	mu      sync.Mutex
	secrets map[string]Secret
	grants  map[string]Grant
	meta    map[string]string

	// putGrantErr, when set, makes the next PutGrant fail. Used to check
	// that a storage failure surfaces as a denial rather than a silent
	// success.
	putGrantErr error
}

func newMemStore() *memStore {
	return &memStore{
		secrets: make(map[string]Secret),
		grants:  make(map[string]Grant),
		meta:    make(map[string]string),
	}
}

func (m *memStore) PutSecret(s Secret) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[s.ID] = s
	return nil
}

func (m *memStore) GetSecret(id string) (Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.secrets[id]
	if !ok {
		return Secret{}, wrapf(ErrSecretNotFound, "%s", id)
	}
	return s, nil
}

func (m *memStore) ListSecrets() ([]Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Secret, 0, len(m.secrets))
	for _, s := range m.secrets {
		out = append(out, s)
	}
	return out, nil
}

func (m *memStore) DeleteSecret(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.secrets[id]; !ok {
		return wrapf(ErrSecretNotFound, "%s", id)
	}
	delete(m.secrets, id)
	return nil
}

func (m *memStore) PutGrant(g Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.putGrantErr != nil {
		err := m.putGrantErr
		m.putGrantErr = nil
		return err
	}
	m.grants[g.ID] = g
	return nil
}

func (m *memStore) GetGrant(id string) (Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	if !ok {
		return Grant{}, wrapf(ErrGrantNotFound, "%s", id)
	}
	return g, nil
}

func (m *memStore) ListGrants() ([]Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Grant, 0, len(m.grants))
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
		return wrapf(ErrGrantNotFound, "%s", id)
	}
	if !g.RevokedAt.IsZero() {
		return nil // idempotent; the original timestamp stands
	}
	g.RevokedAt = at.UTC()
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

// recordingAuditor captures events so tests can assert on what was logged —
// including that nothing resembling a credential appears in them.
type recordingAuditor struct {
	mu     sync.Mutex
	events []Event
}

func (r *recordingAuditor) Audit(ev Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordingAuditor) all() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

// byAction returns the recorded events for one action.
func (r *recordingAuditor) byAction(a Action) []Event {
	var out []Event
	for _, ev := range r.all() {
		if ev.Action == a {
			out = append(out, ev)
		}
	}
	return out
}

// testKey is a fixed AES key so tests avoid the 200k-round KDF.
var testKey = func() []byte {
	k := make([]byte, keySize)
	for i := range k {
		k[i] = byte(i * 7)
	}
	return k
}()

// newTestBroker builds a broker over a fresh memStore with a controllable
// clock, returning all three so a test can drive time and inspect audit.
func newTestBroker(t interface{ Fatalf(string, ...any) }) (*Broker, *memStore, *recordingAuditor, *fakeClock) {
	store := newMemStore()
	cipher, err := NewCipherWithKey(testKey)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	auditor := &recordingAuditor{}
	clock := &fakeClock{now: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	b, err := New(store,
		WithCipher(cipher),
		WithAuditor(auditor),
		WithClock(clock.Now),
	)
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	return b, store, auditor, clock
}

// fakeClock lets TTL tests advance time without sleeping.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
