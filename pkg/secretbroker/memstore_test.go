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
	// requests and uses back the RequestStore half below (Task 20271).
	requests map[string]AccessRequest
	uses     map[string][]RequestUse

	// putGrantErr, when set, makes the next PutGrant fail. Used to check
	// that a storage failure surfaces as a denial rather than a silent
	// success.
	putGrantErr error
	// putRequestErr makes the next PutAccessRequest fail, which is how the
	// "approval recorded, grant already minted" rollback is tested.
	putRequestErr error
}

func newMemStore() *memStore {
	return &memStore{
		secrets:  make(map[string]Secret),
		grants:   make(map[string]Grant),
		meta:     make(map[string]string),
		requests: make(map[string]AccessRequest),
		uses:     make(map[string][]RequestUse),
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

// ---------------------------------------------------------------------------
// RequestStore (Task 20271)
// ---------------------------------------------------------------------------

// The request half of the store, so the policy tests in request_test.go — the
// two-person rule, the delegation clamp, the expiry refusal — run without a
// SQLite file, exactly as the grant tests do.
//
// The one behaviour it must reproduce faithfully is ExpireAccessRequests
// touching *only* pending rows. A double that also expired decided ones would
// make the race test in TestExpireLeavesDecidedRequestsAlone pass against a
// store whose real counterpart loses approvals.

var _ RequestStore = (*memStore)(nil)

func (m *memStore) PutAccessRequest(r AccessRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.putRequestErr != nil {
		err := m.putRequestErr
		m.putRequestErr = nil
		return err
	}
	if m.requests == nil {
		m.requests = make(map[string]AccessRequest)
	}
	m.requests[r.ID] = r
	return nil
}

func (m *memStore) GetAccessRequest(id string) (AccessRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.requests[id]
	if !ok {
		return AccessRequest{}, wrapf(ErrRequestNotFound, "%s", id)
	}
	return r, nil
}

func (m *memStore) ListAccessRequests() ([]AccessRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]AccessRequest, 0, len(m.requests))
	for _, r := range m.requests {
		out = append(out, r)
	}
	return out, nil
}

func (m *memStore) ExpireAccessRequests(now time.Time) ([]AccessRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var lapsed []AccessRequest
	for id, r := range m.requests {
		if r.State != RequestPending || r.ExpiresAt.IsZero() || now.Before(r.ExpiresAt) {
			continue
		}
		r.State = RequestExpired
		r.DecidedAt = now.UTC()
		m.requests[id] = r
		lapsed = append(lapsed, r)
	}
	return lapsed, nil
}

func (m *memStore) RecordRequestUse(u RequestUse) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.uses == nil {
		m.uses = make(map[string][]RequestUse)
	}
	for i, existing := range m.uses[u.RequestID] {
		if existing.LeaseID == u.LeaseID {
			// Upsert, preserving first_seen — the property the real store's
			// ON CONFLICT clause guarantees and the reason a renewal does not
			// rewrite when a credential came into use.
			u.FirstSeen = existing.FirstSeen
			if u.TaskID == 0 {
				u.TaskID = existing.TaskID
			}
			m.uses[u.RequestID][i] = u
			return nil
		}
	}
	m.uses[u.RequestID] = append(m.uses[u.RequestID], u)
	return nil
}

func (m *memStore) ListRequestUses(requestID string) ([]RequestUse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if requestID != "" {
		return append([]RequestUse(nil), m.uses[requestID]...), nil
	}
	var out []RequestUse
	for _, list := range m.uses {
		out = append(out, list...)
	}
	return out, nil
}
