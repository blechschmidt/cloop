package deviceforward

import (
	"fmt"
	"sync"
	"time"
)

// memStore is an in-memory Store for tests, with an atomic single-use redeem.
type memStore struct {
	mu         sync.Mutex
	enroll     map[string]EnrollmentRecord
	forwarders map[string]ForwarderRecord
}

func newMemStore() *memStore {
	return &memStore{
		enroll:     map[string]EnrollmentRecord{},
		forwarders: map[string]ForwarderRecord{},
	}
}

func (m *memStore) PutEnrollment(rec EnrollmentRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enroll[rec.ID] = rec
	return nil
}

func (m *memStore) GetEnrollment(id string) (EnrollmentRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.enroll[id]
	if !ok {
		return EnrollmentRecord{}, fmt.Errorf("%w: enrollment %s", ErrTokenInvalid, id)
	}
	return rec, nil
}

func (m *memStore) RedeemEnrollment(id, forwarderID string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.enroll[id]
	if !ok {
		return fmt.Errorf("%w: enrollment %s", ErrTokenInvalid, id)
	}
	if !rec.RedeemedAt.IsZero() {
		return fmt.Errorf("%w: %s", ErrTokenAlreadyUsed, id)
	}
	rec.RedeemedAt = at
	rec.RedeemedAgentID = forwarderID
	m.enroll[id] = rec
	return nil
}

func (m *memStore) RevokeEnrollment(id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.enroll[id]
	if !ok {
		return fmt.Errorf("%w: enrollment %s", ErrTokenInvalid, id)
	}
	rec.RevokedAt = at
	m.enroll[id] = rec
	return nil
}

func (m *memStore) ListEnrollments() ([]EnrollmentRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]EnrollmentRecord, 0, len(m.enroll))
	for _, r := range m.enroll {
		out = append(out, r)
	}
	return out, nil
}

func (m *memStore) PutForwarder(rec ForwarderRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.forwarders[rec.ForwarderID] = rec
	return nil
}

func (m *memStore) GetForwarder(id string) (ForwarderRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.forwarders[id]
	if !ok {
		return ForwarderRecord{}, fmt.Errorf("%w: forwarder %s", ErrForwarderNotFound, id)
	}
	return rec, nil
}

func (m *memStore) RevokeForwarder(id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.forwarders[id]
	if !ok {
		return fmt.Errorf("%w: forwarder %s", ErrForwarderNotFound, id)
	}
	rec.RevokedAt = at
	m.forwarders[id] = rec
	return nil
}

func (m *memStore) TouchForwarder(id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.forwarders[id]
	if !ok {
		return fmt.Errorf("%w: forwarder %s", ErrForwarderNotFound, id)
	}
	rec.LastSeen = at
	m.forwarders[id] = rec
	return nil
}

func (m *memStore) ListForwarders() ([]ForwarderRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ForwarderRecord, 0, len(m.forwarders))
	for _, r := range m.forwarders {
		out = append(out, r)
	}
	return out, nil
}
