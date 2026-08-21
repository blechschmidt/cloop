package remote_test

// memStore is an in-memory remote.Store for tests.
//
// It lives in the external test package so the e2e test can use it alongside
// pkg/executor/agent (which imports pkg/executor/remote, so an internal test
// package could not import it back).
//
// RedeemEnrollment implements the same atomic check-and-claim the SQLite
// implementation gets from a conditional UPDATE. That is the whole point of
// having it here: the single-use guarantee is a property of the Store
// contract, and a fake that checked-then-wrote would let the replay test pass
// against a store that does not actually provide it.

import (
	"fmt"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

type memStore struct {
	mu          sync.Mutex
	enrollments map[string]remote.EnrollmentRecord
	agents      map[string]remote.AgentRecord
}

func newMemStore() *memStore {
	return &memStore{
		enrollments: make(map[string]remote.EnrollmentRecord),
		agents:      make(map[string]remote.AgentRecord),
	}
}

func (m *memStore) PutEnrollment(rec remote.EnrollmentRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enrollments[rec.ID] = rec
	return nil
}

func (m *memStore) GetEnrollment(id string) (remote.EnrollmentRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.enrollments[id]
	if !ok {
		return remote.EnrollmentRecord{}, fmt.Errorf("%w: no enrollment %q", remote.ErrTokenInvalid, id)
	}
	return rec, nil
}

// RedeemEnrollment claims the token under a single lock, so two concurrent
// callers cannot both observe it unredeemed.
func (m *memStore) RedeemEnrollment(id, agentID string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.enrollments[id]
	if !ok {
		return fmt.Errorf("%w: no enrollment %q", remote.ErrTokenInvalid, id)
	}
	if !rec.RevokedAt.IsZero() {
		return fmt.Errorf("%w: %s", remote.ErrRevoked, id)
	}
	if !rec.RedeemedAt.IsZero() {
		return fmt.Errorf("%w: %s already redeemed by %s", remote.ErrTokenAlreadyUsed, id, rec.RedeemedAgentID)
	}
	rec.RedeemedAt = at
	rec.RedeemedAgentID = agentID
	m.enrollments[id] = rec
	return nil
}

func (m *memStore) RevokeEnrollment(id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.enrollments[id]
	if !ok {
		return fmt.Errorf("%w: no enrollment %q", remote.ErrTokenInvalid, id)
	}
	rec.RevokedAt = at
	m.enrollments[id] = rec
	return nil
}

func (m *memStore) ListEnrollments() ([]remote.EnrollmentRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]remote.EnrollmentRecord, 0, len(m.enrollments))
	for _, rec := range m.enrollments {
		out = append(out, rec)
	}
	return out, nil
}

func (m *memStore) PutAgent(rec remote.AgentRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.agents[rec.AgentID] = rec
	return nil
}

func (m *memStore) GetAgent(agentID string) (remote.AgentRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.agents[agentID]
	if !ok {
		return remote.AgentRecord{}, fmt.Errorf("%w: %q", remote.ErrAgentNotFound, agentID)
	}
	return rec, nil
}

func (m *memStore) RevokeAgent(agentID string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.agents[agentID]
	if !ok {
		return fmt.Errorf("%w: %q", remote.ErrAgentNotFound, agentID)
	}
	rec.RevokedAt = at
	m.agents[agentID] = rec
	return nil
}

func (m *memStore) TouchAgent(agentID string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.agents[agentID]
	if !ok {
		return fmt.Errorf("%w: %q", remote.ErrAgentNotFound, agentID)
	}
	rec.LastSeen = at
	m.agents[agentID] = rec
	return nil
}

func (m *memStore) ListAgents() ([]remote.AgentRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]remote.AgentRecord, 0, len(m.agents))
	for _, rec := range m.agents {
		out = append(out, rec)
	}
	return out, nil
}
