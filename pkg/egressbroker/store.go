package egressbroker

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Store persists egress grants.
//
// Only grants: sessions are memory-resident by design (see Session), so
// there is deliberately no session method here. A store that could write a
// session would be a store that could be asked to read one back after a
// restart, and a resurrected proxy credential is exactly what the TTL exists
// to prevent.
//
// Implementations must be safe for concurrent use.
type Store interface {
	// PutGrant inserts or replaces a grant.
	PutGrant(g Grant) error
	// GetGrant returns one grant by ID, or an error wrapping
	// ErrGrantNotFound.
	GetGrant(id string) (Grant, error)
	// ListGrants returns every grant, including expired and revoked ones —
	// filtering is the broker's job, and an audit reader needs the history.
	ListGrants() ([]Grant, error)
	// RevokeGrant stamps a grant revoked at the given time. Revocation is a
	// stamp rather than a delete so "who could reach the Internet in March"
	// stays answerable.
	RevokeGrant(id string, at time.Time) error
}

// MemStore is an in-memory Store, used by tests and by `cloop egress test`
// when it needs a throwaway policy.
//
// It is exported rather than test-only because the test command genuinely
// needs it: constructing a proxy for a one-shot connectivity check should not
// require writing a grant into the project database.
type MemStore struct {
	mu     sync.RWMutex
	grants map[string]Grant
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{grants: make(map[string]Grant)}
}

var _ Store = (*MemStore)(nil)

// PutGrant stores a copy of g.
func (m *MemStore) PutGrant(g Grant) error {
	if g.ID == "" {
		return fmt.Errorf("%w: grant id is empty", ErrInvalidGrant)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.grants[g.ID] = g
	return nil
}

// GetGrant returns one grant by ID.
func (m *MemStore) GetGrant(id string) (Grant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	g, ok := m.grants[id]
	if !ok {
		return Grant{}, fmt.Errorf("%w: %s", ErrGrantNotFound, id)
	}
	return g, nil
}

// ListGrants returns every grant, newest first.
func (m *MemStore) ListGrants() ([]Grant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Grant, 0, len(m.grants))
	for _, g := range m.grants {
		out = append(out, g)
	}
	sortGrants(out)
	return out, nil
}

// RevokeGrant stamps a grant revoked.
func (m *MemStore) RevokeGrant(id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrGrantNotFound, id)
	}
	if g.RevokedAt.IsZero() {
		g.RevokedAt = at.UTC()
		m.grants[id] = g
	}
	return nil
}

// sortGrants orders newest-first with a stable ID tiebreak, so two listings
// of the same data never differ.
func sortGrants(gs []Grant) {
	sort.Slice(gs, func(i, j int) bool {
		if gs[i].CreatedAt.Equal(gs[j].CreatedAt) {
			return gs[i].ID < gs[j].ID
		}
		return gs[i].CreatedAt.After(gs[j].CreatedAt)
	})
}
