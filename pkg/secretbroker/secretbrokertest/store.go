package secretbrokertest

import (
	"fmt"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// Store is an in-memory secretbroker.Store. It also keeps access requests
// and tombstones, so a test can exercise the request path and see a deleted
// secret named in a refusal without a database (Task 20400).
type Store struct {
	mu         sync.Mutex
	secrets    map[string]secretbroker.Secret
	grants     map[string]secretbroker.Grant
	meta       map[string]string
	requests   map[string]secretbroker.AccessRequest
	uses       []secretbroker.RequestUse
	tombstones map[string]secretbroker.Tombstone
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{
		secrets:    map[string]secretbroker.Secret{},
		grants:     map[string]secretbroker.Grant{},
		meta:       map[string]string{},
		requests:   map[string]secretbroker.AccessRequest{},
		tombstones: map[string]secretbroker.Tombstone{},
	}
}

func (s *Store) PutSecret(sec secretbroker.Secret) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[sec.ID] = sec
	return nil
}

func (s *Store) GetSecret(id string) (secretbroker.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.secrets[id]
	if !ok {
		return secretbroker.Secret{}, fmt.Errorf("%w: %s", secretbroker.ErrSecretNotFound, id)
	}
	return sec, nil
}

func (s *Store) ListSecrets() ([]secretbroker.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]secretbroker.Secret, 0, len(s.secrets))
	for _, sec := range s.secrets {
		out = append(out, sec)
	}
	return out, nil
}

func (s *Store) DeleteSecret(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.secrets[id]; !ok {
		return fmt.Errorf("%w: %s", secretbroker.ErrSecretNotFound, id)
	}
	delete(s.secrets, id)
	return nil
}

func (s *Store) PutGrant(g secretbroker.Grant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[g.ID] = g
	return nil
}

func (s *Store) GetGrant(id string) (secretbroker.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return secretbroker.Grant{}, fmt.Errorf("%w: %s", secretbroker.ErrGrantNotFound, id)
	}
	return g, nil
}

func (s *Store) ListGrants() ([]secretbroker.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]secretbroker.Grant, 0, len(s.grants))
	for _, g := range s.grants {
		out = append(out, g)
	}
	return out, nil
}

// RevokeGrant marks a grant revoked, as another broker instance over the same
// database would: the broker holding a lease learns of it only by re-reading.
func (s *Store) RevokeGrant(id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return fmt.Errorf("%w: %s", secretbroker.ErrGrantNotFound, id)
	}
	if g.RevokedAt.IsZero() {
		g.RevokedAt = at.UTC()
		s.grants[id] = g
	}
	return nil
}

func (s *Store) Meta(key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.meta[key]
	return v, ok, nil
}

func (s *Store) SetMeta(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.meta[key] = value
	return nil
}

var _ secretbroker.Store = (*Store)(nil)

// DeleteSecretTombstoned removes a secret and remembers what it was.
func (s *Store) DeleteSecretTombstoned(id string, t secretbroker.Tombstone) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.secrets[id]; !ok {
		return fmt.Errorf("%w: %s", secretbroker.ErrSecretNotFound, id)
	}
	delete(s.secrets, id)
	t.SecretID = id
	s.tombstones[id] = t
	return nil
}

// GetTombstone returns what a deleted secret was.
func (s *Store) GetTombstone(secretID string) (secretbroker.Tombstone, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tombstones[secretID]
	if !ok {
		return secretbroker.Tombstone{}, fmt.Errorf("%w: no tombstone for %s", secretbroker.ErrSecretNotFound, secretID)
	}
	return t, nil
}

var _ secretbroker.TombstoneStore = (*Store)(nil)

// RevokeGrantWithCause marks a grant revoked and records why.
func (s *Store) RevokeGrantWithCause(id string, at time.Time, cause secretbroker.RevocationCause) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return fmt.Errorf("%w: %s", secretbroker.ErrGrantNotFound, id)
	}
	if g.RevokedAt.IsZero() {
		g.RevokedAt, g.RevokedCause = at.UTC(), cause
		s.grants[id] = g
	}
	return nil
}

var _ secretbroker.CausedRevoker = (*Store)(nil)

// PutAccessRequest inserts or replaces a request.
func (s *Store) PutAccessRequest(r secretbroker.AccessRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[r.ID] = r
	return nil
}

// GetAccessRequest returns one request.
func (s *Store) GetAccessRequest(id string) (secretbroker.AccessRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.requests[id]
	if !ok {
		return secretbroker.AccessRequest{}, fmt.Errorf("%w: %s", secretbroker.ErrRequestNotFound, id)
	}
	return r, nil
}

// ListAccessRequests returns every request.
func (s *Store) ListAccessRequests() ([]secretbroker.AccessRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]secretbroker.AccessRequest, 0, len(s.requests))
	for _, r := range s.requests {
		out = append(out, r)
	}
	return out, nil
}

// ExpireAccessRequests moves lapsed pending requests to expired.
func (s *Store) ExpireAccessRequests(now time.Time) ([]secretbroker.AccessRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []secretbroker.AccessRequest
	for id, r := range s.requests {
		if r.State == secretbroker.RequestPending && !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt) {
			r.State = secretbroker.RequestExpired
			s.requests[id] = r
			out = append(out, r)
		}
	}
	return out, nil
}

// RecordRequestUse notes a lease redeeming an approved request's grant.
func (s *Store) RecordRequestUse(u secretbroker.RequestUse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uses = append(s.uses, u)
	return nil
}

// ListRequestUses returns the uses of one request, or all of them.
func (s *Store) ListRequestUses(requestID string) ([]secretbroker.RequestUse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []secretbroker.RequestUse
	for _, u := range s.uses {
		if requestID == "" || u.RequestID == requestID {
			out = append(out, u)
		}
	}
	return out, nil
}

var _ secretbroker.RequestStore = (*Store)(nil)

// Recorder is a secretbroker.Auditor that keeps every event.
type Recorder struct {
	mu     sync.Mutex
	events []secretbroker.Event
}

// Audit implements secretbroker.Auditor.
func (r *Recorder) Audit(ev secretbroker.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

// Events returns the recorded events of one action, or all when action is "".
func (r *Recorder) Events(action secretbroker.Action) []secretbroker.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []secretbroker.Event
	for _, ev := range r.events {
		if action == "" || ev.Action == action {
			out = append(out, ev)
		}
	}
	return out
}
