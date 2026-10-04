package secretbrokertest

import (
	"fmt"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// Store is an in-memory secretbroker.Store.
type Store struct {
	mu      sync.Mutex
	secrets map[string]secretbroker.Secret
	grants  map[string]secretbroker.Grant
	meta    map[string]string
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{
		secrets: map[string]secretbroker.Secret{},
		grants:  map[string]secretbroker.Grant{},
		meta:    map[string]string{},
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
