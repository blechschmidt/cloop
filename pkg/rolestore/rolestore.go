// Package rolestore is the statedb-backed authz.RuntimeSource: the layer of
// role bindings an operator writes during an incident, as opposed to the layer
// deployed in .cloop/config.yaml (Task 20248).
//
// It is the same split as pkg/sessionstore and pkg/quotastore. pkg/authz owns
// the model and the precedence rule and stays stdlib-only; this package owns
// storage, the translation between a table row and a binding, and the caching
// that makes reading it on every authorization decision affordable.
//
// # Why it is cached rather than loaded once
//
// The configured bindings are read once at startup because configuration does
// not change under a running process. Runtime bindings are the opposite: their
// entire purpose is to change while the hub serves, from a shell, without a
// restart — "demote this account, now". So they are re-read on a short TTL and
// a write converges within it.
//
// The TTL is also the propagation bound an operator is entitled to know, and
// it is deliberately shorter than the 30 seconds pkg/oidcauth already accepts
// for session revocation: the two are used together during a compromise, and
// the demotion should not be the slower half.
//
// # Failure policy
//
// A read that fails returns the last good answer, never an empty one. Bindings
// here only ever remove or redirect authority that config already granted, so
// "the database is briefly unreachable" must not be a path back to admin. The
// first load happens eagerly in New and its failure is fatal to hub startup,
// which keeps the degraded case ("serving from a stale list") strictly bounded
// by a case that was known-good once.
package rolestore

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// DefaultTTL bounds how long a runtime binding write takes to reach a running
// hub's authorization decisions.
const DefaultTTL = 10 * time.Second

// Store reads runtime role bindings and caches them for TTL.
type Store struct {
	db  *statedb.DB
	ttl time.Duration
	now func() time.Time

	// onError reports a refresh that failed. Refreshes happen on the
	// authorization path, where there is no caller to return an error to and
	// nothing sensible to do with one; the hub logs it instead.
	onError func(error)

	mu      sync.Mutex
	cached  []authz.Binding
	fetched time.Time
}

// Option configures a Store.
type Option func(*Store)

// WithTTL overrides the refresh interval. A non-positive value is ignored
// rather than disabling caching: a zero TTL would put a SQLite query on every
// permission check of every request.
func WithTTL(d time.Duration) Option {
	return func(s *Store) {
		if d > 0 {
			s.ttl = d
		}
	}
}

// WithErrorHandler installs a sink for failed refreshes.
func WithErrorHandler(fn func(error)) Option {
	return func(s *Store) {
		if fn != nil {
			s.onError = fn
		}
	}
}

// WithClock injects a clock, for tests.
func WithClock(now func() time.Time) Option {
	return func(s *Store) {
		if now != nil {
			s.now = now
		}
	}
}

// New adapts a control-plane database and performs the first load.
//
// Which database matters, and it is the same rule as sessions and API tokens:
// runtime bindings belong in the *hub's* own state, never a managed project's.
// A tenant able to write the file holding this table could grant itself admin
// across the fleet with one INSERT.
func New(db *statedb.DB, opts ...Option) (*Store, error) {
	if db == nil {
		return nil, errors.New("rolestore: nil database")
	}
	s := &Store{db: db, ttl: DefaultTTL, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	bindings, err := s.load()
	if err != nil {
		return nil, err
	}
	s.cached, s.fetched = bindings, s.now()
	return s, nil
}

// RuntimeBindings implements authz.RuntimeSource.
func (s *Store) RuntimeBindings() []authz.Binding {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now := s.now(); now.Sub(s.fetched) >= s.ttl {
		// Stamp the attempt before it runs. On a wedged database every request
		// would otherwise queue behind the same failing query for as long as
		// the fault lasted, turning a storage problem into an outage of the
		// authorization path.
		s.fetched = now
		if bindings, err := s.load(); err != nil {
			if s.onError != nil {
				s.onError(err)
			}
		} else {
			s.cached = bindings
		}
	}
	return s.cached
}

func (s *Store) load() ([]authz.Binding, error) {
	rows, err := s.db.ListRoleBindings()
	if err != nil {
		return nil, fmt.Errorf("rolestore: load role bindings: %w", err)
	}
	out := make([]authz.Binding, 0, len(rows))
	for _, row := range rows {
		b, err := BindingFrom(row)
		if err != nil {
			// One unreadable row must not take the rest of the table with it,
			// and it especially must not take the denies: a binding written by
			// a newer build with a role this one does not know would otherwise
			// disarm every demotion on the hub. Skipped and reported.
			if s.onError != nil {
				s.onError(fmt.Errorf("rolestore: skipping role binding %s: %w", row.ID, err))
			}
			continue
		}
		out = append(out, b)
	}
	return out, nil
}

// BindingFrom translates a stored row into the binding the resolver evaluates.
//
// The single translation point for both readers: the resolver's cache above
// and the `cloop hub role` CLI. A second copy would be a second chance for
// what an operator is shown to differ from what is enforced.
func BindingFrom(row statedb.RoleBindingRow) (authz.Binding, error) {
	return authz.NormalizeBinding(authz.Binding{
		Claim:    authz.ClaimKind(row.Claim),
		Value:    row.Value,
		Role:     authz.Role(row.Role),
		Project:  row.Project,
		Executor: row.Executor,
		Deny:     strings.EqualFold(row.Effect, statedb.RoleEffectDeny),
	})
}

// RowFor is the inverse: the row that stores b, stamped with who wrote it and
// why. The binding is normalized first, so the row's derived id is computed
// from the same values the resolver will match on.
func RowFor(b authz.Binding, reason, actor string, at time.Time) (statedb.RoleBindingRow, error) {
	nb, err := authz.NormalizeBinding(b)
	if err != nil {
		return statedb.RoleBindingRow{}, err
	}
	effect := statedb.RoleEffectAllow
	if nb.Deny {
		effect = statedb.RoleEffectDeny
	}
	return statedb.RoleBindingRow{
		Effect:    effect,
		Claim:     string(nb.Claim),
		Value:     nb.Value,
		Role:      string(nb.Role),
		Project:   nb.Project,
		Executor:  nb.Executor,
		Reason:    reason,
		CreatedAt: at,
		CreatedBy: actor,
	}, nil
}

var _ authz.RuntimeSource = (*Store)(nil)
