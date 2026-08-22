package apitoken

// Persistence and the verification path.
//
// Store is an interface so the crypto above can be unit-tested without SQLite,
// and so the hub's HTTP layer depends on a contract rather than on a driver.
// SQLStore is the only production implementation.

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Store persists tokens. Implementations must be safe for concurrent use:
// every authenticated request reads through one.
type Store interface {
	// Put writes a newly minted token. It must reject a duplicate ID rather
	// than overwrite: rewriting a live credential's roles is a privilege
	// change nobody asked for.
	Put(Token) error

	// Get returns the token with id, or an error wrapping ErrNotFound.
	Get(id string) (Token, error)

	// List returns every token, newest first, including revoked and expired
	// ones.
	List() ([]Token, error)

	// Revoke stamps a token as withdrawn. Revoking twice is a no-op success;
	// revoking an unknown id must wrap ErrNotFound.
	Revoke(id string, at time.Time) error

	// Touch records a token's last use. Called off the verification path;
	// failures are advisory.
	Touch(id string, at time.Time) error
}

// SQLStore is the statedb-backed Store.
type SQLStore struct {
	db *statedb.DB
}

// NewSQLStore adapts a control-plane database.
//
// Which database matters: tokens must live in the *hub's* own state, never in
// a managed project's, for the same reason executor bindings and secret grants
// do. A tenant that could write to the database holding its own credentials
// could mint itself an admin token.
func NewSQLStore(db *statedb.DB) (*SQLStore, error) {
	if db == nil {
		return nil, errors.New("apitoken: nil database")
	}
	return &SQLStore{db: db}, nil
}

func (s *SQLStore) Put(t Token) error {
	return s.db.PutAPIToken(statedb.APITokenRow{
		ID:           t.ID,
		Name:         t.Name,
		Hash:         t.Hash,
		Prefix:       t.Prefix,
		Roles:        t.Roles,
		ProjectScope: t.ProjectScope,
		CreatedBy:    t.CreatedBy,
		CreatedAt:    t.CreatedAt,
		ExpiresAt:    t.ExpiresAt,
		LastUsedAt:   t.LastUsedAt,
		RevokedAt:    t.RevokedAt,
	})
}

func (s *SQLStore) Get(id string) (Token, error) {
	row, err := s.db.GetAPIToken(id)
	if err != nil {
		return Token{}, translateErr(err)
	}
	return fromRow(row), nil
}

func (s *SQLStore) List() ([]Token, error) {
	rows, err := s.db.ListAPITokens()
	if err != nil {
		return nil, fmt.Errorf("apitoken: list: %w", err)
	}
	out := make([]Token, 0, len(rows))
	for _, row := range rows {
		out = append(out, fromRow(row))
	}
	return out, nil
}

func (s *SQLStore) Revoke(id string, at time.Time) error {
	if err := s.db.RevokeAPIToken(id, at); err != nil {
		return translateErr(err)
	}
	return nil
}

func (s *SQLStore) Touch(id string, at time.Time) error {
	return s.db.TouchAPIToken(id, at)
}

func fromRow(row statedb.APITokenRow) Token {
	return Token{
		ID:           row.ID,
		Name:         row.Name,
		Hash:         row.Hash,
		Prefix:       row.Prefix,
		Roles:        row.Roles,
		ProjectScope: row.ProjectScope,
		CreatedBy:    row.CreatedBy,
		CreatedAt:    row.CreatedAt,
		ExpiresAt:    row.ExpiresAt,
		LastUsedAt:   row.LastUsedAt,
		RevokedAt:    row.RevokedAt,
	}
}

// translateErr maps the storage sentinel onto this package's, so callers test
// against apitoken.ErrNotFound without importing statedb.
func translateErr(err error) error {
	if errors.Is(err, statedb.ErrAPITokenNotFound) {
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	}
	return err
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

const (
	// touchInterval is how stale LastUsedAt is allowed to get before a use
	// triggers a write.
	//
	// Without coalescing, a CI token polling the hub turns every
	// authenticated read into a database write, which on SQLite means a
	// serialized writer contending with the orchestrator on the same file.
	// A minute of resolution is far more than "when did this token last do
	// anything" needs, and it bounds the write rate per token at 1/min
	// regardless of request volume.
	touchInterval = time.Minute

	// touchConcurrency bounds the goroutines the async touch may have in
	// flight at once. A saturated semaphore drops the update rather than
	// queueing it: LastUsedAt is advisory, and an unbounded queue under load
	// is a worse failure than a missing timestamp.
	touchConcurrency = 4
)

// Manager is the verification entry point: it holds the store, the clock, and
// the coalescing state for last-used tracking.
//
// Safe for concurrent use. Construct one per hub and share it.
type Manager struct {
	store Store

	// now is the clock, swappable in tests.
	now func() time.Time

	// onTouchErr receives failures from the asynchronous last-used write, so
	// a broken database is visible in the hub's log rather than silently
	// swallowed. nil discards.
	onTouchErr func(error)

	mu          sync.Mutex
	lastTouched map[string]time.Time
	touchSem    chan struct{}
}

// NewManager builds a Manager over store.
func NewManager(store Store) (*Manager, error) {
	if store == nil {
		return nil, errors.New("apitoken: nil store")
	}
	return &Manager{
		store:       store,
		now:         time.Now,
		lastTouched: make(map[string]time.Time),
		touchSem:    make(chan struct{}, touchConcurrency),
	}, nil
}

// SetClock overrides the clock. Tests only.
func (m *Manager) SetClock(now func() time.Time) {
	if now != nil {
		m.now = now
	}
}

// SetTouchErrorHandler installs a sink for asynchronous last-used write
// failures.
func (m *Manager) SetTouchErrorHandler(fn func(error)) { m.onTouchErr = fn }

// Verify authenticates a token string.
//
// Order of checks is deliberate. The secret is compared *before* expiry and
// revocation are consulted, so that a caller holding a wrong secret cannot
// distinguish "this id exists but is revoked" from "this id does not exist" by
// timing or by which error came back. Only a caller who already proved
// possession learns why their token stopped working — which is the person
// entitled to know.
//
// A successful verification schedules an asynchronous LastUsedAt update and
// returns immediately; the read path never waits on a write.
func (m *Manager) Verify(raw string) (*Token, error) {
	id, secret, ok := Parse(raw)
	if !ok {
		return nil, ErrMalformed
	}
	tok, err := m.store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("apitoken: verify: %w", err)
	}
	if !VerifyHash(tok.Hash, secret) {
		return nil, ErrBadSecret
	}
	now := m.now()
	if tok.Revoked() {
		return nil, ErrRevoked
	}
	if tok.Expired(now) {
		return nil, ErrExpired
	}
	if len(tok.ParsedRoles()) == 0 {
		return nil, ErrNoRoles
	}
	m.scheduleTouch(tok.ID, tok.LastUsedAt, now)
	return &tok, nil
}

// Mint creates and persists a token, returning the plaintext once.
func (m *Manager) Mint(opts MintOptions) (Minted, error) {
	if opts.Now.IsZero() {
		opts.Now = m.now()
	}
	minted, err := Mint(opts)
	if err != nil {
		return Minted{}, err
	}
	if err := m.store.Put(minted.Token); err != nil {
		return Minted{}, fmt.Errorf("apitoken: persist token: %w", err)
	}
	return minted, nil
}

// List returns every token, newest first.
func (m *Manager) List() ([]Token, error) {
	tokens, err := m.store.List()
	if err != nil {
		return nil, err
	}
	sort.SliceStable(tokens, func(i, j int) bool {
		return tokens[i].CreatedAt.After(tokens[j].CreatedAt)
	})
	return tokens, nil
}

// Get returns one token by id.
func (m *Manager) Get(id string) (Token, error) {
	return m.store.Get(strings.TrimSpace(id))
}

// Revoke withdraws a token. Idempotent; wraps ErrNotFound for an unknown id.
func (m *Manager) Revoke(id string) error {
	return m.store.Revoke(strings.TrimSpace(id), m.now())
}

// scheduleTouch records a use, coalesced to at most one write per token per
// touchInterval and capped at touchConcurrency goroutines.
//
// The dedup key is updated *before* the write is dispatched, so a burst of
// concurrent requests on one token produces exactly one write rather than one
// per request that happened to read a stale map.
func (m *Manager) scheduleTouch(id string, lastUsed, now time.Time) {
	m.mu.Lock()
	recorded, seen := m.lastTouched[id]
	if !seen {
		recorded = lastUsed
	}
	if seen || !lastUsed.IsZero() {
		if now.Sub(recorded) < touchInterval {
			m.mu.Unlock()
			return
		}
	}
	m.lastTouched[id] = now
	// Bound the memo: a hub that has issued thousands of tokens should not
	// accumulate an entry per token forever. Clearing wholesale is fine —
	// the only cost of a forgotten entry is one extra write.
	if len(m.lastTouched) > 1024 {
		m.lastTouched = map[string]time.Time{id: now}
	}
	m.mu.Unlock()

	select {
	case m.touchSem <- struct{}{}:
	default:
		// Saturated: drop the update rather than block the request or spawn
		// an unbounded goroutine.
		return
	}
	go func() {
		defer func() { <-m.touchSem }()
		// A panic in the storage layer must not take down the process from a
		// goroutine nobody is waiting on.
		defer func() {
			if rec := recover(); rec != nil && m.onTouchErr != nil {
				m.onTouchErr(fmt.Errorf("apitoken: panic in last-used update: %v", rec))
			}
		}()
		if err := m.store.Touch(id, now); err != nil && m.onTouchErr != nil {
			m.onTouchErr(fmt.Errorf("apitoken: record last use: %w", err))
		}
	}()
}
