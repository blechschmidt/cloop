package oidcauth

// Session persistence, the two expiry clocks, and the audit contract
// (Task 20176).
//
// The storage interface lives here rather than in the package that implements
// it so oidcauth keeps its stdlib-only property: pkg/sessionstore adapts a
// statedb handle to SessionStore and does the sealing, and this package never
// learns that SQLite or AES exist. It is the same split pkg/secretbroker uses
// against pkg/secretstore, for the same reason — the policy is worth reading
// on its own, without a driver in the way.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"
)

// ErrSessionNotFound is what a store returns for an id it does not hold. It is
// an ordinary outcome on the authentication path: a forged cookie, a cookie
// that predates a restart, and a session an administrator just terminated are
// indistinguishable to the caller, and must stay that way.
var ErrSessionNotFound = errors.New("oidcauth: session not found")

// SessionRecord is one persisted session.
//
// ID is a hex SHA-256 of the cookie value, never the cookie itself — see
// HashSessionID. It doubles as the session's public identifier in the admin
// API, which is safe for the same reason a username is: the digest does not
// yield the preimage a request would have to present.
//
// RefreshToken is plaintext *in this struct only*. It crosses the SessionStore
// boundary in the clear and is sealed on the other side, so a store
// implementation is free to encrypt it at rest without this package holding a
// key. It is empty when the deployment has no encryption key configured, and
// nothing here may log it.
type SessionRecord struct {
	ID       string
	Identity Identity

	IP        string
	UserAgent string

	IssuedAt  time.Time
	LastSeen  time.Time
	ExpiresAt time.Time

	RefreshToken     string
	RefreshCheckedAt time.Time
}

// Expired reports whether the session is past its absolute ceiling.
func (s SessionRecord) Expired(now time.Time) bool {
	return !s.ExpiresAt.IsZero() && !now.Before(s.ExpiresAt)
}

// Idle reports whether the session has gone unused for longer than timeout.
// A non-positive timeout disables the idle clock.
func (s SessionRecord) Idle(now time.Time, timeout time.Duration) bool {
	if timeout <= 0 {
		return false
	}
	return now.Sub(s.LastSeen) >= timeout
}

// SessionStore persists sessions. Implementations must be safe for concurrent
// use: every authenticated request may read through one.
//
// Every method takes and returns the session id already hashed. A store that
// receives a raw cookie value has been called wrongly.
type SessionStore interface {
	// Put writes a new session. It must not overwrite an existing id.
	Put(SessionRecord) error

	// Get returns the session with id, or an error wrapping
	// ErrSessionNotFound.
	Get(id string) (SessionRecord, error)

	// List returns every session, most recently active first.
	List() ([]SessionRecord, error)

	// Touch records that a session was used at t. Called off the
	// authentication path and throttled by the caller; failures are advisory
	// and must not fail a request.
	Touch(id string, t time.Time) error

	// Delete removes one session and reports whether it existed.
	Delete(id string) (bool, error)

	// DeleteBySubject removes every session for subject except keepID (empty
	// removes all of them), returning what it deleted so each can be audited.
	DeleteBySubject(subject, keepID string) ([]SessionRecord, error)

	// DeleteExpired removes sessions whose ExpiresAt is at or before
	// absoluteCutoff, or whose LastSeen is at or before idleCutoff, returning
	// what it deleted. Both cutoffs are absolute times: the store holds no
	// opinion about how long a session should live.
	DeleteExpired(absoluteCutoff, idleCutoff time.Time) ([]SessionRecord, error)

	// DueForRefresh returns up to limit sessions holding a refresh token whose
	// last IdP check is at or before cutoff, oldest first.
	DueForRefresh(cutoff time.Time, limit int) ([]SessionRecord, error)

	// SetRefresh stores a rotated refresh token and stamps the check time. An
	// empty token clears the stored one, which is how a session that can no
	// longer be revalidated stops being retried.
	SetRefresh(id, refreshToken string, checkedAt time.Time) error
}

// HashSessionID maps a session cookie to the identifier used everywhere else.
//
// SHA-256 with no salt and no stretching, deliberately. The preimage is 256
// bits of CSPRNG output rather than a chosen secret, so there is no dictionary
// for a KDF to slow down, and an unsalted digest is what allows the lookup to
// be a single primary-key read on the authentication path.
func HashSessionID(sessionID string) string {
	sum := sha256.Sum256([]byte(sessionID))
	return hex.EncodeToString(sum[:])
}

// ── audit ───────────────────────────────────────────────────────────────────

// Session audit event types. These are the strings written into the
// hash-chained trail; they are wire values and must never be renamed.
const (
	// AuditSessionCreated records a successful sign-in.
	AuditSessionCreated = "session.created"

	// AuditSessionExpired records a session the janitor removed because one of
	// its two clocks ran out. Distinct from a revocation because "nobody
	// intervened, it simply lapsed" is a different answer to "why is this
	// person signed out".
	AuditSessionExpired = "session.expired"

	// AuditSessionRevoked records a deliberate termination: the user signing
	// out, the user ending every session, or an operator terminating one.
	AuditSessionRevoked = "session.revoked"

	// AuditSessionIdPRevoked records a session terminated because the identity
	// provider refused to renew it — the user was disabled, consent was
	// withdrawn, or the IdP forced a sign-out. This is the event that proves
	// IdP-side revocation actually reached the hub.
	AuditSessionIdPRevoked = "session.idp_revoked"
)

// SessionAudit describes one session lifecycle event.
//
// It carries no credential material by construction: the session id here is
// the digest, and there is no field a refresh or ID token could be written to.
type SessionAudit struct {
	Event     string
	SessionID string
	Subject   string
	Email     string
	Actor     string
	Reason    string
	IP        string
	UserAgent string
	At        time.Time
}

// ── in-memory store ─────────────────────────────────────────────────────────

// memStore is the default SessionStore: the pre-Task-20176 behaviour, kept as
// a real implementation rather than a nil branch so the hot path has exactly
// one shape.
//
// It is what a hub without a state database falls back to, and what the
// package's own tests run against. Sessions do not survive a restart, which is
// the whole point of configuring a durable one.
type memStore struct {
	mu   sync.Mutex
	max  int
	rows map[string]SessionRecord
}

// NewMemorySessionStore returns a process-local store bounded at max entries
// (zero uses the built-in bound). Oldest-first eviction keeps a burst of
// logins from growing the process without limit.
func NewMemorySessionStore(max int) SessionStore {
	if max <= 0 {
		max = maxSessions
	}
	return &memStore{max: max, rows: map[string]SessionRecord{}}
}

func (m *memStore) Put(rec SessionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.rows[rec.ID]; exists {
		return errors.New("oidcauth: session already exists")
	}
	for len(m.rows) >= m.max {
		if !m.evictOldestLocked() {
			break
		}
	}
	m.rows[rec.ID] = rec
	return nil
}

func (m *memStore) evictOldestLocked() bool {
	var oldest string
	var oldestAt time.Time
	for id, s := range m.rows {
		if oldest == "" || s.IssuedAt.Before(oldestAt) {
			oldest, oldestAt = id, s.IssuedAt
		}
	}
	if oldest == "" {
		return false
	}
	delete(m.rows, oldest)
	return true
}

func (m *memStore) Get(id string) (SessionRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.rows[id]
	if !ok {
		return SessionRecord{}, ErrSessionNotFound
	}
	return rec, nil
}

func (m *memStore) List() ([]SessionRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SessionRecord, 0, len(m.rows))
	for _, s := range m.rows {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out, nil
}

func (m *memStore) Touch(id string, t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.rows[id]
	if !ok {
		return ErrSessionNotFound
	}
	// Monotonic, matching the SQL store: two concurrent requests must not walk
	// last_seen backwards and shorten the idle window.
	if t.After(rec.LastSeen) {
		rec.LastSeen = t
		m.rows[id] = rec
	}
	return nil
}

func (m *memStore) Delete(id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.rows[id]
	delete(m.rows, id)
	return ok, nil
}

func (m *memStore) DeleteBySubject(subject, keepID string) ([]SessionRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []SessionRecord
	for id, s := range m.rows {
		if s.Identity.Sub != subject || id == keepID {
			continue
		}
		out = append(out, s)
		delete(m.rows, id)
	}
	return out, nil
}

func (m *memStore) DeleteExpired(absoluteCutoff, idleCutoff time.Time) ([]SessionRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []SessionRecord
	for id, s := range m.rows {
		expired := !s.ExpiresAt.IsZero() && !s.ExpiresAt.After(absoluteCutoff)
		idle := !s.LastSeen.After(idleCutoff)
		if !expired && !idle {
			continue
		}
		out = append(out, s)
		delete(m.rows, id)
	}
	return out, nil
}

func (m *memStore) DueForRefresh(cutoff time.Time, limit int) ([]SessionRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []SessionRecord
	for _, s := range m.rows {
		if s.RefreshToken == "" {
			continue
		}
		if s.RefreshCheckedAt.IsZero() || !s.RefreshCheckedAt.After(cutoff) {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RefreshCheckedAt.Before(out[j].RefreshCheckedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *memStore) SetRefresh(id, refreshToken string, checkedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.rows[id]
	if !ok {
		return ErrSessionNotFound
	}
	rec.RefreshToken = refreshToken
	rec.RefreshCheckedAt = checkedAt
	m.rows[id] = rec
	return nil
}
