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

	// ClaimsAsOf is when the identity provider last asserted Identity's groups
	// and roles, and ClaimsExpireAt is the provider's own deadline on that
	// assertion (Task 20273).
	//
	// They are separate from RefreshCheckedAt because the two answer different
	// questions and routinely disagree. RefreshCheckedAt is stamped on every
	// revalidation attempt including the ones that learned nothing, so it means
	// "the grant was still alive at this instant" — which is what bounds
	// IdP-initiated revocation. These two mean "the claims in this row were
	// true at this instant", which is what bounds authorization staleness. A
	// provider that renews the grant without restating claims advances the
	// first and not the second, and collapsing them would report such a hub as
	// re-authorizing every fifteen minutes while its roles never move.
	//
	// See claimfresh.go for how they are read; ClaimsAssertedAt handles the
	// zero value, which is a session created before these columns existed.
	ClaimsAsOf     time.Time
	ClaimsExpireAt time.Time
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

	// ApplyRefresh records the outcome of one IdP revalidation. It must apply
	// every field of res in a single atomic write — see RefreshResult for why
	// splitting it is a privilege-retention bug.
	ApplyRefresh(id string, res RefreshResult) error
}

// RefreshResult is what one IdP revalidation learned about a session.
//
// It is applied as a unit rather than field by field, and that is a security
// property rather than an optimisation. The stamp is what marks a session
// re-authorized until the next interval; the claims are the authority it is
// re-authorized *with*. A store that wrote the stamp and then failed to write
// the claims would leave a session recorded as freshly checked while still
// carrying the roles it held before the IdP narrowed them — the exact
// retention window this machinery exists to close, now hidden behind a
// successful-looking check. Written together, a failure leaves the session
// unstamped and the next pass simply retries it.
type RefreshResult struct {
	// RefreshToken is the token to present next time: the provider's
	// replacement when it rotated, otherwise the one just redeemed. Empty
	// clears the stored token, which is how a session that can no longer be
	// revalidated stops being retried.
	RefreshToken string

	// CheckedAt stamps when the IdP last answered for this session.
	CheckedAt time.Time

	// ClaimsAsserted reports whether the refresh response carried an id_token
	// that verified. Only then are Groups and Roles meaningful; when it is
	// false the stored claims must be left exactly as they are, because
	// "the IdP did not say" is not "the IdP said nothing applies".
	ClaimsAsserted bool
	Groups         []string
	Roles          []string

	// ClaimsAsOf and ClaimsExpireAt update the session's claim-freshness clocks
	// (Task 20273). A zero value leaves the stored one alone, which is what
	// makes the three outcomes of a revalidation expressible:
	//
	//	claims re-asserted   both set — the assertion, and how long the IdP
	//	                     stands behind it (from the access token's
	//	                     expires_in, or zero when it named none)
	//	claims repudiated    ClaimsExpireAt set to the instant of the refusal,
	//	                     ClaimsAsOf untouched — the row still records when
	//	                     the claims were last true, and now also records
	//	                     that they have stopped being so
	//	nothing learned      both zero — the grant is alive, the claims are as
	//	                     stale as they were, and nothing may pretend
	//	                     otherwise
	//
	// They are part of RefreshResult, and therefore of its single atomic write,
	// for the reason in the type comment: a stamp written without the claims it
	// stands for is a session that looks re-authorized while holding authority
	// the provider has withdrawn.
	ClaimsAsOf     time.Time
	ClaimsExpireAt time.Time
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

	// AuditSessionRoleNarrowed records a live session losing authority because
	// the IdP stopped releasing a group or role it released at sign-in.
	//
	// Deprivileging is the one claim change that must never be silent. Every
	// other outcome of a revalidation leaves a trace an operator can reason
	// about — the session ends, or it visibly continues — but authority
	// quietly draining out of a session that stays signed in is invisible
	// unless it is written down. It is also the event an auditor asks for by
	// name after an incident: "show me that removing them from the admin group
	// actually took effect, and when."
	AuditSessionRoleNarrowed = "session.role_narrowed"

	// AuditSessionClaimsUnverified records that a renewal could re-assert the
	// session's claims from neither source: the provider returned no id_token,
	// and the userinfo endpoint did not answer either (it is unadvertised,
	// unreachable, or refused the access token).
	//
	// This is not a failure of the renewal: many providers only issue an
	// id_token on the initial code exchange, and the refresh grant succeeding
	// still proves the grant is alive, which is what IdP-side revocation
	// depends on. What it does mean is that the session's groups and roles are
	// still the ones captured at sign-in and will stay that way until it ends —
	// so a group removal at the IdP does not take effect on this hub. An
	// operator reading the trail has to be able to tell such a deployment from
	// one where claims genuinely are re-checked every interval, otherwise
	// "cloop re-authorizes every 15 minutes" is believed where it does not
	// happen. Emitted once per process rather than once per session per
	// interval: it describes the provider, not the user, so every session on
	// such a hub would otherwise write the same fact forever.
	//
	// Before Task 20261 this was the outcome for every provider that omits the
	// id_token, which is most of them. It is now the exception.
	AuditSessionClaimsUnverified = "session.claims_unverified"

	// AuditSessionClaimsRejected records the identity provider refusing to
	// vouch for a session's claims: the userinfo endpoint answered 401, or
	// named invalid_token, for an access token the very same refresh grant had
	// minted seconds earlier (Task 20273).
	//
	// Before this event that response was read and discarded, on the reasoning
	// that a provider which does not accept its own access token at userinfo,
	// or which wants a scope this deployment did not request, is a
	// misconfiguration rather than a revocation — and signing the fleet out
	// over it would turn a claim-freshness feature into a logout bug. That
	// reasoning still holds, and the conclusion drawn from it did not: the
	// session survives, and its claims stop being usable for anything above
	// operator until a later read succeeds. So the ambiguous case costs
	// privileged actions rather than everybody's session, and — unlike before
	// — it costs something, which is what gets it noticed and fixed.
	AuditSessionClaimsRejected = "session.claims_rejected"

	// AuditSessionClaimsStale records a privileged operation refused because
	// the session's claims were older than max_claim_age and could not be
	// refreshed (Task 20273).
	//
	// This is the event that proves the bound is load-bearing. Without it an
	// operator sees a 403 and nothing else, and cannot distinguish "my role
	// binding is wrong" — which they will go and change, incorrectly — from
	// "the hub could not reach the IdP", which is a different fix entirely.
	AuditSessionClaimsStale = "session.claims_stale"
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

	// PriorRole and Role name the effective role before and after a claim
	// refresh, and are set only by AuditSessionRoleNarrowed. They are empty
	// when the deployment supplies no EffectiveRole hook, in which case
	// DroppedClaims alone describes the narrowing.
	PriorRole string
	Role      string

	// DroppedClaims lists the group and role values the IdP released at
	// sign-in and no longer releases. Naming them is the difference between
	// an event an auditor can act on and one that only says something changed.
	DroppedClaims []string
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

func (m *memStore) ApplyRefresh(id string, res RefreshResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.rows[id]
	if !ok {
		return ErrSessionNotFound
	}
	rec.RefreshToken = res.RefreshToken
	rec.RefreshCheckedAt = res.CheckedAt
	// The same rule the SQL store applies, for the same reasons: a fresh
	// assertion replaces both clocks — including clearing a previous
	// provider deadline this response did not restate — while a repudiation
	// sets only the deadline, leaving on record when the claims were last true.
	switch {
	case !res.ClaimsAsOf.IsZero():
		rec.ClaimsAsOf, rec.ClaimsExpireAt = res.ClaimsAsOf, res.ClaimsExpireAt
	case !res.ClaimsExpireAt.IsZero():
		rec.ClaimsExpireAt = res.ClaimsExpireAt
	}
	if res.ClaimsAsserted {
		// Copied, not aliased: the caller's slices came from a decoded token
		// it is free to reuse, and a store that kept a reference to them would
		// let a later refresh mutate a session's authority in place.
		rec.Identity.Groups = append([]string(nil), res.Groups...)
		rec.Identity.Roles = append([]string(nil), res.Roles...)
	}
	m.rows[id] = rec
	return nil
}
