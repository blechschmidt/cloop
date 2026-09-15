package claudeproxy

// session.go is the registry of live CI sessions.
//
// Sessions live in memory and nowhere else, for the same reason gitproxy's and
// kubeguard's do: a session holds a policy and is authenticated by a secret
// this process minted, and the process that mints must be the process that
// serves. Persisting them would put a bearer credential at rest to survive a
// restart that a CI job does not outlive anyway — a runner whose hub restarts
// mid-job has already lost, and re-federating costs it one HTTP request.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Session bounds. MaxSessions is a memory guard: each session is a few
// hundred bytes, so the bound exists to make an unbounded mint path
// impossible rather than because the memory matters.
const (
	MinTTL      = 1 * time.Minute
	MaxTTL      = 6 * time.Hour
	MaxSessions = 4096
)

// Session is one federated pipeline's authority to relay.
//
// Counters are atomic and read without the registry lock, so a status page
// listing sessions cannot block a request in flight.
type Session struct {
	ID     string
	Policy Policy

	// Provenance: which rule admitted which pipeline. Recorded at mint so an
	// audit entry describes the identity that was actually accepted, not
	// whatever the rule says today.
	RuleID     string
	RuleName   string
	Project    string
	Subject    string
	Repository string
	Ref        string
	Workflow   string
	Actor      string
	RunID      string
	RunURL     string

	IssuedAt  time.Time
	ExpiresAt time.Time

	// tokenHash authenticates. The token itself is returned once by Mint and
	// is not retained: a registry that could produce its own session tokens
	// would be a registry an attacker with read access could mint from.
	tokenHash [sha256.Size]byte

	closed       atomic.Bool
	closedReason atomic.Pointer[string]

	requests   atomic.Int64
	denied     atomic.Int64
	inTok      atomic.Int64
	outTok     atomic.Int64
	cacheRead  atomic.Int64
	cacheWrite atomic.Int64
	bytesUp    atomic.Int64
	bytesDown  atomic.Int64
	lastUsed   atomic.Int64 // unix nanos
}

// Expired reports whether the session has lapsed.
func (s *Session) Expired(now time.Time) bool { return !now.Before(s.ExpiresAt) }

// Closed reports whether the session was revoked.
func (s *Session) Closed() bool { return s.closed.Load() }

// CloseReason returns why the session was revoked, or "".
func (s *Session) CloseReason() string {
	if p := s.closedReason.Load(); p != nil {
		return *p
	}
	return ""
}

// LastUsed returns the last time a request authenticated against this
// session, or the zero time.
func (s *Session) LastUsed() time.Time {
	n := s.lastUsed.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// Usage snapshots the counters.
func (s *Session) Usage() Usage {
	return Usage{
		Requests:     s.requests.Load(),
		Denied:       s.denied.Load(),
		InputTokens:  s.inTok.Load(),
		OutputTokens: s.outTok.Load(),
		CacheRead:    s.cacheRead.Load(),
		CacheWrite:   s.cacheWrite.Load(),
		BytesUp:      s.bytesUp.Load(),
		BytesDown:    s.bytesDown.Load(),
	}
}

// RemainingRequests reports how many relayed calls the session has left, or
// -1 when its policy sets no cap.
func (s *Session) RemainingRequests() int64 {
	if s.Policy.MaxRequests <= 0 {
		return -1
	}
	left := int64(s.Policy.MaxRequests) - s.requests.Load()
	if left < 0 {
		return 0
	}
	return left
}

// Label is a credential-free description for audit entries.
func (s *Session) Label() string {
	parts := make([]string, 0, 3)
	if s.Repository != "" {
		parts = append(parts, s.Repository)
	}
	if s.Ref != "" {
		parts = append(parts, s.Ref)
	}
	if s.Workflow != "" {
		parts = append(parts, s.Workflow)
	}
	if len(parts) == 0 {
		return s.ID
	}
	return strings.Join(parts, " ")
}

// claimRequest reserves one request against the budget.
//
// It is a compare-and-swap loop rather than a plain increment because two
// concurrent requests on the last unit of budget must not both succeed. A
// pipeline running several agent turns in parallel is exactly the case that
// would find that bug, and it would find it as an overspend.
func (s *Session) claimRequest() bool {
	if s.Policy.MaxRequests <= 0 {
		s.requests.Add(1)
		return true
	}
	max := int64(s.Policy.MaxRequests)
	for {
		cur := s.requests.Load()
		if cur >= max {
			return false
		}
		if s.requests.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// releaseRequest gives back a reservation that was never spent upstream.
func (s *Session) releaseRequest() {
	if s.requests.Load() > 0 {
		s.requests.Add(-1)
	}
}

// MintRequest describes the session to create.
type MintRequest struct {
	Policy Policy

	RuleID     string
	RuleName   string
	Project    string
	Subject    string
	Repository string
	Ref        string
	Workflow   string
	Actor      string
	RunID      string
	RunURL     string

	// TTL is the session lifetime, clamped to [MinTTL, MaxTTL].
	TTL time.Duration
}

// Minted is the one-time result of creating a session.
type Minted struct {
	Session *Session

	// Token is the only copy. It is not stored, and a caller that loses it
	// must mint again.
	Token string

	// BaseURL is what the pipeline sets ANTHROPIC_BASE_URL to.
	BaseURL string
}

// Registry holds live sessions.
type Registry struct {
	baseURL string

	mu       sync.Mutex
	sessions map[string]*Session

	now func() time.Time

	// OnEvent receives audit events. It is called on the calling goroutine,
	// so a sink that blocks blocks a request.
	OnEvent func(Event)
}

// NewRegistry returns an empty registry. baseURL is the externally reachable
// mount point of the proxy, handed to pipelines as ANTHROPIC_BASE_URL.
func NewRegistry(baseURL string) *Registry {
	return &Registry{
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		sessions: map[string]*Session{},
		now:      time.Now,
	}
}

// SetClock overrides the registry clock. For tests.
func (r *Registry) SetClock(now func() time.Time) {
	if now != nil {
		r.now = now
	}
}

// BaseURL returns the proxy mount point.
func (r *Registry) BaseURL() string { return r.baseURL }

// Mint creates a session and returns its one-time token.
func (r *Registry) Mint(req MintRequest) (*Minted, error) {
	if len(req.Policy.Models) == 0 {
		// An empty model allowlist would produce a session that can
		// authenticate and do nothing, which reads as a broken proxy rather
		// than as a policy decision. Callers resolve the hub default first.
		return nil, errors.New("claudeproxy: a session needs at least one permitted model")
	}
	ttl := clampDuration(req.TTL, MinTTL, MaxTTL)
	if req.TTL <= 0 {
		ttl = clampDuration(30*time.Minute, MinTTL, MaxTTL)
	}
	id, err := randomHex(12)
	if err != nil {
		return nil, fmt.Errorf("claudeproxy: %w", err)
	}
	secret, err := randomHex(32)
	if err != nil {
		return nil, fmt.Errorf("claudeproxy: %w", err)
	}
	token := TokenPrefix + id + "." + secret
	now := r.now()
	s := &Session{
		ID:         id,
		Policy:     req.Policy,
		RuleID:     req.RuleID,
		RuleName:   req.RuleName,
		Project:    req.Project,
		Subject:    req.Subject,
		Repository: req.Repository,
		Ref:        req.Ref,
		Workflow:   req.Workflow,
		Actor:      req.Actor,
		RunID:      req.RunID,
		RunURL:     req.RunURL,
		IssuedAt:   now,
		ExpiresAt:  now.Add(ttl),
		tokenHash:  sha256.Sum256([]byte(token)),
	}

	r.mu.Lock()
	if len(r.sessions) >= MaxSessions {
		// Sweep before refusing: the bound is almost always reached because
		// nothing has expired sessions recently, not because that many are
		// live.
		r.reapLocked(now)
	}
	if len(r.sessions) >= MaxSessions {
		r.mu.Unlock()
		return nil, fmt.Errorf("claudeproxy: %d sessions are live, which is the limit", MaxSessions)
	}
	r.sessions[id] = s
	r.mu.Unlock()

	r.emit(Event{
		Kind: EventSessionMinted, SessionID: id, RuleID: s.RuleID, RuleName: s.RuleName,
		Project: s.Project, Repository: s.Repository, Ref: s.Ref, Workflow: s.Workflow,
		Actor: s.Actor, RunID: s.RunID, Subject: s.Subject,
		Detail: fmt.Sprintf("models=%s ttl=%s max_requests=%d",
			strings.Join(s.Policy.Models, ","), ttl, s.Policy.MaxRequests),
		At: now,
	})
	return &Minted{Session: s, Token: token, BaseURL: r.baseURL}, nil
}

// Authenticate resolves a presented token to a live session.
//
// Every failure returns ErrUnauthenticated with no further detail, so a caller
// cannot tell an unknown session from an expired or revoked one by probing.
func (r *Registry) Authenticate(token string) (*Session, error) {
	id, ok := sessionIDOf(token)
	if !ok {
		return nil, ErrUnauthenticated
	}
	r.mu.Lock()
	s := r.sessions[id]
	r.mu.Unlock()
	if s == nil {
		return nil, ErrUnauthenticated
	}
	// Constant-time: the id half is public, the secret half is not, and a
	// byte-wise early exit on the hash comparison would leak it.
	got := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(got[:], s.tokenHash[:]) != 1 {
		return nil, ErrUnauthenticated
	}
	if s.Closed() {
		return nil, ErrUnauthenticated
	}
	now := r.now()
	if s.Expired(now) {
		return nil, ErrUnauthenticated
	}
	s.lastUsed.Store(now.UnixNano())
	return s, nil
}

// sessionIDOf splits a token into its public id half without validating the
// secret.
func sessionIDOf(token string) (string, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(token), TokenPrefix)
	if !ok {
		return "", false
	}
	id, secret, ok := strings.Cut(rest, ".")
	if !ok || id == "" || secret == "" {
		return "", false
	}
	return id, true
}

// Session returns a session by ID.
func (r *Registry) Session(id string) (*Session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	return s, ok
}

// Sessions lists live sessions, newest first.
func (r *Registry) Sessions() []*Session {
	r.mu.Lock()
	out := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, s)
	}
	r.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt.After(out[j].IssuedAt) })
	return out
}

// Close revokes a session. It is idempotent.
func (r *Registry) Close(id, reason string) error {
	r.mu.Lock()
	s := r.sessions[id]
	if s != nil {
		delete(r.sessions, id)
	}
	r.mu.Unlock()
	if s == nil {
		return ErrSessionNotFound
	}
	r.closeSession(s, reason)
	return nil
}

// CloseAll revokes every session, returning how many were live. Used on hub
// shutdown, and when an operator turns CI federation off: a policy change that
// leaves already-minted sessions relaying is a policy change that did not
// happen.
func (r *Registry) CloseAll(reason string) int {
	r.mu.Lock()
	live := make([]*Session, 0, len(r.sessions))
	for id, s := range r.sessions {
		live = append(live, s)
		delete(r.sessions, id)
	}
	r.mu.Unlock()
	for _, s := range live {
		r.closeSession(s, reason)
	}
	return len(live)
}

// CloseByRule revokes every session minted under a rule. Called when a rule is
// disabled or deleted, for the same reason CloseAll exists.
func (r *Registry) CloseByRule(ruleID, reason string) int {
	if ruleID == "" {
		return 0
	}
	r.mu.Lock()
	var hit []*Session
	for id, s := range r.sessions {
		if s.RuleID == ruleID {
			hit = append(hit, s)
			delete(r.sessions, id)
		}
	}
	r.mu.Unlock()
	for _, s := range hit {
		r.closeSession(s, reason)
	}
	return len(hit)
}

func (r *Registry) closeSession(s *Session, reason string) {
	if s.closed.Swap(true) {
		return
	}
	s.closedReason.Store(&reason)
	u := s.Usage()
	r.emit(Event{
		Kind: EventSessionClosed, SessionID: s.ID, RuleID: s.RuleID, RuleName: s.RuleName,
		Project: s.Project, Repository: s.Repository, Ref: s.Ref, Workflow: s.Workflow,
		Actor: s.Actor, RunID: s.RunID, Subject: s.Subject,
		Detail: fmt.Sprintf("%s: %d requests, %d denied, %d tokens",
			reason, u.Requests, u.Denied, u.TotalTokens()),
		At: r.now(),
	})
}

// ReapExpired sweeps lapsed sessions and returns how many were removed.
// Expiry is enforced at authentication regardless, so this is hygiene.
func (r *Registry) ReapExpired() int {
	now := r.now()
	r.mu.Lock()
	gone := r.reapLocked(now)
	r.mu.Unlock()
	for _, s := range gone {
		r.closeSession(s, "expired")
	}
	return len(gone)
}

func (r *Registry) reapLocked(now time.Time) []*Session {
	var gone []*Session
	for id, s := range r.sessions {
		if s.Expired(now) {
			gone = append(gone, s)
			delete(r.sessions, id)
		}
	}
	return gone
}

func (r *Registry) emit(e Event) {
	if r.OnEvent == nil {
		return
	}
	if e.At.IsZero() {
		e.At = r.now()
	}
	r.OnEvent(e)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read randomness: %w", err)
	}
	return hex.EncodeToString(b), nil
}
