package gitproxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/redact"
)

// DefaultSessionTTL bounds one sandbox's access to the proxy.
//
// It is the length of a task's git traffic, not the length of a task: the
// session is minted when a workload is dispatched and the clone and the
// write-back push both happen inside it. An hour covers a slow clone of a large
// repository over a slow link and still expires long before anything that
// leaked the token could be used at leisure.
const DefaultSessionTTL = time.Hour

// MaxSessionTTL is the ceiling an operator cannot configure past. A git proxy
// session is a standing authority to push, and a long-lived one is
// indistinguishable from having handed the sandbox the credential itself.
const MaxSessionTTL = 12 * time.Hour

// Errors a caller distinguishes.
var (
	// ErrUnauthenticated covers every authentication failure — unknown
	// session, wrong token, expired, closed. They are one error on purpose: a
	// caller that could tell "no such session" from "wrong token" would be an
	// oracle for enumerating session IDs.
	ErrUnauthenticated = errors.New("gitproxy: unauthenticated")
	// ErrSessionNotFound is for management operations, where the caller is the
	// operator rather than the sandbox and precision is the point.
	ErrSessionNotFound = errors.New("gitproxy: session not found")
	// ErrWrongRepo means an authenticated session addressed a repository it
	// was not minted for.
	ErrWrongRepo = errors.New("gitproxy: session is not scoped to this repository")
)

// Credential is what the proxy presents upstream on the sandbox's behalf.
//
// It is the whole point of the design. The sandbox never holds this — it holds
// a session token that works against this proxy, for this repository, for this
// TTL, under this policy, and nowhere else. A token that escapes a sandbox
// buys an attacker exactly the authority the policy already granted, which is
// "push to refs/heads/cloop/**", rather than everything the underlying PAT can
// reach.
type Credential struct {
	Username string
	Password string
	// GrantID and LeaseID are audit bookkeeping. Neither is secret.
	GrantID string
	LeaseID string
}

// Empty reports whether there is nothing to present upstream.
func (c Credential) Empty() bool { return strings.TrimSpace(c.Password) == "" }

// authorization renders the credential as an HTTP basic header value.
func (c Credential) authorization() string {
	if c.Empty() {
		return ""
	}
	user := strings.TrimSpace(c.Username)
	if user == "" {
		user = "x-access-token"
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+c.Password))
}

// Session is one sandbox's brokered access to one repository.
type Session struct {
	// ID identifies the session and is the username half of the basic
	// credential the sandbox presents. Not secret.
	ID string
	// RepoPath is the "owner/name" the sandbox addresses, and the path the
	// proxy serves this session under. Pinning it means a session minted for
	// one repository cannot be replayed against another the same proxy happens
	// to be serving.
	//
	// Empty on a scoped session, where RepoPatterns takes over. See scope.go.
	RepoPath string
	// RepoPatterns is an owner/name glob allowlist. When non-empty the session
	// is *scoped* rather than pinned: it admits every repository the allowlist
	// matches, which is what lets one session stand in for a user's PAT grant
	// whose allowlist the hub cannot enumerate. See scope.go.
	RepoPatterns []string
	// Upstream is the real https clone URL — or, for a scoped session, the
	// forge host base beneath which repository paths are resolved. Either way
	// it never reaches the sandbox, and it is the only source of the host the
	// credential is ever presented to.
	Upstream string
	// ForgeHost is the forge host the session's credential is good against,
	// canonical: github.com, or a GitHub Enterprise Server host (Task 20423).
	// The proxy serves the session on that host's route only (forge.go).
	// Upstream is on this host, except for a scoped github.com session's,
	// which is the hub's to point at github.com or, in a test, a stand-in.
	ForgeHost string
	// Policy is what this session may do.
	Policy Policy

	// Labels for the audit trail.
	ProjectID  string
	TaskID     string
	ExecutorID string
	Actor      string
	// RunID, GrantID and LeaseID say which run the session serves and which
	// grant of which lease its upstream credential stands on (Task 20383): the
	// lease it is closed with, and the record a restore finds it by. None is
	// secret.
	RunID   string
	GrantID string
	LeaseID string

	IssuedAt time.Time

	// expiresAt is when the session stops authenticating, and renewedAt
	// when Renew last moved it — zero for a session never renewed. Guarded
	// by lifeMu: a workspace's session is renewed while its sandbox
	// authenticates with it (Task 20422). Read through ExpiresAt and
	// RenewedAt.
	lifeMu    sync.Mutex
	expiresAt time.Time
	renewedAt time.Time

	tokenHash [sha256.Size]byte

	// durable: the registry's Store holds a record of the session, which its
	// end must close (durable.go). Set before the session is visible.
	durable bool

	// The upstream credential, in generations (refresh.go). credMu guards all
	// four fields; cred is never nil on a minted session.
	credMu     sync.Mutex
	cred       *credentialGen
	refresh    RefreshFunc
	refreshing *refreshCall
	// retryAt holds back the next refresh after one failed for a reason that
	// may pass, so a busy workload does not ask GitHub once per request.
	retryAt time.Time
	// refreshErr is why the last refresh failed, for the error a request gets
	// when the held credential has already expired.
	refreshErr string

	closed    atomic.Bool
	reason    atomic.Value // string
	pushes    atomic.Int64
	fetches   atomic.Int64
	denied    atomic.Int64
	bytesUp   atomic.Int64
	bytesDown atomic.Int64
	// used records that the session authenticated at least once — the
	// sandbox presented it, whatever it went on to ask for.
	used atomic.Bool

	// onEnd is MintRequest.OnEnd, run once by end.
	onEnd   func()
	endOnce sync.Once

	// scans bounds the push scans running for this session at once
	// (pushgate.go).
	scansOnce sync.Once
	scans     chan struct{}
}

// maxScansPerSession is how many of one session's pushes are scanned at once;
// a third waits for a slot.
const maxScansPerSession = 2

// acquireScan waits for one of the session's scan slots, or for ctx to end,
// and returns the function that gives it back.
func (s *Session) acquireScan(ctx context.Context) (func(), error) {
	s.scansOnce.Do(func() { s.scans = make(chan struct{}, maxScansPerSession) })
	select {
	case s.scans <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-s.scans }) }, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}

// Used reports whether the session ever authenticated a request.
func (s *Session) Used() bool { return s.used.Load() }

// end runs the session's OnEnd hook, at most once, after the session has left
// the registry.
func (s *Session) end() {
	s.endOnce.Do(func() {
		if s.onEnd != nil {
			s.onEnd()
		}
	})
}

// ExpiresAt returns when the session stops authenticating.
func (s *Session) ExpiresAt() time.Time {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	return s.expiresAt
}

// RenewedAt returns when Renew last moved the deadline, or zero.
func (s *Session) RenewedAt() time.Time {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	return s.renewedAt
}

// Expired reports whether the session's TTL has run out.
func (s *Session) Expired(now time.Time) bool { return !now.Before(s.ExpiresAt()) }

// Closed reports whether the session was revoked.
func (s *Session) Closed() bool { return s.closed.Load() }

// CloseReason returns why the session was revoked, or "".
func (s *Session) CloseReason() string {
	v, _ := s.reason.Load().(string)
	return v
}

// Stats is a snapshot of one session's traffic, for the UI and audit rows.
type Stats struct {
	Pushes    int64 `json:"pushes"`
	Fetches   int64 `json:"fetches"`
	Denied    int64 `json:"denied"`
	BytesUp   int64 `json:"bytes_up"`
	BytesDown int64 `json:"bytes_down"`
}

// Stats returns the session's counters.
func (s *Session) Stats() Stats {
	return Stats{
		Pushes:    s.pushes.Load(),
		Fetches:   s.fetches.Load(),
		Denied:    s.denied.Load(),
		BytesUp:   s.bytesUp.Load(),
		BytesDown: s.bytesDown.Load(),
	}
}

// MintRequest describes the session to create.
type MintRequest struct {
	// Upstream is the real https repository URL the proxy will forward to —
	// or, when RepoPatterns is set, the forge host base (https://github.com)
	// beneath which the allowlisted repositories live.
	Upstream string
	// RepoPatterns, when non-empty, mints a *scoped* session: one that admits
	// every repository matching an owner/name glob, rather than the single
	// repository Upstream names. Upstream must then be a bare host base.
	//
	// This is the mode a user's GitHub PAT grant uses, because its allowlist
	// ("acme/*") names a set that only the forge can enumerate. See scope.go.
	RepoPatterns []string
	// ForgeHost is the forge host Credential is good against (Task 20423):
	// github.com, or the GitHub Enterprise Server host the grant names. The
	// session is served on that host's route alone, and a pinned session's
	// Upstream must be on it, as must a scoped one's for any host but
	// github.com. Empty is github.com for a scoped session and Upstream's own
	// host for a pinned one — what every request meant before hosts were
	// recorded.
	ForgeHost string
	// Credential authenticates the proxy upstream. Optional: a public
	// repository needs none, though pushing to one generally does.
	Credential Credential
	// CredentialExpiresAt is when the forge stops honouring Credential — a
	// GitHub App installation token's hour. Zero for a credential that does
	// not expire on a clock the hub knows (a PAT).
	CredentialExpiresAt time.Time
	// Refresh, when set, re-mints Credential before CredentialExpiresAt
	// (Task 20375). The session calls it from its request path once
	// CredentialRefreshWindow or less of the credential's life remains,
	// single-flight, presents the result to every later upstream request, and
	// retires the superseded credential once no request presents it. Requires
	// CredentialExpiresAt. See refresh.go.
	Refresh RefreshFunc
	// Policy is what the sandbox may do. Zero value gets WriteBackPolicy.
	Policy Policy
	// TTL bounds the session. 0 means DefaultSessionTTL; anything above
	// MaxSessionTTL is an error rather than a silent clamp, because a caller
	// that asked for a day and got twelve hours would discover it as a failed
	// push halfway through.
	TTL time.Duration

	ProjectID  string
	TaskID     string
	ExecutorID string
	Actor      string
	// RunID names the run the session is for, recorded with it.
	RunID string

	// Durable records the session in the registry's Store (Task 20383), so
	// that the hub process adopting its run after this one stops can restore
	// it under the same id and token. The lease path sets it: its sessions
	// stand on the run's lease, which the adopter takes over and re-derives
	// the upstream credential from. A session no lease is taken over for —
	// a workspace's, whose credential stands on a lease of its own — would
	// have nothing to be restored with, and is left out.
	Durable bool

	// OnEnd, when set, runs once after the session has left the registry —
	// closed, reaped after its TTL, or closed at shutdown — on the goroutine
	// that ended it and outside the registry's lock.
	//
	// It is for releasing what the upstream credential stands on. A GitHub
	// App installation token is destroyed at GitHub when the lease that
	// minted it is released, and a session presents that token upstream for
	// its whole life: releasing the lease when the credential was *delivered*
	// left the session holding a dead token (Task 20349).
	OnEnd func()
}

// Minted is a new session plus the one-time secret.
type Minted struct {
	Session *Session
	// Token is the plaintext session token. The registry keeps only its hash,
	// so this is the only copy that will ever exist.
	Token string
	// RepoURL is what the sandbox uses as its remote: the proxy's public base
	// with the session's repository path — or, for a scoped session, the route
	// its forge host's URLs are rewritten to (ForgeRoute). It carries no
	// credential.
	RepoURL string
}

// Credential renders what a driver delivers into the sandbox: a basic
// credential whose username is the session ID and whose password is the token.
func (m Minted) Credential() Credential {
	return Credential{Username: m.Session.ID, Password: m.Token}
}

// Registry holds live sessions.
//
// It is the hub-side half of the proxy and has no HTTP in it, so the policy
// decisions it gates can be tested without sockets — the same split
// pkg/egressbroker draws between Broker and Proxy, for the same reason.
type Registry struct {
	// BaseURL is the https base the sandbox reaches the proxy at, e.g.
	// "https://hub.internal:8443". Sessions render their RepoURL beneath it.
	BaseURL string
	// Now is the clock, injectable for tests. nil means time.Now.
	Now func() time.Time
	// OnEvent, if set, receives every authorisation decision. It runs on the
	// request goroutine, so an implementation that blocks blocks a push.
	OnEvent func(Event)
	// Store, if set, records every Durable session and its end (durable.go),
	// so another hub process can restore it. Nil keeps sessions in memory
	// only, as every registry did before Task 20383.
	Store SessionStore

	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewRegistry returns a registry serving sessions beneath baseURL.
func NewRegistry(baseURL string) (*Registry, error) {
	base, err := NormalizeBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	return &Registry{BaseURL: base, sessions: make(map[string]*Session)}, nil
}

func (r *Registry) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Mint creates a session and returns its one-time token.
func (r *Registry) Mint(req MintRequest) (*Minted, error) {
	// Two shapes of session, distinguished by whether the caller supplied an
	// allowlist. They validate Upstream against opposite requirements — a
	// pinned session needs a repository URL, a scoped one needs a bare host —
	// so getting this wrong fails here rather than at the first fetch.
	var (
		repoPath string
		patterns []string
		upstream string
		err      error
	)
	if len(req.RepoPatterns) > 0 {
		patterns, err = normalizeRepoPatterns(req.RepoPatterns)
		if err != nil {
			return nil, err
		}
		upstream, err = UpstreamHostBase(req.Upstream)
		if err != nil {
			return nil, err
		}
	} else {
		repoPath, err = UpstreamRepoPath(req.Upstream)
		if err != nil {
			return nil, err
		}
		upstream = strings.TrimSuffix(strings.TrimSpace(req.Upstream), "/")
	}
	forge, err := sessionForgeHost(req.ForgeHost, upstream, len(patterns) > 0)
	if err != nil {
		return nil, err
	}

	pol := req.Policy
	if pol.IsZero() {
		pol = WriteBackPolicy()
	}
	pol.Normalize()
	if err := pol.Validate(); err != nil {
		return nil, fmt.Errorf("gitproxy: %w", err)
	}

	if req.Refresh != nil && req.CredentialExpiresAt.IsZero() {
		// A refresher with nothing to measure the credential against would
		// never run, and the session would fail at an expiry nobody recorded.
		return nil, errors.New("gitproxy: a refreshable upstream credential needs its expiry")
	}

	ttl := req.TTL
	switch {
	case ttl == 0:
		ttl = DefaultSessionTTL
	case ttl < 0:
		return nil, fmt.Errorf("gitproxy: session TTL %s is negative", ttl)
	case ttl > MaxSessionTTL:
		return nil, fmt.Errorf("gitproxy: session TTL %s exceeds the %s maximum", ttl, MaxSessionTTL)
	}

	id, err := randomToken(12)
	if err != nil {
		return nil, err
	}
	secret, err := randomToken(sessionTokenBytes)
	if err != nil {
		return nil, err
	}
	// The prefix (Task 20454) is what lets a hub process that adopted the run,
	// and holds only this token's hash, find it in the run's output and its
	// pushes and confirm it against the hash.
	token := redact.GitProxyTokenPrefix + secret

	now := r.now()
	s := &Session{
		ID:           id,
		RepoPath:     repoPath,
		RepoPatterns: patterns,
		Upstream:     upstream,
		ForgeHost:    forge,
		Policy:       pol,
		ProjectID:    req.ProjectID,
		TaskID:       req.TaskID,
		ExecutorID:   req.ExecutorID,
		Actor:        req.Actor,
		RunID:        strings.TrimSpace(req.RunID),
		GrantID:      strings.TrimSpace(req.Credential.GrantID),
		LeaseID:      strings.TrimSpace(req.Credential.LeaseID),
		IssuedAt:     now,
		expiresAt:    now.Add(ttl),
		tokenHash:    sha256.Sum256([]byte(token)),
		cred:         &credentialGen{cred: req.Credential, expiresAt: req.CredentialExpiresAt},
		refresh:      req.Refresh,
		onEnd:        req.OnEnd,
	}

	// Durable before the session is handed out, so a hub that dies the moment
	// Mint returns leaves a record its successor can restore. A record that
	// cannot be written costs the session its survival, not its use: it works
	// here, and the minted row says what was lost.
	var recordErr error
	if req.Durable && r.Store != nil {
		if recordErr = r.Store.SaveSession(s.record()); recordErr == nil {
			s.durable = true
		}
	}

	r.mu.Lock()
	if r.sessions == nil {
		r.sessions = make(map[string]*Session)
	}
	r.sessions[id] = s
	r.mu.Unlock()

	// A scoped session has no single repository to name, so the audit row
	// carries the allowlist instead. Leaving RepoPath empty in the event would
	// make every scoped mint look like a malformed one.
	scope := repoPath
	if s.Scoped() {
		scope = strings.Join(patterns, ",")
	}
	r.emit(Event{
		Kind:      EventSessionMinted,
		SessionID: id,
		RepoPath:  scope,
		ProjectID: req.ProjectID,
		TaskID:    req.TaskID,
		Actor:     req.Actor,
		At:        now,
		Detail:    mintDetail(pol, s.ExpiresAt(), recordErr) + forgeDetail(forge),
	})

	// A pinned session hands back the one remote URL the sandbox clones. A
	// scoped one cannot: the repository is not known until the sandbox asks
	// for it, so what it gets is the route to rewrite its forge host to — the
	// base for github.com, /_forge/<host> beneath it for any other host — and
	// the path comes from whatever it was already trying to clone.
	repoURL := r.BaseURL
	if !s.Scoped() {
		repoURL = r.BaseURL + "/" + repoPath
	} else if path, perr := forgeRoutePath(forge); perr == nil && path != "" {
		repoURL = r.BaseURL + "/" + path
	}
	return &Minted{Session: s, Token: token, RepoURL: repoURL}, nil
}

// forgeDetail names a session's forge host on its audit rows, when it is not
// github.com: the host its credential is presented to.
func forgeDetail(host string) string {
	if host == "" || host == "github.com" {
		return ""
	}
	return "; presented to " + host
}

// Authenticate resolves a session from the basic credential a sandbox
// presented. Every failure returns ErrUnauthenticated.
func (r *Registry) Authenticate(id, token string) (*Session, error) {
	r.mu.RLock()
	s := r.sessions[id]
	r.mu.RUnlock()

	// Hash unconditionally so an unknown session ID costs the same as a known
	// one with a wrong token.
	got := sha256.Sum256([]byte(token))
	if s == nil {
		// Compare against a fixed value to keep the branch shapes alike; the
		// result is discarded.
		subtle.ConstantTimeCompare(got[:], make([]byte, sha256.Size))
		return nil, ErrUnauthenticated
	}
	if subtle.ConstantTimeCompare(got[:], s.tokenHash[:]) != 1 {
		return nil, ErrUnauthenticated
	}
	if s.Closed() {
		return nil, fmt.Errorf("%w: session was revoked (%s)", ErrUnauthenticated, s.CloseReason())
	}
	if s.Expired(r.now()) {
		return nil, fmt.Errorf("%w: session expired at %s", ErrUnauthenticated, s.ExpiresAt().UTC().Format(time.RFC3339))
	}
	s.used.Store(true)
	return s, nil
}

// Session returns a session by ID, for management and for tests.
func (r *Registry) Session(id string) (*Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSessionNotFound, id)
	}
	return s, nil
}

// Sessions returns every live session.
func (r *Registry) Sessions() []*Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, s)
	}
	return out
}

// Known reports whether id names a session this registry holds, live or not.
// It does not authenticate anything; see Options.Fallback for its one use.
func (r *Registry) Known(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.sessions[id]
	return ok
}

// Renew moves a live session's deadline to ttl from now — 0 is
// DefaultSessionTTL, more than MaxSessionTTL is refused as Mint refuses it —
// and never backwards, recording the renewal in the Store when the session is
// durable. It returns the deadline afterwards.
//
// It is how a workspace's session outlives session_minutes while its run does
// (Task 20422): the session is minted when the run is dispatched and has to
// authenticate the run's write-back push at its end, however long the run
// took. Whoever calls it decides the run is alive; the registry decides only
// that the session is. A session that is closed or unknown is
// ErrSessionNotFound, one already past its deadline ErrSessionLapsed —
// reviving it would race the reaper into serving a session it had written off.
func (r *Registry) Renew(id string, ttl time.Duration) (time.Time, error) {
	switch {
	case ttl == 0:
		ttl = DefaultSessionTTL
	case ttl < 0:
		return time.Time{}, fmt.Errorf("gitproxy: session TTL %s is negative", ttl)
	case ttl > MaxSessionTTL:
		return time.Time{}, fmt.Errorf("gitproxy: session TTL %s exceeds the %s maximum", ttl, MaxSessionTTL)
	}
	r.mu.RLock()
	s := r.sessions[id]
	r.mu.RUnlock()
	if s == nil || s.Closed() {
		return time.Time{}, fmt.Errorf("%w: %s", ErrSessionNotFound, id)
	}
	now := r.now()
	next := now.Add(ttl)
	s.lifeMu.Lock()
	current := s.expiresAt
	switch {
	case !now.Before(current):
		s.lifeMu.Unlock()
		return time.Time{}, fmt.Errorf("%w: %s expired at %s", ErrSessionLapsed, id, current.UTC().Format(time.RFC3339))
	case !next.After(current):
		s.lifeMu.Unlock()
		return current, nil
	}
	s.expiresAt, s.renewedAt = next, now
	s.lifeMu.Unlock()
	detail := "renewed while its run lives; allow " + s.Policy.RefSummary() + " until " + next.UTC().Format(time.RFC3339)
	if s.durable && r.Store != nil {
		// Renewed here all the same: refusing would end a live run's
		// write-back over a busy database. The trail says what a restart
		// would make of it, as a mint's does, and the next renewal writes
		// the record again.
		if err := r.Store.RenewSession(s.ID, next, now); err != nil {
			detail += "; not recorded durably, so a hub process that adopts its run restores it only until " +
				current.UTC().Format(time.RFC3339) + ": " + err.Error()
		}
	}
	r.emit(Event{
		Kind:      EventSessionRenewed,
		SessionID: s.ID,
		RepoPath:  s.scopeDescription(),
		ProjectID: s.ProjectID,
		TaskID:    s.TaskID,
		Actor:     s.Actor,
		At:        now,
		Detail:    detail,
	})
	return next, nil
}

// RenewMargin is how close to its deadline a session is renewed: five minutes,
// or half its TTL for a shorter one.
func RenewMargin(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	if half := ttl / 2; half < 5*time.Minute {
		return half
	}
	return 5 * time.Minute
}

// RenewTick is how often a renewer looks: a minute, or a quarter of the TTL
// for a shorter one — at least twice inside RenewMargin either way.
func RenewTick(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	if q := ttl / 4; q < time.Minute {
		return q
	}
	return time.Minute
}

// RenewalDue reports whether id is open with RenewMargin(ttl) or less of its
// life left, on the registry's clock: what a renewer asks before anything
// costlier, such as whether the run is still alive.
func (r *Registry) RenewalDue(id string, ttl time.Duration) bool {
	r.mu.RLock()
	s := r.sessions[id]
	r.mu.RUnlock()
	return s != nil && !s.Closed() && s.ExpiresAt().Sub(r.now()) <= RenewMargin(ttl)
}

// RenewDue renews id when RenewMargin(ttl) or less of its life remains, on the
// registry's clock, and reports whether it did and the deadline afterwards.
// A session that is closed or unknown is ErrSessionNotFound, one past its
// deadline ErrSessionLapsed, as for Renew.
func (r *Registry) RenewDue(id string, ttl time.Duration) (bool, time.Time, error) {
	r.mu.RLock()
	s := r.sessions[id]
	r.mu.RUnlock()
	if s == nil || s.Closed() {
		return false, time.Time{}, fmt.Errorf("%w: %s", ErrSessionNotFound, id)
	}
	current := s.ExpiresAt()
	if !r.RenewalDue(id, ttl) {
		return false, current, nil
	}
	next, err := r.Renew(id, ttl)
	if err != nil {
		return false, time.Time{}, err
	}
	return next.After(current), next, nil
}

// LeaseSessions returns the live sessions whose upstream credential stands on
// leaseID.
func (r *Registry) LeaseSessions(leaseID string) []*Session {
	var out []*Session
	for _, id := range r.sessionsForLease(leaseID) {
		r.mu.RLock()
		s := r.sessions[id]
		r.mu.RUnlock()
		if s != nil {
			out = append(out, s)
		}
	}
	return out
}

// Close revokes a session. It is idempotent, so a driver can call it from a
// defer without checking whether the run already ended.
func (r *Registry) Close(id, reason string) {
	r.mu.Lock()
	s := r.sessions[id]
	delete(r.sessions, id)
	r.mu.Unlock()
	if s == nil || !s.closed.CompareAndSwap(false, true) {
		return
	}
	if reason == "" {
		reason = "closed"
	}
	s.reason.Store(reason)
	r.closeRecord(s, reason)
	st := s.Stats()
	r.emit(Event{
		Kind:      EventSessionClosed,
		SessionID: s.ID,
		// The allowlist for a scoped session, as the mint row names it: its
		// RepoPath is empty, and a closing row that named nothing could not
		// be matched to the session it ends by anyone reading repositories.
		RepoPath:  s.scopeDescription(),
		ProjectID: s.ProjectID,
		TaskID:    s.TaskID,
		Actor:     s.Actor,
		At:        r.now(),
		Detail: fmt.Sprintf("%s (pushes=%d fetches=%d denied=%d)",
			reason, st.Pushes, st.Fetches, st.Denied),
	})
	s.end()
}

// ReapExpired drops sessions past their TTL and returns how many went.
//
// Authenticate already refuses an expired session, so this is hygiene rather
// than enforcement: without it the map grows for the life of the process.
func (r *Registry) ReapExpired() int {
	now := r.now()
	r.mu.Lock()
	var dead []*Session
	for id, s := range r.sessions {
		if s.Expired(now) {
			dead = append(dead, s)
			delete(r.sessions, id)
		}
	}
	r.mu.Unlock()
	for _, s := range dead {
		if s.closed.CompareAndSwap(false, true) {
			s.reason.Store("expired")
			r.closeRecord(s, "expired")
			r.emit(Event{
				Kind:      EventSessionClosed,
				SessionID: s.ID,
				RepoPath:  s.scopeDescription(),
				ProjectID: s.ProjectID,
				TaskID:    s.TaskID,
				Actor:     s.Actor,
				At:        now,
				Detail:    "expired",
			})
			s.end()
		}
	}
	return len(dead)
}

func (r *Registry) emit(e Event) {
	if r.OnEvent != nil {
		r.OnEvent(e)
	}
}

// UpstreamRepoPath extracts the "owner/name" a proxy serves an upstream under.
//
// The shape is not cosmetic. pkg/executor's Workspace.RepoPath parses exactly
// this out of a clone URL to match a GitHub grant's repository allowlist, so a
// proxy URL that did not preserve it would break grant matching for every
// workspace routed through the proxy.
func UpstreamRepoPath(upstream string) (string, error) {
	raw := strings.TrimSpace(upstream)
	if raw == "" {
		return "", errors.New("gitproxy: upstream repository URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("gitproxy: upstream %q is not a URL: %w", raw, err)
	}
	switch {
	case u.Scheme != "https":
		return "", fmt.Errorf("gitproxy: upstream must be an https:// URL, got scheme %q", u.Scheme)
	case u.Host == "":
		return "", errors.New("gitproxy: upstream has no host")
	case u.User != nil:
		// An upstream with credentials in it would put them in audit rows and
		// in the session's Upstream field. The credential belongs in
		// MintRequest.Credential, where it is handled as one.
		return "", errors.New("gitproxy: upstream must not embed credentials in the URL")
	}
	p := strings.Trim(u.Path, "/")
	p = strings.TrimSuffix(p, ".git")
	if p == "" || strings.Count(p, "/") != 1 {
		return "", fmt.Errorf("gitproxy: upstream path %q is not owner/name", u.Path)
	}
	for _, comp := range strings.Split(p, "/") {
		if comp == "" || comp == "." || comp == ".." {
			return "", fmt.Errorf("gitproxy: upstream path %q has an unusable component", u.Path)
		}
	}
	return p, nil
}

// sessionTokenBytes is the entropy in a session's password.
const sessionTokenBytes = 32

// TokenLen is the length of the password a session is minted with since Task
// 20454: redact.GitProxyTokenPrefix and 32 bytes of entropy, base64url. A
// session minted before then has an unprefixed 43-character password, which
// still authenticates — only its hash is kept, of whatever was minted.
const TokenLen = len(redact.GitProxyTokenPrefix) + (sessionTokenBytes*8+5)/6

// randomToken returns n bytes of entropy as an unpadded base64url string.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("gitproxy: reading entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
