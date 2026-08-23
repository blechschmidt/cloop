package gitproxy

import (
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
	RepoPath string
	// Upstream is the real https clone URL. It never reaches the sandbox.
	Upstream string
	// Policy is what this session may do.
	Policy Policy

	// Labels for the audit trail.
	ProjectID  string
	TaskID     string
	ExecutorID string
	Actor      string

	IssuedAt  time.Time
	ExpiresAt time.Time

	tokenHash  [sha256.Size]byte
	credential Credential

	closed    atomic.Bool
	reason    atomic.Value // string
	pushes    atomic.Int64
	fetches   atomic.Int64
	denied    atomic.Int64
	bytesUp   atomic.Int64
	bytesDown atomic.Int64
}

// Expired reports whether the session's TTL has run out.
func (s *Session) Expired(now time.Time) bool { return !now.Before(s.ExpiresAt) }

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
	// Upstream is the real https repository URL the proxy will forward to.
	Upstream string
	// Credential authenticates the proxy upstream. Optional: a public
	// repository needs none, though pushing to one generally does.
	Credential Credential
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
}

// Minted is a new session plus the one-time secret.
type Minted struct {
	Session *Session
	// Token is the plaintext session token. The registry keeps only its hash,
	// so this is the only copy that will ever exist.
	Token string
	// RepoURL is what the sandbox uses as its remote: the proxy's public base
	// with the session's repository path. It carries no credential.
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

	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewRegistry returns a registry serving sessions beneath baseURL.
func NewRegistry(baseURL string) (*Registry, error) {
	base, err := normalizeBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	return &Registry{BaseURL: base, sessions: make(map[string]*Session)}, nil
}

// normalizeBaseURL checks the public base the sandbox will clone from.
//
// https is required for the same reason pkg/executor requires it of a
// workspace repo: the sandbox presents its session token as an Authorization
// header on every request, and over cleartext that token is published rather
// than delivered. A loopback proxy is not an exception — a sandbox is, by
// construction, something that might be sharing the host.
func normalizeBaseURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("gitproxy: base URL is empty")
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("gitproxy: base URL %q is not a URL: %w", s, err)
	}
	switch {
	case u.Scheme != "https":
		return "", fmt.Errorf("gitproxy: base URL must be https, got scheme %q", u.Scheme)
	case u.Host == "":
		return "", errors.New("gitproxy: base URL has no host")
	case u.User != nil:
		return "", errors.New("gitproxy: base URL must not embed credentials")
	case strings.Trim(u.Path, "/") != "":
		return "", fmt.Errorf("gitproxy: base URL must have no path, got %q", u.Path)
	case u.RawQuery != "" || u.Fragment != "":
		return "", errors.New("gitproxy: base URL must not carry a query or fragment")
	}
	return u.Scheme + "://" + u.Host, nil
}

func (r *Registry) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Mint creates a session and returns its one-time token.
func (r *Registry) Mint(req MintRequest) (*Minted, error) {
	repoPath, err := UpstreamRepoPath(req.Upstream)
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
	token, err := randomToken(32)
	if err != nil {
		return nil, err
	}

	now := r.now()
	s := &Session{
		ID:         id,
		RepoPath:   repoPath,
		Upstream:   strings.TrimSuffix(strings.TrimSpace(req.Upstream), "/"),
		Policy:     pol,
		ProjectID:  req.ProjectID,
		TaskID:     req.TaskID,
		ExecutorID: req.ExecutorID,
		Actor:      req.Actor,
		IssuedAt:   now,
		ExpiresAt:  now.Add(ttl),
		tokenHash:  sha256.Sum256([]byte(token)),
		credential: req.Credential,
	}

	r.mu.Lock()
	if r.sessions == nil {
		r.sessions = make(map[string]*Session)
	}
	r.sessions[id] = s
	r.mu.Unlock()

	r.emit(Event{
		Kind:      EventSessionMinted,
		SessionID: id,
		RepoPath:  repoPath,
		ProjectID: req.ProjectID,
		TaskID:    req.TaskID,
		Actor:     req.Actor,
		At:        now,
		Detail:    fmt.Sprintf("allow %s until %s", strings.Join(pol.AllowedRefs, ","), s.ExpiresAt.UTC().Format(time.RFC3339)),
	})

	return &Minted{Session: s, Token: token, RepoURL: r.BaseURL + "/" + repoPath}, nil
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
		return nil, fmt.Errorf("%w: session expired at %s", ErrUnauthenticated, s.ExpiresAt.UTC().Format(time.RFC3339))
	}
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
	st := s.Stats()
	r.emit(Event{
		Kind:      EventSessionClosed,
		SessionID: s.ID,
		RepoPath:  s.RepoPath,
		ProjectID: s.ProjectID,
		TaskID:    s.TaskID,
		Actor:     s.Actor,
		At:        r.now(),
		Detail: fmt.Sprintf("%s (pushes=%d fetches=%d denied=%d)",
			reason, st.Pushes, st.Fetches, st.Denied),
	})
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
			r.emit(Event{
				Kind:      EventSessionClosed,
				SessionID: s.ID,
				RepoPath:  s.RepoPath,
				ProjectID: s.ProjectID,
				TaskID:    s.TaskID,
				Actor:     s.Actor,
				At:        now,
				Detail:    "expired",
			})
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

// randomToken returns n bytes of entropy as an unpadded base64url string.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("gitproxy: reading entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
