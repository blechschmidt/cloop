package kubeguard

// session.go holds the sessions the proxy authenticates against.
//
// A session is one sandbox's scoped access to one cluster. It holds the real
// credential — the whole point, since that is what is being kept off the
// sandbox — plus the policy that credential may be spent under and a hash of
// the bearer token the sandbox presents.
//
// The token itself exists in exactly one place after minting: the kubeconfig
// delivered into the sandbox. The registry keeps a SHA-256 of it, so a dump
// of the hub's memory or a leak of this struct yields nothing that can
// authenticate.
//
// # What a leaked session token is worth
//
// The policy, for the remaining TTL, against one cluster, through one proxy.
// Under the default that is: read pods and configmaps in the granted
// namespaces, and nothing else — no writes, no exec, no secrets outside the
// allowlist, nothing at all once the TTL lapses. The kubeconfig it stands in
// for is worth whatever that cluster's RBAC grants the uploading user, which
// on a developer's own kubeconfig is frequently cluster-admin, from anywhere,
// until someone rotates it.

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

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

// Session lifetimes.
const (
	// DefaultSessionTTL is how long a session lives when the caller does not
	// say. A task's Kubernetes work happens inside one dispatch, so an hour
	// is generous.
	DefaultSessionTTL = time.Hour

	// MaxSessionTTL is the ceiling. Twelve hours, matching
	// gitproxy.MaxSessionTTL and for the same reason: a session that outlives
	// a working day is indistinguishable from having handed the sandbox the
	// kubeconfig outright.
	MaxSessionTTL = 12 * time.Hour
)

// Errors returned by the registry.
var (
	// ErrUnauthenticated covers every authentication failure. It is
	// deliberately one error: distinguishing "no such session" from "wrong
	// token" would be an oracle for enumerating live sessions.
	ErrUnauthenticated = errors.New("kubeguard: unauthenticated")
	// ErrSessionExpired is reported separately from ErrUnauthenticated
	// because the remedy differs and the token was genuinely correct. It is
	// only ever returned to a caller that already proved it held the token.
	ErrSessionExpired = errors.New("kubeguard: session expired")
	// ErrSessionClosed is an operator revocation or hub shutdown.
	ErrSessionClosed = errors.New("kubeguard: session closed")
)

// Stats is a session's traffic, for the closing audit row.
type Stats struct {
	Allowed  int64
	Denied   int64
	BytesIn  int64
	BytesOut int64
}

// Session is one sandbox's scoped access to one cluster.
type Session struct {
	// ID identifies the session. It is not a secret: it is the first half of
	// the bearer token and appears in every audit row.
	ID string
	// ClusterURL is the API server the session is pinned to. Recorded for
	// audit; the actual destination is upstream.Server, which no caller can
	// influence.
	ClusterURL string
	// ContextName is the kubeconfig context the session was minted from.
	ContextName string
	// Policy is what this session may do. Applied to every request.
	Policy Policy

	// Attribution, all recorded on audit rows.
	ProjectID  string
	TaskID     string
	ExecutorID string
	Actor      string
	GrantID    string
	LeaseID    string

	IssuedAt  time.Time
	ExpiresAt time.Time

	// upstream is the real cluster credential. Unexported, and never
	// serialised: Session has no MarshalJSON and every exported field above
	// is safe, so an accidental json.Marshal of a session cannot leak it.
	upstream *kubernetes.RESTConfig

	tokenHash [sha256.Size]byte

	mu     sync.Mutex
	closed bool
	reason string

	allowed  atomic.Int64
	denied   atomic.Int64
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

// Expired reports whether the session has lapsed.
func (s *Session) Expired(now time.Time) bool { return !now.Before(s.ExpiresAt) }

// Closed reports whether the session was revoked.
func (s *Session) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// CloseReason returns why the session was closed, or "".
func (s *Session) CloseReason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reason
}

// Stats snapshots the counters.
func (s *Session) Stats() Stats {
	return Stats{
		Allowed:  s.allowed.Load(),
		Denied:   s.denied.Load(),
		BytesIn:  s.bytesIn.Load(),
		BytesOut: s.bytesOut.Load(),
	}
}

// Upstream returns the real cluster credential. Only the proxy calls it, and
// only to build the outbound request.
func (s *Session) Upstream() *kubernetes.RESTConfig { return s.upstream }

// Describe renders the session for a diagnostic line, never its credential.
func (s *Session) Describe() string {
	return fmt.Sprintf("session=%s cluster=%s context=%s policy=[%s] expires=%s",
		s.ID, s.ClusterURL, orNone(s.ContextName), s.Policy.Summary(),
		s.ExpiresAt.UTC().Format(time.RFC3339))
}

// MintRequest describes a session to create.
type MintRequest struct {
	// Kubeconfig is the credential the hub holds, as delivered by the secret
	// broker. It is parsed here and kept only in RESTConfig form.
	Kubeconfig []byte
	// Context selects which context in the kubeconfig to use. Empty means the
	// document's current-context.
	Context string
	// Policy is what the session may do. The zero value means
	// ReadOnlyPolicy.
	Policy Policy
	// TTL bounds the session. Zero means DefaultSessionTTL; above
	// MaxSessionTTL is an error rather than a silent clamp.
	TTL time.Duration

	ProjectID  string
	TaskID     string
	ExecutorID string
	Actor      string
	GrantID    string
	LeaseID    string
}

// Minted is a new session plus the one copy of its token.
type Minted struct {
	Session *Session
	// Token is the bearer token the sandbox presents. This is the only copy
	// that will ever exist; the registry keeps a hash.
	Token string
	// Kubeconfig is the document to deliver into the sandbox. It points at
	// the proxy and carries Token, and it contains no cluster credential.
	Kubeconfig []byte
}

// Registry holds the process's live sessions.
type Registry struct {
	// BaseURL is the https endpoint sandboxes are pointed at.
	BaseURL string
	// CABundle is the PEM the sandbox should trust when connecting to
	// BaseURL. Empty means the sandbox's own trust store is expected to
	// contain it — correct for a publicly-signed certificate, and the reason
	// this is a separate field rather than an implicit skip-verify.
	CABundle []byte
	// Now is the clock, injectable for tests.
	Now func() time.Time
	// OnEvent receives audit rows. It runs on the request goroutine, so it
	// must be quick: a slow sink here delays a sandbox's API call.
	//
	// Denials are always delivered. Allowed requests are not, by default —
	// a `kubectl get pods` is several requests and a watch is one that never
	// ends, so a row per allowed request would bury the denials that matter
	// in discovery traffic. Set SampleAllowed to change that.
	OnEvent func(Event)
	// SampleAllowed, when true, emits an EventRequestAllowed for every
	// forwarded request. Off by default; see OnEvent.
	SampleAllowed bool

	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewRegistry returns a registry whose sessions are advertised at baseURL.
//
// baseURL must be https. The bearer token rides an Authorization header on
// every request, and a loopback listener is no exception: a sandbox is by
// construction something that may share a host with whatever else is
// listening on loopback.
func NewRegistry(baseURL string) (*Registry, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return nil, fmt.Errorf("kubeguard: base url %q: %w", baseURL, err)
	}
	switch {
	case u.Scheme != "https":
		return nil, fmt.Errorf("kubeguard: base url must be https (got %q)", baseURL)
	case u.Host == "":
		return nil, fmt.Errorf("kubeguard: base url has no host (got %q)", baseURL)
	case u.User != nil:
		return nil, errors.New("kubeguard: base url must not embed credentials")
	}
	return &Registry{
		BaseURL:  strings.TrimSuffix(u.String(), "/"),
		Now:      time.Now,
		sessions: make(map[string]*Session),
	}, nil
}

func (r *Registry) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
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

// Mint parses the kubeconfig, stores the credential, and returns a session
// plus the sandbox-facing document.
//
// The kubeconfig is parsed by pkg/executor/kubernetes.ParseKubeconfig rather
// than a parser of this package's own. That function already refuses the
// three things a tenant-supplied kubeconfig must never be allowed to do —
// name an `exec` credential plugin, name an `auth-provider`, or point a
// credential at a file path on the control-plane host — and having one parser
// means those refusals cannot drift apart from the driver's.
func (r *Registry) Mint(req MintRequest) (*Minted, error) {
	if len(req.Kubeconfig) == 0 {
		return nil, errors.New("kubeguard: mint with no kubeconfig")
	}

	rc, err := kubernetes.ParseKubeconfig(req.Kubeconfig, strings.TrimSpace(req.Context))
	if err != nil {
		return nil, fmt.Errorf("kubeguard: %w", err)
	}

	policy := req.Policy
	if policy.IsZero() {
		policy = ReadOnlyPolicy()
	}
	policy.Normalize()
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("kubeguard: session policy: %w", err)
	}

	ttl := req.TTL
	switch {
	case ttl == 0:
		ttl = DefaultSessionTTL
	case ttl < 0:
		return nil, fmt.Errorf("kubeguard: negative session ttl %s", ttl)
	case ttl > MaxSessionTTL:
		// Refused rather than clamped: an operator who configured a day and
		// silently got twelve hours would discover it as a kubectl call that
		// stopped working halfway through a long run.
		return nil, fmt.Errorf("kubeguard: session ttl %s exceeds the maximum %s", ttl, MaxSessionTTL)
	}

	id, err := randomToken(12)
	if err != nil {
		return nil, fmt.Errorf("kubeguard: session id: %w", err)
	}
	secret, err := randomToken(32)
	if err != nil {
		return nil, fmt.Errorf("kubeguard: session token: %w", err)
	}

	now := r.now()
	s := &Session{
		ID:          id,
		ClusterURL:  rc.Server,
		ContextName: rc.Context,
		Policy:      policy,
		ProjectID:   strings.TrimSpace(req.ProjectID),
		TaskID:      strings.TrimSpace(req.TaskID),
		ExecutorID:  strings.TrimSpace(req.ExecutorID),
		Actor:       strings.TrimSpace(req.Actor),
		GrantID:     strings.TrimSpace(req.GrantID),
		LeaseID:     strings.TrimSpace(req.LeaseID),
		IssuedAt:    now,
		ExpiresAt:   now.Add(ttl),
		upstream:    rc,
		tokenHash:   sha256.Sum256([]byte(bearerToken(id, secret))),
	}

	doc, err := r.renderKubeconfig(s, bearerToken(id, secret), rc.Namespace)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	if r.sessions == nil {
		r.sessions = make(map[string]*Session)
	}
	r.sessions[id] = s
	r.mu.Unlock()

	r.emit(Event{
		Kind: EventSessionMinted, SessionID: id, Cluster: rc.Server, Context: rc.Context,
		ProjectID: s.ProjectID, TaskID: s.TaskID, ExecutorID: s.ExecutorID,
		Actor: s.Actor, GrantID: s.GrantID, LeaseID: s.LeaseID,
		Detail: fmt.Sprintf("%s until %s", policy.Summary(),
			s.ExpiresAt.UTC().Format(time.RFC3339)),
		At: now,
	})

	return &Minted{Session: s, Token: bearerToken(id, secret), Kubeconfig: doc}, nil
}

// Authenticate resolves a bearer token to a live session.
//
// The token is "<id>.<secret>". Splitting it lets the map be indexed without
// scanning, and the comparison that decides the answer is a constant-time
// compare of the full token's hash — so a caller learns nothing from timing
// about either half.
func (r *Registry) Authenticate(token string) (*Session, error) {
	id, _, ok := strings.Cut(strings.TrimSpace(token), ".")
	if !ok || id == "" {
		return nil, ErrUnauthenticated
	}

	r.mu.RLock()
	s := r.sessions[id]
	r.mu.RUnlock()

	if s == nil {
		// Hash anyway. Returning early here would make an unknown session
		// measurably faster to reject than a known one with a wrong token,
		// which is the enumeration oracle the single error type exists to
		// close.
		var dummy [sha256.Size]byte
		got := sha256.Sum256([]byte(token))
		subtle.ConstantTimeCompare(got[:], dummy[:])
		return nil, ErrUnauthenticated
	}

	got := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(got[:], s.tokenHash[:]) != 1 {
		return nil, ErrUnauthenticated
	}
	if s.Closed() {
		return nil, ErrSessionClosed
	}
	if s.Expired(r.now()) {
		return nil, ErrSessionExpired
	}
	return s, nil
}

// Session returns a session by ID without authenticating, for operators.
func (r *Registry) Session(id string) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[id]
	return s, ok
}

// Sessions returns every session the registry holds.
func (r *Registry) Sessions() []*Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, s)
	}
	return out
}

// Close revokes a session and records why.
//
// The session is closed rather than deleted so an in-flight request finds it
// and is refused with ErrSessionClosed, and so the closing row carries the
// counters. ReapExpired removes it later.
func (r *Registry) Close(id, reason string) {
	r.mu.RLock()
	s := r.sessions[id]
	r.mu.RUnlock()
	if s == nil {
		return
	}

	s.mu.Lock()
	already := s.closed
	if !already {
		s.closed = true
		s.reason = reason
	}
	s.mu.Unlock()
	if already {
		return
	}

	st := s.Stats()
	r.emit(Event{
		Kind: EventSessionClosed, SessionID: s.ID, Cluster: s.ClusterURL,
		Context: s.ContextName, ProjectID: s.ProjectID, TaskID: s.TaskID,
		ExecutorID: s.ExecutorID, Actor: s.Actor, GrantID: s.GrantID, LeaseID: s.LeaseID,
		Detail: fmt.Sprintf("%s (allowed=%d denied=%d)", reason, st.Allowed, st.Denied),
	})
}

// CloseForLease revokes every session minted against a lease, and reports how
// many it closed.
//
// This is what makes lease revocation mean something for Kubernetes. Without
// it, revoking a lease wipes the credential directory in the sandbox while
// the session the sandbox already authenticated with keeps working until its
// TTL — the exact gap Task 20178 closed for the other kinds.
func (r *Registry) CloseForLease(leaseID, reason string) int {
	leaseID = strings.TrimSpace(leaseID)
	if leaseID == "" {
		return 0
	}
	n := 0
	for _, s := range r.Sessions() {
		if s.LeaseID == leaseID && !s.Closed() {
			r.Close(s.ID, reason)
			n++
		}
	}
	return n
}

// ReapExpired drops lapsed and closed sessions, and returns how many it
// removed.
//
// Expiry is enforced at authentication regardless, so this is hygiene —
// without it the map grows for the life of the process.
func (r *Registry) ReapExpired() int {
	now := r.now()
	var lapsed []*Session

	r.mu.Lock()
	for id, s := range r.sessions {
		if s.Expired(now) || s.Closed() {
			if !s.Closed() {
				lapsed = append(lapsed, s)
			}
			delete(r.sessions, id)
		}
	}
	r.mu.Unlock()

	// Emitted outside the lock: OnEvent writes to the audit database, and
	// holding the registry's write lock across a disk write would stall every
	// in-flight request.
	for _, s := range lapsed {
		s.mu.Lock()
		s.closed, s.reason = true, "expired"
		s.mu.Unlock()
		st := s.Stats()
		r.emit(Event{
			Kind: EventSessionClosed, SessionID: s.ID, Cluster: s.ClusterURL,
			Context: s.ContextName, ProjectID: s.ProjectID, TaskID: s.TaskID,
			ExecutorID: s.ExecutorID, Actor: s.Actor, GrantID: s.GrantID, LeaseID: s.LeaseID,
			Detail: fmt.Sprintf("expired (allowed=%d denied=%d)", st.Allowed, st.Denied),
		})
	}
	return len(lapsed)
}

// bearerToken joins the two halves. "." separates them because base64url
// never produces one, so the split is unambiguous.
func bearerToken(id, secret string) string { return id + "." + secret }

// randomToken returns n bytes of crypto/rand as unpadded base64url.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
