package egressbroker

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// MaxSessionTTLCeiling is the hard upper bound on a session, regardless of
// what a grant or the config asks for. A proxy credential that lives for
// hours is not a lease, it is a configuration.
const MaxSessionTTLCeiling = 4 * time.Hour

// DefaultGrantTTL matches pkg/secretbroker's, so `--ttl` means the same thing
// in `cloop secret grant` and `cloop egress grant`.
const DefaultGrantTTL = 24 * time.Hour

// Broker issues and enforces egress grants.
//
// It owns the policy and the live sessions; pkg/egressbroker's Proxy owns the
// wire. The split is the same one pkg/secretbroker draws between broker and
// store: the part worth testing exhaustively should be testable without a
// socket, and it is — every decision below runs against an in-memory store
// with no network in sight.
//
// Safe for concurrent use.
type Broker struct {
	store   Store
	auditor secretbroker.Auditor

	mu       sync.RWMutex
	sessions map[string]*Session

	clock         func() time.Time
	maxSessionTTL time.Duration
	endpoint      string
}

// Option configures a Broker.
type Option func(*Broker)

// WithAuditor sets the audit sink. Without one, decisions are enforced but
// not recorded — acceptable for tests, never for a control plane, which is
// why cmd wires secretstore.NewAuditor unconditionally.
func WithAuditor(a secretbroker.Auditor) Option {
	return func(b *Broker) {
		if a != nil {
			b.auditor = a
		}
	}
}

// WithClock overrides the time source, so TTL expiry can be exercised
// without sleeping.
func WithClock(fn func() time.Time) Option {
	return func(b *Broker) {
		if fn != nil {
			b.clock = fn
		}
	}
}

// WithMaxSessionTTL sets the ceiling applied to every redemption. Values
// above MaxSessionTTLCeiling are clamped down to it: a config typo must not
// be able to mint an all-day credential.
func WithMaxSessionTTL(d time.Duration) Option {
	return func(b *Broker) {
		if d > 0 {
			if d > MaxSessionTTLCeiling {
				d = MaxSessionTTLCeiling
			}
			b.maxSessionTTL = d
		}
	}
}

// WithEndpoint sets the address sandboxes should use to reach the proxy
// ("127.0.0.1:8899", "host.containers.internal:8899"). It is what goes into
// HTTPS_PROXY, so it must be routable *from the sandbox*, which is not
// always the same as the address the proxy listens on.
func WithEndpoint(addr string) Option {
	return func(b *Broker) {
		if s := strings.TrimSpace(addr); s != "" {
			b.endpoint = s
		}
	}
}

// New builds a Broker over store.
func New(store Store, opts ...Option) (*Broker, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidGrant)
	}
	b := &Broker{
		store:         store,
		auditor:       nopAuditor{},
		sessions:      make(map[string]*Session),
		clock:         time.Now,
		maxSessionTTL: DefaultSessionTTL,
	}
	for _, opt := range opts {
		opt(b)
	}
	return b, nil
}

func (b *Broker) now() time.Time { return b.clock().UTC() }

// Endpoint returns the address handed to sandboxes.
func (b *Broker) Endpoint() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.endpoint
}

// SetEndpoint updates the advertised address. The proxy calls it after
// binding, so an operator who configured port 0 still gets a usable
// HTTPS_PROXY value rather than one naming a port nothing listens on.
func (b *Broker) SetEndpoint(addr string) {
	if s := strings.TrimSpace(addr); s != "" {
		b.mu.Lock()
		b.endpoint = s
		b.mu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// grants
// ---------------------------------------------------------------------------

// GrantRequest describes an egress grant to create.
type GrantRequest struct {
	Subject      secretbroker.Subject
	Scope        string
	Hosts        []string
	CIDRs        []string
	Ports        []int
	Methods      []string
	MaxBytesUp   int64
	MaxBytesDown int64
	SessionTTL   time.Duration
	// TTL is the grant's own lifetime. Zero means DefaultGrantTTL.
	TTL   time.Duration
	Actor string
}

// Grant authorises a subject to reach the network through the proxy.
func (b *Broker) Grant(ctx context.Context, req GrantRequest) (Grant, error) {
	if err := ctx.Err(); err != nil {
		return Grant{}, err
	}
	id, err := newID("egress")
	if err != nil {
		return Grant{}, err
	}
	now := b.now()
	g := Grant{
		ID:           id,
		Scope:        req.Scope,
		Subject:      req.Subject,
		Hosts:        req.Hosts,
		CIDRs:        req.CIDRs,
		Ports:        req.Ports,
		Methods:      req.Methods,
		MaxBytesUp:   req.MaxBytesUp,
		MaxBytesDown: req.MaxBytesDown,
		SessionTTL:   req.SessionTTL,
		CreatedAt:    now,
		CreatedBy:    req.Actor,
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = DefaultGrantTTL
	}
	g.ExpiresAt = now.Add(ttl)

	ev := secretbroker.Event{
		Action:  secretbroker.ActionEgressGrant,
		Actor:   req.Actor,
		Subject: req.Subject.String(),
	}
	if err := g.Validate(); err != nil {
		// A grant that fails validation never became a security decision, so
		// it is reported to the operator but not written as a denial — the
		// audit log records access outcomes, not typos.
		return Grant{}, err
	}
	ev.Constraints = g.Summary()
	ev.GrantID = g.ID
	ev.ExpiresAt = g.ExpiresAt

	if err := b.store.PutGrant(g); err != nil {
		return Grant{}, b.deny(ev, fmt.Errorf("%w: store grant: %v", ErrInvalidGrant, err))
	}
	ev.Decision = secretbroker.DecisionAllow
	b.emit(ev)
	return g, nil
}

// GrantFilter narrows ListGrants.
type GrantFilter struct {
	// Subject keeps only grants whose subject renders to this string.
	Subject string
	// ActiveOnly drops expired and revoked grants.
	ActiveOnly bool
}

// ListGrants returns grants matching the filter, newest first.
func (b *Broker) ListGrants(f GrantFilter) ([]Grant, error) {
	grants, err := b.store.ListGrants()
	if err != nil {
		return nil, err
	}
	now := b.now()
	out := grants[:0:0]
	for _, g := range grants {
		if f.Subject != "" && g.Subject.String() != f.Subject {
			continue
		}
		if f.ActiveOnly && !g.Active(now) {
			continue
		}
		out = append(out, g)
	}
	sortGrants(out)
	return out, nil
}

// Revoke marks a grant unusable and closes every live session it authorised.
//
// Closing the sessions is the difference between this and
// secretbroker.Revoke, and it is available here precisely because the
// capability is brokered rather than handed over: a leaked PAT cannot be
// recalled from a running container, but a proxy session can be torn down at
// the proxy, mid-tunnel, from the control plane. Revocation is therefore
// immediate rather than bounded by the session TTL.
func (b *Broker) Revoke(ctx context.Context, grantID, actor string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ev := secretbroker.Event{
		Action:  secretbroker.ActionEgressRevoke,
		Actor:   actor,
		GrantID: grantID,
	}
	g, err := b.store.GetGrant(grantID)
	if err != nil {
		return b.deny(ev, fmt.Errorf("%w: %s", ErrGrantNotFound, grantID))
	}
	ev.Subject = g.Subject.String()
	ev.Constraints = g.Summary()

	if !g.RevokedAt.IsZero() {
		// Idempotent: a retry is a success, not an error.
		ev.Decision = secretbroker.DecisionAllow
		ev.Reason = "already revoked at " + g.RevokedAt.UTC().Format(time.RFC3339)
		b.emit(ev)
		return nil
	}
	if err := b.store.RevokeGrant(grantID, b.now()); err != nil {
		return b.deny(ev, fmt.Errorf("%w: revoke: %v", ErrInvalidGrant, err))
	}

	closed := b.closeSessionsForGrant(grantID, "grant revoked")
	ev.Decision = secretbroker.DecisionAllow
	ev.Reason = fmt.Sprintf("revoked; %d live session(s) closed", closed)
	b.emit(ev)
	return nil
}

// ---------------------------------------------------------------------------
// sessions
// ---------------------------------------------------------------------------

// RedeemRequest identifies who wants a proxy credential.
type RedeemRequest struct {
	Requester secretbroker.Requester
	// TaskID is the unit of work, carried into every audit row this session
	// produces.
	TaskID string
	Actor  string
	// GrantID pins the redemption to one grant. Empty picks the widest
	// active match — see Redeem.
	GrantID string
}

// Redeem mints a single-use proxy credential for the first active grant that
// matches the requester.
//
// "Single-use" is about minting, not about requests: the token authorises one
// session, which may carry many connections, and cannot be presented to mint
// a second session. The plaintext is returned here and nowhere else — the
// broker keeps only its SHA-256, so a memory dump of the control plane taken
// after this call does not yield a usable credential.
//
// When several grants match, the first by the store's newest-first ordering
// wins rather than the union of all of them. Unioning would let two narrow
// grants silently compose into a wide one, and "why can this sandbox reach
// that host" would stop having a single answer.
func (b *Broker) Redeem(ctx context.Context, req RedeemRequest) (*Redemption, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r := req.Requester
	r.ProjectID = secretbroker.NormalizeProjectID(r.ProjectID)
	actor := req.Actor
	if actor == "" {
		actor = r.ExecutorID
	}

	base := secretbroker.Event{
		Action:     secretbroker.ActionEgressRedeem,
		Actor:      actor,
		ExecutorID: r.ExecutorID,
		ProjectID:  r.ProjectID,
		TaskID:     req.TaskID,
	}

	grants, err := b.store.ListGrants()
	if err != nil {
		return nil, b.deny(base, fmt.Errorf("%w: list grants: %v", ErrGrantNotFound, err))
	}
	now := b.now()

	var chosen *Grant
	var lastReason string
	for i := range grants {
		g := grants[i]
		if req.GrantID != "" && g.ID != req.GrantID {
			continue
		}
		if !g.Subject.Matches(r) {
			continue
		}
		// From here the grant was aimed at this requester, so a refusal is
		// worth a row: "the token is not arriving" must be debuggable.
		if reason := g.DenyReason(now); reason != "" {
			ev := base
			ev.GrantID = g.ID
			ev.Subject = g.Subject.String()
			ev.Constraints = g.Summary()
			ev.ExpiresAt = g.ExpiresAt
			lastReason = reason
			_ = b.deny(ev, fmt.Errorf("%w: %s", g.DenySentinel(), reason))
			continue
		}
		chosen = &g
		break
	}
	if chosen == nil {
		if lastReason == "" {
			lastReason = "no grant targets this executor/project"
		}
		return nil, b.deny(base, fmt.Errorf("%w: %s", ErrNoGrant, lastReason))
	}

	id, err := newSessionID()
	if err != nil {
		return nil, err
	}
	token, hash, err := newToken()
	if err != nil {
		return nil, err
	}
	sess := &Session{
		ID:         id,
		GrantID:    chosen.ID,
		Grant:      *chosen,
		ExecutorID: r.ExecutorID,
		ProjectID:  r.ProjectID,
		TaskID:     req.TaskID,
		Actor:      actor,
		IssuedAt:   now,
		ExpiresAt:  chosen.SessionDeadline(now, b.maxSessionTTL),
		tokenHash:  hash,
		doneCh:     make(chan struct{}),
	}

	b.mu.RLock()
	endpoint := b.endpoint
	b.mu.RUnlock()
	proxyURL, err := buildProxyURL(endpoint, sess.ID, token)
	if err != nil {
		return nil, b.deny(base, err)
	}

	b.mu.Lock()
	b.sessions[sess.ID] = sess
	b.mu.Unlock()

	// Re-read the grant now that the session is visible, and only now.
	//
	// This closes a race between Redeem and Revoke. Revoke stamps the store
	// and *then* snapshots the session map, so the two orderings are: either
	// the stamp lands before this re-read, and we refuse; or it lands after,
	// in which case the session is already in the map and Revoke's snapshot
	// closes it. Checking before the insert would leave a window where
	// neither happens and a live session outlives its authority.
	if fresh, ferr := b.store.GetGrant(chosen.ID); ferr != nil || !fresh.Active(b.now()) {
		b.CloseSession(sess.ID, "grant became inactive during redemption")
		reason := "grant was revoked or expired during redemption"
		if ferr != nil {
			reason = "grant disappeared during redemption"
		}
		return nil, b.deny(base, fmt.Errorf("%w: %s", ErrNoGrant, reason))
	}

	ev := base
	ev.GrantID = chosen.ID
	ev.Subject = chosen.Subject.String()
	ev.Constraints = chosen.Summary()
	ev.LeaseID = sess.ID
	ev.ExpiresAt = sess.ExpiresAt
	ev.Decision = secretbroker.DecisionAllow
	ev.Reason = "proxy session issued"
	b.emit(ev)

	return &Redemption{Session: sess, Token: token, ProxyURL: proxyURL}, nil
}

// Authenticate resolves a presented credential to its session.
//
// Every failure returns the same ErrUnauthenticated, and the token comparison
// runs even when the session ID is unknown — against a zero hash, which no
// token can match. Both are there so that response timing does not reveal
// whether a session ID exists, which would otherwise turn the proxy into an
// enumeration oracle for live sessions.
func (b *Broker) Authenticate(sessionID, token string) (*Session, error) {
	b.mu.RLock()
	sess := b.sessions[sessionID]
	b.mu.RUnlock()

	if sess == nil {
		// Burn a comparison so the unknown-ID path costs the same as the
		// wrong-token path.
		(&Session{}).verify(token)
		return nil, fmt.Errorf("%w: unknown session", ErrUnauthenticated)
	}
	if !sess.verify(token) {
		return nil, fmt.Errorf("%w: token mismatch", ErrUnauthenticated)
	}
	if err := sess.checkLive(b.now()); err != nil {
		return nil, err
	}
	return sess, nil
}

// Session returns a live session by ID, or nil.
func (b *Broker) Session(id string) *Session {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.sessions[id]
}

// Sessions returns a snapshot of the live sessions, for the CLI and UI.
func (b *Broker) Sessions() []*Session {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]*Session, 0, len(b.sessions))
	for _, s := range b.sessions {
		out = append(out, s)
	}
	return out
}

// CloseSession retires a session, closes any socket it still holds, and
// records its final byte counts.
//
// Closing the sockets is what makes revocation immediate rather than
// TTL-bounded. That is the payoff for brokering a capability instead of
// handing over a token: a leaked PAT cannot be recalled from a running
// container, but a tunnel can be severed at the proxy, mid-transfer, by the
// process that owns the socket.
//
// It is idempotent: a session torn down by the proxy and then released by the
// orchestrator produces one close row, not two.
func (b *Broker) CloseSession(id, reason string) {
	b.mu.Lock()
	sess := b.sessions[id]
	delete(b.sessions, id)
	b.mu.Unlock()
	if !sess.end() {
		return
	}
	b.emit(secretbroker.Event{
		Action:     secretbroker.ActionEgressClose,
		Actor:      sess.Actor,
		LeaseID:    sess.ID,
		GrantID:    sess.GrantID,
		ExecutorID: sess.ExecutorID,
		ProjectID:  sess.ProjectID,
		TaskID:     sess.TaskID,
		BytesUp:    sess.BytesUp(),
		BytesDown:  sess.BytesDown(),
		Decision:   secretbroker.DecisionAllow,
		Reason:     fmt.Sprintf("%s after %d request(s)", reason, sess.Requests()),
	})
}

// closeSessionsForGrant retires every session issued under a grant and
// reports how many there were.
func (b *Broker) closeSessionsForGrant(grantID, reason string) int {
	b.mu.RLock()
	var ids []string
	for id, s := range b.sessions {
		if s.GrantID == grantID {
			ids = append(ids, id)
		}
	}
	b.mu.RUnlock()

	for _, id := range ids {
		b.CloseSession(id, reason)
	}
	return len(ids)
}

// ReapExpired retires sessions whose TTL has elapsed and returns how many.
// The proxy calls it on a ticker so that an idle expired session does not
// linger in memory until someone happens to present its credential.
func (b *Broker) ReapExpired() int {
	now := b.now()
	b.mu.RLock()
	var ids []string
	for id, s := range b.sessions {
		if !now.Before(s.ExpiresAt) {
			ids = append(ids, id)
		}
	}
	b.mu.RUnlock()

	for _, id := range ids {
		b.CloseSession(id, "session expired")
	}
	return len(ids)
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

// nopAuditor drops events, so the broker never nil-checks at a call site.
type nopAuditor struct{}

func (nopAuditor) Audit(secretbroker.Event) {}

// emit redacts and forwards an event, stamping the time if unset.
//
// Redact is pkg/secretbroker's, reused rather than reimplemented: an egress
// event carries no credential by construction, but its Reason is built from
// wrapped errors, and the whole point of redacting at the boundary is that it
// keeps working when a future error string is less careful than this one.
func (b *Broker) emit(ev secretbroker.Event) {
	if ev.Time.IsZero() {
		ev.Time = b.now()
	}
	b.auditor.Audit(secretbroker.Redact(ev))
}

// deny emits a denial event carrying err's message and returns err unchanged.
//
// Pairing the two makes "denied but not logged" inexpressible: there is no
// path in this package that refuses a request without producing a row.
func (b *Broker) deny(ev secretbroker.Event, err error) error {
	ev.Decision = secretbroker.DecisionDeny
	ev.Reason = err.Error()
	b.emit(ev)
	return err
}

// auditRequest records one proxy request decision, allowed or refused.
//
// This is the row the task's audit requirement names: identity, task, host,
// port, bytes, verdict — and, by construction, nothing else. There is no
// field on secretbroker.Event capable of carrying a URL path, a header, or a
// body, so a future change cannot start logging request contents by accident.
func (b *Broker) auditRequest(sess *Session, action secretbroker.Action, host string, port int, err error, reason string) {
	ev := secretbroker.Event{
		Action: action,
		Host:   host,
		Port:   port,
	}
	if sess != nil {
		ev.Actor = sess.Actor
		ev.LeaseID = sess.ID
		ev.GrantID = sess.GrantID
		ev.ExecutorID = sess.ExecutorID
		ev.ProjectID = sess.ProjectID
		ev.TaskID = sess.TaskID
		ev.Constraints = sess.Grant.Summary()
		ev.ExpiresAt = sess.ExpiresAt
		ev.BytesUp = sess.BytesUp()
		ev.BytesDown = sess.BytesDown()
	}
	if err != nil {
		ev.Decision = secretbroker.DecisionDeny
		ev.Reason = err.Error()
	} else {
		ev.Decision = secretbroker.DecisionAllow
		ev.Reason = reason
	}
	b.emit(ev)
}
