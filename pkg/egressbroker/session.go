package egressbroker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TokenBytes is the size of a minted proxy token. 256 bits from crypto/rand
// is well past the point where guessing is the attack anyone would choose,
// which is what lets the token be stored as a bare SHA-256 rather than run
// through a password KDF: there is no dictionary to attack and no low-entropy
// user choice to protect.
const TokenBytes = 32

// DefaultSessionTTL bounds one redemption when neither the grant nor the
// broker says otherwise.
//
// Fifteen minutes matches pkg/secretbroker's lease TTL on purpose. The two
// are the same kind of object — a short-lived materialisation of a longer
// authorisation — and an operator who has learned "credentials in a sandbox
// last fifteen minutes and renew" should not have to learn a second number
// for the network.
const DefaultSessionTTL = 15 * time.Minute

// Session is one redemption of a grant: a live proxy credential, the policy
// snapshot it was issued under, and the byte counters that bound it.
//
// Sessions are memory-resident and die with the process. That is deliberate
// and matches pkg/secretbroker's decision not to persist leases: a session is
// a usable credential, and persisting one would create a durable artifact
// that outlives the proxy able to enforce its quota. A restarted control
// plane issues new sessions; it does not resurrect old ones.
//
// Safe for concurrent use — a single session is shared by every connection
// the sandbox opens.
type Session struct {
	ID string `json:"id"`
	// GrantID names the authority. The policy itself is snapshotted into
	// Grant below rather than re-read per request, so a request cannot be
	// evaluated against a half-updated grant; revocation lands at the next
	// redemption, bounded by the session TTL.
	GrantID string `json:"grant_id"`
	Grant   Grant  `json:"-"`

	ExecutorID string `json:"executor_id,omitempty"`
	ProjectID  string `json:"project_id,omitempty"`
	// TaskID ties every audit row to the unit of work that caused it, which
	// is what makes "what did task 20163 talk to" an answerable question.
	TaskID string `json:"task_id,omitempty"`
	Actor  string `json:"actor,omitempty"`

	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`

	// tokenHash is SHA-256 of the minted token. The token itself is returned
	// once, from Redeem, and is never stored, logged, or recoverable —
	// including by this process.
	tokenHash [sha256.Size]byte

	bytesUp   atomic.Int64
	bytesDown atomic.Int64
	requests  atomic.Int64
	closed    atomic.Bool

	// live holds the sockets this session currently owns, so ending the
	// session ends the traffic rather than only the right to start more.
	live connSet
	// done is closed when the session ends, so an in-flight plain-HTTP
	// transfer can be cancelled through its context.
	doneOnce sync.Once
	doneCh   chan struct{}
}

// connSet is a group of connections closed together.
//
// It exists because a proxy session is only as revocable as its open sockets.
// Marking a session closed and deleting it from a map stops the *next*
// request; it does nothing to a CONNECT tunnel that is already moving bytes,
// which is precisely the case revocation needs to cover. Tracking the sockets
// is what turns "no new connections" into "this stops now".
//
// The closed flag makes the set one-shot: a connection registered after the
// set was closed is closed immediately rather than escaping the teardown.
type connSet struct {
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

// add registers c and reports whether the set is still open. A false return
// means the caller must abandon the connection.
func (s *connSet) add(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if s.conns == nil {
		s.conns = make(map[net.Conn]struct{})
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *connSet) remove(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, c)
}

// closeAll closes every registered connection and refuses further
// registrations. Idempotent.
func (s *connSet) closeAll() {
	s.mu.Lock()
	conns := s.conns
	s.conns = nil
	s.closed = true
	s.mu.Unlock()

	for c := range conns {
		_ = c.Close()
	}
}

// track registers a connection with the session, or reports that the session
// has already ended.
func (s *Session) track(c net.Conn) bool { return s.live.add(c) }

// untrack deregisters a connection that closed on its own.
func (s *Session) untrack(c net.Conn) { s.live.remove(c) }

// Done returns a channel closed when the session ends, by expiry or by
// revocation.
func (s *Session) Done() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.doneCh
}

// end marks the session finished, releases its sockets, and unblocks anything
// waiting on Done. It reports whether this call was the one that ended it, so
// the caller can emit exactly one audit row.
func (s *Session) end() bool {
	if s == nil || !s.closed.CompareAndSwap(false, true) {
		return false
	}
	s.doneOnce.Do(func() { close(s.doneCh) })
	s.live.closeAll()
	return true
}

// BindContext returns a context bounded by the session: it is cancelled at
// the session's TTL, and immediately if the session is revoked.
//
// The plain-HTTP path needs this because it has no socket of its own to put a
// deadline on — the response body is streamed by an http.Transport, and the
// only handle on it is the request context. Without it a workload could hold
// an endless chunked response open long past its lease.
func (s *Session) BindContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithDeadline(parent, s.ExpiresAt)
	// The watcher exits on ctx.Done, which the caller's deferred cancel
	// guarantees, so it cannot outlive the request.
	go func() {
		select {
		case <-s.doneCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// Redemption is what a caller gets back from Broker.Redeem: the session, and
// the one and only copy of its token.
//
// The token is a separate field rather than a Session field so that a Session
// can be marshalled, logged, or returned over an API without any possibility
// of carrying the credential with it — the same property pkg/secretbroker
// gets by keeping Secret.Sealed json:"-".
type Redemption struct {
	Session *Session
	// Token is the plaintext proxy token. Single-use in the sense that
	// matters: it is minted for exactly one session and cannot be presented
	// to mint another.
	Token string
	// ProxyURL is the full "http://id:token@host:port" the sandbox uses. It
	// carries the credential, so it is never audited or logged.
	ProxyURL string
}

// Env returns the environment a workload needs to route through the proxy.
//
// Both cases of each variable are set because the ecosystem never agreed:
// curl and most Unix tooling read the lowercase forms, Go's
// http.ProxyFromEnvironment and most language runtimes read either, and a
// handful of Windows-origin tools read only the uppercase. Setting one and
// not the other is how a sandbox ends up with a proxy that half its tools
// ignore — and a tool that ignores the proxy in a --network=none sandbox does
// not leak, it simply fails, which is a confusing way to discover the
// mistake.
//
// NO_PROXY keeps loopback traffic local. Without it a workload that talks to
// its own sidecar on 127.0.0.1 would send that request to the proxy, which
// would refuse it as a blocked destination — correct, but for a request that
// never needed brokering.
func (r Redemption) Env() map[string]string {
	if r.Session == nil {
		return nil
	}
	noProxy := "localhost,127.0.0.1,::1"
	env := map[string]string{
		"HTTP_PROXY":            r.ProxyURL,
		"HTTPS_PROXY":           r.ProxyURL,
		"http_proxy":            r.ProxyURL,
		"https_proxy":           r.ProxyURL,
		"NO_PROXY":              noProxy,
		"no_proxy":              noProxy,
		"CLOOP_EGRESS_SESSION":  r.Session.ID,
		"CLOOP_EGRESS_ALLOW":    strings.Join(r.Session.Grant.Hosts, ","),
		"CLOOP_EGRESS_EXPIRES":  r.Session.ExpiresAt.UTC().Format(time.RFC3339),
		"CLOOP_EGRESS_GRANT_ID": r.Session.GrantID,
	}
	if len(r.Session.Grant.CIDRs) > 0 {
		env["CLOOP_EGRESS_ALLOW_CIDRS"] = strings.Join(r.Session.Grant.CIDRs, ",")
	}
	return env
}

// EnvLines renders Env as sorted "K=V" strings, ready to append to an
// executor.Spec's Env.
func (r Redemption) EnvLines() []string {
	env := r.Env()
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out
}

// Expired reports whether the session's TTL has elapsed at now.
func (s *Session) Expired(now time.Time) bool {
	return s == nil || s.closed.Load() || !now.Before(s.ExpiresAt)
}

// TTL returns the remaining lifetime at now, clamped at zero.
func (s *Session) TTL(now time.Time) time.Duration {
	if s == nil {
		return 0
	}
	d := s.ExpiresAt.Sub(now)
	if d < 0 {
		return 0
	}
	return d
}

// BytesUp and BytesDown report the running totals.
func (s *Session) BytesUp() int64   { return s.bytesUp.Load() }
func (s *Session) BytesDown() int64 { return s.bytesDown.Load() }

// Requests reports how many proxy requests this session has made.
func (s *Session) Requests() int64 { return s.requests.Load() }

// Closed reports whether the session has been retired.
func (s *Session) Closed() bool { return s != nil && s.closed.Load() }

// verify compares a presented token against the stored hash in constant time.
//
// The comparison is over hashes rather than over the tokens themselves so
// that no code path holds the plaintext for longer than the request, and it
// is constant-time so that the number of leading bytes an attacker guessed
// right is not observable in the response latency.
func (s *Session) verify(token string) bool {
	if s == nil {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(sum[:], s.tokenHash[:]) == 1
}

// addUp records bytes sent by the sandbox and reports whether the up quota
// is now exceeded.
//
// The counter is advanced before the check, so the returned error describes
// the state the transfer is actually in. Callers tear the transfer down on
// true rather than trimming the write: a truncated request body delivered to
// an origin is worse than a failed one.
func (s *Session) addUp(n int64) error {
	if n <= 0 {
		return nil
	}
	total := s.bytesUp.Add(n)
	if limit := s.Grant.MaxBytesUp; limit > 0 && total > limit {
		return fmt.Errorf("%w: sent %s of the %s upload budget",
			ErrQuotaExceeded, FormatBytes(total), FormatBytes(limit))
	}
	return nil
}

// addDown records bytes received from the origin and reports whether the
// down quota is now exceeded.
func (s *Session) addDown(n int64) error {
	if n <= 0 {
		return nil
	}
	total := s.bytesDown.Add(n)
	if limit := s.Grant.MaxBytesDown; limit > 0 && total > limit {
		return fmt.Errorf("%w: received %s of the %s download budget",
			ErrQuotaExceeded, FormatBytes(total), FormatBytes(limit))
	}
	return nil
}

// checkLive is the per-request gate on the session itself: still open, not
// expired.
func (s *Session) checkLive(now time.Time) error {
	if s == nil || s.closed.Load() {
		return fmt.Errorf("%w: session was closed", ErrSessionExpired)
	}
	if !now.Before(s.ExpiresAt) {
		return fmt.Errorf("%w: session %s expired at %s",
			ErrSessionExpired, s.ID, s.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if s.Grant.MaxBytesUp > 0 && s.bytesUp.Load() >= s.Grant.MaxBytesUp {
		return fmt.Errorf("%w: upload budget of %s is spent",
			ErrQuotaExceeded, FormatBytes(s.Grant.MaxBytesUp))
	}
	if s.Grant.MaxBytesDown > 0 && s.bytesDown.Load() >= s.Grant.MaxBytesDown {
		return fmt.Errorf("%w: download budget of %s is spent",
			ErrQuotaExceeded, FormatBytes(s.Grant.MaxBytesDown))
	}
	return nil
}

// newToken mints a proxy token and its stored hash.
func newToken() (string, [sha256.Size]byte, error) {
	buf := make([]byte, TokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", [sha256.Size]byte{}, fmt.Errorf("egressbroker: generate token: %w", err)
	}
	tok := hex.EncodeToString(buf)
	return tok, sha256.Sum256([]byte(tok)), nil
}

// newSessionID returns a session identifier. Unlike the token this is not a
// secret — it is a map key and an audit field — but it is random anyway so
// that session counts and issuance rates are not inferable from it.
func newSessionID() (string, error) { return newID("sess") }

// newID returns a prefixed 96-bit identifier, matching pkg/secretbroker's
// format so IDs from the two brokers are visibly of a kind.
func newID(prefix string) (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("egressbroker: generate id: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(buf), nil
}

// buildProxyURL assembles the credential-bearing URL for a session.
//
// url.UserPassword handles the escaping, which matters because the session ID
// carries an underscore and a naive concatenation would be one encoding bug
// away from a credential that only works by accident.
func buildProxyURL(endpoint, sessionID, token string) (string, error) {
	e := strings.TrimSpace(endpoint)
	if e == "" {
		return "", fmt.Errorf("egressbroker: proxy endpoint is not configured")
	}
	if !strings.Contains(e, "://") {
		e = "http://" + e
	}
	u, err := url.Parse(e)
	if err != nil {
		return "", fmt.Errorf("egressbroker: parse proxy endpoint %q: %w", endpoint, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("egressbroker: proxy endpoint %q has no host", endpoint)
	}
	// The proxy speaks cleartext HTTP on its listener; the confidentiality of
	// what flows through it comes from the tunnelled TLS, not from the hop to
	// the proxy. Forcing the scheme keeps a stray "https://" in config from
	// producing a client that TLS-handshakes at a plaintext listener and
	// reports a certificate error nobody can explain.
	u.Scheme = "http"
	u.User = url.UserPassword(sessionID, token)
	u.Path = ""
	u.RawQuery = ""
	return u.String(), nil
}
