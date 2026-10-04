package gitproxy

// refresh.go keeps a session's upstream credential alive past the forge's own
// expiry (Task 20375).
//
// A session presents one credential upstream for its whole life, and for a
// GitHub App grant that credential is an installation token GitHub honours for
// an hour. A session that outlived it — any run still using git an hour after
// dispatch — presented a dead token, and every fetch and push it carried failed
// upstream with a 401 the sandbox could not explain.
//
// So a session minted with a refresher (MintRequest.Refresh) holds its
// credential in generations. Every upstream request takes the current
// generation and gives it back when the forge's response is finished. When a
// request finds CredentialRefreshWindow or less of the current credential's life
// left, it asks the refresher for a new one — one caller at a time; the rest
// wait for that answer — and from then on every request takes the new
// generation. The superseded one is retired, which for a GitHub App token means
// destroyed at GitHub, the moment the last request still holding it finishes.
//
// A refresh that fails for a reason that may pass leaves the held credential in
// use while it still works and tries again after credentialRefreshBackoff. One
// the issuer refuses for good (ErrCredentialRefused: the grant was revoked, the
// installation suspended, the repository removed) closes the session, which is
// what revocation does: the next request is refused at authentication.

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// CredentialRefreshWindow is how much of an upstream credential's life may
// remain before a session with a refresher renews it. It matches the broker's
// window (secretbroker.AppTokenRefreshWindow), which this package does not
// import.
const CredentialRefreshWindow = 10 * time.Minute

// credentialRefreshBackoff is how long a session waits after a refresh failed
// for a reason that may pass before it asks again.
const credentialRefreshBackoff = time.Minute

// credentialRefreshTimeout bounds one refresh. It runs detached from the
// request that started it, because the requests waiting on it outlive that
// request's own client, and it covers a mint at GitHub with room to spare.
const credentialRefreshTimeout = 45 * time.Second

// ErrCredentialRefused is what a RefreshFunc wraps when the upstream credential
// will not be renewed, now or later. The session is closed.
var ErrCredentialRefused = errors.New("gitproxy: upstream credential will not be renewed")

// errCredentialExpired is the request-time failure when the credential has
// already lapsed and could not be renewed (yet).
var errCredentialExpired = errors.New("gitproxy: upstream credential expired")

// Refreshed is a renewed upstream credential.
type Refreshed struct {
	// Credential is presented upstream from now on.
	Credential Credential
	// ExpiresAt is when the forge stops honouring it.
	ExpiresAt time.Time
	// Retire ends the credential this one superseded — destroys a GitHub App
	// token at GitHub. The session calls it once, after the last request
	// presenting the old credential has finished. Nil when there is nothing to
	// retire, which is also what a refresher returns when another caller had
	// already renewed the credential.
	Retire func()
}

// RefreshFunc renews a session's upstream credential. held is the password the
// session presents now. An error wrapping ErrCredentialRefused is final; any
// other is retried.
type RefreshFunc func(ctx context.Context, held string) (Refreshed, error)

// credentialGen is one generation of a session's upstream credential.
type credentialGen struct {
	cred      Credential
	expiresAt time.Time
	// users counts upstream requests presenting this generation right now.
	users int
	// superseded: a newer generation replaced this one. retire runs when
	// users reaches zero.
	superseded bool
	retire     func()
}

// refreshCall is one refresh in progress; the callers waiting on it read err
// once done is closed.
type refreshCall struct {
	done chan struct{}
	err  error
}

// CredentialExpiresAt reports when the forge stops honouring the credential
// the session presents now. Zero when it does not expire on a clock the hub
// knows.
func (s *Session) CredentialExpiresAt() time.Time {
	s.credMu.Lock()
	defer s.credMu.Unlock()
	return s.cred.expiresAt
}

// Refreshable reports whether the session renews its upstream credential.
func (s *Session) Refreshable() bool {
	s.credMu.Lock()
	defer s.credMu.Unlock()
	return s.refresh != nil
}

// upstreamPasswords returns the upstream password the session presents now,
// for scrubbing error text. Not for anything else.
func (s *Session) upstreamPasswords() []string {
	s.credMu.Lock()
	defer s.credMu.Unlock()
	return []string{s.cred.cred.Password}
}

// dueLocked reports whether the current credential should be renewed before
// the next request presents it. Callers hold credMu.
func (s *Session) dueLocked(now time.Time) bool {
	if s.refresh == nil || s.cred.expiresAt.IsZero() {
		return false
	}
	if s.cred.expiresAt.Sub(now) > CredentialRefreshWindow {
		return false
	}
	// Backing off after a failure that may pass. While the held credential
	// still works there is nothing to wait for; once it has lapsed, asking on
	// every request would turn a struggling issuer into a hammered one.
	return !now.Before(s.retryAt)
}

// credentialFor returns the credential to present for one upstream request,
// and the function to call once the forge's response to it is finished.
func (r *Registry) credentialFor(ctx context.Context, s *Session) (Credential, func(), error) {
	for {
		now := r.now()
		s.credMu.Lock()
		if !s.dueLocked(now) {
			gen := s.cred
			if !gen.expiresAt.IsZero() && !now.Before(gen.expiresAt) && s.refresh != nil {
				// Lapsed, and a renewal failed moments ago: refuse quickly with
				// the reason rather than present a credential the forge will
				// refuse with less of one.
				why := s.refreshErr
				retry := s.retryAt
				s.credMu.Unlock()
				return Credential{}, func() {}, fmt.Errorf("%w at %s and could not be renewed (%s); "+
					"retrying after %s", errCredentialExpired, gen.expiresAt.UTC().Format(time.RFC3339),
					why, retry.UTC().Format(time.RFC3339))
			}
			gen.users++
			s.credMu.Unlock()
			return gen.cred, s.releaser(gen), nil
		}
		call := s.refreshing
		leader := call == nil
		if leader {
			call = &refreshCall{done: make(chan struct{})}
			s.refreshing = call
		}
		held := s.cred.cred.Password
		s.credMu.Unlock()

		if leader {
			call.err = r.refreshSession(ctx, s, held)
			s.credMu.Lock()
			s.refreshing = nil
			s.credMu.Unlock()
			close(call.done)
		} else {
			select {
			case <-call.done:
			case <-ctx.Done():
				return Credential{}, func() {}, ctx.Err()
			}
		}
		if call.err != nil && errors.Is(call.err, ErrCredentialRefused) {
			return Credential{}, func() {}, call.err
		}
		// Renewed, or failed in a way the loop above now answers: with the
		// held credential while it works, or a prompt refusal once it does not.
	}
}

// refreshSession runs one refresh and installs its result. It returns an error
// only to tell the waiting callers the session was closed.
func (r *Registry) refreshSession(ctx context.Context, s *Session, held string) error {
	s.credMu.Lock()
	refresh := s.refresh
	s.credMu.Unlock()
	if refresh == nil {
		return nil
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), credentialRefreshTimeout)
	defer cancel()

	got, err := callRefresh(rctx, refresh, held)
	now := r.now()
	if err != nil {
		msg := scrubPasswords(err.Error(), held)
		if errors.Is(err, ErrCredentialRefused) {
			// The same end a revocation brings: the session goes, and with it
			// the upstream credential's last holder. Close reports it on the
			// session_closed row; every later request is refused at
			// authentication, exactly as for a released lease.
			r.Close(s.ID, "upstream credential will not be renewed: "+msg)
			return fmt.Errorf("%w: %s", ErrCredentialRefused, msg)
		}
		s.credMu.Lock()
		s.retryAt = now.Add(credentialRefreshBackoff)
		s.refreshErr = msg
		s.credMu.Unlock()
		return nil
	}

	s.credMu.Lock()
	unchanged := subtle.ConstantTimeCompare([]byte(got.Credential.Password), []byte(held)) == 1
	if got.Credential.Password == "" || unchanged {
		// Someone else renewed first, or the refresher declined to mint: keep
		// presenting what the session has, but stop asking until the
		// credential's own deadline says otherwise.
		if !got.ExpiresAt.IsZero() && unchanged {
			s.cred.expiresAt = got.ExpiresAt
		}
		if s.cred.expiresAt.Sub(now) <= CredentialRefreshWindow {
			s.retryAt = now.Add(credentialRefreshBackoff)
		}
		s.credMu.Unlock()
		return nil
	}
	old := s.cred
	next := &credentialGen{cred: got.Credential, expiresAt: got.ExpiresAt}
	if next.cred.Username == "" {
		next.cred.Username = old.cred.Username
	}
	if next.cred.GrantID == "" {
		next.cred.GrantID = old.cred.GrantID
	}
	if next.cred.LeaseID == "" {
		next.cred.LeaseID = old.cred.LeaseID
	}
	s.cred = next
	s.retryAt = time.Time{}
	s.refreshErr = ""
	if next.expiresAt.Sub(now) <= CredentialRefreshWindow {
		// Renewed into a credential already inside the window — a forge whose
		// tokens live less than the window. Without the backoff every request
		// would mint another.
		s.retryAt = now.Add(credentialRefreshBackoff)
	}
	old.superseded = true
	old.retire = got.Retire
	retire := takeRetire(old)
	s.credMu.Unlock()
	if retire != nil {
		runRetire(retire)
	}
	return nil
}

// callRefresh runs a refresher, turning a panic into an error so a broken
// issuer fails one request rather than the proxy.
func callRefresh(ctx context.Context, fn RefreshFunc, held string) (out Refreshed, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("gitproxy: credential refresher panicked: %v", p)
		}
	}()
	return fn(ctx, held)
}

// releaser returns the function a request calls when it no longer presents
// gen. Idempotent.
func (s *Session) releaser(gen *credentialGen) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			s.credMu.Lock()
			gen.users--
			retire := takeRetire(gen)
			s.credMu.Unlock()
			if retire != nil {
				runRetire(retire)
			}
		})
	}
}

// takeRetire returns gen's retire function once it is due — superseded and no
// longer presented — and clears it so it runs once. Callers hold credMu.
func takeRetire(gen *credentialGen) func() {
	if gen == nil || !gen.superseded || gen.users > 0 || gen.retire == nil {
		return nil
	}
	retire := gen.retire
	gen.retire = nil
	return retire
}

// runRetire retires a credential off the request path: destroying a GitHub App
// token is a round trip to GitHub, and the response it would delay is already
// on its way to the sandbox.
func runRetire(retire func()) {
	go func() {
		defer func() { _ = recover() }()
		retire()
	}()
}

// scrubPasswords removes any of passwords from msg. A refresher's error is
// built by the hub and names no credential, but it is about to be written to
// an audit row and a sandbox's terminal.
func scrubPasswords(msg string, passwords ...string) string {
	for _, pw := range passwords {
		if pw = strings.TrimSpace(pw); pw != "" {
			msg = strings.ReplaceAll(msg, pw, "[redacted]")
		}
	}
	return msg
}
