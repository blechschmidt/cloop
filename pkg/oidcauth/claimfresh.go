package oidcauth

// Bounded authorization staleness (Task 20273).
//
// Everything else in this package moves a session's claims *eventually*: the
// janitor picks up sessions whose last IdP check is older than RefreshInterval
// and re-asserts them. That is the right shape for revocation — an unreachable
// IdP must make the dashboard slow to revoke, never slow to serve — and it is
// the wrong shape for the moment somebody exercises authority. Between the IdP
// removing an account from the admin group and the next background pass, this
// hub will still grant admin, for up to RefreshInterval (default 15 minutes)
// and forever if an operator set refresh_interval_minutes: -1.
//
// The window is only intolerable for a small set of operations. Reading a task
// list with claims that are fourteen minutes old is fine; granting a
// credential, minting an API token, or rewriting role bindings with claims
// that are fourteen minutes old is the thing an incident report is written
// about. So the enforcement is proportional:
//
//	read paths          background cadence, unchanged, no IdP contact
//	above operator      claims must be no older than MaxClaimAge, re-asserted
//	                    synchronously if they are, and denied if they cannot be
//
// # Why a timestamp rather than a flag
//
// A session records *when* its claims were asserted, not whether they are
// "fresh", because freshness is a question only the caller can ask: the
// threshold belongs to the policy, and the same session is fresh enough to
// list projects and too stale to grant a secret. Storing the verdict instead of
// the timestamp would bake one threshold into the row.
//
// # Two clocks again, for the same reason
//
// ClaimsAsOf is cloop's clock: how long ago the hub last heard. ClaimsExpireAt
// is the IdP's: the access token that authorised the last claim read carried an
// expires_in, which is the provider stating how long it is prepared to stand
// behind that authorisation. Before this file that value was parsed into
// tokenResponse.ExpiresIn and never read. Honouring it means a provider
// configured for short-lived tokens gets the stricter freshness it asked for
// without an operator having to mirror the setting in cloop's config — and a
// provider with hour-long tokens is still held to MaxClaimAge, because the
// bound is a minimum of the two, never a maximum.

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	// DefaultMaxClaimAge is used when Config.MaxClaimAge is zero.
	//
	// Five minutes, chosen against what it costs rather than what sounds
	// strict. The cost is one token-endpoint round trip per privileged
	// operation per five minutes per administrator — single-flighted, so a
	// dashboard that fires six admin calls when a panel opens pays for one.
	// The benefit is that the interval in "we removed them at the IdP and they
	// still had admin for N minutes" is five rather than fifteen, and is
	// bounded at all on a hub that disabled background revalidation.
	DefaultMaxClaimAge = 5 * time.Minute

	// MaxMaxClaimAge caps the configured bound. Past an hour the setting has
	// stopped being a freshness guarantee and become a second, longer session
	// TTL that happens to be checked on privileged calls — and an operator who
	// wrote a day meant to disable this, which is what -1 is for.
	MaxMaxClaimAge = time.Hour
)

// ErrClaimsUnverifiable means a session's claims are older than the policy
// allows and the identity provider could not be asked for current ones.
//
// It is deliberately not a session termination. The realistic causes are an
// IdP outage, a network partition, and a hub with no CLOOP_SECRET_KEY (which
// retains no refresh token to revalidate with) — none of which is evidence
// about the user, and all of which would sign out the entire fleet if they
// ended sessions. What it does do is refuse the privileged operation, so a hub
// that cannot establish current authority does not act on stale authority.
var ErrClaimsUnverifiable = errors.New("oidcauth: this session's claims are stale and the identity provider could not confirm them")

// ClaimFreshnessError carries the actionable half of ErrClaimsUnverifiable:
// what the hub tried, and what an operator can do about it.
//
// The message reaches an administrator in a 403 body at the moment their action
// was refused, which is the one moment they will read it. "Forbidden" there
// sends them to look at their role bindings, which are fine; naming the cause
// is the difference between a five-minute fix and an afternoon.
type ClaimFreshnessError struct {
	// Age is how stale the claims were, and Limit the configured bound.
	Age   time.Duration
	Limit time.Duration

	// Reason is the machine-readable cause, also used as the audit reason:
	// no_refresh_token, idp_unreachable, or claims_rejected.
	Reason string

	// Err is the underlying failure, if there was one. Nil for
	// no_refresh_token, where nothing was attempted because nothing could be.
	Err error
}

func (e *ClaimFreshnessError) Error() string {
	switch e.Reason {
	case reasonNoRefreshToken:
		return fmt.Sprintf("oidcauth: this session's group and role claims are %s old (limit %s) "+
			"and cannot be re-checked: no refresh token is retained for it. "+
			"Set CLOOP_SECRET_KEY so the hub can seal refresh tokens, or set "+
			"ui.oidc.max_claim_age_minutes: -1 to accept sign-in-time claims for privileged actions",
			roundDuration(e.Age), e.Limit)
	case reasonClaimsRejected:
		return fmt.Sprintf("oidcauth: the identity provider refused to confirm this session's "+
			"group and role claims, so they cannot be used for a privileged action. "+
			"Sign out and back in; if it persists, check that the client requests a scope "+
			"the userinfo endpoint accepts (underlying error: %v)", e.Err)
	default:
		return fmt.Sprintf("oidcauth: this session's group and role claims are %s old (limit %s) "+
			"and the identity provider could not be reached to refresh them: %v",
			roundDuration(e.Age), e.Limit, e.Err)
	}
}

func (e *ClaimFreshnessError) Unwrap() error { return ErrClaimsUnverifiable }

// The closed set of reasons a claim-freshness check can fail. They are audit
// values and metric labels, so they are constants rather than prose.
const (
	reasonNoRefreshToken = "no_refresh_token"
	reasonIdPUnreachable = "idp_unreachable"
	reasonClaimsRejected = "claims_rejected"
)

// roundDuration renders an age for a human reading a refusal. Sub-second
// precision in "your claims are 5m0.483291s old" is noise.
func roundDuration(d time.Duration) time.Duration {
	if d < time.Second {
		return d.Round(time.Millisecond)
	}
	return d.Round(time.Second)
}

// ── the record's view of its own freshness ──────────────────────────────────

// ClaimsAssertedAt reports when this session's groups and roles were last
// asserted by the identity provider.
//
// It falls back to IssuedAt when the field is unset, which is both true and
// what makes the upgrade survivable: a session created before this column
// existed had its claims asserted exactly once, by the id_token at sign-in, and
// reporting that as "never" would make every live session on a hub instantly
// unable to perform a privileged action the moment the binary rolls.
func (s SessionRecord) ClaimsAssertedAt() time.Time {
	if !s.ClaimsAsOf.IsZero() {
		return s.ClaimsAsOf
	}
	return s.IssuedAt
}

// ClaimAge is how long ago the IdP last vouched for this session's claims.
// Negative ages (a clock that moved backwards) are reported as zero.
func (s SessionRecord) ClaimAge(now time.Time) time.Duration {
	at := s.ClaimsAssertedAt()
	if at.IsZero() {
		return 0
	}
	if d := now.Sub(at); d > 0 {
		return d
	}
	return 0
}

// ClaimsStale reports whether the session's claims are too old to authorise an
// operation above operator, under a bound of maxAge.
//
// A non-positive maxAge disables the check entirely — the documented opt-out
// for a deployment that cannot retain refresh tokens and has accepted the
// consequence.
//
// Two independent deadlines, whichever comes first:
//
//   - maxAge after the claims were asserted. cloop's own bound.
//   - ClaimsExpireAt, the provider's. Set from the access token's expires_in
//     when claims were last read, and set to the instant of the refusal when
//     the provider repudiated them — which is what makes a rejected claim read
//     stale immediately and stay that way until a later read succeeds.
func (s SessionRecord) ClaimsStale(now time.Time, maxAge time.Duration) bool {
	if maxAge <= 0 {
		return false
	}
	if !s.ClaimsExpireAt.IsZero() && !now.Before(s.ClaimsExpireAt) {
		return true
	}
	at := s.ClaimsAssertedAt()
	if at.IsZero() {
		// No timestamp at all: a corrupt or hand-written row. Fail closed —
		// the whole point of this path is to refuse authority it cannot date.
		return true
	}
	return now.Sub(at) >= maxAge
}

// MaxClaimAge returns the configured freshness bound (non-positive means the
// check is off). Safe on a nil receiver.
func (a *Authenticator) MaxClaimAge() time.Duration {
	if a == nil {
		return 0
	}
	return a.cfg.MaxClaimAge
}

// ── synchronous revalidation ────────────────────────────────────────────────

// claimFlight is one in-progress synchronous revalidation, shared by every
// caller that asked for the same session while it was running.
type claimFlight struct {
	done chan struct{}
	rec  SessionRecord
	err  error
}

// EnsureFreshClaims returns the session with claims no older than the
// configured bound, re-asserting them against the identity provider if needed.
//
// It is the gate a permission above operator passes through, and it is
// deliberately the *only* place in this package that contacts the IdP on a
// request goroutine. Callers must not put it on a read path: see the package
// note on why an IdP outage may make the hub slow to revoke but never slow to
// serve.
//
// Three outcomes:
//
//   - claims are within the bound → the stored session, no IdP contact, no
//     lock held beyond a map read. This is the overwhelmingly common case and
//     the one the benchmark covers.
//   - claims are stale and the IdP answers → the session with its claims
//     replaced, which may be narrower than a moment ago. That narrowing is
//     what the caller must then re-evaluate its decision against.
//   - claims are stale and the IdP cannot vouch → an error wrapping
//     ErrClaimsUnverifiable. Never a termination; see that variable.
//
// A session the IdP has revoked is terminated here exactly as it would be by
// the background pass, and reported as ErrSessionNotFound: from the caller's
// side there is no longer a session to authorise anything.
//
// # Single flight
//
// Concurrent calls for one session share one round trip. That is not only an
// optimisation. A dashboard opening its admin panel fires several privileged
// requests at once; without collapsing them an administrator being demoted at
// that instant would race N revalidations, and the one that landed last would
// decide what the others had already been allowed to do. Sharing the flight
// means every one of those requests sees the same answer, and it is the newest
// one — a demotion cannot be outrun by sending more requests.
func (a *Authenticator) EnsureFreshClaims(ctx context.Context, sessionID string) (SessionRecord, error) {
	if a == nil || !a.Enabled() {
		return SessionRecord{}, errors.New("oidcauth: not configured")
	}
	maxAge := a.cfg.MaxClaimAge
	if maxAge <= 0 {
		// Check disabled. Still return the stored session so the caller has
		// one shape to handle.
		return a.storedSession(sessionID)
	}

	rec, err := a.storedSession(sessionID)
	if err != nil {
		return SessionRecord{}, err
	}
	if !rec.ClaimsStale(a.now(), maxAge) {
		return rec, nil
	}
	return a.refreshClaimsNow(ctx, sessionID, maxAge)
}

// storedSession reads a session straight from the store.
//
// Not through the read-through cache, on purpose: that cache exists to keep the
// authentication path off the database, and its entries are up to
// sessionCacheTTL stale — which is a perfectly good trade for "is this session
// alive" and exactly the wrong one for "what may this person do right now". The
// cost is one primary-key read per privileged request, paid by requests that
// are rare by construction.
func (a *Authenticator) storedSession(id string) (SessionRecord, error) {
	rec, err := a.store.Get(id)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return SessionRecord{}, ErrSessionNotFound
		}
		return SessionRecord{}, fmt.Errorf("oidcauth: read session: %w", err)
	}
	return rec, nil
}

// refreshClaimsNow performs (or joins) one synchronous revalidation.
func (a *Authenticator) refreshClaimsNow(ctx context.Context, sessionID string, maxAge time.Duration) (SessionRecord, error) {
	a.flightMu.Lock()
	if fl, ok := a.flights[sessionID]; ok {
		a.flightMu.Unlock()
		select {
		case <-fl.done:
			return fl.rec, fl.err
		case <-ctx.Done():
			// The joiner gave up; the leader carries on for everyone else.
			return SessionRecord{}, ctx.Err()
		}
	}
	fl := &claimFlight{done: make(chan struct{})}
	if a.flights == nil {
		a.flights = map[string]*claimFlight{}
	}
	a.flights[sessionID] = fl
	a.flightMu.Unlock()

	fl.rec, fl.err = a.revalidateForClaims(ctx, sessionID, maxAge)

	a.flightMu.Lock()
	delete(a.flights, sessionID)
	a.flightMu.Unlock()
	close(fl.done)
	return fl.rec, fl.err
}

// revalidateForClaims is the leader's half of the flight: one IdP round trip,
// then the store re-read that turns it into an answer.
func (a *Authenticator) revalidateForClaims(ctx context.Context, sessionID string, maxAge time.Duration) (SessionRecord, error) {
	rec, err := a.storedSession(sessionID)
	if err != nil {
		return SessionRecord{}, err
	}
	// Re-checked after claiming the flight: a leader that just finished may
	// have refreshed this very session while this call was queuing for the
	// mutex, and paying a second round trip for an answer already on disk is
	// the thing single-flighting exists to avoid.
	now := a.now()
	if !rec.ClaimsStale(now, maxAge) {
		return rec, nil
	}

	if rec.RefreshToken == "" {
		// Nothing to revalidate with. Either the deployment has no
		// CLOOP_SECRET_KEY, so no refresh token was ever sealed, or the
		// provider issued none. Both are hub-level degradations already
		// reported by the Active Sessions panel; here they become a refusal
		// with the remedy attached rather than a silent grant on old claims.
		a.noteClaimRefusal(rec, reasonNoRefreshToken, now)
		return SessionRecord{}, &ClaimFreshnessError{
			Age:    rec.ClaimAge(now),
			Limit:  maxAge,
			Reason: reasonNoRefreshToken,
		}
	}

	outcome := a.revalidate(ctx, rec)
	if outcome.terminated {
		// The IdP withdrew the grant. terminate() has already removed the row
		// and audited it; there is no session left to hold an opinion about.
		return SessionRecord{}, ErrSessionNotFound
	}

	fresh, err := a.storedSession(sessionID)
	if err != nil {
		return SessionRecord{}, err
	}
	now = a.now()

	// Success is "the provider just restated the claims", not "the timestamp is
	// now inside the bound". They look equivalent and are not: re-deriving
	// staleness here measures the claims against a deadline that the round trip
	// itself consumed part of, so a bound shorter than the latency to the IdP
	// could never be satisfied — every privileged request would make a call,
	// succeed, and then refuse on the answer it had just received. Config
	// clamps max_claim_age to a minute, which hides that rather than fixing it;
	// a provider deadline shorter than the round trip would expose it again.
	//
	// The claim clock advancing is the exact signal, because it is written on
	// one branch only: the one where the id_token or the userinfo response
	// actually replaced this session's groups and roles. A repudiation and a
	// renewal that learned nothing both leave it where it was, and both fall
	// through to the refusal below.
	if fresh.ClaimsAssertedAt().After(rec.ClaimsAssertedAt()) {
		return fresh, nil
	}
	if !fresh.ClaimsStale(now, maxAge) {
		// Somebody else's flight refreshed it while this one was in the air.
		return fresh, nil
	}

	// The grant is alive but the provider would not restate the claims — it
	// returned no id_token and its userinfo endpoint is absent, unreachable, or
	// refused the access token.
	reason := reasonIdPUnreachable
	if outcome.claimsRejected {
		reason = reasonClaimsRejected
	}
	a.noteClaimRefusal(fresh, reason, now)
	return SessionRecord{}, &ClaimFreshnessError{
		Age:    fresh.ClaimAge(now),
		Limit:  maxAge,
		Reason: reason,
		Err:    outcome.err,
	}
}

// noteClaimRefusal audits a privileged operation refused for stale claims, and
// counts it.
//
// Once per *check*, not once per process and not once per request. The contrast
// with AuditSessionClaimsUnverified is deliberate: that event describes the
// provider and would repeat identically forever, so it fires once. This one
// describes an attempt that was refused, which an operator needs per
// occurrence.
//
// "Per occurrence" means per flight, because a burst of privileged requests
// shares one round trip and therefore one verdict — the joiners receive the
// leader's error without re-auditing it. That is the right granularity rather
// than a compromise: a dashboard panel firing six admin calls is one refusal
// with six symptoms, and writing six identical rows is the audit amplification
// Task 20218 went to some trouble to remove.
//
// The counter behind ClaimsRefused is incremented on the same schedule, so the
// number in the Active Sessions panel and the rows in the trail agree.
func (a *Authenticator) noteClaimRefusal(rec SessionRecord, reason string, now time.Time) {
	a.mu.Lock()
	a.claimsRefused++
	a.mu.Unlock()
	a.audit(SessionAudit{
		Event:     AuditSessionClaimsStale,
		SessionID: rec.ID,
		Subject:   rec.Identity.Sub,
		Email:     rec.Identity.Email,
		Actor:     "system",
		Reason:    reason,
		IP:        rec.IP,
		UserAgent: rec.UserAgent,
		At:        now,
	})
}

// ClaimsRefused reports how many privileged operations this process has
// refused because the session's claims could not be brought within the bound.
//
// A hub where this climbs is not one under attack; it is one whose IdP cannot
// be re-asked, and its administrators are being locked out of exactly the
// operations they most need. It belongs next to RefreshClaimStats for the same
// reason: the honest answer to "is claim freshness working here" is a pair of
// numbers, not a boolean.
func (a *Authenticator) ClaimsRefused() uint64 {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.claimsRefused
}

// claimFlightsInProgress reports how many revalidations are running. Test-only
// observability for the single-flight property.
func (a *Authenticator) claimFlightsInProgress() int {
	a.flightMu.Lock()
	defer a.flightMu.Unlock()
	return len(a.flights)
}
