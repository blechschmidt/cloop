// Package provision is what SCIM provisioning means to the hub (Task 20415):
// which hub identity a provisioned user is, what deactivating one severs,
// what reactivating one restores, what deleting one destroys, and what a
// provisioned group grants.
//
// pkg/scim speaks the protocol and decides nothing. This package decides, and
// leaves the HTTP surface — authentication, rate limiting, the routes — to
// pkg/ui, and storage to pkg/statedb.
//
// # The gap it closes
//
// "Disabling an account at the identity provider does not, on its own, sever
// anything this hub has already issued" was a sentence in the runbook, and
// true: sessions ran to their absolute TTL, API tokens to their ExpiresAt,
// glasses links for up to 30 days, and leases, running tasks and stored
// credentials until an administrator ran `cloop hub user offboard`. With an
// identity provider provisioning the hub over SCIM, the provider's own
// deactivation is the trigger:
//
//   - active:false suspends the identity. In one transaction the hub writes a
//     deny binding for every identifier it resolved, deletes the sessions,
//     revokes the API tokens and glasses links, and suspends the grants over
//     the person's personal secrets; then it releases their leases and stops
//     their running tasks. Memberships and stored credentials are kept.
//   - active:true lifts the suspension: the deny bindings it wrote and the
//     grants it suspended, and nothing else. What it destroyed stays
//     destroyed.
//   - DELETE, or ui.oidc.scim.offboard_after_days of inactivity, runs the full
//     offboarding (pkg/offboard) — under a legal hold when one is placed.
//   - A provisioned group is a claim source a role binding can name
//     (claim: scim_group), read at every authorization decision.
//
// # Who a provisioned user is
//
// ui.oidc.scim.match_claim says which claim of a signed-in identity a
// provisioned user is matched against: email (the default), preferred_username,
// oid or sub. A match that addresses more than one hub identity is never
// resolved by guessing — see targetFor.
package provision

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// MatchClaim is the claim a provisioned user is matched against.
type MatchClaim string

const (
	// MatchEmail matches the user's primary email against the email claim
	// (or an address-shaped preferred_username, as sign-in reads one).
	MatchEmail MatchClaim = "email"
	// MatchUsername matches userName against preferred_username.
	MatchUsername MatchClaim = "preferred_username"
	// MatchOID matches externalId against Entra ID's oid claim — what
	// Entra provisions as externalId when objectId is mapped to it.
	MatchOID MatchClaim = "oid"
	// MatchSub matches externalId against the subject — what Okta provisions
	// as externalId.
	MatchSub MatchClaim = "sub"
)

// MatchClaims lists the valid match claims, the default first.
var MatchClaims = []MatchClaim{MatchEmail, MatchUsername, MatchOID, MatchSub}

// ParseMatchClaim reads a configured match claim. Empty is MatchEmail.
func ParseMatchClaim(s string) (MatchClaim, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "email":
		return MatchEmail, nil
	case "preferred_username", "username":
		return MatchUsername, nil
	case "oid":
		return MatchOID, nil
	case "sub":
		return MatchSub, nil
	}
	return "", fmt.Errorf("ui.oidc.scim.match_claim %q is not one of email, preferred_username, oid, sub", s)
}

// UserValue is the value a provisioned user is matched by under claim: what
// its identity must carry in the claim to be this user. "" means the user
// cannot be matched.
func UserValue(claim MatchClaim, row statedb.SCIMUserRow) string {
	switch claim {
	case MatchUsername:
		return strings.ToLower(strings.TrimSpace(row.UserName))
	case MatchOID:
		// An Entra object ID is a GUID. Entra's default attribute mapping
		// provisions mailNickname as externalId, which no oid claim can ever
		// equal: such a user is unmatchable, and reported as such, rather than
		// matched — and denied — by a value nothing carries.
		v := strings.ToLower(strings.TrimSpace(row.ExternalID))
		if !isObjectID(v) {
			return ""
		}
		return v
	case MatchSub:
		return strings.TrimSpace(row.ExternalID)
	}
	return strings.ToLower(strings.TrimSpace(row.Email))
}

// isObjectID reports whether s is a GUID in its 8-4-4-4-12 form.
func isObjectID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
				return false
			}
		}
	}
	return true
}

// SubjectValue is the value a signed-in subject is matched by under claim.
func SubjectValue(claim MatchClaim, s *authz.Subject) string {
	if s == nil {
		return ""
	}
	switch claim {
	case MatchUsername:
		return strings.ToLower(strings.TrimSpace(s.Username))
	case MatchOID:
		return strings.ToLower(strings.TrimSpace(s.OID))
	case MatchSub:
		return strings.TrimSpace(s.Sub)
	}
	return strings.ToLower(strings.TrimSpace(s.Email))
}

// matchColumn is the scim_users column a match value is unique in.
func matchColumn(claim MatchClaim) string {
	switch claim {
	case MatchUsername:
		return "user_name_key"
	case MatchOID:
		return "external_id_key"
	case MatchSub:
		return "external_id"
	}
	return "email"
}

// Config is a hub's provisioning policy, ui.oidc.scim.
type Config struct {
	// MatchClaim says which claim a provisioned user is matched against.
	MatchClaim MatchClaim
	// OffboardAfter is how long a user stays suspended before the full
	// offboarding runs. Zero never runs it: only a DELETE does.
	OffboardAfter time.Duration
}

// Actor is the SCIM credential a request authenticated with.
type Actor struct {
	CredentialID string
	Name         string
}

// Label is how the audit trail names the actor: scim:<credential name>.
func (a Actor) Label() string {
	if strings.TrimSpace(a.Name) == "" {
		return "scim"
	}
	return "scim:" + a.Name
}

// ErrInvalid wraps a request the hub refuses for a reason of its own, not the
// protocol's: a credential name that is malformed or taken, a hold with no
// reason.
var ErrInvalid = errors.New("provision: invalid")

// ── rate limiting ───────────────────────────────────────────────────────────

// DefaultRatePerMinute is a SCIM credential's request budget when
// ui.oidc.scim.rate_limit_per_minute is unset: enough for an identity
// provider's initial cycle over a directory of thousands, which it paces on
// 429s anyway, and a ceiling on what a stolen credential can do in a minute.
const DefaultRatePerMinute = 600

// RateLimiter is a token bucket per credential.
type RateLimiter struct {
	perMinute int
	burst     float64
	now       func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter allows perMinute requests a minute per credential, in bursts
// of up to a sixth of that (at least ten). A non-positive perMinute is
// DefaultRatePerMinute.
func NewRateLimiter(perMinute int) *RateLimiter {
	if perMinute <= 0 {
		perMinute = DefaultRatePerMinute
	}
	burst := float64(perMinute) / 6
	if burst < 10 {
		burst = 10
	}
	return &RateLimiter{perMinute: perMinute, burst: burst, now: time.Now, buckets: map[string]*bucket{}}
}

// SetClock replaces the clock, for tests.
func (l *RateLimiter) SetClock(now func() time.Time) { l.now = now }

// PerMinute reports the configured rate.
func (l *RateLimiter) PerMinute() int { return l.perMinute }

// Allow takes one request from key's bucket. When the bucket is empty it
// reports false and how long until a request would be admitted.
func (l *RateLimiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) > 1024 {
			// Keys are credential ids, of which a hub has a handful; this
			// only bounds a pathological caller.
			l.buckets = map[string]*bucket{}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	rate := float64(l.perMinute) / 60
	b.tokens += now.Sub(b.last).Seconds() * rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / rate * float64(time.Second))
	return false, wait
}

// ── per-resource serialisation ──────────────────────────────────────────────

// keyedMutex serialises operations on one resource in this process. Across
// hub members the resource's version does it: a write that lost the race
// re-reads and retries.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*keyedLock
}

type keyedLock struct {
	mu   sync.Mutex
	refs int
}

func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = map[string]*keyedLock{}
	}
	l, ok := k.locks[key]
	if !ok {
		l = &keyedLock{}
		k.locks[key] = l
	}
	l.refs++
	k.mu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		k.mu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}
