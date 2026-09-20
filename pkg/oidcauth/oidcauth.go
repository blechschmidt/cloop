// Package oidcauth implements a minimal OpenID Connect relying party for the
// cloop web dashboard: the authorization-code flow with PKCE for a
// confidential client, ID-token validation against the provider's JWKS, and
// in-memory cookie-backed sessions.
//
// The package is intentionally dependency-free (stdlib only). Only the parts
// of OIDC that cloop needs are implemented: provider discovery, the code
// flow, RS256/ES256 signature verification, and iss/aud/exp/nonce claim
// validation.
//
// # Session lifecycle
//
// A session ends for one of four reasons, and the hub can tell them apart:
//
//	the user signed out            session.revoked
//	an operator terminated it      session.revoked
//	a clock ran out                session.expired
//	the IdP refused to renew it    session.idp_revoked
//
// Two clocks run concurrently. The absolute ceiling is set at login and cannot
// be extended; the idle clock is refreshed by authenticated requests and is
// what bounds an unattended browser. Both are enforced on the read path — so a
// session is dead the moment either lapses, whether or not the janitor has got
// to the row yet — and swept off it, so the table does not accumulate corpses.
//
// The fourth reason is the one that needs a mechanism rather than a timer. If
// the identity provider disables a user, nothing about the cookie changes, so
// a hub that never asks again keeps honouring it until the ceiling lapses.
// Storing the refresh token (sealed, see SessionStore) and redeeming it on an
// interval turns "the IdP says no" into a session that ends in minutes rather
// than hours. That check runs in the background, never on the request path: an
// unreachable IdP must make the dashboard slow to *revoke*, not slow to serve.
//
// Sessions are held by a SessionStore. The default is process-local and dies
// with the hub; pkg/sessionstore persists them so a restart or a rolling
// upgrade does not sign everyone out.
package oidcauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// SessionCookieName is the browser cookie that carries the opaque
	// session ID established after a successful IdP callback.
	SessionCookieName = "cloop_session"

	// loginStateTTL bounds how long a login attempt (state + nonce + PKCE
	// verifier) stays valid between the redirect to the IdP and the
	// callback. Fifteen minutes is generous for a human completing an SSO
	// prompt while keeping abandoned attempts from accumulating.
	loginStateTTL = 15 * time.Minute

	// maxPendingLogins and maxSessions bound the two in-memory maps so a
	// client hammering /auth/login (or a burst of users) cannot grow
	// process memory without limit. Oldest entries are evicted first.
	maxPendingLogins = 5000
	maxSessions      = 10000

	// httpTimeout bounds every outbound call to the IdP (discovery, token
	// exchange, JWKS fetch).
	httpTimeout = 15 * time.Second

	// DefaultClockSkew is the leeway applied to exp/iat validation so a
	// modest clock drift between cloop and the IdP does not reject valid
	// tokens. Used when Config.ClockSkew is zero.
	DefaultClockSkew = 5 * time.Minute

	// MaxClockSkew is the largest leeway a deployment may configure.
	//
	// Ten minutes is already generous for hosts that both run NTP; past it
	// the setting stops compensating for drift and starts extending the life
	// of every expired token by the same amount, which is a different and
	// much worse trade than the one the knob exists to make. Exceeding it is
	// a startup error rather than a silent clamp: an operator who wrote an
	// hour believes they got an hour, and quietly giving them ten minutes
	// would leave them debugging the wrong thing.
	MaxClockSkew = 10 * time.Minute

	// jwksMinRefreshInterval throttles JWKS re-fetches on unknown key IDs
	// so a flood of forged tokens with bogus kids cannot make cloop hammer
	// the IdP.
	jwksMinRefreshInterval = time.Minute

	// maxIdPResponseBytes bounds how much of any IdP HTTP response body is
	// read (discovery document, token response, JWKS).
	maxIdPResponseBytes = 1 << 20 // 1 MiB

	// DefaultSessionTTL is used when Config.SessionTTL is zero.
	DefaultSessionTTL = 24 * time.Hour

	// maxSessionTTL caps configured session lifetimes.
	maxSessionTTL = 30 * 24 * time.Hour

	// DefaultIdleTimeout is used when Config.IdleTimeout is zero. Eight hours
	// is one working day: a browser left open over lunch stays signed in, one
	// left open overnight does not.
	DefaultIdleTimeout = 8 * time.Hour

	// DefaultRefreshInterval is used when Config.RefreshInterval is zero. It
	// is the worst-case delay between the IdP disabling a user and their cloop
	// session ending, so it is short — but not so short that a hub with a
	// thousand sessions turns into a load generator against the token
	// endpoint.
	DefaultRefreshInterval = 15 * time.Minute

	// sessionCacheTTL bounds how long a cached session is trusted without
	// re-reading the store.
	//
	// This is what makes revocation propagate. Within one process a
	// termination evicts the cache entry immediately, but a second hub replica
	// sharing the database has no such signal, so a cached entry must expire
	// on its own or "revoked" would mean "revoked on whichever replica handled
	// the DELETE". Thirty seconds bounds that window while still absorbing the
	// overwhelming majority of reads — a session used once a second costs two
	// database reads a minute rather than sixty.
	sessionCacheTTL = 30 * time.Second

	// lastSeenWriteInterval throttles idle-clock persistence.
	//
	// Without it, every authenticated read becomes a write on the state DB —
	// a dashboard with a WebSocket and a few polling panels would generate
	// more session writes than the whole rest of cloop combined. The cost of
	// throttling is that a crash can lose up to a minute of "was recently
	// used", which shortens the idle window by up to a minute. That is the
	// safe direction to be wrong in.
	lastSeenWriteInterval = time.Minute

	// janitorInterval is how often expired sessions are swept and IdP
	// revalidation is attempted.
	janitorInterval = time.Minute

	// refreshBatchSize bounds how many sessions one revalidation pass may
	// check, so a hub where everything comes due at once spreads its token
	// endpoint calls over several ticks instead of opening hundreds of
	// connections to the IdP in one burst.
	refreshBatchSize = 25
)

// Config holds the relying-party settings, typically mapped from
// config.OIDCConfig (ui.oidc.* in .cloop/config.yaml).
type Config struct {
	Enabled  bool
	Issuer   string // e.g. https://auth.example.com/realms/main
	ClientID string

	// ClientSecret is optional. Empty means cloop registers as a public
	// client and presents no credential at the token endpoint, relying on
	// the PKCE S256 binding that every authorization request carries
	// regardless. That is the default the Terraform module provisions,
	// because a credential that must be rotated, distributed and revoked is
	// the most expensive part of running this and PKCE removes the need for
	// one. Set it to add client authentication on top.
	ClientSecret string

	RedirectURL  string   // e.g. https://cloop.example.com/auth/callback
	Scopes       []string // default: openid profile email
	AdminEmails  []string // users who see every project regardless of owner
	SessionTTL   time.Duration
	CookieSecure string // "auto" (default), "always", "never"

	// IdleTimeout ends a session that has gone unused for this long, even
	// though its absolute ceiling has not been reached. Zero uses
	// DefaultIdleTimeout; negative disables the idle clock entirely, which is
	// only appropriate on a single-operator loopback deployment.
	IdleTimeout time.Duration

	// RefreshInterval is how often a session is revalidated against the IdP
	// using its stored refresh token. Zero uses DefaultRefreshInterval;
	// negative disables the check, which also disables IdP-side revocation —
	// the two timeouts then become the only way a session ends.
	RefreshInterval time.Duration

	// MaxClaimAge bounds how stale a session's group and role claims may be at
	// the moment it exercises a permission above operator — granting a
	// credential, minting a token, rewriting role bindings (Task 20273). Past
	// it, EnsureFreshClaims re-asserts them against the IdP synchronously and
	// the operation is refused if the provider cannot be asked.
	//
	// Zero uses DefaultMaxClaimAge; negative disables the check, which is the
	// documented opt-out for a deployment that cannot retain refresh tokens.
	// Anything above MaxMaxClaimAge is rejected by New — past an hour this has
	// stopped being a freshness bound.
	//
	// It is deliberately independent of RefreshInterval. That knob sets a
	// background cadence and can be switched off entirely; this one is a
	// property the privileged path must hold whatever the background pass is
	// doing, so "never re-check" must not be expressible for it by accident.
	MaxClaimAge time.Duration

	// Store persists sessions. Nil installs a process-local store, which is
	// the pre-Task-20176 behaviour: a restart signs everyone out.
	Store SessionStore

	// Audit receives every session lifecycle event. Nil discards them.
	//
	// A callback rather than a direct write to the trail because this package
	// is stdlib-only by design and the trail lives in SQLite. pkg/ui supplies
	// the sink. Implementations must not block: they are called while a
	// request or the janitor is waiting.
	Audit func(SessionAudit)

	// ClockSkew is the leeway applied to an ID token's exp and iat claims.
	// Zero uses DefaultClockSkew; negative means no leeway at all (the
	// strictest setting, appropriate where both clocks are known-good).
	// Anything above MaxClockSkew is rejected by New.
	//
	// It is a knob rather than a constant because the deployments that need
	// it are the ones that cannot fix the underlying problem: an on-premise
	// IdP on a host whose NTP is blocked by the same firewall that makes it
	// on-premise. The bound is what keeps it from being used as a way to
	// accept tokens that expired ten minutes ago.
	ClockSkew time.Duration

	// Clock supplies the current time. Nil means time.Now. It exists so the
	// two expiry clocks can be tested without sleeping through them.
	Clock func() time.Time

	// SessionLimit reports how many concurrent sessions one identity may
	// hold. Zero (and a nil hook) means unlimited. Supplied by pkg/ui from
	// the per-identity quota policy; this package stays stdlib-only and
	// holds no opinion about where the number comes from (Task 20182).
	//
	// The cap is enforced by evicting the identity's least recently used
	// sessions, never by refusing the login. Refusing would leave the user
	// with no session at all — and the self-service remedy, POST
	// /api/session/logout-all, requires one, so a capped user could be
	// locked out of their own account with no way back in. Eviction keeps
	// the invariant the cap exists for (no identity holds more than N)
	// without that failure mode.
	SessionLimit func(identity string, groups, roles []string) int

	// EffectiveRole reports the role a set of claims resolves to, and its
	// rank on the role ladder (higher is more authority). It exists so a
	// revalidation that narrows somebody's authority can say *what* they
	// lost — "admin → viewer" rather than "claims changed".
	//
	// Supplied by pkg/ui from the pkg/authz resolver, for the same reason
	// SessionLimit is: this package stays stdlib-only and holds no opinion
	// about how claims become roles. Nil is fully supported — narrowing is
	// then reported by the claims that disappeared, which is the fact this
	// package can establish on its own.
	//
	// It is consulted only on the revalidation path, never per request, so
	// its cost is paid once per session per refresh interval.
	EffectiveRole func(identity string, groups, roles []string) (role string, rank int)
}

// Identity is the authenticated user extracted from a validated ID token.
type Identity struct {
	Sub   string `json:"sub"`
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`

	// Groups and Roles carry the group/role claims the IdP released,
	// flattened from whatever shape it used. They are the input to
	// pkg/authz role mappings; an IdP that releases neither leaves both
	// empty and every identity falls back to oidc.default_role.
	Groups []string `json:"groups,omitempty"`
	Roles  []string `json:"roles,omitempty"`
}

// OwnerKey returns the stable string used to record project ownership:
// the lowercased email when present, otherwise the issuer subject. A nil
// identity yields "" (no owner / shared).
func (id *Identity) OwnerKey() string {
	if id == nil {
		return ""
	}
	if id.Email != "" {
		return strings.ToLower(id.Email)
	}
	return "sub:" + id.Sub
}

// DisplayName returns the friendliest non-empty label for the user.
func (id *Identity) DisplayName() string {
	if id == nil {
		return ""
	}
	if id.Name != "" {
		return id.Name
	}
	if id.Email != "" {
		return id.Email
	}
	return id.Sub
}

type pendingLogin struct {
	nonce    string
	verifier string
	created  time.Time
}

// cachedSession is one entry of the read-through session cache.
//
// fetchedAt bounds how long the copy is trusted (see sessionCacheTTL);
// lastPersisted is the throttle for idle-clock writes. Both are held here
// rather than on SessionRecord because they describe this process's knowledge
// of the session, not the session.
type cachedSession struct {
	rec           SessionRecord
	fetchedAt     time.Time
	lastPersisted time.Time
}

// Authenticator is the OIDC relying party. The zero value is not usable;
// construct via New. A nil *Authenticator is valid and reports Enabled() ==
// false, so callers can hold one optional field without nil checks.
type Authenticator struct {
	cfg    Config
	client *http.Client

	discMu sync.Mutex
	disc   *discoveryDoc

	jwksMu      sync.Mutex
	jwksKeys    map[string]any // kid -> *rsa.PublicKey | *ecdsa.PublicKey
	jwksFetched time.Time

	store SessionStore

	// idpMu guards the readiness view: whether the issuer has ever resolved,
	// and the last failure if it has not.
	//
	// Its own mutex rather than discMu because /readyz reads this on every
	// probe and must never queue behind an in-flight round trip to an
	// unreachable IdP — a readiness probe that hangs is reported as a failed
	// probe, which would turn "the IdP is slow" into "the hub is down".
	idpMu    sync.Mutex
	idpReady bool
	idpErr   error

	// mu guards pending and cache. It is deliberately not held across a store
	// call: the store has its own synchronisation, and holding a process-wide
	// mutex across SQLite would serialise every authenticated request behind
	// the slowest one.
	mu      sync.Mutex
	pending map[string]*pendingLogin
	cache   map[string]*cachedSession

	// Whether IdP revalidations actually re-assert claims, counted so an
	// operator can answer "are my users' roles being re-checked?" with a
	// number instead of a belief. Guarded by mu. claimsUnverifiedSeen is the
	// one-shot guard on AuditSessionClaimsUnverified — see its doc for why
	// the event is per-process rather than per-session.
	claimsAsserted       uint64
	claimsUnverified     uint64
	claimsUnverifiedSeen bool

	// claimsRefused counts privileged operations denied because the session's
	// claims were stale and could not be refreshed (Task 20273). Guarded by mu.
	claimsRefused uint64

	// flights collapses concurrent synchronous revalidations of one session
	// into a single IdP round trip — see EnsureFreshClaims. Its own mutex
	// rather than mu because a flight is held for the duration of a network
	// call, and mu is taken on paths that must never queue behind one.
	flightMu sync.Mutex
	flights  map[string]*claimFlight
}

// RefreshClaimStats reports how many IdP revalidations since startup returned
// an id_token whose claims were re-applied, and how many returned none and so
// left the session's authority as captured at sign-in.
//
// A hub whose unverified count climbs while asserted stays at zero is one
// where deprivileging at the IdP will not reach live sessions before they
// expire, however short the refresh interval is set.
func (a *Authenticator) RefreshClaimStats() (asserted, unverified uint64) {
	if a == nil {
		return 0, 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.claimsAsserted, a.claimsUnverified
}

// New validates cfg and returns a ready Authenticator. It is an error to
// call New with Enabled=false — callers should simply not construct one.
// Validation is strict (fail closed): a dashboard that claims to require
// SSO must not silently start without it.
func New(cfg Config) (*Authenticator, error) {
	if !cfg.Enabled {
		return nil, errors.New("oidcauth: config has enabled=false")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("oidcauth: issuer is required")
	}
	iss, err := url.Parse(cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: invalid issuer URL: %w", err)
	}
	if iss.Scheme != "https" && !isLoopbackHost(iss.Hostname()) {
		return nil, fmt.Errorf("oidcauth: issuer %q must use https (plain http is only allowed for localhost development IdPs)", cfg.Issuer)
	}
	if cfg.ClientID == "" {
		return nil, errors.New("oidcauth: client_id is required")
	}
	// No client_secret check. An empty secret is a supported configuration,
	// not a missing one: cloop then acts as an RFC 6749 §2.1 *public* client
	// and authenticates at the token endpoint with nothing but its client_id,
	// which is what `token_endpoint_auth_method: none` means.
	//
	// That is only safe because PKCE is unconditional here — BeginLogin has
	// always sent code_challenge_method=S256 and exchangeCode has always sent
	// the verifier — so an intercepted authorization code is useless without
	// the verifier that never left this process. The secret was the belt; the
	// PKCE binding is the braces, and it is the braces that hold.
	//
	// It is deliberately not gated on the IdP advertising "none" in
	// token_endpoint_auth_methods_supported. Entra ID accepts exactly this
	// exchange for a public-client registration and still omits "none" from
	// that list (it also omits code_challenge_methods_supported while fully
	// supporting S256), so believing the metadata would refuse the very
	// deployment this is for. See deploy/terraform/azure-entra-id.
	if cfg.RedirectURL == "" {
		return nil, errors.New("oidcauth: redirect_url is required (e.g. https://cloop.example.com/auth/callback)")
	}
	red, err := url.Parse(cfg.RedirectURL)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: invalid redirect_url: %w", err)
	}
	// The path is not decoration: it is the route the hub has to answer on
	// when the browser comes back from the IdP. Registering the callback
	// somewhere the redirect never lands produces the worst failure this
	// package has — the IdP authenticates the user, redirects to a path that
	// falls through to the SPA shell, the shell finds no session and bounces
	// to /auth/login, and the operator watches an endless login loop with
	// nothing in the log. Constrain it to /auth/ so the one gate that lets
	// unauthenticated requests through (oidcGate) covers it by construction,
	// and so a stray redirect_url cannot shadow "/" or an /api route.
	if !isCallbackPath(red.Path) {
		return nil, fmt.Errorf("oidcauth: redirect_url path must be under /auth/ (got %q in %q) — "+
			"cloop serves the callback there and nowhere else", red.Path, cfg.RedirectURL)
	}
	switch cfg.CookieSecure {
	case "", "auto", "always", "never":
	default:
		return nil, fmt.Errorf("oidcauth: cookie_secure must be auto, always, or never (got %q)", cfg.CookieSecure)
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	} else if !containsFold(cfg.Scopes, "openid") {
		cfg.Scopes = append([]string{"openid"}, cfg.Scopes...)
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = DefaultSessionTTL
	}
	if cfg.SessionTTL > maxSessionTTL {
		cfg.SessionTTL = maxSessionTTL
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	// An idle window longer than the absolute ceiling can never fire, so it is
	// not a configuration this can honour. Clamping rather than erroring keeps
	// "I lowered session_ttl_hours" from refusing to start the hub.
	if cfg.IdleTimeout > cfg.SessionTTL {
		cfg.IdleTimeout = cfg.SessionTTL
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = DefaultRefreshInterval
	}
	switch {
	case cfg.MaxClaimAge == 0:
		cfg.MaxClaimAge = DefaultMaxClaimAge
	case cfg.MaxClaimAge < 0:
		// The explicit opt-out, normalised so ClaimsStale has one comparison.
		cfg.MaxClaimAge = -1
	case cfg.MaxClaimAge > MaxMaxClaimAge:
		return nil, fmt.Errorf("oidcauth: max_claim_age %s exceeds the maximum of %s — "+
			"past that it is a second session lifetime rather than a freshness bound; "+
			"set it negative to disable the check outright", cfg.MaxClaimAge, MaxMaxClaimAge)
	}
	switch {
	case cfg.ClockSkew == 0:
		cfg.ClockSkew = DefaultClockSkew
	case cfg.ClockSkew < 0:
		// The explicit "no leeway" opt-out. Normalised to zero so the
		// validation path has one shape to check and jwt.go one value to add.
		cfg.ClockSkew = 0
	case cfg.ClockSkew > MaxClockSkew:
		return nil, fmt.Errorf("oidcauth: clock_skew %s exceeds the maximum of %s — "+
			"past that the setting extends the life of every expired token rather than "+
			"compensating for drift", cfg.ClockSkew, MaxClockSkew)
	}
	store := cfg.Store
	if store == nil {
		store = NewMemorySessionStore(maxSessions)
	}
	return &Authenticator{
		cfg:      cfg,
		client:   &http.Client{Timeout: httpTimeout},
		jwksKeys: map[string]any{},
		pending:  map[string]*pendingLogin{},
		cache:    map[string]*cachedSession{},
		flights:  map[string]*claimFlight{},
		store:    store,
	}, nil
}

// now returns the authenticator's clock.
func (a *Authenticator) now() time.Time {
	if a != nil && a.cfg.Clock != nil {
		return a.cfg.Clock()
	}
	return time.Now()
}

// IdleTimeout returns the configured idle window (zero or less means the idle
// clock is off).
func (a *Authenticator) IdleTimeout() time.Duration {
	if a == nil {
		return 0
	}
	return a.cfg.IdleTimeout
}

// SessionTTL returns the absolute session ceiling.
func (a *Authenticator) SessionTTL() time.Duration {
	if a == nil {
		return 0
	}
	return a.cfg.SessionTTL
}

// audit emits one lifecycle event, filling in the timestamp. Never fatal: a
// wedged audit sink must not be able to prevent a sign-in or a revocation.
func (a *Authenticator) audit(ev SessionAudit) {
	if a == nil || a.cfg.Audit == nil {
		return
	}
	if ev.At.IsZero() {
		ev.At = a.now()
	}
	a.cfg.Audit(ev)
}

// Enabled reports whether OIDC authentication is active. Safe on nil.
func (a *Authenticator) Enabled() bool {
	return a != nil && a.cfg.Enabled
}

// Issuer returns the configured issuer URL ("" when disabled).
func (a *Authenticator) Issuer() string {
	if a == nil {
		return ""
	}
	return a.cfg.Issuer
}

// DefaultCallbackPath is where cloop serves the OIDC redirect when
// redirect_url does not say otherwise. It is only a default: the IdP decides
// this path, and on a registration somebody else already created it is
// routinely something else (Entra's SPA platform, for instance, is commonly
// registered as /auth/oidc).
const DefaultCallbackPath = "/auth/callback"

// CallbackPath is the path component of the configured redirect_url — the
// route the hub must serve for the authorization-code flow to complete.
// Safe on nil and on a disabled authenticator, both of which report the
// default so the route table has a stable shape either way.
func (a *Authenticator) CallbackPath() string {
	if a == nil || a.cfg.RedirectURL == "" {
		return DefaultCallbackPath
	}
	u, err := url.Parse(a.cfg.RedirectURL)
	if err != nil || !isCallbackPath(u.Path) {
		// Unreachable via New, which rejects both. Falling back rather than
		// panicking keeps a hand-built Authenticator in a test from taking
		// the whole route table down.
		return DefaultCallbackPath
	}
	return u.Path
}

// isCallbackPath reports whether p may serve as the OIDC redirect path. The
// rule is deliberately narrow: under /auth/, and with something after it.
func isCallbackPath(p string) bool {
	return strings.HasPrefix(p, "/auth/") && len(p) > len("/auth/")
}

// IsAdmin reports whether id's email is on the configured admin list.
// Admins see (and may manage) every project regardless of owner.
func (a *Authenticator) IsAdmin(id *Identity) bool {
	if a == nil || id == nil || id.Email == "" {
		return false
	}
	for _, e := range a.cfg.AdminEmails {
		if strings.EqualFold(strings.TrimSpace(e), id.Email) {
			return true
		}
	}
	return false
}

// LoginOutcome is the verdict of one sign-in attempt.
//
// It is returned rather than recorded internally because this package is
// stdlib-only by design and the hub's metric registry is not — the same split
// that makes Config.Audit a callback. The values are a closed set, which is
// what lets them be a metric label: see hubmetrics.OIDCLogins.
type LoginOutcome string

const (
	// LoginPending is the zero value: the attempt has not reached a verdict.
	// BeginLogin returns it on the redirect to the IdP, which is a sign-in
	// still in progress and must not be counted as a completed one.
	LoginPending LoginOutcome = ""

	// LoginSuccess is a session established.
	LoginSuccess LoginOutcome = "success"

	// LoginDiscoveryFailed means the issuer could not be resolved, so the
	// flow never started. This is the misconfiguration outcome.
	LoginDiscoveryFailed LoginOutcome = "discovery_failed"

	// LoginIdPError means the provider itself refused, redirecting back with
	// an error parameter — a disabled account, a consent denial.
	LoginIdPError LoginOutcome = "idp_error"

	// LoginInvalidRequest means the callback arrived without state or code.
	LoginInvalidRequest LoginOutcome = "invalid_request"

	// LoginInvalidState means the state is unknown, expired, or replayed.
	// A sustained rate of these against a hub with working logins is someone
	// replaying callbacks.
	LoginInvalidState LoginOutcome = "invalid_state"

	// LoginExchangeFailed means the token endpoint refused the code —
	// usually a wrong client secret or an unregistered redirect URI.
	LoginExchangeFailed LoginOutcome = "exchange_failed"

	// LoginTokenInvalid means the ID token failed validation: signature,
	// issuer, audience, nonce, or expiry.
	LoginTokenInvalid LoginOutcome = "token_invalid"

	// LoginSessionError means everything about the identity checked out and
	// the session could not be stored.
	LoginSessionError LoginOutcome = "session_error"

	// LoginStateError means the CSPRNG failed. It has never been observed;
	// it is enumerated so no branch of the flow is unaccounted for.
	LoginStateError LoginOutcome = "state_error"
)

// Recorded reports whether o is a verdict worth counting. A pending login is
// not an outcome.
func (o LoginOutcome) Recorded() bool { return o != LoginPending }

// BeginLogin starts the authorization-code flow: it records a one-shot
// state + nonce + PKCE verifier and redirects the browser to the IdP's
// authorization endpoint.
//
// It returns LoginPending on the redirect. Any other value means the response
// is already an error page and the attempt is over.
func (a *Authenticator) BeginLogin(w http.ResponseWriter, r *http.Request) LoginOutcome {
	disc, err := a.discover(r.Context())
	if err != nil {
		a.errorPage(w, http.StatusServiceUnavailable, "The identity provider is unreachable or misconfigured.", err)
		return LoginDiscoveryFailed
	}
	state, err1 := randToken()
	nonce, err2 := randToken()
	verifier, err3 := randToken()
	if err := errors.Join(err1, err2, err3); err != nil {
		a.errorPage(w, http.StatusInternalServerError, "Could not generate login state.", err)
		return LoginStateError
	}

	now := time.Now()
	a.mu.Lock()
	a.purgePendingLocked(now)
	a.pending[state] = &pendingLogin{nonce: nonce, verifier: verifier, created: now}
	a.mu.Unlock()

	challenge := sha256.Sum256([]byte(verifier))
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", a.cfg.ClientID)
	q.Set("redirect_uri", a.cfg.RedirectURL)
	q.Set("scope", strings.Join(a.cfg.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	q.Set("code_challenge_method", "S256")

	sep := "?"
	if strings.Contains(disc.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	http.Redirect(w, r, disc.AuthorizationEndpoint+sep+q.Encode(), http.StatusFound)
	return LoginPending
}

// HandleCallback completes the flow: validates state, exchanges the code,
// verifies the ID token, creates a session, and redirects to the dashboard.
// The returned outcome is always a verdict — this is where a sign-in ends.
func (a *Authenticator) HandleCallback(w http.ResponseWriter, r *http.Request) LoginOutcome {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		desc := strings.TrimSpace(e + " " + q.Get("error_description"))
		a.errorPage(w, http.StatusForbidden, "The identity provider rejected the sign-in: "+desc, nil)
		return LoginIdPError
	}
	state, code := q.Get("state"), q.Get("code")
	if state == "" || code == "" {
		a.errorPage(w, http.StatusBadRequest, "The callback is missing its state or code parameter.", nil)
		return LoginInvalidRequest
	}

	now := time.Now()
	a.mu.Lock()
	p := a.pending[state]
	delete(a.pending, state) // one-shot: a replayed state must not work twice
	a.mu.Unlock()
	if p == nil || now.Sub(p.created) > loginStateTTL {
		a.errorPage(w, http.StatusBadRequest, "This sign-in attempt has expired or was not initiated here. Please try again.", nil)
		return LoginInvalidState
	}

	ctx, cancel := context.WithTimeout(r.Context(), httpTimeout)
	defer cancel()
	tok, err := a.exchangeCode(ctx, code, p.verifier)
	if err != nil {
		a.errorPage(w, http.StatusBadGateway, "Exchanging the authorization code with the identity provider failed.", err)
		// A code exchange that could not even reach discovery is a
		// misconfigured issuer, not a rejected code, and must be reported
		// as the former or the operator debugs the wrong end.
		if isPreflightFailure(err) {
			return LoginDiscoveryFailed
		}
		return LoginExchangeFailed
	}
	id, err := a.verifyIDToken(ctx, tok.IDToken, p.nonce)
	if err != nil {
		a.errorPage(w, http.StatusForbidden, "The identity token failed validation.", err)
		if isPreflightFailure(err) {
			return LoginDiscoveryFailed
		}
		return LoginTokenInvalid
	}

	sid, err := a.createSession(*id, r, tok.RefreshToken, tok)
	if err != nil {
		a.errorPage(w, http.StatusInternalServerError, "Could not create a session.", err)
		return LoginSessionError
	}
	http.SetCookie(w, a.sessionCookie(r, sid, int(a.cfg.SessionTTL.Seconds())))
	a.completeLogin(w, r)
	return LoginSuccess
}

// isPreflightFailure reports whether err is the issuer failing to resolve,
// as opposed to the sign-in itself being refused.
func isPreflightFailure(err error) bool {
	var pe *PreflightError
	return errors.As(err, &pe)
}

// completeLogin sends the browser to the dashboard after a successful sign-in.
//
// A 302 would be the obvious thing, and it is wrong here. The navigation that
// arrives at /auth/callback was initiated by the identity provider, so the
// whole redirect chain — including a Location we emit — is cross-site as far
// as the browser is concerned. A SameSite=Strict cookie set on this response
// is therefore *not* sent on the immediately following request to "/", the
// dashboard sees an anonymous visitor, bounces back to /auth/login, and the
// user is in a redirect loop that only reproduces under Strict and only in
// some browsers.
//
// A client-initiated navigation has no such ambiguity: it originates from a
// page already on our own origin, so it is same-site and the cookie rides
// along. Hence the tiny landing page. The meta refresh covers script being
// blocked; the link covers both being blocked, in which case one click
// finishes the job instead of a dead end.
func (a *Authenticator) completeLogin(w http.ResponseWriter, r *http.Request) {
	if !a.cookieSecure(r) {
		// Lax cookie: the plain redirect works and is one round trip cheaper.
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, loginLandingHTML)
}

// loginLandingHTML is served once, immediately after sign-in. It is inline
// rather than a redirect for the reason documented on completeLogin.
const loginLandingHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="0; url=/">
<title>Signing in…</title>
<style>body{font:14px system-ui,sans-serif;margin:4rem auto;max-width:28rem;text-align:center;color:#333}</style>
</head><body>
<p>Signed in. Opening the dashboard…</p>
<p><a href="/">Continue</a></p>
<script>location.replace("/");</script>
</body></html>
`

// purgePendingLocked drops expired login attempts and, if the map is still
// at capacity, evicts oldest-first. Caller holds a.mu.
func (a *Authenticator) purgePendingLocked(now time.Time) {
	for st, p := range a.pending {
		if now.Sub(p.created) > loginStateTTL {
			delete(a.pending, st)
		}
	}
	for len(a.pending) >= maxPendingLogins {
		var oldest string
		var oldestAt time.Time
		for st, p := range a.pending {
			if oldest == "" || p.created.Before(oldestAt) {
				oldest, oldestAt = st, p.created
			}
		}
		if oldest == "" {
			return
		}
		delete(a.pending, oldest)
	}
}

// sessionCookie builds the session cookie with the Secure flag resolved
// per config ("auto" inspects the request: direct TLS or an https
// X-Forwarded-Proto from a reverse proxy).
//
// SameSite follows Secure: Strict when the connection is TLS, Lax otherwise.
// Strict withholds the cookie from every cross-site request including
// top-level navigations, so a link planted elsewhere cannot carry the
// operator's session into a state-changing request — CSRF against the
// dashboard stops being expressible rather than merely being defended against.
//
// Lax is retained on plaintext because that is the loopback development case,
// where Strict's one real cost (the navigation immediately after the IdP
// callback — see completeLogin) is friction with no attacker to justify it.
// Over TLS that cost is paid properly, by the landing page, not by weakening
// the cookie.
func (a *Authenticator) sessionCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	secure := a.cookieSecure(r)
	sameSite := http.SameSiteLaxMode
	if secure {
		sameSite = http.SameSiteStrictMode
	}
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: sameSite,
		Secure:   secure,
	}
}

// cookieSecure resolves the Secure flag from config and the request.
func (a *Authenticator) cookieSecure(r *http.Request) bool {
	switch a.cfg.CookieSecure {
	case "always":
		return true
	case "never":
		return false
	default: // "auto" / ""
		return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	}
}

// errorPage renders a small self-contained HTML error page with a retry
// link. err detail is included (escaped) because the dashboard's audience
// is the operator who must debug their own IdP config.
func (a *Authenticator) errorPage(w http.ResponseWriter, status int, msg string, err error) {
	detail := ""
	if err != nil {
		detail = "<p class=\"detail\">" + html.EscapeString(err.Error()) + "</p>"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><html><head><title>cloop — sign-in problem</title>
<style>body{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{max-width:520px;padding:32px;background:#161b22;border:1px solid #30363d;border-radius:12px}
h1{font-size:18px;margin:0 0 12px}p{margin:8px 0;line-height:1.5}.detail{color:#8b949e;font-size:13px;word-break:break-word}
a{color:#58a6ff}</style></head><body><div class="card"><h1>Sign-in problem</h1><p>%s</p>%s<p><a href="/auth/login">Try again</a></p></div></body></html>`,
		html.EscapeString(msg), detail)
}

// randToken returns 256 bits of CSPRNG entropy, base64url-encoded (43
// chars — also a valid PKCE code verifier).
func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oidcauth: rng: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func isLoopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

func containsFold(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// ── IdP HTTP: discovery + token exchange ────────────────────────────────────

type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`

	// UserinfoEndpoint is how a session's claims stay current on a provider
	// that returns no id_token from the refresh grant — which is most of them.
	// See userinfo.go.
	UserinfoEndpoint string `json:"userinfo_endpoint"`
}

// discover fetches (and caches) the issuer's well-known configuration.
// Only a successful fetch is cached, so a transient IdP outage at first
// login retries on the next attempt — which is also what makes the lazy path
// the retry mechanism for a preflight that failed at startup.
func (a *Authenticator) discover(ctx context.Context) (*discoveryDoc, error) {
	a.discMu.Lock()
	defer a.discMu.Unlock()
	if a.disc != nil {
		return a.disc, nil
	}

	doc, err := fetchDiscovery(ctx, a.client, a.cfg.Issuer)
	if err != nil {
		a.noteIdPErr(err)
		return nil, err
	}
	a.disc = doc
	return a.disc, nil
}

// clockSkew is the configured leeway for exp/iat validation. Safe on a nil
// receiver so the jwt path needs no guard.
func (a *Authenticator) clockSkew() time.Duration {
	if a == nil {
		return DefaultClockSkew
	}
	return a.cfg.ClockSkew
}

// issuerEqual compares issuer URLs, tolerating a trailing-slash mismatch
// (a common config-vs-document difference).
func issuerEqual(a, b string) bool {
	return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
}

// idpStatusError is a non-200 answer from an IdP metadata endpoint.
//
// A type rather than a formatted string because the status is the single most
// useful thing an operator can be told about an unreachable issuer — a 404 is
// a wrong path, a 401 is an issuer behind authentication, a 503 is an outage
// that will clear on its own — and PreflightError surfaces it as its own
// field so nothing has to parse it back out of a sentence.
type idpStatusError struct {
	URL    string
	Status int
	Body   string
}

func (e *idpStatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("unexpected status %d", e.Status)
	}
	return fmt.Sprintf("unexpected status %d: %s", e.Status, e.Body)
}

// getJSON performs one bounded GET against an IdP metadata endpoint. It takes
// the client rather than hanging off the Authenticator so the standalone
// Preflight — which runs before any Authenticator exists — uses exactly this
// code, including the response-size bound.
func getJSON(ctx context.Context, client *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIdPResponseBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &idpStatusError{
			URL:    u,
			Status: resp.StatusCode,
			Body:   truncate(strings.TrimSpace(string(body)), 200),
		}
	}
	return body, nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`

	// RefreshToken is retained — sealed by the session store — solely so the
	// hub can ask the IdP "is this person still allowed in" on an interval.
	// It is never used to obtain an access token for calling anything, and it
	// is never returned to the browser: the cookie is the only credential the
	// client holds.
	RefreshToken string `json:"refresh_token"`
}

// exchangeCode redeems the authorization code at the token endpoint.
func (a *Authenticator) exchangeCode(ctx context.Context, code, verifier string) (*tokenResponse, error) {
	disc, err := a.discover(ctx)
	if err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", a.cfg.RedirectURL)
	// Unconditional, and on a public client it is the only thing standing
	// between an intercepted code and a session. See clientAuth.
	form.Set("code_verifier", verifier)

	tok, err := a.postTokenAuthenticated(ctx, disc.TokenEndpoint, form)
	if err != nil {
		return nil, err
	}
	if tok.IDToken == "" {
		return nil, errors.New("oidcauth: token response contained no id_token (is the openid scope configured on the client?)")
	}
	return tok, nil
}

// clientAuth is how cloop proves its own identity to the token endpoint.
type clientAuth int

const (
	// authBasic is client_secret_basic, the OIDC default.
	authBasic clientAuth = iota
	// authPost is client_secret_post, for IdPs that only accept form
	// credentials.
	authPost
	// authNone is a public client: client_id and nothing else. Not a
	// degraded authBasic — the secret is absent by configuration, and
	// sending an empty one would be a different request that IdPs reject
	// on its own terms rather than treating as unauthenticated.
	authNone
)

// postTokenAuthenticated performs a token-endpoint POST with whichever client
// authentication this hub is configured for, retrying once across the two
// secret-bearing methods.
//
// The retry exists because client_secret_basic and client_secret_post are both
// permitted and IdPs disagree about which they accept, so the first refusal
// that looks like a credential problem is worth one second attempt. A public
// client has no second method — there is no credential to re-encode — so it
// makes exactly one request and returns its error. Retrying a byte-identical
// request would only double the load on the IdP and halve the clarity of the
// error the operator eventually sees.
func (a *Authenticator) postTokenAuthenticated(ctx context.Context, endpoint string, form url.Values) (*tokenResponse, error) {
	if a.cfg.ClientSecret == "" {
		tok, _, err := a.postToken(ctx, endpoint, form, authNone, "")
		if err != nil && isSPACrossOriginRefusal(err) {
			// Entra ID refusing a browser-registered callback redeemed from
			// a server. See spaOriginRetry for why the header is the fix and
			// why it is only ever sent on the second attempt.
			tok, _, err = a.postToken(ctx, endpoint, form, authNone, a.redirectOrigin())
		}
		return tok, err
	}
	tok, status, err := a.postToken(ctx, endpoint, form, authBasic, "")
	if err != nil && (status == http.StatusUnauthorized || isOAuthCode(err, "invalid_client")) {
		// Retry once with credentials in the form body.
		tok, _, err = a.postToken(ctx, endpoint, form, authPost, "")
	}
	// Deliberately no SPA retry here. Entra rejects client credentials and an
	// Origin header in the same request, so a confidential client cannot take
	// this route — and a registration that needs it should not have a secret.
	return tok, err
}

// isSPACrossOriginRefusal reports whether err is Entra ID declining a
// server-side redemption of a callback registered as a single-page app — the
// one vendor-specific behaviour this package carries, because the alternative
// is a deployment that cannot sign anyone in and gives no hint why.
//
// Entra types each redirect URI by platform. A URI registered under
// "Single-page application" may only be redeemed cross-origin: the token
// request must carry an Origin header, and Entra answers AADSTS9002327 —
// "Tokens issued for the 'Single-Page Application' client-type may only be
// redeemed via cross-origin requests" — when it does not. Go's http.Client
// never sends Origin, so cloop's redemption fails every time against such a
// registration, and the error that reaches the operator blames the
// authorization code rather than the platform the URI was filed under.
//
// Setting Origin to the redirect URI's own origin satisfies the check. It is
// only ever attempted after a refusal naming 9002327, never pre-emptively,
// because the inverse rule also exists: a Web or desktop registration
// redeemed *with* an Origin header is refused with AADSTS9002326. Sending it
// unconditionally would trade this failure for its mirror image, so the
// refusal itself is what selects the second attempt.
//
// Matching on a provider-specific code is what oauthError's own documentation
// warns against. The justification is that the AADSTS numbers are Microsoft's
// stable, documented identifiers for exactly this condition — unlike the prose
// beside them — and that a false positive costs one extra request rather than
// a wrong security decision.
func isSPACrossOriginRefusal(err error) bool {
	var oe *oauthError
	if !errors.As(err, &oe) {
		return false
	}
	return strings.Contains(oe.Description, "AADSTS9002327") || strings.Contains(oe.Body, "AADSTS9002327")
}

// redirectOrigin is the scheme://host[:port] of the configured redirect_url —
// the value Entra expects to see in the Origin header, since that is the
// origin the SPA redirect URI was registered under. Empty when the redirect
// URL cannot be parsed, which suppresses the retry rather than sending a
// header that means nothing.
func (a *Authenticator) redirectOrigin() string {
	u, err := url.Parse(a.cfg.RedirectURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// postToken performs one token-endpoint POST using the given client
// authentication method (RFC 6749 §2.3.1: for Basic, credentials are
// form-urlencoded before the header).
//
// origin, when non-empty, is sent as the Origin header. Only the SPA retry
// sets it — see isSPACrossOriginRefusal.
func (a *Authenticator) postToken(ctx context.Context, endpoint string, form url.Values, auth clientAuth, origin string) (*tokenResponse, int, error) {
	f := url.Values{}
	for k, v := range form {
		f[k] = v
	}
	// Sent under every method. RFC 6749 makes it optional alongside Basic,
	// but it is what lets an IdP identify the client before it has decided
	// how to authenticate it, and it is required outright for authNone.
	f.Set("client_id", a.cfg.ClientID)
	if auth == authPost {
		f.Set("client_secret", a.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(f.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if auth == authBasic {
		req.SetBasicAuth(url.QueryEscape(a.cfg.ClientID), url.QueryEscape(a.cfg.ClientSecret))
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("oidcauth: token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIdPResponseBytes))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("oidcauth: token endpoint read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, newOAuthError(resp.StatusCode, body)
	}
	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("oidcauth: token response parse: %w", err)
	}
	return &tok, resp.StatusCode, nil
}

// oauthError is a token-endpoint refusal, parsed into its RFC 6749 §5.2 parts.
//
// It is a type rather than a formatted string because one of these codes —
// invalid_grant — is the signal that a user's access has been withdrawn at the
// provider, and deciding to end someone's session by substring-matching an
// error message is exactly the kind of thing that silently stops working when
// a provider rewords its response.
type oauthError struct {
	Status      int
	Code        string
	Description string
	Body        string
}

func (e *oauthError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("oidcauth: token endpoint status %d: %s", e.Status, truncate(e.Body, 300))
	}
	msg := fmt.Sprintf("oidcauth: token endpoint status %d: %s", e.Status, e.Code)
	if e.Description != "" {
		msg += ": " + e.Description
	}
	return msg
}

// newOAuthError parses an error response body, falling back to the raw text
// when it is not the JSON the spec calls for.
func newOAuthError(status int, body []byte) *oauthError {
	e := &oauthError{Status: status, Body: string(body)}
	var parsed struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		e.Code = parsed.Error
		e.Description = truncate(parsed.Description, 200)
	}
	return e
}

// isOAuthCode reports whether err is a token-endpoint refusal carrying code.
func isOAuthCode(err error, code string) bool {
	var oe *oauthError
	return errors.As(err, &oe) && oe.Code == code
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
