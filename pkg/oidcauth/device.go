package oidcauth

// The device authorization grant that signs a terminal in to a hub with single
// sign-on (Task 20412).
//
// A developer's terminal has no browser to complete an authorization-code flow
// in, and on an SSO hub every other credential is wrong for it: an API token
// takes token.admin to mint, and a long-lived token bypasses everything a
// session guarantees. So the terminal runs RFC 8628 against the hub:
//
//	POST /api/device/code        the terminal asks; it is told a user code
//	GET  /device                 a signed-in browser enters the code and sees
//	                             who is asking — IP, user agent, host name
//	POST /api/device/approve     the browser approves, and is sent through the
//	                             identity provider once more
//	POST /api/device/token       the terminal polls until it is approved,
//	                             denied, or the code expires
//
// What comes out is a session — a row in the session store with Kind
// SessionKindCLI — not a new kind of credential. It idles out and expires on
// clocks never longer than a browser's, re-checks its claims on the same rule,
// is listed and revoked like any session, and ends when its identity is
// offboarded, because every one of those already works on sessions.
//
// # The approval is a sign-in of its own
//
// Approving does not copy the browser session's claims or its refresh token.
// It sends the browser through the authorization endpoint again (silently, if
// the identity provider still has a session for the person; with prompt=login
// and max_age=0 when the browser session is older than
// Config.DeviceApprovalMaxAge), and the callback writes the CLI session from
// what that round trip returned: claims the provider asserted that instant,
// and a refresh grant of the session's own. A shared refresh token would end
// one of the two sessions the first time a provider that rotates them was
// asked about the other, and claims copied from the browser would be as old as
// the browser's sign-in. Re-asserting them is also the only way the background
// revalidation, IdP-side revocation and the freshness bound reach a terminal
// at all.
//
// # No credential is ever handed out
//
// The terminal generates its session credential itself and sends only its
// digest when it asks for a code (DeviceRequest.CredentialHash) — the way PKCE
// commits to a verifier before the authorization request. The approval writes
// the session under a digest of that digest (CLISessionID), and the token
// endpoint answers "approved" with no secret in the body. So there is nothing
// for a log, a proxy, a database backup or the device table to leak that could
// be replayed as the session, and nothing the hub has to keep between
// approving and being polled.
//
// The second digest is what keeps the commitment from being a way in. Anybody
// may ask for a code, committing to anything; were the session written under
// the commitment itself, somebody who knew a session's id — the audit trail,
// the Active Sessions panel and `cloop hub session list` all show it — could
// commit to that id once the session ended, approve the code as themselves,
// and the terminal still holding the ended session's credential would go on
// working, signed in as them. No id the hub ever shows can be committed to.
//
// # Phishing
//
// The known attack on this grant is a code somebody else started, sent to the
// victim to approve. Nothing in the protocol can tell the two apart, so the
// approval page has to: it says what approving does, shows where the request
// came from beside where the browser is, and says to approve only a code you
// started yourself. Approving is a sign-in at the provider, a code is approved
// or denied once and exchanged once, and it is dead after ten minutes.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/blechschmidt/cloop/pkg/auditaction"
)

const (
	// DeviceCodeLifetime is how long a code may wait for approval. RFC 8628
	// leaves it to the server; ten minutes is enough to switch to a browser and
	// sign in, and short enough that a phished code goes stale before most
	// victims open the message carrying it.
	DeviceCodeLifetime = 10 * time.Minute

	// DefaultDevicePollInterval is how often a terminal may poll.
	DefaultDevicePollInterval = 5 * time.Second

	// deviceSlowDownStep is what a slow_down adds to the interval, for this
	// and every later poll (RFC 8628 §3.5), and maxDevicePollInterval where
	// the growth stops.
	deviceSlowDownStep    = 5 * time.Second
	maxDevicePollInterval = time.Minute

	// deviceSweepGrace is how long an authorization's row outlives its expiry,
	// so a terminal that polls a moment late is told what happened rather than
	// "never heard of it". An approval still uncollected at the end of it has
	// its session ended: nobody took it.
	deviceSweepGrace = 10 * time.Minute

	// DefaultDeviceApprovalMaxAge is used when Config.DeviceApprovalMaxAge is
	// zero: a browser session signed in longer ago than this must sign in
	// again at the identity provider to approve a terminal. Two hours, which
	// is about the "sudo mode" window forges use for minting credentials: a
	// developer approving the code their own terminal just printed is rarely
	// asked, and a browser left signed in since yesterday always is.
	DefaultDeviceApprovalMaxAge = 2 * time.Hour

	// maxDevicesInFlight caps the codes issued hub-wide in one lifetime. The
	// hub's per-address limiter answers long before this; the cap is what
	// keeps a flood from many addresses from growing the table without limit.
	maxDevicesInFlight = 2000

	// UserCodeLength is how many letters a user code has, drawn from
	// userCodeAlphabet: 20^10 ≈ 2^43 codes, past the 40 bits the grant asks
	// for, and still short enough to read off one screen and type into
	// another. Shown as two groups of five.
	UserCodeLength = 10

	// userCodeAlphabet is RFC 8628 §6.1's: upper-case consonants only. No
	// vowels, so no code spells a word; no digits, so nothing is ambiguous
	// between 0/O, 1/I/L or 5/S; and case-insensitive, so it reads aloud.
	userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

	// maxClientLabelLen bounds the host name a terminal reports. It is shown
	// on the approval page and written to the audit trail.
	maxClientLabelLen = 128

	// DevicePath is the approval page. The hub serves it; this package names
	// it because the approval returns there.
	DevicePath = "/device"

	// DeviceGrantType is the grant_type the token endpoint takes (RFC 8628
	// §3.4).
	DeviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

	// CLICredentialPrefix begins every terminal session credential, so the
	// hub can tell one from an API token or the static token by its shape and
	// send it to the session store without trying the others.
	CLICredentialPrefix = "cloop_cli_"

	// cliCredentialRandomLen is the length of the random part: 32 bytes,
	// unpadded base64url — the same entropy as a session cookie.
	cliCredentialRandomLen = 43
)

// The errors the token endpoint answers with (RFC 8628 §3.5; invalid_grant
// from RFC 6749 §5.2 for a code it does not know or has already exchanged).
// They are wire values.
const (
	DeviceErrPending      = "authorization_pending"
	DeviceErrSlowDown     = "slow_down"
	DeviceErrExpired      = "expired_token"
	DeviceErrDenied       = "access_denied"
	DeviceErrInvalidGrant = "invalid_grant"
)

// DeviceTokenError is the token endpoint's answer to a poll that did not
// yield a session.
type DeviceTokenError struct {
	// Code is one of the DeviceErr* values.
	Code string
	// Description says it in words, for the terminal to print.
	Description string
	// Interval is the polling interval from now on; set with slow_down.
	Interval time.Duration
}

func (e *DeviceTokenError) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// Errors the approval side answers with.
var (
	// ErrDeviceLoginDisabled: this hub does not sign terminals in.
	ErrDeviceLoginDisabled = errors.New("oidcauth: terminal sign-in is not enabled on this hub")

	// ErrNeedsBrowserSession: approving, denying or even looking up a code
	// takes a signed-in browser session. A terminal session approving
	// another terminal would be a credential that copies itself, and an API
	// token approving one would be minting a session with no person behind it.
	ErrNeedsBrowserSession = errors.New("oidcauth: approving a terminal sign-in takes a browser signed in to this hub")

	// ErrDeviceExpired: the code is past its lifetime.
	ErrDeviceExpired = errors.New("oidcauth: this code has expired — start `cloop login` again")

	// ErrDeviceDecided: the code was already approved or denied.
	ErrDeviceDecided = errors.New("oidcauth: this code has already been used")

	// ErrDeviceRequestInvalid: the terminal's request is malformed.
	ErrDeviceRequestInvalid = errors.New("oidcauth: invalid device authorization request")

	// ErrDeviceBusy: the hub-wide cap on codes in flight is reached.
	ErrDeviceBusy = errors.New("oidcauth: too many terminal sign-ins are in progress on this hub — try again in a few minutes")
)

// ── kinds and credentials ───────────────────────────────────────────────────

// SessionKind is what a session authenticates (Task 20412).
type SessionKind string

const (
	// SessionKindBrowser authenticates by the session cookie.
	SessionKindBrowser SessionKind = "browser"
	// SessionKindCLI authenticates by `Authorization: Bearer cloop_cli_…`.
	SessionKindCLI SessionKind = "cli"
)

// IsCLI reports whether rec is a terminal session. A record with no kind is a
// browser session: it predates the column, when that was the only kind.
func (s SessionRecord) IsCLI() bool { return s.Kind == SessionKindCLI }

// KindName is rec's kind as a word, for listings and the audit trail.
func (s SessionRecord) KindName() string {
	if s.IsCLI() {
		return string(SessionKindCLI)
	}
	return string(SessionKindBrowser)
}

// NewCLICredential returns a fresh terminal session credential and the digest
// a terminal sends when it asks for a code. The credential never leaves the
// terminal except as its own bearer.
func NewCLICredential() (credential, digest string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	credential = CLICredentialPrefix + base64.RawURLEncoding.EncodeToString(b)
	return credential, HashSessionID(credential), nil
}

// cliSessionLabel separates a terminal session's id from every other digest
// the hub computes, a browser session's id among them.
const cliSessionLabel = "cloop cli session v1\x00"

// CLISessionID is the id of the session a terminal holds, from the digest of
// its credential that it committed to when it asked for a code. Not the
// commitment itself: see "No credential is ever handed out" above.
func CLISessionID(credentialHash string) string {
	sum := sha256.Sum256([]byte(cliSessionLabel + credentialHash))
	return hex.EncodeToString(sum[:])
}

// IsCLICredential reports whether s has the shape of a terminal session
// credential: the prefix and 32 bytes of unpadded base64url.
func IsCLICredential(s string) bool {
	rest, ok := strings.CutPrefix(s, CLICredentialPrefix)
	if !ok || len(rest) != cliCredentialRandomLen {
		return false
	}
	for _, c := range rest {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// PresentsCLICredential reports whether r carries a terminal credential in its
// Authorization header — live, ended or malformed. The auth gate asks it to
// answer an ended terminal session itself, rather than let the bearer fall
// through to the API-token and static-token checks it was never meant for.
func PresentsCLICredential(r *http.Request) bool {
	return strings.HasPrefix(bearer(r), CLICredentialPrefix)
}

// cliCredential returns the well-formed terminal credential r presents, if
// any. The header only, never the query string: a credential in a URL is
// written to every access log it passes.
func cliCredential(r *http.Request) (string, bool) {
	b := bearer(r)
	if !IsCLICredential(b) {
		return "", false
	}
	return b, true
}

func bearer(r *http.Request) string {
	if r == nil {
		return ""
	}
	auth := r.Header.Get("Authorization")
	if len(auth) < 7 || !strings.EqualFold(auth[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(auth[7:])
}

// validCredentialHash reports whether h is a digest HashSessionID could have
// produced: 64 lower-case hex digits.
func validCredentialHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	for _, c := range h {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ── codes ───────────────────────────────────────────────────────────────────

// newUserCode draws a user code uniformly from the alphabet.
func newUserCode() (string, error) {
	n := big.NewInt(int64(len(userCodeAlphabet)))
	var b strings.Builder
	for i := 0; i < UserCodeLength; i++ {
		v, err := rand.Int(rand.Reader, n)
		if err != nil {
			return "", err
		}
		b.WriteByte(userCodeAlphabet[v.Int64()])
	}
	return b.String(), nil
}

// NormalizeUserCode turns what a person typed into the canonical code, or ""
// when it cannot be one. Case, spaces and dashes are forgiven, as RFC 8628
// §6.1 asks; any other character is refused rather than dropped, so a pasted
// paragraph does not happen to normalise into somebody's code.
func NormalizeUserCode(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c == '-' || unicode.IsSpace(c):
			continue
		case c > unicode.MaxASCII:
			return ""
		}
		c = unicode.ToUpper(c)
		if !strings.ContainsRune(userCodeAlphabet, c) {
			return ""
		}
		b.WriteRune(c)
		if b.Len() > UserCodeLength {
			return ""
		}
	}
	if b.Len() != UserCodeLength {
		return ""
	}
	return b.String()
}

// FormatUserCode renders a canonical code the way people read it: two groups
// of five.
func FormatUserCode(code string) string {
	if len(code) != UserCodeLength {
		return code
	}
	return code[:5] + "-" + code[5:]
}

// The digests the store keeps instead of the codes. Domain-separated, so
// neither can be mistaken for the other or for a session id.
func deviceDigest(deviceCode string) string {
	sum := sha256.Sum256([]byte("cloop-device-code\x00" + deviceCode))
	return hex.EncodeToString(sum[:])
}

func userCodeDigest(code string) string {
	sum := sha256.Sum256([]byte("cloop-user-code\x00" + code))
	return hex.EncodeToString(sum[:])
}

// DeviceID is the public name of an authorization in the audit trail and the
// hub's log: a prefix of its device code's digest. Like a session id it names
// the row without yielding anything to present.
func DeviceID(deviceHash string) string {
	if len(deviceHash) > 16 {
		return deviceHash[:16]
	}
	return deviceHash
}

// cleanLabel bounds a client-supplied label and drops control characters, so
// what lands on the approval page and in the audit trail is one printable line.
func cleanLabel(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > max {
		s = s[:max]
		for len(s) > 0 && !utfBoundary(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// utfBoundary reports whether s does not end in the middle of a rune.
func utfBoundary(s string) bool {
	for i := len(s) - 1; i >= 0 && i >= len(s)-4; i-- {
		c := s[i]
		if c < 0x80 {
			return true
		}
		if c >= 0xC0 {
			// The lead byte of the last rune: complete when enough
			// continuation bytes follow it.
			need := 2
			switch {
			case c >= 0xF0:
				need = 4
			case c >= 0xE0:
				need = 3
			}
			return len(s)-i == need
		}
	}
	return false
}

// ── configuration ───────────────────────────────────────────────────────────

// DeviceLoginEnabled reports whether this hub signs terminals in. Safe on nil.
func (a *Authenticator) DeviceLoginEnabled() bool {
	return a.Enabled() && a.cfg.DeviceLogin
}

// CLISessionTTL is a terminal session's absolute lifetime.
func (a *Authenticator) CLISessionTTL() time.Duration {
	if a == nil {
		return 0
	}
	return a.cfg.CLISessionTTL
}

// CLIIdleTimeout is a terminal session's idle window (zero or less: off).
func (a *Authenticator) CLIIdleTimeout() time.Duration {
	if a == nil {
		return 0
	}
	return a.cfg.CLIIdleTimeout
}

// DeviceApprovalMaxAge is how old a browser session may be and still approve
// a terminal without signing in again (zero or less: never asked).
func (a *Authenticator) DeviceApprovalMaxAge() time.Duration {
	if a == nil {
		return 0
	}
	return a.cfg.DeviceApprovalMaxAge
}

// idleTimeoutFor is the idle window rec is held to: its kind's.
func (a *Authenticator) idleTimeoutFor(rec SessionRecord) time.Duration {
	if rec.IsCLI() {
		return a.cfg.CLIIdleTimeout
	}
	return a.cfg.IdleTimeout
}

// normalizeDeviceConfig fills in and clamps the terminal-session settings.
// A terminal session never outlives a browser one, on either clock: it is the
// credential that sits in a file, so it is the one that should go stale first.
func normalizeDeviceConfig(cfg *Config) {
	if cfg.CLISessionTTL <= 0 || cfg.CLISessionTTL > cfg.SessionTTL {
		cfg.CLISessionTTL = cfg.SessionTTL
	}
	switch {
	case cfg.IdleTimeout <= 0:
		// The browser's idle clock is off; a terminal's may still be on.
		if cfg.CLIIdleTimeout == 0 {
			cfg.CLIIdleTimeout = cfg.IdleTimeout
		}
	case cfg.CLIIdleTimeout <= 0 || cfg.CLIIdleTimeout > cfg.IdleTimeout:
		cfg.CLIIdleTimeout = cfg.IdleTimeout
	}
	if cfg.CLIIdleTimeout > cfg.CLISessionTTL {
		cfg.CLIIdleTimeout = cfg.CLISessionTTL
	}
	switch {
	case cfg.DeviceApprovalMaxAge == 0:
		cfg.DeviceApprovalMaxAge = DefaultDeviceApprovalMaxAge
	case cfg.DeviceApprovalMaxAge < 0:
		cfg.DeviceApprovalMaxAge = -1
	}
}

// ── issuing ─────────────────────────────────────────────────────────────────

// DeviceRequest is what a terminal sends when it asks for a code.
type DeviceRequest struct {
	// CredentialHash is HashSessionID of the credential the terminal generated
	// and will present once approved: 64 lower-case hex digits.
	CredentialHash string
	// Hostname is what the terminal calls the machine it runs on.
	Hostname string
	// IP and UserAgent are the request's, as the hub saw it.
	IP        string
	UserAgent string
}

// DeviceGrant is what the terminal is told: RFC 8628 §3.2's response, less the
// verification URIs, which the hub knows and this package does not.
type DeviceGrant struct {
	DeviceCode string
	// UserCode is formatted for reading: two groups of five.
	UserCode  string
	ExpiresIn time.Duration
	Interval  time.Duration
}

// BeginDeviceAuthorization issues a device code and a user code.
func (a *Authenticator) BeginDeviceAuthorization(req DeviceRequest) (DeviceGrant, error) {
	if !a.DeviceLoginEnabled() {
		return DeviceGrant{}, ErrDeviceLoginDisabled
	}
	req.CredentialHash = strings.TrimSpace(req.CredentialHash)
	if !validCredentialHash(req.CredentialHash) {
		return DeviceGrant{}, fmt.Errorf("%w: credential_hash must be the SHA-256 of the credential the terminal will present, as 64 lower-case hex digits", ErrDeviceRequestInvalid)
	}
	now := a.now()
	if n, err := a.devices.CountDevicesSince(now.Add(-DeviceCodeLifetime)); err == nil && n >= maxDevicesInFlight {
		return DeviceGrant{}, ErrDeviceBusy
	}
	deviceCode, err := randToken()
	if err != nil {
		return DeviceGrant{}, err
	}
	rec := DeviceRecord{
		DeviceHash:      deviceDigest(deviceCode),
		CredentialHash:  req.CredentialHash,
		Status:          DeviceStatusPending,
		ClientIP:        cleanLabel(req.IP, 64),
		ClientUserAgent: cleanLabel(req.UserAgent, 300),
		ClientHostname:  cleanLabel(req.Hostname, maxClientLabelLen),
		CreatedAt:       now,
		ExpiresAt:       now.Add(DeviceCodeLifetime),
		Interval:        DefaultDevicePollInterval,
	}
	// Draw until the code is not one a live request already holds. At 43 bits
	// and a ten-minute life a collision does not happen; the loop is what makes
	// "the newest row for this code" mean "the only live one".
	var userCode string
	for tries := 0; ; tries++ {
		if tries == 5 {
			return DeviceGrant{}, errors.New("oidcauth: could not draw an unused user code")
		}
		userCode, err = newUserCode()
		if err != nil {
			return DeviceGrant{}, err
		}
		prior, gerr := a.devices.GetDeviceByUserCode(userCodeDigest(userCode))
		if gerr != nil || prior.expired(now) {
			break
		}
	}
	rec.UserCodeHash = userCodeDigest(userCode)
	if err := a.devices.PutDevice(rec); err != nil {
		return DeviceGrant{}, fmt.Errorf("oidcauth: record device authorization: %w", err)
	}
	a.audit(SessionAudit{
		Event:     AuditDeviceCodeIssued,
		Actor:     "anonymous",
		IP:        rec.ClientIP,
		UserAgent: rec.ClientUserAgent,
		At:        now,
		Device:    deviceAuditDetail(rec, false),
	})
	return DeviceGrant{
		DeviceCode: deviceCode,
		UserCode:   FormatUserCode(userCode),
		ExpiresIn:  DeviceCodeLifetime,
		Interval:   DefaultDevicePollInterval,
	}, nil
}

// ── the approval page ───────────────────────────────────────────────────────

// DeviceView is what the approval page shows about a code.
type DeviceView struct {
	// UserCode is the code, formatted.
	UserCode string
	Status   DeviceStatus
	Expired  bool

	// Who is asking, as the hub saw them and as the terminal said. Empty
	// once somebody else decided the code: what another person's terminal
	// is called is none of the caller's business.
	ClientIP        string
	ClientUserAgent string
	ClientHostname  string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	// ExpiresIn is what is left of the code's life, on the authenticator's
	// clock; zero once it has run out.
	ExpiresIn time.Duration

	// DecidedByCaller reports that the person asking decided the code.
	DecidedByCaller bool
	DecidedAt       time.Time

	// Reauth reports that approving will ask the caller to sign in again at
	// the identity provider, and SignedInAt when their browser session did.
	Reauth     bool
	SignedInAt time.Time

	// Identity is who approving would sign the terminal in as — the caller.
	Identity Identity
}

// LookupDevice resolves a code for the approval page. It takes the same
// browser session approving does, and answers ErrDeviceNotFound for a code
// that does not exist.
func (a *Authenticator) LookupDevice(r *http.Request, userCode string) (DeviceView, error) {
	rec, browser, err := a.deviceForBrowser(r, userCode)
	if err != nil {
		return DeviceView{}, err
	}
	now := a.now()
	v := DeviceView{
		UserCode:   FormatUserCode(NormalizeUserCode(userCode)),
		Status:     rec.Status,
		Expired:    rec.Status == DeviceStatusPending && rec.expired(now),
		ExpiresAt:  rec.ExpiresAt,
		CreatedAt:  rec.CreatedAt,
		Reauth:     a.deviceReauth(browser, now),
		SignedInAt: browser.IssuedAt,
		Identity:   browser.Identity,
	}
	if left := rec.ExpiresAt.Sub(now); left > 0 {
		v.ExpiresIn = left
	}
	if rec.Status == DeviceStatusPending {
		v.ClientIP, v.ClientUserAgent, v.ClientHostname = rec.ClientIP, rec.ClientUserAgent, rec.ClientHostname
		return v, nil
	}
	if rec.Subject != "" && rec.Subject == browser.Identity.Sub {
		v.DecidedByCaller, v.DecidedAt = true, rec.DecidedAt
		v.ClientIP, v.ClientUserAgent, v.ClientHostname = rec.ClientIP, rec.ClientUserAgent, rec.ClientHostname
	}
	return v, nil
}

// deviceForBrowser resolves a code on behalf of a signed-in browser: the
// session the request carries by cookie — never a terminal's, never a token —
// and the authorization the code names.
func (a *Authenticator) deviceForBrowser(r *http.Request, userCode string) (DeviceRecord, SessionRecord, error) {
	if !a.DeviceLoginEnabled() {
		return DeviceRecord{}, SessionRecord{}, ErrDeviceLoginDisabled
	}
	// A request that carries a terminal credential is a terminal, whatever
	// cookie rode along with it.
	if PresentsCLICredential(r) {
		return DeviceRecord{}, SessionRecord{}, ErrNeedsBrowserSession
	}
	browser, ok := a.browserSession(r)
	if !ok {
		return DeviceRecord{}, SessionRecord{}, ErrNeedsBrowserSession
	}
	code := NormalizeUserCode(userCode)
	if code == "" {
		return DeviceRecord{}, browser, ErrDeviceNotFound
	}
	rec, err := a.devices.GetDeviceByUserCode(userCodeDigest(code))
	if err != nil {
		return DeviceRecord{}, browser, err
	}
	return rec, browser, nil
}

// deviceReauth reports whether a browser session is too old to approve a
// terminal without signing in again.
func (a *Authenticator) deviceReauth(browser SessionRecord, now time.Time) bool {
	limit := a.cfg.DeviceApprovalMaxAge
	if limit <= 0 {
		return false
	}
	return browser.IssuedAt.IsZero() || now.Sub(browser.IssuedAt) >= limit
}

// DeviceApproval is where the approval page sends the browser next.
type DeviceApproval struct {
	// RedirectURL is the identity provider's authorization endpoint. The
	// approval completes when the provider sends the browser back.
	RedirectURL string
	// Reauth reports that the provider was asked to have the person sign in
	// again (prompt=login, max_age=0).
	Reauth bool
}

// BeginDeviceApproval starts approving a code: it checks the code can still be
// approved by this browser session, and returns the authorization request
// that will complete it.
//
// The code is not marked approved here. It is marked when the identity
// provider has answered, on the callback, so a browser that is sent to the
// provider and never comes back leaves the code pending — to be approved again
// or to expire — rather than approved with nothing behind it.
func (a *Authenticator) BeginDeviceApproval(ctx context.Context, r *http.Request, userCode string) (DeviceApproval, error) {
	rec, browser, err := a.deviceForBrowser(r, userCode)
	if err != nil {
		return DeviceApproval{}, err
	}
	now := a.now()
	if rec.Status != DeviceStatusPending {
		return DeviceApproval{}, ErrDeviceDecided
	}
	if rec.expired(now) {
		return DeviceApproval{}, ErrDeviceExpired
	}
	reauth := a.deviceReauth(browser, now)
	returnTo := DevicePath + "?code=" + url.QueryEscape(FormatUserCode(NormalizeUserCode(userCode)))
	dest, err := a.deviceRoundTrip(ctx, rec.DeviceHash, browser.ID, browser.Identity, returnTo, reauth)
	if err != nil {
		return DeviceApproval{}, err
	}
	return DeviceApproval{RedirectURL: dest, Reauth: reauth}, nil
}

// deviceRoundTrip returns the authorization request an approval completes on:
// for the code, from the browser session approving it, as the person signed
// in to that session — and, when reauth, demanding they sign in again.
func (a *Authenticator) deviceRoundTrip(ctx context.Context, device, browserID string, who Identity, returnTo string, reauth bool) (string, error) {
	disc, err := a.discover(ctx)
	if err != nil {
		return "", err
	}
	p, state, err := a.newPendingLogin(pendingLogin{
		device:      device,
		reauth:      reauth,
		sessionHash: browserID,
		subject:     who.Sub,
		returnTo:    returnTo,
	})
	if err != nil {
		return "", err
	}
	extra := url.Values{}
	// The browser is signed in as somebody; the provider should answer for
	// them, not offer an account picker that could approve as someone else.
	extra.Set("login_hint", renewLoginHint(who))
	switch limit := a.cfg.DeviceApprovalMaxAge; {
	case reauth:
		// prompt=login makes the provider ask, max_age=0 makes it say when it
		// did (auth_time), which the callback checks: a provider that ignored
		// the prompt is caught rather than believed.
		extra.Set("prompt", "login")
		extra.Set("max_age", "0")
	case limit > 0:
		// A recent dashboard session says nothing about when the person last
		// authenticated: signing in to the dashboard can be silent, on a
		// provider session hours old. max_age has the provider ask again when
		// its own sign-in is older than an approval allows, and report
		// auth_time, which the callback checks for the providers that ignore it.
		extra.Set("max_age", strconv.FormatInt(int64(limit/time.Second), 10))
	}
	return a.authorizeURL(disc, state, p, extra), nil
}

// DenyDevice refuses a code on behalf of the signed-in browser.
func (a *Authenticator) DenyDevice(r *http.Request, userCode string) error {
	rec, browser, err := a.deviceForBrowser(r, userCode)
	if err != nil {
		return err
	}
	now := a.now()
	denied, err := a.devices.UpdateDevice(rec.DeviceHash, func(d *DeviceRecord) (bool, error) {
		if d.Status != DeviceStatusPending {
			return false, ErrDeviceDecided
		}
		if d.expired(now) {
			return false, ErrDeviceExpired
		}
		d.Status = DeviceStatusDenied
		d.Approver = browser.Identity.OwnerKey()
		d.ApproverSession = browser.ID
		d.Subject = browser.Identity.Sub
		d.DecidedAt = now
		d.Reason = "denied_at_approval_page"
		return true, nil
	})
	if err != nil {
		return err
	}
	a.audit(SessionAudit{
		Event:     AuditDeviceDenied,
		Subject:   browser.Identity.Sub,
		Email:     browser.Identity.Email,
		Actor:     browser.Identity.OwnerKey(),
		Reason:    denied.Reason,
		IP:        RequestIP(r),
		UserAgent: truncate(userAgent(r), 300),
		At:        now,
		Device:    deviceAuditDetail(denied, false),
	})
	return nil
}

// completeDeviceApproval finishes an approval when the identity provider sends
// the browser back: it checks what the provider said, writes the terminal's
// session, marks the code approved, and returns the browser to the approval
// page, which reads the outcome back from the hub.
func (a *Authenticator) completeDeviceApproval(w http.ResponseWriter, r *http.Request, p *pendingLogin, q url.Values) {
	if e := q.Get("error"); e != "" {
		a.devicePage(w, http.StatusForbidden, p,
			"The identity provider did not complete the sign-in ("+strings.TrimSpace(e+" "+q.Get("error_description"))+
				"). Nothing was approved: the code is still waiting, and you can approve it again.", nil)
		return
	}
	code := q.Get("code")
	if code == "" {
		a.devicePage(w, http.StatusBadRequest, p, "The identity provider returned neither an authorization code nor an error. Nothing was approved.", nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), httpTimeout)
	defer cancel()
	tok, err := a.exchangeCode(ctx, code, p.verifier)
	if err != nil {
		a.devicePage(w, http.StatusBadGateway, p, "Exchanging the authorization code with the identity provider failed. Nothing was approved.", err)
		return
	}
	id, err := a.verifyIDToken(ctx, tok.IDToken, p.nonce)
	if err != nil {
		a.devicePage(w, http.StatusForbidden, p, "The identity token failed validation. Nothing was approved.", err)
		return
	}
	// The terminal is signed in as the person who approved, and nobody else:
	// a browser signed into another account at the provider in the meantime
	// must not turn this approval into a session for that account.
	if id.Sub != p.subject {
		a.devicePage(w, http.StatusForbidden, p,
			"You signed in at the identity provider as a different account from the one signed in to this dashboard. "+
				"Nothing was approved. Sign in to the provider as yourself and approve the code again.", nil)
		return
	}
	// When the person last authenticated, as the provider reports it. A
	// provider that reports nothing (Entra ID, unless the auth_time optional
	// claim is configured) cannot be checked and is trusted to have honoured
	// what it was asked: the browser session's age, which decided reauth, is
	// all the hub has to go on.
	switch limit := a.cfg.DeviceApprovalMaxAge; {
	case id.AuthTime.IsZero():
	case p.reauth:
		// We asked for a fresh sign-in; the provider has to say it did one.
		if id.AuthTime.Before(p.created.Add(-a.clockSkew())) {
			a.devicePage(w, http.StatusForbidden, p,
				"Approving a terminal needs a fresh sign-in at the identity provider — and it did not ask you to sign "+
					"in again (its token reports no recent auth_time). Nothing was approved.", nil)
			return
		}
	case limit > 0 && time.Since(id.AuthTime) > limit+a.clockSkew():
		// The dashboard session is recent but the sign-in behind it is not:
		// it was silent, on a provider session older than an approval
		// allows, at a provider that ignored max_age. Once more, demanding a
		// fresh one.
		dest, err := a.deviceRoundTrip(ctx, p.device, p.sessionHash, *id, p.returnTo, true)
		if err != nil {
			a.devicePage(w, http.StatusBadGateway, p, "Asking the identity provider for a fresh sign-in failed. Nothing was approved.", err)
			return
		}
		http.Redirect(w, r, dest, http.StatusFound)
		return
	}
	// The browser session that pressed Approve must still be live. The
	// callback cannot read its cookie — the provider's redirect is a
	// cross-site navigation — so it asks about the session the approval
	// captured, without counting the question as activity.
	if _, state := a.CheckSession(p.sessionHash); state != SessionLive {
		a.devicePage(w, http.StatusForbidden, p, "Your dashboard session ended while you were approving. Sign in and approve the code again.", nil)
		return
	}
	if a.cfg.SessionGate != nil {
		if gerr := a.cfg.SessionGate(*id); gerr != nil {
			a.refuseDevice(p.device, *id, p.sessionHash, "identity_refused", r)
			a.devicePage(w, http.StatusForbidden, p, "This hub does not let your account start a terminal session: "+gerr.Error(), nil)
			return
		}
	}

	now := a.now()
	decidable := func(d DeviceRecord) error {
		if d.Status != DeviceStatusPending {
			return ErrDeviceDecided
		}
		if d.expired(now) {
			return ErrDeviceExpired
		}
		return nil
	}
	pending, err := a.devices.GetDevice(p.device)
	if err == nil {
		err = decidable(pending)
	}
	if err != nil {
		a.devicePage(w, http.StatusConflict, p, undecidableMessage(err), nil)
		return
	}
	// The session first, the approval after it: a poll that finds the code
	// approved finds the session there to collect, never an approval with
	// nothing behind it yet.
	sess, err := a.createCLISession(*id, pending, tok, now)
	if err != nil {
		a.refuseDevice(p.device, *id, p.sessionHash, "session_error", r)
		a.devicePage(w, http.StatusInternalServerError, p, "The terminal's session could not be created. Nothing was approved.", err)
		return
	}
	approved, err := a.devices.UpdateDevice(p.device, func(d *DeviceRecord) (bool, error) {
		if err := decidable(*d); err != nil {
			return false, err
		}
		d.Status = DeviceStatusApproved
		d.Approver = id.OwnerKey()
		d.ApproverSession = p.sessionHash
		d.Subject = id.Sub
		d.DecidedAt = now
		return true, nil
	})
	if err != nil {
		// Decided or expired in the moment since the read: the session is
		// for nobody now, and nobody was told it exists.
		a.discardSession(sess.ID)
		a.devicePage(w, http.StatusConflict, p, undecidableMessage(err), nil)
		return
	}
	a.audit(SessionAudit{
		Event:     AuditSessionCreated,
		SessionID: sess.ID,
		Subject:   id.Sub,
		Email:     id.Email,
		Actor:     id.OwnerKey(),
		IP:        sess.IP,
		UserAgent: sess.UserAgent,
		At:        now,
		Reason:    refreshReadyReason(tok.RefreshToken),
		Kind:      SessionKindCLI,
		Client:    sess.Client,
		Via:       "device_grant",
	})
	a.audit(SessionAudit{
		Event:     AuditDeviceApproved,
		SessionID: sess.ID,
		Subject:   id.Sub,
		Email:     id.Email,
		Actor:     id.OwnerKey(),
		IP:        RequestIP(r),
		UserAgent: truncate(userAgent(r), 300),
		At:        now,
		Kind:      SessionKindCLI,
		Client:    approved.ClientHostname,
		Device:    deviceAuditDetail(approved, p.reauth),
	})
	a.completeLanding(w, r, p.returnTo, "Approved. Returning to the approval page…")
}

// refuseDevice marks a code denied by the hub, on the approver's behalf, and
// audits it. Used when the approval cannot go ahead for a reason that will not
// change by trying again.
func (a *Authenticator) refuseDevice(deviceHash string, id Identity, approverSession, reason string, r *http.Request) {
	now := a.now()
	refused, err := a.devices.UpdateDevice(deviceHash, func(d *DeviceRecord) (bool, error) {
		if d.Status != DeviceStatusPending && d.Status != DeviceStatusApproved {
			return false, nil
		}
		d.Status = DeviceStatusDenied
		d.Approver = id.OwnerKey()
		d.ApproverSession = approverSession
		d.Subject = id.Sub
		d.DecidedAt = now
		d.Reason = reason
		return true, nil
	})
	if err != nil || refused.Status != DeviceStatusDenied || refused.Reason != reason {
		return
	}
	a.audit(SessionAudit{
		Event:     AuditDeviceDenied,
		Subject:   id.Sub,
		Email:     id.Email,
		Actor:     "hub",
		Reason:    reason,
		IP:        RequestIP(r),
		UserAgent: truncate(userAgent(r), 300),
		At:        now,
		Device:    deviceAuditDetail(refused, false),
	})
}

// undecidableMessage tells the person approving why a code they signed in
// for can no longer be approved.
func undecidableMessage(err error) string {
	switch {
	case errors.Is(err, ErrDeviceExpired):
		return "This code expired while you were signing in. Start `cloop login` again for a new one."
	case errors.Is(err, ErrDeviceDecided):
		return "This code was approved or denied while you were signing in."
	}
	return "This code can no longer be approved."
}

// createCLISession writes the terminal's session under the id its commitment
// names, from what the identity provider just asserted. It does not announce
// it: the approval does, once it is recorded.
func (a *Authenticator) createCLISession(id Identity, dev DeviceRecord, tok *tokenResponse, now time.Time) (SessionRecord, error) {
	// The quota counts a terminal session like any other: it is one.
	a.enforceSessionLimit(id, now)
	id.AuthTime = time.Time{}
	rec := SessionRecord{
		ID:        CLISessionID(dev.CredentialHash),
		Identity:  id,
		Kind:      SessionKindCLI,
		Client:    dev.ClientHostname,
		IP:        dev.ClientIP,
		UserAgent: dev.ClientUserAgent,
		IssuedAt:  now,
		LastSeen:  now,
		// From the approval, the moment the person authenticated — so a
		// terminal session ends no later than a browser session signed in
		// at the same instant would.
		ExpiresAt:    now.Add(a.cfg.CLISessionTTL),
		RefreshToken: tok.RefreshToken,
		// The id_token just verified is a current assertion of the claims;
		// see createSession for why the claim clock starts now.
		ClaimsAsOf:     now,
		ClaimsExpireAt: accessTokenExpiry(tok, now),
	}
	if err := a.store.Put(rec); err != nil {
		return SessionRecord{}, fmt.Errorf("oidcauth: persist terminal session: %w", err)
	}
	a.mu.Lock()
	a.cache[rec.ID] = &cachedSession{rec: withoutRefreshToken(rec), fetchedAt: now, lastPersisted: now}
	a.mu.Unlock()
	return rec, nil
}

// discardSession removes a terminal session written for an approval that
// could then not be recorded. Nobody was told it exists — not the terminal,
// not the audit trail — so it goes without an event.
func (a *Authenticator) discardSession(id string) {
	a.mu.Lock()
	delete(a.cache, id)
	a.mu.Unlock()
	_, _ = a.store.Delete(id)
	a.notifyInvalidated(id)
}

// devicePage answers the callback of an approval that did not complete, in
// the style of errorPage. The message is this package's own text, never a
// value from the request; err, if any, is escaped into the detail line, as
// errorPage does, for the operator debugging their identity provider.
func (a *Authenticator) devicePage(w http.ResponseWriter, status int, p *pendingLogin, msg string, err error) {
	back := DevicePath
	if p != nil && p.returnTo != "" {
		back = p.returnTo
	}
	detail := ""
	if err != nil {
		detail = "<p class=\"detail\">" + html.EscapeString(err.Error()) + "</p>"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>cloop — terminal sign-in not approved</title>
<style>body{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{max-width:520px;padding:32px;background:#161b22;border:1px solid #30363d;border-radius:12px}
h1{font-size:18px;margin:0 0 12px}p{margin:8px 0;line-height:1.5}.detail{color:#8b949e;font-size:13px;word-break:break-word}
a{color:#58a6ff}</style></head><body><div class="card"><h1>Terminal sign-in not approved</h1><p>`+
		html.EscapeString(msg)+`</p>`+detail+`<p><a href="`+html.EscapeString(back)+`">Back to the approval page</a></p></div></body></html>
`)
}

// ── the terminal's poll ─────────────────────────────────────────────────────

// DeviceSession is what the token endpoint tells a terminal whose code was
// approved. It carries no credential: the terminal has held its own since it
// asked for the code.
type DeviceSession struct {
	// SessionID is the session's public id — the digest the terminal
	// committed to — as the Active Sessions table lists it.
	SessionID string
	Identity  Identity
	ExpiresAt time.Time
	// ExpiresIn is what is left of the session's absolute lifetime, on the
	// authenticator's clock.
	ExpiresIn time.Duration
	// IdleTimeout is the idle window, zero when the clock is off.
	IdleTimeout time.Duration
	// Revalidated reports that the hub keeps a refresh grant for the session,
	// so the identity provider is asked about it again: a demotion or a
	// disabled account reaches it, and privileged actions can re-check their
	// claims. False on a hub with no CLOOP_SECRET_KEY, or a provider that
	// issues no refresh token.
	Revalidated bool
}

// ExchangeDeviceCode is one poll: it answers with the session once the code
// is approved, and otherwise with a *DeviceTokenError saying why not.
func (a *Authenticator) ExchangeDeviceCode(deviceCode string) (DeviceSession, error) {
	if !a.DeviceLoginEnabled() {
		return DeviceSession{}, ErrDeviceLoginDisabled
	}
	deviceCode = strings.TrimSpace(deviceCode)
	if deviceCode == "" {
		return DeviceSession{}, &DeviceTokenError{Code: DeviceErrInvalidGrant, Description: "device_code is required"}
	}
	unknown := &DeviceTokenError{Code: DeviceErrInvalidGrant,
		Description: "this hub does not know that code: it was never issued, or it expired and was removed"}
	digest := deviceDigest(deviceCode)
	cur, err := a.devices.GetDevice(digest)
	// A code the hub never issued is answered from a read: guessing at codes
	// must not cost anybody else the database's write lock.
	if errors.Is(err, ErrDeviceNotFound) {
		return DeviceSession{}, unknown
	}
	now := a.now()
	// Nor may polling one it did issue, past a point: once the interval is as
	// long as it gets, polling too fast changes nothing more, and is answered
	// from the read as well.
	if err == nil && cur.Status == DeviceStatusPending && !cur.expired(now) &&
		cur.Interval >= maxDevicePollInterval && now.Sub(cur.LastPolledAt) < cur.Interval {
		return DeviceSession{}, slowDown(cur.Interval)
	}
	var verdict *DeviceTokenError
	var sessionID string
	_, err = a.devices.UpdateDevice(digest, func(d *DeviceRecord) (bool, error) {
		switch d.Status {
		case DeviceStatusConsumed:
			verdict = &DeviceTokenError{Code: DeviceErrInvalidGrant,
				Description: "this code has already been exchanged: a code is single-use"}
			return false, nil
		case DeviceStatusDenied:
			verdict = &DeviceTokenError{Code: DeviceErrDenied, Description: deniedDescription(d.Reason)}
			return false, nil
		case DeviceStatusApproved:
			d.Status = DeviceStatusConsumed
			d.LastPolledAt = now
			// Collected, so the commitment is needed no more — and kept, it is
			// what a session could be planted under once this one ends.
			sessionID = CLISessionID(d.CredentialHash)
			d.CredentialHash = ""
			return true, nil
		}
		if d.expired(now) {
			verdict = &DeviceTokenError{Code: DeviceErrExpired,
				Description: "the code expired before it was approved — run `cloop login` again"}
			return false, nil
		}
		if d.Interval <= 0 {
			d.Interval = DefaultDevicePollInterval
		}
		if !d.LastPolledAt.IsZero() && now.Sub(d.LastPolledAt) < d.Interval {
			d.Interval += deviceSlowDownStep
			if d.Interval > maxDevicePollInterval {
				d.Interval = maxDevicePollInterval
			}
			verdict = slowDown(d.Interval)
		} else {
			verdict = &DeviceTokenError{Code: DeviceErrPending, Interval: d.Interval,
				Description: "waiting for the code to be approved in a browser"}
		}
		d.LastPolledAt = now
		return true, nil
	})
	if errors.Is(err, ErrDeviceNotFound) {
		return DeviceSession{}, unknown
	}
	if err != nil {
		return DeviceSession{}, err
	}
	if verdict != nil {
		return DeviceSession{}, verdict
	}
	// Collected. The session was written before the approval was recorded;
	// it is gone only if it ended since — signed out everywhere, revoked,
	// offboarded — which the terminal must be told rather than handed a
	// credential that will not work.
	sess, err := a.store.Get(sessionID)
	if err != nil {
		return DeviceSession{}, &DeviceTokenError{Code: DeviceErrDenied,
			Description: "the session approved for this code was ended before the terminal collected it"}
	}
	idle := a.idleTimeoutFor(sess)
	if idle < 0 {
		idle = 0
	}
	id := sess.Identity
	out := DeviceSession{
		SessionID:   sess.ID,
		Identity:    id,
		ExpiresAt:   sess.ExpiresAt,
		IdleTimeout: idle,
		Revalidated: sess.RefreshToken != "",
	}
	if left := sess.ExpiresAt.Sub(a.now()); left > 0 {
		out.ExpiresIn = left
	}
	return out, nil
}

// slowDown answers a poll that came sooner than interval allows.
func slowDown(interval time.Duration) *DeviceTokenError {
	return &DeviceTokenError{Code: DeviceErrSlowDown, Interval: interval,
		Description: fmt.Sprintf("polling too fast; wait %s between polls", interval)}
}

// deniedDescription says why a code was denied, for the terminal.
func deniedDescription(reason string) string {
	switch reason {
	case "denied_at_approval_page":
		return "the code was denied in the browser"
	case "identity_refused":
		return "this hub does not let the approving account start a terminal session"
	case "session_error":
		return "the hub could not create the session; try `cloop login` again"
	}
	return "the code was denied"
}

// ── janitor ─────────────────────────────────────────────────────────────────

// SweepDevices removes authorizations past their expiry and the grace after
// it, and ends the session behind any that was approved and never collected:
// a session nobody took is a credential with nobody to revoke it. A pending
// one is looked at too, for the session a hub that stopped between writing it
// and recording the approval left behind. Returns how many authorizations it
// removed.
func (a *Authenticator) SweepDevices() int {
	if !a.Enabled() || a.devices == nil {
		return 0
	}
	gone, err := a.devices.DeleteDevicesBefore(a.now().Add(-deviceSweepGrace))
	if err != nil {
		return 0
	}
	for _, d := range gone {
		uncollected := d.Status == DeviceStatusApproved || d.Status == DeviceStatusPending
		if uncollected && d.CredentialHash != "" {
			_, _ = a.RevokeSession(CLISessionID(d.CredentialHash), "system", ReasonDeviceUncollected)
		}
	}
	return len(gone)
}

// ReasonDeviceUncollected is the Reason a session.revoked event carries for a
// terminal session whose approval the terminal never collected.
const ReasonDeviceUncollected = "device_uncollected"

// ── audit ───────────────────────────────────────────────────────────────────

// The device authorization audit events (Task 20412). Wire values.
const (
	// AuditDeviceCodeIssued records a terminal asking for a code.
	AuditDeviceCodeIssued = auditaction.ActionDeviceCodeIssued
	// AuditDeviceApproved records a code approved, and the session it became.
	AuditDeviceApproved = auditaction.ActionDeviceApproved
	// AuditDeviceDenied records a code denied, by its person or by the hub.
	AuditDeviceDenied = auditaction.ActionDeviceDenied
)

// DeviceAuditDetail is what a device.* event says about the authorization.
// Nothing in it is a credential: ID is a prefix of the device code's digest.
type DeviceAuditDetail struct {
	ID              string
	ClientIP        string
	ClientUserAgent string
	ClientHostname  string
	ExpiresAt       time.Time
	// Reauth reports that approving it demanded a fresh sign-in at the
	// identity provider.
	Reauth bool
}

func deviceAuditDetail(d DeviceRecord, reauth bool) *DeviceAuditDetail {
	return &DeviceAuditDetail{
		ID:              DeviceID(d.DeviceHash),
		ClientIP:        d.ClientIP,
		ClientUserAgent: d.ClientUserAgent,
		ClientHostname:  d.ClientHostname,
		ExpiresAt:       d.ExpiresAt,
		Reauth:          reauth,
	}
}
