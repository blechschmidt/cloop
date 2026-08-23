// Package apitoken implements scoped, expiring, individually revocable API
// tokens for non-interactive access to the cloop hub (Task 20175).
//
// # Why this exists
//
// The hub previously had exactly two ways in. An OIDC browser session, which
// CI cannot hold; and one static bearer token (`--token`) that bypassed RBAC
// entirely and saw every project on the hub. There was no credential you could
// give a build job, a deploy script, or an edge device that was narrower than
// "everything", expired on its own, or could be taken away without rotating the
// secret every other caller also depended on.
//
// A personal access token (PAT) is that credential. It carries its own roles,
// optionally names the projects it may address, optionally expires, and can be
// revoked one at a time.
//
// # The token string
//
//	cloop_pat_<id>_<secret>
//
// `id` is the public half: 64 bits of randomness, stored in the clear, used as
// the primary key on the verification path so authenticating a request costs
// one indexed read rather than a scan-and-compare across every token the hub
// has ever issued. `secret` is 256 bits of randomness and is the only part that
// authenticates anything.
//
// The `cloop_pat_` prefix is deliberate and load-bearing in two directions: it
// lets the auth chain tell "this is a PAT" from "this is the static token"
// without a database read, and it is the anchor a secret scanner needs to
// recognise a leaked cloop credential in a repository or a CI log.
//
// # What is stored
//
// Only `<alg>$<salt-hex>$<digest-hex>` over the secret half, plus a display
// prefix. The plaintext is returned by Mint exactly once and is never written
// anywhere — not to the database, not to the audit trail, not to a log line.
// A stolen database file yields no usable credential.
//
// # Why HMAC-SHA256 and not argon2id
//
// Password KDFs exist to make guessing expensive when the input is guessable.
// The secret here is 256 bits from crypto/rand: there is no dictionary, no
// reuse across sites, and no human choosing it. Stretching adds nothing an
// attacker must overcome, while putting a deliberately-slow function on the
// authentication path of every API request — which is a self-inflicted denial
// of service, since an unauthenticated caller controls how often it runs.
//
// So the construction is HMAC-SHA256 keyed by a per-token salt: a proper PRF,
// constant-time to verify, and with a per-row key so one precomputed table
// cannot attack the whole column. The stored form is algorithm-tagged, so if a
// future token type ever does take low-entropy input, argon2id can be added
// alongside without a migration or a flag day.
//
// # What this package does not decide
//
// It does not know about HTTP, OIDC, or the route table. Verify answers "is
// this string a live token, and if so which one" — the caller turns that into
// an authz.Decision (see Token.Decision) and the route gates enforce it
// unchanged. Deny-by-default therefore applies to PATs for free: a token is
// not a bypass, it is an identity with a permission set.
package apitoken

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
)

// Prefix is the literal every minted token starts with. Exported so the auth
// chain can classify a credential without a database read, and so secret
// scanners have one constant to match.
const Prefix = "cloop_pat_"

const (
	// idBytes is the entropy in the public half. 64 bits makes collision
	// across a hub's lifetime negligible while keeping the printed token
	// short enough to paste into a CI variable.
	idBytes = 8

	// secretBytes is the entropy that actually authenticates. 256 bits, as
	// specified: brute force is not a threat model this has to reason about.
	secretBytes = 32

	// saltBytes keys the HMAC per token.
	saltBytes = 16

	// hashAlgHMACSHA256 tags the stored digest format. Stored rather than
	// assumed so a second algorithm can coexist with this one.
	hashAlgHMACSHA256 = "hmac-sha256"

	// MaxNameLen bounds the operator-supplied label. Long enough to describe
	// a purpose ("github-actions deploy — payments"), short enough that the
	// column cannot be used as storage.
	MaxNameLen = 200

	// MaxProjectScope bounds how many projects one token may name. A token
	// that needs more than this wants an unscoped token and an honest
	// conversation about it.
	MaxProjectScope = 64
)

// Errors returned by Verify. Callers on the authentication path must not
// distinguish these to the client: every one of them is answered with the same
// 401, so an unauthenticated caller cannot use the response to learn whether a
// token id exists, whether it is merely expired, or whether it was revoked.
// They are distinguished here so the *audit trail* can say which it was.
var (
	// ErrMalformed means the string is not shaped like a token at all.
	ErrMalformed = errors.New("apitoken: malformed token")

	// ErrNotFound means no token has that id.
	ErrNotFound = errors.New("apitoken: token not found")

	// ErrBadSecret means the id resolved but the secret did not match.
	ErrBadSecret = errors.New("apitoken: token secret does not match")

	// ErrExpired means the token passed its ExpiresAt.
	ErrExpired = errors.New("apitoken: token has expired")

	// ErrRevoked means the token was withdrawn by an operator.
	ErrRevoked = errors.New("apitoken: token has been revoked")

	// ErrNoRoles means the token carries no role this binary recognises.
	// Treated as a hard failure rather than an empty permission set so a
	// token written by a newer binary cannot silently degrade into a
	// credential that authenticates but authorizes nothing — which reads to
	// an operator as "the token is broken", not "the token is unsafe".
	ErrNoRoles = errors.New("apitoken: token carries no usable role")
)

// Kind labels what a token was issued for. The empty kind is an ordinary
// operator-minted PAT; named kinds mark tokens the hub issues on a user's
// behalf, which have their own lifecycle rules.
const (
	// KindGlasses is a per-user display-glasses link (Task 20194). One live
	// token per identity: minting rotates, so a link handed out yesterday
	// stops working the moment a new one is generated.
	KindGlasses = "glasses"
)

// Owner is the identity a token was minted on behalf of.
//
// It is the claim bundle as it stood at mint time, not a foreign key: cloop
// has no user directory to resolve one against, and an IdP subject that has
// not signed in recently exists nowhere else on the hub. Storing the claims
// lets the authorization path re-resolve the owner's *current* authority from
// the *current* policy on every request — so an operator who edits a role
// mapping changes what every delegated token can do, immediately, without
// having to find and revoke them.
//
// What it deliberately does not store: anything from the ID token beyond the
// claims pkg/authz already resolves against. No access token, no refresh
// token, nothing that would let a stolen database act as the user elsewhere.
type Owner struct {
	Sub    string   `json:"sub,omitempty"`
	Email  string   `json:"email,omitempty"`
	Name   string   `json:"name,omitempty"`
	Groups []string `json:"groups,omitempty"`
	Roles  []string `json:"roles,omitempty"`
}

// Key returns the stable per-user string, matching oidcauth.Identity.OwnerKey
// so a token's owner and a project's recorded owner compare directly. A nil
// owner yields "", which is "no owner" and never matches a recorded one.
func (o *Owner) Key() string {
	if o == nil {
		return ""
	}
	if o.Email != "" {
		return strings.ToLower(o.Email)
	}
	if o.Sub == "" {
		return ""
	}
	return "sub:" + o.Sub
}

// Label is the friendliest name for the owning user, for display and audit.
func (o *Owner) Label() string {
	if o == nil {
		return ""
	}
	switch {
	case o.Name != "":
		return o.Name
	case o.Email != "":
		return o.Email
	}
	return o.Sub
}

// Token is one API token as persisted. Hash is the derived secret; the
// plaintext exists only in the return value of Mint.
type Token struct {
	ID           string
	Name         string
	Hash         string
	Prefix       string
	Roles        []string
	ProjectScope []string
	CreatedBy    string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	LastUsedAt   time.Time
	RevokedAt    time.Time

	// Kind is "" for an ordinary PAT, or one of the Kind* constants.
	Kind string

	// Owner is set on a token minted on a user's behalf. When present, the
	// token's authority is the *intersection* of its own roles and whatever
	// the owner may currently do — see authz.Intersect and the ui package's
	// grant.decide. Roles alone are a ceiling, never a grant.
	Owner *Owner

	// OwnerUnreadable marks a row whose stored owner binding did not decode.
	// Only List sets it: the verification path refuses such a row outright
	// (see SQLStore.Get), but a listing has to keep showing it or an operator
	// would have no surface from which to revoke it. A token carrying this
	// flag must never be treated as unbound — "we cannot tell whose this is"
	// is not the same answer as "it belongs to nobody".
	OwnerUnreadable bool
}

// Revoked reports whether the token has been withdrawn.
func (t *Token) Revoked() bool { return t != nil && !t.RevokedAt.IsZero() }

// OwnerBinding returns the identity this token acts for, or nil. Nil-safe on
// the receiver so callers can chain it off a lookup that may have found no
// token at all — "no token" and "a token acting as nobody" are the same
// answer to every question the callers ask.
func (t *Token) OwnerBinding() *Owner {
	if t == nil {
		return nil
	}
	return t.Owner
}

// Expired reports whether the token is past its expiry at time now. A zero
// ExpiresAt means the token does not expire.
func (t *Token) Expired(now time.Time) bool {
	return t != nil && !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt)
}

// Active reports whether the token would be accepted at now.
func (t *Token) Active(now time.Time) bool {
	return t != nil && !t.Revoked() && !t.Expired(now)
}

// Label identifies the token in audit records. It never contains the secret:
// the prefix is the public half by construction.
func (t *Token) Label() string {
	if t == nil {
		return "anonymous"
	}
	if t.Name != "" {
		return "token:" + t.Name + " (" + t.Prefix + ")"
	}
	return "token:" + t.Prefix
}

// ParsedRoles returns the token's roles as validated authz.Role values,
// dropping any this binary does not recognise.
//
// Dropping rather than failing is the conservative direction: an unknown role
// name can only ever have granted permissions this binary cannot enumerate, so
// ignoring it can shrink the permission set but never grow it. Verify turns a
// token left with nothing into ErrNoRoles.
func (t *Token) ParsedRoles() []authz.Role {
	if t == nil {
		return nil
	}
	out := make([]authz.Role, 0, len(t.Roles))
	for _, name := range t.Roles {
		if role, ok := authz.ParseRole(name); ok && role != authz.RoleNone {
			out = append(out, role)
		}
	}
	return out
}

// Decision resolves the token's authority over scope.
//
// Two rules, in order:
//
//  1. If the token names a project scope and the request is about a project
//     outside it, the answer is a full deny — not a reduced role. The caller's
//     404/403 split then reports the project as nonexistent, which is the
//     correct answer to give a credential that has no business knowing it is
//     there.
//
//  2. Otherwise the token's roles apply as an ordinary permission set.
//
// Note what rule 1 does *not* do: it does not narrow global-scope actions. A
// project scope limits which projects a token can reach; it is not a second
// axis of privilege. What a token may do anywhere is decided by its roles, and
// the mint path is what keeps those from exceeding the minter's own.
func (t *Token) Decision(scope authz.Scope, now time.Time) authz.Decision {
	if t == nil || !t.Active(now) {
		return authz.Deny(authz.SourceAPIToken, t.Label(), scope)
	}
	if !t.AllowsProject(scope.Project, scope.ProjectPath) {
		return authz.Deny(authz.SourceAPIToken, t.Label(), scope)
	}
	roles := t.ParsedRoles()
	if len(roles) == 0 {
		return authz.Deny(authz.SourceAPIToken, t.Label(), scope)
	}
	return authz.FromRoles(roles, authz.SourceAPIToken, t.Label(), scope)
}

// AllowsProject reports whether the token may address a project identified by
// its registry name and/or filesystem path.
//
// An empty ProjectScope means every project the roles allow. A non-empty scope
// matches either identifier, case-insensitively, mirroring how authz.Binding
// resolves a project so an operator writes the same thing in both places.
//
// A scoped token asked about *no* project at all (both arguments empty, i.e.
// the global scope) is allowed through: that is a fleet-wide action, which
// rule 1 above deliberately does not govern.
func (t *Token) AllowsProject(name, path string) bool {
	if t == nil {
		return false
	}
	if len(t.ProjectScope) == 0 {
		return true
	}
	if name == "" && path == "" {
		return true
	}
	for _, want := range t.ProjectScope {
		want = strings.TrimSpace(want)
		if want == "" {
			continue
		}
		if name != "" && strings.EqualFold(want, name) {
			return true
		}
		if path != "" && strings.EqualFold(want, path) {
			return true
		}
	}
	return false
}

// Minted is the one-time result of Mint: the persistable record plus the
// plaintext, which the caller must hand to the operator and then drop.
type Minted struct {
	Token Token

	// Plaintext is the full `cloop_pat_<id>_<secret>` string. It exists only
	// in this struct and only until the caller returns it; nothing in cloop
	// stores it, and no later API call can retrieve it.
	Plaintext string
}

// MintOptions describes the token to create.
type MintOptions struct {
	// Name is the operator-supplied label. Required: an unnamed credential
	// is one nobody can decide whether to revoke.
	Name string

	// Roles are the authz roles the bearer acts with. Required — a token
	// with no role can authenticate and do nothing, which is a support
	// ticket, not a security posture.
	Roles []string

	// ProjectScope optionally restricts which projects the token may
	// address, by registry name or filesystem path.
	ProjectScope []string

	// CreatedBy records the acting identity for the audit trail.
	CreatedBy string

	// ExpiresAt is when the token stops working. Zero means never, which
	// callers should discourage but which the model permits: an edge device
	// that cannot be re-provisioned needs a credential that outlives the
	// operator's calendar.
	ExpiresAt time.Time

	// Kind labels a hub-issued token; "" for an ordinary PAT.
	Kind string

	// Owner binds the token to the identity it acts for. See Token.Owner.
	Owner *Owner

	// Now overrides the clock, for tests.
	Now time.Time
}

// Mint generates a new token. The plaintext is returned exactly once.
//
// Validation is strict and happens before any randomness is drawn, so a
// rejected request cannot leave a half-formed record or consume entropy.
func Mint(opts MintOptions) (Minted, error) {
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		return Minted{}, errors.New("apitoken: a name is required")
	}
	if len(name) > MaxNameLen {
		return Minted{}, fmt.Errorf("apitoken: name is longer than %d characters", MaxNameLen)
	}

	roles, err := NormalizeRoles(opts.Roles)
	if err != nil {
		return Minted{}, err
	}
	scope, err := NormalizeProjectScope(opts.ProjectScope)
	if err != nil {
		return Minted{}, err
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	expires := opts.ExpiresAt
	if !expires.IsZero() {
		expires = expires.UTC()
		if !expires.After(now) {
			return Minted{}, errors.New("apitoken: expiry is in the past")
		}
	}

	id, err := randomHex(idBytes)
	if err != nil {
		return Minted{}, fmt.Errorf("apitoken: generate id: %w", err)
	}
	secret, err := randomHex(secretBytes)
	if err != nil {
		return Minted{}, fmt.Errorf("apitoken: generate secret: %w", err)
	}
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return Minted{}, fmt.Errorf("apitoken: generate salt: %w", err)
	}

	return Minted{
		Token: Token{
			ID:           id,
			Name:         name,
			Hash:         hashSecret(secret, salt),
			Prefix:       Prefix + id,
			Roles:        roles,
			ProjectScope: scope,
			CreatedBy:    strings.TrimSpace(opts.CreatedBy),
			CreatedAt:    now,
			ExpiresAt:    expires,
			Kind:         strings.TrimSpace(opts.Kind),
			Owner:        opts.Owner,
		},
		Plaintext: Prefix + id + "_" + secret,
	}, nil
}

// NormalizeRoles validates and de-duplicates a role list, returning the
// canonical lowercase names to persist.
//
// Unknown names are rejected rather than dropped. This is the mirror image of
// ParsedRoles, and the asymmetry is intentional: at *mint* time a typo must be
// a loud failure, because silently issuing a token weaker than the operator
// asked for produces a credential that fails mysteriously in CI a week later.
// At *verification* time the same value must be ignored rather than fatal,
// because by then the token exists and the safe reading of an unrecognised
// role is "grants nothing".
func NormalizeRoles(in []string) ([]string, error) {
	seen := make(map[authz.Role]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		role, ok := authz.ParseRole(raw)
		if !ok {
			return nil, fmt.Errorf("apitoken: %q is not a known role", strings.TrimSpace(raw))
		}
		if role == authz.RoleNone {
			return nil, errors.New("apitoken: role \"none\" grants nothing — omit the token instead")
		}
		if _, dup := seen[role]; dup {
			continue
		}
		seen[role] = struct{}{}
		out = append(out, string(role))
	}
	if len(out) == 0 {
		return nil, errors.New("apitoken: at least one role is required")
	}
	return out, nil
}

// NormalizeProjectScope trims, de-duplicates, and bounds a project scope list.
// An empty result means "every project", which is the documented meaning of
// omitting the field.
func NormalizeProjectScope(in []string) ([]string, error) {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		key := strings.ToLower(v)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, v)
	}
	if len(out) > MaxProjectScope {
		return nil, fmt.Errorf("apitoken: project scope names %d projects, the limit is %d", len(out), MaxProjectScope)
	}
	return out, nil
}

// Parse splits a token string into its id and secret halves without touching
// any storage. ok is false for anything not shaped like a token.
//
// Both halves are required to be lowercase hex of exactly the minted length.
// That strictness is what lets the auth chain reject obvious garbage — a
// truncated copy-paste, a URL-encoded blob, an SQL fragment — before it
// becomes a database lookup.
func Parse(raw string) (id, secret string, ok bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, Prefix) {
		return "", "", false
	}
	rest := raw[len(Prefix):]
	sep := strings.IndexByte(rest, '_')
	if sep <= 0 || sep == len(rest)-1 {
		return "", "", false
	}
	id, secret = rest[:sep], rest[sep+1:]
	if len(id) != idBytes*2 || len(secret) != secretBytes*2 {
		return "", "", false
	}
	if !isLowerHex(id) || !isLowerHex(secret) {
		return "", "", false
	}
	return id, secret, true
}

// LooksLikeToken reports whether a credential string is claiming to be a PAT.
//
// Used by the auth chain to decide whether to consult the token store at all,
// so that a deployment with no PATs — or a request carrying the static token —
// never pays for a database read. It is a prefix test, not validation: Verify
// still decides.
func LooksLikeToken(raw string) bool {
	return strings.HasPrefix(strings.TrimSpace(raw), Prefix)
}

// hashSecret derives the stored form of a secret under salt.
func hashSecret(secret string, salt []byte) string {
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(secret))
	return hashAlgHMACSHA256 + "$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(mac.Sum(nil))
}

// VerifyHash reports whether secret derives to encoded, in constant time with
// respect to the digest.
//
// The comparison is subtle.ConstantTimeCompare over the raw digest bytes, not
// a string == on the hex form: an early-exit compare over the encoding leaks,
// through response timing, how many leading bytes of a guess were right, which
// turns an offline problem into an online one.
//
// A malformed or unknown-algorithm stored value returns false. That case is
// database corruption, not an attacker-controlled path, so returning early is
// not a leak — there is no secret in the comparison that never happened.
func VerifyHash(encoded, secret string) bool {
	alg, salt, want, ok := splitHash(encoded)
	if !ok || alg != hashAlgHMACSHA256 {
		return false
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(secret))
	return subtle.ConstantTimeCompare(mac.Sum(nil), want) == 1
}

// splitHash decodes the `<alg>$<salt-hex>$<digest-hex>` stored form.
func splitHash(encoded string) (alg string, salt, digest []byte, ok bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 {
		return "", nil, nil, false
	}
	saltBytes, err := hex.DecodeString(parts[1])
	if err != nil || len(saltBytes) == 0 {
		return "", nil, nil, false
	}
	digestBytes, err := hex.DecodeString(parts[2])
	if err != nil || len(digestBytes) == 0 {
		return "", nil, nil, false
	}
	return parts[0], saltBytes, digestBytes, true
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return len(s) > 0
}
