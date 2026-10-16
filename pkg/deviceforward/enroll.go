package deviceforward

// enroll.go is how a forwarder acquires, and the hub verifies, a long-lived
// credential — without either side needing an inbound route to the other.
//
// It is deliberately the executor agent's enrollment model (pkg/executor/
// remote/enroll.go), applied to a population that is not an executor. A
// forwarder runs no work, so it must never be registered as one, and keeping
// its enrollment in its own tables with its own token prefixes is what makes
// that structural rather than a check someone can forget: a forwarder
// credential presented to the executor endpoint is looked up in a store that
// has never heard of it.
//
// The two secrets have different lifetimes for the usual reason: the
// enrollment token is the one pasted into a terminal or a provisioning script
// — the one that leaks — so it is single-use and short-lived, and a leak that
// is redeemed by an attacker makes the real device's redemption fail loudly
// rather than both sharing an identity. Only SHA-256 of each secret is
// stored; a stolen database yields no usable credential. A truncated HMAC
// keyed by pkg/security binds a token to this control plane, so foreign and
// garbage tokens are rejected before any storage access — defence in depth,
// not the authentication boundary, which is the stored hash.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/security"
)

// Token prefixes. Distinct from the agent's clet1/clac1 so a forwarder token
// pasted where an agent token belongs fails with a legible message, and so a
// human reading a token knows which kind it is.
const (
	enrollTokenPrefix = "clft1"
	credentialPrefix  = "clfc1"
)

const (
	secretBytes = 32
	idBytes     = 12
	macBytes    = 16
)

// DefaultEnrollTTL bounds an unredeemed enrollment token.
const DefaultEnrollTTL = 15 * time.Minute

// MaxEnrollTTL caps --ttl, so a single-use token cannot be turned into a
// standing credential.
const MaxEnrollTTL = 24 * time.Hour

var b64 = base64.RawURLEncoding

// EnrollmentRecord is the hub's durable view of one minted forwarder token.
// The secret itself is never stored — only SecretHash.
type EnrollmentRecord struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	SecretHash string          `json:"secret_hash"`
	Device     ForwardedDevice `json:"device"`
	CreatedAt  time.Time       `json:"created_at"`
	ExpiresAt  time.Time       `json:"expires_at"`
	CreatedBy  string          `json:"created_by,omitempty"`
	// Owner scopes the forwarder to one identity on a multi-user hub, so a
	// forwarder is listed and revocable by its owner. Empty on a single-user
	// hub.
	Owner           string    `json:"owner,omitempty"`
	RedeemedAt      time.Time `json:"redeemed_at,omitempty"`
	RedeemedAgentID string    `json:"redeemed_agent_id,omitempty"`
	RevokedAt       time.Time `json:"revoked_at,omitempty"`
}

// Expired reports whether the token's TTL has elapsed as of now.
func (r EnrollmentRecord) Expired(now time.Time) bool {
	return !r.ExpiresAt.IsZero() && now.After(r.ExpiresAt)
}

// Redeemed reports whether the token has already been used.
func (r EnrollmentRecord) Redeemed() bool { return !r.RedeemedAt.IsZero() }

// Revoked reports whether the token was explicitly revoked.
func (r EnrollmentRecord) Revoked() bool { return !r.RevokedAt.IsZero() }

// ForwarderRecord is the hub's durable view of one enrolled forwarder.
type ForwarderRecord struct {
	ForwarderID  string          `json:"forwarder_id"`
	Name         string          `json:"name"`
	SecretHash   string          `json:"secret_hash"`
	Device       ForwardedDevice `json:"device"`
	Owner        string          `json:"owner,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	LastSeen     time.Time       `json:"last_seen,omitempty"`
	RevokedAt    time.Time       `json:"revoked_at,omitempty"`
	EnrollmentID string          `json:"enrollment_id,omitempty"`
}

// Revoked reports whether the forwarder's credential was revoked.
func (r ForwarderRecord) Revoked() bool { return !r.RevokedAt.IsZero() }

// Store is the persistence the enrollment flow needs. It is an interface so
// the security-relevant logic can be tested against an in-memory fake,
// including the concurrent-redemption race. RedeemEnrollment must perform the
// "still unredeemed?" check and the write atomically.
type Store interface {
	PutEnrollment(rec EnrollmentRecord) error
	GetEnrollment(id string) (EnrollmentRecord, error)
	RedeemEnrollment(id, forwarderID string, at time.Time) error
	RevokeEnrollment(id string, at time.Time) error
	ListEnrollments() ([]EnrollmentRecord, error)

	PutForwarder(rec ForwarderRecord) error
	GetForwarder(forwarderID string) (ForwarderRecord, error)
	RevokeForwarder(forwarderID string, at time.Time) error
	TouchForwarder(forwarderID string, at time.Time) error
	ListForwarders() ([]ForwarderRecord, error)
}

// MintOptions parameterises token creation.
type MintOptions struct {
	Name   string
	Device ForwardedDevice
	TTL    time.Duration
	Owner  string
	// CreatedBy identifies the minting operator (OIDC subject, or "" local).
	CreatedBy string
	// Server and Pin go into the bundle the operator carries to the device;
	// they are not persisted.
	Server string
	Pin    string
	Now    func() time.Time
}

func (o MintOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Mint creates a single-use enrollment token, persists its hash, and returns
// the token string. The token is the only time the secret exists outside the
// operator's terminal.
func Mint(store Store, opts MintOptions) (token string, rec EnrollmentRecord, err error) {
	if store == nil {
		return "", EnrollmentRecord{}, fmt.Errorf("deviceforward: mint: nil store")
	}
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		return "", EnrollmentRecord{}, fmt.Errorf("deviceforward: mint: forwarder name is required")
	}
	dev, err := opts.Device.Normalize()
	if err != nil {
		return "", EnrollmentRecord{}, err
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultEnrollTTL
	}
	if ttl > MaxEnrollTTL {
		return "", EnrollmentRecord{}, fmt.Errorf(
			"deviceforward: mint: ttl %s exceeds the %s maximum; enrollment tokens are short-lived",
			ttl, MaxEnrollTTL)
	}
	id, err := randomString(idBytes)
	if err != nil {
		return "", EnrollmentRecord{}, fmt.Errorf("deviceforward: mint: generate id: %w", err)
	}
	secret, err := randomString(secretBytes)
	if err != nil {
		return "", EnrollmentRecord{}, fmt.Errorf("deviceforward: mint: generate secret: %w", err)
	}
	now := opts.now()
	rec = EnrollmentRecord{
		ID:         id,
		Name:       name,
		SecretHash: hashSecret(secret),
		Device:     dev,
		Owner:      strings.TrimSpace(opts.Owner),
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
		CreatedBy:  opts.CreatedBy,
	}
	if err := store.PutEnrollment(rec); err != nil {
		return "", EnrollmentRecord{}, fmt.Errorf("deviceforward: mint: persist: %w", err)
	}
	return encodeToken(enrollTokenPrefix, id, secret), rec, nil
}

// Redeem exchanges an enrollment token for a long-lived forwarder credential.
// The order of checks matches the agent's: format and MAC, existence,
// revocation, replay, expiry, secret, then the atomic single-use claim.
func Redeem(store Store, token string, now time.Time) (credential string, fwd ForwarderRecord, err error) {
	if store == nil {
		return "", ForwarderRecord{}, fmt.Errorf("deviceforward: redeem: nil store")
	}
	id, secret, err := decodeToken(enrollTokenPrefix, token)
	if err != nil {
		return "", ForwarderRecord{}, err
	}
	rec, err := store.GetEnrollment(id)
	if err != nil {
		return "", ForwarderRecord{}, err
	}
	if rec.Revoked() {
		return "", ForwarderRecord{}, fmt.Errorf("%w: enrollment token %s was revoked at %s",
			ErrRevoked, id, rec.RevokedAt.Format(time.RFC3339))
	}
	if rec.Redeemed() {
		return "", ForwarderRecord{}, fmt.Errorf("%w: token %s was redeemed at %s by forwarder %s",
			ErrTokenAlreadyUsed, id, rec.RedeemedAt.Format(time.RFC3339), rec.RedeemedAgentID)
	}
	if rec.Expired(now) {
		return "", ForwarderRecord{}, fmt.Errorf("%w: token %s expired at %s",
			ErrTokenExpired, id, rec.ExpiresAt.Format(time.RFC3339))
	}
	if !secretMatches(secret, rec.SecretHash) {
		return "", ForwarderRecord{}, fmt.Errorf("%w: secret does not match token %s", ErrTokenInvalid, id)
	}
	fwdID, err := randomString(idBytes)
	if err != nil {
		return "", ForwarderRecord{}, fmt.Errorf("deviceforward: redeem: generate id: %w", err)
	}
	fwdSecret, err := randomString(secretBytes)
	if err != nil {
		return "", ForwarderRecord{}, fmt.Errorf("deviceforward: redeem: generate secret: %w", err)
	}
	if err := store.RedeemEnrollment(id, fwdID, now); err != nil {
		return "", ForwarderRecord{}, err
	}
	fwd = ForwarderRecord{
		ForwarderID:  fwdID,
		Name:         rec.Name,
		SecretHash:   hashSecret(fwdSecret),
		Device:       rec.Device,
		Owner:        rec.Owner,
		CreatedAt:    now,
		EnrollmentID: id,
	}
	if err := store.PutForwarder(fwd); err != nil {
		return "", ForwarderRecord{}, fmt.Errorf("deviceforward: redeem: persist: %w", err)
	}
	return encodeToken(credentialPrefix, fwdID, fwdSecret), fwd, nil
}

// Authenticate verifies a long-lived forwarder credential on every reconnect.
func Authenticate(store Store, credential string, now time.Time) (ForwarderRecord, error) {
	if store == nil {
		return ForwarderRecord{}, fmt.Errorf("deviceforward: authenticate: nil store")
	}
	fwdID, secret, err := decodeToken(credentialPrefix, credential)
	if err != nil {
		return ForwarderRecord{}, fmt.Errorf("%w: %v", ErrCredentialInvalid, err)
	}
	rec, err := store.GetForwarder(fwdID)
	if err != nil {
		return ForwarderRecord{}, err
	}
	if rec.Revoked() {
		return ForwarderRecord{}, fmt.Errorf("%w: forwarder %s was revoked at %s",
			ErrRevoked, fwdID, rec.RevokedAt.Format(time.RFC3339))
	}
	if !secretMatches(secret, rec.SecretHash) {
		return ForwarderRecord{}, fmt.Errorf("%w: secret does not match forwarder %s", ErrCredentialInvalid, fwdID)
	}
	if err := store.TouchForwarder(fwdID, now); err != nil {
		_ = err // bookkeeping, never a reason to deny a valid credential
	}
	return rec, nil
}

// Revoke invalidates an enrollment token or a forwarder credential by ID. An
// enrollment ID additionally revokes the forwarder it produced, so a token
// that leaked and was redeemed by an attacker does not leave a live credential.
func Revoke(store Store, id string, now time.Time) (kind string, err error) {
	if store == nil {
		return "", fmt.Errorf("deviceforward: revoke: nil store")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return "", fmt.Errorf("deviceforward: revoke: id is required")
	}
	if rec, gerr := store.GetEnrollment(id); gerr == nil {
		if err := store.RevokeEnrollment(id, now); err != nil {
			return "", fmt.Errorf("deviceforward: revoke enrollment %s: %w", id, err)
		}
		if rec.RedeemedAgentID != "" {
			if err := store.RevokeForwarder(rec.RedeemedAgentID, now); err != nil {
				return "", fmt.Errorf(
					"deviceforward: revoked token %s but failed to revoke the forwarder %s it minted: %w",
					id, rec.RedeemedAgentID, err)
			}
			return "enrollment+forwarder", nil
		}
		return "enrollment", nil
	}
	if _, gerr := store.GetForwarder(id); gerr == nil {
		if err := store.RevokeForwarder(id, now); err != nil {
			return "", fmt.Errorf("deviceforward: revoke forwarder %s: %w", id, err)
		}
		return "forwarder", nil
	}
	return "", fmt.Errorf("%w: no enrollment token or forwarder with ID %q", ErrForwarderNotFound, id)
}

func encodeToken(prefix, id, secret string) string {
	body := prefix + "." + id + "." + secret
	return body + "." + tokenMAC(body)
}

func decodeToken(wantPrefix, token string) (id, secret string, err error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", "", fmt.Errorf("%w: token is empty", ErrTokenInvalid)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return "", "", fmt.Errorf("%w: expected 4 dot-separated segments, got %d", ErrTokenInvalid, len(parts))
	}
	prefix, id, secret, mac := parts[0], parts[1], parts[2], parts[3]
	if prefix != wantPrefix {
		return "", "", fmt.Errorf("%w: expected a %q token, got %q", ErrTokenInvalid, wantPrefix, prefix)
	}
	if id == "" || secret == "" {
		return "", "", fmt.Errorf("%w: token has an empty id or secret", ErrTokenInvalid)
	}
	expected := tokenMAC(prefix + "." + id + "." + secret)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(mac)) != 1 {
		return "", "", fmt.Errorf("%w: token signature does not verify against this control plane", ErrTokenInvalid)
	}
	return id, secret, nil
}

func tokenMAC(body string) string {
	full := security.Sign(security.SigningKey(), []byte(body))
	if len(full) > macBytes*2 {
		full = full[:macBytes*2]
	}
	return full
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return fmt.Sprintf("%x", sum)
}

func secretMatches(secret, storedHash string) bool {
	got := hashSecret(secret)
	return subtle.ConstantTimeCompare([]byte(got), []byte(storedHash)) == 1
}

func randomString(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b64.EncodeToString(buf), nil
}
