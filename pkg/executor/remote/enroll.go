package remote

// Enrollment is how a device with no prior relationship to a control plane
// acquires one, without either side needing an inbound route to the other.
//
// The flow has two secrets with deliberately different lifetimes:
//
//	control plane:  cloop executor enroll --name edge-1 --ttl 15m
//	                  → prints a single-use, short-lived enrollment token
//	device:         cloop executor agent --server wss://... --token <tok>
//	                  → redeems it, receives a long-lived agent credential,
//	                    persists that credential 0600 and never needs the
//	                    enrollment token again
//
// Why two: the enrollment token is the one that gets pasted into a terminal,
// copied through a chat window, or baked into a provisioning script — i.e. the
// one that leaks. Making it single-use and TTL-bounded means a leak is only
// exploitable in a narrow window, and only if the attacker wins the race
// against the real device. If they do, the legitimate device's redemption
// fails loudly with ErrTokenAlreadyUsed instead of both silently sharing an
// identity, which is what turns a leak into a detected leak.
//
// # What is stored
//
// Never the secret. The database holds SHA-256 of each secret, so a stolen
// state.db yields no usable credential. Verification recomputes the hash and
// compares in constant time.
//
// The token additionally carries an HMAC over its public and secret parts,
// keyed by pkg/security.SigningKey. That MAC is defence in depth, not the
// authentication boundary: the stored hash is authoritative. What the MAC buys
// is a cheap, DB-free rejection of tokens that were never minted here, so
// garbage and cross-control-plane tokens are dropped before touching storage.
// When no signing key is configured the MAC degrades to an unkeyed checksum —
// still a valid format check, no longer an authenticity claim — and the stored
// hash continues to carry the whole security argument.

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

// Token prefixes. The version segment lets the format change without
// ambiguity, and the distinct prefixes mean an enrollment token pasted where a
// credential belongs fails with a clear message instead of a hash mismatch.
const (
	enrollTokenPrefix = "clet1"
	credentialPrefix  = "clac1"
)

// Secret sizing. 32 bytes is well beyond brute-force reach; the 16-byte ID is
// a public lookup key, not a secret, and only needs to avoid collisions.
const (
	secretBytes = 32
	idBytes     = 12
	macBytes    = 16
)

// DefaultEnrollTTL bounds an unredeemed enrollment token. Fifteen minutes is
// long enough to paste a command onto a device over a slow link and short
// enough that a token left in shell history is inert by the time anyone finds
// it.
const DefaultEnrollTTL = 15 * time.Minute

// MaxEnrollTTL caps --ttl. Operators reach for "just make it a week" when
// provisioning is awkward; that converts a single-use token into a standing
// credential, which is the thing this design exists to avoid.
const MaxEnrollTTL = 24 * time.Hour

// b64 encodes secrets without padding so tokens stay copy-pasteable as a
// single shell word.
var b64 = base64.RawURLEncoding

// EnrollmentRecord is the control plane's durable view of one minted token.
// The secret itself is absent by construction — only SecretHash is persisted.
type EnrollmentRecord struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// SecretHash is hex-encoded SHA-256 of the token secret.
	SecretHash  string            `json:"secret_hash"`
	WorkDirRoot string            `json:"workdir_root,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
	CreatedBy   string            `json:"created_by,omitempty"`
	// RedeemedAt is zero until redemption. Non-zero is what makes the token
	// single-use: redemption is a conditional update that only succeeds while
	// this is still zero, so two concurrent redemptions cannot both win.
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

// AgentRecord is the control plane's durable view of one enrolled agent and
// its long-lived credential.
type AgentRecord struct {
	AgentID string `json:"agent_id"`
	Name    string `json:"name"`
	// SecretHash is hex-encoded SHA-256 of the credential secret.
	SecretHash  string            `json:"secret_hash"`
	WorkDirRoot string            `json:"workdir_root,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	LastSeen    time.Time         `json:"last_seen,omitempty"`
	RevokedAt   time.Time         `json:"revoked_at,omitempty"`
	// EnrollmentID records which token minted this agent, so revoking a
	// leaked token can also reach the identity it produced.
	EnrollmentID string `json:"enrollment_id,omitempty"`
}

// Revoked reports whether the agent's credential was revoked.
func (r AgentRecord) Revoked() bool { return !r.RevokedAt.IsZero() }

// Store is the persistence the enrollment flow needs.
//
// It is an interface rather than a *statedb.DB so that enrollment logic —
// which is where the security-relevant decisions live — can be tested against
// an in-memory fake, including the concurrent-redemption race that a
// SQLite-backed test would make awkward to provoke deterministically.
//
// RedeemEnrollment carries the atomicity requirement: implementations must
// perform the "is it still unredeemed?" check and the write to RedeemedAt in a
// single atomic step. A read-then-write implementation would let two racing
// devices both redeem one token and end up sharing an identity.
type Store interface {
	// PutEnrollment persists a newly minted token record.
	PutEnrollment(rec EnrollmentRecord) error
	// GetEnrollment loads a token by its public ID. Returns ErrTokenInvalid
	// when no such row exists.
	GetEnrollment(id string) (EnrollmentRecord, error)
	// RedeemEnrollment atomically marks id redeemed by agentID. It must
	// return ErrTokenAlreadyUsed if the row is already redeemed.
	RedeemEnrollment(id, agentID string, at time.Time) error
	// RevokeEnrollment marks a token revoked; unredeemed or not.
	RevokeEnrollment(id string, at time.Time) error
	// ListEnrollments returns every token record, newest first.
	ListEnrollments() ([]EnrollmentRecord, error)

	// PutAgent persists an agent credential record.
	PutAgent(rec AgentRecord) error
	// GetAgent loads an agent by ID. Returns ErrAgentNotFound when absent.
	GetAgent(agentID string) (AgentRecord, error)
	// RevokeAgent marks an agent's credential revoked.
	RevokeAgent(agentID string, at time.Time) error
	// TouchAgent records that the agent was seen at t.
	TouchAgent(agentID string, at time.Time) error
	// ListAgents returns every enrolled agent.
	ListAgents() ([]AgentRecord, error)
}

// MintOptions parameterises token creation.
type MintOptions struct {
	// Name is the operator-facing label the agent will carry.
	Name string
	// TTL bounds redemption. Zero uses DefaultEnrollTTL; values above
	// MaxEnrollTTL are rejected rather than silently clamped, because an
	// operator who asked for a week should learn that the answer is no.
	TTL time.Duration
	// WorkDirRoot is the filesystem root the enrolled agent will confine
	// every workload to. Empty lets the device choose its own default.
	WorkDirRoot string
	// Labels are free-form scheduler selectors.
	Labels map[string]string
	// CreatedBy identifies the minting operator (OIDC subject, or "" local).
	CreatedBy string
	// Server is the control-plane WebSocket URL to record in the enrollment
	// bundle. Not persisted: it is what the operator carries to the device,
	// not something the control plane needs to remember.
	Server string
	// Pin is the hub's SPKI fingerprint ("sha256:<base64>") to record in the
	// bundle, so the device can tell its control plane apart from anything
	// else that answers the same hostname. Also not persisted.
	Pin string
	// Now overrides the clock for tests.
	Now func() time.Time
}

func (o MintOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Mint creates a single-use enrollment token, persists its hash, and returns
// the token string. The returned string is the only time the secret exists
// outside the operator's terminal — it is not recoverable from the database.
func Mint(store Store, opts MintOptions) (token string, rec EnrollmentRecord, err error) {
	if store == nil {
		return "", EnrollmentRecord{}, fmt.Errorf("remote: mint: nil store")
	}
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		return "", EnrollmentRecord{}, fmt.Errorf("remote: mint: agent name is required")
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultEnrollTTL
	}
	if ttl > MaxEnrollTTL {
		return "", EnrollmentRecord{}, fmt.Errorf(
			"remote: mint: ttl %s exceeds the %s maximum; enrollment tokens are meant to be short-lived",
			ttl, MaxEnrollTTL)
	}

	id, err := randomString(idBytes)
	if err != nil {
		return "", EnrollmentRecord{}, fmt.Errorf("remote: mint: generate id: %w", err)
	}
	secret, err := randomString(secretBytes)
	if err != nil {
		return "", EnrollmentRecord{}, fmt.Errorf("remote: mint: generate secret: %w", err)
	}

	now := opts.now()
	rec = EnrollmentRecord{
		ID:          id,
		Name:        name,
		SecretHash:  hashSecret(secret),
		WorkDirRoot: strings.TrimSpace(opts.WorkDirRoot),
		Labels:      opts.Labels,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
		CreatedBy:   opts.CreatedBy,
	}
	if err := store.PutEnrollment(rec); err != nil {
		return "", EnrollmentRecord{}, fmt.Errorf("remote: mint: persist: %w", err)
	}
	return encodeToken(enrollTokenPrefix, id, secret), rec, nil
}

// RedeemOptions parameterises redemption.
type RedeemOptions struct {
	// Now overrides the clock for tests.
	Now func() time.Time
}

func (o RedeemOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Redeem exchanges an enrollment token for a long-lived agent credential.
//
// It is the security-critical path, so the order of checks is deliberate:
// format and MAC first (cheap, no storage access), then existence, then
// revocation, then expiry, then the secret comparison, and only then the
// atomic single-use claim. Verifying the secret before claiming means a wrong
// secret cannot burn a legitimate token; claiming atomically after means two
// correct-secret racers cannot both succeed.
//
// The returned credential string is shown once and stored only as a hash.
func Redeem(store Store, token string, opts RedeemOptions) (credential string, agent AgentRecord, err error) {
	if store == nil {
		return "", AgentRecord{}, fmt.Errorf("remote: redeem: nil store")
	}
	id, secret, err := decodeToken(enrollTokenPrefix, token)
	if err != nil {
		return "", AgentRecord{}, err
	}

	rec, err := store.GetEnrollment(id)
	if err != nil {
		return "", AgentRecord{}, err
	}
	now := opts.now()

	if rec.Revoked() {
		return "", AgentRecord{}, fmt.Errorf("%w: enrollment token %s was revoked at %s",
			ErrRevoked, id, rec.RevokedAt.Format(time.RFC3339))
	}
	// Replay is reported before expiry: a redeemed token is a more alarming
	// finding than a stale one, and an operator seeing "already redeemed"
	// needs to go look at who redeemed it.
	if rec.Redeemed() {
		return "", AgentRecord{}, fmt.Errorf("%w: token %s was redeemed at %s by agent %s",
			ErrTokenAlreadyUsed, id, rec.RedeemedAt.Format(time.RFC3339), rec.RedeemedAgentID)
	}
	if rec.Expired(now) {
		return "", AgentRecord{}, fmt.Errorf("%w: token %s expired at %s",
			ErrTokenExpired, id, rec.ExpiresAt.Format(time.RFC3339))
	}
	if !secretMatches(secret, rec.SecretHash) {
		return "", AgentRecord{}, fmt.Errorf("%w: secret does not match token %s", ErrTokenInvalid, id)
	}

	agentID, err := randomString(idBytes)
	if err != nil {
		return "", AgentRecord{}, fmt.Errorf("remote: redeem: generate agent id: %w", err)
	}
	agentSecret, err := randomString(secretBytes)
	if err != nil {
		return "", AgentRecord{}, fmt.Errorf("remote: redeem: generate agent secret: %w", err)
	}

	// Claim the token before writing the agent record. If the claim loses the
	// race we must not leave a credential behind for an identity that never
	// legitimately enrolled.
	if err := store.RedeemEnrollment(id, agentID, now); err != nil {
		return "", AgentRecord{}, err
	}

	agent = AgentRecord{
		AgentID:      agentID,
		Name:         rec.Name,
		SecretHash:   hashSecret(agentSecret),
		WorkDirRoot:  rec.WorkDirRoot,
		Labels:       rec.Labels,
		CreatedAt:    now,
		EnrollmentID: id,
	}
	if err := store.PutAgent(agent); err != nil {
		return "", AgentRecord{}, fmt.Errorf("remote: redeem: persist agent: %w", err)
	}
	return encodeToken(credentialPrefix, agentID, agentSecret), agent, nil
}

// Authenticate verifies a long-lived agent credential and returns the agent it
// belongs to. It is called on every reconnect, so revoking an agent takes
// effect the next time it dials rather than requiring the control plane to
// hunt down a live session — though the session layer also drops live
// connections on revoke, so both paths are covered.
func Authenticate(store Store, credential string, now time.Time) (AgentRecord, error) {
	if store == nil {
		return AgentRecord{}, fmt.Errorf("remote: authenticate: nil store")
	}
	agentID, secret, err := decodeToken(credentialPrefix, credential)
	if err != nil {
		// Report a credential-shaped error rather than a token-shaped one so
		// the agent's log says "your saved credential is bad; re-enroll".
		return AgentRecord{}, fmt.Errorf("%w: %v", ErrCredentialInvalid, err)
	}
	rec, err := store.GetAgent(agentID)
	if err != nil {
		return AgentRecord{}, err
	}
	if rec.Revoked() {
		return AgentRecord{}, fmt.Errorf("%w: agent %s was revoked at %s",
			ErrRevoked, agentID, rec.RevokedAt.Format(time.RFC3339))
	}
	if !secretMatches(secret, rec.SecretHash) {
		return AgentRecord{}, fmt.Errorf("%w: secret does not match agent %s", ErrCredentialInvalid, agentID)
	}
	if err := store.TouchAgent(agentID, now); err != nil {
		// A failed last-seen update must not deny a valid credential; it is
		// bookkeeping, not authentication.
		_ = err
	}
	return rec, nil
}

// Revoke invalidates an enrollment token or an agent credential by ID.
//
// The same command handles both because an operator responding to a leak
// knows the ID they were given, not which table it lives in. An enrollment ID
// additionally revokes the agent it produced: a token that leaked before
// redemption and was redeemed by an attacker must not leave that attacker's
// credential live.
func Revoke(store Store, id string, now time.Time) (kind string, err error) {
	if store == nil {
		return "", fmt.Errorf("remote: revoke: nil store")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return "", fmt.Errorf("remote: revoke: id is required")
	}

	if rec, err := store.GetEnrollment(id); err == nil {
		if err := store.RevokeEnrollment(id, now); err != nil {
			return "", fmt.Errorf("remote: revoke enrollment %s: %w", id, err)
		}
		if rec.RedeemedAgentID != "" {
			if err := store.RevokeAgent(rec.RedeemedAgentID, now); err != nil {
				return "", fmt.Errorf(
					"remote: revoked token %s but failed to revoke the agent %s it minted: %w",
					id, rec.RedeemedAgentID, err)
			}
			return "enrollment+agent", nil
		}
		return "enrollment", nil
	}

	if _, err := store.GetAgent(id); err == nil {
		if err := store.RevokeAgent(id, now); err != nil {
			return "", fmt.Errorf("remote: revoke agent %s: %w", id, err)
		}
		return "agent", nil
	}
	return "", fmt.Errorf("%w: no enrollment token or agent with ID %q", ErrAgentNotFound, id)
}

// ---------------------------------------------------------------------------
// Token encoding
// ---------------------------------------------------------------------------

// encodeToken renders "<prefix>.<id>.<secret>.<mac>".
func encodeToken(prefix, id, secret string) string {
	body := prefix + "." + id + "." + secret
	return body + "." + tokenMAC(body)
}

// decodeToken parses and MAC-checks a token, returning its ID and secret.
//
// The MAC check happens here, before any storage access, so malformed or
// foreign tokens never reach the database. It is not the authentication
// boundary — see the file header — which is why a MAC failure and an unknown
// ID both surface as ErrTokenInvalid rather than leaking which one it was.
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

// tokenMAC computes the truncated HMAC that binds a token to this control
// plane. security.Sign is HMAC-SHA256 hex; truncating to macBytes keeps tokens
// short while leaving far more collision resistance than a format check needs.
func tokenMAC(body string) string {
	full := security.Sign(security.SigningKey(), []byte(body))
	if len(full) > macBytes*2 {
		full = full[:macBytes*2]
	}
	return full
}

// hashSecret returns the hex SHA-256 of a secret, which is the only form ever
// written to storage. SHA-256 rather than a password KDF is correct here: the
// input is 32 bytes of CSPRNG output, not a human-chosen password, so there is
// no dictionary to slow down and key stretching would only add latency to
// every reconnect.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return fmt.Sprintf("%x", sum)
}

// secretMatches compares a presented secret against a stored hash in constant
// time, so a timing oracle cannot be used to recover the hash byte by byte.
func secretMatches(secret, storedHash string) bool {
	got := hashSecret(secret)
	return subtle.ConstantTimeCompare([]byte(got), []byte(storedHash)) == 1
}

// randomString returns n cryptographically random bytes, base64url encoded.
func randomString(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b64.EncodeToString(buf), nil
}
