package executorpool

// credential.go: the controller's credential (Task 20482).
//
// cloop_pool1_<id>.<secret> — a public ID, the lookup key, and a 32-byte
// secret. Long-lived, because a controller runs unattended for months, and
// revocable on its own or with its pool. The database holds the SHA-256 of
// the secret and nothing else, so a copy of the database authenticates
// nothing; the comparison is constant-time.
//
// The versioned prefix is what pkg/redact's shared registry recognises, so a
// credential pasted into a task, a log line or a browser error is scrubbed
// like every other cloop secret.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// CredentialPrefix starts every controller credential.
const CredentialPrefix = "cloop_pool1_"

// Credential sizes: a 12-byte public ID and a 32-byte secret.
const (
	credentialIDBytes     = 12
	credentialSecretBytes = 32
)

// newCredential mints a credential and returns it with its ID and the hash of
// its secret.
func newCredential() (token, id, secretHash string, err error) {
	id, err = randomString(credentialIDBytes)
	if err != nil {
		return "", "", "", fmt.Errorf("executorpool: generate credential id: %w", err)
	}
	secret, err := randomString(credentialSecretBytes)
	if err != nil {
		return "", "", "", fmt.Errorf("executorpool: generate credential secret: %w", err)
	}
	return CredentialPrefix + id + "." + secret, id, hashSecret(secret), nil
}

// ParseCredential splits a controller credential into its ID and secret, or
// reports it malformed. It checks shape only; Store.Authenticate decides.
func ParseCredential(token string) (id, secret string, err error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(token), CredentialPrefix)
	if !ok {
		return "", "", fmt.Errorf("%w: not a %s… credential", ErrCredentialInvalid, CredentialPrefix)
	}
	id, secret, ok = strings.Cut(rest, ".")
	if !ok || id == "" || secret == "" || strings.Contains(secret, ".") {
		return "", "", fmt.Errorf("%w: expected %s<id>.<secret>", ErrCredentialInvalid, CredentialPrefix)
	}
	if len(id) > 64 || len(secret) > 128 {
		return "", "", fmt.Errorf("%w: credential is too long", ErrCredentialInvalid)
	}
	return id, secret, nil
}

// hashSecret is the hex SHA-256 the database holds. A plain hash, not a
// password KDF: the input is 32 bytes of CSPRNG output with no dictionary to
// slow down, and the feed authenticates often.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// secretMatches compares a presented secret with a stored hash in constant
// time.
func secretMatches(secret, storedHash string) bool {
	got := hashSecret(secret)
	return subtle.ConstantTimeCompare([]byte(got), []byte(storedHash)) == 1
}

// CredentialActor is how a controller credential appears as an audit actor.
func CredentialActor(poolID, credentialID string) string {
	return "pool:" + poolID + "/" + credentialID
}

// touchInterval bounds how often a credential's last use is written: the feed
// authenticates on every long-poll, and last-used is for an administrator
// deciding whether a credential is still in service, which a minute's
// precision answers.
const touchInterval = time.Minute
