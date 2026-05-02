// Package security provides cryptographic utilities for cloop's data integrity.
package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
)

// ErrInvalidSignature is returned when HMAC verification fails.
var ErrInvalidSignature = errors.New("state file signature mismatch: file may have been tampered with")

// envKey is the environment variable that holds the HMAC signing key.
const envKey = "CLOOP_STATE_HMAC_KEY"

// SigningKey returns the HMAC key from the environment variable CLOOP_STATE_HMAC_KEY.
// Returns an empty string when the variable is not set (signing disabled).
func SigningKey() string {
	return os.Getenv(envKey)
}

// Sign computes HMAC-SHA256 of data using key and returns the hex-encoded digest.
func Sign(key string, data []byte) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify returns nil when the provided sig matches HMAC-SHA256(key, data).
// Returns ErrInvalidSignature otherwise.
func Verify(key string, data []byte, sig string) error {
	expected := Sign(key, data)
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return ErrInvalidSignature
	}
	return nil
}

// RedactAPIKey masks all but the first 4 and last 4 characters of a secret.
// Values of 8 or fewer characters are fully masked as "****".
// Used to ensure sensitive values are never logged in plaintext.
func RedactAPIKey(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	masked := make([]byte, len(s))
	copy(masked[:4], s[:4])
	for i := 4; i < len(s)-4; i++ {
		masked[i] = '*'
	}
	copy(masked[len(s)-4:], s[len(s)-4:])
	return string(masked)
}
