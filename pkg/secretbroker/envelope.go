package secretbroker

// The on-disk shape of envelope-encrypted material, and the AEAD primitives
// both layers share (Task 20181).
//
// Envelope is deliberately a plain struct with no methods that decrypt. It is
// what crosses the storage boundary in both directions, and keeping it inert
// is the same argument as Secret having no plaintext field: a type that
// cannot hold a credential cannot leak one into a log line, a JSON response,
// or a panic backtrace, however enthusiastically someone later instruments
// the code that carries it.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Envelope is one piece of envelope-encrypted material.
//
// A row stores all three parts. KeyID names the KEK that WrappedDEK is sealed
// under; Ciphertext is sealed under the DEK inside WrappedDEK. Rotation
// rewrites the first two and leaves the third byte-identical.
//
// KeyID == LegacyKeyID (or "") means the pre-envelope construction:
// WrappedDEK is empty and Ciphertext is sealed directly under the
// passphrase-derived key. Those rows keep working until a rotation upgrades
// them.
type Envelope struct {
	KeyID      string
	WrappedDEK []byte
	Ciphertext []byte
}

// IsLegacy reports whether this envelope predates envelope encryption.
func (e Envelope) IsLegacy() bool {
	return e.KeyID == "" || e.KeyID == LegacyKeyID
}

// Empty reports whether there is anything sealed here at all. A session with
// no refresh token stores an empty envelope rather than a sealed empty
// string, so "nothing to protect" and "protected nothing" stay distinct.
func (e Envelope) Empty() bool { return len(e.Ciphertext) == 0 }

// LegacyEnvelope wraps a pre-envelope ciphertext for the open path.
func LegacyEnvelope(ciphertext []byte) Envelope {
	return Envelope{KeyID: LegacyKeyID, Ciphertext: ciphertext}
}

// sealWith encrypts plaintext under a raw 32-byte key with the given
// associated data, returning nonce||ciphertext||tag.
//
// The nonce is random rather than a counter. With a per-row DEK the question
// barely arises — each DEK encrypts exactly one message — but the KEK wraps
// many DEKs, and a 96-bit random nonce's collision probability across the
// number of DEKs a hub will ever hold is far below the point at which any
// other part of this system is the weak link. A counter would need durable
// state that survives restore-from-backup, which is a much easier thing to
// get wrong.
func sealWith(key, aad, plaintext []byte) ([]byte, error) {
	gcm, err := gcmFor(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("secretbroker: generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// openWith decrypts an envelope produced by sealWith.
//
// A wrong key, a tampered ciphertext, and associated data that does not match
// the row are indistinguishable here, and that is correct: all three mean
// "this material is not what it claims to be", and distinguishing them for
// the caller would be distinguishing them for an attacker. The *caller*
// supplies the operator-facing distinction (retired key, underivable key,
// unknown key) from information it holds outside the ciphertext.
func openWith(key, aad, sealed []byte) ([]byte, error) {
	if len(sealed) <= nonceSize {
		return nil, fmt.Errorf("%w: envelope is too short", ErrSealFailed)
	}
	gcm, err := gcmFor(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, sealed[:nonceSize], sealed[nonceSize:], aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSealFailed, err)
	}
	return plaintext, nil
}

func gcmFor(key []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("%w: key must be %d bytes, got %d", ErrSealFailed, keySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSealFailed, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSealFailed, err)
	}
	return gcm, nil
}

// sealer is what the broker and the session store need from a key source. It
// lets a *Cipher (single key, no registry — the shape a test double wants)
// and a *Keyring (envelope encryption, rotation) be used interchangeably.
type sealer interface {
	SealFor(aad string, plaintext []byte) (Envelope, error)
	OpenEnvelope(aad string, env Envelope) ([]byte, error)
}

// SealFor lets a plain Cipher satisfy sealer. It produces legacy-shaped
// envelopes: no wrapped DEK, ciphertext directly under the one key.
//
// Associated data is ignored, because the legacy construction has nowhere to
// put it. That is a real (small) difference in the guarantees a Cipher-backed
// broker offers versus a Keyring-backed one, and it is the reason production
// paths use a Keyring: pkg/secretstore implements KeyStore, so every hub gets
// envelope encryption and the row binding that comes with it.
func (c *Cipher) SealFor(_ string, plaintext []byte) (Envelope, error) {
	ct, err := c.Seal(plaintext)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{KeyID: LegacyKeyID, Ciphertext: ct}, nil
}

// OpenEnvelope lets a plain Cipher satisfy sealer.
func (c *Cipher) OpenEnvelope(_ string, env Envelope) ([]byte, error) {
	if !env.IsLegacy() {
		return nil, fmt.Errorf("%w: material is sealed under key %s but this broker has no key registry",
			ErrKeyUnknown, env.KeyID)
	}
	return c.Unseal(env.Ciphertext)
}

var (
	_ sealer = (*Cipher)(nil)
	_ sealer = (*Keyring)(nil)
)
