package secretbroker

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

// EnvPassphraseKey is the environment variable holding the passphrase that
// protects sealed payloads. It is the same variable pkg/secret uses, so an
// existing deployment's key keeps working across the migration.
const EnvPassphraseKey = "CLOOP_SECRET_KEY"

const (
	saltSize  = 32
	nonceSize = 12
	keySize   = 32 // AES-256
	// kdfRounds matches pkg/secret so the two stores derive identically
	// from the same passphrase.
	kdfRounds = 200_000
)

// metaKeySalt is the metadata row holding the broker's KDF salt.
const metaKeySalt = "secretbroker.salt"

// Cipher seals and opens secret payloads with AES-256-GCM.
//
// Unlike pkg/secret, which re-derives its key from a fresh salt on every
// save, the broker derives once from a salt persisted in the store and
// caches the key. That matters here: pkg/secret rewrites one file wholesale,
// while the broker opens individual payloads on every lease. At 200 000
// SHA-256 rounds, per-payload derivation would put roughly a fifth of a
// second of CPU between an executor and each of its credentials. Per-payload
// randomness comes from the GCM nonce instead, which is what it is for.
type Cipher struct {
	key []byte
}

// NewCipher derives the payload key from the CLOOP_SECRET_KEY passphrase and
// the store-wide salt. The salt is created on first use and persisted, so
// the same passphrase yields the same key across restarts.
func NewCipher(store Store) (*Cipher, error) {
	pass := os.Getenv(EnvPassphraseKey)
	if pass == "" {
		return nil, fmt.Errorf("%w: set it to seal and open secret payloads", ErrNoKey)
	}
	salt, err := loadOrCreateSalt(store)
	if err != nil {
		return nil, err
	}
	return &Cipher{key: deriveKey(pass, salt)}, nil
}

// NewCipherWithKey builds a Cipher from a raw 32-byte key. Used by tests and
// by callers that manage key material themselves.
func NewCipherWithKey(key []byte) (*Cipher, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("%w: key must be %d bytes, got %d", ErrSealFailed, keySize, len(key))
	}
	cp := make([]byte, keySize)
	copy(cp, key)
	return &Cipher{key: cp}, nil
}

// loadOrCreateSalt reads the store-wide KDF salt, generating and persisting
// one on first use. Storing it hex-encoded keeps the metadata table textual.
func loadOrCreateSalt(store Store) ([]byte, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidSecret)
	}
	if v, ok, err := store.Meta(metaKeySalt); err != nil {
		return nil, fmt.Errorf("secretbroker: read salt: %w", err)
	} else if ok && v != "" {
		salt, derr := decodeHex(v)
		if derr != nil || len(salt) != saltSize {
			return nil, fmt.Errorf("%w: stored salt is corrupt", ErrSealFailed)
		}
		return salt, nil
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("secretbroker: generate salt: %w", err)
	}
	if err := store.SetMeta(metaKeySalt, encodeHex(salt)); err != nil {
		return nil, fmt.Errorf("secretbroker: persist salt: %w", err)
	}
	return salt, nil
}

// deriveKey stretches passphrase+salt with iterated SHA-256, matching
// pkg/secret's derivation so a single passphrase serves both stores.
func deriveKey(passphrase string, salt []byte) []byte {
	h := sha256.New()
	data := make([]byte, 0, len(salt)+len(passphrase))
	data = append(data, salt...)
	data = append(data, []byte(passphrase)...)
	for i := 0; i < kdfRounds; i++ {
		h.Reset()
		h.Write(data)
		data = h.Sum(data[:0])
	}
	key := make([]byte, keySize)
	copy(key, data)
	return key
}

// Seal encrypts plaintext, returning nonce||ciphertext||tag.
func (c *Cipher) Seal(plaintext []byte) ([]byte, error) {
	if c == nil || len(c.key) != keySize {
		return nil, fmt.Errorf("%w: cipher is not initialised", ErrSealFailed)
	}
	gcm, err := c.gcm()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("secretbroker: generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Unseal decrypts an envelope produced by Seal. A wrong key and a tampered
// envelope are indistinguishable — both surface as ErrSealFailed, which is
// the correct amount of information to give a caller.
func (c *Cipher) Unseal(envelope []byte) ([]byte, error) {
	if c == nil || len(c.key) != keySize {
		return nil, fmt.Errorf("%w: cipher is not initialised", ErrSealFailed)
	}
	if len(envelope) <= nonceSize {
		return nil, fmt.Errorf("%w: envelope is too short", ErrSealFailed)
	}
	gcm, err := c.gcm()
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, envelope[:nonceSize], envelope[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSealFailed, err)
	}
	return plaintext, nil
}

func (c *Cipher) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSealFailed, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSealFailed, err)
	}
	return gcm, nil
}

const hexDigits = "0123456789abcdef"

func encodeHex(b []byte) string {
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0x0f]
	}
	return string(out)
}

func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex string")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, err := hexVal(s[i*2])
		if err != nil {
			return nil, err
		}
		lo, err := hexVal(s[i*2+1])
		if err != nil {
			return nil, err
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("invalid hex digit %q", string(rune(c)))
}
