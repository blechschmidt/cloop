// Package secret provides AES-256-GCM encrypted project secrets management.
// Secrets are stored in .cloop/secrets.enc and protected by the hub's root key,
// CLOOP_SECRET_KEY, resolved by pkg/rootkey from a key file, a systemd
// credential or the environment. During a change of root the file opens under
// the previous root as well, and every save seals it under the current one.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
	"github.com/blechschmidt/cloop/pkg/rootkey"
)

const (
	secretsFile = "secrets.enc"
	// EnvPassphraseKey is the environment variable that holds the passphrase:
	// one of the sources pkg/rootkey resolves it from.
	EnvPassphraseKey = rootkey.EnvKey

	saltSize  = 32
	nonceSize = 12
	keySize   = 32 // AES-256
	// iterations for key derivation (manual SHA-256 stretching)
	kdfRounds = 200_000
)

// Store holds the decrypted set of secrets in memory.
type Store struct {
	entries map[string]string
	workDir string
	passKey []byte // derived AES key cached for re-encryption
}

// secretsPath returns the path to .cloop/secrets.enc.
func secretsPath(workDir string) string {
	return filepath.Join(workDir, ".cloop", secretsFile)
}

// deriveKey stretches the passphrase + salt into a 32-byte AES key using
// iterated SHA-256 (poor-man's PBKDF2 without external dependencies).
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

// encrypt encrypts plaintext with the given 32-byte key using AES-256-GCM.
// Returns salt (32 bytes) + nonce (12 bytes) + ciphertext.
func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt decrypts data (nonce + ciphertext) using the given 32-byte key.
func decrypt(key, data []byte) ([]byte, error) {
	if len(data) < nonceSize {
		return nil, errors.New("secret: ciphertext too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// filePayload is the on-disk format serialized to JSON then encrypted.
type filePayload struct {
	Secrets map[string]string `json:"secrets"`
}

// Open loads and decrypts the secrets store from workDir.
// If the file does not exist, an empty store is returned.
// The passphrase is read from CLOOP_SECRET_KEY; an error is returned if it is
// absent and the file exists.
func Open(workDir string) (*Store, error) {
	path := secretsPath(workDir)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// New store — we need a passphrase to encrypt on first save.
		pass, _ := resolvePassphrase(false)
		s := &Store{entries: make(map[string]string), workDir: workDir}
		if pass != "" {
			// Pre-derive so we don't need to ask again on Save.
			salt := make([]byte, saltSize)
			if _, err2 := io.ReadFull(rand.Reader, salt); err2 == nil {
				s.passKey = deriveKey(pass, salt)
				// Store salt alongside so Save can regenerate the header.
				// We regenerate salt on each Save for forward secrecy.
			}
		}
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("secret: read %s: %w", secretsFile, err)
	}

	// File exists: need passphrase to decrypt.
	roots, err := resolveRoots(true)
	if err != nil {
		return nil, err
	}

	// Layout: [saltSize bytes salt] [rest encrypted with deriveKey(pass, salt)]
	if len(data) < saltSize {
		return nil, errors.New("secret: corrupt secrets file (too short)")
	}
	salt := data[:saltSize]
	encrypted := data[saltSize:]

	// The current root first, then the previous one: a file last saved
	// before the root changed is sealed under the old key, and is resealed
	// under the new one by the next Save.
	var (
		key       []byte
		plaintext []byte
	)
	for _, pass := range roots {
		key = deriveKey(pass, salt)
		if plaintext, err = decrypt(key, encrypted); err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("secret: decrypt failed (wrong passphrase?): %w", err)
	}

	var payload filePayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("secret: corrupt secrets payload: %w", err)
	}
	if payload.Secrets == nil {
		payload.Secrets = make(map[string]string)
	}
	return &Store{entries: payload.Secrets, workDir: workDir, passKey: key}, nil
}

// Save encrypts and writes the store to disk, under the current root. A new
// random salt is generated on each save (providing forward secrecy for the
// encryption layer).
func (s *Store) Save() error {
	pass, err := resolvePassphrase(false)
	if err != nil {
		return err
	}
	if pass == "" {
		return errors.New("secret: CLOOP_SECRET_KEY is not set — cannot save secrets")
	}

	payload := filePayload{Secrets: s.entries}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("secret: marshal: %w", err)
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("secret: generate salt: %w", err)
	}
	key := deriveKey(pass, salt)

	encrypted, err := encrypt(key, plaintext)
	if err != nil {
		return fmt.Errorf("secret: encrypt: %w", err)
	}

	out := append(salt, encrypted...)

	dir := filepath.Join(s.workDir, ".cloop")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("secret: mkdir .cloop: %w", err)
	}
	return atomicfile.Write(secretsPath(s.workDir), out, 0o600)
}

// Set stores key=value in the store (not persisted until Save is called).
func (s *Store) Set(key, value string) {
	s.entries[key] = value
}

// Get returns the plain-text value for key and whether it was found.
func (s *Store) Get(key string) (string, bool) {
	v, ok := s.entries[key]
	return v, ok
}

// Delete removes key from the store. Returns false if the key was not found.
func (s *Store) Delete(key string) bool {
	_, ok := s.entries[key]
	if ok {
		delete(s.entries, key)
	}
	return ok
}

// Keys returns the sorted list of secret keys.
func (s *Store) Keys() []string {
	keys := make([]string, 0, len(s.entries))
	for k := range s.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Len returns the number of secrets in the store.
func (s *Store) Len() int { return len(s.entries) }

// EnvLines returns KEY=value pairs for every secret, suitable for os/exec Env.
func (s *Store) EnvLines() []string {
	lines := make([]string, 0, len(s.entries))
	for k, v := range s.entries {
		lines = append(lines, k+"="+v)
	}
	return lines
}

// InjectIntoPrompt replaces {{KEY}} placeholders in prompt with the
// corresponding secret values. Unknown placeholders are left intact.
func (s *Store) InjectIntoPrompt(prompt string) string {
	for k, v := range s.entries {
		prompt = strings.ReplaceAll(prompt, "{{"+k+"}}", v)
	}
	return prompt
}

// resolvePassphrase returns the current root (pkg/rootkey), the one a save
// seals under. If require is true and none is configured, an error is
// returned; if require is false, ("", nil) is. A root source that is
// configured and refused is always an error.
func resolvePassphrase(require bool) (string, error) {
	roots, err := resolveRoots(require)
	if err != nil || len(roots) == 0 {
		return "", err
	}
	return roots[0], nil
}

// resolveRoots returns the roots the file may be sealed under, current first.
func resolveRoots(require bool) ([]string, error) {
	r, err := rootkey.Resolve()
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}
	roots := r.Values()
	if len(roots) == 0 && require {
		return nil, fmt.Errorf("secret: %s is not set — cannot decrypt secrets", EnvPassphraseKey)
	}
	return roots, nil
}
