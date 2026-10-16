package kmstest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Transit is a fake Vault Transit server on loopback: one mount, one key with
// versions, token and Kubernetes-login authentication.
type Transit struct {
	Server *httptest.Server
	Mount  string
	Key    string
	// Token is the static token the server accepts.
	Token string
	// Role and JWT are what a Kubernetes login must present; the token it
	// issues expires after LeaseSeconds.
	Role         string
	JWT          string
	LeaseSeconds int

	mu       sync.Mutex
	versions []cipher.AEAD
	issued   map[string]bool
	delay    time.Duration
	status   int // non-zero: every request answers this status
	calls    map[string]int
}

// StartTransit starts the server with key version 1. It stops when the test
// ends.
func StartTransit(t testing.TB) *Transit {
	t.Helper()
	tr := &Transit{
		Mount: "transit", Key: "cloop", Token: "s.kmstest-static-token",
		Role: "cloop-hub", JWT: "kmstest-service-account-jwt", LeaseSeconds: 3600,
		issued: map[string]bool{}, calls: map[string]int{},
	}
	if err := tr.addVersion(); err != nil {
		t.Fatalf("kmstest: transit key: %v", err)
	}
	tr.Server = httptest.NewServer(http.HandlerFunc(tr.serve))
	t.Cleanup(tr.Server.Close)
	return tr
}

// URL is the server's address.
func (tr *Transit) URL() string { return tr.Server.URL }

// Rotate adds a key version and makes it the latest. It returns its number.
func (tr *Transit) Rotate() int {
	if err := tr.addVersion(); err != nil {
		panic(err)
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return len(tr.versions)
}

// SetDelay delays every answer by d.
func (tr *Transit) SetDelay(d time.Duration) {
	tr.mu.Lock()
	tr.delay = d
	tr.mu.Unlock()
}

// SetStatus makes every request answer code (503 for a sealed Vault, 403 for
// a revoked policy); zero restores normal service.
func (tr *Transit) SetStatus(code int) {
	tr.mu.Lock()
	tr.status = code
	tr.mu.Unlock()
}

// RevokeIssued invalidates every token a Kubernetes login issued.
func (tr *Transit) RevokeIssued() {
	tr.mu.Lock()
	tr.issued = map[string]bool{}
	tr.mu.Unlock()
}

// Calls counts requests by operation: encrypt, decrypt, keys, login.
func (tr *Transit) Calls(op string) int {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.calls[op]
}

func (tr *Transit) addVersion() error {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	tr.mu.Lock()
	tr.versions = append(tr.versions, aead)
	tr.mu.Unlock()
	return nil
}

func (tr *Transit) serve(w http.ResponseWriter, r *http.Request) {
	tr.mu.Lock()
	delay, forced := tr.delay, tr.status
	tr.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	op := ""
	switch {
	case path == "auth/kubernetes/login" && r.Method == http.MethodPost:
		op = "login"
	case path == tr.Mount+"/encrypt/"+tr.Key && r.Method == http.MethodPost:
		op = "encrypt"
	case path == tr.Mount+"/decrypt/"+tr.Key && r.Method == http.MethodPost:
		op = "decrypt"
	case path == tr.Mount+"/keys/"+tr.Key && r.Method == http.MethodGet:
		op = "keys"
	default:
		vaultError(w, http.StatusNotFound, "no handler for route "+r.URL.Path)
		return
	}
	tr.mu.Lock()
	tr.calls[op]++
	tr.mu.Unlock()
	if forced != 0 {
		vaultError(w, forced, "kmstest: forced status "+strconv.Itoa(forced))
		return
	}
	var body map[string]string
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			vaultError(w, http.StatusBadRequest, "bad JSON")
			return
		}
	}
	if op == "login" {
		if body["role"] != tr.Role || subtle.ConstantTimeCompare([]byte(body["jwt"]), []byte(tr.JWT)) != 1 {
			vaultError(w, http.StatusForbidden, "permission denied")
			return
		}
		tok := "s.login-" + randomHex(8)
		tr.mu.Lock()
		tr.issued[tok] = true
		tr.mu.Unlock()
		writeJSON(w, map[string]any{"auth": map[string]any{"client_token": tok, "lease_duration": tr.LeaseSeconds}})
		return
	}
	tok := r.Header.Get("X-Vault-Token")
	tr.mu.Lock()
	ok := subtle.ConstantTimeCompare([]byte(tok), []byte(tr.Token)) == 1 || tr.issued[tok]
	tr.mu.Unlock()
	if !ok {
		vaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	switch op {
	case "keys":
		tr.mu.Lock()
		n := len(tr.versions)
		tr.mu.Unlock()
		writeJSON(w, map[string]any{"data": map[string]any{"latest_version": n, "type": "aes256-gcm96"}})
	case "encrypt":
		pt, err := base64.StdEncoding.DecodeString(body["plaintext"])
		if err != nil {
			vaultError(w, http.StatusBadRequest, "plaintext is not base64")
			return
		}
		tr.mu.Lock()
		v := len(tr.versions)
		aead := tr.versions[v-1]
		tr.mu.Unlock()
		nonce := make([]byte, aead.NonceSize())
		_, _ = io.ReadFull(rand.Reader, nonce)
		ct := aead.Seal(nonce, nonce, pt, nil)
		writeJSON(w, map[string]any{"data": map[string]any{
			"ciphertext":  fmt.Sprintf("vault:v%d:%s", v, base64.StdEncoding.EncodeToString(ct)),
			"key_version": v,
		}})
	case "decrypt":
		ct := body["ciphertext"]
		rest, ok := strings.CutPrefix(ct, "vault:v")
		num, b64, ok2 := strings.Cut(rest, ":")
		v, err := strconv.Atoi(num)
		tr.mu.Lock()
		valid := ok && ok2 && err == nil && v >= 1 && v <= len(tr.versions)
		var aead cipher.AEAD
		if valid {
			aead = tr.versions[v-1]
		}
		tr.mu.Unlock()
		raw, derr := base64.StdEncoding.DecodeString(b64)
		if !valid || derr != nil || len(raw) < 12 {
			vaultError(w, http.StatusBadRequest, "invalid ciphertext")
			return
		}
		pt, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], nil)
		if err != nil {
			vaultError(w, http.StatusBadRequest, "cipher: message authentication failed")
			return
		}
		writeJSON(w, map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(pt)}})
	}
}

func vaultError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{msg}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, b)
	return fmt.Sprintf("%x", b)
}
