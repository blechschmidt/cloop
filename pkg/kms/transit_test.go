package kms_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/kms/kmstest"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

func writeToken(t *testing.T, tok string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault-token")
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func transitConfig(tr *kmstest.Transit, tokenFile string) config.KMSConfig {
	return config.KMSConfig{
		Provider: config.KMSProviderTransit,
		Timeout:  "2s",
		Transit: config.KMSTransitConfig{
			Address: tr.URL(), Mount: tr.Mount, Key: tr.Key, TokenFile: tokenFile,
		},
	}
}

func openTransit(t *testing.T, cfg config.KMSConfig) kms.Provider {
	t.Helper()
	if err := config.ValidateSecrets(config.SecretsConfig{KMS: cfg}); err != nil {
		t.Fatalf("config refused: %v", err)
	}
	prov, err := kms.Open(cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = prov.Close() })
	return prov
}

// Transit wraps and unwraps through Vault's HTTP API, reports the key's latest
// version, and follows a rotation.
func TestTransitRoundTripAndRotation(t *testing.T) {
	tr := kmstest.StartTransit(t)
	prov := openTransit(t, transitConfig(tr, writeToken(t, tr.Token)))
	ctx := context.Background()

	cur, err := prov.CurrentKeyID(ctx)
	if err != nil || cur != "transit/cloop:v1" {
		t.Fatalf("current key = %q, %v", cur, err)
	}
	secret := bytes.Repeat([]byte{0x42}, 32)
	ct, err := prov.Encrypt(ctx, secret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if ct.KeyID != "transit/cloop:v1" || !bytes.HasPrefix(ct.Ciphertext, []byte("vault:v1:")) {
		t.Fatalf("ciphertext = %q / %q", ct.KeyID, ct.Ciphertext)
	}
	got, err := prov.Decrypt(ctx, ct)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("decrypt = %x, %v", got, err)
	}

	if v := tr.Rotate(); v != 2 {
		t.Fatalf("rotate gave v%d", v)
	}
	if cur, _ := prov.CurrentKeyID(ctx); cur != "transit/cloop:v2" {
		t.Fatalf("after rotation the current key is %q", cur)
	}
	if again, err := prov.Decrypt(ctx, ct); err != nil || !bytes.Equal(again, secret) {
		t.Fatalf("v1 ciphertext after rotation: %v", err)
	}
	if !strings.HasPrefix(prov.Name(), "transit:127.0.0.1:") || !strings.HasSuffix(prov.Name(), "/transit/cloop") {
		t.Fatalf("default name = %q", prov.Name())
	}
}

// The token file is re-read on every call, as a Vault Agent sink renews it in
// place; a wrong token is a refusal, not an outage.
func TestTransitTokenFileIsReReadAndRefusalIsDenied(t *testing.T) {
	tr := kmstest.StartTransit(t)
	path := writeToken(t, "s.not-the-token")
	prov := openTransit(t, transitConfig(tr, path))
	ctx := context.Background()

	_, err := prov.Encrypt(ctx, bytes.Repeat([]byte{1}, 32))
	var ke *kms.Error
	if !errors.As(err, &ke) || ke.Result != kms.ResultDenied || kms.Unreachable(err) {
		t.Fatalf("a wrong token: %v", err)
	}
	if err := os.WriteFile(path, []byte(tr.Token), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := prov.Encrypt(ctx, bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatalf("the renewed token was not read: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := prov.Encrypt(ctx, bytes.Repeat([]byte{1}, 32)); err == nil ||
		!strings.Contains(err.Error(), "every user on the host") {
		t.Fatalf("a token file anyone can rewrite was used: %v", err)
	}
}

// The Kubernetes auth method logs in with the service account token, and logs
// in again when Vault stops honouring the token it issued.
func TestTransitKubernetesLogin(t *testing.T) {
	tr := kmstest.StartTransit(t)
	jwt := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(jwt, []byte(tr.JWT), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := transitConfig(tr, "")
	cfg.Transit.Kubernetes = config.KMSTransitKubernetesAuth{Role: tr.Role, TokenFile: jwt}
	prov := openTransit(t, cfg)
	ctx := context.Background()

	if _, err := prov.Encrypt(ctx, bytes.Repeat([]byte{3}, 32)); err != nil {
		t.Fatalf("encrypt after login: %v", err)
	}
	if tr.Calls("login") != 1 {
		t.Fatalf("logins = %d, want 1", tr.Calls("login"))
	}
	if _, err := prov.Encrypt(ctx, bytes.Repeat([]byte{3}, 32)); err != nil || tr.Calls("login") != 1 {
		t.Fatalf("the login was not reused: logins = %d, %v", tr.Calls("login"), err)
	}
	tr.RevokeIssued()
	if _, err := prov.Encrypt(ctx, bytes.Repeat([]byte{3}, 32)); err != nil {
		t.Fatalf("no new login after the token was revoked: %v", err)
	}
	if tr.Calls("login") != 2 {
		t.Fatalf("logins = %d, want 2", tr.Calls("login"))
	}
}

// A sealed Vault (503) is unreachable; a slow one times out.
func TestTransitSealedAndSlow(t *testing.T) {
	tr := kmstest.StartTransit(t)
	cfg := transitConfig(tr, writeToken(t, tr.Token))
	cfg.Timeout = "300ms"
	prov := openTransit(t, cfg)
	ctx := context.Background()

	tr.SetStatus(http.StatusServiceUnavailable)
	if _, err := prov.Status(ctx); err == nil || !kms.Unreachable(err) {
		t.Fatalf("a sealed Vault: %v", err)
	}
	tr.SetStatus(0)
	tr.SetDelay(2 * time.Second)
	var ke *kms.Error
	if _, err := prov.Decrypt(ctx, kmsCiphertext("vault:v1:AAAA")); !errors.As(err, &ke) || ke.Result != kms.ResultTimeout {
		t.Fatalf("a slow Vault: %v", err)
	}
}

// A redirect to another server is not followed: the token would go with it.
func TestTransitRefusesARedirectToAnotherServer(t *testing.T) {
	var leaked string
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("X-Vault-Token")
	}))
	defer elsewhere.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.Replace(elsewhere.URL, "127.0.0.1", "localhost", 1)+r.URL.Path,
			http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	cfg := config.KMSConfig{Provider: config.KMSProviderTransit, Timeout: "2s", Transit: config.KMSTransitConfig{
		Address: redirector.URL, Key: "cloop", TokenFile: writeToken(t, "s.must-not-leak")}}
	prov := openTransit(t, cfg)
	if _, err := prov.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "another server") {
		t.Fatalf("redirect: %v", err)
	}
	if leaked != "" {
		t.Fatal("the token was sent to the server Vault redirected to")
	}
}

// Plain http to a host that is not loopback is refused at configuration.
func TestTransitRefusesPlaintextOffTheHost(t *testing.T) {
	err := config.ValidateSecrets(config.SecretsConfig{KMS: config.KMSConfig{Provider: config.KMSProviderTransit,
		Transit: config.KMSTransitConfig{Address: "http://vault.example.com:8200", Key: "cloop", TokenFile: "/run/t"}}})
	if err == nil || !strings.Contains(err.Error(), "plain http") {
		t.Fatalf("plain http off the host: %v", err)
	}
	for _, bad := range []config.KMSTransitConfig{
		{Address: "https://v:8200", Key: "cloop"}, // no auth
		{Address: "https://v:8200", Key: "cloop", TokenFile: "/t", Kubernetes: config.KMSTransitKubernetesAuth{Role: "r"}},
		{Address: "https://v:8200", Key: "a/b", TokenFile: "/t"},
		{Address: "https://user:pw@v:8200", Key: "cloop", TokenFile: "/t"},
		{Address: "https://v:8200", Key: "cloop", TokenFile: "relative"},
	} {
		if err := config.ValidateSecrets(config.SecretsConfig{KMS: config.KMSConfig{
			Provider: config.KMSProviderTransit, Transit: bad}}); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func kmsCiphertext(s string) secretbroker.KMSCiphertext {
	return secretbroker.KMSCiphertext{Ciphertext: []byte(s)}
}
