package kms_test

// Transit against a real Vault or OpenBao (Task 20433).
//
// The rest of this package's Transit tests run against kmstest.Transit, which
// answers the API as the hub uses it. This one runs against the real server,
// because the claims worth checking are the server's: that the three
// capabilities docs/operations/runbook.md tells an operator to grant are
// enough, and that what they deny is denied; that a key rotated with the
// server's own endpoint is followed; that the server's ciphertext format and
// key versions are what the client parses.
//
// It needs a dev server and a token able to configure it:
//
//	docker run -d --name kms-vault -p 8200:8200 hashicorp/vault:1.18.0 \
//	  server -dev -dev-root-token-id=root -dev-listen-address=0.0.0.0:8200
//	CLOOP_KMS_VAULT_ADDR=http://127.0.0.1:8200 CLOOP_KMS_VAULT_TOKEN=root \
//	  go test ./pkg/kms -run RealVault -v
//
// (openbao/openbao takes the same arguments.) Without the variables it skips —
// unless CLOOP_KMS_VAULT_REQUIRED is set, as CI sets it, where a skip would be
// a gate that is not one.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// vaultAdmin calls the server with the configuring token.
type vaultAdmin struct {
	t     *testing.T
	addr  string
	token string
}

func (v vaultAdmin) call(method, path string, body any) map[string]any {
	v.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, v.addr+"/v1/"+path, rd)
	if err != nil {
		v.t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", v.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		v.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		v.t.Fatalf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, data)
	}
	out := map[string]any{}
	if len(data) > 0 {
		_ = json.Unmarshal(data, &out)
	}
	return out
}

// policyToken mints a token holding exactly the capabilities in policy.
func (v vaultAdmin) policyToken(name, policy string) string {
	v.t.Helper()
	v.call(http.MethodPut, "sys/policies/acl/"+name, map[string]any{"policy": policy})
	out := v.call(http.MethodPost, "auth/token/create", map[string]any{"policies": []string{name}, "ttl": "15m",
		"no_default_policy": true})
	auth, _ := out["auth"].(map[string]any)
	tok, _ := auth["client_token"].(string)
	if tok == "" {
		v.t.Fatalf("no token for policy %s: %v", name, out)
	}
	return tok
}

func TestTransitAgainstARealVault(t *testing.T) {
	addr, admin := os.Getenv("CLOOP_KMS_VAULT_ADDR"), os.Getenv("CLOOP_KMS_VAULT_TOKEN")
	if addr == "" || admin == "" {
		if os.Getenv("CLOOP_KMS_VAULT_REQUIRED") != "" {
			t.Fatal("CLOOP_KMS_VAULT_REQUIRED is set and CLOOP_KMS_VAULT_ADDR / CLOOP_KMS_VAULT_TOKEN are not")
		}
		t.Skip("set CLOOP_KMS_VAULT_ADDR and CLOOP_KMS_VAULT_TOKEN to run against a real Vault or OpenBao dev server")
	}
	t.Cleanup(secretbroker.ForgetOpenedKeys)
	v := vaultAdmin{t: t, addr: strings.TrimRight(addr, "/"), token: admin}
	mount := fmt.Sprintf("cloop-kms-%d", time.Now().UnixNano())
	v.call(http.MethodPost, "sys/mounts/"+mount, map[string]any{"type": "transit"})
	t.Cleanup(func() {
		req, _ := http.NewRequest(http.MethodDelete, v.addr+"/v1/sys/mounts/"+mount, nil)
		req.Header.Set("X-Vault-Token", admin)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	})
	v.call(http.MethodPost, mount+"/keys/cloop", map[string]any{"type": "aes256-gcm96"})

	// Exactly the policy the runbook documents, and nothing else.
	least := v.policyToken(mount+"-hub", fmt.Sprintf(`
path "%[1]s/encrypt/cloop" { capabilities = ["update"] }
path "%[1]s/decrypt/cloop" { capabilities = ["update"] }
path "%[1]s/keys/cloop"    { capabilities = ["read"] }
`, mount))
	tokenFile := filepath.Join(t.TempDir(), "vault-token")
	if err := os.WriteFile(tokenFile, []byte(least), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.KMSConfig{Provider: config.KMSProviderTransit, Timeout: "10s",
		Transit: config.KMSTransitConfig{Address: v.addr, Mount: mount, Key: "cloop", TokenFile: tokenFile}}
	if err := config.ValidateSecrets(config.SecretsConfig{KMS: cfg}); err != nil {
		t.Fatal(err)
	}
	prov, err := kms.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer prov.Close()
	ctx := context.Background()
	st, err := prov.Status(ctx)
	if err != nil || st.KeyID != mount+"/cloop:v1" {
		t.Fatalf("status with the documented policy: %+v, %v", st, err)
	}

	// The keyring over a real database: minted, sealed, reopened through
	// Vault alone.
	m := newMember(t, statedbtest.Path(t))
	root := secretbroker.KMSRoot(prov)
	kr := m.mustKeyring(t, root, secretbroker.Root{})
	want := map[string]string{mint(t, m.broker(t, kr), "s", "real-vault-value"): "real-vault-value"}
	secretbroker.ForgetOpenedKeys()
	opens(t, m, m.mustKeyring(t, root, secretbroker.Root{}), want)

	// A rotation with Vault's own endpoint is followed.
	v.call(http.MethodPost, mount+"/keys/cloop/rotate", nil)
	kr = m.mustKeyring(t, root, secretbroker.Root{})
	rep, err := kr.RewrapKMS(ctx)
	if err != nil || rep.Rewrapped != 1 || rep.CurrentKey != mount+"/cloop:v2" {
		t.Fatalf("rewrap after rotation: %+v, %v", rep, err)
	}
	secretbroker.ForgetOpenedKeys()
	opens(t, m, m.mustKeyring(t, root, secretbroker.Root{}), want)

	// What the policy does not grant is refused, as a refusal: an identity
	// that may encrypt and not decrypt mints nothing.
	encryptOnly := v.policyToken(mount+"-encrypt-only", fmt.Sprintf(`
path "%[1]s/encrypt/cloop" { capabilities = ["update"] }
path "%[1]s/keys/cloop"    { capabilities = ["read"] }
`, mount))
	if err := os.WriteFile(tokenFile, []byte(encryptOnly), 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := newMember(t, statedbtest.Path(t))
	_, err = fresh.keyring(t, root, secretbroker.Root{})
	if err == nil || !strings.Contains(err.Error(), "would not unwrap it again") {
		t.Fatalf("an encrypt-only identity: %v", err)
	}
	if rows := kekRows(t, fresh); len(rows) != 0 {
		t.Fatalf("an encrypt-only identity recorded %d key(s)", len(rows))
	}
	// And a revoked identity cannot open the store at all.
	v.call(http.MethodPost, "auth/token/revoke", map[string]any{"token": least})
	if err := os.WriteFile(tokenFile, []byte(least), 0o600); err != nil {
		t.Fatal(err)
	}
	secretbroker.ForgetOpenedKeys()
	_, err = m.keyring(t, root, secretbroker.Root{})
	if err == nil || errors.Is(err, secretbroker.ErrKMSUnavailable) || !strings.Contains(err.Error(), "refused this hub's identity") {
		t.Fatalf("a revoked identity is not refused as one: %v", err)
	}
}
