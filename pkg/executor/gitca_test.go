package executor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testCA returns a CA certificate's PEM and the PEM of its private key.
func testCA(t *testing.T, isCA bool) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestGitCAValidate(t *testing.T) {
	caPEM, keyPEM := testCA(t, true)
	leafPEM, _ := testCA(t, false)
	ok := &GitCA{URLs: []string{"https://hub.internal:8443/"}, PEM: caPEM}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a CA for one URL: %v", err)
	}
	for name, c := range map[string]*GitCA{
		// The refusal that matters: a key must never ride to a sandbox here.
		"a private key beside the CA": {URLs: ok.URLs, PEM: append(append([]byte(nil), caPEM...), keyPEM...)},
		"a private key alone":         {URLs: ok.URLs, PEM: keyPEM},
		"a leaf, not a CA":            {URLs: ok.URLs, PEM: leafPEM},
		"no URL":                      {PEM: caPEM},
		"an http URL":                 {URLs: []string{"http://hub.internal:8443/"}, PEM: caPEM},
		"a URL not in normal form":    {URLs: []string{"https://HUB.internal:8443"}, PEM: caPEM},
		"no PEM":                      {URLs: ok.URLs},
		"trailing junk":               {URLs: ok.URLs, PEM: append(append([]byte(nil), caPEM...), "junk"...)},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// And Spec.Validate runs it, so no driver writes a bad bundle.
	spec := Spec{Argv: []string{"true"}, GitCA: &GitCA{URLs: ok.URLs, PEM: keyPEM}}
	if err := spec.Validate(); err == nil {
		t.Error("Spec.Validate accepted a git_ca holding a private key")
	}
}

// TestGitCAIsScopedToItsURL: the configuration names the proxy's URL only, and
// Covers agrees with git's prefix-at-a-slash matching.
func TestGitCAIsScopedToItsURL(t *testing.T) {
	caPEM, _ := testCA(t, true)
	c := &GitCA{URLs: []string{"https://hub.internal:8443/"}, PEM: caPEM}
	pairs := c.ConfigPairs("/etc/cloop/hub-ca/ca.crt")
	if len(pairs) != 1 || pairs[0][0] != "http.https://hub.internal:8443/.sslCAInfo" {
		t.Fatalf("pairs = %v", pairs)
	}
	for url, want := range map[string]bool{
		"https://hub.internal:8443/acme/tool":       true,
		"https://hub.internal:8443":                 true,
		"https://HUB.internal:8443/acme/tool.git":   true,
		"https://hub.internal:8444/acme/tool":       false,
		"https://hub.internal:8443.evil.example/x":  false,
		"https://github.com/acme/tool":              false,
		"http://hub.internal:8443/acme/tool":        false,
		"https://user@hub.internal:8443/acme/tool":  false,
		"https://other.internal:8443/acme/tool.git": false,
	} {
		if got := c.Covers(url); got != want {
			t.Errorf("Covers(%q) = %v, want %v", url, got, want)
		}
	}
}

func TestWithGitConfigJoinsTheExistingBlock(t *testing.T) {
	env := []string{"A=1", "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=core.x", "GIT_CONFIG_VALUE_0=y"}
	out, err := WithGitConfig(env, [][2]string{{"http.https://h/.sslCAInfo", "/ca"}})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(out, " ")
	for _, want := range []string{"GIT_CONFIG_COUNT=2", "GIT_CONFIG_KEY_1=http.https://h/.sslCAInfo",
		"GIT_CONFIG_VALUE_1=/ca", "GIT_CONFIG_KEY_0=core.x"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	if strings.Count(got, "GIT_CONFIG_COUNT=") != 1 {
		t.Errorf("two counts: %s", got)
	}
	if _, err := WithGitConfig([]string{"GIT_CONFIG_COUNT=x"}, [][2]string{{"k", "v"}}); err == nil {
		t.Error("a count that is not a number was overwritten")
	}
}

// TestNeedsGitCA: only a workload that talks to the proxy needs the CA, which
// is what lets an older device keep running everything else.
func TestNeedsGitCA(t *testing.T) {
	caPEM, _ := testCA(t, true)
	ca := &GitCA{URLs: []string{"https://hub.internal:8443/"}, PEM: caPEM}
	base := Spec{Argv: []string{"true"}, GitCA: ca}
	if base.NeedsGitCA("") {
		t.Error("a workload that never reaches the proxy needs the CA")
	}
	lease := base
	lease.Env = []string{"CLOOP_GIT_PROXY_URL=https://hub.internal:8443"}
	if !lease.NeedsGitCA("") {
		t.Error("a guarded lease's workload does not need the CA")
	}
	if !base.NeedsGitCA("https://hub.internal:8443/acme/tool") {
		t.Error("a workspace routed through the proxy does not need the CA")
	}
	if base.NeedsGitCA("https://github.com/acme/tool") {
		t.Error("a workspace fetched from the forge needs the CA")
	}
	none := lease
	none.GitCA = nil
	if none.NeedsGitCA("") {
		t.Error("a spec with no CA needs one")
	}
}
