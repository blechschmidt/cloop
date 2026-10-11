package localprocess

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

func testGitCA(t *testing.T) *executor.GitCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "hub CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &executor.GitCA{URLs: []string{"https://hub.internal:8443/"},
		PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// TestHostProcessTrustsTheHubCAForTheProxyOnly: the workload's git is told to
// trust the hub's CA through http.<url>.sslCAInfo for the proxy's URL — never
// GIT_SSL_CAINFO — in a file that is gone once the workload ends. Inherited
// and explicit environments both get it.
func TestHostProcessTrustsTheHubCAForTheProxyOnly(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
	}{
		{"inherited", nil},
		{"explicit", []string{"PATH=" + os.Getenv("PATH"), "GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=core.hooksPath", "GIT_CONFIG_VALUE_0=/dev/null"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := testGitCA(t)
			spec := executor.Spec{
				WorkDir: t.TempDir(),
				Argv: []string{"/bin/sh", "-c", `i=0; while [ "$i" -lt "$GIT_CONFIG_COUNT" ]; do
eval k=\$GIT_CONFIG_KEY_$i; eval v=\$GIT_CONFIG_VALUE_$i; echo "pair $k=$v"; i=$((i+1)); done
echo "cainfo=${GIT_SSL_CAINFO:-unset}"
eval f=\$GIT_CONFIG_VALUE_$((GIT_CONFIG_COUNT-1)); head -1 "$f"`},
				Env:   tc.env,
				GitCA: ca,
			}
			res, err := executor.Run(context.Background(), New("test"), spec)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			out := string(res.Output)
			m := regexp.MustCompile(`pair http\.https://hub\.internal:8443/\.sslCAInfo=(\S+)`).FindStringSubmatch(out)
			if m == nil {
				t.Fatalf("no per-URL trust for the proxy in:\n%s", out)
			}
			if !strings.Contains(out, "cainfo=unset") {
				t.Errorf("GIT_SSL_CAINFO was set, which replaces the trust store:\n%s", out)
			}
			if !strings.Contains(out, "-----BEGIN CERTIFICATE-----") {
				t.Errorf("the named file is not the CA:\n%s", out)
			}
			if tc.env != nil && !strings.Contains(out, "pair core.hooksPath=/dev/null") {
				t.Errorf("the existing GIT_CONFIG_COUNT block was replaced rather than joined:\n%s", out)
			}
			if _, err := os.Stat(m[1]); !os.IsNotExist(err) {
				t.Errorf("the CA file %s outlived the workload (stat: %v)", m[1], err)
			}
		})
	}
}
