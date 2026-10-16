package container

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// TestStageGitCAHandsTheBundleToNodeOnlyWhenAsked: a sandbox whose harness
// talks to the hub's model relay (Task 20435) gets NODE_EXTRA_CA_CERTS naming
// the bundle mounted read-only at /etc/cloop/hub-ca/ca.crt; one that did not
// ask gets git's per-URL trust and no Node trust.
func TestStageGitCAHandsTheBundleToNodeOnlyWhenAsked(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "hub CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	e := fakeExecutor(t, Options{StageDir: t.TempDir()})
	for _, node := range []bool{true, false} {
		spec := executor.Spec{Argv: []string{"true"}, Env: []string{"A=1"},
			GitCA: &executor.GitCA{URLs: []string{"https://hub.internal:8443/"}, PEM: caPEM, Node: node}}
		out, m, dir, err := e.stageGitCA(spec)
		if err != nil {
			t.Fatalf("stageGitCA: %v", err)
		}
		if m == nil || m.TargetPath != executor.SandboxGitCADir || !m.ReadOnly {
			t.Fatalf("mount %+v", m)
		}
		if b, err := os.ReadFile(filepath.Join(dir, executor.SandboxGitCAFileName)); err != nil || string(b) != string(caPEM) {
			t.Fatalf("staged bundle %q, %v", b, err)
		}
		has := false
		for _, kv := range out.Env {
			if kv == executor.NodeCAEnvKey+"="+executor.SandboxGitCAFile {
				has = true
			}
			if strings.HasPrefix(kv, "GIT_SSL_CAINFO=") {
				t.Errorf("GIT_SSL_CAINFO set: %s", kv)
			}
		}
		if has != node {
			t.Errorf("node=%v: NODE_EXTRA_CA_CERTS present=%v in %v", node, has, out.Env)
		}
		if len(spec.Env) != 1 {
			t.Errorf("the caller's environment was rewritten: %v", spec.Env)
		}
		removeGitCA(dir)
	}
}
