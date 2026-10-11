package ui

// hubtls_test.go covers the hub's half of tls: auto (Task 20409): a monitor
// whose section names no certificate files serves a leaf the hub issued from
// its own CA, both monitors share that CA, the kube guard embeds it in the
// kubeconfigs it issues, and every dispatch is told to trust it for the
// proxy's URL only.

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubca"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// autoTLSDir is a control plane with a sealing key, which tls: auto needs.
func autoTLSDir(t *testing.T) string {
	t.Helper()
	// Before anything seals: the agent's environment may carry another hub's
	// key (see the keyring tests' note on the ambient CLOOP_SECRET_KEY).
	t.Setenv(secretbroker.EnvPassphraseKey, "hubtls-test-passphrase")
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	return dir
}

func autoTLSConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Executors.GitProxy = config.GitProxyConfig{Enabled: true, ListenAddr: "127.0.0.1:0", TLS: config.MonitorTLSAuto}
	cfg.Executors.KubeGuard = config.KubeGuardConfig{Enabled: true, ListenAddr: "127.0.0.1:0", TLS: config.MonitorTLSAuto}
	return cfg
}

// dialWith opens a TLS connection to addr trusting only pemBytes.
func dialWith(addr string, pemBytes []byte) error {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemBytes)
	host, _, _ := net.SplitHostPort(addr)
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12})
	if err == nil {
		_ = conn.Close()
	}
	return err
}

// TestAutoTLSGitProxyServesALeafFromTheHubCA: no cert_file, no key_file, and a
// client that trusts the hub's CA — and nothing else — verifies the proxy.
func TestAutoTLSGitProxyServesALeafFromTheHubCA(t *testing.T) {
	dir := autoTLSDir(t)
	svc, err := startGitProxy(autoTLSConfig(), dir)
	if err != nil {
		t.Fatalf("startGitProxy with tls: auto: %v", err)
	}
	defer svc.Close()

	ca := svc.SandboxGitCA()
	if ca == nil {
		t.Fatal("an auto-TLS proxy offers sandboxes no CA")
	}
	if err := ca.Validate(); err != nil {
		t.Fatalf("the CA the hub would ship does not validate: %v", err)
	}
	if want := svc.BaseURL() + "/"; len(ca.URLs) != 1 || ca.URLs[0] != want {
		t.Errorf("CA trusted for %v, want exactly the proxy's URL %s", ca.URLs, want)
	}
	if err := dialWith(svc.Addr(), ca.PEM); err != nil {
		t.Fatalf("a client trusting the hub CA cannot verify the proxy: %v", err)
	}
	// The system roots do not know the hub's CA: what the sandbox is spared
	// having to bake in.
	if conn, err := tls.Dial("tcp", svc.Addr(), &tls.Config{ServerName: "127.0.0.1"}); err == nil {
		_ = conn.Close()
		t.Fatal("the proxy's certificate verified against the system roots")
	}
	// The leaf, not the CA, is what the listener serves, and it is short-lived.
	leaf := svc.certs.srv.Current()
	if leaf.Cert.IsCA || !hubca.Covers(leaf.Cert, []string{"127.0.0.1"}) {
		t.Errorf("served certificate IsCA=%v names %v", leaf.Cert.IsCA, leaf.SANs())
	}

	// The CA's private key is in the database sealed, never in the bundle.
	if strings.Contains(string(ca.PEM), "PRIVATE KEY") {
		t.Fatal("the bundle sandboxes are given holds a private key")
	}
}

// TestAutoTLSMonitorsShareOneCA: the git proxy and the kube guard chain to the
// same hub CA, and the kube guard embeds it in every kubeconfig it issues.
func TestAutoTLSMonitorsShareOneCA(t *testing.T) {
	dir := autoTLSDir(t)
	cfg := autoTLSConfig()
	gp, err := startGitProxy(cfg, dir)
	if err != nil {
		t.Fatalf("startGitProxy: %v", err)
	}
	defer gp.Close()
	kg, err := startKubeGuard(cfg, dir)
	if err != nil {
		t.Fatalf("startKubeGuard with tls: auto: %v", err)
	}
	defer kg.Close()

	if string(kg.certs.caPEM()) != string(gp.certs.caPEM()) {
		t.Fatal("the two monitors serve leaves from different CAs")
	}
	if string(kg.reg.CABundle) != string(gp.certs.caPEM()) {
		t.Fatal("the kube guard's kubeconfigs do not carry the hub CA")
	}
	if err := dialWith(kg.Addr(), kg.reg.CABundle); err != nil {
		t.Fatalf("a kubectl trusting the embedded CA cannot verify the monitor: %v", err)
	}
	if gp.certs.srv.Current().Serial == kg.certs.srv.Current().Serial {
		t.Fatal("the two monitors serve one leaf")
	}
}

// TestAutoTLSWithoutAKeyFailsClosed: the CA's private key is sealed under
// CLOOP_SECRET_KEY, so without one there is no proxy — and the refusal says
// which variable, rather than a certificate error.
func TestAutoTLSWithoutAKeyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	t.Setenv(secretbroker.EnvPassphraseKey, "")
	svc, err := startGitProxy(autoTLSConfig(), dir)
	if err == nil {
		svc.Close()
		t.Fatal("an auto-TLS proxy started with no sealing key")
	}
	if !strings.Contains(err.Error(), "CLOOP_SECRET_KEY") {
		t.Errorf("the refusal does not name the key: %v", err)
	}
}

// TestDispatchIsToldToTrustTheProxyOnly: applyGitProxyTrust attaches the CA
// for the running auto-TLS proxy, and nothing for one serving operator files.
func TestDispatchIsToldToTrustTheProxyOnly(t *testing.T) {
	prev := gitProxySingleton.Load()
	t.Cleanup(func() { gitProxySingleton.Store(prev) })

	dir := autoTLSDir(t)
	svc, err := startGitProxy(autoTLSConfig(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	gitProxySingleton.Store(svc)
	spec := applyGitProxyTrust(executor.Spec{Argv: []string{"true"}})
	if spec.GitCA == nil || !spec.GitCA.Covers(svc.BaseURL()+"/acme/tool") || spec.GitCA.Covers("https://github.com/acme/tool") {
		t.Fatalf("dispatch GitCA = %+v", spec.GitCA)
	}

	files, err := startGitProxy(gitProxyTestConfig(t), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	gitProxySingleton.Store(files)
	if got := applyGitProxyTrust(executor.Spec{Argv: []string{"true"}}); got.GitCA != nil {
		t.Fatal("a proxy serving the operator's files had the hub ship a CA it did not issue")
	}
	gitProxySingleton.Store(nil)
	if got := applyGitProxyTrust(executor.Spec{Argv: []string{"true"}}); got.GitCA != nil {
		t.Fatal("a hub with no proxy shipped a CA")
	}
}
