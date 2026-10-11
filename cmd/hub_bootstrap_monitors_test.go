package cmd

// The credential monitors in the hosted profile (Task 20409): `cloop hub
// bootstrap` turns on the git interception proxy and the Kubernetes access
// monitor with tls: auto, at advertise URLs derived from --external-url, and
// the rendered file is pinned against a golden copy so a change to what an
// operator is told is a reviewed change.

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
)

var updateBootstrapGolden = flag.Bool("update-bootstrap-golden", false,
	"rewrite cmd/testdata/hub_bootstrap.golden.yaml from the current template")

// bootstrapGolden is resolved while the working directory is still this
// package's: other tests here change it, and a relative path read after them
// names a file that is not there.
var bootstrapGolden = func() string {
	p, err := filepath.Abs(filepath.Join("testdata", "hub_bootstrap.golden.yaml"))
	if err != nil {
		return filepath.Join("testdata", "hub_bootstrap.golden.yaml")
	}
	return p
}()

func TestHubBootstrap_EnablesBothCredentialMonitors(t *testing.T) {
	dir := t.TempDir()
	cfg := bootstrapInto(t, dir, "--external-url", "https://hub.example.com")

	gp, kg := cfg.Executors.GitProxy, cfg.Executors.KubeGuard
	if !gp.Enabled || !gp.AutoTLS() {
		t.Errorf("git_proxy = %+v, want enabled with tls: auto", gp)
	}
	if gp.AdvertiseURL != "https://hub.example.com:8443" || gp.ListenAddr != "0.0.0.0:8443" {
		t.Errorf("git_proxy at %q, listening on %q", gp.AdvertiseURL, gp.ListenAddr)
	}
	if !kg.Enabled || !kg.AutoTLS() {
		t.Errorf("kube_guard = %+v, want enabled with tls: auto", kg)
	}
	if kg.AdvertiseURL != "https://hub.example.com:8444" || kg.ListenAddr != "0.0.0.0:8444" {
		t.Errorf("kube_guard at %q, listening on %q", kg.AdvertiseURL, kg.ListenAddr)
	}
	// Neither may be switched off at load: a bootstrap whose monitors the
	// loader quietly disabled would hand out credentials while its file says
	// it does not.
	for _, r := range cfg.LoadRepairs() {
		t.Errorf("the generated config was repaired at load: %+v", r)
	}
	// And no files: the hub issues the certificates.
	if gp.CertFile != "" || gp.KeyFile != "" || kg.CertFile != "" || kg.KeyFile != "" || kg.CAFile != "" {
		t.Errorf("the generated config names certificate files under tls: auto: %+v %+v", gp, kg)
	}
}

func TestHubBootstrap_MonitorPorts(t *testing.T) {
	cfg := bootstrapInto(t, t.TempDir(), "--external-url", "https://[2001:db8::7]:9000", "--port", "9000",
		"--git-proxy-port", "9443", "--kube-guard-port", "9444")
	if got := cfg.Executors.GitProxy.AdvertiseURL; got != "https://[2001:db8::7]:9443" {
		t.Errorf("git_proxy.advertise_url = %q", got)
	}
	if got := cfg.Executors.KubeGuard.ListenAddr; got != "0.0.0.0:9444" {
		t.Errorf("kube_guard.listen_addr = %q", got)
	}
	for _, args := range [][]string{
		{"--git-proxy-port", "8080"},                              // the dashboard's own
		{"--git-proxy-port", "9443", "--kube-guard-port", "9443"}, // one port, two monitors
		{"--kube-guard-port", "0"},
	} {
		if err := runBootstrap(t, t.TempDir(), args...); err == nil {
			t.Errorf("bootstrap accepted %v", args)
		}
	}
}

// TestHubBootstrap_Golden pins the whole generated config for one set of
// flags. Run with -update-bootstrap-golden to accept a deliberate change.
func TestHubBootstrap_Golden(t *testing.T) {
	dir := t.TempDir()
	if err := runBootstrap(t, dir, "--external-url", "https://hub.example.com",
		"--tls-cert", "/etc/cloop/tls/cert.pem", "--tls-key", "/etc/cloop/tls/key.pem"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	got, err := os.ReadFile(config.ConfigPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	golden := bootstrapGolden
	if *updateBootstrapGolden {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read %s (run with -update-bootstrap-golden to create it): %v", golden, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the generated config differs from %s; if the change is deliberate, rerun with "+
			"-update-bootstrap-golden.\n--- got ---\n%s", golden, got)
	}
	for _, want := range []string{"git_proxy:\n    enabled: true\n    tls: auto",
		"kube_guard:\n    enabled: true\n    tls: auto"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("the golden config does not carry %q", want)
		}
	}
}
