package hubdoctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
)

// kubeGuardTLS writes a readable cert/key pair. The checks only stat them, so
// the contents do not have to be real TLS material.
func kubeGuardTLS(t *testing.T) (cert, key string) {
	t.Helper()
	dir := t.TempDir()
	cert = filepath.Join(dir, "monitor.crt")
	key = filepath.Join(dir, "monitor.key")
	for _, p := range []string{cert, key} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	return cert, key
}

func TestKubeGuardDisabledOnAHostOnlyHubIsAPass(t *testing.T) {
	got := findingsFor(t, t.TempDir(), hostOnlyConfig(), Options{Offline: true})
	f := only(t, got, "kubeguard.enabled")
	wantSeverity(t, f, SeverityPass)
	if !strings.Contains(f.Message, "no Kubernetes executor or kubeconfig secret") {
		t.Fatalf("message does not explain why this is fine: %q", f.Message)
	}
}

// TestKubeGuardDisabledWithKubernetesWarns is the finding the check exists for:
// nothing is broken, nothing else reports, and a sandbox is holding a cluster
// credential whose namespace list nothing enforces.
func TestKubeGuardDisabledWithKubernetesWarns(t *testing.T) {
	got := findingsFor(t, t.TempDir(), cloningConfig(), Options{Offline: true})
	f := only(t, got, "kubeguard.enabled")
	wantSeverity(t, f, SeverityWarn)
	// The message has to say the allowlist is unenforced, not merely weakly
	// enforced — that is the whole difference from the git proxy's warning.
	if !strings.Contains(f.Message, "default kubectl uses without -n") {
		t.Fatalf("message does not say the namespace list is unenforced: %q", f.Message)
	}
	if !strings.Contains(f.Remediation, "executors.kube_guard.enabled: true") {
		t.Fatalf("remediation does not name the setting: %q", f.Remediation)
	}
}

func TestKubeGuardEnabledAndWellConfiguredPasses(t *testing.T) {
	cert, key := kubeGuardTLS(t)
	cfg := cloningConfig()
	cfg.Executors.KubeGuard = config.KubeGuardConfig{
		Enabled: true, CertFile: cert, KeyFile: key,
		AdvertiseURL: "https://hub.internal:8444",
	}
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	f := only(t, got, "kubeguard.enabled")
	wantSeverity(t, f, SeverityPass)
	// An unset floor is "no verb ceiling", not "read-only" — Summary would
	// otherwise call an absent ceiling the tightest one, which is backwards.
	if !strings.Contains(f.Message, "no verb ceiling") {
		t.Fatalf("the pass does not state the policy in force: %q", f.Message)
	}
	for _, unwanted := range []string{"kubeguard.tls", "kubeguard.advertise_url", "kubeguard.verbs"} {
		if len(got[unwanted]) != 0 {
			t.Fatalf("a well-configured monitor still produced %s: %+v", unwanted, got[unwanted])
		}
	}
}

func TestKubeGuardEnabledWithoutTLSMaterialFails(t *testing.T) {
	cfg := cloningConfig()
	cfg.Executors.KubeGuard = config.KubeGuardConfig{
		Enabled: true, AdvertiseURL: "https://hub.internal:8444",
	}
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	if len(got["kubeguard.tls"]) != 2 {
		t.Fatalf("want one finding per missing file, got %d", len(got["kubeguard.tls"]))
	}
	for _, f := range got["kubeguard.tls"] {
		wantSeverity(t, f, SeverityFail)
	}
}

func TestKubeGuardUnreadableCAFails(t *testing.T) {
	cert, key := kubeGuardTLS(t)
	cfg := cloningConfig()
	cfg.Executors.KubeGuard = config.KubeGuardConfig{
		Enabled: true, CertFile: cert, KeyFile: key,
		CAFile:       filepath.Join(t.TempDir(), "absent.pem"),
		AdvertiseURL: "https://hub.internal:8444",
	}
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	if len(got["kubeguard.tls"]) != 1 {
		t.Fatalf("want one finding for the unreadable ca_file, got %d", len(got["kubeguard.tls"]))
	}
	wantSeverity(t, got["kubeguard.tls"][0], SeverityFail)
}

func TestKubeGuardLoopbackAdvertiseWarns(t *testing.T) {
	cert, key := kubeGuardTLS(t)
	cfg := cloningConfig()
	cfg.Executors.KubeGuard = config.KubeGuardConfig{
		Enabled: true, CertFile: cert, KeyFile: key,
		AdvertiseURL: "https://127.0.0.1:8444",
	}
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	f := only(t, got, "kubeguard.advertise_url")
	wantSeverity(t, f, SeverityWarn)
	if !strings.Contains(f.Message, "kubectl inside the sandbox") {
		t.Fatalf("message does not name the symptom: %q", f.Message)
	}
}

// TestKubeGuardWriteFloorWarns: the verb floor is the setting that decides
// whether any project on the hub can change a cluster, so widening it is
// deliberate and worth stating.
func TestKubeGuardWriteFloorWarns(t *testing.T) {
	cert, key := kubeGuardTLS(t)
	cfg := cloningConfig()
	cfg.Executors.KubeGuard = config.KubeGuardConfig{
		Enabled: true, CertFile: cert, KeyFile: key,
		AdvertiseURL: "https://hub.internal:8444",
		Verbs:        []string{"get", "list", "watch", "create", "delete"},
	}
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	f := only(t, got, "kubeguard.verbs")
	wantSeverity(t, f, SeverityWarn)
	if !strings.Contains(f.Remediation, "--verbs") {
		t.Fatalf("remediation does not point at the per-project alternative: %q", f.Remediation)
	}
	// And the default does not warn.
	cfg.Executors.KubeGuard.Verbs = nil
	if got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true}); len(got["kubeguard.verbs"]) != 0 {
		t.Fatalf("the read-only default warned: %+v", got["kubeguard.verbs"])
	}
}
