package hubdoctor

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// kubeGuardTLS returns a real certificate and key for the monitor.
func kubeGuardTLS(t *testing.T) (cert, key string) { return tlsPair(t, "monitor") }

func TestKubeGuardDisabledOnAHostOnlyHubIsAPass(t *testing.T) {
	got := findingsFor(t, t.TempDir(), hostOnlyConfig(), Options{Offline: true})
	f := only(t, got, "kubeguard.enabled")
	wantSeverity(t, f, SeverityPass)
	if !strings.Contains(f.Message, "no Kubernetes executor or kubeconfig grant") {
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
	f := only(t, got, "kubeguard.tls")
	wantSeverity(t, f, SeverityFail)
	if !strings.Contains(f.Message, "every kubeconfig lease is refused") {
		t.Fatalf("message does not state the consequence: %q", f.Message)
	}
	if fs := got["kubeguard.enabled"]; len(fs) != 0 {
		t.Fatalf("a monitor that will not start was also passed: %+v", fs)
	}
}

// TestKubeGuardCAFileThatIsADirectoryFails: the check used to stat ca_file,
// and a directory stats fine. The hub reads it, fails, and does not start the
// monitor; the doctor now reads it with the same method (Task 20387).
func TestKubeGuardCAFileThatIsADirectoryFails(t *testing.T) {
	cert, key := kubeGuardTLS(t)
	cfg := cloningConfig()
	cfg.Executors.KubeGuard = config.KubeGuardConfig{
		Enabled: true, CertFile: cert, KeyFile: key,
		CAFile:       t.TempDir(),
		AdvertiseURL: "https://hub.internal:8444",
	}
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	f := only(t, got, "kubeguard.tls")
	wantSeverity(t, f, SeverityFail)
	if !strings.Contains(f.Message, "will not start") {
		t.Errorf("want the startup consequence, got %q", f.Message)
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
// TestKubeGuardAdvertiseIsJudgedByTheHubsRules: the base a kubeconfig names is
// what kubeguard.NormalizeBaseURL accepts — a path it refuses means no monitor,
// not a warning — and "this machine only" is decided by parsing the host, not
// by the substring match that flagged https://localhost.corp.example (Task 20387).
func TestKubeGuardAdvertiseIsJudgedByTheHubsRules(t *testing.T) {
	cert, key := kubeGuardTLS(t)
	for _, tc := range []struct {
		adv  string
		want Severity // "" = no advertise finding
	}{
		{"https://localhost.corp.example:8444", ""},
		{"https://127.0.0.2:8444", SeverityWarn},
		{"https://monitor.localhost:8444", SeverityWarn},
		{"https://hub.internal:8444/k8s", SeverityFail},
		{"https://:8444", SeverityFail},
	} {
		t.Run(tc.adv, func(t *testing.T) {
			cfg := cloningConfig()
			cfg.Executors.KubeGuard = config.KubeGuardConfig{
				Enabled: true, CertFile: cert, KeyFile: key, AdvertiseURL: tc.adv,
			}
			got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
			fs := got["kubeguard.advertise_url"]
			if tc.want == "" {
				if len(fs) != 0 {
					t.Errorf("want no finding, got %+v", fs)
				}
				return
			}
			wantSeverity(t, only(t, got, "kubeguard.advertise_url"), tc.want)
			if tc.want == SeverityFail && len(got["kubeguard.enabled"]) != 0 {
				t.Errorf("a monitor that will not start was also passed: %+v", got["kubeguard.enabled"])
			}
		})
	}
}

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

// TestKubeGuardDisabledWithAKubeconfigGrantWarns: a kubeconfig grant delivers
// the cluster credential into a sandbox of any kind when the monitor is off.
// The pass on a host-only hub said "no kubeconfig secret is configured"
// without ever reading the store (Task 20387).
func TestKubeGuardDisabledWithAKubeconfigGrantWarns(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CLOOP_SECRET_KEY", "hubdoctor-kubeconfig-grants")
	db, err := statedb.Open(mustInitStateDB(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	b, err := secretbroker.New(store)
	if err != nil {
		t.Fatal(err)
	}
	kc := "apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: k\n  cluster:\n    server: https://k.example.com\n" +
		"contexts:\n- name: c\n  context:\n    cluster: k\n    user: u\nusers:\n- name: u\n  user:\n    token: not-a-real-token\n"
	sec, err := b.Mint(context.Background(), secretbroker.MintRequest{Name: "kube", Kind: secretbroker.KindKubeconfig,
		Payload: []byte(kc), Actor: "test"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := b.Grant(context.Background(), secretbroker.GrantRequest{SecretRef: sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: "/srv/app"},
		Constraints: secretbroker.Constraints{Contexts: []string{"c"}}}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	_ = db.Close()

	got := findingsFor(t, dir, hostOnlyConfig(), Options{Offline: true})
	wantSeverity(t, only(t, got, "kubeguard.enabled"), SeverityWarn)
}
