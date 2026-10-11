package config

import (
	"strings"
	"testing"
)

// TestAutoTLSKeepsAMonitorWithNoFilesRunning: tls: auto is the way to run a
// monitor without cert_file and key_file (Task 20409).
func TestAutoTLSKeepsAMonitorWithNoFilesRunning(t *testing.T) {
	dir := writeConfigs(t, `executors:
  git_proxy:
    enabled: true
    tls: AUTO
    listen_addr: 0.0.0.0:8443
    advertise_url: https://hub.example.com:8443
  kube_guard:
    enabled: true
    tls: auto
    listen_addr: 0.0.0.0:8444
    advertise_url: https://hub.example.com:8444
`, "", 0)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Executors.GitProxy.Enabled || !cfg.Executors.GitProxy.AutoTLS() {
		t.Errorf("git_proxy with tls: auto was switched off or lost its mode: %+v", cfg.Executors.GitProxy)
	}
	if cfg.Executors.GitProxy.TLS != MonitorTLSAuto {
		t.Errorf("tls normalised to %q, want %q", cfg.Executors.GitProxy.TLS, MonitorTLSAuto)
	}
	if !cfg.Executors.KubeGuard.Enabled || !cfg.Executors.KubeGuard.AutoTLS() {
		t.Errorf("kube_guard with tls: auto was switched off: %+v", cfg.Executors.KubeGuard)
	}
	if err := ValidateExecutors(cfg.Executors); err != nil {
		t.Errorf("a tls: auto section does not validate: %v", err)
	}
	if b, err := cfg.Executors.KubeGuard.CABundle(); err != nil || b != nil {
		t.Errorf("CABundle under tls: auto = %q, %v; want nothing — the hub embeds its own CA", b, err)
	}
}

// TestAMissingCertificateIsNotReadAsAuto is the upgrade guarantee: a section
// that says enabled: true with no files has always been switched off at load,
// and must stay off rather than start interposing a monitor the day tls: auto
// exists.
func TestAMissingCertificateIsNotReadAsAuto(t *testing.T) {
	dir := writeConfigs(t, `executors:
  git_proxy:
    enabled: true
    advertise_url: https://hub.example.com:8443
  kube_guard:
    enabled: true
    advertise_url: https://hub.example.com:8444
`, "", 0)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Executors.GitProxy.Enabled || cfg.Executors.GitProxy.AutoTLS() {
		t.Errorf("an enabled git_proxy without files now runs: %+v", cfg.Executors.GitProxy)
	}
	if cfg.Executors.KubeGuard.Enabled || cfg.Executors.KubeGuard.AutoTLS() {
		t.Errorf("an enabled kube_guard without files now runs: %+v", cfg.Executors.KubeGuard)
	}
	var says bool
	for _, r := range cfg.LoadRepairs() {
		if r.SwitchedOff == "executors.git_proxy" && strings.Contains(r.Detail, "tls: auto") {
			says = true
		}
	}
	if !says {
		t.Errorf("the switch-off does not name the remedy: %+v", cfg.LoadRepairs())
	}
}

func TestValidateMonitorTLS(t *testing.T) {
	for _, c := range []struct {
		name string
		g    GitProxyConfig
		k    KubeGuardConfig
		want string
	}{
		{name: "git auto and files", g: GitProxyConfig{Enabled: true, TLS: "auto", CertFile: "/c", KeyFile: "/k"},
			want: "drop cert_file and key_file"},
		{name: "git unknown mode", g: GitProxyConfig{TLS: "acme"}, want: `tls must be "auto" or empty`},
		{name: "git enabled no files", g: GitProxyConfig{Enabled: true}, want: "set tls: auto"},
		{name: "kube auto and ca", k: KubeGuardConfig{Enabled: true, TLS: "auto", CAFile: "/ca"},
			want: "drop cert_file, key_file and ca_file"},
		{name: "kube enabled no files", k: KubeGuardConfig{Enabled: true}, want: "set tls: auto"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateGitProxyConfig(c.g)
			if err == nil {
				err = ValidateKubeGuardConfig(c.k)
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want one containing %q", err, c.want)
			}
		})
	}
	if err := ValidateGitProxyConfig(GitProxyConfig{Enabled: true, TLS: "auto"}); err != nil {
		t.Errorf("enabled with tls: auto alone: %v", err)
	}
}

// TestClampMonitorTLS: explicit files win over auto, an unknown mode is
// dropped, and a kubeconfig CA beside auto is dropped rather than embedded
// beside a certificate it did not sign.
func TestClampMonitorTLS(t *testing.T) {
	g := GitProxyConfig{Enabled: true, TLS: "auto", CertFile: "/c", KeyFile: "/k"}
	if changed := clampGitProxyConfig(&g); len(changed) == 0 || g.AutoTLS() || !g.Enabled {
		t.Errorf("auto beside files: changed=%v cfg=%+v", changed, g)
	}
	g = GitProxyConfig{Enabled: true, TLS: "letsencrypt"}
	if changed := clampGitProxyConfig(&g); len(changed) == 0 || g.TLS != "" || g.Enabled {
		t.Errorf("unknown mode with no files must switch the proxy off: changed=%v cfg=%+v", changed, g)
	}
	k := KubeGuardConfig{Enabled: true, TLS: "auto", CAFile: "/ca"}
	if changed := clampKubeGuardConfig(&k); len(changed) == 0 || k.CAFile != "" || !k.AutoTLS() || !k.Enabled {
		t.Errorf("auto beside ca_file: changed=%v cfg=%+v", changed, k)
	}
}
