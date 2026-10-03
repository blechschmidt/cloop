package hubdoctor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
)

// TestSmokeGitProxyRequiredAsksEveryHub: the smoke lease must keep a git token
// on the hub when any hub sharing the control plane routes git through its
// proxy. Since Task 20364 that is usually stated in one hub's per-instance
// overlay, which the guard used to miss because it read config.yaml alone.
func TestSmokeGitProxyRequiredAsksEveryHub(t *testing.T) {
	write := func(t *testing.T, dir, name, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".cloop", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// TLS paths, because a section enabled without them is switched off at
	// load (clampGitProxyConfig), and the hub then runs without a proxy too.
	const proxyOn = "executors:\n  git_proxy:\n    enabled: true\n" +
		"    cert_file: /etc/cloop/proxy.crt\n    key_file: /etc/cloop/proxy.key\n"

	cases := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"no proxy anywhere", map[string]string{
			"config.yaml": "provider: claudecode\n", "config.ui-8081.yaml": "ui: {}\n"}, false},
		{"proxy in config.yaml", map[string]string{"config.yaml": proxyOn}, true},
		{"proxy in one hub's overlay", map[string]string{
			"config.yaml": "provider: claudecode\n", "config.ui-8081.yaml": proxyOn}, true},
		{"an unreadable overlay", map[string]string{
			"config.yaml": "provider: claudecode\n", "config.ui-8081.yaml": "executors: [not, a, map\n"}, true},
		{"an unreadable config.yaml", map[string]string{"config.yaml": "executors: [\n"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range c.files {
				write(t, dir, name, body)
			}
			if got := smokeGitProxyRequired(dir); got != c.want {
				t.Errorf("smokeGitProxyRequired = %v, want %v", got, c.want)
			}
		})
	}

	// The overlay case is the one config.yaml alone gets wrong.
	dir := t.TempDir()
	write(t, dir, "config.yaml", "provider: claudecode\n")
	write(t, dir, "config.ui-8081.yaml", proxyOn)
	if cfg, err := config.Load(dir); err != nil || cfg.Executors.GitProxy.Enabled {
		t.Fatalf("fixture: config.yaml alone should not enable the proxy (err=%v)", err)
	}
}
