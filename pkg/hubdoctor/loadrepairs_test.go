package hubdoctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
)

// loadedHub writes yaml as dir's config.yaml and loads it the way `cloop hub
// doctor` does, so the loader's repairs are part of what is diagnosed.
func loadedHub(t *testing.T, yaml string) (string, *config.Config) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.ConfigPath(dir), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.LoadUIInstance(dir, 0)
	if err != nil {
		t.Fatalf("LoadUIInstance: %v", err)
	}
	return dir, cfg
}

// TestASectionTheLoaderSwitchedOffFails: the loader switches off a git proxy,
// Kubernetes monitor or egress proxy it could only start unusable or unsafe,
// and every check that looks at the result afterwards saw "disabled" — the
// same green line as a section nobody enabled, over a hub whose operator asked
// for a control it is not running (Task 20387). Each is reported under the
// section's own check, saying what the hub does without it.
func TestASectionTheLoaderSwitchedOffFails(t *testing.T) {
	cases := []struct {
		name, yaml, check, consequence string
	}{
		{"git proxy without TLS material", `executors:
  allow_host_process: false
  git_proxy:
    enabled: true
    advertise_url: https://hub.example.com:8443
`, "gitproxy.enabled", "forge credential"},
		{"kubernetes monitor without TLS material", `executors:
  allow_host_process: false
  kube_guard:
    enabled: true
`, "kubeguard.enabled", "cluster credential"},
		{"egress proxy with an unusable listen address", `executors:
  egress:
    enabled: true
    listen_addr: "8899"
`, "egress.enabled", "refused"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, cfg := loadedHub(t, "provider: claudecode\n"+tc.yaml)
			got := findingsFor(t, dir, cfg, Options{Offline: true})
			f := only(t, got, tc.check)
			wantSeverity(t, f, SeverityFail)
			if !strings.Contains(f.Message, "switched off at load") || !strings.Contains(f.Message, tc.consequence) {
				t.Errorf("want the switch-off and its consequence, got %q", f.Message)
			}
			for _, r := range got["config.repaired"] {
				if r.Severity == SeverityFail {
					t.Errorf("the switch-off is reported twice: %q", r.Message)
				}
			}
		})
	}
}

// TestLoadRepairsAreReported: the loader's other repairs, which it announced
// once on stderr and nowhere a deployment gate can read.
func TestLoadRepairsAreReported(t *testing.T) {
	dir, cfg := loadedHub(t, `provider: claudecode
max_parallel: 999
executors:
  container:
    enabled: true
    oci_runtime: "runsc --debug"
`)
	got := findingsFor(t, dir, cfg, Options{Offline: true})
	var warned, failed bool
	for _, f := range got["config.repaired"] {
		switch {
		case f.Severity == SeverityWarn && strings.Contains(f.Message, "max_parallel"):
			warned = true
		case f.Severity == SeverityFail && strings.Contains(f.Message, "executors.container is enabled"):
			failed = true
		}
		if f.Remediation == "" {
			t.Errorf("a repair finding names no fix: %+v", f)
		}
	}
	if !warned {
		t.Errorf("an out-of-range max_parallel was not reported: %+v", got["config.repaired"])
	}
	if !failed {
		t.Errorf("a container executor switched off at load was not a failure: %+v", got["config.repaired"])
	}
	// One finding for the section, not a second saying the hub runs with a
	// repaired oci_runtime of an executor it does not run.
	if n := len(got["config.repaired"]); n != 2 {
		t.Errorf("want 2 findings (max_parallel, the container switch-off), got %d: %+v", n, got["config.repaired"])
	}

	// And a config the loader took as written reports nothing.
	dir, cfg = loadedHub(t, "provider: claudecode\n")
	if fs := findingsFor(t, dir, cfg, Options{Offline: true})["config.repaired"]; len(fs) != 0 {
		t.Errorf("a clean config reported repairs: %+v", fs)
	}
}
