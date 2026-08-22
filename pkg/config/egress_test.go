package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/container"
)

func TestValidateEgressConfig(t *testing.T) {
	cases := []struct {
		name    string
		cfg     EgressConfig
		wantErr string
	}{
		{name: "zero value is valid", cfg: EgressConfig{}},
		{name: "fully specified", cfg: EgressConfig{
			Enabled:             true,
			ListenAddr:          "0.0.0.0:8899",
			AdvertiseAddr:       "host.containers.internal:8899",
			MaxSessionMinutes:   10,
			DialTimeoutSeconds:  20,
			DefaultMaxBytesUp:   "10m",
			DefaultMaxBytesDown: "2g",
		}},
		{name: "bare host advertise is fine", cfg: EgressConfig{AdvertiseAddr: "host.docker.internal"}},

		{
			name:    "session ceiling",
			cfg:     EgressConfig{MaxSessionMinutes: EgressMaxSessionMinutesUpper + 1},
			wantErr: "max_session_minutes",
		},
		{
			name:    "negative session",
			cfg:     EgressConfig{MaxSessionMinutes: -1},
			wantErr: "max_session_minutes",
		},
		{
			name:    "dial ceiling",
			cfg:     EgressConfig{DialTimeoutSeconds: EgressDialTimeoutSecondsUpper + 1},
			wantErr: "dial_timeout_seconds",
		},
		{
			name:    "listen addr needs a port",
			cfg:     EgressConfig{ListenAddr: "0.0.0.0"},
			wantErr: "listen_addr",
		},
		{
			name:    "listen addr is not a url",
			cfg:     EgressConfig{ListenAddr: "http://0.0.0.0:8899"},
			wantErr: "listen_addr",
		},
		{
			name:    "listen port out of range",
			cfg:     EgressConfig{ListenAddr: "0.0.0.0:70000"},
			wantErr: "listen_addr",
		},
		{
			name:    "bad quota",
			cfg:     EgressConfig{DefaultMaxBytesDown: "banana"},
			wantErr: "default_max_bytes_down",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEgressConfig(tc.cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error naming %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q should name %q", err, tc.wantErr)
			}
		})
	}
}

// TestValidateEgressConfig_RunsWhenDisabled matches the other executor
// validators: a broken section is reported when it is written, not discovered
// months later at the moment someone flips enabled to true.
func TestValidateEgressConfig_RunsWhenDisabled(t *testing.T) {
	if err := ValidateEgressConfig(EgressConfig{Enabled: false, ListenAddr: "nonsense"}); err == nil {
		t.Fatal("a disabled but broken egress section must still be rejected")
	}
}

// TestLoadClampsEgressConfig proves the defensive path repairs a hand-edited
// file rather than honouring it or refusing to boot.
func TestLoadClampsEgressConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := `provider: claudecode
executors:
  egress:
    enabled: true
    listen_addr: "not-an-address"
    advertise_addr: "http://bad"
    max_session_minutes: 99999
    dial_timeout_seconds: -5
    default_max_bytes_down: banana
`
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load must not fail on a repairable config: %v", err)
	}
	e := cfg.Executors.Egress

	// An unusable bind address disables the proxy rather than silently
	// binding an ephemeral loopback port nobody asked for: "egress is off" is
	// a visible misconfiguration, "egress is on but unreachable" is not.
	if e.Enabled {
		t.Error("an unusable listen_addr must disable the egress proxy")
	}
	if e.ListenAddr != "" || e.AdvertiseAddr != "" {
		t.Errorf("bad addresses survived Load: %+v", e)
	}
	if e.MaxSessionMinutes != 0 || e.DialTimeoutSeconds != 0 || e.DefaultMaxBytesDown != "" {
		t.Errorf("out-of-range values survived Load: %+v", e)
	}
	if err := cfg.ValidateNumeric(); err != nil {
		t.Fatalf("a loaded config must pass strict validation: %v", err)
	}
}

// TestLoadKeepsAValidEgressSection is the other half: clamping must not
// mangle a config an operator wrote correctly.
func TestLoadKeepsAValidEgressSection(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := `provider: claudecode
executors:
  egress:
    enabled: true
    listen_addr: "10.88.0.1:8899"
    advertise_addr: "host.containers.internal:8899"
    max_session_minutes: 10
    default_max_bytes_down: 500m
`
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	e := cfg.Executors.Egress
	if !e.Enabled || e.ListenAddr != "10.88.0.1:8899" ||
		e.AdvertiseAddr != "host.containers.internal:8899" ||
		e.MaxSessionMinutes != 10 || e.DefaultMaxBytesDown != "500m" {
		t.Fatalf("a valid section was altered: %+v", e)
	}
}

func TestExecutorWarnings_Egress(t *testing.T) {
	t.Run("loopback bind with a bridged sandbox", func(t *testing.T) {
		e := ExecutorsConfig{}
		e.Container.Enabled = true
		e.Egress.Enabled = true
		e.Egress.ListenAddr = "127.0.0.1:8899"

		warnings := ExecutorWarnings(e)
		if !containsSubstring(warnings, "advertise_addr") {
			t.Errorf("expected a loopback-unreachable warning, got %v", warnings)
		}
	})

	t.Run("advertise_addr silences it", func(t *testing.T) {
		e := ExecutorsConfig{}
		e.Container.Enabled = true
		e.Container.Network = "bridge"
		e.Egress.Enabled = true
		e.Egress.ListenAddr = "127.0.0.1:8899"
		e.Egress.AdvertiseAddr = "host.containers.internal:8899"
		e.Egress.DefaultMaxBytesDown = "1g"
		e.Egress.DefaultMaxBytesUp = "100m"

		if containsSubstring(ExecutorWarnings(e), "advertise_addr") {
			t.Errorf("a configured advertise_addr should silence the warning: %v", ExecutorWarnings(e))
		}
	})

	t.Run("no quota default", func(t *testing.T) {
		e := ExecutorsConfig{}
		e.Egress.Enabled = true
		e.Egress.ListenAddr = "10.88.0.1:8899"

		if !containsSubstring(ExecutorWarnings(e), "transfer quota") {
			t.Errorf("expected an unbounded-quota warning, got %v", ExecutorWarnings(e))
		}
	})

	t.Run("isolated sandbox with no egress broker at all", func(t *testing.T) {
		e := ExecutorsConfig{}
		e.Container.Enabled = true
		e.Container.Network = container.NetworkNone

		if !containsSubstring(ExecutorWarnings(e), "no route out") {
			t.Errorf("expected a no-route-out warning, got %v", ExecutorWarnings(e))
		}
	})
}

func containsSubstring(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}
