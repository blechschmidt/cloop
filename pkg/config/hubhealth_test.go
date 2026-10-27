package config

// ui.hub_health_interval (Task 20446): how often each hub member makes its Hub
// health report. Within [1m, 1h] it is honoured; anything else runs at the
// default rather than every few seconds or never, and says so.

import (
	"strings"
	"testing"
	"time"
)

func TestHubHealthInterval(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
		bad  bool
	}{
		{"", HubHealthIntervalDefault, false},
		{"15m", 15 * time.Minute, false},
		{" 1m ", time.Minute, false},
		{"1h", time.Hour, false},
		{"30s", HubHealthIntervalDefault, true},
		{"2h", HubHealthIntervalDefault, true},
		{"often", HubHealthIntervalDefault, true},
	}
	for _, tc := range cases {
		u := UIConfig{HubHealthInterval: tc.raw}
		if got := u.EffectiveHubHealthInterval(); got != tc.want {
			t.Errorf("ui.hub_health_interval %q is in force as %s, want %s", tc.raw, got, tc.want)
		}
		c := Default()
		c.UI.HubHealthInterval = tc.raw
		if err := c.ValidateNumeric(); (err != nil) != tc.bad {
			t.Errorf("ValidateNumeric(%q) = %v, want an error: %v", tc.raw, err, tc.bad)
		} else if err != nil && !strings.Contains(err.Error(), "ui.hub_health_interval") {
			t.Errorf("ValidateNumeric(%q) does not name the key: %v", tc.raw, err)
		}
	}
}

// TestLoad_ClampsHubHealthInterval: a cadence out of bounds in the file is
// dropped at load, with a warning naming the key, so the hub runs the default.
func TestLoad_ClampsHubHealthInterval(t *testing.T) {
	resetClampWarned()
	dir := tempDir(t)
	writeYAMLConfig(t, dir, "provider: claudecode\nui:\n  hub_health_interval: 5s\n")
	var cfg *Config
	out := captureStderr(t, func() {
		var err error
		if cfg, err = Load(dir); err != nil {
			t.Fatalf("load: %v", err)
		}
	})
	if cfg.UI.HubHealthInterval != "" || cfg.UI.EffectiveHubHealthInterval() != HubHealthIntervalDefault {
		t.Errorf("a 5s cadence loaded as %q (in force %s), want the default", cfg.UI.HubHealthInterval,
			cfg.UI.EffectiveHubHealthInterval())
	}
	if !strings.Contains(out, "ui.hub_health_interval") {
		t.Errorf("no warning names ui.hub_health_interval: %q", out)
	}

	resetClampWarned()
	writeYAMLConfig(t, dir, "provider: claudecode\nui:\n  hub_health_interval: 10m\n")
	if cfg, err := Load(dir); err != nil || cfg.UI.EffectiveHubHealthInterval() != 10*time.Minute {
		t.Errorf("a 10m cadence loaded as %v (%v)", cfg.UI.EffectiveHubHealthInterval(), err)
	}
}
