package config

import (
	"os"
	"strings"
	"testing"
)

// The free-space floor (Task 20381): unset means the default, 0 turns it
// off, and anything else is bounded like every other numeric setting (Task
// 20082) — repaired toward the default by Load, refused by the writers.

func TestMinFreeDiskMB_Load(t *testing.T) {
	cases := []struct {
		name     string
		yaml     string
		want     int
		stated   bool
		warnings bool
	}{
		{"unset is the default", "provider: claudecode\n", MinFreeDiskMBDefault, false, false},
		{"zero turns it off", "orchestrator:\n  min_free_disk_mb: 0\n", 0, true, false},
		{"a value in the band", "orchestrator:\n  min_free_disk_mb: 4096\n", 4096, true, false},
		{"the lower bound", "orchestrator:\n  min_free_disk_mb: 64\n", 64, true, false},
		// A typo is repaired toward keeping the check on, never toward off.
		{"below the band", "orchestrator:\n  min_free_disk_mb: 10\n", MinFreeDiskMBDefault, false, true},
		{"negative", "orchestrator:\n  min_free_disk_mb: -1\n", MinFreeDiskMBDefault, false, true},
		{"bytes typed for megabytes", "orchestrator:\n  min_free_disk_mb: 1073741824\n", MinFreeDiskMBDefault, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetClampWarned()
			dir := tempDir(t)
			writeYAMLConfig(t, dir, tc.yaml)
			var cfg *Config
			out := captureStderr(t, func() {
				var err error
				if cfg, err = Load(dir); err != nil {
					t.Fatalf("Load: %v", err)
				}
			})
			if got := cfg.Orchestrator.EffectiveMinFreeDiskMB(); got != tc.want {
				t.Errorf("EffectiveMinFreeDiskMB = %d, want %d", got, tc.want)
			}
			if got := cfg.Orchestrator.MinFreeDiskMB != nil; got != tc.stated {
				t.Errorf("stated after Load = %v, want %v", got, tc.stated)
			}
			if got := strings.Contains(out, "orchestrator.min_free_disk_mb"); got != tc.warnings {
				t.Errorf("warning printed = %v, want %v (stderr %q)", got, tc.warnings, out)
			}
		})
	}
}

func TestMinFreeDiskMB_ValidateNumeric(t *testing.T) {
	for _, v := range []int{0, MinFreeDiskMBLower, 1024, MinFreeDiskMBUpper} {
		v := v
		c := Default()
		c.Orchestrator.MinFreeDiskMB = &v
		if err := c.ValidateNumeric(); err != nil {
			t.Errorf("ValidateNumeric(%d) = %v, want nil", v, err)
		}
	}
	for _, v := range []int{-1, 1, MinFreeDiskMBLower - 1, MinFreeDiskMBUpper + 1} {
		v := v
		c := Default()
		c.Orchestrator.MinFreeDiskMB = &v
		err := c.ValidateNumeric()
		if err == nil || !strings.Contains(err.Error(), "orchestrator.min_free_disk_mb") {
			t.Errorf("ValidateNumeric(%d) = %v, want a refusal naming the key", v, err)
		}
	}
	if err := Default().ValidateNumeric(); err != nil {
		t.Errorf("the default config fails ValidateNumeric: %v", err)
	}
}

// TestMinFreeDiskMB_OverlaySave: Settings writes the floor into the hub's
// overlay — 0 included, so config.yaml's value cannot show through a save
// that turned the check off — and leaves the overlay's other keys alone.
func TestMinFreeDiskMB_OverlaySave(t *testing.T) {
	dir := writeConfigs(t, baseWithoutSSO+"orchestrator:\n    min_free_disk_mb: 2048\n",
		"# :8081 only.\nui:\n    allowed_origins: [https://hub.example:8888]\n", 8081)
	path := UIInstanceConfigPath(dir, 8081)

	if err := SaveUIInstanceMinFreeDisk(path, 0); err != nil {
		t.Fatalf("SaveUIInstanceMinFreeDisk: %v", err)
	}
	cfg, _, err := LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance: %v", err)
	}
	if got := cfg.Orchestrator.EffectiveMinFreeDiskMB(); got != 0 {
		t.Errorf("floor through the overlay = %d, want 0: config.yaml's 2048 showed through", got)
	}
	if len(cfg.UI.AllowedOrigins) != 1 {
		t.Errorf("AllowedOrigins = %v, want the overlay's other key intact", cfg.UI.AllowedOrigins)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "# :8081 only.") {
		t.Error("the operator's comment was lost")
	}
	// config.yaml, which `cloop run` reads, is untouched.
	base, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := base.Orchestrator.EffectiveMinFreeDiskMB(); got != 2048 {
		t.Errorf("config.yaml's floor = %d after an overlay save, want 2048", got)
	}

	if err := SaveUIInstanceMinFreeDisk(path, 5); err == nil {
		t.Error("an out-of-range floor was written to the overlay")
	}
}
