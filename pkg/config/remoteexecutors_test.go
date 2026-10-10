package config

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// executors.remote (Task 20399): the per-executor budget and the process-wide
// ceiling on returned work a hub holds in memory. Unset means the defaults;
// anything outside [1 MiB, 64 GiB] is repaired toward the default by Load and
// refused by the writers — never toward "unbounded". The third path,
// `cloop config validate`, is exercised in pkg/configvalidate.

func TestPinnedWriteBack_Load(t *testing.T) {
	const (
		defPer   = executor.DefaultPinnedWriteBackBytes
		defTotal = executor.DefaultPinnedWriteBackTotalBytes
	)
	cases := []struct {
		name      string
		yaml      string
		per       int64
		total     int64
		repairKey string
	}{
		{"unset is the default", "provider: claudecode\n", defPer, defTotal, ""},
		{"values in the band",
			"executors:\n  remote:\n    max_pinned_writeback_bytes: 67108864\n    max_pinned_writeback_total_bytes: 268435456\n",
			64 << 20, 256 << 20, ""},
		{"megabytes written as bytes",
			"executors:\n  remote:\n    max_pinned_writeback_bytes: 256\n",
			defPer, defTotal, "executors.remote.max_pinned_writeback_bytes"},
		{"negative ceiling",
			"executors:\n  remote:\n    max_pinned_writeback_total_bytes: -1\n",
			defPer, defTotal, "executors.remote.max_pinned_writeback_total_bytes"},
		{"a typo for unlimited",
			"executors:\n  remote:\n    max_pinned_writeback_total_bytes: 999999999999999\n",
			defPer, defTotal, "executors.remote.max_pinned_writeback_total_bytes"},
		{"a budget above the ceiling is lowered to it",
			"executors:\n  remote:\n    max_pinned_writeback_bytes: 536870912\n    max_pinned_writeback_total_bytes: 268435456\n",
			256 << 20, 256 << 20, "executors.remote.max_pinned_writeback_bytes"},
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
			per, total := cfg.Executors.Remote.PinnedWriteBackLimits()
			if per != tc.per || total != tc.total {
				t.Errorf("limits = %d/%d, want %d/%d", per, total, tc.per, tc.total)
			}
			warned := strings.Contains(out, "executors.remote.")
			if warned != (tc.repairKey != "") {
				t.Errorf("warning printed = %v, want %v (stderr %q)", warned, tc.repairKey != "", out)
			}
			repaired := false
			for _, r := range cfg.LoadRepairs() {
				if r.Field == tc.repairKey {
					repaired = true
				}
			}
			if tc.repairKey != "" && !repaired {
				t.Errorf("no load repair recorded for %s — `cloop hub doctor` reads these", tc.repairKey)
			}
			// Whatever Load leaves must pass the strict check, or the repaired
			// config could not be saved back through `cloop config set`.
			if err := ValidateRemoteExecutors(cfg.Executors.Remote); err != nil {
				t.Errorf("Load left a section the strict check refuses: %v", err)
			}
		})
	}
}

func TestPinnedWriteBack_ValidateRefusesOutOfBand(t *testing.T) {
	ok := []RemoteExecutorsConfig{
		{},
		{MaxPinnedWriteBackBytes: PinnedWriteBackBytesLower},
		{MaxPinnedWriteBackBytes: 1 << 30, MaxPinnedWriteBackTotalBytes: PinnedWriteBackBytesUpper},
		{MaxPinnedWriteBackTotalBytes: 256 << 20},
	}
	for _, r := range ok {
		c := Default()
		c.Executors.Remote = r
		if err := c.ValidateNumeric(); err != nil {
			t.Errorf("ValidateNumeric(%+v) = %v, want nil", r, err)
		}
		if err := ValidateExecutors(c.Executors); err != nil {
			t.Errorf("ValidateExecutors(%+v) = %v, want nil", r, err)
		}
	}
	bad := map[string]RemoteExecutorsConfig{
		"max_pinned_writeback_bytes":       {MaxPinnedWriteBackBytes: 256},
		"max_pinned_writeback_total_bytes": {MaxPinnedWriteBackTotalBytes: PinnedWriteBackBytesUpper + 1},
		"exceeds":                          {MaxPinnedWriteBackBytes: 512 << 20, MaxPinnedWriteBackTotalBytes: 256 << 20},
		// Against the default ceiling, which is what the hub would enforce.
		"exceeds max_pinned_writeback_total_bytes": {MaxPinnedWriteBackBytes: 2 << 30},
	}
	for want, r := range bad {
		c := Default()
		c.Executors.Remote = r
		if err := c.ValidateNumeric(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ValidateNumeric(%+v) = %v, want a refusal naming %q", r, err, want)
		}
		if err := ValidateExecutors(c.Executors); err == nil {
			t.Errorf("ValidateExecutors(%+v) accepted it", r)
		}
	}
}

// TestPinnedWriteBack_WarnsWhenTheBudgetIsBelowTheFeatureCap: in band and
// accepted, but a budget smaller than the bundles this hub asks devices for
// refuses them after the work is done, so it is said where operators look.
func TestPinnedWriteBack_WarnsWhenTheBudgetIsBelowTheFeatureCap(t *testing.T) {
	e := ExecutorsConfig{FeatureBundleMB: 64, Remote: RemoteExecutorsConfig{MaxPinnedWriteBackBytes: 32 << 20}}
	found := false
	for _, w := range ExecutorWarnings(e) {
		if strings.Contains(w, "max_pinned_writeback_bytes") {
			found = true
		}
	}
	if !found {
		t.Error("no warning for a budget below executors.feature_bundle_mb")
	}
	e.Remote.MaxPinnedWriteBackBytes = 0
	for _, w := range ExecutorWarnings(e) {
		if strings.Contains(w, "max_pinned_writeback_bytes") {
			t.Errorf("the default budget was warned about: %s", w)
		}
	}
}

// TestPinnedWriteBack_OverlayIsTheHubsOwn: a hub-scope key, so a per-instance
// overlay sets it for its hub alone, held to the same bound.
func TestPinnedWriteBack_OverlayIsTheHubsOwn(t *testing.T) {
	base := "provider: claudecode\nexecutors:\n  remote:\n    max_pinned_writeback_bytes: 134217728\n"
	dir := writeConfigs(t, base, "executors:\n  remote:\n    max_pinned_writeback_bytes: 67108864\n", 8081)
	hub, overlay, err := LoadUIInstance(dir, 8081)
	if err != nil || overlay == "" {
		t.Fatalf("LoadUIInstance = %v, %q", err, overlay)
	}
	if per, _ := hub.Executors.Remote.PinnedWriteBackLimits(); per != 64<<20 {
		t.Errorf("the overlay's hub runs with a budget of %d, want the overlay's 64 MiB", per)
	}
	other, _, err := LoadUIInstance(dir, 8080)
	if err != nil {
		t.Fatal(err)
	}
	if per, _ := other.Executors.Remote.PinnedWriteBackLimits(); per != 128<<20 {
		t.Errorf("the hub without an overlay runs with a budget of %d, want config.yaml's 128 MiB", per)
	}
}
