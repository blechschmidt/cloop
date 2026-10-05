package cmd

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
)

// `cloop config set orchestrator.min_free_disk_mb` (Task 20381): refused
// outside the band, like every numeric key, and 0 is the way to turn it off.
func TestApplyConfigKey_MinFreeDiskMB(t *testing.T) {
	for _, v := range []string{"0", "64", "2048"} {
		cfg := config.Default()
		if err := applyConfigKey(cfg, "orchestrator.min_free_disk_mb", v); err != nil {
			t.Errorf("%s: %v", v, err)
			continue
		}
		if cfg.Orchestrator.MinFreeDiskMB == nil {
			t.Errorf("%s: the key was not set", v)
		}
	}
	if cfg := config.Default(); applyConfigKey(cfg, "orchestrator.min_free_disk_mb", "0") == nil &&
		cfg.Orchestrator.EffectiveMinFreeDiskMB() != 0 {
		t.Error("setting 0 did not turn the check off")
	}
	for _, v := range []string{"-1", "10", "2000000", "lots"} {
		cfg := config.Default()
		err := applyConfigKey(cfg, "orchestrator.min_free_disk_mb", v)
		if err == nil || !strings.Contains(err.Error(), "min_free_disk_mb") {
			t.Errorf("%s: err = %v, want a refusal naming the key", v, err)
		}
		if cfg.Orchestrator.MinFreeDiskMB != nil {
			t.Errorf("%s: a refused value was stored", v)
		}
	}
}

// minFreeDiskMB: a hub hands a run of its own directory its Settings value
// through the environment, ahead of config.yaml; an unusable one is ignored.
func TestMinFreeDiskMB_Resolution(t *testing.T) {
	stated := 2048
	cfg := config.Default()
	cfg.Orchestrator.MinFreeDiskMB = &stated

	t.Setenv(config.EnvMinFreeDiskMB, "")
	if got := minFreeDiskMB(nil); got != config.MinFreeDiskMBDefault {
		t.Errorf("no config, no env = %d, want the default", got)
	}
	if got := minFreeDiskMB(cfg); got != 2048 {
		t.Errorf("config only = %d, want 2048", got)
	}

	t.Setenv(config.EnvMinFreeDiskMB, "0")
	if got := minFreeDiskMB(cfg); got != 0 {
		t.Errorf("env 0 = %d, want 0: the hub's Settings turned the check off", got)
	}
	t.Setenv(config.EnvMinFreeDiskMB, "4096")
	if got := minFreeDiskMB(cfg); got != 4096 {
		t.Errorf("env 4096 = %d, want 4096", got)
	}
	for _, bad := range []string{"12", "-5", "a gigabyte"} {
		t.Setenv(config.EnvMinFreeDiskMB, bad)
		if got := minFreeDiskMB(cfg); got != 2048 {
			t.Errorf("env %q = %d, want config.yaml's 2048", bad, got)
		}
	}
}
