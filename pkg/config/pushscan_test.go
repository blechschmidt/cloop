package config

// The git proxy's push scan settings (Task 20436).

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
)

// TestPushScanSettingNamesAreTheYAMLKeys holds the names a refusal tells an
// operator to change to the keys this package reads.
func TestPushScanSettingNamesAreTheYAMLKeys(t *testing.T) {
	want := map[string]string{
		"PushScan":            gitproxy.SettingPushScan,
		"PushScanMaxObjectMB": gitproxy.SettingPushScanObjectMB,
		"PushScanMaxPushMB":   gitproxy.SettingPushScanPushMB,
		"PushScanSeconds":     gitproxy.SettingPushScanSeconds,
	}
	typ := reflect.TypeOf(GitProxyConfig{})
	for field, setting := range want {
		f, ok := typ.FieldByName(field)
		if !ok {
			t.Fatalf("GitProxyConfig has no field %s", field)
		}
		key := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if "executors.git_proxy."+key != setting {
			t.Errorf("%s reads executors.git_proxy.%s, and refusals name %s", field, key, setting)
		}
	}
}

func TestPushScanDefaultsToValues(t *testing.T) {
	var g GitProxyConfig
	if m := g.PushScanMode(); m != gitproxy.ScanValues {
		t.Fatalf("an unset push_scan scans %q, want values", m)
	}
	for in, want := range map[string]gitproxy.ScanMode{"off": gitproxy.ScanOff, "Shapes": gitproxy.ScanShapes, "values": gitproxy.ScanValues} {
		g.PushScan = in
		if m := g.PushScanMode(); m != want {
			t.Errorf("push_scan %q scans %q, want %q", in, m, want)
		}
	}
	if l := (GitProxyConfig{PushScanMaxObjectMB: 2, PushScanMaxPushMB: 3, PushScanSeconds: 4}).PushScanLimits(); l.MaxObjectBytes != 2<<20 ||
		l.MaxPushBytes != 3<<20 || l.MaxDuration != 4*time.Second {
		t.Fatalf("limits = %+v", l)
	}
}

func TestPushScanValidationAndRepair(t *testing.T) {
	bad := []GitProxyConfig{
		{PushScan: "strict"},
		{PushScanMaxObjectMB: -1},
		{PushScanMaxPushMB: PushScanMaxPushMBUpper + 1},
		{PushScanSeconds: PushScanSecondsUpper + 1},
	}
	for _, g := range bad {
		if err := ValidateGitProxyConfig(g); err == nil {
			t.Errorf("ValidateGitProxyConfig(%+v) accepted it", g)
		}
		repaired := g
		if changed := clampGitProxyConfig(&repaired); len(changed) == 0 {
			t.Errorf("clamp left %+v unrepaired", g)
		}
		if err := ValidateGitProxyConfig(repaired); err != nil {
			t.Errorf("after the repair %+v still fails: %v", repaired, err)
		}
		// An unreadable mode is repaired to values, never to off.
		if repaired.PushScanMode() == gitproxy.ScanOff {
			t.Errorf("the repair of %+v switched the scan off", g)
		}
	}
}

func TestPushScanLoadsFromConfigYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o700); err != nil {
		t.Fatal(err)
	}
	yaml := "executors:\n  git_proxy:\n    push_scan: shapes\n    push_scan_seconds: 60\n"
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Executors.GitProxy.PushScanMode() != gitproxy.ScanShapes || cfg.Executors.GitProxy.PushScanLimits().MaxDuration != time.Minute {
		t.Fatalf("loaded %+v", cfg.Executors.GitProxy)
	}
}
