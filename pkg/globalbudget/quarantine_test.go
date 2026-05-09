package globalbudget

// Regression tests for the corrupt-file quarantine path in
// globalbudget.Load.
//
// Before the fix a malformed ~/.config/cloop/budget.yaml (zero-byte from a
// torn pre-atomicfile write, schema drift, or a manual edit gone wrong)
// caused every Load to return the yaml.Unmarshal error. Pre-task budget
// enforcement loads this file on every cloop invocation across the host,
// so a corrupt budget config bricked all cloop work until the user
// manually removed or fixed the file. Empty config means "no limits"
// which is the same as the file not existing — quarantining the bad
// bytes and returning empty restores forward progress, with the original
// preserved for forensics or recovery of the prior cap.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_CorruptFileQuarantined(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	path, err := ConfigPath()
	if err != nil {
		t.Fatalf("ConfigPath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Mid-document garbage — what a torn pre-atomicfile write would
	// produce if the writer was killed during yaml.Marshal.
	if err := os.WriteFile(path, []byte("daily_usd_limit: 12.5\n  not: yaml: at all"), 0o600); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load on corrupt file should not return an error, got: %v", err)
	}
	if got.DailyUSDLimit != 0 || got.DailyTokenLimit != 0 || got.AlertThresholdPct != 0 {
		t.Errorf("Load on corrupt file should return zero-value config, got: %+v", got)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected corrupt %s to be moved aside, stat err = %v", path, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	found := false
	for _, e := range entries {
		if strings.Contains(e.Name(), ".corrupt-") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a .corrupt-* sibling preserving the bad bytes, dir contents: %v", entries)
	}
}

func TestLoad_RecoversAfterQuarantineWithSave(t *testing.T) {
	// User-visible recovery flow: corrupt → Load returns empty → Save
	// succeeds (replaces the now-absent file) → next Load returns the
	// fresh config. Confirms there's no lingering inode-level wedge.
	home := t.TempDir()
	t.Setenv("HOME", home)

	path, err := ConfigPath()
	if err != nil {
		t.Fatalf("ConfigPath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("\x00\x00\x00not yaml"), 0o600); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	if _, err := Load(); err != nil {
		t.Fatalf("first Load: %v", err)
	}

	if err := Save(GlobalBudgetConfig{DailyUSDLimit: 5.0}); err != nil {
		t.Fatalf("Save after quarantine: %v", err)
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	if got.DailyUSDLimit != 5.0 {
		t.Errorf("expected DailyUSDLimit=5.0 after recovery, got %v", got.DailyUSDLimit)
	}
}
