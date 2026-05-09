package globalbudget

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSave_MirrorsToSQLite(t *testing.T) {
	withFakeHome(t)
	in := GlobalBudgetConfig{
		DailyUSDLimit:     20.5,
		DailyTokenLimit:   2_500_000,
		AlertThresholdPct: 75,
	}
	if err := Save(in); err != nil {
		t.Fatalf("save: %v", err)
	}
	// SQLite mirror should now exist alongside YAML.
	dbPath, err := globalDBPath()
	if err != nil {
		t.Fatalf("globalDBPath: %v", err)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("global.db missing after Save: %v", err)
	}
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()
	var blob string
	if err := conn.QueryRow(`SELECT value FROM metadata WHERE key=?`, globalDBMetaKey).Scan(&blob); err != nil {
		t.Fatalf("read blob: %v", err)
	}
	if !containsString(blob, "daily_usd_limit: 20.5") {
		t.Errorf("expected daily_usd_limit in blob, got: %s", blob)
	}
	if !containsString(blob, "daily_token_limit: 2500000") {
		t.Errorf("expected daily_token_limit in blob, got: %s", blob)
	}
}

func TestLoad_FallsBackToSQLiteWhenYAMLMissing(t *testing.T) {
	home := withFakeHome(t)
	in := GlobalBudgetConfig{
		DailyUSDLimit:     8.25,
		DailyTokenLimit:   500_000,
		AlertThresholdPct: 90,
	}
	if err := Save(in); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Wipe budget.yaml; SQLite mirror should still rehydrate the limits.
	yamlPath := filepath.Join(home, ".config", "cloop", "budget.yaml")
	if err := os.Remove(yamlPath); err != nil {
		t.Fatalf("rm yaml: %v", err)
	}
	out, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if out != in {
		t.Errorf("recovery mismatch: got %+v want %+v", out, in)
	}
}

func TestLoad_NoYAMLNoSQLiteReturnsEmpty(t *testing.T) {
	withFakeHome(t)
	out, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if (out != GlobalBudgetConfig{}) {
		t.Errorf("expected zero config when nothing exists, got %+v", out)
	}
}

func TestSave_GlobalDB_PermsAre0600(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("perm bits are POSIX only")
	}
	withFakeHome(t)
	if err := Save(GlobalBudgetConfig{DailyUSDLimit: 1}); err != nil {
		t.Fatalf("save: %v", err)
	}
	dbPath, err := globalDBPath()
	if err != nil {
		t.Fatalf("path: %v", err)
	}
	fi, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Errorf("global.db perms: got %o want 600", mode)
	}
}

func containsString(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
