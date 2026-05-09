package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// initStateDB creates an empty .cloop/state.db so Save() will mirror into it.
// Without this, mirrorToSQLite is a no-op (by design — we don't want
// config.Save to spuriously create a state.db in arbitrary directories).
func initStateDB(t *testing.T, workdir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(workdir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	db, err := statedb.Open(stateDBPath(workdir))
	if err != nil {
		t.Fatalf("open state.db: %v", err)
	}
	_ = db.Close()
}

func TestSave_MirrorsToSQLite(t *testing.T) {
	dir := tempDir(t)
	initStateDB(t, dir)

	cfg := Default()
	cfg.Provider = "anthropic"
	cfg.Anthropic.APIKey = "sk-mirror-test"
	cfg.Budget.DailyUSDLimit = 7.50
	cfg.Budget.DailyTokenLimit = 250_000
	cfg.Budget.AlertThresholdPct = 75
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	db, err := statedb.Open(stateDBPath(dir))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	blob, err := db.GetConfigBlob()
	if err != nil {
		t.Fatalf("get blob: %v", err)
	}
	if blob == "" {
		t.Fatal("expected mirrored config blob in state.db, got empty string")
	}
	for _, want := range []string{"sk-mirror-test", "daily_usd_limit: 7.5", "daily_token_limit: 250000"} {
		if !contains(blob, want) {
			t.Errorf("mirror blob missing %q\nblob:\n%s", want, blob)
		}
	}
}

func TestSave_NoStateDB_DoesNotCreateOne(t *testing.T) {
	// If state.db doesn't exist, Save must not create one — we only want
	// the mirror to attach to projects that have already been initialised.
	dir := tempDir(t)
	cfg := Default()
	cfg.Anthropic.APIKey = "should-not-be-mirrored"
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(stateDBPath(dir)); err == nil {
		t.Fatal("Save() should not have created state.db when none existed")
	}
}

func TestLoad_FallsBackToSQLiteWhenYAMLMissing(t *testing.T) {
	// Sequence: write config via Save (mirrors to SQLite), delete YAML,
	// Load should rehydrate the budget caps and API key from SQLite.
	dir := tempDir(t)
	initStateDB(t, dir)

	cfg := Default()
	cfg.Provider = "openai"
	cfg.OpenAI.APIKey = "sk-recovered"
	cfg.Budget.DailyUSDLimit = 3.14
	cfg.Budget.DailyTokenLimit = 99_999
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	if err := os.Remove(ConfigPath(dir)); err != nil {
		t.Fatalf("rm yaml: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Provider != "openai" {
		t.Errorf("provider not recovered: got %q want %q", loaded.Provider, "openai")
	}
	if loaded.OpenAI.APIKey != "sk-recovered" {
		t.Errorf("api key not recovered: got %q", loaded.OpenAI.APIKey)
	}
	if loaded.Budget.DailyUSDLimit != 3.14 {
		t.Errorf("daily USD limit not recovered: got %v want 3.14", loaded.Budget.DailyUSDLimit)
	}
	if loaded.Budget.DailyTokenLimit != 99_999 {
		t.Errorf("daily token limit not recovered: got %d want 99999", loaded.Budget.DailyTokenLimit)
	}
}

func TestLoad_YAMLWinsOverSQLiteWhenBothPresent(t *testing.T) {
	// Hand-edited YAML must continue to take precedence — the SQLite mirror
	// is a recovery fallback, not the source of truth. Otherwise users who
	// edit config.yaml directly would be confused by stale SQLite values.
	dir := tempDir(t)
	initStateDB(t, dir)

	// Write via Save → both YAML and SQLite have the same blob.
	cfg := Default()
	cfg.Anthropic.APIKey = "sqlite-mirror-key"
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Now overwrite YAML directly with a different key.
	yaml := []byte("provider: claudecode\nanthropic:\n  api_key: yaml-edit-key\n")
	if err := os.WriteFile(ConfigPath(dir), yaml, 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Anthropic.APIKey != "yaml-edit-key" {
		t.Errorf("YAML must win over SQLite mirror; got %q want %q", loaded.Anthropic.APIKey, "yaml-edit-key")
	}
}

func TestSave_ChmodsStateDBTo0600(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("perm bits are POSIX only")
	}
	dir := tempDir(t)
	initStateDB(t, dir)

	// Make state.db world-readable to start.
	dbPath := stateDBPath(dir)
	if err := os.Chmod(dbPath, 0o644); err != nil {
		t.Fatalf("chmod 644: %v", err)
	}
	cfg := Default()
	cfg.Anthropic.APIKey = "sk-protected"
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	fi, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Errorf("state.db perms after Save: got %o want 600 (config carries API keys)", mode)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

// Tiny strings.Contains-equivalent local to avoid widening the imports.
func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
