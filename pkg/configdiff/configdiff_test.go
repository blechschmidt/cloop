package configdiff

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// initStateDB creates an empty state.db so Save() will mirror into it.
func initStateDB(t *testing.T, workdir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(workdir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	db, err := statedb.Open(filepath.Join(workdir, ".cloop", "state.db"))
	if err != nil {
		t.Fatalf("open state.db: %v", err)
	}
	_ = db.Close()
}

// writeBlobToDB stomps the SQLite mirror with arbitrary YAML so we can
// simulate drift introduced from outside cloop (e.g. a stale binary or a
// hand-edited config.yaml).
func writeBlobToDB(t *testing.T, workdir, blob string) {
	t.Helper()
	db, err := statedb.Open(filepath.Join(workdir, ".cloop", "state.db"))
	if err != nil {
		t.Fatalf("open state.db: %v", err)
	}
	defer db.Close()
	if err := db.SetConfigBlob(blob); err != nil {
		t.Fatalf("set blob: %v", err)
	}
}

// findEntry returns the first entry matching the given path, or nil.
func findEntry(rep *Report, path string) *Entry {
	for i := range rep.Entries {
		if rep.Entries[i].Path == path {
			return &rep.Entries[i]
		}
	}
	return nil
}

// TestCompute_NoDrift verifies the happy path: YAML and SQLite written via
// the same Save() call must compare equal.
func TestCompute_NoDrift(t *testing.T) {
	dir := t.TempDir()
	initStateDB(t, dir)

	cfg := config.Default()
	cfg.Provider = "anthropic"
	cfg.Anthropic.APIKey = "sk-aligned"
	cfg.Budget.DailyUSDLimit = 4.20
	if err := config.Save(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	rep, err := Compute(dir)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if !rep.YAMLPresent || !rep.DBPresent {
		t.Fatalf("expected both stores present, got yaml=%v db=%v", rep.YAMLPresent, rep.DBPresent)
	}
	if len(rep.Entries) != 0 {
		t.Errorf("expected no drift, got %d entries:\n%s", len(rep.Entries), Render(rep))
	}
	if rep.HasDrift() {
		t.Errorf("HasDrift() should be false")
	}
}

// TestCompute_DriftAfterMutatingYAML is the spec-required test: mutate one
// source after Save(), run diff, verify the expected key differences are
// reported.
func TestCompute_DriftAfterMutatingYAML(t *testing.T) {
	dir := t.TempDir()
	initStateDB(t, dir)

	// Establish baseline: both stores aligned.
	cfg := config.Default()
	cfg.Provider = "anthropic"
	cfg.Anthropic.APIKey = "sk-original"
	cfg.Anthropic.Model = "claude-opus-4-6"
	cfg.Budget.DailyUSDLimit = 5.00
	cfg.MaxParallel = 4
	if err := config.Save(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Now mutate the YAML directly without going through Save() — this
	// simulates a hand-edit that doesn't refresh the SQLite mirror.
	mutated := config.Default()
	mutated.Provider = "openai"             // changed
	mutated.Anthropic.APIKey = "sk-changed" // changed
	mutated.Anthropic.Model = "claude-opus-4-6"
	mutated.Budget.DailyUSDLimit = 5.00
	mutated.OpenAI.APIKey = "sk-newkey" // added (didn't exist before)
	// MaxParallel removed entirely
	data, err := yaml.Marshal(mutated)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(config.ConfigPath(dir), data, 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	rep, err := Compute(dir)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if !rep.HasDrift() {
		t.Fatalf("expected drift, got none")
	}

	// provider: changed anthropic → openai
	e := findEntry(rep, "provider")
	if e == nil || e.Kind != Changed || e.YAMLValue != "openai" || e.DBValue != "anthropic" {
		t.Errorf("provider drift wrong: %+v", e)
	}

	// anthropic.api_key: changed sk-original → sk-changed
	// (note: in YAML view, "yaml" is left/new; "db" is right/old)
	e = findEntry(rep, "anthropic.api_key")
	if e == nil || e.Kind != Changed || e.YAMLValue != "sk-changed" || e.DBValue != "sk-original" {
		t.Errorf("anthropic.api_key drift wrong: %+v", e)
	}

	// openai.api_key: added in YAML (not in DB).
	// NB: yaml.v3 + omitempty means the DB blob may not even include this key,
	// or may include it as empty string. Either way it should surface.
	e = findEntry(rep, "openai.api_key")
	if e == nil {
		t.Errorf("expected drift entry for openai.api_key; entries:\n%s", Render(rep))
	} else if e.YAMLValue != "sk-newkey" {
		t.Errorf("openai.api_key YAML side wrong: got %q want sk-newkey", e.YAMLValue)
	}

	// max_parallel: was 4 in DB, not in YAML (omitempty stripped it). The
	// diff convention is "Added means only in DB" — so this surfaces as
	// Added, not Removed.
	e = findEntry(rep, "max_parallel")
	if e == nil {
		t.Errorf("expected drift entry for max_parallel; entries:\n%s", Render(rep))
	} else if e.Kind != Added || e.DBValue != "4" {
		t.Errorf("max_parallel drift wrong: got kind=%s yaml=%q db=%q want kind=added db=4", e.Kind, e.YAMLValue, e.DBValue)
	}
}

// TestCompute_DriftAfterMutatingDB simulates a stale or corrupt mirror by
// rewriting the SQLite blob without touching YAML. Doctor and config diff
// must surface this.
func TestCompute_DriftAfterMutatingDB(t *testing.T) {
	dir := t.TempDir()
	initStateDB(t, dir)

	cfg := config.Default()
	cfg.Provider = "anthropic"
	cfg.Anthropic.APIKey = "sk-current"
	if err := config.Save(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Now stomp the SQLite mirror with an old/different blob.
	stale := "provider: ollama\nanthropic:\n  api_key: sk-stale\n  model: claude-opus-4-6\n"
	writeBlobToDB(t, dir, stale)

	rep, err := Compute(dir)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if !rep.HasDrift() {
		t.Fatalf("expected drift, got none:\n%s", Render(rep))
	}
	e := findEntry(rep, "provider")
	if e == nil || e.Kind != Changed || e.YAMLValue != "anthropic" || e.DBValue != "ollama" {
		t.Errorf("provider drift wrong: %+v", e)
	}
	e = findEntry(rep, "anthropic.api_key")
	if e == nil || e.Kind != Changed || e.YAMLValue != "sk-current" || e.DBValue != "sk-stale" {
		t.Errorf("anthropic.api_key drift wrong: %+v", e)
	}
}

// TestCompute_YAMLOnly: SQLite mirror missing entirely (e.g. fresh project
// before any state.db has been created). Drift report should flag it so the
// user can run sync.
func TestCompute_YAMLOnly(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Provider = "openai"
	if err := config.Save(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	// state.db never created — Save's mirror is a no-op.

	rep, err := Compute(dir)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if !rep.YAMLPresent {
		t.Fatal("expected yaml present")
	}
	if rep.DBPresent {
		t.Fatal("expected db absent")
	}
	if !rep.HasDrift() {
		t.Fatal("YAML-only state should be reported as drift (mirror needs initialising)")
	}
	if !strings.Contains(rep.Summary(), "missing") {
		t.Errorf("summary should mention missing mirror, got %q", rep.Summary())
	}
}

// TestCompute_BothMissing: a directory without any config at all should not
// be reported as drift — it's just an uninitialised project.
func TestCompute_BothMissing(t *testing.T) {
	dir := t.TempDir()
	rep, err := Compute(dir)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if rep.HasDrift() {
		t.Fatal("empty directory should not be reported as drift")
	}
}

// TestSync_FromYAML restores the SQLite mirror after it was stomped.
func TestSync_FromYAML(t *testing.T) {
	dir := t.TempDir()
	initStateDB(t, dir)

	cfg := config.Default()
	cfg.Provider = "anthropic"
	cfg.Anthropic.APIKey = "sk-canonical"
	if err := config.Save(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	writeBlobToDB(t, dir, "provider: ollama\nanthropic:\n  api_key: sk-stomped\n")

	// Confirm drift is present before sync.
	pre, err := Compute(dir)
	if err != nil {
		t.Fatalf("pre-compute: %v", err)
	}
	if !pre.HasDrift() {
		t.Fatal("expected drift before sync")
	}

	if err := Sync(dir, FromYAML); err != nil {
		t.Fatalf("sync: %v", err)
	}

	post, err := Compute(dir)
	if err != nil {
		t.Fatalf("post-compute: %v", err)
	}
	if post.HasDrift() {
		t.Fatalf("expected no drift after sync from-yaml, got:\n%s", Render(post))
	}
}

// TestSync_FromDB recovers a missing YAML from the SQLite mirror.
func TestSync_FromDB(t *testing.T) {
	dir := t.TempDir()
	initStateDB(t, dir)

	cfg := config.Default()
	cfg.Provider = "openai"
	cfg.OpenAI.APIKey = "sk-recovery"
	cfg.Budget.DailyUSDLimit = 9.99
	if err := config.Save(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Simulate accidental deletion of config.yaml.
	if err := os.Remove(config.ConfigPath(dir)); err != nil {
		t.Fatalf("rm yaml: %v", err)
	}

	if err := Sync(dir, FromDB); err != nil {
		t.Fatalf("sync from-db: %v", err)
	}

	// YAML must exist now.
	if _, err := os.Stat(config.ConfigPath(dir)); err != nil {
		t.Fatalf("yaml not restored: %v", err)
	}
	loaded, err := config.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.OpenAI.APIKey != "sk-recovery" {
		t.Errorf("api key not restored: got %q", loaded.OpenAI.APIKey)
	}
	if loaded.Budget.DailyUSDLimit != 9.99 {
		t.Errorf("budget not restored: got %v want 9.99", loaded.Budget.DailyUSDLimit)
	}
}

// TestSync_FromDBFailsWithoutMirror: refusing to overwrite YAML with empty
// data is critical — otherwise a fresh project's first sync command would
// blank out config.yaml.
func TestSync_FromDBFailsWithoutMirror(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Anthropic.APIKey = "sk-keep-this"
	if err := config.Save(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	// state.db doesn't exist, so no mirror.
	err := Sync(dir, FromDB)
	if err == nil {
		t.Fatal("expected error syncing from-db with no mirror")
	}
	if !strings.Contains(err.Error(), "mirror") {
		t.Errorf("error message should mention mirror, got: %v", err)
	}
	// YAML must be untouched.
	loaded, err := config.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Anthropic.APIKey != "sk-keep-this" {
		t.Errorf("yaml should not have been modified; got api_key=%q", loaded.Anthropic.APIKey)
	}
}

// TestSync_UnknownDirection rejects bogus direction strings.
func TestSync_UnknownDirection(t *testing.T) {
	dir := t.TempDir()
	if err := Sync(dir, Direction("bogus")); err == nil {
		t.Fatal("expected error for unknown direction")
	}
}

// TestRender_MasksSensitiveValues: secret-bearing diff entries must not
// expose raw values. This is the property doctor and `cloop config diff`
// rely on for safe interactive output.
func TestRender_MasksSensitiveValues(t *testing.T) {
	rep := &Report{
		YAMLPresent: true,
		DBPresent:   true,
		Entries: []Entry{
			{Path: "anthropic.api_key", Kind: Changed, YAMLValue: "sk-very-long-secret-yaml", DBValue: "sk-very-long-secret-db-old"},
			{Path: "github.token", Kind: Removed, YAMLValue: "ghp_long-secret"},
			{Path: "provider", Kind: Changed, YAMLValue: "openai", DBValue: "anthropic"},
		},
	}
	out := Render(rep)
	if strings.Contains(out, "sk-very-long-secret-yaml") {
		t.Error("YAML api key leaked in Render output")
	}
	if strings.Contains(out, "sk-very-long-secret-db-old") {
		t.Error("DB api key leaked in Render output")
	}
	if strings.Contains(out, "ghp_long-secret") {
		t.Error("GitHub token leaked in Render output")
	}
	// Non-sensitive value should appear in the clear.
	if !strings.Contains(out, "openai") || !strings.Contains(out, "anthropic") {
		t.Errorf("provider value missing from output:\n%s", out)
	}
}

// TestIsSensitive covers the path-substring detection used by Render.
func TestIsSensitive(t *testing.T) {
	cases := map[string]bool{
		"anthropic.api_key":      true,
		"openai.api_key":         true,
		"github.token":           true,
		"webhook.secret":         true,
		"webhook.url":            true, // "webhook" is in the substring list
		"notify.slack_webhook":   true,
		"provider":               false,
		"anthropic.model":        false,
		"budget.daily_usd_limit": false,
	}
	for path, want := range cases {
		if got := IsSensitive(path); got != want {
			t.Errorf("IsSensitive(%q) = %v, want %v", path, got, want)
		}
	}
}
