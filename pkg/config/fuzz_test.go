package config

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoadConfig feeds arbitrary bytes into Load() via the config.yaml on disk.
// Goal: surface panics in YAML decoding and the validateAndClamp / applyEnvVars
// post-processing path. Load() must always return either a populated Config or
// an error — never panic — even on torn writes, mojibake, or hostile YAML.
func FuzzLoadConfig(f *testing.F) {
	// Seeds derived from real fixtures: a fully-populated config, an empty
	// document, and a few edge cases that have historically tripped YAML
	// decoders (anchors, aliases, !!str tags, BOMs, deeply nested maps).
	seeds := [][]byte{
		[]byte(""),
		[]byte("{}\n"),
		[]byte("provider: anthropic\n"),
		[]byte("provider: openai\nopenai:\n  api_key: sk-fixture\n  model: gpt-4o\n"),
		[]byte("max_parallel: 8\nbudget:\n  daily_usd_limit: 5.0\n  alert_threshold_pct: 80\n"),
		[]byte("provider: claudecode\nclaudecode:\n  model: claude-sonnet-4-6\n  max_weekly_pct: 90\n"),
		// Pathological numerics — must clamp, not panic.
		[]byte("max_parallel: -1\n"),
		[]byte("max_parallel: 999999\n"),
		[]byte("budget:\n  daily_usd_limit: -3.14\n"),
		// Anchors / aliases.
		[]byte("a: &x\n  k: v\nb: *x\n"),
		// Indentation chaos.
		[]byte("provider:\n\t\tanthropic\n"),
		// Unicode / BOM.
		[]byte("\xef\xbb\xbfprovider: anthropic\n"),
		// Outright garbage.
		[]byte("\x00\x01\x02\x03\x04"),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		path := ConfigPath(dir)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		// Load may legitimately return a YAML parse error; that is fine.
		// Anything else (panic, fatal) is a bug.
		cfg, err := Load(dir)
		if err == nil && cfg == nil {
			t.Fatal("Load returned nil cfg with nil error")
		}
	})
}
