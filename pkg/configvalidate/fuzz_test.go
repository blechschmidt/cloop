package configvalidate

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// FuzzValidate feeds arbitrary bytes into Run() via the config.yaml on disk.
// Run reads, parses, and applies multiple semantic checks against the YAML —
// none of those passes should panic on hostile input. We do not use --probe
// (which would issue real HTTP requests) and we do not use --fix (which would
// rewrite the file).
func FuzzValidate(f *testing.F) {
	// Seeds spanning representative shapes the validator must tolerate.
	seeds := [][]byte{
		[]byte(""),
		[]byte("{}\n"),
		// Valid minimal config.
		[]byte("provider: anthropic\nanthropic:\n  api_key: sk-x\n  model: claude-sonnet-4-6\n"),
		// Unknown top-level key — must produce a WARN finding, not panic.
		[]byte("unknown_field: something\nprovider: anthropic\n"),
		// Out-of-range numerics — checkBudgetValues / checkNumericBounds path.
		[]byte("budget:\n  daily_usd_limit: -3.14\n  alert_threshold_pct: 250\n"),
		[]byte("max_parallel: 99999\n"),
		[]byte("rate_limit:\n  requests_per_second: -1\n  burst: -5\n"),
		// Bad URL.
		[]byte("ollama:\n  base_url: \"\\x00not-a-url\"\n"),
		// Router with bogus provider.
		[]byte("router:\n  routes:\n    backend: nopesuchprovider\n"),
		// Pathological YAML.
		[]byte(":\n: : :\n"),
		[]byte("- - - - -\n"),
		// BOM.
		[]byte("\xef\xbb\xbfprovider: anthropic\n"),
		// Garbage.
		[]byte("\x00\x01\xff\xfe"),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		// pkg/config exposes ConfigPath; we replicate the path here to avoid
		// pulling the import for one constant. Keeping it in sync is cheap.
		path := filepath.Join(dir, ".cloop", "config.yaml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}

		ctx := context.Background()
		// Probe=false: never hit the network. Fix=false: never rewrite the
		// fuzzer's input file (would break corpus reproduction).
		rep, err := Run(ctx, dir, ValidateOptions{Probe: false, Fix: false})
		if err != nil {
			t.Fatalf("Run returned an error (it should always succeed and surface findings instead): %v", err)
		}
		if rep == nil {
			t.Fatal("Run returned nil report")
		}
	})
}
