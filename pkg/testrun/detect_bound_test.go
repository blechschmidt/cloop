package testrun

// Regression tests: package.json reads in detectNodeFramework are bounded.
//
// Detect probes a workspace-relative directory and reads package.json to
// pick between vitest, jest, and the npm test fallback. Without a size
// cap, a hostile or accidentally-runaway package.json (e.g. /dev/zero
// renamed) would be slurped into memory before json.Unmarshal could even
// look at it. boundedread.ReadFile stats the file first and refuses to
// load anything larger than maxPackageJSONBytes; on overshoot
// detectNodeFramework returns nil (caller treats as "no Node project").

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDetectNodeFramework_PackageJSONOversize confirms that an oversized
// package.json is treated as if absent — detectNodeFramework returns nil
// without ever loading the payload into memory.
func TestDetectNodeFramework_PackageJSONOversize(t *testing.T) {
	prev := maxPackageJSONBytes
	maxPackageJSONBytes = 256
	t.Cleanup(func() { maxPackageJSONBytes = prev })

	dir := t.TempDir()
	// 4 KiB > 256 B cap — boundedread.ReadFile short-circuits on stat().
	body := []byte(`{"scripts":{"test":"vitest"},"_pad":"` + string(make([]byte, 4096)) + `"}`)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), body, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if got := detectNodeFramework(dir); got != nil {
		t.Fatalf("oversize package.json should yield nil framework; got %+v", got)
	}
}

// TestDetectNodeFramework_PackageJSONSmall confirms a normally sized
// package.json parses correctly under the cap. Catches regressions where
// the size guard mis-rejects valid input.
func TestDetectNodeFramework_PackageJSONSmall(t *testing.T) {
	prev := maxPackageJSONBytes
	maxPackageJSONBytes = 1 << 20
	t.Cleanup(func() { maxPackageJSONBytes = prev })

	dir := t.TempDir()
	body := []byte(`{"scripts":{"test":"vitest"},"devDependencies":{"vitest":"^1.0.0"}}`)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), body, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got := detectNodeFramework(dir)
	if got == nil {
		t.Fatalf("expected vitest framework, got nil")
	}
	if got.Name != "vitest" {
		t.Fatalf("framework name: want vitest, got %q", got.Name)
	}
}

// TestDetectNodeFramework_PackageJSONMissing confirms the absence path
// continues to work — a missing file should also produce nil.
func TestDetectNodeFramework_PackageJSONMissing(t *testing.T) {
	dir := t.TempDir()
	if got := detectNodeFramework(dir); got != nil {
		t.Fatalf("missing package.json should yield nil framework; got %+v", got)
	}
}
