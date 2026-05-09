package cipipe

// Regression tests: tech-stack detection reads workspace project files
// (go.mod, package.json) with a size cap.
//
// Detect probes a workspace-relative directory; the files it reads are
// attacker-controlled in the sense that any repo cloop is pointed at could
// plant a runaway file under those names. Without a cap, os.ReadFile would
// load the entire payload into memory before parsing — a 5 GB go.mod would
// OOM-kill the process. boundedread.ReadFile stats the file first and skips
// loading any payload that exceeds maxProjectMetaFileBytes; on overshoot
// the corresponding TechStack field is left at its zero value (the file is
// treated as if absent for parsing purposes), but presence is still recorded
// from the os.Stat in `check`. The integration test below confirms both
// halves of that contract.

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDetect_GoModOversize confirms that an oversized go.mod is detected as
// present (HasGoMod=true) but its contents are *not* parsed (GoModule stays
// empty). The size guard short-circuits before any bytes reach memory.
func TestDetect_GoModOversize(t *testing.T) {
	prev := maxProjectMetaFileBytes
	maxProjectMetaFileBytes = 256
	t.Cleanup(func() { maxProjectMetaFileBytes = prev })

	dir := t.TempDir()
	// Plant a 4 KiB go.mod with a real "module" line; size guard should
	// still skip parsing because the file exceeds the cap.
	body := []byte("module example.com/big\n\n" + string(make([]byte, 4096)))
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), body, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	s := Detect(dir)
	if !s.HasGoMod {
		t.Fatalf("Detect should still flag presence via os.Stat: HasGoMod=%v", s.HasGoMod)
	}
	if s.GoModule != "" {
		t.Fatalf("oversize go.mod should not be parsed; got module=%q", s.GoModule)
	}
}

// TestDetect_GoModSmall confirms that a normally sized go.mod parses
// correctly under the cap. Catches regressions where the size guard
// mis-rejects valid input.
func TestDetect_GoModSmall(t *testing.T) {
	prev := maxProjectMetaFileBytes
	maxProjectMetaFileBytes = 1 << 20
	t.Cleanup(func() { maxProjectMetaFileBytes = prev })

	dir := t.TempDir()
	body := []byte("module example.com/small\n\ngo 1.25\n")
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), body, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	s := Detect(dir)
	if !s.HasGoMod {
		t.Fatalf("HasGoMod=false")
	}
	if s.GoModule != "example.com/small" {
		t.Fatalf("GoModule mismatch: got %q", s.GoModule)
	}
}

// TestDetect_PackageJSONOversize confirms that an oversized package.json
// is detected as present (HasPackageJSON=true) but its contents are *not*
// parsed (PackageName stays empty).
func TestDetect_PackageJSONOversize(t *testing.T) {
	prev := maxProjectMetaFileBytes
	maxProjectMetaFileBytes = 256
	t.Cleanup(func() { maxProjectMetaFileBytes = prev })

	dir := t.TempDir()
	body := []byte(`{"name":"big-pkg",` + string(make([]byte, 4096)) + `}`)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), body, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	s := Detect(dir)
	if !s.HasPackageJSON {
		t.Fatalf("Detect should still flag presence via os.Stat: HasPackageJSON=%v", s.HasPackageJSON)
	}
	if s.PackageName != "" {
		t.Fatalf("oversize package.json should not be parsed; got name=%q", s.PackageName)
	}
}

// TestDetect_PackageJSONSmall confirms a normally sized package.json
// parses correctly under the cap.
func TestDetect_PackageJSONSmall(t *testing.T) {
	prev := maxProjectMetaFileBytes
	maxProjectMetaFileBytes = 1 << 20
	t.Cleanup(func() { maxProjectMetaFileBytes = prev })

	dir := t.TempDir()
	body := []byte(`{
  "name": "small-pkg",
  "version": "1.0.0"
}`)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), body, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	s := Detect(dir)
	if !s.HasPackageJSON {
		t.Fatalf("HasPackageJSON=false")
	}
	if s.PackageName != "small-pkg" {
		t.Fatalf("PackageName mismatch: got %q", s.PackageName)
	}
}
