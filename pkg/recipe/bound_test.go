package recipe

// Regression tests: recipe Load and fetchSource (local-file path) read
// user-supplied YAML through a size cap.
//
// Recipes are config files installed via `cloop recipe install <source>`,
// where <source> can be a local path or HTTP(S) URL. Without a cap, an
// attacker-controlled --source pointing at a multi-GB file (or a runaway
// payload landing in .cloop/recipes/<name>.yaml after a torn write) would
// be loaded entirely into memory by os.ReadFile before parsing — enough to
// OOM-kill cloop. boundedread.ReadFile stats the file first and refuses to
// load any payload that exceeds maxRecipeBytes; the *boundedread.SizeError
// matches errors.Is(err, boundedread.ErrTooLarge).
//
// The HTTP path is already bounded via provider.ReadResponseBody +
// maxRecipeBytes (covered by separate tests in pkg/provider) — this file
// covers the local-file paths.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/boundedread"
)

// validRecipeYAML returns a minimal but valid recipe YAML payload. Used as
// the body for tests where we want the parse to succeed under the cap.
func validRecipeYAML() []byte {
	return []byte(`name: bound-test
description: regression test recipe
flow_yaml: |
  name: inner
  steps:
    - name: noop
      command: lint
`)
}

// TestLoad_OversizeRejected confirms that an oversize recipe file in
// .cloop/recipes/<name>.yaml is rejected with *boundedread.SizeError before
// any bytes are loaded — the OOM blast radius stays bounded even if the
// recipes directory holds a runaway file.
func TestLoad_OversizeRejected(t *testing.T) {
	prev := maxRecipeBytes
	maxRecipeBytes = 256
	t.Cleanup(func() { maxRecipeBytes = prev })

	workDir := t.TempDir()
	dir := filepath.Join(workDir, ".cloop", "recipes")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Plant a 4 KiB file containing valid recipe YAML padded with comments —
	// well over the 256-byte cap.
	body := append(validRecipeYAML(), make([]byte, 4096)...)
	if err := os.WriteFile(filepath.Join(dir, "big.yaml"), body, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, err := Load(workDir, "big")
	if err == nil {
		t.Fatalf("Load: want error, got nil")
	}
	if !errors.Is(err, boundedread.ErrTooLarge) {
		t.Fatalf("Load: want boundedread.ErrTooLarge, got %v", err)
	}
}

// TestLoad_UnderCapParses confirms that a normally sized recipe parses
// correctly under the cap. Catches regressions where the size guard
// mis-rejects valid input.
func TestLoad_UnderCapParses(t *testing.T) {
	prev := maxRecipeBytes
	maxRecipeBytes = 1 << 20
	t.Cleanup(func() { maxRecipeBytes = prev })

	workDir := t.TempDir()
	dir := filepath.Join(workDir, ".cloop", "recipes")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ok.yaml"), validRecipeYAML(), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	r, err := Load(workDir, "ok")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if r.Name != "bound-test" {
		t.Fatalf("Name mismatch: got %q", r.Name)
	}
}

// TestLoad_MissingFileError confirms that the not-found branch still
// produces the user-facing "recipe %q not found …" message — i.e. the
// boundedread.ReadFile error is correctly funneled into the existing
// os.IsNotExist path rather than leaking a generic boundedread error.
func TestLoad_MissingFileError(t *testing.T) {
	workDir := t.TempDir()
	_, err := Load(workDir, "does-not-exist")
	if err == nil {
		t.Fatalf("Load: want error, got nil")
	}
	if !strings.Contains(err.Error(), `recipe "does-not-exist" not found`) {
		t.Fatalf("Load: missing-file error mismatch, got %v", err)
	}
}

// TestInstall_LocalSourceOversizeRejected confirms that `cloop recipe
// install <local-path>` short-circuits when the source file exceeds the
// cap — the attacker-controlled path is the highest-risk surface here.
func TestInstall_LocalSourceOversizeRejected(t *testing.T) {
	prev := maxRecipeBytes
	maxRecipeBytes = 256
	t.Cleanup(func() { maxRecipeBytes = prev })

	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "huge.yaml")
	body := append(validRecipeYAML(), make([]byte, 4096)...)
	if err := os.WriteFile(src, body, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	workDir := t.TempDir()
	_, err := Install(workDir, src)
	if err == nil {
		t.Fatalf("Install: want error, got nil")
	}
	if !errors.Is(err, boundedread.ErrTooLarge) {
		t.Fatalf("Install: want boundedread.ErrTooLarge, got %v", err)
	}

	// And the destination must NOT have been created — the size check
	// short-circuits before parsing or writing.
	if _, statErr := os.Stat(filepath.Join(workDir, ".cloop", "recipes")); !os.IsNotExist(statErr) {
		t.Fatalf("recipes dir should not exist after rejected install (stat err=%v)", statErr)
	}
}

// TestInstall_LocalSourceUnderCapSucceeds confirms a normally sized
// install still works — guards against the cap mis-rejecting valid input.
func TestInstall_LocalSourceUnderCapSucceeds(t *testing.T) {
	prev := maxRecipeBytes
	maxRecipeBytes = 1 << 20
	t.Cleanup(func() { maxRecipeBytes = prev })

	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "ok.yaml")
	if err := os.WriteFile(src, validRecipeYAML(), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	workDir := t.TempDir()
	r, err := Install(workDir, src)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if r.Name != "bound-test" {
		t.Fatalf("Name mismatch: got %q", r.Name)
	}
	// And the destination should exist on disk.
	dest := filepath.Join(workDir, ".cloop", "recipes", "bound-test.yaml")
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("dest stat: %v", err)
	}
}
