package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/boundedread"
)

// TestActiveDir_OversizedActiveSessionFile guards against pkg/state slurping a
// runaway .cloop/active_session into memory. ActiveDir promises a graceful
// fallback to workDir on any read error, so an oversized file should produce
// the same fallback rather than allocating the whole file.
func TestActiveDir_OversizedActiveSessionFile(t *testing.T) {
	prev := maxActiveSessionBytes
	maxActiveSessionBytes = 32
	t.Cleanup(func() { maxActiveSessionBytes = prev })

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// 4 KiB — well past the 32-byte test cap. Use a single-line blob so the
	// pre-cap version (TrimSpace on the whole thing) would also have produced
	// a wrong answer, not just an OOM hazard.
	blob := strings.Repeat("x", 4*1024)
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "active_session"), []byte(blob), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := ActiveDir(dir)
	if got != dir {
		t.Fatalf("ActiveDir = %q, want fallback to %q (oversized file should be treated as missing)", got, dir)
	}
}

// TestActiveDir_HappyPath ensures the bounded-read swap didn't change the
// behaviour for the small-file case ActiveDir is designed for.
func TestActiveDir_HappyPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "active_session"), []byte("alpha\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := ActiveDir(dir)
	want := filepath.Join(dir, ".cloop", "sessions", "alpha")
	if got != want {
		t.Fatalf("ActiveDir = %q, want %q", got, want)
	}
}

// TestMigrateFromJSON_RefusesOversizedLegacyState verifies the legacy state.json
// migration path refuses to load anything past the cap. Returning an error here
// is the right outcome — silently producing an empty state would lose data;
// failing loudly tells the user the legacy file is corrupt or runaway.
func TestMigrateFromJSON_RefusesOversizedLegacyState(t *testing.T) {
	prev := maxLegacyStateBytes
	maxLegacyStateBytes = 256
	t.Cleanup(func() { maxLegacyStateBytes = prev })

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "state.json")
	dbPath := filepath.Join(dir, "state.db")
	// 4 KiB of valid-looking JSON — past the 256-byte test cap.
	blob := `{"goal":"` + strings.Repeat("x", 4*1024) + `"}`
	if err := os.WriteFile(jsonPath, []byte(blob), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := migrateFromJSON(dir, jsonPath, dbPath)
	if err == nil {
		t.Fatal("expected migrateFromJSON to refuse oversized state.json, got nil")
	}
	if !errors.Is(err, boundedread.ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
	if _, statErr := os.Stat(dbPath); statErr == nil {
		t.Errorf("state.db was created despite oversized legacy file — migration should be all-or-nothing")
	}
}
