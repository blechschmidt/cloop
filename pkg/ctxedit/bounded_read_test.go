package ctxedit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/boundedread"
)

// TestLoadOverride_HappyPath verifies normal small overrides still load verbatim.
func TestLoadOverride_HappyPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, OverrideDir), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := "you are a helpful assistant"
	if err := os.WriteFile(OverridePath(dir, 7), []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := LoadOverride(dir, 7)
	if err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if got != body {
		t.Fatalf("body: want %q got %q", body, got)
	}
}

// TestLoadOverride_MissingReturnsEmpty verifies a missing override file is not
// treated as an error (callers depend on this — most tasks have no override).
func TestLoadOverride_MissingReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	got, err := LoadOverride(dir, 42)
	if err != nil {
		t.Fatalf("LoadOverride on missing file should return nil error, got: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty content, got %q", got)
	}
}

// TestLoadOverride_OversizeRejected verifies a 2 MiB override file is refused
// rather than slurped into memory. Uses os.Truncate so the test runs in
// constant time without allocating 2 MiB.
func TestLoadOverride_OversizeRejected(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, OverrideDir), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := OverridePath(dir, 99)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	f.Close()
	// 2 MiB — well over the 1 MiB cap.
	if err := os.Truncate(path, 2<<20); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	_, err = LoadOverride(dir, 99)
	if err == nil {
		t.Fatalf("expected size error, got nil")
	}
	if !errors.Is(err, boundedread.ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got: %v", err)
	}
	if !strings.Contains(err.Error(), "task 99") {
		t.Fatalf("expected error to identify task 99, got: %v", err)
	}
}
