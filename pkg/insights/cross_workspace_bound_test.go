package insights

// Regression test: --workspace JSON file reads are bounded.
//
// readLocalWorkspaceFile parses a user-supplied path (the --workspace flag
// in cmd/insights.go). Without a size cap, pointing it at a runaway file
// (a multi-GB log, /dev/zero, an accidentally renamed binary) would push
// the process into swap or get it OOM-killed. boundedread.ReadFile stats
// the file first and refuses to load anything larger than the configured
// cap, returning *boundedread.SizeError that matches errors.Is(err,
// ErrTooLarge).

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/boundedread"
)

// TestReadLocalWorkspaceFile_RejectsOversize verifies that a workspace
// file larger than the configured cap is rejected with ErrTooLarge,
// without the bytes ever reaching memory.
func TestReadLocalWorkspaceFile_RejectsOversize(t *testing.T) {
	prev := maxWorkspaceFileBytes
	maxWorkspaceFileBytes = 256
	t.Cleanup(func() { maxWorkspaceFileBytes = prev })

	dir := t.TempDir()
	path := filepath.Join(dir, "ws.json")

	// Write a payload comfortably above the cap. Content is irrelevant —
	// boundedread short-circuits on the stat() before reading any data.
	big := make([]byte, 4096)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(path, big, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, err := readLocalWorkspaceFile(path)
	if err == nil {
		t.Fatalf("expected size-cap error, got nil")
	}
	if !errors.Is(err, boundedread.ErrTooLarge) {
		t.Fatalf("expected boundedread.ErrTooLarge, got %v", err)
	}
}

// TestReadLocalWorkspaceFile_AcceptsSmallRegistry confirms a normally
// sized workspace registry still parses correctly under the cap. Catches
// regressions where the size guard mis-rejects valid input.
func TestReadLocalWorkspaceFile_AcceptsSmallRegistry(t *testing.T) {
	prev := maxWorkspaceFileBytes
	maxWorkspaceFileBytes = 1 << 20
	t.Cleanup(func() { maxWorkspaceFileBytes = prev })

	dir := t.TempDir()
	path := filepath.Join(dir, "ws.json")
	body := `{"workspaces":[{"name":"alpha","path":"/tmp/a"},{"name":"beta","path":"/tmp/b"}]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	entries, err := readLocalWorkspaceFile(path)
	if err != nil {
		t.Fatalf("readLocalWorkspaceFile: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entry count: want 2, got %d", len(entries))
	}
	if entries[0].Name != "alpha" || entries[1].Name != "beta" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

// TestReadLocalWorkspaceFile_AcceptsBareArrayFormat confirms the
// alternative [{"name":"","path":""}] format also parses correctly under
// the cap. This is the local format, vs. the wrapped-registry format
// covered above.
func TestReadLocalWorkspaceFile_AcceptsBareArrayFormat(t *testing.T) {
	prev := maxWorkspaceFileBytes
	maxWorkspaceFileBytes = 1 << 20
	t.Cleanup(func() { maxWorkspaceFileBytes = prev })

	dir := t.TempDir()
	path := filepath.Join(dir, "ws.json")
	body := `[{"name":"local","path":"/tmp/local"}]`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	entries, err := readLocalWorkspaceFile(path)
	if err != nil {
		t.Fatalf("readLocalWorkspaceFile: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "local" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}
