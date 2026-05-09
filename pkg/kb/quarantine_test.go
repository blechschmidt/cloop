package kb_test

// Regression tests for the corrupt-file quarantine path in kb.Load.
//
// Before the fix a malformed .cloop/kb.json (zero-byte from a torn
// pre-atomicfile write, schema drift, or a manual edit gone wrong) caused
// Load to return `kb: parse: ...`. That error path silently disabled
// context injection on every subsequent task — `cloop run` proceeded with
// the AI deprived of the project's accumulated knowledge instead of
// surfacing the corruption — and the only fix was a manual `rm`. Now Load
// quarantines the bad bytes aside and returns an empty KB so the next Add
// can rebuild from scratch, with the original bytes preserved next to the
// original path for forensics.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/kb"
)

func TestLoad_CorruptFileQuarantined(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, ".cloop", "kb.json")
	// Truncated JSON object — exactly the shape a torn pre-atomicfile write
	// would produce if the writer was killed during MarshalIndent.
	if err := os.WriteFile(path, []byte(`{"entries":[{"id":1,"title":`), 0o644); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	got, err := kb.Load(dir)
	if err != nil {
		t.Fatalf("Load on corrupt file should not return an error, got: %v", err)
	}
	if got == nil {
		t.Fatalf("Load on corrupt file should return empty KB, got nil")
	}
	if len(got.Entries) != 0 {
		t.Errorf("expected empty KB after quarantine, got %d entries", len(got.Entries))
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected corrupt %s to be moved aside, stat err = %v", path, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	found := false
	for _, e := range entries {
		if strings.Contains(e.Name(), ".corrupt-") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a .corrupt-* sibling preserving the bad bytes, dir contents: %v", entries)
	}
}

func TestLoad_ZeroByteFileQuarantined(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, ".cloop", "kb.json")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatalf("seed empty: %v", err)
	}

	got, err := kb.Load(dir)
	if err != nil {
		t.Fatalf("Load on zero-byte file should not return an error, got: %v", err)
	}
	if got == nil || len(got.Entries) != 0 {
		t.Errorf("expected empty KB after zero-byte quarantine, got: %+v", got)
	}
}
