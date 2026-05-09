package memory_test

// Regression tests for the corrupt-file quarantine path in memory.Load.
//
// memory.json holds the persistent learnings injected into every future
// session prompt. Before the fix, a single bad save (zero-byte from a torn
// pre-atomicfile write, schema drift after an upgrade, manual edit gone
// wrong) returned `parse memory: ...`. Most callers — including the prompt
// builder — silently swallowed the error and treated memory as empty, which
// meant a one-time corruption could erase the entire knowledge base for the
// rest of the run without any operator-visible signal. Now Load quarantines
// the bad bytes aside, prints a stderr warning, and returns an empty Memory
// — making the loss explicit and preserving the bytes for forensics.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/memory"
)

func TestLoad_CorruptFileQuarantined(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, ".cloop", "memory.json")
	// Truncated mid-array — same shape as a torn write.
	if err := os.WriteFile(path, []byte(`{"entries":[{"id":1,"content":`), 0o644); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	m, err := memory.Load(dir)
	if err != nil {
		t.Fatalf("Load on corrupt file should not return an error, got: %v", err)
	}
	if m == nil {
		t.Fatal("Load on corrupt file should return a non-nil empty Memory")
	}
	if len(m.Entries) != 0 {
		t.Errorf("expected empty entries on corrupt file, got %d", len(m.Entries))
	}
	if m.NextID != 1 {
		t.Errorf("expected NextID=1 on fresh memory, got %d", m.NextID)
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
	path := filepath.Join(dir, ".cloop", "memory.json")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatalf("seed empty: %v", err)
	}

	m, err := memory.Load(dir)
	if err != nil {
		t.Fatalf("Load on zero-byte file should not return an error, got: %v", err)
	}
	if m == nil || len(m.Entries) != 0 {
		t.Errorf("expected empty Memory, got %+v", m)
	}
}
