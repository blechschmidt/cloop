package clarify_test

// Regression tests for the corrupt-file quarantine path in clarify.Load.
//
// Before the fix a malformed .cloop/clarification.json (zero-byte from a
// torn pre-atomicfile write, schema drift, or a manual edit gone wrong)
// caused Load to return `clarification: parse: ...`. Callers in cmd/run.go
// and the orchestrator treated that as fatal, blocking `cloop run --pm`
// from progressing to decomposition until the user manually deleted the
// file. Now Load quarantines the bad bytes aside and returns (nil, nil)
// so the next decomposition either re-prompts (TTY) or proceeds without
// the audit (non-interactive).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/clarify"
)

func TestLoad_CorruptFileQuarantined(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := clarify.ClarificationPath(dir)
	// Truncated mid-array — what a torn pre-atomicfile write would produce.
	if err := os.WriteFile(path, []byte(`[{"question":"what is`), 0o644); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	got, err := clarify.Load(dir)
	if err != nil {
		t.Fatalf("Load on corrupt file should not return an error, got: %v", err)
	}
	if got != nil {
		t.Errorf("Load on corrupt file should return nil QA slice, got: %+v", got)
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
	path := clarify.ClarificationPath(dir)
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatalf("seed empty: %v", err)
	}

	got, err := clarify.Load(dir)
	if err != nil {
		t.Fatalf("Load on zero-byte file should not return an error, got: %v", err)
	}
	if got != nil {
		t.Errorf("Load on zero-byte file should return nil QA slice, got: %+v", got)
	}
}
