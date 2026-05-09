package trace_test

// Regression tests for the corrupt-file quarantine path in
// trace.LoadTraceJSON.
//
// Before the fix a malformed .cloop/trace.json (zero-byte from a torn
// pre-atomicfile write, schema drift, or a manual edit gone wrong) caused
// every LoadTraceJSON to return the json.Unmarshal error. `cloop status`
// calls LastLinkedCommit on every invocation and any orchestrator path
// that wants to correlate commits to tasks fanned the error up to the
// user. The trace map is a derived index — losing it costs nothing once
// the next commit-walk repopulates — so quarantining the bad bytes and
// returning (nil, nil) is strictly better than refusing every status
// query until the user `rm`s the file.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/trace"
)

func TestLoadTraceJSON_CorruptFileQuarantined(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, ".cloop", "trace.json")
	if err := os.WriteFile(path, []byte(`{"generated_at":"2026-`), 0o644); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	got, err := trace.LoadTraceJSON(dir)
	if err != nil {
		t.Fatalf("LoadTraceJSON on corrupt file should not return an error, got: %v", err)
	}
	if got != nil {
		t.Errorf("LoadTraceJSON on corrupt file should return nil, got: %+v", got)
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

func TestLastLinkedCommit_RecoversFromCorruptTrace(t *testing.T) {
	// LastLinkedCommit is the single most-called consumer of the trace
	// (every `cloop status`). Pre-fix: returns nil but logs nothing because
	// LoadTraceJSON's error swallowed the actual cause. With quarantine, a
	// corrupt trace still resolves to nil here AND the bad bytes are moved
	// aside so the next commit-walk can rebuild the map cleanly.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, ".cloop", "trace.json")
	if err := os.WriteFile(path, []byte("not json at all"), 0o644); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	if got := trace.LastLinkedCommit(dir); got != nil {
		t.Errorf("LastLinkedCommit on corrupt trace should return nil, got: %+v", got)
	}
	// And the bad bytes should now be aside, freeing the path for a clean
	// next write.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected corrupt trace.json to be moved aside, stat err = %v", err)
	}
}
