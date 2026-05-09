package agent_test

// Regression tests for the corrupt-file quarantine path in agent.Load.
//
// Before the fix a malformed agent.json (zero-byte from a torn pre-atomicfile
// write, schema drift after an upgrade, or a manual edit gone wrong) caused
// every Load to return `corrupt agent state: ...`, which propagated up to
// `cloop agent status`, every heartbeat read in the daemon worker, and the
// orchestrator's preflight checks. Recovery required the user to manually
// delete the file. Now Load quarantines the bad bytes aside and returns
// (nil, nil) so the next Save can recreate the file from scratch — and the
// original bytes are preserved for forensics.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/agent"
)

func TestLoad_CorruptFileQuarantined(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := agent.StatePath(dir)
	// Truncated mid-object — exactly the shape a torn pre-atomicfile write
	// would have produced if the daemon was killed during MarshalIndent.
	if err := os.WriteFile(path, []byte(`{"pid":42, "status":`), 0o644); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	got, err := agent.Load(dir)
	if err != nil {
		t.Fatalf("Load on corrupt file should not return an error, got: %v", err)
	}
	if got != nil {
		t.Errorf("Load on corrupt file should return nil State, got: %+v", got)
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
	path := agent.StatePath(dir)
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatalf("seed empty: %v", err)
	}

	got, err := agent.Load(dir)
	if err != nil {
		t.Fatalf("Load on zero-byte file should not return an error, got: %v", err)
	}
	if got != nil {
		t.Errorf("Load on zero-byte file should return nil State, got: %+v", got)
	}
}
