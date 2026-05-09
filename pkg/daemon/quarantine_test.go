package daemon_test

// Regression tests for the corrupt-file quarantine path in daemon.Load.
//
// A torn write of daemon.json — most plausibly from a SIGKILL during
// MarshalIndent in a pre-atomicfile binary, or a `truncate -s 0` from outside
// cloop — used to make Load return `corrupt daemon state: ...`. That error
// propagated to `cloop daemon status`, the orchestrator's pre-run heartbeat
// check, and the daemon worker's own self-read on next tick. Now Load
// quarantines the bad bytes aside and returns (nil, nil) so the daemon can
// rebuild its state from scratch on the next Save.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/daemon"
)

func TestLoad_CorruptFileQuarantined(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := daemon.StatePath(dir)
	if err := os.WriteFile(path, []byte(`{"pid":42, "status":`), 0o644); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	got, err := daemon.Load(dir)
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
	path := daemon.StatePath(dir)
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatalf("seed empty: %v", err)
	}

	got, err := daemon.Load(dir)
	if err != nil {
		t.Fatalf("Load on zero-byte file should not return an error, got: %v", err)
	}
	if got != nil {
		t.Errorf("Load on zero-byte file should return nil State, got: %+v", got)
	}
}
