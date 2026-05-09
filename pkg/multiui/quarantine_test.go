package multiui_test

// Regression tests for the corrupt-file quarantine path in multiui.Load.
//
// Before the fix a malformed ~/.cloop/projects.json (zero-byte from a torn
// pre-atomicfile write, schema drift after an upgrade, or a manual edit gone
// wrong) caused every Load to return the json.Unmarshal error. That bricked
// the entire multi-project Web UI — `cloop ui` listing, the projects SSE
// stream, the project picker — across every project on the host, since the
// registry is global. Recovery required `rm ~/.cloop/projects.json`. Now
// Load quarantines the bad bytes aside and returns (nil, nil) so the user
// can re-add projects via `cloop ui add`.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/multiui"
)

func TestLoad_CorruptFileQuarantined(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".cloop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "projects.json")
	// Truncated mid-object — the shape a torn write would produce if the
	// process was killed during MarshalIndent.
	if err := os.WriteFile(path, []byte(`{"projects":[{"name":"`), 0o644); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	got, err := multiui.Load()
	if err != nil {
		t.Fatalf("Load on corrupt file should not return an error, got: %v", err)
	}
	if got != nil {
		t.Errorf("Load on corrupt file should return nil entries, got: %+v", got)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected corrupt %s to be moved aside, stat err = %v", path, err)
	}
	entries, _ := os.ReadDir(dir)
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
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".cloop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "projects.json")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatalf("seed empty: %v", err)
	}

	got, err := multiui.Load()
	if err != nil {
		t.Fatalf("Load on zero-byte file should not return an error, got: %v", err)
	}
	if got != nil {
		t.Errorf("Load on zero-byte file should return nil entries, got: %+v", got)
	}
}
