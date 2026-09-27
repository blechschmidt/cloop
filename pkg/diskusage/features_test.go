package diskusage

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMeasureFilesSkipsFeatureWorktrees: a feature (Task 20341) is a source
// checkout with a .cloop of its own, so its bytes are neither this project's
// control state nor anything `cloop compact` could reclaim.
func TestMeasureFilesSkipsFeatureWorktrees(t *testing.T) {
	work := t.TempDir()
	cloop := filepath.Join(work, ".cloop")
	if err := os.MkdirAll(filepath.Join(cloop, "features", "login"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cloop, "features", "login", "big.bin"), make([]byte, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cloop, "config.yaml"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	u, err := MeasureFiles(work)
	if err != nil {
		t.Fatal(err)
	}
	if u.TotalBytes != 1 {
		t.Errorf("TotalBytes = %d, want 1 — the feature's tree was counted", u.TotalBytes)
	}
	for _, e := range u.Entries {
		if e.Name == "features" {
			t.Errorf("features listed as an entry: %+v", e)
		}
	}
}
