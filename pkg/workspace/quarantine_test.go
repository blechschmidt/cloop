package workspace_test

// Regression tests for the corrupt-file quarantine path in workspace.load.
//
// The workspace registry lives in the user's XDG config dir, so a single bad
// save would brick every `cloop workspace *` subcommand globally — across all
// projects on the machine — until the user manually deleted the file.
// Quarantining converts that hard-fail into a soft reset: the bad bytes are
// preserved next to the original location for forensics, and the next `cloop
// workspace add` writes a fresh registry.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/workspace"
)

func TestList_CorruptRegistryQuarantined(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	regDir := filepath.Join(tmp, "cloop")
	if err := os.MkdirAll(regDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	regPath := filepath.Join(regDir, "workspaces.json")
	if err := os.WriteFile(regPath, []byte(`{"workspaces":[{"name":"a"`), 0o644); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	got, err := workspace.List()
	if err != nil {
		t.Fatalf("List on corrupt registry should not return an error, got: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty workspace list on corrupt registry, got %d", len(got))
	}

	if _, err := os.Stat(regPath); !os.IsNotExist(err) {
		t.Errorf("expected corrupt %s to be moved aside, stat err = %v", regPath, err)
	}
	entries, _ := os.ReadDir(regDir)
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

func TestList_ZeroByteRegistryQuarantined(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	regDir := filepath.Join(tmp, "cloop")
	if err := os.MkdirAll(regDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	regPath := filepath.Join(regDir, "workspaces.json")
	if err := os.WriteFile(regPath, []byte{}, 0o644); err != nil {
		t.Fatalf("seed empty: %v", err)
	}

	got, err := workspace.List()
	if err != nil {
		t.Fatalf("List on empty registry should not return an error, got: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty workspace list on empty registry, got %d", len(got))
	}
}

// TestAddRecoversFromCorruptRegistry verifies the user-visible recovery flow:
// after a corrupt registry is observed by List(), the next mutation succeeds
// against a fresh registry rather than refusing because the load returned an
// error. This is the bug shape that would have stranded users until they
// manually `rm`-ed the file.
func TestAddRecoversFromCorruptRegistry(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	regDir := filepath.Join(tmp, "cloop")
	if err := os.MkdirAll(regDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	regPath := filepath.Join(regDir, "workspaces.json")
	if err := os.WriteFile(regPath, []byte(`not even close to json`), 0o644); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	projDir := t.TempDir()
	if err := workspace.Add("recovered", projDir, ""); err != nil {
		t.Fatalf("Add after corrupt registry should succeed, got: %v", err)
	}

	got, err := workspace.List()
	if err != nil {
		t.Fatalf("List after recovery: %v", err)
	}
	if len(got) != 1 || got[0].Name != "recovered" {
		t.Errorf("expected exactly the new workspace after recovery, got %+v", got)
	}
}
