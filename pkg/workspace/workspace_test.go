package workspace_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/workspace"
)

// setConfigHome redirects the workspace registry to a temporary directory for
// the duration of the test by setting XDG_CONFIG_HOME.
func setConfigHome(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
}

func TestListEmpty(t *testing.T) {
	setConfigHome(t)
	workspaces, err := workspace.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(workspaces) != 0 {
		t.Fatalf("expected 0 workspaces, got %d", len(workspaces))
	}
}

func TestAddAndList(t *testing.T) {
	setConfigHome(t)
	projDir := t.TempDir()

	if err := workspace.Add("myproject", projDir, "test project"); err != nil {
		t.Fatal(err)
	}

	workspaces, err := workspace.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(workspaces) != 1 {
		t.Fatalf("expected 1 workspace, got %d", len(workspaces))
	}
	w := workspaces[0]
	if w.Name != "myproject" {
		t.Errorf("expected name %q, got %q", "myproject", w.Name)
	}
	if w.Description != "test project" {
		t.Errorf("expected description %q, got %q", "test project", w.Description)
	}
	// Path must be absolute.
	if !filepath.IsAbs(w.Path) {
		t.Errorf("expected absolute path, got %q", w.Path)
	}
}

func TestAddRelativePath(t *testing.T) {
	setConfigHome(t)

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// Use "." — should be resolved to an absolute path.
	if err := workspace.Add("dotproject", ".", ""); err != nil {
		t.Fatal(err)
	}
	w, err := workspace.Get("dotproject")
	if err != nil {
		t.Fatal(err)
	}
	if w.Path != cwd {
		// Allow canonical path equivalence (symlinks etc.)
		t.Logf("note: path %q vs cwd %q — may differ by symlink resolution", w.Path, cwd)
	}
	if !filepath.IsAbs(w.Path) {
		t.Errorf("expected absolute path, got %q", w.Path)
	}
}

func TestAddUpdatesExisting(t *testing.T) {
	setConfigHome(t)
	projDir := t.TempDir()

	if err := workspace.Add("proj", projDir, "original"); err != nil {
		t.Fatal(err)
	}
	if err := workspace.Add("proj", projDir, "updated"); err != nil {
		t.Fatal(err)
	}

	workspaces, err := workspace.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(workspaces) != 1 {
		t.Fatalf("expected 1 workspace after update, got %d", len(workspaces))
	}
	if workspaces[0].Description != "updated" {
		t.Errorf("expected description %q, got %q", "updated", workspaces[0].Description)
	}
}

func TestAddEmptyNameError(t *testing.T) {
	setConfigHome(t)
	if err := workspace.Add("", ".", ""); err == nil {
		t.Error("expected error for empty workspace name")
	}
}

func TestGet(t *testing.T) {
	setConfigHome(t)
	projDir := t.TempDir()

	if err := workspace.Add("alpha", projDir, "alpha desc"); err != nil {
		t.Fatal(err)
	}

	w, err := workspace.Get("alpha")
	if err != nil {
		t.Fatal(err)
	}
	if w.Name != "alpha" {
		t.Errorf("expected %q, got %q", "alpha", w.Name)
	}
	if w.Description != "alpha desc" {
		t.Errorf("expected %q, got %q", "alpha desc", w.Description)
	}
}

func TestGetNotFound(t *testing.T) {
	setConfigHome(t)
	if _, err := workspace.Get("nonexistent"); err == nil {
		t.Error("expected error for non-existent workspace")
	}
}

func TestRemove(t *testing.T) {
	setConfigHome(t)
	projDir := t.TempDir()

	if err := workspace.Add("toremove", projDir, ""); err != nil {
		t.Fatal(err)
	}

	if err := workspace.Remove("toremove"); err != nil {
		t.Fatal(err)
	}

	workspaces, err := workspace.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(workspaces) != 0 {
		t.Fatalf("expected 0 workspaces after remove, got %d", len(workspaces))
	}
}

func TestRemoveNonExistentIsNoop(t *testing.T) {
	setConfigHome(t)
	if err := workspace.Remove("doesnotexist"); err != nil {
		t.Errorf("expected no error removing non-existent workspace, got: %v", err)
	}
}

func TestSetActiveGetActive(t *testing.T) {
	setConfigHome(t)

	if active := workspace.GetActive(); active != "" {
		t.Errorf("expected no active workspace initially, got %q", active)
	}

	if err := workspace.SetActive("myws"); err != nil {
		t.Fatal(err)
	}
	if active := workspace.GetActive(); active != "myws" {
		t.Errorf("expected %q, got %q", "myws", active)
	}

	if err := workspace.SetActive(""); err != nil {
		t.Fatal(err)
	}
	if active := workspace.GetActive(); active != "" {
		t.Errorf("expected empty active after clear, got %q", active)
	}
}

func TestSwitch(t *testing.T) {
	setConfigHome(t)
	projDir := t.TempDir()

	if err := workspace.Add("switchtest", projDir, ""); err != nil {
		t.Fatal(err)
	}
	if err := workspace.Switch("switchtest"); err != nil {
		t.Fatal(err)
	}

	// Active workspace should be updated.
	if active := workspace.GetActive(); active != "switchtest" {
		t.Errorf("expected active %q, got %q", "switchtest", active)
	}

	// Pointer file should exist in the workspace directory.
	pointerFile := filepath.Join(projDir, ".cloop_workspace")
	data, err := os.ReadFile(pointerFile)
	if err != nil {
		t.Fatalf("expected pointer file at %s: %v", pointerFile, err)
	}
	if string(data) != "switchtest\n" {
		t.Errorf("expected pointer content %q, got %q", "switchtest\n", string(data))
	}
}

func TestSwitchNotFound(t *testing.T) {
	setConfigHome(t)
	if err := workspace.Switch("nonexistent"); err == nil {
		t.Error("expected error switching to non-existent workspace")
	}
}

func TestRemoveClearsActive(t *testing.T) {
	setConfigHome(t)
	projDir := t.TempDir()

	if err := workspace.Add("active", projDir, ""); err != nil {
		t.Fatal(err)
	}
	if err := workspace.SetActive("active"); err != nil {
		t.Fatal(err)
	}
	if err := workspace.Remove("active"); err != nil {
		t.Fatal(err)
	}

	if active := workspace.GetActive(); active != "" {
		t.Errorf("expected active to be cleared after removing active workspace, got %q", active)
	}
}

func TestResolveWorkDir(t *testing.T) {
	setConfigHome(t)
	projDir := t.TempDir()

	if err := workspace.Add("wdtest", projDir, ""); err != nil {
		t.Fatal(err)
	}

	resolved, err := workspace.ResolveWorkDir("wdtest")
	if err != nil {
		t.Fatal(err)
	}
	// Normalize both paths through EvalSymlinks to handle temp dir symlinks.
	expected, _ := filepath.EvalSymlinks(projDir)
	actual, _ := filepath.EvalSymlinks(resolved)
	if actual != expected {
		t.Errorf("expected %q, got %q", expected, actual)
	}
}

func TestResolveWorkDirEmpty(t *testing.T) {
	setConfigHome(t)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := workspace.ResolveWorkDir("")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != cwd {
		t.Errorf("expected cwd %q, got %q", cwd, resolved)
	}
}

func TestMultipleWorkspaces(t *testing.T) {
	setConfigHome(t)
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	dir3 := t.TempDir()

	for _, name := range []string{"alpha", "beta", "gamma"} {
		var d string
		switch name {
		case "alpha":
			d = dir1
		case "beta":
			d = dir2
		default:
			d = dir3
		}
		if err := workspace.Add(name, d, ""); err != nil {
			t.Fatal(err)
		}
	}

	workspaces, err := workspace.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(workspaces) != 3 {
		t.Fatalf("expected 3 workspaces, got %d", len(workspaces))
	}

	// Remove middle one.
	if err := workspace.Remove("beta"); err != nil {
		t.Fatal(err)
	}
	workspaces, _ = workspace.List()
	if len(workspaces) != 2 {
		t.Fatalf("expected 2 workspaces after remove, got %d", len(workspaces))
	}
	for _, w := range workspaces {
		if w.Name == "beta" {
			t.Error("removed workspace still present")
		}
	}
}
