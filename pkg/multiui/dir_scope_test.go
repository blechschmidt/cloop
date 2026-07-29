package multiui

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDirScopeMatch covers the cwd-scoping predicate used by
// CloopRunPIDsInDir. The predicate must accept the project directory itself
// and anything below it (worktree runs live at .cloop/worktrees/<task>),
// while rejecting siblings that merely share a string prefix — otherwise
// stopping project "/work/proj" would also signal "/work/proj-b".
func TestDirScopeMatch(t *testing.T) {
	cases := []struct {
		name string
		dir  string
		cwd  string
		want bool
	}{
		{"exact match", "/work/proj", "/work/proj", true},
		{"subdirectory (worktree) match", "/work/proj", "/work/proj/.cloop/worktrees/task-7", true},
		{"sibling with common prefix rejected", "/work/proj", "/work/proj-b", false},
		{"parent directory rejected", "/work/proj", "/work", false},
		{"unrelated path rejected", "/work/proj", "/other/proj", false},
		{"trailing slash on dir normalised", "/work/proj/", "/work/proj", true},
		{"unclean dir normalised", "/work/./proj", "/work/proj/sub", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dirScopeMatch(tc.dir)(tc.cwd); got != tc.want {
				t.Fatalf("dirScopeMatch(%q)(%q) = %v, want %v", tc.dir, tc.cwd, got, tc.want)
			}
		})
	}
}

// TestDirScopeMatchSymlink verifies a registry path reached via a symlink
// still matches the kernel-canonical cwd reported by /proc/PID/cwd. Pre-fix
// (Task 20153) the comparison was a raw string equality, so a project
// registered under a symlinked path could never be stopped from the UI.
func TestDirScopeMatchSymlink(t *testing.T) {
	tmp := t.TempDir()
	real := filepath.Join(tmp, "real-project")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", real, err)
	}
	link := filepath.Join(tmp, "link-project")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	// /proc reports the resolved path; the registry holds the symlinked one.
	canonicalCwd, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", real, err)
	}
	if !dirScopeMatch(link)(canonicalCwd) {
		t.Fatalf("dirScopeMatch(%q)(%q) = false; want true (symlinked registry path must match canonical cwd)", link, canonicalCwd)
	}
	if !dirScopeMatch(link)(filepath.Join(canonicalCwd, ".cloop", "worktrees", "task-1")) {
		t.Fatalf("dirScopeMatch(%q) rejected worktree under canonical path", link)
	}
}
