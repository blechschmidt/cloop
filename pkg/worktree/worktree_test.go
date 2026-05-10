package worktree

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

func gitAvailable() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// initRepo creates a minimal git repo in a temp dir and returns its path.
// One initial commit is made so HEAD is valid for `git worktree add`.
func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run("init", "-b", "main")
	run("config", "user.email", "cloop-test@example.com")
	run("config", "user.name", "cloop test")
	run("config", "commit.gpgsign", "false")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "README.md")
	run("commit", "-m", "initial")
	return dir
}

func TestBranchName(t *testing.T) {
	got := BranchName(&pm.Task{ID: 42, Title: "Add REST API endpoint"})
	want := "cloop/task-42-add-rest-api-endpoint"
	if got != want {
		t.Errorf("BranchName = %q, want %q", got, want)
	}
}

func TestIsGitRepo(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	if !IsGitRepo(repo) {
		t.Errorf("IsGitRepo(%q) = false, want true", repo)
	}
	tmp := t.TempDir()
	if IsGitRepo(tmp) {
		t.Errorf("IsGitRepo(%q) = true, want false", tmp)
	}
}

func TestCreateAndCommit(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	task := &pm.Task{ID: 1, Title: "Add feature X"}

	wt, err := Create(repo, task)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if wt.Branch != "cloop/task-1-add-feature-x" {
		t.Errorf("Branch = %q", wt.Branch)
	}
	if wt.BaseBranch != "main" {
		t.Errorf("BaseBranch = %q, want main", wt.BaseBranch)
	}
	if _, err := os.Stat(wt.Path); err != nil {
		t.Fatalf("worktree path missing: %v", err)
	}

	// Initially clean.
	if dirty, err := wt.HasChanges(); err != nil || dirty {
		t.Errorf("HasChanges (clean) = (%v, %v)", dirty, err)
	}

	// Write a file inside the worktree.
	fp := filepath.Join(wt.Path, "feature.txt")
	if err := os.WriteFile(fp, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	if dirty, err := wt.HasChanges(); err != nil || !dirty {
		t.Errorf("HasChanges (dirty) = (%v, %v)", dirty, err)
	}

	sha, err := wt.Commit(task)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if sha == "" {
		t.Errorf("Commit returned empty SHA")
	}

	// Now clean again.
	if dirty, err := wt.HasChanges(); err != nil || dirty {
		t.Errorf("HasChanges (after commit) = (%v, %v)", dirty, err)
	}

	// Removing the worktree should succeed.
	if err := wt.Remove(repo); err != nil {
		t.Errorf("Remove: %v", err)
	}
	if _, err := os.Stat(wt.Path); !os.IsNotExist(err) {
		t.Errorf("worktree path still exists after Remove: %v", err)
	}
}

func TestCreate_IndependentWorktrees(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)

	t1 := &pm.Task{ID: 10, Title: "task ten"}
	t2 := &pm.Task{ID: 11, Title: "task eleven"}

	w1, err := Create(repo, t1)
	if err != nil {
		t.Fatalf("Create t1: %v", err)
	}
	defer w1.Remove(repo)
	w2, err := Create(repo, t2)
	if err != nil {
		t.Fatalf("Create t2: %v", err)
	}
	defer w2.Remove(repo)

	// Each worktree must have its own path.
	if w1.Path == w2.Path {
		t.Fatalf("worktrees share path: %q", w1.Path)
	}

	// Touch independent files in each worktree.
	if err := os.WriteFile(filepath.Join(w1.Path, "a.txt"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w2.Path, "b.txt"), []byte("B"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The other worktree must not see the peer's file.
	if _, err := os.Stat(filepath.Join(w1.Path, "b.txt")); !os.IsNotExist(err) {
		t.Errorf("w1 saw peer's file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(w2.Path, "a.txt")); !os.IsNotExist(err) {
		t.Errorf("w2 saw peer's file: %v", err)
	}
}

func TestCreate_RecreatesStaleWorktree(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	task := &pm.Task{ID: 7, Title: "redo"}

	w1, err := Create(repo, task)
	if err != nil {
		t.Fatalf("Create #1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(w1.Path, "x.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Re-create over the existing path; should succeed and leave the dir clean.
	w2, err := Create(repo, task)
	if err != nil {
		t.Fatalf("Create #2: %v", err)
	}
	if _, err := os.Stat(filepath.Join(w2.Path, "x.txt")); !os.IsNotExist(err) {
		t.Errorf("stale file survived re-Create: %v", err)
	}
	dirty, err := w2.HasChanges()
	if err != nil || dirty {
		t.Errorf("re-Created worktree is dirty: dirty=%v err=%v", dirty, err)
	}
}
