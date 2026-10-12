package security

// The hub's background worktree sweep runs no program a repository names
// (Task 20418). pkg/worktree.runGit is a sanctioned door in callgraph_test.go
// on this condition; this is the proof the door's reason points at, made
// through the package's exported API the way reconcile calls it.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/worktree"
)

func TestBackgroundSweepRunsNoRepositoryProgram(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main")
	run("config", "user.email", "sweep@example.com")
	run("config", "user.name", "sweep")
	run("config", "commit.gpgsign", "false")
	if err := os.WriteFile(filepath.Join(repo, "README"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "README")
	run("commit", "-qm", "first")

	task := &pm.Task{ID: 3, Title: "leaked"}
	wt, err := worktree.Create(repo, task)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wt.Path, "work.txt"), []byte("w\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Commit(task); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	run("merge", "-q", "--no-ff", "-m", "merge", wt.Branch)

	// What a sandbox that can write the repository can plant: a hook that git
	// runs when a branch is deleted, and a monitor and a filter it runs when
	// it reads the tree. Each would record the environment it was handed.
	marker := filepath.Join(t.TempDir(), "ran")
	script := filepath.Join(t.TempDir(), "planted.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nenv >> '"+marker+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "hooks", "reference-transaction"),
		[]byte("#!/bin/sh\nenv >> '"+marker+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	run("config", "core.fsmonitor", script)
	run("config", "filter.planted.clean", script)
	t.Setenv("CLOOP_SECRET_KEY", "background-sweep-canary")

	res, err := worktree.Prune(repo, worktree.PruneOptions{MinAge: -1, DeleteBranches: true, BaseBranch: "main"})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(res.Removed) != 1 || !res.Removed[0].BranchDeleted {
		t.Fatalf("Prune = %s; want the worktree removed and its merged branch deleted", res.Summary())
	}
	if data, err := os.ReadFile(marker); err == nil {
		leaked := strings.Contains(string(data), "background-sweep-canary")
		t.Fatalf("the sweep ran a program the repository configured (hub secret in its environment: %v)", leaked)
	}
}
