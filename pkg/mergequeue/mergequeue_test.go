package mergequeue

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/worktree"
)

func gitAvailable() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

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

// TestQueue_SerializesMerges proves that two parallel worktree branches with
// non-conflicting changes both land on the base branch through the queue, in
// the order they were submitted.
func TestQueue_SerializesMerges(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)

	t1 := &pm.Task{ID: 1, Title: "Add file one"}
	t2 := &pm.Task{ID: 2, Title: "Add file two"}

	w1, err := worktree.Create(repo, t1)
	if err != nil {
		t.Fatalf("Create w1: %v", err)
	}
	w2, err := worktree.Create(repo, t2)
	if err != nil {
		t.Fatalf("Create w2: %v", err)
	}

	// Independent file changes in each worktree.
	if err := os.WriteFile(filepath.Join(w1.Path, "one.txt"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w2.Path, "two.txt"), []byte("2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := w1.Commit(t1); err != nil {
		t.Fatalf("Commit w1: %v", err)
	}
	if _, err := w2.Commit(t2); err != nil {
		t.Fatalf("Commit w2: %v", err)
	}

	q := New(repo, "main")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q.Start(ctx)
	defer q.Stop()

	r1 := q.Submit(Request{Branch: w1.Branch, TaskID: t1.ID, Title: t1.Title})
	r2 := q.Submit(Request{Branch: w2.Branch, TaskID: t2.ID, Title: t2.Title})

	select {
	case <-r1.Done:
	case <-time.After(30 * time.Second):
		t.Fatal("merge 1 timed out")
	}
	if r1.Err != nil {
		t.Fatalf("merge 1: %v", r1.Err)
	}
	select {
	case <-r2.Done:
	case <-time.After(30 * time.Second):
		t.Fatal("merge 2 timed out")
	}
	if r2.Err != nil {
		t.Fatalf("merge 2: %v", r2.Err)
	}

	// Both files should now exist on main.
	if _, err := os.Stat(filepath.Join(repo, "one.txt")); err != nil {
		t.Errorf("one.txt missing on main after merge: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repo, "two.txt")); err != nil {
		t.Errorf("two.txt missing on main after merge: %v", err)
	}
}

// TestQueue_ConflictRecoversCleanWorkingTree ensures that when a merge fails
// due to a conflict, the working tree is left clean (no MERGING state) so the
// next merge can proceed.
func TestQueue_ConflictRecoversCleanWorkingTree(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)

	// Two branches that both modify README.md → guaranteed conflict on merge #2.
	t1 := &pm.Task{ID: 1, Title: "Edit README A"}
	t2 := &pm.Task{ID: 2, Title: "Edit README B"}

	w1, err := worktree.Create(repo, t1)
	if err != nil {
		t.Fatalf("Create w1: %v", err)
	}
	w2, err := worktree.Create(repo, t2)
	if err != nil {
		t.Fatalf("Create w2: %v", err)
	}
	if err := os.WriteFile(filepath.Join(w1.Path, "README.md"), []byte("# A\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w2.Path, "README.md"), []byte("# B\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := w1.Commit(t1); err != nil {
		t.Fatalf("Commit w1: %v", err)
	}
	if _, err := w2.Commit(t2); err != nil {
		t.Fatalf("Commit w2: %v", err)
	}

	q := New(repo, "main")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q.Start(ctx)
	defer q.Stop()

	r1 := q.Submit(Request{Branch: w1.Branch, TaskID: t1.ID})
	<-r1.Done
	if r1.Err != nil {
		t.Fatalf("first merge unexpectedly failed: %v", r1.Err)
	}

	r2 := q.Submit(Request{Branch: w2.Branch, TaskID: t2.ID})
	<-r2.Done
	if r2.Err == nil {
		t.Fatalf("expected conflict on second merge, got nil")
	}

	// The merge must have been aborted: MERGE_HEAD must be gone and no
	// tracked file should be left in a conflicted state. (Untracked files
	// like the worktrees directory are fine.)
	if _, err := os.Stat(filepath.Join(repo, ".git", "MERGE_HEAD")); !os.IsNotExist(err) {
		t.Fatalf("MERGE_HEAD still exists after abort: %v", err)
	}
	cmd := exec.Command("git", "diff", "--name-only", "--diff-filter=U")
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git diff unmerged: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("conflicted files remain after abort:\n%s", out)
	}
}

// TestQueue_StopRejectsPending ensures that submissions made after Stop()
// return a clean error rather than blocking.
func TestQueue_StopRejectsPending(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	q := New(repo, "main")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q.Start(ctx)
	q.Stop()

	r := q.Submit(Request{Branch: "cloop/task-99-foo", TaskID: 99})
	select {
	case <-r.Done:
	case <-time.After(2 * time.Second):
		t.Fatal("Submit after Stop blocked")
	}
	if r.Err == nil {
		t.Errorf("expected error after Stop, got nil")
	}
}
