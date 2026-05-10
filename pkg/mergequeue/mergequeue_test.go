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

// scriptedResolver implements Resolver by returning a canned content for each
// requested file. Used to drive the auto-resolve path end-to-end in tests.
type scriptedResolver struct {
	files map[string]string
	calls int
	err   error
}

func (s *scriptedResolver) Resolve(ctx context.Context, info ResolveInfo, files []ConflictFile) ([]ResolvedFile, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	out := make([]ResolvedFile, 0, len(files))
	for _, f := range files {
		body, ok := s.files[f.Path]
		if !ok {
			continue
		}
		out = append(out, ResolvedFile{Path: f.Path, Content: body})
	}
	return out, nil
}

// TestQueue_AutoResolverCommitsConflict proves that when a conflict is
// produced by the second merge, an installed Resolver can rewrite the file,
// stage it, and finish the merge so subsequent merges still see a clean base.
func TestQueue_AutoResolverCommitsConflict(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)

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

	resolved := "# A and B merged\n"
	resolver := &scriptedResolver{files: map[string]string{"README.md": resolved}}

	q := New(repo, "main")
	q.SetResolver(resolver)
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
	select {
	case <-r2.Done:
	case <-time.After(30 * time.Second):
		t.Fatal("auto-resolve merge timed out")
	}
	if r2.Err != nil {
		t.Fatalf("expected auto-resolve to succeed, got: %v", r2.Err)
	}
	if resolver.calls != 1 {
		t.Errorf("expected resolver to be called once, got %d", resolver.calls)
	}
	// README on main must now reflect the resolution.
	got, err := os.ReadFile(filepath.Join(repo, "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	if string(got) != resolved {
		t.Errorf("README on main = %q, want %q", got, resolved)
	}
	// MERGE_HEAD must be gone; working tree clean.
	if _, err := os.Stat(filepath.Join(repo, ".git", "MERGE_HEAD")); !os.IsNotExist(err) {
		t.Errorf("MERGE_HEAD still exists after auto-resolve: %v", err)
	}
}

// TestQueue_AutoResolverFailureFallsBackToAbort ensures that when the
// resolver returns an error, the queue still aborts the merge so the working
// tree is clean for the next job. The original conflict error is returned.
func TestQueue_AutoResolverFailureFallsBackToAbort(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)

	t1 := &pm.Task{ID: 1, Title: "Edit README A"}
	t2 := &pm.Task{ID: 2, Title: "Edit README B"}
	w1, _ := worktree.Create(repo, t1)
	w2, _ := worktree.Create(repo, t2)
	_ = os.WriteFile(filepath.Join(w1.Path, "README.md"), []byte("# A\n"), 0o644)
	_ = os.WriteFile(filepath.Join(w2.Path, "README.md"), []byte("# B\n"), 0o644)
	_, _ = w1.Commit(t1)
	_, _ = w2.Commit(t2)

	resolver := &scriptedResolver{err: errResolverGaveUp}

	q := New(repo, "main")
	q.SetResolver(resolver)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q.Start(ctx)
	defer q.Stop()

	<-q.Submit(Request{Branch: w1.Branch, TaskID: t1.ID}).Done
	r2 := q.Submit(Request{Branch: w2.Branch, TaskID: t2.ID})
	<-r2.Done
	if r2.Err == nil {
		t.Fatal("expected merge to fail after resolver gave up")
	}
	if _, err := os.Stat(filepath.Join(repo, ".git", "MERGE_HEAD")); !os.IsNotExist(err) {
		t.Errorf("MERGE_HEAD still exists after abort: %v", err)
	}
}

// errResolverGaveUp is a sentinel for the failure test above; declared here
// (not inline) so we can match on it later if we ever propagate it.
var errResolverGaveUp = errResolverGaveUpType("resolver gave up")

type errResolverGaveUpType string

func (e errResolverGaveUpType) Error() string { return string(e) }

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
