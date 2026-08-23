package worktree

// Tests for worktree garbage collection (Task 20191).
//
// Every test here runs against a real git repository in t.TempDir(), because
// the interesting behaviour is entirely in what git does and does not consider
// a worktree: a fake would have to encode the same assumptions the code under
// test encodes, and would then agree with it about anything it got wrong.
// initRepo (worktree_test.go) already sets user.email/user.name/commit.gpgsign
// locally, which is required — a CI container has no global git identity, so an
// unconfigured commit aborts.
//
// The safety properties get the sharpest tests, because they are the ones whose
// failure is unrecoverable: MinAge sparing a live run, Active sparing a named
// task, DeleteBranches refusing unmerged work, and Prune never reaching the
// main worktree.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// mustCreate makes a worktree for a task, failing the test if it cannot.
func mustCreate(t *testing.T, repo string, id int, title string) *Worktree {
	t.Helper()
	wt, err := Create(repo, &pm.Task{ID: id, Title: title})
	if err != nil {
		t.Fatalf("Create task %d: %v", id, err)
	}
	return wt
}

// git runs a git command in dir and fails the test on error.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return string(out)
}

// unregister deletes git's bookkeeping for a worktree while leaving the
// directory in place, which is the shape a `git worktree prune` (or a
// hand-cleaned .git) leaves behind: a full checkout git will never mention
// again.
func unregister(t *testing.T, repo string, taskID int) {
	t.Helper()
	admin := filepath.Join(repo, ".git", "worktrees", fmt.Sprintf("task-%d", taskID))
	if err := os.RemoveAll(admin); err != nil {
		t.Fatalf("unregister task %d: %v", taskID, err)
	}
}

// backdate ages every mtime source entryModTime consults, so an age-sensitive
// test does not have to sleep. Backdating all of them is the point: leaving one
// current is how the next test proves the admin directory is consulted.
func backdate(t *testing.T, repo string, taskID int, age time.Duration) {
	t.Helper()
	when := time.Now().Add(-age)
	for _, root := range []string{
		filepath.Join(WorktreesDir(repo), fmt.Sprintf("task-%d", taskID)),
		filepath.Join(repo, ".git", "worktrees", fmt.Sprintf("task-%d", taskID)),
	} {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		entries, _ := os.ReadDir(root)
		for _, de := range entries {
			_ = os.Chtimes(filepath.Join(root, de.Name()), when, when)
		}
		if err := os.Chtimes(root, when, when); err != nil {
			t.Fatalf("backdate %s: %v", root, err)
		}
	}
}

// entryFor finds the listed entry for a task, or fails.
func entryFor(t *testing.T, entries []Entry, taskID int) Entry {
	t.Helper()
	for _, e := range entries {
		if e.TaskID == taskID {
			return e
		}
	}
	t.Fatalf("no entry for task %d in %v", taskID, entries)
	return Entry{}
}

func hasBranch(t *testing.T, repo, branch string) bool {
	t.Helper()
	branches, err := ListBranches(repo)
	if err != nil {
		t.Fatalf("ListBranches: %v", err)
	}
	for _, b := range branches {
		if b == branch {
			return true
		}
	}
	return false
}

// TestList_ReconcilesGitAndDisk covers the premise of the whole file: git's
// view and the directory's view disagree in exactly the cases that are leaks,
// so both have to be read.
func TestList_ReconcilesGitAndDisk(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)

	healthy := mustCreate(t, repo, 1, "healthy")
	orphanDir := mustCreate(t, repo, 2, "dir without registration")
	orphanReg := mustCreate(t, repo, 3, "registration without dir")

	// A checkout git has forgotten.
	unregister(t, repo, 2)
	// A registration whose checkout was deleted from under it.
	if err := os.RemoveAll(orphanReg.Path); err != nil {
		t.Fatal(err)
	}

	entries, err := List(repo)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("List returned %d entries, want 3: %v", len(entries), entries)
	}

	got := entryFor(t, entries, 1)
	if !got.DirExists || !got.Registered {
		t.Errorf("healthy worktree listed as dir=%v registered=%v", got.DirExists, got.Registered)
	}
	if got.Branch != healthy.Branch {
		t.Errorf("healthy branch = %q, want %q", got.Branch, healthy.Branch)
	}
	if got.Path != healthy.Path {
		t.Errorf("healthy path = %q, want %q", got.Path, healthy.Path)
	}
	if got.ModTime.IsZero() {
		t.Error("a live worktree must have a modification time; without one MinAge cannot protect it")
	}

	got = entryFor(t, entries, 2)
	if !got.DirExists || got.Registered {
		t.Errorf("unregistered checkout listed as dir=%v registered=%v, want dir=true registered=false",
			got.DirExists, got.Registered)
	}
	if got.Branch != orphanDir.Branch {
		t.Errorf("unregistered checkout branch = %q, want %q recovered from the branch list",
			got.Branch, orphanDir.Branch)
	}

	got = entryFor(t, entries, 3)
	if got.DirExists || !got.Registered {
		t.Errorf("missing checkout listed as dir=%v registered=%v, want dir=false registered=true",
			got.DirExists, got.Registered)
	}
	if got.Branch != orphanReg.Branch {
		t.Errorf("missing checkout branch = %q, want %q", got.Branch, orphanReg.Branch)
	}
}

// TestList_IgnoresTheMainWorktree is the containment rule. A sweep that could
// reach the operator's own checkout would not be a garbage collector.
func TestList_IgnoresTheMainWorktree(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	mustCreate(t, repo, 1, "real worktree")

	// The nastiest shape: the main worktree itself has a cloop task branch
	// checked out, so a sweep that filtered by branch name instead of by
	// location would list — and then delete — the checkout the operator is
	// sitting in.
	git(t, repo, "checkout", "-q", "-b", "cloop/task-99-decoy")

	entries, err := List(repo)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, e := range entries {
		if resolvePath(e.Path) == resolvePath(repo) {
			t.Fatalf("List returned the main worktree: %v", e)
		}
		if e.TaskID == 99 {
			t.Fatalf("List attributed the main worktree to task 99: %v", e)
		}
	}

	res, err := Prune(repo, PruneOptions{MinAge: -1, DeleteBranches: true, BaseBranch: "cloop/task-99-decoy"})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repo, "README.md")); err != nil {
		t.Fatalf("the sweep reached the main worktree: %v (result: %s)", err, res.Summary())
	}
	if !hasBranch(t, repo, "cloop/task-99-decoy") {
		t.Fatal("the sweep deleted the branch checked out in the main worktree")
	}
}

// TestPrune_RemovesOldOrphan is the base case: a worktree older than MinAge
// with nothing claiming it is collected, directory and registration both.
func TestPrune_RemovesOldOrphan(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	wt := mustCreate(t, repo, 1, "crashed run")
	backdate(t, repo, 1, 48*time.Hour)

	res, err := Prune(repo, PruneOptions{MinAge: time.Hour})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(res.Removed) != 1 || len(res.Kept) != 0 || len(res.Errors) != 0 {
		t.Fatalf("Prune = %s; want exactly one removal", res.Summary())
	}
	if res.Removed[0].TaskID != 1 {
		t.Errorf("removed task %d, want 1", res.Removed[0].TaskID)
	}
	if _, err := os.Stat(wt.Path); !os.IsNotExist(err) {
		t.Errorf("the worktree directory survived the sweep: %v", err)
	}
	entries, err := List(repo)
	if err != nil {
		t.Fatalf("List after prune: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("git still registers the collected worktree: %v", entries)
	}
	// The branch is the task's only copy of its work and DeleteBranches was off.
	if !hasBranch(t, repo, wt.Branch) {
		t.Errorf("branch %q was deleted without DeleteBranches being set", wt.Branch)
	}
}

// TestPrune_MinAgeSparesAYoungWorktree is the single most important test in the
// package: a live parallel run's worktrees are in this directory right now, and
// collecting one destroys uncommitted work nothing can restore.
func TestPrune_MinAgeSparesAYoungWorktree(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	old := mustCreate(t, repo, 1, "finished long ago")
	young := mustCreate(t, repo, 2, "running right now")
	backdate(t, repo, 1, 48*time.Hour)

	// Uncommitted work in the young tree: exactly what a sweep must not eat.
	inflight := filepath.Join(young.Path, "in-flight.txt")
	if err := os.WriteFile(inflight, []byte("half a feature\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Prune(repo, PruneOptions{MinAge: time.Hour})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(res.Removed) != 1 || res.Removed[0].TaskID != 1 {
		t.Fatalf("Prune removed %v, want only task 1", res.Removed)
	}
	if len(res.Kept) != 1 || res.Kept[0].TaskID != 2 {
		t.Fatalf("Prune kept %v, want only task 2", res.Kept)
	}
	if res.Kept[0].Code != KeepTooYoung {
		t.Errorf("keep code = %q, want %q", res.Kept[0].Code, KeepTooYoung)
	}
	if _, err := os.Stat(inflight); err != nil {
		t.Fatalf("the sweep destroyed a running task's uncommitted work: %v", err)
	}
	if _, err := os.Stat(old.Path); !os.IsNotExist(err) {
		t.Errorf("the old worktree survived: %v", err)
	}
}

// TestPrune_ZeroOptionsAreSafe pins the default. PruneOptions{} is what a
// caller writes when they have not thought about age, so it has to protect
// everything recent rather than delete everything.
func TestPrune_ZeroOptionsAreSafe(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	wt := mustCreate(t, repo, 1, "just started")

	res, err := Prune(repo, PruneOptions{})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(res.Removed) != 0 {
		t.Fatalf("the zero PruneOptions collected a fresh worktree: %v", res.Removed)
	}
	if len(res.Kept) != 1 || res.Kept[0].Code != KeepTooYoung {
		t.Fatalf("Kept = %v, want one too-young entry", res.Kept)
	}
	if _, err := os.Stat(wt.Path); err != nil {
		t.Fatalf("the worktree was removed: %v", err)
	}
}

// TestPrune_AdminDirectoryKeepsAWorktreeYoung: an agent editing files deep in
// the tree does not move the worktree root's mtime, but every commit and index
// refresh moves the git admin directory. Backdating only the checkout must
// therefore still leave the entry protected.
func TestPrune_AdminDirectoryKeepsAWorktreeYoung(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	wt := mustCreate(t, repo, 1, "deep edits only")

	root := filepath.Join(WorktreesDir(repo), "task-1")
	when := time.Now().Add(-48 * time.Hour)
	entries, _ := os.ReadDir(root)
	for _, de := range entries {
		_ = os.Chtimes(filepath.Join(root, de.Name()), when, when)
	}
	if err := os.Chtimes(root, when, when); err != nil {
		t.Fatal(err)
	}

	res, err := Prune(repo, PruneOptions{MinAge: time.Hour})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(res.Removed) != 0 {
		t.Fatalf("a worktree whose git admin directory is current was collected: %v", res.Removed)
	}
	if _, err := os.Stat(wt.Path); err != nil {
		t.Fatalf("worktree removed: %v", err)
	}
}

// TestPrune_ActiveTasksAreSpared: the caller's own knowledge of what is running
// outranks every heuristic, including a directory that has not been touched
// for two days because the agent is waiting on a slow model call.
func TestPrune_ActiveTasksAreSpared(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	byMap := mustCreate(t, repo, 1, "running, named in Active")
	bySlice := mustCreate(t, repo, 2, "running, named in KeepTaskIDs")
	dead := mustCreate(t, repo, 3, "genuinely abandoned")
	for _, id := range []int{1, 2, 3} {
		backdate(t, repo, id, 48*time.Hour)
	}

	res, err := Prune(repo, PruneOptions{
		MinAge:      time.Hour,
		Active:      map[int]bool{1: true},
		KeepTaskIDs: []int{2},
	})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(res.Removed) != 1 || res.Removed[0].TaskID != 3 {
		t.Fatalf("Prune removed %v, want only task 3", res.Removed)
	}
	if len(res.Kept) != 2 {
		t.Fatalf("Prune kept %v, want tasks 1 and 2", res.Kept)
	}
	for _, k := range res.Kept {
		if k.Code != KeepActive {
			t.Errorf("task %d kept with code %q, want %q", k.TaskID, k.Code, KeepActive)
		}
	}
	for _, wt := range []*Worktree{byMap, bySlice} {
		if _, err := os.Stat(wt.Path); err != nil {
			t.Errorf("an active task's worktree was removed: %v", err)
		}
	}
	if _, err := os.Stat(dead.Path); !os.IsNotExist(err) {
		t.Errorf("the abandoned worktree survived: %v", err)
	}
}

// TestPrune_CollectsDirWithoutRegistration: git will never mention this
// directory again, so nothing but a directory scan can find it.
func TestPrune_CollectsDirWithoutRegistration(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	wt := mustCreate(t, repo, 1, "forgotten by git")
	unregister(t, repo, 1)

	if out := git(t, repo, "worktree", "list", "--porcelain"); strings.Contains(out, wt.Path) {
		t.Fatalf("git still registers %s; the test premise is wrong:\n%s", wt.Path, out)
	}

	res, err := Prune(repo, PruneOptions{MinAge: -1})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(res.Removed) != 1 || len(res.Errors) != 0 {
		t.Fatalf("Prune = %s; want one removal and no errors", res.Summary())
	}
	if _, err := os.Stat(wt.Path); !os.IsNotExist(err) {
		t.Errorf("an unregistered checkout survived the sweep: %v", err)
	}
}

// TestPrune_CollectsRegistrationWithoutDir: nothing is on disk, so only git's
// list can find this one, and leaving it makes `git worktree add` at the same
// path fail forever after.
func TestPrune_CollectsRegistrationWithoutDir(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	wt := mustCreate(t, repo, 1, "deleted by hand")
	if err := os.RemoveAll(wt.Path); err != nil {
		t.Fatal(err)
	}

	res, err := Prune(repo, PruneOptions{MinAge: -1})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(res.Removed) != 1 || len(res.Errors) != 0 {
		t.Fatalf("Prune = %s; want one removal and no errors", res.Summary())
	}
	entries, err := List(repo)
	if err != nil {
		t.Fatalf("List after prune: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("the stale registration survived: %v", entries)
	}
}

// TestPrune_StaleRegistrationAgesFromTheGitAdminDir covers the entry with no
// directory of its own to read an mtime from. Its age comes from git's
// bookkeeping, and it has to, in both directions: an old registration must not
// become immortal just because its checkout is gone, and a brand new one must
// still be spared, because that is what a `git worktree add` looks like in the
// instant between git writing its bookkeeping and the checkout appearing.
func TestPrune_StaleRegistrationAgesFromTheGitAdminDir(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	old := mustCreate(t, repo, 1, "deleted long ago")
	fresh := mustCreate(t, repo, 2, "being created right now")
	for _, wt := range []*Worktree{old, fresh} {
		if err := os.RemoveAll(wt.Path); err != nil {
			t.Fatal(err)
		}
	}
	backdate(t, repo, 1, 48*time.Hour)
	now := time.Now()
	if err := os.Chtimes(filepath.Join(repo, ".git", "worktrees", "task-2"), now, now); err != nil {
		t.Fatal(err)
	}

	res, err := Prune(repo, PruneOptions{MinAge: time.Hour})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(res.Removed) != 1 || res.Removed[0].TaskID != 1 {
		t.Fatalf("Removed = %v, want only the long-dead registration", res.Removed)
	}
	if len(res.Kept) != 1 || res.Kept[0].TaskID != 2 || res.Kept[0].Code != KeepTooYoung {
		t.Fatalf("Kept = %v, want task 2 spared as too young", res.Kept)
	}
}

// TestPrune_DeleteBranchesOnlyWhenMerged is the second unrecoverable-loss
// guard: an unmerged cloop/task-N branch is the only copy of that task's work.
func TestPrune_DeleteBranchesOnlyWhenMerged(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)

	mergedWT := mustCreate(t, repo, 1, "merged work")
	if err := os.WriteFile(filepath.Join(mergedWT.Path, "one.txt"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := mergedWT.Commit(&pm.Task{ID: 1, Title: "merged work"}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	git(t, repo, "merge", "--no-ff", "-m", "merge task 1", mergedWT.Branch)

	unmergedWT := mustCreate(t, repo, 2, "unmerged work")
	precious := filepath.Join(unmergedWT.Path, "two.txt")
	if err := os.WriteFile(precious, []byte("2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sha, err := unmergedWT.Commit(&pm.Task{ID: 2, Title: "unmerged work"})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if sha == "" {
		t.Fatal("the unmerged fixture produced no commit")
	}

	res, err := Prune(repo, PruneOptions{MinAge: -1, DeleteBranches: true, BaseBranch: "main"})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(res.Removed) != 2 {
		t.Fatalf("Prune = %s; both worktrees should be collected regardless of branch state",
			res.Summary())
	}
	for _, p := range res.Removed {
		switch p.TaskID {
		case 1:
			if !p.BranchDeleted {
				t.Errorf("a merged branch was kept: %q", p.BranchKept)
			}
		case 2:
			if p.BranchDeleted {
				t.Fatal("an unmerged branch was deleted — that work is unrecoverable")
			}
			if !strings.Contains(p.BranchKept, "not merged") {
				t.Errorf("BranchKept = %q, want it to say the branch is not merged", p.BranchKept)
			}
		}
	}
	if hasBranch(t, repo, mergedWT.Branch) {
		t.Errorf("merged branch %q survived DeleteBranches", mergedWT.Branch)
	}
	if !hasBranch(t, repo, unmergedWT.Branch) {
		t.Fatalf("unmerged branch %q was deleted", unmergedWT.Branch)
	}
	// And the work is genuinely still reachable, not merely the ref name.
	if out := git(t, repo, "show", "--stat", unmergedWT.Branch); !strings.Contains(out, "two.txt") {
		t.Errorf("the unmerged task's commit is gone: %s", out)
	}
}

// TestPrune_DryRunChangesNothing: the plan a caller inspects has to be the plan
// a real run would carry out, computed without carrying any of it out.
func TestPrune_DryRunChangesNothing(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	wt := mustCreate(t, repo, 1, "collectible")
	if err := os.WriteFile(filepath.Join(wt.Path, "one.txt"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Commit(&pm.Task{ID: 1, Title: "collectible"}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	git(t, repo, "merge", "--no-ff", "-m", "merge task 1", wt.Branch)

	res, err := Prune(repo, PruneOptions{MinAge: -1, DryRun: true, DeleteBranches: true, BaseBranch: "main"})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if !res.DryRun {
		t.Error("PruneResult.DryRun must echo the option")
	}
	if len(res.Removed) != 1 || !res.Removed[0].BranchDeleted {
		t.Fatalf("dry run reported %v, want one removal with its merged branch deleted", res.Removed)
	}
	if _, err := os.Stat(wt.Path); err != nil {
		t.Errorf("a dry run removed the worktree directory: %v", err)
	}
	if !hasBranch(t, repo, wt.Branch) {
		t.Error("a dry run deleted the branch")
	}
	entries, err := List(repo)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || !entries[0].Registered {
		t.Errorf("a dry run changed git's registrations: %v", entries)
	}
}

// TestPrune_LockedWorktreeIsSpared: `git worktree lock` is an operator saying
// "do not collect this", and it outranks age.
func TestPrune_LockedWorktreeIsSpared(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	wt := mustCreate(t, repo, 1, "under investigation")
	git(t, repo, "worktree", "lock", "--reason", "debugging a crash", wt.Path)
	t.Cleanup(func() { _ = exec.Command("git", "-C", repo, "worktree", "unlock", wt.Path).Run() })
	backdate(t, repo, 1, 48*time.Hour)

	entries, err := List(repo)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if e := entryFor(t, entries, 1); !e.Locked || e.LockReason != "debugging a crash" {
		t.Fatalf("lock not reported: locked=%v reason=%q", e.Locked, e.LockReason)
	}

	res, err := Prune(repo, PruneOptions{MinAge: -1})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(res.Removed) != 0 {
		t.Fatalf("a locked worktree was collected: %v", res.Removed)
	}
	if len(res.Kept) != 1 || res.Kept[0].Code != KeepLocked {
		t.Fatalf("Kept = %v, want one locked entry", res.Kept)
	}
	if _, err := os.Stat(wt.Path); err != nil {
		t.Errorf("locked worktree removed: %v", err)
	}
}

// TestPrune_OneWedgedWorktreeDoesNotAbortTheSweep: the sweep that gives up on
// the first failure is the sweep that never finishes, so failures are per-entry.
func TestPrune_OneWedgedWorktreeDoesNotAbortTheSweep(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory permissions this test uses to wedge a worktree")
	}
	repo := initRepo(t)
	wedged := mustCreate(t, repo, 1, "wedged")
	healthy := mustCreate(t, repo, 2, "collectible")

	// Make the checkout's contents un-unlinkable, which is what an unreadable
	// mount or a hostile permission set looks like to os.RemoveAll.
	if err := os.Chmod(wedged.Path, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(wedged.Path, 0o700) })

	res, err := Prune(repo, PruneOptions{MinAge: -1})
	if err != nil {
		t.Fatalf("Prune returned a fatal error for one bad entry: %v", err)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("Errors = %v, want exactly one", res.Errors)
	}
	if !strings.Contains(res.Errors[0].Error(), wedged.Path) {
		t.Errorf("the error must name the entry it belongs to; got %v", res.Errors[0])
	}
	if len(res.Removed) != 1 || res.Removed[0].TaskID != 2 {
		t.Fatalf("Removed = %v, want the healthy worktree to have been collected anyway", res.Removed)
	}
	if _, err := os.Stat(healthy.Path); !os.IsNotExist(err) {
		t.Errorf("the sweep stopped at the wedged entry: %v", err)
	}
}

func TestListBranches(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	mustCreate(t, repo, 2, "second")
	mustCreate(t, repo, 10, "tenth")
	// A branch in the cloop namespace that is not a task branch, and an
	// ordinary branch: neither is this package's to report.
	git(t, repo, "branch", "cloop/scratch")
	git(t, repo, "branch", "feature/unrelated")

	got, err := ListBranches(repo)
	if err != nil {
		t.Fatalf("ListBranches: %v", err)
	}
	want := []string{"cloop/task-2-second", "cloop/task-10-tenth"}
	if len(got) != len(want) {
		t.Fatalf("ListBranches = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ListBranches = %v, want %v (ordered by task ID, not lexically)", got, want)
		}
	}
}

func TestList_RejectsNonRepositories(t *testing.T) {
	if _, err := List(t.TempDir()); err == nil {
		t.Fatal("List on a non-repository returned no error")
	}
	if _, err := Prune(t.TempDir(), PruneOptions{}); err == nil {
		t.Fatal("Prune on a non-repository returned no error")
	}
}

// TestList_EmptyRepoHasNoWorktrees: a repo that has never run a parallel task
// has no .cloop/worktrees at all, and a missing directory is not an error.
func TestList_EmptyRepoHasNoWorktrees(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	entries, err := List(repo)
	if err != nil {
		t.Fatalf("List on a repo with no worktrees: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("List = %v, want none", entries)
	}
	res, err := Prune(repo, PruneOptions{MinAge: -1})
	if err != nil {
		t.Fatalf("Prune on a repo with no worktrees: %v", err)
	}
	if len(res.Removed) != 0 || len(res.Kept) != 0 || len(res.Errors) != 0 {
		t.Fatalf("Prune = %s, want a no-op", res.Summary())
	}
}

// TestPruneOptions_MinAgeDefaulting pins the sign convention, which is the one
// piece of this API a caller can get wrong silently.
func TestPruneOptions_MinAgeDefaulting(t *testing.T) {
	if got := (PruneOptions{}).normalize().MinAge; got != DefaultMinAge {
		t.Errorf("zero MinAge normalised to %s, want the %s default", got, DefaultMinAge)
	}
	if got := (PruneOptions{MinAge: 5 * time.Minute}).normalize().MinAge; got != 5*time.Minute {
		t.Errorf("explicit MinAge normalised to %s", got)
	}
	if got := (PruneOptions{MinAge: -1}).normalize().MinAge; got != 0 {
		t.Errorf("negative MinAge normalised to %s, want the guard disabled", got)
	}
	// normalize must not mutate the caller's struct, or a dry run and the real
	// run that follows it would be given different inputs.
	opts := PruneOptions{}
	_ = opts.normalize()
	if opts.MinAge != 0 {
		t.Errorf("normalize mutated the caller's options: MinAge = %s", opts.MinAge)
	}
}
