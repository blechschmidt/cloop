package gitstate_test

// Inspect against real git: a project cloned from an upstream, with branches
// ahead of it, a feature worktree, changes of every kind and a stash. Every
// scene plants a hook, an fsmonitor and a filter driver in the repository that
// leave a marker if they run, and the tests check the marker never appears and
// the index is never rewritten — the preflight is a read.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
	"github.com/blechschmidt/cloop/pkg/executor/gitstate"
)

func TestMain(m *testing.M) { os.Exit(hometest.Isolate(m)) }

func gitEnv() []string {
	return append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
	)
}

// git runs the test's own git with the planted traps disarmed, so only the
// inspection under test could set them off.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	disarmed := []string{"-C", dir, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
		"-c", "filter.trap.clean=cat", "-c", "filter.trap.smudge=cat"}
	cmd := exec.Command("git", append(disarmed, args...)...)
	cmd.Env = gitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// scene is an upstream and a project cloned from it, with traps planted in the
// project's repository.
type scene struct {
	upstream string
	project  string
	marker   string
}

func newScene(t *testing.T) *scene {
	t.Helper()
	root := t.TempDir()
	s := &scene{
		upstream: filepath.Join(root, "upstream.git"),
		project:  filepath.Join(root, "project"),
		marker:   filepath.Join(root, "ran"),
	}
	seed := filepath.Join(root, "seed")
	git(t, root, "init", "-q", "-b", "main", seed)
	write(t, filepath.Join(seed, "README.md"), "hello\n")
	write(t, filepath.Join(seed, "tracked.txt"), "one\n")
	git(t, seed, "add", ".")
	git(t, seed, "commit", "-q", "-m", "base")
	git(t, root, "clone", "-q", "--bare", seed, s.upstream)
	git(t, root, "clone", "-q", s.upstream, s.project)

	// Each of these would run a program on `git status` or `git add` if the
	// inspection honoured the repository's own configuration.
	hook := "#!/bin/sh\ntouch " + s.marker + "\n"
	for _, name := range []string{"post-checkout", "reference-transaction", "post-index-change"} {
		p := filepath.Join(s.project, ".git", "hooks", name)
		write(t, p, hook)
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	monitor := filepath.Join(root, "fsmonitor.sh")
	write(t, monitor, hook)
	if err := os.Chmod(monitor, 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, s.project, "config", "core.fsmonitor", monitor)
	git(t, s.project, "config", "filter.trap.clean", "sh -c 'touch "+s.marker+"; cat'")
	git(t, s.project, "config", "filter.trap.smudge", "sh -c 'touch "+s.marker+"; cat'")
	write(t, filepath.Join(s.project, ".gitattributes"), "*.txt filter=trap\n")
	return s
}

func (s *scene) assertNothingRan(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(s.marker); err == nil {
		t.Fatal("a program configured in the repository ran during the inspection")
	}
}

func inspect(t *testing.T, dir string, opts gitstate.Options) gitstate.State {
	t.Helper()
	st, err := gitstate.Inspect(context.Background(), dir, opts)
	if err != nil {
		t.Fatalf("Inspect(%s): %v", dir, err)
	}
	return st
}

func branch(st gitstate.State, name string) (gitstate.Branch, bool) {
	for _, b := range st.Branches {
		if b.Name == name {
			return b, true
		}
	}
	return gitstate.Branch{}, false
}

func worktree(st gitstate.State, rel string) (gitstate.Worktree, bool) {
	for _, w := range st.Worktrees {
		if w.Rel == rel {
			return w, true
		}
	}
	return gitstate.Worktree{}, false
}

func TestACleanPushedCloneHoldsNothing(t *testing.T) {
	s := newScene(t)
	// Commit the planted attributes so the tree is clean, then push them.
	git(t, s.project, "add", ".gitattributes")
	git(t, s.project, "commit", "-q", "-m", "attrs")
	git(t, s.project, "push", "-q", "origin", "main")

	st := inspect(t, s.project, gitstate.Options{Exclude: []string{".cloop"}})
	if !st.Repository {
		t.Fatalf("not reported as a repository: %s", st.NotARepository)
	}
	if !reflect.DeepEqual(st.Remotes, []string{"origin"}) {
		t.Errorf("remotes = %v, want [origin]", st.Remotes)
	}
	if got := st.Unpushed(); len(got) != 0 {
		t.Errorf("unpushed branches = %+v, want none", got)
	}
	main, ok := worktree(st, "")
	if !ok || main.Dirty() {
		t.Errorf("main worktree = %+v (found %v), want clean", main, ok)
	}
	if main.Branch != "main" {
		t.Errorf("main worktree branch = %q, want main", main.Branch)
	}
	s.assertNothingRan(t)
}

func TestChangesAreCountedAndTheExcludedDirectoryIsNot(t *testing.T) {
	s := newScene(t)
	write(t, filepath.Join(s.project, "tracked.txt"), "changed\n")
	write(t, filepath.Join(s.project, "staged file.md"), "new\n")
	git(t, s.project, "add", "staged file.md")
	git(t, s.project, "mv", "README.md", "READ ME.md")
	write(t, filepath.Join(s.project, "loose.txt"), "untracked\n")
	write(t, filepath.Join(s.project, "newdir", "a"), "x\n")
	write(t, filepath.Join(s.project, "newdir", "b"), "y\n")
	write(t, filepath.Join(s.project, ".cloop", "artifacts", "1_output.txt"), "bookkeeping\n")
	indexBefore, err := os.ReadFile(filepath.Join(s.project, ".git", "index"))
	if err != nil {
		t.Fatal(err)
	}

	st := inspect(t, s.project, gitstate.Options{Exclude: []string{".cloop"}})
	main, _ := worktree(st, "")
	// tracked.txt (modified), "staged file.md" (added), "READ ME.md" (renamed).
	if main.Changed != 3 {
		t.Errorf("changed = %d %v, want 3", main.Changed, main.ChangedPaths)
	}
	for _, want := range []string{"tracked.txt", "staged file.md", "READ ME.md"} {
		if !contains(main.ChangedPaths, want) {
			t.Errorf("changed paths %q lack %q", main.ChangedPaths, want)
		}
	}
	// .gitattributes, loose.txt and newdir/ — one entry for the directory.
	if main.Untracked != 3 {
		t.Errorf("untracked = %d %v, want 3", main.Untracked, main.UntrackedPaths)
	}
	for _, p := range append(main.ChangedPaths, main.UntrackedPaths...) {
		if strings.HasPrefix(p, ".cloop") {
			t.Errorf("the excluded .cloop directory was reported: %q", p)
		}
	}
	indexAfter, err := os.ReadFile(filepath.Join(s.project, ".git", "index"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(indexBefore, indexAfter) {
		t.Error("the inspection rewrote the index; it must take no optional lock and refresh nothing")
	}
	s.assertNothingRan(t)
}

func TestCommitsNoRemoteHoldsAreCountedPerBranch(t *testing.T) {
	s := newScene(t)
	git(t, s.project, "commit", "-q", "--allow-empty", "-m", "ahead on main")
	git(t, s.project, "checkout", "-q", "-b", "side")
	git(t, s.project, "commit", "-q", "--allow-empty", "-m", "side 1")
	git(t, s.project, "commit", "-q", "--allow-empty", "-m", "side 2")
	git(t, s.project, "checkout", "-q", "main")
	// A pushed branch counts nothing, however far it is from main.
	git(t, s.project, "checkout", "-q", "-b", "published", "origin/main")
	git(t, s.project, "commit", "-q", "--allow-empty", "-m", "published")
	git(t, s.project, "push", "-q", "origin", "published")
	git(t, s.project, "checkout", "-q", "main")

	st := inspect(t, s.project, gitstate.Options{Exclude: []string{".cloop"}})
	// side holds main's unpushed commit too: it was branched after it.
	for name, want := range map[string]int{"main": 1, "side": 3, "published": 0} {
		b, ok := branch(st, name)
		if !ok {
			t.Fatalf("branch %s not listed: %+v", name, st.Branches)
		}
		if b.Unpushed != want {
			t.Errorf("branch %s: unpushed = %d, want %d", name, b.Unpushed, want)
		}
	}
	if b, _ := branch(st, "main"); b.Upstream != "refs/remotes/origin/main" {
		t.Errorf("main's upstream = %q, want refs/remotes/origin/main", b.Upstream)
	}
	s.assertNothingRan(t)
}

func TestARepositoryWithNoRemoteHoldsEveryCommitAlone(t *testing.T) {
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	git(t, dir, "commit", "-q", "--allow-empty", "-m", "one")
	git(t, dir, "commit", "-q", "--allow-empty", "-m", "two")

	st := inspect(t, dir, gitstate.Options{})
	if len(st.Remotes) != 0 {
		t.Errorf("remotes = %v, want none", st.Remotes)
	}
	if b, _ := branch(st, "main"); b.Unpushed != 2 {
		t.Errorf("main unpushed = %d, want 2 — with no remote every commit exists only here", b.Unpushed)
	}
}

func TestFeatureWorktreesAreInspectedAndOutsideOnesOnlyCounted(t *testing.T) {
	s := newScene(t)
	feature := filepath.Join(s.project, ".cloop", "features", "widget")
	git(t, s.project, "worktree", "add", "-q", "-b", "cloop/feature/widget", feature)
	git(t, feature, "commit", "-q", "--allow-empty", "-m", "feature work")
	write(t, filepath.Join(feature, "wip.go"), "package wip\n")
	// The feature's own bookkeeping is excluded like the project's.
	write(t, filepath.Join(feature, ".cloop", "state.db"), "db")
	outside := filepath.Join(t.TempDir(), "elsewhere")
	git(t, s.project, "worktree", "add", "-q", "-b", "elsewhere", outside)
	write(t, filepath.Join(outside, "not-ours.txt"), "x\n")
	// A detached worktree holding a commit no branch has.
	task := filepath.Join(s.project, ".cloop", "worktrees", "task-7")
	git(t, s.project, "worktree", "add", "-q", "--detach", task)
	git(t, task, "commit", "-q", "--allow-empty", "-m", "only here")
	git(t, s.project, "worktree", "lock", "--reason", "cloop: kept for the task's next attempt", task)

	st := inspect(t, s.project, gitstate.Options{Exclude: []string{".cloop"}})
	if st.WorktreesOutside != 1 {
		t.Errorf("worktrees outside = %d, want 1", st.WorktreesOutside)
	}
	if len(st.Worktrees) != 3 || st.Worktrees[0].Rel != "" {
		t.Fatalf("worktrees = %+v, want the main worktree first and two inside the project", st.Worktrees)
	}
	fw, ok := worktree(st, ".cloop/features/widget")
	if !ok {
		t.Fatalf("feature worktree not inspected: %+v", st.Worktrees)
	}
	if fw.Branch != "cloop/feature/widget" || fw.Untracked != 1 || !contains(fw.UntrackedPaths, "wip.go") {
		t.Errorf("feature worktree = %+v, want branch cloop/feature/widget with wip.go untracked", fw)
	}
	if b, _ := branch(st, "cloop/feature/widget"); b.Unpushed != 1 {
		t.Errorf("feature branch unpushed = %d, want 1", b.Unpushed)
	}
	tw, ok := worktree(st, ".cloop/worktrees/task-7")
	if !ok {
		t.Fatalf("task worktree not inspected: %+v", st.Worktrees)
	}
	if !tw.Detached || tw.Orphaned != 1 {
		t.Errorf("task worktree = %+v, want detached holding 1 orphaned commit", tw)
	}
	if tw.Locked != "cloop: kept for the task's next attempt" {
		t.Errorf("lock reason = %q", tw.Locked)
	}
	main, _ := worktree(st, "")
	for _, p := range main.UntrackedPaths {
		if strings.HasPrefix(p, ".cloop") {
			t.Errorf("a worktree inside .cloop was reported as untracked in the main worktree: %q", p)
		}
	}
	s.assertNothingRan(t)
}

func TestStashEntriesAreCounted(t *testing.T) {
	s := newScene(t)
	for i := 0; i < 2; i++ {
		write(t, filepath.Join(s.project, "README.md"), strings.Repeat("x", i+1)+"\n")
		git(t, s.project, "stash", "-q")
	}
	st := inspect(t, s.project, gitstate.Options{})
	if st.Stash != 2 {
		t.Errorf("stash = %d, want 2", st.Stash)
	}
}

func TestNotTheTopOfARepository(t *testing.T) {
	cases := map[string]func(t *testing.T) string{
		"no .git": func(t *testing.T) string { return t.TempDir() },
		"a directory inside another repository": func(t *testing.T) string {
			s := newScene(t)
			sub := filepath.Join(s.project, "sub")
			if err := os.MkdirAll(filepath.Join(sub, ".git"), 0o755); err != nil {
				t.Fatal(err)
			}
			// An empty .git directory is not a repository; git looks upward
			// and must not be allowed to answer with the enclosing one.
			return sub
		},
		"a .git that is a symbolic link": func(t *testing.T) string {
			s := newScene(t)
			dir := t.TempDir()
			if err := os.Symlink(filepath.Join(s.project, ".git"), filepath.Join(dir, ".git")); err != nil {
				t.Fatal(err)
			}
			return dir
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			dir := setup(t)
			st, err := gitstate.Inspect(context.Background(), dir, gitstate.Options{})
			if err != nil {
				// An unusable .git directory may also fail outright; what must
				// never happen is a report about another repository.
				if strings.Contains(name, "inside") {
					return
				}
				t.Fatalf("Inspect: %v", err)
			}
			if st.Repository {
				t.Fatalf("reported as a repository: %+v", st)
			}
			if st.NotARepository == "" {
				t.Error("no reason given")
			}
		})
	}
}

func TestOutputBeyondTheCapIsReportedAsCut(t *testing.T) {
	s := newScene(t)
	for i := 0; i < 50; i++ {
		write(t, filepath.Join(s.project, "untracked-file-with-a-long-name-"+strings.Repeat("x", 20)+string(rune('a'+i%26))+string(rune('a'+i/26))), "x")
	}
	st := inspect(t, s.project, gitstate.Options{MaxOutput: 256, MaxPaths: 3})
	main, _ := worktree(st, "")
	if !main.Truncated {
		t.Fatalf("a status cut at 256 bytes was not reported as cut: %+v", main)
	}
	if main.Untracked == 0 || main.Untracked >= 51 {
		t.Errorf("untracked = %d, want a lower bound between 1 and 50", main.Untracked)
	}
	if len(main.UntrackedPaths) > 3 {
		t.Errorf("kept %d paths, want at most 3", len(main.UntrackedPaths))
	}
}

func TestARelativePathIsRefused(t *testing.T) {
	if _, err := gitstate.Inspect(context.Background(), "relative/dir", gitstate.Options{}); err == nil {
		t.Fatal("a relative directory was accepted")
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
