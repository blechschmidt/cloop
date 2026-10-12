package worktree

// The hub's background sweep runs git in repositories a sandbox could write
// (Task 20418). These tests plant what such a sandbox could plant and check
// that the sweep runs none of it, hands it nothing of the hub's environment,
// refuses a repository that points git somewhere else, and cannot be held
// forever.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// plantPrograms configures repo to run a program that appends to marker from
// a hook, the fsmonitor and a clean filter — the three ways a repository's own
// configuration makes git execute something.
func plantPrograms(t *testing.T, repo, marker string) {
	t.Helper()
	script := filepath.Join(t.TempDir(), "planted.sh")
	body := "#!/bin/sh\n{ echo \"ran: $0 $*\"; env; } >> '" + marker + "'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, hook := range []string{"reference-transaction", "post-checkout", "pre-commit", "post-commit"} {
		path := filepath.Join(repo, ".git", "hooks", hook)
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	git(t, repo, "config", "core.fsmonitor", script)
	git(t, repo, "config", "filter.planted.clean", script)
	git(t, repo, "config", "filter.planted.required", "true")
	if err := os.WriteFile(filepath.Join(repo, ".gitattributes"), []byte("* filter=planted\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// mergedTask makes task id's worktree with one commit, merges it into main
// and ages it past the sweep's minimum, so a sweep with DeleteBranches removes
// the worktree and deletes its branch with `git branch -d`.
func mergedTask(t *testing.T, repo string, id int) *Worktree {
	t.Helper()
	wt := mustCreate(t, repo, id, "merged work")
	if err := os.WriteFile(filepath.Join(wt.Path, "f.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Commit(&pm.Task{ID: id, Title: "merged work"}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	git(t, repo, "merge", "--no-ff", "-m", "merge", wt.Branch)
	backdate(t, repo, id, 48*time.Hour)
	return wt
}

func TestSweepRunsNoProgramTheRepositoryConfigures(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	t.Setenv("CLOOP_SECRET_KEY", "sweep-canary-0f9e8d")
	repo := initRepo(t)
	wt := mergedTask(t, repo, 1)
	marker := filepath.Join(t.TempDir(), "marker")
	plantPrograms(t, repo, marker)

	res, err := Prune(repo, PruneOptions{MinAge: time.Hour, DeleteBranches: true, BaseBranch: "main"})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(res.Removed) != 1 || !res.Removed[0].BranchDeleted {
		t.Fatalf("Prune = %s; want the worktree removed and its merged branch deleted", res.Summary())
	}
	if _, err := os.Stat(wt.Path); !os.IsNotExist(err) {
		t.Fatalf("the worktree is still there: %v", err)
	}
	if data, err := os.ReadFile(marker); err == nil {
		t.Fatalf("the sweep ran a program the repository configured:\n%s", data)
	}

	// The control: the same deletion by an ordinary git runs the hook, with
	// the caller's environment — which is what the sweep used to hand it.
	git(t, repo, "branch", "plain", "main")
	git(t, repo, "branch", "-d", "plain")
	data, err := os.ReadFile(marker)
	if err != nil || !strings.Contains(string(data), "reference-transaction") {
		t.Fatalf("the planted hook does not run for an ordinary git either (%v), so the test proves nothing", err)
	}
	if !strings.Contains(string(data), "sweep-canary-0f9e8d") {
		t.Fatalf("an ordinary git's hook did not see the caller's environment; the canary is not where expected:\n%s", data)
	}
}

func TestSweepEnvironmentIsClosed(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	t.Setenv("CLOOP_SECRET_KEY", "sweep-canary-0f9e8d")
	repo := initRepo(t)
	git(t, repo, "config", "filter.lfs.clean", "git-lfs clean -- %f")
	env, err := sweepEnv(context.Background(), repo)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(env, "\n")
	for _, want := range []string{
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0",
		"GIT_DIR=" + filepath.Join(repo, ".git"), "GIT_WORK_TREE=" + repo,
	} {
		if !strings.Contains(joined, want+"\n") && !strings.HasSuffix(joined, want) {
			t.Errorf("the sweep's environment lacks %s:\n%s", want, joined)
		}
	}
	pairs := map[string]string{}
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(k, "GIT_CONFIG_KEY_") {
			pairs[v] = os.Expand("$"+strings.Replace(k, "KEY", "VALUE", 1), func(name string) string {
				for _, kv2 := range env {
					if strings.HasPrefix(kv2, name+"=") {
						return strings.TrimPrefix(kv2, name+"=")
					}
				}
				return "<unset>"
			})
		}
	}
	for key, want := range map[string]string{
		"core.hooksPath": "/dev/null", "core.fsmonitor": "false", "filter.lfs.clean": "",
		"safe.directory": repo, "gc.auto": "0",
	} {
		if got, ok := pairs[key]; !ok || got != want {
			t.Errorf("%s = %q (set %v), want %q", key, got, ok, want)
		}
	}
	for _, kv := range env {
		if strings.Contains(kv, "sweep-canary") || strings.HasPrefix(kv, "PATH=") || strings.HasPrefix(kv, "HOME=") {
			t.Errorf("the sweep's environment carries the hub's own: %s", kv)
		}
	}
}

// TestSweepRefusesARedirectedRepository: a .git file — a gitdir pointer, which
// a sandbox can write in place of its own .git — and an alternates file both
// point the sweep's git at another repository. Neither is followed, and the
// other repository's worktrees are untouched.
func TestSweepRefusesARedirectedRepository(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	victim := initRepo(t)
	victimWT := mustCreate(t, victim, 7, "the victim's live work")
	backdate(t, victim, 7, 48*time.Hour)

	redirected := t.TempDir()
	if err := os.MkdirAll(filepath.Join(redirected, ".cloop", "worktrees", "task-7"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(redirected, ".git"), []byte("gitdir: "+filepath.Join(victim, ".git")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Prune(redirected, PruneOptions{MinAge: time.Hour}); err == nil ||
		!strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("Prune through a gitdir file = %v, want a refusal", err)
	}
	if _, err := os.Stat(victimWT.Path); err != nil {
		t.Fatalf("the victim's worktree was removed through the pointer: %v", err)
	}

	alt := initRepo(t)
	altFile := filepath.Join(alt, ".git", "objects", "info", "alternates")
	if err := os.WriteFile(altFile, []byte(filepath.Join(victim, ".git", "objects")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Prune(alt, PruneOptions{MinAge: time.Hour}); err == nil || !strings.Contains(err.Error(), "alternates") {
		t.Fatalf("Prune with an alternates file = %v, want a refusal", err)
	}
	if _, err := os.Stat(altFile); err != nil {
		t.Fatalf("the sweep removed the repository's alternates file: %v", err)
	}
}

// TestSweepGitIsBounded: a git that never finishes — and leaves a child
// holding its output — does not hold the sweep.
func TestSweepGitIsBounded(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initRepo(t)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\nsleep 60 &\nsleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if p, err := exec.LookPath("git"); err != nil || p != filepath.Join(bin, "git") {
		t.Fatalf("the stand-in git is not first on PATH: %q %v", p, err)
	}
	old := gitTimeout
	gitTimeout = time.Second
	t.Cleanup(func() { gitTimeout = old })

	start := time.Now()
	_, err := runGit(repo, "worktree", "list", "--porcelain")
	if err == nil {
		t.Fatal("a git that never finished reported success")
	}
	if took := time.Since(start); took > 20*time.Second {
		t.Fatalf("the sweep's git took %s to give up, want about its 1s deadline", took)
	}
}
