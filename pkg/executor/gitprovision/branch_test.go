package gitprovision_test

// Building a tree from a shipped branch (Task 20367), and running git safely in
// a tree a sandbox wrote.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
	"github.com/blechschmidt/cloop/pkg/executor/internal/gitforge"
)

const featureBranch = "cloop/feature/widget"

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// shippedBranch makes a repository whose feature branch tracks a .cloop/ file,
// and bundles the branch.
func shippedBranch(t *testing.T) (*executor.BranchBundle, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := filepath.Join(t.TempDir(), "repo")
	gitIn(t, filepath.Dir(repo), "init", "-q", "-b", "main", repo)
	write := func(rel, body string) {
		p := filepath.Join(repo, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("README.md", "hi\n")
	write(".cloop/sandbox.yaml", "image: alpine\n")
	gitIn(t, repo, "add", "-A")
	gitIn(t, repo, "commit", "-qm", "base")
	gitIn(t, repo, "checkout", "-q", "-b", featureBranch)
	write("feature.txt", "feature\n")
	gitIn(t, repo, "add", "-A")
	gitIn(t, repo, "commit", "-qm", "feature")
	head := gitIn(t, repo, "rev-parse", "HEAD")
	path := filepath.Join(t.TempDir(), "b.bundle")
	gitIn(t, repo, "bundle", "create", "--quiet", path, "refs/heads/"+featureBranch)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return &executor.BranchBundle{Branch: featureBranch, Head: head, Bytes: int64(len(data)),
		SHA256: hex.EncodeToString(sum[:])}, path
}

func provisionBundle(dir string, b *executor.BranchBundle, file string) error {
	return gitprovision.Provision(context.Background(), gitprovision.Request{
		Dir:              dir,
		Workspace:        executor.Workspace{Kind: executor.WorkspaceBundle, Branch: b},
		BranchBundleFile: file,
	})
}

func TestProvisionFromABranchRebuildsTheTreeEveryTime(t *testing.T) {
	b, file := shippedBranch(t)
	dir := filepath.Join(t.TempDir(), "tree")
	// A previous dispatch's leftovers: an uncommitted file, and a .git that
	// the previous workload could have written anything into.
	if err := os.MkdirAll(filepath.Join(dir, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "leftover.txt"), []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "hooks", "post-checkout"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := provisionBundle(dir, b, file); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "leftover.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Error("the previous dispatch's leftovers survived")
	}
	if got := gitIn(t, dir, "symbolic-ref", "HEAD"); got != "refs/heads/"+featureBranch {
		t.Errorf("HEAD = %s, want the feature's branch attached", got)
	}
	if got := gitIn(t, dir, "rev-parse", "HEAD"); got != b.Head {
		t.Errorf("HEAD at %s, want %s", got, b.Head)
	}
	// The harness can commit without an identity of its own.
	if got := gitIn(t, dir, "config", "--local", "user.name"); got != gitprovision.CommitIdentityName {
		t.Errorf("user.name = %q", got)
	}
	// The project's state stays out of the tree's commits: untracked .cloop
	// is ignored, and tracked .cloop files are skip-worktree.
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "state.db"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "sandbox.yaml"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if st := gitIn(t, dir, "status", "--porcelain"); st != "" {
		t.Errorf("changes under .cloop/ show as changes to commit:\n%s", st)
	}
}

// TestProvisionOverlayBuildsTheBranchOnTheUpstream: a feature of a parent with
// an https upstream travels as its own commits only. The device fetches the
// base from the upstream, with the project's credential, as it would fetch the
// project, applies the bundle on top and is left on the feature's branch —
// over the package's real TLS forge, with the leak checks every fetch here
// gets.
func TestProvisionOverlayBuildsTheBranchOnTheUpstream(t *testing.T) {
	f := newFixture(t, gitforge.Options{})
	base := f.forge.SHA(t, owner, repo, gitforge.DefaultBranch)

	// The hub's side: the feature's commits on the upstream's base, bundled
	// without it — the bundle names the base as its prerequisite.
	hub := filepath.Join(t.TempDir(), "hub")
	gitIn(t, filepath.Dir(hub), "clone", "-q", f.forge.Path(owner, repo), hub)
	gitIn(t, hub, "checkout", "-q", "-b", featureBranch)
	if err := os.WriteFile(filepath.Join(hub, "feature.txt"), []byte("feature\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, hub, "add", "-A")
	gitIn(t, hub, "commit", "-qm", "feature")
	head := gitIn(t, hub, "rev-parse", "HEAD")
	file := filepath.Join(t.TempDir(), "overlay.bundle")
	gitIn(t, hub, "bundle", "create", "--quiet", file, base+"..refs/heads/"+featureBranch)
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	f.ws = executor.Workspace{Kind: executor.WorkspaceGit, Repo: f.forge.RepoURL(owner, repo), Ref: base,
		Branch: &executor.BranchBundle{Branch: featureBranch, Head: head, Bytes: int64(len(data)),
			SHA256: hex.EncodeToString(sum[:])}}
	if err := f.ws.Validate(); err != nil {
		t.Fatalf("the overlay workspace does not validate: %v", err)
	}

	req := f.request()
	req.BranchBundleFile = file
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	err = gitprovision.Provision(ctx, req)
	f.assertNoLeak(err)
	if err != nil {
		t.Fatalf("Provision: %v\n%s\nforge:\n%s", err, f.log(), f.forge.Log())
	}
	if f.forge.Count() == 0 {
		t.Error("the base did not come from the upstream")
	}
	if got := gitIn(t, f.dir, "symbolic-ref", "HEAD"); got != "refs/heads/"+featureBranch {
		t.Errorf("HEAD = %s, want the feature's branch attached", got)
	}
	if got := gitIn(t, f.dir, "rev-parse", "HEAD"); got != head {
		t.Errorf("HEAD at %s, want %s", got, head)
	}
	for _, name := range []string{"README.md", "feature.txt"} {
		if _, err := os.Stat(filepath.Join(f.dir, name)); err != nil {
			t.Errorf("the checkout lacks %s: %v", name, err)
		}
	}
}

func TestProvisionFromABranchRefusesWhatWasNotSent(t *testing.T) {
	b, file := shippedBranch(t)

	tampered := *b
	tampered.SHA256 = strings.Repeat("0", 64)
	dir := filepath.Join(t.TempDir(), "tree")
	err := provisionBundle(dir, &tampered, file)
	if !errors.Is(err, executor.ErrWorkspaceUnavailable) || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a bundle that is not what was sent = %v", err)
	}

	elsewhere := *b
	elsewhere.Head = strings.Repeat("a", 40)
	dir = filepath.Join(t.TempDir(), "tree")
	err = provisionBundle(dir, &elsewhere, file)
	if err == nil || !strings.Contains(err.Error(), "control plane sent it at") {
		t.Fatalf("a branch at another commit than the one sent = %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("a refused tree was left half-built: %v", entries)
	}

	if err := provisionBundle(filepath.Join(t.TempDir(), "t"), b, ""); err == nil {
		t.Error("a branch whose bundle never arrived was provisioned")
	}
}

func TestSandboxedRepoEnvPinsTheRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := filepath.Join(t.TempDir(), "tree")
	gitIn(t, filepath.Dir(dir), "init", "-q", "-b", "main", dir)

	// A workload configured a clean filter that would run on `git add`...
	marker := filepath.Join(t.TempDir(), "filter-ran")
	gitIn(t, dir, "config", "filter.evil.clean", "sh -c 'touch "+marker+"; cat'")
	// ...and left an alternates file and a commondir behind, pointing git at
	// another directory's objects and configuration.
	other := filepath.Join(t.TempDir(), "other")
	gitIn(t, filepath.Dir(other), "init", "-q", "--bare", other)
	for _, rel := range []string{"objects/info/alternates", "commondir"} {
		target := filepath.Join(other, "objects")
		if rel == "commondir" {
			target = other
		}
		if err := os.WriteFile(filepath.Join(dir, ".git", rel), []byte(target+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitattributes"), []byte("* filter=evil\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	env, err := gitprovision.SandboxedRepoEnv(context.Background(), dir)
	if err != nil {
		t.Fatalf("SandboxedRepoEnv: %v", err)
	}
	for _, rel := range []string{"objects/info/alternates", "commondir"} {
		if _, err := os.Lstat(filepath.Join(dir, ".git", rel)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf(".git/%s survived", rel)
		}
	}
	joined := strings.Join(env, "\n")
	for _, want := range []string{"GIT_DIR=" + filepath.Join(dir, ".git"), "GIT_WORK_TREE=" + dir, "filter.evil.clean"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the environment does not pin %s", want)
		}
	}
	cmd := exec.Command("git", "-C", dir, "add", "-A")
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add under the hardened environment: %v\n%s", err, out)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the repository's clean filter ran")
	}

	// A .git that is a pointer is not a repository cloop runs git in.
	ptr := filepath.Join(t.TempDir(), "ptr")
	if err := os.MkdirAll(ptr, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ptr, ".git"), []byte("gitdir: "+filepath.Join(dir, ".git")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := gitprovision.SandboxedRepoEnv(context.Background(), ptr); err == nil {
		t.Error("a gitdir pointer was accepted as a repository")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.MkdirAll(link, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, ".git"), filepath.Join(link, ".git")); err != nil {
		t.Fatal(err)
	}
	if _, err := gitprovision.SandboxedRepoEnv(context.Background(), link); err == nil {
		t.Error("a linked .git was accepted as a repository")
	}
}
