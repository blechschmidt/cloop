package writeback

// These tests drive real git. That is deliberate: every claim this package
// makes is a claim about what git does with a bundle, a refspec or a tree, and
// a fake git would only prove that the fake agrees with the assertions.
//
// The shape of every test is the shape of the real system — an origin, a hub
// clone that is the project, and a sandbox clone that is the untrusted party —
// because the bugs worth catching here are the ones where those three roles get
// confused.

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitwriteback"
	"github.com/blechschmidt/cloop/pkg/mergequeue"
)

const testBranch = "cloop/task-42-write-back"

// --- harness ----------------------------------------------------------------

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

// scene is an origin, the hub's clone of it, and a sandbox's clone of it.
type scene struct {
	origin  string // bare
	hub     string // the project on the control plane
	sandbox string // the untrusted working tree
	base    string // the commit both clones start at
}

func newScene(t *testing.T) *scene {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()

	seed := filepath.Join(root, "seed")
	if err := os.MkdirAll(seed, 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, seed, "init", "--quiet", "--initial-branch=main")
	write(t, filepath.Join(seed, "README.md"), "hello\n")
	write(t, filepath.Join(seed, "app", "main.go"), "package main\n")
	git(t, seed, "add", "-A")
	git(t, seed, "commit", "--quiet", "-m", "seed")

	origin := filepath.Join(root, "origin.git")
	git(t, root, "clone", "--quiet", "--bare", seed, origin)

	hub := filepath.Join(root, "hub")
	git(t, root, "clone", "--quiet", origin, hub)
	sandbox := filepath.Join(root, "sandbox")
	git(t, root, "clone", "--quiet", origin, sandbox)

	// A committer identity written into each repository's own config, not
	// passed through the environment of the helper above.
	//
	// Production code runs git here too — mergequeue shells out to
	// `git merge --no-ff`, which writes a merge commit — and it inherits this
	// process's environment, not the helper's. On a developer machine that
	// still worked, because git fell back to a global ~/.gitconfig; on a CI
	// runner, which has none, it failed with "Committer identity unknown" and
	// the test read as "remote work did not merge".
	for _, repo := range []string{hub, sandbox} {
		git(t, repo, "config", "user.name", "cloop test")
		git(t, repo, "config", "user.email", "test@example.invalid")
	}

	return &scene{origin: origin, hub: hub, sandbox: sandbox, base: git(t, hub, "rev-parse", "HEAD")}
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

func (s *scene) workspace() executor.Workspace {
	return executor.Workspace{
		Kind: executor.WorkspaceGit,
		Repo: "https://example.invalid/acme/widgets.git",
		Ref:  "main",
	}
}

// produceBundle runs the real producer against the sandbox tree.
func (s *scene) produceBundle(t *testing.T, wb executor.WriteBack) (gitwriteback.Result, []byte) {
	t.Helper()
	res, err := gitwriteback.Produce(context.Background(), gitwriteback.Request{
		Dir:       s.sandbox,
		Workspace: s.workspace(),
		WriteBack: wb,
		BaseSHA:   s.base,
		Host:      "this sandbox",
	})
	if err != nil {
		t.Fatalf("Produce: %v", err)
	}
	if res.BundlePath == "" {
		return res, nil
	}
	t.Cleanup(func() { _ = os.Remove(res.BundlePath) })
	raw, err := os.ReadFile(res.BundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	return res, raw
}

func bundleSpec() executor.WriteBack {
	return executor.WriteBack{
		Mode:    executor.WriteBackBundle,
		Branch:  testBranch,
		Message: "cloop(task-42): add a retry",
	}
}

// --- the happy path ---------------------------------------------------------

func TestApply_BundleRoundTrip(t *testing.T) {
	s := newScene(t)
	write(t, filepath.Join(s.sandbox, "app", "main.go"), "package main\n\nfunc main() {}\n")
	write(t, filepath.Join(s.sandbox, "app", "retry.go"), "package main\n")

	produced, raw := s.produceBundle(t, bundleSpec())
	if produced.Skipped {
		t.Fatalf("producer skipped a dirty tree: %+v", produced.WriteBackResult)
	}
	if produced.FilesChanged != 2 {
		t.Errorf("FilesChanged = %d, want 2", produced.FilesChanged)
	}
	if err := executor.ValidateCommitSHA(produced.CommitSHA); err != nil {
		t.Fatalf("producer reported an unusable commit: %v", err)
	}

	res, err := Apply(context.Background(), Request{
		RepoDir: s.hub, Reported: produced.WriteBackResult, Bundle: raw,
		TaskID: 42, TaskTitle: "add a retry",
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.CommitSHA != produced.CommitSHA {
		t.Errorf("landed %s, sandbox produced %s", res.CommitSHA, produced.CommitSHA)
	}
	if res.Branch != testBranch {
		t.Errorf("Branch = %q, want %q", res.Branch, testBranch)
	}
	if res.FilesChanged != 2 {
		t.Errorf("FilesChanged = %d, want 2", res.FilesChanged)
	}

	// The branch exists on the hub at exactly the SHA the sandbox reported.
	if got := git(t, s.hub, "rev-parse", "refs/heads/"+testBranch); got != produced.CommitSHA {
		t.Errorf("hub branch is at %s, sandbox reported %s", got, produced.CommitSHA)
	}
	// And the content actually arrived — the whole point of the exercise.
	body := git(t, s.hub, "show", testBranch+":app/retry.go")
	if !strings.Contains(body, "package main") {
		t.Errorf("app/retry.go on the landed branch = %q", body)
	}

	// The quarantine ref must not survive: an unpromoted name for the same
	// commit is a ref that goes stale and confuses the next reader.
	if out, err := exec.Command("git", "-C", s.hub, "rev-parse", "--verify",
		QuarantineRefPrefix+testBranch).CombinedOutput(); err == nil {
		t.Errorf("quarantine ref survived Apply: %s", out)
	}
}

func TestApply_HandsBranchToMergeQueue(t *testing.T) {
	s := newScene(t)
	write(t, filepath.Join(s.sandbox, "app", "retry.go"), "package main\n")
	produced, raw := s.produceBundle(t, bundleSpec())

	q := mergequeue.New(s.hub, "main")
	q.Start(context.Background())
	defer q.Stop()

	res, err := Apply(context.Background(), Request{
		RepoDir: s.hub, Reported: produced.WriteBackResult, Bundle: raw,
		TaskID: 42, TaskTitle: "add a retry", Queue: q, MergeTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Merged {
		t.Fatalf("remote work did not merge: %v", res.MergeErr)
	}
	// Merged means merged: the file is on main in the hub's working tree,
	// reached through the same queue local parallel work uses.
	if _, err := os.Stat(filepath.Join(s.hub, "app", "retry.go")); err != nil {
		t.Errorf("merged file is not in the hub's working tree: %v", err)
	}
	if got := git(t, s.hub, "rev-parse", "HEAD"); got != res.MergeSHA {
		t.Errorf("HEAD = %s, MergeSHA = %s", got, res.MergeSHA)
	}
}

// TestApply_MergeConflictKeepsTheBranch pins the one case where a failure must
// not be a failure. The work is on disk; reporting an error would read as
// "your task's output was lost".
func TestApply_MergeConflictKeepsTheBranch(t *testing.T) {
	s := newScene(t)
	write(t, filepath.Join(s.sandbox, "README.md"), "sandbox version\n")
	produced, raw := s.produceBundle(t, bundleSpec())

	// The hub moves on independently, touching the same line.
	write(t, filepath.Join(s.hub, "README.md"), "hub version\n")
	git(t, s.hub, "commit", "--quiet", "-am", "hub edit")

	q := mergequeue.New(s.hub, "main")
	q.Start(context.Background())
	defer q.Stop()

	res, err := Apply(context.Background(), Request{
		RepoDir: s.hub, Reported: produced.WriteBackResult, Bundle: raw,
		TaskID: 42, Queue: q, MergeTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("a merge conflict must not fail Apply: %v", err)
	}
	if res.Merged || res.MergeErr == nil {
		t.Errorf("expected an unmerged result with a reason, got merged=%v err=%v", res.Merged, res.MergeErr)
	}
	if got := git(t, s.hub, "rev-parse", "refs/heads/"+testBranch); got != produced.CommitSHA {
		t.Errorf("the conflicting branch was not kept: %q", got)
	}
}

// --- refusals ---------------------------------------------------------------

func TestApply_SkipsWhenNothingChanged(t *testing.T) {
	s := newScene(t)
	produced, raw := s.produceBundle(t, bundleSpec())
	if !produced.Skipped {
		t.Fatalf("a clean tree should skip, got %+v", produced.WriteBackResult)
	}
	if raw != nil {
		t.Error("a skipped write-back produced a bundle")
	}
	res, err := Apply(context.Background(), Request{RepoDir: s.hub, Reported: produced.WriteBackResult})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Skipped {
		t.Error("Apply did not report the skip")
	}
	// Nothing may be created for a skip — not even an empty branch.
	if out, err := exec.Command("git", "-C", s.hub, "rev-parse", "--verify",
		"refs/heads/"+testBranch).CombinedOutput(); err == nil {
		t.Errorf("a skipped write-back created a branch: %s", out)
	}
}

// TestApply_FailedTaskWritesNothingBack is the test the task description asks
// for by name. A harness that exited non-zero left the tree mid-edit, and a
// half-applied refactor merged into main is worse than one that was discarded,
// because the loss is visible and the half-change is not.
func TestApply_FailedTaskWritesNothingBack(t *testing.T) {
	s := newScene(t)
	write(t, filepath.Join(s.sandbox, "app", "half-written.go"), "package ma")

	produced, err := gitwriteback.Produce(context.Background(), gitwriteback.Request{
		Dir: s.sandbox, Workspace: s.workspace(), WriteBack: bundleSpec(),
		BaseSHA: s.base, ExitCode: 1, OnlyOnSuccess: true,
	})
	if err != nil {
		t.Fatalf("Produce: %v", err)
	}
	if !produced.Skipped {
		t.Fatalf("a failed task must not write back, got %+v", produced.WriteBackResult)
	}
	if produced.CommitSHA != "" || produced.BundlePath != "" {
		t.Fatalf("a failed task produced a commit or bundle: %+v", produced)
	}
	if !strings.Contains(produced.SkipReason, "exited 1") {
		t.Errorf("SkipReason = %q, want it to name the exit status", produced.SkipReason)
	}
	// The refusal has to be visible in the sandbox too: no branch was created,
	// so a later run cannot pick the half-edit up by accident.
	if out, err := exec.Command("git", "-C", s.sandbox, "rev-parse", "--verify",
		"refs/heads/"+testBranch).CombinedOutput(); err == nil {
		t.Errorf("a failed task left a branch behind in the sandbox: %s", out)
	}

	res, err := Apply(context.Background(), Request{RepoDir: s.hub, Reported: produced.WriteBackResult})
	if err != nil || !res.Skipped {
		t.Fatalf("Apply of a skipped result: res=%+v err=%v", res, err)
	}
}

// TestApply_SucceedingTaskStillWritesBackUnderOnlyOnSuccess is the control for
// the test above: the gate has to be the exit code, not the flag.
func TestApply_SucceedingTaskStillWritesBackUnderOnlyOnSuccess(t *testing.T) {
	s := newScene(t)
	write(t, filepath.Join(s.sandbox, "app", "retry.go"), "package main\n")

	produced, err := gitwriteback.Produce(context.Background(), gitwriteback.Request{
		Dir: s.sandbox, Workspace: s.workspace(), WriteBack: bundleSpec(),
		BaseSHA: s.base, ExitCode: 0, OnlyOnSuccess: true,
	})
	if err != nil {
		t.Fatalf("Produce: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(produced.BundlePath) })
	if produced.Skipped || produced.CommitSHA == "" {
		t.Fatalf("a successful task produced nothing: %+v", produced.WriteBackResult)
	}
}

func TestApply_RejectsMismatchedDigest(t *testing.T) {
	s := newScene(t)
	write(t, filepath.Join(s.sandbox, "app", "retry.go"), "package main\n")
	produced, raw := s.produceBundle(t, bundleSpec())

	rep := produced.WriteBackResult
	rep.BundleSHA256 = strings.Repeat("0", 64)
	_, err := Apply(context.Background(), Request{RepoDir: s.hub, Reported: rep, Bundle: raw})
	if err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("a tampered bundle was accepted or misreported: %v", err)
	}
}

func TestApply_RejectsMismatchedCommitSHA(t *testing.T) {
	s := newScene(t)
	write(t, filepath.Join(s.sandbox, "app", "retry.go"), "package main\n")
	produced, raw := s.produceBundle(t, bundleSpec())

	rep := produced.WriteBackResult
	rep.CommitSHA = strings.Repeat("a", 40) // well-formed, and not what arrived
	rep.BundleSHA256 = ""                   // let it get as far as the ref comparison

	_, err := Apply(context.Background(), Request{RepoDir: s.hub, Reported: rep, Bundle: raw})
	if err == nil {
		t.Fatal("a bundle whose ref does not match the reported SHA was accepted")
	}
	var rej *executor.WriteBackRejection
	if !errors.As(err, &rej) {
		t.Fatalf("want a *WriteBackRejection, got %T: %v", err, err)
	}
	if got := git(t, s.hub, "branch", "--list", testBranch); got != "" {
		t.Errorf("a rejected write-back created a branch: %q", got)
	}
}

func TestApply_RejectsUnknownBase(t *testing.T) {
	s := newScene(t)
	write(t, filepath.Join(s.sandbox, "app", "retry.go"), "package main\n")
	produced, raw := s.produceBundle(t, bundleSpec())

	rep := produced.WriteBackResult
	rep.BaseSHA = strings.Repeat("b", 40)
	_, err := Apply(context.Background(), Request{RepoDir: s.hub, Reported: rep, Bundle: raw})
	if !errors.Is(err, executor.ErrWriteBackRejected) {
		t.Fatalf("want ErrWriteBackRejected for a base the hub never had, got %v", err)
	}
}

// TestApply_RejectsBranchOutsideTheCloopNamespace is what stops a sandbox from
// having the hub force-update a branch a human owns.
func TestApply_RejectsBranchOutsideTheCloopNamespace(t *testing.T) {
	s := newScene(t)
	for _, branch := range []string{"main", "release/2.0", "../../etc/passwd", "-oProxyCommand=x"} {
		rep := executor.WriteBackResult{
			Mode: executor.WriteBackBundle, Branch: branch,
			CommitSHA: strings.Repeat("a", 40), BaseSHA: strings.Repeat("b", 40),
		}
		_, err := Apply(context.Background(), Request{RepoDir: s.hub, Reported: rep, Bundle: []byte("x")})
		if !errors.Is(err, executor.ErrWriteBackRejected) {
			t.Errorf("branch %q: want ErrWriteBackRejected, got %v", branch, err)
		}
	}
}

func TestApply_RejectsGarbageBundle(t *testing.T) {
	s := newScene(t)
	rep := executor.WriteBackResult{
		Mode: executor.WriteBackBundle, Branch: testBranch,
		CommitSHA: strings.Repeat("a", 40), BaseSHA: s.base,
	}
	_, err := Apply(context.Background(), Request{
		RepoDir: s.hub, Reported: rep, Bundle: []byte("this is not a git bundle"),
	})
	if err == nil {
		t.Fatal("a non-bundle was accepted")
	}
	if git(t, s.hub, "branch", "--list", testBranch) != "" {
		t.Error("a garbage bundle created a branch")
	}
}

func TestApply_RejectsOversizeBundle(t *testing.T) {
	s := newScene(t)
	rep := executor.WriteBackResult{
		Mode: executor.WriteBackBundle, Branch: testBranch,
		CommitSHA: strings.Repeat("a", 40), BaseSHA: s.base,
		BundleBytes: executor.MaxWriteBackBundleBytes + 1,
	}
	_, err := Apply(context.Background(), Request{
		RepoDir: s.hub, Reported: rep,
		Bundle: make([]byte, executor.MaxWriteBackBundleBytes+1),
	})
	if !errors.Is(err, executor.ErrWriteBackRejected) {
		t.Fatalf("want ErrWriteBackRejected for an oversize bundle, got %v", err)
	}
}

// TestProduce_RefusesToExceedTheSpecCap proves the ceiling is also enforced at
// the source, so an oversize bundle never occupies the link in the first place.
func TestProduce_RefusesToExceedTheSpecCap(t *testing.T) {
	s := newScene(t)
	// Incompressible, deliberately: a bundle is zlib-compressed, so 200 KB of
	// the same byte lands well under any cap and would make this test pass for
	// a reason unrelated to the ceiling it claims to check.
	noise := make([]byte, 200_000)
	if _, err := rand.Read(noise); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(s.sandbox, "big.bin"), string(noise))

	wb := bundleSpec()
	wb.MaxBundleBytes = 1024
	res, err := gitwriteback.Produce(context.Background(), gitwriteback.Request{
		Dir: s.sandbox, Workspace: s.workspace(), WriteBack: wb, BaseSHA: s.base,
	})
	if !errors.Is(err, executor.ErrWriteBackUnavailable) {
		t.Fatalf("want ErrWriteBackUnavailable for an oversize bundle, got %v", err)
	}
	if res.BundlePath != "" {
		t.Errorf("an over-cap bundle was left on disk at %q", res.BundlePath)
	}
}

// TestApply_PushPathIsInspectedToo pins the decision that the transport does
// not decide the trust level. A sandbox holding a push credential is exactly as
// untrusted as one holding none.
func TestApply_PushPathIsInspectedToo(t *testing.T) {
	s := newScene(t)
	write(t, filepath.Join(s.sandbox, "app", "retry.go"), "package main\n")

	// Stand in for the sandbox's push: the branch is already at the origin,
	// which is what the hub will fetch from.
	git(t, s.sandbox, "checkout", "--quiet", "-B", testBranch)
	git(t, s.sandbox, "add", "-A")
	git(t, s.sandbox, "commit", "--quiet", "-m", "sandbox work")
	sha := git(t, s.sandbox, "rev-parse", "HEAD")
	git(t, s.sandbox, "push", "--quiet", "origin", testBranch)

	res, err := Apply(context.Background(), Request{
		RepoDir: s.hub,
		Reported: executor.WriteBackResult{
			Mode: executor.WriteBackPush, Branch: testBranch,
			CommitSHA: sha, BaseSHA: s.base, Pushed: true,
		},
		TaskID: 42,
	})
	if err != nil {
		t.Fatalf("Apply of a pushed branch: %v", err)
	}
	if res.CommitSHA != sha {
		t.Errorf("landed %s, sandbox pushed %s", res.CommitSHA, sha)
	}
	if got := git(t, s.hub, "rev-parse", "refs/heads/"+testBranch); got != sha {
		t.Errorf("hub branch is at %s, want %s", got, sha)
	}
}

func TestApply_PushPathRejectsWrongSHA(t *testing.T) {
	s := newScene(t)
	write(t, filepath.Join(s.sandbox, "app", "retry.go"), "package main\n")
	git(t, s.sandbox, "checkout", "--quiet", "-B", testBranch)
	git(t, s.sandbox, "add", "-A")
	git(t, s.sandbox, "commit", "--quiet", "-m", "sandbox work")
	git(t, s.sandbox, "push", "--quiet", "origin", testBranch)

	_, err := Apply(context.Background(), Request{
		RepoDir: s.hub,
		Reported: executor.WriteBackResult{
			Mode: executor.WriteBackPush, Branch: testBranch,
			CommitSHA: strings.Repeat("c", 40), BaseSHA: s.base, Pushed: true,
		},
	})
	if !errors.Is(err, executor.ErrWriteBackRejected) {
		t.Fatalf("want ErrWriteBackRejected when the pushed ref is not at the reported SHA, got %v", err)
	}
	if git(t, s.hub, "branch", "--list", testBranch) != "" {
		t.Error("a rejected push created a branch on the hub")
	}
}

// --- unit-level helpers -----------------------------------------------------

func TestValidateRemoteName(t *testing.T) {
	for _, ok := range []string{"origin", "up-stream", "fork.2", "a_b"} {
		if err := validateRemoteName(ok); err != nil {
			t.Errorf("validateRemoteName(%q) = %v, want nil", ok, err)
		}
	}
	// The dashed forms are the ones that matter: git would read them as flags,
	// and --upload-pack turns a fetch into command execution.
	for _, bad := range []string{"", "-o", "--upload-pack=sh", "origin;rm", "a b", "https://x/y"} {
		if err := validateRemoteName(bad); err == nil {
			t.Errorf("validateRemoteName(%q) = nil, want an error", bad)
		}
	}
}
