// Tests for the half of the credential circuit that carries work *out* of an
// isolated executor.
//
// The package had no test file at all, and the failure it exists to prevent is
// the quietest one in the system: a run that streams a plausible transcript and
// delivers nothing. A write-back that produced no commit looks exactly like a
// task that changed no files, so a defect here is reported as a successful run
// with an empty result — and nobody goes looking.
//
// Which shapes the assertions. It is never enough that Produce returned no
// error: every test that expects a commit asks git for the ref, the SHA and the
// parent, and every test that expects a refusal asks the forge whether it
// received a request at all. The distinction between "refused" and "attempted
// and rejected by the remote" is the whole of the push-policy claim, and only
// the forge can settle it.
//
// The bundle path needs no network, so most of this file runs against a local
// repository; the push path runs against the same real TLS forge
// pkg/executor/gitprovision is tested with, and one test drives the entire
// circuit — provision, edit, write back — through both packages at once.
package gitwriteback_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
	"github.com/blechschmidt/cloop/pkg/executor/gitwriteback"
	"github.com/blechschmidt/cloop/pkg/executor/internal/gitforge"
	"github.com/blechschmidt/cloop/pkg/redact"
)

const (
	owner = "acme"
	repo  = "tool"

	credUser = "x-access-token"
	// Longer than redact.MinLen, or every leak assertion here would pass
	// because the redactor declined to match rather than because nothing
	// leaked. gitforge.NoSecretIn fails loudly on an empty Set so that cannot
	// happen silently.
	credToken = "cloop-test-lease-DO-NOT-LOG-7Kq2Vx9m"

	branch = "cloop/task-42-add-retry"
)

// --- fixture -------------------------------------------------------------------

type fixture struct {
	t     *testing.T
	tools gitforge.Tools
	// home isolates fixture git from the developer's own configuration, and is
	// a second place a leaked credential would plausibly land.
	home string
	// dir is the work tree a harness would have run in.
	dir string
	// forge is nil for the bundle-mode tests, which contact no remote at all.
	forge *gitforge.Forge

	ws   executor.Workspace
	wb   executor.WriteBack
	cred executor.GitCredential
	set  *redact.Set

	emitted strings.Builder
}

// newLocal builds a work tree with one commit and no remote.
//
// Repo still names an https URL because executor.Workspace demands one, but
// nothing in bundle mode contacts it — which is the point: a sandbox with no
// egress must be able to write back, and a test that needed a server to prove
// it would not be testing that.
func newLocal(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		t:     t,
		tools: gitforge.RequireGit(t),
		home:  t.TempDir(),
		dir:   filepath.Join(t.TempDir(), "workspace"),
	}
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		t.Fatalf("creating the work tree: %v", err)
	}
	f.git("init", "-b", gitforge.DefaultBranch, f.dir)
	gitforge.WriteFile(t, f.dir, "README.md", "seed\n")
	f.git("-C", f.dir, "add", "--all", "--", ".")
	f.git("-C", f.dir, "commit", "--no-gpg-sign", "-m", "seed")

	f.ws = executor.Workspace{
		Kind: executor.WorkspaceGit,
		Repo: "https://forge.example.invalid/" + owner + "/" + repo + ".git",
		Ref:  gitforge.DefaultBranch,
	}
	f.wb = executor.WriteBack{Mode: executor.WriteBackBundle, Branch: branch}
	f.set = redact.New(credToken)
	return f
}

// newPushable builds a work tree cloned from a real forge that demands the
// leased credential, so a served push is an authenticated one.
func newPushable(t *testing.T, opt gitforge.Options) *fixture {
	t.Helper()
	if opt.User == "" && opt.Password == "" {
		opt.User, opt.Password = credUser, credToken
	}
	f := &fixture{
		t:     t,
		tools: gitforge.RequireGit(t),
		home:  t.TempDir(),
		dir:   filepath.Join(t.TempDir(), "workspace"),
		forge: gitforge.Start(t, opt),
	}
	f.forge.Create(t, owner, repo)
	f.forge.Trust(t)

	// Cloned over the filesystem, not over HTTP: fixture setup must not depend
	// on the path under test, or a broken fetch would surface as a broken
	// write-back.
	f.git("clone", "--branch", gitforge.DefaultBranch, f.forge.Path(owner, repo), f.dir)

	f.ws = executor.Workspace{
		Kind: executor.WorkspaceGit,
		Repo: f.forge.RepoURL(owner, repo),
		Ref:  gitforge.DefaultBranch,
	}
	f.wb = executor.WriteBack{Mode: executor.WriteBackPush, Branch: branch}
	f.cred = executor.GitCredential{Username: credUser, Password: credToken}
	f.set = redact.New(f.cred.Secrets()...)
	return f
}

func (f *fixture) git(args ...string) string {
	f.t.Helper()
	return gitforge.Git(f.t, f.tools, f.home, f.dirOrHome(), args...)
}

func (f *fixture) tryGit(args ...string) (string, error) {
	f.t.Helper()
	return gitforge.TryGit(f.t, f.tools, f.home, f.dirOrHome(), args...)
}

// dirOrHome keeps git out of the caller's cwd even before the work tree exists.
func (f *fixture) dirOrHome() string {
	if st, err := os.Stat(f.dir); err == nil && st.IsDir() {
		return f.dir
	}
	return f.home
}

func (f *fixture) request() gitwriteback.Request {
	return gitwriteback.Request{
		Dir:           f.dir,
		Workspace:     f.ws,
		WriteBack:     f.wb,
		Credential:    f.cred,
		OnlyOnSuccess: true,
		Host:          "this test sandbox",
		Emit:          func(s string) { f.emitted.WriteString(s) },
	}
}

func (f *fixture) produce() (gitwriteback.Result, error) {
	f.t.Helper()
	return f.produceWith(f.request())
}

func (f *fixture) produceWith(r gitwriteback.Request) (gitwriteback.Result, error) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := gitwriteback.Produce(ctx, r)
	if res.BundlePath != "" {
		path := res.BundlePath
		f.t.Cleanup(func() { _ = os.Remove(path) })
	}
	return res, err
}

func (f *fixture) log() string { return f.emitted.String() }

// dirty writes a file the harness would have produced.
func (f *fixture) dirty(rel, content string) {
	f.t.Helper()
	gitforge.WriteFile(f.t, f.dir, rel, content)
}

// localSHA resolves a ref in the work tree, returning "" when it does not
// exist. The empty string is the useful answer for "the branch was never
// created", which is what most refusals here have to prove.
func (f *fixture) localSHA(ref string) string {
	f.t.Helper()
	out, err := f.tryGit("-C", f.dir, "rev-parse", "--verify", "--quiet", ref)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// assertNoLeak runs every leak assertion against one write-back: the error, the
// reported Err, the emitted log, the work tree, the home directory and the
// bundle. See the twin in pkg/executor/gitprovision for why they are checked
// together, and why the scanned count is returned rather than asserted here.
//
// A write-back always leaves a repository behind, so unlike provisioning the
// count is never legitimately zero — the guard is kept in place.
func (f *fixture) assertNoLeak(res gitwriteback.Result, err error) {
	f.t.Helper()
	if err != nil {
		gitforge.NoSecretIn(f.t, f.set, "the returned error", err.Error())
	}
	gitforge.NoSecretIn(f.t, f.set, "the reported Result.Err", res.Err)
	gitforge.NoSecretIn(f.t, f.set, "the emitted log", f.log())
	scanned := gitforge.NoSecretUnder(f.t, f.set, f.dir)
	scanned += gitforge.NoSecretUnder(f.t, f.set, f.home)
	if res.BundlePath != "" {
		scanned += gitforge.NoSecretUnder(f.t, f.set, res.BundlePath)
	}
	if scanned == 0 {
		f.t.Fatalf("the on-disk leak scan read no files, so it proves nothing")
	}
}

// --- what a write-back produces --------------------------------------------------

func TestProduceCommitsADirtyTreeToItsBranch(t *testing.T) {
	f := newLocal(t)
	base := f.localSHA("HEAD")
	f.dirty("src/retry.go", "package src\n")
	f.dirty("README.md", "seed\nand more\n")

	res, err := f.produce()
	if err != nil {
		t.Fatalf("Produce: %v\nlog:\n%s", err, f.log())
	}
	if res.Skipped {
		t.Fatalf("Produce skipped a dirty tree: %s", res.SkipReason)
	}
	if res.BaseSHA != base {
		t.Errorf("BaseSHA = %s, want the tree's HEAD before the write-back (%s)", res.BaseSHA, base)
	}
	if err := executor.ValidateCommitSHA(res.CommitSHA); err != nil {
		t.Errorf("CommitSHA is not a usable object name: %v", err)
	}
	if res.Commits != 1 {
		t.Errorf("Commits = %d, want 1", res.Commits)
	}
	// One modified file and one new one. A count taken from `git add` rather
	// than from the diff would report something else.
	if res.FilesChanged != 2 {
		t.Errorf("FilesChanged = %d, want 2", res.FilesChanged)
	}
	if res.Branch != branch {
		t.Errorf("Branch = %q, want %q", res.Branch, branch)
	}

	// The ref really exists and really is where the result says.
	if got := f.localSHA("refs/heads/" + branch); got != res.CommitSHA {
		t.Errorf("refs/heads/%s is at %s, but the result reported %s", branch, got, res.CommitSHA)
	}
	if parent := strings.TrimSpace(f.git("-C", f.dir, "rev-parse", res.CommitSHA+"^")); parent != base {
		t.Errorf("the write-back commit's parent is %s, want the base %s", parent, base)
	}
	if !res.Delivered() {
		t.Error("Delivered() is false for a write-back that produced a commit")
	}
}

// TestProduceRecordsAFixedIdentity covers a property that only shows up when
// the same task runs on two machines: an identity read from the machine's git
// config would make the same work produce different commits, and would credit
// a model's edits to whoever happens to own the executor.
func TestProduceRecordsAFixedIdentity(t *testing.T) {
	f := newLocal(t)
	f.dirty("a.txt", "x\n")
	// A hostile ambient identity. It is inherited by any git child that does
	// not set its own.
	t.Setenv("GIT_AUTHOR_NAME", "attacker")
	t.Setenv("GIT_AUTHOR_EMAIL", "attacker@example.invalid")
	t.Setenv("GIT_COMMITTER_NAME", "attacker")
	t.Setenv("GIT_COMMITTER_EMAIL", "attacker@example.invalid")

	res, err := f.produce()
	if err != nil {
		t.Fatalf("Produce: %v\nlog:\n%s", err, f.log())
	}
	got := strings.TrimSpace(f.git("-C", f.dir, "log", "-1", "--format=%an|%ae|%cn|%ce", res.CommitSHA))
	const want = "cloop|cloop@localhost|cloop|cloop@localhost"
	if got != want {
		t.Errorf("the write-back commit is attributed to %q, want %q; the machine's ambient "+
			"identity reached git", got, want)
	}
}

func TestProduceUsesTheRequestedMessageAndADefault(t *testing.T) {
	t.Run("the spec's message", func(t *testing.T) {
		f := newLocal(t)
		f.wb.Message = "cloop: task 42 — add the retry"
		f.dirty("a.txt", "x\n")
		res, err := f.produce()
		if err != nil {
			t.Fatalf("Produce: %v", err)
		}
		got := strings.TrimSpace(f.git("-C", f.dir, "log", "-1", "--format=%B", res.CommitSHA))
		if got != f.wb.Message {
			t.Errorf("commit message = %q, want %q", got, f.wb.Message)
		}
	})
	t.Run("a generated one", func(t *testing.T) {
		f := newLocal(t)
		f.dirty("a.txt", "x\n")
		res, err := f.produce()
		if err != nil {
			t.Fatalf("Produce: %v", err)
		}
		got := strings.TrimSpace(f.git("-C", f.dir, "log", "-1", "--format=%B", res.CommitSHA))
		if got == "" {
			t.Error("a write-back with no message produced a commit with no subject")
		}
	})
}

// TestProduceWorksFromADetachedHEAD covers the state gitprovision actually
// leaves a workspace in: it checks out a fetched commit, which is a detached
// HEAD, so this is the ordinary case rather than an edge one.
func TestProduceWorksFromADetachedHEAD(t *testing.T) {
	f := newLocal(t)
	f.dirty("first.txt", "1\n")
	f.git("-C", f.dir, "add", "--all", "--", ".")
	f.git("-C", f.dir, "commit", "--no-gpg-sign", "-m", "second")
	f.git("-C", f.dir, "checkout", "--force", "--detach", "HEAD")
	base := f.localSHA("HEAD")
	if head := strings.TrimSpace(f.git("-C", f.dir, "rev-parse", "--abbrev-ref", "HEAD")); head != "HEAD" {
		t.Fatalf("the fixture is not detached: HEAD resolves to %q", head)
	}
	f.dirty("from-harness.txt", "produced\n")

	res, err := f.produce()
	if err != nil {
		t.Fatalf("Produce from a detached HEAD: %v\nlog:\n%s", err, f.log())
	}
	if res.BaseSHA != base {
		t.Errorf("BaseSHA = %s, want the detached HEAD %s", res.BaseSHA, base)
	}
	if got := f.localSHA("refs/heads/" + branch); got != res.CommitSHA {
		t.Errorf("refs/heads/%s is at %s, want %s", branch, got, res.CommitSHA)
	}
}

// TestProduceReusesItsOwnBranch covers the retry case: `checkout -B` rather
// than `-b`, so a second attempt does not depend on cleanup that may never have
// run.
func TestProduceReusesItsOwnBranch(t *testing.T) {
	f := newLocal(t)
	f.dirty("a.txt", "first\n")
	first, err := f.produce()
	if err != nil {
		t.Fatalf("first Produce: %v", err)
	}

	f.emitted.Reset()
	f.dirty("b.txt", "second\n")
	second, err := f.produce()
	if err != nil {
		t.Fatalf("second Produce over an existing branch: %v\nlog:\n%s", err, f.log())
	}
	if second.CommitSHA == first.CommitSHA {
		t.Error("the retry produced the same commit as the first attempt")
	}
	if got := f.localSHA("refs/heads/" + branch); got != second.CommitSHA {
		t.Errorf("refs/heads/%s is at %s, want the retry's commit %s", branch, got, second.CommitSHA)
	}
}

// --- what a write-back declines to produce ----------------------------------------

// TestProduceSkipsRatherThanFails covers the outcomes an operator must be able
// to tell apart from a broken write-back. Each one leaves no branch behind: a
// ref nobody can explain later is its own kind of failure.
func TestProduceSkipsRatherThanFails(t *testing.T) {
	cases := map[string]struct {
		setup      func(*fixture) gitwriteback.Request
		wantReason string
	}{
		"the harness changed no files": {
			setup:      func(f *fixture) gitwriteback.Request { return f.request() },
			wantReason: "changed no files",
		},
		"no write-back was requested": {
			setup: func(f *fixture) gitwriteback.Request {
				f.dirty("a.txt", "x\n")
				f.wb = executor.WriteBack{}
				return f.request()
			},
			wantReason: "no write-back was requested",
		},
		"the harness failed and OnlyOnSuccess is set": {
			setup: func(f *fixture) gitwriteback.Request {
				f.dirty("a.txt", "x\n")
				r := f.request()
				r.ExitCode = 3
				return r
			},
			wantReason: "exited 3",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newLocal(t)
			res, err := f.produceWith(tc.setup(f))
			if err != nil {
				t.Fatalf("Produce returned an error for a skip case: %v", err)
			}
			if !res.Skipped {
				t.Fatalf("Produce did not skip; it reported %+v", res.WriteBackResult)
			}
			if !strings.Contains(res.SkipReason, tc.wantReason) {
				t.Errorf("SkipReason = %q, want it to mention %q", res.SkipReason, tc.wantReason)
			}
			if res.Mode != executor.WriteBackNone {
				t.Errorf("Mode = %q on a skip, want %q", res.Mode, executor.WriteBackNone)
			}
			if res.Delivered() {
				t.Error("Delivered() is true for a skipped write-back")
			}
			if got := f.localSHA("refs/heads/" + branch); got != "" {
				t.Errorf("a skipped write-back left refs/heads/%s at %s behind", branch, got)
			}
			if !strings.Contains(f.log(), res.SkipReason) {
				t.Errorf("the skip was not reported to the caller's log:\n%s", f.log())
			}
		})
	}
}

// TestProduceWritesBackAFailedHarnessWhenAsked is the other half of
// OnlyOnSuccess: the policy is the caller's, and the default Request does not
// impose it.
func TestProduceWritesBackAFailedHarnessWhenAsked(t *testing.T) {
	f := newLocal(t)
	f.dirty("half-finished.txt", "partial\n")
	r := f.request()
	r.ExitCode = 3
	r.OnlyOnSuccess = false

	res, err := f.produceWith(r)
	if err != nil {
		t.Fatalf("Produce: %v", err)
	}
	if res.Skipped {
		t.Fatalf("Produce skipped although OnlyOnSuccess was off: %s", res.SkipReason)
	}
	if res.FilesChanged != 1 {
		t.Errorf("FilesChanged = %d, want 1", res.FilesChanged)
	}
}

// TestProduceRefusesAConflictedTree covers the state a harness leaves behind
// when it started a merge it could not finish.
//
// The refusal is the correct behaviour and worth pinning: committing a tree
// with conflict markers in it would deliver something that compiles nowhere and
// that the merge queue would happily merge.
func TestProduceRefusesAConflictedTree(t *testing.T) {
	f := newLocal(t)
	f.git("-C", f.dir, "checkout", "-b", "side")
	f.dirty("a.txt", "side\n")
	f.git("-C", f.dir, "add", "--all", "--", ".")
	f.git("-C", f.dir, "commit", "--no-gpg-sign", "-m", "side")
	f.git("-C", f.dir, "checkout", gitforge.DefaultBranch)
	f.dirty("a.txt", "trunk\n")
	f.git("-C", f.dir, "add", "--all", "--", ".")
	f.git("-C", f.dir, "commit", "--no-gpg-sign", "-m", "trunk")
	if _, err := f.tryGit("-C", f.dir, "merge", "side"); err == nil {
		t.Fatal("the fixture merge did not conflict")
	}
	if _, err := os.Stat(filepath.Join(f.dir, ".git", "MERGE_HEAD")); err != nil {
		t.Fatalf("the fixture is not mid-merge: %v", err)
	}

	res, err := f.produce()
	if err == nil {
		t.Fatalf("Produce committed a conflicted tree: %+v", res.WriteBackResult)
	}
	if !errors.Is(err, executor.ErrWriteBackUnavailable) {
		t.Errorf("error does not wrap ErrWriteBackUnavailable: %v", err)
	}
	if res.Err == "" {
		t.Error("Result.Err is empty on a failure, so a caller reading the record sees nothing")
	}
	if got := f.localSHA("refs/heads/" + branch); got != "" {
		t.Errorf("the failed write-back left refs/heads/%s at %s behind", branch, got)
	}
	// Nothing was committed, so the operator can still resolve the merge.
	if _, err := os.Stat(filepath.Join(f.dir, ".git", "MERGE_HEAD")); err != nil {
		t.Errorf("the conflicted merge state was destroyed: %v", err)
	}
}

// TestProduceRefusesAnUnusableRequest covers the validation that runs before
// anything is touched.
func TestProduceRefusesAnUnusableRequest(t *testing.T) {
	cases := map[string]struct {
		mutate func(*fixture, *gitwriteback.Request)
		want   string
	}{
		"a branch outside the cloop namespace": {
			mutate: func(_ *fixture, r *gitwriteback.Request) {
				r.WriteBack.Branch = gitforge.DefaultBranch
			},
			want: "cloop/",
		},
		"a branch that is a full ref": {
			mutate: func(_ *fixture, r *gitwriteback.Request) {
				r.WriteBack.Branch = "refs/heads/cloop/x"
			},
			want: "branch",
		},
		"an empty branch": {
			mutate: func(_ *fixture, r *gitwriteback.Request) { r.WriteBack.Branch = "" },
			want:   "branch",
		},
		"a bundle cap on a push": {
			mutate: func(_ *fixture, r *gitwriteback.Request) {
				r.WriteBack.Mode = executor.WriteBackPush
				r.WriteBack.MaxBundleBytes = 1 << 20
			},
			want: "max_bundle_bytes",
		},
		"a relative directory": {
			mutate: func(_ *fixture, r *gitwriteback.Request) { r.Dir = "relative/path" },
			want:   "absolute path",
		},
		"a directory that is not a repository": {
			mutate: func(f *fixture, r *gitwriteback.Request) { r.Dir = f.home },
			want:   "not a git repository",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newLocal(t)
			f.dirty("a.txt", "x\n")
			r := f.request()
			tc.mutate(f, &r)

			res, err := f.produceWith(r)
			if err == nil {
				t.Fatalf("Produce accepted an unusable request: %+v", res.WriteBackResult)
			}
			if !errors.Is(err, executor.ErrWriteBackUnavailable) {
				t.Errorf("error does not wrap ErrWriteBackUnavailable: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not mention %q: %v", tc.want, err)
			}
			if got := f.localSHA("refs/heads/" + branch); got != "" {
				t.Errorf("a refused request still created refs/heads/%s", branch)
			}
		})
	}
}

// --- the bundle path ---------------------------------------------------------------

// TestProduceBundlesOnlyTheNewCommits is the claim in the delivery switch: the
// bundle is the *range*, not the branch, because bundling the branch would pack
// the whole reachable history and would let rewritten history past an
// inspection that only looks at new commits.
func TestProduceBundlesOnlyTheNewCommits(t *testing.T) {
	f := newLocal(t)
	// Some history to leave out.
	f.dirty("history.txt", "old\n")
	f.git("-C", f.dir, "add", "--all", "--", ".")
	f.git("-C", f.dir, "commit", "--no-gpg-sign", "-m", "history")

	// A peer that already has everything up to the base — the hub's position.
	peer := filepath.Join(t.TempDir(), "peer")
	f.git("clone", "--branch", gitforge.DefaultBranch, f.dir, peer)

	f.dirty("new.txt", "produced\n")
	res, err := f.produce()
	if err != nil {
		t.Fatalf("Produce: %v\nlog:\n%s", err, f.log())
	}
	if res.BundlePath == "" {
		t.Fatal("bundle mode produced no BundlePath")
	}
	info, err := os.Stat(res.BundlePath)
	if err != nil {
		t.Fatalf("the reported bundle does not exist: %v", err)
	}
	if info.Size() != res.BundleBytes {
		t.Errorf("BundleBytes = %d, but the file is %d bytes", res.BundleBytes, info.Size())
	}
	if got := gitwriteback.SHA256(readFile(t, res.BundlePath)); got != res.BundleSHA256 {
		t.Errorf("BundleSHA256 = %q, but the file digests to %q", res.BundleSHA256, got)
	}

	// A repository that has nothing must not be able to apply it. That is what
	// makes this a range rather than a clone.
	empty := filepath.Join(t.TempDir(), "empty")
	f.git("init", "-b", gitforge.DefaultBranch, empty)
	if out, err := gitforge.TryGit(t, f.tools, f.home, empty,
		"-C", empty, "bundle", "verify", res.BundlePath); err == nil {
		t.Errorf("the bundle verified against a repository with no history, so it carries more "+
			"than the new commits:\n%s", out)
	}

	// The peer, which has the base, applies it and gets exactly one new commit.
	gitforge.Git(t, f.tools, f.home, peer, "-C", peer, "bundle", "verify", res.BundlePath)
	gitforge.Git(t, f.tools, f.home, peer, "-C", peer, "fetch", res.BundlePath,
		"refs/heads/"+branch+":refs/heads/applied")
	applied := strings.TrimSpace(gitforge.Git(t, f.tools, f.home, peer,
		"-C", peer, "rev-parse", "refs/heads/applied"))
	if applied != res.CommitSHA {
		t.Errorf("the applied bundle landed at %s, but the result reported %s", applied, res.CommitSHA)
	}
	newCommits := strings.Fields(gitforge.Git(t, f.tools, f.home, peer,
		"-C", peer, "rev-list", res.BaseSHA+"..refs/heads/applied"))
	if len(newCommits) != 1 {
		t.Errorf("the bundle carried %d commits past the base, want 1", len(newCommits))
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return b
}

func TestProduceWritesTheBundleWhereAsked(t *testing.T) {
	f := newLocal(t)
	f.dirty("a.txt", "x\n")
	want := filepath.Join(t.TempDir(), "explicit.bundle")
	r := f.request()
	r.BundlePath = want

	res, err := f.produceWith(r)
	if err != nil {
		t.Fatalf("Produce: %v", err)
	}
	if res.BundlePath != want {
		t.Errorf("BundlePath = %q, want %q", res.BundlePath, want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Errorf("the bundle was not written where asked: %v", err)
	}
}

// TestProduceRemovesAnOversizedBundle covers the cleanup path a failure is most
// likely to skip: a bundle that was written, measured, and refused.
//
// Leaving it would be a disk leak on the machine least able to absorb one — a
// sandbox is the party whose disk nobody is watching — and Result.BundlePath
// would name a file the caller was told not to expect.
func TestProduceRemovesAnOversizedBundle(t *testing.T) {
	f := newLocal(t)
	// One byte: smaller than a bundle git can physically write, and chosen
	// rather than a plausible-looking figure because git compresses the pack —
	// a "small" cap in the hundreds of bytes is one a real bundle can slip
	// under, which is how the first version of this test passed while doing
	// nothing.
	f.wb.MaxBundleBytes = 1
	f.dirty("a.txt", strings.Repeat("content that will not fit\n", 200))

	res, err := f.produce()
	if err == nil {
		t.Fatalf("Produce accepted a bundle over the workload's cap: %+v", res.WriteBackResult)
	}
	if !errors.Is(err, executor.ErrWriteBackUnavailable) {
		t.Errorf("error does not wrap ErrWriteBackUnavailable: %v", err)
	}
	if res.BundlePath != "" {
		t.Errorf("Result.BundlePath = %q after a refusal; it must name only a file that exists",
			res.BundlePath)
		if _, err := os.Stat(res.BundlePath); err == nil {
			t.Errorf("the refused bundle is still on disk at %s", res.BundlePath)
		}
	}
	if !strings.Contains(err.Error(), "over this workload's limit") {
		t.Errorf("the refusal does not name the limit: %v", err)
	}
}

// TestProduceHonoursAnExplicitBaseSHA covers the case the field exists for: a
// harness that committed on its own moved HEAD, so a base read from the
// repository afterwards would shrink the range and silently drop the harness's
// own earlier commits.
func TestProduceHonoursAnExplicitBaseSHA(t *testing.T) {
	f := newLocal(t)
	provisionedAt := f.localSHA("HEAD")

	// A peer at the commit the workspace was provisioned at — what the hub
	// holds.
	peer := filepath.Join(t.TempDir(), "peer")
	f.git("clone", "--branch", gitforge.DefaultBranch, f.dir, peer)

	// The harness commits once itself, then leaves the tree dirty.
	f.dirty("step-one.txt", "1\n")
	f.git("-C", f.dir, "add", "--all", "--", ".")
	f.git("-C", f.dir, "commit", "--no-gpg-sign", "-m", "the harness's own commit")
	f.dirty("step-two.txt", "2\n")

	t.Run("without it the harness's own commit is dropped", func(t *testing.T) {
		res, err := f.produce()
		if err != nil {
			t.Fatalf("Produce: %v", err)
		}
		if res.BaseSHA == provisionedAt {
			t.Fatal("the fixture did not move HEAD, so this test proves nothing")
		}
		carried := strings.Fields(f.git("-C", f.dir, "rev-list", provisionedAt+"..refs/heads/"+branch))
		if len(carried) != 2 {
			t.Fatalf("the fixture produced %d commits past the provisioned base, want 2", len(carried))
		}
		// The range the bundle covered is one commit; the work past the
		// provisioned base is two. That gap is the reason for the field.
		if got := len(strings.Fields(f.git("-C", f.dir, "rev-list", res.BaseSHA+"..refs/heads/"+branch))); got != 1 {
			t.Fatalf("the implicit range covered %d commits, want 1", got)
		}
	})

	t.Run("with it the whole range is delivered", func(t *testing.T) {
		f.emitted.Reset()
		f.dirty("step-three.txt", "3\n")
		r := f.request()
		r.BaseSHA = provisionedAt

		res, err := f.produceWith(r)
		if err != nil {
			t.Fatalf("Produce: %v\nlog:\n%s", err, f.log())
		}
		if res.BaseSHA != provisionedAt {
			t.Fatalf("BaseSHA = %s, want the caller's %s", res.BaseSHA, provisionedAt)
		}
		gitforge.Git(t, f.tools, f.home, peer, "-C", peer, "fetch", res.BundlePath,
			"refs/heads/"+branch+":refs/heads/applied")
		carried := strings.Fields(gitforge.Git(t, f.tools, f.home, peer,
			"-C", peer, "rev-list", provisionedAt+"..refs/heads/applied"))
		if len(carried) < 2 {
			t.Errorf("the bundle carried %d commits past the provisioned base; the harness's "+
				"own commits were dropped", len(carried))
		}
	})
}

func TestProduceRejectsAnUnusableBaseSHA(t *testing.T) {
	f := newLocal(t)
	f.dirty("a.txt", "x\n")
	r := f.request()
	r.BaseSHA = "not-a-sha"

	res, err := f.produceWith(r)
	if err == nil {
		t.Fatalf("Produce accepted a malformed base: %+v", res.WriteBackResult)
	}
	if !errors.Is(err, executor.ErrWriteBackUnavailable) {
		t.Errorf("error does not wrap ErrWriteBackUnavailable: %v", err)
	}
}

// --- the push path -------------------------------------------------------------------

// TestProducePushesTheBranchAndNothingElse is the positive case, and the second
// half of its name is the security property: WriteBack has no Remote field and
// the refspec is fully qualified on both sides, so a push moves one ref on one
// host.
func TestProducePushesTheBranchAndNothingElse(t *testing.T) {
	f := newPushable(t, gitforge.Options{})
	trunkBefore := f.forge.SHA(t, owner, repo, gitforge.DefaultBranch)
	f.dirty("produced.txt", "by the sandbox\n")

	res, err := f.produce()
	if err != nil {
		t.Fatalf("Produce: %v\nlog:\n%s", err, f.log())
	}
	if !res.Pushed {
		t.Fatalf("Pushed is false: %+v", res.WriteBackResult)
	}
	if got := f.forge.SHA(t, owner, repo, branch); got != res.CommitSHA {
		t.Errorf("the forge has refs/heads/%s at %q, but the result reported %s",
			branch, got, res.CommitSHA)
	}
	if got := f.forge.SHA(t, owner, repo, gitforge.DefaultBranch); got != trunkBefore {
		t.Errorf("the push moved the project's trunk from %s to %s", trunkBefore, got)
	}
	// The forge demands the credential, so a served push is an authenticated
	// one; assert no request slipped through unauthenticated.
	for _, r := range f.forge.Requests() {
		if !r.Authorized {
			t.Errorf("the forge refused %s %s during a push it accepted", r.Method, r.Path)
		}
	}
	f.assertNoLeak(res, nil)
}

// TestProducePushRefusalsHappenBeforeTheNetwork is the distinction that matters
// most on this boundary: a refusal made here is a policy that holds, while one
// made by the remote is a policy that depends on the remote agreeing.
func TestProducePushRefusalsHappenBeforeTheNetwork(t *testing.T) {
	cases := map[string]struct {
		mutate func(*fixture, *gitwriteback.Request)
		want   string
	}{
		"no credential was leased": {
			mutate: func(_ *fixture, r *gitwriteback.Request) {
				r.Credential = executor.GitCredential{}
			},
			want: "none was leased",
		},
		"the credential has expired": {
			mutate: func(_ *fixture, r *gitwriteback.Request) {
				r.Credential.ExpiresAt = time.Now().Add(-time.Minute)
			},
			want: "expired",
		},
		"the branch is outside the namespace the hub may force-update": {
			mutate: func(_ *fixture, r *gitwriteback.Request) {
				r.WriteBack.Branch = gitforge.DefaultBranch
			},
			want: "cloop/",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newPushable(t, gitforge.Options{})
			trunkBefore := f.forge.SHA(t, owner, repo, gitforge.DefaultBranch)
			f.dirty("produced.txt", "by the sandbox\n")
			r := f.request()
			tc.mutate(f, &r)

			res, err := f.produceWith(r)
			if err == nil {
				t.Fatalf("Produce pushed despite %s: %+v", name, res.WriteBackResult)
			}
			if !errors.Is(err, executor.ErrWriteBackUnavailable) {
				t.Errorf("error does not wrap ErrWriteBackUnavailable: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not mention %q: %v", tc.want, err)
			}
			if res.Pushed {
				t.Error("Pushed is true on a refusal")
			}
			if n := f.forge.Count(); n != 0 {
				t.Errorf("the forge received %d request(s); the push was attempted rather than "+
					"refused: %s", n, f.forge.Log())
			}
			if got := f.forge.SHA(t, owner, repo, gitforge.DefaultBranch); got != trunkBefore {
				t.Errorf("the project's trunk moved from %s to %s during a refusal", trunkBefore, got)
			}
			if got := f.forge.SHA(t, owner, repo, branch); got != "" {
				t.Errorf("a refused push created refs/heads/%s at %s on the forge", branch, got)
			}
			f.assertNoLeak(res, err)
		})
	}
}

// TestProducePushCredentialNeverEscapes drives the one path that holds a
// credential and fails.
//
// A rejected push is where git is most talkative — it quotes the URL, the
// refspec and sometimes the header it sent — so it is the case a redaction bug
// surfaces in first.
func TestProducePushCredentialNeverEscapes(t *testing.T) {
	f := newPushable(t, gitforge.Options{User: credUser, Password: "an-entirely-different-secret"})
	f.dirty("produced.txt", "by the sandbox\n")

	res, err := f.produce()
	if err == nil {
		t.Fatalf("the push succeeded with the wrong credential: %+v", res.WriteBackResult)
	}
	if !errors.Is(err, executor.ErrWriteBackUnavailable) {
		t.Errorf("error does not wrap ErrWriteBackUnavailable: %v", err)
	}
	// The forge must have seen the attempt — otherwise this test would pass
	// without the credential ever having been in play.
	if n := f.forge.Count(); n == 0 {
		t.Fatal("the forge received nothing, so no credential was ever sent and the leak " +
			"assertions below prove nothing")
	}
	f.assertNoLeak(res, err)

	// The local commit still exists: the failure is in delivery, not in the
	// work, and destroying it would lose the task's output.
	if got := f.localSHA("refs/heads/" + branch); got == "" {
		t.Error("the failed push discarded the commit it was trying to deliver")
	}
}

// TestProducePushDoesNotInheritTheHostEnvironment mirrors the gitprovision
// test: the same closed environment has to hold on the way out, or a machine
// could decide where the sandbox's work lands.
func TestProducePushDoesNotInheritTheHostEnvironment(t *testing.T) {
	t.Run("GIT_SSL_NO_VERIFY is not forwarded", func(t *testing.T) {
		f := newPushable(t, gitforge.Options{})
		f.dirty("produced.txt", "x\n")
		t.Setenv("GIT_SSL_CAINFO", "")
		t.Setenv("GIT_SSL_NO_VERIFY", "true")

		res, err := f.produce()
		if err == nil {
			t.Fatalf("the push succeeded against an untrusted certificate: %+v", res.WriteBackResult)
		}
		if res.Pushed {
			t.Error("Pushed is true after a TLS failure")
		}
	})

	t.Run("a host GIT_ASKPASS is never consulted", func(t *testing.T) {
		f := newPushable(t, gitforge.Options{})
		f.dirty("produced.txt", "x\n")
		marker := filepath.Join(t.TempDir(), "askpass-ran")
		script := filepath.Join(t.TempDir(), "askpass.sh")
		if err := os.WriteFile(script,
			[]byte("#!/bin/sh\ntouch "+marker+"\necho "+credToken+"\n"), 0o700); err != nil {
			t.Fatalf("writing the askpass script: %v", err)
		}
		t.Setenv("GIT_ASKPASS", script)
		t.Setenv("SSH_ASKPASS", script)
		t.Setenv("GIT_TERMINAL_PROMPT", "1")

		r := f.request()
		// No credential, so the only way to authenticate is to ask the host.
		r.Credential = executor.GitCredential{}
		if _, err := f.produceWith(r); err == nil {
			t.Fatal("the push succeeded with no credential")
		}
		if _, err := os.Stat(marker); err == nil {
			t.Error("the host's GIT_ASKPASS helper ran during a write-back")
		}
	})
}

// TestProduceIsBoundedByItsTimeout covers the ceiling the package documents: a
// hang here loses work that already exists, which makes a bound more important
// than a generous one.
//
// It is also a regression test. Before gitprovision.BoundChild existed the
// bound was decorative: `git push` runs the transfer in git-remote-https, which
// inherits the captured pipes, so killing git at the deadline left the helper
// holding the write end and CombinedOutput waiting for an EOF that a
// non-answering remote never sends. Produce would sit past its own Timeout with
// the commit already made and undelivered. See the twin regression test in
// pkg/executor/gitprovision.
func TestProduceIsBoundedByItsTimeout(t *testing.T) {
	blocked := make(chan struct{})
	t.Cleanup(func() { close(blocked) })

	f := newPushable(t, gitforge.Options{
		User: credUser, Password: credToken,
		Intercept: func(_ http.ResponseWriter, r *http.Request) bool {
			select {
			case <-blocked:
			case <-r.Context().Done():
			}
			return true
		},
	})
	f.dirty("produced.txt", "x\n")

	r := f.request()
	r.Timeout = 750 * time.Millisecond

	start := time.Now()
	res, err := f.produceWith(r)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("Produce succeeded against a forge that never answers: %+v", res.WriteBackResult)
	}
	if elapsed > 30*time.Second {
		t.Errorf("Produce took %s to honour a 750ms timeout", elapsed)
	}
	if !strings.Contains(err.Error(), "cancelled") {
		t.Errorf("a timed-out push is not reported as cancelled, so an operator would read it "+
			"as a repository failure: %v", err)
	}
	f.assertNoLeak(res, err)
}

// --- the whole circuit ------------------------------------------------------------------

// TestRoundTripProvisionEditAndPush drives both halves against one forge.
//
// Each package's own tests fake the other side — gitprovision's tree is built
// by fixture git, gitwriteback's clone is made over the filesystem — so neither
// suite can catch a disagreement between them about what a provisioned
// workspace is. This one can: it provisions exactly as an edge device would,
// edits the tree as a harness would, and pushes with the same lease, then asks
// the forge what arrived.
func TestRoundTripProvisionEditAndPush(t *testing.T) {
	forge := gitforge.Start(t, gitforge.Options{User: credUser, Password: credToken})
	forge.Create(t, owner, repo)
	forge.Trust(t)

	dir := filepath.Join(t.TempDir(), "sandbox-workspace")
	ws := executor.Workspace{
		Kind:  executor.WorkspaceGit,
		Repo:  forge.RepoURL(owner, repo),
		Ref:   gitforge.DefaultBranch,
		Depth: 1,
	}
	cred := executor.GitCredential{Username: credUser, Password: credToken}
	set := redact.New(cred.Secrets()...)

	var emitted strings.Builder
	emit := func(s string) { emitted.WriteString(s) }

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := gitprovision.Provision(ctx, gitprovision.Request{
		Dir: dir, Workspace: ws, Credential: cred, Host: "this edge device", Emit: emit,
	}); err != nil {
		t.Fatalf("Provision: %v\nlog:\n%s", err, emitted.String())
	}
	tools := gitforge.RequireGit(t)
	home := t.TempDir()
	base := strings.TrimSpace(gitforge.Git(t, tools, home, dir, "-C", dir, "rev-parse", "HEAD"))

	// What a harness does.
	gitforge.WriteFile(t, dir, "src/feature.go", "package src\n\n// authored inside the sandbox\n")

	res, err := gitwriteback.Produce(ctx, gitwriteback.Request{
		Dir: dir, Workspace: ws, Credential: cred, BaseSHA: base,
		WriteBack:     executor.WriteBack{Mode: executor.WriteBackPush, Branch: branch},
		OnlyOnSuccess: true, Host: "this edge device", Emit: emit,
	})
	if err != nil {
		t.Fatalf("Produce: %v\nlog:\n%s", err, emitted.String())
	}
	if !res.Delivered() || !res.Pushed {
		t.Fatalf("the circuit did not deliver: %+v", res.WriteBackResult)
	}
	if res.BaseSHA != base {
		t.Errorf("BaseSHA = %s, want the commit the workspace was provisioned at (%s)",
			res.BaseSHA, base)
	}
	if got := forge.SHA(t, owner, repo, branch); got != res.CommitSHA {
		t.Fatalf("the forge has refs/heads/%s at %q, want %s", branch, got, res.CommitSHA)
	}
	// The file the sandbox wrote really is in the commit the hub would fetch.
	files := gitforge.Git(t, tools, home, forge.Path(owner, repo),
		"--git-dir="+forge.Path(owner, repo), "show", "--name-only", "--format=", res.CommitSHA)
	if !strings.Contains(files, "src/feature.go") {
		t.Errorf("the pushed commit does not contain the sandbox's file:\n%s", files)
	}

	gitforge.NoSecretIn(t, set, "the emitted log of the whole circuit", emitted.String())
	if gitforge.NoSecretUnder(t, set, dir) == 0 {
		t.Fatal("the on-disk leak scan read no files")
	}
}

// --- helpers ---------------------------------------------------------------------------

func TestSHA256MatchesTheFileDigest(t *testing.T) {
	// Not a restatement of crypto/sha256: the point is that the byte-slice
	// helper the hub uses to check what it received agrees with the file
	// digest the sandbox reports, since a mismatch would reject every bundle.
	f := newLocal(t)
	f.dirty("a.txt", "x\n")
	res, err := f.produce()
	if err != nil {
		t.Fatalf("Produce: %v", err)
	}
	if got := gitwriteback.SHA256(readFile(t, res.BundlePath)); got != res.BundleSHA256 {
		t.Errorf("SHA256 of the bundle = %q, want the reported %q", got, res.BundleSHA256)
	}
	if len(res.BundleSHA256) != 64 {
		t.Errorf("BundleSHA256 is %d characters, want 64 hex", len(res.BundleSHA256))
	}
}

func TestProduceFallsBackToAHostLabel(t *testing.T) {
	f := newLocal(t)
	f.dirty("a.txt", "x\n")
	r := f.request()
	r.Host = "  "
	r.Emit = nil // also covers the nil-Emit path
	r.Dir = filepath.Join(f.home, "not-a-repository")

	_, err := f.produceWith(r)
	if err == nil {
		t.Fatal("Produce accepted a directory that is not a repository")
	}
	if !strings.Contains(err.Error(), "this machine") {
		t.Errorf("an unnamed host did not fall back to a label: %v", err)
	}
}
