package featurehub_test

// The hub's half of a feature run on an isolating executor (Task 20367), tested
// against real git: a parent repository with a feature worktree, a sandbox tree
// built from what Ship produced, a write-back produced from it by the same
// engine a device or container runs, and Land applying it.
//
// Every scene plants hooks in the parent repository that leave a marker when
// they run, and snapshots the parent's .git/config, so each test also proves the
// hub-side git touched neither.

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/hometest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/featurehub"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
	"github.com/blechschmidt/cloop/pkg/executor/gitwriteback"
	"github.com/blechschmidt/cloop/pkg/feature"
)

func TestMain(m *testing.M) { os.Exit(hometest.Isolate(m)) }

const slug = "widget"

var branch = feature.BranchName(slug)

// gitEnv is a closed environment with a fixed identity, so the test's own git
// does not read the machine's configuration either.
func gitEnv() []string {
	return append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
	)
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
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

// scene is a parent repository with one feature.
type scene struct {
	root    string
	parent  string
	feature string
	marker  string
	config  []byte
	main    string
}

func newScene(t *testing.T) *scene {
	t.Helper()
	root := t.TempDir()
	s := &scene{root: root, parent: filepath.Join(root, "proj"), marker: filepath.Join(root, "hook-ran")}
	git(t, root, "init", "-q", "-b", "main", s.parent)
	write(t, filepath.Join(s.parent, "README.md"), "hello\n")
	git(t, s.parent, "add", "-A")
	git(t, s.parent, "commit", "-qm", "first")
	write(t, filepath.Join(s.parent, "src", "a.txt"), "a\n")
	git(t, s.parent, "add", "-A")
	git(t, s.parent, "commit", "-qm", "second")
	s.main = git(t, s.parent, "rev-parse", "HEAD")
	// "On the upstream as of the last fetch", without a network.
	git(t, s.parent, "update-ref", "refs/remotes/origin/main", s.main)
	// What featureops.Create sets up: .cloop/ excluded, the worktree on its
	// branch, the record.
	write(t, filepath.Join(s.parent, ".git", "info", "exclude"), "/.cloop/\n")
	s.feature = feature.Path(s.parent, slug)
	git(t, s.parent, "worktree", "add", "-q", "-b", branch, s.feature, s.main)
	if err := os.MkdirAll(filepath.Join(s.feature, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := feature.SaveMeta(s.feature, &feature.Meta{
		Slug: slug, Title: "Widget", Branch: branch, Base: "main", BaseCommit: s.main,
		Parent: s.parent, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	// Hooks that would announce themselves, planted after setup so only the
	// code under test could fire them.
	for _, h := range []string{"post-checkout", "post-merge", "reference-transaction", "pre-commit",
		"post-commit", "pre-push", "post-rewrite"} {
		path := filepath.Join(s.parent, ".git", "hooks", h)
		write(t, path, "#!/bin/sh\necho "+h+" >> "+s.marker+"\n")
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// And a configured program, which hardened git must never run.
	git(t, s.parent, "config", "core.fsmonitor", filepath.Join(root, "fsmonitor.sh"))
	write(t, filepath.Join(root, "fsmonitor.sh"), "#!/bin/sh\necho fsmonitor >> "+s.marker+"\n")
	_ = os.Chmod(filepath.Join(root, "fsmonitor.sh"), 0o755)
	s.config = readFile(t, filepath.Join(s.parent, ".git", "config"))
	return s
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// commitOnFeature commits on the hub-side feature worktree, as a host run or a
// person would.
func (s *scene) commitOnFeature(t *testing.T, name, body string) string {
	t.Helper()
	write(t, filepath.Join(s.feature, name), body)
	git(t, s.feature, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "add", "-A")
	git(t, s.feature, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "commit", "-qm", "hub: "+name)
	return git(t, s.feature, "rev-parse", "HEAD")
}

// assertParentUntouched checks the parent's branch, configuration and hooks.
func (s *scene) assertParentUntouched(t *testing.T) {
	t.Helper()
	if got := git(t, s.parent, "rev-parse", "refs/heads/main"); got != s.main {
		t.Errorf("the parent's main moved from %s to %s", s.main, got)
	}
	if got := readFile(t, filepath.Join(s.parent, ".git", "config")); !bytes.Equal(got, s.config) {
		t.Errorf("the parent's .git/config changed:\n%s", got)
	}
	if b, err := os.ReadFile(s.marker); err == nil {
		t.Errorf("a hook or program configured in the parent repository ran on the hub: %s", b)
	}
}

// sandbox builds the tree a sandbox gets from a shipment, the way a device or
// the container driver does.
func sandbox(t *testing.T, sh *featurehub.Shipment) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "tree")
	if err := gitprovision.Provision(context.Background(), gitprovision.Request{
		Dir:              dir,
		Workspace:        sh.Workspace(0, ""),
		BranchBundleFile: sh.File,
	}); err != nil {
		t.Fatalf("provision the sandbox tree: %v", err)
	}
	return dir
}

// harnessCommit commits in a sandbox tree, as a harness told to commit to its
// feature's branch does.
func harnessCommit(t *testing.T, dir, name, body string) string {
	t.Helper()
	write(t, filepath.Join(dir, name), body)
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-qm", "harness: "+name)
	return git(t, dir, "rev-parse", "HEAD")
}

// writeBack produces the bundle the sandbox returns.
func writeBack(t *testing.T, dir string, sh *featurehub.Shipment) (executor.WriteBackResult, []byte) {
	t.Helper()
	res, err := gitwriteback.Produce(context.Background(), gitwriteback.Request{
		Dir:           dir,
		WriteBack:     executor.WriteBack{Mode: executor.WriteBackBundle, Branch: sh.Branch},
		BaseSHA:       sh.Head,
		ExitCode:      0,
		OnlyOnSuccess: true,
	})
	if err != nil {
		t.Fatalf("produce the write-back: %v", err)
	}
	if res.BundlePath == "" {
		return res.WriteBackResult, nil
	}
	defer os.Remove(res.BundlePath)
	return res.WriteBackResult, readFile(t, res.BundlePath)
}

func ship(t *testing.T, s *scene, req featurehub.ShipRequest) *featurehub.Shipment {
	t.Helper()
	req.FeatureDir = s.feature
	sh, err := featurehub.Ship(context.Background(), req)
	if err != nil {
		t.Fatalf("Ship: %v", err)
	}
	t.Cleanup(sh.Remove)
	return sh
}

func land(t *testing.T, s *scene, sh *featurehub.Shipment, rep executor.WriteBackResult, bundle []byte) (featurehub.LandResult, error) {
	t.Helper()
	return featurehub.Land(context.Background(), featurehub.LandRequest{
		FeatureDir: s.feature, Reported: rep, Bundle: bundle, ShippedHead: sh.Head, Label: "run-1",
	})
}

// --- shipping ---------------------------------------------------------------

func TestShipOverlayCarriesOnlyTheFeaturesCommits(t *testing.T) {
	s := newScene(t)
	s.commitOnFeature(t, "f1.txt", "one\n")
	head := s.commitOnFeature(t, "f2.txt", "two\n")

	sh := ship(t, s, featurehub.ShipRequest{Upstream: "https://github.com/acme/proj"})
	if sh.Mode != featurehub.ShipOverlay || sh.Base != s.main || sh.Head != head {
		t.Fatalf("shipment = %+v, want an overlay of %s on %s", sh, head, s.main)
	}
	// Exactly the feature's commits, building on the base and nothing else.
	out := git(t, s.parent, "bundle", "list-heads", sh.File)
	if !strings.Contains(out, head+" refs/heads/"+branch) {
		t.Errorf("the bundle's heads are %q", out)
	}
	header := string(readFile(t, sh.File))
	if !strings.Contains(header, "-"+s.main) {
		t.Errorf("the overlay bundle does not name the base %s as its prerequisite", s.main)
	}
	ws := sh.Workspace(0, "grant-a")
	if ws.Kind != executor.WorkspaceGit || ws.Ref != s.main || ws.Repo != "https://github.com/acme/proj" ||
		ws.CredentialGrant != "grant-a" || ws.Branch == nil {
		t.Errorf("overlay workspace = %+v", ws)
	}
	if err := ws.Validate(); err != nil {
		t.Errorf("the overlay workspace does not validate: %v", err)
	}
	s.assertParentUntouched(t)
}

func TestShipOverlayWithNoCommitsShipsNothing(t *testing.T) {
	s := newScene(t)
	sh := ship(t, s, featurehub.ShipRequest{Upstream: "https://github.com/acme/proj"})
	if sh.Mode != featurehub.ShipOverlay || sh.Bytes != 0 || sh.File != "" || sh.Head != s.main {
		t.Fatalf("shipment = %+v, want an empty overlay at the base", sh)
	}
	if err := sh.Workspace(0, "").Validate(); err != nil {
		t.Errorf("an empty overlay's workspace does not validate: %v", err)
	}
}

func TestShipFallsBackToTheWholeBranchWhenTheBaseIsNotUpstream(t *testing.T) {
	s := newScene(t)
	// A base nobody pushed: no remote-tracking ref holds it.
	git(t, s.parent, "update-ref", "-d", "refs/remotes/origin/main")
	s.commitOnFeature(t, "f.txt", "x\n")
	sh := ship(t, s, featurehub.ShipRequest{Upstream: "https://github.com/acme/proj"})
	if sh.Mode != featurehub.ShipFull {
		t.Fatalf("mode = %s, want full: an overlay on a base the upstream does not have cannot be fetched", sh.Mode)
	}
}

func TestShipFullBuildsAStandaloneCheckoutOnTheBranch(t *testing.T) {
	s := newScene(t)
	head := s.commitOnFeature(t, "f.txt", "feature\n")
	sh := ship(t, s, featurehub.ShipRequest{})
	if sh.Mode != featurehub.ShipFull || sh.Head != head {
		t.Fatalf("shipment = %+v", sh)
	}
	tree := sandbox(t, sh)
	if got := git(t, tree, "symbolic-ref", "HEAD"); got != "refs/heads/"+branch {
		t.Errorf("the sandbox tree is on %q, want the feature's branch attached", got)
	}
	if got := git(t, tree, "rev-parse", "HEAD"); got != head {
		t.Errorf("the sandbox tree is at %s, want %s", got, head)
	}
	// A standalone repository: its .git is a directory, not a pointer into the
	// hub's repository.
	if info, err := os.Lstat(filepath.Join(tree, ".git")); err != nil || !info.IsDir() {
		t.Errorf("the sandbox tree's .git is not a directory of its own: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(tree, "f.txt")); string(b) != "feature\n" {
		t.Errorf("the feature's file is %q in the sandbox tree", b)
	}
	// The project's control directory stays out of the tree's commits.
	if out := git(t, tree, "check-ignore", "-q", "--no-index", ".cloop/state.db"); out != "" {
		t.Errorf("check-ignore printed %q", out)
	}
	s.assertParentUntouched(t)
}

func TestShipGoesShallowWhenTheBranchIsTooLarge(t *testing.T) {
	s := newScene(t)
	// History far larger than the tip: several versions of an incompressible
	// file, each superseding the last.
	var head string
	for i := 0; i < 4; i++ {
		head = s.commitOnFeature(t, "blob.bin", randomString(t, 96<<10))
	}
	sh := ship(t, s, featurehub.ShipRequest{MaxBytes: 200 << 10})
	if sh.Mode != featurehub.ShipShallow || sh.Head != head || len(sh.Shallow) == 0 {
		t.Fatalf("shipment = %+v, want a shallow slice", sh)
	}
	if sh.Bytes > 200<<10 {
		t.Errorf("shallow bundle is %d bytes, over the cap", sh.Bytes)
	}
	tree := sandbox(t, sh)
	if got := git(t, tree, "rev-parse", "HEAD"); got != head {
		t.Errorf("the shallow tree is at %s, want %s", got, head)
	}
	// And the round trip works from a shallow tree: the write-back is
	// measured against the shipped head, which the hub has.
	tip := harnessCommit(t, tree, "more.txt", "more\n")
	rep, bundle := writeBack(t, tree, sh)
	res, err := land(t, s, sh, rep, bundle)
	if err != nil || res.Outcome != featurehub.LandFastForwarded || res.CommitSHA != tip {
		t.Fatalf("land from a shallow tree: %+v, %v", res, err)
	}
	s.assertParentUntouched(t)
}

func TestShipRefusesABranchTooLargeEvenAsOneCommit(t *testing.T) {
	s := newScene(t)
	s.commitOnFeature(t, "huge.bin", randomString(t, 300<<10))
	_, err := featurehub.Ship(context.Background(), featurehub.ShipRequest{FeatureDir: s.feature, MaxBytes: 100 << 10})
	var tooLarge *featurehub.TooLargeError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("Ship = %v, want a TooLargeError", err)
	}
	for _, want := range []string{branch, "even as a single commit", "executors.feature_bundle_mb"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
	if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
		t.Errorf("the refusal does not match ErrWorkspaceUnavailable: %v", err)
	}
}

// --- landing ----------------------------------------------------------------

func TestLandFastForwardsACleanWorktree(t *testing.T) {
	s := newScene(t)
	sh := ship(t, s, featurehub.ShipRequest{})
	tree := sandbox(t, sh)
	harnessCommit(t, tree, "one.txt", "1\n")
	tip := harnessCommit(t, tree, "two.txt", "2\n")
	// And something the harness left uncommitted, which the write-back
	// commits on top.
	write(t, filepath.Join(tree, "three.txt"), "3\n")

	rep, bundle := writeBack(t, tree, sh)
	if rep.Commits != 3 {
		t.Errorf("the write-back reports %d commits, want the harness's two plus its leftovers", rep.Commits)
	}
	res, err := land(t, s, sh, rep, bundle)
	if err != nil {
		t.Fatalf("Land: %v", err)
	}
	if res.Outcome != featurehub.LandFastForwarded || res.CommitSHA != rep.CommitSHA {
		t.Fatalf("Land = %+v", res)
	}
	if got := git(t, s.parent, "rev-parse", "refs/heads/"+branch); got != rep.CommitSHA {
		t.Errorf("the feature's branch is at %s, want %s", got, rep.CommitSHA)
	}
	if !strings.Contains(git(t, s.parent, "log", "--format=%H", "refs/heads/"+branch), tip) {
		t.Error("the harness's own commits are not on the feature's branch")
	}
	for _, f := range []string{"one.txt", "two.txt", "three.txt"} {
		if _, err := os.Stat(filepath.Join(s.feature, f)); err != nil {
			t.Errorf("the worktree was not updated: %s: %v", f, err)
		}
	}
	if out := git(t, s.feature, "-c", "core.fsmonitor=false", "status", "--porcelain"); out != "" {
		t.Errorf("the worktree is not clean after the fast-forward:\n%s", out)
	}
	if refs := git(t, s.parent, "for-each-ref", "refs/cloop/"); refs != "" {
		t.Errorf("the quarantine ref survived: %s", refs)
	}
	s.assertParentUntouched(t)
}

func TestLandKeepsWorkWhenTheWorktreeIsDirty(t *testing.T) {
	s := newScene(t)
	sh := ship(t, s, featurehub.ShipRequest{})
	tree := sandbox(t, sh)
	harnessCommit(t, tree, "remote.txt", "from the sandbox\n")
	rep, bundle := writeBack(t, tree, sh)

	// Someone is editing the feature on the hub.
	write(t, filepath.Join(s.feature, "README.md"), "local edit\n")
	write(t, filepath.Join(s.feature, "scratch.txt"), "untracked\n")

	res, err := land(t, s, sh, rep, bundle)
	if err != nil {
		t.Fatalf("Land: %v", err)
	}
	if res.Outcome != featurehub.LandConflict || !strings.Contains(res.Reason, "uncommitted changes") {
		t.Fatalf("Land = %+v, want a conflict naming the uncommitted changes", res)
	}
	if got := git(t, s.parent, "rev-parse", "refs/heads/"+branch); got != sh.Head {
		t.Errorf("the feature's branch moved to %s although its worktree was dirty", got)
	}
	if b := readFile(t, filepath.Join(s.feature, "README.md")); string(b) != "local edit\n" {
		t.Errorf("the local edit was lost: %q", b)
	}
	if _, err := os.Stat(filepath.Join(s.feature, "remote.txt")); err == nil {
		t.Error("the returned work was written into a dirty worktree")
	}
	// Nothing lost on the other side either: the work is on its own branch.
	if !strings.HasPrefix(res.KeptOn, featurehub.ReturnedBranchPrefix+slug+"/") {
		t.Errorf("kept on %q", res.KeptOn)
	}
	if got := git(t, s.parent, "rev-parse", "refs/heads/"+res.KeptOn); got != rep.CommitSHA {
		t.Errorf("the kept branch is at %s, want %s", got, rep.CommitSHA)
	}
	if d := res.Describe(); !strings.Contains(d, res.KeptOn) || !strings.Contains(d, "Nothing was forced") {
		t.Errorf("Describe = %q", d)
	}
	s.assertParentUntouched(t)
}

func TestLandKeepsWorkWhenTheBranchMoved(t *testing.T) {
	s := newScene(t)
	sh := ship(t, s, featurehub.ShipRequest{})
	tree := sandbox(t, sh)
	harnessCommit(t, tree, "remote.txt", "r\n")
	rep, bundle := writeBack(t, tree, sh)

	moved := s.commitOnFeature(t, "hub.txt", "committed on the hub meanwhile\n")
	res, err := land(t, s, sh, rep, bundle)
	if err != nil {
		t.Fatalf("Land: %v", err)
	}
	if res.Outcome != featurehub.LandConflict || !strings.Contains(res.Reason, "moved") {
		t.Fatalf("Land = %+v, want a conflict about the moved branch", res)
	}
	if got := git(t, s.parent, "rev-parse", "refs/heads/"+branch); got != moved {
		t.Errorf("the feature's branch is at %s, want it left at %s", got, moved)
	}
}

func TestLandKeepsWorkThatTouchesTheControlDirectory(t *testing.T) {
	s := newScene(t)
	sh := ship(t, s, featurehub.ShipRequest{})
	tree := sandbox(t, sh)
	// Forced past the tree's own exclude: a harness can do this deliberately.
	write(t, filepath.Join(tree, ".cloop", "state.db"), "not the hub's\n")
	git(t, tree, "add", "-f", ".cloop/state.db")
	git(t, tree, "commit", "-qm", "sweep the state in")
	rep, bundle := writeBack(t, tree, sh)

	write(t, filepath.Join(s.feature, ".cloop", "state.db"), "the hub's own\n")
	res, err := land(t, s, sh, rep, bundle)
	if err != nil {
		t.Fatalf("Land: %v", err)
	}
	if res.Outcome != featurehub.LandConflict || !strings.Contains(res.Reason, ".cloop") {
		t.Fatalf("Land = %+v, want a conflict about .cloop", res)
	}
	if b := readFile(t, filepath.Join(s.feature, ".cloop", "state.db")); string(b) != "the hub's own\n" {
		t.Errorf("the hub's state was overwritten: %q", b)
	}
}

func TestLandRefusesWorkBuiltOnAnotherBase(t *testing.T) {
	s := newScene(t)
	sh := ship(t, s, featurehub.ShipRequest{})
	tree := sandbox(t, sh)
	harnessCommit(t, tree, "x.txt", "x\n")
	rep, bundle := writeBack(t, tree, sh)

	_, err := featurehub.Land(context.Background(), featurehub.LandRequest{
		FeatureDir: s.feature, Reported: rep, Bundle: bundle,
		ShippedHead: strings.Repeat("a", 40),
	})
	if !errors.Is(err, executor.ErrWriteBackRejected) {
		t.Fatalf("Land = %v, want a rejection", err)
	}
	rep.Branch = "cloop/feature/other"
	if _, err := land(t, s, sh, rep, bundle); !errors.Is(err, executor.ErrWriteBackRejected) {
		t.Fatalf("Land onto another branch = %v, want a rejection", err)
	}
	if got := git(t, s.parent, "rev-parse", "refs/heads/"+branch); got != sh.Head {
		t.Errorf("a refused write-back moved the branch to %s", got)
	}
}

func TestLandRefusesAnEscapingSymlink(t *testing.T) {
	s := newScene(t)
	sh := ship(t, s, featurehub.ShipRequest{})
	tree := sandbox(t, sh)
	if err := os.Symlink("/etc/passwd", filepath.Join(tree, "leak")); err != nil {
		t.Fatal(err)
	}
	rep, bundle := writeBack(t, tree, sh)
	_, err := land(t, s, sh, rep, bundle)
	if !errors.Is(err, executor.ErrWriteBackRejected) {
		t.Fatalf("Land = %v, want the content policy to refuse it", err)
	}
	if _, err := os.Lstat(filepath.Join(s.feature, "leak")); err == nil {
		t.Error("the escaping symlink reached the hub's worktree")
	}
	if refs := git(t, s.parent, "for-each-ref", "refs/heads/cloop/returned/", "refs/cloop/"); refs != "" {
		t.Errorf("a refused write-back left refs behind: %s", refs)
	}
	s.assertParentUntouched(t)
}

func TestLandRefusesAnOversizedBundle(t *testing.T) {
	s := newScene(t)
	sh := ship(t, s, featurehub.ShipRequest{})
	tree := sandbox(t, sh)
	harnessCommit(t, tree, "big.bin", randomString(t, 64<<10))
	rep, bundle := writeBack(t, tree, sh)
	_, err := featurehub.Land(context.Background(), featurehub.LandRequest{
		FeatureDir: s.feature, Reported: rep, Bundle: bundle, ShippedHead: sh.Head, MaxBytes: 16 << 10,
	})
	if !errors.Is(err, executor.ErrWriteBackRejected) || !strings.Contains(err.Error(), "over the") {
		t.Fatalf("Land = %v, want a size refusal", err)
	}
	if got := git(t, s.parent, "rev-parse", "refs/heads/"+branch); got != sh.Head {
		t.Errorf("an oversized write-back moved the branch to %s", got)
	}
}

func TestLandWithNothingToReturn(t *testing.T) {
	s := newScene(t)
	sh := ship(t, s, featurehub.ShipRequest{})
	tree := sandbox(t, sh)
	rep, bundle := writeBack(t, tree, sh)
	res, err := land(t, s, sh, rep, bundle)
	if err != nil || res.Outcome != featurehub.LandNothing {
		t.Fatalf("Land = %+v, %v; want nothing", res, err)
	}
}

func TestWriteBackFromAFailedHarnessReturnsOnlyItsCommits(t *testing.T) {
	s := newScene(t)
	sh := ship(t, s, featurehub.ShipRequest{})
	tree := sandbox(t, sh)
	committed := harnessCommit(t, tree, "done.txt", "task one finished\n")
	write(t, filepath.Join(tree, "half.txt"), "task two died here\n")

	res, err := gitwriteback.Produce(context.Background(), gitwriteback.Request{
		Dir:           tree,
		WriteBack:     executor.WriteBack{Mode: executor.WriteBackBundle, Branch: sh.Branch},
		BaseSHA:       sh.Head,
		ExitCode:      1,
		OnlyOnSuccess: true,
	})
	if err != nil {
		t.Fatalf("Produce: %v", err)
	}
	defer os.Remove(res.BundlePath)
	if !res.Delivered() || res.CommitSHA != committed || res.Commits != 1 {
		t.Fatalf("a failed harness's commits were not returned as made: %+v", res.WriteBackResult)
	}
	landed, err := land(t, s, sh, res.WriteBackResult, readFile(t, res.BundlePath))
	if err != nil || landed.Outcome != featurehub.LandFastForwarded {
		t.Fatalf("Land = %+v, %v", landed, err)
	}
	if _, err := os.Stat(filepath.Join(s.feature, "half.txt")); err == nil {
		t.Error("a failed harness's uncommitted file was written back")
	}
}

func randomString(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	// Printable, still incompressible enough for the size tests.
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// TestShipAndLandInAProjectAnotherAccountOwns: a project bound to a container
// executor is owned by its sandbox's unprivileged uid, and the hub's account
// may be another. git refuses such a repository by default; the hub's own
// hardened git must not.
func TestShipAndLandInAProjectAnotherAccountOwns(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("handing the project to another uid needs root")
	}
	s := newScene(t)
	if err := filepath.Walk(s.parent, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, 1000, 1000)
	}); err != nil {
		t.Fatal(err)
	}
	sh := ship(t, s, featurehub.ShipRequest{})
	tree := sandbox(t, sh)
	harnessCommit(t, tree, "x.txt", "x\n")
	rep, bundle := writeBack(t, tree, sh)
	res, err := land(t, s, sh, rep, bundle)
	if err != nil || res.Outcome != featurehub.LandFastForwarded {
		t.Fatalf("Land in a project owned by uid 1000 = %+v, %v", res, err)
	}
}
