package reviewgate

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// helperEnv makes this test binary act as the git remote helper: NewHold's
// script execs it through /usr/bin/env with this variable set, and TestMain
// then serves the protocol instead of running tests. It is how the hold is
// tested against a real `git push` without building cloop.
const helperEnv = "CLOOP_REVIEWGATE_TEST_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		if err := ServeRemoteHelper(context.Background(), os.Args[1:], os.Getenv(HoldFileEnv), os.Stdin, os.Stdout); err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func helperArgv(t *testing.T) []string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env, err := exec.LookPath("env")
	if err != nil {
		t.Skip("no env(1)")
	}
	return []string{env, helperEnv + "=1", exe}
}

func needGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
}

// git runs git in dir and fails the test on error.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// gitEnvRun runs git with extra environment and returns its output and error.
func gitEnvRun(dir string, env []string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t"), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
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

// fixture is a project repository cloned from a bare remote, with one commit
// on main that the remote already has.
type fixture struct {
	root, remote string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	needGit(t)
	base := t.TempDir()
	remote := filepath.Join(base, "remote.git")
	git(t, base, "init", "-q", "--bare", "-b", "main", remote)
	root := filepath.Join(base, "project")
	git(t, base, "clone", "-q", remote, root)
	git(t, root, "config", "commit.gpgsign", "false")
	git(t, root, "checkout", "-q", "-b", "main")
	write(t, filepath.Join(root, "README.md"), "hello\n")
	git(t, root, "add", ".")
	git(t, root, "commit", "-q", "-m", "initial")
	git(t, root, "push", "-q", "-u", "origin", "main")
	return fixture{root: absClean(root), remote: remote}
}

func (f fixture) remoteHead(t *testing.T) string {
	return git(t, f.remote, "rev-parse", "refs/heads/main")
}

func TestCollectFindsCommittedUncommittedAndNewFiles(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	snap := TakeSnapshot(ctx, f.root)

	write(t, filepath.Join(f.root, "a.go"), "package a\n")
	git(t, f.root, "add", "a.go")
	git(t, f.root, "commit", "-q", "-m", "add a")
	write(t, filepath.Join(f.root, "README.md"), "hello\nworld\n") // uncommitted
	write(t, filepath.Join(f.root, "notes.txt"), "new\nfile\n")    // untracked
	write(t, filepath.Join(f.root, ".cloop", "state.json"), "{}")  // cloop's own

	c, err := Collect(ctx, snap, nil)
	if err != nil {
		t.Fatal(err)
	}
	rc := c.Repo(f.root)
	if rc == nil {
		t.Fatalf("the project's repository is missing from %+v", c.Repos)
	}
	if rc.Rel != "." || rc.CommitCount != 1 || !rc.Uncommitted {
		t.Errorf("rel=%q commits=%d uncommitted=%v", rc.Rel, rc.CommitCount, rc.Uncommitted)
	}
	if rc.Files != 3 {
		t.Errorf("files = %d, want 3 (a.go, README.md, notes.txt)", rc.Files)
	}
	for _, want := range []string{"+package a", "+world", "+++ b/notes.txt", "+new"} {
		if !strings.Contains(rc.Diff, want) {
			t.Errorf("diff lacks %q:\n%s", want, rc.Diff)
		}
	}
	if strings.Contains(rc.Diff, "state.json") {
		t.Errorf("cloop's own files leaked into the diff:\n%s", rc.Diff)
	}
	if rc.Tree == "" {
		t.Error("no reviewed tree recorded")
	}
	if c.Empty() {
		t.Error("changes reported empty")
	}
	// The reviewed tree is exactly what `git add -A && git commit` produces.
	git(t, f.root, "add", "-A")
	git(t, f.root, "commit", "-q", "-m", "rest")
	if got := TreeOf(ctx, f.root, "HEAD"); got != rc.Tree {
		t.Errorf("tree after committing = %s, reviewed tree = %s", got, rc.Tree)
	}
}

func TestCollectNothingChanged(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	snap := TakeSnapshot(ctx, f.root)
	c, err := Collect(ctx, snap, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Empty() {
		t.Errorf("an untouched project reports changes: %+v", c.Repos)
	}
}

func TestCollectFindsARepositoryClonedDuringTheTask(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	snap := TakeSnapshot(ctx, f.root)

	// The agent clones a (granted) repository into the project and commits.
	other := filepath.Join(filepath.Dir(f.root), "other.git")
	git(t, filepath.Dir(f.root), "init", "-q", "--bare", "-b", "main", other)
	seed := filepath.Join(filepath.Dir(f.root), "seed")
	git(t, filepath.Dir(f.root), "clone", "-q", other, seed)
	git(t, seed, "checkout", "-q", "-b", "main")
	write(t, filepath.Join(seed, "lib.txt"), "v1\n")
	git(t, seed, "add", ".")
	git(t, seed, "commit", "-q", "-m", "v1")
	git(t, seed, "push", "-q", "origin", "main")

	clone := filepath.Join(f.root, "vendor-repo")
	git(t, f.root, "clone", "-q", other, clone)
	write(t, filepath.Join(clone, "lib.txt"), "v2\n")
	git(t, clone, "commit", "-q", "-am", "v2")

	c, err := Collect(ctx, snap, nil)
	if err != nil {
		t.Fatal(err)
	}
	rc := c.Repo(clone)
	if rc == nil {
		t.Fatalf("the cloned repository is missing: %+v", c.Repos)
	}
	if rc.Rel != "vendor-repo" || rc.CommitCount != 1 || !strings.Contains(rc.Diff, "+v2") {
		t.Errorf("clone: rel=%q commits=%d diff:\n%s", rc.Rel, rc.CommitCount, rc.Diff)
	}
	// The clone's contents are its own entry's, not the project's untracked files.
	if root := c.Repo(f.root); root != nil && strings.Contains(root.Diff, "lib.txt") {
		t.Errorf("the project's diff includes the nested clone:\n%s", root.Diff)
	}
}

func TestHeldPushWidensTheReviewToEverythingItWouldPublish(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// A commit that was already sitting unpushed before the task.
	write(t, filepath.Join(f.root, "old.txt"), "older unpushed work\n")
	git(t, f.root, "add", ".")
	git(t, f.root, "commit", "-q", "-m", "older")
	snap := TakeSnapshot(ctx, f.root)
	write(t, filepath.Join(f.root, "new.txt"), "task work\n")
	git(t, f.root, "add", ".")
	git(t, f.root, "commit", "-q", "-m", "task")

	c, _ := Collect(ctx, snap, nil)
	if rc := c.Repo(f.root); rc == nil || rc.CommitCount != 1 || strings.Contains(rc.Diff, "older unpushed") {
		t.Fatalf("without a push the review is the task's own commit: %+v", rc)
	}
	held := []HeldPush{{Repo: f.root, Remote: "origin", Src: "HEAD", SrcRef: "refs/heads/main", Dst: "refs/heads/main"}}
	c, _ = Collect(ctx, snap, held)
	rc := c.Repo(f.root)
	if rc == nil || rc.CommitCount != 2 || !strings.Contains(rc.Diff, "older unpushed") {
		t.Fatalf("with a held push the review must cover both unpushed commits: %+v", rc)
	}
}

func TestHoldEnvAppendsToExistingGitConfig(t *testing.T) {
	t.Setenv("GIT_CONFIG_COUNT", "2")
	h, err := NewHold([]string{"/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	env := map[string]string{}
	for _, kv := range h.Env() {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}
	if env["GIT_CONFIG_COUNT"] != "10" {
		t.Errorf("GIT_CONFIG_COUNT = %q, want 10 (2 inherited + 8 rewrites)", env["GIT_CONFIG_COUNT"])
	}
	if _, clobbered := env["GIT_CONFIG_KEY_0"]; clobbered {
		t.Error("the hold overwrote an inherited GIT_CONFIG_KEY_0")
	}
	if env["GIT_CONFIG_KEY_2"] != "url.cloopgate::.pushInsteadOf" || env["GIT_CONFIG_VALUE_2"] != "" {
		t.Errorf("first rewrite = %q=%q", env["GIT_CONFIG_KEY_2"], env["GIT_CONFIG_VALUE_2"])
	}
	if !strings.HasPrefix(env["PATH"], filepath.Join(h.dir, "bin")+string(os.PathListSeparator)) {
		t.Errorf("PATH does not lead with the helper directory: %q", env["PATH"])
	}
	if env[HoldFileEnv] == "" {
		t.Error("the hold file is not named")
	}
}

func TestNewHoldRefusesARelativeProgram(t *testing.T) {
	if _, err := NewHold([]string{"cloop", HelperSubcommand}); err == nil {
		t.Fatal("a relative helper path was accepted")
	}
}

func TestServeRemoteHelperProtocol(t *testing.T) {
	f := newFixture(t)
	hold := filepath.Join(t.TempDir(), "held.jsonl")
	in := strings.NewReader("capabilities\nlist for-push\npush refs/heads/main:refs/heads/main\npush +HEAD:refs/heads/topic\npush :refs/heads/gone\n\n\n")
	var out strings.Builder
	wd, _ := os.Getwd()
	if err := os.Chdir(f.root); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)
	if err := ServeRemoteHelper(context.Background(), []string{"origin", f.remote}, hold, in, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.HasPrefix(got, "push\n\n") {
		t.Errorf("capabilities answer: %q", got)
	}
	// The remote's main, as last fetched, is advertised so git's own
	// fast-forward check keeps working.
	if !strings.Contains(got, f.remoteHead(t)+" refs/heads/main\n") {
		t.Errorf("list did not advertise origin/main:\n%s", got)
	}
	for _, ref := range []string{"refs/heads/main", "refs/heads/topic", "refs/heads/gone"} {
		if !strings.Contains(got, "error "+ref+" held by cloop's review gate") {
			t.Errorf("%s was not refused as held:\n%s", ref, got)
		}
	}
	held := ReadHeld(hold)
	if len(held) != 3 {
		t.Fatalf("held %d pushes, want 3: %+v", len(held), held)
	}
	if held[0].SrcRef != "refs/heads/main" || held[0].Expect != f.remoteHead(t) || held[0].Repo != f.root {
		t.Errorf("first held push: %+v", held[0])
	}
	if !held[1].Force || held[1].Dst != "refs/heads/topic" {
		t.Errorf("forced push not recorded as forced: %+v", held[1])
	}
	if !held[2].Delete() {
		t.Errorf("deletion not recorded as one: %+v", held[2])
	}
}

func TestServeRemoteHelperWithoutAHoldRefuses(t *testing.T) {
	f := newFixture(t)
	wd, _ := os.Getwd()
	if err := os.Chdir(f.root); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)
	var out strings.Builder
	in := strings.NewReader("capabilities\nlist for-push\npush HEAD:refs/heads/main\n\n\n")
	if err := ServeRemoteHelper(context.Background(), []string{"origin", f.remote}, "", in, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "error refs/heads/main cloop's review gate could not record this push") {
		t.Errorf("a push with nowhere to be held was not refused:\n%s", out.String())
	}
}

// TestHeldPushIsSentOnlyAfterApproval drives the whole path with a real git:
// the agent's push is rewritten to the helper and held, the remote does not
// move, and Publish then sends exactly the reviewed commit.
func TestHeldPushIsSentOnlyAfterApproval(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	h, err := NewHold(helperArgv(t))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	snap := TakeSnapshot(ctx, f.root)
	before := f.remoteHead(t)

	write(t, filepath.Join(f.root, "feature.txt"), "reviewed work\n")
	git(t, f.root, "add", ".")
	git(t, f.root, "commit", "-q", "-m", "feature")
	out, err := gitEnvRun(f.root, h.Env(), "push")
	if err == nil {
		t.Fatalf("the agent's push went through the hold:\n%s", out)
	}
	if !strings.Contains(out, "held by cloop's review gate") {
		t.Errorf("git did not relay the hold's reason:\n%s", out)
	}
	if got := f.remoteHead(t); got != before {
		t.Fatalf("the remote moved before any review: %s -> %s", before, got)
	}
	held := h.Pushes()
	if len(held) != 1 {
		t.Fatalf("held %d pushes, want 1", len(held))
	}

	c, err := Collect(ctx, snap, held)
	if err != nil {
		t.Fatal(err)
	}
	reviewed := git(t, f.root, "rev-parse", "HEAD")
	// A commit made after the review must not ride along.
	write(t, filepath.Join(f.root, "late.txt"), "unreviewed\n")
	git(t, f.root, "add", ".")
	git(t, f.root, "commit", "-q", "-m", "late")

	pubs := Publish(ctx, c, held)
	if len(pubs) != 1 {
		t.Fatalf("publish records: %+v", pubs)
	}
	if pubs[0].Outcome != pm.PublishRefused || !strings.Contains(pubs[0].Detail, "moved after the review") {
		t.Fatalf("a branch that moved after the review was published: %+v", pubs[0])
	}
	git(t, f.root, "reset", "-q", "--hard", reviewed)
	pubs = Publish(ctx, c, held)
	if pubs[0].Outcome != pm.PublishPushed {
		t.Fatalf("approved push not sent: %+v", pubs[0])
	}
	if got := f.remoteHead(t); got != reviewed {
		t.Errorf("remote main = %s, want the reviewed commit %s", got, reviewed)
	}
}

func TestPublishRefusesCommitsTheReviewDidNotCover(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	write(t, filepath.Join(f.root, "old.txt"), "unpushed before the task\n")
	git(t, f.root, "add", ".")
	git(t, f.root, "commit", "-q", "-m", "older")
	snap := TakeSnapshot(ctx, f.root)
	write(t, filepath.Join(f.root, "new.txt"), "task\n")
	git(t, f.root, "add", ".")
	git(t, f.root, "commit", "-q", "-m", "task")

	// A review that saw only the task's own commit (no push was held when
	// it ran) cannot license a push that would also send the older one.
	c, _ := Collect(ctx, snap, nil)
	held := []HeldPush{{Repo: f.root, Remote: "origin", Src: "HEAD", SrcRef: "refs/heads/main", Dst: "refs/heads/main"}}
	pubs := Publish(ctx, c, held)
	if len(pubs) != 1 || pubs[0].Outcome != pm.PublishRefused || !strings.Contains(pubs[0].Detail, "1 commit(s) the reviewer did not see") {
		t.Fatalf("publish = %+v", pubs)
	}
	if got := f.remoteHead(t); got == git(t, f.root, "rev-parse", "HEAD") {
		t.Error("the remote received unreviewed commits")
	}
}

func TestPublishLeasesAForcedPush(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	snap := TakeSnapshot(ctx, f.root)
	git(t, f.root, "commit", "-q", "--amend", "-m", "rewritten")
	c, _ := Collect(ctx, snap, nil)
	// Someone else pushes to main while the review runs.
	other := filepath.Join(filepath.Dir(f.root), "other")
	git(t, filepath.Dir(f.root), "clone", "-q", f.remote, other)
	write(t, filepath.Join(other, "theirs.txt"), "theirs\n")
	git(t, other, "add", ".")
	git(t, other, "commit", "-q", "-m", "theirs")
	git(t, other, "push", "-q", "origin", "main")
	theirs := f.remoteHead(t)

	held := []HeldPush{{Repo: f.root, Remote: "origin", Src: "HEAD", SrcRef: "refs/heads/main",
		Dst: "refs/heads/main", Force: true, Expect: git(t, f.root, "rev-parse", "origin/main")}}
	pubs := Publish(ctx, c, held)
	if pubs[0].Outcome != pm.PublishFailed {
		t.Fatalf("a forced replay clobbered work pushed during the review: %+v", pubs[0])
	}
	if got := f.remoteHead(t); got != theirs {
		t.Errorf("remote main = %s, want %s left alone", got, theirs)
	}
}

func TestWithholdRecordsEveryHeldPush(t *testing.T) {
	held := []HeldPush{
		{Repo: "/p", Remote: "origin", Src: "HEAD", Dst: "refs/heads/main"},
		{Repo: "/p", Remote: "origin", Src: "HEAD", Dst: "refs/heads/main"}, // retried
		{Repo: "/p/x", Remote: "https://tok:secret@example.com/r.git", Dst: "refs/heads/old"},
	}
	got := Withhold("/p", held, "no")
	if len(got) != 2 {
		t.Fatalf("withheld %d, want 2 after de-duplication: %+v", len(got), got)
	}
	if got[1].Ref != "delete refs/heads/old" || strings.Contains(got[1].Remote, "secret") {
		t.Errorf("second record: %+v", got[1])
	}
	for _, r := range got {
		if r.Outcome != pm.PublishWithheld {
			t.Errorf("outcome %q", r.Outcome)
		}
	}
}
