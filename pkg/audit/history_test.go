package audit

import (
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/redact/redacttest"
)

// gitRepo is a repository for the history scan to read, built with git's
// configuration closed to this machine's: the scan runs git in this process's
// environment, so the same variables keep a developer's ~/.gitconfig and
// /etc/gitconfig out of what the test asserts.
type gitRepo struct {
	t   *testing.T
	dir string
}

func newGitRepo(t *testing.T) *gitRepo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	for _, k := range []string{"GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"} {
		t.Setenv(k, "cloop test")
	}
	for _, k := range []string{"GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"} {
		t.Setenv(k, "test@example.com")
	}
	r := &gitRepo{t: t, dir: t.TempDir()}
	r.git("", "init", "-q")
	return r
}

// git runs a git command in the repository, feeding it stdin, and returns its
// trimmed output.
func (r *gitRepo) git(stdin string, args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", r.dir}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *gitRepo) write(rel, body string) {
	r.t.Helper()
	path := filepath.Join(r.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

// scanHistory runs the git-history check alone and returns its one finding.
func (r *gitRepo) scanHistory() Finding {
	r.t.Helper()
	var got []Finding
	checkCredentialsInGit(r.dir, config.Default(), func(f Finding) { got = append(got, f) })
	if len(got) != 1 {
		r.t.Fatalf("the git-history check reported %d findings, want 1: %+v", len(got), got)
	}
	return got[0]
}

// TestGitHistoryScanRunsNoProgramTheRepositoryNames: cloop audit reads a
// checkout whose .git/config it does not control — an agent working in the
// tree can write it — and nothing in that config may choose a program for the
// scan to run. log.showSignature hands every signed commit the log shows to
// gpg.program. The scan has no use for signatures, so it does not ask for
// them, whatever the repository says.
func TestGitHistoryScanRunsNoProgramTheRepositoryNames(t *testing.T) {
	repo := newGitRepo(t)
	repo.write(".cloop/config.yaml", "provider: claudecode\n")
	repo.git("", "add", ".cloop/config.yaml")

	// A signed commit, so that log.showSignature has something to verify. The
	// signature does not have to be valid for git to hand it to the program.
	tree := repo.git("", "write-tree")
	commit := repo.git("tree "+tree+"\n"+
		"author cloop test <test@example.com> 1759500000 +0000\n"+
		"committer cloop test <test@example.com> 1759500000 +0000\n"+
		"gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEE\n -----END PGP SIGNATURE-----\n"+
		"\nconfigure\n", "hash-object", "-t", "commit", "-w", "--stdin")
	repo.git("", "update-ref", "HEAD", commit)

	ran := filepath.Join(t.TempDir(), "ran")
	program := filepath.Join(t.TempDir(), "gpg")
	if err := os.WriteFile(program, []byte("#!/bin/sh\ntouch '"+ran+"'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	repo.git("", "config", "log.showSignature", "true")
	repo.git("", "config", "gpg.program", program)

	f := repo.scanHistory()
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("the history scan ran the program the repository's own config named")
	}
	// The scan must still have read the history, or the assertion above only
	// shows that git was never run.
	if f.Level != Pass || !strings.Contains(f.Message, "no detected credentials") {
		t.Errorf("the scan did not read the history: %+v", f)
	}
}

// TestGitHistoryScanSeesThroughReplaceRefs: `git replace` swaps one object for
// another wherever git reads it, history included, so one replace ref is
// enough to show the scan a clean commit where the leak was. The scan reads
// what was committed, not what a ref says to show in its place.
func TestGitHistoryScanSeesThroughReplaceRefs(t *testing.T) {
	repo := newGitRepo(t)
	tok := redacttest.GitHubToken(rand.New(rand.NewPCG(redacttest.Seed, 21)), "ghp_")

	repo.write(".cloop/config.yaml", "provider: claudecode\ngithub:\n  token: "+tok+"\n")
	repo.git("", "add", ".cloop/config.yaml")
	repo.git("", "commit", "-q", "-m", "configure github")
	leak := repo.git("", "rev-parse", "HEAD")
	repo.write(".cloop/config.yaml", "provider: claudecode\n")
	repo.git("", "commit", "-q", "-am", "remove the token")

	// The leaking commit's stand-in: the cleaned tree, no parent, the same
	// message — what the history would look like had the token never been
	// committed.
	stand := repo.git("", "commit-tree", repo.git("", "rev-parse", "HEAD^{tree}"), "-m", "configure github")
	repo.git("", "replace", leak, stand)

	f := repo.scanHistory()
	if f.Level != Fail || !strings.Contains(f.Message, "GitHub token") {
		t.Errorf("a replace ref hid a committed token from the scan: %+v", f)
	}
}

// TestGitHistoryScanReadsAMergesOwnChanges: git log -p shows no diff for a
// merge commit, so a credential added while resolving a conflict — in no
// parent's history — was never read.
func TestGitHistoryScanReadsAMergesOwnChanges(t *testing.T) {
	repo := newGitRepo(t)
	tok := redacttest.GitHubToken(rand.New(rand.NewPCG(redacttest.Seed, 22)), "ghp_")

	repo.write(".cloop/config.yaml", "a: 1\n")
	repo.git("", "add", ".cloop/config.yaml")
	repo.git("", "commit", "-q", "-m", "base")
	trunk := repo.git("", "branch", "--show-current")
	repo.git("", "checkout", "-q", "-b", "side")
	repo.write(".cloop/config.yaml", "a: 2\n")
	repo.git("", "commit", "-q", "-am", "side")
	repo.git("", "checkout", "-q", trunk)
	repo.write(".cloop/config.yaml", "a: 3\n")
	repo.git("", "commit", "-q", "-am", "trunk")
	// The merge conflicts; its resolution carries the token.
	_ = exec.Command("git", "-C", repo.dir, "merge", "-q", "side").Run()
	repo.write(".cloop/config.yaml", "a: 4\ntoken: "+tok+"\n")
	repo.git("", "add", ".cloop/config.yaml")
	repo.git("", "commit", "-q", "-m", "merge side")

	if f := repo.scanHistory(); f.Level != Fail || !strings.Contains(f.Message, "GitHub token") {
		t.Errorf("a token added in a merge commit's resolution was not found: %+v", f)
	}
}

// TestGitHistoryScanReadsFilesMarkedBinary: a committed .gitattributes line
// marking .cloop/ "-diff", or one NUL byte in a file, turns its diff into
// "Binary files differ" — and the content out of the scan's reach.
func TestGitHistoryScanReadsFilesMarkedBinary(t *testing.T) {
	r := rand.New(rand.NewPCG(redacttest.Seed, 23))
	for name, files := range map[string]map[string]string{
		"diff attribute": {".gitattributes": ".cloop/** -diff\n", ".cloop/config.yaml": "token: " + redacttest.GitHubToken(r, "ghp_") + "\n"},
		"NUL byte":       {".cloop/state.bin": "\x00\x01\ntoken: " + redacttest.GitHubToken(r, "ghp_") + "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			repo := newGitRepo(t)
			for path, body := range files {
				repo.write(path, body)
			}
			repo.git("", "add", "-A")
			repo.git("", "commit", "-q", "-m", "configure")
			if f := repo.scanHistory(); f.Level != Fail || !strings.Contains(f.Message, "GitHub token") {
				t.Errorf("a token in a file git calls binary was not found: %+v", f)
			}
		})
	}
}

// TestGitHistoryScanFollowsAMovedFile: a file moved and changed in one commit
// is a rename to git, and a rename was outside the scan's diff filter, along
// with whatever the commit added to the file.
func TestGitHistoryScanFollowsAMovedFile(t *testing.T) {
	repo := newGitRepo(t)
	tok := redacttest.GitHubToken(rand.New(rand.NewPCG(redacttest.Seed, 24)), "ghp_")

	var plan strings.Builder
	for i := 1; i <= 40; i++ {
		fmt.Fprintf(&plan, "step_%d: an ordinary line of the plan, number %d\n", i, i)
	}
	repo.write(".cloop/plan.yaml", plan.String())
	repo.git("", "add", ".cloop/plan.yaml")
	repo.git("", "commit", "-q", "-m", "plan")
	repo.git("", "mv", ".cloop/plan.yaml", ".cloop/plan-v2.yaml")
	repo.write(".cloop/plan-v2.yaml", plan.String()+"token: "+tok+"\n")
	repo.git("", "add", "-A")
	repo.git("", "commit", "-q", "-m", "move the plan")

	if f := repo.scanHistory(); f.Level != Fail || !strings.Contains(f.Message, "GitHub token") {
		t.Errorf("a token added in the commit that moved its file was not found: %+v", f)
	}
}

// TestGitHistoryScanFetchesNothing: in a partial clone, git fetches a missing
// blob the moment log -p needs it, by running the remote's upload-pack — and
// .git/config says which program that is. The scan fetches nothing, and says
// that it could not read the whole history rather than that it was clean.
func TestGitHistoryScanFetchesNothing(t *testing.T) {
	src := newGitRepo(t)
	src.write(".cloop/config.yaml", "provider: claudecode\n")
	src.git("", "add", ".cloop/config.yaml")
	src.git("", "commit", "-q", "-m", "configure")
	origin := t.TempDir()
	src.git("", "clone", "-q", "--bare", src.dir, origin)
	for _, kv := range [][2]string{{"uploadpack.allowFilter", "true"}, {"uploadpack.allowAnySHA1InWant", "true"}} {
		if out, err := exec.Command("git", "-C", origin, "config", kv[0], kv[1]).CombinedOutput(); err != nil {
			t.Fatalf("git config %s: %v\n%s", kv[0], err, out)
		}
	}
	partial := &gitRepo{t: t, dir: filepath.Join(t.TempDir(), "partial")}
	if out, err := exec.Command("git", "clone", "-q", "--filter=blob:none", "--no-checkout",
		"file://"+origin, partial.dir).CombinedOutput(); err != nil {
		t.Fatalf("partial clone: %v\n%s", err, out)
	}

	ran := filepath.Join(t.TempDir(), "ran")
	program := filepath.Join(t.TempDir(), "upload-pack")
	if err := os.WriteFile(program, []byte("#!/bin/sh\ntouch '"+ran+"'\nexec git-upload-pack \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	partial.git("", "config", "remote.origin.uploadpack", program)

	f := partial.scanHistory()
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("the history scan ran the upload-pack the repository's own config named")
	}
	if f.Level != Warn {
		t.Errorf("a history the scan could not read whole was reported as %s, not a warning: %+v", f.Level, f)
	}
}
