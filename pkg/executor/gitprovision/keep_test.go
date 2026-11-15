package gitprovision_test

// Workspace.Keep (Task 20497): a checkout a project move placed on a device is
// the project's working copy, and the next run starts from it as it is.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/internal/gitforge"
)

// movedCopy turns the fixture's checkout into what a move leaves on a
// device: HEAD on the project's branch, a commit no remote has that changes
// README.md, and an uncommitted change to the same file on top. It returns
// the branch's tip and the bytes on disk.
func movedCopy(t *testing.T, f *fixture) (string, string) {
	t.Helper()
	tools := gitforge.RequireGit(t)
	run := func(args ...string) string {
		t.Helper()
		return strings.TrimSpace(gitforge.Git(t, tools, f.home, f.dir, append([]string{"-C", f.dir}, args...)...))
	}
	run("checkout", "-q", "-B", gitforge.DefaultBranch)
	readme := filepath.Join(f.dir, "README.md")
	if err := os.WriteFile(readme, []byte("seed\nchanged by a commit no remote has\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qam", "unpushed")
	tip := run("rev-parse", "HEAD")
	const dirty = "seed\nchanged by a commit no remote has\nand edited since, never committed\n"
	if err := os.WriteFile(readme, []byte(dirty), 0o644); err != nil {
		t.Fatal(err)
	}
	return tip, dirty
}

// TestProvisionKeepsAMovedWorkingCopy: with Keep, a reused checkout is fetched
// into and left as it is — its branch, its unpushed commit and its
// uncommitted change — where without it the checkout of the fetched commit
// refuses outright over the uncommitted change.
func TestProvisionKeepsAMovedWorkingCopy(t *testing.T) {
	f := newFixture(t, gitforge.Options{})
	f.ws.Depth = 0
	if err := f.provision(); err != nil {
		t.Fatalf("first Provision: %v\nlog:\n%s", err, f.log())
	}
	tip, dirty := movedCopy(t, f)
	tools := gitforge.RequireGit(t)

	// Without Keep: what a device did with a moved working copy before.
	f.emitted.Reset()
	err := f.provision()
	if err == nil || !strings.Contains(err.Error(), "would be overwritten by checkout") {
		t.Fatalf("without Keep, provisioning over the moved copy = %v, want the checkout's refusal\nlog:\n%s", err, f.log())
	}

	f.ws.Keep = true
	f.emitted.Reset()
	requestsBefore := f.forge.Count()
	if err := f.provision(); err != nil {
		t.Fatalf("Provision with Keep: %v\nlog:\n%s", err, f.log())
	}
	if f.forge.Count() == requestsBefore {
		t.Error("with Keep the checkout was not fetched into")
	}
	if !strings.Contains(f.log(), "keeping the working copy a project move placed here") {
		t.Errorf("the log does not say the working copy was kept:\n%s", f.log())
	}
	if got := strings.TrimSpace(gitforge.Git(t, tools, f.home, f.dir, "-C", f.dir, "symbolic-ref", "HEAD")); got != "refs/heads/"+gitforge.DefaultBranch {
		t.Errorf("HEAD = %s, want it left on refs/heads/%s", got, gitforge.DefaultBranch)
	}
	if got := headOf(t, f); got != tip {
		t.Errorf("HEAD is at %s, want the unpushed %s", got, tip)
	}
	if b, err := os.ReadFile(filepath.Join(f.dir, "README.md")); err != nil || string(b) != dirty {
		t.Errorf("the uncommitted change = %q (%v), want it as it was", b, err)
	}
	// The fetch did its job: the remote's branch is current.
	fetched := strings.TrimSpace(gitforge.Git(t, tools, f.home, f.dir, "-C", f.dir, "rev-parse", "FETCH_HEAD"))
	if want := f.forge.SHA(t, owner, repo, gitforge.DefaultBranch); fetched != want {
		t.Errorf("FETCH_HEAD = %s, want the forge's %s", fetched, want)
	}
	f.assertNoLeak(nil)
}

// TestProvisionWithKeepClonesWhenNothingIsThere: Keep keeps a checkout; with
// none in the directory the tree is cloned as without it.
func TestProvisionWithKeepClonesWhenNothingIsThere(t *testing.T) {
	f := newFixture(t, gitforge.Options{})
	f.ws.Keep = true
	if err := f.provision(); err != nil {
		t.Fatalf("Provision: %v\nlog:\n%s", err, f.log())
	}
	if got, want := headOf(t, f), f.forge.SHA(t, owner, repo, gitforge.DefaultBranch); got != want {
		t.Errorf("HEAD = %s, want the fetched %s", got, want)
	}
	if strings.Contains(f.log(), "keeping the working copy a project move placed here") {
		t.Errorf("a fresh clone claimed to keep a working copy:\n%s", f.log())
	}
}
