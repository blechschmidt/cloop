package gitprovision_test

// A working copy kept on a device that serves several projects (Task 20500):
// the run that last wrote it was confined to its project, and this machine's
// own git, which provisions the next run outside that confinement, must obey
// nothing it left in .git — yet the working copy a move placed there keeps
// its branch, commits and uncommitted changes.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
	"github.com/blechschmidt/cloop/pkg/executor/internal/gitforge"
)

func TestAHardenedKeptWorkingCopyObeysNothingItsLastRunLeft(t *testing.T) {
	f := newFixture(t, gitforge.Options{})
	if err := f.provision(); err != nil {
		t.Fatalf("first provisioning: %v\nlog:\n%s", err, f.log())
	}
	tools := gitforge.RequireGit(t)
	// What a confined run could leave: a filter whose smudge runs a program,
	// a redirect of the authenticated fetch, and an alternates file pointing
	// git at another project's objects.
	marker := filepath.Join(t.TempDir(), "pwned")
	for _, kv := range [][2]string{
		{"filter.x.smudge", "touch " + marker},
		{"filter.x.required", "true"},
		{"url.https://evil.invalid/.insteadOf", "https://"},
	} {
		gitforge.Git(t, tools, f.home, f.dir, "-C", f.dir, "config", "--local", kv[0], kv[1])
	}
	if err := os.WriteFile(filepath.Join(f.dir, ".gitattributes"), []byte("* filter=x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other-project", ".git", "objects")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, ".git", "objects", "info", "alternates"), []byte(other+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The move's working copy: an uncommitted change, kept.
	tracked := firstTrackedFile(t, f)
	if err := os.WriteFile(filepath.Join(f.dir, tracked), []byte("uncommitted work\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	f.emitted.Reset()
	req := f.request()
	req.Harden = true
	req.Workspace.Keep = true
	ctx, cancel := contextWithTimeout()
	defer cancel()
	if err := gitprovision.Provision(ctx, req); err != nil {
		t.Fatalf("hardened provisioning: %v\nlog:\n%s", err, f.log())
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the filter the last run left ran")
	}
	for _, key := range []string{"filter.x.smudge", "url.https://evil.invalid/.insteadof"} {
		if v, err := gitforge.TryGit(t, tools, f.home, f.dir, "-C", f.dir, "config", "--local", "--get", key); err == nil || strings.TrimSpace(v) != "" {
			t.Errorf("%s survived as %q", key, v)
		}
	}
	if _, err := os.Lstat(filepath.Join(f.dir, ".git", "objects", "info", "alternates")); err == nil {
		t.Error("the alternates file survived")
	}
	if b, err := os.ReadFile(filepath.Join(f.dir, tracked)); err != nil || string(b) != "uncommitted work\n" {
		t.Errorf("the working copy's change was not kept: %q %v", b, err)
	}
	if got := gitConfig(t, f, "remote.origin.url"); got != f.ws.Repo {
		t.Errorf("origin is %q", got)
	}

	// A .git that is a link leads git to another repository: refused, never
	// followed or discarded.
	gitDir := filepath.Join(f.dir, ".git")
	moved := gitDir + "-elsewhere"
	if err := os.Rename(gitDir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, gitDir); err != nil {
		t.Fatal(err)
	}
	if err := gitprovision.Provision(context.Background(), req); err == nil ||
		!strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("a .git link: %v", err)
	}
}

// TestHideControlDirFollowsNoLinkTheTreeLeft: the exclude file the agent
// appends to is never reached through a link a run left at .git/info or the
// file itself, which would carry the append into another repository.
func TestHideControlDirFollowsNoLinkTheTreeLeft(t *testing.T) {
	f := newFixture(t, gitforge.Options{})
	if err := f.provision(); err != nil {
		t.Fatalf("provisioning: %v\nlog:\n%s", err, f.log())
	}
	victim := filepath.Join(t.TempDir(), "victim-config")
	if err := os.WriteFile(victim, []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	exclude := filepath.Join(f.dir, ".git", "info", "exclude")
	_ = os.Remove(exclude)
	if err := os.Symlink(victim, exclude); err != nil {
		t.Fatal(err)
	}
	if err := gitprovision.HideControlDir(context.Background(), f.dir); err != nil {
		t.Fatalf("HideControlDir: %v", err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "[core]\n" {
		t.Fatalf("the append reached the link's target: %q", b)
	}
	if fi, err := os.Lstat(exclude); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("the exclude file: %v %v", fi, err)
	}
}
