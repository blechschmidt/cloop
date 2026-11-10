package gitprovision_test

// Tests for a checkout kept on an executor pool runner's persistent volume
// (Task 20484): reused when it can be trusted, reset to exactly the commit
// fetched, discarded and cloned afresh when it cannot — and the git object
// cache beside it.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
	"github.com/blechschmidt/cloop/pkg/executor/internal/gitforge"
)

// pristine makes the fixture provision as a runner with a persistent volume.
func (f *fixture) pristineProvision(cache string) error {
	f.t.Helper()
	req := f.request()
	req.Pristine, req.ObjectCache = true, cache
	ctx, cancel := contextWithTimeout()
	defer cancel()
	return provisionWith(ctx, req)
}

func TestAKeptCheckoutIsResetToExactlyTheFetchedCommit(t *testing.T) {
	f := newFixture(t, gitforge.Options{})
	f.ws.Depth = 0
	if err := f.pristineProvision(""); err != nil {
		t.Fatalf("first provisioning: %v\nlog:\n%s", err, f.log())
	}
	// The last run left a modified tracked file, an untracked one, an ignored
	// build cache, and a branch of its own checked out.
	tools := gitforge.RequireGit(t)
	tracked := firstTrackedFile(t, f)
	gitforge.WriteFile(t, f.dir, ".gitignore", "node_modules/\n")
	gitforge.Git(t, tools, f.home, f.dir, "-C", f.dir, "-c", "user.name=t", "-c", "user.email=t@t", "add", ".gitignore")
	gitforge.Git(t, tools, f.home, f.dir, "-C", f.dir, "-c", "user.name=t", "-c", "user.email=t@t",
		"commit", "-qm", "a commit of the last run's own")
	gitforge.Git(t, tools, f.home, f.dir, "-C", f.dir, "checkout", "-qb", "feature")
	if err := os.WriteFile(filepath.Join(f.dir, tracked), []byte("changed by the last run\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitforge.WriteFile(t, f.dir, "stray.txt", "left behind\n")
	gitforge.WriteFile(t, f.dir, "node_modules/dep/index.js", "cached\n")

	// Upstream moves on.
	next := f.forge.AddFile(t, owner, repo, gitforge.DefaultBranch, "NEW.md", "new\n", "upstream moved")

	f.emitted.Reset()
	if err := f.pristineProvision(""); err != nil {
		t.Fatalf("second provisioning: %v\nlog:\n%s", err, f.log())
	}
	if !strings.Contains(f.log(), "reusing the existing checkout") || strings.Contains(f.log(), "discarding") {
		t.Fatalf("the kept checkout was not reused\nlog:\n%s", f.log())
	}
	if head := headOf(t, f); head != next {
		t.Fatalf("HEAD is %s, want the fetched %s", head, next)
	}
	for _, gone := range []string{"stray.txt", ".gitignore"} {
		if _, err := os.Stat(filepath.Join(f.dir, gone)); err == nil {
			t.Errorf("%s survived the reset", gone)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(f.dir, tracked)); strings.Contains(string(b), "changed by the last run") {
		t.Errorf("%s keeps the last run's change", tracked)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "NEW.md")); err != nil {
		t.Errorf("the fetched commit's file is missing: %v", err)
	}
	f.assertNoLeak(nil)
}

// TestAKeptCheckoutsConfigurationIsRewritten: the last run wrote its
// .git/config — a proxy and a disabled certificate check, an insteadOf, a
// filter, an include, a hooks path — which the next fetch would obey with
// the next run's credential in its environment. The checkout is kept, its
// configuration rewritten to what a checkout needs, and the fetch goes
// nowhere near the proxy.
func TestAKeptCheckoutsConfigurationIsRewritten(t *testing.T) {
	for name, poison := range map[string][][2]string{
		"proxy":     {{"http.proxy", "http://127.0.0.1:9"}, {"http.sslVerify", "false"}},
		"insteadOf": {{"url.https://evil.invalid/.insteadOf", "https://"}},
		"filter":    {{"filter.lfs.smudge", "touch /tmp/pwned"}},
		"include":   {{"include.path", "/tmp/elsewhere"}},
		"hooks":     {{"core.hooksPath", ".husky/_"}},
		"case":      {{"core.ignorecase", "true"}},
		"refspec":   {{"remote.origin.fetch", "+refs/tags/*:refs/heads/*"}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, gitforge.Options{})
			if err := f.pristineProvision(""); err != nil {
				t.Fatalf("first provisioning: %v\nlog:\n%s", err, f.log())
			}
			tools := gitforge.RequireGit(t)
			for _, kv := range poison {
				gitforge.Git(t, tools, f.home, f.dir, "-C", f.dir, "config", "--local", kv[0], kv[1])
			}
			f.emitted.Reset()
			if err := f.pristineProvision(""); err != nil {
				t.Fatalf("second provisioning: %v\nlog:\n%s", err, f.log())
			}
			if strings.Contains(f.log(), "discarding the kept checkout") || !strings.Contains(f.log(), "dropped") {
				t.Fatalf("the configuration was not rewritten in place\nlog:\n%s", f.log())
			}
			for _, kv := range poison {
				if kv[0] == "remote.origin.fetch" {
					if got := gitConfig(t, f, kv[0]); got != "+refs/heads/*:refs/remotes/origin/*" {
						t.Errorf("the fetch refspec is %q", got)
					}
					continue
				}
				// Exit 1 with nothing printed is git's "not set".
				if v, err := gitforge.TryGit(t, tools, f.home, f.dir, "-C", f.dir, "config", "--local", "--get", kv[0]); err == nil || strings.TrimSpace(v) != "" {
					t.Errorf("%s survived as %q", kv[0], v)
				}
			}
			if got := gitConfig(t, f, "remote.origin.url"); got != f.ws.Repo {
				t.Errorf("origin is %q", got)
			}
			f.assertNoLeak(nil)
		})
	}
}

// TestAKeptCheckoutOfAnotherRepositoryIsReplaced: on a runner's volume the
// refusal a permanent device gives would strand the project; the checkout is
// the hub's copy and is cloned afresh instead.
func TestAKeptCheckoutOfAnotherRepositoryIsReplaced(t *testing.T) {
	f := newFixture(t, gitforge.Options{})
	if err := f.pristineProvision(""); err != nil {
		t.Fatalf("first provisioning: %v\nlog:\n%s", err, f.log())
	}
	f.forge.Create(t, owner, "renamed")
	f.ws.Repo = f.forge.RepoURL(owner, "renamed")
	f.emitted.Reset()
	if err := f.pristineProvision(""); err != nil {
		t.Fatalf("provisioning another repository: %v\nlog:\n%s", err, f.log())
	}
	if got := gitConfig(t, f, "remote.origin.url"); got != f.ws.Repo {
		t.Fatalf("origin is %q", got)
	}
}

// TestTheObjectCacheFeedsAFreshCheckout: the second fresh checkout of a
// repository takes its objects from the cache, and the fetch after it sends
// only what is new.
func TestTheObjectCacheFeedsAFreshCheckout(t *testing.T) {
	f := newFixture(t, gitforge.Options{})
	f.ws.Depth = 0
	cache := filepath.Join(t.TempDir(), "git-cache")
	if err := f.pristineProvision(cache); err != nil {
		t.Fatalf("first provisioning: %v\nlog:\n%s", err, f.log())
	}
	entries, err := os.ReadDir(cache)
	if err != nil || len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".git") {
		t.Fatalf("the cache holds %v (%v)", entries, err)
	}
	next := f.forge.AddFile(t, owner, repo, gitforge.DefaultBranch, "NEW.md", "new\n", "upstream moved")

	// A fresh directory: the same repository for a tree whose workspace was
	// wiped, or another tree of the same project.
	f.dir = filepath.Join(t.TempDir(), "workspace-2")
	f.emitted.Reset()
	if err := f.pristineProvision(cache); err != nil {
		t.Fatalf("second provisioning: %v\nlog:\n%s", err, f.log())
	}
	if !strings.Contains(f.log(), "took what the git object cache holds") {
		t.Fatalf("the cache was not used\nlog:\n%s", f.log())
	}
	if head := headOf(t, f); head != next {
		t.Fatalf("HEAD is %s, want %s", head, next)
	}
	tools := gitforge.RequireGit(t)
	if refs := gitforge.Git(t, tools, f.home, f.dir, "-C", f.dir, "for-each-ref", "refs/cloop-cache/"); strings.TrimSpace(refs) != "" {
		t.Errorf("the cache's refs were left in the checkout: %s", refs)
	}
	// A cache whose configuration was tampered with is removed, not used.
	repoDir := filepath.Join(cache, entries[0].Name())
	gitforge.Git(t, tools, f.home, repoDir, "--git-dir", repoDir, "config", "core.sshCommand", "touch /tmp/pwned")
	f.dir = filepath.Join(t.TempDir(), "workspace-3")
	f.emitted.Reset()
	if err := f.pristineProvision(cache); err != nil {
		t.Fatalf("third provisioning: %v\nlog:\n%s", err, f.log())
	}
	if !strings.Contains(f.log(), "cannot be trusted") || strings.Contains(f.log(), "took what the git object cache holds") {
		t.Fatalf("a tampered cache was used\nlog:\n%s", f.log())
	}
	f.assertNoLeak(nil)
}

// firstTrackedFile names a file the fixture repository tracks.
func firstTrackedFile(t *testing.T, f *fixture) string {
	t.Helper()
	tools := gitforge.RequireGit(t)
	out := gitforge.Git(t, tools, f.home, f.dir, "-C", f.dir, "ls-files")
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line != "" && !strings.HasPrefix(line, ".cloop") {
			return line
		}
	}
	t.Fatal("the fixture repository tracks no file")
	return ""
}

func contextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 2*time.Minute)
}

func provisionWith(ctx context.Context, req gitprovision.Request) error {
	return gitprovision.Provision(ctx, req)
}

// TestTheObjectCacheWorksWithoutAKeptWorkspace: a runner whose workspace is
// not kept still takes objects from the cache; a kept checkout that was not
// vetted (a permanent device's) never feeds it.
func TestTheObjectCacheWorksWithoutAKeptWorkspace(t *testing.T) {
	f := newFixture(t, gitforge.Options{})
	f.ws.Depth = 0
	cache := filepath.Join(t.TempDir(), "git-cache")
	provision := func() error {
		req := f.request()
		req.ObjectCache = cache
		ctx, cancel := contextWithTimeout()
		defer cancel()
		return provisionWith(ctx, req)
	}
	if err := provision(); err != nil {
		t.Fatalf("first provisioning: %v\nlog:\n%s", err, f.log())
	}
	entries, _ := os.ReadDir(cache)
	if len(entries) != 1 {
		t.Fatalf("a fresh checkout did not fill the cache: %v", entries)
	}
	f.dir = filepath.Join(t.TempDir(), "workspace-2")
	f.emitted.Reset()
	if err := provision(); err != nil {
		t.Fatalf("second provisioning: %v\nlog:\n%s", err, f.log())
	}
	if !strings.Contains(f.log(), "took what the git object cache holds") {
		t.Fatalf("the cache was not used\nlog:\n%s", f.log())
	}
	// Reused without vetting: the cache is not refreshed from it.
	repoDir := filepath.Join(cache, entries[0].Name())
	before, _ := os.ReadFile(filepath.Join(repoDir, "packed-refs"))
	refsBefore := gitforge.Git(t, gitforge.RequireGit(t), f.home, repoDir, "--git-dir", repoDir, "for-each-ref")
	f.forge.AddFile(t, owner, repo, gitforge.DefaultBranch, "NEWER.md", "newer\n", "upstream moved")
	f.emitted.Reset()
	if err := provision(); err != nil {
		t.Fatalf("third provisioning: %v\nlog:\n%s", err, f.log())
	}
	if refsAfter := gitforge.Git(t, gitforge.RequireGit(t), f.home, repoDir, "--git-dir", repoDir, "for-each-ref"); refsAfter != refsBefore {
		t.Fatalf("an unvetted kept checkout refreshed the cache: %q → %q (%d bytes of packed-refs before)", refsBefore,
			refsAfter, len(before))
	}
}

// TestAHookTheLastRunPlantedNeverRuns: a reference-transaction hook runs on
// every fetch that moves a ref, with the fetch's environment — the
// credential among it. Provisioning runs no hook of a kept checkout's, and
// the reset removes them, so the next run's own git runs none either.
func TestAHookTheLastRunPlantedNeverRuns(t *testing.T) {
	f := newFixture(t, gitforge.Options{})
	f.ws.Depth = 0
	if err := f.pristineProvision(""); err != nil {
		t.Fatalf("first provisioning: %v\nlog:\n%s", err, f.log())
	}
	marker := filepath.Join(t.TempDir(), "hook-ran")
	for _, hook := range []string{"reference-transaction", "post-checkout", "pre-auto-gc"} {
		gitforge.WriteFile(t, f.dir, ".git/hooks/"+hook, "#!/bin/sh\nenv >> "+marker+"\n")
		if err := os.Chmod(filepath.Join(f.dir, ".git", "hooks", hook), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.forge.AddFile(t, owner, repo, gitforge.DefaultBranch, "NEW.md", "new\n", "upstream moved")
	f.emitted.Reset()
	if err := f.pristineProvision(""); err != nil {
		t.Fatalf("second provisioning: %v\nlog:\n%s", err, f.log())
	}
	if b, err := os.ReadFile(marker); err == nil {
		t.Fatalf("a planted hook ran during provisioning; it saw:\n%s", b)
	}
	if entries, _ := os.ReadDir(filepath.Join(f.dir, ".git", "hooks")); len(entries) != 0 {
		t.Fatalf("the planted hooks outlived the reset: %v", entries)
	}
	f.assertNoLeak(nil)
}

func TestAKeptCheckoutThatPointsItsFetchElsewhereIsDiscarded(t *testing.T) {
	for name, tamper := range map[string]func(t *testing.T, f *fixture, tools gitforge.Tools){
		"a second origin url": func(t *testing.T, f *fixture, tools gitforge.Tools) {
			other := f.forge.RepoURL(owner, "other")
			f.forge.Create(t, owner, "other")
			gitforge.Git(t, tools, f.home, f.dir, "-C", f.dir, "config", "--add", "remote.origin.url", other)
		},
		"no .git at all": func(t *testing.T, f *fixture, tools gitforge.Tools) {
			if err := os.RemoveAll(filepath.Join(f.dir, ".git")); err != nil {
				t.Fatal(err)
			}
		},
		"a ref lock a killed fetch left": func(t *testing.T, f *fixture, tools gitforge.Tools) {
			gitforge.WriteFile(t, f.dir, ".git/refs/remotes/origin/"+gitforge.DefaultBranch+".lock", "")
			f.forge.AddFile(t, owner, repo, gitforge.DefaultBranch, "LOCKED.md", "x\n", "upstream moved")
		},
		"replacement refs": func(t *testing.T, f *fixture, tools gitforge.Tools) {
			head := strings.TrimSpace(gitforge.Git(t, tools, f.home, f.dir, "-C", f.dir, "rev-parse", "HEAD"))
			gitforge.Git(t, tools, f.home, f.dir, "-C", f.dir, "update-ref", "refs/replace/"+head, head)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, gitforge.Options{})
			if err := f.pristineProvision(""); err != nil {
				t.Fatalf("first provisioning: %v\nlog:\n%s", err, f.log())
			}
			tamper(t, f, gitforge.RequireGit(t))
			f.emitted.Reset()
			if err := f.pristineProvision(""); err != nil {
				t.Fatalf("second provisioning: %v\nlog:\n%s", err, f.log())
			}
			if !strings.Contains(f.log(), "discarding the kept checkout") {
				t.Fatalf("a checkout that cannot be used as it is was reused\nlog:\n%s", f.log())
			}
			if got := gitConfig(t, f, "remote.origin.url"); got != f.ws.Repo {
				t.Fatalf("origin is %q", got)
			}
		})
	}
}

// TestATrackedFileChangedWithItsTimestampsKeptIsRestored: git trusts an index
// entry whose size and times match the file; the reset writes every tracked
// file from the fetched objects instead.
func TestATrackedFileChangedWithItsTimestampsKeptIsRestored(t *testing.T) {
	f := newFixture(t, gitforge.Options{})
	if err := f.pristineProvision(""); err != nil {
		t.Fatalf("first provisioning: %v\nlog:\n%s", err, f.log())
	}
	tracked := firstTrackedFile(t, f)
	path := filepath.Join(f.dir, tracked)
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	forged := []byte(strings.Repeat("X", len(orig)))
	if err := os.WriteFile(path, forged, info.Mode()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	f.emitted.Reset()
	if err := f.pristineProvision(""); err != nil {
		t.Fatalf("second provisioning: %v\nlog:\n%s", err, f.log())
	}
	if got, _ := os.ReadFile(path); string(got) != string(orig) {
		t.Fatalf("%s still holds what the last run wrote: %q", tracked, got)
	}
}

// TestAKeptBuildCacheSurvivesAndIsNotHeldToTheTreesLimit: what the project
// ignores — node_modules here — is the cache a kept workspace exists for; the
// reset keeps it, and the provisioned tree's disk limit, which a fresh clone
// is held to, is not applied to it.
func TestAKeptBuildCacheSurvivesAndIsNotHeldToTheTreesLimit(t *testing.T) {
	f := newFixture(t, gitforge.Options{})
	f.forge.AddFile(t, owner, repo, gitforge.DefaultBranch, ".gitignore", "node_modules/\n", "ignore the build cache")
	f.ws.SizeLimitMB = 1
	if err := f.pristineProvision(""); err != nil {
		t.Fatalf("first provisioning: %v\nlog:\n%s", err, f.log())
	}
	gitforge.WriteFile(t, f.dir, "node_modules/dep/big.bin", incompressible(2<<20))
	f.emitted.Reset()
	if err := f.pristineProvision(""); err != nil {
		t.Fatalf("second provisioning: %v\nlog:\n%s", err, f.log())
	}
	if strings.Contains(f.log(), "discarding") {
		t.Fatalf("the kept checkout was discarded\nlog:\n%s", f.log())
	}
	if _, err := os.Stat(filepath.Join(f.dir, "node_modules", "dep", "big.bin")); err != nil {
		t.Fatalf("the build cache did not survive: %v", err)
	}
}
