package secretbroker

// Tests for KindLocalRepo (Task 20187).
//
// The bulk of these are containment tests, because this is the one credential
// kind whose delivered material is a path into the control plane's own
// filesystem. Everything else here narrows bytes; this narrows *reach*, and the
// failure mode of getting it wrong is a sandbox with a bind mount of / rather
// than a leaked token.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mintLocalRepo stores a local_repo secret whose payload is root.
func mintLocalRepo(t *testing.T, b *Broker, name, root string) Secret {
	t.Helper()
	s, err := b.Mint(context.Background(), MintRequest{
		Name:    name,
		Kind:    KindLocalRepo,
		Payload: []byte(root),
		Actor:   "test",
	})
	if err != nil {
		t.Fatalf("mint %s: %v", name, err)
	}
	return s
}

// mkRepo creates a directory that isGitRepo will accept.
func mkRepo(t *testing.T, root, name string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatalf("create repo %s: %v", name, err)
	}
	return dir
}

// mkPlain creates a directory that is not a repository.
func mkPlain(t *testing.T, root, name string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create dir %s: %v", name, err)
	}
	return dir
}

func TestParseLocalRepoRootRejectsUnusablePaths(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, payload := range map[string]string{
		"empty":           "",
		"relative":        "relative/path",
		"missing":         filepath.Join(dir, "nope"),
		"a file":          file,
		"NUL":             "/tmp/a\x00b",
		"newline":         "/tmp/a\nb",
		"filesystem root": "/",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseLocalRepoRoot([]byte(payload)); err == nil {
				t.Fatalf("accepted %q; a local_repo payload that is not a usable directory "+
					"must fail at mint time, not during someone's run", payload)
			}
		})
	}
}

func TestParseLocalRepoRootResolvesSymlinkedRoot(t *testing.T) {
	// A root that is itself a symlink is ordinary (/home/dev/src ->
	// /mnt/big/src) and must be accepted, resolved.
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	got, err := ParseLocalRepoRoot([]byte(link))
	if err != nil {
		t.Fatalf("symlinked root rejected: %v", err)
	}
	want, _ := filepath.EvalSymlinks(real)
	if got != want {
		t.Errorf("root = %q, want the resolved %q — every containment check "+
			"compares against this, so it must be the resolved form", got, want)
	}
}

func TestSelectReposHonoursAllowlist(t *testing.T) {
	root := t.TempDir()
	mkRepo(t, root, "api")
	mkRepo(t, root, "shared-models")
	mkRepo(t, root, "shared-utils")
	mkRepo(t, root, "unrelated")
	mkPlain(t, root, "not-a-repo")

	got, err := selectRepos(root, Constraints{Repos: []string{"api", "shared-*"}})
	if err != nil {
		t.Fatalf("selectRepos: %v", err)
	}
	var names []string
	for _, r := range got {
		names = append(names, r.name)
	}
	want := "api,shared-models,shared-utils"
	if strings.Join(names, ",") != want {
		t.Errorf("selected %v, want %s (sorted, allowlisted, git-only)", names, want)
	}
}

func TestSelectReposEmptyAllowlistMatchesNothing(t *testing.T) {
	// ValidateFor already refuses to create such a grant. This is the second
	// place that reading is unavailable: an allowlist falling open when empty
	// would turn a storage bug into the whole root.
	root := t.TempDir()
	mkRepo(t, root, "api")

	got, err := selectRepos(root, Constraints{})
	if err != nil {
		t.Fatalf("selectRepos: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("an empty allowlist selected %d repositories; it must select none", len(got))
	}
}

func TestSelectReposRefusesSymlinkEscape(t *testing.T) {
	// The core containment property. A symlink under the granted root — put
	// there by a dependency's postinstall, a tarball, anything that has ever
	// written to the tree — must not redirect a bind out of the root.
	root := t.TempDir()
	outside := t.TempDir()
	mkRepo(t, outside, "secrets")

	if err := os.Symlink(filepath.Join(outside, "secrets"), filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// And a link straight to the filesystem root, which is the version that
	// matters most.
	if err := os.Symlink("/", filepath.Join(root, "everything")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	got, err := selectRepos(root, Constraints{Repos: []string{"*"}})
	if err != nil {
		t.Fatalf("selectRepos: %v", err)
	}
	for _, r := range got {
		if !strings.HasPrefix(r.path, root) {
			t.Errorf("selected %s at %s, which is outside the granted root %s", r.name, r.path, root)
		}
	}
	if len(got) != 0 {
		t.Errorf("selected %d entries; both were symlinks leaving the root and "+
			"must have been dropped", len(got))
	}
}

func TestSelectReposFollowsSymlinkWithinRoot(t *testing.T) {
	// The converse: a symlinked checkout that stays inside the root is a
	// normal way to arrange a source tree and must still be found. Without
	// this, the containment check would be indistinguishable from "ignore all
	// symlinks", which is a different and worse feature.
	root := t.TempDir()
	mkRepo(t, root, "real-api")
	if err := os.Symlink(filepath.Join(root, "real-api"), filepath.Join(root, "api")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	got, err := selectRepos(root, Constraints{Repos: []string{"api"}})
	if err != nil {
		t.Fatalf("selectRepos: %v", err)
	}
	if len(got) != 1 || got[0].name != "api" {
		t.Fatalf("selected %v, want the in-root symlink 'api'", got)
	}
}

func TestSelectReposAcceptsRootThatIsItselfARepo(t *testing.T) {
	base := t.TempDir()
	repo := mkRepo(t, base, "solo")

	got, err := selectRepos(repo, Constraints{Repos: []string{"solo"}})
	if err != nil {
		t.Fatalf("selectRepos: %v", err)
	}
	if len(got) != 1 || got[0].name != "solo" {
		t.Fatalf("selected %v, want the root itself", got)
	}

	// Still subject to the allowlist: pointing the secret at a repository
	// rather than a tree must not make the grant broader.
	denied, err := selectRepos(repo, Constraints{Repos: []string{"something-else"}})
	if err != nil {
		t.Fatalf("selectRepos: %v", err)
	}
	if len(denied) != 0 {
		t.Errorf("a root that is itself a repo bypassed the allowlist: %v", denied)
	}
}

func TestSelectReposSkipsNamesThatCannotBeBound(t *testing.T) {
	// A directory named with a colon would append mount options to the
	// runtime's -v flag. It is skipped rather than fatal: it is a property of
	// what happens to be in the directory, so failing the lease would let
	// anyone who can write to the root break an unrelated project's runs.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "evil:ro", ".git"), 0o755); err != nil {
		t.Skipf("cannot create a colon-named directory here: %v", err)
	}
	mkRepo(t, root, "good")

	got, err := selectRepos(root, Constraints{Repos: []string{"*"}})
	if err != nil {
		t.Fatalf("selectRepos: %v", err)
	}
	if len(got) != 1 || got[0].name != "good" {
		t.Fatalf("selected %v, want only 'good' — the colon-named entry must be skipped", got)
	}
}

func TestValidRepoNameRejectsSeparatorsAndControls(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "a/b", `a\b`, "a:b", "a\x00b", "a\nb", strings.Repeat("x", 129)} {
		if err := validRepoName(bad); err == nil {
			t.Errorf("accepted repository name %q", bad)
		}
	}
	for _, ok := range []string{"api", "my-service", "my_service", "v1.2", "UPPER"} {
		if err := validRepoName(ok); err != nil {
			t.Errorf("rejected ordinary repository name %q: %v", ok, err)
		}
	}
}

func TestRepoMountValidateRejectsReinterpretablePaths(t *testing.T) {
	base := RepoMount{Name: "api", Source: "/src/api", Target: "/repos/api"}
	if err := base.validate(); err != nil {
		t.Fatalf("rejected a well-formed mount: %v", err)
	}
	for name, m := range map[string]RepoMount{
		"relative source": {Name: "api", Source: "src/api", Target: "/repos/api"},
		"relative target": {Name: "api", Source: "/src/api", Target: "repos/api"},
		"colon in source": {Name: "api", Source: "/src:/etc", Target: "/repos/api"},
		"colon in target": {Name: "api", Source: "/src/api", Target: "/repos:/etc"},
		"empty source":    {Name: "api", Target: "/repos/api"},
		"empty target":    {Name: "api", Source: "/src/api"},
		"bad name":        {Name: "a/b", Source: "/src/api", Target: "/repos/api"},
	} {
		if err := m.validate(); err == nil {
			t.Errorf("%s: accepted %+v", name, m)
		}
	}
}

func TestConstraintsValidateForLocalRepo(t *testing.T) {
	// A local_repo grant with no allowlist is the whole root, which there is
	// no safe default for.
	if err := (Constraints{}).ValidateFor(KindLocalRepo); err == nil {
		t.Error("accepted a local_repo grant with no repository allowlist")
	}
	if err := (Constraints{Repos: []string{"api"}}).ValidateFor(KindLocalRepo); err != nil {
		t.Errorf("rejected a well-formed local_repo grant: %v", err)
	}
	if err := (Constraints{Repos: []string{"api"}, Writable: true}).ValidateFor(KindLocalRepo); err != nil {
		t.Errorf("rejected a writable local_repo grant: %v", err)
	}
	// writable is meaningless everywhere else, and silently ignoring it would
	// let an operator believe they had asked for something.
	if err := (Constraints{Repos: []string{"o/r"}, Writable: true}).ValidateFor(KindGitHubPAT); err == nil {
		t.Error("accepted writable on a github_pat grant")
	}
	if !errors.Is((Constraints{}).ValidateFor(KindLocalRepo), ErrInvalidConstraint) {
		t.Error("the refusal does not chain ErrInvalidConstraint")
	}
}

func TestLocalRepoKindIsRegistered(t *testing.T) {
	if !KindLocalRepo.Valid() {
		t.Fatal("KindLocalRepo is not Valid()")
	}
	got, err := ParseKind("local_repo")
	if err != nil || got != KindLocalRepo {
		t.Fatalf("ParseKind(local_repo) = %q, %v", got, err)
	}
	var listed bool
	for _, k := range Kinds() {
		if k == KindLocalRepo {
			listed = true
		}
	}
	if !listed {
		t.Error("KindLocalRepo missing from Kinds(), so it is invisible to CLI help and the dashboard")
	}
}

func TestConstraintsSummaryMentionsWritableOnlyWhenTrue(t *testing.T) {
	ro := Constraints{Repos: []string{"api"}}.Summary()
	if strings.Contains(ro, "writable") {
		t.Errorf("read-only summary %q mentions writable; the absence is what read-only means", ro)
	}
	rw := Constraints{Repos: []string{"api"}, Writable: true}.Summary()
	if !strings.Contains(rw, "writable") {
		t.Errorf("writable summary %q does not say so", rw)
	}
}

// --- end-to-end through the broker ------------------------------------------

func TestLocalRepoLeaseDeliversMountsNotBytes(t *testing.T) {
	root := t.TempDir()
	mkRepo(t, root, "api")
	mkRepo(t, root, "shared")
	mkRepo(t, root, "private")

	b, _, _, _ := newTestBroker(t)
	sec := mintLocalRepo(t, b, "dev-src", root)
	grantTo(t, b, sec.ID, "project:/srv/app", Constraints{Repos: []string{"api", "shared"}}, time.Hour)

	lease, err := b.Lease(context.Background(), "exec-1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if len(lease.Materials) != 1 {
		t.Fatalf("got %d materials, want 1", len(lease.Materials))
	}
	mat := lease.Materials[0]

	if len(mat.Files) != 0 {
		t.Errorf("a local_repo material wrote %d files; it delivers a mount, not bytes", len(mat.Files))
	}
	if len(mat.Mounts) != 2 {
		t.Fatalf("got %d mounts, want 2 (api, shared)", len(mat.Mounts))
	}
	for _, m := range mat.Mounts {
		if !m.ReadOnly {
			t.Errorf("mount %s is read-write; a grant that did not ask for writable must be read-only", m.Name)
		}
		if want := "/repos/" + m.Name; m.Target != want {
			t.Errorf("mount %s target = %q, want %q", m.Name, m.Target, want)
		}
		if m.Name == "private" {
			t.Error("delivered a repository outside the allowlist")
		}
	}
	if got := mat.Env["CLOOP_LOCAL_REPOS"]; got != "api,shared" {
		t.Errorf("CLOOP_LOCAL_REPOS = %q, want %q", got, "api,shared")
	}
	// The host layout is the hub's business: it must not ride into a harness
	// environment and from there into a model context and a log.
	for k, v := range mat.Env {
		if strings.Contains(v, root) {
			t.Errorf("env %s leaks the host path %q", k, root)
		}
	}
}

func TestLocalRepoWritableGrantDeliversReadWrite(t *testing.T) {
	root := t.TempDir()
	mkRepo(t, root, "api")

	b, _, _, _ := newTestBroker(t)
	sec := mintLocalRepo(t, b, "dev-src", root)
	grantTo(t, b, sec.ID, "project:/srv/app", Constraints{Repos: []string{"api"}, Writable: true}, time.Hour)

	lease, err := b.Lease(context.Background(), "exec-1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	m := lease.Materials[0].Mounts[0]
	if m.ReadOnly {
		t.Error("a writable grant delivered a read-only mount")
	}
	if !strings.Contains(lease.Materials[0].Summary, "read-write") {
		t.Errorf("summary %q does not record that this is read-write", lease.Materials[0].Summary)
	}
}

func TestLocalRepoGrantMatchingNothingFails(t *testing.T) {
	// Delivering an empty /repos would let the harness discover the problem as
	// a missing directory several minutes in.
	root := t.TempDir()
	mkRepo(t, root, "api")

	b, _, _, _ := newTestBroker(t)
	sec := mintLocalRepo(t, b, "dev-src", root)
	grantTo(t, b, sec.ID, "project:/srv/app", Constraints{Repos: []string{"does-not-exist"}}, time.Hour)

	lease, err := b.Lease(context.Background(), "exec-1", "/srv/app")
	// The broker's policy is that one denied grant does not fail the lease, so
	// assert on what was delivered rather than on the error.
	if err == nil && !lease.Empty() {
		for _, m := range lease.Materials {
			if len(m.Mounts) > 0 {
				t.Fatalf("delivered %d mounts for an allowlist matching nothing", len(m.Mounts))
			}
		}
	}
}

func TestLocalRepoBareRepositoryIsFound(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	bare := filepath.Join(root, "mirror.git")
	if err := exec.Command("git", "init", "--bare", bare).Run(); err != nil {
		t.Skipf("git init --bare: %v", err)
	}
	got, err := selectRepos(root, Constraints{Repos: []string{"*"}})
	if err != nil {
		t.Fatalf("selectRepos: %v", err)
	}
	if len(got) != 1 || got[0].name != "mirror.git" {
		t.Fatalf("selected %v, want the bare repository", got)
	}
}

// --- regressions found by review ---------------------------------------------

// TestParseLocalRepoRootRejectsColonInTheRoot is a regression test with an
// outsized blast radius.
//
// A colon is unexpressible as a bind source, but it used to be caught only at
// Materialize time — and a Materialize failure fails the *whole lease*, which
// acquireSecretLease reports as "no credentials" and continues. So a developer
// whose source tree happened to live under a path containing a colon silently
// lost this project's GitHub token and kubeconfig too, on every run, with one
// line on stderr. It has to fail at mint time, which is what ParseLocalRepoRoot
// is for.
func TestParseLocalRepoRootRejectsColonInTheRoot(t *testing.T) {
	base := t.TempDir()
	for _, name := range []string{"my:src", `back\slash`} {
		dir := filepath.Join(base, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Skipf("cannot create %q here: %v", name, err)
		}
		if _, err := ParseLocalRepoRoot([]byte(dir)); err == nil {
			t.Errorf("accepted a root containing %q; it would fail the entire lease at "+
				"materialisation and strip this project's unrelated credentials", name)
		}
	}
}

// TestSelectReposMatchesCaseSensitively is a regression test.
//
// The matcher folded case, borrowed from the github matcher beside it. GitHub
// repository names genuinely are case-insensitive; POSIX directory names are
// not, so a grant on "api" was also opening "API" and "ApI" — two unrelated
// repositories the operator never named.
func TestSelectReposMatchesCaseSensitively(t *testing.T) {
	root := t.TempDir()
	for _, n := range []string{"api", "API", "ApI"} {
		if err := os.MkdirAll(filepath.Join(root, n, ".git"), 0o755); err != nil {
			t.Skipf("case-insensitive filesystem: %v", err)
		}
	}
	// Confirm the filesystem really does distinguish them, or the test proves
	// nothing (macOS).
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 3 {
		t.Skip("filesystem does not distinguish case; nothing to assert")
	}

	got, err := selectRepos(root, Constraints{Repos: []string{"api"}})
	if err != nil {
		t.Fatalf("selectRepos: %v", err)
	}
	if len(got) != 1 || got[0].name != "api" {
		var names []string
		for _, r := range got {
			names = append(names, r.name)
		}
		t.Fatalf("selected %v, want only [api]; case folding opened repositories the "+
			"operator did not name", names)
	}
}

// TestRepoMountValidateRequiresTheDerivedTarget pins the invariant that the
// target is derived rather than supplied, so a tampered Material cannot point
// a bind somewhere else.
func TestRepoMountValidateRequiresTheDerivedTarget(t *testing.T) {
	if err := (RepoMount{Name: "api", Source: "/src/api", Target: "/etc"}).validate(); err == nil {
		t.Error("accepted a repo mount whose target is not the derived /repos/<name>")
	}
	if err := (RepoMount{Name: "api", Source: "/src/api", Target: "/repos/api"}).validate(); err != nil {
		t.Errorf("rejected the derived target: %v", err)
	}
}
