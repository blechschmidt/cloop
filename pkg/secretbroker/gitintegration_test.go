package secretbroker

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The claim this package makes about github_pat is that a repository
// allowlist is enforced rather than documented. githubpat_test.go checks the
// generated script against /bin/sh; this file checks it against the program
// that actually invokes it.
//
// That distinction matters, because between the script and the enforcement
// sit two things sh cannot exercise: whether git's credential.helper "!"
// form finds the script through $CLOOP_LEASE_DIR, and whether
// credential.useHttpPath is really on — without which git never sends the
// repository path and the allowlist has nothing to match against. Either one
// silently misconfigured would produce a helper that answers every request
// or none, and the sh-level test would still pass.

// gitCredentialFill asks git to resolve a credential for repoURL using only
// the configuration and helper the lease materialised, and returns what git
// came back with.
func gitCredentialFill(t *testing.T, mount *Mount, repoURL string) string {
	t.Helper()

	u := strings.TrimPrefix(repoURL, "https://")
	host, path, _ := strings.Cut(u, "/")

	cmd := exec.Command("git", "credential", "fill")
	cmd.Stdin = strings.NewReader("protocol=https\nhost=" + host + "\npath=" + path + "\n\n")

	// A pristine environment plus exactly what the lease provides. HOME is
	// redirected at a scratch directory so a real ~/.gitconfig on the test
	// machine cannot supply a credential and make a denial look like an
	// allow.
	home := t.TempDir()
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"GIT_TERMINAL_PROMPT=0", // never block waiting for a human
		"GIT_ASKPASS=true",      // ... or for an askpass helper
		"GIT_CONFIG_NOSYSTEM=1", // ignore /etc/gitconfig
	}, mount.Env()...)

	out, _ := cmd.CombinedOutput()
	return string(out)
}

// newGitHubLease materialises a github_pat lease with the given allowlist.
func newGitHubLease(t *testing.T, token string, repos []string) *Mount {
	t.Helper()

	b, _, _, _ := newTestBroker(t)
	s := mintGitHub(t, b, "gitpat", token)
	grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: repos}, time.Hour)

	lease, err := b.Lease(t.Context(), "e1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if len(lease.Materials) != 1 {
		t.Fatalf("got %d materials, want 1", len(lease.Materials))
	}
	mount, err := lease.Materialize(t.TempDir())
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	t.Cleanup(func() { _ = mount.Close() })
	return mount
}

// TestGitHonoursRepoAllowlist drives the whole delivery path with real git.
func TestGitHonoursRepoAllowlist(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	const token = "ghp_gitintegrationcanary"

	tests := []struct {
		name  string
		repos []string
		url   string
		allow bool
	}{
		{"owner glob allows own repo", []string{"org/*"}, "https://github.com/org/tool", true},
		{"owner glob denies other owner", []string{"org/*"}, "https://github.com/other/tool", false},
		{"exact pattern allows", []string{"org/tool"}, "https://github.com/org/tool", true},
		{"exact pattern denies sibling", []string{"org/tool"}, "https://github.com/org/other", false},
		// path.Match's "*" does not cross "/", and the generated helper's
		// single-slash guard makes shell globbing agree. Without that guard
		// the shell would match here and quietly be the wider of the two.
		{"extra path segment denied", []string{"org/*"}, "https://github.com/org/sub/tool", false},
		{"wildcard allows anything", []string{"*"}, "https://github.com/anyone/anything", true},
		// A host the grant says nothing about must get nothing, even under
		// a "*" repo allowlist: the allowlist scopes repositories, not the
		// internet.
		{"other host denied", []string{"*"}, "https://gitlab.com/org/tool", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mount := newGitHubLease(t, token, tc.repos)
			out := gitCredentialFill(t, mount, tc.url)

			got := strings.Contains(out, "password="+token)
			if got != tc.allow {
				t.Errorf("git credential fill for %s with repos=%v: token released=%v, want %v\ngit said:\n%s",
					tc.url, tc.repos, got, tc.allow, out)
			}
			if tc.allow && !strings.Contains(out, "username=x-access-token") {
				t.Errorf("expected the x-access-token username, git said:\n%s", out)
			}
		})
	}
}

// TestGitConfigEnablesHTTPPath guards the configuration bit the whole
// mechanism rests on. If useHttpPath were off, git would send only the host,
// every repository would look identical to the helper, and an "org/*" grant
// would effectively become "*".
func TestGitConfigEnablesHTTPPath(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	mount := newGitHubLease(t, "ghp_confcanary", []string{"org/*"})

	cmd := exec.Command("git", "config", "--global", "--get", "credential.useHttpPath")
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
	}, mount.Env()...)

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git config --get credential.useHttpPath: %v", err)
	}
	if strings.TrimSpace(string(out)) != "true" {
		t.Fatalf("credential.useHttpPath = %q, want true", strings.TrimSpace(string(out)))
	}
}

// TestLeaseFilePermissions: the token file sits on a filesystem for the life
// of the lease, so it must not be readable by other users on the host.
func TestLeaseFilePermissions(t *testing.T) {
	mount := newGitHubLease(t, "ghp_permcanary", []string{"org/*"})

	info, err := os.Stat(mount.Dir)
	if err != nil {
		t.Fatalf("stat lease dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("lease dir mode = %04o, want 0700", perm)
	}

	tokenPath := filepath.Join(mount.Dir, tokenFileName)
	tinfo, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if perm := tinfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("token file mode = %04o, want 0600", perm)
	}

	helperPath := filepath.Join(mount.Dir, credentialHelperName)
	hinfo, err := os.Stat(helperPath)
	if err != nil {
		t.Fatalf("stat helper: %v", err)
	}
	// The helper must be executable by its owner and nobody else.
	if perm := hinfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("helper mode = %04o, want 0700", perm)
	}
}

// TestLeaseWipeRemovesToken closes the loop the task asks for: credentials
// live in a lease directory that is wiped on exit.
func TestLeaseWipeRemovesToken(t *testing.T) {
	mount := newGitHubLease(t, "ghp_wipecanary", []string{"org/*"})
	dir := mount.Dir
	tokenPath := filepath.Join(dir, tokenFileName)

	if _, err := os.Stat(tokenPath); err != nil {
		t.Fatalf("token file should exist before Close: %v", err)
	}
	if err := mount.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Errorf("token file survived the wipe: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("lease directory survived the wipe: %v", err)
	}
}
