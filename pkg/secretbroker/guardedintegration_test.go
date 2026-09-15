package secretbroker

// Integration tests for guarded github_pat delivery, driven by the real git
// binary against the files a lease actually materialises.
//
// githubguarded_test.go asserts on the Material — which files exist and what
// is not in them. That is necessary and not sufficient: between those bytes
// and a working sandbox sit two things only git can answer. Whether git
// applies the url.insteadOf rewriting to a github.com remote, and whether the
// generated helper answers for the proxy host while staying silent for
// github.com. A rewriting that did not fire would leave the workload talking
// to GitHub directly with no credential, and a helper that answered too
// broadly would hand the session token to whoever asked.
//
// Both failures leave every unit test in this package green.

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// guardedTestGuard is the guard these tests install: it stands in for the
// proxy and returns a fixed session credential.
type guardedTestGuard struct{ base string }

func (g guardedTestGuard) GuardGitHub(_ context.Context, req GitGuardRequest) (GitGuardResult, error) {
	return GitGuardResult{
		BaseURL:   g.base,
		Username:  "sess-1",
		Password:  "session-token-only-good-here",
		SessionID: "sess-1",
		ExpiresAt: time.Now().Add(time.Hour),
		ReadOnly:  true,
	}, nil
}

// newGuardedLease materialises a github_pat lease delivered through a guard.
func newGuardedLease(t *testing.T, token string, repos []string, proxyBase string) *Mount {
	t.Helper()

	b, _, _, _ := newTestBroker(t)
	b.GitGuard = guardedTestGuard{base: proxyBase}
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

// gitRewrittenURL asks git what a URL becomes after insteadOf rewriting.
//
// `ls-remote --get-url` resolves the remote and prints it without contacting
// anything, which is the only way to observe the rewriting without a network.
func gitRewrittenURL(t *testing.T, mount *Mount, url string) string {
	t.Helper()

	cmd := exec.Command("git", "ls-remote", "--get-url", url)
	home := t.TempDir()
	cmd.Dir = home
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=true",
		"GIT_CONFIG_NOSYSTEM=1",
	}, mount.Env()...)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git ls-remote --get-url %s: %v\n%s", url, err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestGuardedLeaseRewritesGitHubToTheProxy proves the interception is real
// from git's point of view: a workload that was told to clone from GitHub
// reaches the proxy instead, without having opted in.
func TestGuardedLeaseRewritesGitHubToTheProxy(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	const proxy = "https://hub.internal:8443"
	mount := newGuardedLease(t, "ghp_broadTokenReachingEverything0000", []string{"acme/*"}, proxy)

	cases := []struct{ in, want string }{
		{"https://github.com/acme/tool", proxy + "/acme/tool"},
		{"https://github.com/acme/tool.git", proxy + "/acme/tool.git"},
		// An ssh-form remote is rewritten too, so a submodule or a task
		// instruction that names one becomes an authorised fetch rather than
		// a dead end in a sandbox that holds no key.
		{"git@github.com:acme/tool.git", proxy + "/acme/tool.git"},
		{"ssh://git@github.com/acme/tool", proxy + "/acme/tool"},
	}
	for _, tc := range cases {
		if got := gitRewrittenURL(t, mount, tc.in); got != tc.want {
			t.Errorf("git rewrote %s to %s, want %s", tc.in, got, tc.want)
		}
	}

	// A different forge is left alone: the grant is about GitHub, and
	// hijacking every remote would break unrelated fetches.
	const other = "https://gitlab.com/acme/tool"
	if got := gitRewrittenURL(t, mount, other); got != other {
		t.Errorf("git rewrote an unrelated forge URL %s to %s", other, got)
	}
}

// TestGuardedHelperReleasesOnlyForTheProxy checks the other half with real
// git: the session credential is handed out for the proxy and for nothing
// else, and the PAT is handed out nowhere.
func TestGuardedHelperReleasesOnlyForTheProxy(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	const (
		proxy = "https://hub.internal:8443"
		pat   = "ghp_broadTokenReachingEverything0000"
	)
	mount := newGuardedLease(t, pat, []string{"acme/*"}, proxy)

	// The proxy: git gets the session credential.
	got := gitCredentialFill(t, mount, proxy+"/acme/tool")
	if !strings.Contains(got, "password=session-token-only-good-here") {
		t.Errorf("git did not get the session credential for the proxy:\n%s", got)
	}
	if !strings.Contains(got, "username=sess-1") {
		t.Errorf("git did not get the session username:\n%s", got)
	}

	// github.com directly: nothing. A workload that resets its remote past
	// the rewriting gets no credential rather than a usable one.
	direct := gitCredentialFill(t, mount, "https://github.com/acme/tool")
	if strings.Contains(direct, "password=session-token-only-good-here") {
		t.Errorf("the session credential was released for github.com directly:\n%s", direct)
	}

	// And under no circumstances the PAT.
	for _, url := range []string{
		proxy + "/acme/tool",
		"https://github.com/acme/tool",
		"https://evil.example/acme/tool",
	} {
		if out := gitCredentialFill(t, mount, url); strings.Contains(out, pat) {
			t.Errorf("git released the PAT for %s:\n%s", url, out)
		}
	}
}

// TestGuardedLeaseWritesNoTokenToDisk is the file-system statement of the
// property: the materialised lease directory — every byte of it — does not
// contain the token.
func TestGuardedLeaseWritesNoTokenToDisk(t *testing.T) {
	const pat = "ghp_broadTokenReachingEverything0000"
	mount := newGuardedLease(t, pat, []string{"acme/*"}, "https://hub.internal:8443")

	entries, err := os.ReadDir(mount.Dir)
	if err != nil {
		t.Fatalf("reading the lease directory: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("the lease directory is empty; the test would prove nothing")
	}
	for _, e := range entries {
		body, err := os.ReadFile(mount.Dir + "/" + e.Name())
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		if strings.Contains(string(body), pat) {
			t.Errorf("%s in the lease directory contains the PAT", e.Name())
		}
	}
	for _, kv := range mount.Env() {
		if strings.Contains(kv, pat) {
			t.Errorf("the lease environment contains the PAT: %s", strings.SplitN(kv, "=", 2)[0])
		}
	}
}
