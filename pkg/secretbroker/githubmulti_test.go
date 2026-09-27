package secretbroker

// Several GitHub grants in one lease (Task 20349). Each rendered its files under
// the same names, so a delivered lease was refused ("secret_files[N] repeats
// path …/github-token") and a materialised one kept whichever grant wrote last.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// twoGrantLease issues one lease holding two GitHub PAT grants.
func twoGrantLease(t *testing.T, first, second grantSpec) *Lease {
	t.Helper()
	b, _, _, _ := newTestBroker(t)
	for _, g := range []grantSpec{first, second} {
		s := mintGitHub(t, b, g.name, g.token)
		grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: g.repos, Permissions: g.perms}, time.Hour)
	}
	lease, err := b.Lease(t.Context(), "e1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if len(lease.Materials) != 2 {
		t.Fatalf("got %d materials, want both grants", len(lease.Materials))
	}
	return lease
}

type grantSpec struct {
	name, token string
	repos       []string
	perms       []string
}

var (
	libGrant = grantSpec{name: "lib-read", token: "ghp_multilibreadcanary000000000000",
		repos: []string{"acme/lib"}, perms: []string{"contents:read"}}
	appGrant = grantSpec{name: "app-write", token: "ghp_multiappwritecanary00000000000",
		repos: []string{"acme/app"}, perms: []string{"contents:write"}}
)

// TestTwoGitHubGrantsDeliverTogether is the reported failure: the files a
// driver is handed must be distinct, or the spec is refused outright.
func TestTwoGitHubGrantsDeliverTogether(t *testing.T) {
	lease := twoGrantLease(t, libGrant, appGrant)
	d, err := lease.Deliver("/run/cloop/cloop-lease-multi000000")
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	files := ExecutorSecretFiles(lease.ID, d.Files())
	if err := executor.ValidateSecretFiles(files); err != nil {
		t.Fatalf("the delivered lease is refused, as it was before: %v", err)
	}

	var configs int
	for _, f := range files {
		if f.Name == gitconfigName {
			configs++
			for _, helper := range []string{credentialHelperName, credentialHelperName + "-2"} {
				if !strings.Contains(string(f.Content), "$CLOOP_LEASE_DIR/"+helper+"\"") {
					t.Errorf("the gitconfig does not install %s:\n%s", helper, f.Content)
				}
			}
		}
	}
	if configs != 1 {
		t.Fatalf("got %d gitconfigs; GIT_CONFIG_GLOBAL can name exactly one", configs)
	}

	env := envOf(d.Env())
	if got := env["CLOOP_GITHUB_REPO_ALLOWLIST"]; got != "acme/lib,acme/app" && got != "acme/app,acme/lib" {
		t.Errorf("CLOOP_GITHUB_REPO_ALLOWLIST = %q, want both grants' repositories", got)
	}
	// The grants disagree on access, so neither speaks for both: the prompt
	// must not tell the agent it may push to the read-only library.
	if got, ok := env["CLOOP_GITHUB_PERMISSIONS"]; ok {
		t.Errorf("CLOOP_GITHUB_PERMISSIONS = %q for two grants that disagree on it", got)
	}
}

// TestTwoGitHubGrantsEachAuthenticateTheirOwnRepository drives real git: every
// repository gets the token of the grant that names it, and one no grant names
// gets nothing.
func TestTwoGitHubGrantsEachAuthenticateTheirOwnRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	lease := twoGrantLease(t, libGrant, appGrant)
	mount, err := lease.Materialize(t.TempDir())
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	t.Cleanup(func() { _ = mount.Close() })

	for _, c := range []struct {
		url, want, not string
	}{
		{"https://github.com/acme/lib", libGrant.token, appGrant.token},
		{"https://github.com/acme/app", appGrant.token, libGrant.token},
	} {
		out := gitCredentialFill(t, mount, c.url)
		if !strings.Contains(out, "password="+c.want) {
			t.Errorf("git credential fill for %s did not release its grant's token; git said:\n%s", c.url, out)
		}
		if strings.Contains(out, c.not) {
			t.Errorf("git credential fill for %s released the other grant's token", c.url)
		}
	}
	// GIT_ASKPASS=true answers git's own prompt with nothing, so git still
	// prints an empty "password=" line: what matters is that no token is in it.
	if out := gitCredentialFill(t, mount, "https://github.com/acme/other"); strings.Contains(out, libGrant.token) ||
		strings.Contains(out, appGrant.token) {
		t.Errorf("a repository neither grant names got a credential:\n%s", out)
	}
}

// TestANamedRepositoryOutranksAWildcard: git takes the first helper that
// answers, so a grant that merely matches a repository must not answer for it
// ahead of the grant that names it — whichever was issued first.
func TestANamedRepositoryOutranksAWildcard(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	wide := grantSpec{name: "acme-read", token: "ghp_multiwildcardcanary00000000000",
		repos: []string{"acme/*"}, perms: []string{"contents:read"}}
	lease := twoGrantLease(t, wide, appGrant) // the wildcard is issued first
	mount, err := lease.Materialize(t.TempDir())
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	t.Cleanup(func() { _ = mount.Close() })

	if out := gitCredentialFill(t, mount, "https://github.com/acme/app"); !strings.Contains(out, "password="+appGrant.token) {
		t.Errorf("acme/app was not authenticated by the grant that names it; git said:\n%s", out)
	}
	if out := gitCredentialFill(t, mount, "https://github.com/acme/tool"); !strings.Contains(out, "password="+wide.token) {
		t.Errorf("acme/tool, which only the wildcard covers, got no credential; git said:\n%s", out)
	}
}

// TestOneGitHubGrantRendersAsBefore: coalescing is for several grants; a lease
// with one keeps exactly the files it always had.
func TestOneGitHubGrantRendersAsBefore(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	s := mintGitHub(t, b, "solo", "ghp_multisolocanary000000000000000")
	grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"acme/app"}}, time.Hour)
	lease, err := b.Lease(t.Context(), "e1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	d, err := lease.Deliver("/run/cloop/cloop-lease-solo00000000")
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	var names []string
	for _, f := range d.Files() {
		names = append(names, f.Name)
	}
	if strings.Join(names, ",") != tokenFileName+","+credentialHelperName+","+gitconfigName {
		t.Errorf("a single grant rendered %v", names)
	}
	helper, _ := buildGitCredentialHelper([]string{"acme/app"})
	for _, f := range d.Files() {
		if f.Name == credentialHelperName && string(f.Content) != helper {
			t.Errorf("a single grant's helper changed:\n%s", f.Content)
		}
	}
}

// TestTwoGuardedGrantsEachPresentTheirOwnSession: behind the git proxy both
// sessions answer for the same host, so each helper must also check the
// repository — or every clone would present the first grant's session and the
// proxy would refuse what only the second covers.
func TestTwoGuardedGrantsEachPresentTheirOwnSession(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	const base = "https://hub.internal:8443"
	guarded := func(grantID string, repos []string, user, pass string) Material {
		t.Helper()
		m, err := deliverGuardedGitHub(Material{
			GrantID: grantID, SecretName: grantID, Kind: KindGitHubPAT,
			Constraints: Constraints{Repos: repos}, Env: map[string]string{},
		}, GitGuardResult{BaseURL: base, Username: user, Password: pass, SessionID: user})
		if err != nil {
			t.Fatalf("deliverGuardedGitHub: %v", err)
		}
		return m
	}
	lease := &Lease{ID: "lease_guardedpair", ExpiresAt: time.Now().Add(time.Hour), Materials: []Material{
		guarded("grant_lib", []string{"acme/lib"}, "gps_libsession", "libsessiontoken"),
		guarded("grant_app", []string{"acme/app"}, "gps_appsession", "appsessiontoken"),
	}}
	mount, err := lease.Materialize(t.TempDir())
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	t.Cleanup(func() { _ = mount.Close() })

	for _, c := range []struct{ path, want string }{
		{"acme/lib", "username=gps_libsession"},
		{"acme/app", "username=gps_appsession"},
	} {
		out := gitCredentialFill(t, mount, "https://hub.internal:8443/"+c.path)
		if !strings.Contains(out, c.want) {
			t.Errorf("the proxy request for %s did not present its own session (%s); git said:\n%s",
				c.path, c.want, out)
		}
	}
	entries, err := os.ReadDir(mount.Dir)
	if err != nil {
		t.Fatalf("read the lease directory: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	for _, want := range []string{gitconfigName, credentialHelperName, credentialHelperName + "-2",
		proxyCredentialName, proxyCredentialName + "-2"} {
		if !hasString(names, want) {
			t.Errorf("the lease directory lacks %s: %v", want, names)
		}
	}
	config, err := os.ReadFile(filepath.Join(mount.Dir, gitconfigName))
	if err != nil {
		t.Fatalf("read the gitconfig: %v", err)
	}
	if n := strings.Count(string(config), "[url \""+base+"/\"]"); n != 1 {
		t.Errorf("the proxy rewrite appears %d times in the combined gitconfig, want once:\n%s", n, config)
	}
}

func envOf(pairs []string) map[string]string {
	out := make(map[string]string, len(pairs))
	for _, kv := range pairs {
		k, v, _ := strings.Cut(kv, "=")
		out[k] = v
	}
	return out
}
