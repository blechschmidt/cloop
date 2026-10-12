package ui

// The hub chooses and binds a GitHub credential by (host, path) (Task 20423):
// the grant picker a dispatch names its grant from, the feature path's push
// and pull-request token, and a restored pinned session all refuse an origin
// on another host with a matching owner/name — naming both hosts — and a
// GitHub Enterprise Server grant is good on its own server only, with its own
// API.

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/featureops"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// mintHostedGrant mints a PAT issued by host ("" for github.com) and grants it
// to subject for repos.
func mintHostedGrant(t *testing.T, controlPlaneDir, name, host, subject string, repos []string) {
	t.Helper()
	broker, closeDB, err := openUIBroker(controlPlaneDir)
	if err != nil {
		t.Fatalf("openUIBroker: %v", err)
	}
	defer closeDB()
	payload, err := secretbroker.GitHubPATPayload("ghp_0123456789abcdef0123456789abcdef0123", host)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Mint(context.Background(), secretbroker.MintRequest{
		Name: name, Kind: secretbroker.KindGitHubPAT, Payload: payload, Actor: "test",
	}); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	subj, err := secretbroker.ParseSubject(subject)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Grant(context.Background(), secretbroker.GrantRequest{
		SecretRef: name, Subject: subj, Constraints: secretbroker.Constraints{Repos: repos},
		TTL: time.Hour, Actor: "test",
	}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
}

// otherHostOrigins are origins on hosts other than github.com with the
// owner/name a github.com grant for acme/* admits.
var otherHostOrigins = []struct{ origin, host string }{
	{"https://attacker.example/acme/widgets.git", "attacker.example"},
	{"https://ATTACKER.example./acme/widgets.git", "attacker.example"},
	{"https://github.com:8443/acme/widgets.git", "github.com:8443"},
	{"https://github.com.attacker.example/acme/widgets.git", "github.com.attacker.example"},
	{"https://gіthub.com/acme/widgets.git", "xn--gthub-n2e.com"},
}

func TestTheGrantPickerRefusesAGrantForAnotherHost(t *testing.T) {
	for _, tc := range otherHostOrigins {
		t.Run(tc.origin, func(t *testing.T) {
			cpDir := newWorkspaceControlPlane(t)
			dir := writeGitFixture(t, tc.origin, "main")
			ex := remoteExecutor()
			mintGitHubGrant(t, cpDir, "ci-pat", "executor:"+ex.ID(), []string{"acme/*"})

			spec, err := applyWorkspace(uiSpec(dir, []string{"cloop", "run"}, nil), ex, dir)
			var denied *executor.WorkspaceGrantError
			if !errors.As(err, &denied) {
				t.Fatalf("applyWorkspace = %+v, %v; want a *WorkspaceGrantError", spec.Workspace, err)
			}
			if !denied.HostMismatch() || denied.Host != tc.host || denied.GrantHost != "github.com" {
				t.Fatalf("refusal = %+v, want hosts %s and github.com", denied, tc.host)
			}
			if msg := err.Error(); !strings.Contains(msg, tc.host) || !strings.Contains(msg, "github.com") ||
				!strings.Contains(msg, "ci-pat") {
				t.Fatalf("the refusal does not name both hosts and the grant: %s", msg)
			}
		})
	}
}

func TestTheGrantPickerChoosesTheGrantForTheOriginsHost(t *testing.T) {
	cpDir := newWorkspaceControlPlane(t)
	ex := remoteExecutor()
	mintHostedGrant(t, cpDir, "ghes-pat", "ghes.example.com", "executor:"+ex.ID(), []string{"acme/*"})
	mintHostedGrant(t, cpDir, "gh-pat", "", "executor:"+ex.ID(), []string{"acme/*"})

	for origin, want := range map[string]string{
		"https://ghes.example.com/acme/widgets.git": "ghes-pat",
		"https://GitHub.com/acme/widgets.git":       "gh-pat",
	} {
		dir := writeGitFixture(t, origin, "main")
		spec, err := applyWorkspace(uiSpec(dir, []string{"cloop", "run"}, nil), ex, dir)
		if err != nil {
			t.Fatalf("%s: %v", origin, err)
		}
		if spec.Workspace.CredentialGrant != want {
			t.Errorf("%s: chose %q, want %q", origin, spec.Workspace.CredentialGrant, want)
		}
	}
}

// bindFeatureProject makes dir a real repository whose origin is origin,
// bound to a registered executor holding grants.
func bindFeatureProject(t *testing.T, origin string) (dir string, ex *workspaceTestExecutor) {
	t.Helper()
	dir = writeRepolessProject(t, "feature host")
	realRepo(t, dir)
	if out, err := exec.Command("git", "-C", dir, "remote", "add", "origin", origin).CombinedOutput(); err != nil {
		t.Fatalf("git remote add: %v\n%s", err, out)
	}
	ex = remoteExecutor()
	ex.id = "edge-feature-host"
	if err := executor.DefaultRegistry.Register(ex); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(ex.ID()) })
	if err := executor.Bind(dir, ex.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })
	return dir, ex
}

func TestTheFeatureTokenIsNeverLeasedForAnotherHost(t *testing.T) {
	for _, tc := range otherHostOrigins {
		t.Run(tc.origin, func(t *testing.T) {
			cpDir := newWorkspaceControlPlane(t)
			dir, ex := bindFeatureProject(t, tc.origin)
			mintGitHubGrant(t, cpDir, "ci-pat", "executor:"+ex.ID(), []string{"acme/*"})

			s := &Server{WorkDir: dir}
			cred, release, err := s.hubFeatureToken(context.Background(), dir, "cloop/feature/x")
			release()
			if cred.Token != "" {
				t.Fatalf("a token was found for an origin on %s", tc.host)
			}
			if !errors.Is(err, featureops.ErrNoToken) {
				t.Fatalf("err = %v, want ErrNoToken", err)
			}
			if !strings.Contains(err.Error(), tc.host) || !strings.Contains(err.Error(), "github.com") {
				t.Fatalf("the refusal does not name both hosts: %v", err)
			}
		})
	}
}

func TestTheFeatureTokensAPIIsItsGrantsHosts(t *testing.T) {
	cpDir := newWorkspaceControlPlane(t)
	dir, ex := bindFeatureProject(t, "https://ghes.example.com/acme/widgets.git")
	mintHostedGrant(t, cpDir, "ghes-pat", "ghes.example.com", "executor:"+ex.ID(), []string{"acme/*"})

	s := &Server{WorkDir: dir}
	cred, release, err := s.hubFeatureToken(context.Background(), dir, "cloop/feature/x")
	defer release()
	if err != nil || cred.Token == "" {
		t.Fatalf("hubFeatureToken = %v", err)
	}
	if cred.APIURL != "https://ghes.example.com/api/v3" {
		t.Fatalf("the pull request would be opened at %q, not the grant's server", cred.APIURL)
	}

	// The same grant, with the origin moved to github.com: nothing.
	if out, err := exec.Command("git", "-C", dir, "remote", "set-url", "origin",
		"https://github.com/acme/widgets.git").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	cred2, release2, err := s.hubFeatureToken(context.Background(), dir, "cloop/feature/x")
	release2()
	if cred2.Token != "" || !errors.Is(err, featureops.ErrNoToken) {
		t.Fatalf("a GitHub Enterprise Server token was found for github.com: %v", err)
	}
}

// TestARestoredPinnedSessionIsHeldToTheGrantsHost: a pinned session's record,
// and the project's origin, can both name a host the grant is not for — a
// record minted before hosts were bound, against an origin since moved. The
// restore is refused, naming the hosts, whatever the record says.
func TestARestoredPinnedSessionIsHeldToTheGrantsHost(t *testing.T) {
	r := newWorkspaceRestoreRig(t)
	r.pinOrigin("https://attacker.example/" + restoreRepo)
	rec := gitproxy.SessionRecord{Upstream: "https://attacker.example/" + restoreRepo}
	forgeHost := strings.TrimPrefix(r.forge.URL, "https://")
	_, why := pinnedUpstream(rec, r.dir, forgeHost)
	if why == "" {
		t.Fatal("a pinned session was restorable toward a host its grant is not for")
	}
	if !strings.Contains(why, "attacker.example") || !strings.Contains(why, forgeHost) {
		t.Fatalf("the refusal does not name both hosts: %s", why)
	}

	// The grant's own host, spelled as the origin spells it: restored toward
	// the grant's host.
	r.setOrigin(strings.ToUpper(r.forge.URL[:8]) + forgeHost + "/" + restoreRepo)
	rec.Upstream = r.forge.URL + "/" + restoreRepo
	up, why := pinnedUpstream(rec, r.dir, forgeHost)
	if why != "" || up != "https://"+forgeHost+"/"+restoreRepo {
		t.Fatalf("pinnedUpstream = %q, %q", up, why)
	}
}

// TestARestoredScopedSessionIsHeldToTheGrantsHost: a lease-path session is
// restored only for the forge host its grant's credential is for, toward the
// upstream this hub mints for that host. A record from before hosts were
// recorded reads as github.com.
func TestARestoredScopedSessionIsHeldToTheGrantsHost(t *testing.T) {
	svc := &gitProxyService{githubUpstream: "https://127.0.0.1:41234"}
	rec := func(host, upstream string) gitproxy.SessionRecord {
		return gitproxy.SessionRecord{RepoPatterns: []string{"acme/*"}, ForgeHost: host, Upstream: upstream}
	}
	for _, tc := range []struct {
		name      string
		rec       gitproxy.SessionRecord
		grantHost string
		refused   []string
	}{
		{"legacy github.com record", rec("", "https://127.0.0.1:41234"), "github.com", nil},
		{"github.com record", rec("github.com", "https://127.0.0.1:41234"), "github.com", nil},
		{"enterprise record", rec("ghes.example.com", "https://ghes.example.com"), "ghes.example.com", nil},
		{"legacy record, grant now enterprise", rec("", "https://127.0.0.1:41234"), "ghes.example.com",
			[]string{"github.com", "ghes.example.com"}},
		{"enterprise record, github.com grant", rec("ghes.example.com", "https://ghes.example.com"), "github.com",
			[]string{"ghes.example.com", "github.com"}},
		{"enterprise record presented elsewhere", rec("ghes.example.com", "https://attacker.example"), "ghes.example.com",
			[]string{"attacker.example", "ghes.example.com"}},
		{"github.com record presented elsewhere", rec("github.com", "https://attacker.example"), "github.com",
			[]string{"attacker.example"}},
	} {
		why := gitUpstreamMismatch(tc.rec, svc, tc.grantHost)
		if (why == "") != (tc.refused == nil) {
			t.Errorf("%s: refusal %q", tc.name, why)
			continue
		}
		for _, h := range tc.refused {
			if !strings.Contains(why, h) {
				t.Errorf("%s: the refusal %q does not name %s", tc.name, why, h)
			}
		}
	}
}

// TestARefusalForAnotherForgeSaysWhatCanFixIt: with no grant at all for a
// repository on a host that is not github.com, "grant a github.com PAT" would
// send the operator the wrong way — none would ever be presented there.
func TestARefusalForAnotherForgeSaysWhatCanFixIt(t *testing.T) {
	newWorkspaceControlPlane(t)
	dir := writeGitFixture(t, "https://git.example.org/acme/widgets.git", "main")
	ex := remoteExecutor()
	_, err := applyWorkspace(uiSpec(dir, []string{"cloop", "run"}, nil), ex, dir)
	var denied *executor.WorkspaceGrantError
	if !errors.As(err, &denied) || denied.Host != "git.example.org" || denied.HostMismatch() {
		t.Fatalf("applyWorkspace = %v; want a refusal on git.example.org", err)
	}
	fix := denied.Remediation()
	for _, want := range []string{"git.example.org", "--github-host", "no brokered credential", "acme/widgets"} {
		if !strings.Contains(fix, want) {
			t.Errorf("remediation %q does not mention %q", fix, want)
		}
	}
	if !strings.Contains(err.Error(), "acme/widgets on git.example.org") {
		t.Errorf("the refusal reads as a github.com one: %v", err)
	}
}
