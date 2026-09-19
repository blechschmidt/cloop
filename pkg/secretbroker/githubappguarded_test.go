package secretbroker

// The github_app half of the guarded-delivery property.
//
// githubguarded_test.go proves it for a PAT. This file proves it for an App
// token, which until Task 20306 it was not true of: githubAppMaterial went
// straight to deliverGitHubToken, so on a hub running a git proxy the App kind
// — the narrower of the two GitHub credentials, and the one the hub recommends
// — was the one that still wrote a usable GitHub token into the sandbox.
//
// The tests below are deliberately written against the observable delivery
// (Files, Env) rather than against which function was called, because the
// property is about what the workload can read, not about the control flow that
// decided it.

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// appMaterialWithGuard runs the App delivery path end to end against a fake
// GitHub and an optional guard, and returns the material a sandbox would get.
func appMaterialWithGuard(t *testing.T, g GitGuard, repos []InstallationRepo, c Constraints) (Material, *fakeGitHub, error) {
	t.Helper()
	gh := newFakeGitHub(repos...)
	b := &Broker{
		GitGuard:  g,
		appMinter: newGitHubAppMinter(gh, nil),
	}
	mat := Material{
		SecretName:  "my-app",
		GrantID:     "grant-1",
		Kind:        KindGitHubApp,
		Constraints: c,
		Env:         map[string]string{},
	}
	payload := appPayloadJSON(t)
	out, err := b.githubAppMaterial(context.Background(), mat, payload, &mints{})
	return out, gh, err
}

// TestGuardedAppDeliveryKeepsTheInstallationTokenOutOfTheSandbox is the
// regression for the defect this task fixed.
func TestGuardedAppDeliveryKeepsTheInstallationTokenOutOfTheSandbox(t *testing.T) {
	guard := workingGuard()
	repos := []InstallationRepo{{ID: 1, FullName: "acme/api"}}
	mat, gh, err := appMaterialWithGuard(t, guard, repos, Constraints{
		Repos:       []string{"acme/api"},
		Permissions: []string{"contents:read"},
	})
	if err != nil {
		t.Fatalf("githubAppMaterial: %v", err)
	}
	if guard.calls != 1 {
		t.Fatalf("guard called %d times, want 1 — the App path did not consult the guard", guard.calls)
	}

	// The token GitHub minted. Everything below asks whether the sandbox can
	// see it.
	minted := gh.liveTokens()
	if len(minted) == 0 {
		t.Fatal("no token was minted, so this test would pass vacuously")
	}

	for _, f := range mat.Files {
		if f.Name == tokenFileName {
			t.Errorf("a %s file was written into the sandbox under a guard", tokenFileName)
		}
		for _, tok := range minted {
			if strings.Contains(string(f.Content), tok) {
				t.Errorf("file %s contains the installation token", f.Name)
			}
		}
	}
	for k, v := range mat.Env {
		for _, tok := range minted {
			if strings.Contains(v, tok) {
				t.Errorf("env %s carries the installation token", k)
			}
		}
	}
	if _, ok := mat.Env["GITHUB_TOKEN"]; ok {
		t.Error("GITHUB_TOKEN was exported under a guard")
	}

	// The hub still holds it: workspace provisioning hands it to the proxy, and
	// Release destroys it at GitHub. A guard that hid the token from the hub as
	// well would have broken both.
	held, ok := mat.GitHubToken()
	if !ok || held == "" {
		t.Fatal("the hub lost the minted token — the proxy has nothing to authenticate with")
	}
	if !slices.Contains(minted, held) {
		t.Errorf("hub holds %q, which is not among the live minted tokens %v", held, minted)
	}

	// And the sandbox got a working credential: the proxy session.
	if got := mat.Env["CLOOP_GIT_PROXY_URL"]; got != "https://hub.internal:8443" {
		t.Errorf("CLOOP_GIT_PROXY_URL = %q, want the proxy base", got)
	}
	if !strings.Contains(mat.Summary, "proxy-guarded") {
		t.Errorf("summary %q does not record that the delivery was guarded", mat.Summary)
	}
	// The summary must still name the installation and repository, because that
	// is what an operator reading a lease needs to see.
	if !strings.Contains(mat.Summary, "acme/api") || !strings.Contains(mat.Summary, "67890") {
		t.Errorf("summary %q lost the installation or repository scope", mat.Summary)
	}
}

// TestUnguardedAppDeliveryIsUnchanged pins the behaviour of a hub with no proxy.
// The fix must not have made the App kind unusable where there is no guard to
// route through.
func TestUnguardedAppDeliveryIsUnchanged(t *testing.T) {
	repos := []InstallationRepo{{ID: 1, FullName: "acme/api"}}
	mat, gh, err := appMaterialWithGuard(t, nil, repos, Constraints{
		Repos:       []string{"acme/api"},
		Permissions: []string{"contents:read"},
	})
	if err != nil {
		t.Fatalf("githubAppMaterial: %v", err)
	}
	minted := gh.liveTokens()
	if len(minted) == 0 {
		t.Fatal("no token minted")
	}
	token := minted[0]

	var sawTokenFile bool
	for _, f := range mat.Files {
		if f.Name == tokenFileName && strings.Contains(string(f.Content), token) {
			sawTokenFile = true
		}
	}
	if !sawTokenFile {
		t.Error("without a guard the token file is the delivery mechanism, and it is missing")
	}
	if mat.Env["CLOOP_GITHUB_TOKEN_EXPIRES_AT"] == "" {
		t.Error("the unguarded path no longer announces the token expiry")
	}
	if strings.Contains(mat.Summary, "proxy-guarded") {
		t.Errorf("summary %q claims a guard that was not configured", mat.Summary)
	}
}

// TestBrokenAppGuardFailsTheLease: a guard that was asked for and errors must
// deny the credential rather than fall back to handing the token over. This is
// the same rule githubMaterial follows, and the fallback would be a silent
// downgrade of the exact property the guard exists to provide.
func TestBrokenAppGuardFailsTheLease(t *testing.T) {
	guard := &fakeGuard{err: errors.New("proxy is not running")}
	repos := []InstallationRepo{{ID: 1, FullName: "acme/api"}}
	mat, _, err := appMaterialWithGuard(t, guard, repos, Constraints{
		Repos: []string{"acme/api"},
	})
	if err == nil {
		t.Fatalf("a broken guard delivered material anyway: %+v", mat.Files)
	}
	if !strings.Contains(err.Error(), "guard") {
		t.Errorf("error %v does not name the guard as the cause", err)
	}
	if len(mat.Files) != 0 {
		t.Errorf("material was returned alongside the error: %+v", mat.Files)
	}
}
