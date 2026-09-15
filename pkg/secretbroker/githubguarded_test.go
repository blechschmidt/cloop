package secretbroker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// theBroadPAT stands in for what a user actually stores: a token that can reach
// far more than the grant admits. Every assertion below is ultimately "this
// string is not in what the sandbox receives".
const theBroadPAT = "ghp_broadTokenReachingEverything0000"

// fakeGuard is a GitGuard under test control.
type fakeGuard struct {
	result GitGuardResult
	err    error
	// seen records what the broker handed over, so the labels the proxy needs
	// for its audit rows can be asserted on.
	seen GitGuardRequest
	// calls counts invocations, to prove the guarded path ran at all.
	calls int
}

func (g *fakeGuard) GuardGitHub(_ context.Context, req GitGuardRequest) (GitGuardResult, error) {
	g.calls++
	g.seen = req
	return g.result, g.err
}

// workingGuard returns a guard that behaves like the real one.
func workingGuard() *fakeGuard {
	return &fakeGuard{result: GitGuardResult{
		BaseURL:   "https://hub.internal:8443",
		Username:  "sess-abc",
		Password:  "session-token-xyz",
		SessionID: "sess-abc",
		ExpiresAt: time.Now().Add(time.Hour),
	}}
}

// guardedMaterial runs the PAT delivery path with a guard attached.
func guardedMaterial(t *testing.T, g GitGuard, constraints Constraints) (Material, error) {
	t.Helper()
	b := &Broker{GitGuard: g}
	mat := Material{
		SecretName:  "my-pat",
		Kind:        KindGitHubPAT,
		Constraints: constraints,
		Env:         map[string]string{},
	}
	return b.githubMaterial(context.Background(), mat, []byte(theBroadPAT))
}

// TestGuardedDeliveryKeepsTheTokenOutOfTheSandbox is the security property the
// whole feature rests on.
//
// Everything in Files is written into the workload's filesystem and everything
// in Env is exported into its environment, so the test is exhaustive over both
// rather than checking the one file the token used to live in — a future
// delivery that reintroduced it under a different name would otherwise pass.
func TestGuardedDeliveryKeepsTheTokenOutOfTheSandbox(t *testing.T) {
	g := workingGuard()
	mat, err := guardedMaterial(t, g, Constraints{Repos: []string{"acme/*"}})
	if err != nil {
		t.Fatalf("guarded github delivery: %v", err)
	}
	if g.calls != 1 {
		t.Fatalf("guard called %d times, want 1", g.calls)
	}

	for _, f := range mat.Files {
		if strings.Contains(string(f.Content), theBroadPAT) {
			t.Errorf("file %q delivered into the sandbox contains the PAT", f.Name)
		}
		if f.Name == tokenFileName {
			t.Errorf("the raw token file %q was written under a guarded delivery", tokenFileName)
		}
	}
	for k, v := range mat.Env {
		if strings.Contains(v, theBroadPAT) {
			t.Errorf("environment variable %s contains the PAT", k)
		}
	}
	// GITHUB_TOKEN is exported for an unrestricted allowlist on the unguarded
	// path. Under a guard there is no token to export at any width.
	for _, k := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if _, ok := mat.Env[k]; ok {
			t.Errorf("%s was exported under a guarded delivery", k)
		}
	}

	// The session credential is what the workload gets instead, and git has to
	// be able to find it: a credential file, a helper, and a config that
	// rewrites GitHub to the proxy.
	var names []string
	for _, f := range mat.Files {
		names = append(names, f.Name)
	}
	for _, want := range []string{proxyCredentialName, credentialHelperName, gitconfigName} {
		if !contains(names, want) {
			t.Errorf("guarded delivery is missing %q; got %v", want, names)
		}
	}
	cfg := fileNamed(mat.Files, gitconfigName)
	if !strings.Contains(string(cfg.Content), "insteadOf") ||
		!strings.Contains(string(cfg.Content), "hub.internal:8443") {
		t.Errorf("the gitconfig does not rewrite GitHub to the proxy:\n%s", cfg.Content)
	}
	cred := fileNamed(mat.Files, proxyCredentialName)
	if !strings.Contains(string(cred.Content), "session-token-xyz") {
		t.Errorf("the credential file does not carry the session token:\n%s", cred.Content)
	}
	if cred.Mode != 0o600 {
		t.Errorf("credential file mode = %o, want 0600", cred.Mode)
	}

	// The hub still needs the real token for its own workspace provisioning,
	// which is the reason it lives outside Files rather than nowhere.
	if tok, ok := mat.GitHubToken(); !ok || tok != theBroadPAT {
		t.Errorf("GitHubToken() = %q/%v, want the PAT available to the hub", tok, ok)
	}
	if !strings.Contains(mat.Summary, "proxy-guarded") {
		t.Errorf("summary %q does not record that the delivery was guarded", mat.Summary)
	}
}

// TestGuardFailureDoesNotFallBackToTheRawToken is the fail-closed rule.
//
// A guard that errors means the boundary meant to narrow the credential is
// broken. Delivering the broad token anyway would hand it over at precisely
// the moment it is least contained, so the lease must fail instead.
func TestGuardFailureDoesNotFallBackToTheRawToken(t *testing.T) {
	g := &fakeGuard{err: errors.New("proxy is not running")}
	mat, err := guardedMaterial(t, g, Constraints{Repos: []string{"acme/*"}})
	if err == nil {
		t.Fatalf("a failing guard produced a delivery: %+v", mat.Files)
	}
	if !errors.Is(err, ErrGuardUnavailable) {
		t.Errorf("err = %v, want it to wrap ErrGuardUnavailable", err)
	}
	for _, f := range mat.Files {
		if strings.Contains(string(f.Content), theBroadPAT) {
			t.Fatalf("the PAT was delivered despite the guard failing (%q)", f.Name)
		}
	}
}

// TestGuardReturningTheTokenIsRefused catches the mistake that would undo the
// exchange while looking correct from every other angle.
func TestGuardReturningTheTokenIsRefused(t *testing.T) {
	g := workingGuard()
	g.result.Password = theBroadPAT
	if _, err := guardedMaterial(t, g, Constraints{Repos: []string{"acme/*"}}); err == nil {
		t.Fatal("a guard that handed back the unguarded token was accepted")
	} else if !errors.Is(err, ErrGuardUnavailable) {
		t.Errorf("err = %v, want it to wrap ErrGuardUnavailable", err)
	}
}

// TestDeclinedGuardFallsBackToTheHelper keeps a hub with no proxy working.
//
// The zero result means "not guarding this one", which is a decision, not a
// failure — so delivery continues down the original path and the token is
// written with its credential helper as before.
func TestDeclinedGuardFallsBackToTheHelper(t *testing.T) {
	g := &fakeGuard{} // zero result, nil error
	mat, err := guardedMaterial(t, g, Constraints{Repos: []string{"acme/*"}})
	if err != nil {
		t.Fatalf("a declined guard broke delivery: %v", err)
	}
	if g.calls != 1 {
		t.Fatalf("guard called %d times, want 1", g.calls)
	}
	tok := fileNamed(mat.Files, tokenFileName)
	if tok.Name == "" {
		t.Fatal("the unguarded path did not write the token file")
	}
	if !strings.Contains(string(tok.Content), theBroadPAT) {
		t.Error("the unguarded token file does not carry the token")
	}
	if !strings.Contains(mat.Summary, "helper-scoped") {
		t.Errorf("summary %q does not describe the unguarded delivery", mat.Summary)
	}
}

// TestNoGuardIsUnchanged is the regression guard for every existing hub: with
// no GitGuard set at all, delivery is byte-for-byte what it was.
func TestNoGuardIsUnchanged(t *testing.T) {
	b := &Broker{}
	mat := Material{
		SecretName:  "my-pat",
		Kind:        KindGitHubPAT,
		Constraints: Constraints{Repos: []string{"*"}},
		Env:         map[string]string{},
	}
	got, err := b.githubMaterial(context.Background(), mat, []byte(theBroadPAT))
	if err != nil {
		t.Fatalf("unguarded delivery: %v", err)
	}
	if fileNamed(got.Files, tokenFileName).Name == "" {
		t.Error("the token file is missing from an unguarded delivery")
	}
	// The wildcard allowlist still exports the bare env vars it always did.
	if got.Env["GITHUB_TOKEN"] != theBroadPAT {
		t.Error("GITHUB_TOKEN is no longer exported for an unrestricted grant")
	}
}

// TestGuardRequestCarriesItsLabels checks the proxy gets what it needs to
// attribute a session — in particular the owner, which for a personal PAT is
// the person whose credential is being spent.
func TestGuardRequestCarriesItsLabels(t *testing.T) {
	g := workingGuard()
	b := &Broker{GitGuard: g}
	mat := Material{
		SecretName:  "my-pat",
		SecretID:    "sec-1",
		GrantID:     "grant-1",
		Kind:        KindGitHubPAT,
		Constraints: Constraints{Repos: []string{"acme/*"}, Permissions: []string{"contents:read"}},
		Env:         map[string]string{},
		projectID:   "/srv/projects/app",
		executorID:  "exec-7",
		actor:       "executor:exec-7",
		owner:       "dev@example.com",
	}
	if _, err := b.githubMaterial(context.Background(), mat, []byte(theBroadPAT)); err != nil {
		t.Fatalf("guarded delivery: %v", err)
	}
	got := g.seen
	if got.Token != theBroadPAT {
		t.Error("the guard was not given the token to take custody of")
	}
	if got.Owner != "dev@example.com" {
		t.Errorf("Owner = %q, want the personal secret's owner", got.Owner)
	}
	if got.GrantID != "grant-1" || got.SecretID != "sec-1" || got.ProjectID != "/srv/projects/app" ||
		got.ExecutorID != "exec-7" {
		t.Errorf("guard request lost its audit labels: %+v", got)
	}
	if len(got.Repos) != 1 || got.Repos[0] != "acme/*" {
		t.Errorf("Repos = %v, want the grant's allowlist", got.Repos)
	}
	if len(got.Permissions) != 1 || got.Permissions[0] != "contents:read" {
		t.Errorf("Permissions = %v, want the grant's permission set", got.Permissions)
	}
}

// TestGuardedDeliveryRequiresAnAllowlist refuses the grant that would produce a
// session admitting nothing.
func TestGuardedDeliveryRequiresAnAllowlist(t *testing.T) {
	g := workingGuard()
	if _, err := guardedMaterial(t, g, Constraints{}); err == nil {
		t.Fatal("a github grant with no repository allowlist was guarded")
	} else if !errors.Is(err, ErrRepoDenied) {
		t.Errorf("err = %v, want ErrRepoDenied", err)
	}
	if g.calls != 0 {
		t.Error("the guard was called for a grant with no allowlist")
	}
}

// TestProxyGitConfigRejectsABadBase keeps a malformed proxy base out of the
// generated config and helper, where it would land in a shell comparison.
func TestProxyGitConfigRejectsABadBase(t *testing.T) {
	for _, bad := range []string{
		"", "http://hub", "https://", "https://u:p@hub", "https://hub/path",
		"https://hub\nevil",
	} {
		if _, err := buildProxyGitConfig(bad); err == nil {
			t.Errorf("buildProxyGitConfig(%q) was accepted", bad)
		}
		if _, err := buildProxyCredentialHelper(bad); err == nil {
			t.Errorf("buildProxyCredentialHelper(%q) was accepted", bad)
		}
	}
	if _, err := buildProxyGitConfig("https://hub.internal:8443"); err != nil {
		t.Errorf("a well-formed base was rejected: %v", err)
	}
}

// --- helpers -----------------------------------------------------------------

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func fileNamed(files []File, name string) File {
	for _, f := range files {
		if f.Name == name {
			return f
		}
	}
	return File{}
}
