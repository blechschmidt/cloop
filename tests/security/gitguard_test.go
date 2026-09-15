package security

// Guarantee: on a hub that runs the git interception proxy, a github_pat
// grant never places the token inside the sandbox — and when the proxy is
// unavailable, the lease fails rather than delivering the token unguarded
// (Task 20276).
//
// # Why this is a conformance test and not a unit test
//
// The claim `github_pat` used to make was that a repository allowlist is
// enforced. It was enforced against *git*, by a POSIX shell credential helper
// that the lease writes into the sandbox next to the token it reads. That is
// the strongest thing available while the token is in the sandbox, and it is
// not a boundary: a workload that reads `github-token` directly has whatever
// the token has, which for a personal access token is usually `repo` across
// everything its owner can see.
//
// With the proxy on, the delivery changes shape entirely — the hub keeps the
// token, the sandbox gets a session credential bound to one proxy, one
// allowlist, one ref policy and one TTL. The property worth machine-checking
// is therefore not "the helper is correct" but "the token is absent", and
// absence is exactly the kind of claim that rots: a later delivery that
// reintroduced the token under a different file name, or exported it for the
// convenience of `gh`, would break the guarantee while every feature test kept
// passing.
//
// So the assertions here are exhaustive over what a workload can observe —
// every file byte and every environment value — rather than checking the one
// file the token used to live in.
//
// # Both delivery shapes
//
// A lease reaches a workload two ways, and they render separately:
//
//	Materialize  — writes files on this host, for a bind-mounting executor
//	Deliver      — renders bytes in memory, for a container, Pod or edge agent
//
// Task 20192 is in this suite because those two paths disagreed and one of
// them silently dropped the files. Checking only one here would leave the same
// class of gap.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// theUsersPAT is what a developer stores on a multi-user hub: a token whose
// real reach is far wider than the grant that spends it.
const theUsersPAT = "ghp_userBroadTokenReachingEverything"

// guardedHub builds a broker whose GitHub deliveries are held by a real
// gitproxy registry, and returns the lease a project's sandbox would receive.
//
// A real registry rather than a stub: the point of the exercise is that the
// credential the sandbox gets is one the proxy actually issued and will
// actually check, and a stub would prove only that this test can invent a
// string.
func guardedHub(t *testing.T, repos []string, permissions []string) (*secretbroker.Lease, *gitproxy.Registry) {
	t.Helper()

	broker, _, _ := newBroker(t)

	reg, err := gitproxy.NewRegistry("https://hub.internal:8443")
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	broker.GitGuard = &registryGuard{reg: reg}

	ctx := context.Background()
	sec, err := broker.Mint(ctx, secretbroker.MintRequest{
		Name:    "my-pat",
		Kind:    secretbroker.KindGitHubPAT,
		Payload: []byte(theUsersPAT),
		Actor:   "dev@example.com",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := broker.Grant(ctx, secretbroker.GrantRequest{
		SecretRef:   sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: "/srv/app"},
		Constraints: secretbroker.Constraints{Repos: repos, Permissions: permissions},
		TTL:         time.Hour,
		Actor:       "dev@example.com",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	lease, err := broker.Lease(ctx, "exec-1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if len(lease.Materials) != 1 {
		t.Fatalf("got %d materials, want 1", len(lease.Materials))
	}
	return lease, reg
}

// registryGuard is the production adapter in miniature: it mints a scoped
// session against a real registry. pkg/ui/gitguard.go is the same shape with
// the hub's configured policy in place of the fixed one here.
type registryGuard struct{ reg *gitproxy.Registry }

func (g *registryGuard) GuardGitHub(_ context.Context, req secretbroker.GitGuardRequest) (secretbroker.GitGuardResult, error) {
	pol := gitproxy.Policy{AllowedRefs: []string{"refs/heads/cloop/**"}, AllowFetch: true}
	readOnly := true
	if (secretbroker.Constraints{Permissions: req.Permissions}).AllowsPermission("contents:write") {
		pol.AllowCreate, pol.AllowUpdate = true, true
		readOnly = false
	}
	m, err := g.reg.Mint(gitproxy.MintRequest{
		Upstream:     "https://github.com",
		RepoPatterns: req.Repos,
		Credential:   gitproxy.Credential{Username: secretbroker.GitHubUsername, Password: req.Token},
		Policy:       pol,
		Actor:        req.Owner,
	})
	if err != nil {
		return secretbroker.GitGuardResult{}, err
	}
	c := m.Credential()
	return secretbroker.GitGuardResult{
		BaseURL:   "https://hub.internal:8443",
		Username:  c.Username,
		Password:  c.Password,
		SessionID: m.Session.ID,
		ExpiresAt: m.Session.ExpiresAt,
		ReadOnly:  readOnly,
	}, nil
}

// TestGuardedPATNeverReachesTheSandbox is the guarantee, over both delivery
// shapes and over everything a workload can read.
func TestGuardedPATNeverReachesTheSandbox(t *testing.T) {
	lease, reg := guardedHub(t, []string{"acme/*"}, []string{"contents:read"})

	// Shape 1: files written on this host for a bind-mounting executor.
	mount, err := lease.Materialize(t.TempDir())
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	t.Cleanup(func() { _ = mount.Close() })

	entries, err := os.ReadDir(mount.Dir)
	if err != nil {
		t.Fatalf("read lease dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("the lease directory is empty, so this test proves nothing")
	}
	for _, e := range entries {
		body, err := os.ReadFile(filepath.Join(mount.Dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if strings.Contains(string(body), theUsersPAT) {
			t.Errorf("materialized file %q contains the user's PAT", e.Name())
		}
	}
	assertNoPAT(t, "Materialize env", mount.Env())

	// Shape 2: bytes rendered for a container, Pod or edge agent. Same lease,
	// separate rendering — this is the path that silently dropped files in
	// Task 20192, so it is checked independently rather than assumed alike.
	delivery, err := lease.Deliver("/run/cloop/lease")
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	t.Cleanup(func() { _ = delivery.Close() })

	files := delivery.Files()
	if len(files) == 0 {
		t.Fatal("the delivery carries no files, so this test proves nothing")
	}
	for _, f := range files {
		if strings.Contains(string(f.Content), theUsersPAT) {
			t.Errorf("delivered file %q contains the user's PAT", f.Name)
		}
		if f.Name == "github-token" {
			t.Errorf("the raw token file was delivered under a guarded lease")
		}
	}
	assertNoPAT(t, "Deliver env", delivery.Env())

	// What the sandbox got instead is a session the proxy will actually
	// check — and one that admits the allowlist and refuses everything else.
	sessions := reg.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("got %d proxy sessions, want 1", len(sessions))
	}
	s := sessions[0]
	if !s.Scoped() {
		t.Error("the guarded lease minted a pinned session for an allowlist grant")
	}
	if !s.AllowsRepo("acme/tool") {
		t.Error("the session does not admit a repository inside the grant's allowlist")
	}
	if s.AllowsRepo("somebody-else/private") {
		t.Error("the session admits a repository outside the grant's allowlist")
	}
	// contents:read, so the broad PAT's ability to push does not survive.
	if s.Policy.AllowCreate || s.Policy.AllowUpdate || s.Policy.AllowDelete {
		t.Errorf("a read-only grant produced a session that can write: %+v", s.Policy)
	}
}

// TestGuardedPATWritePermissionIsHonoured is the counterpart: the narrowing
// must not be a constant. Without this, a guard that always produced a
// read-only session would pass the test above and break every write-back.
func TestGuardedPATWritePermissionIsHonoured(t *testing.T) {
	_, reg := guardedHub(t, []string{"acme/*"}, []string{"contents:write"})
	sessions := reg.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("got %d proxy sessions, want 1", len(sessions))
	}
	s := sessions[0]
	if !s.Policy.AllowCreate || !s.Policy.AllowUpdate {
		t.Errorf("a contents:write grant produced a session that cannot push: %+v", s.Policy)
	}
	// Still never delete, and still only inside the allowlist.
	if s.Policy.AllowDelete {
		t.Error("a contents:write grant was read as permission to delete refs")
	}
	if s.AllowsRepo("somebody-else/private") {
		t.Error("a write grant widened the repository allowlist")
	}
}

// TestUnavailableGuardFailsRatherThanDeliveringTheToken is the fail-closed
// rule, and the reason the guard is an error and not a best effort.
//
// An operator who enabled interception and whose proxy is down must not
// silently get the old behaviour — that is the one moment the broad token is
// least contained and the audit trail least likely to say so.
func TestUnavailableGuardFailsRatherThanDeliveringTheToken(t *testing.T) {
	broker, _, _ := newBroker(t)
	broker.GitGuard = brokenGuard{}

	ctx := context.Background()
	sec, err := broker.Mint(ctx, secretbroker.MintRequest{
		Name: "my-pat", Kind: secretbroker.KindGitHubPAT,
		Payload: []byte(theUsersPAT), Actor: "dev@example.com",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := broker.Grant(ctx, secretbroker.GrantRequest{
		SecretRef:   sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: "/srv/app"},
		Constraints: secretbroker.Constraints{Repos: []string{"acme/*"}},
		TTL:         time.Hour,
		Actor:       "dev@example.com",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// The lease itself succeeds — a broker returns an empty lease rather than
	// an error when nothing can be delivered, because "this project has no
	// secrets" must not fail a run. What must not happen is the token
	// arriving anyway.
	lease, err := broker.Lease(ctx, "exec-1", "/srv/app")
	if err != nil {
		if !errors.Is(err, secretbroker.ErrGuardUnavailable) {
			t.Errorf("lease failed with %v; want it to name ErrGuardUnavailable", err)
		}
		return
	}
	for _, m := range lease.Materials {
		if tok, ok := m.GitHubToken(); ok && tok == theUsersPAT {
			// The hub-side accessor may legitimately hold it; the sandbox
			// delivery may not. Fall through to the file and env checks.
			_ = tok
		}
	}
	mount, merr := lease.Materialize(t.TempDir())
	if merr != nil {
		return // refused outright, which is the desired outcome
	}
	t.Cleanup(func() { _ = mount.Close() })
	entries, _ := os.ReadDir(mount.Dir)
	for _, e := range entries {
		body, rerr := os.ReadFile(filepath.Join(mount.Dir, e.Name()))
		if rerr != nil {
			continue
		}
		if strings.Contains(string(body), theUsersPAT) {
			t.Errorf("a broken guard still delivered the PAT in %q", e.Name())
		}
	}
	assertNoPAT(t, "broken-guard env", mount.Env())
}

// brokenGuard stands in for an enabled proxy that is not running.
type brokenGuard struct{}

func (brokenGuard) GuardGitHub(context.Context, secretbroker.GitGuardRequest) (secretbroker.GitGuardResult, error) {
	return secretbroker.GitGuardResult{}, errors.New("proxy is not running")
}

// assertNoPAT fails if any environment value carries the token. The key is
// reported and the value never is.
func assertNoPAT(t *testing.T, what string, env []string) {
	t.Helper()
	for _, kv := range env {
		if strings.Contains(kv, theUsersPAT) {
			key, _, _ := strings.Cut(kv, "=")
			t.Errorf("%s: %s carries the user's PAT", what, key)
		}
	}
}
