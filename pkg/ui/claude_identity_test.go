package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/executor"
)

// authedRequest builds a request carrying c's session cookie, so the scope
// resolver sees the same identity the browser would present.
func authedRequest(t *testing.T, c *http.Client, ts *httptest.Server) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/claudecode/auth/status", nil)
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	for _, ck := range c.Jar.Cookies(u) {
		req.AddCookie(ck)
	}
	return req
}

// The core guarantee: two signed-in users resolve to two different Claude
// accounts. Before Task 20241 a hub had exactly one, so whoever logged in last
// owned it and everybody's tasks billed that person's subscription.
func TestClaudeScopeIsPerUser(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)

	aliceClient := jarClient(t)
	login(t, aliceClient, ts)
	aliceScope, err := srv.claudeScopeFor(authedRequest(t, aliceClient, ts))
	if err != nil {
		t.Fatalf("scope for alice: %v", err)
	}

	idp.email, idp.sub, idp.name = "bob@example.com", "sub-bob", "Bob"
	bobClient := jarClient(t)
	login(t, bobClient, ts)
	bobScope, err := srv.claudeScopeFor(authedRequest(t, bobClient, ts))
	if err != nil {
		t.Fatalf("scope for bob: %v", err)
	}

	if !aliceScope.PerUser() || !bobScope.PerUser() {
		t.Fatalf("OIDC is on but a scope is not per-user: alice=%+v bob=%+v", aliceScope, bobScope)
	}
	if aliceScope.ConfigDir == bobScope.ConfigDir {
		t.Fatalf("two users share one Claude config dir: %s", aliceScope.ConfigDir)
	}
	if aliceScope.Owner == bobScope.Owner {
		t.Fatalf("two users share one session key: %s", aliceScope.Owner)
	}

	// The directory must be the one the identity package allocates, not an
	// ad-hoc path that happens to differ.
	want, err := claudecodeauth.HomeFor("alice@example.com")
	if err != nil {
		t.Fatalf("HomeFor: %v", err)
	}
	if aliceScope.ConfigDir != want {
		t.Fatalf("alice's config dir = %s, want %s", aliceScope.ConfigDir, want)
	}
}

// A single-machine install has no identities and must behave exactly as it did
// before: one operator, the host's own ~/.claude.
func TestClaudeScopeWithoutOIDCUsesHostCredential(t *testing.T) {
	srv := New(setupProjectDir(t, cloopGoal, nil), 0, "")
	scope, err := srv.claudeScopeFor(httptest.NewRequest(http.MethodGet, "/api/claudecode/auth/status", nil))
	if err != nil {
		t.Fatalf("claudeScopeFor with OIDC off: %v", err)
	}
	if scope.PerUser() {
		t.Fatalf("OIDC is off but the scope claims to be per-user: %+v", scope)
	}
	if scope.ConfigDir != "" || scope.Owner != "" {
		t.Fatalf("expected the zero scope, got %+v", scope)
	}
}

// "I cannot tell who you are" must not resolve to "then use the shared
// account", which would hand an unidentified caller the operator's
// subscription.
func TestClaudeScopeFailsClosedWithoutIdentity(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, _ := newOIDCTestServer(t, idp, "", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/claudecode/auth/status", nil)
	scope, err := srv.claudeScopeFor(req)
	if err == nil {
		t.Fatalf("an unidentified caller resolved to a Claude account: %+v", scope)
	}
	if scope.ConfigDir != "" {
		t.Fatalf("a failed resolution still returned a directory: %s", scope.ConfigDir)
	}
}

// The dispatched harness must carry the user's directory and must not carry an
// ambient token, which would outrank it.
func TestClaudeWorkloadEnvPinsTheCallersAccount(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	c := jarClient(t)
	login(t, c, ts)
	req := authedRequest(t, c, ts)

	env := srv.claudeWorkloadEnv(req, hostExecutor())
	if len(env) == 0 {
		t.Fatal("no environment pinned for a host executor under OIDC")
	}
	final := map[string]string{}
	for _, kv := range env {
		parts := strings.SplitN(kv, "=", 2)
		final[parts[0]] = parts[1]
	}
	want, err := claudecodeauth.HomeFor("alice@example.com")
	if err != nil {
		t.Fatalf("HomeFor: %v", err)
	}
	if final["CLAUDE_CONFIG_DIR"] != want {
		t.Fatalf("CLAUDE_CONFIG_DIR = %q, want %q", final["CLAUDE_CONFIG_DIR"], want)
	}
	if v, ok := final["CLAUDE_CODE_OAUTH_TOKEN"]; !ok || v != "" {
		t.Fatalf("CLAUDE_CODE_OAUTH_TOKEN = %q (present=%v), want an explicit empty assignment", v, ok)
	}
}

// A hub-local path means nothing inside a sandbox, and the hub deliberately
// does not forward its environment to an isolating executor at all. Those
// receive credentials through the secret broker instead.
func TestClaudeWorkloadEnvSkipsIsolatingExecutors(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	c := jarClient(t)
	login(t, c, ts)
	req := authedRequest(t, c, ts)

	if env := srv.claudeWorkloadEnv(req, sandboxExecutor()); env != nil {
		t.Fatalf("a hub filesystem path was pushed into an isolating executor: %v", env)
	}
}

// The brainstorm path dispatches from a goroutine after the handler has
// returned, so the resolver must capture the answer rather than the request.
func TestClaudeEnvResolverOutlivesTheRequest(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	c := jarClient(t)
	login(t, c, ts)

	resolve := func() func(executor.Executor) []string {
		req := authedRequest(t, c, ts)
		inner := srv.claudeEnvResolver(req)
		if inner == nil {
			t.Fatal("resolver was nil for a signed-in caller")
		}
		// Drop every reference to req before the resolver is used.
		return func(ex executor.Executor) []string { return inner(ex) }
	}()

	env := resolve(hostExecutor())
	want, err := claudecodeauth.HomeFor("alice@example.com")
	if err != nil {
		t.Fatalf("HomeFor: %v", err)
	}
	if len(env) == 0 || !containsAssignment(env, "CLAUDE_CONFIG_DIR", want) {
		t.Fatalf("resolver lost the identity once the request was gone: %v", env)
	}
}

func containsAssignment(env []string, key, value string) bool {
	for _, kv := range env {
		if kv == key+"="+value {
			return true
		}
	}
	return false
}

// With OIDC off there is nothing to pin, and the harness must inherit the
// host's environment exactly as it always has.
func TestClaudeWorkloadEnvEmptyWithoutOIDC(t *testing.T) {
	srv := New(setupProjectDir(t, cloopGoal, nil), 0, "")
	req := httptest.NewRequest(http.MethodGet, "/api/run", nil)
	if env := srv.claudeWorkloadEnv(req, hostExecutor()); env != nil {
		t.Fatalf("single-user mode pinned an environment: %v", env)
	}
}
