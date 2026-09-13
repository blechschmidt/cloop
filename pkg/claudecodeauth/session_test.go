package claudecodeauth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeClaudeLogin puts a stand-in `claude` binary first on PATH. It mimics the
// real login flow closely enough for the session machinery: print an OAuth URL,
// then block reading the pasted code from stdin.
//
// The URL carries the CLAUDE_CONFIG_DIR the process was started with, so a test
// can prove a session was scoped to the right identity rather than merely
// asserting that two sessions exist.
func fakeClaudeLogin(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"echo \"Visit: https://claude.com/cai/oauth/authorize?dir=${CLAUDE_CONFIG_DIR:-none}&tok=${CLAUDE_CODE_OAUTH_TOKEN:-none}\"\n" +
		"read code\n" +
		"echo \"received:$code\"\n"
	path := filepath.Join(dir, "claude")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake claude: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// Two people signing in at once is the ordinary case on a hub. Before this,
// one global session meant the second person's Start killed the first
// person's in-flight OAuth flow.
func TestLoginSessionsAreIndependentPerIdentity(t *testing.T) {
	fakeClaudeLogin(t)
	m := NewManager()
	t.Cleanup(m.Shutdown)

	if _, err := m.Start(context.Background(), "alice@example.com", "/homes/alice", LoginOptions{}); err != nil {
		t.Fatalf("start alice: %v", err)
	}
	if _, err := m.Start(context.Background(), "bob@example.com", "/homes/bob", LoginOptions{}); err != nil {
		t.Fatalf("start bob: %v", err)
	}

	alice := m.Snapshot("alice@example.com")
	bob := m.Snapshot("bob@example.com")
	if !alice.Active {
		t.Fatal("alice's session died when bob started one")
	}
	if !bob.Active {
		t.Fatal("bob's session is not active")
	}
	if !strings.Contains(alice.URL, "dir=/homes/alice") {
		t.Fatalf("alice's login ran under the wrong config dir: %s", alice.URL)
	}
	if !strings.Contains(bob.URL, "dir=/homes/bob") {
		t.Fatalf("bob's login ran under the wrong config dir: %s", bob.URL)
	}
}

// The ambient token must be cleared for the login subprocess too. With one
// present the CLI treats the user as already signed in and never performs the
// exchange, so every user would silently inherit the host's account.
func TestLoginSubprocessSeesNoAmbientToken(t *testing.T) {
	fakeClaudeLogin(t)
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "host-token")
	m := NewManager()
	t.Cleanup(m.Shutdown)

	sess, err := m.Start(context.Background(), "alice@example.com", "/homes/alice", LoginOptions{})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if strings.Contains(sess.Snapshot().URL, "tok=host-token") {
		t.Fatalf("login subprocess inherited the host token: %s", sess.Snapshot().URL)
	}
	if !strings.Contains(sess.Snapshot().URL, "tok=none") {
		t.Fatalf("expected an empty ambient token, got: %s", sess.Snapshot().URL)
	}
}

// A user abandoning their own login must not disturb anyone else's.
func TestCancelAffectsOnlyOneIdentity(t *testing.T) {
	fakeClaudeLogin(t)
	m := NewManager()
	t.Cleanup(m.Shutdown)

	if _, err := m.Start(context.Background(), "alice@example.com", "/homes/alice", LoginOptions{}); err != nil {
		t.Fatalf("start alice: %v", err)
	}
	if _, err := m.Start(context.Background(), "bob@example.com", "/homes/bob", LoginOptions{}); err != nil {
		t.Fatalf("start bob: %v", err)
	}

	m.Cancel("alice@example.com")

	if m.Snapshot("alice@example.com").Active {
		t.Fatal("alice's session survived her own cancel")
	}
	if !m.Snapshot("bob@example.com").Active {
		t.Fatal("cancelling alice's login also killed bob's")
	}
}

// A code pasted by one user must never complete another user's OAuth flow —
// that would bind the wrong account to the wrong identity.
func TestSubmitCodeCompletesOnlyItsOwnSession(t *testing.T) {
	fakeClaudeLogin(t)
	m := NewManager()
	t.Cleanup(m.Shutdown)

	if _, err := m.Start(context.Background(), "alice@example.com", "/homes/alice", LoginOptions{}); err != nil {
		t.Fatalf("start alice: %v", err)
	}
	if _, err := m.Start(context.Background(), "bob@example.com", "/homes/bob", LoginOptions{}); err != nil {
		t.Fatalf("start bob: %v", err)
	}

	st, err := m.SubmitCode("alice@example.com", "alice-code")
	if err != nil {
		t.Fatalf("submit alice: %v", err)
	}
	if !st.Done {
		t.Fatalf("alice's session did not finish: %+v", st)
	}
	if !strings.Contains(st.Output, "received:alice-code") {
		t.Fatalf("alice's code did not reach her own session: %q", st.Output)
	}
	if !m.Snapshot("bob@example.com").Active {
		t.Fatal("alice submitting her code completed or killed bob's session")
	}
}

func TestSubmitCodeUnknownIdentityFails(t *testing.T) {
	fakeClaudeLogin(t)
	m := NewManager()
	t.Cleanup(m.Shutdown)

	if _, err := m.Start(context.Background(), "alice@example.com", "/homes/alice", LoginOptions{}); err != nil {
		t.Fatalf("start alice: %v", err)
	}
	if _, err := m.SubmitCode("mallory@example.com", "stolen-code"); err == nil {
		t.Fatal("submitting a code for an identity with no session succeeded")
	}
	if !m.Snapshot("alice@example.com").Active {
		t.Fatal("a stranger's submit disturbed alice's session")
	}
}

// Each session is a parked subprocess, so an unbounded map is a process
// exhaustion lever for any authenticated user with a loop.
func TestSessionLimitIsEnforced(t *testing.T) {
	fakeClaudeLogin(t)
	m := NewManager()
	t.Cleanup(m.Shutdown)

	for i := 0; i < maxSessions; i++ {
		key := string(rune('a'+i%26)) + strings.Repeat("x", i)
		if _, err := m.Start(context.Background(), key, "/homes/"+key, LoginOptions{}); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
	}
	if _, err := m.Start(context.Background(), "one-too-many", "/homes/extra", LoginOptions{}); err == nil {
		t.Fatalf("session %d started; the %d-session bound is not enforced", maxSessions+1, maxSessions)
	}
}

// Retrying your own login is not "another session" and must never be refused
// by the bound.
func TestRestartingOwnSessionReplacesIt(t *testing.T) {
	fakeClaudeLogin(t)
	m := NewManager()
	t.Cleanup(m.Shutdown)

	for i := 0; i < maxSessions; i++ {
		key := "user" + strings.Repeat("y", i)
		if _, err := m.Start(context.Background(), key, "/homes/"+key, LoginOptions{}); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
	}
	// At the limit, the first user retries. Their old session is evicted
	// first, so there is room.
	if _, err := m.Start(context.Background(), "user", "/homes/user", LoginOptions{}); err != nil {
		t.Fatalf("restarting an existing identity's own login was refused: %v", err)
	}
}

func TestShutdownKillsEverySession(t *testing.T) {
	fakeClaudeLogin(t)
	m := NewManager()

	for _, key := range []string{"alice", "bob", "carol"} {
		if _, err := m.Start(context.Background(), key, "/homes/"+key, LoginOptions{}); err != nil {
			t.Fatalf("start %s: %v", key, err)
		}
	}
	m.Shutdown()
	for _, key := range []string{"alice", "bob", "carol"} {
		if st := m.Snapshot(key); st.Active {
			t.Fatalf("%s's login subprocess survived shutdown: %+v", key, st)
		}
	}
}
