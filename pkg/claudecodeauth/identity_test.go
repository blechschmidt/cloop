package claudecodeauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHomeForIsolatesIdentities(t *testing.T) {
	alice, err := HomeFor("alice@example.com")
	if err != nil {
		t.Fatalf("HomeFor(alice): %v", err)
	}
	bob, err := HomeFor("bob@example.com")
	if err != nil {
		t.Fatalf("HomeFor(bob): %v", err)
	}
	if alice == bob {
		t.Fatalf("two identities share one Claude home: %s", alice)
	}
	// Neither may live inside the other, or one user's agent could walk into
	// the other's credential.
	if strings.HasPrefix(alice, bob+string(os.PathSeparator)) || strings.HasPrefix(bob, alice+string(os.PathSeparator)) {
		t.Fatalf("one identity's home nests inside another: %s vs %s", alice, bob)
	}
}

func TestHomeForIsStableAndCaseInsensitive(t *testing.T) {
	first, err := HomeFor("Alice@Example.com")
	if err != nil {
		t.Fatalf("HomeFor: %v", err)
	}
	second, err := HomeFor("alice@example.com  ")
	if err != nil {
		t.Fatalf("HomeFor: %v", err)
	}
	if first != second {
		t.Fatalf("same identity resolved to two homes:\n  %s\n  %s", first, second)
	}
}

func TestHomeForRejectsEmptyIdentity(t *testing.T) {
	// "I don't know who you are" must never resolve to a usable shared
	// directory — that is the pooled credential this package exists to end.
	if _, err := HomeFor("   "); err == nil {
		t.Fatal("HomeFor(empty) returned a directory; want ErrNoIdentity")
	}
	if err := ForgetHome(""); err == nil {
		t.Fatal("ForgetHome(empty) succeeded; want ErrNoIdentity")
	}
}

// An IdP subject is whatever the issuer says it is, so an owner key is
// attacker-influenced. It must never be able to steer the directory out of
// the identity root.
func TestHomeForContainsPathTraversal(t *testing.T) {
	root, err := HomeRoot()
	if err != nil {
		t.Fatalf("HomeRoot: %v", err)
	}
	for _, evil := range []string{
		"sub:../../../../etc",
		"../../../root/.claude",
		"sub:a/b/c",
		"sub:" + strings.Repeat("n", 4096),
		"sub:.",
		"sub:..",
	} {
		dir, err := HomeFor(evil)
		if err != nil {
			t.Fatalf("HomeFor(%q): %v", evil, err)
		}
		parent := filepath.Dir(filepath.Clean(dir))
		if parent != filepath.Clean(root) {
			t.Fatalf("owner key %q escaped the identity root: %s (parent %s, want %s)", evil, dir, parent, root)
		}
	}
}

func TestIdentityHomesArePrivate(t *testing.T) {
	dir, err := HomeFor("alice@example.com")
	if err != nil {
		t.Fatalf("HomeFor: %v", err)
	}
	root, err := HomeRoot()
	if err != nil {
		t.Fatalf("HomeRoot: %v", err)
	}
	for _, p := range []string{root, dir} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if mode := st.Mode().Perm(); mode != 0o700 {
			t.Fatalf("%s has mode %o, want 0700: OAuth refresh tokens for every hub user live here", p, mode)
		}
	}
}

// A directory left over from an older build (or a careless operator) must be
// tightened rather than trusted as-is.
func TestHomeForTightensLoosePermissions(t *testing.T) {
	dir, err := HomeFor("loose@example.com")
	if err != nil {
		t.Fatalf("HomeFor: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	again, err := HomeFor("loose@example.com")
	if err != nil {
		t.Fatalf("HomeFor (second): %v", err)
	}
	st, err := os.Stat(again)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := st.Mode().Perm(); mode != 0o700 {
		t.Fatalf("mode %o after re-resolve, want 0700", mode)
	}
}

func TestForgetHomeDestroysCredential(t *testing.T) {
	dir, err := HomeFor("leaver@example.com")
	if err != nil {
		t.Fatalf("HomeFor: %v", err)
	}
	cred := CredentialsPath(dir)
	if err := os.WriteFile(cred, []byte(`{"claudeAiOauth":{"accessToken":"x"}}`), 0o600); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	if !HasCredential(dir) {
		t.Fatal("HasCredential = false after seeding")
	}
	if err := ForgetHome("leaver@example.com"); err != nil {
		t.Fatalf("ForgetHome: %v", err)
	}
	if _, err := os.Stat(cred); !os.IsNotExist(err) {
		t.Fatalf("credential survived deprovisioning: stat err = %v", err)
	}
	if HasCredential(dir) {
		t.Fatal("HasCredential = true after ForgetHome")
	}
}

func TestHasCredentialFalseWithoutDir(t *testing.T) {
	if HasCredential("") {
		t.Fatal("HasCredential(\"\") = true")
	}
	if HasCredential(t.TempDir()) {
		t.Fatal("HasCredential on empty dir = true")
	}
}

// The security linchpin. An ambient CLAUDE_CODE_OAUTH_TOKEN outranks the
// configuration directory: measured against the real CLI, an empty config dir
// plus an ambient token reports `loggedIn: true, authMethod: oauth_token` and
// actually executes prompts on that token's account. cloop injects exactly
// such a token from ~/.openclaw/workspace/.env. If ScopeEnv ever stops
// clearing these, every user of an OIDC hub silently shares one subscription.
func TestScopeEnvClearsAmbientTokens(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"CLAUDE_CODE_OAUTH_TOKEN=host-token",
		"ANTHROPIC_API_KEY=host-key",
		"ANTHROPIC_AUTH_TOKEN=host-auth",
		"HOME=/root",
	}
	got := ScopeEnv(env, "/srv/identities/alice")

	// exec keeps the last assignment of a key, so evaluate the same way.
	final := map[string]string{}
	for _, kv := range got {
		parts := strings.SplitN(kv, "=", 2)
		final[parts[0]] = parts[1]
	}
	for _, k := range AmbientTokenVars {
		if v := final[k]; v != "" {
			t.Fatalf("%s survived scoping as %q: the host credential would override the user's", k, v)
		}
	}
	if final["CLAUDE_CONFIG_DIR"] != "/srv/identities/alice" {
		t.Fatalf("CLAUDE_CONFIG_DIR = %q, want the identity's home", final["CLAUDE_CONFIG_DIR"])
	}
	// Unrelated variables must be preserved — the child still needs PATH.
	if final["PATH"] != "/usr/bin" {
		t.Fatalf("PATH = %q, want it preserved", final["PATH"])
	}
	if final["HOME"] != "/root" {
		t.Fatalf("HOME = %q, want it preserved", final["HOME"])
	}
}

// A dispatched harness is a whole `cloop run`, which may be using a provider
// that has nothing to do with Claude Code. Isolating the claudecode credential
// must not confiscate another provider's key: blanking ANTHROPIC_API_KEY in
// the harness environment would fail every anthropic-provider run on an OIDC
// hub with "ANTHROPIC_API_KEY not set".
func TestScopeHarnessEnvPreservesOtherProviderKeys(t *testing.T) {
	env := []string{
		"CLAUDE_CODE_OAUTH_TOKEN=host-token",
		"ANTHROPIC_API_KEY=anthropic-provider-key",
		"OPENAI_API_KEY=openai-provider-key",
	}
	final := map[string]string{}
	for _, kv := range ScopeHarnessEnv(env, "/srv/identities/alice") {
		parts := strings.SplitN(kv, "=", 2)
		final[parts[0]] = parts[1]
	}
	if final["CLAUDE_CODE_OAUTH_TOKEN"] != "" {
		t.Fatalf("CLAUDE_CODE_OAUTH_TOKEN survived as %q; the host credential would win", final["CLAUDE_CODE_OAUTH_TOKEN"])
	}
	if final["ANTHROPIC_API_KEY"] != "anthropic-provider-key" {
		t.Fatalf("ANTHROPIC_API_KEY = %q; the anthropic provider needs it and does not use the Claude config dir", final["ANTHROPIC_API_KEY"])
	}
	if final["OPENAI_API_KEY"] != "openai-provider-key" {
		t.Fatalf("OPENAI_API_KEY = %q, want it preserved", final["OPENAI_API_KEY"])
	}
	if final["CLAUDE_CONFIG_DIR"] != "/srv/identities/alice" {
		t.Fatalf("CLAUDE_CONFIG_DIR = %q, want the identity's home", final["CLAUDE_CONFIG_DIR"])
	}
}

// A single-user install has no identity and must keep working exactly as it
// did, ambient tokens included.
func TestScopeEnvNoopWithoutConfigDir(t *testing.T) {
	env := []string{"CLAUDE_CODE_OAUTH_TOKEN=host-token", "PATH=/usr/bin"}
	got := ScopeEnv(env, "")
	if len(got) != len(env) {
		t.Fatalf("ScopeEnv with no config dir rewrote the environment: %v", got)
	}
	for i := range env {
		if got[i] != env[i] {
			t.Fatalf("ScopeEnv(%q) changed entry %d to %q", "", i, got[i])
		}
	}
}

// An inherited CLAUDE_CONFIG_DIR from the hub's own environment must not
// shadow the per-user one, or every user would land in the hub's directory.
func TestScopeEnvReplacesInheritedConfigDir(t *testing.T) {
	got := ScopeEnv([]string{"CLAUDE_CONFIG_DIR=/hub/default"}, "/srv/identities/bob")
	count := 0
	last := ""
	for _, kv := range got {
		if strings.HasPrefix(kv, "CLAUDE_CONFIG_DIR=") {
			count++
			last = strings.TrimPrefix(kv, "CLAUDE_CONFIG_DIR=")
		}
	}
	if count != 1 {
		t.Fatalf("CLAUDE_CONFIG_DIR appears %d times, want exactly 1: %v", count, got)
	}
	if last != "/srv/identities/bob" {
		t.Fatalf("CLAUDE_CONFIG_DIR = %q, want the identity's home", last)
	}
}
