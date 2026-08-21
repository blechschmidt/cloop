package secretbroker

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// testGitHubToken is the material the generated helper must release for an
// allowed repository and withhold for every other one.
const testGitHubToken = "ghp_secrettoken"

// shellPath returns the POSIX shell to run the generated helper with, or
// skips: the helper's enforcement only exists at all when there is a shell to
// interpret it, and asserting on the script's *text* would prove nothing
// about what it actually releases.
func shellPath(t *testing.T) string {
	t.Helper()
	sh, err := exec.LookPath("/bin/sh")
	if err != nil {
		t.Skipf("/bin/sh not available: %v", err)
	}
	return sh
}

// credRequest builds git's credential request. An empty path omits the line
// entirely, which is what git does when credential.useHttpPath is off.
func credRequest(protocol, host, path string) string {
	var b strings.Builder
	b.WriteString("protocol=" + protocol + "\n")
	b.WriteString("host=" + host + "\n")
	if path != "" {
		b.WriteString("path=" + path + "\n")
	}
	b.WriteString("\n")
	return b.String()
}

// runHelper writes the generated helper plus its token file into a temp dir,
// runs it with `sh <script> get` feeding git's credential request on stdin,
// and returns stdout.
func runHelper(t *testing.T, patterns []string, request string) string {
	t.Helper()
	return runHelperOp(t, patterns, request, "get")
}

// runHelperOp is runHelper with git's operation argument under test control,
// so the "only answers to get" rule can be checked too.
func runHelperOp(t *testing.T, patterns []string, request, op string) string {
	t.Helper()
	sh := shellPath(t)

	script, err := buildGitCredentialHelper(patterns)
	if err != nil {
		t.Fatalf("buildGitCredentialHelper(%v): %v", patterns, err)
	}

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, credentialHelperName)
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	// The helper reads the token from a sibling file rather than carrying it
	// in its own text, so the layout here has to match that.
	if err := os.WriteFile(filepath.Join(dir, tokenFileName), []byte(testGitHubToken+"\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	cmd := exec.Command(sh, scriptPath, op)
	cmd.Stdin = strings.NewReader(request)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("run helper (patterns=%v op=%s): %v\nstderr: %s\nscript:\n%s",
			patterns, op, err, stderr.String(), script)
	}
	if s := stderr.String(); s != "" {
		t.Errorf("helper wrote to stderr: %q", s)
	}
	return stdout.String()
}

// TestCredentialHelperReleasesTokenOnlyForAllowedRepos executes the generated
// script. This is the enforcement point for github credentials: GitHub cannot
// narrow an already-issued PAT, so "may only touch org/*" is real only
// because the helper stays silent for everything else.
func TestCredentialHelperReleasesTokenOnlyForAllowedRepos(t *testing.T) {
	shellPath(t) // skip the whole table if there is no shell to run it with

	tests := []struct {
		name      string
		patterns  []string
		request   string
		wantAllow bool
	}{
		{
			name:      "owner glob allows a repo in the org",
			patterns:  []string{"org/*"},
			request:   credRequest("https", githubHost, "org/tool"),
			wantAllow: true,
		},
		{
			name:      "owner glob denies another org",
			patterns:  []string{"org/*"},
			request:   credRequest("https", githubHost, "other/tool"),
			wantAllow: false,
		},
		{
			name:      "exact pattern allows the exact repo",
			patterns:  []string{"org/tool"},
			request:   credRequest("https", githubHost, "org/tool"),
			wantAllow: true,
		},
		{
			name:      "exact pattern denies a different repo in the same org",
			patterns:  []string{"org/tool"},
			request:   credRequest("https", githubHost, "org/other"),
			wantAllow: false,
		},
		{
			name:      "exact pattern is not a prefix match",
			patterns:  []string{"org/tool"},
			request:   credRequest("https", githubHost, "org/toolkit"),
			wantAllow: false,
		},
		{
			// Shell `case` globbing lets "*" cross "/", so without the
			// single-slash guard "org/*" would match "org/sub/tool" here while
			// Go's path.Match refuses it. The two matchers must agree, and the
			// narrower reading is the one the operator wrote.
			name:      "extra path segment is denied",
			patterns:  []string{"org/*"},
			request:   credRequest("https", githubHost, "org/sub/tool"),
			wantAllow: false,
		},
		{
			// Same guard, reached the other way: a traversal segment must not
			// let a request outside the allowlist glob back into it.
			name:      "traversal segment is denied",
			patterns:  []string{"org/*"},
			request:   credRequest("https", githubHost, "org/../other/tool"),
			wantAllow: false,
		},
		{
			// A workload that controls /etc/hosts or a proxy can make
			// "evil.test" resolve wherever it likes; the token must not follow.
			name:      "wrong host is denied even under a total allowlist",
			patterns:  []string{"*"},
			request:   credRequest("https", "evil.test", "any/thing"),
			wantAllow: false,
		},
		{
			name:      "github lookalike host is denied",
			patterns:  []string{"*"},
			request:   credRequest("https", "github.com.evil.test", "org/tool"),
			wantAllow: false,
		},
		{
			// Plaintext http would put the PAT on the wire.
			name:      "http is denied",
			patterns:  []string{"*"},
			request:   credRequest("http", githubHost, "org/tool"),
			wantAllow: false,
		},
		{
			// No path means credential.useHttpPath is off, so there is nothing
			// to check the allowlist against. Silence is the only safe answer.
			name:      "missing path line is denied",
			patterns:  []string{"*"},
			request:   "protocol=https\nhost=" + githubHost + "\n\n",
			wantAllow: false,
		},
		{
			name:      "empty path value is denied",
			patterns:  []string{"*"},
			request:   "protocol=https\nhost=" + githubHost + "\npath=\n\n",
			wantAllow: false,
		},
		{
			name:      "leading slash on the path is normalised",
			patterns:  []string{"org/tool"},
			request:   credRequest("https", githubHost, "/org/tool"),
			wantAllow: true,
		},
		{
			name:      "dot-git suffix is stripped",
			patterns:  []string{"org/tool"},
			request:   credRequest("https", githubHost, "org/tool.git"),
			wantAllow: true,
		},
		{
			// GitHub names are case-insensitive, so a lowercase allowlist has
			// to cover a mixed-case clone URL or the grant would be trivially
			// bypassed in the deny direction and unusable in the allow one.
			name:      "matching is case-insensitive",
			patterns:  []string{"org/tool"},
			request:   credRequest("https", githubHost, "Org/Tool"),
			wantAllow: true,
		},
		{
			name:      "wildcard allowlist releases for any two-segment repo",
			patterns:  []string{"*"},
			request:   credRequest("https", githubHost, "anyone/anything"),
			wantAllow: true,
		},
		{
			name:      "second pattern in the list can match",
			patterns:  []string{"a/b", "org/*"},
			request:   credRequest("https", githubHost, "org/tool"),
			wantAllow: true,
		},
		{
			name:      "unknown request keys are ignored, not fatal",
			patterns:  []string{"org/*"},
			request:   "protocol=https\nhost=" + githubHost + "\npath=org/tool\nwwwauth[]=Basic realm=x\nusername=someone\n\n",
			wantAllow: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := runHelper(t, tc.patterns, tc.request)
			if tc.wantAllow {
				if !strings.Contains(out, "password="+testGitHubToken) {
					t.Errorf("helper withheld the token for an allowed repo; output = %q", out)
				}
				if !strings.Contains(out, "username=x-access-token") {
					t.Errorf("helper omitted the username git needs; output = %q", out)
				}
				return
			}
			if strings.TrimSpace(out) != "" {
				t.Errorf("helper released output for a denied repo: %q", out)
			}
			if strings.Contains(out, testGitHubToken) {
				t.Errorf("helper leaked the token for a denied repo: %q", out)
			}
		})
	}
}

// TestCredentialHelperIgnoresNonGetOperations: git also calls a helper with
// "store" and "erase". Answering those would print the token in a context
// where git is not asking for it.
func TestCredentialHelperIgnoresNonGetOperations(t *testing.T) {
	shellPath(t)
	req := credRequest("https", githubHost, "org/tool")
	for _, op := range []string{"store", "erase", "", "GET"} {
		t.Run("op="+op, func(t *testing.T) {
			out := runHelperOp(t, []string{"org/*"}, req, op)
			if strings.TrimSpace(out) != "" {
				t.Errorf("operation %q produced output: %q", op, out)
			}
		})
	}
}

// TestCredentialHelperMatchesConstraintsAllowsRepo is the parity check.
//
// Two independent matchers decide the same question: Constraints.AllowsRepo
// in Go (used at cloop's own call sites and in the audit trail) and the
// generated shell `case` (used by git at the moment the token would be
// handed over). If they disagree, the wider one silently wins, because it is
// the one actually holding the credential — and shell globbing is the wider
// of the two by default, since its "*" crosses "/". Any drift here is a
// vulnerability, not a cosmetic inconsistency.
func TestCredentialHelperMatchesConstraintsAllowsRepo(t *testing.T) {
	shellPath(t)

	tests := []struct {
		pattern string
		repo    string
		want    bool
	}{
		{"org/*", "org/tool", true},
		{"org/*", "org/sub/tool", false}, // "*" must not cross "/"
		{"*", "any/thing", true},
		{"org/tool", "org/toolkit", false}, // prefix is not a match
		{"org/tool", "org/tool", true},
		{"org/tool", "Org/Tool", true},
		{"*/*", "any/thing", true},
		{"org/*", "other/tool", false},
		{"org/*", "org-evil/tool", false},
		{"org/*", "evilorg/tool", false},
		{"org/svc-*", "org/svc-api", true},
		{"org/svc-*", "org/api", false},
		{"org/svc?", "org/svc1", true},
		{"org/svc?", "org/svc12", false},
		{"*", "any/sub/thing", false}, // three segments are not a repository
	}

	for _, tc := range tests {
		t.Run(tc.pattern+" vs "+tc.repo, func(t *testing.T) {
			goVerdict := Constraints{Repos: []string{tc.pattern}}.AllowsRepo(tc.repo)
			shellVerdict := strings.Contains(
				runHelper(t, []string{tc.pattern}, credRequest("https", githubHost, tc.repo)),
				"password=",
			)
			if goVerdict != tc.want {
				t.Errorf("AllowsRepo(%q) with %q = %v, want %v", tc.repo, tc.pattern, goVerdict, tc.want)
			}
			if shellVerdict != tc.want {
				t.Errorf("shell helper with %q on %q = %v, want %v", tc.pattern, tc.repo, shellVerdict, tc.want)
			}
			if goVerdict != shellVerdict {
				t.Errorf("matcher drift for pattern %q repo %q: Go says %v, shell says %v",
					tc.pattern, tc.repo, goVerdict, shellVerdict)
			}
		})
	}
}

// TestBuildGitCredentialHelperRejectsHostilePatterns: the generator is the
// sink for repo patterns, so it re-validates rather than trusting that the
// row it read came from a writer that ran validatePattern.
func TestBuildGitCredentialHelperRejectsHostilePatterns(t *testing.T) {
	hostile := []string{
		"org/'; id; '",
		"org/$(id)",
		"org/`id`",
		"org/a;b",
		"org/a|b",
		"org/a\nb",
		`org/a\b`,
		"org/../etc",
		"",
		"   ",
	}
	for _, p := range hostile {
		t.Run(strings.ReplaceAll(p, "\n", "\\n"), func(t *testing.T) {
			script, err := buildGitCredentialHelper([]string{p})
			if err == nil {
				t.Fatalf("pattern %q must be rejected, got script:\n%s", p, script)
			}
			if !errors.Is(err, ErrInvalidConstraint) {
				t.Errorf("err = %v, want ErrInvalidConstraint", err)
			}
			if script != "" {
				t.Errorf("a rejected pattern must not yield a script, got %q", script)
			}
		})
	}
}

// TestBuildGitCredentialHelperKeepsTokenOutOfTheScript: a script is the sort
// of thing that lands in a `set -x` trace or a debug dump of the lease
// directory. The token lives in a sibling file instead.
func TestBuildGitCredentialHelperKeepsTokenOutOfTheScript(t *testing.T) {
	script, err := buildGitCredentialHelper([]string{"org/*"})
	if err != nil {
		t.Fatalf("buildGitCredentialHelper: %v", err)
	}
	if !strings.Contains(script, tokenFileName) {
		t.Errorf("script should read the token from %q, got:\n%s", tokenFileName, script)
	}
	if !strings.HasPrefix(script, "#!/bin/sh\n") {
		t.Errorf("script should be a POSIX sh script, got:\n%s", script)
	}
}

// TestAllowsAllRepos gates whether a bare GITHUB_TOKEN is exported. An env
// var is unscoped by construction, so it is only honest for an operator who
// said "all repositories"; anything narrower must go through the helper.
func TestAllowsAllRepos(t *testing.T) {
	tests := []struct {
		patterns []string
		want     bool
	}{
		{[]string{"*"}, true},
		{[]string{"*/*"}, true},
		{[]string{" * "}, true},
		{[]string{"org/*", "*"}, true},
		{[]string{"org/*"}, false},
		{[]string{"org/tool", "other/*"}, false},
		{nil, false},
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.patterns, ","), func(t *testing.T) {
			if got := allowsAllRepos(tc.patterns); got != tc.want {
				t.Errorf("allowsAllRepos(%v) = %v, want %v", tc.patterns, got, tc.want)
			}
		})
	}
}

// TestBuildGitConfigEnablesHTTPPath: without useHttpPath git never sends the
// repository path, the helper's allowlist has nothing to match against, and
// the scoping quietly stops existing.
func TestBuildGitConfigEnablesHTTPPath(t *testing.T) {
	cfg := buildGitConfig()
	if !strings.Contains(cfg, "useHttpPath = true") {
		t.Errorf("gitconfig must enable useHttpPath, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, credentialHelperName) {
		t.Errorf("gitconfig must install %q, got:\n%s", credentialHelperName, cfg)
	}
	// The helper is referenced through the lease dir because the config is
	// built before that directory exists.
	if !strings.Contains(cfg, "$CLOOP_LEASE_DIR/") {
		t.Errorf("gitconfig must reference the helper via $CLOOP_LEASE_DIR, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, "[credential]") {
		t.Errorf("gitconfig must set the credential section, got:\n%s", cfg)
	}
}
