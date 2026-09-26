package pm

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// Tests for what the agent is told about a grant's branch restriction
// (Task 20340).

// TestBranchEnvNamesMatchTheBroker: the broker sets these and this package
// reads them, and a spelling that drifted on either side would silently drop
// the restriction from every prompt.
func TestBranchEnvNamesMatchTheBroker(t *testing.T) {
	for ours, theirs := range map[string]string{
		envPushBranches:  secretbroker.GitHubPushBranchesEnvKey,
		envPushRefs:      secretbroker.GitPushRefsEnvKey,
		envWriteWithheld: secretbroker.GitHubWriteWithheldEnvKey,
	} {
		if ours != theirs {
			t.Errorf("pm reads %q where the broker sets %q", ours, theirs)
		}
	}
}

// TestRepositoryAccessSectionStatesTheBranchRestriction is the report that
// started the task: an agent with write access pushed straight to main. With a
// restriction it is told, before it starts, where its work has to go.
func TestRepositoryAccessSectionStatesTheBranchRestriction(t *testing.T) {
	got := RepositoryAccessSection(leaseEnv(map[string]string{
		envRepoAllowlist: "bb-selforg/cloop-hello-world",
		envRepoPerms:     "contents:write,pull_requests:write",
		envGitProxyURL:   "https://hub.example:8443",
		envGitProxyMode:  "read-write",
		envPushBranches:  "cloop/*,feature/**",
		envPushRefs:      "refs/heads/**",
	}))
	for _, want := range []string{
		"(read and write)",
		"limited to branches matching `cloop/*`, `feature/**`",
		"do not push to it",
		"`cloop/<short-description>`",
		"git proxy enforces this",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("section is missing %q:\n%s", want, got)
		}
	}
	// A hub allowing every branch adds nothing to say.
	if strings.Contains(got, "This hub also limits") {
		t.Errorf("an all-branches ceiling was described as a limit:\n%s", got)
	}
	// The generic advice predates the restriction and would contradict it: a
	// grant limited to feature/** must not be told to fall back to cloop/.
	if strings.Contains(got, "push to a new branch under `cloop/`") {
		t.Errorf("the pre-restriction fallback advice is still rendered:\n%s", got)
	}
}

func TestRepositoryAccessSectionNamesBothListsWhenTheHubNarrows(t *testing.T) {
	got := RepositoryAccessSection(leaseEnv(map[string]string{
		envRepoAllowlist: "acme/tool",
		envGitProxyURL:   "https://hub.example:8443",
		envGitProxyMode:  "read-write",
		envPushBranches:  "cloop/fix-*",
		envPushRefs:      "refs/heads/cloop/**",
	}))
	if !strings.Contains(got, "This hub also limits pushes to `cloop/**`") {
		t.Errorf("the hub's own ceiling is not mentioned:\n%s", got)
	}
	if !strings.Contains(got, "`cloop/fix-<short-description>`") {
		t.Errorf("the example branch does not follow the grant's pattern:\n%s", got)
	}
}

// TestRepositoryAccessSectionUsesTheAnnouncedCeiling: behind a proxy with no
// grant restriction, the advice follows the hub's actual policy rather than
// assuming the default namespace.
func TestRepositoryAccessSectionUsesTheAnnouncedCeiling(t *testing.T) {
	got := RepositoryAccessSection(leaseEnv(map[string]string{
		envRepoAllowlist: "acme/tool",
		envGitProxyURL:   "https://hub.example:8443",
		envGitProxyMode:  "read-write",
		envPushRefs:      "refs/heads/agents/**",
	}))
	if !strings.Contains(got, "accepts only branches matching `agents/**`") ||
		!strings.Contains(got, "`agents/<short-description>`") {
		t.Errorf("the hub's ceiling was not used for the advice:\n%s", got)
	}

	open := RepositoryAccessSection(leaseEnv(map[string]string{
		envRepoAllowlist: "acme/tool",
		envGitProxyURL:   "https://hub.example:8443",
		envGitProxyMode:  "read-write",
		envPushRefs:      "refs/heads/**",
	}))
	if strings.Contains(open, "accepts only") || strings.Contains(open, "`cloop/`") {
		t.Errorf("a hub admitting every branch was described as restricting:\n%s", open)
	}
}

// TestRepositoryAccessSectionExplainsAWithheldPush: a grant whose push the
// broker withheld is read-only however it was written, and the agent should
// report the actual reason rather than "write access is missing".
func TestRepositoryAccessSectionExplainsAWithheldPush(t *testing.T) {
	reason := "this grant limits pushes to branches cloop/*, which only cloop's git proxy can " +
		"enforce, and this hub runs none"
	got := RepositoryAccessSection(leaseEnv(map[string]string{
		envRepoAllowlist: "acme/tool",
		// What the broker announces after withholding: the read-only set.
		envRepoPerms:     "contents:read,pull_requests:read",
		envWriteWithheld: reason,
	}))
	for _, want := range []string{"(read only)", "Pushing is withheld on this hub: " + reason, "TASK_FAILED"} {
		if !strings.Contains(got, want) {
			t.Errorf("section is missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "push it to that clone's origin") {
		t.Errorf("a withheld push was still described as available:\n%s", got)
	}

	// Even if the permissions still said write, the withholding wins: it is
	// what the credential was actually minted with.
	stale := RepositoryAccessSection(leaseEnv(map[string]string{
		envRepoAllowlist: "acme/tool",
		envRepoPerms:     "contents:write",
		envWriteWithheld: reason,
	}))
	if !strings.Contains(stale, "(read only)") {
		t.Errorf("a withheld push was rendered as writable:\n%s", stale)
	}
}

func TestExampleBranch(t *testing.T) {
	for in, want := range map[string]string{
		"cloop/*":         "cloop/<short-description>",
		"feature/**":      "feature/<short-description>",
		"develop":         "develop",
		"release-?":       "release-x",
		"**":              "cloop/<short-description>",
		"refs/heads/main": "main",
	} {
		if got := exampleBranch([]string{in}); got != want {
			t.Errorf("exampleBranch(%q) = %q, want %q", in, got, want)
		}
	}
	if got := exampleBranch([]string{"refs/tags/v*", "hotfix/*"}); got != "hotfix/<short-description>" {
		t.Errorf("exampleBranch skipped past a non-branch pattern wrongly: %q", got)
	}
}
