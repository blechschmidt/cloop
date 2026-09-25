package pm

import (
	"fmt"
	"strings"
	"testing"
)

// leaseEnv is a getenv backed by a map, shaped like what a GitHub lease sets.
func leaseEnv(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

// TestRepositoryAccessSectionIsAbsentWithoutAGrant: most runs hold no GitHub
// grant, and their prompts must not change.
func TestRepositoryAccessSectionIsAbsentWithoutAGrant(t *testing.T) {
	if got := RepositoryAccessSection(leaseEnv(nil)); got != "" {
		t.Fatalf("section rendered with no grant: %q", got)
	}
	if got := RepositoryAccessSection(leaseEnv(map[string]string{envRepoAllowlist: " , "})); got != "" {
		t.Fatalf("section rendered for an empty allowlist: %q", got)
	}
	if got := RepositoryAccessSection(nil); got != "" {
		t.Fatalf("section rendered with a nil getenv: %q", got)
	}
}

// TestRepositoryAccessSectionNamesTheRepo is the sgx case (Task 20337): one
// repository, granted read-write through a GitHub App, and a task that says
// "commit it to the repo". The agent has to be told which repository that is,
// how to get it, and that an unpushed commit delivers nothing.
func TestRepositoryAccessSectionNamesTheRepo(t *testing.T) {
	got := RepositoryAccessSection(leaseEnv(map[string]string{
		envRepoAllowlist: "bb-selforg/cloop-hello-world",
		envRepoPerms:     "contents:write,pull_requests:write",
	}))
	for _, want := range []string{
		"## REPOSITORY ACCESS",
		"`bb-selforg/cloop-hello-world` (read and write)",
		`"the repo"`,
		"means `bb-selforg/cloop-hello-world`",
		"git clone https://github.com/bb-selforg/cloop-hello-world",
		"push it to that clone's origin",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("section is missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "proxy") {
		t.Errorf("a lease delivered without a proxy should not mention one:\n%s", got)
	}
	if strings.Contains(got, "TASK_FAILED") {
		t.Errorf("a writable grant must not tell the agent to give up:\n%s", got)
	}
}

// TestRepositoryAccessSectionReadOnly: with a read-only grant a push is going
// to be refused, and an agent that was not told would discover that as an
// authentication error after doing all the work.
func TestRepositoryAccessSectionReadOnly(t *testing.T) {
	got := RepositoryAccessSection(leaseEnv(map[string]string{
		envRepoAllowlist: "acme/tool",
		envRepoPerms:     "contents:read",
	}))
	if !strings.Contains(got, "`acme/tool` (read only)") || !strings.Contains(got, "read-only") {
		t.Errorf("read-only grant not described as such:\n%s", got)
	}
	if !strings.Contains(got, "TASK_FAILED") {
		t.Errorf("read-only guidance should say how to report a push it cannot make:\n%s", got)
	}
	if strings.Contains(got, "push it to that clone's origin") {
		t.Errorf("a read-only grant must not be told to push:\n%s", got)
	}
}

// TestRepositoryAccessSectionDoesNotGuessAnUnstatedAccess: a lease that names
// no permissions may be a GitHub App grant (contents:read) or a personal token
// that can push anywhere. Calling it read-only would tell an agent holding a
// working push credential to fail.
func TestRepositoryAccessSectionDoesNotGuessAnUnstatedAccess(t *testing.T) {
	got := RepositoryAccessSection(leaseEnv(map[string]string{envRepoAllowlist: "acme/tool"}))
	if strings.Contains(got, "read only") || strings.Contains(got, "TASK_FAILED") {
		t.Errorf("unstated access rendered as read-only:\n%s", got)
	}
	if !strings.Contains(got, "push it to that clone's origin") {
		t.Errorf("unstated access should still say how to deliver work:\n%s", got)
	}
}

// TestRepositoryAccessMatchesTheBroker: the permission spellings that
// authorise a push are the ones the broker mints a writable token for.
func TestRepositoryAccessMatchesTheBroker(t *testing.T) {
	for _, tc := range []struct {
		perms, proxyMode string
		want             accessMode
	}{
		{"contents:write", "", accessWrite},
		{"CONTENTS:WRITE", "", accessWrite},
		{"contents", "", accessWrite}, // a bare scope covers both levels
		{"contents:admin", "", accessWrite},
		{"*", "", accessWrite},
		{"contents:read", "", accessRead},
		{"pull_requests:write", "", accessRead}, // contents defaults to read
		{"", "", accessUnknown},
		// The proxy enforces its mode, so its statement wins.
		{"contents:write", "read-only", accessRead},
		{"", "read-write", accessWrite},
	} {
		if got := repoAccess(tc.perms, tc.proxyMode); got != tc.want {
			t.Errorf("repoAccess(%q, %q) = %v, want %v", tc.perms, tc.proxyMode, got, tc.want)
		}
	}
}

// TestRepositoryAccessSectionThroughTheProxy: behind the git proxy a push may
// be refused by branch policy, and the agent needs a way forward that the
// policy admits.
func TestRepositoryAccessSectionThroughTheProxy(t *testing.T) {
	got := RepositoryAccessSection(leaseEnv(map[string]string{
		envRepoAllowlist: "acme/tool",
		envGitProxyURL:   "https://hub.example:8443",
		envGitProxyMode:  "read-write",
	}))
	if !strings.Contains(got, "git proxy") || !strings.Contains(got, "`cloop/`") {
		t.Errorf("proxied lease should explain the branch policy:\n%s", got)
	}
	if strings.Contains(got, "hub.example") {
		t.Errorf("the proxy's address is plumbing the agent must not be steered to:\n%s", got)
	}
}

// TestRepositoryAccessSectionWithSeveralRepos: "the repo" is only resolved
// when there is exactly one concrete candidate; a wildcard is described as a
// pattern, not offered as a clone URL.
func TestRepositoryAccessSectionWithSeveralRepos(t *testing.T) {
	got := RepositoryAccessSection(leaseEnv(map[string]string{
		envRepoAllowlist: "acme/one, acme/two,acme/one",
		envRepoPerms:     "contents:write",
	}))
	if strings.Contains(got, `"the repo"`) {
		t.Errorf("two repositories must not be collapsed into \"the repo\":\n%s", got)
	}
	if strings.Count(got, "acme/one`") != 1 {
		t.Errorf("a duplicated allowlist entry was listed twice:\n%s", got)
	}

	wild := RepositoryAccessSection(leaseEnv(map[string]string{
		envRepoAllowlist: "acme/*",
		envRepoPerms:     "contents:write",
	}))
	if !strings.Contains(wild, "any repository matching `acme/*`") {
		t.Errorf("wildcard not described as a pattern:\n%s", wild)
	}
	if strings.Contains(wild, "github.com/acme/*") {
		t.Errorf("a wildcard was offered as a clone URL:\n%s", wild)
	}
}

// TestRepositoryAccessSectionIsBounded: an operator-authored allowlist cannot
// crowd the task out of the prompt.
func TestRepositoryAccessSectionIsBounded(t *testing.T) {
	var repos []string
	for i := 0; i < maxAnnouncedRepos+25; i++ {
		repos = append(repos, fmt.Sprintf("acme/repo-%03d", i))
	}
	got := RepositoryAccessSection(leaseEnv(map[string]string{
		envRepoAllowlist: strings.Join(repos, ","),
		envRepoPerms:     "contents:write",
	}))
	if strings.Contains(got, fmt.Sprintf("acme/repo-%03d", maxAnnouncedRepos)) {
		t.Errorf("the list was not bounded at %d entries", maxAnnouncedRepos)
	}
	if !strings.Contains(got, "and 25 more") {
		t.Errorf("a truncated list should say how much it left out:\n%s", got)
	}
}

// TestExecuteTaskPromptCarriesRepositoryAccess drives the real prompt builder
// with the lease's variables in the process environment, which is where a
// dispatched `cloop run` finds them.
func TestExecuteTaskPromptCarriesRepositoryAccess(t *testing.T) {
	task := &Task{ID: 1, Title: "Create test-executor and commit it to the repo", Status: TaskPending}
	plan := &Plan{Goal: "g", Tasks: []*Task{task}}

	t.Setenv(envRepoAllowlist, "")
	if p := ExecuteTaskPrompt("g", "", "", plan, task, true); strings.Contains(p, "REPOSITORY ACCESS") {
		t.Fatalf("prompt carries a repository section with no grant:\n%s", p)
	}

	t.Setenv(envRepoAllowlist, "bb-selforg/cloop-hello-world")
	t.Setenv(envRepoPerms, "contents:write")
	p := ExecuteTaskPrompt("g", "", "", plan, task, true)
	if !strings.Contains(p, "git clone https://github.com/bb-selforg/cloop-hello-world") {
		t.Fatalf("prompt does not tell the agent about its granted repository:\n%s", p)
	}
	// Before the instructions and the completion signals, so it reads as
	// context for the task rather than as an afterthought.
	if strings.Index(p, "REPOSITORY ACCESS") > strings.Index(p, "## INSTRUCTIONS") {
		t.Errorf("repository section placed after the instructions")
	}
}
