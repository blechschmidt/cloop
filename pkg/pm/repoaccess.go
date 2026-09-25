package pm

// repoaccess.go tells the agent which repositories it has been granted.
//
// # The gap this closes (Task 20337)
//
// A project that is not itself a git checkout — the shape an executor-owned
// workspace has, where the project is a unit of work and its code is whatever
// repositories have been granted to it — runs its harness in a directory with
// no repository in it. The secret broker leases the grant correctly: git is
// configured to authenticate to exactly the allowlisted repositories, and the
// lease announces which ones in CLOOP_GITHUB_REPO_ALLOWLIST. But nothing said
// so to the agent. On the sgx edge device, asked to "commit it to the repo",
// it found no repository, ran `git init` in its working directory, committed
// there, reported success, and pushed nothing: a correct, authorised, fully
// provisioned credential for bb-selforg/cloop-hello-world sat unused beside it.
//
// The announcement variables are read here rather than passed down from the
// hub because they are what the workload actually received. They are set by
// the lease the executor applied, so they are true on whichever machine the
// harness runs, and absent — along with this section — when no repository was
// granted. None of them is a credential.

import (
	"fmt"
	"strings"
)

// The variables a GitHub lease announces itself with. See
// secretbroker.deliverGitHubToken and deliverGuardedGitHub.
const (
	envRepoAllowlist = "CLOOP_GITHUB_REPO_ALLOWLIST"
	envRepoPerms     = "CLOOP_GITHUB_PERMISSIONS"
	envGitProxyURL   = "CLOOP_GIT_PROXY_URL"
	envGitProxyMode  = "CLOOP_GIT_PROXY_MODE"
)

// maxAnnouncedRepos bounds the list rendered into a prompt. An allowlist is
// operator-authored and normally a handful of entries; the bound is for the one
// that is not, so a pathological grant cannot crowd the task out of the prompt.
const maxAnnouncedRepos = 50

// RepositoryAccessSection renders the prompt section describing the
// repositories this run may reach, from the environment the lease established.
// getenv is os.Getenv in production. It returns "" when no repository was
// granted, so a caller can append it unconditionally.
func RepositoryAccessSection(getenv func(string) string) string {
	if getenv == nil {
		return ""
	}
	repos := splitRepoList(getenv(envRepoAllowlist))
	if len(repos) == 0 {
		return ""
	}
	proxied := strings.TrimSpace(getenv(envGitProxyURL)) != ""
	mode := repoAccess(getenv(envRepoPerms), getenv(envGitProxyMode))

	access := "access as granted"
	switch mode {
	case accessWrite:
		access = "read and write"
	case accessRead:
		access = "read only"
	}

	var b strings.Builder
	b.WriteString("## REPOSITORY ACCESS\n")
	b.WriteString("This run has been granted access to these GitHub repositories:\n")
	var concrete []string
	for i, r := range repos {
		if i == maxAnnouncedRepos {
			fmt.Fprintf(&b, "- … and %d more\n", len(repos)-maxAnnouncedRepos)
			break
		}
		if strings.Contains(r, "*") {
			fmt.Fprintf(&b, "- any repository matching `%s` (%s)\n", r, access)
			continue
		}
		fmt.Fprintf(&b, "- `%s` (%s)\n", r, access)
		concrete = append(concrete, r)
	}
	b.WriteString("\n")

	if len(concrete) == 1 {
		fmt.Fprintf(&b, "When the task refers to \"the repository\" or \"the repo\" without naming one, it "+
			"means `%s`.\n", concrete[0])
	}
	example := "<owner>/<name>"
	if len(concrete) > 0 {
		example = concrete[0]
	}
	b.WriteString("These repositories are not checked out here unless you can see them in the working " +
		"directory. Clone the one you need into the working directory by its plain https URL:\n")
	fmt.Fprintf(&b, "    git clone https://github.com/%s\n", example)
	b.WriteString("git is already configured to authenticate for them: do not ask for, create, print or " +
		"store a token, and do not change the remote URL.\n")

	if mode == accessRead {
		b.WriteString("This grant is read-only: you can clone and fetch, but a push will be refused. If the " +
			"task needs a push, do everything else, then end with TASK_FAILED and say that write " +
			"access to the repository is missing.\n\n")
		return b.String()
	}
	b.WriteString("Work that is committed but not pushed stays on this machine, where nobody will see " +
		"it: to deliver a change, commit it in the clone and push it to that clone's origin.")
	if proxied {
		b.WriteString(" Pushes pass through cloop's git proxy, which enforces a branch policy; if " +
			"it refuses a push to the branch you chose, push to a new branch under `cloop/` " +
			"(for example `cloop/<short-description>`) and say so in your summary.")
	}
	b.WriteString("\n\n")
	return b.String()
}

// accessMode is what the lease says the workload may do to its repositories.
type accessMode int

const (
	// accessUnknown: the lease did not say. Rendered without a verdict,
	// because the two readings it could be given are both wrong for somebody —
	// see repoAccess.
	accessUnknown accessMode = iota
	accessRead
	accessWrite
)

// splitRepoList parses the allowlist the lease announced: comma-separated,
// whitespace-tolerant, duplicates dropped, order kept.
func splitRepoList(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		r := strings.TrimSpace(part)
		if r == "" || seen[strings.ToLower(r)] {
			continue
		}
		seen[strings.ToLower(r)] = true
		out = append(out, r)
	}
	return out
}

// repoAccess decides what the lease lets the workload do.
//
// A proxy-guarded lease states its mode outright, and that statement wins: the
// proxy is what enforces it. Otherwise the grant's permission list decides,
// read the way the broker reads it (secretbroker.GitHubAppPermissions and
// Constraints.AllowsPermission): "*", a bare "contents" and a contents level of
// write or admin all authorise a push, and a list naming none of them does not.
//
// An empty list is left unknown rather than called read-only. For a GitHub App
// grant it does mean contents:read, but a personal access token delivered
// without a proxy can do whatever the token itself can, and the environment
// does not say which kind this is. Telling an agent holding a working push
// credential to give up would be the worse mistake.
func repoAccess(perms, proxyMode string) accessMode {
	switch strings.ToLower(strings.TrimSpace(proxyMode)) {
	case "read-only":
		return accessRead
	case "read-write":
		return accessWrite
	}
	named := false
	for _, raw := range strings.Split(perms, ",") {
		p := strings.ToLower(strings.TrimSpace(raw))
		if p == "" {
			continue
		}
		named = true
		switch p {
		case "*", "contents", "contents:write", "contents:admin":
			return accessWrite
		}
	}
	if named {
		return accessRead
	}
	return accessUnknown
}
