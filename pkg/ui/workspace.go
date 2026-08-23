package ui

// workspace.go decides how the *source tree* reaches the executor a workload
// was dispatched to (Task 20179).
//
// The bug this closes: the UI built every Spec with a WorkDir naming a path on
// the control plane and said nothing about how that path would come to exist
// anywhere else. On the container and localprocess drivers it already did —
// they bind-mount the host directory — so the omission was invisible. On a
// Kubernetes Pod or a remote edge device it did not: the driver created an
// empty directory, started the harness in it, and streamed back a plausible
// transcript of a run that operated on no code at all. Nothing in the hub's
// view distinguished that from a real run.
//
// So every dispatched Spec now carries an explicit executor.Workspace, and this
// file is the single place the UI decides which one:
//
//   - the executor shares the control plane's filesystem → bind. The tree is
//     genuinely already at WorkDir, and cloning over it would rewrite the
//     operator's own checkout.
//   - the workload is not project-scoped (the voice handler passes an empty
//     WorkDir) → none. Stated, so an empty tree cannot be confused with the bug.
//   - otherwise → git, derived from the project's own checkout: the origin
//     remote, the branch it has checked out, and the name of the secret grant
//     that authorises fetching it.
//   - a project on a non-sharing executor with no usable git remote → refused,
//     by name, with the fix. That refusal *is* the fix for this task: the tree
//     cannot be materialised, so the run must not start.
//
// # Why the remote is read from .git and not from `git remote get-url`
//
// pkg/ui may not spawn processes — no_direct_exec_test.go enforces it, because
// a control plane that can fork can only ever run work as itself, on its own
// host. So the two facts needed here are read out of the project's own
// .git/config and .git/HEAD by the small pure parsers below. That is also
// strictly more predictable than shelling out: `git remote get-url` applies the
// *ambient* configuration — url.<base>.insteadOf rewrites and includes from
// whoever last touched the machine — and a clone URL chosen by the hub's
// ~/.gitconfig is not one the operator can reason about from the project alone.

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitcreds"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// applyWorkspace folds the source-tree decision into spec.
//
// It runs *after* applySandbox and *before* dispatch — see the ordering
// comment at both call sites in executor.go — and never widens what the sandbox
// decided: an existing SizeLimitMB (the project's .cloop/sandbox.yaml
// resources.disk, which bounds the provisioned tree) is carried across every
// branch below rather than reset to the executor's default.
//
// The returned error is already user-facing: either a *workspaceSourceError or
// a *executor.WorkspaceGrantError, each carrying its own Remediation() for
// jsonWorkloadErr to render.
func applyWorkspace(spec executor.Spec, ex executor.Executor, workDir string) (executor.Spec, error) {
	if ex == nil {
		// Unreachable from the two call sites, which both have a resolved
		// executor. Fail closed anyway: the whole decision below is a function
		// of the executor's capabilities, and defaulting it would mean guessing
		// whether the tree is already there.
		return spec, &workspaceSourceError{
			ProjectPath: workDir,
			Reason:      "no executor was resolved, so there is no way to tell whether the source tree is reachable",
		}
	}

	// The disk bound is the sandbox's to set and ours to preserve. Every
	// assignment below rebuilds Workspace wholesale — a merge would let a
	// stale Repo from an earlier decision survive a switch to bind, which
	// Workspace.Validate rejects — so the limit is lifted out first.
	sizeLimit := spec.Workspace.SizeLimitMB

	if ex.Capabilities().SharesHostFilesystem {
		// The tree is already at WorkDir because the executor is looking at the
		// same filesystem the hub is. Provisioning here would clone over the
		// operator's own checkout and discard uncommitted work.
		spec.Workspace = executor.Workspace{Kind: executor.WorkspaceBind, SizeLimitMB: sizeLimit}
		return spec, nil
	}

	// Past this point the executor does not share our filesystem, so our paths
	// mean nothing to it. Spec.WorkDir is currently the hub's own project
	// directory, and a remote agent confines workloads beneath its configured
	// root and refuses an absolute path from outside it — so dispatching it
	// unchanged fails every run to a device enrolled with a --workdir-root with
	// an error about escaping a root nobody asked to escape.
	//
	// The rewrite belongs here rather than in the driver, next to the
	// SharesHostFilesystem test that made the same judgement one line up: a
	// driver that silently rewrote an absolute path would also rewrite one a
	// compromised control plane aimed at /etc, turning the agent's refusal into
	// a quiet remap. See executor.DeviceWorkDir.
	spec.WorkDir = executor.DeviceWorkDir(spec.WorkDir)

	if strings.TrimSpace(workDir) == "" {
		// Not project-scoped: the voice handler runs `cloop listen --file …`
		// with no project at all (see uiSpec, which deliberately omits the
		// project label for it). There is no tree to fetch and nothing to name,
		// so the workload is declared as wanting an empty directory rather than
		// left unspecified — "none" is a statement, and the zero value is the
		// silence this task exists to remove.
		spec.Workspace = executor.Workspace{Kind: executor.WorkspaceNone, SizeLimitMB: sizeLimit}
		return spec, nil
	}

	origin, err := readGitOrigin(workDir)
	if err != nil {
		return spec, &workspaceSourceError{
			ProjectPath:  workDir,
			ExecutorID:   ex.ID(),
			ExecutorKind: ex.Kind(),
			Reason:       err.Error(),
		}
	}
	repo, err := normalizeRemoteToHTTPS(origin.Remote)
	if err != nil {
		return spec, &workspaceSourceError{
			ProjectPath:  workDir,
			ExecutorID:   ex.ID(),
			ExecutorKind: ex.Kind(),
			Remote:       origin.Remote,
			Reason:       err.Error(),
		}
	}

	ws := executor.Workspace{
		Kind: executor.WorkspaceGit,
		Repo: repo,
		// Empty means the remote's default branch, which is the right answer
		// for a detached HEAD: the commit a hub happens to be parked on is not
		// necessarily reachable by a fetch, and inventing a ref that the fetch
		// then fails on would be a worse error than starting from the default.
		Ref:         origin.Ref,
		SizeLimitMB: sizeLimit,
	}

	grant, err := workspaceGrantFor(ws, ex, workDir)
	if err != nil {
		return spec, err
	}
	ws.CredentialGrant = grant

	// Validate here rather than leaving it to the driver. Everything in ws was
	// derived from files on disk, so a repository whose branch name git accepts
	// but this contract does not (one starting with a dash, say) is a config
	// problem the operator can see and fix — and a refusal naming it beats one
	// surfacing three layers down as a rejected Spec.
	if err := ws.Validate(); err != nil {
		return spec, &workspaceSourceError{
			ProjectPath:  workDir,
			ExecutorID:   ex.ID(),
			ExecutorKind: ex.Kind(),
			Remote:       origin.Remote,
			Reason:       err.Error(),
		}
	}
	spec.Workspace = ws

	// Last: can this executor actually do what the spec now asks for? The gate
	// runs here rather than at the call sites because only now does the Spec
	// carry a workspace, and RequireWorkspaceProvisioning is derived from it —
	// applySandbox ran its own gate before the field existed and could not have
	// seen this. Re-checking the sandbox-derived requirements alongside it is
	// idempotent and deliberate: SandboxRequirements is the one definition of
	// "what this Spec needs", and a future requirement added there should be
	// gated without anyone remembering to add a second call.
	//
	// The interesting rejection is a remote agent too old to provision. It
	// advertises SupportsWorkspaceProvisioning false, so the refusal names the
	// device instead of dispatching a fetch it cannot perform.
	if err := executor.CheckSandboxSupport(ex, spec.SandboxRequirements(), workDir); err != nil {
		return spec, err
	}
	return spec, nil
}

// workspaceGrantFor returns the name of the secret grant that authorises
// fetching w on ex for workDir, or "" when the fetch must be unauthenticated.
//
// # Why this reads grants instead of taking a lease
//
// The obvious implementation asks the broker for a lease and looks at the
// materials it hands back — which is what pkg/executor/gitcreds does at
// dispatch. It would be wrong here. A lease *unseals* every matching payload
// and emits an audit row per grant, and this function needs one string: the
// name. Minting a credential in order to read a label would put a live token in
// this process's memory on every workload start, for a decision that never
// touches it, and would double the broker's audit trail with leases nobody
// used. ListGrants plus ListSecrets answers the same question from metadata
// alone — no payload is opened, no lease exists to leak or release.
//
// The matching mirrors LeaseFor exactly: same requester shape (executor ID plus
// project path, no labels), same active-grant rule, same repository allowlist.
// It has to. A grant selected here that LeaseFor would not produce is a Spec
// that names a grant the driver cannot lease, which fails at dispatch with a
// worse error than the one this function could have returned.
func workspaceGrantFor(w executor.Workspace, ex executor.Executor, workDir string) (string, error) {
	repoPath, hasRepoPath := w.RepoPath()
	denied := func(reason string) error {
		return &executor.WorkspaceGrantError{
			Repo:        w.Repo,
			RepoPath:    repoPath,
			ExecutorID:  ex.ID(),
			ProjectPath: workDir,
			Reason:      reason,
		}
	}
	if !hasRepoPath {
		// A URL that is not owner/name — a GitLab subgroup, say — cannot be
		// matched against a repository allowlist, because allowlists are
		// owner/name globs. So no grant could ever authorise it, and refusing
		// would hand the operator a problem with no fix in it. The fetch goes
		// out unauthenticated instead: public repositories work, private ones
		// fail inside the fetch with git's own authentication error, and
		// neither outcome is the silent empty tree this file exists to prevent.
		//
		// This is deliberately *not* how a github.com/owner/name URL with no
		// grant is treated. There the refusal below is right, because there a
		// fix exists and the error can name it.
		return "", nil
	}

	broker, closeDB, err := openUIBroker(controlPlaneDir())
	if err != nil {
		if isBrokerUnconfigured(err) {
			// The broker is not in use on this install. That is the same
			// "not adopted yet" state secrets.go treats as "start without
			// brokered credentials", and the same answer applies: fetch
			// anonymously, which works for a public repository. Refusing
			// instead would mean adopting workspace provisioning required
			// adopting the secret broker on the same day, and a private repo
			// still fails — inside the fetch, with git's own authentication
			// error, which names the right problem.
			return "", nil
		}
		// Configured but broken. Fail closed: a hub that cannot read its own
		// grant table must not go on to fetch repositories with whatever
		// authority happens to be lying around on the executor.
		return "", denied(fmt.Sprintf("the secret broker could not be opened: %v", err))
	}
	if closeDB != nil {
		defer closeDB()
	}

	grants, err := broker.ListGrants(secretbroker.GrantFilter{ActiveOnly: true})
	if err != nil {
		return "", denied(fmt.Sprintf("the grant table could not be read: %v", err))
	}
	secrets, err := broker.ListSecrets()
	if err != nil {
		return "", denied(fmt.Sprintf("the secret table could not be read: %v", err))
	}
	byID := make(map[string]secretbroker.Secret, len(secrets))
	for _, s := range secrets {
		byID[s.ID] = s
	}

	requester := secretbroker.Requester{ExecutorID: ex.ID(), ProjectID: workDir}
	var excluded string
	for _, g := range grants {
		if !g.Subject.Matches(requester) {
			continue
		}
		s, ok := byID[g.SecretID]
		if !ok || (s.Kind != secretbroker.KindGitHubPAT && s.Kind != secretbroker.KindGitHubApp) {
			continue
		}
		if !g.Constraints.AllowsRepo(repoPath) {
			// Remembered, not returned yet: a later grant may still admit the
			// repository, and reporting the first exclusion would send the
			// operator to widen a grant they did not need.
			excluded = s.Name
			continue
		}
		// ListGrants is newest-first, so the most recently issued authority
		// wins when several admit the repository. That is the one an operator
		// who just created a grant expects to take effect.
		return s.Name, nil
	}

	if excluded != "" {
		return "", denied(fmt.Sprintf(
			"grant %s is issued to this executor but its allowlist excludes repository %s",
			excluded, repoPath))
	}
	return "", denied(fmt.Sprintf(
		"no active GitHub grant is issued to executor %s for this project, so %s cannot be fetched",
		ex.ID(), repoPath))
}

// --- errors -----------------------------------------------------------------

// workspaceSourceError: this project's tree cannot be materialised on the
// executor it is bound to.
//
// Typed, and naming both the project and the executor, because the alternative
// this task removes is a run that proceeds against an empty directory. The
// operator's question is always "why can this machine not get my code, and what
// do I change" — so the error answers the first and Remediation() answers the
// second. It unwraps to executor.ErrWorkspaceUnavailable, which is deliberately
// distinct from a harness failure: nothing about the task's code is implicated.
type workspaceSourceError struct {
	// ProjectPath is the project whose run was refused.
	ProjectPath string
	// ExecutorID and ExecutorKind name the executor that cannot see it.
	ExecutorID   string
	ExecutorKind string
	// Remote is the origin URL as .git/config records it, when there was one
	// and it was merely unusable. Empty when there was none at all — the two
	// have different fixes and must not read alike.
	Remote string
	// Reason is the specific observation.
	Reason string
}

// Error implements error.
func (e *workspaceSourceError) Error() string {
	var b strings.Builder
	b.WriteString("cannot provide the source tree for ")
	if e.ProjectPath != "" {
		b.WriteString(e.ProjectPath)
	} else {
		b.WriteString("this project")
	}
	if e.ExecutorID != "" {
		b.WriteString(" on executor " + e.ExecutorID)
		if e.ExecutorKind != "" {
			b.WriteString(" (" + e.ExecutorKind + ")")
		}
		// Said explicitly because it is the half of the situation the reader
		// does not have: they know their project, they may well not know that
		// the executor it is bound to is looking at a different filesystem.
		b.WriteString(", which does not share the control plane's filesystem")
	}
	b.WriteString(": ")
	if e.Reason != "" {
		b.WriteString(e.Reason)
	} else {
		b.WriteString("the project has no usable git remote")
	}
	if fix := e.Remediation(); fix != "" {
		b.WriteString(" — " + fix)
	}
	return b.String()
}

// Unwrap lets callers match errors.Is(err, executor.ErrWorkspaceUnavailable).
func (e *workspaceSourceError) Unwrap() error { return executor.ErrWorkspaceUnavailable }

// Remediation returns the fix. Both branches are real fixes, and which one
// applies depends on whether the deployment wants this project running off-host
// at all — so both are offered rather than one guessed at.
func (e *workspaceSourceError) Remediation() string {
	add := "give the project an https git remote and push it " +
		"(git remote add origin https://host/owner/name && git push -u origin HEAD)"
	if e.Remote != "" {
		add = "point the project's origin remote at an https URL " +
			"(git remote set-url origin https://host/owner/name)"
	}
	if e.ExecutorID == "" {
		return add
	}
	return fmt.Sprintf("%s, or bind the project to an executor that shares this host's "+
		"filesystem with: cloop executor bind %s --executor <local-or-container-executor>",
		add, e.ProjectPath)
}

// --- reading the project's own checkout ---------------------------------------

// gitOrigin is what a project's checkout says about where it came from.
type gitOrigin struct {
	// Remote is the origin URL exactly as .git/config records it, in whatever
	// form was written there (https, ssh, scp-like, or a local path).
	Remote string
	// Ref is the checked-out branch, or "" when HEAD is detached.
	Ref string
}

// maxGitMetaFile bounds the files read below. .git/config is a few hundred
// bytes and .git/HEAD is one line; anything at this size is not one of them,
// and reading it into the hub's memory on every workload start would be a
// cheap amplification lever for anyone who can write into a project directory.
const maxGitMetaFile = 1 << 20

// readGitOrigin reads the origin remote and current branch out of a project's
// git metadata, without running git.
//
// The error is the operator-facing half of the refusal, so it says what was
// looked for and where.
func readGitOrigin(projectDir string) (gitOrigin, error) {
	gitDir, commonDir, err := resolveGitDir(projectDir)
	if err != nil {
		return gitOrigin{}, err
	}

	// The remote lives in the *common* directory: a linked worktree shares its
	// parent repository's config, and reading the worktree's own gitdir would
	// find no remotes at all and report a project with none.
	raw, err := readBoundedFile(filepath.Join(commonDir, "config"))
	if err != nil {
		return gitOrigin{}, fmt.Errorf("the repository's config at %s could not be read: %v",
			filepath.Join(commonDir, "config"), err)
	}
	remote := parseGitConfigRemote(string(raw), "origin")
	if remote == "" {
		return gitOrigin{}, fmt.Errorf(
			"the project is a git repository but has no origin remote, so there is no URL to fetch it from")
	}

	// HEAD, by contrast, is per-worktree: it is the branch *this* directory has
	// checked out, which is the one the run is meant to operate on.
	origin := gitOrigin{Remote: remote}
	if head, herr := readBoundedFile(filepath.Join(gitDir, "HEAD")); herr == nil {
		origin.Ref = parseGitHead(string(head))
	}
	return origin, nil
}

// resolveGitDir locates a project's git directory and its common directory.
//
// Three shapes exist and all three occur in the wild: an ordinary .git
// directory, a linked worktree whose .git is a file containing "gitdir: …",
// and a linked worktree whose gitdir contains a "commondir" pointing back at
// the parent repository. The distinction matters because config is shared and
// HEAD is not.
func resolveGitDir(projectDir string) (gitDir, commonDir string, err error) {
	dot := filepath.Join(projectDir, ".git")
	info, err := os.Lstat(dot)
	if err != nil {
		return "", "", fmt.Errorf(
			"%s is not a git repository (no .git), so its source tree cannot be fetched", projectDir)
	}

	gitDir = dot
	if !info.IsDir() {
		// A worktree or submodule: .git is a file naming the real directory.
		raw, rerr := readBoundedFile(dot)
		if rerr != nil {
			return "", "", fmt.Errorf("%s could not be read: %v", dot, rerr)
		}
		line := strings.TrimSpace(string(raw))
		rest, ok := strings.CutPrefix(line, "gitdir:")
		if !ok {
			return "", "", fmt.Errorf("%s is neither a git directory nor a gitdir pointer", dot)
		}
		gitDir = strings.TrimSpace(rest)
		if !filepath.IsAbs(gitDir) {
			gitDir = filepath.Join(projectDir, gitDir)
		}
	}

	commonDir = gitDir
	if raw, cerr := readBoundedFile(filepath.Join(gitDir, "commondir")); cerr == nil {
		if p := strings.TrimSpace(string(raw)); p != "" {
			if !filepath.IsAbs(p) {
				p = filepath.Join(gitDir, p)
			}
			commonDir = filepath.Clean(p)
		}
	}
	return gitDir, commonDir, nil
}

// readBoundedFile reads at most maxGitMetaFile bytes from name.
func readBoundedFile(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxGitMetaFile))
}

// parseGitConfigRemote returns the url of the named remote from git config
// text, or "".
//
// This is a deliberately small subset of git's config grammar: section headers
// with an optional quoted subsection, key = value lines, and comments. It is
// enough for a file git itself wrote, which is the only kind that reaches here,
// and it does not attempt include.path or conditional includes — a URL that
// depends on a file outside the project is one the operator cannot see from the
// project, which is exactly what the run panel would then be lying about.
//
// Section names and keys fold case (git's rule); the subsection name does not.
func parseGitConfigRemote(cfg, name string) string {
	inSection := false
	for _, line := range strings.Split(cfg, "\n") {
		line = strings.TrimSpace(stripGitConfigComment(line))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			end := strings.LastIndex(line, "]")
			if end <= 0 {
				inSection = false
				continue
			}
			inSection = gitConfigSectionIs(line[1:end], "remote", name)
			continue
		}
		if !inSection {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "url") {
			continue
		}
		value = strings.TrimSpace(value)
		// git quotes a value only when it has to; unquoting unconditionally
		// would corrupt a URL that legitimately contains a quote character.
		if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
			value = value[1 : len(value)-1]
		}
		if value != "" {
			return value
		}
	}
	return ""
}

// gitConfigSectionIs reports whether a section header body (the text between
// the brackets) names section "want" with subsection "sub".
func gitConfigSectionIs(body, want, sub string) bool {
	body = strings.TrimSpace(body)
	head, rest, hasSub := strings.Cut(body, " ")
	if !hasSub {
		// [remote.origin] is not a form git writes, but it is legal input and
		// reading it costs one Cut.
		section, subsection, dotted := strings.Cut(body, ".")
		return dotted && strings.EqualFold(section, want) && subsection == sub
	}
	if !strings.EqualFold(strings.TrimSpace(head), want) {
		return false
	}
	rest = strings.TrimSpace(rest)
	rest = strings.TrimPrefix(rest, `"`)
	rest = strings.TrimSuffix(rest, `"`)
	// Subsection names are case-sensitive in git, so this comparison is too.
	return rest == sub
}

// stripGitConfigComment removes a trailing # or ; comment that is not inside a
// quoted value.
func stripGitConfigComment(line string) string {
	inQuotes := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\\':
			i++ // skip the escaped byte, quote or otherwise
		case '"':
			inQuotes = !inQuotes
		case '#', ';':
			if !inQuotes {
				return line[:i]
			}
		}
	}
	return line
}

// parseGitHead returns the branch named by a .git/HEAD file, or "" when HEAD is
// detached (the file holds a raw object id) or unreadable.
func parseGitHead(head string) string {
	line := strings.TrimSpace(head)
	rest, ok := strings.CutPrefix(line, "ref:")
	if !ok {
		return ""
	}
	ref := strings.TrimSpace(rest)
	// refs/heads/main → main. Tags and remote-tracking refs are left in their
	// full form: they are not what a checkout normally points HEAD at, and
	// truncating them would produce a ref the remote does not have.
	if branch, isBranch := strings.CutPrefix(ref, "refs/heads/"); isBranch {
		return branch
	}
	return ref
}

// --- remote normalisation -----------------------------------------------------

// normalizeRemoteToHTTPS converts a git remote URL into the https form the
// workspace contract requires, or explains why it cannot.
//
// https is not a preference. The credential a fetch uses is brokered, and it
// travels as an Authorization header — over http that is a published token, and
// over ssh or git:// there is nothing the broker can lease at all. So the scp
// form every forge prints (git@host:owner/name.git) and ssh:// URLs are
// rewritten to their https equivalents, and everything else is refused by name.
func normalizeRemoteToHTTPS(remote string) (string, error) {
	raw := strings.TrimSpace(remote)
	if raw == "" {
		return "", errors.New("the origin remote is empty")
	}

	// scp-like syntax: [user@]host:path, with no scheme. Distinguished from a
	// URL by having no "://" and from a Windows drive letter by the host being
	// longer than one character.
	if !strings.Contains(raw, "://") {
		host, path, ok := strings.Cut(raw, ":")
		if !ok || strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, ".") {
			return "", fmt.Errorf("the origin remote %q is a local path, not a URL the executor "+
				"could fetch from", raw)
		}
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:]
		}
		host = strings.TrimSpace(host)
		path = strings.TrimSpace(path)
		if host == "" || len(host) < 2 || path == "" {
			return "", fmt.Errorf("the origin remote %q could not be read as host:path", raw)
		}
		return "https://" + host + "/" + strings.TrimPrefix(path, "/"), nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("the origin remote %q is not a URL: %v", raw, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "ssh", "git+ssh":
		// The port is deliberately dropped rather than carried across: an ssh
		// port says nothing about where the same forge serves https, and
		// https://host:22/ would be a confidently wrong URL.
		u.Scheme = "https"
		u.Host = u.Hostname()
	case "http", "git":
		return "", fmt.Errorf("the origin remote %q uses %s, which cannot carry a brokered "+
			"credential safely; use its https:// URL", raw, u.Scheme)
	case "file":
		return "", fmt.Errorf("the origin remote %q is a local path, which an executor on "+
			"another machine cannot reach", raw)
	default:
		return "", fmt.Errorf("the origin remote %q uses the unsupported scheme %q; "+
			"use its https:// URL", raw, u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("the origin remote %q has no host", raw)
	}
	// A remote with credentials in it is exactly what must not reach a Spec:
	// specs are persisted, logged and shipped to remote executors. Stripping
	// rather than refusing is deliberate — the URL still names the right
	// repository, and the grant is where the authority is supposed to come
	// from anyway.
	u.User = nil
	u.RawQuery, u.Fragment = "", ""
	return u.String(), nil
}

// --- driver credential source ---------------------------------------------------

// workspaceLeaseActor is the audit identity the drivers' workspace leases are
// taken under. Distinct from the "ui" actor on a workload's secret lease only
// in intent; kept identical in spelling so an operator filtering the broker
// trail by actor sees one session rather than two.
const workspaceLeaseActor = "ui"

// workspaceCredentialFactory builds the per-executor credential source the
// remote hub hands to each agent's driver.
//
// # Why the driver leases and not this package
//
// The obvious alternative is for the UI to lease the token and put it in the
// Spec. It cannot: a Spec is persisted by pkg/executorstore, marshalled across
// the remote boundary and echoed into audit rows, so a credential placed there
// would be durable in three places before anything used it. The Spec therefore
// carries only the *name* of a grant (see applyWorkspace), and the driver
// dispatching the workload leases the material at the last possible moment,
// holds it for one fetch, and releases it.
//
// db is the hub's own handle and is not closed here — the returned closure
// outlives this call by the life of the process, and the hub already keeps that
// handle open for exactly as long.
//
// A nil return means "no source": the hub then leaves every executor without
// one, and a workload naming a grant is refused rather than dispatched to fetch
// a private repository anonymously.
func workspaceCredentialFactory(db *statedb.DB) func(string) executor.WorkspaceCredentialSource {
	if db == nil {
		return nil
	}
	store, err := secretstore.New(db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: workspace credentials unavailable: %v\n", err)
		return nil
	}
	broker, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		// An install with no CLOOP_SECRET_KEY has not adopted the broker; that
		// is the ordinary state, not a fault, and it must not print on every
		// hub start. Anything else is a real failure worth a line.
		if !isBrokerUnconfigured(err) {
			fmt.Fprintf(os.Stderr, "ui: workspace credentials unavailable: %v\n", err)
		}
		return nil
	}
	return func(executorID string) executor.WorkspaceCredentialSource {
		src, err := gitcreds.New(broker, executorID, workspaceLeaseActor)
		if err != nil {
			// Returning src here would hand back a non-nil interface holding a
			// nil pointer, which the driver would call and panic on. The
			// literal nil is the difference between "no source" and "a broken
			// one".
			return nil
		}
		// Route through the git interception proxy when one is configured, so
		// the edge device gets a session token scoped to one repository and
		// the branch allowlist instead of the forge PAT. Nil-safe: with no
		// proxy the source is returned unchanged.
		return activeGitProxy().Wrap(executorID, src)
	}
}

// --- audit --------------------------------------------------------------------

// workspaceAuditActor is the identity provisioning rows are attributed to.
//
// "system", not the signed-in user, for the same reason auditImageDenial uses
// it: provisioning is decided by the dispatching control plane and also happens
// on the supervisor's failover path, where there is nobody. The identity that
// started the run is already in the trail and correlates by project and time.
const workspaceAuditActor = "system"

// workspaceAuditSink returns the function executor.AuditWorkspace calls,
// forwarding each provisioning event into the control plane's own journal.
//
// A handle is opened per event rather than held: a run produces exactly two of
// these, one at each end of a fetch, so the cost is two SQLite opens per run
// against a database this process opens on many other paths already — and the
// alternative, a connection held for the process's lifetime by a package-level
// sink, is a WAL lock nothing would ever release.
func workspaceAuditSink(dir string) func(executor.WorkspaceEvent) {
	return func(ev executor.WorkspaceEvent) {
		db, err := statedb.Open(state.DBPath(dir))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ui] workspace: audit %s for %s: %v\n",
				ev.Phase, ev.ProjectPath, err)
			return
		}
		defer db.Close()
		statedb.AuditWorkspaceProvision(db, statedb.WorkspaceAuditInput{
			Phase:        string(ev.Phase),
			ProjectPath:  ev.ProjectPath,
			ExecutorID:   ev.ExecutorID,
			ExecutorKind: ev.ExecutorKind,
			HandleID:     ev.HandleID,
			Kind:         string(ev.Workspace.Kind),
			Repo:         ev.Workspace.Repo,
			Ref:          ev.Workspace.Ref,
			Depth:        ev.Workspace.Depth,
			GrantID:      ev.GrantID,
			LeaseID:      ev.LeaseID,
			DurationMS:   ev.DurationMS,
			Err:          ev.Err,
			Actor:        workspaceAuditActor,
		})
	}
}
