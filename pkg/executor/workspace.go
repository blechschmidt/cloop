// workspace.go describes how a workload's source tree gets *into* the place the
// workload runs.
//
// Until this file existed, cloop had no answer to that question for any
// executor that does not share the control plane's filesystem. The container
// driver worked because it bind-mounts a host path; every other driver started
// the harness in a directory that was created and then left empty — the
// Kubernetes driver mounted an emptyDir at /workspace and its own comment
// conceded that "the workload is expected to populate it", and the remote agent
// MkdirAll'd a directory beneath its root. Nothing populated either. The result
// was a run that started cleanly, produced a plausible-looking transcript, and
// operated on no code at all.
//
// So a Spec now says which of the three possible answers applies:
//
//   - bind: the tree is already at WorkDir because the executor shares the
//     control plane's filesystem. Nothing to do, and nothing may be done —
//     cloning over a bind mount would rewrite the operator's own checkout.
//   - git: the executor must fetch the tree before the harness starts.
//   - none: the workload genuinely wants an empty directory (a smoke test, a
//     scratch build). Stated, so it cannot be confused with the bug.
//
// # Credentials
//
// A private repository needs authentication, and the whole point of the secret
// broker is that the credential is short-lived, narrowly scoped, and never
// durable on the executor. Two rules follow, and they shape every function
// here:
//
//   - the credential is never part of a Spec. A Spec is persisted (see
//     pkg/executorstore, which records the dispatched spec), logged, and
//     shipped across the remote-executor boundary. Workspace names a *grant*;
//     the driver leases the material at dispatch time and carries it out of
//     band. There is deliberately no field on this struct that could hold a
//     token, so no future caller can put one there.
//   - the credential never reaches a command line or a file. It travels in the
//     environment of the single git invocation that talks to the remote, as an
//     http.<base>.extraHeader — which is what GitHub's own actions/checkout
//     does, for the same reason: argv is world-readable through /proc and a
//     credential file outlives the process that needed it.
package executor

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// WorkspaceKind selects how a workload's source tree is materialised.
type WorkspaceKind string

const (
	// WorkspaceUnspecified is the zero value: the Spec says nothing, and the
	// driver keeps whatever behaviour it had. It exists so a caller that has
	// no workspace concern at all (a smoke test, `cloop executor test`) is not
	// forced to make a declaration it has no basis for.
	WorkspaceUnspecified WorkspaceKind = ""
	// WorkspaceBind: WorkDir already holds the tree because the executor
	// shares the control plane's filesystem. Only valid on a driver whose
	// Capabilities report SharesHostFilesystem.
	WorkspaceBind WorkspaceKind = "bind"
	// WorkspaceGit: the executor clones Repo at Ref into WorkDir before
	// starting the harness.
	WorkspaceGit WorkspaceKind = "git"
	// WorkspaceNone: an intentionally empty working tree.
	WorkspaceNone WorkspaceKind = "none"
)

// Valid reports whether k is one of the known kinds.
func (k WorkspaceKind) Valid() bool {
	switch k {
	case WorkspaceUnspecified, WorkspaceBind, WorkspaceGit, WorkspaceNone:
		return true
	}
	return false
}

// Bounds on the fields, all of which arrive from outside this process.
const (
	// MaxWorkspaceRepoLen bounds the clone URL. Real ones are under 200 bytes;
	// this is generous and still keeps an unbounded string out of an argv, a
	// label, and an audit row.
	MaxWorkspaceRepoLen = 2048
	// MaxWorkspaceRefLen matches git's own limit on a single refname component
	// budget closely enough to reject nonsense without rejecting reality.
	MaxWorkspaceRefLen = 255
	// MaxWorkspaceDepth bounds a shallow fetch. Past this the "shallow" is
	// doing nothing but the request is still a full history walk on the
	// server, so it is better read as a typo.
	MaxWorkspaceDepth = 100000
	// MaxWorkspaceGrantLen bounds the grant reference.
	MaxWorkspaceGrantLen = 128
)

// Workspace describes how to materialise the project's source tree inside the
// executor. The zero value means "unspecified"; see WorkspaceUnspecified.
type Workspace struct {
	// Kind selects the strategy.
	Kind WorkspaceKind `json:"kind,omitempty"`
	// Repo is the clone URL for Kind git. https only: a token delivered over
	// cleartext http is not a short-lived credential, it is a published one.
	Repo string `json:"repo,omitempty"`
	// Ref is the branch, tag or commit to check out. Empty means the remote's
	// default branch.
	Ref string `json:"ref,omitempty"`
	// Depth is the shallow-fetch depth; 0 fetches full history.
	Depth int `json:"depth,omitempty"`
	// CredentialGrant names the secret grant whose material authenticates the
	// fetch — never the material itself. Empty means an unauthenticated
	// fetch, which only works for a public repository.
	CredentialGrant string `json:"credential_grant,omitempty"`
	// SizeLimitMB bounds the provisioned tree, from the project's
	// .cloop/sandbox.yaml resources.disk. 0 means the executor's own default.
	SizeLimitMB int `json:"size_limit_mb,omitempty"`
}

// NeedsProvisioning reports whether the executor must do work before the
// harness can start. This is the predicate that turns into a placement
// requirement, so it is deliberately narrow: only git needs anything.
func (w Workspace) NeedsProvisioning() bool { return w.Kind == WorkspaceGit }

// RequiresCredential reports whether provisioning needs a leased credential.
func (w Workspace) RequiresCredential() bool {
	return w.NeedsProvisioning() && strings.TrimSpace(w.CredentialGrant) != ""
}

// IsZero reports whether the workspace says nothing at all.
func (w Workspace) IsZero() bool { return w == Workspace{} }

// Validate checks the driver-independent invariants.
//
// Every rule here is about the fields becoming an argv, an environment
// variable, or a URL a moment later. A ref that starts with "-" would be read
// by git as a flag; a repo URL carrying userinfo would smuggle a credential
// into a struct that gets persisted and logged; a non-https scheme would put a
// brokered token on the wire in cleartext.
func (w Workspace) Validate() error {
	if !w.Kind.Valid() {
		return fmt.Errorf("%w: workspace kind %q is not one of bind, git, none",
			ErrInvalidSpec, w.Kind)
	}
	if w.SizeLimitMB < 0 {
		return fmt.Errorf("%w: workspace size_limit_mb must be >= 0, got %d",
			ErrInvalidSpec, w.SizeLimitMB)
	}
	if g := strings.TrimSpace(w.CredentialGrant); g != "" {
		if len(g) > MaxWorkspaceGrantLen {
			return fmt.Errorf("%w: workspace credential_grant is %d bytes, at most %d are allowed",
				ErrInvalidSpec, len(g), MaxWorkspaceGrantLen)
		}
		if err := validateGrantRef(g); err != nil {
			return fmt.Errorf("%w: workspace credential_grant: %w", ErrInvalidSpec, err)
		}
	}

	if w.Kind != WorkspaceGit {
		// The git-only fields must be empty rather than ignored. A spec that
		// sets Kind: bind and a Repo is not a spec with a harmless extra
		// field — it is one whose author believes a clone will happen.
		switch {
		case strings.TrimSpace(w.Repo) != "":
			return fmt.Errorf("%w: workspace repo is set but kind is %q, not git", ErrInvalidSpec, w.Kind)
		case strings.TrimSpace(w.Ref) != "":
			return fmt.Errorf("%w: workspace ref is set but kind is %q, not git", ErrInvalidSpec, w.Kind)
		case w.Depth != 0:
			return fmt.Errorf("%w: workspace depth is set but kind is %q, not git", ErrInvalidSpec, w.Kind)
		case strings.TrimSpace(w.CredentialGrant) != "":
			return fmt.Errorf("%w: workspace credential_grant is set but kind is %q, not git",
				ErrInvalidSpec, w.Kind)
		}
		return nil
	}

	if _, err := w.parseRepo(); err != nil {
		return err
	}
	if err := validateGitRef(w.Ref); err != nil {
		return fmt.Errorf("%w: workspace ref: %w", ErrInvalidSpec, err)
	}
	switch {
	case w.Depth < 0:
		return fmt.Errorf("%w: workspace depth must be >= 0, got %d", ErrInvalidSpec, w.Depth)
	case w.Depth > MaxWorkspaceDepth:
		return fmt.Errorf("%w: workspace depth %d exceeds the maximum of %d",
			ErrInvalidSpec, w.Depth, MaxWorkspaceDepth)
	}
	return nil
}

// parseRepo validates and returns the clone URL.
func (w Workspace) parseRepo() (*url.URL, error) {
	raw := strings.TrimSpace(w.Repo)
	switch {
	case raw == "":
		return nil, fmt.Errorf("%w: workspace kind git requires a repo URL", ErrInvalidSpec)
	case len(raw) > MaxWorkspaceRepoLen:
		return nil, fmt.Errorf("%w: workspace repo is %d bytes, at most %d are allowed",
			ErrInvalidSpec, len(raw), MaxWorkspaceRepoLen)
	case strings.ContainsAny(raw, " \t\r\n"):
		return nil, fmt.Errorf("%w: workspace repo contains whitespace", ErrInvalidSpec)
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return nil, fmt.Errorf("%w: workspace repo contains a control character", ErrInvalidSpec)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: workspace repo %q is not a URL: %v", ErrInvalidSpec, raw, err)
	}
	switch {
	case u.Scheme != "https":
		// http would put the brokered Authorization header on the wire in
		// cleartext; ssh and git:// need a key or offer no authentication at
		// all, neither of which the broker can lease.
		return nil, fmt.Errorf("%w: workspace repo must be an https:// URL, got scheme %q",
			ErrInvalidSpec, u.Scheme)
	case u.User != nil:
		// This is the rule that keeps credentials out of the persisted spec.
		return nil, fmt.Errorf("%w: workspace repo must not embed credentials in the URL; "+
			"grant a secret and set credential_grant instead", ErrInvalidSpec)
	case u.Host == "":
		return nil, fmt.Errorf("%w: workspace repo has no host", ErrInvalidSpec)
	case strings.Trim(u.Path, "/") == "":
		return nil, fmt.Errorf("%w: workspace repo has no path", ErrInvalidSpec)
	case u.RawQuery != "" || u.Fragment != "":
		return nil, fmt.Errorf("%w: workspace repo must not carry a query or fragment", ErrInvalidSpec)
	}
	return u, nil
}

// Host returns the repo's host, or "" when the workspace is not a git one.
func (w Workspace) Host() string {
	u, err := w.parseRepo()
	if err != nil {
		return ""
	}
	return u.Host
}

// BaseURL returns "https://host/", the key prefix an http.<base>.extraHeader
// setting is scoped to.
//
// Scoping matters: an unscoped http.extraHeader is sent to *every* host git
// contacts, including whatever a redirect points at. Scoping it to the origin
// means a repository that redirects elsewhere gets a fetch failure rather than
// a leaked Authorization header.
func (w Workspace) BaseURL() string {
	u, err := w.parseRepo()
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/"
}

// RepoPath returns the "owner/name" form used to match a GitHub grant's
// repository allowlist, and whether the URL had that shape at all.
func (w Workspace) RepoPath() (string, bool) {
	u, err := w.parseRepo()
	if err != nil {
		return "", false
	}
	p := strings.Trim(u.Path, "/")
	p = strings.TrimSuffix(p, ".git")
	if p == "" || strings.Count(p, "/") != 1 {
		return "", false
	}
	return p, true
}

// Describe renders the workspace for a log line or an audit row. It can never
// contain a credential — Workspace has no field that could hold one — so it is
// safe to emit anywhere.
func (w Workspace) Describe() string {
	switch w.Kind {
	case WorkspaceGit:
		s := "git " + strings.TrimSpace(w.Repo)
		if r := strings.TrimSpace(w.Ref); r != "" {
			s += "@" + r
		}
		if w.Depth > 0 {
			s += " (depth " + strconv.Itoa(w.Depth) + ")"
		}
		if g := strings.TrimSpace(w.CredentialGrant); g != "" {
			s += " using grant " + g
		}
		return s
	case WorkspaceBind:
		return "bind (host filesystem)"
	case WorkspaceNone:
		return "none (empty tree)"
	default:
		return "unspecified"
	}
}

// --- provisioning plan ------------------------------------------------------

// GitStep is one command in a workspace provisioning plan.
type GitStep struct {
	// Name identifies the step for logs and audit records.
	Name string
	// Argv is the command. Argv[0] is always "git" and no element is ever
	// passed through a shell.
	Argv []string
	// Authenticated marks the single step that contacts the remote and so
	// receives the credential in its environment. Exactly one step in a plan
	// has it set, which is what lets a driver deliver the token to one child
	// process instead of to the whole provisioning sequence.
	Authenticated bool
}

// GitPlan returns the ordered commands that materialise w into dir.
//
// It is init + fetch + checkout rather than `git clone`, because clone can only
// name a branch or tag with --branch while a fetch can name any ref including a
// bare commit SHA. A plan that works for "main" and silently fails for a pinned
// commit would be the sort of thing discovered in production.
//
// The plan is pure: no I/O, no clock, no environment. That is what lets both
// the Kubernetes init container and the remote agent render the *same*
// sequence, and lets a test assert on it without a git binary.
func (w Workspace) GitPlan(dir string) ([]GitStep, error) {
	if w.Kind != WorkspaceGit {
		return nil, fmt.Errorf("%w: workspace kind %q has no git plan", ErrInvalidSpec, w.Kind)
	}
	if err := w.Validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("%w: workspace target directory is empty", ErrInvalidSpec)
	}

	repo := strings.TrimSpace(w.Repo)
	fetch := []string{"git", "-C", dir, "fetch", "--no-tags", "--prune"}
	if w.Depth > 0 {
		fetch = append(fetch, "--depth", strconv.Itoa(w.Depth))
	}
	// "--" before the remote and refspec so a value that somehow reached here
	// starting with a dash is an unknown remote rather than an unknown flag.
	fetch = append(fetch, "--", "origin")
	ref := strings.TrimSpace(w.Ref)
	if ref != "" {
		fetch = append(fetch, ref)
	} else {
		// No ref: fetch HEAD, which resolves to whatever the remote's default
		// branch is. This is the one case where the checkout target is not
		// something the caller named.
		fetch = append(fetch, "HEAD")
	}

	return []GitStep{
		{Name: "init", Argv: []string{"git", "init", "--quiet", "--", dir}},
		{Name: "remote", Argv: []string{"git", "-C", dir, "remote", "add", "origin", "--", repo}},
		{Name: "fetch", Argv: fetch, Authenticated: true},
		{Name: "checkout", Argv: []string{"git", "-C", dir, "checkout", "--quiet", "--detach", "FETCH_HEAD"}},
	}, nil
}

// GitCredential is the material one authenticated fetch needs.
//
// It is *not* part of Spec and must never be put there: a Spec is persisted by
// pkg/executorstore, echoed into audit rows, and marshalled across the remote
// boundary. Drivers lease this at dispatch time and carry it out of band.
type GitCredential struct {
	// Username and Password are HTTP basic credentials. For a GitHub PAT the
	// broker's convention is username "x-access-token" and the token as the
	// password.
	Username string
	Password string
	// LeaseID, GrantID and SecretName are bookkeeping for the audit trail and
	// for releasing the lease afterwards. None of them is secret.
	LeaseID    string
	GrantID    string
	SecretName string
	// ExpiresAt is the lease deadline, so a driver can refuse to start a
	// provisioning step whose credential will expire mid-fetch.
	ExpiresAt time.Time
}

// Empty reports whether there is no credential to deliver.
func (c GitCredential) Empty() bool { return strings.TrimSpace(c.Password) == "" }

// AuthorizationHeader renders the credential as an HTTP basic header value.
func (c GitCredential) AuthorizationHeader() string {
	if c.Empty() {
		return ""
	}
	user := strings.TrimSpace(c.Username)
	if user == "" {
		user = "x-access-token"
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+c.Password))
}

// Secrets returns every string that must be scrubbed from output before it
// leaves the executor: the token itself and its base64 encoding, since a git
// error message may echo either.
func (c GitCredential) Secrets() []string {
	if c.Empty() {
		return nil
	}
	out := []string{c.Password}
	if h := c.AuthorizationHeader(); h != "" {
		out = append(out, strings.TrimPrefix(h, "Basic "), h)
	}
	return out
}

// GitBaseEnv returns the environment every step of a plan runs with, credential
// or not.
//
// It is a closed environment rather than an inherited one. A provisioning step
// that read the executor's own ~/.gitconfig could pick up a credential helper,
// an insteadOf rewrite pointing the fetch at another host, or a proxy — all
// decided by whoever last touched that machine rather than by the grant.
func GitBaseEnv() []string {
	return []string{
		// No prompting, ever. A git that blocks on a terminal that will never
		// answer turns a missing credential into a hung task.
		"GIT_TERMINAL_PROMPT=0",
		// /nonexistent rather than empty: git treats an empty GIT_ASKPASS as
		// unset and falls back to its own prompting.
		"GIT_ASKPASS=/nonexistent",
		"SSH_ASKPASS=/nonexistent",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		// Advertise the workload, so a server-side log names cloop rather than
		// an anonymous git.
		"GIT_HTTP_USER_AGENT=cloop-workspace",
	}
}

// GitCredentialEnv returns the additional environment for the authenticated
// step of a plan.
//
// The credential is delivered as a URL-scoped http.extraHeader through git's
// GIT_CONFIG_COUNT protocol. That is the only delivery path here that satisfies
// all three constraints at once: nothing is written to disk, nothing appears in
// argv (which /proc publishes to every process with the same uid), and the
// header is scoped to the repository's own origin so a redirect cannot carry it
// to a third party.
//
// The empty credential.helper entry is not redundant: without it, a helper
// configured in a location GIT_CONFIG_GLOBAL does not cover could still answer
// the challenge with a *different* credential, and the fetch would succeed
// using authority the grant never issued.
func GitCredentialEnv(w Workspace, c GitCredential) ([]string, error) {
	if c.Empty() {
		return nil, nil
	}
	base := w.BaseURL()
	if base == "" {
		return nil, fmt.Errorf("%w: workspace has no usable repo URL to scope the credential to",
			ErrInvalidSpec)
	}
	header := c.AuthorizationHeader()
	if strings.ContainsAny(header, "\r\n") {
		// Unreachable via base64, but a header value that could carry a
		// newline would be a header-injection primitive against the remote.
		return nil, fmt.Errorf("%w: workspace credential encodes to a multi-line header", ErrInvalidSpec)
	}
	return []string{
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=http." + base + ".extraHeader",
		"GIT_CONFIG_VALUE_0=Authorization: " + header,
		"GIT_CONFIG_KEY_1=credential.helper",
		"GIT_CONFIG_VALUE_1=",
	}, nil
}

// WorkspaceCredentialSource leases the credential one git workspace fetch
// needs.
//
// It is an interface with no secret-broker types in it so that pkg/executor
// stays a leaf package — the remote agent imports it and must not drag the
// hub's secret store onto an edge device — and so a driver test can supply a
// fake credential without a database, a sealing key, or a grant.
//
// The release function returned alongside the credential is always non-nil,
// including on error paths, so callers can defer it unconditionally.
type WorkspaceCredentialSource interface {
	// ForWorkspace leases material authorising a fetch of w on behalf of
	// projectID. A workspace that needs no credential yields the zero
	// GitCredential, a no-op release, and a nil error.
	//
	// When no grant authorises the fetch the error is a
	// *WorkspaceGrantError, which names the missing grant. Drivers surface it
	// unchanged rather than starting a workload against an empty tree.
	ForWorkspace(ctx context.Context, projectID string, w Workspace) (GitCredential, func(), error)
}

// --- audit ------------------------------------------------------------------

// WorkspaceEventPhase distinguishes the two rows one provisioning produces.
type WorkspaceEventPhase string

const (
	// WorkspaceProvisionStart is emitted before the first fetch byte moves.
	WorkspaceProvisionStart WorkspaceEventPhase = "start"
	// WorkspaceProvisionEnd is emitted once, whether it succeeded or not.
	WorkspaceProvisionEnd WorkspaceEventPhase = "end"
)

// WorkspaceEvent is one provisioning observation for the compliance trail.
//
// Provisioning is worth its own rows rather than being folded into the run's
// because it is the moment a brokered credential is used against an external
// service. "Which grant fetched which repository onto which executor, and did
// it work" is the question an operator has after an incident, and the run's own
// record cannot answer it — the run may look identical whether the tree arrived
// or not, which is the whole reason this subsystem exists.
//
// It carries no credential. GrantID and LeaseID are identifiers; the token is
// never in scope here.
type WorkspaceEvent struct {
	Phase        WorkspaceEventPhase
	ExecutorID   string
	ExecutorKind string
	HandleID     string
	ProjectPath  string
	Workspace    Workspace
	GrantID      string
	LeaseID      string
	// DurationMS is set on the end event only.
	DurationMS int64
	// Err is the failure, already redacted, or "" on success.
	Err string
}

var workspaceAuditor atomic.Pointer[func(WorkspaceEvent)]

// SetWorkspaceAuditor installs the sink provisioning events are reported to.
//
// It is a process-wide hook rather than a field on every driver because the
// drivers must not depend on the hub's database: pkg/executor is imported by
// the edge agent, which has no audit store and no business linking one. The
// control plane installs the sink at bootstrap; anywhere else the events are
// dropped, which is correct — an agent's local provisioning is audited by the
// hub that dispatched it.
//
// Passing nil disables auditing.
func SetWorkspaceAuditor(f func(WorkspaceEvent)) {
	if f == nil {
		workspaceAuditor.Store(nil)
		return
	}
	workspaceAuditor.Store(&f)
}

// AuditWorkspace reports a provisioning event to the installed sink.
//
// Best-effort and non-blocking on the caller's correctness: a sink that panics
// must not take down a workload that is otherwise fine, so the recover is here
// rather than in every sink.
func AuditWorkspace(ev WorkspaceEvent) {
	fn := workspaceAuditor.Load()
	if fn == nil {
		return
	}
	defer func() { _ = recover() }()
	(*fn)(ev)
}

// RedactSecrets replaces every occurrence of each secret in s with a fixed
// marker.
//
// Provisioning output is streamed to the run panel and persisted as an
// artifact, and git is perfectly willing to quote a URL or a header back in an
// error message. Redacting at the point output leaves the provisioning step is
// the only place that catches every such path; filtering at the display layer
// would leave the artifact on disk.
func RedactSecrets(s string, secrets []string) string {
	for _, sec := range secrets {
		if len(sec) < 8 {
			// Too short to be a credential and long enough to appear in
			// ordinary text; replacing it would corrupt the output for no
			// security benefit.
			continue
		}
		s = strings.ReplaceAll(s, sec, "[redacted]")
	}
	return s
}

// --- errors -----------------------------------------------------------------

// ErrWorkspaceGrantMissing: a git workspace needs a credential the project does
// not hold. Match the sentinel; read the *WorkspaceGrantError for the detail.
var ErrWorkspaceGrantMissing = errors.New("executor: no secret grant can authenticate this workspace")

// ErrWorkspaceUnavailable: the source tree could not be materialised. It is
// distinct from a harness failure because the remedy is entirely different —
// nothing about the task's code is implicated.
var ErrWorkspaceUnavailable = errors.New("executor: workspace could not be provisioned")

// WorkspaceGrantError names the grant a workload needed and did not have.
//
// It is typed, and it names the missing grant, because the alternative that
// this whole task exists to remove is a run that proceeds against an empty
// directory. "Missing credential" as a bare string would be indistinguishable
// from a dozen other refusals; the operator's next question is always "which
// repository, on which executor, and what do I create" — so the error answers
// all three and Remediation() prints the command.
type WorkspaceGrantError struct {
	// Repo is the clone URL that could not be authenticated.
	Repo string
	// RepoPath is the owner/name form, when the URL had one.
	RepoPath string
	// Grant is the grant the spec named, or "" when none was named and none
	// could be inferred.
	Grant string
	// ExecutorID is the executor the workload was bound to.
	ExecutorID string
	// ProjectPath is the project whose run was refused.
	ProjectPath string
	// Reason distinguishes "no grant exists" from "a grant exists but excludes
	// this repository" — different fixes, so they must not read alike.
	Reason string
}

// Error implements error.
func (e *WorkspaceGrantError) Error() string {
	var b strings.Builder
	b.WriteString("executor: cannot provision the workspace for ")
	if e.ProjectPath != "" {
		b.WriteString(e.ProjectPath)
	} else {
		b.WriteString("this project")
	}
	if e.ExecutorID != "" {
		b.WriteString(" on executor " + e.ExecutorID)
	}
	b.WriteString(": ")
	if e.Reason != "" {
		b.WriteString(e.Reason)
	} else if e.Grant != "" {
		b.WriteString("grant " + e.Grant + " is not available")
	} else {
		b.WriteString("no grant authorises " + e.Repo)
	}
	if fix := e.Remediation(); fix != "" {
		b.WriteString(" — " + fix)
	}
	return b.String()
}

// Unwrap lets callers match errors.Is(err, ErrWorkspaceGrantMissing).
func (e *WorkspaceGrantError) Unwrap() error { return ErrWorkspaceGrantMissing }

// Remediation returns the command that fixes this, or "" when there is nothing
// specific to suggest.
func (e *WorkspaceGrantError) Remediation() string {
	if e.RepoPath == "" || e.ExecutorID == "" {
		return ""
	}
	name := e.Grant
	if name == "" {
		name = "<github-pat-secret>"
	}
	return fmt.Sprintf(
		"grant one with: cloop secret grant %s --to executor:%s --repos %s",
		name, e.ExecutorID, e.RepoPath)
}

// --- validation helpers -----------------------------------------------------

// validateGrantRef bounds a grant reference to characters that are safe in a
// log line, an audit row, and a Kubernetes label value.
func validateGrantRef(s string) error {
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':':
		default:
			return fmt.Errorf("%q contains %q; use [A-Za-z0-9-_.:]", s, r)
		}
	}
	return nil
}

// validateGitRef applies a conservative subset of git's own check-ref-format
// rules, plus the argv rule git does not have.
//
// The subset is deliberately tighter than git's: this value becomes an argv
// element and an audit field, and a ref that git would accept but that starts
// with a dash would be parsed as a flag by the very command meant to fetch it.
func validateGitRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		// Empty is legal: it means the remote's default branch.
		return nil
	}
	if len(ref) > MaxWorkspaceRefLen {
		return fmt.Errorf("ref is %d bytes, at most %d are allowed", len(ref), MaxWorkspaceRefLen)
	}
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("ref %q starts with a dash, which git would read as a flag", ref)
	}
	for _, r := range ref {
		switch {
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("ref contains a control character")
		case r == ' ', r == '~', r == '^', r == ':', r == '?', r == '*', r == '[', r == '\\':
			return fmt.Errorf("ref %q contains %q, which git forbids in a refname", ref, r)
		}
	}
	switch {
	case strings.Contains(ref, ".."):
		return fmt.Errorf("ref %q contains \"..\"", ref)
	case strings.Contains(ref, "//"):
		return fmt.Errorf("ref %q contains \"//\"", ref)
	case strings.Contains(ref, "@{"):
		return fmt.Errorf("ref %q contains \"@{\"", ref)
	case strings.HasSuffix(ref, ".lock"), strings.HasSuffix(ref, "/"), strings.HasSuffix(ref, "."):
		return fmt.Errorf("ref %q ends with a sequence git forbids", ref)
	case ref == "@":
		return fmt.Errorf("ref %q is not a refname", ref)
	}
	return nil
}
