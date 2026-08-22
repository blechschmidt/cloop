package executor

// Tests for the workspace contract (Task 20179).
//
// Everything here is pure: no git, no cluster, no device. That is the point of
// splitting the plan out of the two drivers that execute it — the rules about
// what may reach an argv and what may reach an environment are decided in one
// place and can be asserted exhaustively, instead of being inferred from a
// container that failed to start.

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func gitWS() Workspace {
	return Workspace{
		Kind:            WorkspaceGit,
		Repo:            "https://github.com/acme/tool.git",
		Ref:             "main",
		Depth:           1,
		CredentialGrant: "github-ci",
	}
}

func TestWorkspaceValidateAccepts(t *testing.T) {
	cases := map[string]Workspace{
		"unspecified":     {},
		"bind":            {Kind: WorkspaceBind},
		"none":            {Kind: WorkspaceNone},
		"git":             gitWS(),
		"git no ref":      {Kind: WorkspaceGit, Repo: "https://github.com/acme/tool.git"},
		"git full clone":  {Kind: WorkspaceGit, Repo: "https://github.com/acme/tool.git", Depth: 0},
		"git commit ref":  {Kind: WorkspaceGit, Repo: "https://git.example/a/b", Ref: "0f1e2d3c4b5a69788796a5b4c3d2e1f001122334"},
		"git slash ref":   {Kind: WorkspaceGit, Repo: "https://git.example/a/b", Ref: "release/1.2"},
		"git nested path": {Kind: WorkspaceGit, Repo: "https://gitlab.example/group/sub/proj.git"},
		"size limit":      {Kind: WorkspaceBind, SizeLimitMB: 2048},
	}
	for name, w := range cases {
		t.Run(name, func(t *testing.T) {
			if err := w.Validate(); err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

// TestWorkspaceValidateRejects is the security-relevant half. Each case is a
// value that would otherwise become an argv element, an environment variable or
// a URL a moment later.
func TestWorkspaceValidateRejects(t *testing.T) {
	cases := map[string]Workspace{
		"unknown kind": {Kind: WorkspaceKind("rsync")},
		// A URL carrying userinfo is how a credential gets into a struct that
		// is persisted, logged and shipped to a remote agent.
		"credentials in url": {Kind: WorkspaceGit, Repo: "https://x-access-token:ghp_secret@github.com/a/b"},
		// http would put the brokered Authorization header on the wire in
		// cleartext.
		"http scheme":  {Kind: WorkspaceGit, Repo: "http://github.com/a/b"},
		"ssh scheme":   {Kind: WorkspaceGit, Repo: "ssh://git@github.com/a/b"},
		"git scheme":   {Kind: WorkspaceGit, Repo: "git://github.com/a/b"},
		"file scheme":  {Kind: WorkspaceGit, Repo: "file:///etc/passwd"},
		"scp syntax":   {Kind: WorkspaceGit, Repo: "git@github.com:a/b.git"},
		"no repo":      {Kind: WorkspaceGit},
		"no host":      {Kind: WorkspaceGit, Repo: "https:///a/b"},
		"no path":      {Kind: WorkspaceGit, Repo: "https://github.com/"},
		"query":        {Kind: WorkspaceGit, Repo: "https://github.com/a/b?x=1"},
		"fragment":     {Kind: WorkspaceGit, Repo: "https://github.com/a/b#frag"},
		"repo newline": {Kind: WorkspaceGit, Repo: "https://github.com/a/b\nrm -rf /"},
		"repo space":   {Kind: WorkspaceGit, Repo: "https://github.com/a b"},
		// A ref beginning with a dash is read by git as a flag by the very
		// command meant to fetch it.
		"flag ref":       {Kind: WorkspaceGit, Repo: "https://github.com/a/b", Ref: "--upload-pack=touch /tmp/pwn"},
		"ref traversal":  {Kind: WorkspaceGit, Repo: "https://github.com/a/b", Ref: "a/../../b"},
		"ref space":      {Kind: WorkspaceGit, Repo: "https://github.com/a/b", Ref: "main branch"},
		"ref tilde":      {Kind: WorkspaceGit, Repo: "https://github.com/a/b", Ref: "main~1"},
		"ref colon":      {Kind: WorkspaceGit, Repo: "https://github.com/a/b", Ref: "a:b"},
		"ref lock":       {Kind: WorkspaceGit, Repo: "https://github.com/a/b", Ref: "main.lock"},
		"ref newline":    {Kind: WorkspaceGit, Repo: "https://github.com/a/b", Ref: "main\nother"},
		"negative depth": {Kind: WorkspaceGit, Repo: "https://github.com/a/b", Depth: -1},
		"huge depth":     {Kind: WorkspaceGit, Repo: "https://github.com/a/b", Depth: MaxWorkspaceDepth + 1},
		"negative size":  {Kind: WorkspaceGit, Repo: "https://github.com/a/b", SizeLimitMB: -1},
		"grant chars":    {Kind: WorkspaceGit, Repo: "https://github.com/a/b", CredentialGrant: "a b;rm"},
		// Setting a git field on a non-git kind is not a harmless extra: it is
		// an author who believes a clone will happen.
		"bind with repo":  {Kind: WorkspaceBind, Repo: "https://github.com/a/b"},
		"none with ref":   {Kind: WorkspaceNone, Ref: "main"},
		"none with grant": {Kind: WorkspaceNone, CredentialGrant: "github-ci"},
		"bind with depth": {Kind: WorkspaceBind, Depth: 1},
	}
	for name, w := range cases {
		t.Run(name, func(t *testing.T) {
			err := w.Validate()
			if err == nil {
				t.Fatalf("Validate() accepted %+v", w)
			}
			if !errors.Is(err, ErrInvalidSpec) {
				t.Errorf("Validate() = %v, want it to carry ErrInvalidSpec so the API renders a 400", err)
			}
		})
	}
}

// TestSpecRefusesGitWorkspaceWithoutNetwork: a tree that must be fetched and a
// workload forbidden from reaching the network is a contradiction whose natural
// failure — "could not resolve host", from a step nobody knew ran — points
// nowhere near either setting.
func TestSpecRefusesGitWorkspaceWithoutNetwork(t *testing.T) {
	spec := Spec{Argv: []string{"cloop", "run"}, Workspace: gitWS(), DisableNetwork: true}
	err := spec.Validate()
	if err == nil {
		t.Fatal("a git workspace with egress disabled was accepted")
	}
	if !strings.Contains(err.Error(), "github.com") {
		t.Errorf("the refusal does not name the host it cannot reach: %v", err)
	}

	// The same spec with egress permitted is fine, so the rule is about the
	// combination and not about git workspaces generally.
	spec.DisableNetwork = false
	if err := spec.Validate(); err != nil {
		t.Fatalf("a git workspace with egress permitted was refused: %v", err)
	}
}

func TestWorkspacePredicates(t *testing.T) {
	if !gitWS().NeedsProvisioning() {
		t.Error("a git workspace must need provisioning, or nothing fetches the tree")
	}
	for _, k := range []WorkspaceKind{WorkspaceUnspecified, WorkspaceBind, WorkspaceNone} {
		if (Workspace{Kind: k}).NeedsProvisioning() {
			t.Errorf("kind %q must not need provisioning", k)
		}
	}
	if !gitWS().RequiresCredential() {
		t.Error("a git workspace naming a grant requires a credential")
	}
	anon := gitWS()
	anon.CredentialGrant = ""
	if anon.RequiresCredential() {
		t.Error("a git workspace with no grant must fetch anonymously, not demand a credential")
	}
	if !(Workspace{}).IsZero() {
		t.Error("the zero workspace must report IsZero")
	}
}

func TestWorkspaceRepoDerivations(t *testing.T) {
	w := gitWS()
	if got := w.Host(); got != "github.com" {
		t.Errorf("Host() = %q", got)
	}
	// The base URL is what the extraHeader is scoped to. An unscoped header
	// follows redirects to third-party hosts and takes the credential along.
	if got := w.BaseURL(); got != "https://github.com/" {
		t.Errorf("BaseURL() = %q", got)
	}
	if got, ok := w.RepoPath(); !ok || got != "acme/tool" {
		t.Errorf("RepoPath() = %q, %v; want acme/tool, true", got, ok)
	}

	// A repository that is not owner/name cannot be matched against a GitHub
	// allowlist, and saying so is what lets the caller refuse rather than lease
	// a credential no constraint could have narrowed.
	nested := Workspace{Kind: WorkspaceGit, Repo: "https://gitlab.example/group/sub/proj.git"}
	if got, ok := nested.RepoPath(); ok {
		t.Errorf("RepoPath() = %q, true for a nested path; want false", got)
	}

	// Derivations on an invalid workspace must be empty rather than partial.
	bad := Workspace{Kind: WorkspaceGit, Repo: "http://github.com/a/b"}
	if bad.Host() != "" || bad.BaseURL() != "" {
		t.Errorf("derivations on a rejected repo returned %q / %q", bad.Host(), bad.BaseURL())
	}
}

// TestGitPlanShape pins the sequence and, more importantly, which single step
// carries the credential.
func TestGitPlanShape(t *testing.T) {
	plan, err := gitWS().GitPlan("/workspace")
	if err != nil {
		t.Fatalf("GitPlan: %v", err)
	}
	var names []string
	authenticated := 0
	for _, step := range plan {
		names = append(names, step.Name)
		if step.Argv[0] != "git" {
			t.Errorf("step %s runs %q, not git", step.Name, step.Argv[0])
		}
		if step.Authenticated {
			authenticated++
			if step.Name != "fetch" {
				t.Errorf("step %s is authenticated; only the step contacting the remote should be", step.Name)
			}
		}
	}
	if got := strings.Join(names, ","); got != "init,remote,fetch,checkout" {
		t.Errorf("plan = %s; want init,remote,fetch,checkout", got)
	}
	if authenticated != 1 {
		t.Errorf("%d authenticated steps, want exactly 1", authenticated)
	}

	// init + fetch rather than `git clone --branch`, because clone can only
	// name a branch or tag while a fetch can name a bare commit — a plan that
	// worked for "main" and failed for a pinned SHA would be found in
	// production.
	fetch := plan[2]
	joined := strings.Join(fetch.Argv, " ")
	for _, want := range []string{"--depth 1", "--no-tags", "-- origin main"} {
		if !strings.Contains(joined, want) {
			t.Errorf("fetch argv %q is missing %q", joined, want)
		}
	}

	// No ref means the remote's default branch, which is the one case where
	// the checkout target is not something the caller named.
	noRef := gitWS()
	noRef.Ref = ""
	noRef.Depth = 0
	plan, err = noRef.GitPlan("/workspace")
	if err != nil {
		t.Fatalf("GitPlan without a ref: %v", err)
	}
	joined = strings.Join(plan[2].Argv, " ")
	if !strings.HasSuffix(joined, "-- origin HEAD") {
		t.Errorf("fetch argv %q does not fall back to HEAD", joined)
	}
	if strings.Contains(joined, "--depth") {
		t.Errorf("fetch argv %q asked for a shallow fetch with depth 0", joined)
	}
}

func TestGitPlanRefusesNonGitAndEmptyDir(t *testing.T) {
	if _, err := (Workspace{Kind: WorkspaceBind}).GitPlan("/workspace"); err == nil {
		t.Error("a bind workspace produced a git plan; cloning over a bind mount would " +
			"overwrite the operator's own checkout")
	}
	if _, err := gitWS().GitPlan("  "); err == nil {
		t.Error("GitPlan accepted an empty target directory")
	}
	// An invalid workspace must not produce a plan that a driver would then
	// execute; validation happens inside GitPlan for exactly that reason.
	bad := gitWS()
	bad.Ref = "--upload-pack=evil"
	if _, err := bad.GitPlan("/workspace"); err == nil {
		t.Error("GitPlan built a plan from a ref that would be read as a flag")
	}
}

func TestGitCredentialEncoding(t *testing.T) {
	var zero GitCredential
	if !zero.Empty() || zero.AuthorizationHeader() != "" || zero.Secrets() != nil {
		t.Error("the zero credential must be inert")
	}

	c := GitCredential{Password: "ghp_secret_token_value", ExpiresAt: time.Now().Add(time.Hour)}
	if c.Empty() {
		t.Fatal("a credential with a password reports empty")
	}
	// An empty username defaults rather than producing "…:token", which GitHub
	// rejects with an error that reads like a bad token.
	header := c.AuthorizationHeader()
	if !strings.HasPrefix(header, "Basic ") {
		t.Fatalf("AuthorizationHeader() = %q", header)
	}
	if strings.Contains(header, c.Password) {
		t.Error("the header contains the raw token; it must be base64-encoded")
	}

	// Secrets must include the encoded form: git will happily quote a header
	// back in an error message, and only the raw token would be scrubbed
	// otherwise.
	secrets := c.Secrets()
	var sawRaw, sawEncoded bool
	for _, s := range secrets {
		if s == c.Password {
			sawRaw = true
		}
		if strings.Contains(header, s) && s != c.Password {
			sawEncoded = true
		}
	}
	if !sawRaw || !sawEncoded {
		t.Errorf("Secrets() = %v; must cover both the raw token and its base64 encoding", secrets)
	}
}

func TestGitCredentialEnvScopesTheHeader(t *testing.T) {
	w := gitWS()
	c := GitCredential{Username: "x-access-token", Password: "ghp_secret_token_value"}
	env, err := GitCredentialEnv(w, c)
	if err != nil {
		t.Fatalf("GitCredentialEnv: %v", err)
	}
	joined := strings.Join(env, "\n")

	if !strings.Contains(joined, "GIT_CONFIG_KEY_0=http.https://github.com/.extraHeader") {
		t.Errorf("the header is not scoped to the repository's origin:\n%s", joined)
	}
	// An inherited credential helper could answer the challenge with a
	// different credential, and the fetch would succeed using authority the
	// grant never issued.
	if !strings.Contains(joined, "GIT_CONFIG_KEY_1=credential.helper") ||
		!strings.Contains(joined, "GIT_CONFIG_VALUE_1=") {
		t.Errorf("the environment does not disable inherited credential helpers:\n%s", joined)
	}
	if !strings.Contains(joined, "GIT_CONFIG_COUNT=2") {
		t.Errorf("GIT_CONFIG_COUNT does not match the number of entries:\n%s", joined)
	}

	// No credential is not an error: a public repository fetches anonymously.
	env, err = GitCredentialEnv(w, GitCredential{})
	if err != nil || env != nil {
		t.Errorf("GitCredentialEnv with no credential = %v, %v; want nil, nil", env, err)
	}

	// A workspace with no usable URL cannot scope a header, and delivering an
	// unscoped one instead would be the wrong way to recover.
	if _, err := GitCredentialEnv(Workspace{Kind: WorkspaceBind}, c); err == nil {
		t.Error("GitCredentialEnv produced an unscoped header for a workspace with no repo")
	}
}

func TestGitBaseEnvIsClosed(t *testing.T) {
	joined := strings.Join(GitBaseEnv(), "\n")
	// Each of these turns a missing credential or a hostile configuration into
	// something other than a silent success.
	for _, want := range []string{
		"GIT_TERMINAL_PROMPT=0", // never block on a terminal nobody will answer
		"GIT_ASKPASS=",          // git treats an empty value as unset, so it points at /nonexistent
		"GIT_CONFIG_NOSYSTEM=1", // no /etc/gitconfig insteadOf rewrite
		"GIT_CONFIG_GLOBAL=",    // no ~/.gitconfig credential helper
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("GitBaseEnv is missing %q:\n%s", want, joined)
		}
	}
}

func TestRedactSecrets(t *testing.T) {
	const token = "ghp_secret_token_value"
	got := RedactSecrets("fatal: authentication failed for "+token, []string{token})
	if strings.Contains(got, token) {
		t.Fatalf("RedactSecrets left the token in %q", got)
	}
	if !strings.Contains(got, "[redacted]") {
		t.Errorf("RedactSecrets = %q; want a visible marker so the reader knows something was removed", got)
	}

	// A short "secret" is not a credential and is long enough to appear in
	// ordinary text; replacing it would corrupt the output for no benefit.
	if got := RedactSecrets("the abc of it", []string{"abc"}); got != "the abc of it" {
		t.Errorf("RedactSecrets mangled ordinary text: %q", got)
	}
	if got := RedactSecrets("nothing here", nil); got != "nothing here" {
		t.Errorf("RedactSecrets with no secrets = %q", got)
	}
}

func TestWorkspaceGrantErrorNamesTheFix(t *testing.T) {
	err := &WorkspaceGrantError{
		Repo:        "https://github.com/acme/tool.git",
		RepoPath:    "acme/tool",
		Grant:       "github-ci",
		ExecutorID:  "k8s-prod",
		ProjectPath: "/srv/acme",
		Reason:      "no active GitHub grant authorises acme/tool",
	}
	if !errors.Is(err, ErrWorkspaceGrantMissing) {
		t.Fatal("WorkspaceGrantError does not unwrap to its sentinel")
	}
	msg := err.Error()
	for _, want := range []string{"/srv/acme", "k8s-prod", "acme/tool", "cloop secret grant"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error omits %q, which is what the operator needs to act: %s", want, msg)
		}
	}

	// Without a repo path or an executor there is no command to suggest, and a
	// half-formed one would be worse than none.
	bare := &WorkspaceGrantError{Repo: "https://example.invalid/x"}
	if fix := bare.Remediation(); fix != "" {
		t.Errorf("Remediation() = %q for an error with nothing to name", fix)
	}
	if bare.Error() == "" {
		t.Error("an error with no remediation still needs a message")
	}
}

func TestSandboxRequirementsDeriveWorkspaceConstraints(t *testing.T) {
	git := Spec{Argv: []string{"cloop"}, Workspace: gitWS()}.SandboxRequirements()
	if !git.RequireWorkspaceProvisioning || git.RequireHostFilesystemWorkspace {
		t.Errorf("a git workspace derived %+v; want provisioning required and bind not", git)
	}

	bind := Spec{Argv: []string{"cloop"}, Workspace: Workspace{Kind: WorkspaceBind}}.SandboxRequirements()
	if bind.RequireWorkspaceProvisioning || !bind.RequireHostFilesystemWorkspace {
		t.Errorf("a bind workspace derived %+v; want the host filesystem required", bind)
	}

	// An unspecified workspace must constrain nothing, or every existing
	// caller that has no workspace concern would start failing placement.
	none := Spec{Argv: []string{"cloop"}}.SandboxRequirements()
	if none.RequireWorkspaceProvisioning || none.RequireHostFilesystemWorkspace {
		t.Errorf("an unspecified workspace derived %+v; want no workspace constraint", none)
	}
}

// TestWorkspaceAuditorIsOptionalAndSafe: the hook is process-wide because
// pkg/executor is imported by the edge agent, which has no audit store. An
// absent or misbehaving sink must never affect a workload.
func TestWorkspaceAuditorIsOptionalAndSafe(t *testing.T) {
	t.Cleanup(func() { SetWorkspaceAuditor(nil) })

	SetWorkspaceAuditor(nil)
	AuditWorkspace(WorkspaceEvent{Phase: WorkspaceProvisionStart}) // must not panic

	var got []WorkspaceEvent
	SetWorkspaceAuditor(func(ev WorkspaceEvent) { got = append(got, ev) })
	AuditWorkspace(WorkspaceEvent{Phase: WorkspaceProvisionStart, ExecutorID: "k8s"})
	AuditWorkspace(WorkspaceEvent{Phase: WorkspaceProvisionEnd, ExecutorID: "k8s", DurationMS: 12})
	if len(got) != 2 {
		t.Fatalf("the sink received %d events, want 2", len(got))
	}
	if got[0].Phase != WorkspaceProvisionStart || got[1].Phase != WorkspaceProvisionEnd {
		t.Errorf("phases arrived as %q, %q", got[0].Phase, got[1].Phase)
	}

	// A sink that panics must not take down the workload it was reporting on.
	SetWorkspaceAuditor(func(WorkspaceEvent) { panic("sink is broken") })
	AuditWorkspace(WorkspaceEvent{Phase: WorkspaceProvisionEnd})
}

func TestWorkspaceDescribeIsLogSafe(t *testing.T) {
	cases := map[Workspace]string{
		{}:                    "unspecified",
		{Kind: WorkspaceBind}: "bind (host filesystem)",
		{Kind: WorkspaceNone}: "none (empty tree)",
		gitWS():               "git https://github.com/acme/tool.git@main (depth 1) using grant github-ci",
	}
	for w, want := range cases {
		if got := w.Describe(); got != want {
			t.Errorf("Describe() = %q, want %q", got, want)
		}
	}
}
