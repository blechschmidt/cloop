package ui

// Tests for the source-tree decision (Task 20179).
//
// Nothing here starts a run. A successful POST to /api/run — or any other path
// that reaches a real executor — poisons process-global executor state and
// flakes the whole package, so every test below builds a Spec and calls the
// helper directly against a fake executor whose Start method is never reached.
//
// The git fixtures are written by hand rather than by shelling out to git. That
// is not only convenient: pkg/ui is forbidden from spawning processes (see
// no_direct_exec_test.go), so the code under test reads .git/config and
// .git/HEAD itself, and a fixture built the same way is the honest input.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// --- fixtures ---------------------------------------------------------------

// workspaceTestExecutor is an executor that only answers questions about
// itself. Start and friends fail loudly: a test that reaches them has started
// real work, which is exactly what this package's tests must not do.
type workspaceTestExecutor struct {
	id   string
	kind string
	caps executor.Capabilities
}

func (e *workspaceTestExecutor) ID() string                          { return e.id }
func (e *workspaceTestExecutor) Kind() string                        { return e.kind }
func (e *workspaceTestExecutor) Capabilities() executor.Capabilities { return e.caps }

func (e *workspaceTestExecutor) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, errors.New("workspaceTestExecutor: Start must not be called")
}
func (e *workspaceTestExecutor) Signal(context.Context, string, executor.Signal) error {
	return errors.New("workspaceTestExecutor: Signal must not be called")
}
func (e *workspaceTestExecutor) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, errors.New("workspaceTestExecutor: Status must not be called")
}
func (e *workspaceTestExecutor) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	return nil, errors.New("workspaceTestExecutor: Stream must not be called")
}
func (e *workspaceTestExecutor) HealthCheck(context.Context) error { return nil }

// hostExecutor shares the control plane's filesystem, like localprocess and
// container do.
func hostExecutor() *workspaceTestExecutor {
	return &workspaceTestExecutor{
		id:   "local",
		kind: executor.KindLocalProcess,
		caps: executor.Capabilities{SharesHostFilesystem: true},
	}
}

// remoteExecutor sees no part of the control plane's filesystem and can fetch
// its own tree, like the Kubernetes and remote-agent drivers.
func remoteExecutor() *workspaceTestExecutor {
	return &workspaceTestExecutor{
		id:   "edge-01",
		kind: executor.KindRemoteAgent,
		caps: executor.Capabilities{
			Isolation:                     executor.IsolationRemote,
			SharesHostFilesystem:          false,
			SupportsWorkspaceProvisioning: true,
		},
	}
}

// writeGitFixture creates a project directory whose git metadata says it was
// cloned from remote and has head checked out. head may be a branch name or
// "detached" for a raw object id.
func writeGitFixture(t *testing.T, remote, head string) string {
	t.Helper()
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	cfg := "[core]\n\trepositoryformatversion = 0\n"
	if remote != "" {
		cfg += "[remote \"origin\"]\n\turl = " + remote +
			"\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
	}
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	content := "ref: refs/heads/" + head + "\n"
	if head == "detached" {
		content = "9c1f0e2b7a5d4c3b2a1908f7e6d5c4b3a2918070\n"
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte(content), 0o644); err != nil {
		t.Fatalf("write HEAD: %v", err)
	}
	return dir
}

// useControlPlaneDir points the package-level control-plane directory at dir
// for the duration of one test, restoring whatever was there before.
func useControlPlaneDir(t *testing.T, dir string) {
	t.Helper()
	controlPlaneDirMu.Lock()
	previous := controlPlaneDirValue
	controlPlaneDirValue = dir
	controlPlaneDirMu.Unlock()
	t.Cleanup(func() {
		controlPlaneDirMu.Lock()
		controlPlaneDirValue = previous
		controlPlaneDirMu.Unlock()
	})
}

// newWorkspaceControlPlane creates a control plane with an initialised state
// database and a sealing key, and points the package at it. It returns the
// directory.
func newWorkspaceControlPlane(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("generate sealing key: %v", err)
	}
	t.Setenv("CLOOP_SECRET_KEY", base64.StdEncoding.EncodeToString(key[:]))

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close state db: %v", err)
	}
	useControlPlaneDir(t, dir)
	return dir
}

// --- the decision -----------------------------------------------------------

// TestApplyWorkspaceBindsOnHostFilesystemExecutor: when the executor is looking
// at the same filesystem, the tree is already there and provisioning would
// clone over the operator's own checkout.
func TestApplyWorkspaceBindsOnHostFilesystemExecutor(t *testing.T) {
	dir := writeGitFixture(t, "https://github.com/acme/widgets.git", "main")

	spec, err := applyWorkspace(uiSpec(dir, []string{"cloop", "run"}, nil), hostExecutor(), dir)
	if err != nil {
		t.Fatalf("applyWorkspace: %v", err)
	}
	if spec.Workspace.Kind != executor.WorkspaceBind {
		t.Fatalf("Kind = %q, want %q", spec.Workspace.Kind, executor.WorkspaceBind)
	}
	// A bind workspace that also named a repo would be a spec whose author
	// believes a clone happens; Validate rejects it, and so should we.
	if spec.Workspace.Repo != "" || spec.Workspace.CredentialGrant != "" {
		t.Fatalf("bind workspace carried git fields: %+v", spec.Workspace)
	}
	if err := spec.Workspace.Validate(); err != nil {
		t.Fatalf("bind workspace does not validate: %v", err)
	}
}

// TestApplyWorkspaceDerivesGitWorkspace covers the whole point of the task: an
// executor that cannot see the project directory is told where to fetch it
// from, in the https form the contract requires.
func TestApplyWorkspaceDerivesGitWorkspace(t *testing.T) {
	cpDir := newWorkspaceControlPlane(t)
	// A grant wide enough for every fixture below, so what is under test is the
	// derivation rather than the authority for it.
	mintGitHubGrant(t, cpDir, "ci-pat", "executor:edge-01", []string{"acme/*"})

	cases := []struct {
		name     string
		remote   string
		head     string
		wantRepo string
		wantRef  string
	}{
		{
			name:     "https",
			remote:   "https://github.com/acme/widgets.git",
			head:     "main",
			wantRepo: "https://github.com/acme/widgets.git",
			wantRef:  "main",
		},
		{
			name:     "scp-like ssh remote is rewritten to https",
			remote:   "git@github.com:acme/widgets.git",
			head:     "release/2.0",
			wantRepo: "https://github.com/acme/widgets.git",
			wantRef:  "release/2.0",
		},
		{
			name:     "ssh url is rewritten and its port dropped",
			remote:   "ssh://git@github.com:22/acme/widgets.git",
			head:     "main",
			wantRepo: "https://github.com/acme/widgets.git",
			wantRef:  "main",
		},
		{
			name:     "detached head fetches the remote default branch",
			remote:   "https://github.com/acme/widgets.git",
			head:     "detached",
			wantRepo: "https://github.com/acme/widgets.git",
			wantRef:  "",
		},
		{
			name:     "credentials embedded in the remote are stripped",
			remote:   "https://someone:ghp_leaked_token@github.com/acme/widgets.git",
			head:     "main",
			wantRepo: "https://github.com/acme/widgets.git",
			wantRef:  "main",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeGitFixture(t, tc.remote, tc.head)
			spec, err := applyWorkspace(uiSpec(dir, []string{"cloop", "run"}, nil), remoteExecutor(), dir)
			if err != nil {
				t.Fatalf("applyWorkspace: %v", err)
			}
			if spec.Workspace.Kind != executor.WorkspaceGit {
				t.Fatalf("Kind = %q, want git", spec.Workspace.Kind)
			}
			if spec.Workspace.Repo != tc.wantRepo {
				t.Fatalf("Repo = %q, want %q", spec.Workspace.Repo, tc.wantRepo)
			}
			if spec.Workspace.Ref != tc.wantRef {
				t.Fatalf("Ref = %q, want %q", spec.Workspace.Ref, tc.wantRef)
			}
			if spec.Workspace.CredentialGrant != "ci-pat" {
				t.Fatalf("CredentialGrant = %q, want ci-pat", spec.Workspace.CredentialGrant)
			}
			// The whole contract in one assertion: a spec is persisted, logged
			// and shipped to the executor, and it names a grant rather than
			// carrying anything a token could hide in.
			if err := spec.Workspace.Validate(); err != nil {
				t.Fatalf("derived workspace does not validate: %v", err)
			}
		})
	}
}

// TestApplyWorkspaceRefusesProjectWithoutRemote is the regression this task
// exists for: no remote means no way to move the tree, and the run must be
// refused rather than started against an empty directory.
func TestApplyWorkspaceRefusesProjectWithoutRemote(t *testing.T) {
	newWorkspaceControlPlane(t)

	cases := map[string]func(t *testing.T) string{
		"not a git repository": func(t *testing.T) string { return t.TempDir() },
		"git repository with no origin": func(t *testing.T) string {
			return writeGitFixture(t, "", "main")
		},
	}
	for name, makeDir := range cases {
		t.Run(name, func(t *testing.T) {
			dir := makeDir(t)
			ex := remoteExecutor()
			_, err := applyWorkspace(uiSpec(dir, []string{"cloop", "run"}, nil), ex, dir)
			if err == nil {
				t.Fatal("applyWorkspace accepted a project with no git remote")
			}
			var missing *workspaceSourceError
			if !errors.As(err, &missing) {
				t.Fatalf("error %T (%v) is not a *workspaceSourceError", err, err)
			}
			if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
				t.Errorf("error does not unwrap to ErrWorkspaceUnavailable: %v", err)
			}
			if missing.ProjectPath != dir || missing.ExecutorID != ex.ID() {
				t.Errorf("error names project %q on executor %q, want %q on %q",
					missing.ProjectPath, missing.ExecutorID, dir, ex.ID())
			}
			if fix := missing.Remediation(); !strings.Contains(fix, "git remote") {
				t.Errorf("Remediation() = %q, want it to name the git remote to add", fix)
			}
			if !strings.Contains(err.Error(), ex.ID()) {
				t.Errorf("Error() = %q, want it to name executor %q", err.Error(), ex.ID())
			}
		})
	}
}

// TestApplyWorkspaceRefusesUnfetchableRemote: a remote exists but no executor
// on another machine could fetch from it, or it could not carry a brokered
// credential safely. Both are refusals that name the remote.
func TestApplyWorkspaceRefusesUnfetchableRemote(t *testing.T) {
	newWorkspaceControlPlane(t)

	for _, remote := range []string{
		"/srv/mirrors/widgets.git",
		"../sibling-checkout",
		"file:///srv/mirrors/widgets.git",
		"http://git.internal/acme/widgets.git",
		"git://git.internal/acme/widgets.git",
	} {
		t.Run(remote, func(t *testing.T) {
			dir := writeGitFixture(t, remote, "main")
			_, err := applyWorkspace(uiSpec(dir, []string{"cloop", "run"}, nil), remoteExecutor(), dir)
			var refused *workspaceSourceError
			if !errors.As(err, &refused) {
				t.Fatalf("error %T (%v) is not a *workspaceSourceError", err, err)
			}
			if refused.Remote != remote {
				t.Errorf("error names remote %q, want %q", refused.Remote, remote)
			}
		})
	}
}

// TestApplyWorkspaceRequiresMatchingGrant: a private repository needs an
// authority, and the two ways of not having one have different fixes, so they
// must not read alike.
func TestApplyWorkspaceRequiresMatchingGrant(t *testing.T) {
	t.Run("no grant at all", func(t *testing.T) {
		newWorkspaceControlPlane(t)
		dir := writeGitFixture(t, "https://github.com/acme/widgets.git", "main")
		ex := remoteExecutor()

		_, err := applyWorkspace(uiSpec(dir, []string{"cloop", "run"}, nil), ex, dir)
		var denied *executor.WorkspaceGrantError
		if !errors.As(err, &denied) {
			t.Fatalf("error %T (%v) is not a *executor.WorkspaceGrantError", err, err)
		}
		if !errors.Is(err, executor.ErrWorkspaceGrantMissing) {
			t.Errorf("error does not unwrap to ErrWorkspaceGrantMissing: %v", err)
		}
		fix := denied.Remediation()
		if !strings.Contains(fix, "acme/widgets") || !strings.Contains(fix, ex.ID()) {
			t.Errorf("Remediation() = %q, want it to name acme/widgets and %s", fix, ex.ID())
		}
	})

	t.Run("grant exists but excludes the repository", func(t *testing.T) {
		cpDir := newWorkspaceControlPlane(t)
		dir := writeGitFixture(t, "https://github.com/acme/widgets.git", "main")
		ex := remoteExecutor()
		mintGitHubGrant(t, cpDir, "ci-pat", "executor:"+ex.ID(), []string{"acme/other"})

		_, err := applyWorkspace(uiSpec(dir, []string{"cloop", "run"}, nil), ex, dir)
		var denied *executor.WorkspaceGrantError
		if !errors.As(err, &denied) {
			t.Fatalf("error %T (%v) is not a *executor.WorkspaceGrantError", err, err)
		}
		if !strings.Contains(denied.Reason, "ci-pat") || !strings.Contains(denied.Reason, "excludes") {
			t.Errorf("Reason = %q, want it to say the ci-pat grant excludes the repository",
				denied.Reason)
		}
	})

	t.Run("matching grant is named on the spec", func(t *testing.T) {
		cpDir := newWorkspaceControlPlane(t)
		dir := writeGitFixture(t, "https://github.com/acme/widgets.git", "main")
		ex := remoteExecutor()
		mintGitHubGrant(t, cpDir, "ci-pat", "executor:"+ex.ID(), []string{"acme/*"})

		spec, err := applyWorkspace(uiSpec(dir, []string{"cloop", "run"}, nil), ex, dir)
		if err != nil {
			t.Fatalf("applyWorkspace: %v", err)
		}
		if spec.Workspace.CredentialGrant != "ci-pat" {
			t.Fatalf("CredentialGrant = %q, want ci-pat", spec.Workspace.CredentialGrant)
		}
		// The grant is a *name*. Nothing that could hold a token is on the
		// spec, and Validate is what keeps it that way.
		if err := spec.Workspace.Validate(); err != nil {
			t.Fatalf("derived workspace does not validate: %v", err)
		}
	})

	t.Run("a grant for another executor does not count", func(t *testing.T) {
		cpDir := newWorkspaceControlPlane(t)
		dir := writeGitFixture(t, "https://github.com/acme/widgets.git", "main")
		ex := remoteExecutor()
		mintGitHubGrant(t, cpDir, "other-pat", "executor:edge-99", []string{"acme/*"})

		_, err := applyWorkspace(uiSpec(dir, []string{"cloop", "run"}, nil), ex, dir)
		var denied *executor.WorkspaceGrantError
		if !errors.As(err, &denied) {
			t.Fatalf("error %T (%v) is not a *executor.WorkspaceGrantError", err, err)
		}
	})
}

// TestApplyWorkspaceFetchesAnonymouslyWithoutABroker: an install that has not
// adopted the secret broker must not be told it now has to. It gets a git
// workspace with no grant named, which is a public-repository fetch; a private
// one fails inside the fetch with git's own authentication error rather than
// against an empty tree.
func TestApplyWorkspaceFetchesAnonymouslyWithoutABroker(t *testing.T) {
	// A control-plane directory with no state database at all: the broker is
	// not configured here, as opposed to configured and broken.
	useControlPlaneDir(t, t.TempDir())
	dir := writeGitFixture(t, "https://github.com/acme/widgets.git", "main")

	spec, err := applyWorkspace(uiSpec(dir, []string{"cloop", "run"}, nil), remoteExecutor(), dir)
	if err != nil {
		t.Fatalf("applyWorkspace: %v", err)
	}
	if spec.Workspace.Kind != executor.WorkspaceGit {
		t.Fatalf("Kind = %q, want git", spec.Workspace.Kind)
	}
	if spec.Workspace.CredentialGrant != "" {
		t.Fatalf("CredentialGrant = %q, want no grant named", spec.Workspace.CredentialGrant)
	}
}

// TestApplyWorkspaceAllowsRepositoryOutsideAllowlistShape: a repository URL that
// is not owner/name — a GitLab subgroup — can never match a grant's allowlist,
// so refusing it would hand the operator a problem with no fix in it. The fetch
// goes out unauthenticated and adjudicates itself.
func TestApplyWorkspaceAllowsRepositoryOutsideAllowlistShape(t *testing.T) {
	newWorkspaceControlPlane(t)
	dir := writeGitFixture(t, "https://gitlab.example.com/group/sub/widgets.git", "main")

	spec, err := applyWorkspace(uiSpec(dir, []string{"cloop", "run"}, nil), remoteExecutor(), dir)
	if err != nil {
		t.Fatalf("applyWorkspace: %v", err)
	}
	if spec.Workspace.Repo != "https://gitlab.example.com/group/sub/widgets.git" {
		t.Fatalf("Repo = %q", spec.Workspace.Repo)
	}
	if spec.Workspace.CredentialGrant != "" {
		t.Fatalf("CredentialGrant = %q, want no grant named", spec.Workspace.CredentialGrant)
	}
}

// mintGitHubGrant seals a GitHub PAT in the control plane's store and grants it
// to subject for the given repository patterns.
func mintGitHubGrant(t *testing.T, controlPlaneDir, name, subject string, repos []string) {
	t.Helper()
	broker, closeDB, err := openUIBroker(controlPlaneDir)
	if err != nil {
		t.Fatalf("openUIBroker: %v", err)
	}
	defer closeDB()

	if _, err := broker.Mint(context.Background(), secretbroker.MintRequest{
		Name:    name,
		Kind:    secretbroker.KindGitHubPAT,
		Payload: []byte("ghp_0123456789abcdef0123456789abcdef0123"),
		Actor:   "test",
	}); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	subj, err := secretbroker.ParseSubject(subject)
	if err != nil {
		t.Fatalf("ParseSubject(%q): %v", subject, err)
	}
	if _, err := broker.Grant(context.Background(), secretbroker.GrantRequest{
		SecretRef:   name,
		Subject:     subj,
		Constraints: secretbroker.Constraints{Repos: repos},
		TTL:         time.Hour,
		Actor:       "test",
	}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
}

// TestApplyWorkspacePreservesSizeLimit: the disk bound comes from the project's
// sandbox spec and is applied before this. Losing it here would silently let a
// clone fill the executor's disk past what the project declared.
func TestApplyWorkspacePreservesSizeLimit(t *testing.T) {
	cpDir := newWorkspaceControlPlane(t)
	dir := writeGitFixture(t, "https://github.com/acme/widgets.git", "main")
	mintGitHubGrant(t, cpDir, "ci-pat", "executor:edge-01", []string{"acme/*"})

	for _, ex := range []*workspaceTestExecutor{hostExecutor(), remoteExecutor()} {
		t.Run(ex.Kind(), func(t *testing.T) {
			spec := uiSpec(dir, []string{"cloop", "run"}, nil)
			spec.Workspace.SizeLimitMB = 512

			spec, err := applyWorkspace(spec, ex, dir)
			if err != nil {
				t.Fatalf("applyWorkspace: %v", err)
			}
			if spec.Workspace.SizeLimitMB != 512 {
				t.Fatalf("SizeLimitMB = %d, want 512 to survive", spec.Workspace.SizeLimitMB)
			}
		})
	}
}

// TestApplyWorkspaceDeclaresNoTreeForUnscopedWorkloads: the voice handler runs
// `cloop listen --file …` with no project at all. There is no tree to fetch, so
// the workload says so rather than leaving the field unspecified — the silence
// this subsystem exists to remove.
func TestApplyWorkspaceDeclaresNoTreeForUnscopedWorkloads(t *testing.T) {
	spec, err := applyWorkspace(uiSpec("", []string{"cloop", "listen"}, nil), remoteExecutor(), "")
	if err != nil {
		t.Fatalf("applyWorkspace: %v", err)
	}
	if spec.Workspace.Kind != executor.WorkspaceNone {
		t.Fatalf("Kind = %q, want none", spec.Workspace.Kind)
	}
}

// TestApplyWorkspaceRefusesExecutorThatCannotProvision covers an agent too old
// to fetch a tree: it must be refused at the hub, naming the constraint, rather
// than dispatched to run against an empty directory.
func TestApplyWorkspaceRefusesExecutorThatCannotProvision(t *testing.T) {
	cpDir := newWorkspaceControlPlane(t)
	dir := writeGitFixture(t, "https://github.com/acme/widgets.git", "main")
	mintGitHubGrant(t, cpDir, "ci-pat", "executor:legacy-agent", []string{"acme/*"})

	ex := &workspaceTestExecutor{
		id:   "legacy-agent",
		kind: executor.KindRemoteAgent,
		caps: executor.Capabilities{
			Isolation:                     executor.IsolationRemote,
			SharesHostFilesystem:          false,
			SupportsWorkspaceProvisioning: false,
		},
	}
	_, err := applyWorkspace(uiSpec(dir, []string{"cloop", "run"}, nil), ex, dir)
	var placement *executor.PlacementError
	if !errors.As(err, &placement) {
		t.Fatalf("error %T (%v) is not a *executor.PlacementError", err, err)
	}
	if placement.Constraint != executor.ConstraintWorkspace {
		t.Fatalf("Constraint = %q, want %q", placement.Constraint, executor.ConstraintWorkspace)
	}
}

// --- parsers ----------------------------------------------------------------

func TestParseGitConfigRemote(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
		want string
	}{
		{
			name: "git's own layout",
			cfg: "[core]\n\tbare = false\n[remote \"origin\"]\n" +
				"\turl = https://github.com/acme/widgets.git\n" +
				"\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
			want: "https://github.com/acme/widgets.git",
		},
		{
			name: "another remote does not answer for origin",
			cfg: "[remote \"upstream\"]\n\turl = https://github.com/other/widgets.git\n" +
				"[remote \"origin\"]\n\turl = https://github.com/acme/widgets.git\n",
			want: "https://github.com/acme/widgets.git",
		},
		{
			name: "section name folds case, subsection name does not",
			cfg:  "[REMOTE \"origin\"]\n\tURL = https://github.com/acme/widgets.git\n",
			want: "https://github.com/acme/widgets.git",
		},
		{
			name: "a quoted value is unquoted",
			cfg:  "[remote \"origin\"]\n\turl = \"https://github.com/acme/widgets.git\"\n",
			want: "https://github.com/acme/widgets.git",
		},
		{
			name: "comments are ignored",
			cfg: "# [remote \"origin\"]\n[remote \"origin\"]\n" +
				"\turl = https://github.com/acme/widgets.git ; the one we want\n",
			want: "https://github.com/acme/widgets.git",
		},
		{
			name: "only Origin with a capital O is not origin",
			cfg:  "[remote \"Origin\"]\n\turl = https://github.com/acme/widgets.git\n",
			want: "",
		},
		{
			name: "no remotes at all",
			cfg:  "[core]\n\tbare = false\n",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseGitConfigRemote(tc.cfg, "origin"); got != tc.want {
				t.Fatalf("parseGitConfigRemote = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseGitHead(t *testing.T) {
	cases := map[string]string{
		"ref: refs/heads/main\n":             "main",
		"ref: refs/heads/release/2.0\n":      "release/2.0",
		"9c1f0e2b7a5d4c3b2a1908f7e6d5c4b3\n": "",
		"":                                   "",
	}
	for head, want := range cases {
		if got := parseGitHead(head); got != want {
			t.Errorf("parseGitHead(%q) = %q, want %q", head, got, want)
		}
	}
}

func TestNormalizeRemoteToHTTPS(t *testing.T) {
	ok := map[string]string{
		"https://github.com/acme/widgets.git":     "https://github.com/acme/widgets.git",
		"https://github.com/acme/widgets":         "https://github.com/acme/widgets",
		"git@github.com:acme/widgets.git":         "https://github.com/acme/widgets.git",
		"git@gitlab.example.com:group/sub.git":    "https://gitlab.example.com/group/sub.git",
		"ssh://git@github.com/acme/widgets.git":   "https://github.com/acme/widgets.git",
		"ssh://git@github.com:2222/acme/w.git":    "https://github.com/acme/w.git",
		"https://u:p@github.com/acme/widgets.git": "https://github.com/acme/widgets.git",
	}
	for in, want := range ok {
		got, err := normalizeRemoteToHTTPS(in)
		if err != nil {
			t.Errorf("normalizeRemoteToHTTPS(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("normalizeRemoteToHTTPS(%q) = %q, want %q", in, got, want)
		}
	}

	for _, in := range []string{
		"", "   ",
		"/srv/mirrors/widgets.git",
		"../sibling",
		"file:///srv/mirrors/widgets.git",
		"http://git.internal/acme/widgets.git",
		"git://git.internal/acme/widgets.git",
	} {
		if got, err := normalizeRemoteToHTTPS(in); err == nil {
			t.Errorf("normalizeRemoteToHTTPS(%q) = %q, want an error", in, got)
		}
	}
}

// TestReadGitOriginFollowsWorktreePointer: a linked worktree's .git is a file,
// its config lives in the parent repository and its HEAD does not. Reading the
// worktree's own directory for the config would report a project with no
// remote, which is the refusal this whole file is meant to avoid producing
// spuriously.
func TestReadGitOriginFollowsWorktreePointer(t *testing.T) {
	main := writeGitFixture(t, "https://github.com/acme/widgets.git", "main")
	mainGit := filepath.Join(main, ".git")
	linkedGit := filepath.Join(mainGit, "worktrees", "feature")
	if err := os.MkdirAll(linkedGit, 0o755); err != nil {
		t.Fatalf("mkdir worktree gitdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(linkedGit, "commondir"), []byte("../..\n"), 0o644); err != nil {
		t.Fatalf("write commondir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(linkedGit, "HEAD"),
		[]byte("ref: refs/heads/feature\n"), 0o644); err != nil {
		t.Fatalf("write worktree HEAD: %v", err)
	}

	linked := t.TempDir()
	if err := os.WriteFile(filepath.Join(linked, ".git"),
		[]byte("gitdir: "+linkedGit+"\n"), 0o644); err != nil {
		t.Fatalf("write .git pointer: %v", err)
	}

	origin, err := readGitOrigin(linked)
	if err != nil {
		t.Fatalf("readGitOrigin: %v", err)
	}
	if origin.Remote != "https://github.com/acme/widgets.git" {
		t.Errorf("Remote = %q, want the parent repository's origin", origin.Remote)
	}
	if origin.Ref != "feature" {
		t.Errorf("Ref = %q, want the worktree's own branch", origin.Ref)
	}
}

// --- audit ------------------------------------------------------------------

// TestWorkspaceAuditSinkRecordsProvisioning: a run looks identical whether the
// tree arrived or not, so the provisioning rows are the only record that can
// answer "which grant fetched what onto which executor, and did it work".
func TestWorkspaceAuditSinkRecordsProvisioning(t *testing.T) {
	dir := newWorkspaceControlPlane(t)

	executor.SetWorkspaceAuditor(workspaceAuditSink(dir))
	t.Cleanup(func() { executor.SetWorkspaceAuditor(nil) })

	ws := executor.Workspace{
		Kind:            executor.WorkspaceGit,
		Repo:            "https://github.com/acme/widgets.git",
		Ref:             "main",
		Depth:           1,
		CredentialGrant: "ci-pat",
	}
	executor.AuditWorkspace(executor.WorkspaceEvent{
		Phase:        executor.WorkspaceProvisionStart,
		ExecutorID:   "edge-01",
		ExecutorKind: executor.KindRemoteAgent,
		HandleID:     "wl-123",
		ProjectPath:  "/srv/widgets",
		Workspace:    ws,
		GrantID:      "grant-abc",
	})
	executor.AuditWorkspace(executor.WorkspaceEvent{
		Phase:        executor.WorkspaceProvisionEnd,
		ExecutorID:   "edge-01",
		ExecutorKind: executor.KindRemoteAgent,
		HandleID:     "wl-123",
		ProjectPath:  "/srv/widgets",
		Workspace:    ws,
		GrantID:      "grant-abc",
		LeaseID:      "lease-xyz",
		DurationMS:   1234,
	})

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	defer db.Close()

	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EntityType: "project", Order: "asc"})
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	byType := map[string]statedb.AuditEvent{}
	for _, r := range rows {
		byType[r.EventType] = r
	}
	start, okStart := byType["workspace.provision_start"]
	end, okEnd := byType["workspace.provision_end"]
	if !okStart || !okEnd {
		t.Fatalf("recorded event types = %v, want a provision_start and a provision_end", byType)
	}
	if start.EntityID != "/srv/widgets" {
		t.Errorf("start row filed under %q, want the project path", start.EntityID)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(end.Payload), &payload); err != nil {
		t.Fatalf("unmarshal end payload %q: %v", end.Payload, err)
	}
	for key, want := range map[string]any{
		"executor_id":   "edge-01",
		"executor_kind": executor.KindRemoteAgent,
		"handle_id":     "wl-123",
		"kind":          "git",
		"repo":          "https://github.com/acme/widgets.git",
		"ref":           "main",
		"grant_id":      "grant-abc",
		"lease_id":      "lease-xyz",
	} {
		if got := payload[key]; got != want {
			t.Errorf("payload[%q] = %v, want %v", key, got, want)
		}
	}
	if payload["duration_ms"] != float64(1234) {
		t.Errorf("payload[duration_ms] = %v, want 1234", payload["duration_ms"])
	}
	if payload["depth"] != float64(1) {
		t.Errorf("payload[depth] = %v, want 1", payload["depth"])
	}
}

// TestWorkspaceAuditPhasesAreBounded: an unknown phase is dropped rather than
// written, so a typo cannot create a third event family nobody filters on.
func TestWorkspaceAuditPhasesAreBounded(t *testing.T) {
	dir := newWorkspaceControlPlane(t)
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	defer db.Close()

	statedb.AuditWorkspaceProvision(db, statedb.WorkspaceAuditInput{
		Phase:       "middle",
		ProjectPath: "/srv/widgets",
	})
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EntityType: "project"})
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("an unknown phase wrote %d rows: %+v", len(rows), rows)
	}
}
