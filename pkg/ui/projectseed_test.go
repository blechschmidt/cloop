package ui

// projectseed_test.go covers the hub's half of Task 20316: deciding whether a
// dispatch carries the project's state, and saying so when it cannot.
//
// The decision is easy to get subtly wrong in two opposite directions, and both
// are covered here. Attaching a seed to a bind workspace would overwrite the
// operator's live `.cloop/` with a snapshot of itself. Refusing to dispatch
// when the executor cannot take one would break every installation that works
// today by committing `.cloop/` into the repository — which was the only way
// this path worked before the seed existed.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// seedCapableExecutor is remoteExecutor plus the capability a current agent
// advertises.
func seedCapableExecutor() *workspaceTestExecutor {
	ex := remoteExecutor()
	ex.caps.SupportsProjectSeed = true
	return ex
}

// seedFixture builds a control plane, a git-backed project directory with a
// real plan in it, and the grant that authorises fetching it — the minimum
// state in which applyWorkspace gets as far as the seed decision.
func seedFixture(t *testing.T, goal string) string {
	t.Helper()
	cpDir := newWorkspaceControlPlane(t)
	mintGitHubGrant(t, cpDir, "ci-pat", "executor:edge-01", []string{"acme/*"})
	dir := writeGitFixture(t, "https://github.com/acme/widgets.git", "main")
	if goal != "" {
		initProjectIn(t, dir, goal)
	}
	return dir
}

// initProjectIn turns a git fixture directory into a real cloop project, the
// way `cloop init` would, and gives it a plan worth shipping.
func initProjectIn(t *testing.T, dir, goal string) {
	t.Helper()
	st, err := state.Init(dir, goal, 50)
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	st.Instructions = "the project's instructions"
	st.Provider = "claudecode"
	st.Effort = "max"
	st.Plan = &pm.Plan{
		Goal:  goal,
		Tasks: []*pm.Task{{ID: 1, Title: "a pending task", Status: pm.TaskPending}},
	}
	if err := st.Save(); err != nil {
		t.Fatalf("save project: %v", err)
	}
}

// TestApplyWorkspaceSeedsAGitWorkspace is the hub-side half of the fix: a tree
// the executor has to clone gets the project sent with it.
func TestApplyWorkspaceSeedsAGitWorkspace(t *testing.T) {
	dir := seedFixture(t, "the hub's goal")

	spec, err := applyWorkspace(uiSpec(dir, []string{"cloop", "run"}, nil), seedCapableExecutor(), dir)
	if err != nil {
		t.Fatalf("applyWorkspace: %v", err)
	}
	if spec.Workspace.Kind != executor.WorkspaceGit {
		t.Fatalf("Kind = %q, want git", spec.Workspace.Kind)
	}
	if len(spec.ProjectSeed) == 0 {
		t.Fatal("a git workspace was dispatched with no project state; `cloop run` in the " +
			"sandbox would exit with \"no cloop project found\"")
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("seeded spec does not validate: %v", err)
	}

	// The seed is the real project, not a placeholder: write it into a bare
	// directory and load it back exactly as the sandbox will.
	sandbox := t.TempDir()
	if err := projectseed.Write(sandbox, spec.ProjectSeed); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	got, err := state.Load(sandbox)
	if err != nil {
		t.Fatalf("the seeded project does not load: %v", err)
	}
	if got.Goal != "the hub's goal" {
		t.Errorf("Goal = %q", got.Goal)
	}
	if got.Instructions != "the project's instructions" {
		t.Errorf("Instructions = %q", got.Instructions)
	}
	if got.Effort != "max" {
		t.Errorf("Effort = %q, want max", got.Effort)
	}
	if got.Plan == nil || len(got.Plan.Tasks) != 1 || got.Plan.Tasks[0].Title != "a pending task" {
		t.Errorf("plan did not reach the sandbox: %+v", got.Plan)
	}
}

// TestApplyWorkspaceDoesNotSeedABindWorkspace: the operator's own `.cloop/` is
// already at WorkDir, and a seed would overwrite live state with a copy.
func TestApplyWorkspaceDoesNotSeedABindWorkspace(t *testing.T) {
	dir := seedFixture(t, "the hub's goal")

	spec, err := applyWorkspace(uiSpec(dir, []string{"cloop", "run"}, nil), hostExecutor(), dir)
	if err != nil {
		t.Fatalf("applyWorkspace: %v", err)
	}
	if len(spec.ProjectSeed) != 0 {
		t.Fatal("a bind workspace was given a seed, which would overwrite the operator's " +
			"own project state")
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("spec does not validate: %v", err)
	}
}

// TestApplyWorkspaceDegradesForAnOlderExecutor pins the deliberate choice not
// to refuse. An agent that predates the seed keeps running exactly the work it
// runs today — a fleet mid-upgrade must not stop — and the project's journal
// carries the reason so the failure it may cause is not a mystery.
func TestApplyWorkspaceDegradesForAnOlderExecutor(t *testing.T) {
	dir := seedFixture(t, "the hub's goal")

	// remoteExecutor() advertises provisioning but not seeding: a pre-v10 agent.
	spec, err := applyWorkspace(uiSpec(dir, []string{"cloop", "run"}, nil), remoteExecutor(), dir)
	if err != nil {
		t.Fatalf("an executor that cannot be seeded must still be dispatchable: %v", err)
	}
	if len(spec.ProjectSeed) != 0 {
		t.Fatal("a seed was attached to an executor that cannot place it")
	}
	if spec.Workspace.Kind != executor.WorkspaceGit {
		t.Errorf("Kind = %q, want git", spec.Workspace.Kind)
	}

	rows, _, err := state.ListEvents(dir, 0, 50)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	var found string
	for _, row := range rows {
		if row.Type == state.EventProjectSeed {
			found = row.Message
		}
	}
	if found == "" {
		t.Fatal("the skipped seed left no trace on the project's journal")
	}
	for _, want := range []string{"edge-01", "no cloop project found", "--upgrade"} {
		if !strings.Contains(found, want) {
			t.Errorf("journal row %q should mention %q", found, want)
		}
	}
}

// TestApplyWorkspaceSeedsNothingWithoutAProject: `/api/projects/new` dispatches
// `cloop init` precisely because the project does not exist yet. That must not
// become an error — it worked before and its own refusal is clearer.
func TestApplyWorkspaceSeedsNothingWithoutAProject(t *testing.T) {
	dir := seedFixture(t, "")
	if _, err := os.Stat(filepath.Join(dir, ".cloop")); !os.IsNotExist(err) {
		t.Fatalf("precondition: the fixture must have no project; got %v", err)
	}

	spec, err := applyWorkspace(uiSpec(dir, []string{"cloop", "init"}, nil), seedCapableExecutor(), dir)
	if err != nil {
		t.Fatalf("applyWorkspace on an uninitialised project: %v", err)
	}
	if len(spec.ProjectSeed) != 0 {
		t.Error("a project that does not exist yet produced a seed")
	}
}

// TestApplyWorkspaceSeedsNoTreelessWorkload: the voice handler runs with no
// project at all, so there is nothing to seed and nowhere to put it.
func TestApplyWorkspaceSeedsNoTreelessWorkload(t *testing.T) {
	spec, err := applyWorkspace(uiSpec("", []string{"cloop", "listen"}, nil), seedCapableExecutor(), "")
	if err != nil {
		t.Fatalf("applyWorkspace: %v", err)
	}
	if len(spec.ProjectSeed) != 0 {
		t.Error("an unscoped workload was given a project seed")
	}
}

// TestSeedCarriesTheProviderTheHubResolved: a seed carries state and never
// config.yaml (which can hold API keys), so a provider chosen in config would
// be lost on the device — where Default()'s claudecode used to take over and
// fail on a machine with no `claude` (Task 20339). The hub writes the provider
// and model it resolved into the seed's state instead.
func TestSeedCarriesTheProviderTheHubResolved(t *testing.T) {
	dir := seedFixture(t, "the hub's goal")
	cfg := "provider: openai\nopenai:\n    model: gpt-configured\n"
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	seed, err := projectSeedFor(dir)
	if err != nil {
		t.Fatalf("projectSeedFor: %v", err)
	}
	sandbox := t.TempDir()
	if err := projectseed.Write(sandbox, seed); err != nil {
		t.Fatal(err)
	}
	got, err := state.Load(sandbox)
	if err != nil {
		t.Fatal(err)
	}
	if got.Provider != "openai" || got.Model != "gpt-configured" {
		t.Errorf("seed carries provider %q model %q, want the hub's openai/gpt-configured", got.Provider, got.Model)
	}
	if strings.Contains(string(seed), "api_key") {
		t.Error("the seed must not carry configuration, which can hold API keys")
	}
}
