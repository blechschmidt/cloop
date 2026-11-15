package projectmove

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// fakeExec is an executor whose kind, capabilities and health a test sets.
// It implements executor.Revoker (unless noRevoke), the parent accessor a
// virtual executor has, the pool runner's Ephemeral, and the runtime claim
// isolation placement reads.
type fakeExec struct {
	id       string
	kind     string
	caps     executor.Capabilities
	health   error
	parent   string
	ephem    bool
	noRevoke bool
	runtime  string
}

func (e *fakeExec) ID() string                          { return e.id }
func (e *fakeExec) Kind() string                        { return e.kind }
func (e *fakeExec) Capabilities() executor.Capabilities { return e.caps }
func (e *fakeExec) HealthCheck(context.Context) error   { return e.health }
func (e *fakeExec) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, errors.New("fakeExec: a preflight must never start anything")
}
func (e *fakeExec) Signal(context.Context, string, executor.Signal) error { return nil }
func (e *fakeExec) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, nil
}
func (e *fakeExec) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	ch := make(chan executor.LogLine)
	close(ch)
	return ch, nil
}
func (e *fakeExec) SupportsRevocation() bool { return !e.noRevoke }
func (e *fakeExec) HoldsLease(string) bool   { return false }
func (e *fakeExec) Leases() []string         { return nil }
func (e *fakeExec) RevokeLease(_ context.Context, req executor.RevokeRequest) executor.RevokeOutcome {
	return executor.RevokeOutcome{LeaseID: req.LeaseID, State: executor.RevokeStateRevoked}
}
func (e *fakeExec) Revocations() []executor.RevokeOutcome { return nil }
func (e *fakeExec) ParentID() string                      { return e.parent }
func (e *fakeExec) Ephemeral() bool                       { return e.ephem }
func (e *fakeExec) IsolationRuntime() (string, bool)      { return e.runtime, e.runtime != "" }

// The executors the tests move between.

// hostExec is the hub's host driver.
func hostExec() *fakeExec {
	return &fakeExec{id: "local", kind: executor.KindLocalProcess, caps: executor.Capabilities{
		Isolation: executor.IsolationNone, SharesHostFilesystem: true, SupportsSecretFiles: true,
		SecretFilesFromHostPath: true, NetworkEgress: true,
	}}
}

// containerExec is a container driver on the hub, bind-mounting the project.
func containerExec(id string) *fakeExec {
	return &fakeExec{id: id, kind: executor.KindContainer, caps: executor.Capabilities{
		Isolation: executor.IsolationContainer, SharesHostFilesystem: true, SupportsSecretFiles: true,
		SupportsDevices: true, SupportsInterfaces: true, SupportsHostMounts: true, SupportsImageOverride: true,
		SupportsSandboxMounts: true, SupportsResourceLimits: true, NetworkEgress: true, FilteredEgress: true,
	}}
}

// deviceExec is an enrolled remote device in container mode.
func deviceExec(id string) *fakeExec {
	return &fakeExec{id: id, kind: executor.KindRemoteAgent, caps: executor.Capabilities{
		Isolation: executor.IsolationRemote, SupportsSecretFiles: true, SupportsWorkspaceProvisioning: true,
		SupportsProjectSeed: true, ReturnsProjectState: true, SupportsWriteBack: true, SupportsBranchBundle: true,
		SupportsImageOverride: true, SupportsDevices: true, SupportsInterfaces: true, NetworkEgress: true,
	}}
}

// virtualExec is a virtual executor on device parent.
func virtualExec(id, parent string) *fakeExec {
	e := deviceExec(id)
	e.kind = executor.KindVirtual
	e.parent = parent
	e.caps.SupportsDevices, e.caps.SupportsInterfaces = false, false
	return e
}

// podExec is a Kubernetes executor: a Pod per run, built from the forge.
func podExec(id string) *fakeExec {
	return &fakeExec{id: id, kind: executor.KindKubernetes, caps: executor.Capabilities{
		Isolation: executor.IsolationRemote, SupportsSecretFiles: true, SupportsWorkspaceProvisioning: true,
		SupportsProjectSeed: true, SupportsWriteBack: true, NetworkEgress: true,
	}}
}

// fakeEnv is an Env whose every answer a test sets.
type fakeEnv struct {
	execs       map[string]executor.Executor
	defaultID   string
	hostAllowed bool

	binding    string
	bindingErr error

	roots        map[string]string
	features     []Feature
	featuresErr  error
	runs         map[string]RunFacts
	tree         Tree
	treeErr      error
	treeAsked    int
	pools        map[string]PoolFacts
	poolErr      error
	audience     map[string]bool
	audienceErr  error
	harness      HarnessFacts
	harnessErr   error
	grants       []GrantFacts
	grantsErr    error
	firewall     FirewallFacts
	firewallErr  error
	forwarded    []ForwardedFacts
	forwardedErr error
	takes        error
	virtualDevs  map[string][]string
	sandboxReq   executor.Requirements
	sandboxErr   error
	workspace    []WorkspaceIssue
	paths        []PathBinding
	pathsErr     error

	// reachableAsked records which executors were probed.
	reachableAsked []string
}

// newEnv is a project on the hub's host driver, moving to a device.
func newEnv() *fakeEnv {
	return &fakeEnv{
		execs: map[string]executor.Executor{
			"local":  hostExec(),
			"box":    containerExec("box"),
			"dev1":   deviceExec("dev1"),
			"dev2":   deviceExec("dev2"),
			"vx-hsm": virtualExec("vx-hsm", "dev1"),
			"k8s":    podExec("k8s"),
		},
		defaultID:   "local",
		hostAllowed: true,
		binding:     "local",
		roots:       map[string]string{"dev1": "/var/lib/cloop-executor/work", "dev2": "/srv/work"},
		runs:        map[string]RunFacts{},
		pools:       map[string]PoolFacts{},
		audience:    map[string]bool{},
		tree: Tree{Git: GitState{Dir: testProject.Path, Repository: true, Remotes: []string{"origin"},
			Worktrees: nil, Branches: nil}},
	}
}

var testProject = Project{Name: "app", Path: "/srv/projects/app"}

func (f *fakeEnv) Executor(id string) (executor.Executor, error) {
	if ex, ok := f.execs[id]; ok {
		return ex, nil
	}
	return nil, fmt.Errorf("%w: %q", executor.ErrExecutorNotFound, id)
}

func (f *fakeEnv) DefaultExecutor() (executor.Executor, error) { return f.Executor(f.defaultID) }
func (f *fakeEnv) HostExecutionAllowed() bool                  { return f.hostAllowed }

func (f *fakeEnv) Binding(context.Context, Project) (string, error) { return f.binding, f.bindingErr }

func (f *fakeEnv) Reachable(ctx context.Context, ex executor.Executor) error {
	f.reachableAsked = append(f.reachableAsked, ex.ID())
	return ex.HealthCheck(ctx)
}

func (f *fakeEnv) DeviceRoot(_ context.Context, id string) string { return f.roots[id] }

func (f *fakeEnv) Features(context.Context, Project) ([]Feature, error) {
	return f.features, f.featuresErr
}

func (f *fakeEnv) Runs(_ context.Context, path string) RunFacts { return f.runs[path] }

func (f *fakeEnv) SourceTree(_ context.Context, _ Project, _ []Feature, src Endpoint) (Tree, error) {
	f.treeAsked++
	if src.Workspace != WorkspaceHubTree {
		return Tree{}, ErrUnseen
	}
	return f.tree, f.treeErr
}

func (f *fakeEnv) Pool(_ context.Context, id string, _ Project) (PoolFacts, error) {
	if f.poolErr != nil {
		return PoolFacts{}, f.poolErr
	}
	return f.pools[id], nil
}

func (f *fakeEnv) Audience(_ context.Context, id string) (bool, error) {
	if f.audienceErr != nil {
		return false, f.audienceErr
	}
	if ok, set := f.audience[id]; set {
		return ok, nil
	}
	return true, nil
}

func (f *fakeEnv) HarnessCredential(context.Context, Project, executor.Executor) (HarnessFacts, error) {
	return f.harness, f.harnessErr
}

func (f *fakeEnv) Grants(context.Context, Project, executor.Executor, executor.Executor) ([]GrantFacts, error) {
	return f.grants, f.grantsErr
}

func (f *fakeEnv) Firewall(context.Context, Project, executor.Executor) (FirewallFacts, error) {
	return f.firewall, f.firewallErr
}

func (f *fakeEnv) ForwardedDevices(context.Context, Project) ([]ForwardedFacts, error) {
	return f.forwarded, f.forwardedErr
}

func (f *fakeEnv) TakesForwarded(context.Context, executor.Executor, []string) error { return f.takes }

func (f *fakeEnv) VirtualDevices(_ context.Context, id string) []string { return f.virtualDevs[id] }

func (f *fakeEnv) SandboxRequirements(context.Context, Project) (executor.Requirements, error) {
	return f.sandboxReq, f.sandboxErr
}

func (f *fakeEnv) Workspace(context.Context, Project, []Feature, executor.Executor) []WorkspaceIssue {
	return f.workspace
}

func (f *fakeEnv) PathBindings(context.Context, Project) ([]PathBinding, error) {
	return f.paths, f.pathsErr
}

// preflight runs Preflight against env and fails the test on an error.
func preflightOf(t *testing.T, env *fakeEnv, target string, opts Options) *Report {
	t.Helper()
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC) }
	}
	rep, err := Preflight(context.Background(), env, testProject, target, opts)
	if err != nil {
		t.Fatalf("Preflight(%q): %v", target, err)
	}
	return rep
}

// want is one finding a test expects: its kind and severity, and words its
// title or message must hold.
type want struct {
	kind     Kind
	severity Severity
	says     string
}

// expect asserts the report holds a finding matching each want, and that every
// blocker and warning carries a remedy.
func expect(t *testing.T, rep *Report, wants ...want) {
	t.Helper()
	for _, w := range wants {
		if !holds(rep, w) {
			t.Errorf("no %s finding of kind %s saying %q; findings:\n%s", w.severity, w.kind, w.says, dump(rep))
		}
	}
	for _, f := range rep.Findings {
		if f.Severity != SeverityWillCarry && strings.TrimSpace(f.Remedy) == "" {
			t.Errorf("%s finding %q carries no remedy", f.Severity, f.Title)
		}
	}
}

// expectNone asserts the report holds no finding of kind k at severity s
// ("" for any severity).
func expectNone(t *testing.T, rep *Report, k Kind, s Severity) {
	t.Helper()
	for _, f := range rep.Findings {
		if f.Kind == k && (s == "" || f.Severity == s) {
			t.Errorf("unexpected %s finding of kind %s: %q\n%s", f.Severity, f.Kind, f.Title, dump(rep))
		}
	}
}

func holds(rep *Report, w want) bool {
	for _, f := range rep.Findings {
		if f.Kind != w.kind || f.Severity != w.severity {
			continue
		}
		text := f.Title + "\n" + f.Message + "\n" + f.Remedy
		for _, it := range f.Items {
			text += "\n" + it.Name + " " + it.Path + " " + it.Detail + " " + strings.Join(it.Examples, " ")
		}
		if strings.Contains(text, w.says) {
			return true
		}
	}
	return false
}

func dump(rep *Report) string {
	var b strings.Builder
	_ = rep.WriteText(&b)
	return b.String()
}
