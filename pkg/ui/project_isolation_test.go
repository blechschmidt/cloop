package ui

// Project isolation on a shared host (Task 20500): once the hub's host serves
// a second project, every run it forks there — an administrator's, the static
// token's, the hub's own, on a hub with or without sign-in — is kept to its
// own project, unless the operator opted the project out; and a device that
// serves several projects is asked to keep each host run to its own.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

var (
	// nobodyLocal acts for no one on a hub without sign-in: the dashboard of
	// a single-user install, an automatic resume there.
	nobodyLocal = harnessWho{}
)

func TestHostSandbox_ASecondProjectKeepsEveryRunOnTheHostToItsOwn(t *testing.T) {
	f := newHostSandboxFixture(t, "")
	other := filepath.Join(filepath.Dir(f.project), "bob-app")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	hubLogin := filepath.Join(os.Getenv("HOME"), ".claude")
	if err := os.MkdirAll(hubLogin, 0o700); err != nil {
		t.Fatal(err)
	}

	// One project on the host: nobody to keep apart, as before.
	for name, who := range map[string]harnessWho{"an administrator": adminPerson, "nobody, without sign-in": nobodyLocal} {
		if sb, _, err := sandboxOf(t, f, f.host, f.project, who); err != nil || sb != nil {
			t.Errorf("%s with one project on the host: sandbox %v, err %v; want neither", name, sb, err)
		}
	}

	// A second project: every run is kept to its own, administrators included.
	withHostSharing(t, func(string) bool { return true })
	for name, who := range map[string]harnessWho{
		"an administrator":         adminPerson,
		"the static token":         nobodySSO,
		"nobody, without sign-in":  nobodyLocal,
		"a person without sign-in": {identity: "someone", personal: false},
		"a person":                 alicePerson,
	} {
		sb, spec, err := sandboxOf(t, f, f.host, f.project, who)
		if err != nil || sb == nil {
			t.Errorf("%s with a second project on the host: sandbox %v, err %v; want one", name, sb, err)
			continue
		}
		if spec.Labels[executor.LabelHostSandbox] != "on" {
			t.Errorf("%s: the dispatch is not labelled as sandboxed: %v", name, spec.Labels)
		}
		if !containsPath(sb.ReadWrite, f.project) {
			t.Errorf("%s: the run cannot write its own project: %v", name, sb.ReadWrite)
		}
		for _, p := range append(append([]string{}, sb.ReadWrite...), sb.ReadOnly...) {
			if pathWithin(other, p) || pathWithin(p, other) || pathWithin(f.controlPlane, p) {
				t.Errorf("%s: the sandbox grants %s, which holds the other project or the control plane", name, p)
			}
		}
	}
	// The hub's own login, for a run acting for no one: its Claude directory,
	// named, and nothing else of the hub user's home.
	sb, _, err := sandboxOf(t, f, f.host, f.project, nobodyLocal)
	if err != nil || sb == nil || !containsPath(sb.ReadWrite, hubLogin) ||
		len(sb.Env) != 1 || sb.Env[0] != "CLAUDE_CONFIG_DIR="+hubLogin {
		t.Errorf("a run for no one on a shared host cannot find the hub's own login: %+v %v", sb, err)
	}

	// Mode off keeps nobody to anything, as before.
	off := newHostSandboxFixture(t, config.HostSandboxOff)
	withHostSharing(t, func(string) bool { return true })
	if sb, _, err := sandboxOf(t, off, off.host, off.project, adminPerson); err != nil || sb != nil {
		t.Errorf("mode off on a shared host: sandbox %v, err %v", sb, err)
	}
	// And a container's run is kept to its bind mount by the container.
	if sb, _, err := sandboxOf(t, f, f.box, f.project, adminPerson); err != nil || sb != nil {
		t.Errorf("a container dispatch got a host sandbox: %v %v", sb, err)
	}
	// cloop's own code, for nobody at all, is not a project's run.
	if out, err := applyHostSandbox(executor.Spec{WorkDir: f.project, Argv: []string{"cloop", "init"}},
		f.host, f.project, nil, nil); err != nil || out.HostSandbox != nil {
		t.Errorf("cloop's own init was sandboxed: %v %v", out.HostSandbox, err)
	}
}

func TestHostSandbox_AnOptedOutProjectRunsUnconfinedButNeverFreesAPerson(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "projects", "alice-app")
	link := filepath.Join(root, "alias")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(project, link); err != nil {
		t.Fatal(err)
	}
	for _, named := range []string{project, link} {
		f := newHostSandboxFixtureOptedOut(t, "", []string{named})
		f.project = project
		withHostSharing(t, func(string) bool { return true })
		if !hostSandboxOptedOut(project) {
			t.Fatalf("opt_out naming %s does not name %s", named, project)
		}
		if sb, _, err := sandboxOf(t, f, f.host, f.project, adminPerson); err != nil || sb != nil {
			t.Errorf("an administrator's run of a project opted out as %s: sandbox %v, err %v", named, sb, err)
		}
		if sb, _, err := sandboxOf(t, f, f.host, f.project, nobodyLocal); err != nil || sb != nil {
			t.Errorf("a run for nobody of a project opted out as %s: sandbox %v, err %v", named, sb, err)
		}
		// The opt-out is from the second-project rule alone: a person who is
		// not an administrator is sandboxed on a hub with sign-in whatever it
		// says.
		if sb, _, err := sandboxOf(t, f, f.host, f.project, alicePerson); err != nil || sb == nil {
			t.Errorf("an opt-out freed a person's run: sandbox %v, err %v", sb, err)
		}
		// A feature is its project's, opted out with it.
		feature := filepath.Join(project, ".cloop", "features", "login")
		if err := os.MkdirAll(feature, 0o755); err != nil {
			t.Fatal(err)
		}
		if sb, _, err := sandboxOf(t, f, f.host, feature, adminPerson); err != nil || sb != nil {
			t.Errorf("a feature of an opted-out project: sandbox %v, err %v", sb, err)
		}
	}
	// Mode all keeps everyone to their project; an opt-out does not undo it.
	all := newHostSandboxFixtureOptedOut(t, config.HostSandboxAll, []string{project})
	all.project = project
	if sb, _, err := sandboxOf(t, all, all.host, all.project, adminPerson); err != nil || sb == nil {
		t.Errorf("mode all with an opt-out: sandbox %v, err %v; want one", sb, err)
	}
}

func TestHostSandbox_TheHubsOwnDirectoryNeedsTheOptOutOnASharedHost(t *testing.T) {
	f := newHostSandboxFixture(t, "")
	withHostSharing(t, func(string) bool { return true })
	_, _, err := sandboxOf(t, f, f.host, f.controlPlane, adminPerson)
	if !errors.Is(err, errHostSandboxRefused) || !errors.Is(err, executor.ErrUnsupported) {
		t.Fatalf("an administrator's run of the hub's own directory on a shared host: %v", err)
	}
	if !strings.Contains(err.Error(), "executors.host_sandbox.opt_out") {
		t.Errorf("the refusal does not say how to run it: %v", err)
	}
	_, _, err = sandboxOf(t, f, f.host, f.controlPlane, alicePerson)
	if !errors.Is(err, errHostSandboxRefused) || !strings.Contains(err.Error(), "Only a hub administrator") ||
		!strings.Contains(err.Error(), "executors.host_sandbox.opt_out") {
		t.Errorf("a person's run of the hub's own directory on a shared host: %v", err)
	}

	opted := newHostSandboxFixtureOptedOut(t, "", nil)
	cfg := "executors:\n  host_sandbox:\n    opt_out:\n      - " + opted.controlPlane + "\n"
	if err := os.WriteFile(filepath.Join(opted.controlPlane, ".cloop", "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	withHostSharing(t, func(string) bool { return true })
	if sb, _, err := sandboxOf(t, opted, opted.host, opted.controlPlane, adminPerson); err != nil || sb != nil {
		t.Errorf("an administrator's run of the opted-out hub directory: sandbox %v, err %v", sb, err)
	}
	if _, _, err := sandboxOf(t, opted, opted.host, opted.controlPlane, alicePerson); !errors.Is(err, errHostSandboxRefused) {
		t.Errorf("an opt-out let a person run the hub's own directory: %v", err)
	}
}

// TestHostSharingCountsEveryRegisteredProjectButFeatures: a second project
// is any other registered project, whatever executor it runs on — its
// directory, its state at least, is on the hub's host — but never a feature,
// which is its project's.
func TestHostSharingCountsEveryRegisteredProjectButFeatures(t *testing.T) {
	root := t.TempDir()
	web, api := filepath.Join(root, "web"), filepath.Join(root, "api")
	feature := filepath.Join(web, ".cloop", "features", "login")
	for _, d := range []string{web, api, feature} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The real answer, not the package's pin (main_test.go).
	prevSharing := hostSharingFn.Load()
	setHostSharing(nil)
	t.Cleanup(func() { hostSharingFn.Store(prevSharing) })
	projectListSource.mu.Lock()
	prev := projectListSource.fn
	projectListSource.fn = nil
	projectListSource.mu.Unlock()
	t.Cleanup(func() {
		projectListSource.mu.Lock()
		projectListSource.fn = prev
		projectListSource.mu.Unlock()
	})

	withProjectListEntries(t, entry(web, ""), entry(feature, web))
	if hostSharedWithOtherProjects(web) || hostSharedWithOtherProjects(feature) {
		t.Error("a project and its own feature count as two projects")
	}
	withProjectListEntries(t, entry(web, ""), entry(api, ""), entry(feature, web))
	if !hostSharedWithOtherProjects(web) || !hostSharedWithOtherProjects(api) {
		t.Error("two registered projects do not share the host")
	}
}

func TestDeviceConfinement_ASharedDeviceKeepsAHostRunToItsProject(t *testing.T) {
	f := newHostSandboxFixture(t, "")
	device := newHarnessExec("edge-1", executor.KindRemoteAgent, executor.IsolationRemote)
	device.shares = false
	ask := func(t *testing.T, ex executor.Executor, who *harnessWho) executor.Spec {
		t.Helper()
		spec := executor.Spec{WorkDir: f.project, Argv: []string{"cloop", "run"}}
		var clear *harnessClearance
		if who != nil {
			clear = newHarnessClearance(f.project, *who, "")
		}
		out, err := applyHostSandbox(spec, ex, f.project, clear, nil)
		if err != nil {
			t.Fatal(err)
		}
		if out.HostSandbox != nil {
			t.Fatalf("a device's dispatch got a hub-side host sandbox: %+v", out.HostSandbox)
		}
		return out
	}

	// Only this project on the device: nothing to keep apart.
	if spec := ask(t, device, &adminPerson); spec.ConfineToProject {
		t.Error("a device serving one project was asked to confine its run")
	}
	withDeviceSharing(t, func(id, project string) bool { return id == "edge-1" })
	spec := ask(t, device, &adminPerson)
	if !spec.ConfineToProject || spec.Labels[executor.LabelHostSandbox] != "device" {
		t.Errorf("a device serving another project too was not asked to confine the run: %v %v",
			spec.ConfineToProject, spec.Labels)
	}
	if spec := ask(t, device, nil); spec.ConfineToProject {
		t.Error("cloop's own code, for nobody at all, was confined")
	}
	// A dispatch naming no directory is nobody's project: confined on a
	// device any project's tree may be on, to its private directory.
	var askedFor []string
	withDeviceSharing(t, func(id, project string) bool { askedFor = append(askedFor, project); return true })
	if out, err := applyHostSandbox(executor.Spec{Argv: []string{"cloop", "listen"}}, device, "",
		newHarnessClearance("", adminPerson, ""), nil); err != nil || !out.ConfineToProject {
		t.Errorf("a dispatch naming no directory on a shared device: %v %v", out.ConfineToProject, err)
	}
	if len(askedFor) != 1 || askedFor[0] != "" {
		t.Errorf("the device was asked about %q for a dispatch naming no directory, want \"\"", askedFor)
	}
	withDeviceSharing(t, func(id, project string) bool { return id == "edge-1" })
	// A pool's runner takes one run of one project; a virtual executor's run
	// is a container's.
	runner := &ephemeralExec{harnessExec: newHarnessExec("runner-1", executor.KindRemoteAgent, executor.IsolationRemote)}
	withDeviceSharing(t, func(string, string) bool { return true })
	if spec := ask(t, runner, &adminPerson); spec.ConfineToProject {
		t.Error("a pool's runner was asked to confine its one run")
	}
	virtual := newHarnessExec("edge-1-gpu", executor.KindVirtual, executor.IsolationContainer)
	if spec := ask(t, virtual, &adminPerson); spec.ConfineToProject {
		t.Error("a virtual executor's container run was asked to confine itself")
	}

	optedOut := newHostSandboxFixtureOptedOut(t, "", []string{f.project})
	withDeviceSharing(t, func(string, string) bool { return true })
	if spec, err := applyHostSandbox(executor.Spec{WorkDir: f.project, Argv: []string{"cloop", "run"}}, device,
		f.project, newHarnessClearance(f.project, adminPerson, ""), nil); err != nil || spec.ConfineToProject {
		t.Errorf("an opted-out project's device run was confined: %v %v", spec.ConfineToProject, err)
	}
	_ = optedOut

	off := newHostSandboxFixture(t, config.HostSandboxOff)
	withDeviceSharing(t, func(string, string) bool { return true })
	if spec, _ := applyHostSandbox(executor.Spec{WorkDir: off.project, Argv: []string{"cloop", "run"}}, device,
		off.project, newHarnessClearance(off.project, adminPerson, ""), nil); spec.ConfineToProject {
		t.Error("mode off confined a device run")
	}
	all := newHostSandboxFixture(t, config.HostSandboxAll)
	if spec, _ := applyHostSandbox(executor.Spec{WorkDir: all.project, Argv: []string{"cloop", "run"}}, device,
		all.project, newHarnessClearance(all.project, adminPerson, ""), nil); !spec.ConfineToProject {
		t.Error("mode all left a device run unconfined")
	}
}

// TestDeviceSharingFollowsTheBindings: another project may run on a device
// when it is bound to the device or to one of its virtual executors, or the
// device is the default and the project is bound nowhere — and a project
// bound elsewhere, or a feature of the project itself, is no second project.
func TestDeviceSharingFollowsTheBindings(t *testing.T) {
	root := t.TempDir()
	web, api, docs := filepath.Join(root, "web"), filepath.Join(root, "api"), filepath.Join(root, "docs")
	feature := filepath.Join(web, ".cloop", "features", "login")
	for _, d := range []string{web, api, docs, feature} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	setDeviceSharing(nil)
	t.Cleanup(func() { setDeviceSharing(nil) })
	device := newHarnessExec("t20500-edge", executor.KindRemoteAgent, executor.IsolationRemote)
	elsewhere := newHarnessExec("t20500-elsewhere", executor.KindContainer, executor.IsolationContainer)
	registerStub(t, device)
	registerStub(t, elsewhere)
	child := &childExec{harnessExec: newHarnessExec("t20500-edge-gpu", executor.KindVirtual, executor.IsolationContainer),
		parent: device.ID()}
	registerStub(t, child)
	bind := func(project, id string) {
		t.Helper()
		if err := executor.Bind(project, id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { executor.DefaultRegistry.Unbind(project) })
	}
	withProjectListEntries(t, entry(web, ""), entry(api, ""), entry(feature, web))
	bind(web, device.ID())
	bind(api, elsewhere.ID())
	if deviceSharedWithOtherProjects(device.ID(), web) {
		t.Error("a project bound elsewhere, or the project's own feature, counts as sharing the device")
	}
	bind(api, child.ID())
	if !deviceSharedWithOtherProjects(device.ID(), web) {
		t.Error("a project on the device's virtual executor does not share the device")
	}
	executor.DefaultRegistry.Unbind(api)
	bind(api, elsewhere.ID())
	withProjectListEntries(t, entry(web, ""), entry(api, ""), entry(docs, ""))
	prevDefault := executor.DefaultRegistry.DefaultID()
	if err := executor.DefaultRegistry.SetDefault(device.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if prevDefault != "" {
			_ = executor.DefaultRegistry.SetDefault(prevDefault)
		}
	})
	if !deviceSharedWithOtherProjects(device.ID(), web) {
		t.Error("an unbound project, on a device that is the default, does not share it")
	}
}

// ephemeralExec is a pool runner: it takes one run.
type ephemeralExec struct{ *harnessExec }

func (e *ephemeralExec) Ephemeral() bool { return true }

// childExec is a virtual executor of a device.
type childExec struct {
	*harnessExec
	parent string
}

func (c *childExec) ParentID() string { return c.parent }

func entry(path, parent string) projectEntryArg { return projectEntryArg{path: path, parent: parent} }

type projectEntryArg struct{ path, parent string }

// withProjectListEntries lists entries as the hub's projects, a feature with
// its parent, for the test.
func withProjectListEntries(t *testing.T, entries ...projectEntryArg) {
	t.Helper()
	list := make([]multiui.ProjectEntry, 0, len(entries))
	for _, e := range entries {
		list = append(list, multiui.ProjectEntry{Name: filepath.Base(e.path), Path: e.path, Parent: e.parent})
	}
	projectListSource.mu.Lock()
	prev := projectListSource.fn
	projectListSource.fn = func() []multiui.ProjectEntry { return list }
	projectListSource.mu.Unlock()
	t.Cleanup(func() {
		projectListSource.mu.Lock()
		projectListSource.fn = prev
		projectListSource.mu.Unlock()
	})
}

// TestAFailedOverRunSharesTheDeviceItRunsOn: a run placed on a device by a
// failover carries no binding there, and its project's tree and lease files
// are on the device all the same; the hub's record of the workload is what
// says the device is shared.
func TestAFailedOverRunSharesTheDeviceItRunsOn(t *testing.T) {
	cp := statedbtest.Dir(t)
	withControlPlaneDir(t, cp)
	root := t.TempDir()
	web, api := filepath.Join(root, "web"), filepath.Join(root, "api")
	for _, d := range []string{web, api} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	prev := deviceSharingFn.Load()
	setDeviceSharing(nil)
	t.Cleanup(func() { deviceSharingFn.Store(prev) })
	withProjectListEntries(t, entry(web, ""))
	if deviceSharedWithOtherProjects("t20500-edge-fo", web) {
		t.Fatal("a device with no other project's workload or binding is shared")
	}
	db, err := statedb.Open(state.DBPath(cp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PutExecutorHandle(statedb.ExecutorHandleRow{HandleID: "h-failed-over", ExecutorID: "t20500-edge-fo",
		Driver: "remote", ExternalID: "h-failed-over", ProjectPath: api, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if !deviceSharedWithOtherProjects("t20500-edge-fo", web) {
		t.Error("api's failed-over workload on the device does not share it with web")
	}
	if deviceSharedWithOtherProjects("t20500-edge-fo", api) {
		t.Error("api's own workload counts as another project")
	}
}
