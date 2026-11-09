package ui

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// hostSandboxFixture is a control plane with two people's Claude homes and a
// project that is not the hub's own directory.
type hostSandboxFixture struct {
	controlPlane, project, aliceHome, bobHome string
	host, box                                 executor.Executor
}

func newHostSandboxFixture(t *testing.T, mode string, readOnly ...string) hostSandboxFixture {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	root := t.TempDir()
	f := hostSandboxFixture{
		controlPlane: filepath.Join(root, "hub"),
		project:      filepath.Join(root, "projects", "alice-app"),
		host:         newHarnessExec("sandbox-host", executor.KindLocalProcess, executor.IsolationNone),
		box:          newHarnessExec("sandbox-box", executor.KindContainer, executor.IsolationContainer),
	}
	f.box.(*harnessExec).shares = false
	for _, d := range []string{filepath.Join(f.controlPlane, ".cloop"), f.project} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var cfg strings.Builder
	cfg.WriteString("executors:\n  host_sandbox:\n")
	if mode != "" {
		cfg.WriteString("    mode: " + mode + "\n")
	}
	if len(readOnly) > 0 {
		cfg.WriteString("    read_only:\n")
		for _, p := range readOnly {
			cfg.WriteString("      - " + p + "\n")
		}
	}
	if err := os.WriteFile(filepath.Join(f.controlPlane, ".cloop", "config.yaml"), []byte(cfg.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	withControlPlaneDir(t, f.controlPlane)
	// No project here is one a sandboxed person may write, unless a test says
	// so: that is the Server's to answer (projectExposedToSandboxedPeople).
	withHostSandboxExposure(t, func(string) bool { return false })
	var err error
	if f.aliceHome, err = claudecodeauth.HomeFor("alice@corp.example"); err != nil {
		t.Fatal(err)
	}
	if f.bobHome, err = claudecodeauth.HomeFor("bob@corp.example"); err != nil {
		t.Fatal(err)
	}
	return f
}

var (
	alicePerson = harnessWho{identity: "alice@corp.example", personal: true}
	adminPerson = harnessWho{identity: "root@corp.example", personal: true, hubAdmin: true}
	nobodySSO   = harnessWho{personal: true}
)

func sandboxOf(t *testing.T, f hostSandboxFixture, ex executor.Executor, dir string, who harnessWho) (*executor.HostSandbox, executor.Spec, error) {
	t.Helper()
	spec := executor.Spec{WorkDir: dir, Argv: []string{"cloop", "run"}, Labels: map[string]string{"project": dir}}
	out, err := applyHostSandbox(spec, ex, dir, newHarnessClearance(dir, who, ""), nil)
	return out.HostSandbox, out, err
}

func TestHostSandbox_AutoSandboxesEveryPersonButTheAdministrators(t *testing.T) {
	f := newHostSandboxFixture(t, "")
	sb, spec, err := sandboxOf(t, f, f.host, f.project, alicePerson)
	if err != nil || sb == nil {
		t.Fatalf("alice's run on the hub's host: sandbox %v, err %v", sb, err)
	}
	if spec.Labels[executor.LabelHostSandbox] != "on" {
		t.Errorf("the dispatch is not labelled as sandboxed: %v", spec.Labels)
	}
	if !containsPath(sb.ReadWrite, f.project) || !containsPath(sb.ReadWrite, f.aliceHome) {
		t.Errorf("alice's run cannot write her project and her Claude home: %v", sb.ReadWrite)
	}
	if sb.Home != filepath.Join(f.aliceHome, sandboxHomeDir) {
		t.Errorf("home = %q, want the one kept in alice's Claude home", sb.Home)
	}
	if fi, err := os.Stat(sb.Home); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("alice's sandbox home: %v %v", fi, err)
	}
	root, _ := claudecodeauth.HomeRootPath()
	for _, p := range append(append([]string{}, sb.ReadWrite...), sb.ReadOnly...) {
		if pathWithin(f.bobHome, p) || pathWithin(root, p) || pathWithin(f.controlPlane, p) {
			t.Errorf("alice's sandbox grants %s, which holds bob's login or the control plane", p)
		}
	}

	for name, who := range map[string]harnessWho{
		"an administrator":         adminPerson,
		"the static token":         nobodySSO,
		"a hub without sign-in":    {identity: "", personal: false},
		"a person without sign-in": {identity: "someone", personal: false},
	} {
		if sb, _, err := sandboxOf(t, f, f.host, f.project, who); err != nil || sb != nil {
			t.Errorf("%s under auto: sandbox %v, err %v; want neither", name, sb, err)
		}
	}
	if sb, _, err := sandboxOf(t, f, f.box, f.project, alicePerson); err != nil || sb != nil {
		t.Errorf("a container dispatch got a host sandbox: %v %v", sb, err)
	}
	if out, err := applyHostSandbox(executor.Spec{WorkDir: f.project, Argv: []string{"cloop", "init"}}, f.host, f.project, nil, nil); err != nil || out.HostSandbox != nil {
		t.Errorf("a dispatch for nobody at all — cloop's own init — was sandboxed: %v %v", out.HostSandbox, err)
	}
}

func TestHostSandbox_AllSandboxesAdministratorsAndOffNobody(t *testing.T) {
	f := newHostSandboxFixture(t, config.HostSandboxAll)
	if sb, _, err := sandboxOf(t, f, f.host, f.project, adminPerson); err != nil || sb == nil {
		t.Fatalf("an administrator under mode all: sandbox %v, err %v", sb, err)
	}
	hubLogin := filepath.Join(os.Getenv("HOME"), ".claude")
	if err := os.MkdirAll(hubLogin, 0o700); err != nil {
		t.Fatal(err)
	}
	sb, _, err := sandboxOf(t, f, f.host, f.project, nobodySSO)
	if err != nil || sb == nil || sb.Home != "" {
		t.Fatalf("the hub's own login under mode all: sandbox %+v, err %v; want one with a fresh home", sb, err)
	}
	if !containsPath(sb.ReadWrite, hubLogin) || len(sb.Env) != 1 || sb.Env[0] != "CLAUDE_CONFIG_DIR="+hubLogin {
		t.Errorf("a run for no one under mode all cannot find the hub's own login: %v %v", sb.ReadWrite, sb.Env)
	}

	off := newHostSandboxFixture(t, config.HostSandboxOff)
	if sb, _, err := sandboxOf(t, off, off.host, off.project, alicePerson); err != nil || sb != nil {
		t.Fatalf("mode off sandboxed alice: %v %v", sb, err)
	}
}

func TestHostSandbox_TheHubsOwnDirectoryIsRefusedRatherThanSandboxed(t *testing.T) {
	f := newHostSandboxFixture(t, "")
	_, _, err := sandboxOf(t, f, f.host, f.controlPlane, alicePerson)
	if !errors.Is(err, errHostSandboxRefused) || !errors.Is(err, executor.ErrUnsupported) {
		t.Fatalf("a person's run of the hub's own directory: %v", err)
	}
	if !strings.Contains(err.Error(), "Only a hub administrator") {
		t.Errorf("the refusal does not say who may run it: %v", err)
	}
	// Named through a link, it is still the hub's own directory.
	link := filepath.Join(t.TempDir(), "hub-link")
	if err := os.Symlink(f.controlPlane, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sandboxOf(t, f, f.host, link, alicePerson); !errors.Is(err, errHostSandboxRefused) {
		t.Errorf("the hub's own directory named through a link: %v", err)
	}
	if sb, _, err := sandboxOf(t, f, f.host, f.controlPlane, adminPerson); err != nil || sb != nil {
		t.Errorf("an administrator's run of the hub's own directory: %v %v", sb, err)
	}
	all := newHostSandboxFixture(t, config.HostSandboxAll)
	if _, _, err := sandboxOf(t, all, all.host, all.controlPlane, adminPerson); err == nil ||
		!strings.Contains(err.Error(), "container executor") {
		t.Errorf("mode all let the hub's own directory run on its host: %v", err)
	}
}

func TestHostSandbox_OperatorPathsThatWouldExposeOthersAreLeftOut(t *testing.T) {
	toolchain := t.TempDir()
	f := newHostSandboxFixture(t, "", toolchain, "/", "/tmp")
	other := filepath.Join(filepath.Dir(f.project), "bob-app")
	root, _ := claudecodeauth.HomeRootPath()
	extras := []string{toolchain, "/", filepath.Dir(f.controlPlane), f.controlPlane + "/.cloop", root,
		filepath.Dir(root), f.aliceHome}
	withProjectList(t, f.controlPlane, f.project, other)
	extras = append(extras, other, filepath.Dir(other))
	kept, dropped := safeSandboxExtras(extras, f.project)
	if len(kept) != 1 || kept[0] != toolchain {
		t.Fatalf("kept %v, want only the toolchain; dropped %v", kept, dropped)
	}
	sb, _, err := sandboxOf(t, f, f.host, f.project, alicePerson)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPath(sb.ReadOnly, toolchain) || containsPath(sb.ReadOnly, "/") {
		t.Errorf("the operator's read_only: %v", sb.ReadOnly)
	}
}

func TestHostSandbox_SandboxesDecideFromThePersonNotTheEnvironment(t *testing.T) {
	f := newHostSandboxFixture(t, "")
	// A lease or a grant can put anything in the environment. The sandbox's
	// grants are worked out from whom the run acts for, so naming bob's home
	// there opens nothing.
	spec := executor.Spec{WorkDir: f.project, Argv: []string{"cloop", "run"},
		Env: []string{"CLAUDE_CONFIG_DIR=" + f.bobHome, "HOME=" + f.bobHome}}
	out, err := applyHostSandbox(spec, f.host, f.project, newHarnessClearance(f.project, alicePerson, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range append(append([]string{}, out.HostSandbox.ReadWrite...), out.HostSandbox.ReadOnly...) {
		if pathWithin(f.bobHome, p) {
			t.Fatalf("an environment naming bob's home got it granted: %s", p)
		}
	}
}

func TestHostSandboxModesAreValidated(t *testing.T) {
	for _, ok := range []string{"", "auto", "ALL", " off "} {
		if err := (config.HostSandboxConfig{Mode: ok}).Validate(); err != nil {
			t.Errorf("mode %q: %v", ok, err)
		}
	}
	if err := (config.HostSandboxConfig{Mode: "people"}).Validate(); err == nil {
		t.Error("an unknown mode was accepted")
	}
	if err := (config.HostSandboxConfig{ReadOnly: []string{"opt/tools"}}).Validate(); err == nil {
		t.Error("a relative read_only path was accepted")
	}
}

func containsPath(list []string, p string) bool {
	for _, q := range list {
		if filepath.Clean(q) == filepath.Clean(p) {
			return true
		}
	}
	return false
}

// withProjectList makes registeredProjectDirs answer paths for the test.
func withProjectList(t *testing.T, paths ...string) {
	t.Helper()
	projectListSource.mu.Lock()
	prev := projectListSource.fn
	projectListSource.fn = func() []multiui.ProjectEntry {
		out := make([]multiui.ProjectEntry, 0, len(paths))
		for _, p := range paths {
			out = append(out, multiui.ProjectEntry{Name: filepath.Base(p), Path: p})
		}
		return out
	}
	projectListSource.mu.Unlock()
	t.Cleanup(func() {
		projectListSource.mu.Lock()
		projectListSource.fn = prev
		projectListSource.mu.Unlock()
	})
}

// TestInlineReplaysAreRefusedToAPersonWhoseRunsAreSandboxed: the two replays
// run the provider in the hub's own process, where there is no sandbox, so a
// person whose runs on the hub's host are sandboxed may not make one there.
// An administrator, whose runs are not under mode auto, is not refused for it.
func TestInlineReplaysAreRefusedToAPersonWhoseRunsAreSandboxed(t *testing.T) {
	h := newHarnessHub(t)
	host := newHarnessExec("replay-host", executor.KindLocalProcess, executor.IsolationNone)
	registerStub(t, host)
	executor.DefaultRegistry.Unbind(h.srv.WorkDir)
	if err := executor.Bind(h.srv.WorkDir, host.ID()); err != nil {
		t.Fatal(err)
	}
	ps, err := state.Load(h.srv.WorkDir)
	if err != nil {
		t.Fatal(err)
	}
	ps.Plan = &pm.Plan{Goal: ps.Goal, Tasks: []*pm.Task{{ID: 1, Title: "Replay me", Status: pm.TaskDone, Priority: 1}}}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]any{
		"/api/provider-calls/1/replay": map[string]any{"prompt": "hello"},
		"/api/replay-runs":             map[string]any{"task_id": 1, "provider": "claudecode"},
	} {
		code, out := h.do(t, "alice", http.MethodPost, path, body)
		if code != http.StatusConflict || out["code"] != "inline_call_unsandboxed" {
			t.Errorf("alice's POST %s = %d %v, want 409 inline_call_unsandboxed", path, code, out)
		}
		if _, out := h.do(t, "root", http.MethodPost, path, body); out["code"] == "inline_call_unsandboxed" {
			t.Errorf("the administrator's POST %s was refused for the sandbox: %v", path, out)
		}
	}
	if n := len(host.started()); n != 0 {
		t.Fatalf("a refused replay started %d workload(s)", n)
	}
}

// withHostSandboxMode runs the test under mode, whatever the hub's
// configuration says. For a fixture that runs people's work on the hub's own
// directory, which the host sandbox refuses, to test what it does not change:
// whose account a run acts for, what a Copilot run is pinned to.
func withHostSandboxMode(t *testing.T, mode string) {
	t.Helper()
	prev := hostSandboxModeOverride.Load()
	hostSandboxModeOverride.Store(&mode)
	t.Cleanup(func() { hostSandboxModeOverride.Store(prev) })
}

// withHostSandboxExposure answers, for the test, whether people whose runs are
// sandboxed may write a project.
func withHostSandboxExposure(t *testing.T, fn func(string) bool) {
	t.Helper()
	prev := hostSandboxExposureFn.Load()
	setHostSandboxExposure(fn)
	t.Cleanup(func() { hostSandboxExposureFn.Store(prev) })
}

// TestHostSandbox_AnAdministratorsRunOfAProjectSandboxedPeopleWriteIsSandboxed:
// under auto an administrator's run is left on the host only for a project no
// sandboxed person may write; otherwise it would run what their agent left
// there — a hook in .claude/settings.json, a git hook, a build script — with
// the hub's whole filesystem. Nor is a dispatch nothing can vouch for.
func TestHostSandbox_AnAdministratorsRunOfAProjectSandboxedPeopleWriteIsSandboxed(t *testing.T) {
	f := newHostSandboxFixture(t, "")
	withHostSandboxExposure(t, func(p string) bool { return p == f.project })
	for name, who := range map[string]harnessWho{"an administrator": adminPerson, "the static token": nobodySSO} {
		if sb, _, err := sandboxOf(t, f, f.host, f.project, who); err != nil || sb == nil {
			t.Errorf("%s's run of a project people with sandboxed runs may write: sandbox %v, err %v", name, sb, err)
		}
	}
	other := filepath.Join(filepath.Dir(f.project), "admins-only")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if sb, _, err := sandboxOf(t, f, f.host, other, adminPerson); err != nil || sb != nil {
		t.Errorf("an administrator's run of a project only administrators write: %v %v", sb, err)
	}
	setHostSandboxExposure(nil)
	if sb, _, err := sandboxOf(t, f, f.host, other, adminPerson); err != nil || sb == nil {
		t.Errorf("with nothing to say who may write the project, an administrator's run was left unsandboxed: %v", err)
	}
}

// TestProjectExposureFollowsTheAccessModel: who may write a project, as the
// access model says — its owner, its people and teams, the role policy.
func TestProjectExposureFollowsTheAccessModel(t *testing.T) {
	owned := newMemberFixtureOwnedBy(t, true, rootEmail)
	if owned.srv.projectExposedToSandboxedPeople(owned.project) {
		t.Error("a project an administrator owns and shares with nobody counts as written by sandboxed people")
	}
	if owned.srv.projectExposedToSandboxedPeople(owned.srv.primaryProjectPath()) {
		t.Error("the hub's own directory, which only administrators may run, counts as written by sandboxed people")
	}
	db, err := statedb.Open(state.DBPath(controlPlaneDir()))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.PutProjectMember(statedb.ProjectMemberRow{
		ProjectPath: owned.project, IdentityKey: carolEmail, Role: string(authz.RoleOperator),
	}, nil); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if !owned.srv.projectExposedToSandboxedPeople(owned.project) {
		t.Error("a project shared with a person at operator does not count as written by sandboxed people")
	}

	if f := newMemberFixtureOwnedBy(t, true, aliceEmail); !f.srv.projectExposedToSandboxedPeople(f.project) {
		t.Error("a project a person who is not an administrator owns does not count")
	}
	if f := newMemberFixtureOwnedBy(t, true, ""); !f.srv.projectExposedToSandboxedPeople(f.project) {
		t.Error("a project nobody owns, on a hub whose policy lets alice run anything, does not count")
	}
	if f := newMemberFixtureOwnedBy(t, false, rootEmail); !f.srv.projectExposedToSandboxedPeople(f.project) {
		t.Error("on a hub without a role policy, where everyone who signs in may run anything, a project does not count")
	}
}

// TestHostSandbox_ALinkLeftForTheSandboxHomeIsReplaced: a person's runs may
// write their Claude home, so an earlier one could leave sandbox-home as a
// link to somewhere else; the hub replaces the link, and never grants or
// touches what it points to.
func TestHostSandbox_ALinkLeftForTheSandboxHomeIsReplaced(t *testing.T) {
	f := newHostSandboxFixture(t, "")
	target := t.TempDir()
	marker := filepath.Join(target, "keep.txt")
	if err := os.WriteFile(marker, []byte("not the run's"), 0o600); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(f.aliceHome, sandboxHomeDir)
	if err := os.Symlink(target, planted); err != nil {
		t.Fatal(err)
	}
	sb, _, err := sandboxOf(t, f, f.host, f.project, alicePerson)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(sb.Home)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("the sandbox home is %v (%v), want a real directory", fi, err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("replacing the link touched what it pointed to: %v", err)
	}
	for _, p := range append(append([]string{}, sb.ReadWrite...), sb.ReadOnly...) {
		if pathWithin(target, p) {
			t.Errorf("the link's target %s is granted", target)
		}
	}
}

// TestALocalRepoGrantCannotOpenAnotherPersonsDirectory: a local_repo secret is
// a path anyone with secret.own may mint and grant to their own project, so a
// person's lease may not open the hub's own directory, the identity root,
// another person's project, or a directory above one — on any executor. Their
// own other project may be granted, and an administrator's lease is theirs to
// shape.
func TestALocalRepoGrantCannotOpenAnotherPersonsDirectory(t *testing.T) {
	f := newHostSandboxFixture(t, "")
	bobs := filepath.Join(filepath.Dir(f.project), "bob-app")
	alices := filepath.Join(filepath.Dir(f.project), "alice-lib")
	library := filepath.Join(t.TempDir(), "shared-lib")
	for _, d := range []string{bobs, alices, library} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	projectListSource.mu.Lock()
	prev := projectListSource.fn
	projectListSource.fn = func() []multiui.ProjectEntry {
		return []multiui.ProjectEntry{
			{Name: "hub", Path: f.controlPlane},
			{Name: "alice-app", Path: f.project, Owner: "alice@corp.example"},
			{Name: "alice-lib", Path: alices, Owner: "alice@corp.example"},
			{Name: "bob-app", Path: bobs, Owner: "bob@corp.example"},
		}
	}
	projectListSource.mu.Unlock()
	t.Cleanup(func() {
		projectListSource.mu.Lock()
		projectListSource.fn = prev
		projectListSource.mu.Unlock()
	})
	root, _ := claudecodeauth.HomeRootPath()
	link := filepath.Join(t.TempDir(), "innocent-name")
	if err := os.Symlink(bobs, link); err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{"/", f.controlPlane, filepath.Join(f.controlPlane, ".cloop"),
		filepath.Dir(f.controlPlane), root, f.bobHome, bobs, link} {
		err := checkRepoMounts([]secretbroker.RepoMount{{Name: "repo", Source: src}}, f.project, alicePerson)
		if !errors.Is(err, executor.ErrUnsupported) {
			t.Errorf("alice's lease opening %s: %v", src, err)
		}
	}
	for _, src := range []string{library, alices} {
		if err := checkRepoMounts([]secretbroker.RepoMount{{Name: "repo", Source: src}}, f.project, alicePerson); err != nil {
			t.Errorf("alice's lease opening %s: %v", src, err)
		}
	}
	if err := checkRepoMounts([]secretbroker.RepoMount{{Name: "repo", Source: bobs}}, f.project, adminPerson); err != nil {
		t.Errorf("an administrator's lease: %v", err)
	}
}
