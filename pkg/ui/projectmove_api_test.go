package ui

// The move preflight over a real hub (Task 20493): a project directory that is
// a git repository with changes no commit holds and files under .cloop, fake
// executors in the registry as the source and the target, and the hub's own
// decision functions — the harness-credential report, the broker's grant
// matching, the workspace rules — behind the route. The finding kinds are
// covered table by table in pkg/projectmove; here it is the wiring, the gate,
// and that asking changes nothing.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/projectmove"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// moveExec is a fake executor for the preflight: a harnessExec (which records
// any Start, and can take a credential back) with the capabilities and health
// a test gives it.
type moveExec struct {
	*harnessExec
	caps   executor.Capabilities
	health error
}

func (e *moveExec) Capabilities() executor.Capabilities { return e.caps }
func (e *moveExec) HealthCheck(context.Context) error   { return e.health }

// moveDevice is a remote device that can be seeded and take a branch.
func moveDevice(id string) *moveExec {
	return &moveExec{harnessExec: newHarnessExec(id, executor.KindRemoteAgent, executor.IsolationRemote),
		caps: executor.Capabilities{Isolation: executor.IsolationRemote, SupportsWorkspaceProvisioning: true,
			SupportsProjectSeed: true, ReturnsProjectState: true, SupportsBranchBundle: true, SupportsWriteBack: true,
			SupportsSecretFiles: true, NetworkEgress: true}}
}

// movePod is a Kubernetes executor.
func movePod(id string) *moveExec {
	return &moveExec{harnessExec: newHarnessExec(id, executor.KindKubernetes, executor.IsolationRemote),
		caps: executor.Capabilities{Isolation: executor.IsolationRemote, SupportsWorkspaceProvisioning: true,
			SupportsProjectSeed: true, SupportsWriteBack: true, SupportsSecretFiles: true, NetworkEgress: true}}
}

func registerMoveExec(t *testing.T, ex executor.Executor) {
	t.Helper()
	if err := executor.Register(ex); err != nil {
		t.Fatalf("register %s: %v", ex.ID(), err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(ex.ID()) })
}

// moveGit runs the test's own git in dir.
func moveGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func moveWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// preflightOver asks the hub for a preflight and decodes the report on 200.
func preflightOver(t *testing.T, c *http.Client, base, query string) (int, projectmove.Report, string) {
	t.Helper()
	resp, err := c.Get(base + "/api/projects/0/move/preflight?" + query)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var rep projectmove.Report
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &rep); err != nil {
			t.Fatalf("decode report: %v\n%s", err, raw)
		}
	}
	return resp.StatusCode, rep, string(raw)
}

func findingOf(rep projectmove.Report, kind projectmove.Kind, sev projectmove.Severity, says string) bool {
	for _, f := range rep.Findings {
		if f.Kind != kind || f.Severity != sev {
			continue
		}
		text := f.Title + " " + f.Message
		for _, it := range f.Items {
			text += " " + it.Name + " " + it.Detail + " " + strings.Join(it.Examples, " ")
		}
		if strings.Contains(text, says) {
			return true
		}
	}
	return false
}

func TestMovePreflightReadsTheHubTreeAndJudgesTheTarget(t *testing.T) {
	dir := setupProjectDir(t, "move preflight", nil)
	db := hubWithControlPlane(t, dir)
	ts := newTestServer(t, dir, nil)
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	// A repository with a remote the device could fetch, and work no commit
	// or push holds.
	moveWrite(t, filepath.Join(dir, "tracked.txt"), "one\n")
	moveGit(t, dir, "init", "-q", "-b", "main")
	moveGit(t, dir, "remote", "add", "origin", "https://git.example.com/team/sub/move-demo.git")
	moveGit(t, dir, "add", "tracked.txt")
	moveGit(t, dir, "commit", "-q", "-m", "base")
	moveWrite(t, filepath.Join(dir, "tracked.txt"), "changed\n")
	moveWrite(t, filepath.Join(dir, "loose.txt"), "untracked\n")
	moveWrite(t, filepath.Join(dir, ".cloop", "artifacts", "1_output.txt"), "output\n")
	moveWrite(t, filepath.Join(dir, ".cloop", "attachments", "outbox", "1", "report.txt"), "left behind\n")
	setProvider(t, dir, "claudecode")

	dev := moveDevice("mv-dev")
	registerMoveExec(t, dev)
	index, err := os.ReadFile(filepath.Join(dir, ".git", "index"))
	if err != nil {
		t.Fatal(err)
	}

	status, rep, raw := preflightOver(t, http.DefaultClient, ts.URL, "target=mv-dev")
	if status != http.StatusOK {
		t.Fatalf("preflight = HTTP %d: %s", status, raw)
	}
	if rep.Source.Workspace != projectmove.WorkspaceHubTree || rep.Source.WorkDir != dir {
		t.Errorf("source = %+v, want the hub tree at %s", rep.Source, dir)
	}
	if rep.Target.ExecutorID != "mv-dev" || rep.Target.Workspace != projectmove.WorkspaceDevice ||
		!strings.HasSuffix(rep.Target.WorkDir, executor.DeviceWorkDir(dir)) {
		t.Errorf("target = %+v, want mv-dev's working copy %s", rep.Target, executor.DeviceWorkDir(dir))
	}
	for _, w := range []struct {
		kind projectmove.Kind
		sev  projectmove.Severity
		says string
	}{
		{projectmove.KindWorkingTree, projectmove.SeverityWillCarry, "tracked.txt"},
		{projectmove.KindWorkingTree, projectmove.SeverityWillCarry, "loose.txt"},
		{projectmove.KindProjectFiles, projectmove.SeverityWillCarry, projectmove.FilesArtifacts},
		{projectmove.KindProjectFiles, projectmove.SeverityWarning, "report.txt"},
		// The hub's own harness preflight: a claudecode run in mv-dev's
		// sandbox would get no login, since nothing is granted.
		{projectmove.KindHarnessCredential, projectmove.SeverityBlocker, "Claude login"},
	} {
		if !findingOf(rep, w.kind, w.sev, w.says) {
			t.Errorf("no %s %s finding mentioning %q in:\n%s", w.sev, w.kind, w.says, raw)
		}
	}
	if !rep.Blocked {
		t.Errorf("a move whose target would get no harness credential must be blocked:\n%s", raw)
	}

	// Asking changed nothing: no binding, no started workload, an untouched index.
	if _, bound, err := db.ProjectExecutor(dir); err != nil || bound {
		t.Errorf("the preflight bound the project (bound=%v, err=%v)", bound, err)
	}
	if got := dev.started(); len(got) != 0 {
		t.Errorf("the preflight started %d workload(s) on the target", len(got))
	}
	after, err := os.ReadFile(filepath.Join(dir, ".git", "index"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(index, after) {
		t.Error("the preflight rewrote the repository's index")
	}
}

func TestMovePreflightRefusesWhatIsNotATarget(t *testing.T) {
	dir := setupProjectDir(t, "move bad target", nil)
	hubWithControlPlane(t, dir)
	ts := newTestServer(t, dir, nil)
	for _, q := range []string{"", "target=", "target=executor:mv-dev", "target=" + url.QueryEscape("a b"),
		"target=pool:", "target=mv-dev&abandon_source=perhaps"} {
		if status, _, raw := preflightOver(t, http.DefaultClient, ts.URL, q); status != http.StatusBadRequest {
			t.Errorf("?%s = HTTP %d (%s), want 400", q, status, raw)
		}
	}
	// Only GET: a preflight is a read, and no write verb reaches it.
	resp, err := http.Post(ts.URL+"/api/projects/0/move/preflight?target=mv-dev", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode < 400 {
		t.Errorf("POST = HTTP %d, want a refusal", resp.StatusCode)
	}
}

func TestMovePreflightAbandonsAnOfflineDevice(t *testing.T) {
	dir := setupProjectDir(t, "move off a dead device", nil)
	hubWithControlPlane(t, dir)
	ts := newTestServer(t, dir, nil)
	gone := moveDevice("mv-gone")
	gone.health = errors.New("no session: last seen a week ago")
	registerMoveExec(t, gone)
	registerMoveExec(t, moveDevice("mv-dev"))
	if err := executor.Bind(dir, "mv-gone"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	status, rep, raw := preflightOver(t, http.DefaultClient, ts.URL, "target=mv-dev")
	if status != http.StatusOK {
		t.Fatalf("preflight = HTTP %d: %s", status, raw)
	}
	if !findingOf(rep, projectmove.KindSourceUnreachable, projectmove.SeverityBlocker, "last seen a week ago") || !rep.Blocked {
		t.Fatalf("an offline source must block the move:\n%s", raw)
	}

	status, rep, raw = preflightOver(t, http.DefaultClient, ts.URL, "target=mv-dev&abandon_source=1")
	if status != http.StatusOK {
		t.Fatalf("preflight = HTTP %d: %s", status, raw)
	}
	if !rep.AbandonSource || !findingOf(rep, projectmove.KindSourceUnreachable, projectmove.SeverityWarning, "last seen a week ago") {
		t.Errorf("abandoning must turn the unreachable source into a warning:\n%s", raw)
	}
	if !findingOf(rep, projectmove.KindAbandoned, projectmove.SeverityWarning, "working copy") {
		t.Errorf("abandoning must say what is lost:\n%s", raw)
	}
	for _, f := range rep.Findings {
		if f.Kind == projectmove.KindSourceUnreachable && f.Severity == projectmove.SeverityBlocker {
			t.Errorf("abandon_source left the unreachable source a blocker:\n%s", raw)
		}
	}
}

func TestMovePreflightNeedsAMaintainerOnTheTargetsAccessList(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	db := hubWithControlPlane(t, srv.WorkDir)
	resolver, err := authz.New(authz.Config{Bindings: []authz.Binding{
		{Claim: authz.ClaimGroup, Value: "maintainers", Role: authz.RoleMaintainer},
		{Claim: authz.ClaimGroup, Value: "outsiders", Role: authz.RoleMaintainer},
		{Claim: authz.ClaimGroup, Value: "operators", Role: authz.RoleOperator},
	}})
	if err != nil {
		t.Fatal(err)
	}
	srv.Authz = resolver
	registerMoveExec(t, moveDevice("mv-dev"))
	if err := db.AddExecutorAudience("mv-dev", "group", "maintainers", "test"); err != nil {
		t.Fatal(err)
	}
	as := func(groups ...string) *http.Client {
		idp.groups = groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}

	if status, _, raw := preflightOver(t, as("operators"), ts.URL, "target=mv-dev"); status != http.StatusForbidden {
		t.Errorf("an operator = HTTP %d (%s), want 403: a move is a maintainer's to plan", status, raw)
	}
	status, _, raw := preflightOver(t, as("outsiders"), ts.URL, "target=mv-dev")
	if status != http.StatusForbidden || !strings.Contains(raw, "executor_audience_denied") {
		t.Errorf("a maintainer off the target's access list = HTTP %d (%s), want 403 executor_audience_denied", status, raw)
	}
	if status, _, raw := preflightOver(t, as("maintainers"), ts.URL, "target=mv-dev"); status != http.StatusOK {
		t.Errorf("a maintainer on the access list = HTTP %d (%s), want 200", status, raw)
	}
}

func TestMoveEnvMatchesGrantsToEachEnd(t *testing.T) {
	f := newHarnessFixture(t)
	srv := New(f.dir, 0, "")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	env := &moveEnv{s: srv, r: req, now: time.Now()}
	defer env.close()

	shared := f.env(t, "shared-env", map[string]string{"A": "1"}, "")
	pinned := f.env(t, "pinned-env", map[string]string{"B": "2"}, "")
	f.grant(t, shared, "project:"+f.dir, time.Hour)
	f.grant(t, pinned, "executor:local", time.Hour)

	registerBuiltinExecutors()
	local, err := executor.Get("local")
	if err != nil {
		t.Fatal(err)
	}
	dev := moveDevice("mv-dev")
	got, err := env.Grants(t.Context(), projectmove.Project{Name: "p", Path: f.dir}, local, dev)
	if err != nil {
		t.Fatalf("Grants: %v", err)
	}
	reach := map[string][2]bool{}
	for _, g := range got {
		reach[g.SecretRef] = [2]bool{g.ReachesSource, g.ReachesTarget}
	}
	if r := reach["shared-env"]; !r[0] || !r[1] {
		t.Errorf("a project grant must reach both ends: %v", r)
	}
	if r := reach["pinned-env"]; !r[0] || r[1] {
		t.Errorf("a grant to executor:local must reach the source only: %v", r)
	}
}

func TestMoveEnvCountsRecordsKeyedByThePath(t *testing.T) {
	dir := setupProjectDir(t, "move path records", nil)
	db := hubWithControlPlane(t, dir)
	srv := New(dir, 0, "")
	if err := db.SetProjectFirewall(dir, executor.FirewallRules{AllowPublicInternet: true, AllowPorts: []int{443}}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.PutProjectMember(statedb.ProjectMemberRow{ProjectPath: dir, IdentityKey: "bob@example.com",
		Role: string(authz.RoleOperator), GrantedBy: "test"}, nil); err != nil {
		t.Fatal(err)
	}
	env := &moveEnv{s: srv, r: httptest.NewRequest(http.MethodGet, "/", nil), now: time.Now()}
	defer env.close()
	got, err := env.PathBindings(t.Context(), projectmove.Project{Name: "p", Path: dir})
	if err != nil {
		t.Fatalf("PathBindings: %v", err)
	}
	count := map[string]int{}
	for _, b := range got {
		count[b.Store] = b.Count
	}
	if count["project_firewall_rules"] != 1 || count["project_members"] != 1 {
		t.Errorf("counts = %v, want the firewall rule set and the member", count)
	}
	if count["project_executors"] != 0 {
		t.Errorf("an unbound project counted a binding: %v", count)
	}
}

func TestWorkspaceFitIsTheDispatchsRule(t *testing.T) {
	repoless := t.TempDir()
	if err := workspaceFit(movePod("mv-pod"), repoless); err == nil {
		t.Error("a Pod was accepted for a project with no repository, whose working directory it cannot keep")
	}
	if err := workspaceFit(moveDevice("mv-dev"), repoless); err != nil {
		t.Errorf("a device that keeps working directories refused a project with no repository: %v", err)
	}
	host := &moveExec{harnessExec: newHarnessExec("mv-host", executor.KindContainer, executor.IsolationContainer),
		caps: executor.Capabilities{Isolation: executor.IsolationContainer, SharesHostFilesystem: true}}
	if err := workspaceFit(host, repoless); err != nil {
		t.Errorf("an executor on the hub's own tree needs no source handed to it: %v", err)
	}
	noRemote := t.TempDir()
	moveGit(t, noRemote, "init", "-q", "-b", "main")
	if err := workspaceFit(moveDevice("mv-dev"), noRemote); err == nil {
		t.Error("a repository with no remote was accepted on a device, which could never fetch it")
	}
}
