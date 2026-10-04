package ui

// Parallel features on the hub (Task 20341): discovery, the policy a feature
// inherits from its project, and the feature routes. The routes dispatch the
// `cloop feature` CLI, which this package cannot build (cmd imports pkg/ui), so
// these tests stand in a script that records its argv and prints the framed
// result the CLI would; tests/e2e/features_test.go runs the real one.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/state"
)

// featureFixture is a hub whose primary project is a scratch directory and
// whose second project ("parent", index 1) has features.
type featureFixture struct {
	srv     *Server
	ts      *httptest.Server
	primary string
	parent  string
}

func newFeatureFixture(t *testing.T) *featureFixture {
	t.Helper()
	f := newUnstartedFeatureFixture(t)
	f.start(t)
	return f
}

// newUnstartedFeatureFixture is newFeatureFixture before its hub serves
// anything, for a test that configures the Server first — stubCLI, say — and
// then hands the URL to a browser.
//
// The order matters under -race. A request from this process's own HTTP client
// is ordered after the test's earlier writes to the Server (the race detector
// treats a socket write and the read that receives it as a synchronisation),
// but a request from Chrome carries no such edge: to the detector, the
// handler's read of srv.SelfExe was concurrent with stubCLI's write, and
// TestFeatures_InBrowser failed with "race detected during execution of test"
// about one run in four under load (Task 20344). Configuring the Server before
// start() orders every write before the goroutine that will serve it.
func newUnstartedFeatureFixture(t *testing.T) *featureFixture {
	t.Helper()
	// A home of its own: the package's shared one accumulates other tests'
	// projects, and these tests assert on indices.
	t.Setenv("HOME", t.TempDir())
	t.Setenv(multiui.EnvRoot, t.TempDir())
	primary := setupProjectDir(t, "hub", nil)
	parent := setupProjectDir(t, "parent goal", nil)
	if err := os.MkdirAll(filepath.Join(parent, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	srv := New(primary, 0, "")
	srv.Projects = []string{parent}
	return &featureFixture{srv: srv, primary: primary, parent: parent}
}

// start serves the fixture's hub.
func (f *featureFixture) start(t *testing.T) {
	t.Helper()
	f.ts = httptest.NewServer(f.srv.Handler())
	t.Cleanup(f.ts.Close)
}

// addFeature makes a feature of parent the way `cloop feature new` leaves one:
// a record, and state of its own.
func addFeature(t *testing.T, parent, slug string, created time.Time, mutate func(*feature.Meta, *state.ProjectState)) string {
	t.Helper()
	dir := feature.Path(parent, slug)
	statedbtest.SeedDir(t, dir)
	st, err := state.Init(dir, "goal of "+slug, 0)
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	m := &feature.Meta{Slug: slug, Title: "Feature " + slug, Branch: feature.BranchName(slug),
		Base: "main", Parent: parent, CreatedAt: created}
	if mutate != nil {
		mutate(m, st)
		if err := st.Save(); err != nil {
			t.Fatal(err)
		}
	}
	if err := feature.SaveMeta(dir, m); err != nil {
		t.Fatal(err)
	}
	return dir
}

func (f *featureFixture) do(t *testing.T, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, f.ts.URL+path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// stubCLI installs a script as the hub's cloop binary. It records its argv, one
// argument per line, to the returned file and counts its invocations beside
// it, runs extra shell (in the working directory the hub dispatched to), and
// prints result framed the way clijson.Emit does — after a diagnostic on
// stderr, as a real command's output can carry — exiting with code.
func stubCLI(t *testing.T, srv *Server, extra string, result any, code int) (argvFile string) {
	t.Helper()
	dir := t.TempDir()
	argvFile = filepath.Join(dir, "argv")
	payload, _ := json.Marshal(result)
	payloadFile := filepath.Join(dir, "payload.json")
	if err := os.WriteFile(payloadFile, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$@" > %q
echo x >> %q
%s
echo "warning: an unrelated diagnostic on the shared stream" >&2
echo '<<<cloop-json:begin>>>'
cat %q
echo
echo '<<<cloop-json:end>>>'
exit %d
`, argvFile, filepath.Join(dir, "calls"), extra, payloadFile, code)
	exe := filepath.Join(dir, "cloop")
	if err := os.WriteFile(exe, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	srv.SelfExe = exe
	return argvFile
}

func readArgv(t *testing.T, file string) []string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("the CLI was not dispatched: %v", err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func stubCalls(t *testing.T, argvFile string) int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(filepath.Dir(argvFile), "calls"))
	if err != nil {
		return 0
	}
	return strings.Count(string(b), "x")
}

func auditRows(t *testing.T, dir string, action auditaction.Action) []eventlog.AuditEvent {
	t.Helper()
	// Retried: statedb switches the database to WAL before it sets its busy
	// timeout, so an open that meets another connection's closing checkpoint
	// — the hub's, writing in the background — fails at once with SQLITE_BUSY
	// rather than waiting its turn.
	deadline := time.Now().Add(10 * time.Second)
	for {
		out, err := readAuditRows(dir, action)
		if err == nil {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("read the audit trail: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func readAuditRows(dir string, action auditaction.Action) ([]eventlog.AuditEvent, error) {
	log, err := eventlog.Open(dir)
	if err != nil {
		return nil, err
	}
	defer log.Close()
	evs, _, err := log.List(eventlog.AuditFilter{Limit: 500})
	if err != nil {
		return nil, err
	}
	var out []eventlog.AuditEvent
	for _, e := range evs {
		if e.EventType == string(action) {
			out = append(out, e)
		}
	}
	return out, nil
}

func projectsList(t *testing.T, f *featureFixture) []map[string]any {
	t.Helper()
	code, body := f.do(t, "GET", "/api/projects", nil)
	if code != 200 {
		t.Fatalf("GET /api/projects = %d", code)
	}
	raw, _ := body["projects"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		out = append(out, r.(map[string]any))
	}
	return out
}

func TestFeatures_DiscoveredAfterEveryProject(t *testing.T) {
	f := newFeatureFixture(t)
	other := setupProjectDir(t, "other goal", nil)
	f.srv.Projects = append(f.srv.Projects, other)
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	login := addFeature(t, f.parent, "login", base, nil)
	dark := addFeature(t, f.parent, "dark-mode", base.Add(time.Hour), nil)
	// Not features: a directory with no record, and a registry entry naming a
	// feature path directly.
	if err := os.MkdirAll(filepath.Join(feature.Dir(f.parent), "stray"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := multiui.AddPaths([]string{login}); err != nil {
		t.Fatal(err)
	}

	entries := f.srv.allProjectEntries()
	var got []string
	for _, e := range entries {
		got = append(got, e.Name+"|"+e.Parent+"|"+e.Feature)
	}
	pname := filepath.Base(f.parent)
	want := []string{
		filepath.Base(f.primary) + "||",
		pname + "||",
		filepath.Base(other) + "||",
		pname + "/login|" + f.parent + "|login",
		pname + "/dark-mode|" + f.parent + "|dark-mode",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("entries:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	ps := projectsList(t, f)
	if len(ps) != 5 {
		t.Fatalf("/api/projects lists %d projects, want 5", len(ps))
	}
	if ps[1]["has_git"] != true || ps[0]["has_git"] == true {
		t.Errorf("has_git: parent %v, primary %v", ps[1]["has_git"], ps[0]["has_git"])
	}
	fs, ok := ps[4]["feature"].(map[string]any)
	if !ok || ps[4]["parent"] != f.parent || fs["slug"] != "dark-mode" || fs["branch"] != "cloop/feature/dark-mode" || ps[4]["path"] != dark {
		t.Errorf("feature status = %v", ps[4])
	}

	// The features endpoint answers with each feature's own index.
	code, body := f.do(t, "GET", "/api/projects/1/features", nil)
	if code != 200 {
		t.Fatalf("GET features = %d %v", code, body)
	}
	list, _ := body["features"].([]any)
	if len(list) != 2 {
		t.Fatalf("features = %v", body)
	}
	if idx := list[0].(map[string]any)["project_idx"]; idx != float64(3) {
		t.Errorf("first feature's project_idx = %v, want 3", idx)
	}
	// A feature has no features.
	if code, _ := f.do(t, "GET", "/api/projects/3/features", nil); code != http.StatusBadRequest {
		t.Errorf("features of a feature = %d, want 400", code)
	}
}

func TestFeatures_AggregateCountsProjectsNotFeatures(t *testing.T) {
	f := newFeatureFixture(t)
	addFeature(t, f.parent, "a", time.Now(), nil)
	addFeature(t, f.parent, "b", time.Now(), nil)
	_, body := f.do(t, "GET", "/api/projects", nil)
	stats, _ := body["stats"].(map[string]any)
	if stats["total_projects"] != float64(2) {
		t.Errorf("total_projects = %v, want 2 — features are part of a project, not projects", stats["total_projects"])
	}
}

func TestFeatures_RunWhereTheirProjectRuns(t *testing.T) {
	f := newFeatureFixture(t)
	dir := addFeature(t, f.parent, "login", time.Now(), nil)
	registerBuiltinExecutors()

	iso := &readyzStubExecutor{id: "feature-policy-iso"}
	if err := executor.DefaultRegistry.Register(iso); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(iso.id) })
	if err := executor.Bind(f.parent, iso.id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(f.parent) })

	// The feature has no binding of its own and resolves to its parent's —
	// not to the registry default, which would be the host.
	ex, err := executor.Resolve(dir)
	if err != nil || ex.ID() != iso.id {
		t.Fatalf("Resolve(feature) = %v, %v; want the parent's executor %s", ex, err, iso.id)
	}

	// Which it cannot run on: a feature travels to an isolating executor as
	// its branch (Task 20367), and this one can neither receive a branch nor
	// return work. The refusal names what is missing, is typed, and reaches
	// the browser as a 409 with a remediation.
	_, _, err = startWorkload(dir, []string{"cloop", "run"}, nil)
	if err == nil || !strings.Contains(err.Error(), "feature login cannot run on executor "+iso.id) ||
		!strings.Contains(err.Error(), "receive the feature's branch") {
		t.Fatalf("startWorkload(feature on isolating executor) = %v", err)
	}
	code, body := f.do(t, "POST", "/api/run?project_idx=2", map[string]any{})
	if code != http.StatusConflict || body["code"] != "feature_executor_unsupported" || body["remediation"] == "" {
		t.Errorf("POST /api/run on the feature = %d %v", code, body)
	}

	// A new feature of a project pinned there is made on the hub, where it
	// lives — never dispatched to an executor that cannot see the hub's
	// worktrees. The stub CLI would have answered a dispatch; nothing must.
	realRepo(t, f.parent)
	argv := stubCLI(t, f.srv, "", map[string]any{"ok": false, "error": "dispatched", "code": "failed"}, 3)
	code, body = f.do(t, "POST", "/api/projects/1/features", map[string]any{"name": "x", "description": "y"})
	if code != http.StatusOK || body["slug"] != "x" {
		t.Fatalf("create on an isolated project = %d %v", code, body)
	}
	if !feature.IsFeature(feature.Path(f.parent, "x")) {
		t.Error("the hub reported the feature created, but there is none")
	}
	if _, err := os.Stat(argv); err == nil {
		t.Error("creating a feature of an isolated project dispatched `cloop feature new` to its executor")
	}
}

// realRepo turns the fixture's stand-in .git into a repository with a commit on
// main, for a test in which the hub runs git itself.
func realRepo(t *testing.T, dir string) {
	t.Helper()
	if err := os.RemoveAll(filepath.Join(dir, ".git")); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "README.md")
	run("commit", "-qm", "first")
}

func TestFeatures_AuthorizedAsTheirProject(t *testing.T) {
	f := newFeatureFixture(t)
	dir := addFeature(t, f.parent, "login", time.Now(), nil)

	req := httptest.NewRequest("GET", "/api/state?project_idx=2", nil)
	if sc := f.srv.projectScope(req); sc.ProjectPath != f.parent || sc.Project != filepath.Base(f.parent) {
		t.Errorf("projectScope(feature) = %+v, want the parent's", sc)
	}
	req = httptest.NewRequest("POST", "/api/projects/2/run", nil)
	req.SetPathValue("idx", "2")
	if sc, ok := f.srv.projectScopeFromIdx(req); !ok || sc.ProjectPath != f.parent {
		t.Errorf("projectScopeFromIdx(feature) = %+v, %v", sc, ok)
	}
	if got := policyProjectPath(dir); got != f.parent {
		t.Errorf("policyProjectPath(feature) = %s", got)
	}
	if got := policyProjectPath(f.parent); got != f.parent {
		t.Errorf("policyProjectPath(project) = %s", got)
	}
}

func TestFeatures_FollowTheirProjectIntoATokenScope(t *testing.T) {
	f := newFeatureFixture(t)
	addFeature(t, f.parent, "login", time.Now(), nil)
	entries := f.srv.allProjectEntries()

	scoped := &apitoken.Token{ID: "t1", ProjectScope: []string{filepath.Base(f.parent)}}
	var names []string
	for _, e := range filterEntriesForToken(scoped, entries) {
		names = append(names, e.Name)
	}
	pname := filepath.Base(f.parent)
	if strings.Join(names, ",") != pname+","+pname+"/login" {
		t.Errorf("a token scoped to the project sees %v, want the project and its feature", names)
	}
	other := &apitoken.Token{ID: "t2", ProjectScope: []string{filepath.Base(f.primary)}}
	for _, e := range filterEntriesForToken(other, entries) {
		if e.IsFeature() {
			t.Errorf("a token scoped elsewhere sees feature %s", e.Name)
		}
	}
	statuses := []multiui.ProjectStatus{{Name: pname, Path: f.parent}, {Name: pname + "/login", Path: feature.Path(f.parent, "login"), Parent: f.parent}}
	got, _ := f.srv.filterStatusesForRecipient(nil, scoped, entries, statuses)
	if len(got) != 2 {
		t.Errorf("scoped statuses = %d, want the project and its feature", len(got))
	}
}

func TestFeatureAPI_CreateRefusals(t *testing.T) {
	f := newFeatureFixture(t)
	addFeature(t, f.parent, "taken", time.Now(), nil)
	argv := stubCLI(t, f.srv, "", map[string]any{"ok": true}, 0)

	cases := []struct {
		name string
		path string
		body any
		want int
	}{
		{"no name", "/api/projects/1/features", map[string]any{"description": "d"}, 400},
		{"unusable name", "/api/projects/1/features", map[string]any{"name": "!!!"}, 400},
		{"long name", "/api/projects/1/features", map[string]any{"name": strings.Repeat("a", 121)}, 400},
		{"dash base", "/api/projects/1/features", map[string]any{"name": "x", "base": "-f"}, 400},
		{"space base", "/api/projects/1/features", map[string]any{"name": "x", "base": "a b"}, 400},
		{"parallel", "/api/projects/1/features", map[string]any{"name": "x", "max_parallel": 65}, 400},
		{"too many tasks", "/api/projects/1/features", map[string]any{"name": "x", "tasks": make([]string, 201)}, 200},
		{"taken", "/api/projects/1/features", map[string]any{"name": "Taken"}, 409},
		{"feature of a feature", "/api/projects/2/features", map[string]any{"name": "x"}, 400},
		{"out of range", "/api/projects/9/features", map[string]any{"name": "x"}, 400},
		{"malformed", "/api/projects/1/features", "not an object", 400},
	}
	for _, c := range cases {
		if c.name == "too many tasks" {
			// Blank tasks are dropped rather than counted.
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			code, body := f.do(t, "POST", c.path, c.body)
			if code != c.want {
				t.Errorf("%s = %d %v, want %d", c.path, code, body, c.want)
			}
		})
	}
	tasks := make([]string, 201)
	for i := range tasks {
		tasks[i] = "t"
	}
	if code, _ := f.do(t, "POST", "/api/projects/1/features", map[string]any{"name": "x", "tasks": tasks}); code != 400 {
		t.Errorf("201 tasks = %d, want 400", code)
	}
	if _, err := os.Stat(argv); err == nil {
		t.Error("a refused request still dispatched the CLI")
	}

	// An uninitialised project cannot have features.
	bare := t.TempDir()
	f.srv.Projects = append(f.srv.Projects, bare)
	idx := len(f.srv.allProjectEntries()) - 2 // the bare project sits before the one feature
	if code, body := f.do(t, "POST", fmt.Sprintf("/api/projects/%d/features", idx), map[string]any{"name": "x"}); code != 409 {
		t.Errorf("uninitialised project = %d %v, want 409", code, body)
	}

	// Nor more than MaxPerProject.
	for i := 0; i < feature.MaxPerProject; i++ {
		d := feature.Path(f.parent, fmt.Sprintf("f%d", i))
		if err := os.MkdirAll(filepath.Join(d, ".cloop"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := feature.SaveMeta(d, &feature.Meta{Slug: fmt.Sprintf("f%d", i), Branch: feature.BranchName(fmt.Sprintf("f%d", i)),
			Base: "main", Parent: f.parent}); err != nil {
			t.Fatal(err)
		}
	}
	if code, body := f.do(t, "POST", "/api/projects/1/features", map[string]any{"name": "one more"}); code != 409 || !strings.Contains(fmt.Sprint(body["error"]), "most") {
		t.Errorf("past the cap = %d %v", code, body)
	}
}

func TestFeatureAPI_CreateDispatchesTheCLI(t *testing.T) {
	f := newFeatureFixture(t)
	slug := "payments"
	path := feature.Path(f.parent, slug)
	// The stub does what `cloop feature new` does as far as discovery can
	// tell — writes the record — so the response can name the new index.
	record, _ := json.Marshal(feature.Meta{Version: 1, Slug: slug, Title: "Payments", Branch: feature.BranchName(slug),
		Base: "develop", Parent: f.parent, CreatedAt: time.Now()})
	extra := fmt.Sprintf("mkdir -p %q && printf '%%s' %q > %q", filepath.Join(path, ".cloop"), string(record), feature.MetaPath(path))
	argv := stubCLI(t, f.srv, extra, map[string]any{"ok": true, "feature": map[string]any{
		"slug": slug, "branch": "cloop/feature/payments", "base": "develop", "path": path}}, 0)

	code, body := f.do(t, "POST", "/api/projects/1/features", map[string]any{
		"name": "-Payments", "description": "Take payments", "base": "develop",
		"tasks": []string{"Stripe", " ", "Invoices"}, "auto_evolve": true, "innovate": true,
		"parallel": true, "max_parallel": 3, "auto_pr": true,
	})
	if code != 200 || body["ok"] != true {
		t.Fatalf("create = %d %v", code, body)
	}
	if body["project_idx"] != float64(2) || body["path"] != path || body["branch"] != "cloop/feature/payments" {
		t.Errorf("create response = %v", body)
	}

	args := readArgv(t, argv)
	want := []string{"feature", "new", "--json", "--description=Take payments", "--created-by=local",
		"--base=develop", "--task=Stripe", "--task=Invoices", "--auto-evolve", "--innovate",
		"--parallel", "--max-parallel=3", "--auto-pr", "--", "-Payments"}
	if strings.Join(args, "|") != strings.Join(want, "|") {
		t.Errorf("argv:\n%v\nwant:\n%v", args, want)
	}

	rows := auditRows(t, f.parent, auditaction.ActionFeatureCreate)
	if len(rows) != 1 || rows[0].EntityID != slug || !strings.Contains(rows[0].Payload, `"auto_evolve":true`) {
		t.Errorf("audit rows = %+v", rows)
	}
	evs, _, err := state.ListEvents(f.parent, 0, 20)
	if err == nil {
		found := false
		for _, e := range evs {
			if e.Type == state.EventFeatureCreated {
				found = true
			}
		}
		if !found {
			t.Error("no feature_created event on the parent's journal")
		}
	}
}

func TestFeatureAPI_CLIFailuresMapToStatuses(t *testing.T) {
	cases := []struct {
		code string
		want int
	}{
		{"exists", 409}, {"dirty", 409}, {"running", 409}, {"nothing_to_propose", 409},
		{"no_token", 409}, {"nested", 400}, {"not_found", 404}, {"failed", 500},
	}
	for _, c := range cases {
		t.Run(c.code, func(t *testing.T) {
			f := newFeatureFixture(t)
			addFeature(t, f.parent, "login", time.Now(), nil)
			stubCLI(t, f.srv, "", map[string]any{"ok": false, "code": c.code, "error": "because " + c.code,
				"partial": map[string]any{"pushed": true}}, 1)
			code, body := f.do(t, "POST", "/api/projects/1/features/login/pr", map[string]any{})
			if code != c.want || body["code"] != c.code || body["error"] != "because "+c.code {
				t.Errorf("PR with CLI code %s = %d %v, want %d", c.code, code, body, c.want)
			}
			if p, _ := body["partial"].(map[string]any); p["pushed"] != true {
				t.Errorf("partial result lost: %v", body)
			}
		})
	}
}

func TestFeatureAPI_RemoveAndPR(t *testing.T) {
	f := newFeatureFixture(t)
	dir := addFeature(t, f.parent, "login", time.Now(), nil)

	argv := stubCLI(t, f.srv, "", map[string]any{"ok": true, "result": map[string]any{
		"pr":       map[string]any{"number": 7, "url": "https://github.com/acme/app/pull/7", "state": "open", "base": "main"},
		"existing": false, "pushed": true, "ahead": 2}}, 0)
	code, body := f.do(t, "POST", "/api/projects/1/features/login/pr", map[string]any{"title": "Login", "draft": true})
	if code != 200 || body["ok"] != true {
		t.Fatalf("PR = %d %v", code, body)
	}
	args := readArgv(t, argv)
	if strings.Join(args, "|") != "feature|pr|--json|--title=Login|--draft" {
		t.Errorf("PR argv = %v", args)
	}
	if rows := auditRows(t, f.parent, auditaction.ActionFeaturePROpen); len(rows) != 1 || !strings.Contains(rows[0].Payload, `"automatic":false`) {
		t.Errorf("PR audit = %+v", rows)
	}
	for _, p := range []string{dir, f.parent} {
		evs, _, _ := state.ListEvents(p, 0, 20)
		found := false
		for _, e := range evs {
			if e.Type == state.EventFeaturePR && strings.Contains(e.Message, "#7") {
				found = true
			}
		}
		if !found {
			t.Errorf("no feature_pr event on %s", p)
		}
	}

	if code, _ := f.do(t, "POST", "/api/projects/1/features/nope/pr", map[string]any{}); code != 404 {
		t.Errorf("PR for a missing feature = %d", code)
	}
	if code, _ := f.do(t, "POST", "/api/projects/1/features/Bad_Slug/pr", map[string]any{}); code != 400 {
		t.Errorf("PR for an invalid slug = %d", code)
	}

	argv = stubCLI(t, f.srv, "", map[string]any{"ok": true, "removed": map[string]any{
		"branch": "cloop/feature/login", "branch_deleted": true}}, 0)
	code, body = f.do(t, "DELETE", "/api/projects/1/features/login", map[string]any{"delete_branch": true, "force": true})
	if code != 200 || body["branch_deleted"] != true {
		t.Fatalf("remove = %d %v", code, body)
	}
	if args := readArgv(t, argv); strings.Join(args, "|") != "feature|remove|--json|--delete-branch|--force|--|login" {
		t.Errorf("remove argv = %v", args)
	}
	if rows := auditRows(t, f.parent, auditaction.ActionFeatureRemove); len(rows) != 1 {
		t.Errorf("remove audit = %+v", rows)
	}
}

func TestFeatures_ProjectRoutesRefuseFeatures(t *testing.T) {
	f := newFeatureFixture(t)
	addFeature(t, f.parent, "login", time.Now(), nil)
	if code, body := f.do(t, "DELETE", "/api/projects/2", nil); code != 400 || !strings.Contains(fmt.Sprint(body["error"]), "feature") {
		t.Errorf("DELETE /api/projects/{feature} = %d %v", code, body)
	}
	if code, body := f.do(t, "POST", "/api/projects/2/executor", map[string]any{"executor_id": "local"}); code != 409 {
		t.Errorf("binding a feature's executor = %d %v", code, body)
	}
	if code, body := f.do(t, "POST", "/api/projects/2/repositories", map[string]any{"secret": "x", "repos": []string{"a/b"}}); code != 409 {
		t.Errorf("assigning a feature repositories = %d %v", code, body)
	}
	if code, body := f.do(t, "DELETE", "/api/projects/2/repositories", map[string]any{"grant_id": "g"}); code != 409 {
		t.Errorf("revoking a feature's repositories = %d %v", code, body)
	}
	if code, body := f.do(t, "POST", "/api/projects/2/hidden", map[string]any{"hidden": true}); code != 400 {
		t.Errorf("hiding a feature on its own = %d %v", code, body)
	}
	// Hiding the project hides its features with it.
	if code, body := f.do(t, "POST", "/api/projects/1/hidden", map[string]any{"hidden": true}); code != 200 {
		t.Fatalf("hiding the project = %d %v", code, body)
	}
	ps := projectsList(t, f)
	if ps[1]["hidden"] != true || ps[2]["hidden"] != true {
		t.Errorf("after hiding the project: project hidden=%v, feature hidden=%v", ps[1]["hidden"], ps[2]["hidden"])
	}
}

func TestIsSafeProjectRoot_RefusesControlDirectories(t *testing.T) {
	for _, p := range []string{"/srv/p/.cloop", "/srv/p/.cloop/features/x", "/srv/p/.cloop/sessions/s"} {
		if isSafeProjectRoot(p) {
			t.Errorf("isSafeProjectRoot(%q) = true; nothing inside a control directory is a project", p)
		}
	}
	if !isSafeProjectRoot("/srv/p/.cloopy") || !isSafeProjectRoot("/srv/p") {
		t.Error("ordinary roots refused")
	}
}

func TestFeatures_AutoPROnCompletionOnce(t *testing.T) {
	f := newFeatureFixture(t)
	auto := addFeature(t, f.parent, "auto", time.Now(), func(m *feature.Meta, st *state.ProjectState) {
		m.AutoPR = true
		st.Status = "complete"
	})
	manual := addFeature(t, f.parent, "manual", time.Now(), func(_ *feature.Meta, st *state.ProjectState) {
		st.Status = "complete"
	})
	unfinished := addFeature(t, f.parent, "unfinished", time.Now(), func(m *feature.Meta, st *state.ProjectState) {
		m.AutoPR = true
		st.Status = "paused"
	})
	argv := stubCLI(t, f.srv, "", map[string]any{"ok": true, "result": map[string]any{
		"pr": map[string]any{"number": 9, "url": "https://github.com/acme/app/pull/9", "state": "open", "base": "main"}}}, 0)
	t.Cleanup(func() {
		autoPRLastTry.Delete(auto)
		autoPRLastTry.Delete(manual)
		autoPRLastTry.Delete(unfinished)
	})

	f.srv.maybeAutoOpenFeaturePR(manual)
	f.srv.maybeAutoOpenFeaturePR(unfinished)
	f.srv.maybeAutoOpenFeaturePR(f.parent)
	f.srv.maybeAutoOpenFeaturePR(auto)
	f.srv.maybeAutoOpenFeaturePR(auto) // the second sighting of the same run end

	// Waited out by its in-flight mark, which is set before the attempt starts
	// and cleared once everything it records is written — not by polling the
	// database it is writing to.
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, busy := autoPRInFlight.Load(auto); !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the automatic pull request was still being opened after 20s")
		}
		time.Sleep(10 * time.Millisecond)
	}
	rows := auditRows(t, f.parent, auditaction.ActionFeaturePROpen)
	if len(rows) != 1 || rows[0].EntityID != "auto" || !strings.Contains(rows[0].Payload, `"automatic":true`) || rows[0].Actor != "hub" {
		t.Fatalf("automatic PR audit = %+v", rows)
	}
	if n := stubCalls(t, argv); n != 1 {
		t.Errorf("the CLI was dispatched %d times, want once", n)
	}
	if args := readArgv(t, argv); strings.Join(args, "|") != "feature|pr|--json" {
		t.Errorf("automatic PR argv = %v", args)
	}
	// A later run end inside the cooldown does not try again.
	f.srv.maybeAutoOpenFeaturePR(auto)
	time.Sleep(200 * time.Millisecond)
	if n := stubCalls(t, argv); n != 1 {
		t.Errorf("dispatched %d times after a repeat inside the cooldown", n)
	}
}

func TestFeatures_ListChangeIsNoticed(t *testing.T) {
	f := newFeatureFixture(t)
	dir := addFeature(t, f.parent, "gone", time.Now(), nil)
	f.srv.refreshProjectStatuses()
	if f.srv.entrySetChanged(f.srv.allProjectEntries()) {
		t.Fatal("an unchanged list reads as changed")
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if !f.srv.entrySetChanged(f.srv.allProjectEntries()) {
		t.Error("a removed feature does not register as a change, so the dashboard would keep showing it")
	}
	// And a feature's record changing counts as its state changing.
	dir2 := addFeature(t, f.parent, "pr", time.Now(), nil)
	before, _ := stateModTime(dir2)
	time.Sleep(20 * time.Millisecond)
	m, _ := feature.LoadMeta(dir2)
	m.PR = &feature.PR{Number: 1, URL: "https://x/1", State: "open"}
	if err := feature.SaveMeta(dir2, m); err != nil {
		t.Fatal(err)
	}
	after, _ := stateModTime(dir2)
	if !after.After(before) {
		t.Error("recording a pull request is not seen as a change to the feature")
	}
}

// A request is served on the project it was authorized for. Removing a
// feature renumbers every feature after it, so an index resolved again inside
// the handler could name a different project — one of another parent, where
// the caller's roles differ — or, for ?project_idx, fall back to the primary.
func TestFeatures_RequestKeepsTheProjectItWasAuthorizedFor(t *testing.T) {
	f := newFeatureFixture(t)
	now := time.Now()
	alpha := addFeature(t, f.parent, "alpha", now.Add(-time.Hour), nil) // index 2
	beta := addFeature(t, f.parent, "beta", now, nil)                   // index 3

	query := httptest.NewRequest("GET", "/api/state?project_idx=2", nil)
	pinnedQuery, scope, ok := f.srv.pinProject(scopeProject, query)
	if !ok || scope.ProjectPath != f.parent {
		t.Fatalf("pinProject(?project_idx=2) = %+v, %v; want the parent's scope", scope, ok)
	}
	path := httptest.NewRequest("POST", "/api/projects/2/run", nil)
	path.SetPathValue("idx", "2")
	pinnedPath, scope, ok := f.srv.pinProject(scopeProjectIdx, path)
	if !ok || scope.ProjectPath != f.parent {
		t.Fatalf("pinProject({idx}=2) = %+v, %v; want the parent's scope", scope, ok)
	}

	// Between the gate and the handler, alpha goes and beta moves into 2.
	if err := os.RemoveAll(alpha); err != nil {
		t.Fatal(err)
	}
	if got := f.srv.resolveWorkDir(query); got != beta {
		t.Fatalf("the list did not shift: index 2 resolves to %s", got)
	}

	if got := f.srv.resolveWorkDir(pinnedQuery); got != alpha {
		t.Errorf("?project_idx resolves to %s inside the handler, want %s — the project that was authorized", got, alpha)
	}
	rec := httptest.NewRecorder()
	if e, ok := f.srv.projectAtIdx(rec, pinnedPath); ok || rec.Code != http.StatusConflict {
		t.Errorf("{idx} resolves to %s (ok=%v, status %d) inside the handler, want a 409", e.Path, ok, rec.Code)
	}
	if sc, ok := f.srv.projectScopeFromIdx(pinnedPath); ok {
		t.Errorf("a handler's own scope check resolves the shifted index to %+v", sc)
	}

	// Unpinned — a hub without authorization, whose gate pins nothing — the
	// handler resolves the index as it always has.
	rec = httptest.NewRecorder()
	if e, ok := f.srv.projectAtIdx(rec, path); !ok || e.Path != beta {
		t.Errorf("unpinned {idx} = %s, %v (status %d), want beta", e.Path, ok, rec.Code)
	}
}

// TestFeatures_SettingsAreTheirOwn is the task's own words: a feature has
// independent run and evolve settings. Toggling one on a feature changes that
// feature alone, and toggling the project's leaves its features as they were.
func TestFeatures_SettingsAreTheirOwn(t *testing.T) {
	f := newFeatureFixture(t)
	a := addFeature(t, f.parent, "a", time.Now().Add(-time.Minute), nil)
	b := addFeature(t, f.parent, "b", time.Now(), nil)

	toggle := func(idx int, flag string, value bool) {
		t.Helper()
		code, body := f.do(t, "POST", fmt.Sprintf("/api/options/toggle?project_idx=%d", idx),
			map[string]any{"flag": flag, "value": value})
		if code != 200 {
			t.Fatalf("toggle %s on %d = %d %v", flag, idx, code, body)
		}
	}
	load := func(dir string) *state.ProjectState {
		t.Helper()
		st, err := state.LoadLite(dir)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	toggle(2, "auto_evolve", true)   // feature a
	toggle(3, "innovate_mode", true) // feature b
	toggle(1, "parallel", true)      // the project

	pa, pb, pp := load(a), load(b), load(f.parent)
	if !pa.AutoEvolve || pa.InnovateMode || pa.Parallel {
		t.Errorf("feature a: evolve=%v innovate=%v parallel=%v, want true/false/false", pa.AutoEvolve, pa.InnovateMode, pa.Parallel)
	}
	if pb.AutoEvolve || !pb.InnovateMode || pb.Parallel {
		t.Errorf("feature b: evolve=%v innovate=%v parallel=%v, want false/true/false", pb.AutoEvolve, pb.InnovateMode, pb.Parallel)
	}
	if pp.AutoEvolve || pp.InnovateMode || !pp.Parallel {
		t.Errorf("project: evolve=%v innovate=%v parallel=%v, want false/false/true", pp.AutoEvolve, pp.InnovateMode, pp.Parallel)
	}
	// The dashboard shows each feature's own settings on its row.
	ps := projectsList(t, f)
	fa, _ := ps[2]["feature"].(map[string]any)
	fb, _ := ps[3]["feature"].(map[string]any)
	if fa["auto_evolve"] != true || fa["innovate"] == true || fb["innovate"] != true || fb["auto_evolve"] == true {
		t.Errorf("feature statuses: a=%v b=%v", fa, fb)
	}
}

// TestFeatures_StreamsCloseWithTheirProjectsDeny: a runtime deny on a project
// must close its features' live streams too — they carry the project's tasks,
// logs and state under another path.
func TestFeatures_StreamsCloseWithTheirProjectsDeny(t *testing.T) {
	f := newFeatureFixture(t)
	dir := addFeature(t, f.parent, "login", time.Now(), nil)
	f.srv.Authz = runtimeDenyResolver(t, authz.Config{},
		authz.Binding{Claim: authz.ClaimEmail, Value: "alice@example.com", Deny: true, Project: f.parent})
	alice := &oidcauth.Identity{Sub: "sub-alice", Email: "alice@example.com"}
	if b := f.srv.connectionDenied(alice, nil, f.parent); b == nil {
		t.Fatal("the deny does not even apply to the project")
	}
	if b := f.srv.connectionDenied(alice, nil, dir); b == nil {
		t.Error("a deny on the project left the stream on its feature open")
	}
	if b := f.srv.connectionDenied(alice, nil, f.primary); b != nil {
		t.Error("a deny on one project closed a stream on another")
	}
}
