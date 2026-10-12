package ui

// Where a project may live (Task 20418): creation confined to the projects
// root for anyone but an administrator, refusals that do not reveal what
// exists, a path claimed before anything is made in it, ?delete_root=true only
// for a directory the hub made, and a row that breaks the rule refused at
// dispatch and flagged on the Projects tab.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// confineHub is an OIDC hub whose projects root is a directory of its own,
// with keepers mapped to maintainer and owners to admin.
type confineHub struct {
	srv   *Server
	ts    *httptest.Server
	url   string
	idp   *uiFakeIdP
	root  string
	other string // a scratch directory outside the root
}

func newConfineHub(t *testing.T) *confineHub {
	t.Helper()
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	hubWithControlPlane(t, srv.WorkDir)
	resolver, err := authz.New(authz.Config{Bindings: []authz.Binding{
		{Claim: authz.ClaimGroup, Value: "keepers", Role: authz.RoleMaintainer},
		{Claim: authz.ClaimGroup, Value: "owners", Role: authz.RoleAdmin},
	}})
	if err != nil {
		t.Fatal(err)
	}
	srv.Authz = resolver
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "projects")
	cfg, err := config.Load(srv.WorkDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.UI.ProjectsRoot = root
	if err := config.Save(srv.WorkDir, cfg); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(base, "elsewhere")
	return &confineHub{srv: srv, ts: ts, url: ts.URL, idp: idp, root: root, other: other}
}

// as signs a browser in as email in the given groups.
func (h *confineHub) as(t *testing.T, email string, groups ...string) *http.Client {
	t.Helper()
	h.idp.email, h.idp.sub, h.idp.name = email, "sub-"+email, email
	h.idp.groups = groups
	c := jarClient(t)
	login(t, c, h.ts)
	return c
}

func (h *confineHub) create(t *testing.T, c *http.Client, body string) (int, map[string]any) {
	t.Helper()
	return doJSON(t, c, http.MethodPost, h.url+"/api/projects/new", body)
}

func errMessage(got map[string]any) string {
	if e, ok := got["error"].(map[string]any); ok {
		m, _ := e["message"].(string)
		return m
	}
	m, _ := got["error"].(string)
	return m
}

func errCode(got map[string]any) string {
	if e, ok := got["error"].(map[string]any); ok {
		c, _ := e["code"].(string)
		return c
	}
	c, _ := got["code"].(string)
	return c
}

func TestProjectNewConfinesAMaintainerToTheProjectsRoot(t *testing.T) {
	h := newConfineHub(t)
	keeper := h.as(t, "kim@example.com", "keepers")

	status, got := h.create(t, keeper, `{"name":"widgets","goal":"Ship widgets"}`)
	if status != http.StatusOK || got["dir"] != filepath.Join(h.root, "widgets") {
		t.Fatalf("a maintainer's creation by name = %d %v", status, got)
	}

	for _, c := range []struct {
		name, dir string
		status    int
		says      string
	}{
		{"the root itself", h.root, http.StatusConflict, "is the hub's projects root"},
		{"the root with a trailing slash", h.root + "/", http.StatusConflict, "is the hub's projects root"},
		{"the root's parent", h.root + "/..", http.StatusConflict, "contains the hub's projects root"},
		{"dot-dot out of a project", h.root + "/widgets/../..", http.StatusConflict, "contains the hub's projects root"},
		{"outside the root", h.other, http.StatusForbidden, "only an administrator places a project outside"},
		{"the hub's directory", h.srv.WorkDir, http.StatusForbidden, "only an administrator places a project outside"},
		{"a hidden directory under the root", filepath.Join(h.root, ".ssh"), http.StatusForbidden, "hidden directory"},
		{"a system directory", "/etc/cloop-probe", http.StatusBadRequest, "operating system"},
	} {
		t.Run(c.name, func(t *testing.T) {
			status, got := h.create(t, keeper, `{"dir":`+quote(c.dir)+`,"goal":"g"}`)
			if status != c.status || !strings.Contains(errMessage(got), c.says) {
				t.Fatalf("create at %s = %d %v, want %d saying %q", c.dir, status, got, c.status, c.says)
			}
		})
	}
	// The refusal outside the root says what was needed, as the dashboard's
	// other permission refusals do, for the terminal to explain.
	_, got = h.create(t, keeper, `{"dir":`+quote(h.other)+`,"goal":"g"}`)
	details, _ := got["error"].(map[string]any)["details"].(map[string]any)
	if details["required_permission"] != "executor.manage" || details["projects_root"] != h.root || details["role"] != "maintainer" {
		t.Fatalf("the refusal's details = %v", details)
	}
	for _, d := range []string{h.other, "/etc/cloop-probe", filepath.Join(h.root, ".ssh")} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Fatalf("a refused creation made %s", d)
		}
	}
}

func TestProjectNewHoldsAnAdministratorToTheRest(t *testing.T) {
	h := newConfineHub(t)
	owner := h.as(t, "olga@example.com", "owners")

	if status, got := h.create(t, owner, `{"dir":`+quote(h.other)+`,"goal":"g"}`); status != http.StatusOK {
		t.Fatalf("an administrator's creation outside the root = %d %v", status, got)
	}
	for _, c := range []struct{ name, dir, says string }{
		{"the hub's directory", h.srv.WorkDir, "is the hub's own directory"},
		{"inside a project", filepath.Join(h.other, "sub"), "inside the project at " + h.other},
		{"containing a project", filepath.Dir(h.other), "contains the hub's projects root"},
		{"the root", h.root, "is the hub's projects root"},
	} {
		t.Run(c.name, func(t *testing.T) {
			status, got := h.create(t, owner, `{"dir":`+quote(c.dir)+`,"goal":"g"}`)
			if status != http.StatusConflict || !strings.Contains(errMessage(got), c.says) {
				t.Fatalf("create at %s = %d %v, want 409 saying %q", c.dir, status, got, c.says)
			}
		})
	}
}

// TestProjectNewRefusalsDoNotRevealWhatExists: a maintainer asking for a
// directory that holds someone else's project, one inside it, one another
// creation holds right now, and one with an unregistered project on disk is
// told the same thing each time — and the owner of the project, and an
// administrator, are told what is there.
func TestProjectNewRefusalsDoNotRevealWhatExists(t *testing.T) {
	h := newConfineHub(t)
	alice := h.as(t, "alice@example.com", "keepers")
	if status, got := h.create(t, alice, `{"name":"alice-secret","goal":"hers"}`); status != http.StatusOK {
		t.Fatalf("alice's creation = %d %v", status, got)
	}
	aliceDir := filepath.Join(h.root, "alice-secret")

	// A path another creation is holding at this moment.
	db, err := h.srv.controlPlaneDB()
	if err != nil {
		t.Fatal(err)
	}
	held := filepath.Join(h.root, "being-made")
	if c, err := db.ClaimProjectPath(statedb.ProjectClaim{Path: held, ClaimedBy: "carol"}, nil); err != nil || c != nil {
		t.Fatalf("hold %s: %v %v", held, c, err)
	}
	db.Close()

	// A project on disk that nobody registered.
	loose := filepath.Join(h.root, "loose")
	if err := os.MkdirAll(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if st, err := state.Init(loose, "loose goal", 0); err != nil || st.Save() != nil {
		t.Fatalf("init a loose project: %v", err)
	}

	bob := h.as(t, "bob@example.com", "keepers")
	var answers []string
	for _, dir := range []string{aliceDir, filepath.Join(aliceDir, "sub"), held, loose} {
		status, got := h.create(t, bob, `{"dir":`+quote(dir)+`,"goal":"probe"}`)
		if status != http.StatusConflict || errCode(got) != "CONFLICT" {
			t.Fatalf("bob at %s = %d %v, want 409 CONFLICT", dir, status, got)
		}
		msg := strings.ReplaceAll(errMessage(got), dir, "<dir>")
		for _, leak := range []string{"alice", "exists", "carol", "being made", "inside", "loose goal"} {
			if strings.Contains(msg, leak) {
				t.Errorf("bob was told %q about %s: %q", leak, dir, errMessage(got))
			}
		}
		answers = append(answers, msg)
	}
	for i := 1; i < len(answers); i++ {
		if answers[i] != answers[0] {
			t.Fatalf("bob's refusals differ with what is there:\n%q\n%q", answers[0], answers[i])
		}
	}
	// Alice's row is as she left it: nobody re-registered or re-owned it.
	entries, _ := multiui.Load()
	var owners []string
	for _, e := range entries {
		if e.Path == aliceDir {
			owners = append(owners, e.Owner)
		}
	}
	if len(owners) != 1 || !strings.Contains(owners[0], "alice@example.com") {
		t.Fatalf("alice's project is registered as %v", owners)
	}

	// Alice may see her own project, so she is told it exists.
	_, got := h.create(t, alice, `{"dir":`+quote(aliceDir)+`,"goal":"again"}`)
	if !strings.Contains(errMessage(got), "already exists at "+aliceDir) {
		t.Fatalf("alice at her own project = %v", got)
	}
	// An administrator sees everything, and is told what collided.
	owner := h.as(t, "olga@example.com", "owners")
	_, got = h.create(t, owner, `{"dir":`+quote(held)+`,"goal":"g"}`)
	if !strings.Contains(errMessage(got), "held by another creation") || !strings.Contains(errMessage(got), "carol") {
		t.Fatalf("an administrator at a held path = %v", got)
	}

	// Every refusal is on the trail with the whole reason.
	rows := projectAuditRows(t, h.srv.WorkDir, auditaction.ActionProjectCreate)
	var refused int
	for _, r := range rows {
		if strings.Contains(r, `"outcome":"refused"`) && strings.Contains(r, "bob@example.com") {
			refused++
		}
	}
	if refused != 4 {
		t.Fatalf("%d of bob's 4 refusals are on the trail:\n%s", refused, strings.Join(rows, "\n"))
	}
}

// projectAuditRows returns the control plane's rows of action, as JSON lines
// of actor and payload.
func projectAuditRows(t *testing.T, dir string, action auditaction.Action) []string {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(action), Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range evs {
		out = append(out, fmt.Sprintf(`{"actor":%q,"payload":%s}`, e.Actor, e.Payload))
	}
	return out
}

// TestConcurrentCreationsOfOnePathRunInitOnce: two creations of one path —
// or of a path and its parent — race, and exactly one of them makes a project.
// Before the claim both passed the existence check and both ran `cloop init`.
func TestConcurrentCreationsOfOnePathRunInitOnce(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := setupProjectDir(t, "the hub", nil)
	hubWithControlPlane(t, dir)
	srv := New(dir, 0, "")
	// A cloop that records each init it is asked to run, and takes long
	// enough about it that two creations really are in flight together.
	inits := filepath.Join(t.TempDir(), "inits")
	stubExe := filepath.Join(t.TempDir(), "cloop")
	script := "#!/bin/sh\n[ \"$1\" = init ] && echo \"$2 in $PWD\" >> '" + inits + "'\nsleep 0.5\n"
	if err := os.WriteFile(stubExe, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	srv.SelfExe = stubExe
	ts := newTestServerFor(t, srv)
	target := filepath.Join(home, "projects", "contested")

	race := func(bodies ...string) []int {
		var wg sync.WaitGroup
		statuses := make([]int, len(bodies))
		for i, b := range bodies {
			wg.Add(1)
			go func(i int, b string) {
				defer wg.Done()
				statuses[i], _ = doJSON(t, ts.Client(), http.MethodPost, ts.URL+"/api/projects/new", b)
			}(i, b)
		}
		wg.Wait()
		return statuses
	}
	statuses := race(`{"dir":`+quote(target)+`,"goal":"first"}`, `{"dir":`+quote(target)+`,"goal":"second"}`)
	if !((statuses[0] == http.StatusOK && statuses[1] == http.StatusConflict) ||
		(statuses[1] == http.StatusOK && statuses[0] == http.StatusConflict)) {
		t.Fatalf("two creations of one path = %v, want one 200 and one 409", statuses)
	}
	data, err := os.ReadFile(inits)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(string(data)), "\n"); len(lines) != 1 {
		t.Fatalf("`cloop init` ran %d times for one path:\n%s", len(lines), data)
	}

	parent := filepath.Join(home, "projects", "nest")
	statuses = race(`{"dir":`+quote(parent)+`,"goal":"parent"}`, `{"dir":`+quote(filepath.Join(parent, "child"))+`,"goal":"child"}`)
	ok := 0
	for _, s := range statuses {
		if s == http.StatusOK {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("a path and its child created at once = %v, want exactly one created", statuses)
	}
	entries, _ := multiui.Load()
	var registered []string
	for _, e := range entries {
		if strings.HasPrefix(e.Path, parent) {
			registered = append(registered, e.Path)
		}
	}
	if len(registered) != 1 {
		t.Fatalf("registered under %s: %v, want one", parent, registered)
	}
}

// TestDeleteRootOnlyForDirectoriesTheHubMade: an adopted directory — one that
// existed before its project, or one an operator registered — keeps its files
// and its project when ?delete_root=true is asked, and the refusal is audited.
func TestDeleteRootOnlyForDirectoriesTheHubMade(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := setupProjectDir(t, "the hub", nil)
	hubWithControlPlane(t, dir)
	operators := setupProjectDir(t, "an operator's", nil)
	ts := newTestServer(t, dir, []string{operators})

	adopted := filepath.Join(home, "projects", "adopted")
	keep := filepath.Join(adopted, "keep.txt")
	if err := os.MkdirAll(adopted, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keep, []byte("not the hub's\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	status, got := doJSON(t, ts.Client(), http.MethodPost, ts.URL+"/api/projects/new", `{"dir":`+quote(adopted)+`,"goal":"adopt"}`)
	if status != http.StatusOK {
		t.Fatalf("create in an existing directory = %d %v", status, got)
	}
	idxOf := func(path string) int {
		_, body := doJSON(t, ts.Client(), http.MethodGet, ts.URL+"/api/projects", "")
		list, _ := body["projects"].([]any)
		for i, p := range list {
			if m, _ := p.(map[string]any); m["path"] == path {
				return i
			}
		}
		t.Fatalf("%s is not listed", path)
		return -1
	}
	for _, path := range []string{adopted, operators} {
		status, got := doJSON(t, ts.Client(), http.MethodDelete,
			fmt.Sprintf("%s/api/projects/%d?delete_root=true", ts.URL, idxOf(path)), "")
		if status != http.StatusConflict || !strings.Contains(errMessage(got), "did not create") {
			t.Fatalf("delete_root of %s = %d %v, want 409", path, status, got)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s was deleted: %v", path, err)
		}
		idxOf(path) // still registered
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("the adopted directory's file is gone: %v", err)
	}

	// Without delete_root it is unregistered, and its files stay.
	status, got = doJSON(t, ts.Client(), http.MethodDelete, fmt.Sprintf("%s/api/projects/%d", ts.URL, idxOf(adopted)), "")
	if status != http.StatusOK || got["root_deleted"] != false {
		t.Fatalf("unregister = %d %v", status, got)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("unregistering deleted files: %v", err)
	}

	rows := projectAuditRows(t, dir, auditaction.ActionProjectDelete)
	var refused, removed int
	for _, r := range rows {
		switch {
		case strings.Contains(r, `"outcome":"refused"`):
			refused++
		case strings.Contains(r, `"outcome":"removed"`) && strings.Contains(r, `"root_deleted":false`):
			removed++
		}
	}
	if refused != 2 || removed != 1 {
		t.Fatalf("project.delete rows: %d refused, %d removed; want 2 and 1:\n%s", refused, removed, strings.Join(rows, "\n"))
	}
	// The path can be created again: its claim went with its project.
	if status, got := doJSON(t, ts.Client(), http.MethodPost, ts.URL+"/api/projects/new",
		`{"dir":`+quote(filepath.Join(home, "projects", "fresh"))+`,"goal":"g"}`); status != http.StatusOK {
		t.Fatalf("create after the delete = %d %v", status, got)
	}
}

// TestDispatchRefusesAnUnconfinedRow: a row that breaks the invariant — here
// a project registered inside the hub's own directory, as an operator's
// --projects could — is listed and flagged, and its Run is refused before
// anything is bound or started.
func TestDispatchRefusesAnUnconfinedRow(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := setupProjectDir(t, "the hub", nil)
	hubWithControlPlane(t, dir)
	nested := filepath.Join(dir, "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if st, err := state.Init(nested, "nested goal", 0); err != nil || st.Save() != nil {
		t.Fatalf("init nested: %v", err)
	}
	ts := newTestServer(t, dir, []string{nested})

	stub := newMetricsStub("confine-stub", "confine-stub", executor.IsolationNone)
	if err := executor.Register(stub); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(stub.ID()) })
	if err := executor.Bind(nested, stub.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(nested) })

	_, body := doJSON(t, ts.Client(), http.MethodGet, ts.URL+"/api/projects", "")
	list, _ := body["projects"].([]any)
	idx := -1
	for i, p := range list {
		m, _ := p.(map[string]any)
		switch m["path"] {
		case nested:
			idx = i
			if msg, _ := m["confinement"].(string); !strings.Contains(msg, "will not run this project") ||
				!strings.Contains(msg, "inside the hub's control plane") {
				t.Errorf("the nested project's card flag = %q", msg)
			}
		case dir:
			if m["confinement"] != nil {
				t.Errorf("the hub's own project is flagged: %v", m["confinement"])
			}
		}
	}
	if idx < 0 {
		t.Fatalf("the nested project is not listed: %v", list)
	}

	status, got := doJSON(t, ts.Client(), http.MethodPost, fmt.Sprintf("%s/api/projects/%d/run", ts.URL, idx), `{}`)
	if status != http.StatusConflict || got["code"] != "project_unconfined" ||
		!strings.Contains(fmt.Sprint(got["error"]), "inside the hub's control plane") {
		t.Fatalf("run of the nested project = %d %v, want 409 project_unconfined naming the overlap", status, got)
	}
	stub.mu.Lock()
	started := len(stub.runs)
	stub.mu.Unlock()
	if started != 0 {
		t.Fatalf("the refused run reached the executor %d time(s)", started)
	}
	if err := checkDispatchConfinement(dir); err != nil {
		t.Fatalf("the hub's own project is refused: %v", err)
	}
	// A feature is judged as its project.
	if err := checkDispatchConfinement(filepath.Join(nested, ".cloop", "features", "f")); err == nil {
		t.Fatal("a feature of the refused project was allowed")
	}
}

func TestOperatorProjectWarnings(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	base := t.TempDir()
	hub := filepath.Join(base, "hub")
	clean := filepath.Join(t.TempDir(), "clean") // not under base, which is flagged below
	nested := filepath.Join(hub, "nested")
	for _, d := range []string{nested, clean} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	warnings := OperatorProjectWarnings(hub, nil, []string{clean, nested, filepath.Join(base, "x", "..")})
	if len(warnings) != 2 {
		t.Fatalf("warnings = %q, want the nested project and the hub's parent", warnings)
	}
	for _, w := range warnings {
		if strings.HasPrefix(w, clean) {
			t.Errorf("a clean directory was flagged: %q", w)
		}
		if !strings.Contains(w, "will not run it") {
			t.Errorf("a warning does not say what follows: %q", w)
		}
	}
}
