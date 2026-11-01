package ui

// The requirements a task implements, through the task API and the
// requirements API (Task 20460).

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// linksOf reads the requirements task id implements from dir's database.
func linksOf(t *testing.T, dir string, id int) string {
	t.Helper()
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	task := ps.Plan.TaskByID(id)
	if task == nil {
		t.Fatalf("task %d is not in the plan", id)
	}
	return fmt.Sprint(task.Requirements)
}

func taskIDOf(t *testing.T, d map[string]any) int {
	t.Helper()
	task, _ := d["task"].(map[string]any)
	id, ok := task["id"].(float64)
	if !ok {
		t.Fatalf("no task in %v", d)
	}
	return int(id)
}

// TestTaskAPILinksRequirements: every route that adds or edits a task takes
// `requirements` — ids or R-n names — checks them against the project's own
// requirements, and stores them sorted; a route that leaves it out leaves the
// links alone.
func TestTaskAPILinksRequirements(t *testing.T) {
	dir := setupProjectDir(t, "links", modelCallTasks())
	ts := modelCallHub(t, dir, newModelStub(t))
	approved := addRequirementVia(t, ts, map[string]any{"title": "Approved", "tests": []map[string]any{{"command": "true"}}})
	draft := addRequirementVia(t, ts, map[string]any{"title": "Draft", "status": "draft"})
	retired := addRequirementVia(t, ts, map[string]any{"title": "Retired", "status": "deprecated"})
	soonRetired := addRequirementVia(t, ts, map[string]any{"title": "Retired later"})

	code, d := rawJSON(t, ts, http.MethodPost, "/api/task/add", map[string]any{
		"title": "implements two", "requirements": []any{fmt.Sprintf("R-%d", draft), approved, approved}})
	if code != http.StatusOK {
		t.Fatalf("add with requirements = %d %v", code, d)
	}
	added := taskIDOf(t, d)
	if got := linksOf(t, dir, added); got != fmt.Sprint([]int{approved, draft}) {
		t.Fatalf("the added task implements %s", got)
	}
	code, d = rawJSON(t, ts, http.MethodPost, "/api/tasks", map[string]any{"title": "via REST", "requirements": []int{soonRetired}})
	if code != http.StatusOK {
		t.Fatalf("POST /api/tasks = %d %v", code, d)
	}
	rest := taskIDOf(t, d)

	// Refused, and nothing is written: an id the project has none for, a
	// new link to a deprecated one, and what is not an id at all.
	for name, c := range map[string]struct {
		method, path string
		body         map[string]any
		want         string
	}{
		"unknown on add":        {http.MethodPost, "/api/task/add", map[string]any{"title": "x", "requirements": []int{approved, 99}}, "R-99 is not a requirement of this project"},
		"deprecated on add":     {http.MethodPost, "/api/tasks", map[string]any{"title": "x", "requirements": []int{retired}}, "is deprecated"},
		"unknown on edit":       {http.MethodPost, "/api/task/edit", map[string]any{"id": 1, "requirements": []int{98, 99}}, "R-98, R-99 are not requirements of this project"},
		"deprecated on PUT":     {http.MethodPut, "/api/tasks/1", map[string]any{"requirements": []any{fmt.Sprintf("R-%d", retired)}}, "is deprecated"},
		"not a list":            {http.MethodPatch, "/api/tasks/1", map[string]any{"requirements": "R-1"}, "list of requirement ids"},
		"not an id":             {http.MethodPost, "/api/task/edit", map[string]any{"id": 1, "requirements": []int{0}}, "is not a requirement id"},
		"not a requirement ref": {http.MethodPost, "/api/task/add", map[string]any{"title": "x", "requirements": []string{"REQ-1"}}, "is not a requirement"},
	} {
		code, d := rawJSON(t, ts, c.method, c.path, c.body)
		if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(d["error"]), c.want) {
			t.Errorf("%s: %d %v, want 400 saying %q", name, code, d, c.want)
		}
	}
	if got := linksOf(t, dir, 1); got != "[]" {
		t.Errorf("a refused edit linked task 1 to %s", got)
	}
	ps, _ := state.Load(dir)
	if n := len(ps.Plan.Tasks); n != 4 {
		t.Errorf("a refused add added a task: the plan holds %d", n)
	}

	// Edit replaces the list, [] clears it, and a request without the key
	// leaves it.
	if code, d := rawJSON(t, ts, http.MethodPost, "/api/task/edit", map[string]any{"id": 1, "requirements": []int{approved}}); code != http.StatusOK {
		t.Fatalf("edit = %d %v", code, d)
	}
	if code, d := rawJSON(t, ts, http.MethodPatch, "/api/tasks/1", map[string]any{"title": "renamed"}); code != http.StatusOK {
		t.Fatalf("PATCH title = %d %v", code, d)
	}
	if got := linksOf(t, dir, 1); got != fmt.Sprint([]int{approved}) {
		t.Errorf("an edit without requirements changed them to %s", got)
	}
	if code, d := rawJSON(t, ts, http.MethodPut, "/api/tasks/1", map[string]any{"requirements": []int{}}); code != http.StatusOK {
		t.Fatalf("PUT [] = %d %v", code, d)
	}
	if got := linksOf(t, dir, 1); got != "[]" {
		t.Errorf("PUT [] left task 1 implementing %s", got)
	}

	// A requirement deprecated after the link was made stays linked through
	// an edit that keeps it, and cannot be linked anew elsewhere.
	if code, d := rawJSON(t, ts, http.MethodPut, fmt.Sprintf("/api/requirements/%d", soonRetired),
		map[string]any{"title": "Retired later", "status": "deprecated"}); code != http.StatusOK {
		t.Fatalf("deprecate = %d %v", code, d)
	}
	if code, d := rawJSON(t, ts, http.MethodPost, "/api/task/edit",
		map[string]any{"id": rest, "requirements": []int{soonRetired, approved}}); code != http.StatusOK {
		t.Fatalf("keeping a link to a requirement deprecated since = %d %v", code, d)
	}
	if got := linksOf(t, dir, rest); got != fmt.Sprint([]int{approved, soonRetired}) {
		t.Errorf("task %d implements %s", rest, got)
	}
	if code, _ := rawJSON(t, ts, http.MethodPost, "/api/task/edit", map[string]any{"id": 1, "requirements": []int{soonRetired}}); code != http.StatusBadRequest {
		t.Errorf("a new link to a requirement deprecated since = %d, want 400", code)
	}
}

// TestRequirementsKnowTheTasksThatImplementThem: a requirement's list entry
// and details name the tasks that implement it, its "Add a task" actions link
// the task they add, and deleting it takes it off every task.
func TestRequirementsKnowTheTasksThatImplementThem(t *testing.T) {
	dir := setupProjectDir(t, "links", modelCallTasks())
	ts := modelCallHub(t, dir, newModelStub(t))
	req := addRequirementVia(t, ts, map[string]any{"title": "Builds", "tests": []map[string]any{{"command": "go build ./..."}}})
	other := addRequirementVia(t, ts, map[string]any{"title": "Other"})
	retired := addRequirementVia(t, ts, map[string]any{"title": "Retired", "status": "deprecated"})
	if code, d := rawJSON(t, ts, http.MethodPost, "/api/task/edit", map[string]any{"id": 2, "requirements": []int{req, other}}); code != http.StatusOK {
		t.Fatalf("link = %d %v", code, d)
	}

	code, d := rawJSON(t, ts, http.MethodPost, fmt.Sprintf("/api/requirements/%d/task", req), map[string]any{"kind": "fix"})
	if code != http.StatusOK {
		t.Fatalf("add a task to restore it = %d %v", code, d)
	}
	fix := taskIDOf(t, d)
	if got := linksOf(t, dir, fix); got != fmt.Sprint([]int{req}) {
		t.Errorf("the task added to restore R-%d implements %s", req, got)
	}
	code, d = rawJSON(t, ts, http.MethodPost, fmt.Sprintf("/api/requirements/%d/task", other), map[string]any{"kind": "test"})
	if code != http.StatusOK || linksOf(t, dir, taskIDOf(t, d)) != fmt.Sprint([]int{other}) {
		t.Errorf("add a task to test it = %d %v", code, d)
	}
	if code, d := rawJSON(t, ts, http.MethodPost, fmt.Sprintf("/api/requirements/%d/task", retired), map[string]any{"kind": "fix"}); code != http.StatusBadRequest {
		t.Errorf("a task to restore a deprecated requirement = %d %v, want 400", code, d)
	}

	code, d = rawJSON(t, ts, http.MethodGet, "/api/requirements", nil)
	if code != http.StatusOK {
		t.Fatalf("list = %d %v", code, d)
	}
	for _, r := range d["requirements"].([]any) {
		v := r.(map[string]any)
		if int(v["id"].(float64)) == req && fmt.Sprint(v["tasks"]) != fmt.Sprint([]any{2.0, float64(fix)}) {
			t.Errorf("R-%d's list entry names tasks %v, want [2 %d]", req, v["tasks"], fix)
		}
	}
	code, d = rawJSON(t, ts, http.MethodGet, fmt.Sprintf("/api/requirements/%d/checks", req), nil)
	tasks, _ := d["tasks"].([]any)
	if code != http.StatusOK || len(tasks) != 2 {
		t.Fatalf("details = %d %v", code, d)
	}
	if first := tasks[0].(map[string]any); first["id"] != 2.0 || first["title"] != "Ship it" || first["status"] != "pending" {
		t.Errorf("the details' first task is %v", first)
	}
	if code, d := rawJSON(t, ts, http.MethodGet, fmt.Sprintf("/api/requirements/%d/checks", retired), nil); code != http.StatusOK ||
		fmt.Sprint(d["tasks"]) != "[]" {
		t.Errorf("a requirement no task implements: %d %v, want tasks: []", code, d)
	}

	if code, d := rawJSON(t, ts, http.MethodDelete, fmt.Sprintf("/api/requirements/%d", req), nil); code != http.StatusOK {
		t.Fatalf("delete = %d %v", code, d)
	}
	if got := linksOf(t, dir, 2); got != fmt.Sprint([]int{other}) {
		t.Errorf("after deleting R-%d, task 2 implements %s", req, got)
	}
	if got := linksOf(t, dir, fix); got != "[]" {
		t.Errorf("after deleting R-%d, task %d implements %s", req, fix, got)
	}
}

// TestALinkNeverCrossesProjects is the cross-tenant case. Requirement ids are
// each project's own, so a task can only ever be linked to a requirement of
// its own project: the id of a requirement only another tenant's project has
// is refused, and a requirement's details never show another project's tasks
// — even a task that implements a requirement with the same id there.
func TestALinkNeverCrossesProjects(t *testing.T) {
	f := newMemberFixture(t, false)
	bobs := setupProjectDir(t, "bob's goal", []*pm.Task{{ID: 1, Title: "bob's task", Status: pm.TaskPending}})
	registerOwned(t, bobs, bobEmail)

	aliceIdx, bobIdx := f.idx(t, f.alice, f.project), f.idx(t, f.bob, bobs)
	if aliceIdx < 0 || bobIdx < 0 {
		t.Fatalf("each owner should see their project: alice %d, bob %d", aliceIdx, bobIdx)
	}
	if f.idx(t, f.bob, f.project) >= 0 || f.idx(t, f.alice, bobs) >= 0 {
		t.Fatal("test assumption broken: a tenant sees the other's project")
	}
	at := func(i int, path string) string { return path + "?project_idx=" + itoa(i) }
	mustAdd := func(c *http.Client, i int, title string) int {
		t.Helper()
		code, d := f.call(t, c, http.MethodPost, at(i, "/api/requirements"), map[string]any{"title": title})
		if code != http.StatusOK {
			t.Fatalf("add %q = %d %v", title, code, d)
		}
		return int(d["requirement"].(map[string]any)["id"].(float64))
	}
	alicesOnly := mustAdd(f.alice, aliceIdx, "alice's only requirement")
	bobsFirst := mustAdd(f.bob, bobIdx, "bob's first")
	bobsSecond := mustAdd(f.bob, bobIdx, "bob's second")
	if alicesOnly != bobsFirst || bobsSecond == alicesOnly {
		t.Fatalf("test assumption broken: ids %d, %d, %d", alicesOnly, bobsFirst, bobsSecond)
	}

	// Bob links his task to both of his requirements.
	if code, d := f.call(t, f.bob, http.MethodPost, at(bobIdx, "/api/task/edit"),
		map[string]any{"id": 1, "requirements": []int{bobsFirst, bobsSecond}}); code != http.StatusOK {
		t.Fatalf("bob links his own task = %d %v", code, d)
	}
	// The id of bob's second requirement names nothing in alice's project.
	code, d := f.call(t, f.alice, http.MethodPost, at(aliceIdx, "/api/task/add"),
		map[string]any{"title": "reaches across", "requirements": []int{bobsSecond}})
	if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(d["error"]), "not a requirement of this project") {
		t.Fatalf("alice links bob's requirement = %d %v, want 400", code, d)
	}
	// Bob cannot address alice's project at all: past his own list is nothing.
	_, paths := f.projects(t, f.bob)
	if code, _ := f.call(t, f.bob, http.MethodPost, at(len(paths), "/api/task/add"),
		map[string]any{"title": "x", "requirements": []int{alicesOnly}}); code < 400 {
		t.Errorf("bob added a task past his own project list: %d", code)
	}

	// Alice links a task to her requirement, which has bob's first's id.
	code, d = f.call(t, f.alice, http.MethodPost, at(aliceIdx, "/api/task/add"),
		map[string]any{"title": "alice's task", "requirements": []int{alicesOnly}})
	if code != http.StatusOK {
		t.Fatalf("alice links her own requirement = %d %v", code, d)
	}
	alicesTask := taskIDOf(t, d)

	// Each requirement's details show its own project's tasks and no other's.
	_, d = f.call(t, f.alice, http.MethodGet, at(aliceIdx, fmt.Sprintf("/api/requirements/%d/checks", alicesOnly)), nil)
	if tasks, _ := d["tasks"].([]any); len(tasks) != 1 || tasks[0].(map[string]any)["title"] != "alice's task" ||
		int(tasks[0].(map[string]any)["id"].(float64)) != alicesTask {
		t.Errorf("alice's R-%d lists %v", alicesOnly, d["tasks"])
	}
	_, d = f.call(t, f.bob, http.MethodGet, at(bobIdx, fmt.Sprintf("/api/requirements/%d/checks", bobsFirst)), nil)
	if tasks, _ := d["tasks"].([]any); len(tasks) != 1 || tasks[0].(map[string]any)["title"] != "bob's task" {
		t.Errorf("bob's R-%d lists %v", bobsFirst, d["tasks"])
	}
	if got := linksOf(t, bobs, 1); got != fmt.Sprint([]int{bobsFirst, bobsSecond}) {
		t.Errorf("bob's task implements %s", got)
	}
}

// TestDeletingARequirementTellsOpenDashboards: the deletion changes tasks, so
// the plan's change is pushed as well as the requirements', and a task card
// drops the chip without a reload.
func TestDeletingARequirementTellsOpenDashboards(t *testing.T) {
	dir := setupProjectDir(t, "push", modelCallTasks())
	srv := New(dir, 0, "")
	srv.RPS, srv.Burst = 1e6, 1e6
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	id := addRequirementVia(t, ts, map[string]any{"title": "Gone soon"})
	if code, d := rawJSON(t, ts, http.MethodPost, "/api/task/edit", map[string]any{"id": 1, "requirements": []int{id}}); code != http.StatusOK {
		t.Fatalf("link = %d %v", code, d)
	}
	seedDiffCache(t, srv, dir)
	hc := attachHubClient(srv, dir)
	if code, d := rawJSON(t, ts, http.MethodDelete, fmt.Sprintf("/api/requirements/%d", id), nil); code != http.StatusOK {
		t.Fatalf("delete = %d %v", code, d)
	}
	var diffs []string
	for _, m := range drainAll(hc) {
		if m.Type == "state_diff" {
			diffs = append(diffs, string(m.Data))
		}
	}
	if len(diffs) != 1 || !strings.Contains(diffs[0], `"requirements":null`) || !strings.Contains(diffs[0], `"id":1`) {
		t.Errorf("the deletion pushed %q, want one state_diff clearing task 1's requirements", diffs)
	}
}
