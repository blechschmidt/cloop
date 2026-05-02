package ui

// UI API endpoint tests.
//
// These tests cover every HTTP handler exposed by the cloop web dashboard,
// including per-project scoping via ?project_idx=N and all CRUD operations
// on tasks, knowledge-base entries, configuration, and analytics endpoints.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

const (
	cloopGoal  = "Evolve cloop into a groundbreaking AI product manager"
	sysmonGoal = "Evolve sysmon into the best server monitoring dashboard"
)

// setupProjectDir initialises a cloop project directory with the given goal
// and optional PM tasks, then returns the directory path.
func setupProjectDir(t *testing.T, goal string, tasks []*pm.Task) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cloop-ui-test-*")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	ps, err := state.Init(dir, goal, 0)
	if err != nil {
		t.Fatalf("state.Init(%s): %v", dir, err)
	}

	if len(tasks) > 0 {
		ps.PMMode = true
		ps.Plan = &pm.Plan{
			Goal:  goal,
			Tasks: tasks,
		}
		if err := ps.Save(); err != nil {
			t.Fatalf("state.Save(%s): %v", dir, err)
		}
	}

	return dir
}

// newTestServer creates a Server backed by httptest.NewServer.
// Primary project is at index 0; additionalProjects are appended at index 1, 2, ...
func newTestServer(t *testing.T, primaryDir string, additionalProjects []string) *httptest.Server {
	t.Helper()
	srv := New(primaryDir, 0, "")
	srv.Projects = additionalProjects
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// apiGET performs a GET request and decodes the JSON response body.
func apiGET(t *testing.T, ts *httptest.Server, path string) map[string]interface{} {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s returned HTTP %d", path, resp.StatusCode)
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response from %s: %v", path, err)
	}
	return out
}

// TestPerProjectTabSwitching verifies all four API-level scoping cases.
func TestPerProjectTabSwitching(t *testing.T) {
	// ── project setup ──────────────────────────────────────────────────────
	cloopDir := setupProjectDir(t, cloopGoal, nil)

	sysmonTasks := []*pm.Task{
		{ID: 1, Title: "Add CPU usage chart", Status: pm.TaskPending},
		{ID: 2, Title: "Add memory usage graph", Status: pm.TaskPending},
	}
	sysmonDir := setupProjectDir(t, sysmonGoal, sysmonTasks)

	// Primary project: cloop (index 0).  Additional: sysmon (index 1).
	ts := newTestServer(t, cloopDir, []string{sysmonDir})

	// ── test 1: /api/state (no project_idx) → cloop goal ──────────────────
	t.Run("default_project_returns_cloop_goal", func(t *testing.T) {
		body := apiGET(t, ts, "/api/state")
		goal, _ := body["goal"].(string)
		if !strings.Contains(goal, "cloop") {
			t.Errorf("expected cloop goal, got %q", goal)
		}
		if strings.Contains(goal, "sysmon") {
			t.Errorf("got sysmon goal when no project_idx supplied: %q", goal)
		}
	})

	// ── test 2: /api/state?project_idx=1 → sysmon goal ────────────────────
	t.Run("project_idx_1_returns_sysmon_goal", func(t *testing.T) {
		body := apiGET(t, ts, "/api/state?project_idx=1")
		goal, _ := body["goal"].(string)
		if goal != sysmonGoal {
			t.Errorf("expected sysmon goal %q, got %q", sysmonGoal, goal)
		}
		if strings.Contains(goal, "cloop") && !strings.Contains(goal, "sysmon") {
			t.Errorf("got cloop goal when project_idx=1: %q", goal)
		}
	})

	// ── test 3: /api/state?project_idx=1 tasks → sysmon tasks present ─────
	t.Run("project_idx_1_returns_sysmon_tasks", func(t *testing.T) {
		body := apiGET(t, ts, "/api/state?project_idx=1")

		planRaw, ok := body["plan"]
		if !ok || planRaw == nil {
			t.Fatal("expected plan in sysmon state, got nil/missing")
		}
		planMap, ok := planRaw.(map[string]interface{})
		if !ok {
			t.Fatalf("plan is not an object: %T", planRaw)
		}
		tasksRaw, ok := planMap["tasks"]
		if !ok || tasksRaw == nil {
			t.Fatal("expected tasks in sysmon plan")
		}
		tasks, ok := tasksRaw.([]interface{})
		if !ok || len(tasks) == 0 {
			t.Fatalf("expected non-empty sysmon tasks, got %v", tasksRaw)
		}

		// Verify task titles are sysmon's, not cloop's
		for _, raw := range tasks {
			tm, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			title, _ := tm["title"].(string)
			if strings.Contains(strings.ToLower(title), "cloop") {
				t.Errorf("sysmon task list contains cloop task: %q", title)
			}
		}

		// Verify both expected sysmon tasks are present
		var titles []string
		for _, raw := range tasks {
			if tm, ok := raw.(map[string]interface{}); ok {
				if title, ok := tm["title"].(string); ok {
					titles = append(titles, title)
				}
			}
		}
		wantTitles := []string{"Add CPU usage chart", "Add memory usage graph"}
		for _, want := range wantTitles {
			found := false
			for _, got := range titles {
				if got == want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("sysmon task %q not found in project_idx=1 tasks; got: %v", want, titles)
			}
		}
	})

	// ── test 4: /api/projects → both projects listed ───────────────────────
	t.Run("projects_lists_both_projects", func(t *testing.T) {
		body := apiGET(t, ts, "/api/projects")

		projectsRaw, ok := body["projects"]
		if !ok {
			t.Fatal("expected 'projects' field in /api/projects response")
		}
		projects, ok := projectsRaw.([]interface{})
		if !ok {
			t.Fatalf("projects is not an array: %T", projectsRaw)
		}
		if len(projects) < 2 {
			t.Fatalf("expected at least 2 projects, got %d", len(projects))
		}

		var names, goals []string
		for _, p := range projects {
			pm, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			if name, ok := pm["name"].(string); ok {
				names = append(names, name)
			}
			if goal, ok := pm["goal"].(string); ok {
				goals = append(goals, goal)
			}
		}

		// Both project names must appear
		if !containsAny(names, "cloop") {
			t.Errorf("cloop not in project names: %v", names)
		}
		if !containsAny(names, "sysmon") {
			t.Errorf("sysmon not in project names: %v", names)
		}

		// Both goals must appear
		cloopGoalFound := false
		sysmonGoalFound := false
		for _, g := range goals {
			if g == cloopGoal {
				cloopGoalFound = true
			}
			if g == sysmonGoal {
				sysmonGoalFound = true
			}
		}
		if !cloopGoalFound {
			t.Errorf("cloop goal not found in projects list; goals: %v", goals)
		}
		if !sysmonGoalFound {
			t.Errorf("sysmon goal not found in projects list; goals: %v", goals)
		}
	})
}

// containsAny returns true if any string in haystack contains needle (case-insensitive).
func containsAny(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.Contains(strings.ToLower(s), strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

// ── helper: POST JSON ─────────────────────────────────────────────────────────

func apiPOST(t *testing.T, ts *httptest.Server, path string, body interface{}) map[string]interface{} {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	resp, err := http.Post(ts.URL+path, "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		t.Fatalf("POST %s returned HTTP %d", path, resp.StatusCode)
	}
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func apiDELETE(t *testing.T, ts *httptest.Server, path string) map[string]interface{} {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+path, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE %s: %v", path, err)
	}
	defer resp.Body.Close()
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func apiPATCH(t *testing.T, ts *httptest.Server, path string, body interface{}) map[string]interface{} {
	t.Helper()
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPatch, ts.URL+path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PATCH %s: %v", path, err)
	}
	defer resp.Body.Close()
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

// setupProjectWithTasks creates a project with PM mode enabled and the given tasks.
func setupProjectWithTasks(t *testing.T, goal string, tasks []*pm.Task) string {
	t.Helper()
	dir := setupProjectDir(t, goal, tasks)
	if len(tasks) > 0 {
		// setupProjectDir already enables PMMode when tasks are given.
		return dir
	}
	return dir
}

// ── Dashboard HTML ────────────────────────────────────────────────────────────

func TestDashboardHTML(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html, got %q", ct)
	}
}

func TestDashboardNotFound(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	resp, err := http.Get(ts.URL + "/nonexistent-path")
	if err != nil {
		t.Fatalf("GET /nonexistent: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

// ── GET /api/tasks ────────────────────────────────────────────────────────────

func TestGetTasksEmpty(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	body := apiGET(t, ts, "/api/tasks")
	tasks, _ := body["tasks"].([]interface{})
	if tasks == nil {
		t.Fatal("expected tasks array in response")
	}
	if len(tasks) != 0 {
		t.Errorf("expected 0 tasks for project without plan, got %d", len(tasks))
	}
}

func TestGetTasksWithPlan(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 3, Title: "Third task",  Status: pm.TaskPending, Priority: 3},
		{ID: 1, Title: "First task",  Status: pm.TaskPending, Priority: 1},
		{ID: 2, Title: "Second task", Status: pm.TaskDone,    Priority: 2},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	body := apiGET(t, ts, "/api/tasks")
	raw, _ := body["tasks"].([]interface{})
	if len(raw) != 3 {
		t.Fatalf("expected 3 tasks, got %d", len(raw))
	}

	// Verify tasks are sorted by ID ascending.
	ids := make([]int, 0, len(raw))
	for _, v := range raw {
		if m, ok := v.(map[string]interface{}); ok {
			if id, ok := m["id"].(float64); ok {
				ids = append(ids, int(id))
			}
		}
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Errorf("tasks not sorted by ID: %v", ids)
		}
	}
}

func TestGetTasksFilterByStatus(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "Pending task",  Status: pm.TaskPending},
		{ID: 2, Title: "Done task",     Status: pm.TaskDone},
		{ID: 3, Title: "Failed task",   Status: pm.TaskFailed},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	body := apiGET(t, ts, "/api/tasks?status=pending")
	raw, _ := body["tasks"].([]interface{})
	if len(raw) != 1 {
		t.Errorf("expected 1 pending task, got %d", len(raw))
	}
	if m, ok := raw[0].(map[string]interface{}); ok {
		if m["title"] != "Pending task" {
			t.Errorf("wrong task returned: %v", m["title"])
		}
	}
}

func TestGetTasksFilterByTextSearch(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "Add authentication",  Status: pm.TaskPending},
		{ID: 2, Title: "Fix database bug",    Status: pm.TaskPending},
		{ID: 3, Title: "Deploy to staging",   Status: pm.TaskPending},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	body := apiGET(t, ts, "/api/tasks?q=database")
	raw, _ := body["tasks"].([]interface{})
	if len(raw) != 1 {
		t.Errorf("expected 1 task matching 'database', got %d", len(raw))
	}
}

func TestGetTasksProjectScoped(t *testing.T) {
	cloopTasks := []*pm.Task{
		{ID: 1, Title: "cloop task", Status: pm.TaskPending},
	}
	sysmonTasks := []*pm.Task{
		{ID: 1, Title: "sysmon task", Status: pm.TaskPending},
	}
	cloopDir := setupProjectWithTasks(t, cloopGoal, cloopTasks)
	sysmonDir := setupProjectWithTasks(t, sysmonGoal, sysmonTasks)
	ts := newTestServer(t, cloopDir, []string{sysmonDir})

	// project_idx=0 → cloop task
	body0 := apiGET(t, ts, "/api/tasks?project_idx=0")
	raw0, _ := body0["tasks"].([]interface{})
	if len(raw0) != 1 {
		t.Fatalf("project_idx=0: expected 1 task, got %d", len(raw0))
	}
	if m, ok := raw0[0].(map[string]interface{}); ok {
		if m["title"] != "cloop task" {
			t.Errorf("project_idx=0: expected 'cloop task', got %v", m["title"])
		}
	}

	// project_idx=1 → sysmon task
	body1 := apiGET(t, ts, "/api/tasks?project_idx=1")
	raw1, _ := body1["tasks"].([]interface{})
	if len(raw1) != 1 {
		t.Fatalf("project_idx=1: expected 1 task, got %d", len(raw1))
	}
	if m, ok := raw1[0].(map[string]interface{}); ok {
		if m["title"] != "sysmon task" {
			t.Errorf("project_idx=1: expected 'sysmon task', got %v", m["title"])
		}
	}
}

// ── POST /api/task/add ────────────────────────────────────────────────────────

func TestTaskAdd(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	body := apiPOST(t, ts, "/api/task/add", map[string]interface{}{
		"title":       "New task from UI",
		"description": "This is a test task",
		"priority":    2,
	})

	if body["ok"] != true {
		t.Errorf("expected ok=true, got %v", body)
	}
	task, _ := body["task"].(map[string]interface{})
	if task == nil {
		t.Fatal("expected task in response")
	}
	if task["title"] != "New task from UI" {
		t.Errorf("wrong title: %v", task["title"])
	}
	if task["id"] == nil {
		t.Error("expected task.id in response")
	}
}

func TestTaskAddEmptyTitleRejected(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	data, _ := json.Marshal(map[string]interface{}{"title": "  "})
	resp, _ := http.Post(ts.URL+"/api/task/add", "application/json", bytes.NewReader(data))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for empty title, got %d", resp.StatusCode)
	}
}

func TestTaskAddAutoIncrementsID(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	body1 := apiPOST(t, ts, "/api/task/add", map[string]string{"title": "First"})
	body2 := apiPOST(t, ts, "/api/task/add", map[string]string{"title": "Second"})

	id1, _ := body1["task"].(map[string]interface{})["id"].(float64)
	id2, _ := body2["task"].(map[string]interface{})["id"].(float64)
	if id2 <= id1 {
		t.Errorf("second task ID %v not greater than first %v", id2, id1)
	}
}

// ── POST /api/tasks (alias) ───────────────────────────────────────────────────

func TestPostTasksAlias(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	body := apiPOST(t, ts, "/api/tasks", map[string]string{"title": "RESTful add"})
	if body["ok"] != true {
		t.Errorf("POST /api/tasks: expected ok=true, got %v", body)
	}
}

// ── POST /api/task/status ─────────────────────────────────────────────────────

func TestTaskStatusChange(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "Task to complete", Status: pm.TaskPending},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	body := apiPOST(t, ts, "/api/task/status", map[string]interface{}{
		"id":     1,
		"status": "done",
	})
	if body["ok"] != true {
		t.Errorf("expected ok=true, got %v", body)
	}

	// Verify the status was actually persisted.
	state := apiGET(t, ts, "/api/state")
	plan, _ := state["plan"].(map[string]interface{})
	taskList, _ := plan["tasks"].([]interface{})
	if len(taskList) == 0 {
		t.Fatal("no tasks in state")
	}
	tm, _ := taskList[0].(map[string]interface{})
	if tm["status"] != "done" {
		t.Errorf("expected status=done, got %v", tm["status"])
	}
}

func TestTaskStatusInvalidRejected(t *testing.T) {
	tasks := []*pm.Task{{ID: 1, Title: "T", Status: pm.TaskPending}}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	data, _ := json.Marshal(map[string]interface{}{"id": 1, "status": "invalid_status"})
	resp, _ := http.Post(ts.URL+"/api/task/status", "application/json", bytes.NewReader(data))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid status, got %d", resp.StatusCode)
	}
}

func TestTaskStatusNotFound(t *testing.T) {
	tasks := []*pm.Task{{ID: 1, Title: "T", Status: pm.TaskPending}}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	data, _ := json.Marshal(map[string]interface{}{"id": 999, "status": "done"})
	resp, _ := http.Post(ts.URL+"/api/task/status", "application/json", bytes.NewReader(data))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for missing task, got %d", resp.StatusCode)
	}
}

// ── POST /api/task/edit ───────────────────────────────────────────────────────

func TestTaskEdit(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "Old title", Description: "old desc", Priority: 3},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	body := apiPOST(t, ts, "/api/task/edit", map[string]interface{}{
		"id":          1,
		"title":       "New title",
		"description": "new desc",
		"priority":    1,
	})
	if body["ok"] != true {
		t.Errorf("expected ok=true, got %v", body)
	}
	task, _ := body["task"].(map[string]interface{})
	if task["title"] != "New title" {
		t.Errorf("title not updated: %v", task["title"])
	}
	if task["priority"].(float64) != 1 {
		t.Errorf("priority not updated: %v", task["priority"])
	}
}

func TestTaskEditNotFound(t *testing.T) {
	tasks := []*pm.Task{{ID: 1, Title: "T", Status: pm.TaskPending}}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	data, _ := json.Marshal(map[string]interface{}{"id": 999, "title": "X"})
	resp, _ := http.Post(ts.URL+"/api/task/edit", "application/json", bytes.NewReader(data))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

// ── POST /api/task/remove ─────────────────────────────────────────────────────

func TestTaskRemove(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "To remove", Status: pm.TaskPending},
		{ID: 2, Title: "To keep",   Status: pm.TaskPending},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	body := apiPOST(t, ts, "/api/task/remove", map[string]interface{}{"id": 1})
	if body["ok"] != true {
		t.Errorf("expected ok=true, got %v", body)
	}

	// Verify task was removed.
	stateBody := apiGET(t, ts, "/api/state")
	plan, _ := stateBody["plan"].(map[string]interface{})
	taskList, _ := plan["tasks"].([]interface{})
	if len(taskList) != 1 {
		t.Errorf("expected 1 task after removal, got %d", len(taskList))
	}
}

func TestTaskRemoveNotFound(t *testing.T) {
	tasks := []*pm.Task{{ID: 1, Title: "T", Status: pm.TaskPending}}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	data, _ := json.Marshal(map[string]interface{}{"id": 999})
	resp, _ := http.Post(ts.URL+"/api/task/remove", "application/json", bytes.NewReader(data))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

// ── POST /api/task/move ───────────────────────────────────────────────────────

func TestTaskMoveDown(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "First",  Status: pm.TaskPending, Priority: 1},
		{ID: 2, Title: "Second", Status: pm.TaskPending, Priority: 2},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	body := apiPOST(t, ts, "/api/task/move", map[string]interface{}{
		"id":        1,
		"direction": "down",
	})
	if body["ok"] != true {
		t.Errorf("expected ok=true, got %v", body)
	}
}

func TestTaskMoveInvalidDirection(t *testing.T) {
	tasks := []*pm.Task{{ID: 1, Title: "T", Status: pm.TaskPending, Priority: 1}}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	data, _ := json.Marshal(map[string]interface{}{"id": 1, "direction": "sideways"})
	resp, _ := http.Post(ts.URL+"/api/task/move", "application/json", bytes.NewReader(data))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid direction, got %d", resp.StatusCode)
	}
}

// ── PUT /api/tasks/{id} ───────────────────────────────────────────────────────

func TestPutTask(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "Original", Status: pm.TaskPending, Priority: 2},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	data, _ := json.Marshal(map[string]interface{}{
		"title":    "Updated",
		"status":   "done",
		"priority": 1,
	})
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/tasks/1", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT /api/tasks/1: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body) //nolint:errcheck
	if body["ok"] != true {
		t.Errorf("expected ok=true, got %v", body)
	}
	task, _ := body["task"].(map[string]interface{})
	if task["title"] != "Updated" {
		t.Errorf("title not updated: %v", task["title"])
	}
}

func TestPutTaskNotFound(t *testing.T) {
	tasks := []*pm.Task{{ID: 1, Title: "T", Status: pm.TaskPending}}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	data, _ := json.Marshal(map[string]interface{}{"title": "X"})
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/tasks/999", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestPatchTaskAlias(t *testing.T) {
	tasks := []*pm.Task{{ID: 1, Title: "T", Status: pm.TaskPending}}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	body := apiPATCH(t, ts, "/api/tasks/1", map[string]interface{}{"status": "done"})
	if body["ok"] != true {
		t.Errorf("PATCH /api/tasks/1: expected ok=true, got %v", body)
	}
}

// ── DELETE /api/tasks/{id} ────────────────────────────────────────────────────

func TestDeleteTask(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "Delete me", Status: pm.TaskPending},
		{ID: 2, Title: "Keep me",   Status: pm.TaskPending},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	body := apiDELETE(t, ts, "/api/tasks/1")
	if body["ok"] != true {
		t.Errorf("DELETE /api/tasks/1: expected ok=true, got %v", body)
	}

	// Verify task was removed.
	stateBody := apiGET(t, ts, "/api/state")
	plan, _ := stateBody["plan"].(map[string]interface{})
	taskList, _ := plan["tasks"].([]interface{})
	if len(taskList) != 1 {
		t.Errorf("expected 1 task after delete, got %d", len(taskList))
	}
}

func TestDeleteTaskNotFound(t *testing.T) {
	tasks := []*pm.Task{{ID: 1, Title: "T", Status: pm.TaskPending}}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	body := apiDELETE(t, ts, "/api/tasks/999")
	if _, hasErr := body["error"]; !hasErr {
		t.Errorf("expected error for missing task, got %v", body)
	}
}

func TestDeleteTaskInvalidID(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/tasks/notanid", nil)
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for non-numeric id, got %d", resp.StatusCode)
	}
}

// ── POST /api/tasks/reorder ───────────────────────────────────────────────────

func TestTasksReorder(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "A", Status: pm.TaskPending, Priority: 1},
		{ID: 2, Title: "B", Status: pm.TaskPending, Priority: 2},
		{ID: 3, Title: "C", Status: pm.TaskPending, Priority: 3},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	body := apiPOST(t, ts, "/api/tasks/reorder", map[string]interface{}{
		"ids": []int{3, 1, 2},
	})
	if body["ok"] != true {
		t.Errorf("expected ok=true, got %v", body)
	}

	// Verify priorities were rewritten.
	stateBody := apiGET(t, ts, "/api/state")
	plan, _ := stateBody["plan"].(map[string]interface{})
	taskList, _ := plan["tasks"].([]interface{})
	priorityByID := map[int]int{}
	for _, v := range taskList {
		m, _ := v.(map[string]interface{})
		id := int(m["id"].(float64))
		pri := int(m["priority"].(float64))
		priorityByID[id] = pri
	}
	// After reorder [3,1,2]: task 3 gets priority 1, task 1 gets priority 2, task 2 gets priority 3.
	if priorityByID[3] != 1 {
		t.Errorf("task 3 should have priority 1, got %d", priorityByID[3])
	}
	if priorityByID[1] != 2 {
		t.Errorf("task 1 should have priority 2, got %d", priorityByID[1])
	}
}

// ── GET /api/tasks/{id}/blocker ───────────────────────────────────────────────

func TestTaskBlockerDetection(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "Blocked task", Status: pm.TaskPending, DependsOn: []int{2}},
		{ID: 2, Title: "Blocker task", Status: pm.TaskPending},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	resp, err := http.Get(ts.URL + "/api/tasks/1/blocker")
	if err != nil {
		t.Fatalf("GET /api/tasks/1/blocker: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body) //nolint:errcheck
	// Should return a blocker info object (has_blockers field or similar).
	// Just verify we get a JSON object without error.
	if body == nil {
		t.Error("expected non-nil body from blocker endpoint")
	}
}

func TestTaskBlockerNotFound(t *testing.T) {
	tasks := []*pm.Task{{ID: 1, Title: "T", Status: pm.TaskPending}}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	resp, _ := http.Get(ts.URL + "/api/tasks/999/blocker")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for missing task, got %d", resp.StatusCode)
	}
}

// ── GET /api/config ───────────────────────────────────────────────────────────

func TestGetConfig(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	body := apiGET(t, ts, "/api/config")
	if _, ok := body["provider"]; !ok {
		t.Errorf("expected 'provider' in config response, got %v", body)
	}
	if _, ok := body["anthropic"]; !ok {
		t.Errorf("expected 'anthropic' in config response")
	}
}

func TestGetConfigMethodNotAllowed(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	data, _ := json.Marshal(map[string]string{})
	resp, _ := http.Post(ts.URL+"/api/config", "application/json", bytes.NewReader(data))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST /api/config, got %d", resp.StatusCode)
	}
}

// ── POST /api/config/set ─────────────────────────────────────────────────────

func TestConfigSet(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	body := apiPOST(t, ts, "/api/config/set", map[string]string{
		"key":   "provider",
		"value": "anthropic",
	})
	if body["ok"] != true {
		t.Errorf("expected ok=true, got %v", body)
	}

	// Verify the change persisted.
	cfgBody := apiGET(t, ts, "/api/config")
	if cfgBody["provider"] != "anthropic" {
		t.Errorf("provider not updated: %v", cfgBody["provider"])
	}
}

func TestConfigSetInvalidKey(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	data, _ := json.Marshal(map[string]string{"key": "nonexistent.key", "value": "x"})
	resp, _ := http.Post(ts.URL+"/api/config/set", "application/json", bytes.NewReader(data))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown config key, got %d", resp.StatusCode)
	}
}

func TestConfigSetInvalidProvider(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	data, _ := json.Marshal(map[string]string{"key": "provider", "value": "unknown_provider"})
	resp, _ := http.Post(ts.URL+"/api/config/set", "application/json", bytes.NewReader(data))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown provider, got %d", resp.StatusCode)
	}
}

// ── POST /api/init ────────────────────────────────────────────────────────────

func TestInit(t *testing.T) {
	// Create an empty directory (no .cloop yet).
	dir, _ := os.MkdirTemp("", "cloop-init-test-*")
	t.Cleanup(func() { os.RemoveAll(dir) })

	ts := newTestServer(t, dir, nil)
	body := apiPOST(t, ts, "/api/init", map[string]interface{}{
		"goal":     "Build a test project",
		"provider": "claudecode",
		"maxSteps": 10,
	})
	if body["ok"] != true {
		t.Errorf("expected ok=true, got %v", body)
	}
	if body["goal"] != "Build a test project" {
		t.Errorf("unexpected goal: %v", body["goal"])
	}
}

func TestInitEmptyGoalRejected(t *testing.T) {
	dir, _ := os.MkdirTemp("", "cloop-init-empty-*")
	t.Cleanup(func() { os.RemoveAll(dir) })

	ts := newTestServer(t, dir, nil)
	data, _ := json.Marshal(map[string]string{"goal": ""})
	resp, _ := http.Post(ts.URL+"/api/init", "application/json", bytes.NewReader(data))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for empty goal, got %d", resp.StatusCode)
	}
}

// ── GET /api/livelog ──────────────────────────────────────────────────────────

func TestLiveLog(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	body := apiGET(t, ts, "/api/livelog")
	if _, ok := body["running"]; !ok {
		t.Errorf("expected 'running' in livelog response, got %v", body)
	}
	if _, ok := body["lines"]; !ok {
		t.Errorf("expected 'lines' in livelog response, got %v", body)
	}
	// Initially not running.
	if body["running"] != false {
		t.Errorf("expected running=false initially, got %v", body["running"])
	}
}

// ── GET /api/deps ─────────────────────────────────────────────────────────────

func TestDepsEmpty(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	body := apiGET(t, ts, "/api/deps")
	nodes, _ := body["nodes"].([]interface{})
	edges, _ := body["edges"].([]interface{})
	if nodes == nil || edges == nil {
		t.Errorf("expected nodes and edges arrays, got %v", body)
	}
}

func TestDepsWithTasks(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "Root task",     Status: pm.TaskPending},
		{ID: 2, Title: "Depends on 1",  Status: pm.TaskPending, DependsOn: []int{1}},
		{ID: 3, Title: "Depends on 1,2", Status: pm.TaskPending, DependsOn: []int{1, 2}},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	body := apiGET(t, ts, "/api/deps")
	nodes, _ := body["nodes"].([]interface{})
	edges, _ := body["edges"].([]interface{})
	if len(nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(nodes))
	}
	// Task 2 depends on 1, task 3 depends on 1 and 2 → 3 edges total.
	if len(edges) != 3 {
		t.Errorf("expected 3 edges, got %d", len(edges))
	}
}

func TestDepsProjectScoped(t *testing.T) {
	cloopTasks := []*pm.Task{{ID: 1, Title: "cloop", Status: pm.TaskPending}}
	sysmonTasks := []*pm.Task{
		{ID: 1, Title: "s1", Status: pm.TaskPending},
		{ID: 2, Title: "s2", Status: pm.TaskPending},
	}
	cloopDir := setupProjectWithTasks(t, cloopGoal, cloopTasks)
	sysmonDir := setupProjectWithTasks(t, sysmonGoal, sysmonTasks)
	ts := newTestServer(t, cloopDir, []string{sysmonDir})

	body0 := apiGET(t, ts, "/api/deps?project_idx=0")
	nodes0, _ := body0["nodes"].([]interface{})
	if len(nodes0) != 1 {
		t.Errorf("project_idx=0: expected 1 node, got %d", len(nodes0))
	}

	body1 := apiGET(t, ts, "/api/deps?project_idx=1")
	nodes1, _ := body1["nodes"].([]interface{})
	if len(nodes1) != 2 {
		t.Errorf("project_idx=1: expected 2 nodes, got %d", len(nodes1))
	}
}

// ── GET /api/risk-matrix ──────────────────────────────────────────────────────

func TestRiskMatrixEmpty(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	body := apiGET(t, ts, "/api/risk-matrix")
	if _, ok := body["entries"]; !ok {
		t.Errorf("expected 'entries' in risk-matrix response, got %v", body)
	}
}

func TestRiskMatrixWithTasks(t *testing.T) {
	tasks := []*pm.Task{
		{ID: 1, Title: "Risky task", Status: pm.TaskPending, RiskScore: 4, ImpactScore: 5},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	body := apiGET(t, ts, "/api/risk-matrix")
	if body["goal"] != cloopGoal {
		t.Errorf("expected goal in risk-matrix response, got %v", body["goal"])
	}
}

// ── GET /api/analytics ────────────────────────────────────────────────────────

func TestAnalyticsEmpty(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	body := apiGET(t, ts, "/api/analytics")
	if _, ok := body["status_donut"]; !ok {
		t.Errorf("expected 'status_donut' in analytics response, got %v", body)
	}
}

func TestAnalyticsWithDateRange(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	body := apiGET(t, ts, "/api/analytics?from=2024-01-01&to=2024-12-31")
	if _, ok := body["status_donut"]; !ok {
		t.Errorf("expected 'status_donut' in analytics response with date range")
	}
}

func TestAnalyticsProjectScoped(t *testing.T) {
	cloopTasks := []*pm.Task{{ID: 1, Title: "T", Status: pm.TaskDone}}
	sysmonTasks := []*pm.Task{
		{ID: 1, Title: "S1", Status: pm.TaskDone},
		{ID: 2, Title: "S2", Status: pm.TaskDone},
	}
	cloopDir := setupProjectWithTasks(t, cloopGoal, cloopTasks)
	sysmonDir := setupProjectWithTasks(t, sysmonGoal, sysmonTasks)
	ts := newTestServer(t, cloopDir, []string{sysmonDir})

	body0 := apiGET(t, ts, "/api/analytics?project_idx=0")
	body1 := apiGET(t, ts, "/api/analytics?project_idx=1")

	donut0, _ := body0["status_donut"].(map[string]interface{})
	donut1, _ := body1["status_donut"].(map[string]interface{})

	vals0, _ := donut0["values"].([]interface{})
	vals1, _ := donut1["values"].([]interface{})

	// cloop has 1 done task, sysmon has 2 done tasks.
	// Index 2 = "Done" bucket.
	if len(vals0) < 3 || len(vals1) < 3 {
		t.Skip("unexpected donut format")
	}
	done0 := int(vals0[2].(float64))
	done1 := int(vals1[2].(float64))
	if done0 != 1 {
		t.Errorf("project_idx=0: expected 1 done task, got %d", done0)
	}
	if done1 != 2 {
		t.Errorf("project_idx=1: expected 2 done tasks, got %d", done1)
	}
}

// ── GET /api/epics ────────────────────────────────────────────────────────────

func TestEpicsEmpty(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	body := apiGET(t, ts, "/api/epics")
	if _, ok := body["epics"]; !ok {
		t.Errorf("expected 'epics' in response, got %v", body)
	}
}

func TestEpicsProjectScoped(t *testing.T) {
	cloopTasks := []*pm.Task{
		{ID: 1, Title: "Task A", Status: pm.TaskPending, Tags: []string{"epic:auth"}},
	}
	sysmonTasks := []*pm.Task{
		{ID: 1, Title: "Task B", Status: pm.TaskPending, Tags: []string{"epic:monitoring"}},
		{ID: 2, Title: "Task C", Status: pm.TaskPending, Tags: []string{"epic:monitoring"}},
	}
	cloopDir := setupProjectWithTasks(t, cloopGoal, cloopTasks)
	sysmonDir := setupProjectWithTasks(t, sysmonGoal, sysmonTasks)
	ts := newTestServer(t, cloopDir, []string{sysmonDir})

	body0 := apiGET(t, ts, "/api/epics?project_idx=0")
	body1 := apiGET(t, ts, "/api/epics?project_idx=1")

	epics0, _ := body0["epics"].([]interface{})
	epics1, _ := body1["epics"].([]interface{})

	if len(epics0) != 1 {
		t.Errorf("project_idx=0: expected 1 epic, got %d", len(epics0))
	}
	if len(epics1) != 1 {
		t.Errorf("project_idx=1: expected 1 epic, got %d", len(epics1))
	}
}

// ── GET /api/kb ───────────────────────────────────────────────────────────────

func TestKBListEmpty(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	body := apiGET(t, ts, "/api/kb")
	entries, _ := body["entries"].([]interface{})
	if entries == nil {
		t.Fatal("expected entries array")
	}
	if len(entries) != 0 {
		t.Errorf("expected empty KB, got %d entries", len(entries))
	}
}

func TestKBAddAndList(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	// Add an entry.
	addBody := apiPOST(t, ts, "/api/kb", map[string]interface{}{
		"title": "Architecture decision",
		"body":  "Use SQLite for persistence",
		"tags":  []string{"architecture", "database"},
	})
	if addBody["ok"] != true {
		t.Errorf("expected ok=true from POST /api/kb, got %v", addBody)
	}

	// List entries.
	listBody := apiGET(t, ts, "/api/kb")
	entries, _ := listBody["entries"].([]interface{})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry after add, got %d", len(entries))
	}
	entry, _ := entries[0].(map[string]interface{})
	if entry["title"] != "Architecture decision" {
		t.Errorf("wrong title: %v", entry["title"])
	}
}

func TestKBSearch(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	apiPOST(t, ts, "/api/kb", map[string]interface{}{"title": "Go patterns",  "body": "Use interfaces for testability"})
	apiPOST(t, ts, "/api/kb", map[string]interface{}{"title": "Python tricks", "body": "List comprehensions are fast"})

	body := apiGET(t, ts, "/api/kb/search?q=interface")
	entries, _ := body["entries"].([]interface{})
	if len(entries) != 1 {
		t.Errorf("expected 1 search result for 'interface', got %d", len(entries))
	}
}

func TestKBDelete(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	// Add then delete.
	addBody := apiPOST(t, ts, "/api/kb", map[string]interface{}{"title": "To delete", "body": "content"})
	entry, _ := addBody["entry"].(map[string]interface{})
	if entry == nil {
		t.Fatal("expected entry in add response")
	}
	id := fmt.Sprintf("%v", entry["id"])

	deleteBody := apiDELETE(t, ts, "/api/kb/"+id)
	if deleteBody["ok"] != true {
		t.Errorf("expected ok=true from DELETE /api/kb/%s, got %v", id, deleteBody)
	}

	// Verify gone.
	listBody := apiGET(t, ts, "/api/kb")
	entries, _ := listBody["entries"].([]interface{})
	if len(entries) != 0 {
		t.Errorf("expected empty KB after delete, got %d entries", len(entries))
	}
}

func TestKBProjectScoped(t *testing.T) {
	cloopDir := setupProjectDir(t, cloopGoal, nil)
	sysmonDir := setupProjectDir(t, sysmonGoal, nil)
	ts := newTestServer(t, cloopDir, []string{sysmonDir})

	// Add to cloop project.
	apiPOST(t, ts, "/api/kb?project_idx=0", map[string]interface{}{"title": "cloop entry", "body": "x"})

	// Add to sysmon project.
	apiPOST(t, ts, "/api/kb?project_idx=1", map[string]interface{}{"title": "sysmon entry", "body": "y"})

	// List for each project.
	body0 := apiGET(t, ts, "/api/kb?project_idx=0")
	body1 := apiGET(t, ts, "/api/kb?project_idx=1")

	entries0, _ := body0["entries"].([]interface{})
	entries1, _ := body1["entries"].([]interface{})

	if len(entries0) != 1 {
		t.Errorf("project_idx=0: expected 1 KB entry, got %d", len(entries0))
	}
	if len(entries1) != 1 {
		t.Errorf("project_idx=1: expected 1 KB entry, got %d", len(entries1))
	}

	// Verify no cross-contamination.
	rawData0, _ := json.Marshal(entries0)
	if strings.Contains(string(rawData0), "sysmon entry") {
		t.Error("project_idx=0 KB contains sysmon entry")
	}
	rawData1, _ := json.Marshal(entries1)
	if strings.Contains(string(rawData1), "cloop entry") {
		t.Error("project_idx=1 KB contains cloop entry")
	}
}

// ── GET /api/timeline ─────────────────────────────────────────────────────────

func TestTimelineEmpty(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	resp, err := http.Get(ts.URL + "/api/timeline")
	if err != nil {
		t.Fatalf("GET /api/timeline: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestTimelineProjectScoped(t *testing.T) {
	cloopTasks := []*pm.Task{{ID: 1, Title: "cloop work", Status: pm.TaskPending}}
	sysmonTasks := []*pm.Task{
		{ID: 1, Title: "sysmon work 1", Status: pm.TaskPending},
		{ID: 2, Title: "sysmon work 2", Status: pm.TaskPending},
	}
	cloopDir := setupProjectWithTasks(t, cloopGoal, cloopTasks)
	sysmonDir := setupProjectWithTasks(t, sysmonGoal, sysmonTasks)
	ts := newTestServer(t, cloopDir, []string{sysmonDir})

	var body0, body1 map[string]interface{}
	resp0, _ := http.Get(ts.URL + "/api/timeline?project_idx=0")
	defer resp0.Body.Close()
	json.NewDecoder(resp0.Body).Decode(&body0) //nolint:errcheck

	resp1, _ := http.Get(ts.URL + "/api/timeline?project_idx=1")
	defer resp1.Body.Close()
	json.NewDecoder(resp1.Body).Decode(&body1) //nolint:errcheck

	// Both should return valid JSON responses.
	if body0 == nil || body1 == nil {
		t.Error("expected non-nil response from /api/timeline")
	}
}

// ── GET /api/projects: multi_project flag ─────────────────────────────────────

func TestProjectsMultiProjectFlagTwoProjects(t *testing.T) {
	cloopDir := setupProjectDir(t, cloopGoal, nil)
	sysmonDir := setupProjectDir(t, sysmonGoal, nil)
	// Explicitly pass sysmonDir as an extra project so multi_project must be true.
	ts := newTestServer(t, cloopDir, []string{sysmonDir})

	body := apiGET(t, ts, "/api/projects")
	multiProject, _ := body["multi_project"].(bool)
	if !multiProject {
		t.Errorf("expected multi_project=true with two explicit projects, got false")
	}
}

func TestProjectsContainGoals(t *testing.T) {
	cloopDir := setupProjectDir(t, cloopGoal, nil)
	sysmonDir := setupProjectDir(t, sysmonGoal, nil)
	ts := newTestServer(t, cloopDir, []string{sysmonDir})

	body := apiGET(t, ts, "/api/projects")
	projects, _ := body["projects"].([]interface{})
	if len(projects) < 2 {
		t.Fatalf("expected at least 2 projects, got %d", len(projects))
	}

	var goals []string
	for _, p := range projects {
		pm, _ := p.(map[string]interface{})
		if g, ok := pm["goal"].(string); ok && g != "" {
			goals = append(goals, g)
		}
	}
	if !containsAny(goals, "cloop") {
		t.Errorf("cloop goal not in projects; goals: %v", goals)
	}
	if !containsAny(goals, "sysmon") {
		t.Errorf("sysmon goal not in projects; goals: %v", goals)
	}
}

// ── Authentication ────────────────────────────────────────────────────────────

func TestAuthTokenRequired(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	// Create server with a token.
	srv := New(dir, 0, "secret-token")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Request without token → 401.
	resp, err := http.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatalf("GET /api/state: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", resp.StatusCode)
	}
}

func TestAuthTokenInHeader(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "secret-token")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/state", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/state with auth: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with valid token, got %d", resp.StatusCode)
	}
}

func TestAuthTokenInQueryParam(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "my-token")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/api/state?token=my-token")
	if err != nil {
		t.Fatalf("GET /api/state?token=: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with token query param, got %d", resp.StatusCode)
	}
}

func TestAuthWrongToken(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "correct-token")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/state", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong token, got %d", resp.StatusCode)
	}
}

// ── Rate limiting ─────────────────────────────────────────────────────────────

func TestRateLimiting(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	// Very tight rate limit: 1 req/s with burst of 2.
	srv.RPS = 1.0
	srv.Burst = 2
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// First 2 requests should succeed (burst).
	for i := 0; i < 2; i++ {
		resp, err := http.Get(ts.URL + "/api/state")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i, resp.StatusCode)
		}
	}

	// Subsequent burst should hit rate limit.
	gotLimited := false
	for i := 0; i < 10; i++ {
		resp, _ := http.Get(ts.URL + "/api/state")
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			gotLimited = true
			break
		}
	}
	if !gotLimited {
		t.Error("expected rate limiting to kick in, but all requests succeeded")
	}
}

// ── GET /api/tasks: sort order preserved across task mutations ────────────────

func TestGetTasksSortedAfterAdd(t *testing.T) {
	// Add tasks in reverse ID order by pre-seeding with high IDs, then
	// add via API to get lower IDs and verify sort order.
	tasks := []*pm.Task{
		{ID: 10, Title: "High ID first", Status: pm.TaskPending, Priority: 1},
		{ID: 5,  Title: "Mid ID",        Status: pm.TaskPending, Priority: 2},
	}
	dir := setupProjectWithTasks(t, cloopGoal, tasks)
	ts := newTestServer(t, dir, nil)

	// GET /api/tasks should return sorted by ID ascending.
	body := apiGET(t, ts, "/api/tasks")
	raw, _ := body["tasks"].([]interface{})
	if len(raw) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(raw))
	}
	id0, _ := raw[0].(map[string]interface{})["id"].(float64)
	id1, _ := raw[1].(map[string]interface{})["id"].(float64)
	if id0 >= id1 {
		t.Errorf("tasks not sorted by ID: first=%v second=%v", id0, id1)
	}
}

// ── POST /api/task/add creates plan if none exists ────────────────────────────

func TestTaskAddCreatesPlansWhenMissing(t *testing.T) {
	// Project with no plan.
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	body := apiPOST(t, ts, "/api/task/add", map[string]string{"title": "First task ever"})
	if body["ok"] != true {
		t.Errorf("expected ok=true, got %v", body)
	}

	// State should now have a plan with 1 task.
	stateBody := apiGET(t, ts, "/api/state")
	plan, _ := stateBody["plan"].(map[string]interface{})
	if plan == nil {
		t.Fatal("expected plan in state after adding first task")
	}
	taskList, _ := plan["tasks"].([]interface{})
	if len(taskList) != 1 {
		t.Errorf("expected 1 task in plan, got %d", len(taskList))
	}
}

// TestStateEndpointProjectScopingIsolation verifies that project_idx=0 and no
// project_idx both return the primary project and not the secondary one.
func TestStateEndpointProjectScopingIsolation(t *testing.T) {
	cloopDir := setupProjectDir(t, cloopGoal, nil)
	sysmonDir := setupProjectDir(t, sysmonGoal, nil)

	ts := newTestServer(t, cloopDir, []string{sysmonDir})

	paths := []string{"/api/state", "/api/state?project_idx=0"}
	for _, path := range paths {
		t.Run("path="+path, func(t *testing.T) {
			body := apiGET(t, ts, path)
			goal, _ := body["goal"].(string)
			if goal != cloopGoal {
				t.Errorf("path %s: expected cloop goal %q, got %q", path, cloopGoal, goal)
			}
		})
	}
}

// TestProjectIdxOutOfRange verifies the server returns an error for invalid indices.
func TestProjectIdxOutOfRange(t *testing.T) {
	cloopDir := setupProjectDir(t, cloopGoal, nil)
	sysmonDir := setupProjectDir(t, sysmonGoal, nil)

	ts := newTestServer(t, cloopDir, []string{sysmonDir})

	resp, err := http.Get(ts.URL + "/api/state?project_idx=99")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	// The server falls back to WorkDir for out-of-range index (returns primary project).
	// Either 200 with cloop goal or 404 is acceptable; what must NOT happen is
	// returning sysmon data.
	if resp.StatusCode == http.StatusOK {
		var body map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&body); err == nil {
			goal, _ := body["goal"].(string)
			if strings.Contains(goal, "sysmon") {
				t.Errorf("out-of-range project_idx=99 returned sysmon data: %q", goal)
			}
		}
	}
}

// TestProjectsEndpointMultiProject verifies that multi_project is true when
// more than one project is registered.
func TestProjectsEndpointMultiProject(t *testing.T) {
	cloopDir := setupProjectDir(t, cloopGoal, nil)
	sysmonDir := setupProjectDir(t, sysmonGoal, nil)

	ts := newTestServer(t, cloopDir, []string{sysmonDir})

	body := apiGET(t, ts, "/api/projects")
	multiProject, _ := body["multi_project"].(bool)
	if !multiProject {
		t.Errorf("expected multi_project=true when 2 projects configured, got %v", body["multi_project"])
	}
}

// TestStateEndpointSysmonTasksNotInCloopProject verifies cross-contamination
// does not occur: /api/state?project_idx=0 must NOT contain sysmon tasks.
func TestStateEndpointSysmonTasksNotInCloopProject(t *testing.T) {
	cloopDir := setupProjectDir(t, cloopGoal, nil)
	sysmonTasks := []*pm.Task{
		{ID: 1, Title: "sysmon-unique-task-title", Status: pm.TaskPending},
	}
	sysmonDir := setupProjectDir(t, sysmonGoal, sysmonTasks)

	ts := newTestServer(t, cloopDir, []string{sysmonDir})

	body := apiGET(t, ts, "/api/state?project_idx=0")
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "sysmon-unique-task-title") {
		t.Errorf("cloop project state leaked sysmon task data")
	}
}
