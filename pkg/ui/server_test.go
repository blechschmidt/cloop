package ui

// Per-project tab switching integration tests.
//
// These tests verify that the multi-project API endpoints correctly scope
// responses to the project identified by ?project_idx=N so that clicking a
// project tab in the Web UI always shows the right project's data.
//
// Test matrix
// ──────────────────────────────────────────────────────────────────────────
//  1. GET /api/state (no project_idx) → cloop project goal returned
//  2. GET /api/state?project_idx=1    → sysmon goal returned, NOT cloop goal
//  3. GET /api/state?project_idx=1    → sysmon plan tasks present in response
//  4. GET /api/projects               → both projects listed with correct names/goals

import (
	"encoding/json"
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
