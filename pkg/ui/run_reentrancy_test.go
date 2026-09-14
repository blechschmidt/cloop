package ui

// Starting a run on a project that is already running (Task 20253).
//
// Nothing downstream deduplicates: two harnesses in one working directory both
// schedule from the same plan, so they race for the same task and each
// overwrites the other's status writes. Neither run handler used to ask, which
// was survivable while one Run button existed on one page and the page watched
// run_state. Start now also sits on the Tasks tab, so there are three views
// that can be looking at a stale flag — plus a run somebody started from the
// CLI, which no button ever saw at all.
//
// These tests exercise only the refusal. A POST that is *accepted* reaches a
// real executor and poisons process-global executor state for the whole
// package (see workspace_test.go), so the negative control below proves the
// guard stayed out of the way by looking at which 409 came back rather than by
// letting a harness start.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newRunGuardServer returns a live server plus the Server behind it, which the
// httptest-only helper does not expose and these tests need in order to mark a
// project as running without starting anything.
func newRunGuardServer(t *testing.T, dir string) (*httptest.Server, *Server) {
	t.Helper()
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, srv
}

// decodeRunRefusal reads the JSON body of a refused run.
func decodeRunRefusal(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode refusal body: %v", err)
	}
	return body
}

// TestRun_RefusesASecondHarness is the guard itself: /api/run must not
// dispatch onto a project that is already executing.
func TestRun_RefusesASecondHarness(t *testing.T) {
	dir := setupProjectDir(t, "run reentrancy", nil)
	ts, srv := newRunGuardServer(t, dir)

	// Mark the project running the way a live dispatch does, without one.
	srv.liveLogStartRun(dir)
	if !srv.projectExecuting(dir) {
		t.Fatal("fixture did not take: the project does not read as executing, " +
			"so this test would pass for the wrong reason")
	}

	resp, err := http.Post(ts.URL+"/api/run", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST /api/run: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("POST /api/run on a running project = HTTP %d, want 409 — anything "+
			"2xx started a second harness that will race the first for every task",
			resp.StatusCode)
	}
	body := decodeRunRefusal(t, resp)
	if msg, _ := body["error"].(string); !strings.Contains(msg, "already in progress") {
		t.Errorf("refusal says %q, want it to name the conflict", msg)
	}
	// The flag the client needs in order to correct the button it just proved
	// wrong; without it a stale tab keeps offering Start.
	if running, _ := body["running"].(bool); !running {
		t.Errorf("refusal body = %v, want running:true so the client can flip to Stop", body)
	}
}

// TestProjectRun_RefusesASecondHarness covers the Projects grid's own endpoint.
// One guarded path and one unguarded path is no guard at all — the grid's Run
// button reads the same run flag and goes just as stale.
func TestProjectRun_RefusesASecondHarness(t *testing.T) {
	dir := setupProjectDir(t, "project run reentrancy", nil)
	ts, srv := newRunGuardServer(t, dir)

	srv.liveLogStartRun(dir)
	if !srv.projectExecuting(dir) {
		t.Fatal("fixture did not take: the project does not read as executing")
	}

	resp, err := http.Post(ts.URL+"/api/projects/0/run", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST /api/projects/0/run: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("POST /api/projects/0/run on a running project = HTTP %d, want 409", resp.StatusCode)
	}
	body := decodeRunRefusal(t, resp)
	if msg, _ := body["error"].(string); !strings.Contains(msg, "already in progress") {
		t.Errorf("refusal says %q, want it to name the conflict", msg)
	}
}

// TestRun_GuardIsScopedToOneProject is the multi-project half. A run on alpha
// must not lock beta out — the guard keys on the resolved working directory, and
// resolving it wrongly here would stop an idle tenant from working at all.
//
// Host execution is denied so the request that should get *past* the guard is
// refused by policy instead of starting a harness. The two refusals are
// distinguishable, which is the whole point: beta must fail the later check.
func TestRun_GuardIsScopedToOneProject(t *testing.T) {
	alpha := setupProjectDir(t, "alpha", nil)
	beta := setupProjectDir(t, "beta", nil)

	srv := New(alpha, 0, "")
	srv.Projects = []string{beta}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	denyHostExecution(t)

	srv.liveLogStartRun(alpha)

	// Alpha is running: refused by the re-entrancy guard.
	resp, err := http.Post(ts.URL+"/api/run?project_idx=0", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST /api/run for alpha: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("alpha = HTTP %d, want 409", resp.StatusCode)
	}
	if msg, _ := decodeRunRefusal(t, resp)["error"].(string); !strings.Contains(msg, "already in progress") {
		t.Errorf("alpha refused with %q, want the re-entrancy refusal", msg)
	}

	// Beta is idle: it must reach the policy check beyond the guard. Both are
	// 409s, so the body is what separates "you are already running" from "this
	// deployment will not execute on the host".
	resp2, err := http.Post(ts.URL+"/api/run?project_idx=1", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST /api/run for beta: %v", err)
	}
	defer resp2.Body.Close()
	if msg, _ := decodeRunRefusal(t, resp2)["error"].(string); strings.Contains(msg, "already in progress") {
		t.Errorf("beta was refused as already running (%q) — alpha's run leaked "+
			"across projects, locking an idle tenant out of starting its own", msg)
	}
}
