package ui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/runbuild"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// postStatus POSTs body and returns the status code and the decoded reply.
func postStatus(t *testing.T, ts *httptest.Server, path string, body any) (int, map[string]any) {
	t.Helper()
	data, _ := json.Marshal(body)
	resp, err := http.Post(ts.URL+path, "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// recordRun writes a run-owner record for dir naming this test process, so
// the hub sees a live run.
func recordRun(t *testing.T, dir string, mutate func(o *runbuild.Owner)) *runbuild.Owner {
	t.Helper()
	self, err := runbuild.SelfIdent()
	if err != nil {
		t.Skipf("no procfs: %v", err)
	}
	o := &runbuild.Owner{Ident: self, Host: runbuild.Hostname(), Exe: "/usr/local/bin/cloop-latest",
		Executor: "localprocess", Adoptable: true, StartedAt: time.Now().Add(-time.Hour),
		Build: runbuild.Build{Version: "dev+g4e35bf6", Sequence: 831, Schema: 53}, BuildSince: time.Now().Add(-time.Hour)}
	if mutate != nil {
		mutate(o)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.SaveRunOwner(o); err != nil {
		t.Fatal(err)
	}
	return o
}

// TestAdoptBuild_FilesARequestForTheLiveRun: the request names the run's
// process, lands in the project, rides /api/state, and is audited on the
// project's trail.
func TestAdoptBuild_FilesARequestForTheLiveRun(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)
	owner := recordRun(t, dir, nil)

	code, body := postStatus(t, ts, "/api/run/adopt-build", map[string]any{})
	if code != http.StatusOK || body["ok"] != true {
		t.Fatalf("adopt-build = %d %v", code, body)
	}
	ps := loadStateOrFail(t, dir)
	if ps.AdoptRequest == nil || !ps.AdoptRequest.For(owner.Ident) || ps.AdoptRequest.ID == "" {
		t.Fatalf("stored request = %+v; want one addressed to %+v", ps.AdoptRequest, owner.Ident)
	}
	st := apiGET(t, ts, "/api/state")
	rb, _ := st["run_build"].(map[string]any)
	if rb == nil || rb["live"] != true || rb["adoptable"] != true {
		t.Fatalf("/api/state run_build = %v", st["run_build"])
	}
	if b, _ := rb["build"].(map[string]any); b["sequence"] != float64(831) {
		t.Fatalf("/api/state run_build.build = %v", rb["build"])
	}
	if ar, _ := st["adopt_request"].(map[string]any); ar == nil || ar["id"] != ps.AdoptRequest.ID {
		t.Fatalf("/api/state adopt_request = %v", st["adopt_request"])
	}

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: "run.adopt_requested"})
	if err != nil || len(rows) != 1 || !strings.Contains(rows[0].Payload, ps.AdoptRequest.ID) ||
		!strings.Contains(rows[0].Payload, `"sequence":831`) {
		t.Fatalf("audit rows = %+v, %v", rows, err)
	}
}

// Every reason a request would be pointless or impossible is a 409 that says
// why — and files nothing.
func TestAdoptBuild_Refusals(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(t *testing.T, dir string)
		reason string
	}{
		{"no record", func(t *testing.T, dir string) {}, "has not reported its build"},
		{"not running", func(t *testing.T, dir string) {
			recordRun(t, dir, func(o *runbuild.Owner) { o.StartTicks++ })
		}, "no run of this project is running"},
		{"container", func(t *testing.T, dir string) {
			recordRun(t, dir, func(o *runbuild.Owner) { o.Executor, o.Adoptable = "container", false })
		}, "keeps its own upgrade path"},
		{"another host", func(t *testing.T, dir string) {
			recordRun(t, dir, func(o *runbuild.Owner) { o.Host = "elsewhere.example" })
		}, "cannot be checked from this hub's host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupProjectDir(t, cloopGoal, nil)
			ts := newTestServer(t, dir, nil)
			tc.setup(t, dir)
			code, body := postStatus(t, ts, "/api/run/adopt-build", map[string]any{})
			if code != http.StatusConflict || !strings.Contains(body["error"].(string), tc.reason) {
				t.Fatalf("adopt-build = %d %v; want 409 mentioning %q", code, body, tc.reason)
			}
			if ps := loadStateOrFail(t, dir); ps.AdoptRequest != nil {
				t.Fatalf("a refused request was filed: %+v", ps.AdoptRequest)
			}
		})
	}
}

func TestAdoptRefusal_RunLevelWithTheHub(t *testing.T) {
	hub := runbuild.Build{Version: "dev+g89510f3", Sequence: 963}
	ps := &state.ProjectState{RunOwner: &runbuild.Owner{}}
	st := &runbuild.Status{Build: hub, Reference: hub, Comparable: true, Live: true, LiveKnown: true, Adoptable: true}
	if msg := adoptRefusal(ps, st, hub); !strings.Contains(msg, "not behind this hub") {
		t.Fatalf("a level run: %q", msg)
	}
	st.Behind, st.Build.Sequence = 2, 961
	if msg := adoptRefusal(ps, st, hub); msg != "" {
		t.Fatalf("a run two builds behind was refused: %q", msg)
	}
}

// Follow New Builds is stored through its own setter, so neither another
// badge's full save nor a running orchestrator's save can put a stale copy back.
func TestOptionsToggle_FollowBuilds(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)
	run, err := state.Load(dir) // a run's copy, read before the toggle
	if err != nil {
		t.Fatal(err)
	}
	body := apiPOST(t, ts, "/api/options/toggle", map[string]any{"flag": "follow_builds", "value": true})
	if body["ok"] != true || body["follow_builds"] != true {
		t.Fatalf("toggle = %v", body)
	}
	if !loadStateOrFail(t, dir).FollowBuilds {
		t.Fatal("follow_builds was not stored")
	}
	apiPOST(t, ts, "/api/options/toggle", map[string]any{"flag": "auto_evolve", "value": true})
	if err := run.SaveDirect(); err != nil {
		t.Fatal(err)
	}
	if !loadStateOrFail(t, dir).FollowBuilds {
		t.Fatal("a stale copy's save switched follow_builds off")
	}
	if st := apiGET(t, ts, "/api/state"); st["follow_builds"] != true {
		t.Fatalf("/api/state follow_builds = %v", st["follow_builds"])
	}
	apiPOST(t, ts, "/api/options/toggle", map[string]any{"flag": "follow_builds", "value": false})
	if loadStateOrFail(t, dir).FollowBuilds {
		t.Fatal("follow_builds was not switched off")
	}
}
