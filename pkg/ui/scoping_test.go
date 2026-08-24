package ui

// Cross-project bleed in the dashboard's realtime path (Task 20197).
//
// The report: "switching to the tasks page of a project, switching back to the
// projects page and switching to the tasks page of another project [shows] the
// tasks from another project". Intermittent, so a timing bug.
//
// This bug class has been re-fixed at least seven times (Tasks 150, 152, 163,
// 168, 8000, 20013, 20018) and every fix so far was guarded by a test that
// greps the frontend as text. Text cannot express the property that actually
// broke here — "a frame that arrives after the user selected another project
// must not be rendered" — because it is about ordering, not about which
// strings appear in a file. So these tests run the real bundle in node against
// a DOM shim (testdata/domshim.js) and drive the exact frame interleaving
// (testdata/scoping_scenarios.js).
//
// The scenarios failed before the fix and pass after it; the "before" column is
// recorded in each case below so a future reader can tell a real regression
// from a harness problem.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/state"
	"nhooyr.io/websocket"
)

// Task IDs are partitioned by project so any leak is unambiguous: a 1xx ID on
// screen while beta is selected came from alpha and from nowhere else.
var scopingProjectOfID = func(id int) string {
	switch {
	case id >= 100 && id < 200:
		return "alpha"
	case id >= 200 && id < 300:
		return "beta"
	}
	return "unknown"
}

type scopingResult struct {
	Selected string `json:"selected"`
	Rendered []int  `json:"rendered"`
	Error    string `json:"error"`
}

// TestDashboard_TasksNeverShowAnotherProject is the regression test for the
// report. Each case names the project the user has selected and the task IDs
// the Tasks tab must hold once the scenario's frames have been delivered.
func TestDashboard_TasksNeverShowAnotherProject(t *testing.T) {
	t.Parallel()

	results := runScopingScenarios(t)

	cases := []struct {
		scenario string
		project  string
		want     []int
		before   string // what this rendered before the fix
	}{{
		scenario: "reported_sequence",
		project:  "beta",
		want:     []int{201, 202},
		before:   "101,102 — alpha's tasks under beta, the reported bug verbatim",
	}, {
		scenario: "stale_socket_task_update",
		project:  "beta",
		want:     []int{201, 202},
		before:   "101,102 — a closed socket's frame replaced beta's state",
	}, {
		scenario: "stale_socket_state_diff",
		project:  "beta",
		want:     []int{201, 202},
		before:   "103,201,202 — a stale delta spliced alpha's task into beta's list",
	}, {
		scenario: "no_stale_rows_before_first_frame",
		project:  "beta",
		want:     nil,
		before:   "101,102 — alpha's rows stayed on screen awaiting beta's first frame",
	}, {
		scenario: "stale_socket_legacy_envelopes",
		project:  "beta",
		want:     []int{201, 202},
		before:   "101,102 — the legacy full-state envelopes bypassed the guard",
	}, {
		// The two below must not change: a guard that also drops the frames
		// the user is waiting for trades a leak for a dead dashboard.
		scenario: "single_project_still_renders",
		project:  "alpha",
		want:     []int{101, 102},
		before:   "101,102 — correct before and after",
	}, {
		scenario: "current_socket_keeps_updating",
		project:  "beta",
		want:     []int{201, 202, 203},
		before:   "201,202,203 — correct before and after",
	}}

	if len(cases) != len(results) {
		t.Errorf("scenario drift: testdata/scoping_scenarios.js defines %d scenarios, this "+
			"table asserts on %d — a scenario without an assertion silently proves nothing",
			len(results), len(cases))
	}

	for _, tc := range cases {
		t.Run(tc.scenario, func(t *testing.T) {
			got, ok := results[tc.scenario]
			if !ok {
				t.Fatalf("scenario %q produced no result; scoping_scenarios.js and this "+
					"table have drifted apart", tc.scenario)
			}
			if got.Error != "" {
				t.Fatalf("scenario %q threw in the browser shim:\n%s", tc.scenario, got.Error)
			}

			// The leak check first, and stated in the report's own terms, so a
			// failure reads as the bug rather than as a diff.
			for _, id := range got.Rendered {
				if owner := scopingProjectOfID(id); owner != tc.project {
					t.Errorf("the Tasks tab shows task %d, which belongs to project %q, "+
						"while %q is selected — this is Task 20197's cross-project bleed.\n"+
						"  rendered: %v\n  before the fix this rendered: %s",
						id, owner, tc.project, got.Rendered, tc.before)
				}
			}

			if !sameInts(got.Rendered, tc.want) {
				t.Errorf("Tasks tab for %q = %v, want %v\n"+
					"  before the fix this rendered: %s",
					tc.project, got.Rendered, tc.want, tc.before)
			}
		})
	}
}

// runScopingScenarios assembles the served bundle, runs the scenarios in node
// and returns them by name.
func runScopingScenarios(t *testing.T) map[string]scopingResult {
	t.Helper()

	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the bundle")
	}

	// The bundle as served, not the fragments: the concatenation order is part
	// of what makes the handlers reachable.
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(bundle, []byte(loadAssets().bundle), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	shim, err := filepath.Abs("testdata/domshim.js")
	if err != nil {
		t.Fatalf("resolve shim: %v", err)
	}
	scenarios, err := filepath.Abs("testdata/scoping_scenarios.js")
	if err != nil {
		t.Fatalf("resolve scenarios: %v", err)
	}

	cmd := exec.Command(node, scenarios, shim, bundle)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("running the scenarios failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}

	var results map[string]scopingResult
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	return results
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]int(nil), a...)
	y := append([]int(nil), b...)
	sort.Ints(x)
	sort.Ints(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// server side
// ---------------------------------------------------------------------------

// TestSSEConnectSnapshotIsTheStreamsOwnProject covers the non-racy half of the
// report. handleEvents resolved the stream's project into c.workDir and then
// built its opening state frame from s.WorkDir — the *primary* project —
// regardless of the ?project_idx asked for. So on the SSE fallback path (any
// proxy that blocks WebSocket upgrades) the first thing every client received
// was another project's full task list, every time rather than sometimes.
//
// The live-log replay immediately below it had the same defect and was fixed
// in Task 20189; the snapshot two lines above was missed.
func TestSSEConnectSnapshotIsTheStreamsOwnProject(t *testing.T) {
	dirA, dirB, srv := twoTenantHub(t)
	_ = dirA

	// Give the two projects distinguishable goals; the snapshot carries them.
	psB, err := state.Load(dirB)
	if err != nil {
		t.Fatalf("load project B: %v", err)
	}
	psB.Goal = "BETA-ONLY-GOAL"
	if psB.Plan != nil {
		psB.Plan.Goal = "BETA-ONLY-GOAL"
	}
	if err := psB.Save(); err != nil {
		t.Fatalf("save project B: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/events?project_idx=1", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("open SSE for project B: %v", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 32*1024)
	var body strings.Builder
	for body.Len() < 1<<20 {
		n, err := resp.Body.Read(buf)
		body.Write(buf[:n])
		if err != nil {
			break
		}
	}

	got := body.String()
	if strings.Contains(got, "alice: ship the payments service") {
		t.Errorf("the SSE stream for project B opened with project A's state.\n"+
			"handleEvents must build its snapshot from the stream's own workDir, "+
			"not from s.WorkDir.\nframe: %.400s", got)
	}
	if !strings.Contains(got, "BETA-ONLY-GOAL") {
		t.Errorf("the SSE stream for project B never sent project B's state; "+
			"the connect snapshot is missing.\nframe: %.400s", got)
	}
}

// TestGlobalScopeStreamJoinsNoProjectRoom covers the source of the leak rather
// than its rendering. The dashboard's projects landing page holds a stream with
// no project selected. Without an explicit scope that stream fell through
// resolveWorkDir to the primary project, joined its hub room, and was primed
// with its state — frames that then arrived under whichever project the user
// opened next, and which under OIDC belong to a project the viewer may have no
// claim to.
func TestGlobalScopeStreamJoinsNoProjectRoom(t *testing.T) {
	dirA, _, srv := twoTenantHub(t)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// The primary project has produced output before anyone lands.
	srv.broadcastLog(dirA, secretOutput)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/ws?scope=global"
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial landing stream: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	conn.SetReadLimit(-1)

	readCtx, readCancel := context.WithTimeout(ctx, 2*time.Second)
	defer readCancel()
	for {
		_, data, err := conn.Read(readCtx)
		if err != nil {
			break // deadline: the connect burst, if any, is over
		}
		if strings.Contains(string(data), secretOutput) {
			t.Fatalf("the landing stream replayed the primary project's output: %s", data)
		}
		var msg wsMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		switch msg.Type {
		case "task_update", "state_diff", "step_output", "run_state", "suggest_status":
			t.Fatalf("the landing stream was primed with per-project frame %q; a client "+
				"with no project selected renders none of these, and receiving them is "+
				"what let another project's state arrive under the next selection: %s",
				msg.Type, data)
		}
	}

	// And it must not be in the primary project's room, or every later
	// broadcast would reach it too.
	srv.hubMu.Lock()
	inPrimary := len(srv.hubClients[dirA])
	inGlobal := len(srv.hubClients[hubRoomGlobal])
	srv.hubMu.Unlock()
	if inPrimary != 0 {
		t.Errorf("a scope=global stream joined the primary project's hub room "+
			"(%d client(s)); it must join the fleet-wide room instead", inPrimary)
	}
	if inGlobal == 0 {
		t.Error("a scope=global stream joined no room at all — it would miss the " +
			"fleet-wide broadcasts (projects, executor_update, audit_append) it exists to receive")
	}
}

// TestUnscopedStreamStillPrimedInSingleProjectMode is the other half of the
// contract, and the reason the scope is declared by the client rather than
// inferred from "is this hub multi-project?". A single-project dashboard sends
// no project_idx either. If the server withheld its connect burst on that
// basis, the dashboard would come up permanently empty — a worse failure than
// the leak being fixed.
func TestUnscopedStreamStillPrimedInSingleProjectMode(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := setupProjectDir(t, "the only project", nil)
	srv := New(dir, 0, "")

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http")+"/api/ws", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	conn.SetReadLimit(-1)

	readCtx, readCancel := context.WithTimeout(ctx, 3*time.Second)
	defer readCancel()
	sawState := false
	for !sawState {
		_, data, err := conn.Read(readCtx)
		if err != nil {
			break
		}
		var msg wsMessage
		if err := json.Unmarshal(data, &msg); err == nil && msg.Type == "task_update" {
			sawState = true
		}
	}
	if !sawState {
		t.Error("a single-project dashboard's stream was never primed with its state; " +
			"it sends no project_idx, so the connect burst must still be sent")
	}
}
