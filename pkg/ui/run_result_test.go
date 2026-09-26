package ui

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// resultExecutor is a remote-shaped executor holding one run's project result.
type resultExecutor struct {
	stubExecutor
	id      string
	returns bool
	result  executor.ProjectResult
	err     error
	fetched atomic.Int32
}

func (r *resultExecutor) ID() string   { return r.id }
func (r *resultExecutor) Kind() string { return executor.KindRemoteAgent }
func (r *resultExecutor) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationRemote, ReturnsProjectState: r.returns}
}
func (r *resultExecutor) ProjectResult(string) (executor.ProjectResult, error) {
	r.fetched.Add(1)
	if r.result.Redact == nil {
		r.result.Redact = func(s string) string { return s }
	}
	return r.result, r.err
}

func gzResult(t *testing.T, r projectseed.Result) []byte {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return buf.Bytes()
}

// remoteProject saves the hub's copy of the test project from Task 20339: one
// task, still pending, bound to an executor that cannot read this filesystem.
func remoteProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	st := &state.ProjectState{
		Goal: "Test the cloop remote executor", WorkDir: dir, Status: "initialized",
		Plan: &pm.Plan{Goal: "Test the cloop remote executor", Tasks: []*pm.Task{
			{ID: 1, Title: "Create a file named hello which contains the string world", Status: pm.TaskPending},
		}},
	}
	if err := st.SaveDirect(); err != nil {
		t.Fatalf("save: %v", err)
	}
	return dir
}

func projectResultEvents(t *testing.T, dir string) []state.EventRow {
	t.Helper()
	rows, _, err := state.ListEvents(dir, 0, 100)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var out []state.EventRow
	for _, r := range rows {
		if r.Type == state.EventProjectResult {
			out = append(out, r)
		}
	}
	return out
}

func finishedTask(title string, status pm.TaskStatus) projectseed.TaskChange {
	now := time.Now().UTC()
	return projectseed.TaskChange{
		Before: &pm.Task{ID: 1, Title: title, Status: pm.TaskPending},
		After: &pm.Task{ID: 1, Title: title, Status: status, Result: "Created hello containing world",
			StartedAt: &now, CompletedAt: &now},
	}
}

// TestRunEndedMergesARemoteRunsResults is the defect as the operator met it: a
// run on the sgx executor finished the project's one task, and afterwards the
// dashboard still showed it pending — "immediate completion although there is
// one remaining task". runEnded is where every dispatch path settles a run, so
// it is where the result has to land.
func TestRunEndedMergesARemoteRunsResults(t *testing.T) {
	dir := remoteProject(t)
	title := "Create a file named hello which contains the string world"
	ex := &resultExecutor{
		stubExecutor: stubExecutor{status: executor.Status{State: executor.StateExited}},
		id:           "FL6HRGvUlqxf96aO", returns: true,
		result: executor.ProjectResult{Data: gzResult(t, projectseed.Result{
			Format: 1, Status: "complete", Tasks: []projectseed.TaskChange{finishedTask(title, pm.TaskDone)},
		})},
	}
	rememberSeededDispatch(ex, "h1", projectseed.Provenance{
		ExecutorID: ex.id, ExecutorKind: executor.KindRemoteAgent, Isolation: "remote", RunID: "run_x", Identity: "local",
	})

	srv := &Server{WorkDir: dir}
	srv.runEnded(dir, ex, "h1")

	st, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	task := st.Plan.TaskByID(1)
	if task.Status != pm.TaskDone {
		t.Fatalf("task 1 is %q after the executor reported it done — the reported bug", task.Status)
	}
	if task.ExecutorID != ex.id || task.ExecutorKind != executor.KindRemoteAgent || task.RunID != "run_x" {
		t.Errorf("task attributed to %q/%q run %q", task.ExecutorID, task.ExecutorKind, task.RunID)
	}
	if st.Status != "complete" {
		t.Errorf("project status = %q, want complete", st.Status)
	}
	events := projectResultEvents(t, dir)
	if len(events) != 1 || !strings.Contains(events[0].Message, "#1 done") {
		t.Fatalf("journal = %+v, want one project_result row naming the task", events)
	}

	// Settling the same run again must not merge it twice — its spend would
	// be booked twice.
	srv.runEnded(dir, ex, "h1")
	if n := ex.fetched.Load(); n != 1 {
		t.Errorf("ProjectResult fetched %d times, want once per dispatch", n)
	}
}

// TestRunEndedExplainsWhyNothingCameBack covers the runs whose result cannot be
// merged. In each the dashboard stays stale, and the journal is the only place
// that can say why.
func TestRunEndedExplainsWhyNothingCameBack(t *testing.T) {
	cases := []struct {
		name string
		ex   *resultExecutor
		want string
	}{
		{"an agent too old to report", &resultExecutor{id: "old", returns: false}, "Upgrade its agent"},
		{"a run that sent nothing", &resultExecutor{id: "lost", returns: true,
			err: fmt.Errorf("%w: gone", executor.ErrProjectResultUnavailable)}, "ended without sending its results back"},
		{"a device that could not read the run", &resultExecutor{id: "err", returns: true,
			result: executor.ProjectResult{Err: "the workload removed its project"}}, "the workload removed its project"},
		{"a report that does not parse", &resultExecutor{id: "junk", returns: true,
			result: executor.ProjectResult{Data: []byte("not gzip")}}, "could not be read"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := remoteProject(t)
			tc.ex.stubExecutor = stubExecutor{status: executor.Status{State: executor.StateExited}}
			rememberSeededDispatch(tc.ex, "h1", projectseed.Provenance{ExecutorID: tc.ex.id})
			(&Server{WorkDir: dir}).runEnded(dir, tc.ex, "h1")

			events := projectResultEvents(t, dir)
			if len(events) != 1 || !strings.Contains(events[0].Message, tc.want) {
				t.Fatalf("journal = %+v, want a row containing %q", events, tc.want)
			}
			st, _ := state.Load(dir)
			if st.Plan.TaskByID(1).Status != pm.TaskPending {
				t.Errorf("task changed without a result: %q", st.Plan.TaskByID(1).Status)
			}
		})
	}
}

// TestRunEndedLeavesUnseededRunsAlone: a run that was not sent the project —
// every run on an executor sharing this filesystem — wrote straight into the
// hub's copy and has nothing to bring back.
func TestRunEndedLeavesUnseededRunsAlone(t *testing.T) {
	dir := remoteProject(t)
	ex := &resultExecutor{stubExecutor: stubExecutor{status: executor.Status{State: executor.StateExited}}, id: "local-ish", returns: true}
	(&Server{WorkDir: dir}).runEnded(dir, ex, "never-seeded")
	if ex.fetched.Load() != 0 {
		t.Error("asked for a result from a run that was never sent a project")
	}
	if events := projectResultEvents(t, dir); len(events) != 0 {
		t.Errorf("journal = %+v", events)
	}
}

// TestRunEndedRecoversWhatAKilledRemoteRunLeftInProgress: the run died mid
// task, and its result says so. The merge hands that to dead-run recovery,
// which requeues the task and pauses the project — the same outcome a killed
// local run gets.
func TestRunEndedRecoversWhatAKilledRemoteRunLeftInProgress(t *testing.T) {
	dir := remoteProject(t)
	tc := finishedTask("Create a file named hello which contains the string world", pm.TaskInProgress)
	tc.After.CompletedAt, tc.After.Result = nil, ""
	ex := &resultExecutor{
		stubExecutor: stubExecutor{status: executor.Status{State: executor.StateKilled, Error: "signal: killed"}},
		id:           "sgx", returns: true,
		result: executor.ProjectResult{Data: gzResult(t, projectseed.Result{
			Format: 1, Status: "running", Tasks: []projectseed.TaskChange{tc},
		})},
	}
	rememberSeededDispatch(ex, "h1", projectseed.Provenance{ExecutorID: "sgx", ExecutorKind: executor.KindRemoteAgent})
	(&Server{WorkDir: dir}).runEnded(dir, ex, "h1")

	st, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Plan.TaskByID(1).Status; got != pm.TaskPending {
		t.Errorf("task left %q; recovery should requeue what a killed run stranded", got)
	}
	if st.Status != "paused" || st.PauseReason == nil {
		t.Errorf("project status = %q (%+v), want paused with the executor's account", st.Status, st.PauseReason)
	}
}
