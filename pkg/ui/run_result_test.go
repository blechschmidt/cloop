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

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// resultExecutor is a remote-shaped executor holding one run's project result.
type resultExecutor struct {
	stubExecutor
	id      string
	kind    string // executor.KindRemoteAgent when empty
	returns bool
	result  executor.ProjectResult
	err     error
	fetched atomic.Int32
}

func (r *resultExecutor) ID() string { return r.id }
func (r *resultExecutor) Kind() string {
	if r.kind != "" {
		return r.kind
	}
	return executor.KindRemoteAgent
}
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
	dir := statedbtest.Dir(t)
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
		// Through the helper: the protocol it needs, and the remedy for this
		// hub's build (Task 20371).
		{"an agent too old to report", &resultExecutor{id: "old", returns: false},
			executor.ProtocolShortfall("Its agent", 0, remote.MinProjectResultVersion,
				"to have a seeded run's outcome sent back")},
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

// TestRunEndedSpeaksTheExecutorsLanguage pins the Task 20402 wording: a
// journal row about a missing result names what goes wrong on *that* kind of
// executor and the driver's own account, and an agent upgrade is offered only
// to a device. A Kubernetes run used to be told its connection dropped and to
// upgrade an agent it does not have.
func TestRunEndedSpeaksTheExecutorsLanguage(t *testing.T) {
	cases := []struct {
		name    string
		ex      *resultExecutor
		want    []string
		notWant []string
	}{
		{"a Pod whose frame was cut off",
			&resultExecutor{id: "k8s", kind: executor.KindKubernetes, returns: true,
				err: fmt.Errorf("%w: pod cloop/p: the project result frame was cut off: the stream ended after 10 of 99 bytes",
					executor.ErrProjectResultUnavailable)},
			[]string{"Pod's log", "--project-result-frame", "the stream ended after 10 of 99 bytes"},
			[]string{"connection dropped", "agent", "protocol"}},
		{"a Kubernetes executor that cannot report",
			&resultExecutor{id: "k8s-old", kind: executor.KindKubernetes, returns: false},
			[]string{"Kubernetes executor of this hub's build", "will run again"},
			[]string{"Its agent", "protocol", "--upgrade"}},
		{"a device whose connection dropped",
			&resultExecutor{id: "edge", returns: true,
				err: fmt.Errorf("%w: handle h1 on agent edge", executor.ErrProjectResultUnavailable)},
			[]string{"connection dropped"},
			[]string{"Pod"}},
		{"a container executor that cannot report",
			&resultExecutor{id: "box", kind: executor.KindContainer, returns: false},
			[]string{"shares the control plane's filesystem"},
			[]string{"Its agent", "protocol", "--upgrade"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := remoteProject(t)
			tc.ex.stubExecutor = stubExecutor{status: executor.Status{State: executor.StateExited}}
			rememberSeededDispatch(tc.ex, "h1", projectseed.Provenance{ExecutorID: tc.ex.id})
			(&Server{WorkDir: dir}).runEnded(dir, tc.ex, "h1")
			events := projectResultEvents(t, dir)
			if len(events) != 1 {
				t.Fatalf("journal = %+v, want one project_result row", events)
			}
			msg := events[0].Message
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("row %q lacks %q", msg, w)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(msg, w) {
					t.Errorf("row %q says %q, which is not this executor's remedy", msg, w)
				}
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

// TestLostRunsPlanIsKept is the second half of Task 50, and the loss the
// operator actually hit: a project started in pm mode on a device, the run
// planning twelve tasks of its own and finishing one, and then the executor
// stopped answering. The run never reported an outcome, so nothing reached the
// hub — the dashboard showed an empty project, and the next start planned the
// same twelve tasks again.
//
// What the device did report while it ran is held on the handle, and a run
// nothing replaced takes it on the way out.
func TestLostRunsPlanIsKept(t *testing.T) {
	dir := statedbtest.Dir(t)
	st := &state.ProjectState{
		Goal: "Build an attested enclave and a client for it", WorkDir: dir, Status: "running",
		Plan: &pm.Plan{Goal: "Build an attested enclave and a client for it"},
	}
	if err := st.SaveDirect(); err != nil {
		t.Fatalf("save the hub's copy: %v", err)
	}

	done := time.Now().Add(-time.Minute).UTC()
	ex := &resultExecutor{
		stubExecutor: stubExecutor{status: executor.Status{State: executor.StateRunning}},
		id:           "FL6HRGvUlqxf96aO", returns: true,
		// What the device last reported while it was running: a plan of its
		// own making, with no outcome for the run itself.
		result: executor.ProjectResult{Interim: true, Data: gzResult(t, projectseed.Result{
			Format: 1, Interim: true, Tasks: []projectseed.TaskChange{
				{After: &pm.Task{ID: 1, Title: "Pin down the enclave protocol", Priority: 1,
					Status: pm.TaskDone, Result: "documented", CompletedAt: &done}},
				{After: &pm.Task{ID: 2, Title: "Set up the Cargo workspace", Priority: 2,
					Status: pm.TaskInProgress, StartedAt: &done}},
			},
		})},
	}
	rememberSeededDispatch(ex, "h-lost", projectseed.Provenance{
		ExecutorID: ex.id, ExecutorKind: executor.KindRemoteAgent, Isolation: "remote", RunID: "run_lost",
	})

	srv := &Server{WorkDir: dir}
	srv.trackRun(dir, ex, "h-lost")
	if !srv.retireLostRun(dir, ex.id, "h-lost", runVerdict{
		Detail: "executor " + ex.id + " stopped answering and nothing replaced the run",
	}, true) {
		t.Fatal("retireLostRun did not take the run this test tracked")
	}

	got, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Plan == nil || len(got.Plan.Tasks) != 2 {
		t.Fatalf("the hub's plan holds %d tasks after the run was lost, want the 2 it had reported",
			len(got.Plan.Tasks))
	}
	one := got.Plan.TaskByID(1)
	if one == nil || one.Status != pm.TaskDone {
		t.Fatalf("task #1 = %+v, want the done the run reported", one)
	}
	if one.ExecutorID != ex.id || one.RunID != "run_lost" {
		t.Errorf("task #1 attributed to %q run %q, want the hub's own dispatch record",
			one.ExecutorID, one.RunID)
	}
	// Dead-run recovery runs after the merge, so the task the run was working
	// on is recovered rather than left in progress for ever.
	if two := got.Plan.TaskByID(2); two == nil || two.Status != pm.TaskPending {
		t.Errorf("task #2 = %+v, want it reset to pending by the dead-run recovery", two)
	}
	// The run's end is the hub's verdict, never the report's.
	if got.Status == "running" {
		t.Errorf("the project is still %q after its run was lost", got.Status)
	}
	events := projectResultEvents(t, dir)
	if len(events) != 1 {
		t.Fatalf("journal = %+v, want one project_result row", events)
	}
	if !strings.Contains(events[0].Message, "without reporting its outcome") {
		t.Errorf("the journal row does not say the plan came from a report rather than an outcome: %q",
			events[0].Message)
	}
	// And the dispatch is settled: a second retirement finds nothing to take.
	if n := ex.fetched.Load(); n != 1 {
		t.Errorf("ProjectResult fetched %d times, want once", n)
	}
}

// TestReplacedLostRunKeepsNothing is the control: when the failover put the
// run on another executor, the replacement was seeded from the hub's copy, and
// folding the stranded run's half-finished account in behind it would describe
// work the replacement is about to do again.
func TestReplacedLostRunKeepsNothing(t *testing.T) {
	dir := remoteProject(t)
	ex := &resultExecutor{
		stubExecutor: stubExecutor{status: executor.Status{State: executor.StateRunning}},
		id:           "FL6HRGvUlqxf96aO", returns: true,
		result: executor.ProjectResult{Interim: true, Data: gzResult(t, projectseed.Result{
			Format: 1, Interim: true, Tasks: []projectseed.TaskChange{
				{After: &pm.Task{ID: 9, Title: "A task the stranded run made", Priority: 9}},
			},
		})},
	}
	rememberSeededDispatch(ex, "h-replaced", projectseed.Provenance{ExecutorID: ex.id})

	srv := &Server{WorkDir: dir}
	srv.trackRun(dir, ex, "h-replaced")
	srv.retireLostRun(dir, ex.id, "h-replaced", runVerdict{Detail: "failed over"}, false)

	got, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Plan.Tasks) != 1 {
		t.Fatalf("the hub's plan holds %d tasks, want only its own", len(got.Plan.Tasks))
	}
	if n := ex.fetched.Load(); n != 0 {
		t.Errorf("the stranded run's report was collected %d times; its replacement owns the project", n)
	}
	if isSeededDispatch(ex, "h-replaced") {
		t.Error("the stranded dispatch is still tracked")
	}
}
