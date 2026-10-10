package ui

// The hub's half of a disk-limit stop (Task 20405): a workload its executor
// stopped at its disk limit is recorded as exactly that — on the task, in the
// journal, in task.finish — and the run is paused rather than retried.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// diskStopStatus is what the container driver reports for a workload it
// stopped at a 64 MB limit with 70 MB in the workspace: SIGKILLed, exit 137.
func diskStopStatus() executor.Status {
	b := executor.DiskLimitBreach{UsedBytes: 70 << 20, LimitMB: 64, Source: executor.DiskLimitFromSpec,
		Path: "/srv/proj", MeasuredAt: time.Now()}
	return executor.Status{
		State:     executor.StateKilled,
		ExitCode:  137,
		Error:     "stopped at its disk limit: " + b.Describe(),
		Outcome:   executor.OutcomeDiskLimit,
		DiskLimit: &b,
	}
}

// TestADiskLimitStopIsNotReadAsAnOOM: the stop is a SIGKILL with exit 137,
// exactly the shape the OOM reading claims, so the outcome has to be read
// first or the dashboard would blame memory for a full workspace.
func TestADiskLimitStopIsNotReadAsAnOOM(t *testing.T) {
	v := workloadVerdict(&stubExecutor{status: diskStopStatus()}, "h1")
	if v.DiskLimit == nil || v.OOM || v.Requested {
		t.Fatalf("verdict = %+v, want a disk-limit stop and neither an OOM nor an operator's stop", v)
	}
	r := deadRunPauseReason(v)
	if r.Code != pausereason.CodeDiskLimit {
		t.Fatalf("pause code = %q, want %q", r.Code, pausereason.CodeDiskLimit)
	}
	for _, want := range []string{"70 MB", "64 MB", "resources.disk", "press Run"} {
		if !strings.Contains(r.Detail, want) {
			t.Errorf("pause detail %q does not name %q", r.Detail, want)
		}
	}
	if r.AutoResumable(time.Now().Add(time.Hour)) {
		t.Fatal("a disk-limit pause would be retried on a timer")
	}
	if got := settledReason(diskStopStatus(), nil, false); got != hubmetrics.FailDiskLimit {
		t.Fatalf("metrics reason = %q, want %q", got, hubmetrics.FailDiskLimit)
	}
}

// diskStoppedProject is a project whose run claims to be running with task 7
// in progress and no transcript — what a run on a container executor leaves
// when its sandbox is SIGKILLed at its disk limit.
func diskStoppedProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	st, err := state.Init(dir, "fill the disk", 0)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now().Add(-time.Minute)
	st.Status = "running"
	st.Plan = &pm.Plan{Goal: "fill the disk", Tasks: []*pm.Task{
		{ID: 7, Title: "Generate the fixtures", Status: pm.TaskInProgress, StartedAt: &started},
		{ID: 8, Title: "Use them", Status: pm.TaskPending},
	}}
	if err := st.SaveDirect(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestADiskLimitStopPausesTheRunAndRequeuesTheTaskSayingWhy(t *testing.T) {
	dir := diskStoppedProject(t)
	srv := &Server{WorkDir: dir}

	if !srv.reconcileDeadRun(dir, workloadVerdict(&stubExecutor{status: diskStopStatus()}, "h1")) {
		t.Fatal("the stopped run's status was not settled")
	}

	st, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Paused, naming the limit — not retried.
	if st.Status != "paused" || st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeDiskLimit {
		t.Fatalf("status = %q, reason = %+v; want paused for disk_limit", st.Status, st.PauseReason)
	}
	// The task goes back to pending, and its note — cloop's own, so it is
	// the reason task.finish carries — names the stop and both sizes.
	task := st.Plan.TaskByID(7)
	if task.Status != pm.TaskPending {
		t.Fatalf("task 7 = %q, want pending", task.Status)
	}
	n := len(task.Annotations)
	if n == 0 || task.Annotations[n-1].Author != "cloop" ||
		!strings.Contains(task.Annotations[n-1].Text, "disk limit") ||
		!strings.Contains(task.Annotations[n-1].Text, "70 MB") ||
		!strings.Contains(task.Annotations[n-1].Text, "64 MB") {
		t.Fatalf("task 7's notes = %+v, want cloop's naming the disk limit and both sizes", task.Annotations)
	}
	if st.Plan.TaskByID(8).Status != pm.TaskPending {
		t.Fatal("a task the run never started was touched")
	}

	// The journal: one disk_limit row with the numbers, and the re-queue.
	rows, _, err := state.ListEvents(dir, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	var stopRow, requeueRow *state.EventRow
	for i := range rows {
		switch {
		case rows[i].Type == state.EventDiskLimit:
			stopRow = &rows[i]
		case rows[i].Type == state.EventTaskStatusChange && rows[i].TaskID == 7:
			requeueRow = &rows[i]
		}
	}
	if stopRow == nil || !strings.Contains(stopRow.Message, "stopped at its disk limit") ||
		!strings.Contains(stopRow.Message, "task #7, which it was running, went back to pending") ||
		!strings.Contains(stopRow.Message, "free space in the workspace") {
		t.Fatalf("no disk_limit journal row naming the stop and the remedy: %+v", rows)
	}
	var details map[string]any
	if err := json.Unmarshal([]byte(stopRow.Details), &details); err != nil {
		t.Fatalf("details %q: %v", stopRow.Details, err)
	}
	if details["disk_used_mb"] != float64(70) || details["disk_limit_mb"] != float64(64) {
		t.Fatalf("details = %v", details)
	}
	if requeueRow == nil || !strings.Contains(requeueRow.Message, "disk limit") ||
		!strings.Contains(requeueRow.Details, `"stop":"disk_limit"`) {
		t.Fatalf("re-queue row = %+v, want it to name the disk limit", requeueRow)
	}

	// And task.finish, as fields an auditor can query.
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionTaskFinish),
		EntityType: "task", EntityID: "7"})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("task.finish rows for task 7 = %d, want 1", len(evs))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(evs[0].Payload), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["stop"] != pm.StopDiskLimit || payload["disk_used_mb"] != float64(70) ||
		payload["disk_limit_mb"] != float64(64) || payload["outcome"] != string(pm.TaskPending) {
		t.Fatalf("task.finish payload = %v", payload)
	}
	if r, _ := payload["reason"].(string); !strings.HasPrefix(r, "disk_limit: ") {
		t.Fatalf("task.finish reason = %q, want it to lead with disk_limit", r)
	}
}

func TestADiskLimitStopOfAFinishedTaskKeepsItsOutcome(t *testing.T) {
	// The agent had finished and said so before the stop landed: its outcome
	// stands, and only what it had not finished is re-queued for the limit.
	dir, taskID := stalledProject(t)
	srv := &Server{WorkDir: dir}
	srv.reconcileDeadRun(dir, workloadVerdict(&stubExecutor{status: diskStopStatus()}, "h1"))
	st, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Plan.TaskByID(taskID); got.Status != pm.TaskDone || got.Stop != nil {
		t.Fatalf("task = %q stop %+v, want the agent's done kept", got.Status, got.Stop)
	}
	if st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeDiskLimit {
		t.Fatalf("pause = %+v, want disk_limit whatever the task's outcome", st.PauseReason)
	}
	rows, _, err := state.ListEvents(dir, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Type == state.EventDiskLimit && strings.Contains(r.Message, "went back to pending") {
			t.Fatalf("the journal says a task the agent finished went back to pending: %q", r.Message)
		}
	}
}

func TestARefusedStartIsJournalled(t *testing.T) {
	dir := runningProject(t, "paused")
	refused := &executor.DiskLimitError{Executor: "container", Breach: executor.DiskLimitBreach{
		UsedBytes: 73 << 20, LimitMB: 64, Source: executor.DiskLimitFromCeiling, Path: dir}}
	journalDiskLimitRefusal(dir, fmt.Errorf("start: %w", refused))
	journalDiskLimitRefusal(dir, fmt.Errorf("some other failure"))

	rows, _, err := state.ListEvents(dir, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	var found []state.EventRow
	for _, r := range rows {
		if r.Type == state.EventDiskLimit {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("disk_limit rows = %d, want 1 for the refusal and none for the other error", len(found))
	}
	for _, want := range []string{"refused", "73 MB", "64 MB", "disk ceiling"} {
		if !strings.Contains(found[0].Message, want) {
			t.Errorf("row %q does not name %q", found[0].Message, want)
		}
	}
}

// localStub enforces nothing, like the host-process driver.
type localStub struct{ stubExecutor }

func (*localStub) ID() string   { return "local" }
func (*localStub) Kind() string { return executor.KindLocalProcess }

func TestADiskCeilingTheExecutorCannotHoldIsJournalled(t *testing.T) {
	dir := runningProject(t, "paused")
	executor.ResetResourceCeiling()
	t.Cleanup(executor.ResetResourceCeiling)
	executor.ApplyResourceCeiling(executor.ResourceCeiling{DiskMB: 20480})

	// No clamp: the project asked for nothing, which is the workload a disk
	// ceiling exists for and the one no clamp is ever recorded for.
	logUnenforceableCeiling(&localStub{}, dir, nil)

	rows, _, err := state.ListEvents(dir, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	var msgs []string
	for _, r := range rows {
		if r.Type == state.EventResourceCeiling {
			msgs = append(msgs, r.Message)
		}
	}
	if len(msgs) != 1 || !strings.Contains(msgs[0], "disk ceiling of 20 GB will not bound this run") {
		t.Fatalf("resource_ceiling rows = %q, want one saying the disk ceiling is not held", msgs)
	}
}

// TestARefusedStartIsAConflictNotAServerError: Run pressed over a workspace
// still over its limit is the hub refusing on purpose, with the remedy — not a
// 500 that sends an operator looking for a fault.
func TestARefusedStartIsAConflictNotAServerError(t *testing.T) {
	for _, source := range []string{executor.DiskLimitFromSpec, executor.DiskLimitFromCeiling} {
		refused := &executor.DiskLimitError{Executor: "container", Breach: executor.DiskLimitBreach{
			UsedBytes: 73 << 20, LimitMB: 64, Source: source, Path: "/srv/proj"}}
		rec := httptest.NewRecorder()
		jsonWorkloadErr(rec, fmt.Errorf("start workload: %w", refused))
		if rec.Code != http.StatusConflict {
			t.Fatalf("%s: status = %d, want 409", source, rec.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		remedy, _ := body["remediation"].(string)
		if body["code"] != "workspace_over_disk_limit" || remedy != refused.Breach.Remedy() {
			t.Fatalf("%s: body = %v", source, body)
		}
		if msg, _ := body["error"].(string); !strings.Contains(msg, "73 MB") || !strings.Contains(msg, "64 MB") {
			t.Fatalf("%s: error = %q, want both sizes", source, msg)
		}
	}
}

// TestAnAutoResumeRefusedOverTheDiskLimitRepausesForIt: a cap pause whose
// window reopened over a workspace that is over its disk limit would otherwise
// be retried — and refused, and journalled — on every sweep, under a badge
// still blaming the subscription. It becomes a disk_limit pause, which waits
// for a person.
func TestAnAutoResumeRefusedOverTheDiskLimitRepausesForIt(t *testing.T) {
	reset := time.Date(2026, 9, 15, 14, 50, 0, 0, time.UTC)
	dir := pausedProject(t, pausereason.NewUntil(pausereason.CodeUsageCap, "5-hour cap reached", reset))
	srv, _ := resumeProbe(t, dir, reset.Add(time.Minute))
	calls := 0
	srv.autoResumeStart = func(string) error {
		calls++
		return fmt.Errorf("start workload: %w", &executor.DiskLimitError{Executor: "container",
			Breach: executor.DiskLimitBreach{UsedBytes: 73 << 20, LimitMB: 64, Source: executor.DiskLimitFromSpec}})
	}
	if srv.maybeAutoResume(dir) {
		t.Fatal("a refused resume reported a run started")
	}
	st, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "paused" || st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeDiskLimit ||
		!strings.Contains(st.PauseReason.Detail, "73 MB") {
		t.Fatalf("pause = %q %+v, want disk_limit naming the size", st.Status, st.PauseReason)
	}
	if srv.maybeAutoResume(dir) || calls != 1 {
		t.Fatalf("the next sweep tried again (%d attempts)", calls)
	}

	// Any other refusal leaves the cap pause to be tried again.
	other := pausedProject(t, pausereason.NewUntil(pausereason.CodeUsageCap, "5-hour cap reached", reset))
	srv2, _ := resumeProbe(t, other, reset.Add(time.Minute))
	srv2.autoResumeStart = func(string) error { return fmt.Errorf("no executor answered") }
	srv2.maybeAutoResume(other)
	if st, _ := state.Load(other); st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeUsageCap {
		t.Fatalf("an unrelated refusal changed the pause: %+v", st.PauseReason)
	}
}
