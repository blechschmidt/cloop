package configvalidate

// `cloop config validate --fix` and in-progress tasks (Task 20374).

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/runprobe"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/taskrecover"
)

// stubProbe answers probeRun from answers in turn, repeating the last.
func stubProbe(t *testing.T, answers ...runprobe.Evidence) *int {
	t.Helper()
	calls := 0
	old := probeRun
	probeRun = func(string) runprobe.Evidence {
		i := calls
		if i >= len(answers) {
			i = len(answers) - 1
		}
		calls++
		return answers[i]
	}
	t.Cleanup(func() { probeRun = old })
	return &calls
}

var (
	live = runprobe.Evidence{Live: true, Reason: "a `cloop run` process (pid 4711) is executing in the project"}
	dead = runprobe.Evidence{}
)

// newProject saves a project with tasks and run status, as a run would have
// left it.
func newProject(t *testing.T, status string, tasks ...*pm.Task) string {
	t.Helper()
	dir := statedbtest.Dir(t)
	st, err := state.Init(dir, "validate the state", 0)
	if err != nil {
		t.Fatal(err)
	}
	st.Plan = &pm.Plan{Goal: st.Goal, Tasks: tasks}
	st.Status = status
	if err := st.SaveDirect(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func task(id int, title string, status pm.TaskStatus, started *time.Time) *pm.Task {
	return &pm.Task{ID: id, Title: title, Status: status, StartedAt: started}
}

func load(t *testing.T, dir string) *state.ProjectState {
	t.Helper()
	st, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func taskByID(t *testing.T, st *state.ProjectState, id int) *pm.Task {
	t.Helper()
	for _, tk := range st.Plan.Tasks {
		if tk.ID == id {
			return tk
		}
	}
	t.Fatalf("task %d not found", id)
	return nil
}

func validate(t *testing.T, dir string, fix bool) *Report {
	t.Helper()
	rep := &Report{}
	add := func(f Finding) { rep.Findings = append(rep.Findings, f) }
	if err := checkStateDB(dir, state.DBPath(dir), fix, rep, add); err != nil {
		t.Fatalf("checkStateDB: %v", err)
	}
	return rep
}

func findings(rep *Report, sev Severity, contains string) []Finding {
	var out []Finding
	for _, f := range rep.Findings {
		if f.Severity == sev && strings.Contains(f.Message, contains) {
			out = append(out, f)
		}
	}
	return out
}

func eventCount(t *testing.T, dir string) int {
	t.Helper()
	_, total, err := state.ListEvents(dir, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	return total
}

// The defect: --fix reset an in-progress task to pending with a bare UPDATE
// while a run was executing it. Beside a live run it must change nothing — not
// the task it is running, and not an invalid status the run would write back.
func TestFixLeavesALiveRunsPlanAlone(t *testing.T) {
	started := time.Now().Add(-time.Minute)
	dir := newProject(t, "running",
		task(1, "being executed", pm.TaskInProgress, &started),
		task(2, "garbled", "finished", nil),
	)
	stubProbe(t, live)
	before := eventCount(t, dir)

	rep := validate(t, dir, true)

	st := load(t, dir)
	if got := taskByID(t, st, 1).Status; got != pm.TaskInProgress {
		t.Fatalf("task 1 = %q: --fix reset a task a live run is executing", got)
	}
	if got := taskByID(t, st, 2).Status; got != "finished" {
		t.Fatalf("task 2 = %q: --fix rewrote the plan of a live run", got)
	}
	if st.Status != "running" {
		t.Fatalf("status = %q: --fix paused a live run", st.Status)
	}
	if len(rep.Fixed) != 0 || eventCount(t, dir) != before {
		t.Fatalf("fixed %v, events %d → %d; want nothing done", rep.Fixed, before, eventCount(t, dir))
	}
	if len(findings(rep, SeverityInfo, "a run of this project is live: "+live.Reason)) != 1 {
		t.Errorf("no finding says task 1 belongs to the live run: %+v", rep.Findings)
	}
	if len(findings(rep, SeverityWarn, "did not reset the 1 invalid status")) != 1 {
		t.Errorf("the refusal to touch the invalid status is not reported: %+v", rep.Findings)
	}
	if !rep.HasErrors() {
		t.Error("the invalid status no longer counts as an error, though it was not fixed")
	}
}

// With no run live, the tasks the dead run left are recovered the way the hub
// and the orchestrator recover them: the orchestrator's verdict first, then the
// agent's own report, re-queued only when neither decided.
func TestFixRecoversADeadRunsTasksThroughTaskrecover(t *testing.T) {
	started := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
	dir := newProject(t, "running",
		task(1, "rejected by the review gate", pm.TaskInProgress, &started),
		task(2, "finished before the crash", pm.TaskInProgress, &started),
		task(3, "interrupted", pm.TaskInProgress, &started),
		task(4, "untouched", pm.TaskDone, &started),
	)
	decided := started.Add(10 * time.Minute)
	if err := taskrecover.WriteVerdict(dir, taskrecover.Verdict{
		TaskID: 1, Status: pm.TaskFailed, Reason: "review_blocked", Source: taskrecover.SourceReviewGate,
		Detail: "the reviewer blocked the change", StartedAt: &started, WrittenAt: decided,
	}); err != nil {
		t.Fatal(err)
	}
	livePath := artifact.LiveArtifactPath(dir, 2)
	if err := os.MkdirAll(filepath.Dir(livePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(livePath, []byte("Did the work.\n\nTASK_DONE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(livePath, decided, decided); err != nil {
		t.Fatal(err)
	}
	stubProbe(t, dead)
	before := eventCount(t, dir)

	rep := validate(t, dir, true)

	st := load(t, dir)
	if got := taskByID(t, st, 1).Status; got != pm.TaskFailed {
		t.Errorf("task 1 = %q: the review gate failed it, and --fix brought it back as %q", got, got)
	}
	if got := taskByID(t, st, 2).Status; got != pm.TaskDone {
		t.Errorf("task 2 = %q, want done: the agent had finished, and running it again repeats the work", got)
	}
	t3 := taskByID(t, st, 3)
	if t3.Status != pm.TaskPending || t3.StartedAt != nil {
		t.Errorf("task 3 = %q (started %v), want pending and not started", t3.Status, t3.StartedAt)
	}
	if got := taskByID(t, st, 4).Status; got != pm.TaskDone {
		t.Errorf("task 4 = %q: a finished task was touched", got)
	}
	if !st.PausedFor(pausereason.CodeStale) {
		t.Errorf("status = %q (%+v), want paused as stale", st.Status, st.PauseReason)
	}
	if n := eventCount(t, dir) - before; n != 4 {
		t.Errorf("%d events journalled, want 4: one per recovered task and one for the dead run", n)
	}
	if len(rep.Fixed) != 4 {
		t.Errorf("Fixed = %q, want four entries", rep.Fixed)
	}
	assertAuditedFinish(t, dir, 1, 2, 3)
}

// Invalid statuses are fixed through statedb, so the change reaches the events
// journal and the audit trail like any other status change.
func TestFixResetsAnInvalidStatusThroughStatedb(t *testing.T) {
	dir := newProject(t, "paused", task(1, "garbled", "finished", nil), task(2, "fine", pm.TaskPending, nil))
	stubProbe(t, dead)
	before := eventCount(t, dir)

	rep := validate(t, dir, true)

	tk := taskByID(t, load(t, dir), 1)
	if tk.Status != pm.TaskPending {
		t.Fatalf("task 1 = %q, want pending", tk.Status)
	}
	if len(tk.Annotations) == 0 || !strings.Contains(tk.Annotations[len(tk.Annotations)-1].Text, "config validate --fix") {
		t.Errorf("the reset is not annotated on the task: %+v", tk.Annotations)
	}
	if eventCount(t, dir) != before+1 {
		t.Errorf("events %d → %d, want one status-change row", before, eventCount(t, dir))
	}
	if len(rep.Fixed) != 1 || !strings.Contains(rep.Fixed[0], `"finished"`) {
		t.Errorf("Fixed = %q", rep.Fixed)
	}
	if audited(t, dir, 1) == 0 {
		t.Error("the reset left no row in the audit trail")
	}
}

// The probe is repeated just before the write: a run that started in between
// gets a plan nobody rewrote.
func TestFixDropsTheRepairWhenARunStartsMeanwhile(t *testing.T) {
	started := time.Now().Add(-time.Hour)
	dir := newProject(t, "running", task(1, "interrupted", pm.TaskInProgress, &started))
	calls := stubProbe(t, dead, live)

	rep := validate(t, dir, true)

	if *calls != 2 {
		t.Fatalf("probe asked %d times, want before and again just before writing", *calls)
	}
	st := load(t, dir)
	if got := taskByID(t, st, 1).Status; got != pm.TaskInProgress || st.Status != "running" {
		t.Fatalf("task = %q, status = %q: the repair was written over a run that had started", got, st.Status)
	}
	if len(rep.Fixed) != 0 || len(findings(rep, SeverityWarn, "started while the repair was being prepared")) != 1 {
		t.Fatalf("fixed %q, findings %+v", rep.Fixed, rep.Findings)
	}
}

// Without --fix nothing is written, and an in-progress task is reported for
// what it is: work in hand while a run is live, debris when none is.
func TestValidateReportsInProgressTasksByWhetherARunIsLive(t *testing.T) {
	started := time.Now().Add(-time.Hour)
	dir := newProject(t, "running", task(1, "in hand", pm.TaskInProgress, &started))

	stubProbe(t, live)
	rep := validate(t, dir, false)
	if len(findings(rep, SeverityWarn, "")) != 0 || len(findings(rep, SeverityInfo, "is in progress")) != 1 {
		t.Errorf("beside a live run: %+v; want one info finding and no warning", rep.Findings)
	}

	stubProbe(t, dead)
	rep = validate(t, dir, false)
	inProgress := findings(rep, SeverityWarn, "no run of this project is live")
	stale := findings(rep, SeverityWarn, `status is "running"`)
	if len(inProgress) != 1 || inProgress[0].FixNote == "" || len(stale) != 1 {
		t.Errorf("after a dead run: %+v; want the task and the status reported, with fix notes", rep.Findings)
	}
	if got := taskByID(t, load(t, dir), 1).Status; got != pm.TaskInProgress {
		t.Fatalf("validating without --fix changed task 1 to %q", got)
	}
}

// Run reaches the same check through the session-aware database path.
func TestRunFixesTheProjectsDatabase(t *testing.T) {
	started := time.Now().Add(-time.Hour)
	dir := newProject(t, "running", task(1, "interrupted", pm.TaskInProgress, &started))
	stubProbe(t, dead)

	rep, err := Run(context.Background(), dir, ValidateOptions{Fix: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := taskByID(t, load(t, dir), 1).Status; got != pm.TaskPending {
		t.Fatalf("task 1 = %q after Run --fix, want pending (findings %+v)", got, rep.Findings)
	}
}

// assertAuditedFinish checks the trail recorded each task leaving execution.
func assertAuditedFinish(t *testing.T, dir string, ids ...int) {
	t.Helper()
	db, err := sql.Open("sqlite", state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, id := range ids {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type = 'task.finish' AND entity_id = ?`,
			id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Errorf("task %d: no task.finish row in the audit trail", id)
		}
	}
}

func audited(t *testing.T, dir string, id int) int {
	t.Helper()
	db, err := sql.Open("sqlite", state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE entity_type = 'task' AND entity_id = ?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
