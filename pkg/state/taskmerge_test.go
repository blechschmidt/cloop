package state

// An edit to a task a running process already holds must survive that
// process's next Save (Task 20349). Before, Save upserted every column of every
// task in memory, and only new task IDs made it through a live run.

import (
	"reflect"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/internal/taskfill"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// planProject initialises a project holding two pending tasks.
func planProject(t *testing.T) string {
	t.Helper()
	dir := statedbtest.Dir(t)
	s, err := Init(dir, "goal", 0)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	s.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{
		{ID: 1, Title: "build", Description: "build it", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "ship", Description: "ship it", Priority: 2, Status: pm.TaskPending},
	}}
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return dir
}

func mustLoad(t *testing.T, dir string) *ProjectState {
	t.Helper()
	s, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return s
}

// TestEditDuringARunSurvivesTheRunsSave is the reported case: the dashboard's
// edit modal rewrites a task's description and dependencies while a run holds
// the plan, and the run's next Save — made as the task it was working on
// changes status — used to write the old values straight back.
func TestEditDuringARunSurvivesTheRunsSave(t *testing.T) {
	dir := planProject(t)
	run := mustLoad(t, dir)

	ui := mustLoad(t, dir)
	edited := ui.Plan.TaskByID(2)
	edited.Description = "ship it, with release notes"
	edited.DependsOn = []int{1}
	edited.Tags = []string{"release"}
	if err := ui.SaveDirect(); err != nil {
		t.Fatalf("the edit's SaveDirect: %v", err)
	}

	run.Plan.TaskByID(1).Status = pm.TaskInProgress
	if err := run.Save(); err != nil {
		t.Fatalf("the run's Save: %v", err)
	}

	after := mustLoad(t, dir)
	got := after.Plan.TaskByID(2)
	if got.Description != "ship it, with release notes" {
		t.Errorf("description = %q; the run's save wrote its stale copy over the edit", got.Description)
	}
	if !reflect.DeepEqual(got.DependsOn, []int{1}) || !reflect.DeepEqual(got.Tags, []string{"release"}) {
		t.Errorf("depends_on = %v, tags = %v; the edit did not survive", got.DependsOn, got.Tags)
	}
	if s := after.Plan.TaskByID(1).Status; s != pm.TaskInProgress {
		t.Errorf("task 1 = %q; the run's own change was lost", s)
	}
	// And the run's copy now holds the edit, so the prompt it builds for
	// task 2 uses the new description.
	if d := run.Plan.TaskByID(2).Description; d != "ship it, with release notes" {
		t.Errorf("the run's in-memory task 2 still reads %q", d)
	}
}

// TestTheRunPicksUpAnEditWhenItSyncs: the sync before choosing the next task
// brings in an edit to a task not yet started, so it runs as edited.
func TestTheRunPicksUpAnEditWhenItSyncs(t *testing.T) {
	dir := planProject(t)
	run := mustLoad(t, dir)

	ui := mustLoad(t, dir)
	ui.Plan.TaskByID(2).Title = "ship v2"
	if err := ui.SaveDirect(); err != nil {
		t.Fatalf("SaveDirect: %v", err)
	}

	run.SyncFromDisk()
	if got := run.Plan.TaskByID(2).Title; got != "ship v2" {
		t.Errorf("after the sync the run holds title %q, want the edit", got)
	}
}

// TestTheSaversOwnEditWinsTheSameField: when both processes changed the same
// field, the one saving keeps its own value; a field only the other changed is
// still adopted.
func TestTheSaversOwnEditWinsTheSameField(t *testing.T) {
	dir := planProject(t)
	run := mustLoad(t, dir)

	ui := mustLoad(t, dir)
	ui.Plan.TaskByID(2).Priority = 5
	ui.Plan.TaskByID(2).Tags = []string{"needs-review"}
	if err := ui.SaveDirect(); err != nil {
		t.Fatalf("SaveDirect: %v", err)
	}

	run.Plan.TaskByID(2).Priority = 1 // e.g. an overdue deadline boost
	if err := run.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	after := mustLoad(t, dir).Plan.TaskByID(2)
	if after.Priority != 1 {
		t.Errorf("priority = %d; the saving process's own change should win its own field", after.Priority)
	}
	if !reflect.DeepEqual(after.Tags, []string{"needs-review"}) {
		t.Errorf("tags = %v; a field only the other process changed should be adopted", after.Tags)
	}
}

// TestASecondEditIsAdoptedToo: an adopted value becomes the base, so an edit
// of the same field after it is recognised as another external edit rather
// than mistaken for the run's own change.
func TestASecondEditIsAdoptedToo(t *testing.T) {
	dir := planProject(t)
	run := mustLoad(t, dir)

	for _, desc := range []string{"first rewrite", "second rewrite"} {
		ui := mustLoad(t, dir)
		ui.Plan.TaskByID(2).Description = desc
		if err := ui.SaveDirect(); err != nil {
			t.Fatalf("SaveDirect: %v", err)
		}
		run.SyncFromDisk()
		if err := run.Save(); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if got := mustLoad(t, dir).Plan.TaskByID(2).Description; got != desc {
			t.Fatalf("after %q the stored description is %q", desc, got)
		}
	}
}

// TestExecutionFieldsStayTheRuns: status, results and timestamps belong to the
// process executing the task. A writer holding a stale copy must not be able
// to undo what a worker recorded by way of this merge.
func TestExecutionFieldsStayTheRuns(t *testing.T) {
	dir := planProject(t)
	run := mustLoad(t, dir)
	stale := mustLoad(t, dir)

	run.Plan.TaskByID(1).Status = pm.TaskDone
	run.Plan.TaskByID(1).Result = "built"
	if err := run.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// A stale full save, as from a copy loaded before the task finished.
	if err := stale.SaveDirect(); err != nil {
		t.Fatalf("stale SaveDirect: %v", err)
	}
	run.Plan.TaskByID(2).Status = pm.TaskInProgress
	if err := run.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	after := mustLoad(t, dir).Plan.TaskByID(1)
	if after.Status != pm.TaskDone || after.Result != "built" {
		t.Errorf("task 1 = %q / %q; the run's recorded outcome was undone by a stale copy",
			after.Status, after.Result)
	}
}

// TestDefinitionFieldsExist: every name the merge reaches for by reflection is
// a real field of pm.Task, so a rename cannot silently drop one from the merge.
func TestDefinitionFieldsExist(t *testing.T) {
	ty := reflect.TypeOf(pm.Task{})
	for _, name := range definitionFields {
		if _, ok := ty.FieldByName(name); !ok {
			t.Errorf("definitionFields names %q, which pm.Task does not have", name)
		}
	}
}

// TestDefinitionFieldsRoundTrip: every field the merge compares survives a save
// and a load. One that did not would read back as zero, which the merge takes
// for another process's edit.
func TestDefinitionFieldsRoundTrip(t *testing.T) {
	dir := planProject(t)
	s := mustLoad(t, dir)
	task := s.Plan.TaskByID(2)
	tv := reflect.ValueOf(task).Elem()
	deadline := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, name := range definitionFields {
		f := tv.FieldByName(name)
		switch {
		case f.Kind() == reflect.String:
			f.SetString("set-" + name)
		case f.CanInt():
			f.SetInt(7)
		case f.Kind() == reflect.Bool:
			f.SetBool(true)
		case f.Type() == reflect.TypeOf([]int(nil)):
			f.Set(reflect.ValueOf([]int{1}))
		case f.Type() == reflect.TypeOf([]string(nil)):
			f.Set(reflect.ValueOf([]string{"set-" + name}))
		case f.Type() == reflect.TypeOf([]pm.Link(nil)):
			f.Set(reflect.ValueOf([]pm.Link{{URL: "https://example.com/" + name, Label: name, Kind: pm.LinkKindDoc}}))
		case f.Type() == reflect.TypeOf((*time.Time)(nil)):
			f.Set(reflect.ValueOf(&deadline))
		default:
			t.Fatalf("no test value for %s (%s): add one", name, f.Type())
		}
	}
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	back := reflect.ValueOf(mustLoad(t, dir).Plan.TaskByID(2)).Elem()
	for _, name := range definitionFields {
		if !sameFieldValue(back.FieldByName(name), tv.FieldByName(name)) {
			t.Errorf("%s = %v after a save and a load, want %v: the database does not persist it",
				name, back.FieldByName(name), tv.FieldByName(name))
		}
	}
}

// TestTheRunKeepsItsOwnBranchesAcrossASync: values the running process set
// itself — the OnSuccess branch of a plan it made, an assignee — are still
// there after its own save and its next sync. Until Task 20361 the database
// dropped these fields, and this test pinned that the merge at least did not
// make that worse; now they are stored and merged like any definition field.
func TestTheRunKeepsItsOwnBranchesAcrossASync(t *testing.T) {
	dir := planProject(t)
	run := mustLoad(t, dir)
	task := run.Plan.TaskByID(1)
	task.OnSuccess = []string{"2"}
	task.Assignee = "alice"
	if err := run.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	run.SyncFromDisk()

	task = run.Plan.TaskByID(1)
	if !reflect.DeepEqual(task.OnSuccess, []string{"2"}) || task.Assignee != "alice" {
		t.Errorf("on_success = %v, assignee = %q after a sync; the run lost its own values",
			task.OnSuccess, task.Assignee)
	}
	if got := mustLoad(t, dir).Plan.TaskByID(1); !reflect.DeepEqual(got.OnSuccess, []string{"2"}) {
		t.Errorf("on_success on disk = %v; a branched plan would stop branching at the next load", got.OnSuccess)
	}
}

// TestAPlanningEditDuringARunSurvivesTheRunsSave is the case the new columns
// exist for: sprint planning, an assignment and a branch set from outside
// while a run holds the plan must outlive the run's next save, as an edited
// description already does.
func TestAPlanningEditDuringARunSurvivesTheRunsSave(t *testing.T) {
	dir := planProject(t)
	run := mustLoad(t, dir)

	ui := mustLoad(t, dir)
	edited := ui.Plan.TaskByID(2)
	edited.Assignee = "bob"
	edited.SprintID = 3
	edited.StoryPoints = 5
	edited.OnFailure = []string{"1"}
	edited.RetryBudget = 4
	edited.Links = []pm.Link{{URL: "https://tracker.example/T-7", Kind: pm.LinkKindTicket}}
	if err := ui.SaveDirect(); err != nil {
		t.Fatalf("the edit's SaveDirect: %v", err)
	}

	run.Plan.TaskByID(1).Status = pm.TaskInProgress
	if err := run.Save(); err != nil {
		t.Fatalf("the run's Save: %v", err)
	}

	got := mustLoad(t, dir).Plan.TaskByID(2)
	if got.Assignee != "bob" || got.SprintID != 3 || got.StoryPoints != 5 || got.RetryBudget != 4 ||
		!reflect.DeepEqual(got.OnFailure, []string{"1"}) || len(got.Links) != 1 {
		t.Errorf("task 2 after the run's save = %+v; the run wrote its stale copy over the edit", got)
	}
	if d := run.Plan.TaskByID(2); d.Assignee != "bob" || d.RetryBudget != 4 {
		t.Errorf("the run's in-memory task 2 did not adopt the edit: %+v", d)
	}
}

// runFields are the pm.Task fields the executing run owns: status, outcome,
// timing, counters and where it ran. They are not merged, so a writer holding a
// stale copy cannot undo what a worker recorded (see taskmerge.go). The TDD
// verdict is an outcome of the same kind — projectseed's merge takes it from
// the run that produced it — and is listed here with them.
var runFields = []string{
	"Status", "Result", "StartedAt", "CompletedAt", "VerifyRetries", "ActualMinutes",
	"ArtifactPath", "FailureDiagnosis", "FailCount", "HealAttempts", "Annotations",
	"NextRunAt", "TDDStatus", "TDDScore", "WriteBackBranch", "WriteBackCommit",
	"ExecutorID", "ExecutorKind", "Isolation", "Background", "Abort", "Review",
}

// derivedFields are not stored as themselves: RunID is read from task_runs, and
// ChainInput is rebuilt from the chained predecessor's output at dispatch.
var derivedFields = []string{"ID", "RunID", "ChainInput"}

// TestEveryTaskFieldIsClassified: a new pm.Task field has to be put on one
// side on purpose. Left off both lists, it would be written back from a
// stale copy by every save of a running process — the bug Task 20349 fixed
// for the fields it knew about.
func TestEveryTaskFieldIsClassified(t *testing.T) {
	class := map[string]string{}
	for list, names := range map[string][]string{
		"definitionFields": definitionFields, "runFields": runFields, "derivedFields": derivedFields,
	} {
		for _, name := range names {
			if prev, dup := class[name]; dup {
				t.Errorf("%s is in both %s and %s", name, prev, list)
			}
			class[name] = list
		}
	}
	for _, name := range taskfill.Fields() {
		if _, ok := class[name]; !ok {
			t.Errorf("pm.Task.%s is in none of definitionFields, runFields or derivedFields: "+
				"decide whether a run's save may write a stale copy of it back", name)
		}
		delete(class, name)
	}
	for name, list := range class {
		t.Errorf("%s names %s, which pm.Task does not have", list, name)
	}
}

// BenchmarkSnapshotDefinitions measures the copy every load takes, at the size
// of this project's own plan (~400 tasks).
func BenchmarkSnapshotDefinitions(b *testing.B) {
	plan := &pm.Plan{}
	for i := 1; i <= 400; i++ {
		plan.Tasks = append(plan.Tasks, &pm.Task{
			ID: i, Title: "a task title of ordinary length", Description: "a description",
			DependsOn: []int{i - 1}, Tags: []string{"a", "b"}, Status: pm.TaskDone,
			Annotations: make([]pm.Annotation, 20),
		})
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = snapshotDefinitions(plan)
	}
}
