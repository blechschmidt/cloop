package state

// An edit to a task a running process already holds must survive that
// process's next Save (Task 20349). Before, Save upserted every column of every
// task in memory, and only new task IDs made it through a live run.

import (
	"reflect"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// planProject initialises a project holding two pending tasks.
func planProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
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
