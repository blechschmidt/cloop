package statedb

// Every pm.Task field survives the database (Task 20361).
//
// statedb's writer and readers listed plan_tasks' columns by hand, and
// fourteen pm.Task fields were missing from all three lists for as long as
// state has lived in SQLite. Each feature that set one worked until the next
// load. The tests that should have noticed named the fields they set, and a
// field nobody knew was missing is the one nobody set — so this test sets all
// of them, by reflection, including the next one somebody adds.

import (
	"reflect"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/taskfill"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// notPlanTaskColumns are the pm.Task fields that are deliberately not stored
// as plan_tasks columns, each with where its value comes from instead. Adding
// a field here needs that answer; "it is not important" is how the fourteen
// were lost.
var notPlanTaskColumns = map[string]string{
	"RunID": "task_runs, keyed by task id and maintained by SaveState's lifecycle diff (Task " +
		"20282); the readers join it in, and UpsertTask, which runs no lifecycle diff, leaves it alone",
	"ChainInput": "derived: a copy of the chained predecessor's output, up to 16 MiB, which the " +
		"orchestrator reads again when it dispatches the chained task (ensureChainInput) rather " +
		"than rewriting it into every save",
	"Stop": "transient: set by whoever settles a run for the one save that records the end (Task 20405), " +
		"and read by that save's task.finish row; the durable account is the note written beside it, " +
		"which Annotations keeps",
	"Quarantine": "task_quarantine, written only by the failover that marks a suspected node killer and " +
		"deleted only by the explicit reset that releases it (Task 20391); the readers join it in, and " +
		"neither SaveState nor UpsertTask writes it, so a run saving a copy loaded before the mark can " +
		"neither erase it nor write one back (TestQuarantineSurvivesAStaleSave)",
}

// TestEveryTaskFieldSurvivesTheDatabase saves a task with every field set and
// reads it back through each read path, after each write path.
func TestEveryTaskFieldSurvivesTheDatabase(t *testing.T) {
	skip := make([]string, 0, len(notPlanTaskColumns))
	for name := range notPlanTaskColumns {
		skip = append(skip, name)
	}

	check := func(t *testing.T, path string, want, got *pm.Task) {
		t.Helper()
		if got == nil {
			t.Fatalf("%s: task %d did not come back", path, want.ID)
		}
		for _, name := range taskfill.Diff(want, got, skip...) {
			t.Errorf("%s: %s = %#v, want %#v — the database does not keep it; give plan_tasks a "+
				"column (a migration, taskColumns, taskValues and newTaskScanner), or add it to "+
				"notPlanTaskColumns saying where its value comes from instead",
				path, name, field(got, name), field(want, name))
		}
	}

	t.Run("SaveState", func(t *testing.T) {
		db := openTestDB(t)
		want := taskfill.Task(1)
		other := taskfill.Task(2)
		if err := db.SaveState(&State{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{want, other}}}); err != nil {
			t.Fatalf("SaveState: %v", err)
		}
		full, err := db.LoadState()
		if err != nil {
			t.Fatalf("LoadState: %v", err)
		}
		check(t, "SaveState → LoadState", want, full.Plan.TaskByID(1))
		check(t, "SaveState → LoadState (second row)", other, full.Plan.TaskByID(2))

		lite, err := db.LoadStateLite()
		if err != nil {
			t.Fatalf("LoadStateLite: %v", err)
		}
		check(t, "SaveState → LoadStateLite", want, lite.Plan.TaskByID(1))

		one, err := db.LoadTask(2)
		if err != nil {
			t.Fatalf("LoadTask: %v", err)
		}
		check(t, "SaveState → LoadTask", other, one)
	})

	t.Run("UpsertTask", func(t *testing.T) {
		db := openTestDB(t)
		// Insert, then update over a row holding different values, so an
		// ON CONFLICT clause that forgot a column is caught as surely as an
		// INSERT that did.
		if err := db.UpsertTask(taskfill.Task(3)); err != nil {
			t.Fatalf("UpsertTask (insert): %v", err)
		}
		want := taskfill.Task(4)
		want.ID = 3
		if err := db.UpsertTask(want); err != nil {
			t.Fatalf("UpsertTask (update): %v", err)
		}
		one, err := db.LoadTask(3)
		if err != nil {
			t.Fatalf("LoadTask: %v", err)
		}
		check(t, "UpsertTask → LoadTask", want, one)

		full, err := db.LoadState()
		if err != nil {
			t.Fatalf("LoadState: %v", err)
		}
		check(t, "UpsertTask → LoadState", want, full.Plan.TaskByID(3))
	})

	t.Run("a cleared field clears", func(t *testing.T) {
		// The reverse direction: a value removed in memory must not survive
		// the next save from an earlier one.
		db := openTestDB(t)
		if err := db.SaveState(&State{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{taskfill.Task(5)}}}); err != nil {
			t.Fatalf("SaveState: %v", err)
		}
		want := &pm.Task{ID: 5, Title: "only a title", Status: pm.TaskPending}
		if err := db.SaveState(&State{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{want}}}); err != nil {
			t.Fatalf("SaveState: %v", err)
		}
		got, err := db.LoadTask(5)
		if err != nil {
			t.Fatalf("LoadTask: %v", err)
		}
		check(t, "SaveState(cleared) → LoadTask", want, got)
	})
}

// TestNotPlanTaskColumnsNamesRealFields: an exemption for a field that was
// renamed or removed is a hole nobody can see.
func TestNotPlanTaskColumnsNamesRealFields(t *testing.T) {
	ty := reflect.TypeOf(pm.Task{})
	for name, why := range notPlanTaskColumns {
		if _, ok := ty.FieldByName(name); !ok {
			t.Errorf("notPlanTaskColumns names %q, which pm.Task does not have", name)
		}
		if strings.TrimSpace(why) == "" {
			t.Errorf("notPlanTaskColumns[%q] gives no reason", name)
		}
	}
}

// TestTaskColumnsMatchTheirValues: the writer's values and the column list are
// kept in step by hand, and a mismatch would be a runtime error on every save.
func TestTaskColumnsMatchTheirValues(t *testing.T) {
	if got, want := len(taskValues(&pm.Task{})), len(taskColumns); got != want {
		t.Fatalf("taskValues gives %d values for %d columns", got, want)
	}
	seen := map[string]bool{}
	for _, c := range taskColumns {
		if seen[c] {
			t.Errorf("column %s is listed twice", c)
		}
		seen[c] = true
	}
	// Every listed column exists in a freshly migrated database, and every
	// plan_tasks column is listed — a column nothing reads is a field that
	// is written somewhere and dropped on the way back.
	db := openTestDB(t)
	rows, err := db.conn.Query(`SELECT name FROM pragma_table_info('plan_tasks')`)
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	defer rows.Close()
	inTable := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		inTable[name] = true
		if !seen[name] {
			t.Errorf("plan_tasks.%s is not in taskColumns, so nothing reads or writes it", name)
		}
	}
	for _, c := range taskColumns {
		if !inTable[c] {
			t.Errorf("taskColumns lists %s, which plan_tasks does not have", c)
		}
	}
}

func field(task *pm.Task, name string) any {
	return reflect.ValueOf(task).Elem().FieldByName(name).Interface()
}
