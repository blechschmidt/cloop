package statedb

// Tests for the JSON-encoded task columns (Tasks 20297 and 20361).
//
// These are in-package because the interesting input cannot be produced
// through the API: SaveState always writes well-formed JSON, so the only way
// to stage a damaged row is to write the column directly. That is also the
// realistic shape of the bug — the corruption arrives from a truncated write,
// a restored backup or a hand-edited database, never from the writer.

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// corruptValues are the shapes a damaged column actually takes. Each one
// decodes to a silently-empty field under the discarded-error code Task 20297
// replaced.
var corruptValues = map[string]string{
	"truncated array":  `[1,2`,
	"truncated object": `[{"a":`,
	"empty string":     ``,
	"wrong type":       `{"1":true}`,
	"garbage":          `not json at all`,
	"half written":     `[1,2,3][`,
	"null byte":        "[1,2]\x00",
	// The nastiest shape, and the reason the decode cannot simply be trusted
	// when it errors: a well-formed array with one mistyped element decodes
	// *partially*. See TestDecodeTaskColumnsRejectsPartialDeps.
	"mistyped element": `[1,2,"x"]`,
	"nested object":    `[1,2,{}]`,
}

// fatalColumns are the list columns whose loss changes what runs, so a damaged
// value must fail the load rather than read as empty.
var fatalColumns = []string{"depends_on", "on_success", "on_failure"}

// openTaskColumnsDB returns a database holding one saved task.
func openTaskColumnsDB(t *testing.T, task *pm.Task) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st := &State{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{task}}}
	if err := db.SaveState(st); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	return db
}

// damageColumn overwrites one column of one task row with a raw value,
// bypassing the encoder.
func damageColumn(t *testing.T, db *DB, taskID int, column, value string) {
	t.Helper()
	// #nosec G202 -- column is a test-supplied literal, never user input.
	if _, err := db.conn.Exec(
		fmt.Sprintf(`UPDATE plan_tasks SET %s = ? WHERE id = ?`, column), value, taskID,
	); err != nil {
		t.Fatalf("damaging %s: %v", column, err)
	}
}

// healthyRow writes well-formed values into every list column of a row, so the
// subtests below can share one database — a fresh one per subtest is a full
// migration each, which under -race is most of a second apiece.
func healthyRow(t *testing.T, db *DB, task *pm.Task) {
	t.Helper()
	if _, err := db.conn.Exec(`UPDATE plan_tasks SET depends_on = ?, on_success = ?, on_failure = ?,
		tags = ?, annotations = ?, links = ? WHERE id = ?`,
		listText(task.DependsOn), listText(task.OnSuccess), listText(task.OnFailure),
		listText(task.Tags), listText(task.Annotations), listText(task.Links), task.ID); err != nil {
		t.Fatalf("restore task %d: %v", task.ID, err)
	}
}

// TestCorruptOrderingColumnFailsTheLoad is the correctness half. A dependency
// list or a branch that cannot be read must never reach pm.DepsReady or
// pm.ResolveBranch as an empty one, because empty means "no prerequisites, may
// run now" and "nothing to skip".
func TestCorruptOrderingColumnFailsTheLoad(t *testing.T) {
	task := &pm.Task{
		ID: 7, Title: "deploy", Status: pm.TaskPending, DependsOn: []int{1, 2},
		OnSuccess: []string{"8"}, OnFailure: []string{"9"},
	}
	db := openTaskColumnsDB(t, task)
	for _, column := range fatalColumns {
		for name, bad := range corruptValues {
			t.Run(column+"/"+name, func(t *testing.T) {
				healthyRow(t, db, task)
				damageColumn(t, db, 7, column, bad)

				// Both read paths must refuse. They used to share nothing but
				// a copy-pasted decode, which is how they could have disagreed.
				if _, err := db.LoadTask(7); !errors.Is(err, ErrCorruptTaskColumn) {
					t.Errorf("LoadTask: err = %v, want ErrCorruptTaskColumn", err)
				}
				if _, err := db.LoadStateLite(); !errors.Is(err, ErrCorruptTaskColumn) {
					t.Errorf("LoadStateLite: err = %v, want ErrCorruptTaskColumn", err)
				}
				st, err := db.LoadState()
				if !errors.Is(err, ErrCorruptTaskColumn) {
					t.Fatalf("LoadState: err = %v, want ErrCorruptTaskColumn", err)
				}
				if st != nil {
					t.Errorf("LoadState returned a state alongside the error: %+v", st)
				}
				// Attributable: the message must name the row to repair.
				if msg := err.Error(); !strings.Contains(msg, "task 7") ||
					!strings.Contains(msg, column) {
					t.Errorf("error does not name task and column: %q", msg)
				}
				// And it is not mistaken for a schema problem, which would
				// send the operator to migrate a database that needs one
				// value repaired.
				if errors.Is(err, ErrSchemaMismatch) {
					t.Errorf("a damaged value classified as a schema mismatch: %v", err)
				}
			})
		}
	}
}

// TestCorruptDependsOnNeverAdmitsTheTask states the property the way the bug
// was felt: not "the decode errors" but "the task does not run early".
//
// Task 2 depends on task 1, which is still pending. Reading the plan must
// either refuse, or produce a task that DepsReady holds back — and it must
// never produce one that DepsReady waves through.
func TestCorruptDependsOnNeverAdmitsTheTask(t *testing.T) {
	task := &pm.Task{ID: 2, Title: "publish the artifact", Status: pm.TaskPending, DependsOn: []int{1}}
	db := openTaskColumnsDB(t, task)
	// The prerequisite, unfinished.
	if _, err := db.conn.Exec(
		`INSERT INTO plan_tasks(id, title, status) VALUES (1, 'build', 'pending')`,
	); err != nil {
		t.Fatalf("seeding the prerequisite: %v", err)
	}
	for name, bad := range corruptValues {
		t.Run(name, func(t *testing.T) {
			healthyRow(t, db, task)
			damageColumn(t, db, 2, "depends_on", bad)

			st, err := db.LoadState()
			if err != nil {
				return // Refused the load: the task never reaches the gate.
			}
			plan := st.Plan
			for _, task := range plan.Tasks {
				if task.ID != 2 {
					continue
				}
				if plan.DepsReady(task) {
					t.Fatalf("task 2 was admitted to run with unreadable deps %q: "+
						"its prerequisite is still pending", bad)
				}
			}
			if len(plan.ReadyTasks()) > 0 && plan.ReadyTasks()[0].ID == 2 {
				t.Fatal("task 2 is first in the run queue despite unreadable deps")
			}
		})
	}
}

// TestCorruptBranchNeverRunsTheSkippedBranch is the same property for plan
// branching: task 1 succeeded, so its on_failure task — a rollback, say — must
// not stay runnable because the branch could not be read.
func TestCorruptBranchNeverRunsTheSkippedBranch(t *testing.T) {
	task := &pm.Task{ID: 1, Title: "deploy", Status: pm.TaskDone, OnFailure: []string{"2"}}
	db := openTaskColumnsDB(t, task)
	if _, err := db.conn.Exec(
		`INSERT INTO plan_tasks(id, title, status) VALUES (2, 'roll back', 'pending')`,
	); err != nil {
		t.Fatalf("seeding the rollback: %v", err)
	}
	for name, bad := range corruptValues {
		t.Run(name, func(t *testing.T) {
			healthyRow(t, db, task)
			damageColumn(t, db, 1, "on_failure", bad)

			st, err := db.LoadState()
			if err != nil {
				return // Refused: nothing runs from a plan that cannot be read.
			}
			pm.ResolveBranch(st.Plan, st.Plan.TaskByID(1))
			if st.Plan.TaskByID(2).Status == pm.TaskPending {
				t.Fatalf("the rollback stayed runnable after a successful deploy whose "+
					"on_failure column was %q", bad)
			}
		})
	}
}

// TestCorruptDisplayColumnsDegradeAndReport is the other half of the per-field
// decision: these lose information rather than mis-sequence work, so the load
// survives — but it must not be silent.
func TestCorruptDisplayColumnsDegradeAndReport(t *testing.T) {
	healthy := &pm.Task{
		ID: 3, Title: "refactor", Status: pm.TaskPending,
		DependsOn:   []int{9},
		Tags:        []string{"backend", "security"},
		Annotations: []pm.Annotation{{Author: "ai", Text: "chose option B"}},
		Links:       []pm.Link{{URL: "https://example.com/t/1", Kind: pm.LinkKindTicket}},
	}
	db := openTaskColumnsDB(t, healthy)
	for _, column := range []string{"tags", "annotations", "links"} {
		t.Run(column, func(t *testing.T) {
			healthyRow(t, db, healthy)
			damageColumn(t, db, 3, column, `[{"truncated":`)

			var got []string
			restore := setDegradedColumnReporter(func(taskID int, col, raw string, err error) {
				got = append(got, fmt.Sprintf("%d/%s/%s/%v", taskID, col, raw, err != nil))
			})
			defer restore()

			st, err := db.LoadState()
			if err != nil {
				t.Fatalf("a damaged %s column must not fail the load: %v", column, err)
			}
			task := st.Plan.Tasks[0]

			// Degraded to empty, not left partially filled.
			switch column {
			case "tags":
				if len(task.Tags) != 0 {
					t.Errorf("tags = %v, want empty after a failed decode", task.Tags)
				}
			case "annotations":
				if len(task.Annotations) != 0 {
					t.Errorf("annotations = %v, want empty after a failed decode", task.Annotations)
				}
			case "links":
				if len(task.Links) != 0 {
					t.Errorf("links = %v, want empty after a failed decode", task.Links)
				}
			}
			// The unrelated fields on the same row still load. A damaged note
			// field must not cost the row its dependencies.
			if len(task.DependsOn) != 1 || task.DependsOn[0] != 9 {
				t.Errorf("DependsOn = %v, want [9]: the intact column was dropped too",
					task.DependsOn)
			}
			// Attributable rather than silent — the whole point of the task.
			want := fmt.Sprintf(`3/%s/[{"truncated":/true`, column)
			if len(got) != 1 || got[0] != want {
				t.Errorf("degraded-column reports = %v, want exactly [%s]", got, want)
			}
		})
	}
}

// TestDefaultReporterLogsADamagedValueOnce: the dashboard reloads a project on
// every request, and a log line per reload would bury the one that matters.
func TestDefaultReporterLogsADamagedValueOnce(t *testing.T) {
	var buf strings.Builder
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	degradedLoggedMu.Lock()
	prevLogged := degradedLogged
	degradedLogged = map[[sha256.Size]byte]struct{}{}
	degradedLoggedMu.Unlock()
	defer func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
		degradedLoggedMu.Lock()
		degradedLogged = prevLogged
		degradedLoggedMu.Unlock()
	}()

	err := errors.New("unexpected end of JSON input")
	for i := 0; i < 3; i++ {
		logDegradedColumn(424242, "tags", `["once`, err)
	}
	logDegradedColumn(424242, "tags", `["twice`, err) // a different damage is news
	if n := strings.Count(buf.String(), "task 424242: column tags"); n != 2 {
		t.Errorf("logged %d times, want 2 (once per distinct damaged value):\n%s", n, buf.String())
	}
}

// TestDecodeTaskColumnsRejectsPartialDeps guards the subtle half of the fix.
//
// A type error inside a well-formed array does not abort encoding/json: it
// records the error and keeps going, leaving behind the elements it parsed
// plus a zero for the one it could not. So `[1,2,"x"]` yields {1,2,0} *and* an
// error. Checking the error is therefore not enough on its own — the
// destination has to be discarded too, or a task ends up depending on a subset
// of its real prerequisites plus task 0, which does not exist and so is
// vacuously satisfied.
func TestDecodeTaskColumnsRejectsPartialDeps(t *testing.T) {
	const mistyped = `[1,2,"x"]`

	// Establish the hazard is real rather than hypothetical, so this test
	// keeps its meaning if the standard library ever changes.
	var direct []int
	if err := json.Unmarshal([]byte(mistyped), &direct); err == nil {
		t.Fatal("expected a decode error for a mistyped element")
	} else if len(direct) == 0 {
		t.Skipf("encoding/json no longer leaves a partial slice behind (%v)", err)
	}
	if len(direct) != 3 || direct[2] != 0 {
		t.Fatalf("precondition: raw decode of %s gave %v, want a partial [1 2 0]",
			mistyped, direct)
	}

	task := &pm.Task{ID: 4, DependsOn: []int{5, 6}}
	err := decodeTaskColumns(task, wellFormed(taskListColumns{DependsOn: mistyped}))
	if !errors.Is(err, ErrCorruptTaskColumn) {
		t.Fatalf("err = %v, want ErrCorruptTaskColumn", err)
	}
	if len(task.DependsOn) != 0 {
		t.Errorf("DependsOn = %v, want empty: the partially-decoded list leaked "+
			"through, which is the failure mode this guards", task.DependsOn)
	}

	// The same holds for a branch: `["2", 3]` decodes partially to ["2", ""].
	task = &pm.Task{ID: 4}
	err = decodeTaskColumns(task, wellFormed(taskListColumns{OnSuccess: `["2", 3]`}))
	if !errors.Is(err, ErrCorruptTaskColumn) || len(task.OnSuccess) != 0 {
		t.Errorf("on_success: err = %v, OnSuccess = %v; want ErrCorruptTaskColumn and nothing kept",
			err, task.OnSuccess)
	}
}

// wellFormed fills every column c leaves empty with an empty JSON array.
func wellFormed(c taskListColumns) taskListColumns {
	for _, f := range []*string{&c.DependsOn, &c.Tags, &c.Annotations, &c.Links, &c.OnSuccess, &c.OnFailure} {
		if *f == "" {
			*f = "[]"
		}
	}
	return c
}

// TestDecodeTaskColumnsAcceptsWellFormed keeps the strict path from becoming
// so strict that ordinary rows stop loading — including the two encodings the
// writer actually emits for an absent list.
func TestDecodeTaskColumnsAcceptsWellFormed(t *testing.T) {
	cases := map[string]taskListColumns{
		"populated": {
			DependsOn: `[1,2]`, Tags: `["a"]`, Annotations: `[{"author":"me","text":"note"}]`,
			Links: `[{"url":"https://x","kind":"doc"}]`, OnSuccess: `["3"]`, OnFailure: `["4"]`,
		},
		"empty": {DependsOn: `[]`, Tags: `[]`, Annotations: `[]`, Links: `[]`, OnSuccess: `[]`, OnFailure: `[]`},
		// What json.Marshal writes for a nil slice.
		"null": {DependsOn: `null`, Tags: `null`, Annotations: `null`, Links: `null`, OnSuccess: `null`, OnFailure: `null`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			restore := setDegradedColumnReporter(func(taskID int, col, raw string, err error) {
				t.Errorf("well-formed %s reported as degraded: %v", col, err)
			})
			defer restore()

			task := &pm.Task{ID: 1}
			if err := decodeTaskColumns(task, c); err != nil {
				t.Fatalf("decodeTaskColumns: %v", err)
			}
			if name == "populated" {
				if len(task.DependsOn) != 2 || task.DependsOn[1] != 2 {
					t.Errorf("DependsOn = %v", task.DependsOn)
				}
				if len(task.Tags) != 1 || len(task.Annotations) != 1 || len(task.Links) != 1 ||
					len(task.OnSuccess) != 1 || len(task.OnFailure) != 1 {
					t.Errorf("lists did not decode: %+v", task)
				}
			}
		})
	}
}

// TestCorruptColumnSurvivesRoundTrip: a save/load cycle of a healthy plan must
// not trip any of the new checks. The strict decode runs on every task read on
// every load, so a false positive here would be a fleet-wide outage.
func TestCorruptColumnSurvivesRoundTrip(t *testing.T) {
	restore := setDegradedColumnReporter(func(taskID int, col, raw string, err error) {
		t.Errorf("healthy task %d reported column %s as degraded: %v", taskID, col, err)
	})
	defer restore()

	db := openTaskColumnsDB(t, &pm.Task{ID: 1, Title: "no deps at all", Status: pm.TaskPending})
	// A second task carrying every shape of the list columns.
	st, err := db.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	st.Plan.Tasks = append(st.Plan.Tasks, &pm.Task{
		ID: 2, Title: "with deps", Status: pm.TaskPending,
		DependsOn:   []int{1},
		Tags:        []string{"x"},
		Annotations: []pm.Annotation{{Author: "a", Text: "t"}},
		Links:       []pm.Link{{URL: "https://example.com", Kind: pm.LinkKindDoc}},
		OnSuccess:   []string{"1"},
		OnFailure:   []string{"1"},
	})
	if err := db.SaveState(st); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	back, err := db.LoadState()
	if err != nil {
		t.Fatalf("LoadState after save: %v", err)
	}
	if len(back.Plan.Tasks) != 2 {
		t.Fatalf("got %d tasks, want 2", len(back.Plan.Tasks))
	}
	if len(back.Plan.Tasks[0].DependsOn) != 0 {
		t.Errorf("a task with no deps came back with %v", back.Plan.Tasks[0].DependsOn)
	}
	if len(back.Plan.Tasks[1].DependsOn) != 1 || len(back.Plan.Tasks[1].OnFailure) != 1 {
		t.Errorf("deps or branches did not round-trip: %+v", back.Plan.Tasks[1])
	}
	if _, err := db.LoadTask(2); err != nil {
		t.Errorf("LoadTask on a healthy row: %v", err)
	}
}
