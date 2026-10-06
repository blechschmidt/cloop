package statedb

// A column this binary does not know survives every write it makes (Task 20388).
//
// A nullable or defaulted ADD COLUMN is recorded additive, so a binary that
// predates it keeps opening the database, on the grounds that such a binary
// "neither selects nor inserts the new one". That held for its reads and its
// INSERTs, and not for three of its writes. SaveState emptied plan_tasks and
// re-inserted the plan, PutCIExchange wrote INSERT OR REPLACE, and
// ReplaceQuotaGauges deleted the gauge rows before inserting them again. Each
// of those resets every column the writer does not know to its default, on
// every write. On this deployment it was live: the long-lived run driving the
// cloop project is a build that knows migrations up to 0053, and each of its
// saves erased the thirteen task columns 0054 added.
//
// Each test below gives a table a column no build knows, standing in for the
// next migration, sets values in it, and then writes through the path an
// older binary takes. The values have to survive, and rows that are meant to
// go still have to go.

import (
	"fmt"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// futureColumn is the column a newer build added and this one does not know.
const futureColumn = "from_a_newer_build"

// addFutureColumn appends futureColumn to table, in the shape the classifier
// accepts as an additive migration.
func addFutureColumn(t *testing.T, db *DB, table string) {
	t.Helper()
	if _, err := db.conn.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + futureColumn +
		` TEXT NOT NULL DEFAULT ''`); err != nil {
		t.Fatalf("add %s.%s: %v", table, futureColumn, err)
	}
}

// futureTaskValues reads futureColumn for every plan_tasks row, by id.
func futureTaskValues(t *testing.T, db *DB) map[int]string {
	t.Helper()
	rows, err := db.conn.Query(`SELECT id, ` + futureColumn + ` FROM plan_tasks ORDER BY id`)
	if err != nil {
		t.Fatalf("read %s: %v", futureColumn, err)
	}
	defer rows.Close()
	out := map[int]string{}
	for rows.Next() {
		var (
			id int
			v  string
		)
		if err := rows.Scan(&id, &v); err != nil {
			t.Fatalf("scan %s: %v", futureColumn, err)
		}
		out[id] = v
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read %s: %v", futureColumn, err)
	}
	return out
}

// wantFutureValues fails unless the plan_tasks rows are exactly want: the
// same ids, each holding the value given.
func wantFutureValues(t *testing.T, db *DB, after string, want map[int]string) {
	t.Helper()
	got := futureTaskValues(t, db)
	for id, v := range want {
		g, ok := got[id]
		switch {
		case !ok:
			t.Errorf("after %s: task %d has no row", after, id)
		case g != v:
			t.Errorf("after %s: task %d's %s = %q, want %q — a write by a binary that does not "+
				"know the column reset it", after, id, futureColumn, g, v)
		}
	}
	for id := range got {
		if _, ok := want[id]; !ok {
			t.Errorf("after %s: task %d still has a row, want it deleted", after, id)
		}
	}
}

func futureTask(id int, title string, status pm.TaskStatus) *pm.Task {
	return &pm.Task{ID: id, Title: title, Description: "do " + title, Priority: id, Status: status}
}

func TestSaveStateKeepsColumnsItDoesNotKnow(t *testing.T) {
	db := openTestDB(t)
	plan := &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		futureTask(1, "one", pm.TaskDone),
		futureTask(2, "two", pm.TaskInProgress),
		futureTask(3, "three", pm.TaskPending),
		futureTask(4, "four", pm.TaskPending),
	}}
	save := func(what string) {
		t.Helper()
		if err := db.SaveState(&State{Goal: "g", PMMode: true, Plan: plan}); err != nil {
			t.Fatalf("SaveState (%s): %v", what, err)
		}
	}
	save("seed")

	addFutureColumn(t, db, "plan_tasks")
	if _, err := db.conn.Exec(`UPDATE plan_tasks SET ` + futureColumn + ` = 'kept by ' || id`); err != nil {
		t.Fatalf("set %s: %v", futureColumn, err)
	}
	want := map[int]string{1: "kept by 1", 2: "kept by 2", 3: "kept by 3", 4: "kept by 4"}

	// A save that changes a known column must still change it. The fix is an
	// upsert of the known columns, not a save that leaves rows alone.
	plan.Tasks[1].Status = pm.TaskDone
	plan.Tasks[1].Result = "finished"
	plan.Tasks[0].Title = "one, renamed"
	save("an edit")
	wantFutureValues(t, db, "an edit", want)
	if got, err := db.LoadTask(2); err != nil || got.Status != pm.TaskDone || got.Result != "finished" {
		t.Fatalf("after an edit: task 2 = %+v, %v; want the edit stored", got, err)
	}
	if got, err := db.LoadTask(1); err != nil || got.Title != "one, renamed" {
		t.Fatalf("after an edit: task 1 = %+v, %v; want the new title", got, err)
	}

	save("an unchanged re-save")
	wantFutureValues(t, db, "an unchanged re-save", want)

	// Deletion still deletes: the row of a task the plan no longer carries goes,
	// and only that row.
	plan.Tasks = append(plan.Tasks[:2], plan.Tasks[3])
	save("a deletion")
	delete(want, 3)
	wantFutureValues(t, db, "a deletion", want)

	// A new task starts from the column's default, and so does a new task that
	// reuses a deleted one's id: the deleted row's value went with it.
	plan.Tasks = append(plan.Tasks, futureTask(5, "five", pm.TaskPending), futureTask(3, "three again", pm.TaskPending))
	save("an addition")
	want[5], want[3] = "", ""
	wantFutureValues(t, db, "an addition", want)

	// The single-task writers.
	edited := *plan.TaskByID(4)
	edited.Status = pm.TaskFailed
	if err := db.UpsertTask(&edited); err != nil {
		t.Fatalf("UpsertTask: %v", err)
	}
	wantFutureValues(t, db, "UpsertTask", want)
	if err := db.DeleteTask(5); err != nil {
		t.Fatalf("DeleteTask: %v", err)
	}
	delete(want, 5)
	wantFutureValues(t, db, "DeleteTask", want)

	// A nil plan means "no plan loaded", not "plan emptied": nothing is
	// deleted and nothing is rewritten.
	if err := db.SaveState(&State{Goal: "g", PMMode: true}); err != nil {
		t.Fatalf("SaveState with no plan: %v", err)
	}
	wantFutureValues(t, db, "a save with no plan", want)

	// An emptied plan is a non-nil plan with no tasks, and it still empties
	// the table.
	plan.Tasks = nil
	save("emptying the plan")
	wantFutureValues(t, db, "emptying the plan", map[int]string{})
}

// TestSaveStateStillAuditsWhatChanged keeps the delta SaveState reports the
// same now that it no longer rewrites every row: the fingerprint diff runs
// before the write, and a task that disappeared is still reported as deleted.
func TestSaveStateStillAuditsWhatChanged(t *testing.T) {
	db := openTestDB(t)
	plan := &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		futureTask(1, "one", pm.TaskPending),
		futureTask(2, "two", pm.TaskPending),
		futureTask(3, "three", pm.TaskPending),
	}}
	if _, _, _, err := db.saveStateLocked(&State{Goal: "g", Plan: plan}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	plan.Tasks[0].Title = "one, renamed"
	plan.Tasks = plan.Tasks[:2]
	changed, deleted, _, err := db.saveStateLocked(&State{Goal: "g", Plan: plan})
	if err != nil {
		t.Fatalf("saveStateLocked: %v", err)
	}
	if len(changed) != 1 || changed[0].Task.ID != 1 {
		t.Errorf("changed = %v, want only task 1", changedIDs(changed))
	}
	if len(deleted) != 1 || deleted[0] != 3 {
		t.Errorf("deleted = %v, want [3]", deleted)
	}
}

func changedIDs(c []taskAuditChange) []int {
	out := make([]int, 0, len(c))
	for _, ch := range c {
		out = append(out, ch.Task.ID)
	}
	return out
}

func TestPutCIExchangeKeepsColumnsItDoesNotKnow(t *testing.T) {
	db := openTestDB(t)
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	put := func(row CIExchangeRow) {
		t.Helper()
		if err := db.PutCIExchange(row); err != nil {
			t.Fatalf("PutCIExchange(%s): %v", row.ID, err)
		}
	}
	put(CIExchangeRow{ID: "x1", At: at, Reason: "no_rule", Detail: "no rule matched"})

	addFutureColumn(t, db, "ci_exchanges")
	if _, err := db.conn.Exec(`UPDATE ci_exchanges SET ` + futureColumn + ` = 'kept'`); err != nil {
		t.Fatalf("set %s: %v", futureColumn, err)
	}

	// The same exchange written again, as a retried record of one attempt is.
	put(CIExchangeRow{ID: "x1", At: at, Accepted: true, Reason: "accepted", Detail: "rule r1"})
	put(CIExchangeRow{ID: "x2", At: at.Add(time.Minute), Reason: "no_rule"})

	got := map[string]string{}
	rows, err := db.conn.Query(`SELECT id, ` + futureColumn + ` FROM ci_exchanges`)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, v string
		if err := rows.Scan(&id, &v); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[id] = v
	}
	if got["x1"] != "kept" {
		t.Errorf("x1's %s = %q after it was written again, want %q", futureColumn, got["x1"], "kept")
	}
	if v, ok := got["x2"]; !ok || v != "" {
		t.Errorf("x2's %s = %q (present %v), want the default", futureColumn, v, ok)
	}

	list, err := db.ListCIExchanges(10)
	if err != nil {
		t.Fatalf("ListCIExchanges: %v", err)
	}
	for _, r := range list {
		if r.ID == "x1" && (!r.Accepted || r.Reason != "accepted" || r.Detail != "rule r1") {
			t.Errorf("x1 = %+v, want the second write's known columns", r)
		}
	}
}

func TestReplaceQuotaGaugesKeepsColumnsItDoesNotKnow(t *testing.T) {
	db := openTestDB(t)
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	gauge := func(identity, resource string, v float64) QuotaCounterRow {
		return QuotaCounterRow{Identity: identity, Resource: resource, Value: v, UpdatedAt: at}
	}
	if err := db.ReplaceQuotaGauges([]QuotaCounterRow{
		gauge("alice", "runs", 2), gauge("bob", "runs", 1), gauge("carol", "executors", 1),
	}); err != nil {
		t.Fatalf("seed gauges: %v", err)
	}
	// A daily counter, which a gauge replacement must not touch at all.
	if err := db.PutQuotaCounter(QuotaCounterRow{Identity: "alice", Resource: "tokens",
		Bucket: "2026-10-06", Value: 500, UpdatedAt: at}); err != nil {
		t.Fatalf("PutQuotaCounter: %v", err)
	}

	addFutureColumn(t, db, "quota_counters")
	if _, err := db.conn.Exec(`UPDATE quota_counters SET ` + futureColumn +
		` = 'kept by ' || identity || '/' || resource`); err != nil {
		t.Fatalf("set %s: %v", futureColumn, err)
	}

	if err := db.ReplaceQuotaGauges([]QuotaCounterRow{
		gauge("alice", "runs", 5), gauge("carol", "executors", 1), gauge("dave", "runs", 1),
		gauge("erin", "runs", 0), // nothing held: no row
	}); err != nil {
		t.Fatalf("ReplaceQuotaGauges: %v", err)
	}

	type key struct{ identity, resource, bucket string }
	type val struct {
		value  float64
		future string
	}
	got := map[key]val{}
	rows, err := db.conn.Query(`SELECT identity, resource, bucket, value, ` + futureColumn + ` FROM quota_counters`)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			k key
			v val
		)
		if err := rows.Scan(&k.identity, &k.resource, &k.bucket, &v.value, &v.future); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[k] = v
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read: %v", err)
	}
	want := map[key]val{
		{"alice", "runs", ""}:             {5, "kept by alice/runs"},
		{"carol", "executors", ""}:        {1, "kept by carol/executors"},
		{"dave", "runs", ""}:              {1, ""},
		{"alice", "tokens", "2026-10-06"}: {500, "kept by alice/tokens"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("quota_counters after a gauge replacement:\n got  %v\n want %v", got, want)
	}
}
