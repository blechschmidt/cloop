package statedb

// The requirements a task implements (Task 20460): stored in plan_tasks'
// requirements column, read back as written, refused when damaged, and taken
// out of every task by the deletion of the requirement.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
)

func linkedPlan(links ...[]int) *State {
	plan := &pm.Plan{Goal: "g"}
	for i, l := range links {
		plan.Tasks = append(plan.Tasks, &pm.Task{ID: i + 1, Title: fmt.Sprintf("task %d", i+1), Status: pm.TaskPending,
			Requirements: l})
	}
	return &State{Goal: "g", Plan: plan}
}

func taskLinks(t *testing.T, db *DB) map[int][]int {
	t.Helper()
	st, err := db.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	out := map[int][]int{}
	for _, task := range st.Plan.Tasks {
		out[task.ID] = task.Requirements
	}
	return out
}

// TestTaskRequirementsRoundTrip: a task's links come back as saved through
// every read path, and a task that names none reads back as naming none.
func TestTaskRequirementsRoundTrip(t *testing.T) {
	db := openFresh(t)
	if err := db.SaveState(linkedPlan([]int{3, 5}, nil, []int{})); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	links := taskLinks(t, db)
	if fmt.Sprint(links[1]) != "[3 5]" || len(links[2]) != 0 || len(links[3]) != 0 {
		t.Fatalf("links read back as %v", links)
	}
	one, err := db.LoadTask(1)
	if err != nil || fmt.Sprint(one.Requirements) != "[3 5]" {
		t.Fatalf("LoadTask(1) = %+v, %v", one, err)
	}
	lite, err := db.LoadStateLite()
	if err != nil || fmt.Sprint(lite.Plan.TaskByID(1).Requirements) != "[3 5]" {
		t.Fatalf("LoadStateLite: %v", err)
	}
	if b, _ := json.Marshal(lite.Plan.TaskByID(2)); strings.Contains(string(b), "requirements") {
		t.Errorf("a task that implements nothing says so in JSON: %s", b)
	}

	// UpsertTask, the single-task writer, keeps them too.
	one.Requirements = []int{7}
	if err := db.UpsertTask(one); err != nil {
		t.Fatal(err)
	}
	if got := taskLinks(t, db)[1]; fmt.Sprint(got) != "[7]" {
		t.Errorf("after UpsertTask, task 1 implements %v", got)
	}
}

// TestADamagedRequirementsListIsRefused: the list is the task's contract, and
// "unreadable" read as "none" would hand the agent the task without it — so
// the load fails and names the row, as for depends_on.
func TestADamagedRequirementsListIsRefused(t *testing.T) {
	db := openFresh(t)
	if err := db.SaveState(linkedPlan([]int{3})); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`[3,`, `["R-3"]`, `{"id":3}`} {
		if _, err := db.conn.Exec(`UPDATE plan_tasks SET requirements = ? WHERE id = 1`, bad); err != nil {
			t.Fatal(err)
		}
		_, err := db.LoadState()
		if !errors.Is(err, ErrCorruptTaskColumn) || !strings.Contains(err.Error(), "task 1: column requirements") {
			t.Errorf("a requirements column of %s loads with %v, want ErrCorruptTaskColumn naming the row", bad, err)
		}
	}
}

// TestDeletingARequirementUnlinksItsTasks: the deletion takes the requirement
// out of every task that implements it in its own transaction, says which in
// its audit row, and records each task's change under the same actor — once:
// the next save of an unchanged plan adds no task row of its own.
func TestDeletingARequirementUnlinksItsTasks(t *testing.T) {
	db := openFresh(t)
	r1 := addReq(t, db, "kept", "go test ./a")
	r2 := addReq(t, db, "deleted")
	if err := db.SaveState(linkedPlan([]int{r1.ID, r2.ID}, []int{r2.ID}, []int{r1.ID}, nil)); err != nil {
		t.Fatal(err)
	}
	upserts := auditCount(t, db, auditaction.ActionTaskUpsert)

	if _, _, err := db.DeleteRequirement(r2.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	links := taskLinks(t, db)
	if fmt.Sprint(links[1]) != fmt.Sprint([]int{r1.ID}) || len(links[2]) != 0 || fmt.Sprint(links[3]) != fmt.Sprint([]int{r1.ID}) ||
		len(links[4]) != 0 {
		t.Fatalf("after deleting R-%d the tasks implement %v", r2.ID, links)
	}

	rows, _, err := db.ListAuditEvents(AuditFilter{EventType: string(auditaction.ActionRequirementDelete)})
	if err != nil || len(rows) != 1 {
		t.Fatalf("requirement.delete rows: %d, %v", len(rows), err)
	}
	var payload struct {
		Unlinked []int `json:"unlinked_tasks"`
	}
	if err := json.Unmarshal([]byte(rows[0].Payload), &payload); err != nil || fmt.Sprint(payload.Unlinked) != "[1 2]" {
		t.Errorf("the deletion's row says it unlinked %v (%v): %s", payload.Unlinked, err, rows[0].Payload)
	}
	tasks, _, err := db.ListAuditEvents(AuditFilter{EventType: string(auditaction.ActionTaskUpsert)})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(tasks) - upserts; got != 2 {
		t.Fatalf("the deletion recorded %d task changes, want one for each of the 2 tasks it unlinked", got)
	}
	for _, ev := range tasks[len(tasks)-2:] {
		if ev.Actor != "alice" || (ev.EntityID != "1" && ev.EntityID != "2") {
			t.Errorf("task row %+v: want task 1 or 2, by alice", ev)
		}
	}

	// A save of the plan as it now is: nothing more to record.
	st, err := db.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveState(st); err != nil {
		t.Fatal(err)
	}
	if got := auditCount(t, db, auditaction.ActionTaskUpsert) - upserts; got != 2 {
		t.Errorf("the next save recorded the unlinking again: %d task rows since the deletion", got)
	}

	// A requirement nobody implements goes alone.
	if _, _, err := db.DeleteRequirement(r1.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	if links := taskLinks(t, db); len(links[1]) != 0 || len(links[3]) != 0 {
		t.Errorf("after deleting R-%d the tasks implement %v", r1.ID, links)
	}
}

// TestSeedRequirementsKeepTheirIDs: a device's database receives the
// requirements a seed carries under the ids the hub's tasks name.
func TestSeedRequirementsKeepTheirIDs(t *testing.T) {
	db := openFresh(t)
	seed := []requirements.Requirement{
		{ID: 4, Title: "four", Tests: []requirements.Test{{Command: "true"}}},
		{ID: 9, Title: "nine", Status: requirements.StatusDraft},
	}
	if err := db.SeedRequirements(seed); err != nil {
		t.Fatal(err)
	}
	got, err := db.Requirements()
	if err != nil || len(got) != 2 || got[0].ID != 4 || got[1].ID != 9 || got[1].Status != requirements.StatusDraft ||
		len(got[0].Tests) != 1 {
		t.Fatalf("seeded requirements read back as %+v, %v", got, err)
	}
	// Again, changed: the definition is replaced in place.
	seed[0].Title = "four, again"
	if err := db.SeedRequirements(seed[:1]); err != nil {
		t.Fatal(err)
	}
	if r, err := db.Requirement(4); err != nil || r.Title != "four, again" {
		t.Errorf("R-4 after a second seed: %+v, %v", r, err)
	}
	// A requirement added afterwards does not take a seeded id.
	if r := addReq(t, db, "added"); r.ID != 10 {
		t.Errorf("a requirement added after the seed got id %d, want 10", r.ID)
	}
	for _, bad := range [][]requirements.Requirement{{{ID: 0, Title: "no id"}}, {{ID: 1, Title: ""}}} {
		if err := db.SeedRequirements(bad); err == nil {
			t.Errorf("SeedRequirements(%+v) was accepted", bad)
		}
	}
}

// TestAnImportThatDeletesARequirementUnlinksItsTasks: a requirement the spec
// file no longer has is deleted by the import as DeleteRequirement deletes
// one — taken out of every task in the same transaction, the import's row
// naming the tasks, each task's change recorded under the importer.
func TestAnImportThatDeletesARequirementUnlinksItsTasks(t *testing.T) {
	db := openFresh(t)
	hub := exported(t, db, "one", "two")
	if err := db.SaveState(linkedPlan([]int{1, 2}, []int{2})); err != nil {
		t.Fatal(err)
	}
	upserts := auditCount(t, db, auditaction.ActionTaskUpsert)

	// The file dropped R-2.
	res, err := db.ImportRequirementSpec(RequirementSpecImport{File: hub[:1],
		Sync: RequirementSpecSync{Actor: "carol", Source: "cli", Path: requirements.SpecFileName, SHA256: "bb"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Unlinked[2]) != 2 {
		t.Fatalf("the import unlinked %v", res.Unlinked)
	}
	if links := taskLinks(t, db); fmt.Sprint(links[1]) != "[1]" || len(links[2]) != 0 {
		t.Fatalf("after the import the tasks implement %v", links)
	}
	rows, _, err := db.ListAuditEvents(AuditFilter{EventType: string(auditaction.ActionRequirementImport)})
	if err != nil || len(rows) != 1 || !strings.Contains(rows[0].Payload, `"unlinked_tasks":[1,2]`) {
		t.Fatalf("the import's row: %v %+v", err, rows)
	}
	tasks, _, err := db.ListAuditEvents(AuditFilter{EventType: string(auditaction.ActionTaskUpsert)})
	if err != nil || len(tasks)-upserts != 2 || tasks[len(tasks)-1].Actor != "carol" {
		t.Fatalf("task rows after the import: %d new, %v", len(tasks)-upserts, err)
	}
}
