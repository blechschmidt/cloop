package state

// taskmerge.go keeps edits to a task that another process made while this one
// held the plan in memory (Task 20349).
//
// A running orchestrator holds the whole plan and calls Save dozens of times
// per task, and Save upserts every column of every task it holds. An edit made
// meanwhile to a task the run already knew — a new description or dependency
// from the dashboard's edit modal, a tag from `cloop task edit`, a priority
// from a drag — was written back over by the run's stale copy, usually as the
// task it was working on finished. Only newly created task IDs survived.
//
// So each ProjectState remembers every task's definition fields as it last read
// or wrote them, and before saving (and when syncing) it merges three ways,
// field by field: a field this process left alone but another process changed
// takes the other process's value; a field this process changed keeps its own,
// whatever happened on disk. Neither side's edit is lost unless both edited the
// same field, and then the process saving last keeps its own.
//
// Only definition fields are merged. Status, timestamps, results, counters and
// annotations belong to whoever is executing the task, and taking them from
// disk would let a writer holding a stale copy undo what a worker just
// recorded. Those still go through the kill-request and reset paths built for
// them.

import (
	"reflect"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// definitionFields are the pm.Task fields a person edits, as opposed to the
// ones the executing run writes. The names must match pm.Task's fields;
// TestDefinitionFieldsExist pins that.
var definitionFields = []string{
	"Title", "Description", "Priority", "Role", "DependsOn", "Deadline",
	"EstimatedMinutes", "Tags", "Condition", "Recurrence", "RequiresApproval",
	"Approved", "MaxMinutes", "Assignee", "ExternalURL", "Links", "Pinned",
	"SprintID", "ComplexitySize", "StoryPoints", "OnSuccess", "OnFailure",
	"RiskScore", "ImpactScore", "RetryBudget", "GitHubIssue",
}

// definitionIndex holds each definition field's index in pm.Task, resolved
// once: the snapshot runs on every load, and the dashboard loads state on every
// request.
var definitionIndex = func() [][]int {
	ty := reflect.TypeOf(pm.Task{})
	out := make([][]int, 0, len(definitionFields))
	for _, name := range definitionFields {
		if f, ok := ty.FieldByName(name); ok {
			out = append(out, f.Index)
		}
	}
	return out
}()

// snapshotDefinitions returns every task's definition fields, copied, keyed by
// ID: the base the next three-way merge compares against. Only those fields are
// copied — a task's annotations and results can run to kilobytes, and the
// merge never looks at them.
func snapshotDefinitions(plan *pm.Plan) map[int]*pm.Task {
	if plan == nil {
		return nil
	}
	out := make(map[int]*pm.Task, len(plan.Tasks))
	for _, t := range plan.Tasks {
		if t != nil {
			out[t.ID] = definitionCopy(t)
		}
	}
	return out
}

// definitionCopy returns a task carrying only t's ID and definition fields,
// with no slice or pointer shared with t.
func definitionCopy(t *pm.Task) *pm.Task {
	c := &pm.Task{ID: t.ID}
	src := reflect.ValueOf(t).Elem()
	dst := reflect.ValueOf(c).Elem()
	for _, idx := range definitionIndex {
		dst.FieldByIndex(idx).Set(cloneValue(src.FieldByIndex(idx)))
	}
	return c
}

// cloneValue copies a field value so the copy shares no backing storage.
// Definition fields are scalars, strings, slices of scalars or of flat structs,
// and a time pointer, so one level is deep enough.
func cloneValue(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		c := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		reflect.Copy(c, v)
		return c
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		c := reflect.New(v.Type().Elem())
		c.Elem().Set(v.Elem())
		return c
	}
	return v
}

// mergeDefinitions adopts into s's tasks every definition field another
// process changed on disk while s left it alone, and records the adoption in
// s's base so a later edit of the same field is recognised too. Tasks s has no
// base for — created in memory since the last load — keep their own values.
func (s *ProjectState) mergeDefinitions(disk map[int]*pm.Task) {
	if s.Plan == nil || len(s.base) == 0 {
		return
	}
	for _, ours := range s.Plan.Tasks {
		if ours == nil {
			continue
		}
		base, known := s.base[ours.ID]
		theirs, onDisk := disk[ours.ID]
		if !known || !onDisk || base == nil || theirs == nil {
			continue
		}
		ov := reflect.ValueOf(ours).Elem()
		tv := reflect.ValueOf(theirs).Elem()
		bv := reflect.ValueOf(base).Elem()
		for _, idx := range definitionIndex {
			o, t, b := ov.FieldByIndex(idx), tv.FieldByIndex(idx), bv.FieldByIndex(idx)
			if !sameFieldValue(o, b) || sameFieldValue(t, b) {
				// Ours changed it (ours wins), or nobody did.
				continue
			}
			o.Set(cloneValue(t))
			b.Set(cloneValue(t))
		}
	}
}

// sameFieldValue compares two field values the way they persist: nil and empty
// slices are the same thing on disk, and a time is compared as an instant
// rather than by its in-memory representation.
func sameFieldValue(a, b reflect.Value) bool {
	switch a.Kind() {
	case reflect.Slice:
		if a.Len() == 0 && b.Len() == 0 {
			return true
		}
	case reflect.Pointer:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() == b.IsNil()
		}
		if ta, ok := a.Interface().(*time.Time); ok {
			return ta.Equal(*b.Interface().(*time.Time))
		}
	}
	return reflect.DeepEqual(a.Interface(), b.Interface())
}
