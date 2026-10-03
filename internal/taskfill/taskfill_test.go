package taskfill

import (
	"reflect"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// TestTaskSetsEveryField: a field Task leaves zero is a field every test built
// on it stops checking, which is the gap the package exists to close.
func TestTaskSetsEveryField(t *testing.T) {
	task := Task(3)
	v := reflect.ValueOf(task).Elem()
	for _, name := range Fields() {
		if v.FieldByName(name).IsZero() {
			t.Errorf("Task left %s zero", name)
		}
	}
	if task.ID != 3 {
		t.Errorf("ID = %d, want 3", task.ID)
	}
}

// TestTasksDifferInEveryField: two task numbers give different values in every
// field but the bools, so a round trip that hands back another task's value is
// caught. A bool has only one non-zero value, so every task agrees on those.
func TestTasksDifferInEveryField(t *testing.T) {
	ty := reflect.TypeOf(pm.Task{})
	var want []string
	for _, name := range Fields() {
		if f, _ := ty.FieldByName(name); f.Type.Kind() != reflect.Bool {
			want = append(want, name)
		}
	}
	if got := Diff(Task(1), Task(2)); !reflect.DeepEqual(got, want) {
		t.Errorf("Task(1) and Task(2) differ in %v, want %v", got, want)
	}
	if d := Diff(Task(1), Task(1)); len(d) != 0 {
		t.Errorf("Task(1) differs from itself in %v", d)
	}
}

// TestDiffComparesAsAStoreReturnsValues: a time in another location is the same
// instant, and an empty slice is the same as none — but a different instant or
// a different element is a difference.
func TestDiffComparesAsAStoreReturnsValues(t *testing.T) {
	want := Task(1)
	got := Task(1)
	got.CompletedAt = ptr(want.CompletedAt.In(time.FixedZone("x", 3600)))
	want.Tags, got.Tags = nil, []string{}
	if d := Diff(want, got); len(d) != 0 {
		t.Errorf("equivalent tasks differ in %v", d)
	}

	got.CompletedAt = ptr(want.CompletedAt.Add(time.Nanosecond))
	got.Links[0].Label = "other"
	got.ChainInput = ""
	if d := Diff(want, got, "ChainInput"); !reflect.DeepEqual(d, []string{"CompletedAt", "Links"}) {
		t.Errorf("Diff = %v, want [CompletedAt Links]", d)
	}
}

func ptr(t time.Time) *time.Time { return &t }

// TestFieldsMatchesTheStruct guards the helper the other tests iterate with.
func TestFieldsMatchesTheStruct(t *testing.T) {
	if n := len(Fields()); n != reflect.TypeOf(pm.Task{}).NumField() {
		t.Errorf("Fields has %d names for a struct of %d fields; an unexported field appeared?",
			n, reflect.TypeOf(pm.Task{}).NumField())
	}
}
