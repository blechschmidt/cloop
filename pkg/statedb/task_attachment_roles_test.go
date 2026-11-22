package statedb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// Task 20511: a file attached to a task is either one of its results or an
// input file for its agent, and only the second kind is ever given to a run.

func TestTaskAttachmentRoleMigrationIsAdditive(t *testing.T) {
	m := embeddedMigration(t, 104)
	if got := classifyMigration(m.SQL); got != CompatAdditive {
		t.Fatalf("0104 classifies as %q, want additive: every older build on the host must keep opening the database", got)
	}
	if !strings.Contains(m.SQL, "task_attachments") || strings.Contains(m.SQL, "plan_tasks") {
		t.Fatal("0104 must add its column to task_attachments and touch nothing else")
	}
}

func TestInputFilesAreToldApartFromResults(t *testing.T) {
	db, dir := attachmentFixture(t, 1, 2)
	attach(t, db, dir, 1, attID(1), "report.txt") // a result, as every row was before roles
	for _, in := range []struct {
		id   string
		task int
		name string
	}{{attID(2), 1, "spec.md"}, {attID(3), 1, "data.csv"}, {attID(4), 2, "other.txt"}} {
		if err := os.WriteFile(filepath.Join(dir, in.id), []byte("hello"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := db.AddTaskAttachment(AttachmentRow{ID: in.id, TaskID: in.task, Name: in.name, Size: 5,
			Source: AttachmentSourceUpload, Role: AttachmentRoleInput, CreatedAt: time.Now()}); err != nil {
			t.Fatalf("AddTaskAttachment(%s): %v", in.name, err)
		}
	}

	inputs, err := db.TaskInputs(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 2 || inputs[0].Name != "spec.md" || inputs[1].Name != "data.csv" {
		t.Fatalf("task 1's input files = %+v, want spec.md then data.csv and not its result", inputs)
	}
	for _, in := range inputs {
		if in.Role != AttachmentRoleInput || in.Source != AttachmentSourceUpload {
			t.Fatalf("input %s read back as role %q source %q", in.Name, in.Role, in.Source)
		}
	}
	all, err := db.TaskAttachments(1)
	if err != nil || len(all) != 3 {
		t.Fatalf("task 1 lists %d attachments (%v), want all three", len(all), err)
	}
	if all[0].Role != AttachmentRoleResult {
		t.Fatalf("the result read back as role %q", all[0].Role)
	}
	// Inputs count toward the task's limits like any file.
	if u, err := db.TaskAttachmentUsage(1); err != nil || u.TaskFiles != 3 || u.TaskBytes != 15 {
		t.Fatalf("usage = %+v, %v", u, err)
	}
	if st, err := db.LoadState(); err != nil || st.Plan.TaskByID(1).AttachmentCount != 3 {
		t.Fatalf("task 1's attachment count must cover its input files: %v", err)
	}
	if has, err := db.HasTaskInputs(); err != nil || !has {
		t.Fatalf("HasTaskInputs = %v, %v; want true", has, err)
	}
}

func TestHasTaskInputsWithoutAny(t *testing.T) {
	db, dir := attachmentFixture(t, 1)
	attach(t, db, dir, 1, attID(1), "report.txt")
	if has, err := db.HasTaskInputs(); err != nil || has {
		t.Fatalf("HasTaskInputs = %v, %v; a project whose only file is a result has no input files", has, err)
	}
}

func TestAnAttachmentRoleIsOneCloopGives(t *testing.T) {
	db, _ := attachmentFixture(t, 1)
	err := db.AddTaskAttachment(AttachmentRow{ID: attID(5), TaskID: 1, Name: "x", Role: "instructions"})
	if err == nil || !strings.Contains(err.Error(), "role") {
		t.Fatalf("an unknown role was recorded: %v", err)
	}
	// A row the workload wrote with another role is no input file.
	if _, err := db.conn.Exec(`INSERT INTO task_attachments(id, task_id, name, role) VALUES (?, 1, 'odd', 'inputs')`,
		attID(6)); err != nil {
		t.Fatal(err)
	}
	if in, err := db.TaskInputs(1); err != nil || len(in) != 0 {
		t.Fatalf("TaskInputs = %+v, %v; a role that is not exactly %q is not an input", in, err, AttachmentRoleInput)
	}
}

func TestAGoneTaskTakesItsInboxWithIt(t *testing.T) {
	db, dir := attachmentFixture(t, 1, 2)
	for _, id := range []string{"1", "2"} {
		box := filepath.Join(dir, AttachmentInboxDir, id)
		if err := os.MkdirAll(box, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(box, "spec.md"), []byte("x"), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	st, err := db.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	st.Plan.Tasks = []*pm.Task{st.Plan.TaskByID(1)}
	if err := db.SaveState(st); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(dir, AttachmentInboxDir, "1")) {
		t.Fatal("task 1's inbox went with task 2")
	}
	if exists(filepath.Join(dir, AttachmentInboxDir, "2")) {
		t.Fatal("task 2's inbox outlived it: a later task 2 would be given its copies")
	}
}
