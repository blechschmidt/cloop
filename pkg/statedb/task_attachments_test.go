package statedb

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// attachmentFixture is a database holding a plan of the given task ids, and
// the directory its attachment store lives in.
func attachmentFixture(t *testing.T, ids ...int) (*DB, string) {
	t.Helper()
	db := openFresh(t)
	plan := &pm.Plan{Goal: "g"}
	for _, id := range ids {
		plan.Tasks = append(plan.Tasks, &pm.Task{ID: id, Title: "task", Status: pm.TaskPending})
	}
	if err := db.SaveState(&State{Goal: "g", Plan: plan}); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	dir := AttachmentStoreDir(db.Path())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return db, dir
}

// attach records an attachment and puts bytes in the store under its id.
func attach(t *testing.T, db *DB, dir string, taskID int, id, name string) AttachmentRow {
	t.Helper()
	row := AttachmentRow{ID: id, TaskID: taskID, Name: name, MediaType: "text/plain", Size: 5,
		Source: AttachmentSourceRun, CreatedAt: time.Now()}
	if err := os.WriteFile(filepath.Join(dir, id), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := db.AddTaskAttachment(row); err != nil {
		t.Fatalf("AddTaskAttachment(%s): %v", name, err)
	}
	return row
}

func attID(n byte) string { return strings.Repeat(string("0123456789abcdef"[n%16]), 32) }

func exists(path string) bool { _, err := os.Lstat(path); return err == nil }

func TestTaskAttachmentsMigrationIsAdditive(t *testing.T) {
	m := embeddedMigration(t, 76)
	if got := classifyMigration(m.SQL); got != CompatAdditive {
		t.Fatalf("0076 classifies as %q, want additive: every older build on the host must keep opening the database", got)
	}
	if strings.Contains(m.SQL, "plan_tasks") && strings.Contains(m.SQL, "REFERENCES") {
		t.Fatal("0076 references plan_tasks: an older build's delete of a task would fail on the foreign key")
	}
}

func TestAttachmentRoundTrip(t *testing.T) {
	db, dir := attachmentFixture(t, 1, 2)
	a := attach(t, db, dir, 1, attID(1), "report.txt")
	attach(t, db, dir, 1, attID(2), "plots/loss.png")
	attach(t, db, dir, 2, attID(3), "other.txt")

	rows, err := db.TaskAttachments(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Name != "report.txt" || rows[1].Name != "plots/loss.png" {
		t.Fatalf("task 1's attachments = %+v, want report.txt then plots/loss.png", rows)
	}
	got, err := db.TaskAttachment(1, a.ID)
	if err != nil || got.Name != "report.txt" || got.Size != 5 || got.Source != AttachmentSourceRun {
		t.Fatalf("TaskAttachment = %+v, %v", got, err)
	}
	// Another task's id is not found through this task: a caller allowed to
	// see task 1 must not reach task 2's file by naming it.
	if _, err := db.TaskAttachment(1, attID(3)); !errors.Is(err, ErrAttachmentNotFound) {
		t.Fatalf("task 1 reading task 2's attachment: %v, want ErrAttachmentNotFound", err)
	}
	if _, err := db.TaskAttachment(1, "../../etc/passwd"); !errors.Is(err, ErrAttachmentNotFound) {
		t.Fatalf("a path for an id: %v, want ErrAttachmentNotFound", err)
	}

	u, err := db.TaskAttachmentUsage(1)
	if err != nil || u.TaskFiles != 2 || u.TaskBytes != 10 || u.ProjectFiles != 3 || u.ProjectBytes != 15 {
		t.Fatalf("usage = %+v, %v", u, err)
	}

	st, err := db.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if n := st.Plan.TaskByID(1).AttachmentCount; n != 2 {
		t.Fatalf("task 1 loads with %d attachments, want 2", n)
	}
	if lt, err := db.LoadTask(2); err != nil || lt.AttachmentCount != 1 {
		t.Fatalf("LoadTask(2) = %+v, %v; want one attachment", lt, err)
	}

	removed, err := db.DeleteTaskAttachment(1, a.ID)
	if err != nil || removed.ID != a.ID {
		t.Fatalf("DeleteTaskAttachment = %+v, %v", removed, err)
	}
	if exists(filepath.Join(dir, a.ID)) {
		t.Fatal("the deleted attachment's file is still in the store")
	}
	if _, err := db.DeleteTaskAttachment(1, a.ID); !errors.Is(err, ErrAttachmentNotFound) {
		t.Fatalf("deleting it twice: %v, want ErrAttachmentNotFound", err)
	}
}

func TestAddTaskAttachmentRefusesWhatItCannotRecord(t *testing.T) {
	db, _ := attachmentFixture(t, 1)
	cases := map[string]AttachmentRow{
		"missing task": {ID: attID(1), TaskID: 9, Name: "x"},
		"path for id":  {ID: "../../x", TaskID: 1, Name: "x"},
		"upper hex id": {ID: strings.ToUpper(attID(10)), TaskID: 1, Name: "x"},
		"no name":      {ID: attID(2), TaskID: 1, Name: "  "},
		"no task":      {ID: attID(3), Name: "x"},
	}
	for name, row := range cases {
		if err := db.AddTaskAttachment(row); err == nil {
			t.Errorf("%s: recorded %+v", name, row)
		}
	}
	if err := db.AddTaskAttachment(AttachmentRow{ID: attID(1), TaskID: 9, Name: "x"}); !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("an attachment for a task the plan does not have: %v, want ErrTaskNotFound", err)
	}
	if err := db.AddTaskAttachment(AttachmentRow{ID: attID(4), TaskID: 1, Name: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddTaskAttachment(AttachmentRow{ID: attID(4), TaskID: 1, Name: "y"}); err == nil {
		t.Fatal("the same id was recorded twice")
	}
	// What is kept is clipped, not refused.
	long := AttachmentRow{ID: attID(5), TaskID: 1, Name: strings.Repeat("n", 400), Note: strings.Repeat("é", 1000)}
	if err := db.AddTaskAttachment(long); err != nil {
		t.Fatal(err)
	}
	got, err := db.TaskAttachment(1, attID(5))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Name) != MaxAttachmentNameBytes || len(got.Note) > maxAttachmentNote || got.MediaType != "application/octet-stream" {
		t.Fatalf("clipped row = name %d bytes, note %d bytes, type %q", len(got.Name), len(got.Note), got.MediaType)
	}
}

// TestAttachmentCountIsReadNotSaved: a run saves the copy of the plan it
// loaded before its own files were attached. That save must neither erase the
// attachments nor store a count — the count is the rows, read on every load.
func TestAttachmentCountIsReadNotSaved(t *testing.T) {
	db, dir := attachmentFixture(t, 1)
	stale, err := db.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	attach(t, db, dir, 1, attID(1), "a.txt")
	stale.Plan.TaskByID(1).Status = pm.TaskDone
	stale.Plan.TaskByID(1).AttachmentCount = 42
	if err := db.SaveState(stale); err != nil {
		t.Fatal(err)
	}
	st, err := db.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Plan.TaskByID(1); got.AttachmentCount != 1 || got.Status != pm.TaskDone {
		t.Fatalf("after a stale save: count %d, status %s; want 1, done", got.AttachmentCount, got.Status)
	}
	if !exists(filepath.Join(dir, attID(1))) {
		t.Fatal("a stale save removed an attachment's file")
	}
}

// TestDroppingATaskDropsItsAttachments: both ways a task leaves the plan take
// its attachments, rows and files, with it.
func TestDroppingATaskDropsItsAttachments(t *testing.T) {
	db, dir := attachmentFixture(t, 1, 2, 3)
	attach(t, db, dir, 1, attID(1), "keep.txt")
	attach(t, db, dir, 2, attID(2), "saved-away.txt")
	attach(t, db, dir, 3, attID(3), "deleted.txt")

	st, err := db.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	st.Plan.Tasks = []*pm.Task{st.Plan.TaskByID(1), st.Plan.TaskByID(3)}
	if err := db.SaveState(st); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteTask(3); err != nil {
		t.Fatal(err)
	}
	all, err := db.AllTaskAttachments()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].ID != attID(1) {
		t.Fatalf("attachments left = %+v, want only task 1's", all)
	}
	for _, id := range []string{attID(2), attID(3)} {
		if exists(filepath.Join(dir, id)) {
			t.Errorf("file %s of a dropped task is still in the store", id)
		}
	}
	if !exists(filepath.Join(dir, attID(1))) {
		t.Error("a kept task's file was removed")
	}
}

// TestAReusedTaskIDStartsWithoutAttachments: an older build deletes a task
// without its attachments. When the id comes back for a new task, the save
// that stores the new task drops what is still recorded under it.
func TestAReusedTaskIDStartsWithoutAttachments(t *testing.T) {
	db, dir := attachmentFixture(t, 1, 2)
	attach(t, db, dir, 2, attID(2), "predecessor.txt")
	// An older build's delete: the plan row goes, the attachment stays.
	if _, err := db.conn.Exec(`DELETE FROM plan_tasks WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	st, err := db.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	st.Plan.Tasks = append(st.Plan.Tasks, &pm.Task{ID: 2, Title: "a different task", Status: pm.TaskPending})
	if err := db.SaveState(st); err != nil {
		t.Fatal(err)
	}
	rows, err := db.TaskAttachments(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("the new task 2 opened with its predecessor's attachments: %+v", rows)
	}
	if exists(filepath.Join(dir, attID(2))) {
		t.Fatal("the predecessor's file is still in the store")
	}
}

// TestARowCannotNameAFileOutsideTheStore: on a shared-filesystem executor the
// database is written from inside the sandbox. A row whose id is a path must
// not turn a task's deletion into an unlink of that path.
func TestARowCannotNameAFileOutsideTheStore(t *testing.T) {
	db, dir := attachmentFixture(t, 1)
	victim := filepath.Join(filepath.Dir(dir), "victim")
	if err := os.WriteFile(victim, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := db.conn.Exec(`INSERT INTO task_attachments(id, task_id, name) VALUES ('../victim', 1, 'x')`); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteTask(1); err != nil {
		t.Fatal(err)
	}
	if !exists(victim) {
		t.Fatal("deleting the task unlinked a file a row named by path")
	}

	// A store that is a link is not walked into either.
	db2, dir2 := attachmentFixture(t, 1)
	elsewhere := t.TempDir()
	if err := os.WriteFile(filepath.Join(elsewhere, attID(7)), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := db2.AddTaskAttachment(AttachmentRow{ID: attID(7), TaskID: 1, Name: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir2); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, dir2); err != nil {
		t.Fatal(err)
	}
	if _, err := db2.DeleteTaskAttachment(1, attID(7)); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(elsewhere, attID(7))) {
		t.Fatal("a store replaced by a symlink was followed to delete a file outside it")
	}
}

// TestAGoneTaskTakesItsOutboxWithIt: files waiting in the outbox of a task
// that is deleted — or whose id a save stores afresh — must not be attached to
// the next task given that id.
func TestAGoneTaskTakesItsOutboxWithIt(t *testing.T) {
	db, dir := attachmentFixture(t, 1, 2, 3)
	for _, id := range []string{"1", "2", "3", "4"} {
		box := filepath.Join(dir, AttachmentOutboxDir, id)
		if err := os.MkdirAll(box, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(box, "left.txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.DeleteTask(3); err != nil {
		t.Fatal(err)
	}
	st, err := db.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	// Task 2 dropped, task 4 stored for the first time.
	st.Plan.Tasks = []*pm.Task{st.Plan.TaskByID(1), {ID: 4, Title: "new", Status: pm.TaskPending}}
	if err := db.SaveState(st); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{"1": true, "2": false, "3": false, "4": false} {
		if got := exists(filepath.Join(dir, AttachmentOutboxDir, id)); got != want {
			t.Errorf("outbox of task %s present = %v, want %v", id, got, want)
		}
	}
}

// TestUsageSurvivesRowsNobodyBounded: on a shared-filesystem executor the
// workload can write task_attachments itself. Sizes that would overflow a SUM,
// and rows with ids that name no file, must not break the project's listing or
// its limits.
func TestUsageSurvivesRowsNobodyBounded(t *testing.T) {
	db, dir := attachmentFixture(t, 1)
	attach(t, db, dir, 1, attID(1), "real.txt")
	for i, q := range []string{
		`INSERT INTO task_attachments(id, task_id, name, size) VALUES ('` + attID(2) + `', 1, 'huge', 9223372036854775000)`,
		`INSERT INTO task_attachments(id, task_id, name, size) VALUES ('` + attID(3) + `', 1, 'huge too', 9223372036854775000)`,
		`INSERT INTO task_attachments(id, task_id, name, size) VALUES ('short', 1, 'bad id', 1)`,
		`INSERT INTO task_attachments(id, task_id, name, size, unavailable) VALUES ('` + attID(4) + `', 1, 'kept on a device', 1000, 'left on the device')`,
	} {
		if _, err := db.conn.Exec(q); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	u, err := db.TaskAttachmentUsage(1)
	if err != nil {
		t.Fatalf("TaskAttachmentUsage with sizes that overflow a SUM: %v", err)
	}
	if u.TaskFiles != 4 || u.TaskBytes < 1<<40 || u.TaskBytes > 1<<62 {
		t.Errorf("usage = %+v: four valid rows, and bytes clamped rather than wrapped", u)
	}
	rows, err := db.TaskAttachments(1)
	if err != nil || len(rows) != 4 {
		t.Fatalf("listed %d rows, %v; the row whose id names no file is not one of them", len(rows), err)
	}
	st, err := db.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if n := st.Plan.TaskByID(1).AttachmentCount; n != 4 {
		t.Errorf("counted %d, want 4", n)
	}

	db2, dir2 := attachmentFixture(t, 1)
	attach(t, db2, dir2, 1, attID(5), "stored.txt")
	if _, err := db2.conn.Exec(`INSERT INTO task_attachments(id, task_id, name, size, unavailable) VALUES ('` +
		attID(6) + `', 1, 'kept', 1000, 'left on the device')`); err != nil {
		t.Fatal(err)
	}
	if u, err := db2.TaskAttachmentUsage(1); err != nil || u.TaskBytes != 5 || u.ProjectBytes != 5 || u.TaskFiles != 2 {
		t.Errorf("a file kept on a device took room on the hub: %+v, %v", u, err)
	}
	if err := db2.AddTaskAttachment(AttachmentRow{ID: attID(7), TaskID: 1, Name: "x", Size: 1 << 50}); err == nil {
		t.Error("a size past any file was recorded")
	}
}
