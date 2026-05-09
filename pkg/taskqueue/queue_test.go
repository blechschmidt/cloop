package taskqueue

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestEnqueueAndList(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer q.Close()

	id1, err := q.Enqueue(Entry{
		Kind:        KindTask,
		TaskID:      42,
		Title:       "Build feature",
		Description: "Implement X",
		Source:      "orchestrator",
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if id1 == 0 {
		t.Fatal("expected non-zero id")
	}

	id2, err := q.Enqueue(Entry{
		Kind:    KindHeal,
		TaskID:  42,
		Attempt: 1,
		Title:   "Heal task 42 attempt 1",
		Source:  "orchestrator",
	})
	if err != nil {
		t.Fatalf("Enqueue heal: %v", err)
	}
	if id2 <= id1 {
		t.Fatalf("expected id2 > id1, got %d %d", id1, id2)
	}

	// List newest-first.
	entries, err := q.List(ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].ID != id2 {
		t.Fatalf("expected newest entry first; got id=%d", entries[0].ID)
	}
	if entries[0].Status != StatusQueued {
		t.Fatalf("new entry should be queued, got %s", entries[0].Status)
	}

	// Filter by task_id.
	byTask, err := q.List(ListOptions{TaskID: 42})
	if err != nil {
		t.Fatalf("List by task: %v", err)
	}
	if len(byTask) != 2 {
		t.Fatalf("expected 2 entries for task 42, got %d", len(byTask))
	}

	// Filter by kind.
	healOnly, err := q.List(ListOptions{Kind: KindHeal})
	if err != nil {
		t.Fatalf("List by kind: %v", err)
	}
	if len(healOnly) != 1 || healOnly[0].Kind != KindHeal {
		t.Fatalf("expected 1 heal entry, got %v", healOnly)
	}
}

func TestLifecycleTransitions(t *testing.T) {
	dir := t.TempDir()
	q, _ := Open(dir)
	defer q.Close()

	id, _ := q.Enqueue(Entry{Kind: KindTask, Title: "T1"})

	if err := q.MarkRunning(id); err != nil {
		t.Fatalf("MarkRunning: %v", err)
	}
	entries, _ := q.List(ListOptions{})
	if entries[0].Status != StatusRunning {
		t.Fatalf("expected running, got %s", entries[0].Status)
	}
	if entries[0].StartedAt == nil {
		t.Fatal("StartedAt should be set after MarkRunning")
	}

	if err := q.MarkDone(id, "completed successfully"); err != nil {
		t.Fatalf("MarkDone: %v", err)
	}
	entries, _ = q.List(ListOptions{})
	if entries[0].Status != StatusDone {
		t.Fatalf("expected done, got %s", entries[0].Status)
	}
	if entries[0].CompletedAt == nil {
		t.Fatal("CompletedAt should be set after MarkDone")
	}
	if entries[0].OutputSummary != "completed successfully" {
		t.Fatalf("unexpected summary: %q", entries[0].OutputSummary)
	}
}

func TestMarkFailedAndStats(t *testing.T) {
	dir := t.TempDir()
	q, _ := Open(dir)
	defer q.Close()

	id1, _ := q.Enqueue(Entry{Kind: KindTask, Title: "ok"})
	id2, _ := q.Enqueue(Entry{Kind: KindHeal, Title: "fail"})
	id3, _ := q.Enqueue(Entry{Kind: KindTask, Title: "skip"})

	q.MarkDone(id1, "fine")
	q.MarkFailed(id2, "boom")
	q.MarkSkipped(id3, "filtered")

	stats, err := q.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats[StatusDone] != 1 || stats[StatusFailed] != 1 || stats[StatusSkipped] != 1 {
		t.Fatalf("unexpected stats: %v", stats)
	}
}

func TestTruncate(t *testing.T) {
	dir := t.TempDir()
	q, _ := Open(dir)
	defer q.Close()

	q.Enqueue(Entry{Kind: KindTask, Title: "a"})
	q.Enqueue(Entry{Kind: KindTask, Title: "b"})
	if err := q.Truncate(); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	entries, _ := q.List(ListOptions{})
	if len(entries) != 0 {
		t.Fatalf("expected empty after truncate, got %d", len(entries))
	}
}

func TestNilQueueSafe(t *testing.T) {
	var q *Queue
	if err := q.MarkRunning(1); err != nil {
		t.Fatalf("nil MarkRunning should be no-op, got %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatalf("nil Close should be no-op, got %v", err)
	}
}

// TestLegacyQueueMigration writes a pre-Task-20079 queue.db file with a
// queue row and checks that Open migrates it into state.db and removes
// the legacy file.
func TestLegacyQueueMigration(t *testing.T) {
	dir := t.TempDir()
	cloopDir := filepath.Join(dir, ".cloop")
	if err := os.MkdirAll(cloopDir, 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}
	legacy := filepath.Join(cloopDir, "queue.db")

	// Build a minimal legacy queue.db.
	src, err := sql.Open("sqlite", legacy)
	if err != nil {
		t.Fatalf("create legacy db: %v", err)
	}
	if _, err := src.Exec(schema); err != nil {
		t.Fatalf("legacy schema: %v", err)
	}
	if _, err := src.Exec(
		`INSERT INTO queue (id, kind, task_id, title, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		7, "task", 42, "legacy task", "done", "2026-05-09T00:00:00Z",
	); err != nil {
		t.Fatalf("legacy insert: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("close legacy: %v", err)
	}

	q, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer q.Close()

	entries, err := q.List(ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 migrated entry, got %d", len(entries))
	}
	if entries[0].ID != 7 || entries[0].TaskID != 42 || entries[0].Title != "legacy task" {
		t.Fatalf("migrated row mismatch: %+v", entries[0])
	}

	// Legacy file must be removed.
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy queue.db should have been removed, err=%v", err)
	}
}

func TestQueuePathIsUnderCloop(t *testing.T) {
	dir := t.TempDir()
	// Task 20079: queue lives in state.db, not a separate queue.db.
	want := filepath.Join(dir, ".cloop", "state.db")
	if got := QueuePath(dir); got != want {
		t.Fatalf("QueuePath = %q, want %q", got, want)
	}
}
