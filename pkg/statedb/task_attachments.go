package statedb

// task_attachments.go stores what describes the files attached to a task
// (Task 20428): one row per file, in the database of the plan the task belongs
// to. The bytes are files in the store beside that database
// (AttachmentStoreDir), which pkg/attachments fills and reads. See
// migrations/0076_task_attachments.sql for the table.
//
// The rows are written by three kinds of writer and no other: an attach (a
// run's outbox moved into the store, `cloop task attachments add`, a remote
// run's result merged on the hub), an explicit delete, and the deletion of the
// task itself. SaveState writes none of them except the last. That is the
// property pm.Task.AttachmentCount depends on: a run saving a copy of the plan
// it loaded before a file was attached can neither erase the attachment nor
// write a stale count back, because the count is not stored — the readers
// count the rows.
//
// # Whose files these are
//
// This package deletes the bytes of the rows it deletes, and nothing else. A
// row names its file only by its id, which must have ValidAttachmentID's shape
// before anything is removed: on a shared-filesystem executor the database is
// written from inside the sandbox, so a row may have been put there by the
// workload, and a row is not a licence to unlink whatever path it spells.
//
// For the same reason every operation on the store goes through
// OpenAttachmentStore: an os.Root on the store directory itself, opened inside
// the project directory and checked to be the directory it was looked at as.
// The workload can swap .cloop/attachments for a link at any moment; a path
// resolved again for each write would follow it, and the hub — which runs on
// the host, often as root — would create, rename or unlink files wherever the
// link pointed.

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// Attachment sources: how a file came to be attached.
const (
	// AttachmentSourceRun is a file a run left in its task's outbox.
	AttachmentSourceRun = "run"
	// AttachmentSourceCLI is a file attached by hand with
	// `cloop task attachments add`.
	AttachmentSourceCLI = "cli"
)

// Bounds on what a row carries. Names come from a run's outbox, notes from a
// command line and reasons from the hub; all of them are loaded with every
// listing a dashboard renders.
const (
	// MaxAttachmentNameBytes bounds the name a file is attached under.
	MaxAttachmentNameBytes = 255
	maxAttachmentMediaType = 128
	maxAttachmentNote      = 1024
	maxAttachmentText      = 128
	maxAttachmentReason    = 1024
	// maxAttachmentSize bounds the size a row may claim. pkg/attachments
	// holds files to far less; this is the sanity bound on a size that came
	// from somewhere else — a remote executor's account of a file it kept.
	maxAttachmentSize int64 = 1 << 40
)

// AttachmentOutboxDir is the store's subdirectory holding the tasks' outboxes.
const AttachmentOutboxDir = "outbox"

// attachmentGitignore is the store's .gitignore: everything in it, itself
// included, so a project that does not ignore .cloop/ cannot commit a run's
// files by accident.
const attachmentGitignore = "# cloop task attachments (Task 20428): never committed.\n*\n"

// validAttachmentIDSQL is ValidAttachmentID in SQL, for the readers: a row
// whose id has another shape names no file, and is neither listed nor counted.
const validAttachmentIDSQL = `length(id) = 32 AND id NOT GLOB '*[^0-9a-f]*'`

// attachmentIDPattern is the shape of every attachment id: 128 random bits in
// lower-case hex. The id is also the file's name in the store.
var attachmentIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidAttachmentID reports whether id has the shape cloop gives every
// attachment. Anything else names no file in a store.
func ValidAttachmentID(id string) bool { return attachmentIDPattern.MatchString(id) }

// AttachmentStoreDir is where the bytes of the attachments recorded in the
// database at dbPath live: beside it. Each database — a project's, a
// feature's, a session's — so has a store of its own, and a row can only ever
// name a file in its own.
func AttachmentStoreDir(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "attachments")
}

// attachmentAnchor is the directory the store of the database at dbPath is
// resolved inside: the project — the parent of the .cloop the database lives
// in, directly or in a session's directory — or, for a database kept anywhere
// else, the database's own directory.
func attachmentAnchor(dbPath string) string {
	dir := filepath.Dir(dbPath)
	if filepath.Base(dir) == ".cloop" {
		return filepath.Dir(dir)
	}
	if sessions := filepath.Dir(dir); filepath.Base(sessions) == "sessions" &&
		filepath.Base(filepath.Dir(sessions)) == ".cloop" {
		return filepath.Dir(filepath.Dir(sessions))
	}
	return dir
}

// OpenAttachmentStore opens the attachment store of the database at dbPath as
// an os.Root, creating it — with its .gitignore — when create is set. A store
// that does not exist is an error wrapping os.ErrNotExist.
//
// The store is reached through an os.Root on the project directory, so no
// link can lead it outside the project, and it must be a directory, not a
// link to one, both when it is looked at and once it is open. Every operation
// on the returned root is then bound to that directory: swapping the store
// for a link afterwards redirects nothing.
func OpenAttachmentStore(dbPath string, create bool) (*os.Root, error) {
	anchor, dir := attachmentAnchor(dbPath), AttachmentStoreDir(dbPath)
	rel, err := filepath.Rel(anchor, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("statedb: the attachment store %s is not inside %s", dir, anchor)
	}
	parent, err := os.OpenRoot(anchor)
	if err != nil {
		return nil, fmt.Errorf("statedb: open %s: %w", anchor, err)
	}
	defer parent.Close()
	if create {
		if err := parent.MkdirAll(rel, 0o755); err != nil {
			return nil, fmt.Errorf("statedb: create the attachment store %s: %w", dir, err)
		}
	}
	before, err := parent.Lstat(rel)
	if err != nil {
		return nil, fmt.Errorf("statedb: the attachment store %s: %w", dir, err)
	}
	if !before.IsDir() {
		return nil, fmt.Errorf("statedb: the attachment store %s is not a directory", dir)
	}
	root, err := parent.OpenRoot(rel)
	if err != nil {
		return nil, fmt.Errorf("statedb: open the attachment store %s: %w", dir, err)
	}
	if after, err := root.Stat("."); err != nil || !os.SameFile(before, after) {
		root.Close()
		return nil, fmt.Errorf("statedb: the attachment store %s changed while it was opened", dir)
	}
	if create {
		if f, err := root.OpenFile(".gitignore", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644); err == nil {
			_, _ = f.WriteString(attachmentGitignore)
			_ = f.Close()
		}
	}
	return root, nil
}

// AttachmentRow is one file attached to a task.
type AttachmentRow struct {
	ID        string `json:"id"`
	TaskID    int    `json:"task_id"`
	Name      string `json:"name"`
	MediaType string `json:"media_type"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256,omitempty"`
	Source    string `json:"source,omitempty"`
	RunID     string `json:"run_id,omitempty"`
	Note      string `json:"note,omitempty"`
	AddedBy   string `json:"added_by,omitempty"`
	// CreatedAt is when the file was attached.
	CreatedAt time.Time `json:"created_at"`
	// Unavailable is empty when the bytes are in the store, and otherwise
	// says why they are not: a remote run whose result had no room for the
	// file left it on the device.
	Unavailable string `json:"unavailable,omitempty"`
}

// AttachmentUsage is how much a task's and its project's attachments hold, for
// the limits an attach is checked against.
type AttachmentUsage struct {
	TaskFiles    int
	TaskBytes    int64
	ProjectFiles int
	ProjectBytes int64
}

const attachmentColumns = `id, task_id, name, media_type, size, sha256, source, run_id, note, added_by, created_at, unavailable`

// attachmentCountSelect is the correlated subquery taskSelect reads a task's
// attachment count through. task_attachments_task makes it an index probe.
const attachmentCountSelect = `(SELECT COUNT(*) FROM task_attachments a WHERE a.task_id = plan_tasks.id
		AND length(a.id) = 32 AND a.id NOT GLOB '*[^0-9a-f]*')`

// boundAttachment checks what a row must have and clips what it may carry.
func boundAttachment(row AttachmentRow) (AttachmentRow, error) {
	if !ValidAttachmentID(row.ID) {
		return row, fmt.Errorf("statedb: attachment id %q is not 32 lower-case hex characters", clipText(row.ID, 64))
	}
	if row.TaskID <= 0 {
		return row, fmt.Errorf("statedb: attachment %s: invalid task id %d", row.ID, row.TaskID)
	}
	row.Name = clipText(strings.TrimSpace(row.Name), MaxAttachmentNameBytes)
	if row.Name == "" {
		return row, fmt.Errorf("statedb: attachment %s: a name is required", row.ID)
	}
	if row.Size < 0 || row.Size > maxAttachmentSize {
		return row, fmt.Errorf("statedb: attachment %s: size %d is out of range", row.ID, row.Size)
	}
	row.MediaType = clipText(strings.TrimSpace(row.MediaType), maxAttachmentMediaType)
	if row.MediaType == "" {
		row.MediaType = "application/octet-stream"
	}
	row.SHA256 = clipText(strings.TrimSpace(row.SHA256), 64)
	row.Source = clipText(strings.TrimSpace(row.Source), maxAttachmentText)
	row.RunID = clipText(strings.TrimSpace(row.RunID), maxAttachmentText)
	row.Note = clipText(strings.TrimSpace(row.Note), maxAttachmentNote)
	row.AddedBy = clipText(strings.TrimSpace(row.AddedBy), maxAttachmentText)
	row.Unavailable = clipText(strings.TrimSpace(row.Unavailable), maxAttachmentReason)
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now()
	}
	return row, nil
}

// AddTaskAttachment records an attached file. The task must exist: a row for
// a task the plan does not have would be inherited by whichever task is next
// given that id. It fails with an error wrapping ErrTaskNotFound when the
// task is gone, and refuses an id that is already recorded.
func (d *DB) AddTaskAttachment(row AttachmentRow) error {
	row, err := boundAttachment(row)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: attach %q to task %d: %w", row.Name, row.TaskID, classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck
	var one int
	switch err := tx.QueryRow(`SELECT 1 FROM plan_tasks WHERE id = ?`, row.TaskID).Scan(&one); {
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("%w: task %d (attaching %q)", ErrTaskNotFound, row.TaskID, row.Name)
	case err != nil:
		return fmt.Errorf("statedb: attach %q to task %d: %w", row.Name, row.TaskID, classifyDriverErr(err))
	}
	res, err := tx.Exec(`INSERT INTO task_attachments(`+attachmentColumns+`)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`,
		row.ID, row.TaskID, row.Name, row.MediaType, row.Size, row.SHA256, row.Source,
		row.RunID, row.Note, row.AddedBy, row.CreatedAt.UTC().Format(time.RFC3339Nano), row.Unavailable)
	if err != nil {
		return fmt.Errorf("statedb: attach %q to task %d: %w", row.Name, row.TaskID, classifyDriverErr(err))
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("statedb: attach %q to task %d: %w", row.Name, row.TaskID, classifyDriverErr(err))
	} else if n == 0 {
		return fmt.Errorf("statedb: attachment %s is already recorded", row.ID)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: attach %q to task %d: %w", row.Name, row.TaskID, classifyDriverErr(err))
	}
	return nil
}

// TaskAttachments returns a task's attachments, oldest first.
func (d *DB) TaskAttachments(taskID int) ([]AttachmentRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return queryAttachments(d.conn, `WHERE task_id = ? AND `+validAttachmentIDSQL+` ORDER BY created_at, id`, taskID)
}

// AllTaskAttachments returns every attachment in the database, by task and
// then age.
func (d *DB) AllTaskAttachments() ([]AttachmentRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return queryAttachments(d.conn, `WHERE `+validAttachmentIDSQL+` ORDER BY task_id, created_at, id`)
}

// TaskAttachment returns one attachment of a task, or an error wrapping
// ErrAttachmentNotFound — also when the id names another task's attachment,
// so a caller allowed to see one task cannot read another's through it.
func (d *DB) TaskAttachment(taskID int, id string) (AttachmentRow, error) {
	if !ValidAttachmentID(id) {
		return AttachmentRow{}, fmt.Errorf("%w: %q on task %d", ErrAttachmentNotFound, clipText(id, 64), taskID)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := queryAttachments(d.conn, `WHERE task_id = ? AND id = ?`, taskID, id)
	if err != nil {
		return AttachmentRow{}, err
	}
	if len(rows) == 0 {
		return AttachmentRow{}, fmt.Errorf("%w: %s on task %d", ErrAttachmentNotFound, id, taskID)
	}
	return rows[0], nil
}

// DeleteTaskAttachment removes one attachment of a task — its row, then its
// file — and returns the row it removed. An error wraps ErrAttachmentNotFound
// when the task has no such attachment.
func (d *DB) DeleteTaskAttachment(taskID int, id string) (AttachmentRow, error) {
	if !ValidAttachmentID(id) {
		return AttachmentRow{}, fmt.Errorf("%w: %q on task %d", ErrAttachmentNotFound, clipText(id, 64), taskID)
	}
	d.mu.Lock()
	tx, err := d.conn.Begin()
	if err != nil {
		d.mu.Unlock()
		return AttachmentRow{}, fmt.Errorf("statedb: delete attachment %s: %w", id, classifyDriverErr(err))
	}
	rows, err := queryAttachments(tx, `WHERE task_id = ? AND id = ?`, taskID, id)
	if err == nil && len(rows) == 0 {
		err = fmt.Errorf("%w: %s on task %d", ErrAttachmentNotFound, id, taskID)
	}
	if err == nil {
		if _, xerr := tx.Exec(`DELETE FROM task_attachments WHERE task_id = ? AND id = ?`, taskID, id); xerr != nil {
			err = fmt.Errorf("statedb: delete attachment %s: %w", id, classifyDriverErr(xerr))
		}
	}
	if err == nil {
		if cerr := tx.Commit(); cerr != nil {
			err = fmt.Errorf("statedb: delete attachment %s: %w", id, classifyDriverErr(cerr))
		}
	}
	if err != nil {
		_ = tx.Rollback()
		d.mu.Unlock()
		return AttachmentRow{}, err
	}
	d.mu.Unlock()
	d.removeAttachmentFiles([]string{id}, nil)
	return rows[0], nil
}

// TaskAttachmentUsage reports what a task's attachments and all of its
// project's hold. Files count every row; bytes count only the files in the
// store — a remote run's file it kept is listed, but takes no room here.
//
// TOTAL rather than SUM: a row is written by whoever can write the database,
// which on a shared-filesystem executor includes the workload, and SUM over
// sizes nobody bounded fails with an integer overflow — every attach and every
// listing of the project with it. TOTAL is a float that cannot overflow, and
// it is clamped on the way out.
func (d *DB) TaskAttachmentUsage(taskID int) (AttachmentUsage, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var (
		u                       AttachmentUsage
		projectBytes, taskBytes float64
	)
	if err := d.conn.QueryRow(
		`SELECT COUNT(*), TOTAL(CASE WHEN unavailable = '' THEN size ELSE 0 END),
			COALESCE(SUM(CASE WHEN task_id = ? THEN 1 ELSE 0 END), 0),
			TOTAL(CASE WHEN task_id = ? AND unavailable = '' THEN size ELSE 0 END)
		 FROM task_attachments WHERE `+validAttachmentIDSQL, taskID, taskID,
	).Scan(&u.ProjectFiles, &projectBytes, &u.TaskFiles, &taskBytes); err != nil {
		return u, fmt.Errorf("statedb: measure attachments of task %d: %w", taskID, classifyDriverErr(err))
	}
	u.ProjectBytes, u.TaskBytes = clampBytes(projectBytes), clampBytes(taskBytes)
	return u, nil
}

// clampBytes turns a TOTAL into a byte count: never negative, never anywhere
// near what an int64 holds, so sums of it cannot overflow either.
func clampBytes(v float64) int64 {
	switch {
	case v <= 0 || math.IsNaN(v):
		return 0
	case v >= float64(maxAttachmentSize)*1024:
		return maxAttachmentSize * 1024
	}
	return int64(v)
}

// AttachmentIDs returns the id of every recorded attachment: what a sweep of
// the store keeps.
func (d *DB) AttachmentIDs() (map[string]bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT id FROM task_attachments WHERE ` + validAttachmentIDSQL)
	if err != nil {
		return nil, fmt.Errorf("statedb: list attachment ids: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	ids := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("statedb: list attachment ids: %w", classifyDriverErr(err))
		}
		ids[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list attachment ids: %w", classifyDriverErr(err))
	}
	return ids, nil
}

// AuditTaskAttachmentDelete records an attachment deleted by a person. Best
// effort, like every emit helper; d must be the project's handle.
func AuditTaskAttachmentDelete(d *DB, row AttachmentRow, actor string) {
	if actor == "" {
		actor = "system"
	}
	emit(d, &AuditEvent{
		Actor:      actor,
		EventType:  string(auditaction.ActionTaskAttachmentDelete),
		EntityType: "task",
		EntityID:   fmt.Sprintf("%d", row.TaskID),
		Payload: MarshalAuditPayload(map[string]any{
			"id":            row.TaskID,
			"attachment_id": row.ID,
			"name":          row.Name,
			"size":          row.Size,
			"sha256":        row.SHA256,
		}),
	})
}

// attachmentQuerier is what queryAttachments reads through: the connection,
// or a transaction already holding the write lock.
type attachmentQuerier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

func queryAttachments(q attachmentQuerier, where string, args ...any) ([]AttachmentRow, error) {
	rows, err := q.Query(`SELECT `+attachmentColumns+` FROM task_attachments `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: read attachments: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []AttachmentRow
	for rows.Next() {
		var (
			r       AttachmentRow
			created string
		)
		if err := rows.Scan(&r.ID, &r.TaskID, &r.Name, &r.MediaType, &r.Size, &r.SHA256, &r.Source,
			&r.RunID, &r.Note, &r.AddedBy, &created, &r.Unavailable); err != nil {
			return nil, fmt.Errorf("statedb: read attachments: %w", classifyDriverErr(err))
		}
		r.CreatedAt = parseOptionalTime(created)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read attachments: %w", classifyDriverErr(err))
	}
	return out, nil
}

// settleTaskAttachmentsTx deletes, inside a save, the attachments of every
// task id that is not a stored task carried on: ids the plan being saved drops,
// ids it stores for the first time, and ids no task has. It returns the ids of
// the attachments it deleted, whose files the caller removes once the save has
// committed, and the task ids whose outboxes go with them.
//
// It must run before the save writes plan_tasks, while the table still says
// which ids were already stored. A task id that is new to plan_tasks is a new
// task even when attachments are recorded against it: ids are reused, and a
// build that predates this table deletes a task without its attachments, so
// whatever is still recorded under it — or waiting in its outbox — belongs to
// a task that is gone.
func settleTaskAttachmentsTx(tx *sql.Tx, tasks []*pm.Task) (files []string, outboxes []int, err error) {
	stored, err := distinctInts(tx, `SELECT id FROM plan_tasks`)
	if err != nil {
		return nil, nil, err
	}
	carried := make(map[int]bool, len(tasks))
	for _, t := range tasks {
		if t != nil {
			carried[t.ID] = true
			if !stored[t.ID] {
				outboxes = append(outboxes, t.ID)
			}
		}
	}
	for id := range stored {
		if !carried[id] {
			outboxes = append(outboxes, id)
		}
	}
	attached, err := distinctInts(tx, `SELECT DISTINCT task_id FROM task_attachments`)
	if err != nil {
		return nil, nil, err
	}
	for id := range attached {
		if carried[id] && stored[id] {
			continue
		}
		ids, err := deleteTaskAttachmentsTx(tx, id)
		if err != nil {
			return nil, nil, err
		}
		files = append(files, ids...)
	}
	return files, outboxes, nil
}

// deleteTaskAttachmentsTx deletes every attachment row of a task and returns
// their ids.
func deleteTaskAttachmentsTx(tx *sql.Tx, taskID int) ([]string, error) {
	rows, err := queryAttachments(tx, `WHERE task_id = ?`, taskID)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	if _, err := tx.Exec(`DELETE FROM task_attachments WHERE task_id = ?`, taskID); err != nil {
		return nil, fmt.Errorf("statedb: delete the attachments of task %d: %w", taskID, classifyDriverErr(err))
	}
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	return ids, nil
}

// distinctInts reads a one-column integer query into a set.
func distinctInts(tx *sql.Tx, query string) (map[int]bool, error) {
	rows, err := tx.Query(query)
	if err != nil {
		return nil, fmt.Errorf("statedb: %s: %w", query, classifyDriverErr(err))
	}
	defer rows.Close()
	out := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("statedb: %s: %w", query, classifyDriverErr(err))
		}
		out[v] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: %s: %w", query, classifyDriverErr(err))
	}
	return out, nil
}

// removeAttachmentFiles deletes the stored bytes of attachments whose rows are
// gone, and the outboxes of tasks that are gone. Best effort: a file left
// behind costs disk, not correctness — no row names it any more — and the
// store's sweep collects it later.
//
// Only an id of attachment shape is removed, through OpenAttachmentStore's
// root: the store is in reach of a workload on a shared-filesystem executor.
func (d *DB) removeAttachmentFiles(ids []string, outboxes []int) {
	if (len(ids) == 0 && len(outboxes) == 0) || d.path == "" || strings.Contains(d.path, ":memory:") {
		return
	}
	root, err := OpenAttachmentStore(d.path, false)
	if err != nil {
		return
	}
	defer root.Close()
	for _, id := range ids {
		if ValidAttachmentID(id) {
			_ = root.Remove(id)
		}
	}
	if len(outboxes) == 0 {
		return
	}
	if info, err := root.Lstat(AttachmentOutboxDir); err != nil || !info.IsDir() {
		return
	}
	for _, taskID := range outboxes {
		if taskID > 0 {
			_ = root.RemoveAll(AttachmentOutboxDir + "/" + strconv.Itoa(taskID))
		}
	}
}
