// Package attachments keeps the files attached to a task (Task 20428).
//
// A task's transcript says what an agent did. An attachment is what it made
// for a person to look at: a report, a chart, a screenshot, a data export, a
// log. The transcript is not the place for any of those — a PNG does not
// survive being printed — and the working tree is not either: it is the
// repository's, it is often a worktree that is removed when the task ends,
// and on an isolating executor it is on another machine.
//
// # How a file gets attached
//
// A run attaches files by copying them into its task's outbox,
//
//	<store>/outbox/<task id>/
//
// whose absolute path the agent is given in its prompt and in
// $CLOOP_TASK_ATTACHMENTS (PrepareOutbox). When the attempt ends the
// orchestrator moves every regular file it finds there into the store and
// records it (Ingest). A person attaches one by hand with
// `cloop task attachments add` (Add), and a remote run's files arrive in its
// result and are stored by the hub's merge (Put).
//
// # Where the bytes live
//
// In the store beside the project's database, statedb.AttachmentStoreDir:
// <project>/.cloop/attachments/<id>, where the id is 128 random bits in hex.
// Nothing a run chose ever names a file on disk — the name it attached under
// is a label in the database row, nothing more.
//
// # The trust boundary
//
// On a shared-filesystem executor the store is written from inside the
// sandbox, and the hub — on the host, often as root — reads it to serve
// viewers and writes it when a remote run's files come back. So every
// operation here goes through statedb.OpenAttachmentStore's os.Root, bound to
// the store directory itself: a store swapped for a link redirects nothing. A
// file read must be a regular file, reached without following a link, and the
// same file after it is opened as before (Open). The store also carries a
// .gitignore that ignores everything in it, so a project that does not ignore
// .cloop/ cannot commit a run's attachments by accident.
package attachments

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Limits. Every attach is checked against all of them; a file over one is
// refused and named, never truncated.
const (
	// MaxFileBytes bounds one file.
	MaxFileBytes int64 = 32 << 20
	// MaxTaskFiles and MaxTaskBytes bound one task's attachments together.
	MaxTaskFiles       = 100
	MaxTaskBytes int64 = 128 << 20
	// MaxProjectBytes bounds everything one project's store holds: a run that
	// attaches a gigabyte of plots every task would otherwise fill the disk
	// the hub and every other project share.
	MaxProjectBytes int64 = 1 << 30
)

// Environment variables a run's agent is given.
const (
	// EnvOutbox names the absolute path of the task's outbox.
	EnvOutbox = "CLOOP_TASK_ATTACHMENTS"
	// EnvTaskID names the task the agent is working on.
	EnvTaskID = "CLOOP_TASK_ID"
)

// OutboxDirName is the store's subdirectory that holds the outboxes.
const OutboxDirName = statedb.AttachmentOutboxDir

// Errors.
var (
	// ErrTooLarge reports a file over MaxFileBytes.
	ErrTooLarge = errors.New("attachments: file is over the size limit")
	// ErrQuota reports an attach the task's or the project's limits leave no
	// room for.
	ErrQuota = errors.New("attachments: no room left for the file")
	// ErrUnavailable reports an attachment whose bytes are not in the store.
	ErrUnavailable = errors.New("attachments: the file is not in the store")
	// ErrNotRegular reports something in the store or the outbox that is not
	// a plain file: a link, a directory, a FIFO.
	ErrNotRegular = errors.New("attachments: not a regular file")
)

// StoreDir is where the attachments recorded in the database at dbPath live.
func StoreDir(dbPath string) string { return statedb.AttachmentStoreDir(dbPath) }

// OutboxDir is the outbox of a task of the project whose database is dbPath.
func OutboxDir(dbPath string, taskID int) string {
	return filepath.Join(StoreDir(dbPath), OutboxDirName, strconv.Itoa(taskID))
}

// outboxRel is a task's outbox relative to the store.
func outboxRel(taskID int) string { return OutboxDirName + "/" + strconv.Itoa(taskID) }

// PrepareOutbox makes sure the task's outbox exists, empty or not, and returns
// its absolute path: what the agent is told to copy files into.
func PrepareOutbox(dbPath string, taskID int) (string, error) {
	if taskID <= 0 {
		return "", fmt.Errorf("attachments: invalid task id %d", taskID)
	}
	root, err := statedb.OpenAttachmentStore(dbPath, true)
	if err != nil {
		return "", err
	}
	defer root.Close()
	rel := outboxRel(taskID)
	if err := root.MkdirAll(rel, 0o755); err != nil {
		return "", fmt.Errorf("attachments: create the outbox of task %d: %w", taskID, err)
	}
	if info, err := root.Lstat(rel); err != nil || !info.IsDir() {
		return "", fmt.Errorf("%w: the outbox of task %d is not a directory", ErrNotRegular, taskID)
	}
	abs, err := filepath.Abs(OutboxDir(dbPath, taskID))
	if err != nil {
		return "", fmt.Errorf("attachments: the outbox of task %d: %w", taskID, err)
	}
	return abs, nil
}

// CloseOutbox removes a task's outbox once an attempt is over, when it is
// empty. One that still holds a file an ingest could not take yet is kept for
// the next attempt to try again.
func CloseOutbox(dbPath string, taskID int) {
	root, err := statedb.OpenAttachmentStore(dbPath, false)
	if err != nil {
		return
	}
	defer root.Close()
	_ = root.Remove(outboxRel(taskID))
}

// Outboxes returns the ids of the tasks that have an outbox in the store.
func Outboxes(dbPath string) []int {
	root, err := statedb.OpenAttachmentStore(dbPath, false)
	if err != nil {
		return nil
	}
	defer root.Close()
	if info, err := root.Lstat(OutboxDirName); err != nil || !info.IsDir() {
		return nil
	}
	d, err := root.Open(OutboxDirName)
	if err != nil {
		return nil
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return nil
	}
	var ids []int
	for _, e := range entries {
		if id, err := strconv.Atoi(e.Name()); err == nil && id > 0 && strconv.Itoa(id) == e.Name() {
			ids = append(ids, id)
		}
	}
	return ids
}

// RemoveOutbox removes a task's outbox and whatever is in it: the outbox of a
// task the plan no longer has.
func RemoveOutbox(dbPath string, taskID int) {
	root, err := statedb.OpenAttachmentStore(dbPath, false)
	if err != nil {
		return
	}
	defer root.Close()
	if info, err := root.Lstat(OutboxDirName); err == nil && info.IsDir() {
		_ = root.RemoveAll(outboxRel(taskID))
	}
}

// newID returns a fresh attachment id.
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("attachments: draw an id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// Meta is what an attach records besides the bytes.
type Meta struct {
	Name      string
	Source    string
	RunID     string
	Note      string
	AddedBy   string
	CreatedAt time.Time
}

// Put stores the bytes src yields as a new attachment of the task, records it
// and returns the row. limit bounds what is read from src; scrub, when set,
// removes leased credentials from the bytes on their way into the store, and
// the size and digest recorded are of what was stored.
//
// The caller checks the task's and project's room first (Room); Put checks
// only the file itself, against limit.
func Put(db *statedb.DB, dbPath string, taskID int, meta Meta, src io.Reader, limit int64, scrub *redact.Set) (statedb.AttachmentRow, error) {
	root, err := statedb.OpenAttachmentStore(dbPath, true)
	if err != nil {
		return statedb.AttachmentRow{}, err
	}
	defer root.Close()
	return put(root, db, taskID, meta, src, limit, scrub)
}

// put is Put into a store already open.
func put(root *os.Root, db *statedb.DB, taskID int, meta Meta, src io.Reader, limit int64, scrub *redact.Set) (statedb.AttachmentRow, error) {
	row := statedb.AttachmentRow{
		TaskID: taskID, Name: CleanName(meta.Name), Source: meta.Source, RunID: meta.RunID,
		Note: meta.Note, AddedBy: meta.AddedBy, CreatedAt: meta.CreatedAt,
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now()
	}
	id, err := newID()
	if err != nil {
		return row, err
	}
	row.ID = id

	tmpName := "." + id + ".tmp"
	tmp, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return row, fmt.Errorf("attachments: store %q: %w", row.Name, err)
	}
	cleanup := func() { _ = root.Remove(tmpName); _ = root.Remove(id) }

	sum := sha256.New()
	head := &headBuffer{max: sniffBytes}
	counted := &countingWriter{}
	scrubbed := redact.NewWriter(io.MultiWriter(tmp, sum, head, counted), scrub)
	read, err := io.Copy(scrubbed, io.LimitReader(src, limit+1))
	if err == nil {
		err = scrubbed.Flush()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		cleanup()
		return row, fmt.Errorf("attachments: store %q: %w", row.Name, err)
	case read > limit:
		cleanup()
		return row, fmt.Errorf("%w: %q is over %s", ErrTooLarge, row.Name, HumanBytes(limit))
	}
	if err := root.Rename(tmpName, id); err != nil {
		cleanup()
		return row, fmt.Errorf("attachments: store %q: %w", row.Name, err)
	}
	row.Size = counted.n
	row.SHA256 = hex.EncodeToString(sum.Sum(nil))
	row.MediaType = DetectType(row.Name, head.b)
	if err := recordRow(db, row); err != nil {
		cleanup()
		return row, err
	}
	return row, nil
}

// recordRow records a stored file's row. A variable so a test can make the
// database fail the way a busy or full one does.
var recordRow = (*statedb.DB).AddTaskAttachment

// Record records an attachment whose bytes are not in this store — a remote
// run's file that its result had no room for — with why they are not. Its
// size and digest are what the executor reported.
func Record(db *statedb.DB, taskID int, meta Meta, size int64, sha256Hex, unavailable string) (statedb.AttachmentRow, error) {
	id, err := newID()
	if err != nil {
		return statedb.AttachmentRow{}, err
	}
	row := statedb.AttachmentRow{
		ID: id, TaskID: taskID, Name: CleanName(meta.Name), MediaType: TypeByName(meta.Name),
		Size: min(max(size, 0), MaxFileBytes), SHA256: sha256Hex, Source: meta.Source, RunID: meta.RunID,
		Note: meta.Note, AddedBy: meta.AddedBy, CreatedAt: meta.CreatedAt, Unavailable: unavailable,
	}
	if row.Unavailable == "" {
		row.Unavailable = "the file is not on the hub"
	}
	if err := db.AddTaskAttachment(row); err != nil {
		return row, err
	}
	return row, nil
}

// Room reports why the task cannot take one more file of size bytes, or ""
// when it can.
func Room(u statedb.AttachmentUsage, size int64) string {
	switch {
	case size > MaxFileBytes:
		return fmt.Sprintf("it is %s, over the %s a file may be", HumanBytes(size), HumanBytes(MaxFileBytes))
	case u.TaskFiles+1 > MaxTaskFiles:
		return fmt.Sprintf("the task already has %d attachments, the most a task may have", u.TaskFiles)
	case u.TaskBytes+size > MaxTaskBytes:
		return fmt.Sprintf("the task's attachments would come to %s, over the %s a task may hold",
			HumanBytes(u.TaskBytes+size), HumanBytes(MaxTaskBytes))
	case u.ProjectBytes+size > MaxProjectBytes:
		return fmt.Sprintf("the project's attachments would come to %s, over the %s a project may hold — delete some first",
			HumanBytes(u.ProjectBytes+size), HumanBytes(MaxProjectBytes))
	}
	return ""
}

// Add attaches the file at path to a task by hand, refusing it when it is not
// a regular file or there is no room for it.
func Add(db *statedb.DB, dbPath string, taskID int, path string, meta Meta) (statedb.AttachmentRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return statedb.AttachmentRow{}, fmt.Errorf("attachments: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return statedb.AttachmentRow{}, fmt.Errorf("attachments: %w", err)
	}
	if !info.Mode().IsRegular() {
		return statedb.AttachmentRow{}, fmt.Errorf("%w: %s", ErrNotRegular, path)
	}
	u, err := db.TaskAttachmentUsage(taskID)
	if err != nil {
		return statedb.AttachmentRow{}, err
	}
	if why := Room(u, info.Size()); why != "" {
		return statedb.AttachmentRow{}, fmt.Errorf("%w: %s: %s", ErrQuota, filepath.Base(path), why)
	}
	if meta.Name == "" {
		meta.Name = filepath.Base(path)
	}
	return Put(db, dbPath, taskID, meta, f, MaxFileBytes, nil)
}

// Open opens an attachment's stored bytes for reading.
//
// The file is reached through the store's os.Root, so no link can lead out of
// it, and it must be a regular file both when it is looked at and once it is
// open — so a link, or a FIFO, or a file swapped for one in between, is refused
// rather than read. A file whose size is not the one recorded is refused too:
// the store was changed behind the database's back.
func Open(dbPath string, row statedb.AttachmentRow) (*os.File, os.FileInfo, error) {
	if row.Unavailable != "" {
		return nil, nil, fmt.Errorf("%w: %s", ErrUnavailable, row.Unavailable)
	}
	if !statedb.ValidAttachmentID(row.ID) {
		return nil, nil, fmt.Errorf("%w: invalid id", ErrUnavailable)
	}
	root, err := statedb.OpenAttachmentStore(dbPath, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("%w: the project has no attachment store", ErrUnavailable)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrNotRegular, err)
	}
	defer root.Close()
	rel := row.ID
	before, err := root.Lstat(rel)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("%w: it is missing from the store", ErrUnavailable)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("attachments: %w", err)
	}
	if !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: %s", ErrNotRegular, row.ID)
	}
	f, err := root.OpenFile(rel, os.O_RDONLY|nonBlock, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("attachments: %w", err)
	}
	info, err := f.Stat()
	if err == nil && (!info.Mode().IsRegular() || !os.SameFile(before, info)) {
		err = fmt.Errorf("%w: %s changed while it was opened", ErrNotRegular, row.ID)
	}
	if err == nil && info.Size() != row.Size {
		err = fmt.Errorf("%w: it is %d bytes in the store, not the %d recorded", ErrUnavailable, info.Size(), row.Size)
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

// Sweep removes what the store holds that no row names: files whose rows were
// deleted by something that could not remove them, and copies an attach
// abandoned half-way. Only what is older than minAge is removed, so a file an
// attach in another process has stored but not yet recorded is left alone.
func Sweep(db *statedb.DB, dbPath string, minAge time.Duration) (int, error) {
	root, err := statedb.OpenAttachmentStore(dbPath, false)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer root.Close()
	known, err := db.AttachmentIDs()
	if err != nil {
		return 0, err
	}
	d, err := root.Open(".")
	if err != nil {
		return 0, fmt.Errorf("attachments: read the store: %w", err)
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return 0, fmt.Errorf("attachments: read the store: %w", err)
	}
	cutoff := time.Now().Add(-minAge)
	removed := 0
	for _, e := range entries {
		name := e.Name()
		id := name
		if strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".tmp") {
			id = strings.TrimSuffix(strings.TrimPrefix(name, "."), ".tmp")
		} else if known[id] {
			continue
		}
		if !statedb.ValidAttachmentID(id) || !e.Type().IsRegular() {
			continue
		}
		if info, err := e.Info(); err != nil || info.ModTime().After(cutoff) {
			continue
		}
		if root.Remove(name) == nil {
			removed++
		}
	}
	return removed, nil
}

// HumanBytes renders a byte count for a person.
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}

// sniffBytes is how much of a file content detection looks at: what
// http.DetectContentType reads.
const sniffBytes = 512

// headBuffer keeps the first max bytes written to it.
type headBuffer struct {
	b   []byte
	max int
}

func (h *headBuffer) Write(p []byte) (int, error) {
	if room := h.max - len(h.b); room > 0 {
		h.b = append(h.b, p[:min(len(p), room)]...)
	}
	return len(p), nil
}

// countingWriter counts the bytes written to it.
type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}
