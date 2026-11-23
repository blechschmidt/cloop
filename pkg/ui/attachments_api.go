package ui

// attachments_api.go serves the files attached to a task (Task 20428): the
// list a task's details show, the bytes behind each entry, and deletion.
//
// # Why the bytes are served the way they are
//
// An attachment is written by a run, which is model-authored code, and it is
// served from the hub's own origin — the origin the dashboard's session lives
// on. A document served from here could script the dashboard with the viewer's
// session, so nothing is ever served to be rendered as one:
//
//   - The default is a download: application/octet-stream with
//     Content-Disposition: attachment, whatever the file claims to be.
//   - ?inline=1 displays a file only when it is an image a browser decodes as
//     pixels (PNG, JPEG, GIF, WebP) or text shown as text/plain, judged on the
//     bytes in the store now rather than on the type recorded when it was
//     attached (attachments.InlineType). SVG, HTML and PDF are never inline.
//   - Every response carries its own Content-Security-Policy, default-src
//     'none' with sandbox, so even a response a browser was persuaded to
//     render runs nothing; and nosniff, so it cannot be persuaded.
//
// The file itself is reached through attachments.Open, which refuses a link,
// a FIFO, or a file swapped for one while it was opened: on a shared-filesystem
// executor the store is written from inside the sandbox, and the hub reading a
// link would hand the viewer whatever the link points at on the hub's host.
//
// # Input files
//
// A person attaches a file for a task's agent to work with by uploading it
// (Task 20511): POST with the file itself as the body. Every attempt at the
// task is given a copy (pkg/attachments, inbox.go). The body is
// application/octet-stream, the one route of the hub's that takes it: a page
// on another site can send a form or text/plain without asking, but not that
// type, so it is as out of a forger's reach as JSON is — and the origin check
// in front of every state-changing request applies as it does everywhere.

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/jsonbody"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// attachmentContentPolicy is the Content-Security-Policy of every attachment
// response: nothing loads, nothing runs.
const attachmentContentPolicy = "default-src 'none'; sandbox"

// attachmentView is one attachment as the dashboard lists it.
type attachmentView struct {
	statedb.AttachmentRow
	// Previewable says the dashboard may offer to show the file in place.
	// The bytes have the last word: a preview request is served inline only
	// when they agree (attachments.InlineType).
	Previewable bool `json:"previewable"`
}

// openTaskAttachments opens the project database for an attachment request
// and checks the task is in it. It answers the request itself when it cannot.
func (s *Server) openTaskAttachments(w http.ResponseWriter, r *http.Request) (db *statedb.DB, workDir, dbPath string, taskID int, ok bool) {
	taskID, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || taskID <= 0 {
		jsonErr(w, "invalid task id", http.StatusBadRequest)
		return nil, "", "", 0, false
	}
	workDir = s.resolveWorkDir(r)
	dbPath = state.DBPath(workDir)
	// Never create a database by reading one: a project without one has no
	// tasks to attach anything to.
	if _, err := os.Stat(dbPath); err != nil {
		jsonErr(w, "task not found", http.StatusNotFound)
		return nil, "", "", 0, false
	}
	db, err = statedb.Open(dbPath)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return nil, "", "", 0, false
	}
	if _, err := db.LoadTask(taskID); err != nil {
		db.Close()
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return nil, "", "", 0, false
	}
	return db, workDir, dbPath, taskID, true
}

// handleTaskAttachments lists a task's attachments, with what the task and
// the project hold against their limits.
//
// GET /api/tasks/{id}/attachments
func (s *Server) handleTaskAttachments(w http.ResponseWriter, r *http.Request) {
	db, _, _, taskID, ok := s.openTaskAttachments(w, r)
	if !ok {
		return
	}
	defer db.Close()
	rows, err := db.TaskAttachments(taskID)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	usage, err := db.TaskAttachmentUsage(taskID)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	views := make([]attachmentView, 0, len(rows))
	for _, row := range rows {
		views = append(views, attachmentView{
			AttachmentRow: row,
			Previewable:   row.Unavailable == "" && attachments.Previewable(row.MediaType),
		})
	}
	jsonOK(w, map[string]any{
		"ok":          true,
		"task_id":     taskID,
		"attachments": views,
		"usage": map[string]any{
			"task_files": usage.TaskFiles, "task_bytes": usage.TaskBytes,
			"project_files": usage.ProjectFiles, "project_bytes": usage.ProjectBytes,
		},
		"limits": map[string]any{
			"file_bytes": attachments.MaxFileBytes, "task_files": attachments.MaxTaskFiles,
			"task_bytes": attachments.MaxTaskBytes, "project_bytes": attachments.MaxProjectBytes,
		},
	})
}

// handleTaskAttachmentGet serves an attachment's bytes: as a download, or —
// with ?inline=1, and only for an image or text the bytes confirm — to be
// shown in place. Range and conditional requests are honoured.
//
// GET /api/tasks/{id}/attachments/{aid}
func (s *Server) handleTaskAttachmentGet(w http.ResponseWriter, r *http.Request) {
	db, _, dbPath, taskID, ok := s.openTaskAttachments(w, r)
	if !ok {
		return
	}
	row, err := db.TaskAttachment(taskID, r.PathValue("aid"))
	db.Close()
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	f, info, err := attachments.Open(dbPath, row)
	switch {
	case errors.Is(err, attachments.ErrUnavailable):
		jsonErr(w, "attachment "+row.Name+" cannot be served: "+err.Error(), http.StatusGone)
		return
	case errors.Is(err, attachments.ErrNotRegular):
		jsonErr(w, "attachment "+row.Name+" is not a regular file in the store; it was not served", http.StatusConflict)
		return
	case err != nil:
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	head := make([]byte, 512)
	n, _ := f.ReadAt(head, 0)
	head = head[:n]
	disposition, contentType := "attachment", "application/octet-stream"
	if r.URL.Query().Get("inline") == "1" {
		if t, ok := attachments.InlineType(row.MediaType, head); ok {
			disposition, contentType = "inline", t
		}
	}
	h := w.Header()
	h.Set("Content-Security-Policy", attachmentContentPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cache-Control", "private, no-cache")
	h.Set("Content-Type", contentType)
	cd := mime.FormatMediaType(disposition, map[string]string{"filename": attachments.BaseName(row.Name)})
	if cd == "" {
		cd = disposition
	}
	h.Set("Content-Disposition", cd)
	if row.SHA256 != "" {
		h.Set("ETag", `"`+row.SHA256+`"`)
	}
	// Exactly the bytes recorded: Open checked the size, and a file the
	// workload goes on appending to is served as it was attached.
	http.ServeContent(w, r, "", info.ModTime(), io.NewSectionReader(f, 0, row.Size))
}

// handleTaskAttachmentDelete deletes an attachment — its row and its file —
// and records who did it in the project's audit trail and journal.
//
// DELETE /api/tasks/{id}/attachments/{aid}
func (s *Server) handleTaskAttachmentDelete(w http.ResponseWriter, r *http.Request) {
	db, workDir, _, taskID, ok := s.openTaskAttachments(w, r)
	if !ok {
		return
	}
	db.AsProject()
	row, err := attachments.Delete(db, taskID, r.PathValue("aid"), s.auditActor(r), "dashboard")
	db.Close()
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	s.broadcastAuditAppend(string(auditaction.ActionTaskAttachmentDelete))
	// The task's count and the journal line, pushed now rather than on the
	// watcher's next look at the database: every open dashboard's row for
	// the task shows the file gone.
	if ps, err := state.LoadLite(workDir); err == nil {
		s.broadcastStateDiff(workDir, ps)
	}
	s.pushHistory(workDir)
	jsonOK(w, map[string]any{"ok": true, "deleted": row})
}

// uploadMediaType is the one body type the upload route takes: the file's
// bytes, unencoded.
const uploadMediaType = "application/octet-stream"

// maxUploadNoteBytes bounds the note an upload carries in its query, as the
// database bounds a row's note.
const maxUploadNoteBytes = 1024

// uploadRoutePath reports whether path is a task's upload route,
// /api/tasks/{id}/attachments, for the origin guard's media rule.
func uploadRoutePath(path string) bool {
	rest, ok := strings.CutPrefix(path, "/api/tasks/")
	if !ok {
		return false
	}
	id, tail, ok := strings.Cut(rest, "/")
	if !ok || tail != "attachments" || id == "" || len(id) > 18 {
		return false
	}
	for _, c := range id {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// handleTaskAttachmentUpload attaches the file a person uploads to a task as
// an input file for its agent: every attempt at the task, from the next one
// on, is given a copy (Task 20511).
//
// POST /api/tasks/{id}/attachments?name=<file name>[&note=<note>]
//
// The body is the file, Content-Type: application/octet-stream. It is held to
// the limits every attachment is — a file, the task's and the project's — and
// refused whole when over one, never truncated. The upload is on the
// project's audit trail and in its journal.
func (s *Server) handleTaskAttachmentUpload(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); !jsonbody.IsMediaType(ct, uploadMediaType) {
		got := "no Content-Type"
		if strings.TrimSpace(ct) != "" {
			got = fmt.Sprintf("Content-Type %q", ct)
		}
		jsonErr(w, "this endpoint takes the file itself as the body, Content-Type: "+uploadMediaType+
			"; the request sent "+got, http.StatusUnsupportedMediaType)
		return
	}
	q := r.URL.Query()
	rawName := strings.TrimSpace(q.Get("name"))
	if rawName == "" {
		jsonErr(w, "name is required: the file's name, as ?name=…", http.StatusBadRequest)
		return
	}
	name := attachments.BaseName(rawName)
	note := strings.TrimSpace(q.Get("note"))
	if len(note) > maxUploadNoteBytes || !utf8.ValidString(note) {
		jsonErr(w, fmt.Sprintf("note must be valid UTF-8 of at most %d bytes", maxUploadNoteBytes), http.StatusBadRequest)
		return
	}
	if r.ContentLength > attachments.MaxFileBytes {
		jsonErr(w, fmt.Sprintf("%s is %s, over the %s a file may be", name, attachments.HumanBytes(r.ContentLength),
			attachments.HumanBytes(attachments.MaxFileBytes)), http.StatusRequestEntityTooLarge)
		return
	}
	db, workDir, dbPath, taskID, ok := s.openTaskAttachments(w, r)
	if !ok {
		return
	}
	defer db.Close()
	db.AsProject()
	task, err := db.LoadTask(taskID)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	stored, err := db.TaskAttachmentUsage(taskID)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	// What the hub holds for remote runs takes room too (Task 20513).
	stored.ProjectBytes += attachments.HeldBytes(dbPath)
	// The room this upload may take, counting what uploads still in flight
	// have taken, and taken before a byte is read: uploads at once cannot
	// together hold more of the disk than one could alone.
	limit, release, why, status := attachmentUploads.take(dbPath, taskID, stored, r.ContentLength)
	if why != "" {
		jsonErr(w, name+" was not attached: "+why, status)
		return
	}
	defer release()
	// A body that trickles in holds its slot only so long: a minute, and
	// what the file needs at a slow line's speed.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(uploadReadTime(limit)))
	actor := s.auditActor(r)
	row, err := attachments.Put(db, dbPath, taskID, attachments.Meta{
		Name: name, Source: statedb.AttachmentSourceUpload, Role: statedb.AttachmentRoleInput,
		Note: note, AddedBy: actor, CreatedAt: time.Now(),
	}, http.MaxBytesReader(w, r.Body, limit+1), limit, nil)
	var tooBig *http.MaxBytesError
	switch {
	case errors.Is(err, attachments.ErrTooLarge) || errors.As(err, &tooBig):
		jsonErr(w, fmt.Sprintf("%s was not attached: it is larger than the %s this task has room for",
			name, attachments.HumanBytes(limit)), http.StatusRequestEntityTooLarge)
		return
	case err != nil:
		jsonErr(w, name+" was not attached: "+err.Error(), statedb.HTTPStatus(err))
		return
	}
	// Two uploads at once may each have found room the other then took:
	// checked again with both recorded, and this one given back if the task
	// or the project is now over a limit.
	if after, err := db.TaskAttachmentUsage(taskID); err == nil && overAttachmentLimits(after) {
		_, _ = db.DeleteTaskAttachment(taskID, row.ID)
		jsonErr(w, name+" was not attached: other files attached at the same time took the room it needed",
			http.StatusRequestEntityTooLarge)
		return
	}
	statedb.AuditTaskAttachmentAdd(db, row, actor, "dashboard")
	s.broadcastAuditAppend(string(auditaction.ActionTaskAttachmentAdd))
	attachmentUploads.sweep(db, dbPath)
	message := fmt.Sprintf("%s added %s (%s) to task %d as an input file for its agent",
		actor, row.Name, attachments.HumanBytes(row.Size), taskID)
	state.LogEventDetails(workDir, state.EventRow{
		Type: state.EventTaskAttachments, TaskID: taskID, TaskTitle: task.Title, Step: state.NoStep, Message: message,
	}, map[string]any{"added": []map[string]any{{
		"id": row.ID, "name": row.Name, "size": row.Size, "media_type": row.MediaType, "sha256": row.SHA256,
		"role": row.Role,
	}}, "by": actor})
	if ps, err := state.LoadLite(workDir); err == nil {
		s.broadcastStateDiff(workDir, ps)
	}
	s.pushHistory(workDir)
	writeJSONStatus(w, http.StatusCreated, map[string]any{
		"ok": true,
		"attachment": attachmentView{
			AttachmentRow: row,
			Previewable:   attachments.Previewable(row.MediaType),
		},
		// An attempt already running was given the task's input files when
		// it started: this one reaches the next.
		"running": task.Status == pm.TaskInProgress,
	})
}

// Uploads in flight on this hub process: at most this many in all, and this
// many to one project's store, at once.
const (
	maxUploadsInFlight   = 16
	maxUploadsPerProject = 4
)

// uploadMinBytesPerSecond is the slowest an upload may arrive at before its
// read deadline (uploadReadTime) ends it.
const uploadMinBytesPerSecond = 64 << 10

// uploadReadTime is how long an upload of at most limit bytes may take.
func uploadReadTime(limit int64) time.Duration {
	return time.Minute + time.Duration(limit/uploadMinBytesPerSecond)*time.Second
}

// attachmentUploads is every upload this process is receiving.
var attachmentUploads = &uploadGate{projects: map[string]*projectUploads{}, swept: map[string]time.Time{}}

// uploadGate counts the uploads in flight and the room each has taken, by
// project store (the database path) and task. Every check an upload makes
// against the limits adds what is taken here to what the database records, so
// two uploads at once cannot each find room only one of them has. The check
// after an upload is recorded (overAttachmentLimits) still runs: another hub
// process, or the CLI, attaches without asking this one.
type uploadGate struct {
	mu       sync.Mutex
	total    int
	projects map[string]*projectUploads
	// swept is when each store was last swept of what an upload a dead
	// process was receiving left behind.
	swept map[string]time.Time
}

type projectUploads struct {
	n     int
	bytes int64
	tasks map[int]*statedb.AttachmentUsage // TaskFiles and TaskBytes taken per task
}

// take admits an upload of size bytes (-1: sent without a length) to task of
// the store dbPath, whose recorded usage is stored. It returns the most the
// upload may hold and the release that gives its room back; or why it is
// refused, with the status to answer.
func (g *uploadGate) take(dbPath string, task int, stored statedb.AttachmentUsage, size int64) (int64, func(), string, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := g.projects[dbPath]
	if p == nil {
		p = &projectUploads{tasks: map[int]*statedb.AttachmentUsage{}}
	}
	if g.total >= maxUploadsInFlight || p.n >= maxUploadsPerProject {
		return 0, nil, "too many uploads are in progress; try again when they have finished", http.StatusTooManyRequests
	}
	u := stored
	u.ProjectBytes += p.bytes
	if t := p.tasks[task]; t != nil {
		u.TaskFiles += t.TaskFiles
		u.TaskBytes += t.TaskBytes
	}
	room := max(0, min(attachments.MaxFileBytes, attachments.MaxTaskBytes-u.TaskBytes, attachments.MaxProjectBytes-u.ProjectBytes))
	if size < 0 {
		// A body sent without a length may take what is left, and is read
		// up to that and refused past it.
		size = room
	}
	if why := attachments.Room(u, size); why != "" {
		return 0, nil, why, http.StatusRequestEntityTooLarge
	}
	t := p.tasks[task]
	if t == nil {
		t = &statedb.AttachmentUsage{}
		p.tasks[task] = t
	}
	g.total++
	p.n++
	p.bytes += size
	t.TaskFiles++
	t.TaskBytes += size
	g.projects[dbPath] = p
	var once sync.Once
	return size, func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.total--
			p.n--
			p.bytes -= size
			t.TaskFiles--
			t.TaskBytes -= size
			if t.TaskFiles == 0 {
				delete(p.tasks, task)
			}
			if p.n == 0 {
				delete(g.projects, dbPath)
			}
		})
	}, "", 0
}

// uploadSweepEvery is how often an upload sweeps its project's store.
const uploadSweepEvery = time.Hour

// sweep removes from the store at dbPath, at most once an hour, what no row
// names and is over an hour old: above all the partial copy of an upload a
// process died receiving, which nothing else here would remove until the
// project's next run.
func (g *uploadGate) sweep(db *statedb.DB, dbPath string) {
	g.mu.Lock()
	due := time.Since(g.swept[dbPath]) >= uploadSweepEvery
	if due {
		g.swept[dbPath] = time.Now()
		if len(g.swept) > 4096 {
			for k, at := range g.swept {
				if time.Since(at) >= uploadSweepEvery {
					delete(g.swept, k)
				}
			}
		}
	}
	g.mu.Unlock()
	if due {
		_, _ = attachments.Sweep(db, dbPath, uploadSweepEvery)
	}
}

// overAttachmentLimits reports whether a task's or its project's attachments
// are past a limit.
func overAttachmentLimits(u statedb.AttachmentUsage) bool {
	return u.TaskFiles > attachments.MaxTaskFiles || u.TaskBytes > attachments.MaxTaskBytes ||
		u.ProjectBytes > attachments.MaxProjectBytes
}
