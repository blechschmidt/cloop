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

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"strconv"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/auditaction"
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
