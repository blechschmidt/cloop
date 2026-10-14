package attachments

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Delete removes one attachment of a task at a person's request — its row,
// then its file — and records who did it: an audit row, and a line in the
// project's journal beside the task's history. db must be the project's own
// handle (statedb.DB.AsProject), where a task's audit rows belong. via names
// the surface that asked: "dashboard", "cloop task attachments remove".
func Delete(db *statedb.DB, taskID int, id, actor, via string) (statedb.AttachmentRow, error) {
	row, err := db.DeleteTaskAttachment(taskID, id)
	if err != nil {
		return row, err
	}
	statedb.AuditTaskAttachmentDelete(db, row, actor)
	details, _ := json.Marshal(map[string]any{"deleted": map[string]any{"id": row.ID, "name": row.Name, "size": row.Size}})
	ev := statedb.EventRow{
		Type:    statedb.EventTaskAttachments,
		TaskID:  taskID,
		Step:    statedb.NoStep,
		Message: fmt.Sprintf("Attachment %s (%s) deleted from task #%d by %s (%s)", row.Name, HumanBytes(row.Size), taskID, actor, via),
		Details: string(details),
	}
	if err := db.RecordEvent(ev); err != nil {
		fmt.Fprintf(os.Stderr, "[events] record %s: %v\n", ev.Type, err)
	}
	return row, nil
}

// ErrAmbiguous reports a reference that matches more than one attachment.
var ErrAmbiguous = errors.New("attachments: more than one attachment matches")

// Resolve finds the attachment ref names among a task's rows: its full id, an
// unambiguous id prefix of at least six characters, or its exact name.
func Resolve(rows []statedb.AttachmentRow, ref string) (statedb.AttachmentRow, error) {
	ref = strings.TrimSpace(ref)
	var byPrefix, byName []statedb.AttachmentRow
	for _, r := range rows {
		if r.ID == ref {
			return r, nil
		}
		if len(ref) >= 6 && strings.HasPrefix(r.ID, strings.ToLower(ref)) {
			byPrefix = append(byPrefix, r)
		}
		if r.Name == ref {
			byName = append(byName, r)
		}
	}
	for _, found := range [][]statedb.AttachmentRow{byPrefix, byName} {
		switch len(found) {
		case 0:
			continue
		case 1:
			return found[0], nil
		default:
			ids := make([]string, 0, len(found))
			for _, r := range found {
				ids = append(ids, r.ID[:12])
			}
			return statedb.AttachmentRow{}, fmt.Errorf("%w %q: %s — use the full id", ErrAmbiguous, ref, strings.Join(ids, ", "))
		}
	}
	return statedb.AttachmentRow{}, fmt.Errorf("%w: no attachment %q", statedb.ErrAttachmentNotFound, ref)
}
