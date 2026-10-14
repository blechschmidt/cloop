package attachments

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Bounds on one walk of an outbox. A run can put anything there, including a
// directory tree deep or wide enough to make the walk the expensive part.
const (
	maxOutboxDepth   = 8
	maxOutboxEntries = 1000
)

// Refusal names a file an ingest did not attach, and why.
type Refusal struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// Report is what one ingest did.
type Report struct {
	Added   []statedb.AttachmentRow
	Refused []Refusal
}

// Empty reports whether the outbox held nothing at all.
func (r Report) Empty() bool { return len(r.Added) == 0 && len(r.Refused) == 0 }

// IngestOptions describe the attempt whose outbox is being emptied.
type IngestOptions struct {
	// RunID is the execution the files are attributed to.
	RunID string
	// Scrub removes the credentials leased to the run from the files on their
	// way into the store, as the provider's redaction does for its transcript.
	Scrub *redact.Set
}

// Env is what an agent working on a task is given: where its outbox is, and
// which task it is working on.
func Env(taskID int, outbox string) []string {
	return []string{EnvOutbox + "=" + outbox, EnvTaskID + "=" + strconv.Itoa(taskID)}
}

// PromptSection is what a task's prompt says about its outbox. Short: it is
// part of every task's prompt.
func PromptSection(taskID int, outbox string) string {
	return fmt.Sprintf("## ATTACHMENTS\n"+
		"If this task produces files a person should look at — a report, a chart, a screenshot, "+
		"a data export, a log — copy them into %s (also $%s). When this attempt ends they are "+
		"attached to task %d and shown with it in the dashboard; the directory is then emptied, so "+
		"copy rather than move. At most %s per file. Never put credentials there.\n\n",
		outbox, EnvOutbox, taskID, HumanBytes(MaxFileBytes))
}

// Ingest moves the files a run left in a task's outbox into the store and
// records them. Every regular file at any depth is attached under its path
// inside the outbox; links, devices and FIFOs are not followed or read, only
// named in the report, as is every file the limits leave no room for.
//
// The outbox is emptied of everything it handled, attached or refused, and
// left in place itself: an attempt that is still running may put more in it.
// A file that failed for a reason that may pass — a full disk, a busy
// database — stays, and is tried again by the next ingest. An outbox that does
// not exist is not an error: most attempts attach nothing.
func Ingest(db *statedb.DB, dbPath string, taskID int, opts IngestOptions) (Report, error) {
	var rep Report
	root, err := statedb.OpenAttachmentStore(dbPath, false)
	if errors.Is(err, os.ErrNotExist) {
		return rep, nil
	}
	if err != nil {
		return rep, fmt.Errorf("attachments: the outbox of task %d: %w", taskID, err)
	}
	defer root.Close()
	rel := outboxRel(taskID)
	info, err := root.Lstat(rel)
	if errors.Is(err, os.ErrNotExist) {
		return rep, nil
	}
	if err != nil {
		return rep, fmt.Errorf("attachments: the outbox of task %d: %w", taskID, err)
	}
	if !info.IsDir() {
		rep.Refused = append(rep.Refused, Refusal{
			Name:   rel,
			Reason: "the outbox is not a directory — a link? — so nothing in it was read",
		})
		_ = root.Remove(rel)
		return rep, nil
	}
	box, err := root.OpenRoot(rel)
	if err != nil {
		return rep, fmt.Errorf("attachments: open the outbox of task %d: %w", taskID, err)
	}
	defer box.Close()
	if now, err := box.Stat("."); err != nil || !os.SameFile(info, now) {
		return rep, fmt.Errorf("%w: the outbox of task %d changed while it was opened", ErrNotRegular, taskID)
	}

	w := &walker{root: box}
	w.walk(".", 0)
	rep.Refused = append(rep.Refused, w.refused...)
	if w.truncated {
		rep.Refused = append(rep.Refused, Refusal{
			Name:   "…",
			Reason: fmt.Sprintf("the outbox holds more than %d entries; the rest were not looked at", maxOutboxEntries),
		})
	}

	usage, err := db.TaskAttachmentUsage(taskID)
	if err != nil {
		return rep, err
	}
	for _, c := range w.files {
		name := CleanName(c.rel)
		if why := Room(usage, c.info.Size()); why != "" {
			rep.Refused = append(rep.Refused, Refusal{Name: name, Reason: "not attached: " + why})
			continue
		}
		f, err := openUnchanged(box, c.rel, c.info)
		if err != nil {
			rep.Refused = append(rep.Refused, Refusal{Name: name, Reason: "not attached: " + err.Error()})
			continue
		}
		row, err := put(root, db, taskID, Meta{
			Name: name, Source: statedb.AttachmentSourceRun, RunID: opts.RunID, AddedBy: "agent",
		}, f, MaxFileBytes, opts.Scrub)
		f.Close()
		switch {
		case err == nil:
			usage.TaskFiles++
			usage.TaskBytes += row.Size
			usage.ProjectFiles++
			usage.ProjectBytes += row.Size
			rep.Added = append(rep.Added, row)
			_ = box.Remove(c.rel)
		case errors.Is(err, ErrTooLarge):
			rep.Refused = append(rep.Refused, Refusal{Name: name, Reason: "not attached: " + err.Error()})
		case errors.Is(err, statedb.ErrTaskNotFound):
			// The task is gone; so is anything it would have attached.
			rep.Refused = append(rep.Refused, Refusal{Name: name, Reason: "not attached: the task is no longer in the plan"})
		default:
			rep.Refused = append(rep.Refused, Refusal{Name: name,
				Reason: "not attached yet: " + err.Error() + "; it stays in the outbox and is tried again"})
			w.keep(c.rel)
		}
	}

	// Emptied of what was handled. Left in place, a refused file would be
	// refused again by every later ingest, and the outbox would grow with
	// every run that put something too large in it. RemoveAll unlinks a link
	// rather than following it, and box keeps it inside the outbox.
	if err := w.clear(); err != nil {
		return rep, fmt.Errorf("attachments: empty the outbox of task %d: %w", taskID, err)
	}
	return rep, nil
}

// candidate is a regular file a walk found.
type candidate struct {
	rel  string
	info fs.FileInfo
}

// walker lists an outbox through an os.Root, so no link can take it outside
// the outbox, and looks at every entry without following it.
type walker struct {
	root      *os.Root
	files     []candidate
	refused   []Refusal
	seen      int
	truncated bool
	// kept are the files an ingest leaves in the outbox, and the directories
	// on the way to them.
	kept map[string]bool
}

// keep marks rel, and every directory above it, to be left by clear.
func (w *walker) keep(rel string) {
	if w.kept == nil {
		w.kept = map[string]bool{}
	}
	for p := rel; p != "." && p != "/" && p != ""; p = path.Dir(p) {
		w.kept[p] = true
	}
}

// clear removes everything in the outbox but what keep marked.
func (w *walker) clear() error {
	return w.clearDir(".")
}

func (w *walker) clearDir(dir string) error {
	d, err := w.root.Open(dir)
	if err != nil {
		return err
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return err
	}
	var first error
	for _, e := range entries {
		rel := path.Join(dir, e.Name())
		switch {
		case !w.kept[rel]:
			if err := w.root.RemoveAll(rel); err != nil && first == nil {
				first = err
			}
		case e.IsDir():
			if err := w.clearDir(rel); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

func (w *walker) walk(dir string, depth int) {
	d, err := w.root.Open(dir)
	if err != nil {
		w.refused = append(w.refused, Refusal{Name: CleanName(dir), Reason: "could not be read: " + err.Error()})
		return
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		w.refused = append(w.refused, Refusal{Name: CleanName(dir), Reason: "could not be read: " + err.Error()})
	}
	for _, e := range entries {
		if w.seen >= maxOutboxEntries {
			w.truncated = true
			return
		}
		w.seen++
		rel := path.Join(dir, e.Name())
		switch t := e.Type(); {
		case t.IsDir():
			if depth+1 >= maxOutboxDepth {
				w.refused = append(w.refused, Refusal{Name: CleanName(rel) + "/",
					Reason: fmt.Sprintf("nested more than %d directories deep; not looked into", maxOutboxDepth)})
				continue
			}
			w.walk(rel, depth+1)
		case t&fs.ModeSymlink != 0:
			w.refused = append(w.refused, Refusal{Name: CleanName(rel),
				Reason: "a symbolic link, which is not followed: copy the file itself into the outbox"})
		case t.IsRegular():
			info, err := w.root.Lstat(rel)
			if err != nil || !info.Mode().IsRegular() {
				w.refused = append(w.refused, Refusal{Name: CleanName(rel), Reason: "changed while the outbox was read"})
				continue
			}
			w.files = append(w.files, candidate{rel: rel, info: info})
		default:
			w.refused = append(w.refused, Refusal{Name: CleanName(rel), Reason: "not a regular file"})
		}
	}
}

// openUnchanged opens rel for reading and checks it is still the regular file
// the walk saw, so a file swapped for a link or a FIFO in between is refused.
func openUnchanged(root *os.Root, rel string, seen fs.FileInfo) (*os.File, error) {
	f, err := root.OpenFile(rel, os.O_RDONLY|nonBlock, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && (!info.Mode().IsRegular() || !os.SameFile(seen, info)) {
		err = fmt.Errorf("%w: it changed while the outbox was read", ErrNotRegular)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// Summary is the one line the event journal records for an ingest.
func Summary(taskID int, rep Report) string {
	var b strings.Builder
	if n := len(rep.Added); n > 0 {
		fmt.Fprintf(&b, "Attached %d %s to task #%d: ", n, plural(n, "file", "files"), taskID)
		for i, a := range rep.Added {
			if i == 5 {
				fmt.Fprintf(&b, " and %d more", n-i)
				break
			}
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%s (%s)", a.Name, HumanBytes(a.Size))
		}
	}
	if n := len(rep.Refused); n > 0 {
		if b.Len() > 0 {
			b.WriteString(". ")
		}
		fmt.Fprintf(&b, "%d %s in task #%d's outbox not attached: ", n, plural(n, "file", "files"), taskID)
		for i, r := range rep.Refused {
			if i == 3 {
				fmt.Fprintf(&b, "; and %d more", n-i)
				break
			}
			if i > 0 {
				b.WriteString("; ")
			}
			fmt.Fprintf(&b, "%s — %s", r.Name, r.Reason)
		}
	}
	return b.String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
