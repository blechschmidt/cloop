package projectseed

// send.go sends the hub the files a finished seeded run attached and did not
// send itself (Task 20515).
//
// A run whose project was seeded into its sandbox sends each file it attaches
// to the hub as the attempt that made it ends (pkg/orchestrator,
// resultsend.go), over the run session the hub dispatched it with
// (knowledgerun.EnvResultsURL, EnvResultsToken). Not every run manages it: the
// `cloop` that runs a container's payload is the image's, and an image built
// before that feature sends nothing; a send the hub could not take while the
// run went on, because it was restarting or busy, is given up when the run
// ends. Whatever was not sent came home only in the run's result, as far as
// its one frame had room — and that is how a run on an edge device had four
// of its thirteen files recorded on the hub without their bytes.
//
// The agent that ran the workload holds the same session and outlives the
// run. Once the workload has exited, before its result is read back, it sends
// what the run did not, the same way the run would have: one file at a time,
// to the same endpoint, under the id the run gave the file, which the hub
// checks and records exactly as it does the run's own sends. Each file sent is
// marked in the run's store (attachments.MarkSent), so the result then
// describes it without carrying it.
//
// Everything is read the way Harvest reads it: the workspace's .cloop must be
// a real directory, its database no link, and each file is opened through the
// store's os.Root and must be the plain file its row describes.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ResultSender sends one file a run attached to the hub: a
// *knowledgerun.Client made from the run's session.
type ResultSender interface {
	SendResult(ctx context.Context, u knowledgerun.ResultUpload, body io.Reader) (*knowledgerun.ResultResponse, error)
}

// SentFile is one file SendAttachments sent.
type SentFile struct {
	Name string
	// Task is the task's id in the run's plan.
	Task int
	Size int64
	// Outcome is what the hub did with it: knowledgerun.ResultAttached, to
	// HubTask, or knowledgerun.ResultHeld for the run's result to place.
	Outcome string
	HubTask int
}

// SendReport is what SendAttachments did, for the run's log.
type SendReport struct {
	// Found is how many files the run attached and had not sent.
	Found int
	// Sent are the files the hub took.
	Sent []SentFile
	// NotSent says, one sentence each, which files were not sent and why.
	NotSent []string
	// Stopped says why the files after a failure were not tried: the hub
	// could not be reached, or refused the session, or time ran out. Empty
	// when every file was tried.
	Stopped string
}

// sendRetryWaits are the pauses before each further try of a file whose send
// failed for a reason that may pass: the hub restarting, or busy. A variable
// so a test does not wait them out.
var sendRetryWaits = []time.Duration{time.Second, 5 * time.Second, 15 * time.Second}

// SendAttachments sends the hub, through s, every file the run in dir attached
// as a result of its tasks and has not marked sent — the run's own sends are
// not repeated — and marks each one the hub took. seed is what the workload was
// started with: it says which tasks the run was given, and under which titles,
// so a file of a task the run created or retitled is sent as such and the hub
// holds it for the run's result to place. scrub is applied to what the report
// says.
//
// It returns an error only when it could not tell what there was to send; a
// file that could not be sent is in the report, and comes back in the run's
// result instead, as far as the result has room.
func SendAttachments(ctx context.Context, dir string, seed []byte, s ResultSender, scrub func(string) string) (SendReport, error) {
	var rep SendReport
	if s == nil {
		return rep, nil
	}
	if scrub == nil {
		scrub = func(s string) string { return s }
	}
	base, err := decodeSeed(seed)
	if err != nil {
		return rep, err
	}
	dbPath, err := workspaceDB(dir)
	if err != nil {
		return rep, err
	}
	// A run that never opened its project attached nothing, and opening a
	// database that is not there would create one.
	if _, err := os.Lstat(dbPath); errors.Is(err, os.ErrNotExist) {
		return rep, nil
	}
	todo, err := unsentAttachments(dbPath)
	if err != nil || len(todo) == 0 {
		return rep, err
	}
	rep.Found = len(todo)
	given := map[int]string{}
	if base.Plan != nil {
		for _, t := range base.Plan.Tasks {
			if t != nil {
				given[t.ID] = strings.TrimSpace(t.Title)
			}
		}
	}
	failing := 0
	for _, f := range todo {
		if ctx.Err() != nil {
			rep.Stopped = endedText(ctx)
			break
		}
		name := scrub(f.row.Name)
		seedTitle, wasGiven := given[f.row.TaskID]
		u := knowledgerun.ResultUpload{
			ID: f.row.ID, Task: f.row.TaskID, TitleSHA256: knowledgerun.TitleDigest(f.title), Name: f.row.Name,
			Size: f.row.Size, SHA256: f.row.SHA256, CreatedAt: f.row.CreatedAt,
			Created: !wasGiven || seedTitle != f.title,
		}
		resp, err := sendFile(ctx, s, dbPath, f.row, u)
		if err == nil {
			failing = 0
			if merr := attachments.MarkSent(dbPath, f.row.ID); merr != nil {
				// The hub has it either way. Unmarked, the result carries it
				// too, as far as it has room, and the hub records it once:
				// it was sent under the run's id.
				rep.NotSent = append(rep.NotSent, fmt.Sprintf("%s: sent, but not marked sent here: %s", name,
					scrub(merr.Error())))
			}
			rep.Sent = append(rep.Sent, SentFile{Name: name, Task: f.row.TaskID, Size: f.row.Size,
				Outcome: resp.Outcome, HubTask: resp.Task})
			continue
		}
		why := scrub(sendErrText(err))
		rep.NotSent = append(rep.NotSent, fmt.Sprintf("%s (task %d): %s", name, f.row.TaskID, why))
		var api *knowledgerun.APIError
		var unreadable *unreadableError
		switch {
		case ctx.Err() != nil:
			rep.Stopped = endedText(ctx)
		case errors.As(err, &unreadable):
			// This file's own trouble; the next one may be fine.
		case errors.As(err, &api) && (api.Status == 401 || api.Status == 403):
			// The session is over, or was never this run's to use: no other
			// file would fare differently.
			rep.Stopped = "the hub refused the run's session: " + why
		case !errors.As(err, &api) && knowledgerun.Retryable(err):
			// Not reached at all, after every try: the next file goes to
			// the same address.
			rep.Stopped = "the hub could not be reached: " + why
		case knowledgerun.Retryable(err):
			// Busy or failing after every try. Once may be this file;
			// twice in a row is the hub.
			if failing++; failing >= 2 {
				rep.Stopped = "the hub kept failing: " + why
			}
		default:
			failing = 0
		}
		if rep.Stopped != "" {
			break
		}
	}
	return rep, nil
}

// unsentFile is one file SendAttachments sends: its row, and the title its
// task has in the run's plan as the run left it.
type unsentFile struct {
	row   statedb.AttachmentRow
	title string
}

// unsentAttachments returns the files the run in the database at dbPath
// attached as results and has not marked sent — the oldest, as many as a
// result may describe — smallest first: the small ones take little time, and
// a large one, which the run's result may not carry either, gets the rest of
// it. The database is closed before anything is sent.
func unsentAttachments(dbPath string) ([]unsentFile, error) {
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("projectseed: open %s to read the run's attachments: %w", dbPath, err)
	}
	defer db.Close()
	rows, err := db.AllTaskAttachments()
	if err != nil {
		return nil, fmt.Errorf("projectseed: read the run's attachments: %w", err)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].CreatedAt.Before(rows[j].CreatedAt) })
	titles := map[int]string{}
	var out []unsentFile
	for _, row := range rows {
		// A task's input files are the hub's (Task 20511), and a row the run
		// itself recorded without its file has nothing to send.
		if row.Role != statedb.AttachmentRoleResult || row.Unavailable != "" ||
			!statedb.ValidAttachmentID(row.ID) || attachments.WasSent(dbPath, row.ID) {
			continue
		}
		if len(out) == maxResultAttachments {
			break
		}
		title, ok := titles[row.TaskID]
		if !ok {
			if t, err := db.LoadTask(row.TaskID); err == nil && t != nil {
				title = strings.TrimSpace(t.Title)
			}
			titles[row.TaskID] = title
		}
		out = append(out, unsentFile{row: row, title: title})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].row.Size < out[j].row.Size })
	return out, nil
}

// sendFile sends one file, trying again after each of sendRetryWaits while the
// failure is one that may pass.
func sendFile(ctx context.Context, s ResultSender, dbPath string, row statedb.AttachmentRow,
	u knowledgerun.ResultUpload) (*knowledgerun.ResultResponse, error) {
	for try := 0; ; try++ {
		f, _, err := attachments.Open(dbPath, row)
		if err != nil {
			// Removed, or no longer the plain file its row describes: there is
			// nothing to send, and nothing the result could carry either.
			return nil, &unreadableError{err: err}
		}
		resp, err := s.SendResult(ctx, u, f)
		f.Close()
		if err == nil && resp == nil {
			err = errors.New("the hub sent no answer")
		}
		if err == nil || !knowledgerun.Retryable(err) || try >= len(sendRetryWaits) || ctx.Err() != nil {
			return resp, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(sendRetryWaits[try]):
		}
	}
}

// endedText says why the sending stopped when ctx did: its time ran out, or
// it was called off — the run was stopped.
func endedText(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "there was no time left to send them before the run's outcome is reported"
	}
	return "sending was called off, the run having been stopped"
}

// unreadableError is a file sendFile could not open: the file's own trouble,
// not the hub's.
type unreadableError struct{ err error }

func (e *unreadableError) Error() string { return "it could not be read: " + e.err.Error() }
func (e *unreadableError) Unwrap() error { return e.err }

// sendErrText is a failed send's reason as a person reads it in the run's log.
func sendErrText(err error) string {
	var api *knowledgerun.APIError
	if errors.As(err, &api) {
		if api.Message == "" {
			return fmt.Sprintf("the hub answered %d", api.Status)
		}
		return fmt.Sprintf("the hub answered %d: %s", api.Status, api.Message)
	}
	return strings.TrimPrefix(err.Error(), "knowledge search: ")
}
