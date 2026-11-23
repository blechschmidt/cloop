package ui

// results_run_api.go: the files a seeded run attaches, sent to the hub while
// the run goes on (Task 20513).
//
//	POST /api/run/knowledge/results?id=&task=&title_sha256=&name=&size=&sha256=&created_at=[&created=1]
//	     Content-Type: application/octet-stream, the file as the body
//
// A run on the hub's host, or in a container that mounts the project, attaches
// files straight into the project's store. A run seeded into its sandbox — an
// edge device, a Kubernetes Pod, a containerised feature — attaches them in its
// own copy of the project, and its result, read back when the run is over,
// carries only as many of them as fit its one transport frame. So every such
// run with a network is given its run session for this too (knowledge_run.go,
// applyRunSession), and sends each file when the attempt that made it ends;
// the agent of a device sends, the same way and with the same session, what
// the run did not send before it ended (Task 20515).
//
// What the hub does with one:
//
//   - The bytes are received into the hub's hold for the run
//     (pkg/attachments, held.go) and checked against the size and SHA-256 sent
//     with them before anything else happens. A file that does not check out
//     is refused and nothing of it is kept.
//   - It is attached to the hub's task straight away when the task is one the
//     run was sent — named by its id and the digest of its title, and the hub
//     still has it under that title — and this hub process is the one
//     streaming the run, holding the redaction set that scrubs its log: the
//     file is scrubbed with that set on its way into the store, as every
//     other thing the run sends back is.
//   - Otherwise it is held: for a task the run created, whose id the hub may
//     have given to another task; for a task renamed on the hub while the run
//     went on; and on a hub member that is not streaming the run. The run's
//     result, merged when the run ends, says which task each held file belongs
//     to (projectseed.Apply), and a run whose result never comes still has its
//     files attached to the tasks they were sent for (projectseed.ClaimHeld).
//
// Either way the file is recorded under the id the run gave it, so one that
// also arrives in the run's result is one attachment, not two; and a run that
// sends a file again because the answer never reached it is told where it is.
//
// The session sends its own project's files and nothing else. Every file it
// sends, kept or refused, is on the control plane's audit trail
// (run.result_upload). Since a hostile agent holds the token, every send is
// bounded the way a person's upload is — the file, the task's and the
// project's limits, counting what the hub holds for runs, taken before a byte
// is read; four uploads to a project and sixteen to a hub process at once; a
// read deadline — and held to the session's own rate and byte budget.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/jsonbody"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Each session's rate for sending files: every file of a task that has the
// most a task may have fits the burst, twice over.
var (
	runResultsRate  = 2.0
	runResultsBurst = float64(2*attachments.MaxTaskFiles + 10)
)

// runResultsPath is the route a run sends its files to, for the origin guard's
// media rule.
const runResultsPath = knowledgerun.MountPath + knowledgerun.PathResults

// heldResultsMaxAge is how long the hub keeps what it holds for a run that is
// over once nothing was sent to it, when no merge took it: the merge takes it
// the moment the run ends, so this is for a run the hub lost track of.
var heldResultsMaxAge = 24 * time.Hour

// errRunResultsScope is the answer to a session that was not given this: a
// run whose project is the hub's own attaches its files into the project's
// store itself.
const errRunResultsScope = "this run's session was not given the files its tasks attach: a run that is not " +
	"seeded into its sandbox attaches them into the project's own store"

// handleRunResult receives one file a seeded run attached.
//
// POST /api/run/knowledge/results
func (s *Server) handleRunResult(w http.ResponseWriter, r *http.Request) {
	call, ok := s.openRunKnowledgeCall(w, r)
	if !ok {
		return
	}
	defer call.close()
	if ct := r.Header.Get("Content-Type"); !jsonbody.IsMediaType(ct, uploadMediaType) {
		apierror.WriteError(w, apierror.New(apierror.CodeUnsupportedMediaType,
			"this endpoint takes the file itself as the body, Content-Type: "+uploadMediaType))
		return
	}
	u, err := knowledgerun.ParseResultUpload(r.URL.Query())
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}
	// The name, as the hub keeps and records it: cleaned, and without
	// anything shaped like a credential — the run's own credentials are
	// taken out too below, once the hub knows whether it can.
	name := redact.Scrub(attachments.CleanName(u.Name))
	fields := map[string]any{"task_id": u.Task, "attachment_id": u.ID, "name": name, "size": u.Size, "sha256": u.SHA256}
	audit := func(outcome, reason string) {
		call.audit(auditaction.ActionRunResultUpload, outcome, reason, fields)
	}
	refuse := func(code apierror.Code, reason string) {
		audit("refused", reason)
		apierror.WriteError(w, apierror.New(code, reason))
	}
	// The rate first: every answer below costs the hub something, a refusal
	// on the audit trail included.
	if !allowRunBucket("results:"+call.row.SessionID, runResultsRate, runResultsBurst, time.Now()) {
		w.Header().Set("Retry-After", "2")
		refuse(apierror.CodeRateLimited, "this run sends files too often: at most "+
			strconv.FormatFloat(runResultsRate, 'f', 0, 64)+" a second")
		return
	}
	var scope knowledgeScope
	_ = json.Unmarshal([]byte(call.row.Scope), &scope)
	workDir := strings.TrimSpace(scope.WorkDir)
	if !scope.Results || workDir == "" {
		refuse(apierror.CodeForbidden, errRunResultsScope)
		return
	}
	fields["workdir"] = workDir
	runID := strings.TrimSpace(call.row.RunID)
	if runID == "" {
		refuse(apierror.CodeConflict, "this run's session names no run, so the hub has nowhere to keep its files")
		return
	}
	// The set the run's log is scrubbed with, when this process streams the
	// run: what scrubs the file's name now, and its bytes if it is attached.
	set, canScrub := s.runRedaction(call.row, workDir)
	if canScrub && set != nil {
		name = attachments.CleanName(set.String(name))
		fields["name"] = name
	}
	if u.Size > attachments.MaxFileBytes {
		refuse(apierror.CodePayloadTooLarge, fmt.Sprintf("%s is %s, over the %s a file may be",
			name, attachments.HumanBytes(u.Size), attachments.HumanBytes(attachments.MaxFileBytes)))
		return
	}
	if r.ContentLength >= 0 && r.ContentLength != u.Size {
		refuse(apierror.CodeInvalidInput, fmt.Sprintf("the body is %d bytes, not the %d the request says the file is",
			r.ContentLength, u.Size))
		return
	}
	dbPath := state.DBPath(workDir)
	// Never create a database by sending to one.
	if _, err := os.Stat(dbPath); err != nil {
		refuse(apierror.CodeNotFound, "the run's project has no database on the hub")
		return
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "the project's database is not available"))
		return
	}
	defer db.Close()
	db.AsProject()

	// The hub's task, when the run names one it was sent: by id, under the
	// title the run has.
	task, err := resolveRunTask(db, u)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "the project's database is not available"))
		return
	}
	attachNow := task != nil && canScrub
	switch {
	case task == nil && u.Created:
		fields["held_because"] = "a task the run created or renamed"
	case task == nil:
		fields["held_because"] = "not a task the hub has under the run's title"
	case !canScrub:
		fields["held_because"] = "this hub process is not streaming the run"
	}

	// A file sent again — the answer to the first send never reached the
	// run — is answered from what is here, without its bytes a second time.
	if task != nil {
		if row, err := db.TaskAttachment(task.ID, u.ID); err == nil {
			if row.RunID == runID && row.Role == statedb.AttachmentRoleResult && row.Source == statedb.AttachmentSourceRun {
				s.answerRunResult(w, http.StatusOK, knowledgerun.ResultAttached, u.ID, task.ID, row.Name)
				return
			}
			refuse(apierror.CodeConflict, "the id "+u.ID+" is another attachment's on the hub")
			return
		}
	}
	if h, ok := attachments.HeldNow(dbPath, runID, u.ID); ok && h.SHA256 == u.SHA256 && h.Size == u.Size {
		if !attachNow {
			s.answerRunResult(w, http.StatusOK, knowledgerun.ResultHeld, u.ID, 0, h.Name)
			return
		}
		s.attachRunResult(w, call, db, workDir, dbPath, runID, h, task, set, fields, http.StatusOK)
		return
	}
	if attachments.HeldCount(dbPath, runID) >= attachments.MaxHeldPerRun {
		refuse(apierror.CodePayloadTooLarge, fmt.Sprintf("the hub already holds %d files for this run, the most it "+
			"holds for one; the rest come back in the run's result", attachments.MaxHeldPerRun))
		return
	}

	// What the hub holds for runs it lost track of goes first (at most once
	// an hour): it takes room, and nothing else would free it.
	sweepHeldResults(call.db, dbPath)
	// The room the file may take, counting what the hub holds for runs and
	// what uploads in flight have taken, before a byte is read.
	usageTask := 0
	if attachNow {
		usageTask = task.ID
	}
	stored, err := db.TaskAttachmentUsage(usageTask)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "the project's database is not available"))
		return
	}
	stored.ProjectBytes += attachments.HeldBytes(dbPath)
	limit, release, why, status := attachmentUploads.take(dbPath, usageTask, stored, u.Size)
	if why != "" {
		code := apierror.CodePayloadTooLarge
		if status == http.StatusTooManyRequests {
			code = apierror.CodeRateLimited
			w.Header().Set("Retry-After", "5")
		}
		refuse(code, name+" was not taken: "+why)
		return
	}
	defer release()
	done, why, wait := takeInputTransfer("results:"+call.row.SessionID, u.Size, time.Now())
	if why != "" {
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		refuse(apierror.CodeRateLimited, strings.Replace(why, "fetching", "sending", 1))
		return
	}
	defer done()
	// A body that trickles in holds its slot only so long.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(uploadReadTime(limit)))
	created := u.CreatedAt
	if created.IsZero() || created.After(time.Now()) {
		created = time.Now()
	}
	h, err := attachments.Hold(dbPath, runID, attachments.HeldFile{
		ID: u.ID, Task: u.Task, TitleSHA256: u.TitleSHA256, Name: name, Size: u.Size, SHA256: u.SHA256,
		CreatedAt: created, Created: u.Created,
	}, http.MaxBytesReader(w, r.Body, limit+1))
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig) || errors.Is(err, attachments.ErrTooLarge):
		refuse(apierror.CodePayloadTooLarge, name+" is larger than it said it was")
		return
	case errors.Is(err, attachments.ErrUnavailable):
		refuse(apierror.CodeInvalidInput, strings.TrimPrefix(err.Error(), attachments.ErrUnavailable.Error()+": "))
		return
	case err != nil:
		audit("error", err.Error())
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "the hub could not keep the file: "+err.Error()))
		return
	}
	if !attachNow {
		audit(knowledgerun.ResultHeld, "")
		s.answerRunResult(w, http.StatusCreated, knowledgerun.ResultHeld, h.ID, 0, h.Name)
		return
	}
	s.attachRunResult(w, call, db, workDir, dbPath, runID, h, task, set, fields, http.StatusCreated)
}

// attachRunResult attaches a file the hub holds for a run to the hub's task,
// and answers. One that cannot be attached now stays held for the run's merge,
// which is told so.
func (s *Server) attachRunResult(w http.ResponseWriter, call *runKnowledgeCall, db *statedb.DB, workDir, dbPath,
	runID string, h attachments.HeldFile, task *pm.Task, set *redact.Set, fields map[string]any, status int) {
	fields["hub_task_id"] = task.ID
	u, err := db.TaskAttachmentUsage(task.ID)
	if err == nil {
		if why := attachments.Room(u, h.Size); why != "" {
			err = errors.New(why)
		}
	}
	var row statedb.AttachmentRow
	if err == nil {
		row, err = attachments.AttachHeld(db, dbPath, runID, h, task.ID, attachments.Meta{
			Name: h.Name, Source: statedb.AttachmentSourceRun, RunID: runID, AddedBy: "agent", CreatedAt: h.CreatedAt,
		}, set)
	}
	if err == nil {
		// Two attaches at once may each have found room the other then
		// took — or scrubbing made the file a little larger: checked again
		// with it recorded, and given back if that put the task or the
		// project over a limit. The held copy is still there for the merge.
		if after, aerr := db.TaskAttachmentUsage(task.ID); aerr == nil && overLimitsAfterAttach(after) {
			_, _ = db.DeleteTaskAttachment(task.ID, row.ID)
			err = errors.New("other files attached at the same time took the room it needed")
		}
	}
	if err == nil {
		attachments.RemoveHeld(dbPath, runID, h.ID)
	}
	if err != nil {
		// Kept for the merge, which applies the same limits and records
		// the file without its bytes, saying why, if they still refuse it.
		fields["held_because"] = "not attached now: " + err.Error()
		call.audit(auditaction.ActionRunResultUpload, knowledgerun.ResultHeld, "", fields)
		s.answerRunResult(w, status, knowledgerun.ResultHeld, h.ID, 0, h.Name)
		return
	}
	call.audit(auditaction.ActionRunResultUpload, knowledgerun.ResultAttached, "", fields)
	// The task's count, pushed now: every open dashboard's row for the task
	// shows the file.
	if ps, err := state.LoadLite(workDir); err == nil {
		s.broadcastStateDiff(workDir, ps)
	}
	s.answerRunResult(w, status, knowledgerun.ResultAttached, row.ID, task.ID, row.Name)
}

// overLimitsAfterAttach is the check an attach is given back on; a variable so
// a test can stand in for another attach taking the room at the same moment.
var overLimitsAfterAttach = overAttachmentLimits

// answerRunResult writes the answer to a file a run sent.
func (s *Server) answerRunResult(w http.ResponseWriter, status int, outcome, id string, hubTask int, name string) {
	msg := fmt.Sprintf("%s is on the hub, attached to task #%d", name, hubTask)
	if outcome == knowledgerun.ResultHeld {
		msg = name + " is on the hub, held until the run's result says which task it belongs to"
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(knowledgerun.ResultResponse{Outcome: outcome, ID: id, Task: hubTask, Message: msg})
}

// resolveRunTask returns the hub's task a file a run sent belongs to, or nil
// when it cannot tell yet: a task the run created or renamed, an id the hub
// does not have, or one it has under another title.
func resolveRunTask(db *statedb.DB, u knowledgerun.ResultUpload) (*pm.Task, error) {
	if u.Created {
		return nil, nil
	}
	t, err := db.LoadTask(u.Task)
	switch {
	case errors.Is(err, statedb.ErrTaskNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	case knowledgerun.TitleDigest(t.Title) != u.TitleSHA256:
		return nil, nil
	}
	return t, nil
}

// runRedaction returns the set the run behind session row is scrubbed with,
// and whether this hub process has it: it is streaming the run — the live
// handle of the dispatch the session was minted for — and its driver can say
// what it scrubs that handle's output with.
func (s *Server) runRedaction(row statedb.ProxySessionRow, workDir string) (*redact.Set, bool) {
	run, ok := s.trackedRun(workDir)
	if !ok || run.ex == nil || run.handleID == "" || run.lost {
		return nil, false
	}
	if row.ExecutorID != "" && run.ex.ID() != row.ExecutorID {
		return nil, false
	}
	d, ok := peekSeededDispatch(run.ex, run.handleID)
	if !ok || d.prov.RunID == "" || d.prov.RunID != strings.TrimSpace(row.RunID) {
		return nil, false
	}
	hr, ok := run.ex.(executor.HandleRedaction)
	if !ok {
		return nil, false
	}
	return hr.HandleRedaction(run.handleID)
}

// sweepHeldResults removes, at most once an hour per project, what the hub
// holds for runs that are over and that no merge took. cp is the control
// plane's database, where the sessions of the runs still going are.
func sweepHeldResults(cp *statedb.DB, dbPath string) {
	if cp == nil {
		return
	}
	key := "held:" + dbPath
	attachmentUploads.mu.Lock()
	due := time.Since(attachmentUploads.swept[key]) >= uploadSweepEvery
	if due {
		attachmentUploads.swept[key] = time.Now()
	}
	attachmentUploads.mu.Unlock()
	if !due {
		return
	}
	rows, err := cp.ListProxySessions(statedb.ProxySessionFilter{Kind: statedb.ProxySessionKnowledge, OpenOnly: true})
	if err != nil {
		// Without the runs still going, none can be told from a lost one.
		return
	}
	live := map[string]bool{}
	for _, r := range rows {
		if r.RunID != "" {
			live[attachments.RunKey(r.RunID)] = true
		}
	}
	attachments.SweepHeld(dbPath, live, heldResultsMaxAge)
}

// sweepHeldResultsOf is sweepHeldResults for the project at workDir, from the
// hub's periodic pass over its projects: a project nothing is sent to any more
// still has what lost runs left there removed.
func (s *Server) sweepHeldResultsOf(workDir string) {
	dbPath := state.DBPath(workDir)
	if _, err := os.Lstat(filepath.Join(attachments.StoreDir(dbPath), attachments.HeldDirName)); err != nil {
		return
	}
	cp, err := s.controlPlaneDB()
	if err != nil {
		return
	}
	defer cp.Close()
	sweepHeldResults(cp, dbPath)
}
