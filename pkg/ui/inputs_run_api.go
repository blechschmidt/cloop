package ui

// inputs_run_api.go: a seeded run's tasks' input files (Task 20511).
//
//	POST /api/run/knowledge/inputs       {"task", "title_sha256"}       the task's input files
//	POST /api/run/knowledge/inputs/file  {"task", "title_sha256", "id"} one file's bytes
//
// A person attaches files to a task for its agent (attachments_api.go), and
// every attempt at the task is given a copy. A run on the hub's host, or in a
// container that mounts the project, copies them from the store beside the
// project's database. A run seeded into its sandbox — an edge device, a
// Kubernetes Pod — works on a copy of the project that holds none of them, so
// it asks here, at the start of every attempt, with its run session: minted
// with Inputs set for every seeded run (knowledge_run.go, applyRunSession).
//
// What the session opens is the input files of the tasks of the directory its
// run was dispatched to — a feature's, for a feature's run — and nothing else:
// not another project's, not a task's results, not a file whose bytes the hub
// does not hold. A task is named by its id and by a digest of the title it
// has in the run's plan, and answered for only while the hub's task of that
// id has that title: a seeded run numbers the tasks it creates itself, and its
// task 57 is not the hub's task 57 that a person added while it ran. For a
// task the hub does not have, or has under another title, the list is empty,
// as it is for a task without input files — what a run creates has none —
// except that a task with input files here whose title has changed is named
// as such (InputsResponse.Mismatch), so its agent is told it has none.
//
// Every file whose bytes leave the hub is on the control plane's audit trail
// (run.input_fetch), with the run, the task and the file; so is every refusal
// of one. Each session is held to its own rate, apart from its knowledge
// searches: an attempt asks once for the list and once for each file. Its
// transfers are held too, since a hostile agent holds the token: two at once,
// each with a write deadline and served after both databases are closed, and
// bytes drawn from a budget of two tasks' worth that refills slowly.

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Each session's rate for input files: an attempt's list and every file of a
// task that has the most a task may have fit the burst, twice over.
var (
	runInputsRate  = 4.0
	runInputsBurst = float64(2*attachments.MaxTaskFiles + 10)
)

// Each session's transfers of input files: this many at once, and bytes from
// a bucket holding two tasks' worth that refills at runInputBytesPerSecond.
var (
	runInputStreams        = 2
	runInputBytesBurst     = float64(2 * attachments.MaxTaskBytes)
	runInputBytesPerSecond = float64(2 << 20)
)

// runInputServeTime is how long one file of size bytes may take to send: a
// minute, and what it needs at 64 KiB a second.
func runInputServeTime(size int64) time.Duration {
	return time.Minute + time.Duration(size/(64<<10))*time.Second
}

// runInputTransfers is each session's transfers in this process.
var runInputTransfers = struct {
	mu       sync.Mutex
	sessions map[string]*inputTransfers
}{sessions: map[string]*inputTransfers{}}

type inputTransfers struct {
	streams int
	bytes   float64
	last    time.Time
}

// takeInputTransfer admits a transfer of size bytes for session id: the release
// that ends it, or why it must wait and for how many seconds.
func takeInputTransfer(id string, size int64, now time.Time) (func(), string, int) {
	runInputTransfers.mu.Lock()
	defer runInputTransfers.mu.Unlock()
	if len(runInputTransfers.sessions) > 4096 {
		for k, t := range runInputTransfers.sessions {
			if t.streams == 0 && now.Sub(t.last) > 10*time.Minute {
				delete(runInputTransfers.sessions, k)
			}
		}
	}
	t := runInputTransfers.sessions[id]
	if t == nil {
		t = &inputTransfers{bytes: runInputBytesBurst, last: now}
		runInputTransfers.sessions[id] = t
	}
	t.bytes = min(runInputBytesBurst, t.bytes+now.Sub(t.last).Seconds()*runInputBytesPerSecond)
	t.last = now
	if t.streams >= runInputStreams {
		return nil, "this run is already fetching as many input files as it may at once", 2
	}
	if need := float64(size); need > t.bytes {
		return nil, "this run has fetched more input file bytes than it may in so short a time",
			int((need-t.bytes)/runInputBytesPerSecond) + 1
	}
	t.bytes -= float64(size)
	t.streams++
	var once sync.Once
	return func() {
		once.Do(func() {
			runInputTransfers.mu.Lock()
			t.streams--
			runInputTransfers.mu.Unlock()
		})
	}, "", 0
}

// errRunInputsScope is the answer to a session that was not given its tasks'
// input files: a run whose project is the hub's own reads them from the store.
const errRunInputsScope = "this run's session was not given its tasks' input files: a run that is not seeded " +
	"into its sandbox reads them from the project's own store"

// runInputs is one request's view of the project whose input files a session
// opens.
type runInputs struct {
	call    *runKnowledgeCall
	workDir string
	dbPath  string
	db      *statedb.DB // the project's; nil when it has no database
	// task is the hub's task the request named, nil when the hub has none
	// with that id and title.
	task *pm.Task
	// renamed is the hub's task of that id when its title is not the run's.
	renamed *pm.Task
	// mismatch says why task is nil, for the audit trail.
	mismatch string
}

func (in *runInputs) close() {
	if in != nil && in.db != nil {
		_ = in.db.Close()
		in.db = nil
	}
}

// openRunInputs checks call's session opens its tasks' input files, takes the
// request from the session's rate and resolves the task the request names. It
// writes the refusal and returns false when there is nothing to answer.
func (s *Server) openRunInputs(w http.ResponseWriter, call *runKnowledgeCall, taskID int, titleDigest string,
	audit func(outcome, reason string)) (*runInputs, bool) {
	// The rate first: every answer below costs the hub something, a refusal
	// on the audit trail included.
	if !allowRunBucket("inputs:"+call.row.SessionID, runInputsRate, runInputsBurst, time.Now()) {
		audit("refused", "the session's rate limit")
		w.Header().Set("Retry-After", "2")
		apierror.WriteError(w, apierror.New(apierror.CodeRateLimited,
			"this run asks for its tasks' input files too often: at most "+
				strconv.FormatFloat(runInputsRate, 'f', 0, 64)+" requests a second"))
		return nil, false
	}
	var scope knowledgeScope
	_ = json.Unmarshal([]byte(call.row.Scope), &scope)
	workDir := strings.TrimSpace(scope.WorkDir)
	if !scope.Inputs || workDir == "" {
		audit("refused", "the session was not minted with its tasks' input files")
		apierror.WriteError(w, apierror.New(apierror.CodeForbidden, errRunInputsScope))
		return nil, false
	}
	if taskID <= 0 {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "task must be a task's id"))
		return nil, false
	}
	if !knowledgerun.ValidTitleDigest(titleDigest) {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"title_sha256 must be the hex SHA-256 of the task's title as the run has it"))
		return nil, false
	}
	in := &runInputs{call: call, workDir: workDir, dbPath: state.DBPath(workDir)}
	// Never create a database by asking about one.
	if _, err := os.Stat(in.dbPath); err != nil {
		in.mismatch = "the project has no database on the hub"
		return in, true
	}
	db, err := statedb.Open(in.dbPath)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "the project's database is not available"))
		return nil, false
	}
	in.db = db
	t, err := db.LoadTask(taskID)
	switch {
	case errors.Is(err, statedb.ErrTaskNotFound):
		in.mismatch = "the hub has no task " + strconv.Itoa(taskID)
	case err != nil:
		in.close()
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "the project's database is not available"))
		return nil, false
	case subtle.ConstantTimeCompare([]byte(knowledgerun.TitleDigest(t.Title)), []byte(strings.ToLower(titleDigest))) != 1:
		in.mismatch = "the hub's task " + strconv.Itoa(taskID) + " is another task: its title is not the run's"
		in.renamed = t
	default:
		in.task = t
	}
	return in, true
}

// handleRunInputs lists the input files of a task of the session's project.
//
// POST /api/run/knowledge/inputs
func (s *Server) handleRunInputs(w http.ResponseWriter, r *http.Request) {
	call, ok := s.openRunKnowledgeCall(w, r)
	if !ok {
		return
	}
	defer call.close()
	var req knowledgerun.InputsRequest
	if !call.decode(w, r, &req) {
		return
	}
	// Listing reads names, not bytes: refusals are recorded, answers are not.
	in, ok := s.openRunInputs(w, call, req.Task, req.TitleSHA256, func(outcome, reason string) {
		s.auditRunInput(call, "", req.Task, outcome, reason, nil)
	})
	if !ok {
		return
	}
	defer in.close()
	out := knowledgerun.InputsResponse{Task: req.Task, Files: []knowledgerun.InputFile{}}
	if in.renamed != nil {
		// The run's copy of a task that has input files here no longer has
		// the hub's title: renamed or replaced while the run was out. Said,
		// so the agent is told it has none of them rather than nothing at
		// all. A task the hub has under another title and without input
		// files — the hub's own task that a task the run created collides
		// with — is answered like one the hub does not have.
		if rows, err := in.db.TaskInputs(in.renamed.ID); err == nil && len(rows) > 0 {
			out.Mismatch = "the hub's task " + strconv.Itoa(in.renamed.ID) + " is not this run's copy of it any more: " +
				"it was renamed or replaced on the hub while the run was going"
		}
	}
	if in.task != nil {
		rows, err := in.db.TaskInputs(in.task.ID)
		if err != nil {
			apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "the project's database is not available"))
			return
		}
		for _, row := range rows {
			if row.Unavailable != "" {
				continue
			}
			out.Files = append(out.Files, knowledgerun.InputFile{
				ID: row.ID, Name: row.Name, Size: row.Size, SHA256: row.SHA256, MediaType: row.MediaType, Note: row.Note,
			})
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, out)
}

// handleRunInputFile serves the bytes of one input file of a task of the
// session's project.
//
// POST /api/run/knowledge/inputs/file
func (s *Server) handleRunInputFile(w http.ResponseWriter, r *http.Request) {
	call, ok := s.openRunKnowledgeCall(w, r)
	if !ok {
		return
	}
	defer call.close() // and before the transfer, which close allows
	var req knowledgerun.InputFileRequest
	if !call.decode(w, r, &req) {
		return
	}
	aid := strings.TrimSpace(req.ID)
	fields := map[string]any{}
	if statedb.ValidAttachmentID(aid) {
		fields["attachment_id"] = aid
	}
	refuse := func(outcome, reason string) { s.auditRunInput(call, "", req.Task, outcome, reason, fields) }
	in, ok := s.openRunInputs(w, call, req.Task, req.TitleSHA256, refuse)
	if !ok {
		return
	}
	defer in.close()
	fields["workdir"] = in.workDir
	if in.task == nil {
		refuse("refused", in.mismatch)
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "the task has no such input file"))
		return
	}
	row, err := in.db.TaskAttachment(in.task.ID, aid)
	switch {
	case errors.Is(err, statedb.ErrAttachmentNotFound):
		refuse("refused", "the task has no attachment of that id")
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "the task has no such input file"))
		return
	case err != nil:
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "the project's database is not available"))
		return
	case row.Role != statedb.AttachmentRoleInput:
		// A result is the hub's to show people; a run is given only what a
		// person attached for it.
		refuse("refused", "the attachment is not an input file of the task")
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "the task has no such input file"))
		return
	}
	fields["name"], fields["size"], fields["sha256"] = row.Name, row.Size, row.SHA256
	release, why, wait := takeInputTransfer(call.row.SessionID, row.Size, time.Now())
	if why != "" {
		refuse("refused", why)
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		apierror.WriteError(w, apierror.New(apierror.CodeRateLimited, why))
		return
	}
	defer release()
	f, _, err := attachments.Open(in.dbPath, row)
	switch {
	case errors.Is(err, attachments.ErrUnavailable):
		refuse("error", err.Error())
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "the input file is not in the hub's store: "+err.Error()))
		return
	case err != nil:
		refuse("error", err.Error())
		apierror.WriteError(w, apierror.New(apierror.CodeConflict, "the input file could not be read from the hub's store"))
		return
	}
	defer f.Close()
	s.auditRunInput(call, in.workDir, in.task.ID, "ok", "", fields)
	// Neither database is needed for the transfer, which may be slow: both
	// handles go back before it starts.
	in.close()
	call.close()
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Length", strconv.FormatInt(row.Size, 10))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(runInputServeTime(row.Size)))
	w.WriteHeader(http.StatusOK)
	// Exactly the bytes recorded, which attachments.Open checked the file
	// holds: the run checks them against the digest it was listed.
	_, _ = io.Copy(w, io.NewSectionReader(f, 0, row.Size))
}

// auditRunInput writes one run.input_fetch row on the control plane's trail.
func (s *Server) auditRunInput(call *runKnowledgeCall, workDir string, taskID int, outcome, reason string,
	fields map[string]any) {
	out := map[string]any{"task_id": taskID}
	if workDir != "" {
		out["workdir"] = workDir
	}
	for k, v := range fields {
		out[k] = v
	}
	call.audit(auditaction.ActionRunInputFetch, outcome, reason, out)
}

// projectHasInputFiles reports whether a task of the project at workDir has an
// input file, for a note in its journal when a run cannot be given them.
func projectHasInputFiles(workDir string) bool {
	dbPath := state.DBPath(workDir)
	if _, err := os.Stat(dbPath); err != nil {
		return false
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return false
	}
	defer db.Close()
	has, err := db.HasTaskInputs()
	return err == nil && has
}
