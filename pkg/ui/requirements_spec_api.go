package ui

// requirements_spec_api.go: the Requirements tab's side of requirements as
// code (Task 20459) — the project's spec file, .cloop/requirements.yaml.
//
//	GET  /api/requirements/spec       the file as last read, and how it merges with the hub
//	POST /api/requirements/spec/read  read it again, from the project's checkout
//	POST /api/requirements/import     merge it into the hub, as reviewed
//	GET  /api/requirements/export     the hub's requirements as a spec file, to download
//
// # Where the file is read
//
// Never here. The project's checkout is where its executor has it — a
// container's workspace, a device's directory, a Pod's clone — and the hub's
// own copy of the directory, when it has one, is not what the project's runs
// see. So a read is `cloop requirements validate --json` dispatched to the
// project's executor through runCloopSubcommandFor, like a requirements check,
// under the project's lease; it prints the file's bytes, and the hub parses
// them itself (requirements.ParseSpecFile) rather than take the executor's
// word for what they say. tests/security holds the hub to it: no handler and
// nothing in the background reaches requirements.ReadSpecFile, LoadSpecFile or
// WriteSpecFile. The last read is kept in the project's database
// (requirement_spec_files), so every hub member and every reader sees it.
//
// # Permissions, and how often
//
// Looking is project.read. Reading the file again dispatches a workload, and
// importing writes requirements, so both are task.mutate — a test is a command
// the project's sandbox runs, and the file can add one — and an import is
// audited as requirement.import.
//
// A read runs in the background, like a check: the POST answers 202 and the
// read's end arrives as a requirements_update push. It runs one at a time per
// project on a member, and each starts a workload where the project runs, so
// the hub decides how often: a read asked for by a person is refused nothing
// but a second one within specReadCooldown, and the read a tab asks for when it
// opens (auto) runs only when the last attempt is older than specReadFresh —
// specReadMissing when the checkout had no file. An attempt that got nothing —
// the executor unreachable, its cloop too old — is recorded with why, and the
// last read stands.
//
// # Importing what was reviewed
//
// The dashboard shows a plan — the merge of the file as last read with the
// hub's requirements — and the import names both: the file's SHA-256 and the
// plan's digest. The import applies only that file, and only if the merge
// still plans the same; otherwise it is refused with the new plan (409), and
// the person looks again.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	// specReadTimeout bounds one read of the spec file on the executor:
	// starting the workload where the project runs, which on a Pod includes
	// fetching the project.
	specReadTimeout = 3 * time.Minute
	// specReadFresh is how old a read the tab takes as current: one it asks
	// for when it opens runs only when the last attempt is older than this.
	specReadFresh = 5 * time.Minute
	// specReadMissing is specReadFresh for a checkout that had no spec file:
	// most projects keep none, and each read starts a workload.
	specReadMissing = time.Hour
	// specErrorsListed bounds the problems the list carries.
	specErrorsListed = 5
)

// specReadCooldown is how soon after a read another is answered from it
// rather than dispatched. A variable for the tests, which read again at once.
var specReadCooldown = 10 * time.Second

// States of the spec file, as the tab shows them.
const (
	specUnread   = "unread"   // never read
	specFailed   = "failed"   // the executor could not send it
	specMissing  = "missing"  // the checkout has no spec file
	specInvalid  = "invalid"  // it does not parse
	specConflict = "conflict" // importing needs a choice, or is refused
	specChanged  = "changed"  // it has changes to import
	specAhead    = "ahead"    // only the hub has changes: export them
	specInSync   = "in_sync"
)

// specView is the spec file as the tab draws it.
type specView struct {
	Path  string                       `json:"path"`
	State string                       `json:"state"`
	Read  *statedb.RequirementSpecRead `json:"read,omitempty"`
	Fresh bool                         `json:"fresh"`
	// Reading reports a read under way on this member.
	Reading bool `json:"reading,omitempty"`
	// Attempt is the last attempt to read the file, when it got nothing
	// after the last read did.
	Attempt  *statedb.RequirementSpecAttempt `json:"attempt,omitempty"`
	LastSync *statedb.RequirementSpecSync    `json:"last_sync,omitempty"`
	// Requirements counts what the file holds, by status.
	Requirements map[string]int           `json:"requirements,omitempty"`
	Errors       []requirements.SpecError `json:"errors,omitempty"`
	ErrorCount   int                      `json:"error_count,omitempty"`
	Imports      int                      `json:"imports"`
	Exports      int                      `json:"exports"`
	Conflicts    int                      `json:"conflicts"`
	Refused      int                      `json:"refused"`
	InSync       int                      `json:"in_sync"`
	Digest       string                   `json:"digest,omitempty"`
	// Plan is every change, with the hub's and the file's definitions:
	// only for the review (GET /api/requirements/spec).
	Plan *requirements.Plan `json:"plan,omitempty"`
}

// specParse is one parse of a spec file's bytes.
type specParse struct {
	file requirements.SpecFile
	err  error
}

// specParses caches parses by the file's SHA-256: the list asks on every
// redraw, and a file is parsed the same however often it is asked.
type specParses struct {
	mu sync.Mutex
	m  map[string]specParse
}

func (c *specParses) parse(sha string, content []byte) (requirements.SpecFile, error) {
	c.mu.Lock()
	if p, ok := c.m[sha]; ok && sha != "" {
		c.mu.Unlock()
		return p.file, p.err
	}
	c.mu.Unlock()
	f, err := requirements.ParseSpecFile(content)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || len(c.m) >= 32 {
		c.m = map[string]specParse{}
	}
	c.m[sha] = specParse{f, err}
	return f, err
}

// specReadJobs are the reads of spec files this member is running, one per
// project, so a second is not started beside the first and shutdown can stop
// them.
type specReadJobs struct {
	mu   sync.Mutex
	jobs map[string]context.CancelFunc
	wg   sync.WaitGroup
}

// start claims workDir's read for cancel, unless one is already running.
func (j *specReadJobs) start(workDir string, cancel context.CancelFunc) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, running := j.jobs[workDir]; running {
		return false
	}
	if j.jobs == nil {
		j.jobs = map[string]context.CancelFunc{}
	}
	j.jobs[workDir] = cancel
	j.wg.Add(1)
	return true
}

func (j *specReadJobs) done(workDir string) {
	j.mu.Lock()
	delete(j.jobs, workDir)
	j.mu.Unlock()
	j.wg.Done()
}

func (j *specReadJobs) running(workDir string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	_, ok := j.jobs[workDir]
	return ok
}

// stop cancels every read and waits up to wait for them to end.
func (j *specReadJobs) stop(wait time.Duration) {
	j.mu.Lock()
	for _, cancel := range j.jobs {
		cancel()
	}
	j.mu.Unlock()
	finished := make(chan struct{})
	go func() { j.wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(wait):
	}
}

// specViewFor is what the tab shows of the spec file: its last read merged
// with the hub's requirements. detail adds the plan's changes.
func (s *Server) specViewFor(db *statedb.DB, workDir string, detail bool) (specView, error) {
	v := specView{Path: requirements.SpecFileName, State: specUnread, Reading: s.specReads.running(workDir)}
	if sync, ok, err := db.LastRequirementSpecSync(); err != nil {
		return v, err
	} else if ok {
		v.LastSync = &sync
	}
	rd, found, err := db.RequirementSpecRead()
	if err != nil {
		return v, err
	}
	if a, ok, err := db.LastRequirementSpecAttempt(); err != nil {
		return v, err
	} else if ok && a.Error != "" && (!found || a.At.After(rd.ReadAt)) {
		v.Attempt = &a
	}
	if !found {
		return v, nil
	}
	v.Read, v.Fresh = &rd, time.Since(rd.ReadAt) < specReadFresh
	if rd.Path != "" {
		v.Path = rd.Path
	}
	switch {
	case rd.Error != "":
		v.State = specFailed
		return v, nil
	case !rd.Found:
		v.State = specMissing
		return v, nil
	}
	sf, perr := s.specParses.parse(rd.SHA256, rd.Content)
	if perr != nil {
		v.State = specInvalid
		var errs requirements.SpecErrors
		if !errors.As(perr, &errs) {
			errs = requirements.SpecErrors{{Message: perr.Error()}}
		}
		v.ErrorCount, v.Errors = len(errs), errs
		if !detail && len(errs) > specErrorsListed {
			v.Errors = errs[:specErrorsListed]
		}
		return v, nil
	}
	v.Requirements = sf.Counts()
	snap, err := db.RequirementSpecSnapshot()
	if err != nil {
		return v, err
	}
	plan := requirements.Merge(snap.Base, snap.Hub, sf.Requirements, snap.Assigned)
	v.Imports, v.Exports, v.Conflicts, v.Refused, v.InSync = plan.Imports, plan.Exports, plan.Conflicts, plan.Refused, plan.InSync
	v.Digest = plan.Digest
	switch {
	case plan.Conflicts+plan.Refused > 0:
		v.State = specConflict
	case plan.Imports > 0:
		v.State = specChanged
	case plan.Exports > 0:
		v.State = specAhead
	default:
		v.State = specInSync
	}
	if detail {
		v.Plan = &plan
	}
	return v, nil
}

// handleRequirementSpec answers GET /api/requirements/spec: the review.
func (s *Server) handleRequirementSpec(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	db, ok := openRequirementsDB(w, workDir)
	if !ok {
		return
	}
	defer db.Close()
	s.answerSpec(w, db, workDir)
}

func (s *Server) answerSpec(w http.ResponseWriter, db *statedb.DB, workDir string) {
	v, err := s.specViewFor(db, workDir, true)
	if err != nil {
		requirementErr(w, err)
		return
	}
	jsonOK(w, map[string]any{"ok": true, "reading": v.Reading, "spec": v})
}

// specReadDue reports whether a read asked for now should run, given the last
// read and the last attempt: auto is the tab's own read when it opens.
func specReadDue(db *statedb.DB, auto bool, now time.Time) (bool, error) {
	rd, haveRead, err := db.RequirementSpecRead()
	if err != nil {
		return false, err
	}
	a, haveAttempt, err := db.LastRequirementSpecAttempt()
	if err != nil {
		return false, err
	}
	var last time.Time
	switch {
	case haveAttempt:
		last = a.At
	case haveRead:
		last = rd.ReadAt
	default:
		return true, nil
	}
	if haveRead && rd.ReadAt.After(last) {
		last = rd.ReadAt
	}
	window := specReadCooldown
	if auto {
		window = specReadFresh
		if haveRead && !rd.Found && rd.Error == "" && !(haveAttempt && a.Error != "" && a.At.After(rd.ReadAt)) {
			window = specReadMissing
		}
	}
	return now.Sub(last) >= window, nil
}

// handleRequirementSpecRead answers POST /api/requirements/spec/read: it
// starts a read of the spec file from the project's checkout, on the project's
// executor, and answers 202 — or, when no read is due, the spec as last read.
// {"auto": true} is the tab's own read when it opens: the hub decides whether
// one is due, and a refusal is recorded rather than answered, since nobody
// pressed anything.
func (s *Server) handleRequirementSpecRead(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	// A device's workload is started by the member holding its agent.
	if s.routeDispatch(w, r, workDir) {
		return
	}
	var in struct {
		Auto bool `json:"auto"`
	}
	if !decodeOptionalJSON(w, r, &in) {
		return
	}
	db, ok := openRequirementsDB(w, workDir)
	if !ok {
		return
	}
	defer db.Close()
	if s.specReads.running(workDir) {
		writeJSONStatus(w, http.StatusAccepted, map[string]any{"ok": true, "reading": true})
		return
	}
	if due, err := specReadDue(db, in.Auto, time.Now()); err != nil {
		requirementErr(w, err)
		return
	} else if !due {
		s.answerSpec(w, db, workDir)
		return
	}

	actor := s.auditActor(r)
	refuse := func(err error) {
		if !in.Auto {
			jsonWorkloadErr(w, err)
			return
		}
		if rerr := db.RecordRequirementSpecAttempt(statedb.RequirementSpecAttempt{By: actor, Error: err.Error()}); rerr != nil {
			requirementErr(w, rerr)
			return
		}
		s.answerSpec(w, db, workDir)
	}
	// Refused now, in the words of the refusal: where the project may run.
	registerBuiltinExecutors()
	if err := checkDispatchConfinement(workDir); err != nil {
		refuse(err)
		return
	}
	ex, err := executor.Resolve(workDir)
	if err != nil {
		refuse(fmt.Errorf("no executor available for %s: %w", workDir, err))
		return
	}
	if err := checkFeatureExecutor(workDir, ex); err != nil {
		refuse(err)
		return
	}
	// Reading a file runs no harness: the lease withholds other people's
	// personal Claude credentials, as for any workload, and carries what the
	// workspace needs to be fetched.
	clear := s.leaseClearanceFor(r, workDir)
	exe, executorID := s.selfExe(), ex.ID()
	ctx, cancel := context.WithTimeout(context.Background(), specReadTimeout)
	if !s.specReads.start(workDir, cancel) {
		cancel()
		writeJSONStatus(w, http.StatusAccepted, map[string]any{"ok": true, "reading": true})
		return
	}
	go func() {
		defer s.specReads.done(workDir)
		defer cancel()
		defer func() {
			if rec := recover(); rec != nil {
				fmt.Fprintf(os.Stderr, "ui: requirements spec read of %s: internal error: %v\n", workDir, rec)
			}
		}()
		out, err := runCloopSubcommandFor(ctx, exe, workDir, specReadTimeout, nil, clear,
			"requirements", "validate", "--json")
		s.recordSpecRead(workDir, actor, executorID, out, err)
	}()
	writeJSONStatus(w, http.StatusAccepted, map[string]any{"ok": true, "reading": true})
}

// recordSpecRead records what a read of the spec file brought back — the file,
// parsed here, or why there is none — and tells the project's dashboards.
func (s *Server) recordSpecRead(workDir, actor, executorID string, out []byte, runErr error) {
	defer s.requirementsChanged(workDir, "", "")
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: requirements spec read: %v\n", err)
		return
	}
	defer db.Close()
	db.AsProject()

	rep, reason := readSpecReport(out, runErr)
	if reason != "" {
		if err := db.RecordRequirementSpecAttempt(statedb.RequirementSpecAttempt{
			By: actor, ExecutorID: executorID, Error: reason,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "ui: requirements spec read: %v\n", err)
		}
		return
	}
	rd := statedb.RequirementSpecRead{
		ReadAt: time.Now().UTC(), ReadBy: actor, ExecutorID: executorID, Path: requirements.SpecFileName,
		Found: rep.Found, Commit: requirements.CleanCommit(rep.Commit), Dirty: rep.Dirty, Ignored: rep.Ignored,
	}
	var file []requirements.Requirement
	switch {
	case !rep.Found:
	case len(rep.Content) > requirements.MaxSpecFileBytes:
		rd.Error = fmt.Sprintf("the executor sent a file of %d bytes, more than a spec file may hold", len(rep.Content))
	case len(rep.Content) == 0 && len(rep.Errors) > 0:
		// There, and not sent: past the size bound, or not a file. Its
		// cloop said why; the reason is shown, bounded, and nothing else
		// of what it said is taken.
		rd.Error = "the executor could not send the file: " +
			truncateRunes(strings.Join(strings.Fields(rep.Errors[0].Message), " "), 300)
	default:
		rd.Content, rd.SHA256 = rep.Content, requirements.SpecSHA256(rep.Content)
		if sf, perr := s.specParses.parse(rd.SHA256, rd.Content); perr == nil {
			file = append([]requirements.Requirement{}, sf.Requirements...)
		}
	}
	if err := db.SaveRequirementSpecRead(rd, file); err != nil {
		fmt.Fprintf(os.Stderr, "ui: requirements spec read: %v\n", err)
	}
}

// readSpecReport reads what `cloop requirements validate --json` printed, or
// says why there is nothing to read: the executor's cloop failed, or sent no
// report — an executor older than this hub says so.
func readSpecReport(out []byte, runErr error) (requirements.SpecFileReport, string) {
	var rep requirements.SpecFileReport
	payload, perr := clijson.Extract(out)
	if perr == nil {
		var failed modelCallFailure
		if json.Unmarshal(payload, &failed) == nil && failed.Error != "" {
			return rep, truncateRunes(failed.Error, 1000)
		}
		if runErr == nil {
			if err := json.Unmarshal(payload, &rep); err != nil {
				return rep, "the executor's report could not be read: " + err.Error()
			}
			return rep, ""
		}
	}
	if runErr == nil {
		return rep, "the executor's cloop sent back no report: " + perr.Error()
	}
	return rep, truncateRunes(modelCallReason(out, runErr), 1000)
}

// handleRequirementSpecImport answers POST /api/requirements/import: it merges
// the spec file as last read into the hub's requirements, exactly as the
// caller reviewed it — the file whose SHA-256 it names, the plan whose digest
// it names — with each conflict settled as resolutions says.
func (s *Server) handleRequirementSpecImport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SHA256      string            `json:"sha256"`
		Digest      string            `json:"digest"`
		Resolutions map[string]string `json:"resolutions"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.SHA256 == "" || in.Digest == "" {
		jsonErr(w, "name the read of the spec file and the plan you reviewed (sha256 and digest)", http.StatusBadRequest)
		return
	}
	resolutions := map[int]string{}
	for key, how := range in.Resolutions {
		id, err := strconv.Atoi(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(key), "R-"), "r-"))
		if err != nil || id <= 0 || len(resolutions) >= requirements.MaxRequirements {
			jsonErr(w, fmt.Sprintf("resolutions: %q is not a requirement", truncateRunes(key, 32)), http.StatusBadRequest)
			return
		}
		resolutions[id] = strings.ToLower(strings.TrimSpace(how))
	}
	workDir := s.resolveWorkDir(r)
	db, ok := openRequirementsDB(w, workDir)
	if !ok {
		return
	}
	defer db.Close()
	refuse := func(msg string) {
		body := map[string]any{"ok": false, "error": msg}
		if v, err := s.specViewFor(db, workDir, true); err == nil {
			body["spec"] = v
		}
		writeJSONStatus(w, http.StatusConflict, body)
	}
	rd, found, err := db.RequirementSpecRead()
	if err != nil {
		requirementErr(w, err)
		return
	}
	if !found || !rd.Found || rd.SHA256 != in.SHA256 {
		refuse("the spec file was read again since you reviewed it: review the import again")
		return
	}
	sf, perr := s.specParses.parse(rd.SHA256, rd.Content)
	if perr != nil {
		refuse("the spec file does not validate: " + perr.Error())
		return
	}
	res, err := db.ImportRequirementSpec(statedb.RequirementSpecImport{
		File: sf.Requirements, Digest: in.Digest, Resolutions: resolutions,
		Sync: statedb.RequirementSpecSync{
			Actor: s.auditActor(r), Source: "dashboard", Path: rd.Path, SHA256: rd.SHA256, Commit: rd.Commit,
		},
	})
	var cerr *requirements.ConflictError
	switch {
	case errors.Is(err, statedb.ErrRequirementSpecChanged):
		refuse("the requirements changed since you reviewed the import: review it again")
		return
	case errors.As(err, &cerr):
		refuse(cerr.Error())
		return
	case err != nil:
		requirementErr(w, err)
		return
	}
	done := map[string][]int{}
	for _, st := range res.Steps {
		done[st.Action] = append(done[st.Action], st.Requirement.ID)
	}
	s.requirementsChanged(workDir, "", "")
	// A requirement the import deleted was taken out of the tasks that
	// implemented it (Task 20460).
	if len(res.Unlinked) > 0 {
		if ps, err := state.LoadLite(workDir); err == nil {
			s.broadcastStateDiff(workDir, ps)
		}
	}
	s.broadcastAuditAppend(string(auditaction.ActionRequirementImport))
	body := map[string]any{"ok": true, "done": done}
	if v, err := s.specViewFor(db, workDir, false); err == nil {
		body["spec"] = v
	}
	jsonOK(w, body)
}

// handleRequirementSpecExport answers GET /api/requirements/export: the
// project's requirements as a spec file, for the person to commit. Nothing is
// written anywhere, and nothing is recorded: when the file lands in the
// checkout, the next read finds it agreeing with the hub.
func (s *Server) handleRequirementSpecExport(w http.ResponseWriter, r *http.Request) {
	db, ok := openRequirementsDB(w, s.resolveWorkDir(r))
	if !ok {
		return
	}
	defer db.Close()
	reqs, err := db.Requirements()
	if err != nil {
		requirementErr(w, err)
		return
	}
	out, err := requirements.RenderSpecFile(reqs)
	if err != nil {
		requirementErr(w, err)
		return
	}
	jsonOK(w, map[string]any{
		"ok": true, "path": requirements.SpecFileName, "content": string(out),
		"sha256": requirements.SpecSHA256(out), "requirements": len(reqs),
	})
}
