package ui

// requirements_prove_api.go: the Requirements tab's Prove (Task 20464).
//
//	POST /api/requirements/{id}/prove   prove its tests red-green on the project's executor
//
// A proof runs a requirement's tests twice — on the code before the change, in
// a throwaway checkout of the base, and on the change — and says whether they
// show it (requirements/proof.go). Like a check it never runs here: it is
// `cloop requirements prove --json --no-record --spec=<the requirement>`
// dispatched to the project's executor through runCloopSubcommandFor, in the
// project's sandbox, and the report it sends back is read through
// requirements.SanitizeProofs, the hub's copy of the rules, with the hub's
// definition. The executor picks the base: the commit before the test's
// implementation, or the one the request names.
//
// A proof is a requirement run of kind prove: it takes the project's one check
// slot, so a check and a proof never run the same tests in the same tree at
// once, and it shows, ends, lapses and is cancelled exactly as a check does
// (requirements_api.go). Starting one is run.start, as a check is.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// proofBaseRe is a base a request may name: a commit id, as the executor's
// checkout knows it.
var proofBaseRe = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

// requirementProofJob is one proof run's work.
type requirementProofJob struct {
	run     statedb.RequirementRun
	workDir string
	req     requirements.Requirement
	base    string
	// dispatch runs `cloop <args>` on the project's executor, for whoever
	// started the proof: built by the handler, which knows whom it acts for.
	dispatch func(ctx context.Context, timeout time.Duration, args []string) ([]byte, error)
}

// handleRequirementProve answers POST /api/requirements/{id}/prove: it starts
// a proof of the requirement's tests and returns the run. The proof's end
// arrives as a requirements_update push.
func (s *Server) handleRequirementProve(w http.ResponseWriter, r *http.Request) {
	id, ok := requirementPathID(w, r)
	if !ok {
		return
	}
	workDir := s.resolveWorkDir(r)
	// A device's workload is started by the member holding its agent.
	if s.routeDispatch(w, r, workDir) {
		return
	}
	var in struct {
		// Base names the commit to prove the tests against; empty lets the
		// executor find the commit before the test's implementation.
		Base string `json:"base"`
	}
	if !decodeOptionalJSON(w, r, &in) {
		return
	}
	in.Base = strings.TrimSpace(in.Base)
	if in.Base != "" && !proofBaseRe.MatchString(in.Base) {
		jsonErr(w, "the base is a commit id: 7 to 64 hexadecimal digits", http.StatusBadRequest)
		return
	}
	db, ok := openRequirementsDB(w, workDir)
	if !ok {
		return
	}
	defer db.Close()
	req, err := db.Requirement(id)
	if err != nil {
		requirementErr(w, err)
		return
	}
	switch {
	case req.CurrentStatus() == requirements.StatusDraft:
		jsonErr(w, requirements.Key(id)+" is a draft: its tests run nowhere until a person approves it", http.StatusBadRequest)
		return
	case !req.Tested():
		jsonErr(w, requirements.Key(id)+" has no tests, so there is nothing to prove: give it a test first", http.StatusBadRequest)
		return
	}

	// Refused now, in the words of the refusal: where the project may run.
	registerBuiltinExecutors()
	if err := checkDispatchConfinement(workDir); err != nil {
		jsonWorkloadErr(w, err)
		return
	}
	ex, err := executor.Resolve(workDir)
	if err != nil {
		jsonWorkloadErr(w, fmt.Errorf("no executor available for %s: %w", workDir, err))
		return
	}
	if err := checkFeatureExecutor(workDir, ex); err != nil {
		jsonWorkloadErr(w, err)
		return
	}
	// A proof runs tests and git, and no harness: the lease withholds other
	// people's personal Claude credentials, as for any workload.
	clear := s.leaseClearanceFor(r, workDir)
	exe := s.selfExe()
	job := &requirementProofJob{workDir: workDir, req: req, base: in.Base,
		dispatch: func(ctx context.Context, timeout time.Duration, args []string) ([]byte, error) {
			return runCloopSubcommandFor(ctx, exe, workDir, timeout, nil, clear, args...)
		}}
	budget := min(requirements.ProofBudget([]requirements.Requirement{req}, false), maxRequirementsCheckTime)
	run, err := db.StartRequirementRun(statedb.RequirementRun{
		RunID: artifact.NewRunID(), Source: "dashboard", StartedBy: s.auditActor(r), Kind: statedb.RequirementRunKindProve,
		Deadline: time.Now().Add(budget), ExecutorID: ex.ID(), RequirementIDs: []int{req.ID},
	})
	if err != nil {
		if errors.Is(err, statedb.ErrRequirementCheckRunning) {
			writeJSONStatus(w, http.StatusConflict, map[string]any{
				"ok": false, "error": "a check or proof of this project's requirements is already running", "active": run,
			})
			return
		}
		requirementErr(w, err)
		return
	}
	job.run = run

	base, stop := context.WithDeadline(context.Background(), run.Deadline)
	ctx, cancel := context.WithCancelCause(base)
	s.reqChecks.add(run.RunID, cancel)
	go func() {
		defer stop()
		s.runRequirementProof(ctx, cancel, job)
	}()

	s.requirementsChanged(workDir, run.RunID, run.State)
	writeJSONStatus(w, http.StatusAccepted, map[string]any{"ok": true, "run": run})
}

// runRequirementProof runs job's proof on the project's executor, records what
// it found, and then the run's end.
func (s *Server) runRequirementProof(ctx context.Context, cancel context.CancelCauseFunc, job *requirementProofJob) {
	run := job.run
	var (
		proofs           []requirements.Proof
		endState, reason = statedb.RequirementRunDone, ""
	)
	defer s.reqChecks.done(run.RunID)
	defer cancel(nil)
	defer func() {
		if rec := recover(); rec != nil {
			endState, reason = statedb.RequirementRunFailed, fmt.Sprintf("internal error: %v", rec)
		}
		s.finishRequirementProof(job, endState, proofs, reason)
	}()

	db, err := statedb.Open(state.DBPath(job.workDir))
	if err != nil {
		endState, reason = statedb.RequirementRunFailed, err.Error()
		return
	}
	defer db.Close()
	db.AsProject()

	// The heartbeat that keeps the run holding its project's one check slot,
	// and the way a cancel asked of any member reaches this one.
	beat, stopBeat := context.WithCancel(ctx)
	beating := make(chan struct{})
	defer func() { stopBeat(); <-beating }()
	go func() {
		defer close(beating)
		t := time.NewTicker(statedb.RequirementRunHeartbeat)
		defer t.Stop()
		for {
			select {
			case <-beat.Done():
				return
			case <-t.C:
				if asked, err := db.TouchRequirementRun(run.RunID); err == nil && asked {
					cancel(errRequirementsCancelled)
					return
				}
			}
		}
	}()

	asked := []requirements.Requirement{job.req}
	rep, err := s.dispatchRequirementProof(ctx, job)
	// A proof stopped before it ended says nothing, and is not recorded over
	// the requirement's last proof: the run says how it ended.
	if ctx.Err() == nil {
		if err != nil {
			rep = failedProofReport(asked, err.Error())
		}
		clean := requirements.SanitizeProofs(rep, asked, hubScrubber(), time.Now().UTC())
		proofs = clean.Results
		if _, err := db.RecordRequirementProofs(statedb.ProofRecord{RunID: run.RunID, ExecutorID: run.ExecutorID,
			ProvedBy: run.StartedBy}, proofs); err != nil {
			endState, reason = statedb.RequirementRunFailed, "recording the proof: "+err.Error()
			return
		}
	}
	switch cause := context.Cause(ctx); {
	case ctx.Err() == nil:
	case errors.Is(cause, errHubStopping):
		endState, reason = statedb.RequirementRunFailed, errHubStopping.Error()
	case errors.Is(cause, errRequirementsCancelled):
		endState, reason = statedb.RequirementRunCancelled, "cancelled"
	default:
		endState, reason = statedb.RequirementRunFailed, "the proof ran past its deadline"
	}
}

// dispatchRequirementProof proves job's requirement on the project's executor
// and returns the report it sent back, unread by SanitizeProofs.
func (s *Server) dispatchRequirementProof(ctx context.Context, job *requirementProofJob) (requirements.ProofReport, error) {
	asked := []requirements.Requirement{job.req.ForSpec()}
	spec, err := requirements.EncodeSpec(requirements.Spec{Requirements: asked})
	if err != nil {
		return requirements.ProofReport{}, err
	}
	if len(spec) > requirements.MaxSpecBytes {
		return requirements.ProofReport{}, errors.New("the requirement is too large to send to the executor")
	}
	args := []string{"requirements", "prove", "--json", "--no-record", "--spec=" + string(spec)}
	if job.base != "" {
		args = append(args, "--base="+job.base)
	}
	out, runErr := job.dispatch(ctx, requirements.ProofBudget(asked, false), args)
	payload, perr := clijson.Extract(out)
	if perr == nil {
		var failed modelCallFailure
		if json.Unmarshal(payload, &failed) == nil && failed.Error != "" {
			return requirements.ProofReport{}, errors.New(failed.Error)
		}
		var rep requirements.ProofReport
		if err := json.Unmarshal(payload, &rep); err == nil && rep.Results != nil {
			return rep, nil
		}
	}
	if runErr == nil {
		return requirements.ProofReport{}, fmt.Errorf("the executor's cloop sent back no report: %v", perr)
	}
	return requirements.ProofReport{}, errors.New(modelCallReason(out, runErr))
}

// failedProofReport is a report saying the proof of each of asked did not
// run, and why.
func failedProofReport(asked []requirements.Requirement, why string) requirements.ProofReport {
	rep := requirements.ProofReport{}
	for _, q := range asked {
		rep.Results = append(rep.Results, requirements.Proof{RequirementID: q.ID,
			After: requirements.ProofSide{Skipped: "the proof did not run: " + strings.Join(strings.Fields(why), " ")}})
	}
	return rep
}

// finishRequirementProof records how a proof run ended — in its row, in the
// project's audit trail — and tells the project's dashboards.
func (s *Server) finishRequirementProof(job *requirementProofJob, endState string, proofs []requirements.Proof, reason string) {
	run := job.run
	db, err := statedb.Open(state.DBPath(job.workDir))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: requirements proof %s: record its end: %v\n", run.RunID, err)
		return
	}
	defer db.Close()
	db.AsProject()
	ended, err := db.FinishRequirementRun(run.RunID, endState, requirements.Counts{}, run.ExecutorID, reason)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: requirements proof %s: record its end: %v\n", run.RunID, err)
	}
	if ended {
		run.State, run.Error = endState, reason
		statedb.AuditRequirementProof(db, run, proofs, run.StartedBy)
		s.broadcastAuditAppend(string(auditaction.ActionRequirementProve))
	}
	s.requirementsChanged(job.workDir, run.RunID, endState)
}
