package ui

// run_result.go brings a run on an isolating executor home (Task 20339).
//
// A project bound to an executor that cannot read this hub's filesystem is
// carried out as a seed (workspace.go), and the run on the far side records its
// outcomes in its own copy. The dashboard renders *this* hub's copy. Until this
// file nothing connected the two, and the operator saw exactly what the task
// that motivated it reported: start the run, watch a transcript end with "All
// tasks complete", and find the task still pending — the run "completed
// immediately although there is one remaining task". Starting it again ran the
// task again.
//
// Now the executor reads back what the run changed and sends it before the
// run's final status (see pkg/executor/agent/projectresult.go), and runEnded —
// the one place every dispatch path settles a finished run — merges it into the
// hub's copy before anything else looks at the plan. Dead-run recovery runs
// after the merge, so a task the run left in progress is recovered from the
// run's own account of it rather than from a plan that never heard it started.
//
// Every outcome is written to the project's journal, including the ones where
// nothing could be merged: "this executor is too old to report back" and "the
// run ended without reporting" are the two cases in which the dashboard is
// stale, and a journal row naming why is the difference between an explained
// stale task and the bug this file fixes.

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/state"
)

// seededDispatch is what the hub knew about a dispatch that carried its project
// out: the provenance a merge stamps, which the device does not get a say in.
type seededDispatch struct {
	prov projectseed.Provenance
	// feature is set for a feature's run on an isolating executor: what its
	// returned work is landed against (Task 20367).
	feature *featureReturn
}

// maxSeededDispatches bounds the registry. An entry lives from dispatch to
// runEnded; the few paths that start a run and then lose sight of it (a stream
// that cannot be opened) would otherwise leak one entry each for the life of
// the process. Far above any real number of concurrent runs.
const maxSeededDispatches = 1024

var (
	seededMu    sync.Mutex
	seeded      = map[string]seededDispatch{}
	seededOrder []string
)

func seededKey(executorID, handleID string) string { return executorID + "\x00" + handleID }

// rememberSeededDispatch records that handleID on ex was sent the project.
func rememberSeededDispatch(ex executor.Executor, handleID string, prov projectseed.Provenance) {
	key := seededKey(ex.ID(), handleID)
	seededMu.Lock()
	defer seededMu.Unlock()
	if _, ok := seeded[key]; !ok {
		seededOrder = append(seededOrder, key)
	}
	seeded[key] = seededDispatch{prov: prov}
	for len(seededOrder) > maxSeededDispatches {
		delete(seeded, seededOrder[0])
		seededOrder = seededOrder[1:]
	}
}

// peekSeededDispatch returns the record for handleID on ex without forgetting
// it, so the run's owner row can carry the provenance to a member that adopts
// the run (Task 20354).
func peekSeededDispatch(ex executor.Executor, handleID string) (seededDispatch, bool) {
	if ex == nil || handleID == "" {
		return seededDispatch{}, false
	}
	seededMu.Lock()
	defer seededMu.Unlock()
	d, ok := seeded[seededKey(ex.ID(), handleID)]
	return d, ok
}

// isSeededDispatch reports whether handleID on ex was sent the project and has
// not been settled yet, without forgetting it.
func isSeededDispatch(ex executor.Executor, handleID string) bool {
	if ex == nil || handleID == "" {
		return false
	}
	seededMu.Lock()
	defer seededMu.Unlock()
	_, ok := seeded[seededKey(ex.ID(), handleID)]
	return ok
}

// overlaySeededRunStatus reports a seeded run that is in flight as running
// (Task 20349).
//
// A run on an executor that does not share this filesystem works on a copy of
// the project and brings its state back only when it ends (collectRunResult).
// Until then the hub's state.db still holds the previous run's status, so every
// reader of /api/state and of the state broadcasts saw a finished project while
// a device was working through it. The live flag and the tracked handle are the
// hub's own knowledge that the run is under way, and the wire state says so.
//
// Only a seeded run: a run on this filesystem writes its own status, and
// overriding it would misreport one that is already pausing or finishing.
func (s *Server) overlaySeededRunStatus(workDir string, ps *state.ProjectState) {
	if ps == nil || workDir == "" || ps.Status == "running" || ps.Status == "evolving" {
		return
	}
	// Another hub member may be the one streaming it (Task 20354): its owner
	// row says so, and says whether it was carried out as a seed.
	if o, meta, found := s.clusterRunOwner(workDir); found && !o.Self {
		if meta.Seeded && s.peerRunExecuting(workDir) {
			ps.Status = "running"
			ps.PauseReason = nil
		}
		return
	}
	if !s.liveLogRunningFor(workDir) {
		return
	}
	run, ok := s.trackedRun(workDir)
	if !ok || !isSeededDispatch(run.ex, run.handleID) {
		return
	}
	ps.Status = "running"
	ps.PauseReason = nil
}

// takeSeededDispatch returns and forgets the record for handleID on ex.
func takeSeededDispatch(ex executor.Executor, handleID string) (seededDispatch, bool) {
	key := seededKey(ex.ID(), handleID)
	seededMu.Lock()
	defer seededMu.Unlock()
	d, ok := seeded[key]
	if !ok {
		return seededDispatch{}, false
	}
	delete(seeded, key)
	for i, k := range seededOrder {
		if k == key {
			seededOrder = append(seededOrder[:i], seededOrder[i+1:]...)
			break
		}
	}
	return d, true
}

// collectRunResult merges what ex brought back of the run behind handleID into
// the hub's copy of workDir, and journals what happened. A run that was not
// sent the project — every run on an executor that shares this filesystem —
// has nothing to bring back and returns at once.
func (s *Server) collectRunResult(workDir string, ex executor.Executor, handleID string) {
	defer recoverGoroutine("collect run result: " + workDir)
	if workDir == "" || ex == nil || handleID == "" {
		return
	}
	d, ok := takeSeededDispatch(ex, handleID)
	if !ok {
		return
	}
	// A feature's commits come back beside its project state, and are landed
	// whatever became of the state — deferred so every early return below
	// still reaches it, and after the state merge so the journal reads in the
	// order things happened.
	if d.feature != nil {
		defer s.landFeatureWork(workDir, ex, handleID, d)
	}

	journal := func(msg string, details map[string]any) {
		if details == nil {
			details = map[string]any{}
		}
		details["executor_id"] = ex.ID()
		if d.prov.RunID != "" {
			details["run_id"] = d.prov.RunID
		}
		state.LogEventDetails(workDir, state.EventRow{
			Type:    state.EventProjectResult,
			Step:    state.NoStep,
			Message: msg,
		}, details)
	}

	fetcher, canFetch := ex.(executor.ProjectResultFetcher)
	if !canFetch || !ex.Capabilities().ReturnsProjectState {
		journal(fmt.Sprintf("Executor %q ran this project from a copy of its plan and cannot send the "+
			"outcome back, so tasks it ran still show their earlier status here — and will run again "+
			"if the project is started again. %s", ex.ID(), projectResultRemedy(ex)), nil)
		return
	}

	res, err := fetcher.ProjectResult(handleID)
	if err != nil {
		if errors.Is(err, executor.ErrProjectResultUnavailable) {
			journal(missingProjectResultMessage(ex, err), map[string]any{"reason": err.Error()})
		} else {
			journal(fmt.Sprintf("The run's results could not be collected from executor %q: %v", ex.ID(), err), nil)
		}
		return
	}
	if res.Err != "" {
		journal(fmt.Sprintf("Executor %q could not read the run's results back: %s. Tasks it ran still "+
			"show their earlier status here.", ex.ID(), res.Redact(res.Err)), nil)
		return
	}

	result, err := projectseed.DecodeResult(res.Data)
	if err != nil {
		journal(fmt.Sprintf("Executor %q sent back a report of the run that could not be read (%v); "+
			"nothing from it was merged.", ex.ID(), err), nil)
		return
	}

	rep, err := projectseed.Apply(workDir, result, d.prov, res.Redact)
	details := map[string]any{
		"updated": rep.Updated, "added": rep.Added, "kept": len(rep.Kept),
		"steps": rep.Steps, "events": rep.Events, "costs": rep.Costs,
	}
	if len(rep.Renumbered) > 0 {
		details["renumbered"] = rep.Renumbered
	}
	msg := rep.Summary()
	switch {
	case err != nil && !rep.Changed():
		msg = fmt.Sprintf("The run's results came back from executor %q but could not be merged: %v. "+
			"Tasks it ran still show their earlier status here.", ex.ID(), err)
	case err != nil:
		msg += fmt.Sprintf(" Recording it failed part-way: %v", err)
	}
	if err != nil {
		details["error"] = err.Error()
		s.log().Warn(logger.EventCheckpoint, 0, "remote run result: merge failed",
			map[string]interface{}{"project": workDir, "executor": ex.ID(), "error": err.Error()})
	}
	journal(msg, details)

	if rep.Changed() {
		if st, loadErr := state.LoadLite(workDir); loadErr == nil {
			s.broadcastStateDiff(workDir, st)
		} else {
			fmt.Fprintf(os.Stderr, "ui: reload %s after merging a run: %v\n", workDir, loadErr)
		}
		s.refreshProjectStatuses()
		s.broadcastProjectsUpdate()
	}
}

// projectResultRemedy says how ex comes to send a seeded run's outcome back, in
// the terms of ex's own kind. Only a device's answer is an agent upgrade.
func projectResultRemedy(ex executor.Executor) string {
	switch ex.Kind() {
	case executor.KindRemoteAgent, executor.KindVirtual:
		return executor.NeedsProtocol("Its agent", sessionProtocolOf(ex), remote.MinProjectResultVersion,
			"to have a seeded run's outcome sent back", "")
	case executor.KindKubernetes:
		// Unreachable from this hub's own driver, which reads the outcome back
		// out of the Pod's log; said plainly for whatever reports the kind
		// without the capability.
		return "A Kubernetes executor of this hub's build reads the outcome back out of the Pod's log, " +
			"so this one is not running this hub's driver."
	}
	return "Bind the project to an executor that shares the control plane's filesystem, or to one that " +
		"returns a run's project state."
}

// missingProjectResultMessage is the journal row for a seeded run whose executor
// can return its outcome and did not, naming what is most likely for ex's kind
// and the driver's own account of what it saw.
func missingProjectResultMessage(ex executor.Executor, err error) string {
	why := strings.TrimSpace(strings.TrimPrefix(err.Error(), executor.ErrProjectResultUnavailable.Error()))
	why = strings.TrimSpace(strings.TrimPrefix(why, ":"))
	var likely string
	switch ex.Kind() {
	case executor.KindKubernetes:
		// The Pod's log is the only way home (pkg/executor/kubernetes/
		// projectresult.go), so what can go wrong is what can go wrong with
		// that log.
		likely = "The Pod's log ended without a complete project result in it: the harness image's " +
			"cloop may predate `cloop workspace writeback --project-result-frame`, the Pod may have been " +
			"evicted or stopped before its wrapper finished, or the workload printed a result frame of " +
			"its own, which makes the real one a duplicate and neither is believed"
	case executor.KindRemoteAgent, executor.KindVirtual:
		likely = "Typically the connection dropped before the run finished"
	default:
		likely = "The executor reported no result for the run"
	}
	msg := fmt.Sprintf("The run on executor %q ended without sending its results back, so tasks it ran "+
		"still show their earlier status here. %s.", ex.ID(), likely)
	if why != "" {
		msg += " What the executor saw: " + why + "."
	}
	return msg + " Check the run's log for how far it got."
}
